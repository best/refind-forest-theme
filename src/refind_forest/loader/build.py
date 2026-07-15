"""Reproducibly build the patched rEFInd loader."""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import platform
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from urllib.request import HTTPRedirectHandler, build_opener

from .verify import reject_setmem_call_edges, verify_pe


_SOURCE_DATE_EPOCH = "1738518142"
_CFLAGS = (
    "CFLAGS=-Os -fno-strict-aliasing -fno-tree-loop-distribute-patterns "
    "-fno-stack-protector -fshort-wchar -Wall -DGNU_EFI_3_0_COMPAT"
)
_BUILD_ENVIRONMENT = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": _SOURCE_DATE_EPOCH,
    "TZ": "UTC",
}
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_PATCH_PATH = _PROJECT_ROOT / "patches" / "refind-0.14.2-gnu-efi-abi.patch"
_SBAT_PATH = _PROJECT_ROOT / "assets" / "loader" / "refind-forest-sbat.csv"
_PATCHED_PATHS = frozenset(
    {
        "EfiLib/gnuefi-helper.c",
        "EfiLib/legacy.c",
        "libeg/lodepng_xtra.c",
        "libeg/nanojpeg.c",
        "refind/Makefile",
        "refind/config.c",
        "refind/launch_legacy.c",
        "refind/lib.c",
    }
)
_SETMEM_SOURCE_PATHS = (
    "refind/config.c",
    "refind/lib.c",
    "refind/launch_legacy.c",
    "EfiLib/legacy.c",
    "libeg/lodepng_xtra.c",
)
_SETMEM_CALL = re.compile(r"\bSetMem\s*\(")
_SETMEM_NM_SYMBOL = re.compile(
    r"^([0-9a-fA-F]+)\s+[A-Za-z]\s+_?SetMem$",
    re.MULTILINE,
)
_OBJDUMP_INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+([a-z][a-z0-9]*)\s*(.*?)\s*$"
)
_OBJDUMP_FUNCTION = re.compile(r"^\s*[0-9a-fA-F]+\s+<([^>]+)>:\s*$")
_AUDITED_OBJECTS = (
    "refind/config.o",
    "refind/lib.o",
    "refind/launch_legacy.o",
    "EfiLib/legacy.o",
    "libeg/lodepng_xtra.o",
    "libeg/nanojpeg.o",
)
_OBJECT_STORE_SITES = {
    "refind/config.o": ("config_showtools",),
    "refind/lib.o": ("volume_uuid",),
    "refind/launch_legacy.o": ("mbr_bootcode",),
    "EfiLib/legacy.o": ("device_type_index",),
    "libeg/lodepng_xtra.o": ("my_memset",),
    "libeg/nanojpeg.o": (),
}
_ALL_STORE_SITES = (
    "config_showtools",
    "volume_uuid",
    "mbr_bootcode",
    "device_type_index",
    "my_memset",
)
_STORE_SITE_OWNERS = {
    "config_showtools": "ReadConfig",
    "volume_uuid": "ScanVolumeBootcode",
    "mbr_bootcode": "StartLegacy",
    "device_type_index": "GroupMultipleLegacyBootOption4SameType",
    "my_memset": "MyMemSet",
}
_OBJDUMP_COMMAND = ["objdump", "--no-show-raw-insn", "-dr", "-Mintel"]
_PUBLICATION_FILES = frozenset({"provenance.json", "refind_x64.efi"})
_QUARANTINE_ENTRY = "publication"


@dataclass(frozen=True, slots=True)
class PinnedInput:
    """One immutable external build input."""

    name: str
    filename: str
    url: str
    sha256: str


PINNED_INPUTS = (
    PinnedInput(
        "refind_source",
        "refind_0.14.2.orig.tar.gz",
        "https://archive.ubuntu.com/ubuntu/pool/universe/r/refind/"
        "refind_0.14.2.orig.tar.gz",
        "f7d93ce80da76b86c567281ea225b6a87907ce86ff77233c9357a522c115c8f0",
    ),
    PinnedInput(
        "refind_debian_delta",
        "refind_0.14.2-2.1.debian.tar.xz",
        "https://archive.ubuntu.com/ubuntu/pool/universe/r/refind/"
        "refind_0.14.2-2.1.debian.tar.xz",
        "8304bae605542651d129eb6711e248956291ec3fd0e2a6c48ccafc415d91f900",
    ),
    PinnedInput(
        "gnu_efi",
        "gnu-efi_4.0.0-1_amd64.deb",
        "https://archive.ubuntu.com/ubuntu/pool/main/g/gnu-efi/"
        "gnu-efi_4.0.0-1_amd64.deb",
        "7e00d02cc6cba79d8f99984c3554df42d808ee51c73699e2776a3e86a0c1d038",
    ),
)


@dataclass(frozen=True, slots=True)
class _ObjdumpInstruction:
    address: int
    mnemonic: str
    operands: str
    function: str | None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


urlopen = build_opener(_NoRedirect()).open


def _objdump_instruction_blocks(
    disassembly: str,
) -> list[list[_ObjdumpInstruction]]:
    blocks: list[list[_ObjdumpInstruction]] = []
    instructions: list[_ObjdumpInstruction] = []
    function: str | None = None
    for line in disassembly.splitlines():
        function_match = _OBJDUMP_FUNCTION.match(line)
        if function_match is not None:
            if instructions:
                blocks.append(instructions)
                instructions = []
            function = function_match.group(1).split("+", 1)[0]
            function = function.removesuffix(".localalias")
            continue
        match = _OBJDUMP_INSTRUCTION.match(line)
        if match is None:
            continue
        operands = match.group(3).partition("#")[0].strip().lower()
        operands = re.sub(r"\s+", " ", operands)
        instructions.append(
            _ObjdumpInstruction(
                address=int(match.group(1), 16),
                mnemonic=match.group(2).lower(),
                operands=operands,
                function=function,
            )
        )
    if instructions:
        blocks.append(instructions)
    return blocks


def _branch_target(instruction: _ObjdumpInstruction) -> int | None:
    match = re.match(r"(?:0x)?([0-9a-f]+)\b", instruction.operands)
    return None if match is None else int(match.group(1), 16)


def _config_clear_matches(
    instructions: list[_ObjdumpInstruction], index: int
) -> bool:
    if index + 11 > len(instructions):
        return False
    window = instructions[index : index + 11]
    return (
        (window[0].mnemonic, window[0].operands)
        == ("lea", "rdx,[rbx+0x168]")
        and (window[1].mnemonic, window[1].operands) == ("mov", "eax,0x19")
        and (window[2].mnemonic, window[2].operands) == ("dec", "rax")
        and window[3].mnemonic == "je"
        and _branch_target(window[3]) == window[8].address
        and (window[4].mnemonic, window[4].operands) == ("xor", "r8d,r8d")
        and (window[5].mnemonic, window[5].operands) == ("add", "rdx,0x8")
        and (window[6].mnemonic, window[6].operands)
        == ("mov", "qword ptr [rdx-0x8],r8")
        and window[7].mnemonic == "jmp"
        and _branch_target(window[7]) == window[2].address
        and window[8].mnemonic in {"lea", "mov"}
        and window[8].operands.startswith("rbp,")
        and (window[9].mnemonic, window[9].operands) == ("mov", "eax,0x1")
        and (window[10].mnemonic, window[10].operands)
        == ("mov", "byte ptr [rbp+0x7],0x0")
    )


def _guid_clear_matches(
    instructions: list[_ObjdumpInstruction], index: int
) -> bool:
    if index + 6 > len(instructions):
        return False
    window = instructions[index : index + 6]
    return (
        (window[0].mnemonic, window[0].operands)
        == ("lea", "rax,[rbx+0x30]")
        and (window[1].mnemonic, window[1].operands)
        == ("lea", "rdx,[rbx+0x40]")
        and (window[2].mnemonic, window[2].operands)
        == ("mov", "byte ptr [rax],0x0")
        and (window[3].mnemonic, window[3].operands) == ("inc", "rax")
        and (window[4].mnemonic, window[4].operands) == ("cmp", "rax,rdx")
        and window[5].mnemonic == "jne"
        and _branch_target(window[5]) == window[2].address
    )


def _mbr_clear_matches(
    instructions: list[_ObjdumpInstruction], index: int
) -> bool:
    if index + 6 > len(instructions):
        return False
    window = instructions[index : index + 6]
    return (
        (window[0].mnemonic, window[0].operands) == ("xor", "eax,eax")
        and (window[1].mnemonic, window[1].operands)
        == ("lea", "rdx,[rax+rbp*1]")
        and (window[2].mnemonic, window[2].operands) == ("inc", "rax")
        and (window[3].mnemonic, window[3].operands)
        == ("mov", "byte ptr [rdx],0x0")
        and (window[4].mnemonic, window[4].operands)
        == ("cmp", "rax,0x1b8")
        and window[5].mnemonic == "jne"
        and _branch_target(window[5]) == window[1].address
    )


def _device_type_clear_matches(
    instructions: list[_ObjdumpInstruction], index: int
) -> bool:
    if index + 6 > len(instructions):
        return False
    window = instructions[index : index + 6]
    if (
        (window[0].mnemonic, window[0].operands)
        != ("lea", "rdx,[rsp+0x8]")
        or (window[1].mnemonic, window[1].operands) != ("inc", "rax")
        or (window[2].mnemonic, window[2].operands)
        != ("mov", "qword ptr [rdx],0xffffffffffffffff")
        or (window[3].mnemonic, window[3].operands) != ("add", "rdx,0x8")
        or (window[4].mnemonic, window[4].operands) != ("cmp", "rax,0x7")
        or window[5].mnemonic != "jne"
        or _branch_target(window[5]) != window[1].address
    ):
        return False

    prefix = instructions[max(0, index - 12) : index]
    initializers = [
        prefix_index
        for prefix_index, instruction in enumerate(prefix)
        if (instruction.mnemonic, instruction.operands) == ("xor", "eax,eax")
    ]
    if not initializers:
        return False
    initializer = initializers[-1]
    return not any(
        instruction.operands in {"eax", "rax"}
        or instruction.operands.startswith(("eax,", "rax,"))
        for instruction in prefix[initializer + 1 :]
    )


def _my_memset_matches(
    instructions: list[_ObjdumpInstruction], index: int
) -> bool:
    if index + 9 > len(instructions):
        return False
    window = instructions[index : index + 9]
    return (
        (window[0].mnemonic, window[0].operands) == ("xor", "eax,eax")
        and (window[1].mnemonic, window[1].operands) == ("cmp", "rax,rdx")
        and window[2].mnemonic == "je"
        and _branch_target(window[2]) == window[7].address
        and (window[3].mnemonic, window[3].operands)
        == ("lea", "rcx,[rdi+rax*1]")
        and (window[4].mnemonic, window[4].operands) == ("inc", "rax")
        and (window[5].mnemonic, window[5].operands)
        == ("mov", "byte ptr [rcx],sil")
        and window[6].mnemonic == "jmp"
        and _branch_target(window[6]) == window[1].address
        and (window[7].mnemonic, window[7].operands) == ("mov", "rax,rdi")
        and (window[8].mnemonic, window[8].operands) == ("ret", "")
    )


def _verify_local_store_semantics(
    disassembly: str,
    required_sites: tuple[str, ...],
    *,
    require_function_symbols: bool = False,
) -> None:
    instruction_blocks = _objdump_instruction_blocks(disassembly)
    checks = {
        "config_showtools": _config_clear_matches,
        "volume_uuid": _guid_clear_matches,
        "mbr_bootcode": _mbr_clear_matches,
        "device_type_index": _device_type_clear_matches,
        "my_memset": _my_memset_matches,
    }
    for site in required_sites:
        try:
            check = checks[site]
        except KeyError as error:
            raise ValueError(f"unknown local-store audit site: {site}") from error
        owner = _STORE_SITE_OWNERS[site]
        matches = sum(
            check(instructions, index)
            for instructions in instruction_blocks
            if not require_function_symbols or instructions[0].function == owner
            for index in range(len(instructions))
        )
        if matches != 1:
            raise RuntimeError(
                f"{site} local-store semantics must match exactly once; found {matches}"
            )


def _sha256_file(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot open cache entry {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"cache entry is not a regular file: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, _DOWNLOAD_CHUNK_SIZE):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _prepare_cache(cache: Path) -> None:
    if os.path.lexists(cache):
        metadata = cache.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"cache is not a real directory: {cache}")
        return
    cache.mkdir(parents=True)


def _download_input(item: PinnedInput, destination: Path) -> None:
    temporary_path: Path | None = None
    try:
        with urlopen(item.url, timeout=30) as response:
            if response.geturl() != item.url:
                raise RuntimeError(f"refusing download redirect for {item.url}")
            digest = hashlib.sha256()
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{item.filename}.",
                dir=destination.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                while chunk := response.read(_DOWNLOAD_CHUNK_SIZE):
                    temporary.write(chunk)
                    digest.update(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())
        if digest.hexdigest() != item.sha256:
            raise RuntimeError(f"SHA-256 mismatch for {item.filename}")
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _acquire_inputs(cache: Path) -> dict[str, Path]:
    cache = Path(cache)
    _prepare_cache(cache)
    acquired: dict[str, Path] = {}
    for item in PINNED_INPUTS:
        destination = cache / item.filename
        if os.path.lexists(destination):
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"cache entry is not a regular file: {destination}")
            if _sha256_file(destination) == item.sha256:
                acquired[item.name] = destination
                continue
        _download_input(item, destination)
        if _sha256_file(destination) != item.sha256:
            raise RuntimeError(f"published cache hash changed for {item.filename}")
        acquired[item.name] = destination
    return acquired


def _snapshot_inputs(
    acquired: dict[str, Path], destination: Path
) -> dict[str, Path]:
    destination = Path(destination)
    expected_names = {item.name for item in PINNED_INPUTS}
    if set(acquired) != expected_names:
        raise ValueError("acquired inputs do not match the pinned input set")
    if os.path.lexists(destination):
        raise ValueError(f"input snapshot destination already exists: {destination}")
    destination.mkdir(mode=0o700)
    destination.chmod(0o700)

    snapshots: dict[str, Path] = {}
    source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    snapshot_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    for item in PINNED_INPUTS:
        source = Path(acquired[item.name])
        snapshot = destination / item.filename
        try:
            source_descriptor = os.open(source, source_flags)
        except OSError as error:
            raise ValueError(f"cannot open acquired input {source}: {error}") from error

        snapshot_descriptor: int | None = None
        try:
            metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"acquired input is not a regular file: {source}")
            snapshot_descriptor = os.open(snapshot, snapshot_flags, 0o600)
            digest = hashlib.sha256()
            with os.fdopen(snapshot_descriptor, "wb") as snapshot_file:
                snapshot_descriptor = None
                while chunk := os.read(source_descriptor, _DOWNLOAD_CHUNK_SIZE):
                    digest.update(chunk)
                    if snapshot_file.write(chunk) != len(chunk):
                        raise OSError(f"short write while snapshotting {item.filename}")
                snapshot_file.flush()
                os.fsync(snapshot_file.fileno())
            if digest.hexdigest() != item.sha256:
                raise RuntimeError(f"SHA-256 mismatch for {item.filename} snapshot")
            snapshot.chmod(0o600)
            snapshots[item.name] = snapshot
        except BaseException:
            snapshot.unlink(missing_ok=True)
            raise
        finally:
            if snapshot_descriptor is not None:
                os.close(snapshot_descriptor)
            os.close(source_descriptor)

    return snapshots


def _safe_archive_path(value: str, description: str) -> PurePosixPath:
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or ".." in raw_parts
        or path.is_absolute()
    ):
        raise ValueError(f"unsafe {description}: {value}")
    return path


def _validate_tar_archive(archive: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar.getmembers():
                member_path = _safe_archive_path(member.name, "archive path")
                if member.ischr() or member.isblk() or member.isfifo():
                    raise ValueError(f"archive device entry is forbidden: {member.name}")
                if not (
                    member.isreg()
                    or member.isdir()
                    or member.issym()
                    or member.islnk()
                ):
                    raise ValueError(f"unsafe archive member type: {member.name}")
                if not (member.issym() or member.islnk()):
                    continue
                link = _safe_archive_path(member.linkname, "archive link")
                base = member_path.parent if member.issym() else PurePosixPath()
                resolved = PurePosixPath(posixpath.normpath(str(base / link)))
                if resolved.is_absolute() or ".." in resolved.parts:
                    raise ValueError(
                        f"archive link escapes extraction root: {member.name}"
                    )
    except (tarfile.TarError, OSError) as error:
        raise ValueError(f"cannot inspect tar archive {archive}: {error}") from error


def _new_directory(path: Path) -> None:
    if os.path.lexists(path):
        raise ValueError(f"extraction destination already exists: {path}")
    path.mkdir()


def _extract_tar(archive: Path, destination: Path) -> None:
    archive = Path(archive)
    destination = Path(destination)
    _validate_tar_archive(archive)
    _new_directory(destination)
    subprocess.run(
        [
            "tar",
            "--extract",
            "--file",
            str(archive),
            "--directory",
            str(destination),
            "--no-same-owner",
            "--no-same-permissions",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=dict(_BUILD_ENVIRONMENT),
    )


def _extract_deb(archive: Path, destination: Path) -> None:
    archive = Path(archive)
    destination = Path(destination)
    _new_directory(destination)
    subprocess.run(
        ["dpkg-deb", "--extract", str(archive), str(destination)],
        check=True,
        capture_output=True,
        text=True,
        env=dict(_BUILD_ENVIRONMENT),
    )


def _source_root(container: Path) -> Path:
    container = Path(container)
    expected = container / "refind-0.14.2"
    try:
        entries = list(container.iterdir())
    except OSError as error:
        raise ValueError(f"cannot inspect source extraction: {error}") from error
    if (
        entries != [expected]
        or expected.is_symlink()
        or not expected.is_dir()
    ):
        raise ValueError("source archive must contain exactly refind-0.14.2")
    return expected


def _validate_debian_delta(container: Path) -> Path:
    debian = Path(container) / "debian"
    changelog_path = debian / "changelog"
    series_path = debian / "patches" / "series"
    try:
        changelog = changelog_path.read_text(encoding="utf-8")
        series = series_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"invalid Debian delta metadata: {error}") from error
    lines = changelog.splitlines()
    if not lines or lines[0] != "refind (0.14.2-2.1) unstable; urgency=medium":
        raise ValueError("unexpected Debian delta version")
    try:
        trailer = next(line for line in lines if line.startswith(" -- "))
        timestamp = trailer.rsplit("  ", 1)[1]
        epoch = int(parsedate_to_datetime(timestamp).timestamp())
    except (IndexError, StopIteration, TypeError, ValueError) as error:
        raise ValueError("invalid Debian changelog timestamp") from error
    if epoch != int(_SOURCE_DATE_EPOCH):
        raise ValueError("unexpected Debian changelog epoch")
    if series.strip():
        raise ValueError("Debian patch series must be empty")
    return debian


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _changed_paths(
    before: dict[str, str], after: dict[str, str]
) -> frozenset[str]:
    return frozenset(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


def _verify_source(source: Path) -> None:
    source = Path(source)
    for relative in _SETMEM_SOURCE_PATHS:
        text = (source / relative).read_text(encoding="ascii")
        if _SETMEM_CALL.search(text):
            raise RuntimeError(f"SetMem call remains in {relative}")
    nanojpeg = (source / "libeg" / "nanojpeg.c").read_text(encoding="ascii")
    if "#define memset(b, c, v) MyMemSet(b, c, v)" not in nanojpeg:
        raise RuntimeError("NanoJPEG memset adapter is not in standard order")
    helper = (source / "EfiLib" / "gnuefi-helper.c").read_text(encoding="ascii")
    if "#ifndef _GNU_EFI_4_0" not in helper:
        raise RuntimeError("GNU-EFI 4 AsciiStrLen guard is missing")
    makefile = (source / "refind" / "Makefile").read_text(encoding="ascii")
    if ".sbat+0x1000000" not in makefile or ".sbat+10000000" in makefile:
        raise RuntimeError("loader SBAT RVA is not aligned")


def _prepare_source(base: Path, delta: Path, destination: Path) -> Path:
    base = Path(base)
    destination = Path(destination)
    debian = _validate_debian_delta(delta)
    if os.path.lexists(destination):
        raise ValueError(f"source destination already exists: {destination}")
    shutil.copytree(base, destination, symlinks=True)
    shutil.copytree(
        debian,
        destination / "debian",
        dirs_exist_ok=True,
        symlinks=True,
    )

    patch_artifacts_before = {
        path.relative_to(destination).as_posix()
        for pattern in ("*.rej", "*.orig")
        for path in destination.rglob(pattern)
    }
    before = _tree_hashes(destination)
    subprocess.run(
        [
            "patch",
            "--batch",
            "--forward",
            "--fuzz=0",
            "-p1",
            "-i",
            str(_PATCH_PATH),
        ],
        cwd=destination,
        check=True,
        capture_output=True,
        text=True,
        env=dict(_BUILD_ENVIRONMENT),
    )
    after = _tree_hashes(destination)
    changed = _changed_paths(before, after)
    if changed != _PATCHED_PATHS:
        raise RuntimeError(
            "patch must change exactly eight files; "
            f"changed {', '.join(sorted(changed)) or 'none'}"
        )
    patch_artifacts_after = {
        path.relative_to(destination).as_posix()
        for pattern in ("*.rej", "*.orig")
        for path in destination.rglob(pattern)
    }
    if patch_artifacts_after != patch_artifacts_before:
        raise RuntimeError("patch left reject or backup files")
    shutil.copyfile(_SBAT_PATH, destination / "refind-forest-sbat.csv")
    _verify_source(destination)
    return destination


def _run_build(source: Path, gnu_efi_root: Path) -> None:
    command, environment = make_command(source, gnu_efi_root)
    subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )


def _run_tool(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=dict(_BUILD_ENVIRONMENT),
    )
    return result.stdout


def _tool_versions() -> dict[str, str]:
    """Return path-stable, ASCII version records for the build toolchain."""

    versions = {"python": f"Python {platform.python_version()}"}
    commands = (
        ("make", ["make", "--version"]),
        ("gcc", ["gcc", "--version"]),
        ("ld", ["ld", "--version"]),
        ("objcopy", ["objcopy", "--version"]),
        ("nm", ["nm", "--version"]),
        ("objdump", ["objdump", "--version"]),
        ("patch", ["patch", "--version"]),
        ("tar", ["tar", "--version"]),
        ("dpkg-deb", ["dpkg-deb", "--version"]),
    )
    for name, command in commands:
        output = _run_tool(command)
        lines = output.splitlines()
        if not lines or not lines[0].strip():
            raise RuntimeError(f"{name} did not report a version")
        versions[name] = lines[0].strip()

    for name, version in versions.items():
        try:
            version.encode("ascii")
        except UnicodeEncodeError as error:
            raise RuntimeError(f"{name} reported a non-ASCII version") from error
    return versions


def _audit_build(source: Path, expected_sbat: bytes) -> dict[str, object]:
    source = Path(source)
    object_hashes: dict[str, str] = {}
    for relative in _AUDITED_OBJECTS:
        path = source / relative
        object_hashes[relative] = _sha256_file(path)
        disassembly = _run_tool([*_OBJDUMP_COMMAND, str(path)])
        reject_setmem_call_edges(disassembly)
        _verify_local_store_semantics(
            disassembly,
            _OBJECT_STORE_SITES[relative],
            require_function_symbols=True,
        )

    shared = source / "refind" / "refind_x64.so"
    shared_hash = _sha256_file(shared)
    shared_disassembly = _run_tool([*_OBJDUMP_COMMAND, str(shared)])
    reject_setmem_call_edges(shared_disassembly)
    _verify_local_store_semantics(
        shared_disassembly,
        _ALL_STORE_SITES,
        require_function_symbols=True,
    )
    symbols = _run_tool(["nm", "-n", str(shared)])
    setmem_addresses = _SETMEM_NM_SYMBOL.findall(symbols)
    if len(setmem_addresses) != 1:
        raise RuntimeError(
            "shared object must expose exactly one defined SetMem symbol"
        )
    setmem_address = int(setmem_addresses[0], 16)

    efi = source / "refind" / "refind_x64.efi"
    efi_hash = _sha256_file(efi)
    final_disassembly = _run_tool([*_OBJDUMP_COMMAND, str(efi)])
    reject_setmem_call_edges(
        final_disassembly,
        target_address=setmem_address,
    )
    _verify_local_store_semantics(
        final_disassembly,
        _ALL_STORE_SITES,
        require_function_symbols=False,
    )
    verify_pe(efi, expected_sbat)
    return {
        "objects": object_hashes,
        "shared_object": shared_hash,
        "efi": efi_hash,
    }


def make_command(
    source: Path, gnu_efi_root: Path | None = None
) -> tuple[list[str], dict[str, str]]:
    """Return the pinned non-installing GNU-EFI build command and environment."""

    source = Path(source)
    gnu_efi_root = Path("/") if gnu_efi_root is None else Path(gnu_efi_root)
    include = gnu_efi_root / "usr" / "include" / "efi"
    library = gnu_efi_root / "usr" / "lib"
    command = [
        "make",
        "-C",
        str(source),
        "gnuefi",
        "ARCH=x86_64",
        f"EFIINC={include}",
        f"GNUEFILIB={library}",
        f"EFILIB={library}",
        f"EFICRT0={library}",
        "REFIND_SBAT_CSV=refind-forest-sbat.csv",
        "FORMAT=--output-target=efi-app-x86_64",
        _CFLAGS,
    ]
    return command, dict(_BUILD_ENVIRONMENT)


def _existing_real_directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(
            f"build publication directory identity mismatch at {path}"
        )
    return metadata.st_dev, metadata.st_ino


def _require_build_directory_identity(
    path: Path,
    expected: tuple[int, int],
) -> None:
    if _existing_real_directory_identity(path) != expected:
        raise RuntimeError(
            f"build publication directory identity mismatch at {path}"
        )


def _directory_identity_at(
    directory_fd: int,
    name: str,
) -> tuple[int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(
            f"build publication directory identity mismatch at {name}"
        )
    return metadata.st_dev, metadata.st_ino


def _restore_quarantined_directory(
    quarantine_fd: int,
    path: Path,
) -> bool:
    if os.path.lexists(path):
        return False
    os.rename(
        _QUARANTINE_ENTRY,
        path,
        src_dir_fd=quarantine_fd,
    )
    return True


def _remove_build_directory(path: Path, expected: tuple[int, int]) -> None:
    actual = _existing_real_directory_identity(path)
    if actual is None:
        return
    if actual != expected:
        raise RuntimeError(
            f"build publication directory identity mismatch at {path}"
        )
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    quarantine = Path(
        tempfile.mkdtemp(
            prefix=f".{path.name}.cleanup-",
            dir=path.parent,
        )
    )
    quarantine.chmod(0o700)
    parent_fd = os.open(path.parent, directory_flags)
    quarantine_fd: int | None = None
    isolated = False
    try:
        quarantine_identity = _directory_identity_at(parent_fd, quarantine.name)
        if quarantine_identity is None:
            raise RuntimeError("build publication quarantine identity is unavailable")
        quarantine_fd = os.open(
            quarantine.name,
            directory_flags,
            dir_fd=parent_fd,
        )
        quarantine_metadata = os.fstat(quarantine_fd)
        if (
            quarantine_metadata.st_dev,
            quarantine_metadata.st_ino,
        ) != quarantine_identity:
            raise RuntimeError(
                f"build publication directory identity mismatch at {quarantine}"
            )
        os.rename(
            path,
            _QUARANTINE_ENTRY,
            dst_dir_fd=quarantine_fd,
        )
        isolated = True
        isolated_identity = _directory_identity_at(
            quarantine_fd,
            _QUARANTINE_ENTRY,
        )
        if isolated_identity != expected:
            restored = _restore_quarantined_directory(quarantine_fd, path)
            isolated = not restored
            error = RuntimeError(
                f"build publication directory identity mismatch at {path}"
            )
            if isolated:
                error.add_note(f"foreign directory preserved under {quarantine}")
            raise error

        publication_fd = os.open(
            _QUARANTINE_ENTRY,
            directory_flags,
            dir_fd=quarantine_fd,
        )
        try:
            metadata = os.fstat(publication_fd)
            if (metadata.st_dev, metadata.st_ino) != expected:
                raise RuntimeError(
                    f"build publication directory identity mismatch at {path}"
                )
            entries = frozenset(os.listdir(publication_fd))
            if entries != _PUBLICATION_FILES:
                raise RuntimeError(
                    "build publication directory contents changed during cleanup"
                )
            for name in sorted(entries):
                entry = os.stat(
                    name,
                    dir_fd=publication_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(entry.st_mode):
                    raise RuntimeError(
                        "build publication directory contents changed during cleanup"
                    )
            for name in sorted(entries):
                os.unlink(name, dir_fd=publication_fd)
        finally:
            os.close(publication_fd)

        if _directory_identity_at(quarantine_fd, _QUARANTINE_ENTRY) != expected:
            raise RuntimeError(
                f"build publication directory identity mismatch at {path}"
            )
        os.rmdir(_QUARANTINE_ENTRY, dir_fd=quarantine_fd)
        isolated = False
        # POSIX cannot condition rmdir on an inode; keep the empty random root.
    finally:
        if quarantine_fd is not None:
            os.close(quarantine_fd)
        os.close(parent_fd)


def _recover_build_publication(
    paths: tuple[Path, ...],
    expected: tuple[int, int],
) -> None:
    owned_paths: list[Path] = []
    mismatch: RuntimeError | None = None
    for path in paths:
        try:
            actual = _existing_real_directory_identity(path)
        except RuntimeError as error:
            mismatch = mismatch or error
            continue
        if actual is None:
            continue
        if actual == expected:
            owned_paths.append(path)
        else:
            mismatch = mismatch or RuntimeError(
                f"build publication directory identity mismatch at {path}"
            )

    for path in owned_paths:
        _remove_build_directory(path, expected)
    if mismatch is not None:
        raise mismatch


def build_loader(output: Path, cache: Path) -> Path:
    """Build, audit, and atomically publish a reproducible rEFInd loader."""

    output = Path(output)
    cache = Path(cache)
    if os.path.lexists(output):
        raise ValueError(f"output already exists: {output}")
    resolved_output = output.resolve(strict=False)
    resolved_cache = cache.resolve(strict=False)
    if (
        resolved_cache == resolved_output
        or resolved_output in resolved_cache.parents
    ):
        raise ValueError("cache must not be output or nested inside output")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_workspace = tempfile.TemporaryDirectory(
        prefix=f".{output.name}.build-",
        dir=output.parent,
    )
    pending_output: Path | None = None
    publication_identity: tuple[int, int] | None = None
    try:
        workspace = Path(temporary_workspace.name)
        acquired = _acquire_inputs(cache)
        inputs = _snapshot_inputs(acquired, workspace / "verified-inputs")

        source_container = workspace / "refind-source"
        delta_container = workspace / "refind-debian-delta"
        gnu_efi_root = workspace / "gnu-efi"
        _extract_tar(inputs["refind_source"], source_container)
        _extract_tar(inputs["refind_debian_delta"], delta_container)
        _extract_deb(inputs["gnu_efi"], gnu_efi_root)
        source_root = _source_root(source_container)

        expected_sbat = _SBAT_PATH.read_bytes()
        prepared_sources = [
            _prepare_source(
                source_root,
                delta_container,
                workspace / f"source-{build_number}",
            )
            for build_number in (1, 2)
        ]
        source_hashes = {
            relative: _sha256_file(prepared_sources[0] / relative)
            for relative in sorted(_PATCHED_PATHS)
        }

        audits: list[dict[str, object]] = []
        efi_outputs: list[bytes] = []
        for source in prepared_sources:
            _run_build(source, gnu_efi_root)
            audits.append(_audit_build(source, expected_sbat))
            efi_outputs.append((source / "refind" / "refind_x64.efi").read_bytes())

        if efi_outputs[0] != efi_outputs[1]:
            raise RuntimeError("clean build outputs must be byte-identical")

        first_audit = audits[0]
        efi_hash = hashlib.sha256(efi_outputs[0]).hexdigest()
        build_audits = [
            {
                "build": build_number,
                "objects": dict(audit["objects"]),
                "shared_object": {
                    "path": "refind/refind_x64.so",
                    "sha256": audit["shared_object"],
                },
                "efi": {
                    "path": "refind/refind_x64.efi",
                    "sha256": audit["efi"],
                },
            }
            for build_number, audit in enumerate(audits, start=1)
        ]
        build_command, build_environment = make_command(
            Path("source"),
            Path("gnu-efi"),
        )
        provenance = {
            "schema": "refind-forest-loader-provenance",
            "version": 1,
            "inputs": [
                {
                    "name": item.name,
                    "filename": item.filename,
                    "url": item.url,
                    "sha256": item.sha256,
                }
                for item in PINNED_INPUTS
            ],
            "patch": {
                "path": _PATCH_PATH.relative_to(_PROJECT_ROOT).as_posix(),
                "sha256": _sha256_file(_PATCH_PATH),
            },
            "sbat": {
                "path": _SBAT_PATH.relative_to(_PROJECT_ROOT).as_posix(),
                "sha256": hashlib.sha256(expected_sbat).hexdigest(),
            },
            "build": {
                "command": build_command,
                "environment": build_environment,
            },
            "build_audits": build_audits,
            "canonical_build": 1,
            "sources": source_hashes,
            "objects": dict(first_audit["objects"]),
            "shared_object": {
                "path": "refind/refind_x64.so",
                "sha256": first_audit["shared_object"],
            },
            "efi": {
                "path": "refind_x64.efi",
                "sha256": efi_hash,
            },
            "final_sha256": efi_hash,
            "published": {
                "from_build": 1,
                "path": "refind_x64.efi",
                "sha256": efi_hash,
            },
            "tools": _tool_versions(),
        }

        staging = workspace / "staging"
        staging.mkdir(mode=0o700)
        staging_fd = os.open(
            staging,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            os.fchmod(staging_fd, 0o700)
            staging_metadata = os.fstat(staging_fd)
            if not stat.S_ISDIR(staging_metadata.st_mode):
                raise RuntimeError("build publication staging is not a directory")
            if stat.S_IMODE(staging_metadata.st_mode) != 0o700:
                raise RuntimeError("build publication staging mode is not 0700")
            publication_identity = (
                staging_metadata.st_dev,
                staging_metadata.st_ino,
            )
        finally:
            os.close(staging_fd)
        _require_build_directory_identity(staging, publication_identity)
        (staging / "refind_x64.efi").write_bytes(efi_outputs[0])
        serialized = json.dumps(
            provenance,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        ) + "\n"
        (staging / "provenance.json").write_text(serialized, encoding="ascii")

        pending_candidate = workspace.with_name(f"{workspace.name}.publish")
        if os.path.lexists(pending_candidate):
            raise ValueError(f"publish staging already exists: {pending_candidate}")
        try:
            staging.rename(pending_candidate)
        except BaseException as error:
            try:
                pending_identity = _existing_real_directory_identity(
                    pending_candidate
                )
            except RuntimeError as identity_error:
                raise identity_error from error
            if pending_identity is not None:
                if pending_identity != publication_identity:
                    raise RuntimeError(
                        "build publication directory identity mismatch at "
                        f"{pending_candidate}"
                    ) from error
                pending_output = pending_candidate
            raise
        _require_build_directory_identity(
            pending_candidate,
            publication_identity,
        )
        pending_output = pending_candidate
    except BaseException:
        try:
            temporary_workspace.cleanup()
        finally:
            if pending_output is not None and publication_identity is not None:
                _remove_build_directory(pending_output, publication_identity)
        raise

    try:
        temporary_workspace.cleanup()
    except BaseException:
        if pending_output is not None and publication_identity is not None:
            _remove_build_directory(pending_output, publication_identity)
        raise

    assert pending_output is not None
    assert publication_identity is not None
    _require_build_directory_identity(pending_output, publication_identity)
    if os.path.lexists(output):
        _remove_build_directory(pending_output, publication_identity)
        raise ValueError(f"output already exists: {output}")
    try:
        pending_output.rename(output)
    except BaseException as error:
        try:
            _recover_build_publication(
                (pending_output, output),
                publication_identity,
            )
        except RuntimeError as identity_error:
            raise identity_error from error
        raise
    _require_build_directory_identity(output, publication_identity)

    return output / "refind_x64.efi"

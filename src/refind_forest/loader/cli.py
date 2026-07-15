"""Command-line interface for the separately managed rEFInd loader."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import contextmanager
import ctypes
from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
from typing import Sequence

from .build import (
    _ALL_STORE_SITES,
    _OBJDUMP_COMMAND,
    _verify_local_store_semantics,
    build_loader,
)
from .deploy import (
    _read_regular,
    _write_file_exclusive,
    loader_status,
    promote_loader,
    rollback_loader,
    set_candidate_boot_next,
    stage_loader,
)
from .verify import (
    loaded_section_hashes,
    reject_setmem_call_edges,
    verify_pe,
    verify_signed,
)


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ESP = Path("/boot/efi")
DEFAULT_BACKUP_ROOT = Path("/var/lib/refind-forest/loader-backups")
DEFAULT_BUILD_OUTPUT = Path("build/refind-loader")
DEFAULT_BUILD_CACHE = Path(".cache/refind-loader")
SBAT_PATH = ROOT / "assets" / "loader" / "refind-forest-sbat.csv"
CERTIFICATE_PATH = Path("/etc/refind.d/keys/refind_local.crt")
PRIVATE_KEY_PATH = Path("/etc/refind.d/keys/refind_local.key")
SBSIGN = "/usr/bin/sbsign"
OBJDUMP = "/usr/bin/objdump"
_TRUSTED_TOOL_ENVIRONMENT = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
_RETAINED_ARTIFACT_NOTE = (
    "publication artifact retained for invoking-user removal: "
)
_RENAME_NOREPLACE = 1


def _under_root(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("loader mutation requires root privileges")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="refind-loader",
        description="Build and transactionally manage the patched rEFInd loader.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build and audit the loader")
    build.add_argument("--output", type=Path, default=DEFAULT_BUILD_OUTPUT)
    build.add_argument("--cache", type=Path, default=DEFAULT_BUILD_CACHE)

    verify = subparsers.add_parser("verify", help="verify a loader image")
    verify.add_argument("image", type=Path)

    sign = subparsers.add_parser("sign", help="sign a verified loader image")
    sign.add_argument("image", type=Path)
    sign.add_argument("--output", type=Path)

    stage = subparsers.add_parser("stage", help="stage an alternate loader slot")
    stage.add_argument("image", type=Path)
    stage.add_argument("--esp", type=Path, default=DEFAULT_ESP)
    stage.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)

    boot_next = subparsers.add_parser(
        "boot-next", help="select the candidate for one firmware boot"
    )
    boot_next.add_argument("transaction", type=Path, metavar="BACKUP_PATH")

    for command, help_text in (
        ("status", "report the live loader transaction state"),
        ("promote", "promote a successfully booted candidate"),
        ("rollback", "restore the recorded loader state"),
    ):
        operation = subparsers.add_parser(command, help=help_text)
        operation.add_argument("transaction", type=Path, metavar="BACKUP_PATH")
        operation.add_argument("--esp", type=Path, default=DEFAULT_ESP)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "build":
            loader = build_loader(_under_root(args.output), _under_root(args.cache))
            print(loader.resolve())
        elif args.command == "verify":
            image = _under_root(args.image)
            _verify_loader_image(image)
            print(f"Loader verification passed: {image.resolve()}")
        elif args.command == "sign":
            _require_root()
            signed = _sign_loader(
                _under_root(args.image),
                _under_root(args.output) if args.output is not None else None,
            )
            print(signed.resolve())
        elif args.command == "stage":
            _require_root()
            transaction = stage_loader(
                _under_root(args.image),
                args.esp,
                _under_root(args.backup_root),
            )
            print(transaction.resolve())
        elif args.command == "boot-next":
            _require_root()
            set_candidate_boot_next(_under_root(args.transaction))
            print("Candidate selected for the next boot only.")
        elif args.command == "status":
            status = loader_status(_under_root(args.transaction), args.esp)
            print(json.dumps(asdict(status), sort_keys=True))
        elif args.command == "promote":
            _require_root()
            promote_loader(_under_root(args.transaction), args.esp)
            print("Candidate loader promoted.")
        elif args.command == "rollback":
            _require_root()
            rollback_loader(_under_root(args.transaction), args.esp)
            print("Loader transaction rolled back.")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"refind-loader: {error}", file=sys.stderr)
        return 1
    return 0


def _verify_loader_image(path: Path) -> None:
    data, _ = _read_regular(Path(path), "loader image")
    with tempfile.TemporaryDirectory(prefix="refind-loader-verify-") as temporary:
        snapshot = Path(temporary) / "candidate.efi"
        _write_file_exclusive(snapshot, data)
        image = verify_pe(snapshot, SBAT_PATH.read_bytes())
        try:
            result = subprocess.run(
                [OBJDUMP, *_OBJDUMP_COMMAND[1:], str(snapshot)],
                check=False,
                capture_output=True,
                text=True,
                env=dict(_TRUSTED_TOOL_ENVIRONMENT),
            )
        except OSError as error:
            raise RuntimeError(f"failed to run objdump: {error}") from error
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(
                f"objdump failed with exit code {result.returncode}{suffix}"
            )
        reject_setmem_call_edges(result.stdout)
        _verify_local_store_semantics(
            result.stdout,
            _ALL_STORE_SITES,
            require_function_symbols=False,
        )
        if image.security_directory_size:
            certificate_source = Path(path).with_suffix(".crt")
            if not os.path.lexists(certificate_source):
                certificate_source = CERTIFICATE_PATH
            certificate_data = _approved_certificate_bytes(certificate_source)
            certificate_snapshot = Path(temporary) / "certificate.crt"
            _write_file_exclusive(certificate_snapshot, certificate_data)
            verify_signed(snapshot, certificate_snapshot)


def _sign_loader(image: Path, output: Path | None = None) -> Path:
    image = Path(image)
    destination = (
        image.with_name(f"{image.stem}.signed{image.suffix}")
        if output is None
        else Path(output)
    )
    public_certificate = destination.with_suffix(".crt")
    if public_certificate.name == destination.name:
        raise RuntimeError("signed loader and public certificate outputs must differ")
    credentials = _publication_credentials()

    with _open_publication_directory(
        destination.parent, credentials[0] if credentials is not None else os.geteuid()
    ) as (directory_fd, directory_identity):
        _require_publication_name_absent(
            directory_fd,
            destination.name,
            f"signed loader output already exists: {destination}",
        )
        _require_publication_name_absent(
            directory_fd,
            public_certificate.name,
            f"public certificate output already exists: {public_certificate}",
        )

        unsigned_data, _ = _read_regular(image, "unsigned loader image")
        with tempfile.TemporaryDirectory(prefix="refind-loader-sign-") as temporary:
            workspace = Path(temporary)
            unsigned = workspace / "unsigned.efi"
            signed = workspace / "signed.efi"
            certificate_snapshot = workspace / "certificate.crt"
            _write_file_exclusive(unsigned, unsigned_data)
            _verify_loader_image(unsigned)
            certificate_data = _root_certificate_bytes()
            _write_file_exclusive(certificate_snapshot, certificate_data)
            _run_sbsign(unsigned, signed, PRIVATE_KEY_PATH, certificate_snapshot)
            if loaded_section_hashes(unsigned) != loaded_section_hashes(signed):
                raise RuntimeError("loaded sections changed while signing the loader")
            verify_signed(signed, certificate_snapshot)
            signed_data, _ = _read_regular(signed, "signed loader image")

        _require_publication_directory_identity(
            destination.parent, directory_identity
        )
        _publish_signed_files(
            directory_fd,
            destination.parent,
            directory_identity,
            destination.name,
            signed_data,
            public_certificate.name,
            certificate_data,
            credentials,
        )
    return destination


def _publication_credentials() -> tuple[int, int] | None:
    if os.geteuid() != 0:
        return None
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid is None and sudo_gid is None:
        return None
    if sudo_uid is None or sudo_gid is None:
        raise RuntimeError("sudo publication identity is incomplete")
    try:
        uid = int(sudo_uid, 10)
        gid = int(sudo_gid, 10)
    except ValueError as error:
        raise RuntimeError("sudo publication identity is invalid") from error
    if uid < 0 or gid < 0:
        raise RuntimeError("sudo publication identity is invalid")
    return uid, gid


@contextmanager
def _open_publication_directory(
    path: Path, owner_uid: int
) -> Iterator[tuple[int, tuple[int, int]]]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RuntimeError(
                f"loader publication directory must not be a symbolic link: {path}"
            ) from error
        raise RuntimeError(
            f"unable to open loader publication directory: {path}"
        ) from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"loader publication path is not a directory: {path}")
        if metadata.st_uid != owner_uid:
            raise RuntimeError(
                f"loader publication directory has the wrong owner: {path}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeError(
                f"loader publication directory has unsafe permissions: {path}"
            )
        identity = metadata.st_dev, metadata.st_ino
        _require_publication_directory_identity(path, identity)
        yield descriptor, identity
    finally:
        os.close(descriptor)


def _publication_directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError(
            f"loader publication directory identity mismatch at {path}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(
            f"loader publication directory identity mismatch at {path}"
        )
    return metadata.st_dev, metadata.st_ino


def _require_publication_directory_identity(
    path: Path, expected: tuple[int, int]
) -> None:
    if _publication_directory_identity(path) != expected:
        raise RuntimeError(
            f"loader publication directory identity mismatch at {path}"
        )


def _entry_identity_at(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return metadata.st_dev, metadata.st_ino


def _require_publication_name_absent(
    directory_fd: int, name: str, message: str
) -> None:
    if _entry_identity_at(directory_fd, name) is not None:
        raise RuntimeError(message)


def _quarantine_owned_entry(
    directory_fd: int,
    directory_path: Path,
    name: str,
    expected: tuple[int, int],
) -> Path | None:
    if _entry_identity_at(directory_fd, name) != expected:
        return None
    quarantine_name = f".refind-loader-retained-{secrets.token_hex(16)}"
    os.mkdir(quarantine_name, mode=0o700, dir_fd=directory_fd)
    quarantine_identity = _entry_identity_at(directory_fd, quarantine_name)
    if quarantine_identity is None:
        raise RuntimeError("loader publication cleanup quarantine is unavailable")
    quarantine_fd = os.open(
        quarantine_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    retained_path = directory_path / quarantine_name / name
    retained_owned = False
    try:
        os.fchmod(quarantine_fd, 0o700)
        quarantine_metadata = os.fstat(quarantine_fd)
        if (
            not stat.S_ISDIR(quarantine_metadata.st_mode)
            or (quarantine_metadata.st_dev, quarantine_metadata.st_ino)
            != quarantine_identity
            or stat.S_IMODE(quarantine_metadata.st_mode) != 0o700
            or _entry_identity_at(directory_fd, quarantine_name)
            != quarantine_identity
        ):
            raise RuntimeError(
                "loader publication cleanup quarantine identity mismatch"
            )
        try:
            _rename_noreplace(directory_fd, name, quarantine_fd, name)
        except FileExistsError as error:
            collision = RuntimeError(
                f"loader publication retention destination collision: {name}"
            )
            _record_retained_artifact(collision, directory_path / name)
            collision.add_note(
                "foreign publication entry retained for inspection: "
                f"{retained_path}"
            )
            raise collision from error
        if _entry_identity_at(quarantine_fd, name) != expected:
            _raise_preserved_cleanup_entry(name, retained_path)
        retained_owned = True

        isolated_fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=quarantine_fd,
        )
        try:
            isolated = os.fstat(isolated_fd)
            if (
                not stat.S_ISREG(isolated.st_mode)
                or (isolated.st_dev, isolated.st_ino) != expected
            ):
                _raise_preserved_cleanup_entry(name, retained_path)
            os.fchmod(isolated_fd, 0o644)
            if (
                _entry_identity_at(quarantine_fd, name) != expected
                or _entry_identity_at(directory_fd, quarantine_name)
                != quarantine_identity
            ):
                _raise_preserved_cleanup_entry(name, retained_path)
            os.fsync(isolated_fd)
        finally:
            os.close(isolated_fd)
        os.fsync(quarantine_fd)
        os.fsync(directory_fd)
        return retained_path
    except BaseException as error:
        if retained_owned:
            _record_retained_artifact(error, retained_path)
        raise
    finally:
        os.close(quarantine_fd)


def _rename_noreplace(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise RuntimeError("renameat2 is required for safe loader retention") from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        source_fd,
        os.fsencode(source_name),
        destination_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), source_name)


def _raise_preserved_cleanup_entry(name: str, retained_path: Path) -> None:
    error = RuntimeError(f"foreign publication entry preserved: {name}")
    error.add_note(
        "ambiguous publication entries retained for invoking-user inspection: "
        f"{retained_path.parent}"
    )
    raise error


def _record_retained_artifact(error: BaseException, path: Path) -> None:
    error.add_note(f"{_RETAINED_ARTIFACT_NOTE}{path}")


def _write_public_entry(
    directory_fd: int, directory_path: Path, name: str, data: bytes
) -> tuple[int, int]:
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o644,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"published loader artifact is not regular: {name}")
        identity = metadata.st_dev, metadata.st_ino
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w+b") as output:
            descriptor = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            output.seek(0)
            if output.read() != data:
                raise RuntimeError(
                    f"published loader artifact read-back mismatch: {name}"
                )
        if _entry_identity_at(directory_fd, name) != identity:
            raise RuntimeError(f"published loader artifact identity mismatch: {name}")
        return identity
    except BaseException as error:
        if descriptor is not None:
            os.close(descriptor)
        if identity is not None:
            try:
                retained = _quarantine_owned_entry(
                    directory_fd, directory_path, name, identity
                )
            except BaseException as quarantine_error:
                error.add_note(
                    f"unable to quarantine owned publication entry {name}: "
                    f"{quarantine_error}"
                )
                for note in getattr(quarantine_error, "__notes__", ()):
                    error.add_note(note)
            else:
                if retained is not None:
                    _record_retained_artifact(error, retained)
        raise


def _publish_signed_files_in_process(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    destination_name: str,
    signed_data: bytes,
    certificate_name: str,
    certificate_data: bytes,
) -> None:
    created: list[tuple[str, tuple[int, int]]] = []
    try:
        _require_publication_directory_identity(
            directory_path, directory_identity
        )
        certificate_identity = _write_public_entry(
            directory_fd, directory_path, certificate_name, certificate_data
        )
        created.append((certificate_name, certificate_identity))
        _require_publication_directory_identity(
            directory_path, directory_identity
        )
        destination_identity = _write_public_entry(
            directory_fd, directory_path, destination_name, signed_data
        )
        created.append((destination_name, destination_identity))
        _require_publication_directory_identity(
            directory_path, directory_identity
        )
        for name, identity in created:
            if _entry_identity_at(directory_fd, name) != identity:
                raise RuntimeError(
                    f"published loader artifact identity mismatch: {name}"
                )
        os.fsync(directory_fd)
    except BaseException as error:
        for name, identity in reversed(created):
            try:
                retained = _quarantine_owned_entry(
                    directory_fd, directory_path, name, identity
                )
            except BaseException as quarantine_error:
                error.add_note(
                    f"unable to quarantine owned publication entry {name}: "
                    f"{quarantine_error}"
                )
                for note in getattr(quarantine_error, "__notes__", ()):
                    error.add_note(note)
            else:
                if retained is not None:
                    _record_retained_artifact(error, retained)
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        raise


def _drop_publication_privileges(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresgid() != (gid, gid, gid) or os.getresuid() != (uid, uid, uid):
        raise RuntimeError("unable to drop loader publication privileges")
    os.umask(0o077)


def _fork_publication(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    destination_name: str,
    signed_data: bytes,
    certificate_name: str,
    certificate_data: bytes,
    credentials: tuple[int, int],
) -> None:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    process = os.fork()
    if process == 0:
        os.close(read_fd)
        try:
            _drop_publication_privileges(*credentials)
            _publish_signed_files_in_process(
                directory_fd,
                directory_path,
                directory_identity,
                destination_name,
                signed_data,
                certificate_name,
                certificate_data,
            )
        except BaseException as error:
            notes = "\n".join(getattr(error, "__notes__", ()))
            detail = f"{type(error).__name__}: {error}"
            if notes:
                detail = f"{detail}\n{notes}"
            payload = detail.encode("ascii", errors="backslashreplace")
            frame = len(payload).to_bytes(8, "big") + payload
            try:
                _write_all(write_fd, frame)
            finally:
                os._exit(1)
        os._exit(0)

    os.close(write_fd)
    try:
        chunks: list[bytes] = []
        while chunk := os.read(read_fd, 4096):
            chunks.append(chunk)
    finally:
        os.close(read_fd)
    waited, status = os.waitpid(process, 0)
    if waited != process or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        frame = b"".join(chunks)
        detail = (
            _decode_publication_error_frame(frame)
            if frame
            else "unknown failure"
        )
        raise RuntimeError(f"unprivileged loader publication failed: {detail}")


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "publication error relay made no progress")
        remaining = remaining[written:]


def _decode_publication_error_frame(frame: bytes) -> str:
    if len(frame) < 8:
        raise RuntimeError("incomplete publication error relay header")
    payload_size = int.from_bytes(frame[:8], "big")
    payload = frame[8:]
    if len(payload) != payload_size:
        raise RuntimeError(
            "incomplete publication error relay payload: "
            f"expected {payload_size} bytes, received {len(payload)}"
        )
    return payload.decode("ascii", errors="replace")


def _publish_signed_files(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    destination_name: str,
    signed_data: bytes,
    certificate_name: str,
    certificate_data: bytes,
    credentials: tuple[int, int] | None,
) -> None:
    arguments = (
        directory_fd,
        directory_path,
        directory_identity,
        destination_name,
        signed_data,
        certificate_name,
        certificate_data,
    )
    if credentials is not None and credentials != (0, 0):
        _fork_publication(*arguments, credentials)
        return
    _publish_signed_files_in_process(*arguments)


def _approved_certificate_bytes(path: Path) -> bytes:
    data, _ = _read_regular(Path(path), "loader verification certificate")
    if data != _root_certificate_bytes():
        raise RuntimeError(
            "loader verification certificate does not match local trust certificate"
        )
    return data


def _root_certificate_bytes() -> bytes:
    with _open_root_owned_regular(
        CERTIFICATE_PATH, "signing certificate", private=False
    ) as descriptor:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    data = b"".join(chunks)
    if before_identity != after_identity or len(data) != before.st_size:
        raise RuntimeError("signing certificate changed while it was read")
    return data


@contextmanager
def _open_root_owned_regular(
    path: Path,
    description: str,
    *,
    private: bool,
) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{description} is not a regular file: {path}")
        if metadata.st_uid != 0:
            raise RuntimeError(f"{description} is not owned by root: {path}")
        forbidden = 0o077 if private else 0o022
        if metadata.st_mode & forbidden:
            raise RuntimeError(f"{description} has unsafe permissions: {path}")
        yield descriptor
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RuntimeError(
                f"{description} must not be a symbolic link: {path}"
            ) from error
        raise RuntimeError(f"unable to open {description}: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _run_sbsign(
    unsigned: Path,
    signed: Path,
    key: Path,
    certificate: Path,
) -> None:
    with (
        _open_root_owned_regular(key, "private signing key", private=True) as key_fd,
        _open_root_owned_regular(
            certificate, "signing certificate", private=False
        ) as certificate_fd,
    ):
        command = [
            SBSIGN,
            "--key",
            f"/proc/self/fd/{key_fd}",
            "--cert",
            f"/proc/self/fd/{certificate_fd}",
            "--output",
            str(signed),
            str(unsigned),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                pass_fds=(key_fd, certificate_fd),
                env=dict(_TRUSTED_TOOL_ENVIRONMENT),
            )
        except OSError as error:
            raise RuntimeError(f"failed to run sbsign: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"sbsign failed with exit code {result.returncode}{suffix}"
        )
    _read_regular(signed, "sbsign output")

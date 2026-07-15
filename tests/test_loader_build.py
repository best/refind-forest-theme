from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import refind_forest.loader.build as loader_build
except ModuleNotFoundError:
    loader_build = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PATCH_PATH = PROJECT_ROOT / "patches" / "refind-0.14.2-gnu-efi-abi.patch"
SBAT_PATH = PROJECT_ROOT / "assets" / "loader" / "refind-forest-sbat.csv"

EXPECTED_REMOVED_LINES = [
    "            SetMem(GlobalConfig.ShowTools, NUM_TOOLS * sizeof(UINTN), 0);",
    "        SetMem(&(Volume->VolUuid), sizeof(EFI_GUID), 0);",
    "        SetMem(SectorBuffer, MBR_BOOTCODE_SIZE, 0);",
    "  SetMem (DeviceTypeIndex, sizeof (DeviceTypeIndex), 0xFF);",
    "    SetMem(s, c, n);",
    "#define memset(b, c, v) MyMemSet(b, v, c)",
    "\t\t       --adjust-section-vma .sbat+10000000 $@",
]

EXPECTED_PATCH_ADDITIONS = {
    "EfiLib/gnuefi-helper.c": (
        "#ifndef _GNU_EFI_4_0",
        "#endif",
    ),
    "refind/config.c": (
        "volatile UINTN *ShowTools = GlobalConfig.ShowTools;",
        "for (i = 0; i < NUM_TOOLS; i++)",
        "ShowTools[i] = 0;",
    ),
    "refind/lib.c": (
        "volatile UINT8 *VolUuid = (volatile UINT8 *) &(Volume->VolUuid);",
        "for (i = 0; i < sizeof(EFI_GUID); i++)",
        "VolUuid[i] = 0;",
    ),
    "refind/launch_legacy.c": (
        "volatile UINT8 *BootCode = (volatile UINT8 *) SectorBuffer;",
        "for (i = 0; i < MBR_BOOTCODE_SIZE; i++)",
        "BootCode[i] = 0;",
    ),
    "EfiLib/legacy.c": (
        "volatile UINTN           *DeviceTypeIndexWriter = DeviceTypeIndex;",
        "for (DeviceIndex = 0; DeviceIndex < "
        "sizeof (DeviceTypeIndex) / sizeof (DeviceTypeIndex[0]); "
        "DeviceIndex++) {",
        "DeviceTypeIndexWriter[DeviceIndex] = ~(UINTN)0;",
    ),
    "libeg/lodepng_xtra.c": (
        "volatile UINT8 *Bytes = (volatile UINT8 *) s;",
        "for (i = 0; i < n; i++)",
        "Bytes[i] = (UINT8) c;",
    ),
    "libeg/nanojpeg.c": (
        "#define memset(b, c, v) MyMemSet(b, c, v)",
    ),
    "refind/Makefile": (
        "--adjust-section-vma .sbat+0x1000000 $@",
    ),
}

EXPECTED_SBAT = (
    "sbat,1,SBAT Version,sbat,1,"
    "https://github.com/rhboot/shim/blob/main/SBAT.md\n"
    "refind,1,Roderick W. Smith,refind,0.14.2,"
    "https://www.rodsbooks.com/refind\n"
    "refind.forest,1,Local Forest build,refind-forest,"
    "0.14.2-abi1,https://www.rodsbooks.com/refind\n"
)

HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)

EXPECTED_CFLAGS = (
    "CFLAGS=-Os -fno-strict-aliasing -fno-tree-loop-distribute-patterns "
    "-fno-stack-protector -fshort-wchar -Wall -DGNU_EFI_3_0_COMPAT"
)


def _write_patch_preimage(patch: str, root: Path) -> None:
    lines = patch.splitlines()
    path: Path | None = None
    file_lines: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("--- a/"):
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(file_lines) + "\n", encoding="ascii")
            path = root / line.removeprefix("--- a/")
            file_lines = []
            index += 2
            continue

        match = HUNK_HEADER.match(line)
        if match is None:
            index += 1
            continue
        if path is None:
            raise AssertionError("patch hunk appears before a file header")

        old_start = int(match.group(1))
        old_count = int(match.group(2) or "1")
        new_count = int(match.group(4) or "1")
        old_lines: list[str] = []
        old_seen = 0
        new_seen = 0
        index += 1
        while old_seen < old_count or new_seen < new_count:
            diff_line = lines[index]
            if diff_line.startswith(" "):
                old_lines.append(diff_line[1:])
                old_seen += 1
                new_seen += 1
            elif diff_line.startswith("-"):
                old_lines.append(diff_line[1:])
                old_seen += 1
            elif diff_line.startswith("+"):
                new_seen += 1
            elif diff_line == "":
                old_lines.append("")
                old_seen += 1
                new_seen += 1
            else:
                raise AssertionError(f"invalid unified diff line: {diff_line!r}")
            index += 1

        self_line = len(file_lines) + 1
        if self_line > old_start:
            raise AssertionError("overlapping patch hunks in fixture")
        file_lines.extend(
            f"fixture line {line_number}"
            for line_number in range(self_line, old_start)
        )
        file_lines.extend(old_lines)

    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(file_lines) + "\n", encoding="ascii")


class LoaderBuildCommandTests(unittest.TestCase):
    def test_make_command_is_non_installing_and_reproducible(self) -> None:
        self.assertIsNotNone(loader_build, "loader build module is missing")

        command, environment = loader_build.make_command(
            Path("/work/refind-0.14.2"),
            Path("/work/gnu-efi"),
        )

        self.assertEqual(
            command,
            [
                "make",
                "-C",
                "/work/refind-0.14.2",
                "gnuefi",
                "ARCH=x86_64",
                "EFIINC=/work/gnu-efi/usr/include/efi",
                "GNUEFILIB=/work/gnu-efi/usr/lib",
                "EFILIB=/work/gnu-efi/usr/lib",
                "EFICRT0=/work/gnu-efi/usr/lib",
                "REFIND_SBAT_CSV=refind-forest-sbat.csv",
                "FORMAT=--output-target=efi-app-x86_64",
                EXPECTED_CFLAGS,
            ],
        )
        self.assertNotIn("install", " ".join(command).lower())
        self.assertEqual(
            environment,
            {
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "SOURCE_DATE_EPOCH": "1738518142",
                "TZ": "UTC",
            },
        )

    def test_make_command_does_not_inherit_build_flags(self) -> None:
        self.assertIsNotNone(loader_build, "loader build module is missing")
        inherited = {
            "MAKEFLAGS": "--eval=malicious",
            "CFLAGS": "-DUNTRUSTED",
            "LDFLAGS": "-L/untrusted",
            "CC": "/untrusted/cc",
            "LD": "/untrusted/ld",
        }

        with mock.patch.dict(os.environ, inherited, clear=False):
            _command, environment = loader_build.make_command(Path("source"))

        self.assertTrue(inherited.keys().isdisjoint(environment))

    def test_tool_versions_use_exact_commands_environment_and_first_lines(
        self,
    ) -> None:
        commands = [
            ("make", ["make", "--version"]),
            ("gcc", ["gcc", "--version"]),
            ("ld", ["ld", "--version"]),
            ("objcopy", ["objcopy", "--version"]),
            ("nm", ["nm", "--version"]),
            ("objdump", ["objdump", "--version"]),
            ("patch", ["patch", "--version"]),
            ("tar", ["tar", "--version"]),
            ("dpkg-deb", ["dpkg-deb", "--version"]),
        ]
        results = [
            subprocess.CompletedProcess(
                command,
                0,
                stdout=f"  {name} version  \nignored details\n",
                stderr="",
            )
            for name, command in commands
        ]

        with mock.patch.object(
            loader_build.subprocess,
            "run",
            side_effect=results,
        ) as run, mock.patch.object(
            loader_build.platform,
            "python_version",
            return_value="3.14.0",
        ):
            versions = loader_build._tool_versions()

        self.assertEqual(
            versions,
            {
                "python": "Python 3.14.0",
                **{name: f"{name} version" for name, _command in commands},
            },
        )
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    env={
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "SOURCE_DATE_EPOCH": "1738518142",
                        "TZ": "UTC",
                    },
                )
                for _name, command in commands
            ],
        )

    def test_tool_versions_reject_empty_output(self) -> None:
        for output in ("", " \n\t\n"):
            with self.subTest(output=output), mock.patch.object(
                loader_build,
                "_run_tool",
                return_value=output,
            ) as run, self.assertRaisesRegex(
                RuntimeError,
                "make did not report a version",
            ):
                loader_build._tool_versions()
            run.assert_called_once_with(["make", "--version"])

    def test_tool_versions_reject_non_ascii_output(self) -> None:
        with mock.patch.object(
            loader_build,
            "_run_tool",
            return_value="version caf\N{LATIN SMALL LETTER E WITH ACUTE}\n",
        ), self.assertRaisesRegex(
            RuntimeError,
            "make reported a non-ASCII version",
        ):
            loader_build._tool_versions()


class _FakeResponse:
    def __init__(self, chunks: list[bytes], final_url: str) -> None:
        self.chunks = list(chunks)
        self.final_url = final_url
        self.read_sizes: list[int] = []

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.chunks.pop(0) if self.chunks else b""


class LoaderAcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "PinnedInput"))
        self.assertTrue(hasattr(loader_build, "_acquire_inputs"))
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.cache = Path(self.temporary_directory.name) / "cache"
        self.url = "https://archive.ubuntu.com/ubuntu/pool/test/input.tar"
        self.good_bytes = b"first chunk" + b"second chunk"
        self.input = loader_build.PinnedInput(
            "test",
            "input.tar",
            self.url,
            hashlib.sha256(self.good_bytes).hexdigest(),
        )

    def _pinned_input(self) -> mock._patch:
        return mock.patch.object(loader_build, "PINNED_INPUTS", (self.input,))

    def test_pins_the_three_approved_inputs(self) -> None:
        self.assertEqual(
            [
                (item.name, item.filename, item.url, item.sha256)
                for item in loader_build.PINNED_INPUTS
            ],
            [
                (
                    "refind_source",
                    "refind_0.14.2.orig.tar.gz",
                    "https://archive.ubuntu.com/ubuntu/pool/universe/r/refind/"
                    "refind_0.14.2.orig.tar.gz",
                    "f7d93ce80da76b86c567281ea225b6a87907ce86ff77233c9357a522c115c8f0",
                ),
                (
                    "refind_debian_delta",
                    "refind_0.14.2-2.1.debian.tar.xz",
                    "https://archive.ubuntu.com/ubuntu/pool/universe/r/refind/"
                    "refind_0.14.2-2.1.debian.tar.xz",
                    "8304bae605542651d129eb6711e248956291ec3fd0e2a6c48ccafc415d91f900",
                ),
                (
                    "gnu_efi",
                    "gnu-efi_4.0.0-1_amd64.deb",
                    "https://archive.ubuntu.com/ubuntu/pool/main/g/gnu-efi/"
                    "gnu-efi_4.0.0-1_amd64.deb",
                    "7e00d02cc6cba79d8f99984c3554df42d808ee51c73699e2776a3e86a0c1d038",
                ),
            ],
        )

    @mock.patch("refind_forest.loader.build.urlopen")
    def test_revalidates_and_reuses_a_good_cache_entry(
        self, urlopen: mock.Mock
    ) -> None:
        self.cache.mkdir()
        cached = self.cache / self.input.filename
        cached.write_bytes(self.good_bytes)

        with self._pinned_input():
            acquired = loader_build._acquire_inputs(self.cache)

        self.assertEqual(acquired, {"test": cached})
        urlopen.assert_not_called()

    @mock.patch("refind_forest.loader.build.urlopen")
    def test_rejects_symlink_and_nonregular_cache_entries(
        self, urlopen: mock.Mock
    ) -> None:
        self.cache.mkdir()
        target = self.cache / "target"
        target.write_bytes(self.good_bytes)
        cache_entry = self.cache / self.input.filename

        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind):
                if cache_entry.is_symlink():
                    cache_entry.unlink()
                elif cache_entry.exists():
                    cache_entry.rmdir()
                if kind == "symlink":
                    cache_entry.symlink_to(target)
                else:
                    cache_entry.mkdir()

                with self._pinned_input(), self.assertRaisesRegex(
                    ValueError, "regular file"
                ):
                    loader_build._acquire_inputs(self.cache)

        urlopen.assert_not_called()

    @mock.patch("refind_forest.loader.build.urlopen")
    def test_redownloads_corrupt_cache_with_streaming_atomic_replace(
        self, urlopen: mock.Mock
    ) -> None:
        self.cache.mkdir()
        cached = self.cache / self.input.filename
        cached.write_bytes(b"corrupt")
        response = _FakeResponse(
            [b"first chunk", b"second chunk"],
            self.url,
        )
        urlopen.return_value = response

        with self._pinned_input(), mock.patch.object(
            os, "replace", wraps=os.replace
        ) as replace:
            acquired = loader_build._acquire_inputs(self.cache)

        self.assertEqual(acquired, {"test": cached})
        self.assertEqual(cached.read_bytes(), self.good_bytes)
        urlopen.assert_called_once_with(self.url, timeout=30)
        self.assertGreaterEqual(len(response.read_sizes), 3)
        temporary, destination = replace.call_args.args
        self.assertEqual(Path(temporary).parent, self.cache)
        self.assertEqual(Path(destination), cached)

    @mock.patch("refind_forest.loader.build.urlopen")
    def test_bad_download_preserves_existing_cache_and_removes_temporary_file(
        self, urlopen: mock.Mock
    ) -> None:
        self.cache.mkdir()
        cached = self.cache / self.input.filename
        cached.write_bytes(b"corrupt")
        urlopen.return_value = _FakeResponse([b"still wrong"], self.url)

        with self._pinned_input(), self.assertRaisesRegex(
            RuntimeError, "SHA-256"
        ):
            loader_build._acquire_inputs(self.cache)

        self.assertEqual(cached.read_bytes(), b"corrupt")
        self.assertEqual(sorted(self.cache.iterdir()), [cached])

    @mock.patch("refind_forest.loader.build.urlopen")
    def test_rejects_redirect_before_publishing_download(
        self, urlopen: mock.Mock
    ) -> None:
        urlopen.return_value = _FakeResponse(
            [self.good_bytes],
            "https://mirror.invalid/unapproved",
        )

        with self._pinned_input(), self.assertRaisesRegex(
            RuntimeError, "redirect"
        ):
            loader_build._acquire_inputs(self.cache)

        self.assertEqual(list(self.cache.iterdir()), [])


class LoaderInputSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "_snapshot_inputs"))
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.cache_entry = self.root / "input.tar"
        self.original_bytes = b"verified input bytes"
        self.cache_entry.write_bytes(self.original_bytes)
        self.input = loader_build.PinnedInput(
            "test",
            self.cache_entry.name,
            "https://archive.ubuntu.com/ubuntu/input.tar",
            hashlib.sha256(self.original_bytes).hexdigest(),
        )

    def test_snapshot_reads_verified_bytes_from_the_originally_opened_fd(self) -> None:
        replacement = self.root / "replacement"
        replacement_bytes = b"unverified replacement bytes"
        replacement.write_bytes(replacement_bytes)
        real_open = os.open
        source_descriptors: list[int] = []

        def open_then_replace(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path) == self.cache_entry:
                source_descriptors.append(descriptor)
                os.replace(replacement, self.cache_entry)
            return descriptor

        snapshots_root = self.root / "snapshots"
        with mock.patch.object(loader_build, "PINNED_INPUTS", (self.input,)), mock.patch.object(
            loader_build.os,
            "open",
            side_effect=open_then_replace,
        ):
            snapshots = loader_build._snapshot_inputs(
                {self.input.name: self.cache_entry},
                snapshots_root,
            )

        self.assertEqual(self.cache_entry.read_bytes(), replacement_bytes)
        self.assertEqual(snapshots[self.input.name].read_bytes(), self.original_bytes)
        self.assertEqual(len(source_descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(source_descriptors[0])

    def test_snapshot_rejects_nonregular_source_and_closes_descriptor(self) -> None:
        self.cache_entry.unlink()
        self.cache_entry.mkdir()
        real_open = os.open
        source_descriptors: list[int] = []

        def tracking_open(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path) == self.cache_entry:
                source_descriptors.append(descriptor)
            return descriptor

        snapshots_root = self.root / "nonregular-snapshots"
        with mock.patch.object(
            loader_build,
            "PINNED_INPUTS",
            (self.input,),
        ), mock.patch.object(
            loader_build.os,
            "open",
            side_effect=tracking_open,
        ), self.assertRaisesRegex(ValueError, "not a regular file"):
            loader_build._snapshot_inputs(
                {self.input.name: self.cache_entry},
                snapshots_root,
            )

        self.assertEqual(list(snapshots_root.iterdir()), [])
        self.assertEqual(len(source_descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(source_descriptors[0])

    def test_snapshot_read_failure_closes_descriptors_and_removes_partial_file(
        self,
    ) -> None:
        real_open = os.open
        opened_descriptors: list[int] = []
        source_descriptor: int | None = None

        def tracking_open(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal source_descriptor
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened_descriptors.append(descriptor)
            if Path(path) == self.cache_entry:
                source_descriptor = descriptor
            return descriptor

        real_read = os.read

        def fail_source_read(descriptor: int, size: int) -> bytes:
            if descriptor == source_descriptor:
                raise OSError("injected snapshot read failure")
            return real_read(descriptor, size)

        snapshots_root = self.root / "read-failure-snapshots"
        with mock.patch.object(
            loader_build,
            "PINNED_INPUTS",
            (self.input,),
        ), mock.patch.object(
            loader_build.os,
            "open",
            side_effect=tracking_open,
        ), mock.patch.object(
            loader_build.os,
            "read",
            side_effect=fail_source_read,
        ), self.assertRaisesRegex(OSError, "snapshot read failure"):
            loader_build._snapshot_inputs(
                {self.input.name: self.cache_entry},
                snapshots_root,
            )

        self.assertEqual(list(snapshots_root.iterdir()), [])
        self.assertEqual(len(opened_descriptors), 2)
        for descriptor in opened_descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_snapshot_write_failure_closes_descriptors_and_removes_partial_file(
        self,
    ) -> None:
        real_open = os.open
        real_fdopen = os.fdopen
        opened_descriptors: list[int] = []

        def tracking_open(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened_descriptors.append(descriptor)
            return descriptor

        class FailingWriter:
            def __init__(self, descriptor: int, mode: str) -> None:
                self.file = real_fdopen(descriptor, mode)

            def __enter__(self) -> FailingWriter:
                return self

            def __exit__(self, *args: object) -> None:
                self.file.close()

            def write(self, data: bytes) -> int:
                self.file.write(data[:1])
                raise OSError("injected snapshot write failure")

            def flush(self) -> None:
                self.file.flush()

            def fileno(self) -> int:
                return self.file.fileno()

        snapshots_root = self.root / "write-failure-snapshots"
        with mock.patch.object(
            loader_build,
            "PINNED_INPUTS",
            (self.input,),
        ), mock.patch.object(
            loader_build.os,
            "open",
            side_effect=tracking_open,
        ), mock.patch.object(
            loader_build.os,
            "fdopen",
            side_effect=FailingWriter,
        ), self.assertRaisesRegex(OSError, "snapshot write failure"):
            loader_build._snapshot_inputs(
                {self.input.name: self.cache_entry},
                snapshots_root,
            )

        self.assertEqual(list(snapshots_root.iterdir()), [])
        self.assertEqual(len(opened_descriptors), 2)
        for descriptor in opened_descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)


def _write_tar(path: Path, members: list[tarfile.TarInfo]) -> None:
    with tarfile.open(path, "w") as archive:
        for member in members:
            payload = b"fixture" if member.isreg() else b""
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload) if payload else None)


class LoaderExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "_extract_tar"))
        self.assertTrue(hasattr(loader_build, "_extract_deb"))
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_tar_preflight_rejects_unsafe_members_before_extraction(
        self, run: mock.Mock
    ) -> None:
        cases: dict[str, tarfile.TarInfo] = {}
        cases["absolute path"] = tarfile.TarInfo("/escape")
        cases["parent traversal"] = tarfile.TarInfo("../escape")

        device = tarfile.TarInfo("refind-0.14.2/device")
        device.type = tarfile.CHRTYPE
        cases["device"] = device

        symlink = tarfile.TarInfo("refind-0.14.2/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../escape"
        cases["escaping symlink"] = symlink

        hardlink = tarfile.TarInfo("refind-0.14.2/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "../../escape"
        cases["escaping hardlink"] = hardlink

        for index, (name, member) in enumerate(cases.items()):
            with self.subTest(name=name):
                archive = self.root / f"unsafe-{index}.tar"
                _write_tar(archive, [member])
                destination = self.root / f"destination-{index}"

                with self.assertRaisesRegex(ValueError, "unsafe|device|link"):
                    loader_build._extract_tar(archive, destination)

                self.assertFalse(destination.exists())
        run.assert_not_called()

    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_tar_extracts_only_to_a_new_directory(self, run: mock.Mock) -> None:
        archive = self.root / "source.tar"
        member = tarfile.TarInfo("refind-0.14.2/README.txt")
        _write_tar(archive, [member])
        destination = self.root / "source"

        loader_build._extract_tar(archive, destination)

        self.assertTrue(destination.is_dir())
        run.assert_called_once_with(
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
            env={
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "SOURCE_DATE_EPOCH": "1738518142",
                "TZ": "UTC",
            },
        )

        with self.assertRaisesRegex(ValueError, "already exists"):
            loader_build._extract_tar(archive, destination)
        self.assertEqual(run.call_count, 1)

    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_dpkg_deb_extracts_only_to_a_new_directory(
        self, run: mock.Mock
    ) -> None:
        archive = self.root / "gnu-efi.deb"
        archive.write_bytes(b"fixture deb")
        destination = self.root / "gnu-efi"

        loader_build._extract_deb(archive, destination)

        self.assertTrue(destination.is_dir())
        run.assert_called_once_with(
            ["dpkg-deb", "--extract", str(archive), str(destination)],
            check=True,
            capture_output=True,
            text=True,
            env={
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "SOURCE_DATE_EPOCH": "1738518142",
                "TZ": "UTC",
            },
        )

        with self.assertRaisesRegex(ValueError, "already exists"):
            loader_build._extract_deb(archive, destination)
        self.assertEqual(run.call_count, 1)


def _write_valid_debian_delta(root: Path) -> Path:
    debian = root / "debian"
    patches = debian / "patches"
    patches.mkdir(parents=True)
    (patches / "series").write_text("", encoding="ascii")
    (debian / "changelog").write_text(
        "refind (0.14.2-2.1) unstable; urgency=medium\n"
        "\n"
        "  * Test fixture.\n"
        "\n"
        " -- Helge Kreutzmann <debian@example.invalid>  "
        "Sun, 02 Feb 2025 18:42:22 +0100\n",
        encoding="ascii",
    )
    return debian


class LoaderSourcePreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in (
            "_source_root",
            "_validate_debian_delta",
            "_prepare_source",
            "_verify_source",
        ):
            self.assertTrue(hasattr(loader_build, name), f"missing {name}")
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def test_requires_the_exact_refind_source_root(self) -> None:
        container = self.root / "container"
        source = container / "refind-0.14.2"
        source.mkdir(parents=True)

        self.assertEqual(loader_build._source_root(container), source)

        (container / "unexpected").mkdir()
        with self.assertRaisesRegex(ValueError, "exactly refind-0.14.2"):
            loader_build._source_root(container)

    def test_validates_debian_version_epoch_and_empty_patch_series(self) -> None:
        delta = self.root / "delta"
        debian = _write_valid_debian_delta(delta)

        loader_build._validate_debian_delta(delta)

        invalid_values = {
            "version": "refind (0.14.2-2) unstable; urgency=medium",
            "epoch": "Mon, 03 Feb 2025 18:42:22 +0100",
            "series": "unexpected.patch\n",
        }
        for name, value in invalid_values.items():
            with self.subTest(name=name):
                if name == "version":
                    changelog = (debian / "changelog").read_text(encoding="ascii")
                    (debian / "changelog").write_text(
                        changelog.replace(
                            "refind (0.14.2-2.1) unstable; urgency=medium",
                            value,
                        ),
                        encoding="ascii",
                    )
                elif name == "epoch":
                    changelog = (debian / "changelog").read_text(encoding="ascii")
                    (debian / "changelog").write_text(
                        changelog.replace(
                            "Sun, 02 Feb 2025 18:42:22 +0100",
                            value,
                        ),
                        encoding="ascii",
                    )
                else:
                    (debian / "patches" / "series").write_text(
                        value, encoding="ascii"
                    )

                with self.assertRaisesRegex(ValueError, "Debian"):
                    loader_build._validate_debian_delta(delta)
                shutil.rmtree(delta)
                debian = _write_valid_debian_delta(delta)

    @mock.patch("refind_forest.loader.build.subprocess.run", wraps=subprocess.run)
    def test_prepares_independent_patched_source_with_custom_sbat(
        self, run: mock.Mock
    ) -> None:
        base = self.root / "base"
        _write_patch_preimage(PATCH_PATH.read_text(encoding="ascii"), base)
        delta = self.root / "delta"
        _write_valid_debian_delta(delta)
        destination = self.root / "prepared"

        prepared = loader_build._prepare_source(base, delta, destination)

        self.assertEqual(prepared, destination)
        self.assertTrue(destination.is_dir())
        self.assertIn(
            "SetMem(GlobalConfig.ShowTools",
            (base / "refind" / "config.c").read_text(encoding="ascii"),
        )
        self.assertNotIn(
            "SetMem(GlobalConfig.ShowTools",
            (destination / "refind" / "config.c").read_text(encoding="ascii"),
        )
        self.assertEqual(
            (destination / "refind-forest-sbat.csv").read_bytes(),
            SBAT_PATH.read_bytes(),
        )
        self.assertEqual(
            (destination / "debian" / "changelog").read_bytes(),
            (delta / "debian" / "changelog").read_bytes(),
        )
        self.assertEqual(list(destination.rglob("*.rej")), [])
        self.assertEqual(list(destination.rglob("*.orig")), [])

        patch_call = next(
            call for call in run.call_args_list if call.args[0][0] == "patch"
        )
        self.assertEqual(
            patch_call.args[0],
            [
                "patch",
                "--batch",
                "--forward",
                "--fuzz=0",
                "-p1",
                "-i",
                str(PATCH_PATH),
            ],
        )
        self.assertEqual(patch_call.kwargs["cwd"], destination)

    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_rejects_any_patch_change_outside_the_eight_files(
        self, run: mock.Mock
    ) -> None:
        base = self.root / "base"
        _write_patch_preimage(PATCH_PATH.read_text(encoding="ascii"), base)
        delta = self.root / "delta"
        _write_valid_debian_delta(delta)
        destination = self.root / "prepared"

        def modify_unexpected_file(*args: object, **kwargs: object) -> object:
            (destination / "unexpected.c").write_text("changed\n", encoding="ascii")
            return subprocess.CompletedProcess(args[0], 0, "", "")

        run.side_effect = modify_unexpected_file
        with self.assertRaisesRegex(RuntimeError, "exactly eight"):
            loader_build._prepare_source(base, delta, destination)

    def test_preserves_preexisting_upstream_orig_without_patch_artifacts(self) -> None:
        base = self.root / "base"
        _write_patch_preimage(PATCH_PATH.read_text(encoding="ascii"), base)
        upstream_orig = base / "refind" / "icns.h.orig"
        upstream_bytes = b"legitimate upstream backup\n"
        upstream_orig.write_bytes(upstream_bytes)
        delta = self.root / "delta"
        _write_valid_debian_delta(delta)
        destination = self.root / "prepared"

        loader_build._prepare_source(base, delta, destination)

        self.assertEqual(
            (destination / "refind" / "icns.h.orig").read_bytes(),
            upstream_bytes,
        )
        self.assertEqual(
            {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.orig")
            },
            {"refind/icns.h.orig"},
        )
        self.assertEqual(list(destination.rglob("*.rej")), [])

    def test_source_audit_rejects_reintroduced_abi_calls(self) -> None:
        base = self.root / "base"
        _write_patch_preimage(PATCH_PATH.read_text(encoding="ascii"), base)
        delta = self.root / "delta"
        _write_valid_debian_delta(delta)
        destination = self.root / "prepared"
        loader_build._prepare_source(base, delta, destination)

        config = destination / "refind" / "config.c"
        config.write_text(
            config.read_text(encoding="ascii") + "\nSetMem(Buffer, 1, 0);\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(RuntimeError, "SetMem"):
            loader_build._verify_source(destination)


AUDITED_OBJECTS = (
    "refind/config.o",
    "refind/lib.o",
    "refind/launch_legacy.o",
    "EfiLib/legacy.o",
    "libeg/lodepng_xtra.o",
    "libeg/nanojpeg.o",
)


def _write_build_artifacts(source: Path, efi_bytes: bytes = b"efi") -> None:
    for relative in AUDITED_OBJECTS:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("ascii"))
    shared = source / "refind" / "refind_x64.so"
    shared.write_bytes(b"shared object")
    (source / "refind" / "refind_x64.efi").write_bytes(efi_bytes)


CONFIG_CLEAR_DISASSEMBLY = """
refind/config.o:     file format elf64-x86-64

0000000000000e10 <ReadConfig+0x7ac>:
 e27: lea    rdx,[rbx+0x168]
 e2e: mov    eax,0x19
 e33: dec    rax
 e36: je     e45 <ReadConfig+0x7e1>
 e38: xor    r8d,r8d
 e3b: add    rdx,0x8
 e3f: mov    QWORD PTR [rdx-0x8],r8
 e43: jmp    e33 <ReadConfig+0x7cf>
 e45: mov    rbp,QWORD PTR [rip+0x0] # e4c <ReadConfig+0x7e8>
      e48: R_X86_64_REX_GOTPCRELX GlobalConfig-0x4
 e4c: mov    eax,0x1
 e51: mov    BYTE PTR [rbp+0x7],0x0
"""

GUID_CLEAR_DISASSEMBLY = """
 200: lea    rax,[rbx+0x30]
 207: lea    rdx,[rbx+0x40]
 20e: mov    BYTE PTR [rax],0x0
 211: inc    rax
 214: cmp    rax,rdx
 217: jne    0x20e
"""

MBR_CLEAR_DISASSEMBLY = """
 300: xor    eax,eax
 302: lea    rdx,[rax+rbp*1]
 306: inc    rax
 309: mov    BYTE PTR [rdx],0x0
 30c: cmp    rax,0x1b8
 312: jne    0x302
"""

DEVICE_TYPE_CLEAR_DISASSEMBLY = """
 400: xor    eax,eax
 402: push   r14
 404: mov    r12,rdi
 407: sub    rsp,0x48
 40b: lea    rdx,[rsp+0x8]
 410: inc    rax
 413: mov    QWORD PTR [rdx],0xffffffffffffffff
 41a: add    rdx,0x8
 41e: cmp    rax,0x7
 422: jne    0x410
"""

MY_MEMSET_DISASSEMBLY = """
 500: xor    eax,eax
 502: cmp    rax,rdx
 505: je     0x513
 507: lea    rcx,[rdi+rax*1]
 50b: inc    rax
 50e: mov    BYTE PTR [rcx],sil
 511: jmp    0x502
 513: mov    rax,rdi
 516: ret
"""

ALL_LOCAL_STORE_DISASSEMBLY = "\n".join(
    (
        CONFIG_CLEAR_DISASSEMBLY,
        GUID_CLEAR_DISASSEMBLY,
        MBR_CLEAR_DISASSEMBLY,
        DEVICE_TYPE_CLEAR_DISASSEMBLY,
        MY_MEMSET_DISASSEMBLY,
    )
)
ALL_LOCAL_STORE_SITES = (
    "config_showtools",
    "volume_uuid",
    "mbr_bootcode",
    "device_type_index",
    "my_memset",
)


class LoaderLocalStoreSemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "_verify_local_store_semantics"))

    def test_accepts_exact_config_clear_before_hidden_tags(self) -> None:
        loader_build._verify_local_store_semantics(
            CONFIG_CLEAR_DISASSEMBLY,
            ("config_showtools",),
        )

    def test_rejects_missing_local_fill(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "config_showtools"):
            loader_build._verify_local_store_semantics(
                " 100: mov BYTE PTR [rbp+0x7],0x0\n",
                ("config_showtools",),
            )

    def test_rejects_wrong_local_fill_bound(self) -> None:
        disassembly = CONFIG_CLEAR_DISASSEMBLY.replace("eax,0x19", "eax,0x18")

        with self.assertRaisesRegex(RuntimeError, "config_showtools"):
            loader_build._verify_local_store_semantics(
                disassembly,
                ("config_showtools",),
            )

    def test_rejects_wrong_local_fill_value(self) -> None:
        disassembly = CONFIG_CLEAR_DISASSEMBLY.replace(
            "QWORD PTR [rdx-0x8],r8",
            "QWORD PTR [rdx-0x8],r9",
        )

        with self.assertRaisesRegex(RuntimeError, "config_showtools"):
            loader_build._verify_local_store_semantics(
                disassembly,
                ("config_showtools",),
            )

    def test_accepts_all_exact_local_store_sites(self) -> None:
        try:
            loader_build._verify_local_store_semantics(
                ALL_LOCAL_STORE_DISASSEMBLY,
                ALL_LOCAL_STORE_SITES,
            )
        except Exception as error:
            self.fail(f"valid local-store semantics were rejected: {error}")

    def test_rejects_each_wrong_bound_or_value(self) -> None:
        corruptions = (
            (
                "volume_uuid_bound",
                "volume_uuid",
                GUID_CLEAR_DISASSEMBLY.replace("+0x40", "+0x41"),
            ),
            (
                "volume_uuid_value",
                "volume_uuid",
                GUID_CLEAR_DISASSEMBLY.replace("[rax],0x0", "[rax],0x1"),
            ),
            (
                "mbr_bootcode_bound",
                "mbr_bootcode",
                MBR_CLEAR_DISASSEMBLY.replace("rax,0x1b8", "rax,0x1b7"),
            ),
            (
                "mbr_bootcode_value",
                "mbr_bootcode",
                MBR_CLEAR_DISASSEMBLY.replace("[rdx],0x0", "[rdx],0x1"),
            ),
            (
                "device_type_index_bound",
                "device_type_index",
                DEVICE_TYPE_CLEAR_DISASSEMBLY.replace("rax,0x7", "rax,0x6"),
            ),
            (
                "device_type_index_value",
                "device_type_index",
                DEVICE_TYPE_CLEAR_DISASSEMBLY.replace(
                    "0xffffffffffffffff",
                    "0x0",
                ),
            ),
            (
                "my_memset_bound",
                "my_memset",
                MY_MEMSET_DISASSEMBLY.replace("rax,rdx", "rax,rcx"),
            ),
            (
                "my_memset_value",
                "my_memset",
                MY_MEMSET_DISASSEMBLY.replace("[rcx],sil", "[rcx],dil"),
            ),
        )
        for case, site, disassembly in corruptions:
            with self.subTest(case=case):
                try:
                    loader_build._verify_local_store_semantics(
                        disassembly,
                        (site,),
                    )
                except Exception as error:
                    self.assertIsInstance(error, RuntimeError)
                    self.assertRegex(str(error), site)
                else:
                    self.fail(f"{site} accepted wrong bound or value")

    def test_rejects_device_loop_with_modified_zero_initializer(self) -> None:
        disassembly = DEVICE_TYPE_CLEAR_DISASSEMBLY.replace(
            "400: xor    eax,eax",
            "400: xor    eax,eax\n 401: inc    rax",
        )

        with self.assertRaisesRegex(RuntimeError, "device_type_index"):
            loader_build._verify_local_store_semantics(
                disassembly,
                ("device_type_index",),
            )

    def test_owner_scope_rejects_valid_decoy_for_broken_config_site(self) -> None:
        broken_owner = CONFIG_CLEAR_DISASSEMBLY.replace("eax,0x19", "eax,0x18")
        valid_decoy = CONFIG_CLEAR_DISASSEMBLY.replace(
            "<ReadConfig+0x7ac>",
            "<DecoyFunction>",
        )

        try:
            loader_build._verify_local_store_semantics(
                broken_owner + valid_decoy,
                ("config_showtools",),
                require_function_symbols=True,
            )
        except Exception as error:
            self.assertIsInstance(error, RuntimeError)
            self.assertRegex(str(error), "config_showtools")
        else:
            self.fail("valid decoy masked a broken ReadConfig clear")

    def test_owner_scope_rejects_pattern_split_by_function_header(self) -> None:
        disassembly = CONFIG_CLEAR_DISASSEMBLY.replace(
            " e3b: add    rdx,0x8",
            "0000000000000e3b <DecoyFunction>:\n e3b: add    rdx,0x8",
        )

        with self.assertRaisesRegex(RuntimeError, "config_showtools"):
            loader_build._verify_local_store_semantics(
                disassembly,
                ("config_showtools",),
                require_function_symbols=True,
            )


class LoaderArtifactAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "_run_build"))
        self.assertTrue(hasattr(loader_build, "_audit_build"))
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        _write_build_artifacts(self.source)

    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_run_build_uses_the_pinned_make_command(self, run: mock.Mock) -> None:
        gnu_efi = self.root / "gnu-efi"

        loader_build._run_build(self.source, gnu_efi)

        command, environment = loader_build.make_command(self.source, gnu_efi)
        run.assert_called_once_with(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )

    @mock.patch("refind_forest.loader.build.verify_pe")
    @mock.patch("refind_forest.loader.build._verify_local_store_semantics")
    @mock.patch("refind_forest.loader.build.reject_setmem_call_edges")
    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_audits_exact_objects_shared_object_and_final_pe(
        self,
        run: mock.Mock,
        reject: mock.Mock,
        verify_stores: mock.Mock,
        verify_pe: mock.Mock,
    ) -> None:
        def tool_result(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            if command[0] == "nm":
                output = "000000000002c2a0 T SetMem\n"
            else:
                output = "disassembly\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        run.side_effect = tool_result
        sbat = b"approved sbat\n"

        hashes = loader_build._audit_build(self.source, sbat)

        objdump_commands = [
            call.args[0]
            for call in run.call_args_list
            if call.args[0][0] == "objdump"
        ]
        self.assertTrue(
            all(
                command[:4]
                == ["objdump", "--no-show-raw-insn", "-dr", "-Mintel"]
                for command in objdump_commands
            )
        )
        objdump_paths = [
            Path(command[4]).relative_to(self.source).as_posix()
            for command in objdump_commands
        ]
        self.assertEqual(
            objdump_paths,
            [*AUDITED_OBJECTS, "refind/refind_x64.so", "refind/refind_x64.efi"],
        )
        self.assertNotIn("gptsync", " ".join(objdump_paths))
        self.assertEqual(reject.call_count, 8)
        self.assertEqual(
            [call.args[1] for call in verify_stores.call_args_list],
            [
                ("config_showtools",),
                ("volume_uuid",),
                ("mbr_bootcode",),
                ("device_type_index",),
                ("my_memset",),
                (),
                ALL_LOCAL_STORE_SITES,
                ALL_LOCAL_STORE_SITES,
            ],
        )
        self.assertEqual(
            [call.kwargs for call in verify_stores.call_args_list],
            [
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": True},
                {"require_function_symbols": False},
            ],
        )
        self.assertEqual(
            reject.call_args_list[-1].kwargs,
            {"target_address": 0x2C2A0},
        )
        verify_pe.assert_called_once_with(
            self.source / "refind" / "refind_x64.efi",
            sbat,
        )
        self.assertEqual(set(hashes["objects"]), set(AUDITED_OBJECTS))
        self.assertEqual(len(hashes["shared_object"]), 64)
        self.assertEqual(len(hashes["efi"]), 64)

    @mock.patch("refind_forest.loader.build.verify_pe")
    @mock.patch("refind_forest.loader.build._verify_local_store_semantics")
    @mock.patch("refind_forest.loader.build.reject_setmem_call_edges")
    @mock.patch("refind_forest.loader.build.subprocess.run")
    def test_rejects_missing_or_ambiguous_setmem_symbol(
        self,
        run: mock.Mock,
        _reject: mock.Mock,
        _verify_stores: mock.Mock,
        _verify_pe: mock.Mock,
    ) -> None:
        nm_outputs = (
            "no matching symbol\n",
            "00000010 T SetMem\n00000020 T _SetMem\n",
        )
        for output in nm_outputs:
            with self.subTest(output=output):
                run.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(
                    command,
                    0,
                    output if command[0] == "nm" else "disassembly\n",
                    "",
                )
                with self.assertRaisesRegex(RuntimeError, "SetMem symbol"):
                    loader_build._audit_build(self.source, b"sbat")


class LoaderPublicationCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        (self.candidate / "refind_x64.efi").write_bytes(b"loader")
        (self.candidate / "provenance.json").write_bytes(b"{}\n")
        metadata = self.candidate.lstat()
        self.identity = (metadata.st_dev, metadata.st_ino)

    def test_cleanup_does_not_use_pathname_rmtree(self) -> None:
        with mock.patch.object(
            loader_build.shutil,
            "rmtree",
            side_effect=AssertionError("pathname rmtree is not ownership-bound"),
        ) as rmtree:
            loader_build._remove_build_directory(self.candidate, self.identity)

        rmtree.assert_not_called()
        self.assertFalse(os.path.lexists(self.candidate))

    def test_cleanup_preserves_replacement_after_quarantine_rename(self) -> None:
        real_rename = os.rename
        displaced_owned: Path | None = None

        def rename_then_replace(
            source: os.PathLike[str] | str,
            destination: os.PathLike[str] | str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
        ) -> None:
            nonlocal displaced_owned
            real_rename(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            if Path(source) != self.candidate or dst_dir_fd is None:
                return
            quarantine = Path(f"/proc/self/fd/{dst_dir_fd}").resolve()
            isolated = quarantine / Path(destination)
            displaced_owned = quarantine / "displaced-owned"
            real_rename(isolated, displaced_owned)
            isolated.mkdir()
            (isolated / "owner").write_bytes(b"foreign replacement")

        with mock.patch.object(
            loader_build.os,
            "rename",
            side_effect=rename_then_replace,
        ), self.assertRaisesRegex(RuntimeError, "identity"):
            loader_build._remove_build_directory(self.candidate, self.identity)

        self.assertEqual(
            (self.candidate / "owner").read_bytes(),
            b"foreign replacement",
        )
        self.assertIsNotNone(displaced_owned)
        assert displaced_owned is not None
        self.assertTrue(displaced_owned.is_dir())

    def test_cleanup_validates_all_entries_before_unlinking_any(self) -> None:
        target = self.root / "foreign-loader"
        target.write_bytes(b"foreign")
        loader = self.candidate / "refind_x64.efi"
        loader.unlink()
        loader.symlink_to(target)

        with self.assertRaisesRegex(RuntimeError, "contents changed"):
            loader_build._remove_build_directory(self.candidate, self.identity)

        quarantines = list(self.root.glob(".candidate.cleanup-*"))
        self.assertEqual(len(quarantines), 1)
        isolated = quarantines[0] / "publication"
        self.assertEqual((isolated / "provenance.json").read_bytes(), b"{}\n")
        self.assertTrue((isolated / "refind_x64.efi").is_symlink())
        self.assertEqual(target.read_bytes(), b"foreign")

    def test_cleanup_does_not_remove_quarantine_root_by_name(self) -> None:
        real_rmdir = os.rmdir

        def reject_quarantine_root_removal(
            path: os.PathLike[str] | str,
            *,
            dir_fd: int | None = None,
        ) -> None:
            path_value = Path(path)
            if ".candidate.cleanup-" in path_value.name:
                raise AssertionError(
                    "quarantine root removal is not inode-conditional"
                )
            real_rmdir(path, dir_fd=dir_fd)

        with mock.patch.object(
            loader_build.os,
            "rmdir",
            side_effect=reject_quarantine_root_removal,
        ):
            loader_build._remove_build_directory(self.candidate, self.identity)

        self.assertFalse(os.path.lexists(self.candidate))
        quarantines = list(self.root.glob(".candidate.cleanup-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(list(quarantines[0].iterdir()), [])


class LoaderBuildOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(hasattr(loader_build, "build_loader"))
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.output = self.root / "loader-output"
        self.cache = self.root / "cache"

    def _install_fake_pipeline(
        self,
        efi_outputs: tuple[bytes, bytes] = (b"identical efi", b"identical efi"),
        *,
        fail_second_build: bool = False,
        intermediate_markers: tuple[bytes, bytes] = (b"", b""),
    ) -> dict[str, object]:
        inputs = self.root / "inputs"
        inputs.mkdir()
        acquired: dict[str, Path] = {}
        original_inputs: dict[str, bytes] = {}
        pinned_inputs = []
        for item in loader_build.PINNED_INPUTS:
            path = inputs / item.filename
            contents = item.name.encode("ascii")
            path.write_bytes(contents)
            acquired[item.name] = path
            original_inputs[item.filename] = contents
            pinned_inputs.append(
                loader_build.PinnedInput(
                    item.name,
                    item.filename,
                    item.url,
                    hashlib.sha256(contents).hexdigest(),
                )
            )
        self.enterContext(
            mock.patch.object(loader_build, "PINNED_INPUTS", tuple(pinned_inputs))
        )

        events: list[str] = []
        extracted_inputs: dict[str, bytes] = {}
        snapshot_file_modes: set[int] = set()
        snapshot_directory_modes: set[int] = set()
        extraction_paths: list[Path] = []
        acquire = self.enterContext(
            mock.patch.object(
                loader_build,
                "_acquire_inputs",
                side_effect=lambda cache: events.append("acquire") or acquired,
            )
        )

        def record_extraction_input(archive: Path) -> None:
            archive = Path(archive)
            extraction_paths.append(archive)
            extracted_inputs[archive.name] = archive.read_bytes()
            snapshot_file_modes.add(stat.S_IMODE(archive.stat().st_mode))
            snapshot_directory_modes.add(
                stat.S_IMODE(archive.parent.stat().st_mode)
            )

        def extract_tar(archive: Path, destination: Path) -> None:
            record_extraction_input(archive)
            events.append(f"extract:{Path(archive).name}")
            destination.mkdir()
            if Path(archive).name == pinned_inputs[0].filename:
                (destination / "refind-0.14.2").mkdir()
            else:
                _write_valid_debian_delta(destination)

        extract_tar_mock = self.enterContext(
            mock.patch.object(loader_build, "_extract_tar", side_effect=extract_tar)
        )

        def extract_deb(archive: Path, destination: Path) -> None:
            record_extraction_input(archive)
            events.append("extract:gnu-efi")
            (destination / "usr" / "include" / "efi").mkdir(parents=True)
            (destination / "usr" / "lib").mkdir(parents=True)

        extract_deb_mock = self.enterContext(
            mock.patch.object(loader_build, "_extract_deb", side_effect=extract_deb)
        )

        def prepare_source(
            _base: Path, _delta: Path, destination: Path
        ) -> Path:
            destination.mkdir()
            for relative in loader_build._PATCHED_PATHS:
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"source:{relative}".encode("ascii"))
            (destination / "refind-forest-sbat.csv").write_bytes(SBAT_PATH.read_bytes())
            return destination

        prepare = self.enterContext(
            mock.patch.object(
                loader_build,
                "_prepare_source",
                side_effect=prepare_source,
            )
        )

        build_count = 0

        def run_build(source: Path, _gnu_efi: Path) -> None:
            nonlocal build_count
            if fail_second_build and build_count == 1:
                raise RuntimeError("second build failed")
            _write_build_artifacts(source, efi_outputs[build_count])
            marker = intermediate_markers[build_count]
            for relative in AUDITED_OBJECTS:
                path = source / relative
                path.write_bytes(path.read_bytes() + marker)
            shared = source / "refind" / "refind_x64.so"
            shared.write_bytes(shared.read_bytes() + marker)
            build_count += 1

        run_build_mock = self.enterContext(
            mock.patch.object(loader_build, "_run_build", side_effect=run_build)
        )

        audit_results: list[dict[str, object]] = []

        def audit(source: Path, expected_sbat: bytes) -> dict[str, object]:
            self.assertEqual(expected_sbat, SBAT_PATH.read_bytes())
            result = {
                "objects": {
                    relative: hashlib.sha256((source / relative).read_bytes()).hexdigest()
                    for relative in AUDITED_OBJECTS
                },
                "shared_object": hashlib.sha256(
                    (source / "refind" / "refind_x64.so").read_bytes()
                ).hexdigest(),
                "efi": hashlib.sha256(
                    (source / "refind" / "refind_x64.efi").read_bytes()
                ).hexdigest(),
            }
            audit_results.append(result)
            return result

        audit_mock = self.enterContext(
            mock.patch.object(loader_build, "_audit_build", side_effect=audit)
        )
        tools = {
            "dpkg-deb": "dpkg-deb 1.0",
            "gcc": "gcc 15.2",
            "ld": "GNU ld 2.46",
            "make": "GNU Make 4.4.1",
            "nm": "GNU nm 2.46",
            "objcopy": "GNU objcopy 2.46",
            "objdump": "GNU objdump 2.46",
            "patch": "GNU patch 2.8",
            "python": "Python 3.12.0",
            "tar": "tar 1.35",
        }
        self.enterContext(
            mock.patch.object(loader_build, "_tool_versions", return_value=tools)
        )
        return {
            "acquired": acquired,
            "acquire": acquire,
            "audit": audit_mock,
            "audit_results": audit_results,
            "events": events,
            "extracted_inputs": extracted_inputs,
            "extraction_paths": extraction_paths,
            "extract_deb": extract_deb_mock,
            "extract_tar": extract_tar_mock,
            "original_inputs": original_inputs,
            "prepare": prepare,
            "run_build": run_build_mock,
            "snapshot_directory_modes": snapshot_directory_modes,
            "snapshot_file_modes": snapshot_file_modes,
            "tools": tools,
        }

    def test_rejects_existing_or_broken_symlink_output_before_acquisition(self) -> None:
        acquire = self.enterContext(
            mock.patch.object(loader_build, "_acquire_inputs")
        )
        for kind in ("directory", "broken symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    self.output.mkdir()
                else:
                    self.output.symlink_to(self.root / "missing")
                with self.assertRaisesRegex(ValueError, "already exists"):
                    loader_build.build_loader(self.output, self.cache)
                if self.output.is_symlink():
                    self.output.unlink()
                else:
                    self.output.rmdir()
        acquire.assert_not_called()

    def test_rejects_cache_at_or_below_output_without_creating_parent(self) -> None:
        acquire = self.enterContext(
            mock.patch.object(loader_build, "_acquire_inputs")
        )
        for kind in ("same path", "below output"):
            with self.subTest(kind=kind):
                output = self.root / kind.replace(" ", "-") / "loader-output"
                cache = output if kind == "same path" else output / "cache"

                with self.assertRaisesRegex(ValueError, "cache.*output"):
                    loader_build.build_loader(output, cache)

                self.assertFalse(output.parent.exists())
        acquire.assert_not_called()

    def test_builds_twice_and_atomically_publishes_loader_and_provenance(self) -> None:
        pipeline = self._install_fake_pipeline()

        result = loader_build.build_loader(self.output, self.cache)

        self.assertEqual(result, self.output / "refind_x64.efi")
        self.assertEqual(result.read_bytes(), b"identical efi")
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            {"provenance.json", "refind_x64.efi"},
        )
        self.assertEqual(pipeline["prepare"].call_count, 2)
        prepared = [call.args[2] for call in pipeline["prepare"].call_args_list]
        self.assertEqual(len(set(prepared)), 2)
        self.assertEqual(pipeline["run_build"].call_count, 2)
        self.assertEqual(pipeline["audit"].call_count, 2)
        self.assertEqual(
            pipeline["events"],
            [
                "acquire",
                "extract:refind_0.14.2.orig.tar.gz",
                "extract:refind_0.14.2-2.1.debian.tar.xz",
                "extract:gnu-efi",
            ],
        )
        self.assertEqual(
            [path for path in self.root.iterdir() if ".loader-output.build-" in path.name],
            [],
        )

    def test_published_output_directory_is_0700_independent_of_umask(self) -> None:
        self._install_fake_pipeline()
        previous_umask = os.umask(0)
        try:
            loader_build.build_loader(self.output, self.cache)
        finally:
            os.umask(previous_umask)

        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)

    def test_extracts_only_private_verified_input_snapshots(self) -> None:
        pipeline = self._install_fake_pipeline()

        loader_build.build_loader(self.output, self.cache)

        self.assertEqual(
            pipeline["extracted_inputs"],
            pipeline["original_inputs"],
        )
        self.assertTrue(
            set(pipeline["extraction_paths"]).isdisjoint(
                pipeline["acquired"].values()
            )
        )
        self.assertEqual(pipeline["snapshot_directory_modes"], {0o700})
        self.assertEqual(pipeline["snapshot_file_modes"], {0o600})

    def test_rejects_snapshot_hash_mismatch_before_extraction(self) -> None:
        pipeline = self._install_fake_pipeline()
        pipeline["acquired"]["refind_debian_delta"].write_bytes(b"replacement")

        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            loader_build.build_loader(self.output, self.cache)

        pipeline["extract_tar"].assert_not_called()
        pipeline["extract_deb"].assert_not_called()
        self.assertFalse(os.path.lexists(self.output))

    def test_rejects_nonreproducible_outputs_without_publishing(self) -> None:
        self._install_fake_pipeline((b"first", b"second"))

        with self.assertRaisesRegex(RuntimeError, "byte-identical"):
            loader_build.build_loader(self.output, self.cache)

        self.assertFalse(os.path.lexists(self.output))

    def test_build_failure_does_not_publish_partial_output(self) -> None:
        self._install_fake_pipeline(fail_second_build=True)

        with self.assertRaisesRegex(RuntimeError, "second build failed"):
            loader_build.build_loader(self.output, self.cache)

        self.assertFalse(os.path.lexists(self.output))

    def test_workspace_cleanup_failure_does_not_publish_output(self) -> None:
        self._install_fake_pipeline()
        real_cleanup = tempfile.TemporaryDirectory.cleanup

        def cleanup_then_fail(directory: tempfile.TemporaryDirectory[str]) -> None:
            real_cleanup(directory)
            if ".loader-output.build-" in directory.name:
                raise OSError("injected workspace cleanup failure")

        with mock.patch.object(
            tempfile.TemporaryDirectory,
            "cleanup",
            cleanup_then_fail,
        ), self.assertRaisesRegex(OSError, "workspace cleanup failure"):
            loader_build.build_loader(self.output, self.cache)

        self.assertFalse(os.path.lexists(self.output))

    def test_preexisting_pending_collision_is_not_removed(self) -> None:
        self._install_fake_pipeline()
        real_write_text = Path.write_text
        collision: Path | None = None

        def write_text_then_create_collision(
            path: Path,
            data: str,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal collision
            result = real_write_text(path, data, *args, **kwargs)
            if path.name == "provenance.json":
                workspace = path.parents[1]
                collision = workspace.with_name(f"{workspace.name}.publish")
                collision.mkdir()
                (collision / "owner").write_bytes(b"pre-existing")
            return result

        with mock.patch.object(
            Path,
            "write_text",
            autospec=True,
            side_effect=write_text_then_create_collision,
        ), self.assertRaisesRegex(ValueError, "publish staging already exists"):
            loader_build.build_loader(self.output, self.cache)

        self.assertIsNotNone(collision)
        assert collision is not None
        self.addCleanup(shutil.rmtree, collision, ignore_errors=True)
        self.assertEqual((collision / "owner").read_bytes(), b"pre-existing")
        self.assertFalse(os.path.lexists(self.output))

    def test_foreign_pending_replacement_is_preserved_not_published(self) -> None:
        self._install_fake_pipeline()
        real_cleanup = tempfile.TemporaryDirectory.cleanup
        foreign_pending: Path | None = None

        def cleanup_then_replace_pending(
            directory: tempfile.TemporaryDirectory[str],
        ) -> None:
            nonlocal foreign_pending
            pending = Path(directory.name).with_name(
                f"{Path(directory.name).name}.publish"
            )
            real_cleanup(directory)
            if ".loader-output.build-" in directory.name:
                shutil.rmtree(pending)
                pending.mkdir()
                (pending / "owner").write_bytes(b"foreign pending")
                foreign_pending = pending

        with mock.patch.object(
            tempfile.TemporaryDirectory,
            "cleanup",
            cleanup_then_replace_pending,
        ), self.assertRaisesRegex(RuntimeError, "identity"):
            loader_build.build_loader(self.output, self.cache)

        self.assertIsNotNone(foreign_pending)
        assert foreign_pending is not None
        self.addCleanup(shutil.rmtree, foreign_pending, ignore_errors=True)
        self.assertEqual((foreign_pending / "owner").read_bytes(), b"foreign pending")
        self.assertFalse(os.path.lexists(self.output))

    def test_error_after_final_rename_removes_published_output(self) -> None:
        self._install_fake_pipeline()
        real_rename = Path.rename

        def rename_then_fail(path: Path, target: Path) -> Path:
            result = real_rename(path, target)
            if Path(target) == self.output:
                raise OSError("injected post-rename failure")
            return result

        with mock.patch.object(
            Path,
            "rename",
            autospec=True,
            side_effect=rename_then_fail,
        ), self.assertRaisesRegex(OSError, "post-rename failure"):
            loader_build.build_loader(self.output, self.cache)

        self.assertFalse(os.path.lexists(self.output))

    def test_foreign_output_replacement_after_rename_is_preserved(self) -> None:
        self._install_fake_pipeline()
        real_rename = Path.rename

        def rename_replace_and_fail(path: Path, target: Path) -> Path:
            result = real_rename(path, target)
            if Path(target) == self.output:
                shutil.rmtree(target)
                Path(target).mkdir()
                (Path(target) / "owner").write_bytes(b"foreign output")
                raise OSError("injected post-rename foreign replacement")
            return result

        with mock.patch.object(
            Path,
            "rename",
            autospec=True,
            side_effect=rename_replace_and_fail,
        ), self.assertRaisesRegex(RuntimeError, "identity"):
            loader_build.build_loader(self.output, self.cache)

        self.assertEqual((self.output / "owner").read_bytes(), b"foreign output")

    def test_provenance_is_complete_ascii_and_path_stable(self) -> None:
        pipeline = self._install_fake_pipeline()
        loader_build.build_loader(self.output, self.cache)

        provenance_path = self.output / "provenance.json"
        raw = provenance_path.read_bytes()
        text = raw.decode("ascii")
        provenance = json.loads(text)

        self.assertEqual(provenance["schema"], "refind-forest-loader-provenance")
        self.assertEqual(provenance["version"], 1)
        self.assertEqual(provenance["tools"], pipeline["tools"])
        self.assertEqual(
            {
                (item["name"], item["filename"], item["url"], item["sha256"])
                for item in provenance["inputs"]
            },
            {
                (item.name, item.filename, item.url, item.sha256)
                for item in loader_build.PINNED_INPUTS
            },
        )
        self.assertEqual(set(provenance["sources"]), set(loader_build._PATCHED_PATHS))
        self.assertEqual(set(provenance["objects"]), set(AUDITED_OBJECTS))
        self.assertEqual(provenance["efi"]["path"], "refind_x64.efi")
        self.assertEqual(provenance["final_sha256"], provenance["efi"]["sha256"])
        self.assertEqual(len(provenance["patch"]["sha256"]), 64)
        self.assertEqual(len(provenance["sbat"]["sha256"]), 64)
        self.assertEqual(
            provenance["build"]["environment"],
            loader_build.make_command(Path("source"))[1],
        )
        self.assertIn(EXPECTED_CFLAGS, provenance["build"]["command"])
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("timestamp", text.lower())
        self.assertEqual(
            text,
            json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n",
        )

    def test_provenance_records_both_complete_build_audits(self) -> None:
        pipeline = self._install_fake_pipeline(
            intermediate_markers=(b"first", b"second"),
        )

        loader_build.build_loader(self.output, self.cache)

        provenance = json.loads(
            (self.output / "provenance.json").read_text(encoding="ascii")
        )
        build_audits = provenance["build_audits"]
        self.assertEqual([audit["build"] for audit in build_audits], [1, 2])
        for index, audit in enumerate(build_audits):
            expected = pipeline["audit_results"][index]
            self.assertEqual(audit["objects"], expected["objects"])
            self.assertEqual(set(audit["objects"]), set(AUDITED_OBJECTS))
            self.assertEqual(
                audit["shared_object"],
                {
                    "path": "refind/refind_x64.so",
                    "sha256": expected["shared_object"],
                },
            )
            self.assertEqual(
                audit["efi"],
                {
                    "path": "refind/refind_x64.efi",
                    "sha256": expected["efi"],
                },
            )
        self.assertNotEqual(build_audits[0]["objects"], build_audits[1]["objects"])
        self.assertNotEqual(
            build_audits[0]["shared_object"],
            build_audits[1]["shared_object"],
        )
        self.assertEqual(build_audits[0]["efi"], build_audits[1]["efi"])
        self.assertEqual(provenance["canonical_build"], 1)
        self.assertEqual(provenance["objects"], build_audits[0]["objects"])
        self.assertEqual(
            provenance["published"],
            {
                "from_build": 1,
                "path": "refind_x64.efi",
                "sha256": provenance["final_sha256"],
            },
        )


class LoaderBuildInputTests(unittest.TestCase):
    def _read_required_input(self, path: Path) -> str:
        self.assertTrue(
            path.is_file(),
            f"missing required loader build input: {path.relative_to(PROJECT_ROOT)}",
        )
        return path.read_text(encoding="utf-8")

    def test_patch_has_only_the_expected_deletions(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        removed_lines = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("-")
            and line != "-"
            and not line.startswith("---")
        ]

        self.assertCountEqual(removed_lines, EXPECTED_REMOVED_LINES)

    def test_patch_covers_exactly_the_eight_audited_sources(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        patched_paths = set(re.findall(r"^--- a/(.+)$", patch, re.MULTILINE))

        self.assertEqual(patched_paths, set(EXPECTED_PATCH_ADDITIONS))

    def test_patch_adds_no_direct_setmem_calls(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        added_lines = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]

        self.assertFalse(
            any(re.search(r"\bSetMem\s*\(", line) for line in added_lines)
        )

    def test_patch_additions_define_the_audited_replacement_semantics(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        for path, expected_lines in EXPECTED_PATCH_ADDITIONS.items():
            with self.subTest(path=path):
                marker = f"--- a/{path}\n+++ b/{path}\n"
                self.assertIn(marker, patch)
                start = patch.index(marker)
                end = patch.find("\n--- a/", start + len(marker))
                section = patch[start:] if end == -1 else patch[start:end]
                added_lines = {
                    line[1:].lstrip()
                    for line in section.splitlines()
                    if line.startswith("+") and not line.startswith("+++")
                }
                for expected_line in expected_lines:
                    self.assertIn(expected_line, added_lines)
                if path == "EfiLib/legacy.c":
                    self.assertNotIn(
                        "for (DeviceIndex = 0; DeviceIndex < 7; DeviceIndex++) {",
                        added_lines,
                    )

    def test_gnu_efi_four_uses_its_own_ascii_strlen(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        marker = "--- a/EfiLib/gnuefi-helper.c\n"
        self.assertIn(marker, patch)
        section_start = patch.index(marker)
        section_end = patch.find("\n--- a/", section_start + 1)
        section = (
            patch[section_start:]
            if section_end == -1
            else patch[section_start:section_end]
        )

        guard_start = section.index("+#ifndef _GNU_EFI_4_0")
        function_documentation = section.index(" Returns the length")
        function_return = section.index(" return Length;")
        guard_end = section.index("+#endif", function_return)
        self.assertLess(guard_start, function_documentation)
        self.assertLess(function_return, guard_end)

    def test_loader_sbat_rva_uses_aligned_hexadecimal_offset(self) -> None:
        patch = self._read_required_input(PATCH_PATH)

        self.assertIn(
            "-\t\t       --adjust-section-vma .sbat+10000000 $@",
            patch,
        )
        self.assertIn(
            "+\t\t       --adjust-section-vma .sbat+0x1000000 $@",
            patch,
        )

    def test_patch_applies_without_fuzz_or_rejects(self) -> None:
        patch = self._read_required_input(PATCH_PATH)
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            _write_patch_preimage(patch, source)

            result = subprocess.run(
                [
                    "patch",
                    "--batch",
                    "--forward",
                    "--fuzz=0",
                    "-p1",
                    "-i",
                    str(PATCH_PATH),
                ],
                cwd=source,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(source.rglob("*.rej")), [])

    def test_sbat_has_exact_upstream_and_local_rows(self) -> None:
        self.assertEqual(self._read_required_input(SBAT_PATH), EXPECTED_SBAT)


if __name__ == "__main__":
    unittest.main()

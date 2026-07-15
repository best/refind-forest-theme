"""Structural and policy verification for locally built rEFInd binaries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess


_DOS_HEADER_SIZE = 0x40
_COFF_HEADER_SIZE = 20
_SECTION_HEADER_SIZE = 40
_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
_X86_64_MACHINE = 0x8664
_EFI_APPLICATION_SUBSYSTEM = 10
_SECURITY_DIRECTORY_INDEX = 4

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

_CALL_MNEMONIC_RE = re.compile(r"\bcallq?\b", re.ASCII)
_SETMEM_SYMBOL_RE = re.compile(r"<(?:_?SetMem)(?:[.@+][^>]*)?>")
_DIRECT_CALL_TARGET_RE = re.compile(r"\s*(?:0x)?([0-9a-fA-F]+)\b")
_SETMEM_RELOCATION_RE = re.compile(
    r"\bR_X86_64_PLT32\s+_?SetMem(?:[+-](?:0x)?[0-9a-fA-F]+)?\b"
)
_SIGNATURE_LINE_RE = re.compile(r"^signature [0-9]+\r?$", re.ASCII | re.MULTILINE)
_SBVERIFY = "/usr/bin/sbverify"
_TRUSTED_TOOL_ENVIRONMENT = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}


@dataclass(frozen=True, slots=True)
class PeSection:
    """One section table entry and its bytes from the PE file."""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    raw_data: bytes

    @property
    def memory_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_READ)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_WRITE)

    @property
    def size_of_raw_data(self) -> int:
        return self.raw_size

    @property
    def pointer_to_raw_data(self) -> int:
        return self.raw_offset


@dataclass(frozen=True, slots=True)
class PeImage:
    """The PE metadata needed by the loader verification policy."""

    path: Path
    machine: int
    optional_header_magic: int
    subsystem: int
    entry_point: int
    section_alignment: int
    file_alignment: int
    size_of_headers: int
    size_of_image: int
    security_directory_offset: int
    security_directory_size: int
    sections: tuple[PeSection, ...]

    @property
    def magic(self) -> int:
        return self.optional_header_magic

    @property
    def address_of_entry_point(self) -> int:
        return self.entry_point

    @property
    def security_directory(self) -> tuple[int, int] | None:
        if self.security_directory_size == 0:
            return None
        return self.security_directory_offset, self.security_directory_size


def _require_range(data: bytes, offset: int, size: int, description: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"truncated PE: missing {description}")


def _read_u16(data: bytes, offset: int, description: str) -> int:
    _require_range(data, offset, 2, description)
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int, description: str) -> int:
    _require_range(data, offset, 4, description)
    return struct.unpack_from("<I", data, offset)[0]


@contextmanager
def _open_regular_file(
    path: Path, description: str
) -> Iterator[tuple[int, os.stat_result]]:
    path = Path(path)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"refusing symbolic link: {path}") from error
        raise ValueError(f"cannot open {description} {path}: {error}") from error

    try:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise ValueError(f"cannot inspect {description} {path}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{description} is not a regular file: {path}")
        yield descriptor, metadata
    finally:
        os.close(descriptor)


def _read_image(path: Path) -> bytes:
    path = Path(path)
    with _open_regular_file(path, "PE image") as (descriptor, before):
        try:
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(descriptor)
        except OSError as error:
            raise ValueError(f"cannot read PE image {path}: {error}") from error

    data = b"".join(chunks)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_identity != after_identity or len(data) != before.st_size:
        raise ValueError(f"PE image changed while reading: {path}")
    return data


def _reject_overlaps(
    intervals: list[tuple[int, int, str]], description: str
) -> None:
    intervals.sort(key=lambda interval: (interval[0], interval[1]))
    for previous, current in zip(intervals, intervals[1:]):
        if current[0] < previous[1]:
            raise ValueError(
                f"{description} overlap: {previous[2]} and {current[2]}"
            )


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def parse_pe(path: Path) -> PeImage:
    """Parse the PE fields needed for verification and reject unsafe layouts."""

    path = Path(path)
    data = _read_image(path)
    _require_range(data, 0, _DOS_HEADER_SIZE, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("invalid PE: missing DOS MZ signature")

    pe_offset = _read_u32(data, 0x3C, "PE header offset")
    if pe_offset < _DOS_HEADER_SIZE:
        raise ValueError("invalid PE header offset")
    _require_range(data, pe_offset, 4 + _COFF_HEADER_SIZE, "PE and COFF headers")
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")

    coff_offset = pe_offset + 4
    (
        machine,
        number_of_sections,
        _timestamp,
        _symbol_table_offset,
        _number_of_symbols,
        optional_header_size,
        _characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_offset)
    if number_of_sections == 0:
        raise ValueError("invalid PE: no sections")

    optional_offset = coff_offset + _COFF_HEADER_SIZE
    _require_range(data, optional_offset, optional_header_size, "optional header")
    if optional_header_size < 72:
        raise ValueError("truncated PE: optional header fields")

    optional_magic = _read_u16(data, optional_offset, "optional header magic")
    if optional_magic == _PE32_PLUS_MAGIC:
        directory_count_offset = 108
        directory_table_offset = 112
    elif optional_magic == _PE32_MAGIC:
        directory_count_offset = 92
        directory_table_offset = 96
    else:
        raise ValueError(
            f"unsupported PE optional-header magic 0x{optional_magic:x}"
        )

    required_optional_size = directory_count_offset + 4
    if optional_header_size < required_optional_size:
        raise ValueError("truncated PE: optional header data-directory count")

    entry_point = _read_u32(data, optional_offset + 16, "entry point")
    section_alignment = _read_u32(
        data, optional_offset + 32, "section alignment"
    )
    file_alignment = _read_u32(data, optional_offset + 36, "file alignment")
    size_of_image = _read_u32(data, optional_offset + 56, "image size")
    size_of_headers = _read_u32(data, optional_offset + 60, "header size")
    subsystem = _read_u16(data, optional_offset + 68, "subsystem")
    number_of_directories = _read_u32(
        data, optional_offset + directory_count_offset, "data-directory count"
    )

    if not _is_power_of_two(file_alignment):
        raise ValueError("FileAlignment must be a nonzero power of two")
    if not 0x200 <= file_alignment <= 0x10000:
        raise ValueError("FileAlignment must be between 0x200 and 0x10000")
    if not _is_power_of_two(section_alignment):
        raise ValueError("SectionAlignment must be a nonzero power of two")
    if section_alignment < file_alignment:
        raise ValueError("SectionAlignment must not be smaller than FileAlignment")
    if size_of_headers % file_alignment:
        raise ValueError("SizeOfHeaders must be aligned to FileAlignment")
    if size_of_image % section_alignment:
        raise ValueError("SizeOfImage must be aligned to SectionAlignment")

    security_offset = 0
    security_size = 0
    if number_of_directories > _SECURITY_DIRECTORY_INDEX:
        security_entry_offset = (
            directory_table_offset + _SECURITY_DIRECTORY_INDEX * 8
        )
        if optional_header_size < security_entry_offset + 8:
            raise ValueError("truncated PE: security data-directory entry")
        security_offset, security_size = struct.unpack_from(
            "<II", data, optional_offset + security_entry_offset
        )
        if bool(security_offset) != bool(security_size):
            raise ValueError("invalid PE security directory")
        if security_size:
            if security_offset % 8:
                raise ValueError("PE security directory offset must be 8-byte aligned")
            if security_size % 8:
                raise ValueError("PE security directory size must be 8-byte aligned")
            if security_offset > len(data) or security_size > len(data) - security_offset:
                raise ValueError("PE security directory is outside the file")

    section_table_offset = optional_offset + optional_header_size
    section_table_size = number_of_sections * _SECTION_HEADER_SIZE
    _require_range(data, section_table_offset, section_table_size, "section table")
    section_table_end = section_table_offset + section_table_size
    if size_of_headers < section_table_end or size_of_headers > len(data):
        raise ValueError("invalid PE header size")

    sections: list[PeSection] = []
    section_names: set[str] = set()
    raw_intervals: list[tuple[int, int, str]] = []
    rva_intervals: list[tuple[int, int, str]] = []
    for index in range(number_of_sections):
        section_offset = section_table_offset + index * _SECTION_HEADER_SIZE
        raw_name = data[section_offset : section_offset + 8]
        encoded_name = raw_name.split(b"\x00", 1)[0]
        if not encoded_name:
            raise ValueError(f"invalid empty section name at index {index}")
        try:
            name = encoded_name.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"non-ASCII PE section name at index {index}") from error
        if name in section_names:
            raise ValueError(f"duplicate section name: {name}")
        section_names.add(name)

        (
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            _relocations_offset,
            _line_numbers_offset,
            _number_of_relocations,
            _number_of_line_numbers,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", data, section_offset + 8)

        if raw_offset % file_alignment:
            raise ValueError(f"section {name} raw offset is not file-aligned")
        if raw_size % file_alignment:
            raise ValueError(f"section {name} raw size is not file-aligned")
        if virtual_address % section_alignment:
            raise ValueError(
                f"section {name} virtual address is not section-aligned"
            )

        if raw_size:
            if raw_offset < size_of_headers:
                raise ValueError(f"section {name} raw data overlaps PE headers")
            if raw_offset > len(data) or raw_size > len(data) - raw_offset:
                raise ValueError(f"section {name} raw data is outside the file")
            raw_end = raw_offset + raw_size
            raw_intervals.append((raw_offset, raw_end, name))
            raw_data = data[raw_offset:raw_end]
        else:
            raw_data = b""

        memory_size = max(virtual_size, raw_size)
        if memory_size:
            rva_end = virtual_address + memory_size
            if virtual_address < size_of_headers or rva_end > size_of_image:
                raise ValueError(f"section {name} RVA is outside the image")
            rva_intervals.append((virtual_address, rva_end, name))

        sections.append(
            PeSection(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_offset=raw_offset,
                characteristics=characteristics,
                raw_data=raw_data,
            )
        )

    _reject_overlaps(raw_intervals, "section raw ranges")
    _reject_overlaps(rva_intervals, "section RVA ranges")

    if security_size:
        security_end = security_offset + security_size
        if security_offset < size_of_headers:
            raise ValueError("PE security directory overlaps loaded headers")
        for raw_start, raw_end, name in raw_intervals:
            if security_offset < raw_end and raw_start < security_end:
                raise ValueError(
                    f"PE security directory overlaps section raw data: {name}"
                )

    return PeImage(
        path=path,
        machine=machine,
        optional_header_magic=optional_magic,
        subsystem=subsystem,
        entry_point=entry_point,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        security_directory_offset=security_offset,
        security_directory_size=security_size,
        sections=tuple(sections),
    )


def loaded_section_hashes(path: Path) -> dict[str, str]:
    """Return SHA-256 hashes of section raw bytes, excluding file overlays."""

    image = parse_pe(path)
    metadata = hashlib.sha256()
    metadata.update(b"refind-forest-pe-load-metadata-v1\x00")
    metadata.update(
        struct.pack(
            "<HHHIIIIII",
            image.machine,
            image.optional_header_magic,
            image.subsystem,
            image.entry_point,
            image.section_alignment,
            image.file_alignment,
            image.size_of_headers,
            image.size_of_image,
            len(image.sections),
        )
    )
    for section in image.sections:
        name = section.name.encode("ascii")
        metadata.update(struct.pack("<B", len(name)))
        metadata.update(name)
        metadata.update(
            struct.pack(
                "<IIII",
                section.virtual_address,
                section.virtual_size,
                section.raw_size,
                section.characteristics,
            )
        )

    hashes = {
        section.name: hashlib.sha256(section.raw_data).hexdigest()
        for section in image.sections
    }
    hashes["__pe_load_metadata__"] = metadata.hexdigest()
    return hashes


def verify_pe(path: Path, expected_sbat: bytes) -> PeImage:
    """Verify that a parsed image follows the rEFInd UEFI loader policy."""

    image = parse_pe(path)
    if image.machine != _X86_64_MACHINE:
        raise ValueError(
            f"unexpected PE machine 0x{image.machine:x}; expected x86-64"
        )
    if image.optional_header_magic != _PE32_PLUS_MAGIC:
        raise ValueError("loader must use a PE32+ optional header")
    if image.subsystem != _EFI_APPLICATION_SUBSYSTEM:
        raise ValueError(
            f"unexpected PE subsystem {image.subsystem}; expected EFI application"
        )

    containing_executable_section = any(
        section.executable
        and section.virtual_address
        <= image.entry_point
        < section.virtual_address + section.memory_size
        for section in image.sections
    )
    if not containing_executable_section:
        raise ValueError("PE entry point is not inside an executable section")

    for section in image.sections:
        if section.readable and section.writable and section.executable:
            raise ValueError(f"RWX section is forbidden: {section.name}")

    sections_by_name = {section.name: section for section in image.sections}
    for required_name in (".reloc", ".sbat"):
        if required_name not in sections_by_name:
            raise ValueError(f"required PE section is missing: {required_name}")

    expected_sbat = bytes(expected_sbat)
    sbat_data = sections_by_name[".sbat"].raw_data
    if (
        len(sbat_data) < len(expected_sbat)
        or sbat_data[: len(expected_sbat)] != expected_sbat
        or any(sbat_data[len(expected_sbat) :])
    ):
        raise ValueError("SBAT section does not exactly match the expected bytes")

    return image


def reject_setmem_call_edges(
    disassembly: str, target_address: int | None = None
) -> None:
    """Reject direct calls to SetMem in symbolic or stripped objdump output."""

    previous_line_was_call = False
    for line_number, line in enumerate(disassembly.splitlines(), start=1):
        if previous_line_was_call and _SETMEM_RELOCATION_RE.search(line):
            raise ValueError(
                f"SetMem call relocation found on disassembly line {line_number}"
            )
        previous_line_was_call = False
        mnemonic = _CALL_MNEMONIC_RE.search(line)
        if mnemonic is None:
            continue
        previous_line_was_call = True
        operand = line[mnemonic.end() :]
        if _SETMEM_SYMBOL_RE.search(operand):
            raise ValueError(f"SetMem call edge found on disassembly line {line_number}")
        if target_address is None:
            continue
        direct_target = _DIRECT_CALL_TARGET_RE.match(operand)
        if direct_target is not None and int(direct_target.group(1), 16) == target_address:
            raise ValueError(
                f"call edge to configured SetMem target 0x{target_address:x} "
                f"found on disassembly line {line_number}"
            )


def verify_signed(path: Path, certificate: Path) -> None:
    """Require one signature and validate it against the expected certificate."""

    with (
        _open_regular_file(path, "signed image") as (image_descriptor, _),
        _open_regular_file(certificate, "certificate") as (
            certificate_descriptor,
            _,
        ),
    ):
        image_fd_path = f"/proc/self/fd/{image_descriptor}"
        certificate_fd_path = f"/proc/self/fd/{certificate_descriptor}"
        listed = _run_sbverify(
            [_SBVERIFY, "--list", image_fd_path],
            pass_fds=(image_descriptor,),
        )
        signature_output = f"{listed.stdout}\n{listed.stderr}"
        signature_count = len(_SIGNATURE_LINE_RE.findall(signature_output))
        if signature_count != 1:
            raise RuntimeError(
                "signed image must contain exactly one signature; "
                f"found {signature_count}"
            )
        _run_sbverify(
            [
                _SBVERIFY,
                "--cert",
                certificate_fd_path,
                image_fd_path,
            ],
            pass_fds=(certificate_descriptor, image_descriptor),
        )


def _run_sbverify(
    command: list[str], *, pass_fds: tuple[int, ...]
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            pass_fds=pass_fds,
            env=dict(_TRUSTED_TOOL_ENVIRONMENT),
        )
    except OSError as error:
        raise RuntimeError(f"failed to run sbverify: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"sbverify failed with exit code {result.returncode}{suffix}"
        )
    return result

import hashlib
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from refind_forest.loader.verify import (
    PeImage,
    PeSection,
    loaded_section_hashes,
    parse_pe,
    reject_setmem_call_edges,
    verify_pe,
    verify_signed,
)


PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 4 + 20
OPTIONAL_SIZE = 0xF0
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + OPTIONAL_SIZE
FILE_ALIGNMENT = 0x200
SIZE_OF_IMAGE = 0x4000
SECURITY_DIRECTORY_OFFSET = OPTIONAL_OFFSET + 112 + 4 * 8
CERTIFICATE_PAYLOAD = b"CERTIFICATE" + b"\x00" * 5

EXPECTED_SBAT = (
    b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
    b"refind,1,Roderick W. Smith,refind,0.14.2,https://www.rodsbooks.com/refind\n"
    b"refind.forest,1,Local Forest build,refind-forest,0.14.2-abi1,"
    b"https://www.rodsbooks.com/refind\n"
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _section_specs(sbat_payload: bytes) -> list[dict[str, object]]:
    return [
        {
            "name": ".text",
            "data": b"\x90\xc3",
            "virtual_size": 0x100,
            "virtual_address": 0x1000,
            "raw_offset": 0x200,
            "characteristics": 0x60000020,
        },
        {
            "name": ".reloc",
            "data": b"\x00" * 12,
            "virtual_size": 0x100,
            "virtual_address": 0x2000,
            "raw_offset": 0x400,
            "characteristics": 0x42000040,
        },
        {
            "name": ".sbat",
            "data": sbat_payload,
            "virtual_size": len(sbat_payload),
            "virtual_address": 0x3000,
            "raw_offset": 0x600,
            "characteristics": 0x40000040,
        },
    ]


def make_pe_bytes(
    *,
    machine: int = 0x8664,
    optional_magic: int = 0x20B,
    subsystem: int = 10,
    entry_point: int = 0x1000,
    section_names: tuple[str, ...] = (".text", ".reloc", ".sbat"),
    sbat_payload: bytes = EXPECTED_SBAT,
    security_payload: bytes = b"",
) -> bytes:
    specs = [
        spec for spec in _section_specs(sbat_payload) if spec["name"] in section_names
    ]
    raw_end = max(
        (int(spec["raw_offset"]) + FILE_ALIGNMENT for spec in specs),
        default=FILE_ALIGNMENT,
    )
    security_offset = _align(raw_end, 8) if security_payload else 0
    file_size = security_offset + len(security_payload) if security_payload else raw_end

    image = bytearray(file_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, PE_OFFSET)
    image[PE_OFFSET : PE_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        PE_OFFSET + 4,
        machine,
        len(specs),
        0,
        0,
        0,
        OPTIONAL_SIZE,
        0x2022,
    )

    optional = bytearray(OPTIONAL_SIZE)
    struct.pack_into("<H", optional, 0, optional_magic)
    struct.pack_into("<I", optional, 16, entry_point)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, FILE_ALIGNMENT)
    struct.pack_into("<I", optional, 56, SIZE_OF_IMAGE)
    struct.pack_into("<I", optional, 60, FILE_ALIGNMENT)
    struct.pack_into("<H", optional, 68, subsystem)
    directory_offset = 112 if optional_magic == 0x20B else 96
    directory_count_offset = 108 if optional_magic == 0x20B else 92
    struct.pack_into("<I", optional, directory_count_offset, 16)
    if security_payload:
        struct.pack_into(
            "<II",
            optional,
            directory_offset + 4 * 8,
            security_offset,
            len(security_payload),
        )
    image[OPTIONAL_OFFSET : OPTIONAL_OFFSET + OPTIONAL_SIZE] = optional

    for index, spec in enumerate(specs):
        section_offset = SECTION_TABLE_OFFSET + index * 40
        name = str(spec["name"]).encode("ascii")
        image[section_offset : section_offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into(
            "<IIIIIIHHI",
            image,
            section_offset + 8,
            int(spec["virtual_size"]),
            int(spec["virtual_address"]),
            FILE_ALIGNMENT,
            int(spec["raw_offset"]),
            0,
            0,
            0,
            0,
            int(spec["characteristics"]),
        )
        data = bytes(spec["data"])
        if len(data) > FILE_ALIGNMENT:
            raise ValueError("test section payload exceeds its raw allocation")
        raw_offset = int(spec["raw_offset"])
        image[raw_offset : raw_offset + len(data)] = data

    if security_payload:
        image[security_offset : security_offset + len(security_payload)] = security_payload
    return bytes(image)


def _patch_section_u32(
    image: bytearray, section_index: int, field_offset: int, value: int
) -> None:
    struct.pack_into(
        "<I", image, SECTION_TABLE_OFFSET + section_index * 40 + field_offset, value
    )


class PeFixtureTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.directory = Path(self._temporary_directory.name)

    def write_image(self, data: bytes, name: str = "refind_x64.efi") -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path


class DisassemblyVerificationTests(unittest.TestCase):
    def test_rejects_symbolic_setmem_call_edge(self) -> None:
        disassembly = """
0000000000001180 <clear_config>:
    1180: e8 9b b3 02 00        call   2c520 <SetMem>
"""

        with self.assertRaisesRegex(ValueError, "SetMem"):
            reject_setmem_call_edges(disassembly)

    def test_accepts_audited_local_store_sequence(self) -> None:
        disassembly = """
0000000000001180 <clear_config>:
    1180: c6 00 00              movb   $0x0,(%rax)
    1183: 48 83 c0 01           add    $0x1,%rax
    1187: 48 39 d0              cmp    %rdx,%rax
    118a: 75 f4                 jne    1180 <clear_config>
"""

        reject_setmem_call_edges(disassembly)

    def test_rejects_configured_target_in_stripped_disassembly(self) -> None:
        disassembly = """
    1a2: e8 09 79 04 00        callq  47ab0
"""

        with self.assertRaisesRegex(ValueError, "47ab0"):
            reject_setmem_call_edges(disassembly, target_address=0x47AB0)

    def test_rejects_setmem_relocation_after_a_call_placeholder(self) -> None:
        disassembly = """
    1a2: e8 00 00 00 00        call   1a7 <clear_config+0x27>
         1a3: R_X86_64_PLT32 SetMem-0x4
"""

        with self.assertRaisesRegex(ValueError, "SetMem"):
            reject_setmem_call_edges(disassembly)


class PeParsingTests(PeFixtureTestCase):
    def test_parse_exposes_pe_and_section_metadata(self) -> None:
        parsed = parse_pe(self.write_image(make_pe_bytes()))

        self.assertIsInstance(parsed, PeImage)
        self.assertEqual(parsed.machine, 0x8664)
        self.assertEqual(parsed.optional_header_magic, 0x20B)
        self.assertEqual(parsed.subsystem, 10)
        self.assertEqual(parsed.entry_point, 0x1000)
        self.assertIsInstance(parsed.sections[0], PeSection)
        self.assertEqual([section.name for section in parsed.sections], [".text", ".reloc", ".sbat"])

    def test_parse_rejects_a_symlink(self) -> None:
        target = self.write_image(make_pe_bytes())
        link = self.directory / "linked.efi"
        link.symlink_to(target)

        with self.assertRaisesRegex(ValueError, "symbolic link"):
            parse_pe(link)

    def test_parse_rejects_a_fifo_without_a_blocking_open(self) -> None:
        fifo = self.directory / "loader.fifo"
        os.mkfifo(fifo)
        real_open = os.open

        def require_nonblocking_open(open_path: Path, flags: int) -> int:
            self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(open_path, flags)

        with (
            mock.patch.object(os, "open", side_effect=require_nonblocking_open),
            self.assertRaisesRegex(ValueError, "not a regular file"),
        ):
            parse_pe(fifo)

    def test_parse_remains_bound_to_the_inode_opened_before_path_swap(self) -> None:
        path = self.write_image(make_pe_bytes(machine=0x8664), "loader.efi")
        replacement = self.write_image(
            make_pe_bytes(machine=0x14C), "replacement.efi"
        )
        real_path_stat = Path.stat
        real_fstat = os.fstat
        swapped = False
        inspected_via: list[str] = []

        def swap_once() -> None:
            nonlocal swapped
            if not swapped:
                replacement.replace(path)
                swapped = True

        def path_stat_then_swap(
            stat_path: Path, *args: object, **kwargs: object
        ) -> os.stat_result:
            metadata = real_path_stat(stat_path, *args, **kwargs)
            if stat_path == path and kwargs.get("follow_symlinks", True):
                inspected_via.append("path.stat")
                swap_once()
            return metadata

        def fstat_then_swap(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            inspected_via.append("os.fstat")
            swap_once()
            return metadata

        with (
            mock.patch.object(Path, "stat", path_stat_then_swap),
            mock.patch.object(os, "fstat", side_effect=fstat_then_swap),
        ):
            parsed = parse_pe(path)

        self.assertEqual(parsed.machine, 0x8664)
        self.assertEqual(inspected_via[0], "os.fstat")
        self.assertTrue(swapped)
        self.assertEqual(parse_pe(path).machine, 0x14C)

    def test_parse_rejects_a_truncated_image(self) -> None:
        truncated = make_pe_bytes()[: SECTION_TABLE_OFFSET + 10]

        with self.assertRaisesRegex(ValueError, "truncated"):
            parse_pe(self.write_image(truncated))

    def test_parse_rejects_duplicate_section_names(self) -> None:
        image = bytearray(make_pe_bytes())
        second_name_offset = SECTION_TABLE_OFFSET + 40
        image[second_name_offset : second_name_offset + 8] = b".text\x00\x00\x00"

        with self.assertRaisesRegex(ValueError, "duplicate section"):
            parse_pe(self.write_image(image))

    def test_parse_rejects_raw_data_outside_the_file(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 0, 20, len(image))

        with self.assertRaisesRegex(ValueError, "raw data"):
            parse_pe(self.write_image(image))

    def test_parse_rejects_overlapping_raw_sections(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 1, 20, 0x200)

        with self.assertRaisesRegex(ValueError, "raw.*overlap"):
            parse_pe(self.write_image(image))

    def test_parse_rejects_an_rva_outside_the_image(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 2, 12, SIZE_OF_IMAGE)

        with self.assertRaisesRegex(ValueError, "RVA"):
            parse_pe(self.write_image(image))

    def test_parse_rejects_overlapping_rva_sections(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 1, 12, 0x1000)

        with self.assertRaisesRegex(ValueError, "RVA.*overlap"):
            parse_pe(self.write_image(image))


class PeAlignmentTests(PeFixtureTestCase):
    def test_rejects_zero_file_alignment(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 36, 0)

        with self.assertRaisesRegex(ValueError, "FileAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_zero_section_alignment(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 32, 0)

        with self.assertRaisesRegex(ValueError, "SectionAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_non_power_of_two_file_alignment(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 36, 0x300)

        with self.assertRaisesRegex(ValueError, "FileAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_non_power_of_two_section_alignment(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 32, 0x1800)

        with self.assertRaisesRegex(ValueError, "SectionAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_file_alignment_below_minimum(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 36, 0x100)

        with self.assertRaisesRegex(ValueError, "FileAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_file_alignment_above_maximum(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 36, 0x20000)

        with self.assertRaisesRegex(ValueError, "FileAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_section_alignment_below_file_alignment(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 32, 0x100)

        with self.assertRaisesRegex(ValueError, "SectionAlignment"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_size_of_headers(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 60, FILE_ALIGNMENT + 1)

        with self.assertRaisesRegex(ValueError, "SizeOfHeaders"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_section_raw_offset(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 0, 20, FILE_ALIGNMENT + 1)

        with self.assertRaisesRegex(ValueError, "raw offset"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_section_raw_size(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 0, 16, FILE_ALIGNMENT + 1)

        with self.assertRaisesRegex(ValueError, "raw size"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_section_virtual_address(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 1, 12, 0x2100)

        with self.assertRaisesRegex(ValueError, "virtual address"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_size_of_image(self) -> None:
        image = bytearray(make_pe_bytes())
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 56, SIZE_OF_IMAGE + 1)

        with self.assertRaisesRegex(ValueError, "SizeOfImage"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_security_directory_offset(self) -> None:
        image = bytearray(make_pe_bytes(security_payload=CERTIFICATE_PAYLOAD))
        struct.pack_into("<II", image, SECURITY_DIRECTORY_OFFSET, 0x801, 8)

        with self.assertRaisesRegex(ValueError, "security.*offset"):
            parse_pe(self.write_image(image))

    def test_rejects_unaligned_security_directory_size(self) -> None:
        image = make_pe_bytes(security_payload=b"certificate")

        with self.assertRaisesRegex(ValueError, "security.*size"):
            parse_pe(self.write_image(image))


class PePolicyVerificationTests(PeFixtureTestCase):
    def test_accepts_the_required_uefi_image_policy(self) -> None:
        parsed = verify_pe(self.write_image(make_pe_bytes()), EXPECTED_SBAT)

        self.assertIsInstance(parsed, PeImage)

    def test_rejects_a_non_x86_64_machine(self) -> None:
        path = self.write_image(make_pe_bytes(machine=0x14C))

        with self.assertRaisesRegex(ValueError, "machine"):
            verify_pe(path, EXPECTED_SBAT)

    def test_rejects_a_non_pe32_plus_optional_header(self) -> None:
        path = self.write_image(make_pe_bytes(optional_magic=0x10B))

        with self.assertRaisesRegex(ValueError, r"PE32\+"):
            verify_pe(path, EXPECTED_SBAT)

    def test_rejects_a_non_efi_application_subsystem(self) -> None:
        path = self.write_image(make_pe_bytes(subsystem=3))

        with self.assertRaisesRegex(ValueError, "subsystem"):
            verify_pe(path, EXPECTED_SBAT)

    def test_rejects_an_entry_point_in_a_non_executable_section(self) -> None:
        path = self.write_image(make_pe_bytes(entry_point=0x2000))

        with self.assertRaisesRegex(ValueError, "entry point"):
            verify_pe(path, EXPECTED_SBAT)

    def test_rejects_an_rwx_section(self) -> None:
        image = bytearray(make_pe_bytes())
        _patch_section_u32(image, 0, 36, 0xE0000020)

        with self.assertRaisesRegex(ValueError, "RWX"):
            verify_pe(self.write_image(image), EXPECTED_SBAT)

    def test_requires_a_relocation_section(self) -> None:
        path = self.write_image(make_pe_bytes(section_names=(".text", ".sbat")))

        with self.assertRaisesRegex(ValueError, r"\.reloc"):
            verify_pe(path, EXPECTED_SBAT)

    def test_requires_an_sbat_section(self) -> None:
        path = self.write_image(make_pe_bytes(section_names=(".text", ".reloc")))

        with self.assertRaisesRegex(ValueError, r"\.sbat"):
            verify_pe(path, EXPECTED_SBAT)

    def test_accepts_zero_padding_after_the_expected_sbat(self) -> None:
        verify_pe(self.write_image(make_pe_bytes()), EXPECTED_SBAT)

    def test_rejects_changed_sbat_content(self) -> None:
        changed = EXPECTED_SBAT.replace(b"Local Forest", b"Other Forest")
        path = self.write_image(make_pe_bytes(sbat_payload=changed))

        with self.assertRaisesRegex(ValueError, "SBAT"):
            verify_pe(path, EXPECTED_SBAT)

    def test_rejects_nonzero_data_after_the_expected_sbat(self) -> None:
        path = self.write_image(make_pe_bytes(sbat_payload=EXPECTED_SBAT + b"X"))

        with self.assertRaisesRegex(ValueError, "SBAT"):
            verify_pe(path, EXPECTED_SBAT)


class LoadedSectionHashTests(PeFixtureTestCase):
    def assert_only_load_metadata_hash_changes(
        self, original_data: bytes, modified_data: bytes
    ) -> None:
        original = loaded_section_hashes(
            self.write_image(original_data, "original.efi")
        )
        modified = loaded_section_hashes(
            self.write_image(modified_data, "modified.efi")
        )
        original_metadata = original.pop("__pe_load_metadata__")
        modified_metadata = modified.pop("__pe_load_metadata__")

        self.assertEqual(original, modified)
        self.assertNotEqual(original_metadata, modified_metadata)

    def test_signed_and_unsigned_images_have_the_same_loaded_section_hashes(self) -> None:
        unsigned = self.write_image(make_pe_bytes(), "unsigned.efi")
        signed = self.write_image(
            make_pe_bytes(security_payload=CERTIFICATE_PAYLOAD), "signed.efi"
        )

        self.assertEqual(
            loaded_section_hashes(unsigned), loaded_section_hashes(signed)
        )

    def test_security_directory_is_not_hashed_as_a_loaded_section(self) -> None:
        certificate = CERTIFICATE_PAYLOAD
        signed = self.write_image(
            make_pe_bytes(security_payload=certificate), "signed.efi"
        )

        hashes = loaded_section_hashes(signed)

        self.assertEqual(
            set(hashes),
            {"__pe_load_metadata__", ".text", ".reloc", ".sbat"},
        )
        self.assertNotIn(hashlib.sha256(certificate).hexdigest(), hashes.values())

    def test_entry_point_changes_the_load_metadata_hash(self) -> None:
        self.assert_only_load_metadata_hash_changes(
            make_pe_bytes(), make_pe_bytes(entry_point=0x1001)
        )

    def test_section_virtual_address_changes_the_load_metadata_hash(self) -> None:
        modified = bytearray(make_pe_bytes())
        _patch_section_u32(modified, 1, 12, 0x3000)
        _patch_section_u32(modified, 2, 12, 0x2000)

        self.assert_only_load_metadata_hash_changes(make_pe_bytes(), modified)

    def test_section_flags_change_the_load_metadata_hash(self) -> None:
        modified = bytearray(make_pe_bytes())
        _patch_section_u32(modified, 1, 36, 0x40000040)

        self.assert_only_load_metadata_hash_changes(make_pe_bytes(), modified)


class SignedImageVerificationTests(PeFixtureTestCase):
    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_reports_an_sbverify_subprocess_start_failure(self, run: mock.Mock) -> None:
        binary = self.write_image(b"signed image")
        certificate = self.write_image(b"certificate", "signing.pem")
        run.side_effect = FileNotFoundError(2, "missing sbverify")

        with self.assertRaisesRegex(RuntimeError, "failed to run sbverify"):
            verify_signed(binary, certificate)

        self.assertEqual(run.call_count, 1)

    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_binds_both_sbverify_calls_to_the_opened_files(
        self, run: mock.Mock
    ) -> None:
        binary = self.write_image(b"original signed image", "signed image.efi")
        certificate = self.write_image(b"original certificate", "signing cert.pem")
        replacement_binary = self.write_image(
            b"replacement image", "replacement.efi"
        )
        replacement_certificate = self.write_image(
            b"replacement certificate", "replacement.pem"
        )
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run_sbverify(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append((command, kwargs))
            for descriptor in kwargs["pass_fds"]:
                os.fstat(descriptor)
            if command[1] == "--list":
                replacement_binary.replace(binary)
                replacement_certificate.replace(certificate)
                self.assertEqual(
                    Path(command[2]).read_bytes(), b"original signed image"
                )
                return subprocess.CompletedProcess(command, 0, "signature 1\n", "")
            self.assertEqual(
                Path(command[2]).read_bytes(), b"original certificate"
            )
            self.assertEqual(
                Path(command[3]).read_bytes(), b"original signed image"
            )
            return subprocess.CompletedProcess(command, 0, "verification OK", "")

        run.side_effect = run_sbverify

        verify_signed(binary, certificate)

        self.assertEqual(len(calls), 2)
        list_command, list_kwargs = calls[0]
        verify_command, verify_kwargs = calls[1]
        self.assertEqual(list_command[:2], ["/usr/bin/sbverify", "--list"])
        self.assertRegex(list_command[2], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(verify_command[:2], ["/usr/bin/sbverify", "--cert"])
        self.assertRegex(verify_command[2], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(verify_command[3], list_command[2])
        self.assertEqual(
            set(list_kwargs["pass_fds"]),
            {int(list_command[2].rsplit("/", 1)[1])},
        )
        self.assertEqual(
            set(verify_kwargs["pass_fds"]),
            {
                int(verify_command[2].rsplit("/", 1)[1]),
                int(verify_command[3].rsplit("/", 1)[1]),
            },
        )
        for kwargs in (list_kwargs, verify_kwargs):
            self.assertEqual(kwargs["check"], False)
            self.assertEqual(kwargs["capture_output"], True)
            self.assertEqual(kwargs["text"], True)
            self.assertEqual(
                kwargs["env"],
                {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            )

    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_rejects_an_image_with_no_signatures(self, run: mock.Mock) -> None:
        binary = self.write_image(b"unsigned image")
        certificate = self.write_image(b"certificate", "signing.pem")
        run.return_value = subprocess.CompletedProcess(
            [], 0, "No signatures found\n", ""
        )

        with self.assertRaisesRegex(RuntimeError, "exactly one signature.*found 0"):
            verify_signed(binary, certificate)

        self.assertEqual(run.call_count, 1)

    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_rejects_an_image_with_multiple_signatures(self, run: mock.Mock) -> None:
        binary = self.write_image(b"multiply signed image")
        certificate = self.write_image(b"certificate", "signing.pem")
        run.return_value = subprocess.CompletedProcess(
            [],
            0,
            "signature 1\ncertificate details\nsignature 2\n",
            "",
        )

        with self.assertRaisesRegex(RuntimeError, "exactly one signature.*found 2"):
            verify_signed(binary, certificate)

        self.assertEqual(run.call_count, 1)

    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_reports_a_failed_signature_listing(self, run: mock.Mock) -> None:
        binary = self.write_image(b"bad image")
        certificate = self.write_image(b"certificate", "signing.pem")
        run.return_value = subprocess.CompletedProcess(
            [], 1, "", "Signature verification failed"
        )

        with self.assertRaisesRegex(
            RuntimeError, "sbverify failed with exit code 1.*Signature verification failed"
        ):
            verify_signed(binary, certificate)

        self.assertEqual(run.call_count, 1)

    @mock.patch("refind_forest.loader.verify.subprocess.run")
    def test_reports_a_failed_certificate_verification(self, run: mock.Mock) -> None:
        binary = self.write_image(b"bad signed image")
        certificate = self.write_image(b"certificate", "signing.pem")
        run.side_effect = (
            subprocess.CompletedProcess([], 0, "signature 1\n", ""),
            subprocess.CompletedProcess(
                [], 1, "", "Signature verification failed"
            ),
        )

        with self.assertRaisesRegex(
            RuntimeError, "sbverify failed with exit code 1.*Signature verification failed"
        ):
            verify_signed(binary, certificate)

        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()

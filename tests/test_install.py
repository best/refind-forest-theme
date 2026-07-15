import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image

import refind_forest.install as install_module
from refind_forest.build import build_package
from refind_forest.install import install, rollback, switch_theme, verify


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UBUNTU_SOURCE = PROJECT_ROOT / "assets" / "source" / "ubuntu-logo.png"
ORIGINAL_REFIND_CONF = b"timeout 20\nuse_nvram false\n"
PUBLIC_NOTICE_PATHS = {
    "LICENSE",
    "LICENSES/CC-BY-SA-4.0.txt",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
}


def _fat_boot_sector(fat_type: str, label: bytes) -> bytes:
    boot_sector = bytearray(512)
    boot_sector[510:512] = b"\x55\xaa"
    if fat_type == "FAT32":
        boot_sector[66] = 0x29
        boot_sector[67:71] = bytes.fromhex("44332211")
        boot_sector[71:82] = label.ljust(11, b" ")
        boot_sector[82:90] = b"FAT32   "
    else:
        boot_sector[38] = 0x29
        boot_sector[39:43] = bytes.fromhex("44332211")
        boot_sector[43:54] = label.ljust(11, b" ")
        boot_sector[54:62] = fat_type.encode("ascii").ljust(8, b" ")
    return bytes(boot_sector)


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _tree_entries(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): "directory" if path.is_dir() else "file"
        for path in root.rglob("*")
    }


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.esp = self.root / "esp"
        refind = self.esp / "EFI" / "refind"
        ubuntu = self.esp / "EFI" / "ubuntu"
        microsoft = self.esp / "EFI" / "Microsoft" / "Boot"
        refind.mkdir(parents=True)
        ubuntu.mkdir(parents=True)
        microsoft.mkdir(parents=True)
        (refind / "refind_x64.efi").write_bytes(b"fake rEFInd loader")
        (refind / "refind.conf").write_bytes(ORIGINAL_REFIND_CONF)
        (ubuntu / "grubx64.efi").write_bytes(b"fake Ubuntu loader")
        (microsoft / "bootmgfw.efi").write_bytes(b"fake Windows loader")
        self.staging = self.root / "staging"
        build_package(self.staging, UBUNTU_SOURCE, "TEST-ESP")
        self.backup_root = self.root / "backups"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_install_does_not_copy_package_notices_to_esp(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )

        for relative in PUBLIC_NOTICE_PATHS:
            self.assertFalse((self.esp / relative).exists())

    def test_tampered_package_notice_is_rejected_before_side_effects(self) -> None:
        (self.staging / "THIRD_PARTY_NOTICES.md").write_bytes(b"tampered notice")
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_invalid_package_notice_trees_are_rejected_before_side_effects(
        self,
    ) -> None:
        cases = ("missing", "extra", "symlink")
        for name in cases:
            with self.subTest(name=name):
                staging = self.root / f"staging-{name}"
                shutil.copytree(self.staging, staging)
                if name == "missing":
                    (staging / "LICENSE").unlink()
                elif name == "extra":
                    (staging / "LICENSES" / "unexpected.txt").write_bytes(b"extra")
                else:
                    notice = staging / "TRADEMARKS.md"
                    notice.unlink()
                    notice.symlink_to(PROJECT_ROOT / "TRADEMARKS.md")
                before = _file_bytes(self.esp)

                with self.assertRaises(RuntimeError):
                    install(
                        staging,
                        self.esp,
                        self.backup_root,
                        require_root=False,
                    )

                self.assertEqual(_file_bytes(self.esp), before)
                self.assertFalse(self.backup_root.exists())

    def test_package_notice_parent_swap_is_rejected_before_side_effects(
        self,
    ) -> None:
        original = self.staging / "LICENSES"
        outside = self.root / "outside-licenses"
        outside.mkdir()
        shutil.copy2(
            original / "CC-BY-SA-4.0.txt",
            outside / "CC-BY-SA-4.0.txt",
        )
        before = _file_bytes(self.esp)
        real_open = install_module.os.open
        swapped = False

        def swap_license_directory(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal swapped
            if path == "LICENSES" and kwargs.get("dir_fd") is not None and not swapped:
                original.rename(self.staging / "LICENSES-original")
                original.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, *args, **kwargs)

        with patch.object(
            install_module.os,
            "open",
            side_effect=swap_license_directory,
        ):
            with self.assertRaisesRegex(RuntimeError, "without following links"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertTrue(swapped)
        self.assertTrue(original.is_symlink())
        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_discovers_fat32_label_from_exact_injected_vfat_mount(self) -> None:
        source = Path("/dev/fake-esp")
        device = self.esp.stat().st_dev
        device_field = f"{os.major(device)}:{os.minor(device)}"
        mountinfo = (
            f"36 25 {device_field} / {self.esp.resolve()} rw,relatime - "
            f"vfat {source} rw\n"
        )
        sources = []

        def read_device(requested: Path) -> bytes:
            sources.append(requested)
            return _fat_boot_sector("FAT32", b"TEST-ESP")

        with (
            patch.object(install_module.os, "geteuid", return_value=0),
            patch.object(install_module, "_validate_bound_block_device"),
        ):
            label = install_module.discover_esp_label(
                self.esp,
                mountinfo_reader=lambda: mountinfo,
                device_reader=read_device,
            )

        self.assertEqual(label, "TEST-ESP")
        self.assertEqual(sources, [source])

    def test_mounted_vfat_source_selects_visible_overmount_device(self) -> None:
        esp = self.esp.resolve()
        lower_source = Path("/dev/fake-lower-esp")
        visible_source = Path("/dev/fake-visible-esp")
        mountinfo = (
            f"36 25 259:1 / {esp} rw,relatime - vfat {lower_source} rw\n"
            f"37 25 259:2 / {esp} rw,relatime - vfat {visible_source} rw\n"
        )

        with (
            patch.object(
                install_module.os,
                "stat",
                return_value=SimpleNamespace(st_dev=os.makedev(259, 2)),
            ),
            patch.object(install_module, "_validate_bound_block_device"),
        ):
            source = install_module._mounted_vfat_source(esp, mountinfo)

        self.assertEqual(source.source, visible_source)
        self.assertEqual(source.major_minor, "259:2")

    def test_mounted_vfat_source_rejects_unbound_or_ambiguous_mounts(self) -> None:
        esp = self.esp.resolve()
        visible_device = SimpleNamespace(st_dev=os.makedev(259, 2))
        unbound = f"36 25 259:1 / {esp} rw - vfat /dev/fake-lower-esp rw\n"
        ambiguous = (
            f"36 25 259:2 / {esp} rw - vfat /dev/fake-visible-a rw\n"
            f"37 25 259:2 / {esp} rw - vfat /dev/fake-visible-b rw\n"
        )

        with patch.object(install_module.os, "stat", return_value=visible_device):
            with self.assertRaisesRegex(RuntimeError, "visible device"):
                install_module._mounted_vfat_source(esp, unbound)
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                install_module._mounted_vfat_source(esp, ambiguous)

    def test_mounted_vfat_source_rejects_regular_file_source(self) -> None:
        esp = self.esp.resolve()
        source = self.root / "regular-source"
        source.write_bytes(_fat_boot_sector("FAT32", b"TEST-ESP"))
        device = esp.stat().st_dev
        device_field = f"{os.major(device)}:{os.minor(device)}"
        mountinfo = (
            f"36 25 {device_field} / {esp} rw - vfat {source.resolve()} rw\n"
        )

        with self.assertRaisesRegex(RuntimeError, "block device"):
            install_module._mounted_vfat_source(esp, mountinfo)

    def test_mounted_vfat_source_rejects_rebound_device_node(self) -> None:
        esp = self.esp.resolve()
        source = Path("/dev/fake-visible-esp")
        mountinfo = f"36 25 259:2 / {esp} rw - vfat {source} rw\n"

        with (
            patch.object(
                install_module.os,
                "stat",
                return_value=SimpleNamespace(st_dev=os.makedev(259, 2)),
            ),
            patch.object(install_module.os, "open", return_value=91),
            patch.object(
                install_module.os,
                "fstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFBLK,
                    st_rdev=os.makedev(259, 3),
                ),
            ),
            patch.object(install_module.os, "close"),
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match mountinfo"):
                install_module._mounted_vfat_source(esp, mountinfo)

    def test_mounted_vfat_source_rejects_nested_refind_mount(self) -> None:
        esp = self.esp.resolve()
        source = Path("/dev/fake-visible-esp")
        mountinfo = (
            f"36 25 259:2 / {esp} rw - vfat {source} rw\n"
            f"37 36 259:2 /subtree {esp / 'EFI' / 'refind'} rw - "
            f"vfat {source} rw\n"
        )

        with (
            patch.object(
                install_module.os,
                "stat",
                return_value=SimpleNamespace(st_dev=os.makedev(259, 2)),
            ),
            patch.object(install_module, "_validate_bound_block_device"),
        ):
            with self.assertRaisesRegex(RuntimeError, "nested mount"):
                install_module._mounted_vfat_source(esp, mountinfo)

    def test_reads_safe_fat12_and_fat16_volume_labels(self) -> None:
        for fat_type in ("FAT12", "FAT16"):
            with self.subTest(fat_type=fat_type):
                self.assertEqual(
                    install_module._parse_fat_volume_label(
                        _fat_boot_sector(fat_type, b"SAFE-LABEL")
                    ),
                    "SAFE-LABEL",
                )

    def test_parses_fat_volume_serial_from_all_supported_boot_sectors(self) -> None:
        parser = getattr(install_module, "_parse_fat_volume_identity", None)
        self.assertIsNotNone(parser)
        for fat_type in ("FAT12", "FAT16", "FAT32"):
            with self.subTest(fat_type=fat_type):
                self.assertEqual(
                    parser(_fat_boot_sector(fat_type, b"TEST-ESP")),
                    ("1122-3344", "TEST-ESP"),
                )

    def test_rejects_zero_fat_volume_serial(self) -> None:
        boot_sector = bytearray(_fat_boot_sector("FAT32", b"TEST-ESP"))
        boot_sector[67:71] = b"\0\0\0\0"

        with self.assertRaisesRegex(RuntimeError, "serial"):
            install_module._parse_fat_volume_identity(bytes(boot_sector))

    def test_rejects_invalid_fat_boot_sectors_and_volume_labels(self) -> None:
        bad_signature = bytearray(_fat_boot_sector("FAT32", b"TEST-ESP"))
        bad_signature[510:512] = b"\0\0"
        bad_type = bytearray(_fat_boot_sector("FAT32", b"TEST-ESP"))
        bad_type[82:90] = b"NOTFAT  "
        cases = {
            "signature": bytes(bad_signature),
            "type": bytes(bad_type),
            "NO NAME": _fat_boot_sector("FAT32", b"NO NAME"),
            "unsafe": _fat_boot_sector("FAT16", b"BAD LABEL"),
        }

        for message, boot_sector in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    install_module._parse_fat_volume_label(boot_sector)

    def test_install_rejects_mismatched_physical_esp_label_before_backup(self) -> None:
        before = _file_bytes(self.esp)
        with (
            patch.object(
                install_module,
                "_require_root",
                return_value=install_module._MountedVfatSource(
                    Path("/dev/fake-esp"),
                    os.makedev(259, 2),
                ),
            ),
            patch.object(
                install_module,
                "_read_fat_volume_identity",
                return_value=("1122-3344", "OTHER"),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "staging ESP label TEST-ESP does not match mounted ESP label OTHER",
            ):
                install(self.staging, self.esp, self.backup_root)

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_install_switch_and_rollback_restore_original_esp(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )

        refind = self.esp / "EFI" / "refind"
        refind_conf = (refind / "refind.conf").read_text(encoding="ascii")
        installed_manifest = json.loads(
            (refind / "forest-manifest.json").read_text(encoding="ascii")
        )
        self.assertEqual(installed_manifest["format"], 1)
        self.assertNotIn("notices", installed_manifest)
        self.assertEqual(refind_conf.count("include theme-active.conf"), 1)
        self.assertEqual(
            (refind / "theme-active.conf").read_bytes(),
            (refind / "theme-a.conf").read_bytes(),
        )
        self.assertEqual(verify(self.esp), [])

        switch_theme("b", self.esp, require_root=False)

        self.assertEqual(
            (refind / "theme-active.conf").read_bytes(),
            (refind / "theme-b.conf").read_bytes(),
        )
        self.assertEqual(verify(self.esp), [])

        rollback(backup, self.esp, require_root=False)

        self.assertEqual((refind / "refind.conf").read_bytes(), ORIGINAL_REFIND_CONF)
        self.assertFalse((refind / "themes" / "forest-a").exists())

    def test_rollback_removes_themes_parent_created_by_install(self) -> None:
        before = _tree_entries(self.esp)
        themes = self.esp / "EFI" / "refind" / "themes"
        self.assertFalse(themes.exists())

        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        rollback(backup, self.esp, require_root=False)

        self.assertEqual(_tree_entries(self.esp), before)
        self.assertFalse(themes.exists())

    def test_rollback_preserves_preexisting_themes_parent_and_unrelated_data(
        self,
    ) -> None:
        themes = self.esp / "EFI" / "refind" / "themes"
        unrelated = themes / "custom" / "keep.bin"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_bytes(b"unrelated theme data")
        before_entries = _tree_entries(self.esp)
        before_files = _file_bytes(self.esp)

        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        rollback(backup, self.esp, require_root=False)

        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertTrue(themes.is_dir())

    def test_rollback_uses_recovery_specific_loader_config_and_space_preflight(
        self,
    ) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        windows_loader = self.esp / "EFI" / "Microsoft" / "Boot" / "bootmgfw.efi"
        windows_loader.unlink()
        (refind / "refind.conf").unlink()
        restoration_bytes = sum(
            path.stat().st_size
            for path in (backup / "original").rglob("*")
            if path.is_file()
        )
        free_bytes = restoration_bytes + 2 * 1024 * 1024
        self.assertLess(free_bytes, 32 * 1024 * 1024)

        with patch.object(
            install_module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=free_bytes),
        ):
            rollback(backup, self.esp, require_root=False)

        self.assertEqual((refind / "refind.conf").read_bytes(), ORIGINAL_REFIND_CONF)
        self.assertFalse((refind / "themes" / "forest-a").exists())
        self.assertFalse(windows_loader.exists())

    def test_missing_windows_loader_rejected_without_side_effects(self) -> None:
        missing_loader = self.esp / "EFI" / "Microsoft" / "Boot" / "bootmgfw.efi"
        missing_loader.unlink()
        before = {
            path.relative_to(self.esp).as_posix(): path.read_bytes()
            for path in self.esp.rglob("*")
            if path.is_file()
        }

        with self.assertRaisesRegex(RuntimeError, "bootmgfw[.]efi"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        after = {
            path.relative_to(self.esp).as_posix(): path.read_bytes()
            for path in self.esp.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)
        self.assertFalse(self.backup_root.exists())

    def test_verify_reports_installed_icon_hash_mismatch(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        icon = (
            self.esp
            / "EFI"
            / "refind"
            / "themes"
            / "forest-a"
            / "icons"
            / "os_win.png"
        )
        icon.write_bytes(b"broken")

        self.assertTrue(any("os_win.png" in error for error in verify(self.esp)))

    def test_backup_root_inside_esp_is_rejected_before_side_effects(self) -> None:
        before = _file_bytes(self.esp)
        backup_root = self.esp / "backups"

        with self.assertRaisesRegex(RuntimeError, "backup.*outside.*ESP"):
            install(
                self.staging,
                self.esp,
                backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(backup_root.exists())

    def test_verify_rejects_symlinked_installed_manifest(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        manifest = self.esp / "EFI" / "refind" / "forest-manifest.json"
        outside = self.root / "outside-manifest.json"
        manifest.rename(outside)
        manifest.symlink_to(outside)

        errors = verify(self.esp)

        self.assertTrue(
            any(
                "forest-manifest.json" in error and "symbolic link" in error
                for error in errors
            )
        )

    def test_verify_rejects_symlinked_refind_config(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        config = self.esp / "EFI" / "refind" / "refind.conf"
        outside = self.root / "outside-refind.conf"
        config.rename(outside)
        config.symlink_to(outside)

        errors = verify(self.esp)

        self.assertTrue(
            any(
                "refind.conf" in error and "symbolic link" in error
                for error in errors
            )
        )

    def test_rollback_restores_preexisting_managed_directory_exactly(self) -> None:
        managed = self.esp / "EFI" / "refind" / "forest-manifest.json"
        managed.mkdir()
        sentinel = managed / "nested" / "sentinel.bin"
        sentinel.parent.mkdir()
        sentinel.write_bytes(b"preexisting Forest data")

        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        self.assertTrue(managed.is_file())

        rollback(backup, self.esp, require_root=False)

        self.assertTrue(managed.is_dir())
        self.assertEqual(sentinel.read_bytes(), b"preexisting Forest data")

    def test_install_copy_failure_automatically_restores_fake_esp(self) -> None:
        before = _file_bytes(self.esp)
        real_atomic_write = install_module._atomic_write
        failure_injected = False

        def fail_once(target: Path, data: bytes) -> None:
            nonlocal failure_injected
            if (
                not failure_injected
                and target.name == "os_win.png"
                and "forest-a" in target.parts
            ):
                failure_injected = True
                raise RuntimeError("injected install copy failure")
            real_atomic_write(target, data)

        with patch.object(install_module, "_atomic_write", side_effect=fail_once):
            with self.assertRaisesRegex(RuntimeError, "injected install copy failure"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertTrue(failure_injected)
        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(
            (self.esp / "EFI" / "refind" / "themes" / "forest-a").exists()
        )
        self.assertEqual(len(list(self.backup_root.iterdir())), 1)

    def test_install_keyboard_interrupt_restores_fake_esp_and_reraises(self) -> None:
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        refind = self.esp / "EFI" / "refind"
        real_atomic_write = install_module._atomic_write
        interrupted = False

        def interrupt_after_first_target_write(target: Path, data: bytes) -> None:
            nonlocal interrupted
            if not interrupted and target == refind / "theme-b.conf":
                interrupted = True
                raise KeyboardInterrupt("injected install interruption")
            real_atomic_write(target, data)

        with patch.object(
            install_module,
            "_atomic_write",
            side_effect=interrupt_after_first_target_write,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "install interruption"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertTrue(interrupted)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_install_verification_failure_automatically_restores_fake_esp(self) -> None:
        before = _file_bytes(self.esp)

        with patch.object(
            install_module,
            "verify",
            return_value=["injected verification failure"],
        ):
            with self.assertRaisesRegex(RuntimeError, "injected verification failure"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertEqual(_file_bytes(self.esp), before)

    def test_install_validates_created_backup_before_target_mutation(self) -> None:
        before = _file_bytes(self.esp)
        real_create_backup = install_module._create_backup

        def create_tampered_backup(
            esp: Path,
            backup_root: Path,
            **kwargs: object,
        ) -> Path:
            backup = real_create_backup(esp, backup_root, **kwargs)
            (backup / "backup.json").write_text("not json", encoding="ascii")
            return backup

        with patch.object(
            install_module,
            "_create_backup",
            side_effect=create_tampered_backup,
        ):
            with self.assertRaisesRegex(RuntimeError, "backup.json"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertEqual(_file_bytes(self.esp), before)

    def test_backup_cleanup_does_not_replace_primary_interrupt(self) -> None:
        primary_error = KeyboardInterrupt("injected backup interruption")
        cleanup_error = SystemExit("injected backup cleanup exit")
        real_copy_atomic = install_module._copy_atomic

        def interrupt_backup_copy(source: Path, target: Path) -> None:
            if target.name == "refind.conf" and target.parent.name == "original":
                raise primary_error
            real_copy_atomic(source, target)

        caught: BaseException | None = None
        with (
            patch.object(
                install_module,
                "_copy_atomic",
                side_effect=interrupt_backup_copy,
            ),
            patch.object(
                install_module.shutil,
                "rmtree",
                side_effect=cleanup_error,
            ),
        ):
            try:
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )
            except BaseException as error:
                caught = error

        self.assertIs(caught, primary_error)
        assert caught is not None
        self.assertIn(
            "SystemExit: injected backup cleanup exit",
            "\n".join(caught.__notes__),
        )

    def test_install_uses_validated_snapshot_after_staging_path_changes(self) -> None:
        staged_config = self.staging / "EFI" / "refind" / "theme-a.conf"
        validated_bytes = staged_config.read_bytes()
        real_create_backup = install_module._create_backup

        def create_backup_then_replace_staging(
            esp: Path,
            backup_root: Path,
            **kwargs: object,
        ) -> Path:
            backup = real_create_backup(esp, backup_root, **kwargs)
            staged_config.write_bytes(b"unvalidated replacement")
            return backup

        with patch.object(
            install_module,
            "_create_backup",
            side_effect=create_backup_then_replace_staging,
        ):
            backup = install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        installed_config = self.esp / "EFI" / "refind" / "theme-a.conf"
        self.assertEqual(installed_config.read_bytes(), validated_bytes)
        self.assertEqual(verify(self.esp), [])
        rollback(backup, self.esp, require_root=False)

    def test_tampered_staging_is_rejected_before_side_effects(self) -> None:
        (self.staging / "EFI" / "refind" / "theme-a.conf").write_bytes(
            b"tampered staging"
        )
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "owned Forest build"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_staging_symlink_is_rejected_before_side_effects(self) -> None:
        link = self.staging / "EFI" / "refind" / "unlisted-link"
        link.symlink_to(self.esp / "EFI" / "refind" / "refind.conf")
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "symbolic link"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_unmanifested_staging_file_is_rejected_before_side_effects(self) -> None:
        (self.staging / "EFI" / "outside-refind.bin").write_bytes(b"unowned")
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "exact staging tree"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_target_symlink_is_rejected_before_side_effects(self) -> None:
        outside = self.root / "outside-themes"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"do not follow")
        themes = self.esp / "EFI" / "refind" / "themes"
        themes.symlink_to(outside, target_is_directory=True)
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "symbolic link"):
            install(
                self.staging,
                self.esp,
                self.backup_root,
                require_root=False,
            )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertEqual(sentinel.read_bytes(), b"do not follow")
        self.assertFalse(self.backup_root.exists())

    def test_low_space_is_rejected_before_side_effects(self) -> None:
        before = _file_bytes(self.esp)

        with patch.object(
            install_module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=32 * 1024 * 1024 - 1),
        ):
            with self.assertRaisesRegex(RuntimeError, "32 MiB"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_install_rejects_refind_on_different_device_before_side_effects(
        self,
    ) -> None:
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        refind = (self.esp / "EFI" / "refind").resolve()
        real_stat = os.stat

        def cross_device_stat(
            path: object,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            result = real_stat(path, *args, **kwargs)
            if Path(path) == refind:
                fields = list(result)
                fields[2] = os.makedev(259, 99)
                return os.stat_result(fields)
            return result

        with patch.object(install_module.os, "stat", side_effect=cross_device_stat):
            with self.assertRaisesRegex(RuntimeError, "different filesystem"):
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )

        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(self.backup_root.exists())

    def test_root_mount_validation_precedes_side_effects(self) -> None:
        before = _file_bytes(self.esp)

        with self.assertRaises((PermissionError, RuntimeError)):
            install(self.staging, self.esp, self.backup_root)

        self.assertEqual(_file_bytes(self.esp), before)
        self.assertFalse(self.backup_root.exists())

    def test_malformed_traversal_and_wrong_esp_backups_do_not_mutate_target(
        self,
    ) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        installed = _file_bytes(self.esp)
        base_record = json.loads((backup / "backup.json").read_text(encoding="ascii"))
        cases = {
            "malformed": None,
            "traversal": {**base_record, "managed": ["../escape"]},
            "wrong ESP": {**base_record, "esp": str(self.root / "different-esp")},
        }

        for index, (name, record) in enumerate(cases.items()):
            with self.subTest(name=name):
                candidate = self.root / f"backup-case-{index}"
                shutil.copytree(backup, candidate)
                if record is None:
                    (candidate / "backup.json").write_text("not json", encoding="ascii")
                else:
                    (candidate / "backup.json").write_text(
                        json.dumps(record),
                        encoding="ascii",
                    )

                with self.assertRaises(RuntimeError):
                    rollback(candidate, self.esp, require_root=False)

                self.assertEqual(_file_bytes(self.esp), installed)

    def test_rollback_rejects_swapped_esp_identity_before_target_mutation(
        self,
    ) -> None:
        source = install_module._MountedVfatSource(
            Path("/dev/fake-esp"),
            os.makedev(259, 2),
        )
        identities = iter(
            [
                ("1122-3344", "TEST-ESP"),
                ("DEAD-BEEF", "TEST-ESP"),
            ]
        )
        with (
            patch.object(install_module, "_require_root", return_value=source),
            patch.object(
                install_module,
                "_read_fat_volume_label",
                return_value="TEST-ESP",
            ),
            patch.object(
                install_module,
                "_read_fat_volume_identity",
                side_effect=lambda *_args, **_kwargs: next(identities),
            ),
        ):
            backup = install(self.staging, self.esp, self.backup_root)
            record = json.loads((backup / "backup.json").read_text(encoding="ascii"))
            self.assertEqual(
                record["esp_identity"],
                {
                    "fat_uuid": "1122-3344",
                    "label": "TEST-ESP",
                    "mount_major_minor": "259:2",
                    "mount_source": "/dev/fake-esp",
                },
            )
            before_files = _file_bytes(self.esp)
            before_entries = _tree_entries(self.esp)

            with self.assertRaisesRegex(RuntimeError, "different ESP identity"):
                rollback(backup, self.esp)

        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_rollback_rejects_backup_inside_managed_esp_path_without_mutation(
        self,
    ) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        embedded = (
            self.esp
            / "EFI"
            / "refind"
            / "themes"
            / "forest-a"
            / "embedded-backup"
        )
        shutil.copytree(backup, embedded)
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "backup.*outside.*ESP"):
            rollback(embedded, self.esp, require_root=False)

        self.assertEqual(_file_bytes(self.esp), before)

    def test_rollback_rejects_special_backup_entry_before_target_mutation(
        self,
    ) -> None:
        preexisting = (
            self.esp / "EFI" / "refind" / "themes" / "forest-a"
        )
        preexisting.mkdir(parents=True)
        (preexisting / "sentinel.bin").write_bytes(b"preexisting")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        os.mkfifo(backup / "original" / "themes" / "forest-a" / "tampered-fifo")
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "unsupported .*entry"):
            rollback(backup, self.esp, require_root=False)

        self.assertEqual(_file_bytes(self.esp), before)

    def test_rollback_rejects_unmanifested_root_backup_fifo_before_mutation(
        self,
    ) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        os.mkfifo(backup / "unmanifested-fifo")
        before = _file_bytes(self.esp)

        with self.assertRaisesRegex(RuntimeError, "unsupported backup entry"):
            rollback(backup, self.esp, require_root=False)

        self.assertEqual(_file_bytes(self.esp), before)

    def test_rollback_rejects_tampered_backed_up_managed_file_before_mutation(
        self,
    ) -> None:
        preexisting = self.esp / "EFI" / "refind" / "theme-a.conf"
        preexisting.write_bytes(b"preexisting managed config")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        (backup / "original" / "theme-a.conf").write_bytes(b"tampered backup")
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)

        with self.assertRaisesRegex(RuntimeError, r"backup.*(?:tree|checksum)"):
            rollback(backup, self.esp, require_root=False)

        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)

    def test_rollback_swap_failure_restores_complete_pre_rollback_target(
        self,
    ) -> None:
        refind = self.esp / "EFI" / "refind"
        (refind / "theme-a.conf").write_bytes(b"preexisting A")
        (refind / "theme-b.conf").write_bytes(b"preexisting B")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        failed = False

        def fail_second_managed_swap(source: Path, target: Path) -> None:
            nonlocal failed
            if not failed and Path(target) == refind / "theme-b.conf":
                failed = True
                raise RuntimeError("injected rollback swap failure")
            real_replace(source, target)

        with patch.object(
            install_module.os,
            "replace",
            side_effect=fail_second_managed_swap,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected rollback swap failure"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(failed)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)

        rollback(backup, self.esp, require_root=False)
        self.assertEqual((refind / "theme-a.conf").read_bytes(), b"preexisting A")
        self.assertEqual((refind / "theme-b.conf").read_bytes(), b"preexisting B")

    def test_rollback_keyboard_interrupt_reverses_swaps_and_reraises(self) -> None:
        refind = self.esp / "EFI" / "refind"
        (refind / "theme-a.conf").write_bytes(b"preexisting A")
        (refind / "theme-b.conf").write_bytes(b"preexisting B")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        interrupted = False

        def interrupt_second_managed_swap(source: Path, target: Path) -> None:
            nonlocal interrupted
            if not interrupted and Path(target) == refind / "theme-b.conf":
                interrupted = True
                raise KeyboardInterrupt("injected rollback interruption")
            real_replace(source, target)

        with patch.object(
            install_module.os,
            "replace",
            side_effect=interrupt_second_managed_swap,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "rollback interruption"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(interrupted)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

        rollback(backup, self.esp, require_root=False)
        self.assertEqual((refind / "theme-a.conf").read_bytes(), b"preexisting A")
        self.assertEqual((refind / "theme-b.conf").read_bytes(), b"preexisting B")

    def test_rollback_interrupt_after_prior_move_restores_target(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        interrupted = False

        def interrupt_after_prior_move(source: Path, target: Path) -> None:
            nonlocal interrupted
            real_replace(source, target)
            if (
                not interrupted
                and Path(source) == refind / "theme-b.conf"
                and Path(target).parent.name == "old"
            ):
                interrupted = True
                raise KeyboardInterrupt("injected post-prior-move interruption")

        with patch.object(
            install_module.os,
            "replace",
            side_effect=interrupt_after_prior_move,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "post-prior-move"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(interrupted)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_rollback_interrupt_after_staged_move_removes_new_target(self) -> None:
        refind = self.esp / "EFI" / "refind"
        (refind / "theme-b.conf").write_bytes(b"preexisting B")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        (refind / "theme-b.conf").unlink()
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        interrupted = False

        def interrupt_after_staged_move(source: Path, target: Path) -> None:
            nonlocal interrupted
            real_replace(source, target)
            if (
                not interrupted
                and Path(source).parent.name == "new"
                and Path(target) == refind / "theme-b.conf"
            ):
                interrupted = True
                raise KeyboardInterrupt("injected post-staged-move interruption")

        with patch.object(
            install_module.os,
            "replace",
            side_effect=interrupt_after_staged_move,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "post-staged-move"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(interrupted)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_rollback_reverse_interrupt_does_not_replace_forward_failure(self) -> None:
        refind = self.esp / "EFI" / "refind"
        (refind / "theme-a.conf").write_bytes(b"preexisting A")
        (refind / "theme-b.conf").write_bytes(b"preexisting B")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        failed = False
        interrupted = False
        primary_error = RuntimeError("injected forward swap failure")

        def interrupt_after_reverse_move(source: Path, target: Path) -> None:
            nonlocal failed, interrupted
            source = Path(source)
            target = Path(target)
            if (
                not failed
                and source.parent.name == "new"
                and target == refind / "theme-b.conf"
            ):
                failed = True
                raise primary_error
            real_replace(source, target)
            if (
                failed
                and not interrupted
                and source.parent.name == "old"
                and target == refind / "theme-b.conf"
            ):
                interrupted = True
                raise KeyboardInterrupt("injected post-reverse-move interruption")

        caught: BaseException | None = None
        with patch.object(
            install_module.os,
            "replace",
            side_effect=interrupt_after_reverse_move,
        ):
            try:
                rollback(backup, self.esp, require_root=False)
            except BaseException as error:
                caught = error

        self.assertTrue(failed)
        self.assertTrue(interrupted)
        self.assertIs(caught, primary_error)
        assert caught is not None
        self.assertIn(
            "KeyboardInterrupt: injected post-reverse-move interruption",
            "\n".join(caught.__notes__),
        )
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_rollback_cleanup_retry_reraises_interrupt(self) -> None:
        refind = self.esp / "EFI" / "refind"
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        real_rmtree = install_module.shutil.rmtree
        cleanup_attempts = 0

        def interrupt_cleanup_retry(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal cleanup_attempts
            if Path(path).name.startswith(".refind-forest-rollback-"):
                cleanup_attempts += 1
                if cleanup_attempts == 1:
                    raise OSError("injected initial cleanup failure")
                if cleanup_attempts == 2:
                    raise KeyboardInterrupt("injected cleanup retry interruption")
            real_rmtree(path, *args, **kwargs)

        with patch.object(
            install_module.shutil,
            "rmtree",
            side_effect=interrupt_cleanup_retry,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "cleanup retry"):
                rollback(backup, self.esp, require_root=False)

        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual((refind / "refind.conf").read_bytes(), ORIGINAL_REFIND_CONF)
        journals = [
            path
            for path in self.esp.iterdir()
            if path.name.startswith(".refind-forest-rollback-")
        ]
        self.assertEqual(len(journals), 1)
        real_rmtree(journals[0])

    def test_rollback_cleanup_retry_preserves_swap_interrupt(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_replace = install_module.os.replace
        real_rmtree = install_module.shutil.rmtree
        interrupted = False
        cleanup_attempts = 0

        def interrupt_swap(source: Path, target: Path) -> None:
            nonlocal interrupted
            if (
                not interrupted
                and Path(source) == refind / "theme-b.conf"
                and Path(target).parent.name == "old"
            ):
                interrupted = True
                raise KeyboardInterrupt("injected swap interruption")
            real_replace(source, target)

        def retry_cleanup(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal cleanup_attempts
            if Path(path).name.startswith(".refind-forest-rollback-"):
                cleanup_attempts += 1
                if cleanup_attempts == 1:
                    raise OSError("injected transient cleanup failure")
            real_rmtree(path, *args, **kwargs)

        with (
            patch.object(install_module.os, "replace", side_effect=interrupt_swap),
            patch.object(install_module.shutil, "rmtree", side_effect=retry_cleanup),
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "swap interruption"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(interrupted)
        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_rollback_interrupt_preserves_failed_journal_cleanup(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        before_files = _file_bytes(refind)
        before_entries = _tree_entries(refind)
        real_replace = install_module.os.replace
        real_rmtree = install_module.shutil.rmtree
        interrupted = False
        cleanup_attempts = 0

        def interrupt_swap(source: Path, target: Path) -> None:
            nonlocal interrupted
            if (
                not interrupted
                and Path(source) == refind / "theme-b.conf"
                and Path(target).parent.name == "old"
            ):
                interrupted = True
                raise KeyboardInterrupt("injected swap interruption")
            real_replace(source, target)

        def fail_cleanup(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal cleanup_attempts
            if Path(path).name.startswith(".refind-forest-rollback-"):
                cleanup_attempts += 1
                raise OSError("injected persistent journal cleanup failure")
            real_rmtree(path, *args, **kwargs)

        with (
            patch.object(install_module.os, "replace", side_effect=interrupt_swap),
            patch.object(install_module.shutil, "rmtree", side_effect=fail_cleanup),
        ):
            with self.assertRaisesRegex(
                KeyboardInterrupt,
                "swap interruption",
            ) as caught:
                rollback(backup, self.esp, require_root=False)

        journals = [
            path
            for path in self.esp.iterdir()
            if path.name.startswith(".refind-forest-rollback-")
        ]
        self.assertTrue(interrupted)
        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual(_file_bytes(refind), before_files)
        self.assertEqual(_tree_entries(refind), before_entries)
        self.assertEqual(len(journals), 1)
        notes = "\n".join(caught.exception.__notes__)
        self.assertIn(str(journals[0]), notes)
        real_rmtree(journals[0])

    def test_rollback_preserves_runtime_error_when_journal_cleanup_fails(
        self,
    ) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        before_files = _file_bytes(refind)
        before_entries = _tree_entries(refind)
        real_replace = install_module.os.replace
        real_rmtree = install_module.shutil.rmtree
        primary_error = RuntimeError("injected forward rollback failure")
        cleanup_attempts = 0

        def fail_swap(source: Path, target: Path) -> None:
            if (
                Path(source) == refind / "theme-b.conf"
                and Path(target).parent.name == "old"
            ):
                raise primary_error
            real_replace(source, target)

        def fail_cleanup(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal cleanup_attempts
            if Path(path).name.startswith(".refind-forest-rollback-"):
                cleanup_attempts += 1
                raise OSError(f"injected cleanup failure {cleanup_attempts}")
            real_rmtree(path, *args, **kwargs)

        with (
            patch.object(install_module.os, "replace", side_effect=fail_swap),
            patch.object(install_module.shutil, "rmtree", side_effect=fail_cleanup),
        ):
            with self.assertRaises(RuntimeError) as caught:
                rollback(backup, self.esp, require_root=False)

        journals = [
            path
            for path in self.esp.iterdir()
            if path.name.startswith(".refind-forest-rollback-")
        ]
        self.assertIs(caught.exception, primary_error)
        self.assertEqual(str(caught.exception), "injected forward rollback failure")
        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual(_file_bytes(refind), before_files)
        self.assertEqual(_tree_entries(refind), before_entries)
        self.assertEqual(len(journals), 1)
        notes = "\n".join(caught.exception.__notes__)
        self.assertIn("injected cleanup failure 1", notes)
        self.assertIn("injected cleanup failure 2", notes)
        self.assertIn(str(journals[0]), notes)
        real_rmtree(journals[0])

    def test_rollback_staging_cleanup_preserves_staging_interrupt(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_copy_atomic = install_module._copy_atomic
        real_rmtree = install_module.shutil.rmtree
        interrupted = False
        cleanup_attempts = 0

        def interrupt_staging_copy(source: Path, target: Path) -> None:
            nonlocal interrupted
            if not interrupted and target.parent.name == "new":
                interrupted = True
                raise KeyboardInterrupt("injected staging interruption")
            real_copy_atomic(source, target)

        def retry_cleanup(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal cleanup_attempts
            if Path(path).name.startswith(".refind-forest-rollback-"):
                cleanup_attempts += 1
                if cleanup_attempts == 1:
                    raise OSError("injected transient cleanup failure")
            real_rmtree(path, *args, **kwargs)

        with (
            patch.object(
                install_module,
                "_copy_atomic",
                side_effect=interrupt_staging_copy,
            ),
            patch.object(install_module.shutil, "rmtree", side_effect=retry_cleanup),
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "staging interruption"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(interrupted)
        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_install_automatic_rollback_preserves_install_failure(self) -> None:
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_rmtree = install_module.shutil.rmtree
        interrupted = False

        def interrupt_rollback_cleanup(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal interrupted
            if (
                not interrupted
                and Path(path).name.startswith(".refind-forest-rollback-")
            ):
                interrupted = True
                raise KeyboardInterrupt("injected automatic rollback interruption")
            real_rmtree(path, *args, **kwargs)

        primary_error = RuntimeError("injected install failure")
        caught: BaseException | None = None
        with (
            patch.object(
                install_module,
                "_install_files",
                side_effect=primary_error,
            ),
            patch.object(
                install_module.shutil,
                "rmtree",
                side_effect=interrupt_rollback_cleanup,
            ),
        ):
            try:
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )
            except BaseException as error:
                caught = error

        self.assertTrue(interrupted)
        self.assertIs(caught, primary_error)
        assert caught is not None
        self.assertIn(
            "KeyboardInterrupt: injected automatic rollback interruption",
            "\n".join(caught.__notes__),
        )
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)
        self.assertFalse(
            any(path.name.startswith(".refind-forest-") for path in self.esp.iterdir())
        )

    def test_install_preserves_primary_interrupt_when_rollback_exits(self) -> None:
        primary_error = KeyboardInterrupt("injected install interruption")
        rollback_error = SystemExit("injected rollback exit")

        caught: BaseException | None = None
        with (
            patch.object(
                install_module,
                "_install_files",
                side_effect=primary_error,
            ),
            patch.object(
                install_module,
                "_restore_backup",
                side_effect=rollback_error,
            ),
        ):
            try:
                install(
                    self.staging,
                    self.esp,
                    self.backup_root,
                    require_root=False,
                )
            except BaseException as error:
                caught = error

        self.assertIs(caught, primary_error)
        assert caught is not None
        self.assertIn(
            "SystemExit: injected rollback exit",
            "\n".join(caught.__notes__),
        )

    def test_rollback_parent_mkdir_failure_cleans_journal_and_target(self) -> None:
        refind = self.esp / "EFI" / "refind"
        preexisting = refind / "themes" / "forest-a" / "sentinel.bin"
        preexisting.parent.mkdir(parents=True)
        preexisting.write_bytes(b"preexisting theme")
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        themes = refind / "themes"
        shutil.rmtree(themes)
        before_files = _file_bytes(self.esp)
        before_entries = _tree_entries(self.esp)
        real_mkdir = Path.mkdir
        failed = False

        def fail_after_themes_mkdir(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal failed
            real_mkdir(path, *args, **kwargs)
            if not failed and path == themes:
                failed = True
                raise RuntimeError("injected rollback parent mkdir failure")

        with patch.object(Path, "mkdir", new=fail_after_themes_mkdir):
            with self.assertRaisesRegex(RuntimeError, "parent mkdir failure"):
                rollback(backup, self.esp, require_root=False)

        self.assertTrue(failed)
        self.assertEqual(_file_bytes(self.esp), before_files)
        self.assertEqual(_tree_entries(self.esp), before_entries)

        rollback(backup, self.esp, require_root=False)
        self.assertEqual(preexisting.read_bytes(), b"preexisting theme")

    def test_repeated_install_is_idempotent_and_second_backup_is_usable(self) -> None:
        first_backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        switch_theme("b", self.esp, require_root=False)
        first_install = _file_bytes(self.esp)

        second_backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        self.assertEqual(
            (refind / "refind.conf")
            .read_text(encoding="ascii")
            .count("include theme-active.conf"),
            1,
        )
        self.assertEqual(verify(self.esp), [])

        rollback(second_backup, self.esp, require_root=False)
        self.assertEqual(_file_bytes(self.esp), first_install)
        self.assertEqual(verify(self.esp), [])

        rollback(first_backup, self.esp, require_root=False)
        self.assertEqual((refind / "refind.conf").read_bytes(), ORIGINAL_REFIND_CONF)

    def test_install_consolidates_preexisting_naked_include_directive(self) -> None:
        refind_conf = self.esp / "EFI" / "refind" / "refind.conf"
        original = ORIGINAL_REFIND_CONF + b"include theme-active.conf\n"
        refind_conf.write_bytes(original)

        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )

        self.assertEqual(
            refind_conf.read_text(encoding="ascii").count(
                "include theme-active.conf"
            ),
            1,
        )
        self.assertEqual(verify(self.esp), [])

        rollback(backup, self.esp, require_root=False)
        self.assertEqual(refind_conf.read_bytes(), original)

    def test_install_normalizes_whitespace_include_and_preserves_comment(self) -> None:
        refind_conf = self.esp / "EFI" / "refind" / "refind.conf"
        comment = "# keep mention: include theme-active.conf"
        original = (
            ORIGINAL_REFIND_CONF
            + b" \tinclude theme-active.conf\t \n"
            + comment.encode("ascii")
            + b"\n"
        )
        refind_conf.write_bytes(original)

        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )

        installed = refind_conf.read_text(encoding="ascii")
        self.assertEqual(
            sum(
                line.strip() == "include theme-active.conf"
                for line in installed.splitlines()
            ),
            1,
        )
        self.assertIn(comment, installed)
        self.assertEqual(verify(self.esp), [])

        rollback(backup, self.esp, require_root=False)
        self.assertEqual(refind_conf.read_bytes(), original)

    def test_verify_rejects_duplicate_naked_include_directive(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind_conf = self.esp / "EFI" / "refind" / "refind.conf"
        with refind_conf.open("a", encoding="ascii") as output:
            output.write("include theme-active.conf\n")

        errors = verify(self.esp)

        self.assertTrue(any("exactly one" in error for error in errors))

    def test_verify_rejects_whitespace_equivalent_naked_include(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind_conf = self.esp / "EFI" / "refind" / "refind.conf"
        with refind_conf.open("a", encoding="ascii") as output:
            output.write("\t include theme-active.conf \t\n")

        errors = verify(self.esp)

        self.assertTrue(any("exactly one" in error for error in errors))

    def test_switch_copy_failure_preserves_previous_active_config(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        active = self.esp / "EFI" / "refind" / "theme-active.conf"
        before = active.read_bytes()
        real_copy_atomic = install_module._copy_atomic
        failure_injected = False

        def fail_once(source: Path, target: Path) -> None:
            nonlocal failure_injected
            if not failure_injected and target == active:
                failure_injected = True
                raise RuntimeError("injected switch copy failure")
            real_copy_atomic(source, target)

        with patch.object(install_module, "_copy_atomic", side_effect=fail_once):
            with self.assertRaisesRegex(RuntimeError, "injected switch copy failure"):
                switch_theme("b", self.esp, require_root=False)

        self.assertTrue(failure_injected)
        self.assertEqual(active.read_bytes(), before)
        self.assertEqual(verify(self.esp), [])

    def test_switch_refuses_invalid_install_without_changing_active(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        active = refind / "theme-active.conf"
        before = active.read_bytes()
        (refind / "themes" / "forest-a" / "icons" / "os_win.png").write_bytes(
            b"broken"
        )

        with self.assertRaisesRegex(RuntimeError, "invalid Forest install"):
            switch_theme("b", self.esp, require_root=False)

        self.assertEqual(active.read_bytes(), before)

    def test_verify_rejects_consistently_wrong_theme_config_pair(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        for variant in ("a", "b"):
            config = refind / f"theme-{variant}.conf"
            config.write_bytes(config.read_bytes().replace(b"timeout 8", b"timeout 9"))
        (refind / "theme-active.conf").write_bytes(
            (refind / "theme-a.conf").read_bytes()
        )
        manifest_path = refind / "forest-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        for entry in manifest["files"]:
            if entry["path"] in {"theme-a.conf", "theme-b.conf"}:
                entry["sha256"] = hashlib.sha256(
                    (refind / entry["path"]).read_bytes()
                ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")

        errors = verify(self.esp)

        self.assertTrue(
            any("theme-a.conf" in error and "generated" in error for error in errors)
        )
        self.assertTrue(
            any("theme-b.conf" in error and "generated" in error for error in errors)
        )

    def test_verify_collects_multiple_errors(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        for name in ("os_linux.png", "os_win.png"):
            (refind / "themes" / "forest-a" / "icons" / name).write_bytes(b"broken")
        (refind / "theme-active.conf").unlink()

        errors = verify(self.esp)

        self.assertTrue(any("os_linux.png" in error for error in errors))
        self.assertTrue(any("os_win.png" in error for error in errors))
        self.assertTrue(any("theme-active.conf" in error for error in errors))

    def test_verify_reports_png_dimension_errors_even_when_hash_matches(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        icon = refind / "themes" / "forest-a" / "icons" / "os_win.png"
        Image.new("RGBA", (1, 1)).save(icon, format="PNG")
        manifest_path = refind / "forest-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        for entry in manifest["files"]:
            if entry["path"].endswith("forest-a/icons/os_win.png"):
                entry["sha256"] = hashlib.sha256(icon.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")

        errors = verify(self.esp)

        self.assertTrue(
            any("os_win.png" in error and "properties" in error for error in errors)
        )

    def test_verify_rejects_non_png_image_with_matching_size_mode_and_hash(
        self,
    ) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        refind = self.esp / "EFI" / "refind"
        icon = refind / "themes" / "forest-a" / "icons" / "os_win.png"
        Image.new("RGBA", (128, 128)).save(icon, format="TIFF")
        manifest_path = refind / "forest-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        for entry in manifest["files"]:
            if entry["path"].endswith("forest-a/icons/os_win.png"):
                entry["sha256"] = hashlib.sha256(icon.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")

        errors = verify(self.esp)

        self.assertTrue(
            any("os_win.png" in error and "format" in error for error in errors)
        )

    def test_verify_reports_pillow_decode_limits_as_image_errors(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )

        with patch.object(install_module.Image, "MAX_IMAGE_PIXELS", 0):
            errors = verify(self.esp)

        self.assertTrue(any("invalid PNG" in error for error in errors))

    def test_verify_reports_unmanifested_managed_png_and_decodes_it(self) -> None:
        install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        extra = (
            self.esp
            / "EFI"
            / "refind"
            / "themes"
            / "forest-a"
            / "icons"
            / "extra.png"
        )
        extra.write_bytes(b"not a PNG")

        errors = verify(self.esp)

        self.assertTrue(
            any(
                "unmanifested" in error and "extra.png" in error
                for error in errors
            )
        )
        self.assertTrue(
            any(
                "invalid PNG" in error and "extra.png" in error
                for error in errors
            )
        )

    def test_atomic_temporary_files_are_cleaned(self) -> None:
        backup = install(
            self.staging,
            self.esp,
            self.backup_root,
            require_root=False,
        )
        switch_theme("b", self.esp, require_root=False)
        rollback(backup, self.esp, require_root=False)

        leftovers = [
            path
            for root in (self.esp, self.backup_root)
            for path in root.rglob("*")
            if ".tmp-" in path.name
        ]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()

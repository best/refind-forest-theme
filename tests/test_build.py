import copy
import hashlib
import json
import shutil
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import refind_forest.build as build_module
from refind_forest.build import build_package


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UBUNTU_SOURCE = PROJECT_ROOT / "assets" / "source" / "ubuntu-logo.png"
PUBLIC_NOTICE_PATHS = {
    "LICENSE",
    "LICENSES/CC-BY-SA-4.0.txt",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
}


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


class BuildTests(unittest.TestCase):
    def test_build_carries_redistribution_notices_outside_install_manifest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "staging"

            build_package(output, UBUNTU_SOURCE, "SYSTEM")

            for relative in PUBLIC_NOTICE_PATHS:
                packaged = output / relative
                self.assertTrue(packaged.is_file(), relative)
                self.assertEqual(
                    packaged.read_bytes(),
                    (PROJECT_ROOT / relative).read_bytes(),
                )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="ascii")
            )
            self.assertEqual(manifest["format"], 2)
            self.assertTrue(
                all(entry["path"].startswith("EFI/") for entry in manifest["files"])
            )
            self.assertEqual(
                {entry["path"] for entry in manifest["notices"]},
                PUBLIC_NOTICE_PATHS,
            )

    def test_package_notice_parent_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            outside = root / "outside"
            for relative in PUBLIC_NOTICE_PATHS:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((PROJECT_ROOT / relative).read_bytes())
            outside.mkdir()
            (outside / "CC-BY-SA-4.0.txt").write_bytes(b"outside notice")

            real_open = build_module.os.open
            swapped = False

            def swap_license_directory(
                path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                if path == "LICENSES" and kwargs.get("dir_fd") is not None and not swapped:
                    (source / "LICENSES").rename(source / "LICENSES-original")
                    (source / "LICENSES").symlink_to(outside, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with (
                patch.object(build_module, "_PROJECT_ROOT", source),
                patch.object(build_module.os, "open", side_effect=swap_license_directory),
            ):
                with self.assertRaisesRegex(RuntimeError, "package notice source"):
                    build_module._read_package_notices()

            self.assertTrue(swapped)

    def test_owned_build_notice_parent_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            outside = root / "outside"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            outside.mkdir()
            shutil.copy2(
                output / "LICENSES" / "CC-BY-SA-4.0.txt",
                outside / "CC-BY-SA-4.0.txt",
            )

            real_open = build_module.os.open
            swapped = False

            def swap_license_directory(
                path: object,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal swapped
                if path == "LICENSES" and kwargs.get("dir_fd") is not None and not swapped:
                    (output / "LICENSES").rename(output / "LICENSES-original")
                    (output / "LICENSES").symlink_to(outside, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with patch.object(
                build_module.os,
                "open",
                side_effect=swap_license_directory,
            ):
                self.assertFalse(build_module._is_owned_build(output))

            self.assertTrue(swapped)

    def test_safe_esp_label_is_written_to_manifest_and_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "safe-label"

            build_package(output, UBUNTU_SOURCE, "SAFE-LABEL")

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["esp_label"], "SAFE-LABEL")
            config = (output / "EFI" / "refind" / "theme-a.conf").read_text()
            self.assertIn("SAFE-LABEL:/EFI/Boot", config)

    def test_builds_complete_staging_tree_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "staging"

            build_package(output, UBUNTU_SOURCE, "SYSTEM")

            refind = output / "EFI" / "refind"
            self.assertTrue((refind / "theme-a.conf").is_file())
            self.assertTrue((refind / "theme-b.conf").is_file())
            self.assertEqual(
                (refind / "theme-active.conf").read_bytes(),
                (refind / "theme-a.conf").read_bytes(),
            )

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                set(manifest),
                {"default_variant", "esp_label", "files", "format", "notices"},
            )
            self.assertEqual(manifest["format"], 2)
            self.assertEqual(manifest["default_variant"], "a")
            self.assertEqual(manifest["esp_label"], "SYSTEM")
            manifest_paths = [entry["path"] for entry in manifest["files"]]
            filesystem_paths = sorted(
                path.relative_to(output).as_posix()
                for path in refind.rglob("*")
                if path.is_file()
            )
            self.assertEqual(manifest_paths, filesystem_paths)
            self.assertEqual(len(manifest_paths), len(set(manifest_paths)))
            self.assertIn(
                "EFI/refind/themes/forest-a/background.png",
                manifest_paths,
            )
            self.assertIn(
                "EFI/refind/themes/forest-b/icons/os_ventoy.png",
                manifest_paths,
            )
            for entry in manifest["files"]:
                path = output / entry["path"]
                self.assertTrue(path.is_file())
                self.assertEqual(
                    entry["sha256"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            notice_paths = [entry["path"] for entry in manifest["notices"]]
            self.assertEqual(notice_paths, sorted(PUBLIC_NOTICE_PATHS))
            for entry in manifest["notices"]:
                path = output / entry["path"]
                self.assertEqual(
                    entry["sha256"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

    def test_rejects_cwd_its_ancestor_and_filesystem_root(self) -> None:
        source_bytes = UBUNTU_SOURCE.read_bytes()
        dangerous_outputs = (Path("."), PROJECT_ROOT.parent, Path("/"))

        for output in dangerous_outputs:
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

        self.assertEqual(UBUNTU_SOURCE.read_bytes(), source_bytes)

    def test_rejects_output_that_contains_ubuntu_source(self) -> None:
        source_bytes = UBUNTU_SOURCE.read_bytes()

        with self.assertRaises(ValueError):
            build_package(UBUNTU_SOURCE.parent, UBUNTU_SOURCE, "SYSTEM")

        self.assertEqual(UBUNTU_SOURCE.read_bytes(), source_bytes)

    def test_rejects_source_symlink_located_inside_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            source_link = output / "EFI" / "refind" / "ubuntu-source.png"
            source_link.symlink_to(UBUNTU_SOURCE)
            original_files = _file_bytes(output)

            with self.assertRaises(ValueError):
                build_package(output, source_link, "SYSTEM")

            self.assertTrue(source_link.is_symlink())
            self.assertEqual(_file_bytes(output), original_files)

    def test_rejects_direct_and_broken_output_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.mkdir()
            sentinel = target / "sentinel"
            sentinel.write_bytes(b"preserve me")
            output = root / "output"
            output.symlink_to(target, target_is_directory=True)

            with self.assertRaises(ValueError):
                build_package(output, UBUNTU_SOURCE, "SYSTEM")
            self.assertEqual(sentinel.read_bytes(), b"preserve me")

            output.unlink()
            output.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaises(ValueError):
                build_package(output, UBUNTU_SOURCE, "SYSTEM")
            self.assertTrue(output.is_symlink())
            self.assertFalse((root / "missing").exists())

    def test_rejects_unowned_existing_directories_without_deleting_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            layouts = {
                "missing manifest": (True, None, False),
                "malformed manifest": (True, "not json", False),
                "wrong manifest format": (
                    True,
                    json.dumps({"format": 1}),
                    False,
                ),
                "boolean manifest format": (
                    True,
                    json.dumps({"format": True}),
                    False,
                ),
                "missing refind tree": (
                    False,
                    json.dumps({"format": 2}),
                    False,
                ),
                "unrelated top-level entry": (
                    True,
                    json.dumps({"format": 2}),
                    True,
                ),
            }
            for index, (name, layout) in enumerate(layouts.items()):
                with self.subTest(name=name):
                    has_refind, manifest_text, has_unrelated_entry = layout
                    output = root / f"output-{index}"
                    efi = output / "EFI"
                    sentinel_parent = efi / "refind" if has_refind else efi
                    sentinel_parent.mkdir(parents=True)
                    sentinel = sentinel_parent / "sentinel"
                    sentinel.write_bytes(b"preserve me")
                    if manifest_text is not None:
                        (output / "manifest.json").write_text(manifest_text)
                    if has_unrelated_entry:
                        (output / "unrelated").write_bytes(b"preserve me too")

                    with self.assertRaises(RuntimeError):
                        build_package(output, UBUNTU_SOURCE, "SYSTEM")
                    self.assertEqual(sentinel.read_bytes(), b"preserve me")

    def test_rejects_format_only_manifest_without_deleting_user_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "staging"
            refind = output / "EFI" / "refind"
            refind.mkdir(parents=True)
            unrelated = refind / "unrelated-user-file"
            unrelated.write_bytes(b"preserve me")
            (output / "manifest.json").write_text(json.dumps({"format": 2}))

            with self.assertRaises(RuntimeError):
                build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(unrelated.read_bytes(), b"preserve me")

    def test_rejects_malformed_owned_manifests_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "baseline"
            build_package(baseline, UBUNTU_SOURCE, "SYSTEM")
            valid = json.loads((baseline / "manifest.json").read_text())
            malformed = {}

            candidate = copy.deepcopy(valid)
            candidate["format"] = True
            malformed["boolean format"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["default_variant"] = "b"
            malformed["wrong default variant"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["esp_label"] = ""
            malformed["invalid ESP label"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"] = {}
            malformed["files is not a list"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"][0]["extra"] = "unexpected"
            malformed["file entry has extra key"] = candidate

            invalid_paths = {
                "absolute path": "/EFI/refind/escape",
                "dot path": "EFI/refind/./escape",
                "dotdot path": "EFI/refind/../escape",
                "backslash path": "EFI/refind\\escape",
                "outside refind": "EFI/escape",
            }
            for name, invalid_path in invalid_paths.items():
                candidate = copy.deepcopy(valid)
                candidate["files"].append(
                    {"path": invalid_path, "sha256": "0" * 64}
                )
                candidate["files"].sort(key=lambda entry: entry["path"])
                malformed[name] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"][0]["sha256"] = "A" * 64
            malformed["uppercase checksum"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"].insert(1, copy.deepcopy(candidate["files"][0]))
            malformed["duplicate path"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"].reverse()
            malformed["unsorted paths"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"] = [
                entry
                for entry in candidate["files"]
                if entry["path"] != "EFI/refind/theme-a.conf"
            ]
            malformed["missing required core path"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"].append(
                {
                    "path": "EFI/refind/themes/missing.png",
                    "sha256": "0" * 64,
                }
            )
            candidate["files"].sort(key=lambda entry: entry["path"])
            malformed["listed file is missing"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["files"][0]["sha256"] = "0" * 64
            malformed["checksum mismatch"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"] = {}
            malformed["notices is not a list"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"][0]["extra"] = "unexpected"
            malformed["notice entry has extra key"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"][0]["path"] = "NOTICE.md"
            malformed["unexpected notice path"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"][0]["sha256"] = "A" * 64
            malformed["uppercase notice checksum"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"].insert(1, copy.deepcopy(candidate["notices"][0]))
            malformed["duplicate notice path"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"].reverse()
            malformed["unsorted notice paths"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"].pop()
            malformed["missing notice path"] = candidate

            candidate = copy.deepcopy(valid)
            candidate["notices"][0]["sha256"] = "0" * 64
            malformed["notice checksum mismatch"] = candidate

            for index, (name, manifest) in enumerate(malformed.items()):
                with self.subTest(name=name):
                    output = root / f"case-{index}"
                    shutil.copytree(baseline, output)
                    (output / "manifest.json").write_text(json.dumps(manifest))
                    original_files = _file_bytes(output)

                    with self.assertRaises(RuntimeError):
                        build_package(output, UBUNTU_SOURCE, "SYSTEM")

                    self.assertEqual(_file_bytes(output), original_files)

    def test_rejects_invalid_esp_labels_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            invalid_labels = (
                "",
                "TOO-LONG-123",
                "BAD LABEL",
                "BAD,LABEL",
                "BAD:LABEL",
                "BAD\tLABEL",
                "BAD\nLABEL",
                "BAD/LABEL",
                "BAD\\LABEL",
                "BAD.LABEL",
                "SYST\N{LATIN CAPITAL LETTER E WITH ACUTE}M",
            )
            for index, esp_label in enumerate(invalid_labels):
                with self.subTest(esp_label=esp_label):
                    output = root / f"output-{index}"
                    with self.assertRaisesRegex(ValueError, "1-11 ASCII"):
                        build_package(output, UBUNTU_SOURCE, esp_label)
                    self.assertFalse(output.exists())

    def test_generation_failure_preserves_previous_build_and_cleans_staging(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_generate_theme = build_module.generate_theme

            def fail_on_variant_b(
                variant: str,
                target: Path,
                ubuntu_source: Path,
            ) -> None:
                if variant == "b":
                    raise RuntimeError("injected variant B failure")
                return real_generate_theme(variant, target, ubuntu_source)

            with patch.object(
                build_module,
                "generate_theme",
                side_effect=fail_on_variant_b,
            ):
                with self.assertRaisesRegex(RuntimeError, "injected variant B"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_manifest_failure_preserves_previous_build_and_cleans_staging(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)

            with patch.object(
                build_module,
                "_sha256",
                side_effect=RuntimeError("injected manifest failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected manifest"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_owned_rebuild_is_deterministic_and_removes_stale_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            stale = output / "EFI" / "refind" / "stale.txt"
            stale.write_bytes(b"remove me")

            build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertFalse(stale.exists())
            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_promotion_failure_restores_previous_build_and_cleans_backups(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename

            def fail_staging_promotion(path: Path, target: Path) -> Path:
                if path.name.startswith(".staging.tmp-") and target == output:
                    raise OSError("injected promotion failure")
                return real_rename(path, target)

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=fail_staging_promotion,
            ):
                with self.assertRaisesRegex(OSError, "injected promotion failure"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_promotion_keyboard_interrupt_restores_previous_build_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename

            def interrupt_staging_promotion(path: Path, target: Path) -> Path:
                renamed = real_rename(path, target)
                if path.name.startswith(".staging.tmp-") and target == output:
                    raise KeyboardInterrupt("injected promotion interruption")
                return renamed

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_staging_promotion,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "promotion interruption",
                ):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_backup_commit_failure_restores_previous_build_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            commit_error = OSError("injected backup commit failure")
            real_rename = Path.rename

            def fail_backup_commit(path: Path, target: Path) -> Path:
                if path.name == "previous" and target.name == "obsolete":
                    raise commit_error
                return real_rename(path, target)

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=fail_backup_commit,
            ):
                with self.assertRaisesRegex(OSError, "backup commit") as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            self.assertIs(caught.exception, commit_error)
            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_backup_commit_interrupt_restores_previous_build_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            commit_error = KeyboardInterrupt("injected backup commit interrupt")
            real_rename = Path.rename

            def interrupt_backup_commit(path: Path, target: Path) -> Path:
                if path.name == "previous" and target.name == "obsolete":
                    raise commit_error
                return real_rename(path, target)

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_backup_commit,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "backup commit interrupt",
                ) as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            self.assertIs(caught.exception, commit_error)
            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_backup_commit_failure_notes_failed_new_residual(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename
            real_rmtree = shutil.rmtree

            def fail_backup_commit(path: Path, target: Path) -> Path:
                if path.name == "previous" and target.name == "obsolete":
                    raise OSError("injected backup commit failure")
                return real_rename(path, target)

            def fail_residual_cleanup(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> None:
                name = Path(path).name
                if name == "failed-new":
                    raise OSError("injected failed-new cleanup failure")
                real_rmtree(path, *args, **kwargs)

            with (
                patch.object(
                    Path,
                    "rename",
                    autospec=True,
                    side_effect=fail_backup_commit,
                ),
                patch.object(
                    shutil,
                    "rmtree",
                    side_effect=fail_residual_cleanup,
                ),
            ):
                with self.assertRaisesRegex(OSError, "backup commit") as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            residuals = [
                path
                for path in root.rglob("failed-new")
                if path.is_dir()
            ]
            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual(len(residuals), 1)
            residual_manifest = json.loads(
                (residuals[0] / "manifest.json").read_text()
            )
            self.assertEqual(residual_manifest["esp_label"], "UPDATED")
            self.assertIn(
                str(residuals[0]),
                "\n".join(caught.exception.__notes__),
            )
            real_rmtree(residuals[0].parent)

    def test_backup_commit_restore_failure_preserves_and_reports_backup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename

            def fail_restore(path: Path, target: Path) -> Path:
                if path.name == "previous" and target.name == "obsolete":
                    raise OSError("injected backup commit failure")
                if path.name == "previous" and target == output:
                    raise OSError("injected restoration failure")
                return real_rename(path, target)

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=fail_restore,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "failed to restore previous output",
                ) as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            backup_roots = [
                path
                for path in root.iterdir()
                if path.name.startswith(".staging.backup-")
            ]
            self.assertFalse(output.exists())
            self.assertEqual(len(backup_roots), 1)
            backup = backup_roots[0] / "previous"
            self.assertEqual(_file_bytes(backup), original_files)
            notes = "\n".join(caught.exception.__notes__)
            self.assertIn(str(backup), str(caught.exception))
            self.assertIn("backup commit failure", notes)
            self.assertIn("restoration failure", notes)

    def test_partial_backup_cleanup_failure_keeps_complete_new_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            expected = root / "expected"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            build_package(expected, UBUNTU_SOURCE, "UPDATED")
            expected_files = _file_bytes(expected)
            shutil.rmtree(expected)
            real_rmtree = shutil.rmtree

            def partially_delete_backup(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> None:
                path = Path(path)
                if path.name in {"previous", "obsolete"}:
                    managed_file = path / "EFI" / "refind" / "theme-a.conf"
                    if managed_file.exists():
                        managed_file.unlink()
                    raise OSError("injected partial backup cleanup failure")
                real_rmtree(path, *args, **kwargs)

            with (
                self.assertLogs(build_module.__name__, level="WARNING") as logs,
                patch.object(
                    shutil,
                    "rmtree",
                    side_effect=partially_delete_backup,
                ),
            ):
                result = build_package(output, UBUNTU_SOURCE, "UPDATED")

            residuals = list(root.rglob("obsolete"))
            self.assertEqual(result, output)
            self.assertEqual(_file_bytes(output), expected_files)
            self.assertEqual(len(residuals), 1)
            self.assertFalse(
                (residuals[0] / "EFI" / "refind" / "theme-a.conf").exists()
            )
            log_text = "\n".join(logs.output)
            self.assertIn(str(residuals[0]), log_text)
            self.assertIn("partial backup cleanup failure", log_text)
            real_rmtree(residuals[0].parent)

    def test_cleanup_diagnostic_ignores_warning_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            expected = root / "expected"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            build_package(expected, UBUNTU_SOURCE, "UPDATED")
            expected_files = _file_bytes(expected)
            shutil.rmtree(expected)
            real_rmtree = shutil.rmtree

            def fail_obsolete_cleanup(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> None:
                if Path(path).name == "obsolete":
                    raise OSError("injected persistent obsolete cleanup failure")
                real_rmtree(path, *args, **kwargs)

            with (
                warnings.catch_warnings(),
                self.assertLogs(build_module.__name__, level="WARNING") as logs,
                patch.object(
                    shutil,
                    "rmtree",
                    side_effect=fail_obsolete_cleanup,
                ),
            ):
                warnings.simplefilter("error", RuntimeWarning)
                result = build_package(output, UBUNTU_SOURCE, "UPDATED")

            residuals = list(root.rglob("obsolete"))
            self.assertEqual(result, output)
            self.assertEqual(_file_bytes(output), expected_files)
            self.assertEqual(len(residuals), 1)
            log_text = "\n".join(logs.output)
            self.assertIn(str(residuals[0]), log_text)
            self.assertIn("persistent obsolete cleanup failure", log_text)
            real_rmtree(residuals[0].parent)

    def test_partial_backup_cleanup_interrupt_keeps_complete_new_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            expected = root / "expected"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            build_package(expected, UBUNTU_SOURCE, "UPDATED")
            expected_files = _file_bytes(expected)
            shutil.rmtree(expected)
            cleanup_error = KeyboardInterrupt(
                "injected partial backup cleanup interrupt"
            )
            real_rmtree = shutil.rmtree

            def partially_delete_backup(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> None:
                path = Path(path)
                if path.name in {"previous", "obsolete"}:
                    managed_file = path / "EFI" / "refind" / "theme-a.conf"
                    if managed_file.exists():
                        managed_file.unlink()
                    raise cleanup_error
                real_rmtree(path, *args, **kwargs)

            with patch.object(
                shutil,
                "rmtree",
                side_effect=partially_delete_backup,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "partial backup cleanup interrupt",
                ) as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            self.assertIs(caught.exception, cleanup_error)
            self.assertEqual(_file_bytes(output), expected_files)
            residuals = list(root.rglob("obsolete"))
            self.assertEqual(len(residuals), 1)
            notes = "\n".join(caught.exception.__notes__)
            self.assertIn(f"new output committed at {output}", notes)
            self.assertIn(str(residuals[0]), notes)
            real_rmtree(residuals[0].parent)

    def test_post_syscall_backup_commit_interrupt_keeps_committed_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            real_rename = Path.rename

            def interrupt_after_backup_commit(path: Path, target: Path) -> Path:
                renamed = real_rename(path, target)
                if path.name == "previous" and target.name == "obsolete":
                    raise KeyboardInterrupt("injected post-commit interrupt")
                return renamed

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_after_backup_commit,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "post-commit interrupt",
                ) as caught:
                    build_package(output, UBUNTU_SOURCE, "UPDATED")

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["esp_label"], "UPDATED")
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})
            self.assertIn(
                f"new output committed at {output}",
                "\n".join(caught.exception.__notes__),
            )

    def test_backup_root_cleanup_failure_is_retried_after_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            real_rmdir = Path.rmdir
            cleanup_attempts = 0

            def fail_first_backup_root_cleanup(path: Path) -> None:
                nonlocal cleanup_attempts
                if path.name.startswith(".staging.backup-"):
                    cleanup_attempts += 1
                    if cleanup_attempts == 1:
                        raise OSError("injected backup-root cleanup failure")
                real_rmdir(path)

            with patch.object(
                Path,
                "rmdir",
                autospec=True,
                side_effect=fail_first_backup_root_cleanup,
            ):
                result = build_package(output, UBUNTU_SOURCE, "UPDATED")

            self.assertEqual(result, output)
            self.assertEqual(cleanup_attempts, 2)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["esp_label"], "UPDATED")
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_post_syscall_backup_root_interrupt_keeps_committed_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            real_rmdir = Path.rmdir

            def interrupt_after_backup_root_cleanup(path: Path) -> None:
                real_rmdir(path)
                if path.name.startswith(".staging.backup-"):
                    raise KeyboardInterrupt("injected backup-root cleanup interrupt")

            with patch.object(
                Path,
                "rmdir",
                autospec=True,
                side_effect=interrupt_after_backup_root_cleanup,
            ):
                result = build_package(output, UBUNTU_SOURCE, "UPDATED")

            self.assertEqual(result, output)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["esp_label"], "UPDATED")
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_promotion_interrupt_after_previous_move_restores_previous_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename

            def interrupt_previous_move(path: Path, target: Path) -> Path:
                renamed = real_rename(path, target)
                if path == output and target.name == "previous":
                    raise KeyboardInterrupt("injected previous-move interruption")
                return renamed

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_previous_move,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "previous-move"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_promotion_interrupt_after_restore_move_keeps_previous_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename

            def interrupt_restore_move(path: Path, target: Path) -> Path:
                if path.name.startswith(".staging.tmp-") and target == output:
                    raise OSError("injected promotion failure")
                renamed = real_rename(path, target)
                if path.name == "previous" and target == output:
                    raise KeyboardInterrupt("injected restore-move interruption")
                return renamed

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_restore_move,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "restore-move"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual({path.name for path in root.iterdir()}, {"staging"})

    def test_first_promotion_interrupt_after_rename_removes_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            real_rename = Path.rename

            def interrupt_first_promotion(path: Path, target: Path) -> Path:
                renamed = real_rename(path, target)
                if path.name.startswith(".staging.tmp-") and target == output:
                    raise KeyboardInterrupt("injected first-promotion interruption")
                return renamed

            with patch.object(
                Path,
                "rename",
                autospec=True,
                side_effect=interrupt_first_promotion,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "first-promotion"):
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            self.assertFalse(output.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_promotion_interrupt_preserves_failed_staging_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "staging"
            build_package(output, UBUNTU_SOURCE, "SYSTEM")
            original_files = _file_bytes(output)
            real_rename = Path.rename
            real_rmtree = shutil.rmtree
            cleanup_attempts = 0

            def interrupt_promotion(path: Path, target: Path) -> Path:
                if path.name.startswith(".staging.tmp-") and target == output:
                    raise KeyboardInterrupt("injected promotion interruption")
                return real_rename(path, target)

            def fail_staging_cleanup(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> None:
                nonlocal cleanup_attempts
                if Path(path).name.startswith(".staging.tmp-"):
                    cleanup_attempts += 1
                    raise OSError("injected persistent staging cleanup failure")
                real_rmtree(path, *args, **kwargs)

            with (
                patch.object(
                    Path,
                    "rename",
                    autospec=True,
                    side_effect=interrupt_promotion,
                ),
                patch.object(shutil, "rmtree", side_effect=fail_staging_cleanup),
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "promotion interruption",
                ) as caught:
                    build_package(output, UBUNTU_SOURCE, "SYSTEM")

            staging_residuals = [
                path
                for path in root.iterdir()
                if path.name.startswith(".staging.tmp-")
            ]
            self.assertEqual(cleanup_attempts, 2)
            self.assertEqual(_file_bytes(output), original_files)
            self.assertEqual(len(staging_residuals), 1)
            notes = "\n".join(caught.exception.__notes__)
            self.assertIn(str(staging_residuals[0]), notes)
            real_rmtree(staging_residuals[0])


if __name__ == "__main__":
    unittest.main()

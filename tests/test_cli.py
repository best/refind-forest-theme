import io
import os
import runpy
import sys
import tempfile
import unittest
from contextlib import chdir, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import refind_forest.cli as cli
from refind_forest.cli import ROOT, UBUNTU_SOURCE, main


class CliTests(unittest.TestCase):
    def test_build_rejects_unsafe_esp_label_before_creating_output(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "build"
            with redirect_stderr(stderr):
                result = main(
                    ["build", "--output", str(output), "--esp-label", "BAD LABEL"]
                )

            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
        self.assertIn("1-11 ASCII", stderr.getvalue())

    def test_build_creates_package_with_variant_a_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "build"

            result = main(
                ["build", "--output", str(output), "--esp-label", "SYSTEM"]
            )

            self.assertEqual(result, 0)
            refind = output / "EFI" / "refind"
            self.assertEqual(
                (refind / "theme-active.conf").read_bytes(),
                (refind / "theme-a.conf").read_bytes(),
            )

    def test_switch_theme_rejects_unknown_variant_as_usage_error(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["switch-theme", "c"])

        self.assertEqual(raised.exception.code, 2)

    def test_relative_build_output_resolves_under_project_root(self) -> None:
        with patch.object(cli, "build_package") as build_package:
            result = main(
                ["build", "--output", "staging", "--esp-label", "FOREST"]
            )

        self.assertEqual(result, 0)
        build_package.assert_called_once_with(
            ROOT / "staging",
            UBUNTU_SOURCE,
            "FOREST",
        )

    def test_install_uses_ephemeral_staging_and_preserves_project_build(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as project_directory:
            project_root = Path(project_directory)
            persistent_build = project_root / "build"
            persistent_build.mkdir()
            sentinel = persistent_build / "sentinel"
            sentinel.write_bytes(b"preserve project build")
            backup = project_root / "backups" / "snapshot"
            staging_paths: list[Path] = []

            def build_ephemeral(
                output: Path,
                ubuntu_source: Path,
                esp_label: str,
            ) -> None:
                staging_paths.append(output)
                self.assertNotEqual(output, persistent_build)
                self.assertNotIn(project_root, output.parents)
                self.assertEqual(ubuntu_source, UBUNTU_SOURCE)
                self.assertEqual(esp_label, "ALT-ESP")
                output.mkdir()

            def install_ephemeral(
                staging: Path,
                esp: Path,
                backup_root: Path,
            ) -> Path:
                self.assertTrue(staging.is_dir())
                self.assertEqual(sentinel.read_bytes(), b"preserve project build")
                self.assertEqual(esp, Path("/boot/efi"))
                self.assertEqual(backup_root, project_root / "backups")
                return backup

            stdout = io.StringIO()
            with (
                patch.object(cli, "ROOT", project_root),
                patch.object(
                    cli,
                    "discover_esp_label",
                    return_value="ALT-ESP",
                ) as discover_esp_label,
                patch.object(
                    cli,
                    "build_package",
                    side_effect=build_ephemeral,
                ),
                patch.object(cli, "install", side_effect=install_ephemeral),
                redirect_stdout(stdout),
            ):
                result = main(["install"])

            self.assertEqual(result, 0)
            discover_esp_label.assert_called_once_with(Path("/boot/efi"))
            self.assertEqual(len(staging_paths), 1)
            self.assertFalse(staging_paths[0].exists())
            self.assertFalse(staging_paths[0].parent.exists())
            self.assertEqual(sentinel.read_bytes(), b"preserve project build")
            self.assertEqual(stdout.getvalue(), f"{backup.resolve()}\n")

    def test_install_preserves_absolute_backup_root(self) -> None:
        backup_root = Path(tempfile.gettempdir()) / "absolute-forest-backups"
        with (
            patch.object(
                cli,
                "discover_esp_label",
                return_value="SYSTEM",
            ),
            patch.object(cli, "build_package"),
            patch.object(
                cli,
                "install",
                return_value=backup_root / "snapshot",
            ) as install,
            redirect_stdout(io.StringIO()),
        ):
            result = main(
                [
                    "install",
                    "--esp",
                    "/fake/esp",
                    "--backup-root",
                    str(backup_root),
                ]
            )

        self.assertEqual(result, 0)
        staging = install.call_args.args[0]
        self.assertFalse(staging.exists())
        install.assert_called_once_with(
            staging,
            Path("/fake/esp"),
            backup_root,
        )

    def test_install_cleans_ephemeral_directory_when_build_fails(self) -> None:
        staging_paths: list[Path] = []

        def fail_build(output: Path, *_args: object) -> None:
            staging_paths.append(output)
            output.mkdir()
            (output / "partial-build").write_bytes(b"incomplete")
            raise OSError("injected build failure")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as project_directory:
            project_root = Path(project_directory)
            with (
                patch.object(cli, "ROOT", project_root),
                patch.object(
                    cli,
                    "discover_esp_label",
                    return_value="SYSTEM",
                ),
                patch.object(cli, "build_package", side_effect=fail_build),
                patch.object(cli, "install") as install,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = main(["install"])

            self.assertEqual(len(staging_paths), 1)
            self.assertNotEqual(staging_paths[0], project_root / "build")
            self.assertFalse(staging_paths[0].exists())
            self.assertFalse(staging_paths[0].parent.exists())

        self.assertEqual(result, 1)
        install.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "refind-forest: injected build failure\n",
        )

    def test_install_cleans_ephemeral_staging_when_install_fails(self) -> None:
        staging_paths: list[Path] = []

        def build_ephemeral(output: Path, *_args: object) -> None:
            staging_paths.append(output)
            output.mkdir()

        def fail_install(staging: Path, *_args: object) -> None:
            self.assertTrue(staging.is_dir())
            raise RuntimeError("injected install failure")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as project_directory:
            with (
                patch.object(cli, "ROOT", Path(project_directory)),
                patch.object(
                    cli,
                    "discover_esp_label",
                    return_value="SYSTEM",
                ),
                patch.object(
                    cli,
                    "build_package",
                    side_effect=build_ephemeral,
                ),
                patch.object(cli, "install", side_effect=fail_install),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = main(["install"])

            self.assertEqual(len(staging_paths), 1)
            self.assertFalse(staging_paths[0].exists())
            self.assertFalse(staging_paths[0].parent.exists())

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "refind-forest: injected install failure\n",
        )

    def test_install_cleanup_failure_warns_without_changing_success(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as manual_cleanup_directory:
            temporary_root = Path(manual_cleanup_directory) / "install-staging"
            temporary_root.mkdir()
            backup = Path(manual_cleanup_directory) / "backups" / "snapshot"

            def build_ephemeral(output: Path, *_args: object) -> None:
                output.mkdir()

            with (
                patch.object(
                    cli,
                    "discover_esp_label",
                    return_value="SYSTEM",
                ),
                patch.object(
                    cli.tempfile,
                    "mkdtemp",
                    return_value=str(temporary_root),
                ),
                patch.object(
                    cli.shutil,
                    "rmtree",
                    side_effect=OSError("cleanup denied"),
                ) as cleanup,
                patch.object(cli, "build_package", side_effect=build_ephemeral),
                patch.object(cli, "install", return_value=backup),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = main(["install"])

            self.assertEqual(result, 0)
            self.assertEqual(stdout.getvalue(), f"{backup.resolve()}\n")
            self.assertEqual(
                stderr.getvalue(),
                "refind-forest: warning: unable to remove temporary staging "
                f"{temporary_root}: cleanup denied\n",
            )
            self.assertTrue(temporary_root.exists())
            cleanup.assert_called_once_with(temporary_root)

    def test_install_failure_remains_primary_when_cleanup_also_fails(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as manual_cleanup_directory:
            temporary_root = Path(manual_cleanup_directory) / "install-staging"
            temporary_root.mkdir()

            def build_ephemeral(output: Path, *_args: object) -> None:
                output.mkdir()

            with (
                patch.object(
                    cli,
                    "discover_esp_label",
                    return_value="SYSTEM",
                ),
                patch.object(
                    cli.tempfile,
                    "mkdtemp",
                    return_value=str(temporary_root),
                ),
                patch.object(
                    cli.shutil,
                    "rmtree",
                    side_effect=OSError("cleanup denied"),
                ) as cleanup,
                patch.object(cli, "build_package", side_effect=build_ephemeral),
                patch.object(
                    cli,
                    "install",
                    side_effect=RuntimeError("injected install failure"),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = main(["install"])

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                set(stderr.getvalue().splitlines()),
                {
                    "refind-forest: injected install failure",
                    (
                        "refind-forest: warning: unable to remove temporary staging "
                        f"{temporary_root}: cleanup denied"
                    ),
                },
            )
            self.assertTrue(temporary_root.exists())
            cleanup.assert_called_once_with(temporary_root)

    def test_install_interrupt_remains_primary_when_staging_cleanup_exits(
        self,
    ) -> None:
        primary_error = KeyboardInterrupt("injected install interruption")
        cleanup_error = SystemExit("injected cleanup exit")
        caught: BaseException | None = None
        with tempfile.TemporaryDirectory() as manual_cleanup_directory:
            temporary_root = Path(manual_cleanup_directory) / "install-staging"
            temporary_root.mkdir()

            def build_ephemeral(output: Path, *_args: object) -> None:
                output.mkdir()

            with (
                patch.object(cli, "discover_esp_label", return_value="SYSTEM"),
                patch.object(
                    cli.tempfile,
                    "mkdtemp",
                    return_value=str(temporary_root),
                ),
                patch.object(cli, "build_package", side_effect=build_ephemeral),
                patch.object(cli, "install", side_effect=primary_error),
                patch.object(cli.shutil, "rmtree", side_effect=cleanup_error),
            ):
                try:
                    main(["install"])
                except BaseException as error:
                    caught = error

        self.assertIs(caught, primary_error)
        assert caught is not None
        self.assertIn(
            "SystemExit: injected cleanup exit",
            "\n".join(caught.__notes__),
        )

    def test_verify_prints_confirmation_when_install_is_valid(self) -> None:
        stdout = io.StringIO()
        with (
            patch.object(cli, "verify", return_value=[]) as verify,
            redirect_stdout(stdout),
        ):
            result = main(["verify", "--esp", "/fake/esp"])

        self.assertEqual(result, 0)
        verify.assert_called_once_with(Path("/fake/esp"))
        self.assertEqual(stdout.getvalue(), "Forest theme verification passed.\n")

    def test_verify_combines_all_errors_into_one_cli_error(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(cli, "verify", return_value=["bad manifest", "bad config"]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = main(["verify", "--esp", "/fake/esp"])

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "refind-forest: verification failed: bad manifest; bad config\n",
        )

    def test_switch_theme_dispatches_and_prints_active_variant(self) -> None:
        stdout = io.StringIO()
        with (
            patch.object(cli, "switch_theme") as switch_theme,
            redirect_stdout(stdout),
        ):
            result = main(["switch-theme", "b", "--esp", "/fake/esp"])

        self.assertEqual(result, 0)
        switch_theme.assert_called_once_with("b", Path("/fake/esp"))
        self.assertEqual(stdout.getvalue(), "Active Forest theme: b\n")

    def test_rollback_resolves_relative_backup_and_prints_confirmation(self) -> None:
        stdout = io.StringIO()
        with (
            patch.object(cli, "rollback") as rollback,
            redirect_stdout(stdout),
        ):
            result = main(["rollback", "backups/snapshot", "--esp", "/fake/esp"])

        self.assertEqual(result, 0)
        rollback.assert_called_once_with(
            ROOT / "backups" / "snapshot",
            Path("/fake/esp"),
        )
        self.assertEqual(stdout.getvalue(), "Forest theme rollback complete.\n")

    def test_runtime_errors_are_reported_without_traceback(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(cli, "build_package", side_effect=OSError("disk full")),
            redirect_stderr(stderr),
        ):
            result = main(["build", "--output", "/tmp/unused-forest-build"])

        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "refind-forest: disk full\n")

    def test_package_module_exposes_cli_help(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", ["refind-forest", "--help"]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_module("refind_forest", run_name="__main__")

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        for command in ("build", "install", "verify", "switch-theme", "rollback"):
            self.assertIn(command, stdout.getvalue())

    def test_bin_wrapper_is_executable_and_exposes_cli_help(self) -> None:
        wrapper = ROOT / "bin" / "refind-forest"
        source_root = (ROOT / "src").resolve()
        original_cwd = Path.cwd()
        original_sys_path = sys.path
        cached_refind_modules = {
            name: module
            for name, module in sys.modules.items()
            if name == "refind_forest" or name.startswith("refind_forest.")
        }
        isolated_modules = {
            name: module
            for name, module in sys.modules.items()
            if name not in cached_refind_modules
        }
        isolated_path = [
            entry
            for entry in sys.path
            if Path(entry or original_cwd).resolve() != source_root
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            with (
                chdir(temporary_directory),
                patch.dict(sys.modules, isolated_modules, clear=True),
                patch.object(sys, "argv", [str(wrapper), "--help"]),
                patch.object(sys, "path", isolated_path),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertFalse(
                    any(
                        name == "refind_forest"
                        or name.startswith("refind_forest.")
                        for name in sys.modules
                    )
                )
                self.assertNotEqual(Path.cwd(), original_cwd)
                self.assertTrue(
                    all(
                        Path(entry or Path.cwd()).resolve() != source_root
                        for entry in sys.path
                    )
                )
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(wrapper), run_name="__main__")

        self.assertTrue(os.access(wrapper, os.X_OK))
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("usage: refind-forest", stdout.getvalue())
        self.assertEqual(Path.cwd(), original_cwd)
        self.assertIs(sys.path, original_sys_path)
        self.assertEqual(
            {
                name
                for name in sys.modules
                if name == "refind_forest" or name.startswith("refind_forest.")
            },
            set(cached_refind_modules),
        )
        for name, module in cached_refind_modules.items():
            self.assertIs(sys.modules.get(name), module)


if __name__ == "__main__":
    unittest.main()

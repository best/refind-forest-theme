import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = PROJECT_ROOT / "Makefile"

PUBLIC_TARGETS = (
    "help",
    "setup",
    "test",
    "audit",
    "theme-build",
    "build",
    "deterministic",
    "check",
    "ci",
    "clean",
    "distclean",
    "theme-install",
    "theme-verify",
    "theme-switch",
    "theme-rollback",
    "loader-build",
    "loader-verify",
    "loader-sign",
    "loader-backup-init",
    "loader-stage",
    "loader-status",
    "loader-boot-next",
    "loader-promote",
    "loader-rollback",
    "loader-smoke",
)

PUBLIC_VARIABLES = (
    "SYSTEM_PYTHON",
    "VENV",
    "PYTHON",
    "SUDO",
    "THEME_OUTPUT",
    "ESP_LABEL",
    "ESP",
    "THEME_BACKUP_ROOT",
    "VARIANT",
    "BACKUP_PATH",
    "LOADER_OUTPUT",
    "LOADER_CACHE",
    "LOADER_IMAGE",
    "SIGNED_LOADER_IMAGE",
    "LOADER_BACKUP_ROOT",
    "QEMU_OUTPUT",
    "TEST_ARGS",
    "CONFIRM",
)

CONFIRMED_TARGETS = (
    "theme-install",
    "theme-switch",
    "theme-rollback",
    "loader-sign",
    "loader-backup-init",
    "loader-stage",
    "loader-boot-next",
    "loader-promote",
    "loader-rollback",
)

BACKUP_PATH_TARGETS = (
    "theme-rollback",
    "loader-status",
    "loader-boot-next",
    "loader-promote",
    "loader-rollback",
)


class MakefileContractTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "synthetic project"
        self.root.mkdir()

        if MAKEFILE.is_file():
            shutil.copy2(MAKEFILE, self.root / "Makefile")

        self.command_log = self.root / "commands.log"
        self.python_log = self.root / "python.log"
        self.fake_sudo = self.root / "fake-sudo"
        self.fake_python = self.root / "system-python"
        self._write_executable(
            self.fake_sudo,
            """#!/bin/sh
set -eu
: "${COMMAND_LOG:?}"
for argument in "$@"; do
    printf '%s\\n' "$argument"
done >>"$COMMAND_LOG"
""",
        )
        self._write_executable(
            self.fake_python,
            """#!/bin/sh
set -eu
: "${PYTHON_LOG:?}"
{
    printf 'call'
    for argument in "$@"; do
        printf '\\t%s' "$argument"
    done
    printf '\\n'
} >>"$PYTHON_LOG"
if [ "${1-}" = -m ] && [ "${2-}" = venv ] && [ -n "${3-}" ]; then
    mkdir -p -- "$3/bin"
    cp -- "$0" "$3/bin/python"
    chmod +x "$3/bin/python"
fi
""",
        )
        for relative in (
            "bin/refind-forest",
            "bin/refind-loader",
            "tools/qemu_refind_smoke.sh",
        ):
            self._write_executable(
                self.root / relative,
                "#!/bin/sh\nexit 0\n",
            )
        (self.root / "tools" / "check_public_tree.py").write_text(
            "raise SystemExit(0)\n",
            encoding="ascii",
        )

        self.esp = self.root / "synthetic esp"
        self.theme_backup_root = self.root / "theme backups"
        self.loader_backup_root = self.root / "loader backups"
        self.backup_path = self.root / "transaction backup"
        self.loader_image = self.root / "unsigned loader.efi"
        self.signed_loader_image = self.root / "signed loader.efi"
        self.loader_image.write_bytes(b"synthetic unsigned image")
        self.signed_loader_image.write_bytes(b"synthetic signed image")
        self.backup_path.mkdir()

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="ascii")
        path.chmod(0o755)

    def run_make(
        self,
        *targets: str,
        cwd: Path | None = None,
        dry_run: bool = False,
        ignore_errors: bool = False,
        extra_environment: dict[str, str] | None = None,
        **variables: str,
    ) -> subprocess.CompletedProcess[str]:
        command = ["make", "--no-print-directory"]
        if dry_run:
            command.append("--dry-run")
        if ignore_errors:
            command.append("--ignore-errors")
        command.extend(targets)
        command.extend(f"{name}={value}" for name, value in variables.items())
        environment = os.environ.copy()
        for inherited in (
            *PUBLIC_VARIABLES,
            "MAKEFLAGS",
            "MFLAGS",
            "MAKEOVERRIDES",
        ):
            environment.pop(inherited, None)
        environment.update(
            {
                "COMMAND_LOG": str(self.command_log),
                "PYTHON_LOG": str(self.python_log),
                "LC_ALL": "C",
            }
        )
        if extra_environment is not None:
            environment.update(extra_environment)
        return subprocess.run(
            command,
            cwd=cwd or self.root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def make_variables(self, **overrides: str) -> dict[str, str]:
        variables = {
            "PYTHON": str(self.fake_python),
            "SYSTEM_PYTHON": str(self.fake_python),
            "SUDO": str(self.fake_sudo),
            "THEME_OUTPUT": str(self.root / "theme output"),
            "ESP_LABEL": "SYNTHETIC",
            "ESP": str(self.esp),
            "THEME_BACKUP_ROOT": str(self.theme_backup_root),
            "VARIANT": "a",
            "BACKUP_PATH": str(self.backup_path),
            "LOADER_OUTPUT": str(self.root / "loader output"),
            "LOADER_CACHE": str(self.root / "loader cache"),
            "LOADER_IMAGE": str(self.loader_image),
            "SIGNED_LOADER_IMAGE": str(self.signed_loader_image),
            "LOADER_BACKUP_ROOT": str(self.loader_backup_root),
        }
        variables.update(overrides)
        return variables

    def sudo_arguments(self) -> list[str]:
        if not self.command_log.exists():
            return []
        arguments = self.command_log.read_text(encoding="utf-8").splitlines()
        if arguments and arguments[0] == "--":
            return arguments[1:]
        return arguments

    def assert_make_succeeds(
        self, result: subprocess.CompletedProcess[str]
    ) -> None:
        self.assertEqual(
            result.returncode,
            0,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def assert_make_fails(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(
            result.returncode,
            0,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_default_goal_is_side_effect_free_help_and_lists_public_targets(
        self,
    ) -> None:
        self.assertTrue(MAKEFILE.is_file(), f"missing Makefile: {MAKEFILE}")

        default = self.run_make()
        explicit = self.run_make("help")

        self.assert_make_succeeds(default)
        self.assert_make_succeeds(explicit)
        self.assertEqual(default.stdout, explicit.stdout)
        self.assertFalse(self.command_log.exists())
        self.assertFalse((self.root / ".venv").exists())
        for target in PUBLIC_TARGETS:
            with self.subTest(target=target):
                self.assertIn(target, default.stdout)
        for variable in PUBLIC_VARIABLES:
            with self.subTest(variable=variable):
                self.assertIn(variable, default.stdout)

    def test_setup_creates_configurable_venv_once_and_installs_editable(self) -> None:
        venv = self.root / "venv with spaces"
        variables = self.make_variables(
            VENV=str(venv),
            PYTHON=str(venv / "bin" / "python"),
        )

        first = self.run_make("setup", **variables)
        second = self.run_make("setup", **variables)

        self.assert_make_succeeds(first)
        self.assert_make_succeeds(second)
        calls = self.python_log.read_text(encoding="utf-8").splitlines()
        venv_calls = [line for line in calls if "\t-m\tvenv\t" in line]
        install_calls = [
            line for line in calls if "\t-m\tpip\tinstall\t-e\t." in line
        ]
        self.assertEqual(venv_calls, [f"call\t-m\tvenv\t{venv}"])
        self.assertEqual(len(install_calls), 2, calls)

    def test_setup_rejects_venv_outside_checkout_before_running_python(
        self,
    ) -> None:
        outside = Path(self.temporary.name) / "outside venv"

        result = self.run_make(
            "setup",
            **self.make_variables(
                VENV=str(outside),
                PYTHON=str(outside / "bin" / "python"),
            ),
        )

        self.assert_make_fails(result)
        self.assertIn("outside the project", result.stdout + result.stderr)
        self.assertFalse(self.python_log.exists())
        self.assertFalse(outside.exists())

    def test_unprivileged_targets_use_configured_python_and_expected_clis(
        self,
    ) -> None:
        variables = self.make_variables()
        expected = {
            "test": ("-W error -m unittest discover -s tests -v",),
            "audit": ("tools/check_public_tree.py .",),
            "theme-build": (
                "./bin/refind-forest build",
                str(self.root / "theme output"),
                "SYNTHETIC",
            ),
            "loader-build": (
                "./bin/refind-loader build",
                str(self.root / "loader output"),
                str(self.root / "loader cache"),
            ),
            "loader-verify": (
                "./bin/refind-loader verify",
                str(self.loader_image),
            ),
            "loader-smoke": (
                "tools/qemu_refind_smoke.sh",
                str(self.signed_loader_image),
            ),
        }

        for target, phrases in expected.items():
            with self.subTest(target=target):
                result = self.run_make(
                    target,
                    dry_run=True,
                    **variables,
                )
                self.assert_make_succeeds(result)
                output = " ".join(result.stdout.split())
                if target != "loader-smoke":
                    self.assertIn(str(self.fake_python), output)
                self.assertNotIn(str(self.fake_sudo), output)
                for phrase in phrases:
                    self.assertIn(phrase, output)

    def test_check_and_ci_aggregate_their_documented_quality_gates(self) -> None:
        expected = {
            "check": (
                "unittest",
                "tools/check_public_tree.py",
                "manifest.json",
                "git diff --check",
            ),
            "ci": (
                "unittest",
                "./bin/refind-forest build",
                "tools/check_public_tree.py",
                "git diff --check",
            ),
        }

        for target, phrases in expected.items():
            with self.subTest(target=target):
                result = self.run_make(
                    target,
                    dry_run=True,
                    **self.make_variables(),
                )
                self.assert_make_succeeds(result)
                output = " ".join(result.stdout.split())
                for phrase in phrases:
                    self.assertIn(phrase, output)

    def test_deterministic_target_builds_two_fresh_trees_and_compares_them(
        self,
    ) -> None:
        result = self.run_make(
            "deterministic",
            dry_run=True,
            **self.make_variables(),
        )

        self.assert_make_succeeds(result)
        output = " ".join(result.stdout.split())
        self.assertGreaterEqual(output.count("./bin/refind-forest build"), 2)
        self.assertIn("manifest.json", output)
        self.assertTrue(
            any(command in output for command in ("cmp ", "diff ", "sha256sum")),
            output,
        )

    def test_whitespace_checks_committed_staged_and_unstaged_content(
        self,
    ) -> None:
        for state in ("committed", "staged", "unstaged"):
            with self.subTest(state=state):
                repository = self.root / state
                repository.mkdir()
                shutil.copy2(MAKEFILE, repository / "Makefile")
                tracked = repository / "tracked.txt"
                tracked.write_text("clean\n", encoding="ascii")
                subprocess.run(
                    ["git", "init", "--quiet"],
                    cwd=repository,
                    check=True,
                )
                subprocess.run(
                    ["git", "add", "--", "Makefile", "tracked.txt"],
                    cwd=repository,
                    check=True,
                )
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Make Test",
                        "-c",
                        "user.email=make-test@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "--quiet",
                        "-m",
                        "clean baseline",
                    ],
                    cwd=repository,
                    check=True,
                )

                tracked.write_text("trailing whitespace \n", encoding="ascii")
                if state in ("committed", "staged"):
                    subprocess.run(
                        ["git", "add", "--", "tracked.txt"],
                        cwd=repository,
                        check=True,
                    )
                if state == "committed":
                    subprocess.run(
                        [
                            "git",
                            "-c",
                            "user.name=Make Test",
                            "-c",
                            "user.email=make-test@example.invalid",
                            "-c",
                            "commit.gpgsign=false",
                            "commit",
                            "--quiet",
                            "-m",
                            "bad whitespace",
                        ],
                        cwd=repository,
                        check=True,
                    )

                result = subprocess.run(
                    ["make", "--no-print-directory", "whitespace"],
                    cwd=repository,
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assert_make_fails(result)
                self.assertIn("trailing whitespace", result.stdout + result.stderr)

    def test_confirmation_is_exact_and_checked_before_privileged_command(
        self,
    ) -> None:
        for target in CONFIRMED_TARGETS:
            for confirmation in ("", "yes", "YESx"):
                with self.subTest(target=target, confirmation=confirmation):
                    self.command_log.unlink(missing_ok=True)
                    result = self.run_make(
                        target,
                        **self.make_variables(CONFIRM=confirmation),
                    )
                    self.assert_make_fails(result)
                    self.assertIn("CONFIRM=YES", result.stdout + result.stderr)
                    self.assertEqual(self.sudo_arguments(), [])

    def test_ignore_errors_cannot_bypass_confirmation_before_sudo(self) -> None:
        result = self.run_make(
            "theme-install",
            ignore_errors=True,
            **self.make_variables(CONFIRM="NO"),
        )

        self.assert_make_fails(result)
        self.assertIn("CONFIRM=YES", result.stdout + result.stderr)
        self.assertEqual(self.sudo_arguments(), [])

    def test_exported_confirmation_does_not_replace_explicit_make_argument(
        self,
    ) -> None:
        result = self.run_make(
            "theme-install",
            extra_environment={"CONFIRM": "YES"},
            **self.make_variables(),
        )

        self.assert_make_fails(result)
        self.assertIn("CONFIRM=YES", result.stdout + result.stderr)
        self.assertEqual(self.sudo_arguments(), [])

    def test_makeflags_confirmation_cannot_authorize_privileged_command(
        self,
    ) -> None:
        for makeflags in (
            "CONFIRM=YES",
            "CONFIRM=YES confirm_argument=YES",
            "CONFIRM=YES assert-confirm=",
        ):
            with self.subTest(makeflags=makeflags):
                self.command_log.unlink(missing_ok=True)
                result = self.run_make(
                    "theme-install",
                    ignore_errors=True,
                    extra_environment={"MAKEFLAGS": makeflags},
                    **self.make_variables(),
                )

                self.assert_make_fails(result)
                self.assertIn("explicit argument", result.stdout + result.stderr)
                self.assertEqual(self.sudo_arguments(), [])

    def test_nested_make_does_not_inherit_parent_make_control_flags(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MAKEFLAGS": "TEST_ARGS=tests.test_makefile",
                "MFLAGS": "--silent",
                "MAKEOVERRIDES": "TEST_ARGS",
                "TEST_ARGS": "tests.test_makefile",
            },
        ):
            result = self.run_make(
                "test",
                dry_run=True,
                **self.make_variables(),
            )

        self.assert_make_succeeds(result)
        self.assertIn(
            "-m unittest discover -s tests -v",
            " ".join(result.stdout.split()),
        )

    def test_switch_rejects_missing_or_invalid_variant_before_sudo(self) -> None:
        for variant in ("", "A", "c", "a b"):
            with self.subTest(variant=variant):
                self.command_log.unlink(missing_ok=True)
                result = self.run_make(
                    "theme-switch",
                    **self.make_variables(CONFIRM="YES", VARIANT=variant),
                )
                self.assert_make_fails(result)
                self.assertIn("VARIANT", result.stdout + result.stderr)
                self.assertEqual(self.sudo_arguments(), [])

    def test_transaction_targets_reject_missing_backup_path_before_sudo(
        self,
    ) -> None:
        for target in BACKUP_PATH_TARGETS:
            with self.subTest(target=target):
                self.command_log.unlink(missing_ok=True)
                result = self.run_make(
                    target,
                    **self.make_variables(CONFIRM="YES", BACKUP_PATH=""),
                )
                self.assert_make_fails(result)
                self.assertIn("BACKUP_PATH", result.stdout + result.stderr)
                self.assertEqual(self.sudo_arguments(), [])

    def test_theme_targets_preserve_quoted_parameters_behind_fake_sudo(self) -> None:
        cases = {
            "theme-install": [
                "./bin/refind-forest",
                "install",
                "--esp",
                str(self.esp),
                "--backup-root",
                str(self.theme_backup_root),
            ],
            "theme-verify": [
                "./bin/refind-forest",
                "verify",
                "--esp",
                str(self.esp),
            ],
            "theme-switch": [
                "./bin/refind-forest",
                "switch-theme",
                "b",
                "--esp",
                str(self.esp),
            ],
            "theme-rollback": [
                "./bin/refind-forest",
                "rollback",
                str(self.backup_path),
                "--esp",
                str(self.esp),
            ],
        }

        for target, expected_suffix in cases.items():
            with self.subTest(target=target):
                self.command_log.unlink(missing_ok=True)
                variables = self.make_variables(VARIANT="b", CONFIRM="YES")
                if target in ("theme-verify",):
                    variables.pop("CONFIRM")
                result = self.run_make(target, **variables)
                self.assert_make_succeeds(result)
                arguments = self.sudo_arguments()
                self.assertEqual(arguments[0], str(self.fake_python.resolve()))
                self.assertEqual(arguments[1:], expected_suffix)

    def test_loader_targets_preserve_quoted_parameters_behind_fake_sudo(self) -> None:
        cases = {
            "loader-sign": [
                "./bin/refind-loader",
                "sign",
                str(self.loader_image),
                "--output",
                str(self.signed_loader_image),
            ],
            "loader-stage": [
                "./bin/refind-loader",
                "stage",
                str(self.signed_loader_image),
                "--esp",
                str(self.esp),
                "--backup-root",
                str(self.loader_backup_root),
            ],
            "loader-status": [
                "./bin/refind-loader",
                "status",
                str(self.backup_path),
                "--esp",
                str(self.esp),
            ],
            "loader-boot-next": [
                "./bin/refind-loader",
                "boot-next",
                str(self.backup_path),
            ],
            "loader-promote": [
                "./bin/refind-loader",
                "promote",
                str(self.backup_path),
                "--esp",
                str(self.esp),
            ],
            "loader-rollback": [
                "./bin/refind-loader",
                "rollback",
                str(self.backup_path),
                "--esp",
                str(self.esp),
            ],
        }

        for target, expected_suffix in cases.items():
            with self.subTest(target=target):
                self.command_log.unlink(missing_ok=True)
                variables = self.make_variables(CONFIRM="YES")
                if target == "loader-status":
                    variables.pop("CONFIRM")
                result = self.run_make(target, **variables)
                self.assert_make_succeeds(result)
                arguments = self.sudo_arguments()
                self.assertEqual(arguments[0], str(self.fake_python.resolve()))
                self.assertEqual(arguments[1:], expected_suffix)

    def test_loader_backup_initialization_is_private_and_interceptable(self) -> None:
        result = self.run_make(
            "loader-backup-init",
            **self.make_variables(CONFIRM="YES"),
        )

        self.assert_make_succeeds(result)
        arguments = self.sudo_arguments()
        self.assertIn("install", Path(arguments[0]).name)
        self.assertIn("0700", arguments)
        self.assertIn("root", arguments)
        self.assertEqual(arguments[-2], "--")
        self.assertEqual(arguments[-1], str(self.loader_backup_root))

    def test_cleaning_never_removes_backups_or_paths_outside_checkout(self) -> None:
        outside = Path(self.temporary.name) / "outside sentinel"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("keep\n", encoding="ascii")
        backups = self.root / "backups"
        backups.mkdir()
        (backups / "keep.json").write_text("{}\n", encoding="ascii")
        for relative in ("build", ".cache", ".venv"):
            directory = self.root / relative
            directory.mkdir()
            (directory / "generated.txt").write_text("generated\n", encoding="ascii")

        clean = self.run_make(
            "clean",
            **self.make_variables(
                THEME_OUTPUT=str(outside),
                LOADER_OUTPUT=str(outside),
                LOADER_CACHE=str(outside),
                VENV=str(outside),
            ),
        )

        self.assert_make_succeeds(clean)
        self.assertFalse((self.root / "build").exists())
        self.assertTrue((self.root / ".cache").exists())
        self.assertTrue((self.root / ".venv").exists())
        self.assertTrue((backups / "keep.json").is_file())
        self.assertTrue(sentinel.is_file())

        distclean = self.run_make("distclean", **self.make_variables())

        self.assert_make_succeeds(distclean)
        self.assertFalse((self.root / ".cache").exists())
        self.assertFalse((self.root / ".venv").exists())
        self.assertTrue((backups / "keep.json").is_file())
        self.assertTrue(sentinel.is_file())


if __name__ == "__main__":
    unittest.main()

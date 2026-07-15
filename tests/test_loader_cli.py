from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import errno
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from refind_forest import cli as theme_cli
from refind_forest.build import build_package
from refind_forest.install import install, rollback, switch_theme
from refind_forest.loader import cli as loader_cli
from refind_forest.loader.deploy import LoaderStatus


ROOT = Path(__file__).resolve().parents[1]


class LoaderCliContractTests(unittest.TestCase):
    def test_dedicated_loader_cli_files_exist(self) -> None:
        self.assertTrue(
            (ROOT / "src" / "refind_forest" / "loader" / "cli.py").is_file()
        )
        self.assertTrue((ROOT / "bin" / "refind-loader").is_file())

    def test_parser_exposes_only_the_eight_explicit_loader_commands(self) -> None:
        builder = getattr(loader_cli, "_build_parser", None)
        self.assertIsNotNone(builder, "loader CLI parser is missing")
        parser = builder()
        subparsers = next(
            action
            for action in parser._actions
            if action.__class__.__name__ == "_SubParsersAction"
        )

        self.assertEqual(
            set(subparsers.choices),
            {
                "build",
                "verify",
                "sign",
                "stage",
                "boot-next",
                "status",
                "promote",
                "rollback",
            },
        )
        self.assertNotIn("reboot", subparsers.choices)

    def test_readme_documents_the_exact_two_phase_loader_workflow(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="ascii")
        backup_directory_command = (
            "sudo install -d -m 0700 -o root -g root \\\n"
            "  /var/lib/refind-forest/loader-backups"
        )
        stage_command = (
            "sudo ./bin/refind-loader stage "
            "build/refind-loader/refind_x64.signed.efi"
        )
        for command in (
            "./bin/refind-loader build --output build/refind-loader",
            "sudo ./bin/refind-loader sign build/refind-loader/refind_x64.efi",
            stage_command,
            'sudo ./bin/refind-loader boot-next "$BACKUP_PATH"',
            'sudo ./bin/refind-loader status "$BACKUP_PATH"',
            'sudo ./bin/refind-loader promote "$BACKUP_PATH"',
            'sudo ./bin/refind-loader rollback "$BACKUP_PATH"',
        ):
            self.assertIn(command, readme)
        self.assertEqual(readme.count(backup_directory_command), 1)
        self.assertLess(
            readme.index(backup_directory_command), readme.index(stage_command)
        )
        self.assertIn("No command reboots the machine automatically.", readme)
        self.assertIn("build/refind-theme", readme)
        self.assertIn("retained public artifact", readme)

    def test_theme_installer_has_no_loader_or_nvram_option(self) -> None:
        parser = theme_cli._build_parser()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(["install", "--loader", "candidate.efi"])
        self.assertEqual(raised.exception.code, 2)

    def test_loader_cache_is_outside_both_build_output_trees(self) -> None:
        args = loader_cli._build_parser().parse_args(
            ["build", "--output", "build/refind-loader"]
        )
        self.assertEqual(args.cache, Path(".cache/refind-loader"))

    def test_theme_lifecycle_never_writes_loader_or_nvram_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            esp = root / "esp"
            refind = esp / "EFI" / "refind"
            ubuntu = esp / "EFI" / "ubuntu"
            windows = esp / "EFI" / "Microsoft" / "Boot"
            refind.mkdir(parents=True)
            ubuntu.mkdir(parents=True)
            windows.mkdir(parents=True)
            loader = refind / "refind_x64.efi"
            loader.write_bytes(b"immutable loader sentinel")
            (refind / "refind.conf").write_bytes(b"timeout 20\nuse_nvram false\n")
            (ubuntu / "grubx64.efi").write_bytes(b"immutable GRUB sentinel")
            (windows / "bootmgfw.efi").write_bytes(
                b"immutable Windows sentinel"
            )
            nvram = root / "raw-efivars.snapshot"
            nvram.write_bytes(b"immutable raw NVRAM sentinel")
            staging = root / "staging"
            build_package(
                staging,
                ROOT / "assets" / "source" / "ubuntu-logo.png",
                "SYSTEM",
            )
            backup_root = root / "backups"

            def assert_boot_state_unchanged() -> None:
                self.assertEqual(loader.read_bytes(), b"immutable loader sentinel")
                self.assertEqual(
                    nvram.read_bytes(), b"immutable raw NVRAM sentinel"
                )

            with mock.patch(
                "subprocess.run",
                side_effect=AssertionError(
                    "theme lifecycle must not invoke an NVRAM command"
                ),
            ):
                backup = install(
                    staging,
                    esp,
                    backup_root,
                    require_root=False,
                )
                assert_boot_state_unchanged()
                switch_theme("b", esp, require_root=False)
                assert_boot_state_unchanged()
                rollback(backup, esp, require_root=False)
                assert_boot_state_unchanged()


class LoaderCliDispatchTests(unittest.TestCase):
    def test_build_and_verify_are_offline_and_do_not_require_root(self) -> None:
        built = ROOT / "staging" / "refind_x64.efi"
        stdout = io.StringIO()
        with (
            mock.patch.object(
                loader_cli,
                "_require_root",
                side_effect=AssertionError("root check"),
                create=True,
            ),
            mock.patch.object(
                loader_cli, "build_loader", return_value=built, create=True
            ) as build_loader,
            mock.patch.object(
                loader_cli, "_verify_loader_image", create=True
            ) as verify_loader,
            redirect_stdout(stdout),
        ):
            build_result = loader_cli.main(
                ["build", "--output", "staging", "--cache", "loader-cache"]
            )
            verify_result = loader_cli.main(["verify", "candidate.efi"])

        self.assertEqual((build_result, verify_result), (0, 0))
        build_loader.assert_called_once_with(
            ROOT / "staging", ROOT / "loader-cache"
        )
        verify_loader.assert_called_once_with(ROOT / "candidate.efi")
        self.assertEqual(
            stdout.getvalue(),
            f"{built.resolve()}\nLoader verification passed: "
            f"{(ROOT / 'candidate.efi').resolve()}\n",
        )

    def test_mutating_commands_refuse_before_dispatch_when_not_root(self) -> None:
        stderr = io.StringIO()
        operation_names = (
            "_sign_loader",
            "stage_loader",
            "set_candidate_boot_next",
            "promote_loader",
            "rollback_loader",
        )
        commands = (
            ["sign", "candidate.efi"],
            ["stage", "candidate.efi"],
            ["boot-next", "/backup/transaction"],
            ["promote", "/backup/transaction"],
            ["rollback", "/backup/transaction"],
        )
        with (
            mock.patch("os.geteuid", return_value=1000),
            redirect_stderr(stderr),
        ):
            for command, operation_name in zip(commands, operation_names, strict=True):
                operation = mock.Mock()
                with mock.patch.object(
                    loader_cli, operation_name, operation, create=True
                ):
                    self.assertEqual(loader_cli.main(command), 1)
                operation.assert_not_called()

        self.assertEqual(
            stderr.getvalue().splitlines(),
            ["refind-loader: loader mutation requires root privileges"] * 5,
        )

    def test_loader_operations_dispatch_to_the_separate_deployment_api(self) -> None:
        transaction = Path("/var/lib/refind-forest/loader-backups/loader-test")
        signed = ROOT / "candidate.signed.efi"
        status = LoaderStatus(
            "staged",
            "a" * 64,
            "b" * 64,
            "00AF",
            "0001",
            ("0001", "0002"),
        )
        stdout = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                loader_cli, "stage_loader", return_value=transaction
            ) as stage,
            mock.patch.object(
                loader_cli, "set_candidate_boot_next"
            ) as boot_next,
            mock.patch.object(
                loader_cli, "loader_status", return_value=status
            ) as report_status,
            mock.patch.object(loader_cli, "promote_loader") as promote,
            mock.patch.object(loader_cli, "rollback_loader") as rollback,
            redirect_stdout(stdout),
        ):
            self.assertEqual(loader_cli.main(["stage", str(signed)]), 0)
            self.assertEqual(loader_cli.main(["boot-next", str(transaction)]), 0)
            self.assertEqual(loader_cli.main(["status", str(transaction)]), 0)
            self.assertEqual(loader_cli.main(["promote", str(transaction)]), 0)
            self.assertEqual(loader_cli.main(["rollback", str(transaction)]), 0)

        stage.assert_called_once_with(
            signed,
            Path("/boot/efi"),
            Path("/var/lib/refind-forest/loader-backups"),
        )
        boot_next.assert_called_once_with(transaction)
        report_status.assert_called_once_with(transaction, Path("/boot/efi"))
        promote.assert_called_once_with(transaction, Path("/boot/efi"))
        rollback.assert_called_once_with(transaction, Path("/boot/efi"))
        self.assertIn('"candidate_bootnum": "00AF"', stdout.getvalue())


class LoaderOfflineVerificationTests(unittest.TestCase):
    def test_verification_binds_pe_and_disassembly_checks_to_one_open_image(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "candidate.efi"
            image.write_bytes(b"stable loader bytes")
            calls: list[list[str]] = []

            def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(command)
                self.assertEqual(command[0], "/usr/bin/objdump")
                self.assertEqual(Path(command[-1]).read_bytes(), b"stable loader bytes")
                self.assertNotEqual(Path(command[-1]), image)
                image.write_bytes(b"replacement loader bytes")
                self.assertNotIn("pass_fds", kwargs)
                self.assertEqual(
                    kwargs["env"],
                    {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
                )
                return subprocess.CompletedProcess(command, 0, "disassembly", "")

            with (
                mock.patch.object(
                    loader_cli,
                    "verify_pe",
                    return_value=SimpleNamespace(security_directory_size=0),
                    create=True,
                ) as verify_pe,
                mock.patch.object(
                    loader_cli, "reject_setmem_call_edges", create=True
                ) as reject_edges,
                mock.patch.object(
                    loader_cli, "_verify_local_store_semantics", create=True
                ) as verify_stores,
                mock.patch("subprocess.run", side_effect=run),
            ):
                try:
                    loader_cli._verify_loader_image(image)
                except (AttributeError, NotImplementedError, OSError) as error:
                    self.fail(str(error))

        self.assertEqual(len(calls), 1)
        verified_path = verify_pe.call_args.args[0]
        self.assertEqual(verified_path, Path(calls[0][-1]))
        self.assertNotEqual(verified_path, image)
        self.assertEqual(verify_pe.call_args.args[1], loader_cli.SBAT_PATH.read_bytes())
        reject_edges.assert_called_once_with("disassembly")
        verify_stores.assert_called_once_with(
            "disassembly",
            loader_cli._ALL_STORE_SITES,
            require_function_symbols=False,
        )

    def test_verification_checks_the_local_signature_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "candidate.signed.efi"
            image.write_bytes(b"signed loader")
            certificate_data = b"approved public certificate"
            image.with_suffix(".crt").write_bytes(certificate_data)
            verified_certificate: list[tuple[str, bytes]] = []

            def verify_local_signature(path: Path, certificate: Path) -> None:
                self.assertEqual(path.name, "candidate.efi")
                verified_certificate.append(
                    (certificate.name, certificate.read_bytes())
                )

            with (
                mock.patch.object(
                    loader_cli,
                    "_root_certificate_bytes",
                    return_value=certificate_data,
                ),
                mock.patch.object(
                    loader_cli,
                    "verify_pe",
                    return_value=SimpleNamespace(security_directory_size=64),
                    create=True,
                ),
                mock.patch.object(
                    loader_cli, "reject_setmem_call_edges", create=True
                ),
                mock.patch.object(
                    loader_cli, "_verify_local_store_semantics", create=True
                ),
                mock.patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "", ""),
                ),
                mock.patch.object(
                    loader_cli,
                    "verify_signed",
                    side_effect=verify_local_signature,
                    create=True,
                ) as verify_signed,
            ):
                try:
                    loader_cli._verify_loader_image(image)
                except (AttributeError, NotImplementedError, OSError) as error:
                    self.fail(str(error))

        self.assertEqual(verify_signed.call_count, 1)
        self.assertEqual(
            verified_certificate,
            [("certificate.crt", certificate_data)],
        )


class LoaderCertificateTrustTests(unittest.TestCase):
    def test_loader_cli_source_does_not_embed_a_certificate_fingerprint(self) -> None:
        source = (
            ROOT / "src" / "refind_forest" / "loader" / "cli.py"
        ).read_text(encoding="ascii")

        self.assertNotIn("CERTIFICATE_SHA256", source)

    def test_approved_certificate_accepts_a_sidecar_matching_root_trust(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sidecar = Path(temporary) / "candidate.crt"
            certificate_data = b"locally trusted public certificate"
            sidecar.write_bytes(certificate_data)

            with mock.patch.object(
                loader_cli,
                "_root_certificate_bytes",
                return_value=certificate_data,
            ) as root_certificate:
                self.assertEqual(
                    loader_cli._approved_certificate_bytes(sidecar),
                    certificate_data,
                )

        root_certificate.assert_called_once_with()

    def test_approved_certificate_rejects_a_sidecar_not_matching_root_trust(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sidecar = Path(temporary) / "candidate.crt"
            sidecar.write_bytes(b"untrusted public certificate")

            with mock.patch.object(
                loader_cli,
                "_root_certificate_bytes",
                return_value=b"locally trusted public certificate",
            ) as root_certificate:
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    loader_cli._approved_certificate_bytes(sidecar)

        root_certificate.assert_called_once_with()

    def test_root_certificate_accepts_secure_local_bytes_without_a_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certificate = Path(temporary) / "trusted.crt"
            certificate_data = b"site-specific public certificate"
            certificate.write_bytes(certificate_data)

            @contextmanager
            def open_certificate(
                path: Path,
                description: str,
                *,
                private: bool,
            ):
                self.assertEqual(path, certificate)
                self.assertEqual(description, "signing certificate")
                self.assertFalse(private)
                descriptor = os.open(certificate, os.O_RDONLY)
                try:
                    yield descriptor
                finally:
                    os.close(descriptor)

            with (
                mock.patch.object(loader_cli, "CERTIFICATE_PATH", certificate),
                mock.patch.object(
                    loader_cli,
                    "_open_root_owned_regular",
                    side_effect=open_certificate,
                ) as open_root_certificate,
            ):
                self.assertEqual(
                    loader_cli._root_certificate_bytes(), certificate_data
                )
            open_root_certificate.assert_called_once_with(
                certificate, "signing certificate", private=False
            )

    def test_sidecar_trust_does_not_bypass_root_certificate_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate_data = b"same public certificate"
            sidecar = root / "candidate.crt"
            trust_certificate = root / "trusted.crt"
            sidecar.write_bytes(certificate_data)
            trust_certificate.write_bytes(certificate_data)
            if trust_certificate.stat().st_uid == 0:
                os.chown(trust_certificate, 65534, 65534)
            self.assertNotEqual(trust_certificate.stat().st_uid, 0)

            with mock.patch.object(
                loader_cli, "CERTIFICATE_PATH", trust_certificate
            ):
                with self.assertRaisesRegex(RuntimeError, "not owned by root"):
                    loader_cli._approved_certificate_bytes(sidecar)

    def test_sidecar_trust_does_not_bypass_root_certificate_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate_data = b"same public certificate"
            sidecar = root / "candidate.crt"
            trust_certificate = root / "trusted.crt"
            sidecar.write_bytes(certificate_data)
            trust_certificate.write_bytes(certificate_data)
            trust_certificate.chmod(0o666)
            metadata = trust_certificate.stat()
            unsafe_root_metadata = SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=0,
            )
            open_root_owned_regular = loader_cli._open_root_owned_regular

            @contextmanager
            def open_with_root_metadata(
                path: Path,
                description: str,
                *,
                private: bool,
            ):
                with mock.patch.object(
                    loader_cli.os,
                    "fstat",
                    return_value=unsafe_root_metadata,
                ):
                    with open_root_owned_regular(
                        path, description, private=private
                    ) as descriptor:
                        yield descriptor

            with (
                mock.patch.object(
                    loader_cli, "CERTIFICATE_PATH", trust_certificate
                ),
                mock.patch.object(
                    loader_cli,
                    "_open_root_owned_regular",
                    side_effect=open_with_root_metadata,
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "unsafe permissions"):
                    loader_cli._approved_certificate_bytes(sidecar)

    def test_sidecar_trust_does_not_bypass_root_certificate_path_safety(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate_data = b"same public certificate"
            sidecar = root / "candidate.crt"
            trust_target = root / "trusted-target.crt"
            trust_link = root / "trusted.crt"
            sidecar.write_bytes(certificate_data)
            trust_target.write_bytes(certificate_data)
            trust_target.chmod(0o644)
            trust_link.symlink_to(trust_target.name)

            with mock.patch.object(loader_cli, "CERTIFICATE_PATH", trust_link):
                with self.assertRaisesRegex(RuntimeError, "symbolic link"):
                    loader_cli._approved_certificate_bytes(sidecar)


class LoaderSigningTests(unittest.TestCase):
    _RETAINED_PREFIX = "publication artifact retained for invoking-user removal: "

    def retained_publication_paths(self, error: BaseException) -> list[Path]:
        notes = getattr(error, "__notes__", ())
        return [
            Path(note.removeprefix(self._RETAINED_PREFIX))
            for note in notes
            if note.startswith(self._RETAINED_PREFIX)
        ]

    @contextmanager
    def signing_pipeline(self, sign: object):
        with (
            mock.patch.object(loader_cli, "_verify_loader_image"),
            mock.patch.object(
                loader_cli, "_run_sbsign", side_effect=sign, create=True
            ) as run_sbsign,
            mock.patch.object(
                loader_cli,
                "loaded_section_hashes",
                return_value={".text": "same"},
                create=True,
            ),
            mock.patch.object(loader_cli, "verify_signed"),
            mock.patch.object(
                loader_cli,
                "_root_certificate_bytes",
                return_value=b"public certificate",
                create=True,
            ),
        ):
            yield run_sbsign

    def test_root_owned_private_input_rejects_actual_unsafe_mode(self) -> None:
        root_owned_public_file = Path("/etc/hosts")
        metadata = root_owned_public_file.stat()
        self.assertEqual(metadata.st_uid, 0)
        self.assertNotEqual(metadata.st_mode & 0o077, 0)

        with self.assertRaisesRegex(RuntimeError, "unsafe permissions"):
            with loader_cli._open_root_owned_regular(
                root_owned_public_file, "private signing key", private=True
            ):
                self.fail("unsafe private input was opened")

    def test_root_owned_input_rejects_an_actual_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "key.pem"
            link.symlink_to("/etc/hosts")

            with self.assertRaisesRegex(RuntimeError, "symbolic link"):
                with loader_cli._open_root_owned_regular(
                    link, "private signing key", private=True
                ):
                    self.fail("symbolic link was opened")

    def test_root_owned_input_rejects_an_actual_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "key.fifo"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                with loader_cli._open_root_owned_regular(
                    fifo, "private signing key", private=True
                ):
                    self.fail("FIFO was opened")

    def test_sign_refuses_a_group_writable_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_directory = Path(temporary) / "loader-output"
            output_directory.mkdir()
            output_directory.chmod(0o775)
            image = output_directory / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")

            with self.assertRaisesRegex(RuntimeError, "unsafe permissions"):
                loader_cli._sign_loader(image)

    def test_sign_verifies_before_signing_and_publishes_only_identical_load_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            events: list[str] = []
            certificate_paths: list[Path] = []

            def verify_unsigned(path: Path) -> None:
                events.append("verify-unsigned")
                self.assertEqual(path.read_bytes(), b"unsigned loader")

            def sign(
                unsigned: Path,
                signed: Path,
                _key: Path,
                certificate: Path,
            ) -> None:
                self.assertEqual(events, ["verify-unsigned"])
                self.assertEqual(unsigned.read_bytes(), b"unsigned loader")
                self.assertEqual(certificate.read_bytes(), b"public certificate")
                self.assertNotEqual(certificate, loader_cli.CERTIFICATE_PATH)
                certificate_paths.append(certificate)
                signed.write_bytes(b"signed loader")
                events.append("sbsign")

            def section_hashes(path: Path) -> dict[str, str]:
                events.append(f"hash-{path.name}")
                return {".text": "same", "__pe_load_metadata__": "same"}

            def verify_signature(path: Path, certificate: Path) -> None:
                self.assertEqual(path.read_bytes(), b"signed loader")
                self.assertEqual(certificate.read_bytes(), b"public certificate")
                self.assertEqual(certificate_paths, [certificate])
                events.append("verify-signature")

            with (
                mock.patch.object(
                    loader_cli, "_verify_loader_image", side_effect=verify_unsigned
                ),
                mock.patch.object(
                    loader_cli, "_run_sbsign", side_effect=sign, create=True
                ),
                mock.patch.object(
                    loader_cli,
                    "loaded_section_hashes",
                    side_effect=section_hashes,
                    create=True,
                ),
                mock.patch.object(
                    loader_cli, "verify_signed", side_effect=verify_signature
                ),
                mock.patch.object(
                    loader_cli,
                    "_root_certificate_bytes",
                    return_value=b"public certificate",
                    create=True,
                ) as root_certificate,
            ):
                try:
                    output = loader_cli._sign_loader(image)
                except NotImplementedError as error:
                    self.fail(str(error))

            self.assertEqual(output, image.with_name("refind_x64.signed.efi"))
            self.assertEqual(output.read_bytes(), b"signed loader")
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            public_certificate = output.with_suffix(".crt")
            self.assertEqual(public_certificate.read_bytes(), b"public certificate")
            self.assertEqual(public_certificate.stat().st_mode & 0o777, 0o644)
            root_certificate.assert_called_once_with()
            self.assertEqual(
                events,
                [
                    "verify-unsigned",
                    "sbsign",
                    "hash-unsigned.efi",
                    "hash-signed.efi",
                    "verify-signature",
                ],
            )

    def test_sign_does_not_publish_when_loaded_section_hashes_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = image.with_name("refind_x64.signed.efi")

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"mutated signed loader")

            with (
                mock.patch.object(loader_cli, "_verify_loader_image"),
                mock.patch.object(
                    loader_cli, "_run_sbsign", side_effect=sign, create=True
                ),
                mock.patch.object(
                    loader_cli,
                    "loaded_section_hashes",
                    side_effect=({".text": "old"}, {".text": "new"}),
                    create=True,
                ),
                mock.patch.object(
                    loader_cli,
                    "_root_certificate_bytes",
                    return_value=b"public certificate",
                ),
                mock.patch.object(loader_cli, "verify_signed") as verify_signed,
            ):
                with self.assertRaisesRegex(RuntimeError, "loaded sections changed"):
                    loader_cli._sign_loader(image)

            self.assertFalse(output.exists())
            verify_signed.assert_not_called()

    def test_sign_rejects_a_parent_directory_swap_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_directory = root / "loader-output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            image = output_directory / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            displaced = root / "displaced-loader-output"

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                output_directory.rename(displaced)
                output_directory.mkdir(mode=0o700)
                output_directory.chmod(0o700)
                (output_directory / "foreign").write_bytes(b"foreign directory")
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign):
                with self.assertRaisesRegex(RuntimeError, "directory identity"):
                    loader_cli._sign_loader(image)

            self.assertEqual(
                (output_directory / "foreign").read_bytes(), b"foreign directory"
            )
            self.assertFalse(
                (output_directory / "refind_x64.signed.efi").exists()
            )
            self.assertFalse(
                (output_directory / "refind_x64.signed.crt").exists()
            )

    def test_sign_preserves_foreign_output_and_reports_retained_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            sidecar = output.with_suffix(".crt")
            real_open = os.open
            replaced = False

            def open_then_replace(
                path: os.PathLike[str] | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if (
                    not replaced
                    and flags & os.O_CREAT
                    and flags & os.O_EXCL
                    and Path(path).name == output.name
                ):
                    replaced = True
                    output.unlink()
                    output.write_bytes(b"foreign replacement")
                return descriptor

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign), mock.patch.object(
                loader_cli.os, "open", side_effect=open_then_replace
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "identity|read-back"
                ) as raised:
                    loader_cli._sign_loader(image)

            self.assertTrue(replaced)
            self.assertEqual(output.read_bytes(), b"foreign replacement")
            self.assertFalse(os.path.lexists(sidecar))
            retained = self.retained_publication_paths(raised.exception)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"public certificate")
            self.assertEqual(retained[0].stat().st_mode & 0o777, 0o644)

    def test_sign_reports_retained_sidecar_when_output_creation_collides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            sidecar = output.with_suffix(".crt")
            real_open = os.open
            collided = False

            def open_with_collision(
                path: os.PathLike[str] | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal collided
                if (
                    not collided
                    and flags & os.O_CREAT
                    and flags & os.O_EXCL
                    and Path(path).name == output.name
                ):
                    collided = True
                    output.write_bytes(b"foreign collision")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign), mock.patch.object(
                loader_cli.os, "open", side_effect=open_with_collision
            ):
                with self.assertRaises(
                    (FileExistsError, RuntimeError)
                ) as raised:
                    loader_cli._sign_loader(image)

            self.assertTrue(collided)
            self.assertEqual(output.read_bytes(), b"foreign collision")
            self.assertFalse(os.path.lexists(sidecar))
            retained = self.retained_publication_paths(raised.exception)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"public certificate")
            self.assertEqual(retained[0].stat().st_mode & 0o777, 0o644)

    def test_sign_reports_both_retained_outputs_after_publication_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            sidecar = output.with_suffix(".crt")
            real_fsync = os.fsync
            failed = False

            def fail_output_fsync(descriptor: int) -> None:
                nonlocal failed
                target = os.readlink(f"/proc/self/fd/{descriptor}")
                if not failed and target == str(output):
                    failed = True
                    raise OSError(errno.EIO, "injected publication failure")
                real_fsync(descriptor)

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign), mock.patch.object(
                loader_cli.os, "fsync", side_effect=fail_output_fsync
            ):
                with self.assertRaises(OSError) as raised:
                    loader_cli._sign_loader(image)

            self.assertTrue(failed)
            self.assertFalse(os.path.lexists(output))
            self.assertFalse(os.path.lexists(sidecar))
            retained = self.retained_publication_paths(raised.exception)
            self.assertEqual(len(retained), 2)
            self.assertEqual(
                {path.read_bytes() for path in retained},
                {b"signed loader", b"public certificate"},
            )
            self.assertEqual(
                {path.stat().st_mode & 0o777 for path in retained}, {0o644}
            )

    def test_double_retention_failures_report_every_actual_retained_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            real_fsync = os.fsync
            publication_failed = False
            retained_file_failed = False
            retained_directory_failed = False

            def fail_publication_and_each_retained_fsync(descriptor: int) -> None:
                nonlocal publication_failed
                nonlocal retained_file_failed
                nonlocal retained_directory_failed
                target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                if not publication_failed and target == output:
                    publication_failed = True
                    raise OSError(errno.EIO, "injected publication failure")
                if ".refind-loader-retained-" not in target.as_posix():
                    real_fsync(descriptor)
                    return
                if target.is_file() and not retained_file_failed:
                    retained_file_failed = True
                    raise OSError(errno.EIO, "injected retained-file fsync failure")
                if target.is_dir() and not retained_directory_failed:
                    retained_directory_failed = True
                    raise OSError(errno.EIO, "injected retained-dir fsync failure")
                real_fsync(descriptor)

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign), mock.patch.object(
                loader_cli.os,
                "fsync",
                side_effect=fail_publication_and_each_retained_fsync,
            ):
                with self.assertRaises(OSError) as raised:
                    loader_cli._sign_loader(image)

            actual = {
                path.resolve()
                for directory in root.glob(".refind-loader-retained-*")
                for path in directory.iterdir()
                if path.is_file()
            }
            reported = {
                path.resolve()
                for path in self.retained_publication_paths(raised.exception)
            }
            self.assertTrue(publication_failed)
            self.assertTrue(retained_file_failed)
            self.assertTrue(retained_directory_failed)
            self.assertEqual(
                {path.read_bytes() for path in actual},
                {b"signed loader", b"public certificate"},
            )
            self.assertEqual(reported, actual)

    def test_sign_retry_converges_after_reported_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            real_fsync = os.fsync
            failed = False

            def fail_output_fsync_once(descriptor: int) -> None:
                nonlocal failed
                target = os.readlink(f"/proc/self/fd/{descriptor}")
                if not failed and target == str(output):
                    failed = True
                    raise OSError(errno.EIO, "injected publication failure")
                real_fsync(descriptor)

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign):
                with mock.patch.object(
                    loader_cli.os, "fsync", side_effect=fail_output_fsync_once
                ), self.assertRaises(OSError) as raised:
                    loader_cli._sign_loader(image)
                retained = self.retained_publication_paths(raised.exception)

                result = loader_cli._sign_loader(image)

            self.assertTrue(failed)
            self.assertEqual(result, output)
            self.assertEqual(output.read_bytes(), b"signed loader")
            self.assertEqual(output.with_suffix(".crt").read_bytes(), b"public certificate")
            self.assertEqual(len(retained), 2)
            self.assertTrue(all(path.exists() for path in retained))

    def test_owned_entry_quarantine_retains_instead_of_unlinking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.efi"
            artifact.write_bytes(b"owned artifact")
            metadata = artifact.stat()
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    loader_cli.os,
                    "unlink",
                    side_effect=AssertionError("quarantine must never unlink"),
                ) as unlink:
                    retained = loader_cli._quarantine_owned_entry(
                        directory_fd,
                        root,
                        artifact.name,
                        (metadata.st_dev, metadata.st_ino),
                    )
            finally:
                os.close(directory_fd)

            unlink.assert_not_called()
            self.assertFalse(os.path.lexists(artifact))
            self.assertIsNotNone(retained)
            assert retained is not None
            self.assertEqual(retained.read_bytes(), b"owned artifact")
            self.assertEqual(retained.stat().st_mode & 0o777, 0o644)

    def test_owned_entry_quarantine_preserves_ambiguous_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.efi"
            artifact.write_bytes(b"owned artifact")
            metadata = artifact.stat()
            expected = metadata.st_dev, metadata.st_ino
            real_rename = loader_cli._rename_noreplace
            injected = False

            def rename_then_replace(
                source_fd: int,
                source: str,
                destination_fd: int,
                destination: str,
            ) -> None:
                nonlocal injected
                real_rename(
                    source_fd, source, destination_fd, destination
                )
                if injected or Path(source).name != artifact.name:
                    return
                injected = True
                quarantine = Path(f"/proc/self/fd/{destination_fd}").resolve()
                isolated = quarantine / Path(destination)
                isolated.rename(quarantine / "displaced-owned")
                isolated.write_bytes(b"foreign replacement")

            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    loader_cli,
                    "_rename_noreplace",
                    side_effect=rename_then_replace,
                ), self.assertRaisesRegex(RuntimeError, "foreign publication entry"):
                    loader_cli._quarantine_owned_entry(
                        directory_fd, root, artifact.name, expected
                    )
            finally:
                os.close(directory_fd)

            self.assertTrue(injected)
            self.assertFalse(os.path.lexists(artifact))
            quarantines = list(root.glob(".refind-loader-retained-*"))
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(
                (quarantines[0] / artifact.name).read_bytes(),
                b"foreign replacement",
            )
            self.assertEqual(
                (quarantines[0] / "displaced-owned").read_bytes(),
                b"owned artifact",
            )

    def test_owned_entry_quarantine_destination_collision_preserves_both(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.efi"
            artifact.write_bytes(b"owned artifact")
            metadata = artifact.stat()
            expected = metadata.st_dev, metadata.st_ino

            def collide_without_overwrite(
                _source_fd: int,
                _source_name: str,
                destination_fd: int,
                destination_name: str,
            ) -> None:
                quarantine = Path(
                    f"/proc/self/fd/{destination_fd}"
                ).resolve()
                (quarantine / destination_name).write_bytes(b"foreign artifact")
                raise FileExistsError(errno.EEXIST, "injected collision")

            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    loader_cli,
                    "_rename_noreplace",
                    side_effect=collide_without_overwrite,
                    create=True,
                ), self.assertRaisesRegex(
                    RuntimeError, "retention destination collision"
                ) as raised:
                    loader_cli._quarantine_owned_entry(
                        directory_fd, root, artifact.name, expected
                    )
            finally:
                os.close(directory_fd)

            self.assertEqual(artifact.read_bytes(), b"owned artifact")
            quarantines = list(root.glob(".refind-loader-retained-*"))
            self.assertEqual(len(quarantines), 1)
            foreign = quarantines[0] / artifact.name
            self.assertEqual(foreign.read_bytes(), b"foreign artifact")
            notes = getattr(raised.exception, "__notes__", ())
            self.assertTrue(any(str(artifact) in note for note in notes))
            self.assertTrue(any(str(foreign) in note for note in notes))

    def test_rename_noreplace_never_overwrites_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_directory = root / "source"
            destination_directory = root / "destination"
            source_directory.mkdir()
            destination_directory.mkdir()
            source = source_directory / "artifact"
            destination = destination_directory / "artifact"
            source.write_bytes(b"owned artifact")
            destination.write_bytes(b"foreign artifact")
            source_fd = os.open(source_directory, os.O_RDONLY | os.O_DIRECTORY)
            destination_fd = os.open(
                destination_directory, os.O_RDONLY | os.O_DIRECTORY
            )
            try:
                with self.assertRaises(FileExistsError):
                    loader_cli._rename_noreplace(
                        source_fd, source.name, destination_fd, destination.name
                    )
            finally:
                os.close(destination_fd)
                os.close(source_fd)

            self.assertEqual(source.read_bytes(), b"owned artifact")
            self.assertEqual(destination.read_bytes(), b"foreign artifact")

    def test_owned_entry_quarantine_preserves_replacement_after_initial_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.efi"
            artifact.write_bytes(b"owned artifact")
            metadata = artifact.stat()
            expected = metadata.st_dev, metadata.st_ino
            real_identity = loader_cli._entry_identity_at
            isolated_checks = 0

            def identity_then_replace(
                directory_fd: int, name: str
            ) -> tuple[int, int] | None:
                nonlocal isolated_checks
                if name == artifact.name:
                    isolated_checks += 1
                    if isolated_checks == 2:
                        quarantine = Path(
                            f"/proc/self/fd/{directory_fd}"
                        ).resolve()
                        isolated = quarantine / name
                        isolated.rename(quarantine / "displaced-owned")
                        isolated.write_bytes(b"foreign replacement")
                return real_identity(directory_fd, name)

            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    loader_cli,
                    "_entry_identity_at",
                    side_effect=identity_then_replace,
                ), self.assertRaisesRegex(RuntimeError, "foreign publication entry"):
                    loader_cli._quarantine_owned_entry(
                        directory_fd, root, artifact.name, expected
                    )
            finally:
                os.close(directory_fd)

            self.assertEqual(isolated_checks, 2)
            quarantines = list(root.glob(".refind-loader-retained-*"))
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(
                (quarantines[0] / artifact.name).read_bytes(),
                b"foreign replacement",
            )
            self.assertEqual(
                (quarantines[0] / "displaced-owned").read_bytes(),
                b"owned artifact",
            )

    def test_sign_rejects_an_existing_world_writable_certificate_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "refind_x64.efi"
            image.write_bytes(b"unsigned loader")
            output = root / "refind_x64.signed.efi"
            sidecar = output.with_suffix(".crt")
            sidecar.write_bytes(b"public certificate")
            sidecar.chmod(0o666)

            def sign(
                _unsigned: Path,
                signed: Path,
                _key: Path,
                _certificate: Path,
            ) -> None:
                signed.write_bytes(b"signed loader")

            with self.signing_pipeline(sign) as run_sbsign:
                with self.assertRaisesRegex(
                    RuntimeError, "certificate output already exists|unsafe permissions"
                ):
                    loader_cli._sign_loader(image, output)

            run_sbsign.assert_not_called()
            self.assertEqual(sidecar.read_bytes(), b"public certificate")
            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o666)
            self.assertFalse(output.exists())

    def test_sbsign_uses_open_root_owned_key_and_certificate_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.efi"
            signed = root / "signed.efi"
            key = root / "key.pem"
            certificate = root / "certificate.pem"
            unsigned.write_bytes(b"unsigned")
            key.write_bytes(b"key")
            certificate.write_bytes(b"certificate")

            @contextmanager
            def opened(path: Path, _description: str, *, private: bool):
                self.assertEqual(private, path == key)
                descriptor = Path(path).open("rb")
                try:
                    yield descriptor.fileno()
                finally:
                    descriptor.close()

            def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.assertEqual(command[0:2], ["/usr/bin/sbsign", "--key"])
                self.assertRegex(command[2], r"^/proc/self/fd/[0-9]+$")
                self.assertEqual(command[3], "--cert")
                self.assertRegex(command[4], r"^/proc/self/fd/[0-9]+$")
                self.assertEqual(command[5:7], ["--output", str(signed)])
                self.assertEqual(command[7], str(unsigned))
                self.assertEqual(set(kwargs["pass_fds"]), {
                    int(command[2].rsplit("/", 1)[1]),
                    int(command[4].rsplit("/", 1)[1]),
                })
                self.assertEqual(
                    kwargs["env"],
                    {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
                )
                signed.write_bytes(b"signed")
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                mock.patch.object(
                    loader_cli,
                    "_open_root_owned_regular",
                    side_effect=opened,
                    create=True,
                ),
                mock.patch("subprocess.run", side_effect=run),
            ):
                runner = getattr(loader_cli, "_run_sbsign", None)
                self.assertIsNotNone(runner, "sbsign runner is missing")
                runner(unsigned, signed, key, certificate)

            self.assertEqual(signed.read_bytes(), b"signed")

    def test_sbsign_reports_subprocess_start_and_exit_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.efi"
            signed = root / "signed.efi"
            key = root / "key.pem"
            certificate = root / "certificate.pem"
            for path in (unsigned, key, certificate):
                path.write_bytes(path.name.encode("ascii"))

            @contextmanager
            def opened(path: Path, _description: str, *, private: bool):
                self.assertEqual(private, path == key)
                with Path(path).open("rb") as source:
                    yield source.fileno()

            failures = (
                (
                    FileNotFoundError(errno.ENOENT, "missing sbsign"),
                    "failed to run sbsign",
                ),
                (
                    subprocess.CompletedProcess([], 23, "", "signing failed"),
                    "exit code 23.*signing failed",
                ),
            )
            for result, message in failures:
                subprocess_result = (
                    {"side_effect": result}
                    if isinstance(result, BaseException)
                    else {"return_value": result}
                )
                with self.subTest(message=message), mock.patch.object(
                    loader_cli,
                    "_open_root_owned_regular",
                    side_effect=opened,
                ), mock.patch.object(
                    loader_cli.subprocess, "run", **subprocess_result
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        loader_cli._run_sbsign(
                            unsigned, signed, key, certificate
                        )

    def test_sudo_publication_dispatches_only_to_the_forked_drop_path(self) -> None:
        arguments = (
            12,
            Path("/build/refind-loader"),
            (34, 56),
            "refind_x64.signed.efi",
            b"signed",
            "refind_x64.signed.crt",
            b"certificate",
        )
        with (
            mock.patch.object(loader_cli, "_fork_publication") as forked,
            mock.patch.object(
                loader_cli,
                "_publish_signed_files_in_process",
                side_effect=AssertionError("root publication ran in process"),
            ),
        ):
            loader_cli._publish_signed_files(*arguments, (1000, 1000))

        forked.assert_called_once_with(*arguments, (1000, 1000))

    def test_forked_publication_relays_retained_artifact_notes(self) -> None:
        first = Path("/build").joinpath(
            *(f"first-{index:02d}-" + "a" * 36 for index in range(58)),
            "first-retained-loader.efi",
        )
        second = Path("/build").joinpath(
            *(f"second-{index:02d}-" + "b" * 35 for index in range(58)),
            "second-retained-certificate.crt",
        )
        notes = [
            f"{loader_cli._RETAINED_ARTIFACT_NOTE}{first}",
            f"{loader_cli._RETAINED_ARTIFACT_NOTE}{second}",
        ]
        self.assertGreater(len("\n".join(notes).encode("ascii")), 5000)

        def fail_publication(*_args: object) -> None:
            error = RuntimeError("injected publication failure")
            for note in notes:
                error.add_note(note)
            raise error

        real_write = os.write
        interrupted = False

        def short_write(descriptor: int, data: bytes) -> int:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise InterruptedError(errno.EINTR, "injected relay interruption")
            return real_write(descriptor, data[:37])

        with (
            mock.patch.object(loader_cli, "_drop_publication_privileges"),
            mock.patch.object(
                loader_cli,
                "_publish_signed_files_in_process",
                side_effect=fail_publication,
            ),
            mock.patch.object(loader_cli.os, "write", side_effect=short_write),
        ):
            with self.assertRaises(RuntimeError) as raised:
                loader_cli._fork_publication(
                    -1,
                    Path("/build/refind-loader"),
                    (1, 2),
                    "signed.efi",
                    b"signed",
                    "signed.crt",
                    b"certificate",
                    (1000, 1000),
                )

        relayed = str(raised.exception)
        self.assertIn(str(first), relayed)
        self.assertIn(str(second), relayed)
        self.assertIn(first.name, relayed)
        self.assertIn(second.name, relayed)

    def test_publication_privilege_drop_is_permanent_and_clears_groups(self) -> None:
        events: list[tuple[object, ...]] = []
        with (
            mock.patch.object(
                loader_cli.os,
                "setgroups",
                side_effect=lambda groups: events.append(("groups", tuple(groups))),
            ),
            mock.patch.object(
                loader_cli.os,
                "setresgid",
                side_effect=lambda real, effective, saved: events.append(
                    ("gid", real, effective, saved)
                ),
            ),
            mock.patch.object(
                loader_cli.os,
                "setresuid",
                side_effect=lambda real, effective, saved: events.append(
                    ("uid", real, effective, saved)
                ),
            ),
            mock.patch.object(loader_cli.os, "getresgid", return_value=(1000,) * 3),
            mock.patch.object(loader_cli.os, "getresuid", return_value=(1001,) * 3),
            mock.patch.object(loader_cli.os, "umask", return_value=0o022) as umask,
        ):
            loader_cli._drop_publication_privileges(1001, 1000)

        self.assertEqual(
            events,
            [
                ("groups", ()),
                ("gid", 1000, 1000, 1000),
                ("uid", 1001, 1001, 1001),
            ],
        )
        umask.assert_called_once_with(0o077)


if __name__ == "__main__":
    unittest.main()

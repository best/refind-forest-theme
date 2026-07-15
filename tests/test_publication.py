import hashlib
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import tomllib
import unittest

from tools.check_public_tree import audit_tree


PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_FILES = {
    "LICENSE",
    "LICENSES/CC-BY-SA-4.0.txt",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.zh-CN.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "SECURITY.zh-CN.md",
}

DEP3_HEADER = """Description: Replace ABI-sensitive GNU-EFI SetMem calls with local stores
Origin: other, https://sourceforge.net/projects/refind/files/0.14.2/refind-src-0.14.2.tar.gz/download
Forwarded: no
Author: best
Last-Update: 2026-07-15
License: GPL-3.0-or-later and BSD-2-Clause and Expat"""

PRIVATE_AND_GENERATED_IGNORES = {
    ".cache/",
    ".env",
    ".venv/",
    "venv/",
    "dist/",
    "*.egg-info/",
    "*.efi",
    "*.crt",
    "*.cer",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.auth",
    "*.esl",
    "*.vars",
    "*.fd",
    "qemu-*/",
    "*.ppm",
    "*.log",
    ".idea/",
    ".vscode/",
}


class RepositoryLicenseTests(unittest.TestCase):
    def test_project_license_is_canonical_gpl_3(self) -> None:
        license_bytes = (PROJECT_ROOT / "LICENSE").read_bytes()

        self.assertEqual(
            hashlib.sha256(license_bytes).hexdigest(),
            "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
        )

    def test_cc_by_sa_license_is_canonical_legal_code(self) -> None:
        license_bytes = (
            PROJECT_ROOT / "LICENSES" / "CC-BY-SA-4.0.txt"
        ).read_bytes()

        self.assertEqual(
            hashlib.sha256(license_bytes).hexdigest(),
            "28a9529c7d0bb4dc51f4bf5c116a3d16ef247a052f7591466768ddf563fd1cf5",
        )

    def test_third_party_notices_cover_all_external_inputs(self) -> None:
        notices = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(
            encoding="ascii"
        )

        for component in ("rEFInd", "GNU-EFI", "Yaru", "Pillow", "DejaVu Sans"):
            with self.subTest(component=component):
                self.assertIn(component, notices)

    def test_trademark_notice_covers_referenced_marks_and_disclaimer(self) -> None:
        notice = (PROJECT_ROOT / "TRADEMARKS.md").read_text(encoding="ascii")

        for mark in (
            "rEFInd",
            "Flow Z13",
            "Ubuntu",
            "Windows",
            "Ventoy",
            "Linux",
            "UEFI",
            "ASUS",
            "ROG",
        ):
            with self.subTest(mark=mark):
                self.assertIn(mark, notice)
        self.assertIn("not endorsed", notice)


class RepositoryMetadataTests(unittest.TestCase):
    def test_required_open_source_files_exist(self) -> None:
        for relative in EXPECTED_FILES:
            with self.subTest(relative=relative):
                self.assertTrue((PROJECT_ROOT / relative).is_file(), relative)

    def test_python_metadata_declares_license_and_repository(self) -> None:
        metadata = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="ascii")
        )
        project = metadata["project"]

        self.assertEqual(
            project["description"],
            "Two rEFInd Forest themes with reproducible loader verification tooling",
        )
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["license"], "GPL-3.0-or-later")
        self.assertEqual(
            project["license-files"], ["LICENSE", "LICENSES/*.txt"]
        )
        self.assertEqual(project["authors"], [{"name": "best"}])
        self.assertEqual(project["requires-python"], ">=3.12")
        self.assertFalse(
            any(
                classifier.startswith("License ::")
                for classifier in project["classifiers"]
            ),
            "PEP 639 license expressions must not be combined with license classifiers",
        )
        for version in ("3.12", "3.14"):
            with self.subTest(version=version):
                self.assertIn(
                    f"Programming Language :: Python :: {version}",
                    project["classifiers"],
                )
        self.assertEqual(
            project["urls"]["Repository"],
            "https://github.com/best/refind-forest-theme",
        )
        self.assertEqual(
            project["urls"]["Issues"],
            "https://github.com/best/refind-forest-theme/issues",
        )

    def test_patch_has_exact_dep3_metadata_and_unchanged_diff(self) -> None:
        patch = (
            PROJECT_ROOT / "patches" / "refind-0.14.2-gnu-efi-abi.patch"
        ).read_bytes()
        prefix = f"{DEP3_HEADER}\n\n".encode("ascii")

        self.assertTrue(patch.startswith(prefix))
        self.assertEqual(
            hashlib.sha256(patch[len(prefix) :]).hexdigest(),
            "fa488ff8b9ace0ece0f6af1a38564548994148f29f7df817595de3208e127486",
        )
        header = patch[: len(prefix)].decode("ascii")
        for field in (
            "Description:",
            "Origin:",
            "Forwarded:",
            "Author:",
            "Last-Update:",
            "License:",
        ):
            with self.subTest(field=field):
                self.assertIn(field, header)

    def test_contribution_and_security_policies_cover_public_requirements(self) -> None:
        contributing = (PROJECT_ROOT / "CONTRIBUTING.md").read_text(
            encoding="ascii"
        )
        security = (PROJECT_ROOT / "SECURITY.md").read_text(encoding="ascii")
        contributing_text = " ".join(contributing.split())
        security_text = " ".join(security.split())

        for phrase in (
            "tests",
            "credentials",
            "machine snapshots",
            "Developer Certificate of Origin",
            "Signed-off-by:",
            "rights to contributed visual assets",
            "https://developercertificate.org/",
            "git commit -s",
        ):
            with self.subTest(document="CONTRIBUTING.md", phrase=phrase):
                self.assertIn(phrase, contributing_text)
        for phrase in (
            "GitHub private vulnerability reporting",
            "Do not open a public issue",
            "boot-chain",
            "https://github.com/best/refind-forest-theme/security/advisories/new",
        ):
            with self.subTest(document="SECURITY.md", phrase=phrase):
                self.assertIn(phrase, security_text)
        self.assertNotIn("mailto:", security)

    def test_readme_documents_source_only_use_and_firmware_safety(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="ascii")
        readme_text = " ".join(readme.split())

        for phrase in (
            "Safety warning",
            "root privileges",
            "EFI System Partition",
            "NVRAM",
            "source-only release",
            "source checkout",
            "wheel package data",
            "Python 3.12",
            "Python 3.14",
            "GPL-3.0-or-later",
            "CC-BY-SA-4.0",
            "not endorsed",
            "/etc/refind.d/keys/refind_local.key",
            "/etc/refind.d/keys/refind_local.crt",
            "matching private key and certificate",
            "does not generate, enroll, or distribute signing keys or certificates",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme_text)
        self.assertNotIn("pinned public certificate", readme)
        self.assertNotIn("CERTIFICATE_SHA256", readme)

    def test_private_and_generated_artifacts_are_ignored(self) -> None:
        entries = {
            line
            for line in (PROJECT_ROOT / ".gitignore").read_text(
                encoding="ascii"
            ).splitlines()
            if line and not line.startswith("#")
        }

        self.assertTrue(PRIVATE_AND_GENERATED_IGNORES <= entries)


class BilingualDocumentationTests(unittest.TestCase):
    DOCUMENT_PAIRS = (
        ("README.md", "README.zh-CN.md"),
        ("CONTRIBUTING.md", "CONTRIBUTING.zh-CN.md"),
        ("SECURITY.md", "SECURITY.zh-CN.md"),
    )

    def test_english_and_simplified_chinese_documents_link_to_each_other(
        self,
    ) -> None:
        for english_name, chinese_name in self.DOCUMENT_PAIRS:
            with self.subTest(english=english_name, chinese=chinese_name):
                english = (PROJECT_ROOT / english_name).read_text(encoding="ascii")
                chinese = (PROJECT_ROOT / chinese_name).read_text(encoding="utf-8")
                self.assertIn(f"[Simplified Chinese]({chinese_name})", english)
                self.assertIn(f"[English]({english_name})", chinese)

    def test_chinese_readme_preserves_build_and_firmware_safety_contract(
        self,
    ) -> None:
        readme = (PROJECT_ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
        normalized = " ".join(readme.split())

        for phrase in (
            "安全警告",
            "root 权限",
            "EFI 系统分区",
            "NVRAM",
            "仅源代码",
            "源码检出",
            "Python 3.12",
            "Python 3.14",
            "GPL-3.0-or-later",
            "CC-BY-SA-4.0",
            "/etc/refind.d/keys/refind_local.key",
            "/etc/refind.d/keys/refind_local.crt",
            "签名密钥",
            "证书",
            "不会生成、注册或分发签名密钥或证书",
            "不会自动重启",
            "非官方",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, normalized)
        self.assertNotIn("CERTIFICATE_SHA256", readme)

    def test_chinese_contribution_policy_preserves_privacy_and_dco_contract(
        self,
    ) -> None:
        document = (PROJECT_ROOT / "CONTRIBUTING.zh-CN.md").read_text(
            encoding="utf-8"
        )
        normalized = " ".join(document.split())

        for phrase in (
            "测试",
            "凭据",
            "机器快照",
            "EFI 系统分区",
            "NVRAM",
            "Developer Certificate of Origin",
            "Signed-off-by:",
            "视觉素材",
            "权利",
            "https://developercertificate.org/",
            "git commit -s",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, normalized)

    def test_chinese_security_policy_keeps_private_reporting_requirements(
        self,
    ) -> None:
        document = (PROJECT_ROOT / "SECURITY.zh-CN.md").read_text(
            encoding="utf-8"
        )
        normalized = " ".join(document.split())

        for phrase in (
            "GitHub 私密漏洞报告",
            "公开 issue",
            "启动链",
            "https://github.com/best/refind-forest-theme/security/advisories/new",
            "私钥",
            "证书",
            "NVRAM",
            "磁盘标识",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, normalized)
        self.assertNotIn("mailto:", document)

    def test_user_and_contributor_workflows_are_expressed_through_make(
        self,
    ) -> None:
        readmes = {
            "README.md": (PROJECT_ROOT / "README.md").read_text(encoding="ascii"),
            "README.zh-CN.md": (PROJECT_ROOT / "README.zh-CN.md").read_text(
                encoding="utf-8"
            ),
        }
        contributing = {
            "CONTRIBUTING.md": (PROJECT_ROOT / "CONTRIBUTING.md").read_text(
                encoding="ascii"
            ),
            "CONTRIBUTING.zh-CN.md": (
                PROJECT_ROOT / "CONTRIBUTING.zh-CN.md"
            ).read_text(encoding="utf-8"),
        }

        readme_commands = (
            "make help",
            "make setup",
            "make test",
            "make build",
            "make deterministic",
            "make audit",
            "make check",
            "make theme-install",
            "make theme-verify",
            "make theme-switch",
            "make theme-rollback",
            "make loader-build",
            "make loader-verify",
            "make loader-sign",
            "make loader-backup-init",
            "make loader-smoke",
            "make loader-stage",
            "make loader-status",
            "make loader-boot-next",
            "make loader-promote",
            "make loader-rollback",
        )
        for relative, document in readmes.items():
            for command in readme_commands:
                with self.subTest(relative=relative, command=command):
                    self.assertIn(command, document)

        for relative, document in contributing.items():
            for command in ("make help", "make setup", "make test", "make check"):
                with self.subTest(relative=relative, command=command):
                    self.assertIn(command, document)

        forbidden_direct_invocations = (
            "./bin/refind-forest",
            "./bin/refind-loader",
            "PYTHONPATH=src",
            "python -m unittest",
            "python3 -m unittest",
            "python -m pip",
            "python3 -m pip",
            "python -m venv",
            "python3 -m venv",
        )
        for relative, document in {**readmes, **contributing}.items():
            for invocation in forbidden_direct_invocations:
                with self.subTest(relative=relative, invocation=invocation):
                    self.assertNotIn(invocation, document)


class PublicTreeAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def make_tree(self, files: dict[str, str]) -> Path:
        root = Path(self.temporary.name) / secrets.token_hex(4)
        root.mkdir()
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")
        return root

    @staticmethod
    def initialize_git(root: Path, *tracked: str) -> None:
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True,
            capture_output=True,
        )
        if tracked:
            subprocess.run(
                ["git", "-C", str(root), "add", "--", *tracked],
                check=True,
                capture_output=True,
            )

    def test_auditor_rejects_forbidden_paths_and_sensitive_content(self) -> None:
        home_path = "/" + "home/synthetic-user/project"
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        cases = {
            "docs/superpowers/spec.md": "private plan",
            "build/candidate.efi": "binary",
            "keys/signing.key": "synthetic secret",
            "README.md": home_path,
            "config.txt": private_key_marker,
        }
        for relative, content in cases.items():
            with self.subTest(relative=relative):
                root = self.make_tree({relative: content})
                self.assertTrue(audit_tree(root))

    def test_auditor_rejects_synthetic_token_and_fingerprint_forms(self) -> None:
        synthetic_values = {
            "github.txt": "gh" + "p_" + "A" * 36,
            "github-fine-grained.txt": "github_" + "pat_" + "A" * 32,
            "aws.txt": "AK" + "IA" + "A" * 16,
            "aws-secret.txt": "aws_secret_" + "access_key = '" + "A" * 40 + "'",
            "certificate.txt": "CERTIFICATE_" + "SHA256 = " + "a" * 64,
            "home-quoted.txt": 'path = "' + "/" + 'home/synthetic-user"',
            "private-encrypted.txt": (
                "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"
            ),
        }

        for relative, content in synthetic_values.items():
            with self.subTest(relative=relative):
                root = self.make_tree({relative: content})
                self.assertTrue(audit_tree(root))

    def test_auditor_accepts_the_synthetic_public_fixture(self) -> None:
        root = self.make_tree(
            {"README.md": "public project\n", "src/app.py": "pass\n"}
        )

        self.assertEqual(audit_tree(root), [])

    def test_auditor_scans_only_tracked_files_when_index_has_paths(self) -> None:
        root = self.make_tree({"README.md": "public project\n"})
        self.initialize_git(root, "README.md")
        untracked = root / "build" / "candidate.efi"
        untracked.parent.mkdir()
        untracked.write_bytes(b"untracked generated output")

        self.assertEqual(audit_tree(root), [])

    def test_auditor_does_not_follow_tracked_parent_symlink(self) -> None:
        root = self.make_tree({"nested/file.txt": "public project\n"})
        self.initialize_git(root, "nested/file.txt")
        original = root / "tracked-original"
        (root / "nested").rename(original)
        outside = Path(self.temporary.name) / ("outside-" + secrets.token_hex(4))
        outside.mkdir()
        synthetic_home = "/" + "home/synthetic-user/private-project"
        (outside / "file.txt").write_text(synthetic_home, encoding="ascii")
        (root / "nested").symlink_to(outside, target_is_directory=True)

        findings = audit_tree(root)

        self.assertEqual(findings, ["nested/file.txt:0: symlink-parent"])
        self.assertNotIn("synthetic-user", "\n".join(findings))

    def test_auditor_falls_back_when_git_index_has_no_paths(self) -> None:
        root = self.make_tree({"keys/signing.key": "synthetic secret"})
        self.initialize_git(root)

        findings = audit_tree(root)

        self.assertTrue(any("forbidden-extension" in item for item in findings))

    def test_auditor_rejects_symlinks_without_following_them(self) -> None:
        root = self.make_tree({"target.txt": "public target\n"})
        (root / "linked.txt").symlink_to(root / "target.txt")

        findings = audit_tree(root)

        self.assertTrue(any(item == "linked.txt:0: symlink" for item in findings))

    def test_auditor_rejects_generated_components_at_any_depth(self) -> None:
        cases = {
            "nested/build/output.txt": "generated-or-private-path",
            "nested/backups/state.txt": "generated-or-private-path",
            "nested/cache/download.txt": "cache-path",
            "nested/.venv/package.txt": "virtual-environment-path",
            "nested/qemu-run/screen.txt": "qemu-output-path",
        }
        for relative, rule in cases.items():
            with self.subTest(relative=relative):
                root = self.make_tree({relative: "synthetic output\n"})
                findings = audit_tree(root)
                self.assertTrue(any(rule in item for item in findings), findings)

        clean = self.make_tree(
            {
                "nested/builder/output.txt": "public\n",
                "nested/cache-policy/readme.txt": "public\n",
                "nested/venv-notes/readme.txt": "public\n",
                "nested/qemu_notes/readme.txt": "public\n",
            }
        )
        self.assertEqual(audit_tree(clean), [])

    def test_auditor_enforces_size_limit_with_exact_yaru_exemption(self) -> None:
        root = self.make_tree({})
        oversized = b"x" * (1024 * 1024 + 1)
        (root / "large.bin").write_bytes(oversized)
        yaru = root / "assets" / "source" / "ubuntu-logo.png"
        yaru.parent.mkdir(parents=True)
        yaru.write_bytes(oversized)

        findings = audit_tree(root)

        self.assertEqual(findings, ["large.bin:0: file-too-large"])

    def test_private_plan_exclusion_uses_exact_path_prefix(self) -> None:
        synthetic_home = "/" + "home/synthetic-user/project"
        root = self.make_tree(
            {
                "docs/superpowers/private.md": synthetic_home,
                "docs/superpowers-archive/public.md": synthetic_home,
            }
        )

        findings = audit_tree(root, exclude_private_plans=True)

        self.assertEqual(
            findings,
            ["docs/superpowers-archive/public.md:1: home-path"],
        )

    def test_findings_are_deterministic_and_redact_matched_values(self) -> None:
        synthetic_home = "/" + "home/synthetic-user/private-project"
        root = self.make_tree(
            {
                "z.txt": "public\n" + synthetic_home + "\n",
                "a.txt": "-----BEGIN " + "PRIVATE KEY-----\n",
            }
        )

        findings = audit_tree(root)

        self.assertEqual(findings, sorted(findings))
        self.assertEqual(
            findings,
            ["a.txt:1: private-key", "z.txt:2: home-path"],
        )
        rendered = "\n".join(findings)
        self.assertNotIn("synthetic-user", rendered)
        self.assertNotIn("PRIVATE KEY", rendered)

    def test_cli_uses_zero_and_one_exit_codes_without_echoing_secrets(self) -> None:
        clean = self.make_tree({"README.md": "public project\n"})
        synthetic_home = "/" + "home/synthetic-user/private-project"
        dirty = self.make_tree({"README.md": synthetic_home + "\n"})
        private_plans = self.make_tree(
            {"docs/superpowers/private.md": synthetic_home + "\n"}
        )
        command = [sys.executable, str(PROJECT_ROOT / "tools/check_public_tree.py")]

        clean_result = subprocess.run(
            [*command, str(clean)],
            check=False,
            capture_output=True,
            text=True,
        )
        dirty_result = subprocess.run(
            [*command, str(dirty)],
            check=False,
            capture_output=True,
            text=True,
        )
        private_result = subprocess.run(
            [*command, str(private_plans)],
            check=False,
            capture_output=True,
            text=True,
        )
        excluded_result = subprocess.run(
            [*command, str(private_plans), "--exclude-private-plans"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(clean_result.returncode, 0, clean_result.stderr)
        self.assertEqual(dirty_result.returncode, 1, dirty_result.stderr)
        self.assertEqual(private_result.returncode, 1, private_result.stderr)
        self.assertEqual(excluded_result.returncode, 0, excluded_result.stderr)
        self.assertIn("README.md:1: home-path", dirty_result.stdout)
        self.assertNotIn("synthetic-user", dirty_result.stdout)


class RepositoryAutomationTests(unittest.TestCase):
    def test_ci_workflow_is_read_only_and_delegates_project_steps_to_make(
        self,
    ) -> None:
        workflow = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="ascii"
        )

        for phrase in (
            "push:",
            "pull_request:",
            "permissions:",
            "contents: read",
            'python-version: ["3.12", "3.14"]',
            "actions/checkout@v7",
            "actions/setup-python@v6",
            "python-version: ${{ matrix.python-version }}",
            "make setup",
            "make ci",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, workflow)
        self.assertNotIn("contents: write", workflow)
        for direct_command in (
            "python -m pip install -e .",
            "unittest discover",
            "./bin/refind-forest",
            "tools/check_public_tree.py",
            "git diff --check",
        ):
            with self.subTest(direct_command=direct_command):
                self.assertNotIn(direct_command, workflow)

    def test_issue_forms_collect_sanitized_reproduction_details(self) -> None:
        required_phrases = (
            "Project version",
            "Firmware / rEFInd version",
            "Reproduction steps",
            "Expected behavior",
            "Actual behavior",
            "Sanitized logs",
            "EFI variables",
            "keys",
            "certificates",
            "disk identifiers",
            "private boot configuration",
        )
        for relative in (
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
        ):
            with self.subTest(relative=relative):
                form = (PROJECT_ROOT / relative).read_text(encoding="ascii")
                for phrase in required_phrases:
                    self.assertIn(phrase, form)
                self.assertIn("required: true", form)

    def test_issue_template_config_disables_blank_security_reports(self) -> None:
        config = (
            PROJECT_ROOT / ".github/ISSUE_TEMPLATE/config.yml"
        ).read_text(encoding="ascii")

        self.assertIn("blank_issues_enabled: false", config)
        self.assertIn("Private vulnerability report", config)
        self.assertIn(
            "https://github.com/best/refind-forest-theme/security/advisories/new",
            config,
        )
        self.assertNotIn("mailto:", config)


if __name__ == "__main__":
    unittest.main()

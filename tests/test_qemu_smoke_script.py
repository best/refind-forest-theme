import os
import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SMOKE_SCRIPT = PROJECT_ROOT / "tools" / "qemu_refind_smoke.sh"


class QemuSmokeScriptTests(unittest.TestCase):
    def test_script_defines_the_isolated_ovmf_smoke_contract(self) -> None:
        self.assertTrue(SMOKE_SCRIPT.is_file(), f"missing script: {SMOKE_SCRIPT}")
        self.assertTrue(os.access(SMOKE_SCRIPT, os.X_OK))

        script = SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(script.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("set -euo pipefail", script)
        self.assertIn("LOADER OUTPUT_DIRECTORY", script)
        self.assertIn("OVMF_CODE", script)
        self.assertIn("OVMF_VARS", script)
        self.assertRegex(script, r"cp\s+--\s+\"\$ovmf_vars_template\"")
        self.assertIn("EFI/BOOT/BOOTX64.EFI", script)
        self.assertIn("fat:rw:", script)
        self.assertIn("-accel tcg", script)
        self.assertIn("-monitor", script)
        self.assertIn("unix:", script)
        self.assertIn("nc -U", script)
        self.assertIn("screendump", script)
        self.assertIn("screen.ppm", script)
        self.assertRegex(script, r"(?m)^quit$")
        self.assertRegex(script, r"wait\s+\"\$qemu_pid\"")
        self.assertRegex(
            script,
            r"iconv\s+-f\s+UTF-16\s+-t\s+UTF-8",
        )
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("timeout 0", script)
        self.assertIn("log_level 4", script)
        self.assertIn("use_nvram false", script)
        self.assertIn("showtools reboot,shutdown", script)

        forbidden = (
            "/boot/efi",
            "/sys/firmware/efi",
            "efibootmgr",
            "sudo",
            "rm -rf",
            "-enable-kvm",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, script)

        config = re.search(
            r"^timeout 0\n"
            r"log_level 4\n"
            r"use_nvram false\n"
            r"showtools reboot,shutdown$",
            script,
            re.MULTILINE,
        )
        self.assertIsNotNone(config)

    def test_hmp_failure_triggers_cleanup_before_waiting_for_qemu(self) -> None:
        script = SMOKE_SCRIPT.read_text(encoding="utf-8")
        hmp_command = script.index("nc -U")
        status_check = script.index("((monitor_status == 0))", hmp_command)
        qemu_wait = script.index('wait "$qemu_pid"', hmp_command)

        self.assertLess(status_check, qemu_wait)


if __name__ == "__main__":
    unittest.main()

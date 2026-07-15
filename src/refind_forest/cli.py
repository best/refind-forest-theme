"""Command-line interface for the rEFInd Forest theme."""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .build import build_package
from .install import discover_esp_label, install, rollback, switch_theme, verify


ROOT = Path(__file__).resolve().parents[2]
UBUNTU_SOURCE = ROOT / "assets" / "source" / "ubuntu-logo.png"


def _under_root(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def _remove_temporary_staging(
    path: Path,
    *,
    primary: BaseException | None = None,
) -> None:
    try:
        shutil.rmtree(path)
    except BaseException as error:
        if primary is not None:
            primary.add_note(
                "temporary staging cleanup also raised "
                f"{type(error).__name__}: {error}"
            )
        if isinstance(error, OSError):
            print(
                f"refind-forest: warning: unable to remove temporary staging {path}: "
                f"{error}",
                file=sys.stderr,
            )
            return
        if primary is None:
            raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="refind-forest",
        description="Build and manage the rEFInd Forest theme.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build",
        help="build the Forest theme staging package",
    )
    build_parser.add_argument("--output", type=Path, default=Path("build"))
    build_parser.add_argument("--esp-label", default="SYSTEM")

    install_parser = subparsers.add_parser(
        "install",
        help="build and install the Forest theme",
    )
    install_parser.add_argument("--esp", type=Path, default=Path("/boot/efi"))
    install_parser.add_argument(
        "--backup-root",
        type=Path,
        default=Path("backups"),
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="verify the installed Forest theme",
    )
    verify_parser.add_argument("--esp", type=Path, default=Path("/boot/efi"))

    switch_parser = subparsers.add_parser(
        "switch-theme",
        help="activate an installed Forest theme variant",
    )
    switch_parser.add_argument("variant", choices=("a", "b"))
    switch_parser.add_argument("--esp", type=Path, default=Path("/boot/efi"))

    rollback_parser = subparsers.add_parser(
        "rollback",
        help="restore a Forest theme installation backup",
    )
    rollback_parser.add_argument("backup", type=Path, metavar="BACKUP")
    rollback_parser.add_argument("--esp", type=Path, default=Path("/boot/efi"))

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "build":
            build_package(_under_root(args.output), UBUNTU_SOURCE, args.esp_label)
        elif args.command == "install":
            esp_label = discover_esp_label(args.esp)
            temporary = Path(tempfile.mkdtemp(prefix="refind-forest-"))
            try:
                staging = temporary / "build"
                build_package(staging, UBUNTU_SOURCE, esp_label)
                backup = install(staging, args.esp, _under_root(args.backup_root))
            except BaseException as primary:
                _remove_temporary_staging(temporary, primary=primary)
                raise
            else:
                _remove_temporary_staging(temporary)
            print(backup.resolve())
        elif args.command == "verify":
            errors = verify(args.esp)
            if errors:
                raise RuntimeError("verification failed: " + "; ".join(errors))
            print("Forest theme verification passed.")
        elif args.command == "switch-theme":
            switch_theme(args.variant, args.esp)
            print(f"Active Forest theme: {args.variant}")
        elif args.command == "rollback":
            rollback(_under_root(args.backup), args.esp)
            print("Forest theme rollback complete.")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"refind-forest: {error}", file=sys.stderr)
        return 1
    return 0

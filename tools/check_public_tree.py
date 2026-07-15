#!/usr/bin/env python3
"""Audit a candidate public repository without disclosing matched values."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Sequence


_MAX_FILE_SIZE = 1024 * 1024
_YARU_SOURCE_PATH = "assets/source/ubuntu-logo.png"
_FORBIDDEN_ARTIFACT_SUFFIXES = frozenset(
    {
        ".auth",
        ".cer",
        ".crt",
        ".efi",
        ".esl",
        ".fd",
        ".key",
        ".p12",
        ".pem",
        ".pfx",
        ".vars",
    }
)
_GENERATED_OR_PRIVATE_PARTS = frozenset(
    {
        ".superpowers",
        "backup",
        "backups",
        "build",
        "dist",
    }
)
_CACHE_PARTS = frozenset(
    {
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "cache",
    }
)
_VIRTUAL_ENVIRONMENT_PARTS = frozenset({".nox", ".tox", ".venv", "venv"})
_COVERAGE_PARTS = frozenset({".coverage", "coverage", "htmlcov"})
_CONTENT_RULES = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    ),
    (
        "github-token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
        ),
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "aws-secret-key",
        re.compile(
            r"\baws_secret_access_key\b\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9/+]{40}['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "home-path",
        re.compile(
            r"(?<![A-Za-z0-9_.-])/home/[A-Za-z0-9._-]+"
            r"(?=/|[^A-Za-z0-9._-]|$)"
        ),
    ),
    (
        "certificate-fingerprint",
        re.compile(
            r"\bCERTIFICATE_SHA256\b\s*=\s*['\"]?[0-9A-Fa-f]{64}['\"]?"
        ),
    ),
)


def _finding(relative: str, line_number: int, rule: str) -> str:
    return f"{relative}:{line_number}: {rule}"


def _is_private_plan_path(relative: str) -> bool:
    return relative == "docs/superpowers" or relative.startswith(
        "docs/superpowers/"
    )


def _path_rules(relative: str) -> list[str]:
    path = PurePosixPath(relative)
    parts = path.parts
    if not parts:
        return []

    rules = []
    if _is_private_plan_path(relative):
        rules.append("private-plan-path")
    if ".git" in parts:
        rules.append("git-internal-path")

    if any(
        part in _GENERATED_OR_PRIVATE_PARTS or part.endswith(".egg-info")
        for part in parts
    ):
        rules.append("generated-or-private-path")
    if any(part in _CACHE_PARTS for part in parts):
        rules.append("cache-path")
    if any(part in _VIRTUAL_ENVIRONMENT_PARTS for part in parts):
        rules.append("virtual-environment-path")
    if any(part.startswith("qemu-") for part in parts):
        rules.append("qemu-output-path")
    if any(
        part in _COVERAGE_PARTS or part.startswith(".coverage.") for part in parts
    ):
        rules.append("coverage-path")

    name = path.name.lower()
    if name in {"coverage.json", "coverage.xml"}:
        rules.append("coverage-path")
    if name.endswith((".log", ".ppm")):
        rules.append("qemu-output-path")
    if path.suffix.lower() in _FORBIDDEN_ARTIFACT_SUFFIXES:
        rules.append("forbidden-extension")
    return rules


def _tracked_paths(root: Path) -> list[str] | None:
    git_marker = root / ".git"
    if not os.path.lexists(git_marker):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None

    paths = [os.fsdecode(value) for value in result.stdout.split(b"\0") if value]
    return sorted(paths) or None


def _fallback_paths(root: Path) -> list[str]:
    paths = []
    pending = [PurePosixPath(".")]
    while pending:
        relative_directory = pending.pop()
        directory = (
            root
            if relative_directory == PurePosixPath(".")
            else root / relative_directory
        )
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            relative = (
                "."
                if relative_directory == PurePosixPath(".")
                else relative_directory.as_posix()
            )
            paths.append(relative)
            continue
        child_directories = []
        for entry in entries:
            relative = (
                PurePosixPath(entry.name)
                if relative_directory == PurePosixPath(".")
                else relative_directory / entry.name
            )
            if relative == PurePosixPath(".git"):
                continue
            try:
                if entry.is_symlink():
                    paths.append(relative.as_posix())
                elif entry.is_dir(follow_symlinks=False):
                    child_directories.append(relative)
                else:
                    paths.append(relative.as_posix())
            except OSError:
                paths.append(relative.as_posix())
        pending.extend(reversed(child_directories))
    return sorted(paths)


class _PathAccessError(Exception):
    def __init__(self, rule: str) -> None:
        super().__init__(rule)
        self.rule = rule


def _component_metadata(parent_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise _PathAccessError("missing-path") from error
    except OSError as error:
        raise _PathAccessError("unreadable-path") from error


def _open_beneath(root: Path, relative: str) -> tuple[int, os.stat_result]:
    path = PurePosixPath(relative)
    parts = path.parts
    if path.is_absolute() or not parts or any(part in {".", ".."} for part in parts):
        raise _PathAccessError("unsafe-path")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_fds = []
    try:
        try:
            current_fd = os.open(root, directory_flags)
        except OSError as error:
            raise _PathAccessError("unreadable-root") from error
        directory_fds.append(current_fd)

        for part in parts[:-1]:
            metadata = _component_metadata(current_fd, part)
            if stat.S_ISLNK(metadata.st_mode):
                raise _PathAccessError("symlink-parent")
            if not stat.S_ISDIR(metadata.st_mode):
                raise _PathAccessError("non-directory-parent")
            try:
                next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            except OSError as error:
                rule = (
                    "symlink-parent"
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}
                    else "unreadable-path"
                )
                raise _PathAccessError(rule) from error
            directory_fds.append(next_fd)
            current_fd = next_fd

        leaf = parts[-1]
        metadata = _component_metadata(current_fd, leaf)
        if stat.S_ISLNK(metadata.st_mode):
            raise _PathAccessError("symlink")
        try:
            descriptor = os.open(leaf, file_flags, dir_fd=current_fd)
        except OSError as error:
            rule = "symlink" if error.errno == errno.ELOOP else "unreadable-file"
            raise _PathAccessError(rule) from error
        try:
            stable_metadata = os.fstat(descriptor)
        except OSError as error:
            os.close(descriptor)
            raise _PathAccessError("unreadable-file") from error
        return descriptor, stable_metadata
    finally:
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _audit_path(root: Path, relative: str) -> list[str]:
    findings = [_finding(relative, 0, rule) for rule in _path_rules(relative)]
    descriptor: int | None = None
    try:
        descriptor, metadata = _open_beneath(root, relative)
    except _PathAccessError as error:
        findings.append(_finding(relative, 0, error.rule))
        return findings
    try:
        if not stat.S_ISREG(metadata.st_mode):
            findings.append(_finding(relative, 0, "non-regular-file"))
            return findings
        if metadata.st_size > _MAX_FILE_SIZE and relative != _YARU_SOURCE_PATH:
            findings.append(_finding(relative, 0, "file-too-large"))
            return findings
        try:
            with os.fdopen(descriptor, "rb") as source:
                descriptor = None
                data = source.read()
        except OSError:
            findings.append(_finding(relative, 0, "unreadable-file"))
            return findings
    finally:
        if descriptor is not None:
            os.close(descriptor)

    text = data.decode("utf-8", errors="replace")
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _CONTENT_RULES:
            if pattern.search(line):
                findings.append(_finding(relative, line_number, rule))
    return findings


def audit_tree(
    root: Path,
    *,
    exclude_private_plans: bool = False,
) -> list[str]:
    """Return deterministic redacted findings for a candidate public tree."""

    argument = Path(root)
    if argument.is_symlink():
        return [_finding(".", 0, "root-symlink")]
    try:
        resolved = argument.resolve(strict=True)
    except OSError:
        return [_finding(".", 0, "missing-root")]
    if not resolved.is_dir():
        return [_finding(".", 0, "root-not-directory")]

    findings = []
    git_marker = resolved / ".git"
    if git_marker.is_symlink():
        findings.append(_finding(".git", 0, "symlink"))

    paths = _tracked_paths(resolved)
    if paths is None:
        paths = _fallback_paths(resolved)
    for relative in paths:
        if exclude_private_plans and _is_private_plan_path(relative):
            continue
        findings.extend(_audit_path(resolved, relative))
    return sorted(set(findings))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a repository tree for private or generated artifacts."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument(
        "--exclude-private-plans",
        action="store_true",
        help="skip only the private docs/superpowers tree",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    findings = audit_tree(
        args.root,
        exclude_private_plans=args.exclude_private_plans,
    )
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

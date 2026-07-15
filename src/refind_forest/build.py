"""Build a complete Forest theme staging tree."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import string
import tempfile
from pathlib import Path, PurePosixPath

from .assets import generate_theme
from .config import render_theme_config


_LOWER_HEX = frozenset("0123456789abcdef")
_LOGGER = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE_NOTICE_PATHS = (
    "LICENSE",
    "LICENSES/CC-BY-SA-4.0.txt",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
)
_SAFE_ESP_LABEL_CHARACTERS = frozenset(string.ascii_letters + string.digits + "_-")
_REQUIRED_PACKAGE_PATHS = frozenset(
    {
        "EFI/refind/theme-a.conf",
        "EFI/refind/theme-b.conf",
        "EFI/refind/theme-active.conf",
        "EFI/refind/themes/forest-a/background.png",
        "EFI/refind/themes/forest-b/background.png",
        "EFI/refind/themes/forest-a/icons/os_ubuntu.png",
        "EFI/refind/themes/forest-b/icons/os_ubuntu.png",
        "EFI/refind/themes/forest-a/icons/os_ventoy.png",
        "EFI/refind/themes/forest-b/icons/os_ventoy.png",
    }
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_regular_file_at(root_descriptor: int, relative: str) -> bytes:
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or relative != path.as_posix()
        or ".." in path.parts
    ):
        raise ValueError(f"invalid relative file path: {relative!r}")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    current_descriptor = root_descriptor
    try:
        for part in path.parts[:-1]:
            next_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=current_descriptor,
            )
            if directory_descriptor is not None:
                os.close(directory_descriptor)
            directory_descriptor = next_descriptor
            current_descriptor = next_descriptor

        file_descriptor = os.open(
            path.parts[-1],
            file_flags,
            dir_fd=current_descriptor,
        )
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise RuntimeError(f"path is not a regular file: {relative}")
        with os.fdopen(file_descriptor, "rb") as source:
            file_descriptor = None
            return source.read()
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _read_regular_file_beneath(root: Path, relative: str) -> bytes:
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        return _read_regular_file_at(descriptor, relative)
    finally:
        os.close(descriptor)


def _validate_esp_label(esp_label: str) -> None:
    if (
        not isinstance(esp_label, str)
        or not 1 <= len(esp_label) <= 11
        or not set(esp_label) <= _SAFE_ESP_LABEL_CHARACTERS
    ):
        raise ValueError(
            "esp_label must be 1-11 ASCII letters, digits, underscores, or hyphens"
        )


def _is_valid_manifest_path(value: str) -> bool:
    if not value or "\\" in value or "\0" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and len(path.parts) > 2
        and path.parts[:2] == ("EFI", "refind")
        and ".." not in path.parts
    )


def _manifest_files_are_owned(output: Path, files: object) -> bool:
    if not isinstance(files, list):
        return False

    paths = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            return False
        path_value = entry["path"]
        checksum = entry["sha256"]
        if not isinstance(path_value, str) or not isinstance(checksum, str):
            return False
        if not _is_valid_manifest_path(path_value):
            return False
        if len(checksum) != 64 or not set(checksum) <= _LOWER_HEX:
            return False
        paths.append(path_value)

    if paths != sorted(paths) or len(paths) != len(set(paths)):
        return False
    if not _REQUIRED_PACKAGE_PATHS <= set(paths):
        return False

    for entry in files:
        try:
            data = _read_regular_file_beneath(output, entry["path"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                return False
        except (OSError, RuntimeError, ValueError):
            return False
    return True


def _manifest_notices_are_owned(output: Path, notices: object) -> bool:
    if not isinstance(notices, list):
        return False

    paths = []
    for entry in notices:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            return False
        path_value = entry["path"]
        checksum = entry["sha256"]
        if not isinstance(path_value, str) or not isinstance(checksum, str):
            return False
        if path_value not in _PACKAGE_NOTICE_PATHS:
            return False
        if len(checksum) != 64 or not set(checksum) <= _LOWER_HEX:
            return False
        paths.append(path_value)

    if tuple(paths) != _PACKAGE_NOTICE_PATHS:
        return False

    for entry in notices:
        try:
            data = _read_regular_file_beneath(output, entry["path"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                return False
        except (OSError, RuntimeError, ValueError):
            return False
    return True


def _is_owned_build(output: Path) -> bool:
    if not output.is_dir():
        return False

    manifest_path = output / "manifest.json"
    efi = output / "EFI"
    refind = efi / "refind"
    licenses = output / "LICENSES"
    if {path.name for path in output.iterdir()} != {
        "EFI",
        "LICENSE",
        "LICENSES",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "manifest.json",
    }:
        return False
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or efi.is_symlink()
        or not efi.is_dir()
        or refind.is_symlink()
        or not refind.is_dir()
        or licenses.is_symlink()
        or not licenses.is_dir()
    ):
        return False
    try:
        if {path.name for path in licenses.iterdir()} != {"CC-BY-SA-4.0.txt"}:
            return False
    except OSError:
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or set(manifest) != {
        "format",
        "default_variant",
        "esp_label",
        "files",
        "notices",
    }:
        return False
    manifest_format = manifest.get("format")
    if type(manifest_format) is not int or manifest_format != 2:
        return False
    default_variant = manifest["default_variant"]
    if not isinstance(default_variant, str) or default_variant != "a":
        return False
    esp_label = manifest["esp_label"]
    if not isinstance(esp_label, str):
        return False
    try:
        _validate_esp_label(esp_label)
    except ValueError:
        return False
    return _manifest_files_are_owned(
        output, manifest["files"]
    ) and _manifest_notices_are_owned(output, manifest["notices"])


def _validated_paths(output: Path, ubuntu_source: Path) -> tuple[Path, Path]:
    if output.is_symlink():
        raise ValueError("output must not be a symbolic link")

    argument_output = Path(os.path.abspath(output))
    argument_source = Path(os.path.abspath(ubuntu_source))
    if argument_source == argument_output or argument_output in argument_source.parents:
        raise ValueError("output must not contain ubuntu_source")

    output = output.resolve()
    ubuntu_source = ubuntu_source.resolve()
    cwd = Path.cwd().resolve()
    if output.parent == output:
        raise ValueError("output must not be the filesystem root")
    if output == cwd or output in cwd.parents:
        raise ValueError("output must not be the current directory or its ancestor")
    if ubuntu_source == output or output in ubuntu_source.parents:
        raise ValueError("output must not contain ubuntu_source")
    return output, ubuntu_source


def _read_package_notices() -> dict[str, bytes]:
    notices = {}
    try:
        root_descriptor = os.open(
            _PROJECT_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise RuntimeError(
            f"unable to open package notice root: {_PROJECT_ROOT}"
        ) from error
    try:
        for relative in _PACKAGE_NOTICE_PATHS:
            try:
                notices[relative] = _read_regular_file_at(root_descriptor, relative)
            except (OSError, RuntimeError, ValueError) as error:
                raise RuntimeError(
                    f"unable to read package notice source: {_PROJECT_ROOT / relative}"
                ) from error
    finally:
        os.close(root_descriptor)
    return notices


def _populate_package(output: Path, ubuntu_source: Path, esp_label: str) -> None:
    notice_bytes = _read_package_notices()
    refind = output / "EFI" / "refind"
    refind.mkdir(parents=True)
    for variant in ("a", "b"):
        generate_theme(
            variant,
            refind / "themes" / f"forest-{variant}",
            ubuntu_source,
        )
        (refind / f"theme-{variant}.conf").write_text(
            render_theme_config(variant, esp_label=esp_label),
            encoding="ascii",
        )

    shutil.copy2(refind / "theme-a.conf", refind / "theme-active.conf")

    for relative, data in notice_bytes.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    files = []
    for path in sorted(item for item in refind.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(output).as_posix(),
                "sha256": _sha256(path),
            }
        )

    notices = [
        {
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for relative, data in notice_bytes.items()
    ]
    manifest = {
        "format": 2,
        "default_variant": "a",
        "esp_label": esp_label,
        "files": files,
        "notices": notices,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _rename_committed(source: Path, target: Path) -> bool:
    return not source.exists() and target.exists()


def _complete_rename(source: Path, target: Path) -> BaseException | None:
    first_error: BaseException | None = None
    for _attempt in range(2):
        try:
            source.rename(target)
        except BaseException as error:
            if _rename_committed(source, target):
                if first_error is not None:
                    error.add_note(f"earlier rename error: {first_error}")
                return error
            if first_error is None:
                first_error = error
                continue
            if not isinstance(error, Exception):
                error.add_note(f"earlier rename error: {first_error}")
                raise
            if not isinstance(first_error, Exception):
                first_error.add_note(f"rename retry failed: {error}")
                raise first_error from error
            raise
        return first_error
    raise AssertionError("unreachable rename retry state")


def _raise_after_recovery(
    primary: BaseException,
    recovery_errors: list[BaseException],
    *,
    preserved: Path | None = None,
) -> None:
    chosen = primary
    if isinstance(chosen, Exception):
        chosen = next(
            (error for error in recovery_errors if not isinstance(error, Exception)),
            chosen,
        )
    if chosen is not primary:
        chosen.add_note(f"initial operation raised {type(primary).__name__}: {primary}")
    for error in recovery_errors:
        if error is not chosen:
            chosen.add_note(f"recovery also raised {type(error).__name__}: {error}")
    if preserved is not None and preserved.exists():
        chosen.add_note(f"cleanup path preserved at {preserved}")
    raise chosen


def _raise_restore_failure(
    primary: BaseException,
    restore_error: BaseException,
    backup: Path,
) -> None:
    detail = f"failed to restore previous output; preserved at {backup}"
    if not isinstance(primary, Exception):
        primary.add_note(f"{detail}: {restore_error}")
        raise primary from restore_error
    if not isinstance(restore_error, Exception):
        restore_error.add_note(f"{detail}; initial error: {primary}")
        raise restore_error from primary
    failure = RuntimeError(detail)
    failure.add_note(f"initial operation raised {type(primary).__name__}: {primary}")
    failure.add_note(
        f"restore also raised {type(restore_error).__name__}: {restore_error}"
    )
    raise failure from restore_error


def _rmtree_with_retry(path: Path) -> list[BaseException]:
    errors = []
    for _attempt in range(2):
        try:
            shutil.rmtree(path)
        except BaseException as error:
            errors.append(error)
            if not path.exists():
                break
        else:
            break
    return errors


def _rmdir_with_retry(path: Path) -> list[BaseException]:
    errors = []
    for _attempt in range(2):
        try:
            path.rmdir()
        except BaseException as error:
            errors.append(error)
            if not path.exists():
                break
        else:
            break
    return errors


def _restore_after_backup_cleanup_failure(
    primary: BaseException,
    output: Path,
    backup: Path,
    backup_root: Path,
) -> None:
    """Restore the entry output while the previous build still exists."""
    recovery_errors = []
    failed_new = backup_root / "failed-new"
    try:
        aside_error = _complete_rename(output, failed_new)
    except BaseException as aside_failure:
        _raise_restore_failure(primary, aside_failure, backup)
    if aside_error is not None:
        recovery_errors.append(aside_error)

    try:
        restore_error = _complete_rename(backup, output)
    except BaseException as restore_failure:
        _raise_restore_failure(primary, restore_failure, backup)
    if restore_error is not None:
        recovery_errors.append(restore_error)

    recovery_errors.extend(_rmtree_with_retry(failed_new))
    if not failed_new.exists():
        recovery_errors.extend(_rmdir_with_retry(backup_root))
    preserved = failed_new if failed_new.exists() else backup_root
    _raise_after_recovery(
        primary,
        recovery_errors,
        preserved=preserved,
    )


def _cleanup_obsolete_build(
    output: Path,
    obsolete: Path,
    backup_root: Path,
    commit_error: BaseException | None,
) -> None:
    cleanup_errors = _rmtree_with_retry(obsolete)
    errors = ([commit_error] if commit_error is not None else []) + cleanup_errors
    if not obsolete.exists():
        _rmdir_with_retry(backup_root)

    interruption = next(
        (error for error in errors if not isinstance(error, Exception)),
        None,
    )
    if interruption is not None:
        interruption.add_note(f"new output committed at {output}")
        _raise_after_recovery(
            interruption,
            [error for error in errors if error is not interruption],
            preserved=obsolete if obsolete.exists() else backup_root,
        )

    if obsolete.exists():
        error_details = "; ".join(
            f"{type(error).__name__}: {error}" for error in errors
        )
        _LOGGER.warning(
            "new output committed at %s; cleanup path preserved at %s; "
            "cleanup errors: %s",
            output,
            obsolete,
            error_details,
        )


def _promote_package(staging: Path, output: Path, *, replacing: bool) -> None:
    if not replacing:
        try:
            staging.rename(output)
        except BaseException as promotion_error:
            if _rename_committed(staging, output):
                cleanup_errors = _rmtree_with_retry(output)
                _raise_after_recovery(
                    promotion_error,
                    cleanup_errors,
                    preserved=output,
                )
            raise
        return

    backup_root = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.backup-", dir=output.parent)
    )
    backup = backup_root / "previous"
    try:
        output.rename(backup)
    except BaseException as move_error:
        if _rename_committed(output, backup):
            try:
                restore_error = _complete_rename(backup, output)
            except BaseException as restore_failure:
                _raise_restore_failure(move_error, restore_failure, backup)
            recovery_errors = [restore_error] if restore_error is not None else []
            recovery_errors.extend(_rmdir_with_retry(backup_root))
            _raise_after_recovery(
                move_error,
                recovery_errors,
                preserved=backup_root,
            )
        cleanup_errors = _rmdir_with_retry(backup_root)
        _raise_after_recovery(
            move_error,
            cleanup_errors,
            preserved=backup_root,
        )

    try:
        staging.rename(output)
    except BaseException as promotion_error:
        recovery_errors = []
        interrupted_output = backup_root / "interrupted"
        if _rename_committed(staging, output):
            try:
                aside_error = _complete_rename(output, interrupted_output)
            except BaseException as aside_failure:
                _raise_restore_failure(promotion_error, aside_failure, backup)
            if aside_error is not None:
                recovery_errors.append(aside_error)
        try:
            restore_error = _complete_rename(backup, output)
        except BaseException as restore_failure:
            _raise_restore_failure(promotion_error, restore_failure, backup)
        if restore_error is not None:
            recovery_errors.append(restore_error)
        if interrupted_output.exists():
            recovery_errors.extend(_rmtree_with_retry(interrupted_output))
        if not interrupted_output.exists():
            recovery_errors.extend(_rmdir_with_retry(backup_root))
        _raise_after_recovery(
            promotion_error,
            recovery_errors,
            preserved=backup_root,
        )
    else:
        # The atomic rename is the commit point. Destructive cleanup starts only
        # after the previous build can no longer be mistaken for restorable.
        obsolete = backup_root / "obsolete"
        try:
            commit_error = _complete_rename(backup, obsolete)
        except BaseException as commit_failure:
            _restore_after_backup_cleanup_failure(
                commit_failure,
                output,
                backup,
                backup_root,
            )
        _cleanup_obsolete_build(output, obsolete, backup_root, commit_error)


def build_package(output: Path, ubuntu_source: Path, esp_label: str) -> Path:
    _validate_esp_label(esp_label)
    output, ubuntu_source = _validated_paths(output, ubuntu_source)
    replacing = output.exists()
    if replacing and not _is_owned_build(output):
        raise RuntimeError("refusing to replace an unowned output directory")

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent)
    )
    operation_error: BaseException | None = None
    try:
        _populate_package(staging, ubuntu_source, esp_label)
        _promote_package(staging, output, replacing=replacing)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if staging.exists():
            cleanup_errors = _rmtree_with_retry(staging)
            if cleanup_errors:
                primary = operation_error or cleanup_errors[0]
                secondary = (
                    cleanup_errors
                    if operation_error is not None
                    else cleanup_errors[1:]
                )
                _raise_after_recovery(
                    primary,
                    secondary,
                    preserved=staging,
                )
    return output

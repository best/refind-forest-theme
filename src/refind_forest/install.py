"""Safely install, verify, switch, and roll back the Forest theme."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

from PIL import Image

from .assets import ICON_NAMES
from .build import _PACKAGE_NOTICE_PATHS, _validate_esp_label
from .config import (
    BEGIN_MARKER,
    END_MARKER,
    INCLUDE_BLOCK,
    patch_refind_conf,
    render_theme_config,
)


_MINIMUM_FREE_BYTES = 32 * 1024 * 1024
_ROLLBACK_STAGING_OVERHEAD_BYTES = 1024 * 1024
_LOWER_HEX = frozenset("0123456789abcdef")
_INCLUDE_DIRECTIVE = "include theme-active.conf"
_MANAGED_PATHS = (
    "forest-manifest.json",
    "theme-a.conf",
    "theme-active.conf",
    "theme-b.conf",
    "themes/forest-a",
    "themes/forest-b",
)
_REQUIRED_ESP_FILES = (
    "EFI/refind/refind_x64.efi",
    "EFI/refind/refind.conf",
    "EFI/ubuntu/grubx64.efi",
    "EFI/Microsoft/Boot/bootmgfw.efi",
)


def _expected_immutable_paths() -> frozenset[str]:
    paths = {"theme-a.conf", "theme-b.conf"}
    for variant in ("a", "b"):
        theme = f"themes/forest-{variant}"
        paths.update(
            {
                f"{theme}/background.png",
                f"{theme}/selection-big.png",
                f"{theme}/selection-small.png",
            }
        )
        paths.update(f"{theme}/icons/{name}" for name in ICON_NAMES)
    return frozenset(paths)


_EXPECTED_IMMUTABLE_PATHS = _expected_immutable_paths()
_EXPECTED_THEME_DIRECTORIES = frozenset(
    {"themes/forest-a/icons", "themes/forest-b/icons"}
)
_EXPECTED_STAGING_PATHS = frozenset(
    {f"EFI/refind/{relative}" for relative in _EXPECTED_IMMUTABLE_PATHS}
    | {"EFI/refind/theme-active.conf"}
)


@dataclass(frozen=True)
class _SnapshotFile:
    path: str
    sha256: str
    data: bytes


@dataclass(frozen=True)
class _StagingSnapshot:
    default_variant: str
    esp_label: str
    files: tuple[_SnapshotFile, ...]


@dataclass(frozen=True)
class _MountedVfatSource:
    source: Path
    device: int

    @property
    def major_minor(self) -> str:
        return f"{os.major(self.device)}:{os.minor(self.device)}"


@dataclass(frozen=True)
class _EspIdentity:
    fat_uuid: str | None
    label: str | None
    mount_major_minor: str
    mount_source: str | None


@dataclass
class _RollbackSwap:
    target: Path
    staged: Path
    prior: Path
    staged_moved: bool = False
    prior_moved: bool = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_mount_path(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _read_mountinfo() -> str:
    try:
        return Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("unable to inspect mounted filesystems") from error


def _open_bound_block_device(source: Path, expected_device: int) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise RuntimeError(f"unable to open mounted vfat source: {source}") from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISBLK(status.st_mode):
            raise RuntimeError(f"mounted vfat source is not a block device: {source}")
        if status.st_rdev != expected_device:
            expected = f"{os.major(expected_device)}:{os.minor(expected_device)}"
            actual = f"{os.major(status.st_rdev)}:{os.minor(status.st_rdev)}"
            raise RuntimeError(
                f"mounted vfat source device {actual} does not match mountinfo "
                f"device {expected}: {source}"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_bound_block_device(source: _MountedVfatSource) -> None:
    descriptor = _open_bound_block_device(source.source, source.device)
    os.close(descriptor)


def _mounted_vfat_source(esp: Path, mountinfo: str) -> _MountedVfatSource:
    resolved = str(esp)
    refind = esp / "EFI" / "refind"
    try:
        device = os.stat(esp).st_dev
        visible_device = f"{os.major(device)}:{os.minor(device)}"
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise RuntimeError(
            f"unable to identify the visible ESP mount device: {esp}"
        ) from error

    exact_mounts = 0
    matching_sources = []
    for line in mountinfo.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if separator + 2 >= len(fields) or len(fields) < 5:
            continue
        mount_point = _decode_mount_path(fields[4])
        mounted_path = Path(mount_point)
        if (
            mounted_path != esp
            and esp in mounted_path.parents
            and (
                mounted_path == refind
                or mounted_path in refind.parents
                or refind in mounted_path.parents
            )
        ):
            raise RuntimeError(
                f"nested mount overlaps the rEFInd target tree: {mounted_path}"
            )
        filesystem = fields[separator + 1]
        if mount_point != resolved or filesystem != "vfat":
            continue
        exact_mounts += 1
        if fields[2] != visible_device:
            continue
        source = Path(_decode_mount_path(fields[separator + 2]))
        if not source.is_absolute():
            raise RuntimeError(f"mounted vfat source is not a device path: {source}")
        matching_sources.append(_MountedVfatSource(source, os.makedev(*map(int, fields[2].split(":")))))

    if len(matching_sources) == 1:
        source = matching_sources[0]
        _validate_bound_block_device(source)
        return source
    if len(matching_sources) > 1:
        raise RuntimeError(
            f"ESP has ambiguous exact vfat mounts for visible device "
            f"{visible_device}: {esp}"
        )
    if exact_mounts:
        raise RuntimeError(
            f"no exact vfat mount matches visible device {visible_device}: {esp}"
        )
    raise RuntimeError(f"ESP is not an exact vfat mount: {esp}")


def _require_root(
    esp: Path,
    *,
    mountinfo_reader: Callable[[], str] | None = None,
) -> _MountedVfatSource:
    if os.geteuid() != 0:
        raise PermissionError("installation requires root privileges")

    reader = _read_mountinfo if mountinfo_reader is None else mountinfo_reader
    mountinfo = reader()
    if not isinstance(mountinfo, str):
        raise RuntimeError("mounted filesystem information is invalid")
    return _mounted_vfat_source(esp, mountinfo)


def _read_device_boot_sector(source: _MountedVfatSource) -> bytes:
    descriptor = None
    try:
        descriptor = _open_bound_block_device(source.source, source.device)
        with os.fdopen(descriptor, "rb") as device:
            descriptor = None
            return device.read(512)
    except OSError as error:
        raise RuntimeError(
            f"unable to read mounted vfat source: {source.source}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _parse_fat_volume_identity(boot_sector: bytes) -> tuple[str, str]:
    if len(boot_sector) != 512 or boot_sector[510:512] != b"\x55\xaa":
        raise RuntimeError("invalid FAT boot sector signature")

    if boot_sector[82:90] == b"FAT32   ":
        extended_signature_offset = 66
        serial_offset = 67
        label_offset = 71
    elif boot_sector[54:62] in {b"FAT12   ", b"FAT16   "}:
        extended_signature_offset = 38
        serial_offset = 39
        label_offset = 43
    else:
        raise RuntimeError("invalid FAT filesystem type")

    if boot_sector[extended_signature_offset] != 0x29:
        raise RuntimeError("FAT volume label is unavailable")
    raw_label = boot_sector[label_offset : label_offset + 11]
    try:
        label = raw_label.rstrip(b" ").decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("FAT volume label is invalid ASCII") from error
    if not label or label == "NO NAME":
        raise RuntimeError("FAT volume label is unavailable (NO NAME)")
    try:
        _validate_esp_label(label)
    except ValueError as error:
        raise RuntimeError(f"FAT volume label is unsafe: {label!r}") from error
    serial = int.from_bytes(boot_sector[serial_offset : serial_offset + 4], "little")
    if serial == 0:
        raise RuntimeError("FAT volume serial is unavailable")
    fat_uuid = f"{serial:08X}"
    return f"{fat_uuid[:4]}-{fat_uuid[4:]}", label


def _parse_fat_volume_label(boot_sector: bytes) -> str:
    return _parse_fat_volume_identity(boot_sector)[1]


def _read_fat_volume_label(
    source: _MountedVfatSource,
    *,
    device_reader: Callable[[Path], bytes] | None = None,
) -> str:
    return _read_fat_volume_identity(source, device_reader=device_reader)[1]


def _read_fat_volume_identity(
    source: _MountedVfatSource,
    *,
    device_reader: Callable[[Path], bytes] | None = None,
) -> tuple[str, str]:
    reader = _read_device_boot_sector if device_reader is None else device_reader
    try:
        boot_sector = (
            reader(source)
            if device_reader is None
            else reader(source.source)
        )
    except OSError as error:
        raise RuntimeError(
            f"unable to read mounted vfat source: {source.source}"
        ) from error
    if not isinstance(boot_sector, bytes):
        raise RuntimeError("mounted vfat source returned invalid boot-sector data")
    return _parse_fat_volume_identity(boot_sector)


def discover_esp_label(
    esp: Path,
    *,
    mountinfo_reader: Callable[[], str] | None = None,
    device_reader: Callable[[Path], bytes] | None = None,
) -> str:
    """Return the safe FAT volume label for an exact mounted root ESP."""
    argument = Path(esp)
    if argument.is_symlink():
        raise RuntimeError(f"ESP must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"ESP does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"ESP is not a directory: {resolved}")

    source = _require_root(resolved, mountinfo_reader=mountinfo_reader)
    return _read_fat_volume_label(source, device_reader=device_reader)


def _assert_no_symlink_components(base: Path, path: Path) -> None:
    try:
        relative = path.relative_to(base)
    except ValueError as error:
        raise RuntimeError(f"path escapes expected root: {path}") from error

    current = base
    if current.is_symlink():
        raise RuntimeError(f"symbolic link is not allowed: {current}")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError(f"symbolic link is not allowed: {current}")


def _assert_tree_has_no_symlinks(root: Path) -> None:
    if root.is_symlink():
        raise RuntimeError(f"symbolic link is not allowed: {root}")
    if not root.exists():
        return
    try:
        for path in root.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(f"symbolic link is not allowed: {path}")
    except OSError as error:
        raise RuntimeError(f"unable to inspect path: {root}") from error


def _assert_tree_is_copyable(root: Path) -> None:
    _assert_tree_has_no_symlinks(root)
    if not root.exists():
        return
    if root.is_file():
        return
    if not root.is_dir():
        raise RuntimeError(f"unsupported filesystem entry: {root}")
    try:
        for path in root.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(f"symbolic link is not allowed: {path}")
            if not path.is_file() and not path.is_dir():
                raise RuntimeError(f"unsupported filesystem entry: {path}")
    except OSError as error:
        raise RuntimeError(f"unable to inspect path: {root}") from error


def _validate_managed_targets(esp: Path) -> None:
    refind = esp / "EFI" / "refind"
    _assert_no_symlink_components(esp, refind)
    _assert_no_symlink_components(esp, refind / "refind.conf")
    for relative in _MANAGED_PATHS:
        target = refind / relative
        _assert_no_symlink_components(esp, target)
        _assert_tree_is_copyable(target)


def _assert_refind_tree_on_esp_device(esp: Path) -> None:
    try:
        esp_device = esp.stat().st_dev
    except OSError as error:
        raise RuntimeError(f"unable to identify ESP filesystem: {esp}") from error
    refind = esp / "EFI" / "refind"
    paths = [esp / "EFI", refind]
    try:
        if refind.is_dir():
            paths.extend(refind.rglob("*"))
        for path in paths:
            if path.stat().st_dev != esp_device:
                raise RuntimeError(
                    f"rEFInd path is on a different filesystem than the ESP: {path}"
                )
    except OSError as error:
        raise RuntimeError(f"unable to inspect rEFInd filesystem: {refind}") from error


def _identity_for_mounted_source(source: _MountedVfatSource) -> _EspIdentity:
    fat_uuid, label = _read_fat_volume_identity(source)
    return _EspIdentity(
        fat_uuid=fat_uuid,
        label=label,
        mount_major_minor=source.major_minor,
        mount_source=str(source.source),
    )


def _unverified_esp_identity(esp: Path) -> _EspIdentity:
    device = esp.stat().st_dev
    return _EspIdentity(
        fat_uuid=None,
        label=None,
        mount_major_minor=f"{os.major(device)}:{os.minor(device)}",
        mount_source=None,
    )


def _validate_esp(
    esp: Path,
    *,
    require_root: bool,
    expected_esp_label: str | None = None,
) -> tuple[Path, _EspIdentity]:
    argument = Path(esp)
    if argument.is_symlink():
        raise RuntimeError(f"ESP must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"ESP does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"ESP is not a directory: {resolved}")

    source = _require_root(resolved) if require_root else None
    identity = (
        _identity_for_mounted_source(source)
        if source is not None
        else _unverified_esp_identity(resolved)
    )
    if identity.label is not None and expected_esp_label is not None:
        if identity.label != expected_esp_label:
            raise RuntimeError(
                f"staging ESP label {expected_esp_label} does not match mounted "
                f"ESP label {identity.label}"
            )

    for relative in _REQUIRED_ESP_FILES:
        path = resolved / relative
        _assert_no_symlink_components(resolved, path)
        if not path.is_file():
            raise RuntimeError(f"required ESP file is missing: {relative}")

    try:
        free_bytes = shutil.disk_usage(resolved).free
    except OSError as error:
        raise RuntimeError(
            f"unable to determine free space on ESP: {resolved}"
        ) from error
    if free_bytes < _MINIMUM_FREE_BYTES:
        raise RuntimeError("ESP has less than 32 MiB free space")

    _validate_managed_targets(resolved)
    _assert_refind_tree_on_esp_device(resolved)
    return resolved, identity


def _is_safe_staging_path(value: str) -> bool:
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


def _validate_exact_staging_tree(
    staging: Path,
    manifest_paths: set[str],
    notice_paths: set[str],
) -> None:
    expected_paths = manifest_paths | notice_paths
    expected_files = expected_paths | {"manifest.json"}
    expected_directories = set()
    for value in expected_paths:
        parent = PurePosixPath(value).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent

    actual_files = set()
    actual_directories = set()
    try:
        for path in staging.rglob("*"):
            relative = path.relative_to(staging).as_posix()
            if path.is_symlink():
                raise RuntimeError(f"symbolic link is not allowed: {path}")
            if path.is_file():
                actual_files.add(relative)
            elif path.is_dir():
                actual_directories.add(relative)
            else:
                raise RuntimeError(f"unsupported filesystem entry: {path}")
    except OSError as error:
        raise RuntimeError(f"unable to inspect staging tree: {staging}") from error

    if actual_files != expected_files or actual_directories != expected_directories:
        raise RuntimeError("staging does not match the exact staging tree")


def _read_regular_file_once(root_descriptor: int, relative: str) -> bytes:
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or relative != path.as_posix()
        or ".." in path.parts
    ):
        raise RuntimeError(f"invalid staging file path: {relative!r}")

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
            raise RuntimeError(f"staging entry is not a regular file: {relative}")
        with os.fdopen(file_descriptor, "rb") as source:
            file_descriptor = None
            return source.read()
    except OSError as error:
        raise RuntimeError(
            f"unable to read staging file without following links: {relative}"
        ) from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _load_staging_snapshot(staging: Path) -> _StagingSnapshot:
    argument = Path(staging)
    if argument.is_symlink():
        raise RuntimeError(f"staging must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"staging does not exist: {argument}") from error
    _assert_tree_has_no_symlinks(resolved)

    try:
        root_descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise RuntimeError(f"unable to open staging directory: {resolved}") from error
    try:
        return _load_staging_snapshot_from_descriptor(resolved, root_descriptor)
    finally:
        os.close(root_descriptor)


def _load_staging_snapshot_from_descriptor(
    resolved: Path,
    root_descriptor: int,
) -> _StagingSnapshot:

    try:
        manifest_bytes = _read_regular_file_once(root_descriptor, "manifest.json")
        manifest = json.loads(manifest_bytes.decode("ascii"))
    except (RuntimeError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("staging manifest is invalid") from error

    if not isinstance(manifest, dict) or set(manifest) != {
        "default_variant",
        "esp_label",
        "files",
        "format",
        "notices",
    }:
        raise RuntimeError("staging manifest has an invalid schema")
    if type(manifest["format"]) is not int or manifest["format"] != 2:
        raise RuntimeError("staging manifest has an invalid format")
    if manifest["default_variant"] != "a":
        raise RuntimeError("staging manifest has an invalid default variant")
    if not isinstance(manifest["esp_label"], str):
        raise RuntimeError("staging manifest has an invalid ESP label")
    try:
        _validate_esp_label(manifest["esp_label"])
    except ValueError as error:
        raise RuntimeError("staging manifest has an invalid ESP label") from error

    entries = manifest["files"]
    if not isinstance(entries, list):
        raise RuntimeError("staging manifest files must be a list")
    validated_entries = []
    manifest_paths = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise RuntimeError(f"staging manifest file entry {index} is invalid")
        source_path = entry["path"]
        checksum = entry["sha256"]
        if not isinstance(source_path, str) or not _is_safe_staging_path(source_path):
            raise RuntimeError(f"unsafe staging manifest path: {source_path!r}")
        if not _valid_checksum(checksum):
            raise RuntimeError(
                f"staging manifest checksum for {source_path} is invalid"
            )
        manifest_paths.append(source_path)
        validated_entries.append((source_path, checksum))

    if manifest_paths != sorted(manifest_paths) or len(manifest_paths) != len(
        set(manifest_paths)
    ):
        raise RuntimeError("staging manifest paths must be sorted and unique")
    if set(manifest_paths) != _EXPECTED_STAGING_PATHS:
        raise RuntimeError(
            "staging manifest does not contain the exact Forest file set"
        )

    notice_entries = manifest["notices"]
    if not isinstance(notice_entries, list):
        raise RuntimeError("staging manifest notices must be a list")
    validated_notices = []
    notice_paths = []
    for index, entry in enumerate(notice_entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise RuntimeError(f"staging manifest notice entry {index} is invalid")
        source_path = entry["path"]
        checksum = entry["sha256"]
        if not isinstance(source_path, str) or source_path not in _PACKAGE_NOTICE_PATHS:
            raise RuntimeError(f"unsafe staging notice path: {source_path!r}")
        if not _valid_checksum(checksum):
            raise RuntimeError(
                f"staging manifest notice checksum for {source_path} is invalid"
            )
        notice_paths.append(source_path)
        validated_notices.append((source_path, checksum))

    if notice_paths != sorted(notice_paths) or len(notice_paths) != len(
        set(notice_paths)
    ):
        raise RuntimeError("staging manifest notice paths must be sorted and unique")
    if set(notice_paths) != set(_PACKAGE_NOTICE_PATHS):
        raise RuntimeError(
            "staging manifest does not contain the exact package notice set"
        )

    _validate_exact_staging_tree(
        resolved,
        set(manifest_paths),
        set(notice_paths),
    )

    snapshot_files = []
    for source_path, checksum in validated_entries:
        path = resolved / source_path
        _assert_no_symlink_components(resolved, path)
        data = _read_regular_file_once(root_descriptor, source_path)
        if hashlib.sha256(data).hexdigest() != checksum:
            raise RuntimeError(
                f"staging is not a complete owned Forest build: checksum mismatch "
                f"for {source_path}"
            )
        snapshot_files.append(_SnapshotFile(source_path, checksum, data))

    for source_path, checksum in validated_notices:
        path = resolved / source_path
        _assert_no_symlink_components(resolved, path)
        data = _read_regular_file_once(root_descriptor, source_path)
        if hashlib.sha256(data).hexdigest() != checksum:
            raise RuntimeError(
                f"staging package notice checksum mismatch for {source_path}"
            )
    return _StagingSnapshot(
        default_variant="a",
        esp_label=manifest["esp_label"],
        files=tuple(snapshot_files),
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(3)}")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _copy_atomic(source: Path, target: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"source is not a regular file: {source}")
    _atomic_write(target, source.read_bytes())


def _remove_path(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing to remove symbolic link: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _copy_tree_checked(source: Path, target: Path) -> None:
    _assert_tree_is_copyable(source)
    if not source.is_dir():
        raise RuntimeError(f"backup source is not a directory: {source}")
    target.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        destination = target / relative
        if path.is_symlink():
            raise RuntimeError(f"symbolic link is not allowed: {path}")
        if path.is_dir():
            destination.mkdir()
        elif path.is_file():
            _copy_atomic(path, destination)
        else:
            raise RuntimeError(f"unsupported filesystem entry: {path}")


def _copy_entry_checked(source: Path, target: Path) -> None:
    if source.is_symlink():
        raise RuntimeError(f"symbolic link is not allowed: {source}")
    if source.is_dir():
        _copy_tree_checked(source, target)
    elif source.is_file():
        _copy_atomic(source, target)
    else:
        raise RuntimeError(f"unsupported filesystem entry: {source}")


def _is_safe_backup_tree_path(value: str) -> bool:
    if not value or "\\" in value or "\0" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and ".." not in path.parts
    )


def _build_original_tree_manifest(original: Path) -> list[dict[str, object]]:
    entries = []
    try:
        paths = sorted(original.rglob("*"))
    except OSError as error:
        raise RuntimeError(
            f"unable to inspect backup original tree: {original}"
        ) from error
    for path in paths:
        relative = path.relative_to(original).as_posix()
        if path.is_symlink():
            raise RuntimeError(f"symbolic link is not allowed: {path}")
        if path.is_dir():
            entries.append({"path": relative, "type": "directory"})
        elif path.is_file():
            entries.append(
                {
                    "path": relative,
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                    "type": "file",
                }
            )
        else:
            raise RuntimeError(f"unsupported backup entry: original/{relative}")
    return entries


def _create_backup(
    esp: Path,
    backup_root: Path,
    *,
    esp_identity: _EspIdentity | None = None,
) -> Path:
    backup_root = Path(backup_root)
    if backup_root.is_symlink():
        raise RuntimeError(f"backup root must not be a symbolic link: {backup_root}")
    backup_root.mkdir(parents=True, exist_ok=True)
    backup_root = backup_root.resolve(strict=True)

    prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    while True:
        backup = backup_root / f"{prefix}-{secrets.token_hex(3)}"
        try:
            backup.mkdir()
        except FileExistsError:
            continue
        break

    refind = esp / "EFI" / "refind"
    original = backup / "original"
    try:
        original.mkdir()
        _copy_atomic(refind / "refind.conf", original / "refind.conf")
        presence = {}
        for relative in _MANAGED_PATHS:
            source = refind / relative
            present = source.exists()
            presence[relative] = present
            if present:
                _copy_entry_checked(source, original / relative)

        identity = esp_identity or _unverified_esp_identity(esp)
        record = {
            "esp": str(esp),
            "esp_identity": {
                "fat_uuid": identity.fat_uuid,
                "label": identity.label,
                "mount_major_minor": identity.mount_major_minor,
                "mount_source": identity.mount_source,
            },
            "format": 2,
            "managed": list(_MANAGED_PATHS),
            "original_tree": _build_original_tree_manifest(original),
            "present": presence,
            "refind_conf_sha256": _sha256(original / "refind.conf"),
            "themes_present": (refind / "themes").exists(),
        }
        _atomic_write(
            backup / "backup.json",
            (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("ascii"),
        )
    except BaseException as primary:
        try:
            shutil.rmtree(backup)
        except BaseException as cleanup_error:
            _note_secondary(
                primary,
                cleanup_error,
                context=f"failed to clean incomplete backup at {backup}",
            )
            raise primary from cleanup_error
        raise
    return backup


def _validate_backup_root(backup_root: Path, esp: Path) -> None:
    argument = Path(backup_root)
    if argument.is_symlink():
        raise RuntimeError(f"backup root must not be a symbolic link: {argument}")
    resolved = argument.resolve()
    if resolved == esp or esp in resolved.parents:
        raise RuntimeError("backup root must be outside the ESP")


def _installed_manifest(snapshot: _StagingSnapshot) -> dict[str, object]:
    installed_files = []
    for entry in snapshot.files:
        relative = PurePosixPath(entry.path).relative_to("EFI/refind").as_posix()
        if relative == "theme-active.conf":
            continue
        installed_files.append({"path": relative, "sha256": entry.sha256})
    return {
        "default_variant": snapshot.default_variant,
        "esp_label": snapshot.esp_label,
        "files": installed_files,
        "format": 1,
    }


def _patch_refind_conf_once(text: str) -> str:
    without_naked_includes = "".join(
        raw_line
        for raw_line in text.splitlines(keepends=True)
        if raw_line.strip() != _INCLUDE_DIRECTIVE
    )
    return patch_refind_conf(without_naked_includes)


def _install_files(snapshot: _StagingSnapshot, esp: Path) -> None:
    target_refind = esp / "EFI" / "refind"

    for relative in _MANAGED_PATHS:
        _remove_path(target_refind / relative)

    snapshot_by_path = {}
    for entry in snapshot.files:
        relative = PurePosixPath(entry.path).relative_to("EFI/refind").as_posix()
        snapshot_by_path[relative] = entry.data
        if relative == "theme-active.conf":
            continue
        _atomic_write(target_refind / relative, entry.data)

    installed_manifest = _installed_manifest(snapshot)
    _atomic_write(
        target_refind / "forest-manifest.json",
        (json.dumps(installed_manifest, indent=2, sort_keys=True) + "\n").encode(
            "ascii"
        ),
    )
    _atomic_write(
        target_refind / "theme-active.conf",
        snapshot_by_path["theme-a.conf"],
    )

    try:
        current_config = (target_refind / "refind.conf").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("unable to read refind.conf") from error
    patched_config = _patch_refind_conf_once(current_config)
    _atomic_write(target_refind / "refind.conf", patched_config.encode("ascii"))


def _is_safe_installed_path(value: str) -> bool:
    if not value or "\\" in value or "\0" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and ".." not in path.parts
        and (
            value in {"theme-a.conf", "theme-b.conf"}
            or path.parts[:2] in {
                ("themes", "forest-a"),
                ("themes", "forest-b"),
            }
        )
    )


def _valid_checksum(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _LOWER_HEX
    )


def _validate_png(path: Path, relative: str) -> str | None:
    name = path.name
    expected_size: tuple[int, int] | None
    expected_mode: str | None
    if name == "background.png":
        expected_size, expected_mode = (2560, 1600), "RGB"
    elif name == "selection-big.png":
        expected_size, expected_mode = (144, 144), "RGBA"
    elif name == "selection-small.png":
        expected_size, expected_mode = (64, 64), "RGBA"
    elif name.startswith("os_"):
        expected_size, expected_mode = (128, 128), "RGBA"
    elif name.startswith(("func_", "tool_")):
        expected_size, expected_mode = (48, 48), "RGBA"
    elif name == "vol_external.png":
        expected_size, expected_mode = (32, 32), "RGBA"
    else:
        expected_size, expected_mode = None, None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                image.load()
                actual_format = image.format
                actual_size = image.size
                actual_mode = image.mode
    except (
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as error:
        return f"invalid PNG {relative}: {error}"
    if actual_format != "PNG":
        return (
            f"invalid PNG format for {relative}: expected PNG, got {actual_format}"
        )
    if expected_size is None or expected_mode is None:
        return f"unexpected PNG path: {relative}"
    if actual_size != expected_size or actual_mode != expected_mode:
        return (
            f"invalid PNG properties for {relative}: expected "
            f"{expected_size} {expected_mode}, got {actual_size} {actual_mode}"
        )
    return None


def _load_installed_manifest(
    path: Path,
    errors: list[str],
) -> tuple[list[dict[str, str]], str | None]:
    if path.is_symlink():
        errors.append("symbolic link is not allowed: forest-manifest.json")
        return [], None
    try:
        manifest = json.loads(path.read_text(encoding="ascii"))
    except FileNotFoundError:
        errors.append("missing forest-manifest.json")
        return [], None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"invalid forest-manifest.json: {error}")
        return [], None

    if not isinstance(manifest, dict) or set(manifest) != {
        "default_variant",
        "esp_label",
        "files",
        "format",
    }:
        errors.append("forest-manifest.json has an invalid schema")
        return [], None
    if type(manifest["format"]) is not int or manifest["format"] != 1:
        errors.append("forest-manifest.json has an invalid format")
    if manifest["default_variant"] != "a":
        errors.append("forest-manifest.json has an invalid default variant")
    esp_label = None
    try:
        if not isinstance(manifest["esp_label"], str):
            raise ValueError
        _validate_esp_label(manifest["esp_label"])
    except ValueError:
        errors.append("forest-manifest.json has an invalid ESP label")
    else:
        esp_label = manifest["esp_label"]

    raw_files = manifest["files"]
    if not isinstance(raw_files, list):
        errors.append("forest-manifest.json files must be a list")
        return [], esp_label

    files = []
    paths = []
    for index, entry in enumerate(raw_files):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"forest-manifest.json file entry {index} is invalid")
            continue
        relative = entry["path"]
        checksum = entry["sha256"]
        if not isinstance(relative, str) or not _is_safe_installed_path(relative):
            errors.append(f"forest-manifest.json file path {index} is unsafe")
            continue
        if not _valid_checksum(checksum):
            errors.append(f"forest-manifest.json checksum for {relative} is invalid")
            continue
        paths.append(relative)
        files.append({"path": relative, "sha256": checksum})

    if paths != sorted(paths):
        errors.append("forest-manifest.json file paths are not sorted")
    if len(paths) != len(set(paths)):
        errors.append("forest-manifest.json file paths are not unique")
    if set(paths) != _EXPECTED_IMMUTABLE_PATHS:
        errors.append("forest-manifest.json does not list the exact Forest file set")
    return files, esp_label


def _verify_refind_config(refind: Path, errors: list[str]) -> None:
    path = refind / "refind.conf"
    if path.is_symlink():
        errors.append("symbolic link is not allowed: refind.conf")
        return
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError:
        errors.append("missing refind.conf")
        return
    except (OSError, UnicodeError) as error:
        errors.append(f"invalid refind.conf: {error}")
        return
    directive_count = sum(
        raw_line.strip() == _INCLUDE_DIRECTIVE
        for raw_line in text.splitlines(keepends=True)
    )
    if (
        text.count(INCLUDE_BLOCK) != 1
        or text.count(BEGIN_MARKER) != 1
        or text.count(END_MARKER) != 1
        or directive_count != 1
    ):
        errors.append("refind.conf must contain exactly one exact Forest include block")


def _verify_theme_configs(
    refind: Path,
    errors: list[str],
    *,
    esp_label: str | None,
) -> None:
    contents = {}
    for name in ("theme-a.conf", "theme-b.conf", "theme-active.conf"):
        path = refind / name
        if path.is_symlink():
            errors.append(f"symbolic link is not allowed: {name}")
            continue
        try:
            contents[name] = path.read_bytes()
        except FileNotFoundError:
            errors.append(f"missing {name}")
        except OSError as error:
            errors.append(f"unable to read {name}: {error}")

    if esp_label is not None:
        for variant in ("a", "b"):
            name = f"theme-{variant}.conf"
            expected = render_theme_config(variant, esp_label=esp_label).encode("ascii")
            if name in contents and contents[name] != expected:
                errors.append(f"{name} does not match its generated configuration")
    if "theme-a.conf" in contents and "theme-b.conf" in contents:
        normalized_a = contents["theme-a.conf"].replace(b"forest-a", b"forest-x")
        normalized_b = contents["theme-b.conf"].replace(b"forest-b", b"forest-x")
        if normalized_a != normalized_b:
            errors.append("theme-a.conf and theme-b.conf behaviors differ")
    if "theme-active.conf" in contents and not any(
        contents["theme-active.conf"] == contents.get(name)
        for name in ("theme-a.conf", "theme-b.conf")
    ):
        errors.append("theme-active.conf does not exactly match variant A or B")


def _verify_managed_theme_trees(
    refind: Path,
    checked_pngs: set[str],
    errors: list[str],
) -> None:
    for variant in ("a", "b"):
        root = refind / "themes" / f"forest-{variant}"
        if root.is_symlink():
            errors.append(
                f"symbolic link is not allowed: themes/forest-{variant}"
            )
            continue
        if not root.is_dir():
            continue
        try:
            paths = sorted(root.rglob("*"))
        except OSError as error:
            errors.append(f"unable to inspect themes/forest-{variant}: {error}")
            continue
        for path in paths:
            relative = path.relative_to(refind).as_posix()
            if path.is_symlink():
                errors.append(f"symbolic link is not allowed: {relative}")
                continue
            if path.is_dir():
                if relative not in _EXPECTED_THEME_DIRECTORIES:
                    errors.append(f"unmanifested managed directory: {relative}")
                continue
            if not path.is_file():
                errors.append(f"unsupported managed filesystem entry: {relative}")
                continue
            if relative not in _EXPECTED_IMMUTABLE_PATHS:
                errors.append(f"unmanifested managed file: {relative}")
            if path.suffix.lower() == ".png" and relative not in checked_pngs:
                checked_pngs.add(relative)
                png_error = _validate_png(path, relative)
                if png_error is not None:
                    errors.append(png_error)


def verify(esp: Path) -> list[str]:
    """Return all installed manifest/config/image errors; [] means valid."""
    errors: list[str] = []
    argument = Path(esp)
    if argument.is_symlink():
        return [f"ESP must not be a symbolic link: {argument}"]
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        return [f"ESP does not exist: {error}"]
    if not resolved.is_dir():
        return [f"ESP is not a directory: {resolved}"]

    refind = resolved / "EFI" / "refind"
    try:
        _assert_no_symlink_components(resolved, refind)
    except RuntimeError as error:
        return [str(error)]

    files, esp_label = _load_installed_manifest(
        refind / "forest-manifest.json",
        errors,
    )
    checked_pngs = set()
    for entry in files:
        relative = entry["path"]
        path = refind / relative
        try:
            _assert_no_symlink_components(resolved, path)
        except RuntimeError as error:
            errors.append(str(error))
            continue
        if path.is_symlink():
            errors.append(f"symbolic link is not allowed: {relative}")
            continue
        if not path.is_file():
            errors.append(f"missing installed file: {relative}")
            continue
        try:
            actual_checksum = _sha256(path)
        except OSError as error:
            errors.append(f"unable to hash {relative}: {error}")
            continue
        if actual_checksum != entry["sha256"]:
            errors.append(f"checksum mismatch: {relative}")
        if relative.endswith(".png"):
            checked_pngs.add(relative)
            png_error = _validate_png(path, relative)
            if png_error is not None:
                errors.append(png_error)

    _verify_managed_theme_trees(refind, checked_pngs, errors)
    _verify_refind_config(refind, errors)
    _verify_theme_configs(refind, errors, esp_label=esp_label)
    return errors


def _validate_exact_backup_tree(backup: Path, presence: dict[str, object]) -> None:
    allowed_roots = [
        PurePosixPath("original") / PurePosixPath(relative)
        for relative in _MANAGED_PATHS
        if presence[relative]
    ]
    required_paths = {
        PurePosixPath("backup.json"),
        PurePosixPath("original"),
        PurePosixPath("original/refind.conf"),
    }

    try:
        paths = backup.rglob("*")
        for path in paths:
            relative = PurePosixPath(path.relative_to(backup).as_posix())
            if path.is_symlink():
                raise RuntimeError(f"symbolic link is not allowed: {path}")
            if not path.is_file() and not path.is_dir():
                raise RuntimeError(f"unsupported backup entry: {relative}")
            allowed = relative in required_paths or any(
                relative == root
                or root in relative.parents
                or relative in root.parents
                for root in allowed_roots
            )
            if not allowed:
                raise RuntimeError(f"unexpected backup entry: {relative}")
    except OSError as error:
        raise RuntimeError(f"unable to inspect backup tree: {backup}") from error


def _validate_backup(backup: Path, esp: Path) -> tuple[Path, dict[str, object]]:
    argument = Path(backup)
    if argument.is_symlink():
        raise RuntimeError(f"backup must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"backup does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"backup is not a directory: {resolved}")
    if resolved == esp or esp in resolved.parents:
        raise RuntimeError("backup must be outside the ESP")
    _assert_tree_has_no_symlinks(resolved)

    try:
        record = json.loads((resolved / "backup.json").read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("backup.json is missing or malformed") from error
    if not isinstance(record, dict) or set(record) != {
        "esp",
        "esp_identity",
        "format",
        "managed",
        "original_tree",
        "present",
        "refind_conf_sha256",
        "themes_present",
    }:
        raise RuntimeError("backup.json has an invalid schema")
    if type(record["format"]) is not int or record["format"] != 2:
        raise RuntimeError("backup.json has an invalid format")
    if record["esp"] != str(esp):
        raise RuntimeError("backup belongs to a different ESP")
    esp_identity = record["esp_identity"]
    if not isinstance(esp_identity, dict) or set(esp_identity) != {
        "fat_uuid",
        "label",
        "mount_major_minor",
        "mount_source",
    }:
        raise RuntimeError("backup.json has an invalid ESP identity")
    fat_uuid = esp_identity["fat_uuid"]
    label = esp_identity["label"]
    mount_major_minor = esp_identity["mount_major_minor"]
    mount_source = esp_identity["mount_source"]
    if fat_uuid is not None and (
        not isinstance(fat_uuid, str)
        or len(fat_uuid) != 9
        or fat_uuid[4] != "-"
        or any(
            character not in "0123456789ABCDEF"
            for character in fat_uuid[:4] + fat_uuid[5:]
        )
    ):
        raise RuntimeError("backup.json has an invalid ESP FAT UUID")
    if label is not None:
        if not isinstance(label, str):
            raise RuntimeError("backup.json has an invalid ESP label")
        try:
            _validate_esp_label(label)
        except ValueError as error:
            raise RuntimeError("backup.json has an invalid ESP label") from error
    if (fat_uuid is None) != (label is None):
        raise RuntimeError("backup.json has an incomplete ESP identity")
    if (
        not isinstance(mount_major_minor, str)
        or mount_major_minor.count(":") != 1
        or not all(part.isdigit() for part in mount_major_minor.split(":"))
    ):
        raise RuntimeError("backup.json has an invalid ESP mount device")
    if mount_source is not None and (
        not isinstance(mount_source, str) or not Path(mount_source).is_absolute()
    ):
        raise RuntimeError("backup.json has an invalid ESP mount source")
    if fat_uuid is not None and mount_source is None:
        raise RuntimeError("backup.json has an incomplete mounted ESP identity")
    if record["managed"] != list(_MANAGED_PATHS):
        raise RuntimeError("backup.json has an invalid managed path set")
    original_tree = record["original_tree"]
    if not isinstance(original_tree, list):
        raise RuntimeError("backup.json original_tree must be a list")
    original_paths = []
    for index, entry in enumerate(original_tree):
        if not isinstance(entry, dict) or entry.get("type") not in {
            "directory",
            "file",
        }:
            raise RuntimeError(f"backup.json original_tree entry {index} is invalid")
        expected_keys = (
            {"path", "type"}
            if entry["type"] == "directory"
            else {"path", "sha256", "size", "type"}
        )
        if set(entry) != expected_keys:
            raise RuntimeError(f"backup.json original_tree entry {index} is invalid")
        path_value = entry["path"]
        if not isinstance(path_value, str) or not _is_safe_backup_tree_path(
            path_value
        ):
            raise RuntimeError(f"backup.json original_tree path {index} is unsafe")
        if entry["type"] == "file" and not _valid_checksum(entry["sha256"]):
            raise RuntimeError(
                f"backup.json original_tree checksum for {path_value} is invalid"
            )
        if entry["type"] == "file" and (
            type(entry["size"]) is not int or entry["size"] < 0
        ):
            raise RuntimeError(
                f"backup.json original_tree size for {path_value} is invalid"
            )
        original_paths.append(path_value)
    if original_paths != sorted(original_paths) or len(original_paths) != len(
        set(original_paths)
    ):
        raise RuntimeError("backup.json original_tree paths must be sorted and unique")
    presence = record["present"]
    if not isinstance(presence, dict) or set(presence) != set(_MANAGED_PATHS):
        raise RuntimeError("backup.json has an invalid presence map")
    if any(type(value) is not bool for value in presence.values()):
        raise RuntimeError("backup.json presence values must be booleans")
    if not _valid_checksum(record["refind_conf_sha256"]):
        raise RuntimeError("backup.json has an invalid refind.conf checksum")
    if type(record["themes_present"]) is not bool:
        raise RuntimeError("backup.json themes_present must be a boolean")
    if not record["themes_present"] and any(
        presence[relative] for relative in ("themes/forest-a", "themes/forest-b")
    ):
        raise RuntimeError("backup.json has inconsistent themes presence")
    _validate_exact_backup_tree(resolved, presence)

    original = resolved / "original"
    refind_conf = original / "refind.conf"
    _assert_no_symlink_components(resolved, refind_conf)
    if not refind_conf.is_file():
        raise RuntimeError("backup is missing original/refind.conf")
    live_original_tree = _build_original_tree_manifest(original)
    if [
        (entry["path"], entry["type"], entry.get("size"))
        for entry in live_original_tree
    ] != [
        (entry["path"], entry["type"], entry.get("size"))
        for entry in original_tree
    ]:
        raise RuntimeError("backup original tree does not match backup.json")
    for live_entry, recorded_entry in zip(live_original_tree, original_tree):
        if (
            live_entry["type"] == "file"
            and live_entry["sha256"] != recorded_entry["sha256"]
        ):
            raise RuntimeError(
                f"backup original tree checksum mismatch: {live_entry['path']}"
            )
    if _sha256(refind_conf) != record["refind_conf_sha256"]:
        raise RuntimeError("backup refind.conf checksum mismatch")
    for relative in _MANAGED_PATHS:
        source = original / relative
        _assert_no_symlink_components(resolved, source)
        present = presence[relative]
        if present and not source.exists():
            raise RuntimeError(f"backup is missing original managed path: {relative}")
        if not present and source.exists():
            raise RuntimeError(f"backup unexpectedly contains managed path: {relative}")
        if present:
            _assert_tree_is_copyable(source)
    return resolved, record


def _validate_backup_esp_identity(
    record: dict[str, object],
    current: _EspIdentity,
) -> None:
    recorded = record["esp_identity"]
    assert isinstance(recorded, dict)
    if recorded["fat_uuid"] is None or recorded["label"] is None:
        raise RuntimeError("backup does not contain a verified ESP identity")
    if (
        recorded["fat_uuid"] != current.fat_uuid
        or recorded["label"] != current.label
    ):
        raise RuntimeError(
            "backup belongs to a different ESP identity: expected FAT UUID "
            f"{recorded['fat_uuid']} label {recorded['label']}, got FAT UUID "
            f"{current.fat_uuid} label {current.label}"
        )


def _remove_journal(
    journal: Path,
    *,
    context: str,
    primary: BaseException | None = None,
) -> None:
    cleanup_errors = []
    for _attempt in range(2):
        try:
            shutil.rmtree(journal)
        except BaseException as error:
            cleanup_errors.append(error)
            if not journal.exists():
                break
        else:
            break

    if not cleanup_errors:
        return
    cleanup_interrupt = next(
        (error for error in cleanup_errors if not isinstance(error, Exception)),
        None,
    )
    chosen = primary
    chosen = chosen or cleanup_interrupt
    preserved = journal.exists()
    detail = (
        f"{context}; journal preserved at {journal}"
        if preserved
        else f"{context}; journal cleanup recovered"
    )
    if chosen is not None:
        if primary is not None and primary is not chosen:
            chosen.add_note(f"initial operation error: {primary}")
        chosen.add_note(detail)
        for error in cleanup_errors:
            if error is not chosen:
                chosen.add_note(
                    f"cleanup also raised {type(error).__name__}: {error}"
                )
        raise chosen
    if preserved:
        raise RuntimeError(detail) from cleanup_errors[-1]


def _note_secondary(
    primary: BaseException,
    secondary: BaseException,
    *,
    context: str,
) -> None:
    primary.add_note(
        f"{context}: {type(secondary).__name__}: {secondary}"
    )


def _stage_backup_restoration(
    backup: Path,
    record: dict[str, object],
    esp: Path,
) -> Path:
    while True:
        journal = esp / f".refind-forest-rollback-{secrets.token_hex(6)}"
        try:
            journal.mkdir(mode=0o700)
        except FileExistsError:
            continue
        break

    new = journal / "new"
    old = journal / "old"
    try:
        new.mkdir()
        old.mkdir()
        original = backup / "original"
        presence = record["present"]
        assert isinstance(presence, dict)
        for relative in _MANAGED_PATHS:
            if presence[relative]:
                _copy_entry_checked(original / relative, new / relative)
        _copy_atomic(original / "refind.conf", new / "refind.conf")
        staged_manifest = _build_original_tree_manifest(new)
        if staged_manifest != record["original_tree"]:
            raise RuntimeError("staged rollback tree does not match validated backup")
    except BaseException as staging_error:
        _remove_journal(
            journal,
            context="failed to clean incomplete rollback staging",
            primary=staging_error,
        )
        raise
    return journal


def _replace_for_reversal(source: Path, target: Path) -> BaseException | None:
    first_error: BaseException | None = None
    for _attempt in range(2):
        try:
            os.replace(source, target)
        except BaseException as error:
            committed = not source.exists() and target.exists()
            if committed:
                if first_error is not None:
                    error.add_note(f"earlier reversal move error: {first_error}")
                return error
            if first_error is None:
                first_error = error
                continue
            if not isinstance(error, Exception):
                error.add_note(f"earlier reversal move error: {first_error}")
                raise
            if not isinstance(first_error, Exception):
                first_error.add_note(f"reversal move retry failed: {error}")
                raise first_error from error
            raise
        return first_error
    raise AssertionError("unreachable reversal retry state")


def _reverse_rollback_swaps(
    swaps: list[_RollbackSwap],
) -> BaseException | None:
    interruption: BaseException | None = None
    for swap in reversed(swaps):
        if swap.staged_moved:
            swap.staged.parent.mkdir(parents=True, exist_ok=True)
            error = _replace_for_reversal(swap.target, swap.staged)
            swap.staged_moved = False
            if error is not None and not isinstance(error, Exception):
                interruption = interruption or error
        if swap.prior_moved:
            swap.target.parent.mkdir(parents=True, exist_ok=True)
            error = _replace_for_reversal(swap.prior, swap.target)
            swap.prior_moved = False
            if error is not None and not isinstance(error, Exception):
                interruption = interruption or error
    return interruption


def _apply_staged_restoration(
    journal: Path,
    record: dict[str, object],
    esp: Path,
) -> None:
    refind = esp / "EFI" / "refind"
    new = journal / "new"
    old = journal / "old"
    themes = refind / "themes"
    themes_existed = themes.exists()
    needs_themes = any(
        (refind / relative).exists() or (new / relative).exists()
        for relative in ("themes/forest-a", "themes/forest-b")
    )

    swaps = []
    try:
        if needs_themes and not themes_existed:
            themes.mkdir()
        for relative in (*_MANAGED_PATHS, "refind.conf"):
            target = refind / relative
            staged = new / relative
            prior = old / relative
            swap = _RollbackSwap(target=target, staged=staged, prior=prior)
            swaps.append(swap)
            prior.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                try:
                    os.replace(target, prior)
                except BaseException:
                    swap.prior_moved = not target.exists() and prior.exists()
                    raise
                else:
                    swap.prior_moved = True
            if staged.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.replace(staged, target)
                except BaseException:
                    swap.staged_moved = not staged.exists() and target.exists()
                    raise
                else:
                    swap.staged_moved = True
        if (
            not record["themes_present"]
            and themes.is_dir()
            and not any(themes.iterdir())
        ):
            themes.rmdir()
    except BaseException as swap_error:
        try:
            reverse_interrupt = _reverse_rollback_swaps(swaps)
            if not themes_existed and themes.is_dir() and not any(themes.iterdir()):
                themes.rmdir()
        except BaseException as reverse_error:
            detail = (
                f"rollback swap failed ({swap_error}); restoring the pre-rollback "
                f"target also failed ({reverse_error}); journal preserved at {journal}"
            )
            _note_secondary(
                swap_error,
                reverse_error,
                context=detail,
            )
            raise swap_error from reverse_error
        if reverse_interrupt is not None:
            _note_secondary(
                swap_error,
                reverse_interrupt,
                context="restoring the pre-rollback target was interrupted",
            )
        _remove_journal(
            journal,
            context="failed to clean reversed rollback journal",
            primary=swap_error,
        )
        if reverse_interrupt is not None:
            raise swap_error from reverse_interrupt
        raise

    _remove_journal(journal, context="rollback succeeded but cleanup failed")


def _restore_backup(backup: Path, record: dict[str, object], esp: Path) -> None:
    journal = _stage_backup_restoration(backup, record, esp)
    _apply_staged_restoration(journal, record, esp)


def _resolve_rollback_esp(
    esp: Path,
    *,
    require_root: bool,
) -> tuple[Path, _EspIdentity | None]:
    argument = Path(esp)
    if argument.is_symlink():
        raise RuntimeError(f"ESP must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"ESP does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"ESP is not a directory: {resolved}")
    identity = (
        _identity_for_mounted_source(_require_root(resolved))
        if require_root
        else None
    )
    _validate_managed_targets(resolved)
    _assert_refind_tree_on_esp_device(resolved)
    return resolved, identity


def _required_rollback_bytes(record: dict[str, object]) -> int:
    original_tree = record["original_tree"]
    assert isinstance(original_tree, list)
    return _ROLLBACK_STAGING_OVERHEAD_BYTES + sum(
        entry["size"]
        for entry in original_tree
        if isinstance(entry, dict) and entry.get("type") == "file"
    )


def _validate_rollback_space(esp: Path, record: dict[str, object]) -> None:
    required = _required_rollback_bytes(record)
    try:
        free = shutil.disk_usage(esp).free
    except OSError as error:
        raise RuntimeError(f"unable to determine free space on ESP: {esp}") from error
    if free < required:
        raise RuntimeError(
            f"ESP has insufficient rollback staging space: need {required} bytes, "
            f"have {free}"
        )


def rollback(backup: Path, esp: Path, *, require_root: bool = True) -> None:
    """Restore exact original refind.conf and preexisting Forest paths."""
    resolved_esp, current_identity = _resolve_rollback_esp(
        Path(esp),
        require_root=require_root,
    )
    resolved_backup, record = _validate_backup(Path(backup), resolved_esp)
    if current_identity is not None:
        _validate_backup_esp_identity(record, current_identity)
    _validate_rollback_space(resolved_esp, record)
    _restore_backup(resolved_backup, record, resolved_esp)


def install(
    staging: Path,
    esp: Path,
    backup_root: Path,
    *,
    require_root: bool = True,
) -> Path:
    """Validate, back up, install A, verify; return backup directory."""
    snapshot = _load_staging_snapshot(Path(staging))
    resolved_esp, esp_identity = _validate_esp(
        Path(esp),
        require_root=require_root,
        expected_esp_label=snapshot.esp_label,
    )
    _validate_backup_root(Path(backup_root), resolved_esp)
    backup = _create_backup(
        resolved_esp,
        Path(backup_root),
        esp_identity=esp_identity,
    )
    _validate_backup(backup, resolved_esp)

    try:
        _install_files(snapshot, resolved_esp)
        errors = verify(resolved_esp)
        if errors:
            raise RuntimeError(
                "installed Forest theme failed verification: " + "; ".join(errors)
            )
    except BaseException as install_error:
        try:
            resolved_backup, record = _validate_backup(backup, resolved_esp)
            _restore_backup(resolved_backup, record, resolved_esp)
        except BaseException as rollback_error:
            _note_secondary(
                install_error,
                rollback_error,
                context=f"automatic rollback failed; backup preserved at {backup}",
            )
            raise install_error from rollback_error
        raise
    return backup


def switch_theme(
    variant: str,
    esp: Path,
    *,
    require_root: bool = True,
) -> None:
    """Atomically activate validated variant a/b."""
    if variant not in {"a", "b"}:
        raise ValueError("variant must be 'a' or 'b'")
    resolved_esp, _esp_identity = _validate_esp(
        Path(esp),
        require_root=require_root,
    )
    errors = verify(resolved_esp)
    if errors:
        raise RuntimeError(
            "refusing to switch an invalid Forest install: " + "; ".join(errors)
        )

    refind = resolved_esp / "EFI" / "refind"
    active = refind / "theme-active.conf"
    previous = active.read_bytes()
    try:
        _copy_atomic(refind / f"theme-{variant}.conf", active)
        errors = verify(resolved_esp)
        if errors:
            raise RuntimeError(
                "switched Forest theme failed verification: " + "; ".join(errors)
            )
    except BaseException as switch_error:
        try:
            _atomic_write(active, previous)
        except BaseException as restore_error:
            raise RuntimeError(
                f"theme switch failed ({switch_error}); restoring the previous variant "
                f"also failed ({restore_error})"
            ) from switch_error
        raise

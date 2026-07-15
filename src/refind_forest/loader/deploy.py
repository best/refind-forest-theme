"""Transactional deployment of a verified rEFInd loader candidate.

Threat boundary: the transaction lock serializes cooperating invocations only.
BootNext creation reserves an absent efivarfs name with ``O_EXCL`` and then
performs one whole-variable write; it is not a firmware compare-and-swap. Linux
exposes no content-conditional EFI-variable deletion, so exact raw ownership
checks detect observed drift but cannot prevent a concurrent privileged process
or firmware from changing a variable between check and unlink. Kernel and
firmware enforcement of documented UEFI variable semantics is trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
from types import SimpleNamespace
from typing import Any
import uuid
import zlib


_DISTRIBUTION_ACTIVE_SHA256 = (
    "43df4fd676efc2835c2a546f6875b6134d6ce1662ef486cbf164d96754674fda"
)
_KNOWN_ACTIVE_SHA256 = frozenset({_DISTRIBUTION_ACTIVE_SHA256})
_SCHEMA = "refind-forest-loader-transaction"
_FORMAT = 1
_ACTIVE_RELATIVE = "EFI/refind/refind_x64.efi"
_CANDIDATE_RELATIVE = "EFI/refind/refind_x64_candidate.efi"
_EFI_CANDIDATE_PATH = r"\EFI\refind\refind_x64_candidate.efi"


@dataclass(frozen=True)
class LoaderStatus:
    state: str
    active_sha256: str
    candidate_sha256: str
    candidate_bootnum: str
    boot_current: str
    boot_order: tuple[str, ...]


@dataclass(frozen=True)
class _Snapshot:
    boot_current: str
    boot_next: str | None
    boot_order: tuple[str, ...]
    raw_boot_current: bytes
    raw_boot_next: bytes | None
    raw_boot_order: bytes
    entries: dict[str, bytes]


def _read_regular(path: Path, description: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"{description} is not a regular file: {path}")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RuntimeError(f"{description} must not be a symbolic link: {path}") from error
        raise RuntimeError(f"unable to read {description}: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    data = b"".join(chunks)
    if identity_before != identity_after or len(data) != before.st_size:
        raise RuntimeError(f"{description} changed while it was read: {path}")
    return data, before


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(_read_regular(Path(path), "loader")[0])


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_file_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    except (TypeError, UnicodeEncodeError) as error:
        raise RuntimeError("loader transaction data is not ASCII JSON") from error


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    try:
        _write_file_exclusive(temporary, _json_bytes(value))
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_manifest(transaction: Path, manifest: dict[str, object]) -> None:
    _atomic_json(transaction / "manifest.json", manifest)


def _write_intent(transaction: Path, operation: str, **details: object) -> None:
    _atomic_json(
        transaction / "intent.json",
        {"format": _FORMAT, "operation": operation, **details},
    )


def _clear_intent(transaction: Path) -> None:
    try:
        (transaction / "intent.json").unlink()
    except FileNotFoundError:
        return
    _fsync_directory(transaction)


def _validate_identity(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or not value:
        raise RuntimeError("physical ESP identity is invalid")
    identity = dict(value)
    _json_bytes(identity)
    return identity


def _resolve_esp(
    esp: Path,
    backend: object,
    *,
    require_root: bool,
    esp_identity: Callable[[Path], object] | None = None,
) -> tuple[Path, dict[str, object]]:
    argument = Path(esp)
    if argument.is_symlink():
        raise RuntimeError(f"ESP must not be a symbolic link: {argument}")
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"ESP does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"ESP is not a directory: {resolved}")

    if esp_identity is not None:
        return resolved, _validate_identity(esp_identity(resolved))
    resolver = getattr(backend, "resolve_esp", None)
    if resolver is None:
        raise RuntimeError("EFI backend cannot resolve physical ESP identity")
    backend_esp, identity = resolver(resolved, require_root=require_root)
    backend_path = Path(backend_esp).resolve(strict=True)
    if backend_path != resolved:
        raise RuntimeError("EFI backend resolved a different ESP")
    return resolved, _validate_identity(identity)


def _snapshot(backend: object) -> _Snapshot:
    reader = getattr(backend, "snapshot", None)
    if reader is None:
        raise RuntimeError("EFI backend cannot read NVRAM")
    raw = reader()
    if not isinstance(raw, Mapping):
        raise RuntimeError("EFI backend returned an invalid NVRAM snapshot")
    try:
        boot_current = raw["boot_current"]
        boot_next = raw["boot_next"]
        boot_order = raw["boot_order"]
        raw_boot_order = raw["raw_boot_order"]
        entries = raw["entries"]
    except KeyError as error:
        raise RuntimeError("EFI backend returned an incomplete NVRAM snapshot") from error
    if not isinstance(boot_current, str) or not _valid_bootnum(boot_current):
        raise RuntimeError("BootCurrent is invalid")
    if boot_next is not None and (
        not isinstance(boot_next, str) or not _valid_bootnum(boot_next)
    ):
        raise RuntimeError("BootNext is invalid")
    if not isinstance(boot_order, (tuple, list)) or not all(
        isinstance(item, str) and _valid_bootnum(item) for item in boot_order
    ):
        raise RuntimeError("BootOrder is invalid")
    if not isinstance(raw_boot_order, bytes):
        raise RuntimeError("raw BootOrder is invalid")
    raw_boot_current = raw.get("raw_boot_current")
    if raw_boot_current is None:
        raw_boot_current = int(boot_current, 16).to_bytes(2, "little")
    if not isinstance(raw_boot_current, bytes):
        raise RuntimeError("raw BootCurrent is invalid")
    raw_boot_next = raw.get("raw_boot_next")
    if raw_boot_next is None and boot_next is not None:
        raw_boot_next = int(boot_next, 16).to_bytes(2, "little")
    if raw_boot_next is not None and not isinstance(raw_boot_next, bytes):
        raise RuntimeError("raw BootNext is invalid")
    if not isinstance(entries, Mapping):
        raise RuntimeError("raw Boot entries are invalid")
    entry_numbers: dict[str, str] = {}
    for bootnum in entries:
        if not isinstance(bootnum, str) or not _valid_bootnum(bootnum):
            raise RuntimeError("raw Boot entry number is invalid")
        canonical = bootnum.upper()
        if canonical in entry_numbers:
            raise RuntimeError("Boot entry number collision after normalization")
        entry_numbers[canonical] = bootnum
    if any(canonical != original for canonical, original in entry_numbers.items()):
        raise RuntimeError("noncanonical Boot entry number")
    normalized_entries: dict[str, bytes] = {}
    for bootnum, entry in entries.items():
        if not isinstance(entry, bytes):
            raise RuntimeError(f"raw Boot{bootnum} is invalid")
        normalized_entries[bootnum] = entry
    return _Snapshot(
        boot_current.upper(),
        boot_next.upper() if boot_next is not None else None,
        tuple(item.upper() for item in boot_order),
        raw_boot_current,
        raw_boot_next,
        raw_boot_order,
        normalized_entries,
    )


def _valid_bootnum(value: str) -> bool:
    return len(value) == 4 and all(character in "0123456789abcdefABCDEF" for character in value)


def _expected_boot_next_raw(bootnum: str) -> bytes:
    return (7).to_bytes(4, "little") + int(bootnum, 16).to_bytes(2, "little")


def _snapshot_json(snapshot: _Snapshot) -> dict[str, object]:
    return {
        "boot_current": snapshot.boot_current,
        "boot_next": snapshot.boot_next,
        "boot_order": list(snapshot.boot_order),
        "raw_boot_current": snapshot.raw_boot_current.hex(),
        "raw_boot_next": (
            snapshot.raw_boot_next.hex() if snapshot.raw_boot_next is not None else None
        ),
        "raw_boot_order": snapshot.raw_boot_order.hex(),
        "entries": {
            bootnum: raw.hex() for bootnum, raw in sorted(snapshot.entries.items())
        },
    }


def _validate_boot_references(snapshot: _Snapshot) -> None:
    if snapshot.boot_current not in snapshot.entries:
        raise RuntimeError(
            f"BootCurrent references missing Boot{snapshot.boot_current} entry"
        )
    if snapshot.boot_next is not None and snapshot.boot_next not in snapshot.entries:
        raise RuntimeError(
            f"BootNext references missing Boot{snapshot.boot_next} entry"
        )
    for bootnum in snapshot.boot_order:
        if bootnum not in snapshot.entries:
            raise RuntimeError(f"BootOrder references missing Boot{bootnum} entry")


def _tree_hash(
    root: Path,
    *,
    replacements: Mapping[str, bytes] | None = None,
    absent: set[str] | frozenset[str] = frozenset(),
) -> str:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"loader tree is not a regular directory: {root}")
    replacement_files = dict(replacements or {})
    if set(replacement_files) & set(absent):
        raise RuntimeError("loader tree projection is contradictory")
    existing = {
        path.relative_to(root).as_posix(): path for path in root.rglob("*")
    }
    digest = hashlib.sha256()
    for relative_text in sorted(set(existing) | set(replacement_files)):
        if relative_text in absent:
            continue
        path = existing.get(relative_text, root / relative_text)
        relative = relative_text.encode("utf-8")
        if path.is_symlink():
            raise RuntimeError(f"symbolic link is not allowed in loader tree: {path}")
        if relative_text in replacement_files:
            if path.exists() and not path.is_file():
                raise RuntimeError(f"unsupported entry in loader tree: {path}")
            data = replacement_files[relative_text]
            digest.update(b"F\0" + relative + b"\0")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(hashlib.sha256(data).digest())
            continue
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(b"D\0" + relative + b"\0")
        elif stat.S_ISREG(metadata.st_mode):
            data, _ = _read_regular(path, "loader tree file")
            digest.update(b"F\0" + relative + b"\0")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(hashlib.sha256(data).digest())
        else:
            raise RuntimeError(f"unsupported entry in loader tree: {path}")
    return digest.hexdigest()


def _lock_key(identity: Mapping[str, object]) -> str:
    return hashlib.sha256(_json_bytes(identity)).hexdigest()


@contextmanager
def _esp_lock(
    lock_root: Path, key: str, *, require_root: bool
) -> Iterator[None]:
    if len(key) != 64 or any(character not in "0123456789abcdef" for character in key):
        raise RuntimeError("loader lock key is invalid")
    lock_root = _absolute_lexical(Path(lock_root))
    _validate_path_components(lock_root, require_root=False)
    try:
        root_before = os.lstat(lock_root)
        existed = True
    except FileNotFoundError:
        existed = False
        parent = os.lstat(lock_root.parent)
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise RuntimeError("loader lock parent is not a safe directory")
        if require_root and (
            parent.st_uid != 0
            or (
                stat.S_IMODE(parent.st_mode) & 0o022
                and not parent.st_mode & stat.S_ISVTX
            )
        ):
            raise RuntimeError("loader lock parent is not root-controlled")
        lock_root.mkdir(mode=0o700)
        root_before = os.lstat(lock_root)
    if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
        raise RuntimeError("loader lock root must not be a symbolic link")
    if require_root and root_before.st_uid != 0:
        raise RuntimeError("loader lock root is not root-owned")
    if require_root and stat.S_IMODE(root_before.st_mode) != 0o700:
        raise RuntimeError("loader lock root must have mode 0700")
    if not require_root and stat.S_IMODE(root_before.st_mode) != 0o700:
        os.chmod(lock_root, 0o700)
        root_before = os.lstat(lock_root)
    lock_path = lock_root / f"refind-forest-loader-{key}.lock"
    try:
        path_before = os.lstat(lock_path)
        lock_existed = True
        if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
            raise RuntimeError("loader lock path has an unsafe file type")
        if require_root and path_before.st_uid != 0:
            raise RuntimeError("loader lock file is not root-owned")
        if require_root and stat.S_IMODE(path_before.st_mode) != 0o600:
            raise RuntimeError("loader lock file must have mode 0600")
    except FileNotFoundError:
        lock_existed = False
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("opened loader lock is not a regular file")
        if require_root and opened.st_uid != 0:
            raise RuntimeError("opened loader lock is not root-owned")
        if not lock_existed:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise RuntimeError("opened loader lock must have mode 0600")
        opened_path = os.lstat(lock_path)
        if (opened.st_dev, opened.st_ino) != (opened_path.st_dev, opened_path.st_ino):
            raise RuntimeError("loader lock path was replaced before flock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        locked_path = os.lstat(lock_path)
        root_after = os.lstat(lock_root)
        if (locked.st_dev, locked.st_ino) != (
            locked_path.st_dev,
            locked_path.st_ino,
        ):
            raise RuntimeError("loader lock path was replaced while acquiring flock")
        if (root_before.st_dev, root_before.st_ino) != (
            root_after.st_dev,
            root_after.st_ino,
        ):
            raise RuntimeError("loader lock root was replaced while acquiring flock")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def _load_json(path: Path, description: str) -> dict[str, object]:
    data, _ = _read_regular(path, description)
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{description} is invalid") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{description} is invalid")
    return value


def _load_manifest(transaction: Path) -> dict[str, object]:
    manifest = _load_json(transaction / "manifest.json", "loader transaction manifest")
    if manifest.get("format") != _FORMAT or manifest.get("schema") != _SCHEMA:
        raise RuntimeError("loader transaction manifest has an invalid schema")
    return manifest


def _existing_transaction(
    backup_root: Path,
    esp: Path,
    identity: Mapping[str, object],
) -> tuple[Path, dict[str, object]] | None:
    if not backup_root.exists():
        return None
    if backup_root.is_symlink() or not backup_root.is_dir():
        raise RuntimeError("loader backup root is not a regular directory")
    matches = []
    for child in sorted(backup_root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            continue
        manifest_path = child / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = _load_manifest(child)
        if manifest.get("esp") == str(esp) and manifest.get("esp_identity") == dict(identity):
            matches.append((child, manifest))
    if len(matches) > 1:
        raise RuntimeError("multiple loader transactions exist for this ESP")
    return matches[0] if matches else None


def _validate_backup_root(
    backup_root: Path, esp: Path, *, require_root: bool
) -> Path:
    argument = _absolute_lexical(Path(backup_root))
    _validate_path_components(argument, require_root=require_root)
    resolved = argument
    if resolved == esp or esp in resolved.parents:
        raise RuntimeError("loader backup root must be outside the ESP")
    if resolved.exists():
        _validate_secure_entry(
            resolved,
            directory=True,
            mode=0o700,
            require_root=require_root,
            description="loader backup root",
        )
    elif require_root and not resolved.parent.exists():
        raise RuntimeError("production loader backup parent must already exist")
    return resolved


def _new_transaction(backup_root: Path, *, require_root: bool) -> Path:
    backup_root.mkdir(mode=0o700, parents=not require_root, exist_ok=True)
    os.chmod(backup_root, 0o700)
    _validate_secure_entry(
        backup_root,
        directory=True,
        mode=0o700,
        require_root=require_root,
        description="loader backup root",
    )
    prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    while True:
        transaction = backup_root / f"loader-{prefix}-{secrets.token_hex(6)}"
        try:
            transaction.mkdir(mode=0o700)
        except FileExistsError:
            continue
        os.chmod(transaction, 0o700)
        _validate_secure_entry(
            transaction,
            directory=True,
            mode=0o700,
            require_root=require_root,
            description="loader transaction",
        )
        _fsync_directory(backup_root)
        return transaction


def _publish_candidate(
    data: bytes,
    target: Path,
    temporary: Path,
    expected_hash: str,
    verifier: Callable[[Path], None],
) -> None:
    if temporary.parent != target.parent:
        raise RuntimeError("candidate temporary must share the target directory")
    created = False
    try:
        if temporary.exists() or temporary.is_symlink():
            existing, _ = _read_regular(temporary, "candidate temporary")
            if existing != data or _sha256_bytes(existing) != expected_hash:
                raise RuntimeError("foreign candidate temporary file preserved")
        else:
            _write_file_exclusive(temporary, data)
            created = True
        readback, _ = _read_regular(temporary, "staged candidate loader")
        if _sha256_bytes(readback) != expected_hash or readback != data:
            raise RuntimeError("candidate loader read-back verification failed")
        verifier(temporary)
        os.replace(temporary, target)
        _fsync_directory(target.parent)
        if _sha256(target) != expected_hash:
            raise RuntimeError("published candidate loader hash mismatch")
    finally:
        if created:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _stage_temporary_name(lock_key: str) -> str:
    return f".refind_x64_candidate.efi.stage-{lock_key[:16]}"


def _rollback_artifact_names(lock_key: str) -> tuple[str, str]:
    return (
        f".refind_x64_candidate.efi.rollback-{lock_key[:16]}",
        f".refind_x64.efi.rollback-{lock_key[:16]}",
    )


def _entry_matches(
    backend: object,
    raw: bytes,
    identity: Mapping[str, object],
    loader_path: str,
) -> bool:
    matcher = getattr(backend, "entry_matches", None)
    if matcher is None:
        return loader_path.encode("utf-16-le") in raw
    return bool(matcher(raw, dict(identity), loader_path))


def _default_lock_root(require_root: bool, backup_root: Path) -> Path:
    return Path("/run/lock/refind-forest-loader") if require_root else backup_root / ".locks"


def _manifest_mapping(
    manifest: Mapping[str, object], key: str, description: str
) -> dict[str, object]:
    value = manifest.get(key)
    if not isinstance(value, Mapping):
        raise RuntimeError(f"loader transaction {description} is invalid")
    return dict(value)


def _manifest_hash(manifest: Mapping[str, object], key: str) -> str:
    value = _manifest_mapping(manifest, key, key).get("sha256")
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RuntimeError(f"loader transaction {key} hash is invalid")
    return value


def _manifest_bootnum(manifest: Mapping[str, object]) -> str:
    value = manifest.get("candidate_bootnum")
    if not isinstance(value, str) or not _valid_bootnum(value):
        raise RuntimeError("loader transaction candidate Boot number is invalid")
    return value.upper()


def _manifest_hex(manifest: Mapping[str, object], key: str) -> bytes:
    value = manifest.get(key)
    if not isinstance(value, str):
        raise RuntimeError(f"loader transaction {key} is invalid")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise RuntimeError(f"loader transaction {key} is invalid") from error


def _initial_raw_boot_order(manifest: Mapping[str, object]) -> bytes:
    initial = _manifest_mapping(manifest, "nvram_initial", "initial NVRAM snapshot")
    value = initial.get("raw_boot_order")
    if not isinstance(value, str):
        raise RuntimeError("loader transaction initial raw BootOrder is invalid")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise RuntimeError("loader transaction initial raw BootOrder is invalid") from error


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _validate_path_components(path: Path, *, require_root: bool) -> None:
    absolute = _absolute_lexical(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as error:
            raise RuntimeError(f"unable to inspect secure path component: {current}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"symbolic link component is not allowed: {current}")
        if current != absolute and not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"secure path ancestor is not a directory: {current}")
        if require_root:
            if metadata.st_uid != 0:
                raise RuntimeError(f"production loader path is not root-owned: {current}")
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise RuntimeError(
                    f"production loader path is group/world writable: {current}"
                )


def _validate_secure_entry(
    path: Path,
    *,
    directory: bool,
    mode: int,
    require_root: bool,
    description: str,
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise RuntimeError(f"unable to inspect {description}: {path}") from error
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError(f"{description} has an unsafe file type: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise RuntimeError(f"{description} must have mode {mode:04o}: {path}")
    if require_root and metadata.st_uid != 0:
        raise RuntimeError(f"{description} is not root-owned: {path}")
    return metadata


def _validate_transaction_security(transaction: Path, *, require_root: bool) -> None:
    _validate_path_components(transaction, require_root=require_root)
    _validate_secure_entry(
        transaction,
        directory=True,
        mode=0o700,
        require_root=require_root,
        description="loader transaction",
    )


def _validate_transaction_artifacts(transaction: Path, *, require_root: bool) -> None:
    _validate_secure_entry(
        transaction / "manifest.json",
        directory=False,
        mode=0o600,
        require_root=require_root,
        description="loader transaction manifest",
    )
    _validate_secure_entry(
        transaction / "active",
        directory=True,
        mode=0o700,
        require_root=require_root,
        description="loader active-backup directory",
    )
    _validate_secure_entry(
        transaction / "active" / "refind_x64.efi",
        directory=False,
        mode=0o600,
        require_root=require_root,
        description="backed-up active loader",
    )
    intent = transaction / "intent.json"
    if intent.exists() or intent.is_symlink():
        _validate_secure_entry(
            intent,
            directory=False,
            mode=0o600,
            require_root=require_root,
            description="loader transaction intent",
        )


def _transaction_path(transaction: Path, *, require_root: bool = False) -> Path:
    argument = _absolute_lexical(Path(transaction))
    _validate_path_components(argument, require_root=require_root)
    try:
        resolved = argument.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"loader transaction does not exist: {argument}") from error
    if not resolved.is_dir():
        raise RuntimeError("loader transaction is not a directory")
    _validate_transaction_security(resolved, require_root=require_root)
    return resolved


def _bind_transaction(
    transaction: Path,
    esp: Path,
    backend: object,
    *,
    require_root: bool,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    resolved_transaction = _transaction_path(transaction, require_root=require_root)
    _validate_transaction_security(
        resolved_transaction, require_root=require_root
    )
    _validate_transaction_artifacts(
        resolved_transaction, require_root=require_root
    )
    manifest = _load_manifest(resolved_transaction)
    recorded_esp = manifest.get("esp")
    if not isinstance(recorded_esp, str):
        raise RuntimeError("loader transaction ESP path is invalid")
    resolved_esp, identity = _resolve_esp(
        Path(esp), backend, require_root=require_root
    )
    if recorded_esp != str(resolved_esp):
        raise RuntimeError("loader transaction belongs to a different ESP")
    if resolved_transaction == resolved_esp or resolved_esp in resolved_transaction.parents:
        raise RuntimeError("loader transaction must remain outside the ESP")
    recorded_identity = _manifest_mapping(manifest, "esp_identity", "ESP identity")
    if identity != recorded_identity:
        raise RuntimeError("wrong physical ESP identity")
    if manifest.get("lock_key") != _lock_key(recorded_identity):
        raise RuntimeError("loader transaction lock identity is invalid")
    return resolved_transaction, resolved_esp, manifest, identity


def _validate_nvram_ownership(
    manifest: Mapping[str, object],
    snapshot: _Snapshot,
    backend: object,
    identity: Mapping[str, object],
    *,
    validate_boot_next: bool = True,
) -> str:
    if snapshot.raw_boot_order != _initial_raw_boot_order(manifest):
        raise RuntimeError("BootOrder changed from the loader transaction snapshot")
    _validate_initial_boot_entries(manifest, snapshot)
    bootnum = _manifest_bootnum(manifest)
    if validate_boot_next:
        _validate_boot_next_state(manifest, snapshot, bootnum)
    expected_raw = _manifest_hex(manifest, "candidate_entry_raw")
    if snapshot.entries.get(bootnum) != expected_raw:
        raise RuntimeError("candidate Boot entry ownership changed")
    if bootnum in snapshot.boot_order:
        raise RuntimeError("candidate Boot entry is unexpectedly in BootOrder")
    if not _entry_matches(backend, expected_raw, identity, _EFI_CANDIDATE_PATH):
        raise RuntimeError("candidate Boot entry ownership is invalid")
    return bootnum


def _validate_initial_boot_entries(
    manifest: Mapping[str, object], snapshot: _Snapshot
) -> None:
    for bootnum, expected_raw in _initial_entries(manifest).items():
        if snapshot.entries.get(bootnum) != expected_raw:
            raise RuntimeError(
                f"initial Boot entry ownership changed: Boot{bootnum}"
            )


def _slot_hash(path: Path) -> str:
    try:
        return _sha256(path)
    except RuntimeError:
        if path.is_symlink() or path.exists():
            raise
        return ""


def _candidate_boot_fell_back(
    manifest: Mapping[str, object], snapshot: _Snapshot, bootnum: str
) -> bool:
    return (
        manifest.get("state") == "armed"
        and manifest.get("boot_next_owned") is True
        and _initial_raw_boot_next(manifest) is None
        and snapshot.boot_next is None
        and snapshot.raw_boot_next is None
        and snapshot.boot_current != bootnum
        and snapshot.boot_current in snapshot.boot_order
    )


def _observed_state(
    manifest: Mapping[str, object],
    snapshot: _Snapshot,
    active_hash: str,
    candidate_hash: str,
) -> str:
    old_hash = _manifest_hash(manifest, "active")
    new_hash = _manifest_hash(manifest, "candidate")
    bootnum = _manifest_bootnum(manifest)
    if (active_hash, candidate_hash) == (old_hash, new_hash):
        recorded_state = manifest.get("state")
        if recorded_state in {"rolled_back", "promotion_failed"}:
            return str(recorded_state)
        if snapshot.boot_next == bootnum:
            return "armed"
        if snapshot.boot_current == bootnum:
            return "candidate_booted"
        if _candidate_boot_fell_back(manifest, snapshot, bootnum):
            return "fallback"
        return "staged"
    if (active_hash, candidate_hash) == (new_hash, old_hash):
        return "promoted"
    if active_hash == old_hash and candidate_hash == "" and manifest.get("state") == "rolled_back":
        return "rolled_back"
    raise RuntimeError("loader slot hashes are ambiguous")


def _initial_entries(manifest: Mapping[str, object]) -> dict[str, bytes]:
    initial = _manifest_mapping(manifest, "nvram_initial", "initial NVRAM snapshot")
    entries = initial.get("entries")
    if not isinstance(entries, Mapping):
        raise RuntimeError("loader transaction initial Boot entries are invalid")
    result: dict[str, bytes] = {}
    for number, value in entries.items():
        if not isinstance(number, str) or not _valid_bootnum(number) or not isinstance(value, str):
            raise RuntimeError("loader transaction initial Boot entries are invalid")
        try:
            result[number.upper()] = bytes.fromhex(value)
        except ValueError as error:
            raise RuntimeError("loader transaction initial Boot entries are invalid") from error
    return result


def _observe_created_entry(
    manifest: Mapping[str, object],
    snapshot: _Snapshot,
    backend: object,
    identity: Mapping[str, object],
    *,
    baseline: Mapping[str, object] | None = None,
    transaction: Path | None = None,
) -> tuple[str, bytes] | None:
    if baseline is None:
        baseline = _manifest_mapping(
            manifest, "nvram_initial", "initial NVRAM snapshot"
        )
    raw_order_value = baseline.get("raw_boot_order")
    raw_next_value = baseline.get("raw_boot_next")
    entries_value = baseline.get("entries")
    baseline_next = baseline.get("boot_next")
    if not isinstance(raw_order_value, str) or not isinstance(entries_value, Mapping):
        raise RuntimeError("entry-creation intent before snapshot is invalid")
    try:
        baseline_order = bytes.fromhex(raw_order_value)
        baseline_raw_next = (
            bytes.fromhex(raw_next_value)
            if isinstance(raw_next_value, str)
            else None
        )
        before_entries = {
            str(number).upper(): bytes.fromhex(str(raw))
            for number, raw in entries_value.items()
        }
    except (ValueError, TypeError) as error:
        raise RuntimeError("entry-creation intent before snapshot is invalid") from error
    if baseline_next is not None and (
        not isinstance(baseline_next, str) or not _valid_bootnum(baseline_next)
    ):
        raise RuntimeError("entry-creation intent before BootNext is invalid")
    if any(snapshot.entries.get(number) != raw for number, raw in before_entries.items()):
        raise RuntimeError("initial Boot entry changed during alternate entry creation")
    new_numbers = sorted(set(snapshot.entries) - set(before_entries))
    if not new_numbers:
        return None
    if len(new_numbers) != 1:
        raise RuntimeError("alternate entry creation produced ambiguous Boot entries")
    bootnum = new_numbers[0]
    raw = snapshot.entries[bootnum]
    if not _entry_matches(backend, raw, identity, _EFI_CANDIDATE_PATH):
        raise RuntimeError("created Boot entry does not own the candidate loader")
    if transaction is not None:
        _write_intent(
            transaction,
            "create_entry",
            before=dict(baseline),
            candidate_bootnum=bootnum,
            candidate_entry_raw=raw.hex(),
        )
    if snapshot.raw_boot_order != baseline_order:
        raise RuntimeError("BootOrder changed during alternate entry creation")
    if snapshot.boot_next != baseline_next or snapshot.raw_boot_next != baseline_raw_next:
        raise RuntimeError("BootNext changed during alternate entry creation")
    if baseline_next == bootnum:
        raise RuntimeError("candidate Boot number conflicts with existing BootNext")
    if bootnum in snapshot.boot_order:
        raise RuntimeError("candidate Boot entry was added to BootOrder")
    return bootnum, raw


def _resume_stage(
    transaction: Path,
    manifest: dict[str, object],
    resolved_esp: Path,
    identity: Mapping[str, object],
    backend: object,
    candidate_data: bytes,
    candidate_hash: str,
    verifier: Callable[[Path], None],
) -> Path:
    old_hash = _manifest_hash(manifest, "active")
    if _manifest_hash(manifest, "candidate") != candidate_hash:
        raise RuntimeError("candidate mismatch with existing loader transaction")
    _require_backup(transaction, old_hash)
    if _slot_hash(resolved_esp / _ACTIVE_RELATIVE) != old_hash:
        raise RuntimeError("active loader changed from the staged transaction")
    target = resolved_esp / _CANDIDATE_RELATIVE
    target_hash = _slot_hash(target)
    intent = _load_intent(transaction)
    operation = intent.get("operation") if intent is not None else None
    if operation not in {None, "publish_candidate", "create_entry"}:
        raise RuntimeError(f"loader transaction has pending {operation} intent")
    incomplete_stage = operation is not None or manifest.get("state") in {
        "backup_ready",
        "candidate_published",
    }

    if operation == "publish_candidate" or manifest.get("state") == "backup_ready":
        lock_key = manifest.get("lock_key")
        if not isinstance(lock_key, str):
            raise RuntimeError("loader transaction lock identity is invalid")
        temporary_name = _stage_temporary_name(lock_key)
        if operation == "publish_candidate":
            if intent is None or intent.get("temporary_name") != temporary_name:
                raise RuntimeError("publish intent temporary name is invalid")
        elif operation is None:
            _write_intent(
                transaction,
                "publish_candidate",
                temporary_name=temporary_name,
            )
        temporary = target.parent / temporary_name
        if target_hash == "":
            _publish_candidate(
                candidate_data,
                target,
                temporary,
                candidate_hash,
                verifier,
            )
            target_hash = candidate_hash
        elif temporary.exists() or temporary.is_symlink():
            temporary_data, _ = _read_regular(
                temporary, "recorded candidate temporary"
            )
            if (
                temporary_data != candidate_data
                or _sha256_bytes(temporary_data) != candidate_hash
            ):
                raise RuntimeError("foreign candidate temporary file preserved")
            temporary.unlink()
            _fsync_directory(temporary.parent)
        if target_hash != candidate_hash:
            raise RuntimeError("candidate mismatch with staged loader slot")
        verifier(target)
        _fsync_directory(target.parent)
        _backend_syncfs(backend, resolved_esp)
        manifest["state"] = "candidate_published"
        _write_manifest(transaction, manifest)
        _clear_intent(transaction)
        operation = None
    elif target_hash != candidate_hash:
        raise RuntimeError("candidate mismatch with staged loader slot")
    else:
        verifier(target)

    snapshot = _snapshot(backend)
    recorded_number = manifest.get("candidate_bootnum")
    recorded_raw = manifest.get("candidate_entry_raw")
    if isinstance(recorded_number, str) and isinstance(recorded_raw, str):
        _validate_nvram_ownership(manifest, snapshot, backend, identity)
        if incomplete_stage:
            manifest["state"] = "staged"
            _write_manifest(transaction, manifest)
            _clear_intent(transaction)
        return transaction
    if recorded_number is not None or recorded_raw is not None:
        raise RuntimeError("loader transaction candidate entry metadata is incomplete")

    baseline: Mapping[str, object]
    if operation == "create_entry":
        before_value = intent.get("before") if intent is not None else None
        if not isinstance(before_value, Mapping):
            raise RuntimeError("entry-creation intent is missing its before snapshot")
        baseline = before_value
    else:
        baseline = _manifest_mapping(
            manifest, "nvram_initial", "initial NVRAM snapshot"
        )
        initial_next = baseline.get("boot_next")
        raw_initial_next = _initial_raw_boot_next(manifest)
        if (
            snapshot.boot_next != initial_next
            or snapshot.raw_boot_next != raw_initial_next
        ):
            raise RuntimeError("BootNext changed before alternate entry creation")
        initial_entries = _initial_entries(manifest)
        if snapshot.entries != initial_entries:
            raise RuntimeError("unowned Boot entry appeared before alternate entry creation")
    observed = _observe_created_entry(
        manifest,
        snapshot,
        backend,
        identity,
        baseline=baseline,
        transaction=transaction if operation == "create_entry" else None,
    )
    if observed is None:
        _validate_boot_references(snapshot)
        if operation != "create_entry":
            _write_intent(
                transaction,
                "create_entry",
                before=_snapshot_json(snapshot),
            )
        creator = getattr(backend, "create_only_entry", None)
        if creator is None:
            raise RuntimeError("EFI backend cannot create an alternate boot entry")
        creator(dict(identity), _EFI_CANDIDATE_PATH)
        snapshot = _snapshot(backend)
        observed = _observe_created_entry(
            manifest,
            snapshot,
            backend,
            identity,
            baseline=baseline,
            transaction=transaction,
        )
        if observed is None:
            raise RuntimeError("alternate entry creation did not create a Boot entry")
    bootnum, entry_raw = observed
    manifest["candidate_bootnum"] = bootnum
    manifest["candidate_entry_raw"] = entry_raw.hex()
    manifest["state"] = "staged"
    _write_manifest(transaction, manifest)
    _clear_intent(transaction)
    return transaction


def stage_loader(
    candidate: Path,
    esp: Path,
    backup_root: Path,
    *,
    backend: object | None = None,
    verifier: Callable[[Path], None] | None = None,
    esp_identity: Callable[[Path], object] | None = None,
    require_root: bool = True,
    lock_root: Path | None = None,
) -> Path:
    """Stage a verified loader and create an alternate, non-ordered boot entry."""

    if backend is None:
        backend = _RealBackend()
    if verifier is None:
        verifier = _default_verifier

    candidate_data, _ = _read_regular(Path(candidate), "candidate loader")
    candidate_hash = _sha256_bytes(candidate_data)
    verifier(Path(candidate))
    resolved_esp, identity = _resolve_esp(
        Path(esp),
        backend,
        require_root=require_root,
        esp_identity=esp_identity,
    )
    active = resolved_esp / _ACTIVE_RELATIVE
    active_data, _ = _read_regular(active, "active loader")
    active_hash = _sha256_bytes(active_data)
    backup_root = _validate_backup_root(
        Path(backup_root), resolved_esp, require_root=require_root
    )

    existing = _existing_transaction(backup_root, resolved_esp, identity)
    if existing is not None:
        existing_transaction, manifest = existing
        _validate_transaction_security(
            existing_transaction, require_root=require_root
        )
        _validate_transaction_artifacts(
            existing_transaction, require_root=require_root
        )
        recorded_candidate = manifest.get("candidate")
        if not isinstance(recorded_candidate, Mapping) or recorded_candidate.get("sha256") != candidate_hash:
            raise RuntimeError("candidate mismatch with existing loader transaction")
    elif active_hash not in _KNOWN_ACTIVE_SHA256:
        raise RuntimeError("unknown active loader")

    target = resolved_esp / _CANDIDATE_RELATIVE
    if existing is None and (target.is_symlink() or target.exists()):
        raise RuntimeError("candidate loader slot already exists without ownership")

    lock_key = _lock_key(identity)
    selected_lock_root = lock_root or _default_lock_root(require_root, backup_root)
    with _esp_lock(selected_lock_root, lock_key, require_root=require_root):
        existing = _existing_transaction(backup_root, resolved_esp, identity)
        if existing is not None:
            transaction, manifest = existing
            _validate_transaction_security(transaction, require_root=require_root)
            _validate_transaction_artifacts(transaction, require_root=require_root)
            return _resume_stage(
                transaction,
                manifest,
                resolved_esp,
                identity,
                backend,
                candidate_data,
                candidate_hash,
                verifier,
            )

        locked_active_data, _ = _read_regular(active, "active loader")
        if locked_active_data != active_data or _sha256_bytes(locked_active_data) != active_hash:
            raise RuntimeError("active loader changed while acquiring the ESP lock")

        initial_nvram = _snapshot(backend)
        _validate_boot_references(initial_nvram)
        tree_hashes = {
            "EFI": _tree_hash(resolved_esp / "EFI"),
            "EFI/refind": _tree_hash(resolved_esp / "EFI" / "refind"),
        }
        transaction = _new_transaction(backup_root, require_root=require_root)
        try:
            active_backup_dir = transaction / "active"
            active_backup_dir.mkdir(mode=0o700)
            os.chmod(active_backup_dir, 0o700)
            active_backup = active_backup_dir / "refind_x64.efi"
            _write_file_exclusive(active_backup, active_data)
            os.chmod(active_backup, 0o600)
            if _read_regular(active_backup, "backed-up active loader")[0] != active_data:
                raise RuntimeError("active loader backup verification failed")
            _fsync_directory(active_backup_dir)

            manifest: dict[str, object] = {
                "format": _FORMAT,
                "schema": _SCHEMA,
                "state": "backup_ready",
                "esp": str(resolved_esp),
                "esp_identity": identity,
                "lock_key": lock_key,
                "active": {
                    "path": _ACTIVE_RELATIVE,
                    "sha256": active_hash,
                    "size": len(active_data),
                },
                "candidate": {
                    "path": _CANDIDATE_RELATIVE,
                    "sha256": candidate_hash,
                    "size": len(candidate_data),
                },
                "tree_hashes": tree_hashes,
                "nvram_initial": _snapshot_json(initial_nvram),
                "candidate_bootnum": None,
                "candidate_entry_raw": None,
                "boot_next_owned": False,
                "boot_next_raw": None,
            }
            _write_manifest(transaction, manifest)

            _write_intent(
                transaction,
                "publish_candidate",
                active_sha256=active_hash,
                candidate_sha256=candidate_hash,
                temporary_name=_stage_temporary_name(lock_key),
            )
            _publish_candidate(
                candidate_data,
                target,
                target.parent / _stage_temporary_name(lock_key),
                candidate_hash,
                verifier,
            )
            _backend_syncfs(backend, resolved_esp)
            manifest["state"] = "candidate_published"
            _write_manifest(transaction, manifest)
            _clear_intent(transaction)

            before_entry = _snapshot(backend)
            if before_entry.raw_boot_order != initial_nvram.raw_boot_order:
                raise RuntimeError("BootOrder changed before alternate entry creation")
            if (
                before_entry.entries != initial_nvram.entries
                or before_entry.raw_boot_next != initial_nvram.raw_boot_next
            ):
                raise RuntimeError("NVRAM changed before alternate entry creation")
            before_entry_json = _snapshot_json(before_entry)
            _write_intent(
                transaction,
                "create_entry",
                before=before_entry_json,
            )
            creator = getattr(backend, "create_only_entry", None)
            if creator is None:
                raise RuntimeError("EFI backend cannot create an alternate boot entry")
            creator(identity, _EFI_CANDIDATE_PATH)
            after_entry = _snapshot(backend)
            observed = _observe_created_entry(
                manifest,
                after_entry,
                backend,
                identity,
                baseline=before_entry_json,
                transaction=transaction,
            )
            if observed is None:
                raise RuntimeError(
                    "alternate entry creation did not create exactly one Boot entry"
                )
            bootnum, entry_raw = observed

            manifest["candidate_bootnum"] = bootnum
            manifest["candidate_entry_raw"] = entry_raw.hex()
            manifest["state"] = "staged"
            _write_manifest(transaction, manifest)
            _clear_intent(transaction)
            return transaction
        except BaseException:
            raise


def set_candidate_boot_next(
    transaction: Path,
    backend: object | None = None,
    *,
    lock_root: Path | None = None,
    require_root: bool = True,
) -> None:
    """Select the owned candidate entry for the next boot only."""

    if backend is None:
        backend = _RealBackend()
    resolved_transaction = _transaction_path(transaction, require_root=require_root)
    preliminary = _load_manifest(resolved_transaction)
    esp_value = preliminary.get("esp")
    if not isinstance(esp_value, str):
        raise RuntimeError("loader transaction ESP path is invalid")
    selected_lock_root = lock_root or _default_lock_root(
        require_root, resolved_transaction.parent
    )
    lock_key = preliminary.get("lock_key")
    if not isinstance(lock_key, str):
        raise RuntimeError("loader transaction lock identity is invalid")

    with _esp_lock(selected_lock_root, lock_key, require_root=require_root):
        transaction_path, resolved_esp, manifest, identity = _bind_transaction(
            resolved_transaction,
            Path(esp_value),
            backend,
            require_root=require_root,
        )
        before = _snapshot(backend)
        bootnum = _validate_nvram_ownership(
            manifest,
            before,
            backend,
            identity,
            validate_boot_next=False,
        )
        active_hash = _slot_hash(resolved_esp / _ACTIVE_RELATIVE)
        candidate_hash = _slot_hash(resolved_esp / _CANDIDATE_RELATIVE)
        if (active_hash, candidate_hash) != (
            _manifest_hash(manifest, "active"),
            _manifest_hash(manifest, "candidate"),
        ):
            raise RuntimeError("candidate BootNext requires staged loader slots")
        pending = _load_intent(transaction_path)
        if pending is not None and pending.get("operation") != "set_boot_next":
            raise RuntimeError(
                f"loader transaction has pending {pending.get('operation')} intent"
            )
        expected_raw_boot_next = _expected_boot_next_raw(bootnum)
        if pending is not None and (
            pending.get("candidate_bootnum") != bootnum
            or pending.get("raw_boot_order") != before.raw_boot_order.hex()
            or pending.get("expected_raw_boot_next")
            != expected_raw_boot_next.hex()
        ):
            raise RuntimeError("pending BootNext intent is invalid")
        if pending is not None and before.boot_next == bootnum:
            if before.raw_boot_next != expected_raw_boot_next:
                raise RuntimeError("foreign BootNext with candidate number is present")
            if before.raw_boot_next is None:
                raise RuntimeError("owned BootNext raw value is missing")
            manifest["state"] = "armed"
            manifest["boot_next_owned"] = True
            manifest["boot_next_raw"] = before.raw_boot_next.hex()
            _write_manifest(transaction_path, manifest)
            _clear_intent(transaction_path)
            return
        if before.boot_next is not None:
            raise RuntimeError("BootNext already exists")

        if pending is None:
            _write_intent(
                transaction_path,
                "set_boot_next",
                candidate_bootnum=bootnum,
                raw_boot_order=before.raw_boot_order.hex(),
                expected_raw_boot_next=expected_raw_boot_next.hex(),
            )
        mutation_error: BaseException | None = None
        try:
            setter = getattr(backend, "set_boot_next", None)
            if setter is None:
                raise RuntimeError("EFI backend cannot set BootNext")
            setter(bootnum)
        except BaseException as error:
            mutation_error = error

        try:
            after = _snapshot(backend)
        except BaseException:
            if isinstance(mutation_error, FileExistsError):
                _clear_intent(transaction_path)
            raise
        definite_create_conflict = isinstance(mutation_error, FileExistsError)
        if after.raw_boot_order != before.raw_boot_order:
            if definite_create_conflict:
                _clear_intent(transaction_path)
            raise RuntimeError("BootOrder changed while setting BootNext") from mutation_error
        if definite_create_conflict:
            _clear_intent(transaction_path)
            raise mutation_error
        if after.boot_next != bootnum:
            if mutation_error is not None:
                raise mutation_error
            raise RuntimeError("BootNext read-back does not select the candidate")
        if after.raw_boot_next is None:
            raise RuntimeError("BootNext read-back raw value is missing")
        owned_view = dict(manifest)
        owned_view["boot_next_owned"] = True
        owned_view["boot_next_raw"] = after.raw_boot_next.hex()
        _validate_nvram_ownership(owned_view, after, backend, identity)
        manifest["state"] = "armed"
        manifest["boot_next_owned"] = True
        manifest["boot_next_raw"] = after.raw_boot_next.hex()
        _write_manifest(transaction_path, manifest)
        _clear_intent(transaction_path)


def loader_status(
    transaction: Path,
    esp: Path,
    *,
    backend: object | None = None,
    require_root: bool = True,
    lock_root: Path | None = None,
) -> LoaderStatus:
    """Return loader state derived from live slot hashes and raw EFI variables."""

    if backend is None:
        backend = _RealBackend()
    transaction_path = _transaction_path(transaction, require_root=require_root)
    preliminary = _load_manifest(transaction_path)
    lock_key = preliminary.get("lock_key")
    if not isinstance(lock_key, str):
        raise RuntimeError("loader transaction lock identity is invalid")
    selected_lock_root = lock_root or _default_lock_root(
        require_root, transaction_path.parent
    )
    with _esp_lock(selected_lock_root, lock_key, require_root=require_root):
        _, resolved_esp, manifest, identity = _bind_transaction(
            transaction_path,
            esp,
            backend,
            require_root=require_root,
        )
        intent = _load_intent(transaction_path)
        snapshot = _snapshot(backend)
        _require_backup(transaction_path, _manifest_hash(manifest, "active"))
        if snapshot.raw_boot_order != _initial_raw_boot_order(manifest):
            raise RuntimeError("BootOrder changed from the loader transaction snapshot")
        _validate_initial_boot_entries(manifest, snapshot)
        bootnum = _manifest_bootnum(manifest)
        active_hash = _slot_hash(resolved_esp / _ACTIVE_RELATIVE)
        candidate_hash = _slot_hash(resolved_esp / _CANDIDATE_RELATIVE)
        if intent is not None:
            return LoaderStatus(
                "recovery_required",
                active_hash,
                candidate_hash,
                bootnum,
                snapshot.boot_current,
                snapshot.boot_order,
            )
        if manifest.get("state") == "rolled_back":
            if snapshot.entries.get(bootnum) is not None:
                raise RuntimeError("candidate Boot entry remains after rollback")
            if snapshot.raw_boot_next != _initial_raw_boot_next(manifest):
                raise RuntimeError("BootNext differs from the pre-stage snapshot")
            if active_hash != _manifest_hash(manifest, "active") or candidate_hash != "":
                raise RuntimeError("rolled-back loader slots do not match the transaction")
            return LoaderStatus(
                "rolled_back",
                active_hash,
                candidate_hash,
                bootnum,
                snapshot.boot_current,
                snapshot.boot_order,
            )
        _validate_nvram_ownership(manifest, snapshot, backend, identity)
        state = _observed_state(manifest, snapshot, active_hash, candidate_hash)
        return LoaderStatus(
            state,
            active_hash,
            candidate_hash,
            bootnum,
            snapshot.boot_current,
            snapshot.boot_order,
        )


def _load_intent(transaction: Path) -> dict[str, object] | None:
    path = transaction / "intent.json"
    if not path.exists():
        return None
    intent = _load_json(path, "loader transaction intent")
    if intent.get("format") != _FORMAT or not isinstance(intent.get("operation"), str):
        raise RuntimeError("loader transaction intent has an invalid schema")
    return intent


def _slot_pair(
    resolved_esp: Path, manifest: Mapping[str, object]
) -> tuple[str, str, str, str]:
    active_hash = _slot_hash(resolved_esp / _ACTIVE_RELATIVE)
    candidate_hash = _slot_hash(resolved_esp / _CANDIDATE_RELATIVE)
    old_hash = _manifest_hash(manifest, "active")
    new_hash = _manifest_hash(manifest, "candidate")
    return active_hash, candidate_hash, old_hash, new_hash


def _require_backup(transaction: Path, expected_hash: str) -> bytes:
    backup = transaction / "active" / "refind_x64.efi"
    data, _ = _read_regular(backup, "backed-up active loader")
    if _sha256_bytes(data) != expected_hash:
        raise RuntimeError("backed-up active loader hash mismatch")
    return data


def _backend_syncfs(backend: object, esp: Path) -> None:
    syncer = getattr(backend, "syncfs", None)
    if syncer is None:
        raise RuntimeError("EFI backend cannot sync the ESP filesystem")
    syncer(esp)


def _backend_exchange(backend: object, active: Path, candidate: Path) -> BaseException | None:
    exchange = getattr(backend, "exchange", None)
    if exchange is None:
        return RuntimeError("EFI backend cannot exchange loader slots")
    try:
        exchange(active, candidate)
    except BaseException as error:
        return error
    return None


def _finish_promotion(
    transaction: Path,
    resolved_esp: Path,
    manifest: dict[str, object],
    identity: Mapping[str, object],
    backend: object,
    verifier: Callable[[Path], None],
) -> None:
    active = resolved_esp / _ACTIVE_RELATIVE
    candidate = resolved_esp / _CANDIDATE_RELATIVE
    old_hash = _manifest_hash(manifest, "active")
    new_hash = _manifest_hash(manifest, "candidate")
    _backend_syncfs(backend, resolved_esp)
    if (_slot_hash(active), _slot_hash(candidate)) != (new_hash, old_hash):
        raise RuntimeError("post-exchange loader slot hash verification failed")
    verifier(active)
    if (_slot_hash(active), _slot_hash(candidate)) != (new_hash, old_hash):
        raise RuntimeError("loader slots changed during post-exchange verification")
    after = _snapshot(backend)
    _validate_nvram_ownership(manifest, after, backend, identity)
    manifest["state"] = "promoted"
    manifest["boot_next_owned"] = False
    manifest["boot_next_raw"] = None
    _write_manifest(transaction, manifest)
    _clear_intent(transaction)


def _reverse_failed_promotion(
    transaction: Path,
    resolved_esp: Path,
    manifest: dict[str, object],
    backend: object,
    verification_error: BaseException,
) -> None:
    active = resolved_esp / _ACTIVE_RELATIVE
    candidate = resolved_esp / _CANDIDATE_RELATIVE
    old_hash = _manifest_hash(manifest, "active")
    new_hash = _manifest_hash(manifest, "candidate")
    prior_intent = _load_intent(transaction)
    authorization = {
        key: prior_intent[key]
        for key in ("authorized_bootnum", "authorized_boot_current_raw")
        if prior_intent is not None and key in prior_intent
    }
    _write_intent(
        transaction,
        "promote_revert",
        old_sha256=old_hash,
        candidate_sha256=new_hash,
        **authorization,
    )
    reverse_error = _backend_exchange(backend, active, candidate)
    pair = (_slot_hash(active), _slot_hash(candidate))
    if pair == (old_hash, new_hash):
        _backend_syncfs(backend, resolved_esp)
        if _slot_hash(active) != old_hash:
            raise RuntimeError("reversed active loader hash verification failed") from verification_error
        _require_backup(transaction, old_hash)
        manifest["state"] = "promotion_failed"
        manifest["boot_next_owned"] = False
        manifest["boot_next_raw"] = None
        _write_manifest(transaction, manifest)
        _clear_intent(transaction)
        raise verification_error
    if pair == (new_hash, old_hash):
        failure = RuntimeError("reverse exchange failed; promotion recovery is pending")
        if reverse_error is not None:
            failure.add_note(f"exchange error: {reverse_error}")
        raise failure from verification_error
    raise RuntimeError("reverse exchange left ambiguous loader slot hashes") from verification_error


def _validate_promotion_authorization(
    intent: Mapping[str, object], bootnum: str
) -> None:
    if intent.get("authorized_bootnum") != bootnum:
        raise RuntimeError("promotion intent has invalid BootCurrent authorization")
    raw_value = intent.get("authorized_boot_current_raw")
    if not isinstance(raw_value, str):
        raise RuntimeError("promotion intent has invalid BootCurrent authorization")
    try:
        raw = bytes.fromhex(raw_value)
    except ValueError as error:
        raise RuntimeError("promotion intent has invalid BootCurrent authorization") from error
    if len(raw) < 2 or int.from_bytes(raw[-2:], "little") != int(bootnum, 16):
        raise RuntimeError("promotion intent has invalid BootCurrent authorization")


def promote_loader(
    transaction: Path,
    esp: Path,
    *,
    backend: object | None = None,
    boot_current: str | None = None,
    verifier: Callable[[Path], None] | None = None,
    require_root: bool = True,
    lock_root: Path | None = None,
) -> None:
    """Promote a candidate after firmware booted its alternate entry."""

    if backend is None:
        backend = _RealBackend()
    if verifier is None:
        verifier = _default_verifier
    transaction_path = _transaction_path(transaction, require_root=require_root)
    preliminary = _load_manifest(transaction_path)
    lock_key = preliminary.get("lock_key")
    if not isinstance(lock_key, str):
        raise RuntimeError("loader transaction lock identity is invalid")
    selected_lock_root = lock_root or _default_lock_root(
        require_root, transaction_path.parent
    )
    with _esp_lock(selected_lock_root, lock_key, require_root=require_root):
        transaction_path, resolved_esp, manifest, identity = _bind_transaction(
            transaction_path,
            esp,
            backend,
            require_root=require_root,
        )
        snapshot = _snapshot(backend)
        bootnum = _validate_nvram_ownership(manifest, snapshot, backend, identity)
        intent = _load_intent(transaction_path)
        operation = intent.get("operation") if intent is not None else None
        if operation not in {None, "promote", "promote_revert"}:
            raise RuntimeError(f"loader transaction has pending {operation} intent")
        if boot_current is not None and boot_current.upper() != snapshot.boot_current:
            raise RuntimeError("boot_current assertion does not match live BootCurrent")
        if operation is None:
            if snapshot.boot_current != bootnum:
                raise RuntimeError("BootCurrent is not candidate")
            if snapshot.raw_boot_next != _initial_raw_boot_next(manifest):
                raise RuntimeError("BootNext still exists after candidate boot")
        else:
            assert intent is not None
            _validate_promotion_authorization(intent, bootnum)

        active = resolved_esp / _ACTIVE_RELATIVE
        candidate = resolved_esp / _CANDIDATE_RELATIVE
        active_hash, candidate_hash, old_hash, new_hash = _slot_pair(
            resolved_esp, manifest
        )
        _require_backup(transaction_path, old_hash)

        if operation == "promote_revert":
            if (active_hash, candidate_hash) == (old_hash, new_hash):
                _backend_syncfs(backend, resolved_esp)
                if _slot_hash(active) != old_hash:
                    raise RuntimeError("reverted active loader hash verification failed")
                _require_backup(transaction_path, old_hash)
                manifest["state"] = "promotion_failed"
                manifest["boot_next_owned"] = False
                manifest["boot_next_raw"] = None
                _write_manifest(transaction_path, manifest)
                _clear_intent(transaction_path)
                raise RuntimeError("previous promotion verification failed and was reverted")
            if (active_hash, candidate_hash) != (new_hash, old_hash):
                raise RuntimeError("promotion reversal has ambiguous loader slot hashes")
            _reverse_failed_promotion(
                transaction_path,
                resolved_esp,
                manifest,
                backend,
                RuntimeError("previous promotion verification failed"),
            )

        if (active_hash, candidate_hash) == (new_hash, old_hash):
            try:
                _finish_promotion(
                    transaction_path,
                    resolved_esp,
                    manifest,
                    identity,
                    backend,
                    verifier,
                )
            except BaseException as error:
                _reverse_failed_promotion(
                    transaction_path,
                    resolved_esp,
                    manifest,
                    backend,
                    error,
                )
            return
        if (active_hash, candidate_hash) != (old_hash, new_hash):
            raise RuntimeError("loader slot hashes are ambiguous before promotion")

        if operation is None:
            _write_intent(
                transaction_path,
                "promote",
                old_sha256=old_hash,
                candidate_sha256=new_hash,
                authorized_bootnum=bootnum,
                authorized_boot_current_raw=snapshot.raw_boot_current.hex(),
            )
        exchange_error = _backend_exchange(backend, active, candidate)
        pair = (_slot_hash(active), _slot_hash(candidate))
        if pair == (old_hash, new_hash):
            if exchange_error is not None:
                raise exchange_error
            raise RuntimeError("exchange command did not exchange loader slots")
        if pair != (new_hash, old_hash):
            raise RuntimeError("exchange left ambiguous loader slot hashes") from exchange_error
        try:
            _finish_promotion(
                transaction_path,
                resolved_esp,
                manifest,
                identity,
                backend,
                verifier,
            )
        except BaseException as error:
            _reverse_failed_promotion(
                transaction_path,
                resolved_esp,
                manifest,
                backend,
                error,
            )


def _initial_boot_next(manifest: Mapping[str, object]) -> str | None:
    initial = _manifest_mapping(manifest, "nvram_initial", "initial NVRAM snapshot")
    value = initial.get("boot_next")
    if value is not None and (not isinstance(value, str) or not _valid_bootnum(value)):
        raise RuntimeError("loader transaction initial BootNext is invalid")
    return value.upper() if isinstance(value, str) else None


def _initial_raw_boot_next(manifest: Mapping[str, object]) -> bytes | None:
    initial = _manifest_mapping(manifest, "nvram_initial", "initial NVRAM snapshot")
    value = initial.get("raw_boot_next")
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError("loader transaction initial raw BootNext is invalid")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise RuntimeError("loader transaction initial raw BootNext is invalid") from error


def _validate_boot_next_state(
    manifest: Mapping[str, object], snapshot: _Snapshot, bootnum: str
) -> None:
    if manifest.get("boot_next_owned") is True:
        raw_value = manifest.get("boot_next_raw")
        try:
            owned_raw = bytes.fromhex(raw_value) if isinstance(raw_value, str) else None
        except ValueError as error:
            raise RuntimeError("owned raw BootNext is invalid") from error
        if snapshot.raw_boot_next == owned_raw:
            return
        if snapshot.boot_current == bootnum and snapshot.raw_boot_next is None:
            return
        if _candidate_boot_fell_back(manifest, snapshot, bootnum):
            return
        raise RuntimeError("owned raw BootNext changed")
    if snapshot.raw_boot_next != _initial_raw_boot_next(manifest):
        raise RuntimeError("initial raw BootNext changed")


def _restore_active_from_backup(
    transaction: Path,
    active: Path,
    temporary: Path,
    expected_old_hash: str,
    allowed_current: set[str],
) -> None:
    backup_data = _require_backup(transaction, expected_old_hash)
    current_hash = _slot_hash(active)
    if current_hash not in allowed_current:
        raise RuntimeError("foreign active loader replacement preserved")
    if temporary.parent != active.parent:
        raise RuntimeError("rollback temporary must share the active directory")
    created = False
    try:
        if temporary.exists() or temporary.is_symlink():
            existing, _ = _read_regular(temporary, "rollback active temporary")
            if existing != backup_data or _sha256_bytes(existing) != expected_old_hash:
                raise RuntimeError("foreign rollback active temporary preserved")
        else:
            _write_file_exclusive(temporary, backup_data)
            created = True
        if _sha256(temporary) != expected_old_hash:
            raise RuntimeError("rollback backup read-back hash mismatch")
        if _slot_hash(active) != current_hash:
            raise RuntimeError("active loader changed during rollback restoration")
        os.replace(temporary, active)
        _fsync_directory(active.parent)
        if _sha256(active) != expected_old_hash:
            raise RuntimeError("restored active loader hash mismatch")
    finally:
        if created:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _remove_owned_candidate(
    path: Path, quarantine: Path, allowed_hashes: set[str]
) -> bool:
    if quarantine.parent != path.parent:
        raise RuntimeError("candidate quarantine must share the candidate directory")
    current_hash = _slot_hash(path)
    if quarantine.exists() or quarantine.is_symlink():
        if current_hash != "":
            raise RuntimeError("candidate and recorded quarantine both exist")
        quarantined_data, _ = _read_regular(
            quarantine, "recorded candidate quarantine"
        )
        if _sha256_bytes(quarantined_data) not in allowed_hashes:
            raise RuntimeError("foreign candidate quarantine preserved")
        quarantine.unlink()
        _fsync_directory(path.parent)
        return True
    if current_hash == "":
        return True
    if current_hash not in allowed_hashes:
        return False
    _data, before = _read_regular(path, "owned candidate loader")
    os.replace(path, quarantine)
    try:
        _quarantined_data, after = _read_regular(quarantine, "quarantined candidate loader")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            if not path.exists():
                os.replace(quarantine, path)
            raise RuntimeError("candidate loader changed during owned cleanup")
        if _sha256_bytes(_quarantined_data) not in allowed_hashes:
            if not path.exists():
                os.replace(quarantine, path)
            raise RuntimeError("candidate loader changed during owned cleanup")
        quarantine.unlink()
        _fsync_directory(path.parent)
        return True
    except BaseException:
        if quarantine.exists() and not path.exists():
            os.replace(quarantine, path)
            _fsync_directory(path.parent)
        raise


def _preflight_rollback_ownership(
    manifest: Mapping[str, object],
    backend: object,
    candidate_hash: str,
    pending_operation: object,
) -> None:
    snapshot = _snapshot(backend)
    if snapshot.raw_boot_order != _initial_raw_boot_order(manifest):
        raise RuntimeError("BootOrder changed before rollback")
    _validate_initial_boot_entries(manifest, snapshot)
    bootnum = _manifest_bootnum(manifest)
    expected_entry = _manifest_hex(manifest, "candidate_entry_raw")
    current_entry = snapshot.entries.get(bootnum)
    nvram_conflicts = current_entry not in {None, expected_entry}

    initial_next = _initial_boot_next(manifest)
    initial_raw_next = _initial_raw_boot_next(manifest)
    if snapshot.boot_next == bootnum and initial_next is None:
        raw_value = manifest.get("boot_next_raw")
        try:
            expected_raw_next = (
                bytes.fromhex(raw_value) if isinstance(raw_value, str) else None
            )
        except ValueError:
            expected_raw_next = None
        owns_live_value = (
            manifest.get("boot_next_owned") is True
            and manifest.get("state") == "armed"
            and snapshot.boot_current != bootnum
            and pending_operation not in {"promote", "promote_revert"}
            and snapshot.raw_boot_next == expected_raw_next
        )
        if not owns_live_value:
            nvram_conflicts = True
    elif snapshot.raw_boot_next != initial_raw_next:
        nvram_conflicts = True

    old_hash = _manifest_hash(manifest, "active")
    new_hash = _manifest_hash(manifest, "candidate")
    if candidate_hash not in {"", old_hash, new_hash}:
        raise RuntimeError("foreign candidate replacement preserved during rollback")
    if nvram_conflicts:
        raise RuntimeError("foreign NVRAM replacement preserved during rollback")


def _validate_rollback_artifacts(
    candidate: Path,
    quarantine: Path,
    restore_temporary: Path,
    transaction: Path,
    old_hash: str,
    new_hash: str,
) -> None:
    candidate_hash = _slot_hash(candidate)
    if quarantine.exists() or quarantine.is_symlink():
        if candidate_hash != "":
            raise RuntimeError("candidate and recorded quarantine both exist")
        quarantined, _ = _read_regular(
            quarantine, "recorded candidate quarantine"
        )
        if _sha256_bytes(quarantined) not in {old_hash, new_hash}:
            raise RuntimeError("foreign candidate quarantine preserved")
    if restore_temporary.exists() or restore_temporary.is_symlink():
        temporary_data, _ = _read_regular(
            restore_temporary, "recorded rollback active temporary"
        )
        backup_data = _require_backup(transaction, old_hash)
        if temporary_data != backup_data or _sha256_bytes(temporary_data) != old_hash:
            raise RuntimeError("foreign rollback active temporary preserved")


def _validate_projected_rollback_tree(
    resolved_esp: Path,
    manifest: Mapping[str, object],
    backup_data: bytes,
    quarantine: Path,
    restore_temporary: Path,
) -> None:
    tree_hashes = _manifest_mapping(manifest, "tree_hashes", "tree hashes")
    efi_active = _ACTIVE_RELATIVE.removeprefix("EFI/")
    efi_candidate = _CANDIDATE_RELATIVE.removeprefix("EFI/")
    efi_absent = {
        efi_candidate,
        f"refind/{quarantine.name}",
        f"refind/{restore_temporary.name}",
    }
    refind_absent = {
        Path(_CANDIDATE_RELATIVE).name,
        quarantine.name,
        restore_temporary.name,
    }
    if _tree_hash(
        resolved_esp / "EFI",
        replacements={efi_active: backup_data},
        absent=efi_absent,
    ) != tree_hashes.get("EFI") or _tree_hash(
        resolved_esp / "EFI" / "refind",
        replacements={Path(_ACTIVE_RELATIVE).name: backup_data},
        absent=refind_absent,
    ) != tree_hashes.get("EFI/refind"):
        raise RuntimeError("unrelated ESP drift before rollback")


def _cleanup_owned_nvram(
    manifest: Mapping[str, object],
    backend: object,
) -> list[str]:
    conflicts: list[str] = []
    expected_order = _initial_raw_boot_order(manifest)
    bootnum = _manifest_bootnum(manifest)
    expected_entry = _manifest_hex(manifest, "candidate_entry_raw")
    initial_next = _initial_boot_next(manifest)
    initial_raw_next = _initial_raw_boot_next(manifest)
    snapshot = _snapshot(backend)
    if snapshot.raw_boot_order != expected_order:
        raise RuntimeError("BootOrder changed before rollback cleanup")
    _validate_initial_boot_entries(manifest, snapshot)

    raw_value = manifest.get("boot_next_raw")
    try:
        expected_raw_next = bytes.fromhex(raw_value) if isinstance(raw_value, str) else None
    except ValueError:
        expected_raw_next = None
    if (
        snapshot.boot_next == bootnum
        and initial_next is None
        and manifest.get("boot_next_owned") is True
        and manifest.get("state") == "armed"
        and snapshot.boot_current != bootnum
        and snapshot.raw_boot_next == expected_raw_next
    ):
        clearer = getattr(backend, "clear_boot_next", None)
        if clearer is None:
            raise RuntimeError("EFI backend cannot clear owned BootNext")
        mutation_error: BaseException | None = None
        try:
            clearer(bootnum, expected_raw_next)
        except BaseException as error:
            mutation_error = error
        snapshot = _snapshot(backend)
        if snapshot.raw_boot_order != expected_order:
            raise RuntimeError("BootOrder changed while clearing owned BootNext") from mutation_error
        _validate_initial_boot_entries(manifest, snapshot)
        if snapshot.boot_next is not None:
            if mutation_error is not None:
                raise mutation_error
            raise RuntimeError("owned BootNext was not cleared")
    elif snapshot.raw_boot_next != initial_raw_next:
        conflicts.append("foreign BootNext")

    current_entry = snapshot.entries.get(bootnum)
    if current_entry == expected_entry:
        deleter = getattr(backend, "delete_entry", None)
        if deleter is None:
            raise RuntimeError("EFI backend cannot delete owned Boot entry")
        mutation_error = None
        try:
            deleter(bootnum, expected_entry)
        except BaseException as error:
            mutation_error = error
        snapshot = _snapshot(backend)
        if snapshot.raw_boot_order != expected_order:
            raise RuntimeError("BootOrder changed while deleting owned Boot entry") from mutation_error
        _validate_initial_boot_entries(manifest, snapshot)
        if bootnum in snapshot.entries:
            if mutation_error is not None:
                raise mutation_error
            raise RuntimeError("owned candidate Boot entry was not deleted")
    elif current_entry is not None:
        conflicts.append("foreign Boot entry")
    return conflicts


def rollback_loader(
    transaction: Path,
    esp: Path,
    *,
    backend: object | None = None,
    require_root: bool = True,
    lock_root: Path | None = None,
) -> None:
    """Restore the recorded active loader and remove only transaction-owned state."""

    if backend is None:
        backend = _RealBackend()
    transaction_path = _transaction_path(transaction, require_root=require_root)
    preliminary = _load_manifest(transaction_path)
    lock_key = preliminary.get("lock_key")
    if not isinstance(lock_key, str):
        raise RuntimeError("loader transaction lock identity is invalid")
    selected_lock_root = lock_root or _default_lock_root(
        require_root, transaction_path.parent
    )
    with _esp_lock(selected_lock_root, lock_key, require_root=require_root):
        transaction_path, resolved_esp, manifest, _identity = _bind_transaction(
            transaction_path,
            esp,
            backend,
            require_root=require_root,
        )
        snapshot = _snapshot(backend)
        if snapshot.raw_boot_order != _initial_raw_boot_order(manifest):
            raise RuntimeError("BootOrder changed before loader rollback")
        active = resolved_esp / _ACTIVE_RELATIVE
        candidate = resolved_esp / _CANDIDATE_RELATIVE
        active_hash, candidate_hash, old_hash, new_hash = _slot_pair(
            resolved_esp, manifest
        )
        backup_data = _require_backup(transaction_path, old_hash)
        if active_hash not in {"", old_hash, new_hash}:
            raise RuntimeError("foreign active loader replacement preserved")
        intent = _load_intent(transaction_path)
        pending_operation = intent.get("operation") if intent is not None else None
        quarantine_name, restore_name = _rollback_artifact_names(lock_key)
        if pending_operation == "rollback":
            if (
                intent is None
                or intent.get("candidate_quarantine") != quarantine_name
                or intent.get("restore_temporary") != restore_name
            ):
                raise RuntimeError("rollback intent artifact names are invalid")
        quarantine = candidate.parent / quarantine_name
        restore_temporary = active.parent / restore_name
        if (
            quarantine.exists()
            or quarantine.is_symlink()
            or restore_temporary.exists()
            or restore_temporary.is_symlink()
        ) and pending_operation != "rollback":
            raise RuntimeError("rollback artifacts require matching rollback intent")
        _validate_rollback_artifacts(
            candidate,
            quarantine,
            restore_temporary,
            transaction_path,
            old_hash,
            new_hash,
        )
        _preflight_rollback_ownership(
            manifest, backend, candidate_hash, pending_operation
        )
        _validate_projected_rollback_tree(
            resolved_esp,
            manifest,
            backup_data,
            quarantine,
            restore_temporary,
        )
        recovering_committed_rollback = (
            intent is not None and intent.get("operation") == "rollback"
        )
        if intent is None or intent.get("operation") != "rollback":
            _write_intent(
                transaction_path,
                "rollback",
                old_sha256=old_hash,
                candidate_sha256=new_hash,
                candidate_quarantine=quarantine_name,
                restore_temporary=restore_name,
            )

        mutated_slots = False
        if (active_hash, candidate_hash) == (new_hash, old_hash):
            exchange_error = _backend_exchange(backend, active, candidate)
            active_hash, candidate_hash, _, _ = _slot_pair(resolved_esp, manifest)
            if (active_hash, candidate_hash) == (new_hash, old_hash):
                if exchange_error is not None:
                    raise exchange_error
                raise RuntimeError("rollback exchange did not restore the old loader")
            if (active_hash, candidate_hash) != (old_hash, new_hash):
                raise RuntimeError("rollback exchange left ambiguous loader slot hashes")
            mutated_slots = True
        elif active_hash in {"", new_hash}:
            _restore_active_from_backup(
                transaction_path,
                active,
                restore_temporary,
                old_hash,
                {active_hash},
            )
            active_hash = old_hash
            mutated_slots = True
        elif active_hash != old_hash:
            raise RuntimeError("loader rollback state is ambiguous")

        if mutated_slots or recovering_committed_rollback:
            _backend_syncfs(backend, resolved_esp)
        restored_data, _ = _read_regular(active, "restored active loader")
        backup_data = _require_backup(transaction_path, old_hash)
        if restored_data != backup_data or _sha256_bytes(restored_data) != old_hash:
            raise RuntimeError("rollback did not restore the byte-exact active loader")

        nvram_conflicts = _cleanup_owned_nvram(manifest, backend)
        candidate_owned = _remove_owned_candidate(
            candidate, quarantine, {old_hash, new_hash}
        )
        if not candidate_owned:
            manifest["state"] = "rollback_partial"
            manifest["rollback_conflicts"] = [
                *nvram_conflicts,
                "foreign candidate replacement",
            ]
            _write_manifest(transaction_path, manifest)
            raise RuntimeError("foreign candidate replacement preserved during rollback")
        if nvram_conflicts:
            manifest["state"] = "rollback_partial"
            manifest["rollback_conflicts"] = nvram_conflicts
            _write_manifest(transaction_path, manifest)
            raise RuntimeError("foreign NVRAM replacement preserved during rollback")

        tree_hashes = _manifest_mapping(manifest, "tree_hashes", "tree hashes")
        if _tree_hash(resolved_esp / "EFI") != tree_hashes.get("EFI") or _tree_hash(
            resolved_esp / "EFI" / "refind"
        ) != tree_hashes.get("EFI/refind"):
            raise RuntimeError("rollback changed an unrelated ESP file")
        manifest["state"] = "rolled_back"
        manifest["boot_next_owned"] = False
        manifest["boot_next_raw"] = None
        manifest["rollback_conflicts"] = []
        _write_manifest(transaction_path, manifest)
        _clear_intent(transaction_path)


def _default_verifier(path: Path) -> None:
    from refind_forest.loader.verify import verify_pe, verify_signed

    expected_sbat = (
        Path(__file__).resolve().parents[3]
        / "assets"
        / "loader"
        / "refind-forest-sbat.csv"
    ).read_bytes()
    verify_pe(path, expected_sbat)
    verify_signed(path, Path("/etc/refind.d/keys/refind_local.crt"))


_EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
_EFIBOOTMGR = "/usr/bin/efibootmgr"
_MV = "/usr/bin/mv"
_PHYSICAL_IDENTITY_FIELDS = frozenset(
    {
        "disk",
        "disk_major_minor",
        "partition_number",
        "partition_guid",
        "disk_guid",
        "partition_start_lba",
        "partition_size_lba",
        "logical_sector_size",
        "gpt_sha256",
    }
)


def _sync_filesystem(descriptor: int) -> None:
    native_syncfs = getattr(os, "syncfs", None)
    if native_syncfs is not None:
        native_syncfs(descriptor)
        return

    libc = ctypes.CDLL(None, use_errno=True)
    libc_syncfs = libc.syncfs
    libc_syncfs.argtypes = (ctypes.c_int,)
    libc_syncfs.restype = ctypes.c_int
    ctypes.set_errno(0)
    if libc_syncfs(descriptor) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _pread_exact(descriptor: int, offset: int, size: int, description: str) -> bytes:
    data = os.pread(descriptor, size, offset)
    if len(data) != size:
        raise RuntimeError(f"unable to read complete {description}")
    return data


def _gpt_header(
    descriptor: int, lba: int, sector_size: int, description: str
) -> tuple[bytes, int, int, int, int, int, int, bytes]:
    sector = _pread_exact(
        descriptor, lba * sector_size, sector_size, f"{description} GPT header"
    )
    if sector[:8] != b"EFI PART":
        raise RuntimeError(f"{description} GPT signature is invalid")
    if struct.unpack_from("<I", sector, 8)[0] != 0x00010000:
        raise RuntimeError(f"{description} GPT revision is invalid")
    header_size = struct.unpack_from("<I", sector, 12)[0]
    if header_size != 92 or sector[20:24] != b"\0\0\0\0":
        raise RuntimeError(f"{description} GPT header size is invalid")
    header = bytearray(sector[:header_size])
    recorded_crc = struct.unpack_from("<I", header, 16)[0]
    struct.pack_into("<I", header, 16, 0)
    if zlib.crc32(header) & 0xFFFFFFFF != recorded_crc:
        raise RuntimeError(f"{description} GPT header checksum is invalid")
    current_lba, backup_lba = struct.unpack_from("<QQ", sector, 24)
    first_usable, last_usable = struct.unpack_from("<QQ", sector, 40)
    entries_lba = struct.unpack_from("<Q", sector, 72)[0]
    entry_count, entry_size, entries_crc = struct.unpack_from("<III", sector, 80)
    if (
        current_lba != lba
        or not 1 <= entry_count <= 4096
        or not 128 <= entry_size <= 4096
        or entry_size & (entry_size - 1)
    ):
        raise RuntimeError(f"{description} GPT layout is invalid")
    table_size = entry_count * entry_size
    if table_size > 16 * 1024 * 1024:
        raise RuntimeError(f"{description} GPT table is too large")
    table = _pread_exact(
        descriptor,
        entries_lba * sector_size,
        table_size,
        f"{description} GPT partition table",
    )
    if zlib.crc32(table) & 0xFFFFFFFF != entries_crc:
        raise RuntimeError(f"{description} GPT partition-table checksum is invalid")
    return (
        sector[:header_size],
        backup_lba,
        first_usable,
        last_usable,
        entry_count,
        entry_size,
        entries_lba,
        table,
    )


def _protective_mbr(
    descriptor: int, sector_size: int, disk_sectors: int
) -> bytes:
    sector = _pread_exact(descriptor, 0, sector_size, "protective MBR")
    if sector[510:512] != b"\x55\xaa":
        raise RuntimeError("protective MBR signature is invalid")
    entries = [sector[offset : offset + 16] for offset in range(446, 510, 16)]
    if entries[0][4] != 0xEE:
        raise RuntimeError("protective MBR partition type is invalid")
    if entries[0][0] != 0 or any(entry != b"\0" * 16 for entry in entries[1:]):
        raise RuntimeError("protective MBR layout is invalid")
    start_lba, size_lba = struct.unpack_from("<II", entries[0], 8)
    expected_size = min(disk_sectors - 1, 0xFFFFFFFF)
    if start_lba != 1 or size_lba != expected_size:
        raise RuntimeError("protective MBR range is invalid")
    return sector


def _physical_esp_identity(
    source: Any,
    *,
    sysfs_root: Path = Path("/sys/dev/block"),
    dev_root: Path = Path("/dev"),
    require_block: bool = True,
) -> dict[str, object]:
    sysfs = Path(sysfs_root) / source.major_minor
    try:
        partition_sysfs = sysfs.resolve(strict=True)
        partition_number = int((partition_sysfs / "partition").read_text("ascii").strip())
        start_512 = int((partition_sysfs / "start").read_text("ascii").strip())
        size_512 = int((partition_sysfs / "size").read_text("ascii").strip())
        disk_sysfs = partition_sysfs.parent
        disk_major_minor = (disk_sysfs / "dev").read_text("ascii").strip()
        disk_size_512 = int((disk_sysfs / "size").read_text("ascii").strip())
        sector_size = int(
            (disk_sysfs / "queue" / "logical_block_size").read_text("ascii").strip()
        )
    except (OSError, ValueError) as error:
        raise RuntimeError("unable to resolve the ESP partition through sysfs") from error
    if sector_size < 512 or sector_size & (sector_size - 1):
        raise RuntimeError("ESP disk logical sector size is invalid")
    start_bytes = start_512 * 512
    size_bytes = size_512 * 512
    if start_bytes % sector_size or size_bytes % sector_size:
        raise RuntimeError("ESP partition is not aligned to GPT sectors")
    start_lba = start_bytes // sector_size
    size_lba = size_bytes // sector_size
    disk = Path(dev_root) / disk_sysfs.name
    expected_disk_device = os.makedev(*map(int, disk_major_minor.split(":")))
    descriptor = os.open(disk, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if require_block:
            if not stat.S_ISBLK(metadata.st_mode) or metadata.st_rdev != expected_disk_device:
                raise RuntimeError("GPT disk path does not match its sysfs device")
        elif not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("test GPT disk is not a regular file")
        disk_size_bytes = disk_size_512 * 512
        if disk_size_bytes <= 0 or disk_size_bytes % sector_size:
            raise RuntimeError("GPT disk size is invalid")
        disk_sectors = disk_size_bytes // sector_size
        protective_mbr = _protective_mbr(descriptor, sector_size, disk_sectors)
        (
            primary,
            backup_lba,
            first_usable,
            last_usable,
            count,
            entry_size,
            primary_entries_lba,
            primary_table,
        ) = _gpt_header(descriptor, 1, sector_size, "primary")
        if backup_lba != disk_sectors - 1:
            raise RuntimeError("backup GPT header is not at the end of the disk")
        (
            backup,
            primary_lba,
            backup_first_usable,
            backup_last_usable,
            backup_count,
            backup_entry_size,
            backup_entries_lba,
            backup_table,
        ) = _gpt_header(descriptor, backup_lba, sector_size, "backup")
        if primary_lba != 1:
            raise RuntimeError("backup GPT does not point to the primary header")
        if (count, entry_size) != (backup_count, backup_entry_size):
            raise RuntimeError("primary and backup GPT layouts differ")
        table_sectors = (count * entry_size + sector_size - 1) // sector_size
        if (
            primary_entries_lba != 2
            or primary_entries_lba + table_sectors > first_usable
            or backup_entries_lba + table_sectors != backup_lba
            or last_usable >= backup_entries_lba
            or (first_usable, last_usable)
            != (backup_first_usable, backup_last_usable)
            or first_usable > last_usable
        ):
            raise RuntimeError("primary and backup GPT table layout is invalid")
        if primary[56:72] != backup[56:72] or primary_table != backup_table:
            raise RuntimeError("primary and backup GPT contents differ")
        entry_offset = (partition_number - 1) * entry_size
        if entry_offset < 0 or entry_offset + entry_size > len(primary_table):
            raise RuntimeError("ESP partition number is outside the GPT table")
        entry = primary_table[entry_offset : entry_offset + entry_size]
        esp_type = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le
        if entry[:16] != esp_type:
            raise RuntimeError("mounted ESP does not have the EFI System Partition type")
        partition_guid_value = uuid.UUID(bytes_le=entry[16:32])
        if partition_guid_value.int == 0:
            raise RuntimeError("ESP partition GUID is zero")
        partition_guid = str(partition_guid_value)
        entry_start, entry_end = struct.unpack_from("<QQ", entry, 32)
        if not first_usable <= entry_start <= entry_end <= last_usable:
            raise RuntimeError("ESP partition is outside the usable GPT range")
        if entry_start != start_lba or entry_end + 1 - entry_start != size_lba:
            raise RuntimeError("ESP GPT entry does not match the mounted partition")
        disk_guid_value = uuid.UUID(bytes_le=primary[56:72])
        if disk_guid_value.int == 0:
            raise RuntimeError("GPT disk GUID is zero")
        disk_guid = str(disk_guid_value)
        gpt_sha256 = hashlib.sha256(
            protective_mbr + primary + primary_table + backup + backup_table
        ).hexdigest()
    finally:
        os.close(descriptor)
    return {
        "disk": str(disk),
        "disk_major_minor": disk_major_minor,
        "partition_number": partition_number,
        "partition_guid": partition_guid,
        "disk_guid": disk_guid,
        "partition_start_lba": start_lba,
        "partition_size_lba": size_lba,
        "logical_sector_size": sector_size,
        "gpt_sha256": gpt_sha256,
    }


class _RealBackend:
    """Production EFI backend using efivarfs and fixed command argument lists."""

    def __init__(
        self,
        *,
        efivar_root: Path = Path("/sys/firmware/efi/efivars"),
        runner: Callable[..., Any] = subprocess.run,
        physical_identity_reader: Callable[[Any], Mapping[str, object]] = _physical_esp_identity,
    ) -> None:
        self._efivar_root = Path(efivar_root)
        self._runner = runner
        self._physical_identity_reader = physical_identity_reader

    def _variable_path(self, name: str) -> Path:
        return self._efivar_root / f"{name}-{_EFI_GLOBAL_VARIABLE_GUID}"

    def _read_variable(self, name: str, *, required: bool = True) -> bytes | None:
        path = self._variable_path(name)
        try:
            raw, _ = _read_regular(path, f"EFI variable {name}")
        except RuntimeError:
            try:
                os.lstat(path)
            except FileNotFoundError:
                if not required:
                    return None
            raise
        if len(raw) < 4:
            raise RuntimeError(f"EFI variable {name} is missing its attributes")
        expected_attributes = 6 if name == "BootCurrent" else 7
        if int.from_bytes(raw[:4], "little") != expected_attributes:
            raise RuntimeError(f"EFI variable {name} has invalid attributes")
        return raw

    @staticmethod
    def _decode_number(raw: bytes, name: str) -> str:
        data = raw[4:]
        if len(data) != 2:
            raise RuntimeError(f"{name} EFI variable is invalid")
        return f"{int.from_bytes(data, 'little'):04X}"

    def _run(self, command: list[str]) -> None:
        result = self._runner(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        if getattr(result, "returncode", 0) != 0:
            raise RuntimeError(f"command failed: {command[0]}")

    def resolve_esp(self, esp: Path, *, require_root: bool) -> tuple[Path, dict[str, object]]:
        if not require_root:
            raise PermissionError("loader deployment requires root privileges")
        from refind_forest.install import _identity_for_mounted_source, _require_root

        source = _require_root(esp)
        basic = _identity_for_mounted_source(source)
        physical = dict(self._physical_identity_reader(source))
        if set(physical) != _PHYSICAL_IDENTITY_FIELDS:
            raise RuntimeError("physical ESP identity is incomplete")
        return esp, {
            "fat_uuid": basic.fat_uuid,
            "label": basic.label,
            "mount_major_minor": basic.mount_major_minor,
            "mount_source": basic.mount_source,
            **physical,
        }

    def snapshot(self) -> dict[str, object]:
        raw_current = self._read_variable("BootCurrent")
        raw_order = self._read_variable("BootOrder")
        raw_next = self._read_variable("BootNext", required=False)
        assert raw_current is not None and raw_order is not None
        order_data = raw_order[4:]
        if not order_data or len(order_data) % 2:
            raise RuntimeError("BootOrder EFI variable is invalid")
        boot_order = tuple(
            f"{int.from_bytes(order_data[offset : offset + 2], 'little'):04X}"
            for offset in range(0, len(order_data), 2)
        )
        try:
            children = sorted(self._efivar_root.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise RuntimeError("unable to enumerate EFI variables") from error
        suffix = f"-{_EFI_GLOBAL_VARIABLE_GUID}"
        entry_numbers: dict[str, str] = {}
        for path in children:
            name = path.name
            if len(name) != 4 + 4 + len(suffix) or not name.startswith("Boot") or not name.endswith(suffix):
                continue
            number = name[4:8]
            if not _valid_bootnum(number):
                continue
            canonical = number.upper()
            if canonical in entry_numbers:
                raise RuntimeError("Boot entry name collision after normalization")
            entry_numbers[canonical] = number
        if any(canonical != original for canonical, original in entry_numbers.items()):
            raise RuntimeError("noncanonical Boot entry name")
        entries: dict[str, bytes] = {}
        for number in entry_numbers:
            raw = self._read_variable(f"Boot{number}")
            assert raw is not None
            entries[number] = raw
        return {
            "boot_current": self._decode_number(raw_current, "BootCurrent"),
            "boot_next": (
                self._decode_number(raw_next, "BootNext") if raw_next is not None else None
            ),
            "boot_order": boot_order,
            "raw_boot_current": raw_current,
            "raw_boot_next": raw_next,
            "raw_boot_order": raw_order,
            "entries": entries,
        }

    def create_only_entry(
        self, identity: Mapping[str, object], loader_path: str
    ) -> None:
        disk = identity.get("disk")
        partition = identity.get("partition_number")
        if not isinstance(disk, str) or not Path(disk).is_absolute():
            raise RuntimeError("physical ESP disk path is invalid")
        if type(partition) is not int or partition <= 0:
            raise RuntimeError("physical ESP partition number is invalid")
        if loader_path != _EFI_CANDIDATE_PATH:
            raise RuntimeError("candidate EFI loader path is invalid")
        mount_major_minor = identity.get("mount_major_minor")
        if not isinstance(mount_major_minor, str) or not mount_major_minor:
            raise RuntimeError("mounted ESP device identity is invalid")
        current_physical = dict(
            self._physical_identity_reader(
                SimpleNamespace(major_minor=mount_major_minor)
            )
        )
        if set(current_physical) != _PHYSICAL_IDENTITY_FIELDS:
            raise RuntimeError("physical ESP identity is incomplete")
        recorded_physical = {
            field: identity.get(field) for field in _PHYSICAL_IDENTITY_FIELDS
        }
        if current_physical != recorded_physical:
            raise RuntimeError("physical ESP identity changed before entry creation")
        self._run(
            [
                _EFIBOOTMGR,
                "-C",
                "-d",
                disk,
                "-p",
                str(partition),
                "-L",
                "rEFInd Forest candidate",
                "-l",
                loader_path,
            ]
        )

    def set_boot_next(self, bootnum: str) -> None:
        if not _valid_bootnum(bootnum):
            raise RuntimeError("candidate Boot number is invalid")
        path = self._variable_path("BootNext")
        raw = _expected_boot_next_raw(bootnum)
        descriptor: int | None = None
        created = False
        created_identity: tuple[int, int] | None = None
        write_completed = False
        owned_partial: bytes | None = None
        operation_error: BaseException | None = None
        try:
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                )
            except FileExistsError as error:
                raise FileExistsError(
                    errno.EEXIST, "BootNext already exists", str(path)
                ) from error
            created = True
            metadata = os.fstat(descriptor)
            created_identity = (metadata.st_dev, metadata.st_ino)
            owned_partial = b""
            written = os.write(descriptor, raw)
            if written != len(raw):
                owned_partial = raw[:written]
                raise RuntimeError("unable to write complete BootNext EFI variable")
            write_completed = True
        except BaseException as error:
            operation_error = error

        close_error: OSError | None = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                close_error = error
        if created and not write_completed and owned_partial is not None:
            try:
                current_data, current = _read_regular(
                    path, "incomplete BootNext EFI variable"
                )
                if (
                    created_identity == (current.st_dev, current.st_ino)
                    and current_data == owned_partial
                ):
                    path.unlink()
            except (OSError, RuntimeError):
                pass
        if operation_error is not None:
            if isinstance(operation_error, FileExistsError):
                raise operation_error.with_traceback(operation_error.__traceback__)
            if isinstance(operation_error, OSError):
                raise RuntimeError("unable to create BootNext EFI variable") from operation_error
            raise operation_error.with_traceback(operation_error.__traceback__)
        if close_error is not None:
            raise RuntimeError("unable to close BootNext EFI variable") from close_error
        if self._read_variable("BootNext") != raw:
            raise RuntimeError("BootNext EFI variable read-back mismatch")

    @staticmethod
    def _stable_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _unlink_variable_if_exact(
        self,
        name: str,
        expected_raw: bytes,
        *,
        missing_message: str,
        foreign_message: str,
    ) -> None:
        filename = f"{name}-{_EFI_GLOBAL_VARIABLE_GUID}"
        root_descriptor: int | None = None
        variable_descriptor: int | None = None
        try:
            root_descriptor = os.open(
                self._efivar_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                variable_descriptor = os.open(
                    filename,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError as error:
                raise RuntimeError(missing_message) from error
            before = os.fstat(variable_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError(f"EFI variable {name} is not a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(variable_descriptor, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
            after = os.fstat(variable_descriptor)
            identity = self._stable_metadata(before)
            if self._stable_metadata(after) != identity:
                raise RuntimeError(f"EFI variable {name} changed while reading")
            if raw != expected_raw:
                raise RuntimeError(foreign_message)
            current = os.stat(
                filename,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if self._stable_metadata(current) != identity:
                raise RuntimeError(f"EFI variable {name} changed before deletion")
            os.unlink(filename, dir_fd=root_descriptor)
            try:
                os.stat(
                    filename,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            raise RuntimeError(f"EFI variable {name} was replaced after deletion")
        except OSError as error:
            raise RuntimeError(f"unable to delete EFI variable {name}") from error
        finally:
            if variable_descriptor is not None:
                os.close(variable_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

    def clear_boot_next(self, expected_bootnum: str, expected_raw: bytes) -> None:
        if not _valid_bootnum(expected_bootnum):
            raise RuntimeError("candidate Boot number is invalid")
        current = self._read_variable("BootNext", required=False)
        if current is None:
            raise RuntimeError("owned BootNext is missing")
        if (
            self._decode_number(current, "BootNext") != expected_bootnum.upper()
            or current != expected_raw
        ):
            raise RuntimeError("refusing to clear foreign BootNext")
        self._unlink_variable_if_exact(
            "BootNext",
            expected_raw,
            missing_message="owned BootNext is missing",
            foreign_message="refusing to clear foreign BootNext",
        )

    def delete_entry(self, bootnum: str, expected_raw: bytes) -> None:
        if not _valid_bootnum(bootnum):
            raise RuntimeError("candidate Boot number is invalid")
        current = self._read_variable(f"Boot{bootnum}", required=False)
        if current is None:
            raise RuntimeError("owned Boot entry is missing")
        if current != expected_raw:
            raise RuntimeError("refusing to delete foreign Boot entry")
        self._unlink_variable_if_exact(
            f"Boot{bootnum.upper()}",
            expected_raw,
            missing_message="owned Boot entry is missing",
            foreign_message="refusing to delete foreign Boot entry",
        )

    def exchange(self, active: Path, candidate: Path) -> None:
        self._run(
            [
                _MV,
                "--exchange",
                "--no-copy",
                "-T",
                "--",
                str(active),
                str(candidate),
            ]
        )

    def syncfs(self, esp: Path) -> None:
        descriptor = os.open(
            esp,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        sync_error: BaseException | None = None
        try:
            _sync_filesystem(descriptor)
        except BaseException as error:
            sync_error = error
        try:
            os.close(descriptor)
        except BaseException:
            if sync_error is None:
                raise
        if sync_error is not None:
            raise sync_error.with_traceback(sync_error.__traceback__)

    def entry_matches(
        self,
        raw: bytes,
        identity: Mapping[str, object],
        loader_path: str,
    ) -> bool:
        if len(raw) < 10 or int.from_bytes(raw[:4], "little") != 7:
            return False
        attributes, path_size = struct.unpack_from("<IH", raw, 4)
        if attributes != 1 or path_size < 4:
            return False
        description_offset = 10
        path_offset = -1
        for offset in range(description_offset, len(raw) - 1, 2):
            if raw[offset : offset + 2] == b"\0\0":
                path_offset = offset + 2
                break
        if path_offset < 0 or path_offset + path_size > len(raw):
            return False
        try:
            description = raw[description_offset : path_offset - 2].decode("utf-16-le")
        except UnicodeDecodeError:
            return False
        if description != "rEFInd Forest candidate" or path_offset + path_size != len(raw):
            return False
        device_path = raw[path_offset : path_offset + path_size]
        hard_drive_matches = False
        file_paths: list[str] = []
        saw_end = False
        offset = 0
        node_index = 0
        while offset + 4 <= len(device_path):
            node_type, subtype, node_size = struct.unpack_from("<BBH", device_path, offset)
            if node_size < 4 or offset + node_size > len(device_path):
                return False
            node = device_path[offset : offset + node_size]
            if node_type == 4 and subtype == 1 and node_size == 42:
                if node_index != 0 or hard_drive_matches:
                    return False
                partition, start, size, signature, mbr_type, signature_type = struct.unpack_from(
                    "<IQQ16sBB", node, 4
                )
                try:
                    expected_guid = uuid.UUID(str(identity["partition_guid"])).bytes_le
                except (KeyError, ValueError, AttributeError):
                    return False
                hard_drive_matches = (
                    partition == identity.get("partition_number")
                    and start == identity.get("partition_start_lba")
                    and size == identity.get("partition_size_lba")
                    and signature == expected_guid
                    and mbr_type == 2
                    and signature_type == 2
                )
            elif node_type == 4 and subtype == 4:
                if node_index == 0 or saw_end:
                    return False
                encoded = node[4:]
                if len(encoded) < 2 or len(encoded) % 2 or not encoded.endswith(b"\0\0"):
                    return False
                try:
                    decoded = encoded.decode("utf-16-le")
                except UnicodeDecodeError:
                    return False
                if not decoded.endswith("\0") or "\0" in decoded[:-1]:
                    return False
                file_paths.append(decoded[:-1])
            elif node_type == 0x7F and subtype == 0xFF:
                if (
                    node_size != 4
                    or saw_end
                    or not file_paths
                    or offset + node_size != len(device_path)
                ):
                    return False
                saw_end = True
            else:
                return False
            offset += node_size
            node_index += 1
        return (
            offset == len(device_path)
            and hard_drive_matches
            and saw_end
            and "".join(file_paths) == loader_path
        )

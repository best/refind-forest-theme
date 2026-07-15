from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import FrozenInstanceError, fields
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import unittest
from unittest import mock
import uuid
import zlib

from refind_forest.loader import deploy
from refind_forest.loader.deploy import (
    LoaderStatus,
    loader_status,
    promote_loader,
    rollback_loader,
    set_candidate_boot_next,
    stage_loader,
)


_CANDIDATE_TEST_PATH = "EFI/refind/refind_x64_candidate.efi"


class FakeEfivars:
    def __init__(
        self,
        *,
        boot_next: str | None = None,
        created_bootnum: str = "00AF",
        mutate_boot_order: bool = False,
        mutate_boot_order_on_boot_next: bool = False,
        set_boot_next_error_after_write: bool = False,
        exchange_error_before: set[int] | None = None,
        exchange_error_after: set[int] | None = None,
        inject_foreign_entry_on_snapshot: int | None = None,
        inject_boot_next_on_snapshot: int | None = None,
        create_sets_boot_next: str | None = None,
        create_entry_failures: int = 0,
    ) -> None:
        self.boot_next = boot_next
        self.boot_current = "0001"
        self.boot_order = ("0001", "0002")
        self.raw_boot_order = b"\x01\x00\x02\x00"
        self.entries: dict[str, bytes] = {
            "0001": b"ubuntu fallback",
            "0002": b"windows fallback",
        }
        self.calls: list[tuple[str, object]] = []
        self.created_bootnum = created_bootnum
        self.mutate_boot_order = mutate_boot_order
        self.mutate_boot_order_on_boot_next = mutate_boot_order_on_boot_next
        self.set_boot_next_error_after_write = set_boot_next_error_after_write
        self.exchange_error_before = exchange_error_before or set()
        self.exchange_error_after = exchange_error_after or set()
        self.exchange_count = 0
        self.sync_count = 0
        self.clear_boot_next_count = 0
        self.delete_entry_count = 0
        self.boot_next_attributes = b"\x07\0\0\0"
        self.snapshot_count = 0
        self.inject_foreign_entry_on_snapshot = inject_foreign_entry_on_snapshot
        self.inject_boot_next_on_snapshot = inject_boot_next_on_snapshot
        self.create_sets_boot_next = create_sets_boot_next
        self.create_entry_failures = create_entry_failures
        self.identity = {
            "fat_uuid": "1122-3344",
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "disk_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "partition_number": 7,
            "partition_start_lba": 2048,
            "partition_size_lba": 524288,
            "gpt_sha256": "1" * 64,
            "mount_source": "/dev/fake7",
        }

    def resolve_esp(self, esp: Path, *, require_root: bool) -> tuple[Path, dict[str, object]]:
        self.calls.append(("resolve_esp", require_root))
        return esp.resolve(strict=True), dict(self.identity)

    def snapshot(self) -> dict[str, object]:
        self.snapshot_count += 1
        if self.snapshot_count == self.inject_foreign_entry_on_snapshot:
            self.entries["D00D"] = b"unrelated firmware entry"
        if self.snapshot_count == self.inject_boot_next_on_snapshot:
            self.boot_next = "DEAD"
        self.calls.append(("snapshot", None))
        return {
            "boot_current": self.boot_current,
            "boot_next": self.boot_next,
            "boot_order": self.boot_order,
            "raw_boot_current": b"\x07\0\0\0"
            + int(self.boot_current, 16).to_bytes(2, "little"),
            "raw_boot_next": (
                self.boot_next_attributes
                + int(self.boot_next, 16).to_bytes(2, "little")
                if self.boot_next is not None
                else None
            ),
            "raw_boot_order": self.raw_boot_order,
            "entries": dict(self.entries),
        }

    def create_only_entry(
        self, identity: dict[str, object], loader_path: str
    ) -> None:
        self.calls.append(("create_only_entry", (dict(identity), loader_path)))
        if self.create_entry_failures:
            self.create_entry_failures -= 1
            raise RuntimeError("injected entry creation failure")
        self.entries[self.created_bootnum] = self.entry_bytes(identity, loader_path)
        if self.create_sets_boot_next is not None:
            self.boot_next = self.create_sets_boot_next
        if self.mutate_boot_order:
            self.raw_boot_order += int(self.created_bootnum, 16).to_bytes(2, "little")
            self.boot_order += (self.created_bootnum,)

    @staticmethod
    def entry_bytes(identity: dict[str, object], loader_path: str) -> bytes:
        return (
            json.dumps(
                {"identity": identity, "loader_path": loader_path},
                sort_keys=True,
                separators=(",", ":"),
            )
            .encode("ascii")
        )

    def entry_matches(
        self,
        raw: bytes,
        identity: dict[str, object],
        loader_path: str,
    ) -> bool:
        return raw == self.entry_bytes(identity, loader_path)

    def set_boot_next(self, bootnum: str) -> None:
        self.calls.append(("set_boot_next", bootnum))
        self.boot_next = bootnum
        if self.mutate_boot_order_on_boot_next:
            self.raw_boot_order += b"\xff\xff"
        if self.set_boot_next_error_after_write:
            raise RuntimeError("injected post-write failure")

    def exchange(self, active: Path, candidate: Path) -> None:
        self.exchange_count += 1
        self.calls.append(("exchange", (active, candidate)))
        if self.exchange_count in self.exchange_error_before:
            raise RuntimeError("injected exchange failure")
        temporary = active.with_name(".fake-exchange")
        os.replace(active, temporary)
        os.replace(candidate, active)
        os.replace(temporary, candidate)
        if self.exchange_count in self.exchange_error_after:
            raise RuntimeError("injected post-exchange failure")

    def syncfs(self, esp: Path) -> None:
        self.sync_count += 1
        self.calls.append(("syncfs", esp))

    def clear_boot_next(self, expected_bootnum: str, expected_raw: bytes) -> None:
        self.calls.append(("clear_boot_next", (expected_bootnum, expected_raw)))
        if self.boot_next != expected_bootnum or self.snapshot()["raw_boot_next"] != expected_raw:
            raise RuntimeError("refusing to clear foreign BootNext")
        self.clear_boot_next_count += 1
        self.boot_next = None

    def delete_entry(self, bootnum: str, expected_raw: bytes) -> None:
        self.calls.append(("delete_entry", (bootnum, expected_raw)))
        if self.entries.get(bootnum) != expected_raw:
            raise RuntimeError("refusing to delete foreign Boot entry")
        self.delete_entry_count += 1
        del self.entries[bootnum]


class LoaderStatusTests(unittest.TestCase):
    def test_status_is_frozen_with_exact_fields(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(LoaderStatus)),
            (
                "state",
                "active_sha256",
                "candidate_sha256",
                "candidate_bootnum",
                "boot_current",
                "boot_order",
            ),
        )
        status = LoaderStatus("staged", "a", "b", "0003", "0001", ("0001",))
        with self.assertRaises(FrozenInstanceError):
            status.state = "promoted"


class SnapshotValidationTests(unittest.TestCase):
    def test_snapshot_adapter_rejects_noncanonical_boot_entry_number(self) -> None:
        backend = FakeEfivars()
        backend.entries = {"beef": b"lowercase entry"}

        with self.assertRaisesRegex(RuntimeError, "noncanonical Boot entry number"):
            deploy._snapshot(backend)

    def test_snapshot_adapter_rejects_normalized_boot_entry_collision(self) -> None:
        backend = FakeEfivars()
        backend.entries = {
            "BEEF": b"canonical entry",
            "beef": b"foreign lowercase entry",
        }

        with self.assertRaisesRegex(RuntimeError, "Boot entry number collision"):
            deploy._snapshot(backend)


class LoaderLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_production_lock_rejects_precreated_user_owned_root(self) -> None:
        lock_root = self.root / "locks"
        lock_root.mkdir(mode=0o700)

        with self.assertRaisesRegex(RuntimeError, "lock root is not root-owned"):
            with deploy._esp_lock(lock_root, "a" * 64, require_root=True):
                self.fail("unsafe production lock was acquired")

    def test_lock_rejects_symlinked_root(self) -> None:
        real_root = self.root / "real-locks"
        real_root.mkdir()
        lock_root = self.root / "linked-locks"
        lock_root.symlink_to(real_root, target_is_directory=True)

        with self.assertRaisesRegex(RuntimeError, "symbolic link"):
            with deploy._esp_lock(lock_root, "a" * 64, require_root=False):
                self.fail("symlinked lock root was acquired")

    def test_lock_rejects_path_replacement_after_flock(self) -> None:
        lock_root = self.root / "locks"
        lock_path = lock_root / f"refind-forest-loader-{'a' * 64}.lock"
        real_flock = fcntl.flock

        def replacing_flock(descriptor: int, operation: int) -> None:
            real_flock(descriptor, operation)
            if operation == fcntl.LOCK_EX:
                replacement = lock_root / "replacement"
                replacement.write_bytes(b"")
                os.replace(replacement, lock_path)

        with mock.patch.object(deploy.fcntl, "flock", side_effect=replacing_flock):
            with self.assertRaisesRegex(RuntimeError, "lock path was replaced"):
                with deploy._esp_lock(lock_root, "a" * 64, require_root=False):
                    self.fail("replaced lock inode was trusted")


class LoaderDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.esp = self.root / "esp"
        self.refind = self.esp / "EFI" / "refind"
        self.refind.mkdir(parents=True)
        self.active = self.refind / "refind_x64.efi"
        self.active.write_bytes(b"unknown active loader")
        (self.refind / "refind.conf").write_bytes(b"timeout 20\ninclude theme.conf\n")
        themes = self.refind / "themes" / "forest-a"
        themes.mkdir(parents=True)
        (themes / "background.png").write_bytes(b"theme pixels")
        ubuntu = self.esp / "EFI" / "ubuntu"
        ubuntu.mkdir(parents=True)
        (ubuntu / "shimx64.efi").write_bytes(b"shim")
        (ubuntu / "grubx64.efi").write_bytes(b"grub")
        windows = self.esp / "EFI" / "Microsoft" / "Boot"
        windows.mkdir(parents=True)
        (windows / "bootmgfw.efi").write_bytes(b"windows")
        self.candidate = self.root / "candidate.efi"
        self.candidate.write_bytes(b"candidate loader")
        self.backup_root = self.root / "external-backups"
        self.lock_root = self.root / "locks"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _esp_bytes(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.esp).as_posix(): path.read_bytes()
            for path in self.esp.rglob("*")
            if path.is_file()
        }

    def test_unknown_active_is_rejected_before_side_effects(self) -> None:
        backend = FakeEfivars()
        before = {
            path.relative_to(self.root): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*")
            if path.is_file()
        }

        with self.assertRaisesRegex(RuntimeError, "unknown active loader"):
            stage_loader(
                self.candidate,
                self.esp,
                self.backup_root,
                backend=backend,
                verifier=lambda _path: None,
                esp_identity=lambda _esp: {"device": "test-esp"},
                require_root=False,
            )

        after = {
            path.relative_to(self.root): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)
        self.assertFalse(
            any(call[0] in {"create_only_entry", "set_boot_next"} for call in backend.calls)
        )
        self.assertFalse(self.backup_root.exists())

    def _stage(self, backend: FakeEfivars | None = None) -> tuple[Path, FakeEfivars]:
        backend = backend or FakeEfivars()
        active_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()
        with mock.patch.object(deploy, "_KNOWN_ACTIVE_SHA256", {active_hash}):
            transaction = stage_loader(
                self.candidate,
                self.esp,
                self.backup_root,
                backend=backend,
                verifier=lambda _path: None,
                require_root=False,
                lock_root=self.lock_root,
            )
        return transaction, backend

    def _write_rollback_intent(self, transaction: Path) -> None:
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        deploy._write_intent(
            transaction,
            "rollback",
            old_sha256=manifest["active"]["sha256"],
            candidate_sha256=manifest["candidate"]["sha256"],
            candidate_quarantine=(
                f".refind_x64_candidate.efi.rollback-{manifest['lock_key'][:16]}"
            ),
            restore_temporary=(
                f".refind_x64.efi.rollback-{manifest['lock_key'][:16]}"
            ),
        )

    def test_stage_accepts_known_old_and_records_external_transaction(self) -> None:
        old_bytes = self.active.read_bytes()
        old_hash = hashlib.sha256(old_bytes).hexdigest()
        new_hash = hashlib.sha256(self.candidate.read_bytes()).hexdigest()

        transaction, backend = self._stage()

        self.assertEqual(
            deploy._DISTRIBUTION_ACTIVE_SHA256,
            "43df4fd676efc2835c2a546f6875b6134d6ce1662ef486cbf164d96754674fda",
        )
        self.assertNotEqual(transaction, self.esp)
        self.assertNotIn(self.esp, transaction.parents)
        self.assertEqual(transaction.stat().st_mode & 0o777, 0o700)
        backup = transaction / "active" / "refind_x64.efi"
        self.assertEqual(backup.read_bytes(), old_bytes)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        staged = self.refind / "refind_x64_candidate.efi"
        self.assertEqual(staged.read_bytes(), self.candidate.read_bytes())

        raw_manifest = (transaction / "manifest.json").read_bytes()
        raw_manifest.decode("ascii")
        manifest = json.loads(raw_manifest)
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["schema"], "refind-forest-loader-transaction")
        self.assertEqual(manifest["state"], "staged")
        self.assertEqual(manifest["active"]["sha256"], old_hash)
        self.assertEqual(manifest["candidate"]["sha256"], new_hash)
        self.assertEqual(manifest["candidate"]["size"], self.candidate.stat().st_size)
        self.assertEqual(manifest["esp_identity"], backend.identity)
        self.assertEqual(manifest["candidate_bootnum"], "00AF")
        self.assertEqual(manifest["nvram_initial"]["raw_boot_order"], "01000200")
        self.assertEqual(set(manifest["tree_hashes"]), {"EFI", "EFI/refind"})
        self.assertEqual(manifest["candidate_entry_raw"], backend.entries["00AF"].hex())
        self.assertFalse((transaction / "intent.json").exists())
        self.assertNotIn("00AF", backend.boot_order)
        self.assertEqual(backend.raw_boot_order, b"\x01\x00\x02\x00")
        self.assertEqual(
            [name for name, _value in backend.calls].count("create_only_entry"), 1
        )
        self.assertEqual(backend.sync_count, 1)

    def test_stage_uses_same_directory_atomic_replace(self) -> None:
        replacements: list[tuple[Path, Path]] = []
        real_replace = os.replace

        def recording_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
            replacements.append((Path(source), Path(target)))
            real_replace(source, target)

        with mock.patch.object(deploy.os, "replace", side_effect=recording_replace):
            self._stage()

        candidate_replaces = [
            pair
            for pair in replacements
            if pair[1].name == "refind_x64_candidate.efi"
        ]
        self.assertEqual(len(candidate_replaces), 1)
        self.assertEqual(candidate_replaces[0][0].parent, self.refind)
        self.assertEqual(candidate_replaces[0][1].parent, self.refind)

    def test_stage_is_idempotent_for_same_candidate(self) -> None:
        transaction, backend = self._stage()
        again, _ = self._stage(backend)

        self.assertEqual(again, transaction)
        self.assertEqual(
            [name for name, _value in backend.calls].count("create_only_entry"), 1
        )

    def test_idempotent_restage_preserves_armed_ownership(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        armed_manifest = (transaction / "manifest.json").read_bytes()

        again, _ = self._stage(backend)

        self.assertEqual(again, transaction)
        self.assertEqual((transaction / "manifest.json").read_bytes(), armed_manifest)
        manifest = json.loads(armed_manifest)
        self.assertEqual(manifest["state"], "armed")
        self.assertTrue(manifest["boot_next_owned"])
        self.assertEqual(
            [name for name, _value in backend.calls].count("set_boot_next"), 1
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertIsNone(backend.boot_next)
        self.assertNotIn("00AF", backend.entries)
        self.assertEqual(backend.clear_boot_next_count, 1)
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "rolled_back",
        )

    def test_stage_idempotent_path_rejects_tampered_backup(self) -> None:
        transaction, backend = self._stage()
        (transaction / "active" / "refind_x64.efi").write_bytes(b"tampered")

        with self.assertRaisesRegex(RuntimeError, "backed-up active loader hash mismatch"):
            self._stage(backend)

    def test_stage_recovers_stale_publish_intent_and_validates_entry(self) -> None:
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "backup_ready"
        deploy._atomic_json(transaction / "manifest.json", manifest)
        deploy._write_intent(
            transaction,
            "publish_candidate",
            temporary_name=(
                f".refind_x64_candidate.efi.stage-{manifest['lock_key'][:16]}"
            ),
        )
        before_sync = backend.sync_count

        recovered, _ = self._stage(backend)

        self.assertEqual(recovered, transaction)
        self.assertFalse((transaction / "intent.json").exists())
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "staged",
        )
        self.assertEqual(backend.sync_count, before_sync + 1)

    def test_stage_recovers_entry_intent_by_observing_live_new_entry(self) -> None:
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "candidate_published"
        manifest["candidate_bootnum"] = None
        manifest["candidate_entry_raw"] = None
        deploy._atomic_json(transaction / "manifest.json", manifest)
        deploy._write_intent(
            transaction,
            "create_entry",
            before=manifest["nvram_initial"],
        )

        recovered, _ = self._stage(backend)

        self.assertEqual(recovered, transaction)
        repaired = json.loads((transaction / "manifest.json").read_text("ascii"))
        self.assertEqual(repaired["candidate_bootnum"], "00AF")
        self.assertEqual(repaired["state"], "staged")
        self.assertFalse((transaction / "intent.json").exists())

    def test_stage_idempotent_path_rejects_replaced_raw_entry(self) -> None:
        _transaction, backend = self._stage()
        backend.entries["00AF"] = b"foreign"

        with self.assertRaisesRegex(RuntimeError, "candidate Boot entry ownership"):
            self._stage(backend)

    def test_stage_does_not_adopt_matching_entry_without_create_intent(self) -> None:
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "candidate_published"
        manifest["candidate_bootnum"] = None
        manifest["candidate_entry_raw"] = None
        deploy._atomic_json(transaction / "manifest.json", manifest)

        with self.assertRaisesRegex(RuntimeError, "unowned Boot entry"):
            self._stage(backend)

        self.assertEqual(backend.entries.keys(), {"0001", "0002", "00AF"})

    def test_stage_recovery_diffs_entry_against_intent_before_snapshot(self) -> None:
        transaction, backend = self._stage()
        backend.entries["D00D"] = b"unrelated firmware entry"
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "candidate_published"
        manifest["candidate_bootnum"] = None
        manifest["candidate_entry_raw"] = None
        deploy._atomic_json(transaction / "manifest.json", manifest)
        before = backend.snapshot()
        before["entries"].pop("00AF")
        deploy._write_intent(
            transaction,
            "create_entry",
            before={
                "boot_current": before["boot_current"],
                "boot_next": before["boot_next"],
                "boot_order": list(before["boot_order"]),
                "raw_boot_current": before["raw_boot_current"].hex(),
                "raw_boot_next": (
                    before["raw_boot_next"].hex()
                    if before["raw_boot_next"] is not None
                    else None
                ),
                "raw_boot_order": before["raw_boot_order"].hex(),
                "entries": {
                    key: value.hex() for key, value in before["entries"].items()
                },
            },
        )

        recovered, _ = self._stage(backend)

        self.assertEqual(recovered, transaction)
        repaired = json.loads((transaction / "manifest.json").read_text("ascii"))
        self.assertEqual(repaired["candidate_bootnum"], "00AF")
        self.assertEqual(backend.entries["D00D"], b"unrelated firmware entry")

    def test_stage_retry_rejects_bootnext_changed_before_create(self) -> None:
        backend = FakeEfivars(inject_boot_next_on_snapshot=2)
        with self.assertRaisesRegex(RuntimeError, "NVRAM changed before"):
            self._stage(backend)

        with self.assertRaisesRegex(RuntimeError, "BootNext changed before"):
            self._stage(backend)
        self.assertNotIn("00AF", backend.entries)

    def test_stage_rejects_bootnext_changed_by_entry_creation(self) -> None:
        backend = FakeEfivars(create_sets_boot_next="00AF")

        with self.assertRaisesRegex(RuntimeError, "BootNext changed during"):
            self._stage(backend)

        transactions = list(self.backup_root.iterdir())
        self.assertEqual(len(transactions), 1)
        intent = json.loads((transactions[0] / "intent.json").read_text("ascii"))
        self.assertEqual(intent["operation"], "create_entry")
        self.assertEqual(intent["candidate_bootnum"], "00AF")
        self.assertEqual(intent["candidate_entry_raw"], backend.entries["00AF"].hex())

    def test_stage_rejects_dangling_bootnext_before_candidate_publication(self) -> None:
        backend = FakeEfivars(boot_next="00AF", created_bootnum="00AF")
        before = self._esp_bytes()

        with self.assertRaisesRegex(RuntimeError, "BootNext references missing Boot00AF"):
            self._stage(backend)

        self.assertEqual(backend.boot_next, "00AF")
        self.assertNotIn("00AF", backend.entries)
        self.assertFalse(
            any(name == "create_only_entry" for name, _value in backend.calls)
        )
        self.assertEqual(self._esp_bytes(), before)
        self.assertFalse(self.backup_root.exists())

    def test_stage_rejects_dangling_bootorder_before_candidate_publication(self) -> None:
        backend = FakeEfivars(created_bootnum="00AF")
        backend.boot_order += ("00AF",)
        backend.raw_boot_order += b"\xaf\x00"
        before = self._esp_bytes()

        with self.assertRaisesRegex(RuntimeError, "BootOrder references missing Boot00AF"):
            self._stage(backend)

        self.assertNotIn("00AF", backend.entries)
        self.assertFalse(
            any(name == "create_only_entry" for name, _value in backend.calls)
        )
        self.assertEqual(self._esp_bytes(), before)
        self.assertFalse(self.backup_root.exists())

    def test_stage_rejects_dangling_bootcurrent_before_candidate_publication(self) -> None:
        backend = FakeEfivars(created_bootnum="00AF")
        backend.boot_current = "00AF"
        before = self._esp_bytes()

        with self.assertRaisesRegex(RuntimeError, "BootCurrent references missing Boot00AF"):
            self._stage(backend)

        self.assertNotIn("00AF", backend.entries)
        self.assertFalse(
            any(name == "create_only_entry" for name, _value in backend.calls)
        )
        self.assertEqual(self._esp_bytes(), before)
        self.assertFalse(self.backup_root.exists())

    def test_stage_rejects_candidate_mismatch_without_mutation(self) -> None:
        transaction, backend = self._stage()
        other = self.root / "other.efi"
        other.write_bytes(b"different candidate")
        before = (self.refind / "refind_x64_candidate.efi").read_bytes()
        active_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()

        with mock.patch.object(deploy, "_KNOWN_ACTIVE_SHA256", {active_hash}):
            with self.assertRaisesRegex(RuntimeError, "candidate mismatch"):
                stage_loader(
                    other,
                    self.esp,
                    self.backup_root,
                    backend=backend,
                    verifier=lambda _path: None,
                    require_root=False,
                    lock_root=self.lock_root,
                )

        self.assertTrue(transaction.exists())
        self.assertEqual((self.refind / "refind_x64_candidate.efi").read_bytes(), before)

    def test_stage_rejects_raw_bootorder_mutation_and_keeps_intent(self) -> None:
        backend = FakeEfivars(mutate_boot_order=True)

        with self.assertRaisesRegex(RuntimeError, "BootOrder changed"):
            self._stage(backend)

        transactions = [path for path in self.backup_root.iterdir() if path.is_dir()]
        self.assertEqual(len(transactions), 1)
        self.assertTrue((transactions[0] / "intent.json").exists())
        self.assertEqual(self.active.read_bytes(), b"unknown active loader")

    def test_stage_revalidates_active_loader_after_acquiring_lock(self) -> None:
        backend = FakeEfivars()
        active_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()

        @contextmanager
        def replacing_lock(_root: Path, _key: str, *, require_root: bool):
            del require_root
            self.active.write_bytes(b"foreign active replacement")
            yield

        with mock.patch.object(deploy, "_KNOWN_ACTIVE_SHA256", {active_hash}), mock.patch.object(
            deploy, "_esp_lock", replacing_lock
        ):
            with self.assertRaisesRegex(RuntimeError, "active loader changed"):
                stage_loader(
                    self.candidate,
                    self.esp,
                    self.backup_root,
                    backend=backend,
                    verifier=lambda _path: None,
                    require_root=False,
                    lock_root=self.lock_root,
                )

        self.assertFalse(self.backup_root.exists())

    def test_stage_rejects_nvram_change_before_entry_creation(self) -> None:
        backend = FakeEfivars(inject_foreign_entry_on_snapshot=2)

        with self.assertRaisesRegex(RuntimeError, "NVRAM changed before"):
            self._stage(backend)

        self.assertNotIn("00AF", backend.entries)
        self.assertEqual(backend.entries["D00D"], b"unrelated firmware entry")

    def test_stage_recovers_candidate_write_failure(self) -> None:
        active_before = self.active.read_bytes()
        real_write = deploy._write_file_exclusive
        failed = False

        def fail_candidate_write(path: Path, data: bytes, mode: int = 0o600) -> None:
            nonlocal failed
            if path.name.startswith(".refind_x64_candidate.efi.stage-") and not failed:
                failed = True
                raise OSError("injected candidate write failure")
            real_write(path, data, mode)

        with mock.patch.object(
            deploy, "_write_file_exclusive", side_effect=fail_candidate_write
        ):
            with self.assertRaisesRegex(OSError, "candidate write failure"):
                self._stage()

        self.assertEqual(self.active.read_bytes(), active_before)
        transaction, backend = self._stage(FakeEfivars())
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(),
            self.candidate.read_bytes(),
        )
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "staged",
        )

    def test_stage_recovers_recorded_candidate_temp_after_crash(self) -> None:
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        del backend.entries["00AF"]
        (self.refind / "refind_x64_candidate.efi").unlink()
        manifest["state"] = "backup_ready"
        manifest["candidate_bootnum"] = None
        manifest["candidate_entry_raw"] = None
        deploy._atomic_json(transaction / "manifest.json", manifest)
        temp_name = (
            f".refind_x64_candidate.efi.stage-{manifest['lock_key'][:16]}"
        )
        temporary = self.refind / temp_name
        temporary.write_bytes(self.candidate.read_bytes())
        deploy._write_intent(
            transaction,
            "publish_candidate",
            temporary_name=temp_name,
        )

        recovered, _ = self._stage(backend)

        self.assertEqual(recovered, transaction)
        self.assertFalse(temporary.exists())
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(),
            self.candidate.read_bytes(),
        )

    def test_stage_preserves_foreign_recorded_candidate_temp(self) -> None:
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        del backend.entries["00AF"]
        (self.refind / "refind_x64_candidate.efi").unlink()
        manifest["state"] = "backup_ready"
        manifest["candidate_bootnum"] = None
        manifest["candidate_entry_raw"] = None
        deploy._atomic_json(transaction / "manifest.json", manifest)
        temp_name = (
            f".refind_x64_candidate.efi.stage-{manifest['lock_key'][:16]}"
        )
        temporary = self.refind / temp_name
        temporary.write_bytes(b"foreign publication temp")
        deploy._write_intent(
            transaction,
            "publish_candidate",
            temporary_name=temp_name,
        )

        with self.assertRaisesRegex(RuntimeError, "foreign candidate temporary"):
            self._stage(backend)

        self.assertEqual(temporary.read_bytes(), b"foreign publication temp")

    def test_stage_recovers_manifest_failure_after_candidate_publish(self) -> None:
        backend = FakeEfivars()
        real_write = deploy._write_manifest
        calls = 0

        def fail_second(transaction: Path, manifest: dict[str, object]) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected manifest write failure")
            real_write(transaction, manifest)

        with mock.patch.object(deploy, "_write_manifest", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "manifest write failure"):
                self._stage(backend)

        transaction, _ = self._stage(backend)
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "staged",
        )
        self.assertFalse((transaction / "intent.json").exists())

    def test_stage_recovers_entry_creation_failure(self) -> None:
        backend = FakeEfivars(create_entry_failures=1)

        with self.assertRaisesRegex(RuntimeError, "entry creation failure"):
            self._stage(backend)

        transaction, _ = self._stage(backend)
        self.assertEqual(backend.entries.keys(), {"0001", "0002", "00AF"})
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "staged",
        )

    def test_stage_rejects_symlink_candidate_and_active(self) -> None:
        real_candidate = self.candidate
        candidate_link = self.root / "candidate-link.efi"
        candidate_link.symlink_to(real_candidate)
        with self.assertRaisesRegex(RuntimeError, "must not be a symbolic link"):
            stage_loader(
                candidate_link,
                self.esp,
                self.backup_root,
                backend=FakeEfivars(),
                verifier=lambda _path: None,
                require_root=False,
                lock_root=self.lock_root,
            )

    def test_stage_rejects_user_owned_backup_root_in_production_mode(self) -> None:
        self.backup_root.mkdir(mode=0o700)
        active_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()
        with mock.patch.object(deploy, "_KNOWN_ACTIVE_SHA256", {active_hash}):
            with self.assertRaisesRegex(
                RuntimeError, "root-owned|group/world writable"
            ):
                stage_loader(
                    self.candidate,
                    self.esp,
                    self.backup_root,
                    backend=FakeEfivars(),
                    verifier=lambda _path: None,
                    require_root=True,
                    lock_root=self.lock_root,
                )
        self.assertFalse((self.refind / "refind_x64_candidate.efi").exists())

    def test_stage_rejects_symlinked_backup_root_ancestor(self) -> None:
        real_parent = self.root / "real-backups"
        real_parent.mkdir()
        linked_parent = self.root / "linked-backups"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        active_hash = hashlib.sha256(self.active.read_bytes()).hexdigest()

        with mock.patch.object(deploy, "_KNOWN_ACTIVE_SHA256", {active_hash}):
            with self.assertRaisesRegex(RuntimeError, "symbolic link component"):
                stage_loader(
                    self.candidate,
                    self.esp,
                    linked_parent / "transactions",
                    backend=FakeEfivars(),
                    verifier=lambda _path: None,
                    require_root=False,
                    lock_root=self.lock_root,
                )

    def test_production_rollback_rejects_user_owned_forged_transaction(self) -> None:
        transaction, backend = self._stage()
        active_before = self.active.read_bytes()
        candidate_before = (self.refind / "refind_x64_candidate.efi").read_bytes()

        with self.assertRaisesRegex(RuntimeError, "root-owned|group/world writable"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                require_root=True,
                lock_root=self.lock_root,
            )

        self.assertEqual(self.active.read_bytes(), active_before)
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(), candidate_before
        )

    def test_status_rejects_transaction_relocated_inside_esp(self) -> None:
        transaction, backend = self._stage()
        embedded = self.esp / "loader-transaction"
        os.replace(transaction, embedded)

        with self.assertRaisesRegex(RuntimeError, "outside the ESP"):
            loader_status(
                embedded,
                self.esp,
                backend=backend,
                require_root=False,
                lock_root=self.lock_root,
            )

        self.active.unlink()
        self.active.symlink_to(self.root / "active-real.efi")
        (self.root / "active-real.efi").write_bytes(b"old")
        with self.assertRaisesRegex(RuntimeError, "must not be a symbolic link"):
            stage_loader(
                self.candidate,
                self.esp,
                self.backup_root,
                backend=FakeEfivars(),
                verifier=lambda _path: None,
                require_root=False,
                lock_root=self.lock_root,
            )

    def test_boot_next_refuses_to_overwrite_existing_value(self) -> None:
        transaction, backend = self._stage()
        backend.boot_next = "0002"
        with self.assertRaisesRegex(RuntimeError, "BootNext already exists"):
            set_candidate_boot_next(
                transaction,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )
        self.assertEqual(backend.boot_next, "0002")

    def test_boot_next_sets_only_candidate_and_confirms_raw_order(self) -> None:
        transaction, backend = self._stage(FakeEfivars(created_bootnum="BEEF"))

        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(backend.boot_next, "BEEF")
        self.assertEqual(backend.raw_boot_order, b"\x01\x00\x02\x00")
        self.assertEqual(
            [call for call in backend.calls if call[0] == "set_boot_next"],
            [("set_boot_next", "BEEF")],
        )
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        self.assertEqual(manifest["state"], "armed")
        self.assertFalse((transaction / "intent.json").exists())

    def test_boot_next_converges_when_backend_raises_after_write(self) -> None:
        backend = FakeEfivars(set_boot_next_error_after_write=True)
        transaction, backend = self._stage(backend)

        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(backend.boot_next, "00AF")
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "armed",
        )

    def test_boot_next_retry_converges_from_stale_committed_intent(self) -> None:
        transaction, backend = self._stage()
        deploy._write_intent(
            transaction,
            "set_boot_next",
            candidate_bootnum="00AF",
            raw_boot_order=backend.raw_boot_order.hex(),
            expected_raw_boot_next=(b"\x07\0\0\0\xaf\0").hex(),
        )
        backend.boot_next = "00AF"

        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(
            [call for call in backend.calls if call[0] == "set_boot_next"], []
        )
        self.assertFalse((transaction / "intent.json").exists())
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "armed",
        )

    def test_boot_next_pending_does_not_adopt_foreign_same_number_raw(self) -> None:
        transaction, backend = self._stage()
        deploy._write_intent(
            transaction,
            "set_boot_next",
            candidate_bootnum="00AF",
            raw_boot_order=backend.raw_boot_order.hex(),
            expected_raw_boot_next=(b"\x07\0\0\0\xaf\0").hex(),
        )
        backend.boot_next = "00AF"
        backend.boot_next_attributes = b"\x03\0\0\0"

        with self.assertRaisesRegex(RuntimeError, "foreign BootNext"):
            set_candidate_boot_next(
                transaction,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.boot_next, "00AF")
        self.assertFalse(
            json.loads((transaction / "manifest.json").read_text("ascii"))[
                "boot_next_owned"
            ]
        )

    def test_boot_next_rejects_raw_order_mutation_and_keeps_intent(self) -> None:
        backend = FakeEfivars(mutate_boot_order_on_boot_next=True)
        transaction, backend = self._stage(backend)

        with self.assertRaisesRegex(RuntimeError, "BootOrder changed"):
            set_candidate_boot_next(
                transaction,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertTrue((transaction / "intent.json").exists())

    def test_status_observes_alternate_number_and_live_state(self) -> None:
        transaction, backend = self._stage(FakeEfivars(created_bootnum="CAFE"))
        backend.boot_current = "CAFE"
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "manifest-lie"
        deploy._atomic_json(transaction / "manifest.json", manifest)

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(
            status,
            LoaderStatus(
                "candidate_booted",
                hashlib.sha256(self.active.read_bytes()).hexdigest(),
                hashlib.sha256(self.candidate.read_bytes()).hexdigest(),
                "CAFE",
                "CAFE",
                ("0001", "0002"),
            ),
        )

    def test_status_reports_fallback_after_consumed_candidate_boot(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        backend.boot_next = None
        backend.boot_current = "0001"

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(status.state, "fallback")
        self.assertEqual(status.boot_current, "0001")

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertEqual(backend.delete_entry_count, 1)
        self.assertNotIn("00AF", backend.entries)
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "rolled_back",
        )

    def test_status_rejects_wrong_esp_identity(self) -> None:
        transaction, backend = self._stage()
        backend.identity["partition_guid"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"

        with self.assertRaisesRegex(RuntimeError, "wrong physical ESP identity"):
            loader_status(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

    def test_status_rejects_replaced_raw_candidate_entry(self) -> None:
        transaction, backend = self._stage()
        backend.entries["00AF"] = b"foreign replacement"

        with self.assertRaisesRegex(RuntimeError, "candidate Boot entry ownership"):
            loader_status(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

    def test_status_rejects_replaced_initial_fallback_entry(self) -> None:
        backend = FakeEfivars()
        backend.entries = {"0001": b"ubuntu fallback", "0002": b"windows fallback"}
        transaction, backend = self._stage(backend)
        backend.entries["0001"] = b"foreign ubuntu replacement"

        with self.assertRaisesRegex(RuntimeError, "initial Boot entry ownership"):
            loader_status(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

    def test_status_rejects_tampered_external_backup(self) -> None:
        transaction, backend = self._stage()
        (transaction / "active" / "refind_x64.efi").write_bytes(b"tampered")

        with self.assertRaisesRegex(RuntimeError, "backed-up active loader hash mismatch"):
            loader_status(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

    def test_status_rejects_changed_raw_initial_bootnext_attributes(self) -> None:
        backend = FakeEfivars(boot_next="DEAD")
        backend.entries["DEAD"] = b"existing one-shot entry"
        transaction, backend = self._stage(backend)
        backend.boot_next_attributes = b"\x03\0\0\0"

        with self.assertRaisesRegex(RuntimeError, "initial raw BootNext changed"):
            loader_status(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

    def test_status_reports_recovery_required_for_pending_revert(self) -> None:
        transaction, backend = self._stage()
        backend.exchange(self.active, self.refind / "refind_x64_candidate.efi")
        deploy._write_intent(transaction, "promote_revert")

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(status.state, "recovery_required")

    def test_status_reports_recovery_required_after_rollback_entry_delete_crash(
        self,
    ) -> None:
        transaction, backend = self._stage()
        real_snapshot = backend.snapshot
        real_delete_entry = backend.delete_entry
        crash_next_snapshot = False

        def snapshot_with_crash_cut() -> dict[str, object]:
            nonlocal crash_next_snapshot
            if crash_next_snapshot:
                crash_next_snapshot = False
                raise RuntimeError("injected crash after candidate entry deletion")
            return real_snapshot()

        def delete_entry_then_crash(bootnum: str, expected_raw: bytes) -> None:
            nonlocal crash_next_snapshot
            real_delete_entry(bootnum, expected_raw)
            crash_next_snapshot = True

        backend.snapshot = snapshot_with_crash_cut
        backend.delete_entry = delete_entry_then_crash
        with self.assertRaisesRegex(
            RuntimeError, "injected crash after candidate entry deletion"
        ):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertNotIn("00AF", backend.entries)
        self.assertTrue((transaction / "intent.json").exists())
        self.assertEqual(status.state, "recovery_required")

    def test_status_reports_recovery_required_for_stale_rollback_intent(self) -> None:
        transaction, backend = self._stage()
        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        self._write_rollback_intent(transaction)

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(status.state, "recovery_required")

    def test_status_preserves_promotion_failed_over_candidate_bootcurrent(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        manifest["state"] = "promotion_failed"
        deploy._atomic_json(transaction / "manifest.json", manifest)

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(status.state, "promotion_failed")

    def test_promote_requires_candidate_bootcurrent(self) -> None:
        transaction, backend = self._stage()
        with self.assertRaisesRegex(RuntimeError, "BootCurrent is not candidate"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                boot_current="0001",
                lock_root=self.lock_root,
                require_root=False,
            )
        self.assertEqual(backend.exchange_count, 0)

    def test_promote_bootcurrent_argument_cannot_override_live_value(self) -> None:
        transaction, backend = self._stage()
        self.assertEqual(backend.boot_current, "0001")

        with self.assertRaisesRegex(RuntimeError, "does not match live BootCurrent"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                boot_current="00AF",
                verifier=lambda _path: None,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 0)

    def test_promote_rejects_live_bootnext_before_slot_exchange(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        backend.boot_current = "00AF"

        with self.assertRaisesRegex(RuntimeError, "BootNext.*candidate boot"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                verifier=lambda _path: None,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 0)
        self.assertEqual(backend.boot_next, "00AF")

    def test_promote_exchanges_slots_once_syncs_and_verifies(self) -> None:
        transaction, backend = self._stage(FakeEfivars(created_bootnum="A123"))
        backend.boot_current = "A123"
        old_bytes = self.active.read_bytes()
        new_bytes = self.candidate.read_bytes()
        verified: list[Path] = []

        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=verified.append,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self.active.read_bytes(), new_bytes)
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(), old_bytes
        )
        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(backend.sync_count, 2)
        self.assertEqual(verified, [self.active])
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "promoted",
        )
        self.assertFalse((transaction / "intent.json").exists())

    def test_boot_next_does_not_adopt_a_definite_create_conflict(self) -> None:
        class ConflictingEfivars(FakeEfivars):
            def set_boot_next(self, bootnum: str) -> None:
                self.calls.append(("set_boot_next", bootnum))
                self.boot_next = bootnum
                raise FileExistsError("BootNext already exists")

        transaction, backend = self._stage(ConflictingEfivars())

        with self.assertRaisesRegex(FileExistsError, "BootNext already exists"):
            set_candidate_boot_next(
                transaction,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        self.assertEqual(manifest["state"], "staged")
        self.assertFalse(manifest["boot_next_owned"])
        self.assertFalse((transaction / "intent.json").exists())

    def test_boot_next_create_conflict_clears_intent_when_snapshot_fails(self) -> None:
        class UnreadableConflictEfivars(FakeEfivars):
            snapshot_blocked = False

            def set_boot_next(self, bootnum: str) -> None:
                self.calls.append(("set_boot_next", bootnum))
                self.snapshot_blocked = True
                raise FileExistsError("BootNext already exists")

            def snapshot(self) -> dict[str, object]:
                if self.snapshot_blocked:
                    raise RuntimeError("injected post-conflict snapshot failure")
                return super().snapshot()

        transaction, backend = self._stage(UnreadableConflictEfivars())

        with self.assertRaisesRegex(RuntimeError, "post-conflict snapshot failure"):
            set_candidate_boot_next(
                transaction,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertFalse((transaction / "intent.json").exists())

    def test_promote_exchange_failure_leaves_slots_and_intent(self) -> None:
        backend = FakeEfivars(exchange_error_before={1})
        transaction, backend = self._stage(backend)
        backend.boot_current = "00AF"
        old_bytes = self.active.read_bytes()
        new_bytes = self.candidate.read_bytes()

        with self.assertRaisesRegex(RuntimeError, "injected exchange failure"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                verifier=lambda _path: None,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(self.active.read_bytes(), old_bytes)
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(), new_bytes
        )
        self.assertEqual(
            json.loads((transaction / "intent.json").read_text("ascii"))["operation"],
            "promote",
        )

    def test_promote_converges_after_post_exchange_command_error(self) -> None:
        backend = FakeEfivars(exchange_error_after={1})
        transaction, backend = self._stage(backend)
        backend.boot_current = "00AF"

        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self.active.read_bytes(), self.candidate.read_bytes())
        self.assertEqual(backend.exchange_count, 1)
        self.assertFalse((transaction / "intent.json").exists())

    def test_promote_postverify_failure_reverses_and_verifies_old_hash(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        old_bytes = self.active.read_bytes()
        new_bytes = self.candidate.read_bytes()

        def reject(_path: Path) -> None:
            raise RuntimeError("injected post-exchange verification failure")

        with self.assertRaisesRegex(
            RuntimeError, "injected post-exchange verification failure"
        ):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                verifier=reject,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(self.active.read_bytes(), old_bytes)
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(), new_bytes
        )
        self.assertEqual(backend.exchange_count, 2)
        self.assertEqual(backend.sync_count, 3)
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "promotion_failed",
        )
        self.assertFalse((transaction / "intent.json").exists())

    def test_promote_reverse_failure_retains_recovery_intent(self) -> None:
        backend = FakeEfivars(exchange_error_before={2})
        transaction, backend = self._stage(backend)
        backend.boot_current = "00AF"

        with self.assertRaisesRegex(RuntimeError, "reverse exchange failed"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                verifier=lambda _path: (_ for _ in ()).throw(
                    RuntimeError("postverify failure")
                ),
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 2)
        self.assertEqual(
            json.loads((transaction / "intent.json").read_text("ascii"))["operation"],
            "promote_revert",
        )
        self.assertEqual(self.active.read_bytes(), self.candidate.read_bytes())

    def test_promote_recovers_stale_committed_intent_without_second_exchange(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        deploy._write_intent(
            transaction,
            "promote",
            authorized_bootnum="00AF",
            authorized_boot_current_raw=backend.snapshot()["raw_boot_current"].hex(),
        )
        backend.exchange(
            self.active, self.refind / "refind_x64_candidate.efi"
        )
        self.assertEqual(backend.exchange_count, 1)

        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "promoted",
        )
        self.assertFalse((transaction / "intent.json").exists())

    def test_promote_recovers_committed_intent_after_bootcurrent_changes(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        deploy._write_intent(
            transaction,
            "promote",
            authorized_bootnum="00AF",
            authorized_boot_current_raw=backend.snapshot()["raw_boot_current"].hex(),
        )
        backend.exchange(self.active, self.refind / "refind_x64_candidate.efi")
        backend.boot_current = "0001"
        before_sync = backend.sync_count

        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(backend.sync_count, before_sync + 1)
        self.assertFalse((transaction / "intent.json").exists())

    def test_promote_recovers_reversed_intent_after_reboot_and_syncs(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        authorization = backend.snapshot()["raw_boot_current"].hex()
        backend.exchange(self.active, self.refind / "refind_x64_candidate.efi")
        deploy._write_intent(
            transaction,
            "promote_revert",
            authorized_bootnum="00AF",
            authorized_boot_current_raw=authorization,
        )
        backend.exchange(self.active, self.refind / "refind_x64_candidate.efi")
        backend.boot_current = "0001"
        before_sync = backend.sync_count

        with self.assertRaisesRegex(RuntimeError, "previous promotion verification failed"):
            promote_loader(
                transaction,
                self.esp,
                backend=backend,
                verifier=lambda _path: None,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 2)
        self.assertEqual(backend.sync_count, before_sync + 1)
        self.assertFalse((transaction / "intent.json").exists())

    def test_rollback_before_promotion_is_byte_exact_and_idempotent(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertIsNone(backend.boot_next)
        self.assertEqual(
            backend.entries,
            {"0001": b"ubuntu fallback", "0002": b"windows fallback"},
        )
        self.assertEqual(backend.raw_boot_order, b"\x01\x00\x02\x00")
        self.assertEqual(backend.clear_boot_next_count, 1)
        self.assertEqual(backend.delete_entry_count, 1)

        status = loader_status(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        self.assertEqual(status.state, "rolled_back")
        self.assertEqual(
            json.loads((transaction / "manifest.json").read_text("ascii"))["state"],
            "rolled_back",
        )
        self.assertFalse((transaction / "intent.json").exists())

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.clear_boot_next_count, 1)
        self.assertEqual(backend.delete_entry_count, 1)

    def test_rollback_after_promotion_exchanges_back_and_is_byte_exact(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.exchange_count, 2)
        self.assertEqual(backend.raw_boot_order, b"\x01\x00\x02\x00")

    def test_rollback_uses_external_backup_when_old_slot_is_missing(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        (self.refind / "refind_x64_candidate.efi").unlink()

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.exchange_count, 1)

    def test_rollback_converges_after_post_exchange_error(self) -> None:
        before = self._esp_bytes()
        backend = FakeEfivars(exchange_error_after={2})
        transaction, backend = self._stage(backend)
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.exchange_count, 2)

    def test_rollback_recovers_stale_committed_intent_without_second_exchange(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        deploy._write_intent(
            transaction,
            "rollback",
            candidate_quarantine=(
                f".refind_x64_candidate.efi.rollback-{manifest['lock_key'][:16]}"
            ),
            restore_temporary=(
                f".refind_x64.efi.rollback-{manifest['lock_key'][:16]}"
            ),
        )
        backend.exchange(self.active, self.refind / "refind_x64_candidate.efi")
        self.assertEqual(backend.exchange_count, 2)
        before_sync = backend.sync_count

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.exchange_count, 2)
        self.assertEqual(backend.sync_count, before_sync + 1)

    def test_rollback_recovers_candidate_already_moved_to_recorded_quarantine(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        quarantine_name = (
            f".refind_x64_candidate.efi.rollback-{manifest['lock_key'][:16]}"
        )
        restore_name = f".refind_x64.efi.rollback-{manifest['lock_key'][:16]}"
        candidate_slot = self.refind / "refind_x64_candidate.efi"
        quarantine = self.refind / quarantine_name
        os.replace(candidate_slot, quarantine)
        deploy._write_intent(
            transaction,
            "rollback",
            candidate_quarantine=quarantine_name,
            restore_temporary=restore_name,
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertFalse(quarantine.exists())

    def test_rollback_preserves_matching_quarantine_without_intent(self) -> None:
        transaction, backend = self._stage()
        manifest_before = (transaction / "manifest.json").read_bytes()
        manifest = json.loads(manifest_before)
        quarantine_name = (
            f".refind_x64_candidate.efi.rollback-{manifest['lock_key'][:16]}"
        )
        candidate_slot = self.refind / "refind_x64_candidate.efi"
        quarantine = self.refind / quarantine_name
        os.replace(candidate_slot, quarantine)
        quarantine_bytes = quarantine.read_bytes()

        with self.assertRaisesRegex(
            RuntimeError, "rollback artifacts require matching rollback intent"
        ):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(quarantine.read_bytes(), quarantine_bytes)
        self.assertFalse(candidate_slot.exists())
        self.assertIn("00AF", backend.entries)
        self.assertEqual(backend.exchange_count, 0)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual((transaction / "manifest.json").read_bytes(), manifest_before)
        self.assertFalse((transaction / "intent.json").exists())

    def test_rollback_preserves_matching_restore_temp_without_intent(self) -> None:
        transaction, backend = self._stage()
        manifest_before = (transaction / "manifest.json").read_bytes()
        manifest = json.loads(manifest_before)
        restore_name = f".refind_x64.efi.rollback-{manifest['lock_key'][:16]}"
        restore_temp = self.refind / restore_name
        restore_temp.write_bytes(
            (transaction / "active" / "refind_x64.efi").read_bytes()
        )
        before = self._esp_bytes()

        with self.assertRaisesRegex(
            RuntimeError, "rollback artifacts require matching rollback intent"
        ):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(self._esp_bytes(), before)
        self.assertIn("00AF", backend.entries)
        self.assertEqual(backend.exchange_count, 0)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual((transaction / "manifest.json").read_bytes(), manifest_before)
        self.assertFalse((transaction / "intent.json").exists())

    def test_rollback_recovers_recorded_active_restore_temp(self) -> None:
        before = self._esp_bytes()
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        (self.refind / "refind_x64_candidate.efi").unlink()
        manifest = json.loads((transaction / "manifest.json").read_text("ascii"))
        quarantine_name = (
            f".refind_x64_candidate.efi.rollback-{manifest['lock_key'][:16]}"
        )
        restore_name = f".refind_x64.efi.rollback-{manifest['lock_key'][:16]}"
        restore_temp = self.refind / restore_name
        restore_temp.write_bytes(
            (transaction / "active" / "refind_x64.efi").read_bytes()
        )
        deploy._write_intent(
            transaction,
            "rollback",
            candidate_quarantine=quarantine_name,
            restore_temporary=restore_name,
        )

        rollback_loader(
            transaction,
            self.esp,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )

        self.assertEqual(self._esp_bytes(), before)
        self.assertFalse(restore_temp.exists())

    def test_rollback_preserves_foreign_candidate_replacement(self) -> None:
        transaction, backend = self._stage()
        candidate_slot = self.refind / "refind_x64_candidate.efi"
        candidate_slot.write_bytes(b"foreign candidate replacement")
        unrelated_before = {
            key: value
            for key, value in self._esp_bytes().items()
            if key != _CANDIDATE_TEST_PATH
        }

        with self.assertRaisesRegex(RuntimeError, "foreign candidate replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(candidate_slot.read_bytes(), b"foreign candidate replacement")
        self.assertIn("00AF", backend.entries)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual(
            {
                key: value
                for key, value in self._esp_bytes().items()
                if key != _CANDIDATE_TEST_PATH
            },
            unrelated_before,
        )

    def test_rollback_preserves_foreign_bootnext_and_entry(self) -> None:
        transaction, backend = self._stage()
        candidate_before = (self.refind / "refind_x64_candidate.efi").read_bytes()
        backend.boot_next = "DEAD"
        backend.entries["00AF"] = b"foreign entry replacement"

        with self.assertRaisesRegex(RuntimeError, "foreign NVRAM replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.boot_next, "DEAD")
        self.assertEqual(backend.entries["00AF"], b"foreign entry replacement")
        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual(backend.raw_boot_order, b"\x01\x00\x02\x00")
        self.assertEqual(
            (self.refind / "refind_x64_candidate.efi").read_bytes(),
            candidate_before,
        )

    def test_rollback_does_not_claim_unarmed_matching_bootnext(self) -> None:
        transaction, backend = self._stage()
        backend.boot_next = "00AF"

        with self.assertRaisesRegex(RuntimeError, "foreign NVRAM replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.boot_next, "00AF")
        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertIn("00AF", backend.entries)
        self.assertTrue((self.refind / "refind_x64_candidate.efi").exists())

    def test_rollback_preserves_same_number_bootnext_with_different_raw_attributes(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        backend.boot_next_attributes = b"\x03\0\0\0"

        with self.assertRaisesRegex(RuntimeError, "foreign NVRAM replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.boot_next, "00AF")
        self.assertEqual(backend.clear_boot_next_count, 0)

    def test_rollback_preserves_recreated_candidate_bootnext_after_promotion(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        backend.boot_next = None
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        backend.boot_current = "0001"
        backend.boot_next = "00AF"
        promoted_active = self.active.read_bytes()

        with self.assertRaisesRegex(RuntimeError, "foreign NVRAM replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.boot_next, "00AF")
        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertEqual(self.active.read_bytes(), promoted_active)

    def test_rollback_preflights_foreign_nvram_before_promoted_exchange(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        promoted_active = self.active.read_bytes()
        backend.entries["00AF"] = b"foreign raw replacement"

        with self.assertRaisesRegex(RuntimeError, "foreign NVRAM replacement"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(self.active.read_bytes(), promoted_active)

    def test_rollback_preflights_replaced_initial_entry_before_exchange(self) -> None:
        backend = FakeEfivars()
        backend.entries = {"0001": b"ubuntu fallback", "0002": b"windows fallback"}
        transaction, backend = self._stage(backend)
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        promoted_active = self.active.read_bytes()
        backend.entries["0001"] = b"foreign ubuntu replacement"

        with self.assertRaisesRegex(RuntimeError, "initial Boot entry ownership"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(self.active.read_bytes(), promoted_active)

    def test_rollback_preflights_refind_tree_drift_before_promoted_mutation(self) -> None:
        transaction, backend = self._stage()
        backend.boot_current = "00AF"
        promote_loader(
            transaction,
            self.esp,
            backend=backend,
            verifier=lambda _path: None,
            lock_root=self.lock_root,
            require_root=False,
        )
        candidate_slot = self.refind / "refind_x64_candidate.efi"
        self.active.parent.joinpath("refind.conf").write_bytes(b"foreign config drift")
        before = self._esp_bytes()
        manifest_before = (transaction / "manifest.json").read_bytes()

        with self.assertRaisesRegex(RuntimeError, "unrelated ESP drift before rollback"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(self._esp_bytes(), before)
        self.assertTrue(candidate_slot.exists())
        self.assertIn("00AF", backend.entries)
        self.assertEqual(backend.exchange_count, 1)
        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual((transaction / "manifest.json").read_bytes(), manifest_before)
        self.assertFalse((transaction / "intent.json").exists())

    def test_rollback_preflights_efi_tree_drift_before_armed_mutation(self) -> None:
        transaction, backend = self._stage()
        set_candidate_boot_next(
            transaction,
            backend=backend,
            lock_root=self.lock_root,
            require_root=False,
        )
        (self.esp / "EFI" / "ubuntu" / "shimx64.efi").write_bytes(
            b"foreign shim drift"
        )
        before = self._esp_bytes()
        manifest_before = (transaction / "manifest.json").read_bytes()

        with self.assertRaisesRegex(RuntimeError, "unrelated ESP drift before rollback"):
            rollback_loader(
                transaction,
                self.esp,
                backend=backend,
                lock_root=self.lock_root,
                require_root=False,
            )

        self.assertEqual(self._esp_bytes(), before)
        self.assertEqual(backend.boot_next, "00AF")
        self.assertIn("00AF", backend.entries)
        self.assertEqual(backend.exchange_count, 0)
        self.assertEqual(backend.clear_boot_next_count, 0)
        self.assertEqual(backend.delete_entry_count, 0)
        self.assertEqual((transaction / "manifest.json").read_bytes(), manifest_before)
        self.assertFalse((transaction / "intent.json").exists())


class RealBackendTests(unittest.TestCase):
    GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.efivars = self.root / "efivars"
        self.efivars.mkdir()
        self.attributes = b"\x07\x00\x00\x00"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _variable(
        self, name: str, data: bytes, *, attributes: bytes | None = None
    ) -> bytes:
        raw = (self.attributes if attributes is None else attributes) + data
        (self.efivars / f"{name}-{self.GUID}").write_bytes(raw)
        return raw

    def _load_option(
        self,
        identity: dict[str, object],
        path: str = r"\EFI\refind\refind_x64_candidate.efi",
    ) -> bytes:
        partition_guid = uuid.UUID(str(identity["partition_guid"])).bytes_le
        hard_drive = struct.pack(
            "<BBHIQQ16sBB",
            4,
            1,
            42,
            identity["partition_number"],
            identity["partition_start_lba"],
            identity["partition_size_lba"],
            partition_guid,
            2,
            2,
        )
        encoded_path = (path + "\0").encode("utf-16-le")
        file_path = struct.pack("<BBH", 4, 4, 4 + len(encoded_path)) + encoded_path
        end = b"\x7f\xff\x04\x00"
        device_path = hard_drive + file_path + end
        description = "rEFInd Forest candidate\0".encode("utf-16-le")
        load_option = struct.pack("<IH", 1, len(device_path))
        return self.attributes + load_option + description + device_path

    def _gpt_disk(
        self,
        path: Path,
        *,
        alias_backup_table: bool = False,
        usable_range: tuple[int, int] | None = None,
        zero_partition_guid: bool = False,
        zero_disk_guid: bool = False,
        protective_signature: bool = True,
        protective_type: int = 0xEE,
        protective_start_lba: int = 1,
        protective_size_lba: int | None = None,
        pmbr_boot_byte: int = 0,
    ) -> tuple[str, str]:
        sector_size = 512
        sectors = 10000
        entry_count = 128
        entry_size = 128
        table = bytearray(entry_count * entry_size)
        partition_guid = (
            uuid.UUID(int=0)
            if zero_partition_guid
            else uuid.UUID("11111111-2222-3333-4444-555555555555")
        )
        disk_guid = (
            uuid.UUID(int=0)
            if zero_disk_guid
            else uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        )
        offset = 6 * entry_size
        table[offset : offset + 16] = uuid.UUID(
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        ).bytes_le
        table[offset + 16 : offset + 32] = partition_guid.bytes_le
        struct.pack_into("<QQ", table, offset + 32, 2048, 6143)
        table_crc = zlib.crc32(table) & 0xFFFFFFFF

        def header(current: int, backup: int, entries_lba: int) -> bytes:
            value = bytearray(sector_size)
            value[:8] = b"EFI PART"
            struct.pack_into("<IIII", value, 8, 0x00010000, 92, 0, 0)
            first_usable, last_usable = usable_range or (34, sectors - 34)
            struct.pack_into(
                "<QQQQ", value, 24, current, backup, first_usable, last_usable
            )
            value[56:72] = disk_guid.bytes_le
            struct.pack_into(
                "<QIII", value, 72, entries_lba, entry_count, entry_size, table_crc
            )
            header_bytes = bytearray(value[:92])
            struct.pack_into("<I", header_bytes, 16, 0)
            struct.pack_into("<I", value, 16, zlib.crc32(header_bytes) & 0xFFFFFFFF)
            return bytes(value)

        disk = bytearray(sectors * sector_size)
        disk[0] = pmbr_boot_byte
        protective = bytearray(16)
        protective[1:4] = b"\x00\x02\x00"
        protective[4] = protective_type
        protective[5:8] = b"\xfe\xff\xff"
        struct.pack_into(
            "<II",
            protective,
            8,
            protective_start_lba,
            sectors - 1 if protective_size_lba is None else protective_size_lba,
        )
        disk[446:462] = protective
        if protective_signature:
            disk[510:512] = b"\x55\xaa"
        disk[sector_size : 2 * sector_size] = header(1, sectors - 1, 2)
        disk[2 * sector_size : 2 * sector_size + len(table)] = table
        backup_entries_lba = sectors - 33
        disk[
            backup_entries_lba * sector_size : backup_entries_lba * sector_size + len(table)
        ] = table
        disk[(sectors - 1) * sector_size :] = header(
            sectors - 1, 1, 2 if alias_backup_table else backup_entries_lba
        )
        path.write_bytes(disk)
        return str(partition_guid), str(disk_guid)

    def _identity_from_test_gpt(
        self, name: str, **gpt_options: object
    ) -> dict[str, object]:
        root = self.root / name
        sysfs_root = root / "sys" / "dev" / "block"
        disk_sysfs = root / "sys" / "devices" / "fakedisk"
        partition_sysfs = disk_sysfs / "fakedisk7"
        (disk_sysfs / "queue").mkdir(parents=True)
        partition_sysfs.mkdir()
        sysfs_root.mkdir(parents=True)
        (sysfs_root / "8:7").symlink_to(partition_sysfs)
        for path, value in (
            (partition_sysfs / "partition", "7\n"),
            (partition_sysfs / "start", "2048\n"),
            (partition_sysfs / "size", "4096\n"),
            (disk_sysfs / "dev", "8:0\n"),
            (disk_sysfs / "size", "10000\n"),
            (disk_sysfs / "queue" / "logical_block_size", "512\n"),
        ):
            path.write_text(value, "ascii")
        dev_root = root / "dev"
        dev_root.mkdir()
        self._gpt_disk(dev_root / "fakedisk", **gpt_options)
        return deploy._physical_esp_identity(
            SimpleNamespace(major_minor="8:7"),
            sysfs_root=sysfs_root,
            dev_root=dev_root,
            require_block=False,
        )

    def test_snapshot_decodes_data_but_preserves_complete_raw_blobs(self) -> None:
        raw_current = self._variable(
            "BootCurrent", b"\x34\x12", attributes=b"\x06\x00\x00\x00"
        )
        raw_next = self._variable("BootNext", b"\xef\xbe")
        raw_order = self._variable("BootOrder", b"\x34\x12\xef\xbe")
        raw_entry = self._variable("Boot1234", b"entry payload")

        snapshot = deploy._RealBackend(efivar_root=self.efivars).snapshot()

        self.assertEqual(snapshot["boot_current"], "1234")
        self.assertEqual(snapshot["boot_next"], "BEEF")
        self.assertEqual(snapshot["boot_order"], ("1234", "BEEF"))
        self.assertEqual(snapshot["raw_boot_current"], raw_current)
        self.assertEqual(snapshot["raw_boot_next"], raw_next)
        self.assertEqual(snapshot["raw_boot_order"], raw_order)
        self.assertEqual(snapshot["entries"], {"1234": raw_entry})

    def test_physical_identity_binds_sysfs_partition_and_checked_gpt(self) -> None:
        sysfs_root = self.root / "sys" / "dev" / "block"
        disk_sysfs = self.root / "sys" / "devices" / "fakedisk"
        partition_sysfs = disk_sysfs / "fakedisk7"
        (disk_sysfs / "queue").mkdir(parents=True)
        partition_sysfs.mkdir()
        sysfs_root.mkdir(parents=True)
        (sysfs_root / "8:7").symlink_to(partition_sysfs)
        (partition_sysfs / "partition").write_text("7\n", "ascii")
        (partition_sysfs / "start").write_text("2048\n", "ascii")
        (partition_sysfs / "size").write_text("4096\n", "ascii")
        (disk_sysfs / "dev").write_text("8:0\n", "ascii")
        (disk_sysfs / "size").write_text("10000\n", "ascii")
        (disk_sysfs / "queue" / "logical_block_size").write_text("512\n", "ascii")
        dev_root = self.root / "dev"
        dev_root.mkdir()
        partition_guid, disk_guid = self._gpt_disk(dev_root / "fakedisk")

        disk_mode = (dev_root / "fakedisk").stat().st_mode
        with mock.patch.object(
            deploy.os,
            "fstat",
            return_value=SimpleNamespace(st_mode=disk_mode, st_rdev=0, st_size=0),
        ):
            identity = deploy._physical_esp_identity(
                SimpleNamespace(major_minor="8:7"),
                sysfs_root=sysfs_root,
                dev_root=dev_root,
                require_block=False,
            )

        self.assertEqual(identity["disk"], str(dev_root / "fakedisk"))
        self.assertEqual(identity["disk_major_minor"], "8:0")
        self.assertEqual(identity["partition_number"], 7)
        self.assertEqual(identity["partition_guid"], partition_guid)
        self.assertEqual(identity["disk_guid"], disk_guid)
        self.assertEqual(identity["partition_start_lba"], 2048)
        self.assertEqual(identity["partition_size_lba"], 4096)
        self.assertEqual(identity["logical_sector_size"], 512)
        self.assertRegex(identity["gpt_sha256"], r"^[0-9a-f]{64}$")

    def test_physical_identity_rejects_zero_partition_guid(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "partition GUID is zero"):
            self._identity_from_test_gpt(
                "zero-partition-guid", zero_partition_guid=True
            )

    def test_physical_identity_rejects_zero_disk_guid(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "disk GUID is zero"):
            self._identity_from_test_gpt("zero-disk-guid", zero_disk_guid=True)

    def test_physical_identity_rejects_missing_protective_mbr_signature(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "protective MBR signature"):
            self._identity_from_test_gpt(
                "missing-pmbr-signature", protective_signature=False
            )

    def test_physical_identity_rejects_nonprotective_mbr_partition_type(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "protective MBR partition type"):
            self._identity_from_test_gpt(
                "wrong-pmbr-type", protective_type=0x83
            )

    def test_physical_identity_rejects_incomplete_protective_mbr_range(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "protective MBR range"):
            self._identity_from_test_gpt(
                "short-pmbr-range", protective_size_lba=9998
            )

    def test_physical_identity_hash_binds_protective_mbr_sector(self) -> None:
        first = self._identity_from_test_gpt("pmbr-hash-first")
        second = self._identity_from_test_gpt(
            "pmbr-hash-second", pmbr_boot_byte=0x5A
        )

        self.assertNotEqual(first["gpt_sha256"], second["gpt_sha256"])

    def test_resolve_esp_merges_fat_mount_and_stable_physical_identity(self) -> None:
        source = SimpleNamespace(major_minor="8:7")
        basic = SimpleNamespace(
            fat_uuid="1122-3344",
            label="ESP",
            mount_major_minor="8:7",
            mount_source="/dev/fakedisk7",
        )
        physical = {
            "disk": "/dev/fakedisk",
            "disk_major_minor": "8:0",
            "partition_number": 7,
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "disk_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "partition_start_lba": 2048,
            "partition_size_lba": 4096,
            "logical_sector_size": 512,
            "gpt_sha256": "a" * 64,
        }
        esp = self.root / "esp"
        esp.mkdir()
        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            physical_identity_reader=lambda _source: physical,
        )

        with mock.patch(
            "refind_forest.install._require_root", return_value=source
        ), mock.patch(
            "refind_forest.install._identity_for_mounted_source", return_value=basic
        ):
            resolved, identity = backend.resolve_esp(esp, require_root=True)

        self.assertEqual(resolved, esp)
        self.assertEqual(identity["fat_uuid"], "1122-3344")
        self.assertEqual(identity["mount_source"], "/dev/fakedisk7")
        self.assertEqual(identity["partition_guid"], physical["partition_guid"])
        self.assertEqual(identity["gpt_sha256"], "a" * 64)

    def test_physical_identity_rejects_backup_table_aliasing_primary(self) -> None:
        sysfs_root = self.root / "alias-sys" / "dev" / "block"
        disk_sysfs = self.root / "alias-sys" / "devices" / "fakedisk"
        partition_sysfs = disk_sysfs / "fakedisk7"
        (disk_sysfs / "queue").mkdir(parents=True)
        partition_sysfs.mkdir()
        sysfs_root.mkdir(parents=True)
        (sysfs_root / "8:7").symlink_to(partition_sysfs)
        for path, value in (
            (partition_sysfs / "partition", "7\n"),
            (partition_sysfs / "start", "2048\n"),
            (partition_sysfs / "size", "4096\n"),
            (disk_sysfs / "dev", "8:0\n"),
            (disk_sysfs / "size", "10000\n"),
            (disk_sysfs / "queue" / "logical_block_size", "512\n"),
        ):
            path.write_text(value, "ascii")
        dev_root = self.root / "alias-dev"
        dev_root.mkdir()
        self._gpt_disk(dev_root / "fakedisk", alias_backup_table=True)

        with self.assertRaisesRegex(RuntimeError, "GPT.*table.*layout|GPT.*alias"):
            deploy._physical_esp_identity(
                SimpleNamespace(major_minor="8:7"),
                sysfs_root=sysfs_root,
                dev_root=dev_root,
                require_block=False,
            )

    def test_physical_identity_rejects_partition_outside_usable_gpt_range(self) -> None:
        sysfs_root = self.root / "range-sys" / "dev" / "block"
        disk_sysfs = self.root / "range-sys" / "devices" / "fakedisk"
        partition_sysfs = disk_sysfs / "fakedisk7"
        (disk_sysfs / "queue").mkdir(parents=True)
        partition_sysfs.mkdir()
        sysfs_root.mkdir(parents=True)
        (sysfs_root / "8:7").symlink_to(partition_sysfs)
        for path, value in (
            (partition_sysfs / "partition", "7\n"),
            (partition_sysfs / "start", "2048\n"),
            (partition_sysfs / "size", "4096\n"),
            (disk_sysfs / "dev", "8:0\n"),
            (disk_sysfs / "size", "10000\n"),
            (disk_sysfs / "queue" / "logical_block_size", "512\n"),
        ):
            path.write_text(value, "ascii")
        dev_root = self.root / "range-dev"
        dev_root.mkdir()
        self._gpt_disk(dev_root / "fakedisk", usable_range=(7000, 9000))

        with self.assertRaisesRegex(RuntimeError, "outside.*usable GPT range"):
            deploy._physical_esp_identity(
                SimpleNamespace(major_minor="8:7"),
                sysfs_root=sysfs_root,
                dev_root=dev_root,
                require_block=False,
            )

    def test_snapshot_rejects_malformed_or_symlinked_variables(self) -> None:
        self._variable(
            "BootCurrent", b"\x01\x00", attributes=b"\x06\x00\x00\x00"
        )
        self._variable("BootOrder", b"\x01")
        with self.assertRaisesRegex(RuntimeError, "BootOrder.*invalid"):
            deploy._RealBackend(efivar_root=self.efivars).snapshot()

        (self.efivars / f"BootOrder-{self.GUID}").unlink()
        target = self.root / "order"
        target.write_bytes(self.attributes + b"\x01\x00")
        (self.efivars / f"BootOrder-{self.GUID}").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symbolic link"):
            deploy._RealBackend(efivar_root=self.efivars).snapshot()

    def test_snapshot_rejects_variable_specific_attribute_mismatch(self) -> None:
        self._variable("BootCurrent", b"\x01\x00")
        self._variable("BootOrder", b"\x01\x00")

        with self.assertRaisesRegex(RuntimeError, "BootCurrent.*attributes"):
            deploy._RealBackend(efivar_root=self.efivars).snapshot()

    def test_snapshot_rejects_lowercase_boot_entry_name(self) -> None:
        self._variable(
            "BootCurrent", b"\x01\x00", attributes=b"\x06\x00\x00\x00"
        )
        self._variable("BootOrder", b"\x01\x00")
        self._variable("Bootbeef", b"lowercase entry")

        with self.assertRaisesRegex(RuntimeError, "noncanonical Boot entry name"):
            deploy._RealBackend(efivar_root=self.efivars).snapshot()

    def test_snapshot_rejects_normalized_boot_entry_name_collision(self) -> None:
        self._variable(
            "BootCurrent", b"\x01\x00", attributes=b"\x06\x00\x00\x00"
        )
        self._variable("BootOrder", b"\x01\x00")
        canonical = self._variable("BootBEEF", b"canonical entry")
        lowercase = self._variable("Bootbeef", b"foreign lowercase entry")

        with self.assertRaisesRegex(RuntimeError, "Boot entry name collision"):
            deploy._RealBackend(efivar_root=self.efivars).snapshot()

        self.assertEqual(
            (self.efivars / f"BootBEEF-{self.GUID}").read_bytes(), canonical
        )
        self.assertEqual(
            (self.efivars / f"Bootbeef-{self.GUID}").read_bytes(), lowercase
        )

    def test_real_backend_creates_bootnext_atomically_without_overwrite(self) -> None:
        commands: list[list[str]] = []
        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            runner=lambda command, **_kwargs: commands.append(command),
        )

        backend.set_boot_next("BEEF")

        path = self.efivars / f"BootNext-{self.GUID}"
        expected = self.attributes + b"\xef\xbe"
        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(commands, [])

        with self.assertRaisesRegex(FileExistsError, "BootNext already exists"):
            backend.set_boot_next("CAFE")

        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(commands, [])

    def test_failed_bootnext_create_removes_its_exact_empty_inode(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        path = self.efivars / f"BootNext-{self.GUID}"

        with mock.patch.object(
            deploy.os,
            "write",
            side_effect=OSError(errno.EIO, "injected efivar write failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "create BootNext"):
                backend.set_boot_next("BEEF")

        self.assertFalse(os.path.lexists(path))

    def test_failed_bootnext_write_preserves_error_and_cleans_up_if_close_fails(
        self,
    ) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        path = self.efivars / f"BootNext-{self.GUID}"
        write_error = OSError(errno.EIO, "injected efivar write failure")
        real_close = os.close
        close_calls = 0

        def fail_first_close(descriptor: int) -> None:
            nonlocal close_calls
            close_calls += 1
            real_close(descriptor)
            if close_calls == 1:
                raise OSError(errno.EBADF, "injected close failure")

        with mock.patch.object(deploy.os, "write", side_effect=write_error), mock.patch.object(
            deploy.os, "close", side_effect=fail_first_close
        ):
            with self.assertRaisesRegex(RuntimeError, "create BootNext") as raised:
                backend.set_boot_next("BEEF")

        self.assertIs(raised.exception.__cause__, write_error)
        self.assertFalse(os.path.lexists(path))

    def test_failed_bootnext_create_preserves_a_replacement_path(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        path = self.efivars / f"BootNext-{self.GUID}"
        replacement = self.attributes + b"\xfe\xca"

        def replace_before_short_write(_descriptor: int, _raw: bytes) -> int:
            path.unlink()
            path.write_bytes(replacement)
            return 0

        with mock.patch.object(
            deploy.os, "write", side_effect=replace_before_short_write
        ):
            with self.assertRaisesRegex(RuntimeError, "complete BootNext"):
                backend.set_boot_next("BEEF")

        self.assertEqual(path.read_bytes(), replacement)

    def test_failed_bootnext_create_preserves_foreign_same_inode_bytes(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        path = self.efivars / f"BootNext-{self.GUID}"
        replacement = self.attributes + b"\xfe\xca"
        real_write = os.write

        def replace_before_short_write(descriptor: int, _raw: bytes) -> int:
            real_write(descriptor, replacement)
            return 0

        with mock.patch.object(
            deploy.os, "write", side_effect=replace_before_short_write
        ):
            with self.assertRaisesRegex(RuntimeError, "complete BootNext"):
                backend.set_boot_next("BEEF")

        self.assertEqual(path.read_bytes(), replacement)

    def test_real_backend_directly_unlinks_only_exact_owned_variables(self) -> None:
        commands: list[list[str]] = []
        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            runner=lambda command, **_kwargs: commands.append(command),
        )
        raw_next = self._variable("BootNext", b"\xef\xbe")
        raw_entry = self._variable("BootBEEF", b"owned entry")

        backend.clear_boot_next("BEEF", raw_next)
        backend.delete_entry("BEEF", raw_entry)

        self.assertFalse((self.efivars / f"BootNext-{self.GUID}").exists())
        self.assertFalse((self.efivars / f"BootBEEF-{self.GUID}").exists())
        self.assertEqual(commands, [])

    def test_real_backend_uses_create_only_and_exact_mutation_commands(self) -> None:
        commands: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
            commands.append(command)
            executable = Path(command[0]).name
            if executable == "efibootmgr" and command[1:] == ["-N"]:
                (self.efivars / f"BootNext-{self.GUID}").unlink()
            elif executable == "efibootmgr" and command[1:2] == ["-b"]:
                (self.efivars / f"Boot{command[2]}-{self.GUID}").unlink()
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        physical = {
            "disk": "/dev/fake-disk",
            "disk_major_minor": "8:0",
            "partition_number": 7,
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "disk_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "partition_start_lba": 2048,
            "partition_size_lba": 4096,
            "logical_sector_size": 512,
            "gpt_sha256": "a" * 64,
        }
        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            runner=runner,
            physical_identity_reader=lambda _source: physical,
        )
        identity = {
            "mount_major_minor": "8:7",
            **physical,
        }
        backend.create_only_entry(
            identity, r"\EFI\refind\refind_x64_candidate.efi"
        )
        backend.set_boot_next("BEEF")
        raw_next = (self.efivars / f"BootNext-{self.GUID}").read_bytes()
        backend.clear_boot_next("BEEF", raw_next)
        owned_entry = self._variable("BootBEEF", b"owned")
        backend.delete_entry("BEEF", owned_entry)
        active = self.root / "active.efi"
        candidate = self.root / "candidate.efi"
        backend.exchange(active, candidate)

        self.assertEqual(
            commands[0],
            [
                "/usr/bin/efibootmgr",
                "-C",
                "-d",
                "/dev/fake-disk",
                "-p",
                "7",
                "-L",
                "rEFInd Forest candidate",
                "-l",
                r"\EFI\refind\refind_x64_candidate.efi",
            ],
        )
        self.assertNotIn("-c", commands[0])
        self.assertNotIn("-g", commands[0])
        self.assertEqual(
            commands[1],
            [
                "/usr/bin/mv",
                "--exchange",
                "--no-copy",
                "-T",
                "--",
                str(active),
                str(candidate),
            ],
        )

    def test_real_backend_normalizes_runner_failure_with_check_disabled(self) -> None:
        runner_kwargs: dict[str, object] = {}

        def runner(_command: list[str], **kwargs: object) -> SimpleNamespace:
            runner_kwargs.update(kwargs)
            return SimpleNamespace(returncode=1, stdout="", stderr="injected failure")

        backend = deploy._RealBackend(efivar_root=self.efivars, runner=runner)

        with self.assertRaisesRegex(RuntimeError, "command failed"):
            backend.exchange(self.root / "active.efi", self.root / "candidate.efi")

        self.assertIs(runner_kwargs["check"], False)

    def test_real_backend_syncfs_uses_exposed_os_binding(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)

        with mock.patch.object(
            deploy.os, "open", return_value=71
        ) as opener, mock.patch.object(deploy.os, "close") as closer, mock.patch.object(
            deploy.os, "syncfs", create=True
        ) as syncfs:
            backend.syncfs(self.root)

        opener.assert_called_once_with(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        syncfs.assert_called_once_with(71)
        closer.assert_called_once_with(71)

    def test_real_backend_syncfs_falls_back_to_libc(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        libc_syncfs = mock.Mock(return_value=0)
        libc = SimpleNamespace(syncfs=libc_syncfs)

        with mock.patch.object(
            deploy.os, "open", return_value=72
        ), mock.patch.object(deploy.os, "close") as closer, mock.patch.object(
            deploy.os, "syncfs", None, create=True
        ), mock.patch.object(ctypes, "CDLL", return_value=libc) as load_libc:
            try:
                backend.syncfs(self.root)
            except (AttributeError, TypeError) as error:
                self.fail(f"libc syncfs fallback was not used: {error}")

        load_libc.assert_called_once_with(None, use_errno=True)
        libc_syncfs.assert_called_once_with(72)
        closer.assert_called_once_with(72)

    def test_real_backend_libc_syncfs_preserves_errno_if_close_fails(self) -> None:
        backend = deploy._RealBackend(efivar_root=self.efivars)
        libc_syncfs = mock.Mock(return_value=-1)
        libc = SimpleNamespace(syncfs=libc_syncfs)
        close_error = OSError(errno.EBADF, "injected close failure")
        caught: BaseException | None = None

        with mock.patch.object(
            deploy.os, "open", return_value=73
        ), mock.patch.object(
            deploy.os, "close", side_effect=close_error
        ) as closer, mock.patch.object(
            deploy.os, "syncfs", None, create=True
        ), mock.patch.object(
            ctypes, "CDLL", return_value=libc
        ), mock.patch.object(
            ctypes, "get_errno", return_value=errno.EIO
        ):
            try:
                backend.syncfs(self.root)
            except BaseException as error:
                caught = error

        self.assertIsInstance(caught, OSError)
        self.assertEqual(getattr(caught, "errno", None), errno.EIO)
        libc_syncfs.assert_called_once_with(73)
        closer.assert_called_once_with(73)

    def test_create_only_entry_revalidates_physical_identity_before_command(self) -> None:
        commands: list[list[str]] = []
        recorded = {
            "disk": "/dev/fake-disk",
            "disk_major_minor": "8:0",
            "partition_number": 7,
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "disk_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "partition_start_lba": 2048,
            "partition_size_lba": 4096,
            "logical_sector_size": 512,
            "gpt_sha256": "a" * 64,
        }
        rebound = {**recorded, "disk": "/dev/rebound-disk"}
        observed_sources: list[str] = []

        def reread(source: object) -> dict[str, object]:
            observed_sources.append(str(getattr(source, "major_minor")))
            return rebound

        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            runner=lambda command, **_kwargs: commands.append(command),
            physical_identity_reader=reread,
        )

        with self.assertRaisesRegex(RuntimeError, "physical ESP identity changed"):
            backend.create_only_entry(
                {"mount_major_minor": "8:7", **recorded},
                r"\EFI\refind\refind_x64_candidate.efi",
            )

        self.assertEqual(observed_sources, ["8:7"])
        self.assertEqual(commands, [])

    def test_real_backend_refuses_missing_or_foreign_owned_variables(self) -> None:
        commands: list[list[str]] = []
        backend = deploy._RealBackend(
            efivar_root=self.efivars,
            runner=lambda command, **_kwargs: commands.append(command),
        )

        with self.assertRaisesRegex(RuntimeError, "owned BootNext is missing"):
            backend.clear_boot_next("BEEF", b"missing")
        self._variable("BootNext", b"\x01\x00")
        with self.assertRaisesRegex(RuntimeError, "foreign BootNext"):
            backend.clear_boot_next("BEEF", b"foreign")
        with self.assertRaisesRegex(RuntimeError, "owned Boot entry is missing"):
            backend.delete_entry("BEEF", b"owned")
        self._variable("BootBEEF", b"foreign")
        with self.assertRaisesRegex(RuntimeError, "foreign Boot entry"):
            backend.delete_entry("BEEF", b"owned")

        self.assertEqual(commands, [])

    def test_entry_match_requires_active_exact_path_and_physical_partition(self) -> None:
        identity = {
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "partition_number": 7,
            "partition_start_lba": 2048,
            "partition_size_lba": 524288,
        }
        backend = deploy._RealBackend(efivar_root=self.efivars)
        raw = self._load_option(identity)

        self.assertTrue(
            backend.entry_matches(
                raw, identity, r"\EFI\refind\refind_x64_candidate.efi"
            )
        )
        self.assertFalse(
            backend.entry_matches(
                self._load_option(identity, r"\EFI\refind\refind_x64.efi"),
                identity,
                r"\EFI\refind\refind_x64_candidate.efi",
            )
        )
        wrong_identity = {**identity, "partition_number": 8}
        self.assertFalse(
            backend.entry_matches(
                raw,
                wrong_identity,
                r"\EFI\refind\refind_x64_candidate.efi",
            )
        )
        inactive = bytearray(raw)
        struct.pack_into("<I", inactive, 4, 0)
        self.assertFalse(
            backend.entry_matches(
                bytes(inactive),
                identity,
                r"\EFI\refind\refind_x64_candidate.efi",
            )
        )

    def test_entry_match_rejects_noncanonical_load_options(self) -> None:
        identity = {
            "partition_guid": "11111111-2222-3333-4444-555555555555",
            "partition_number": 7,
            "partition_start_lba": 2048,
            "partition_size_lba": 524288,
        }
        backend = deploy._RealBackend(efivar_root=self.efivars)
        canonical = self._load_option(identity)

        missing_end = bytearray(canonical[:-4])
        struct.pack_into("<H", missing_end, 8, struct.unpack_from("<H", canonical, 8)[0] - 4)
        optional_data = canonical + b"optional"
        wrong_attributes = bytearray(canonical)
        struct.pack_into("<I", wrong_attributes, 0, 3)
        invalid_description = bytearray(canonical)
        invalid_description[10:12] = b"\x00\xd8"

        for malformed in (
            bytes(missing_end),
            optional_data,
            bytes(wrong_attributes),
            bytes(invalid_description),
        ):
            with self.subTest(length=len(malformed), tail=malformed[-8:]):
                self.assertFalse(
                    backend.entry_matches(
                        malformed,
                        identity,
                        r"\EFI\refind\refind_x64_candidate.efi",
                    )
                )

        description_end = next(
            offset
            for offset in range(10, len(canonical) - 1, 2)
            if canonical[offset : offset + 2] == b"\0\0"
        )
        device_start = description_end + 2
        path_size = struct.unpack_from("<H", canonical, 8)[0]
        device = canonical[device_start : device_start + path_size]
        unterminated_device = bytearray(device)
        del unterminated_device[-6:-4]
        file_node_size = struct.unpack_from("<H", unterminated_device, 44)[0]
        struct.pack_into("<H", unterminated_device, 44, file_node_size - 2)
        unterminated = bytearray(canonical[:device_start] + unterminated_device)
        struct.pack_into("<H", unterminated, 8, len(unterminated_device))
        self.assertFalse(
            backend.entry_matches(
                bytes(unterminated),
                identity,
                r"\EFI\refind\refind_x64_candidate.efi",
            )
        )
        wrong_identity = {**identity, "partition_number": 8}
        wrong_hd = self._load_option(wrong_identity)
        wrong_description_end = next(
            offset
            for offset in range(10, len(wrong_hd) - 1, 2)
            if wrong_hd[offset : offset + 2] == b"\0\0"
        )
        wrong_device_start = wrong_description_end + 2
        wrong_device = wrong_hd[
            wrong_device_start : wrong_device_start + struct.unpack_from("<H", wrong_hd, 8)[0]
        ]
        multi_instance_device = (
            wrong_device[:-4]
            + b"\x7f\x01\x04\x00"
            + device[:42]
            + device[-4:]
        )
        multi = bytearray(canonical[:device_start] + multi_instance_device)
        struct.pack_into("<H", multi, 8, len(multi_instance_device))
        self.assertFalse(
            backend.entry_matches(
                bytes(multi),
                identity,
                r"\EFI\refind\refind_x64_candidate.efi",
            )
        )
    def test_default_verifier_checks_pe_sbat_and_signature_certificate(self) -> None:
        candidate = self.root / "candidate.efi"
        candidate.write_bytes(b"candidate")
        with mock.patch(
            "refind_forest.loader.verify.verify_pe"
        ) as verify_pe, mock.patch(
            "refind_forest.loader.verify.verify_signed"
        ) as verify_signed:
            deploy._default_verifier(candidate)

        expected_sbat = (
            Path(__file__).resolve().parents[1]
            / "assets"
            / "loader"
            / "refind-forest-sbat.csv"
        ).read_bytes()
        verify_pe.assert_called_once_with(candidate, expected_sbat)
        verify_signed.assert_called_once_with(
            candidate, Path("/etc/refind.d/keys/refind_local.crt")
        )


if __name__ == "__main__":
    unittest.main()

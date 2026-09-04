import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
import unicodedata
import uuid
import zipfile
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from kindle_jailbreak_lib.models import DeviceInfo, Stage
from kindle_jailbreak_lib.progress import ProgressEvent
from kindle_jailbreak_lib.routing import MethodPolicy
from kindle_jailbreak_lib.session import SessionStore
from kindle_jailbreak_lib.storage import (
    StorageError,
    assert_safe_root,
    backup_visible_storage,
    cleanup_created_files as _cleanup_created_files,
    fill_storage as _fill_storage,
    inspect_archive,
    stage_archive as _stage_archive,
    verify_manifest,
)


MIB = 1024 * 1024


def _grant_test_write(store: SessionStore) -> str:
    state = store.load()
    key = f"write_once:test:{uuid.uuid4().hex}"
    state.approvals[key] = True
    store.save(state)
    return key


def fill_storage(device, store, policy, **kwargs):
    return _fill_storage(
        device,
        store,
        policy,
        authorization_key=_grant_test_write(store),
        **kwargs,
    )


def stage_archive(archive, device, store, policy, **kwargs):
    return _stage_archive(
        archive,
        device,
        store,
        policy,
        authorization_key=_grant_test_write(store),
        **kwargs,
    )


def cleanup_created_files(device, store, **kwargs):
    return _cleanup_created_files(
        device,
        store,
        authorization_key=_grant_test_write(store),
        **kwargs,
    )


class StorageTest(unittest.TestCase):
    def _make_kindle(self, base: Path) -> Path:
        kindle = base / "kindle"
        (kindle / "documents").mkdir(parents=True)
        return kindle

    def _make_session(self, base: Path, kindle: Path) -> tuple[SessionStore, DeviceInfo]:
        device = DeviceInfo(
            transport="usbms",
            root=str(kindle),
            serial="G090TESTDEVICE001",
            model="PW3",
            firmware="5.16.2.1.1",
            read_only=False,
            free_bytes=512 * 1024 * 1024,
        )
        store = SessionStore(base / "session")
        state = store.create(device)
        store.save(state)
        return store, device

    def _policy(self, *, filler: str = "required-by-guide") -> MethodPolicy:
        return MethodPolicy(
            automation="guided-assets",
            generic_filler=filler,
            forbid_nearest_firmware=True,
            separate_approval=(),
        )

    def _write_zip(self, archive: Path, files: dict[str, bytes]) -> None:
        with zipfile.ZipFile(archive, "w") as bundle:
            for name, content in files.items():
                bundle.writestr(name, content)

    def _write_created_journal(
        self,
        store: SessionStore,
        kindle: Path,
        entries: list[dict[str, object]],
    ) -> None:
        state = store.load()
        normalized_entries: list[dict[str, object]] = []
        for source_entry in entries:
            entry = dict(source_entry)
            target = kindle / str(entry["path"])
            if (
                entry.get("state") in {"created", "deleting"}
                and "created_identity" not in entry
                and target.exists()
                and not target.is_symlink()
            ):
                metadata = target.stat()
                entry["created_identity"] = {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IFMT(metadata.st_mode),
                    "modified_ns": metadata.st_mtime_ns,
                    "changed_ns": metadata.st_ctime_ns,
                }
            normalized_entries.append(entry)
        (store.root / "created-files.json").write_text(
            json.dumps({
                "schema_version": 1,
                "session_id": state.session_id,
                "device_fingerprint": state.device_fingerprint,
                "device_root": str(kindle.resolve()),
                "entries": normalized_entries,
            }),
            encoding="utf-8",
        )

    def test_unsafe_roots_and_missing_kindle_marker_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            unmarked = Path(tmp) / "ordinary-directory"
            unmarked.mkdir()
            for unsafe in (Path("/"), Path.home(), Path("/System"), unmarked):
                with self.subTest(root=unsafe):
                    with self.assertRaises(ValueError):
                        assert_safe_root(unsafe)

    def test_public_errors_have_stable_codes_and_chinese_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "unsafe.zip"
            self._write_zip(archive, {"../escaped.txt": b"unsafe"})
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            cases = (
                ("KJA_UNSAFE_ROOT", lambda: assert_safe_root(Path("/"))),
                (
                    "KJA_UNSAFE_PATH",
                    lambda: inspect_archive(archive, base / "staging"),
                ),
                (
                    "KJA_POLICY_DENIED",
                    lambda: fill_storage(
                        device,
                        store,
                        self._policy(filler="forbidden"),
                        device_probe=lambda: device,
                        chunk_bytes=4096,
                        free_space=lambda _root: 80 * MIB + 4096,
                    ),
                ),
            )

            for code, operation in cases:
                with self.subTest(code=code):
                    with self.assertRaises(StorageError) as caught:
                        operation()
                    self.assertEqual(getattr(caught.exception, "code", None), code)
                    self.assertRegex(str(caught.exception), r"[\u4e00-\u9fff]")

    def test_public_write_api_rejects_legacy_persistent_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            state = store.load()
            state.approvals["write_authorization"] = True
            store.save(state)

            with self.assertRaises(StorageError) as caught:
                _fill_storage(
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    chunk_bytes=4096,
                    free_space=lambda _root: 80 * MIB + 4096,
                    authorization_key=None,
                )

            self.assertEqual(caught.exception.code, "KJA_WRITE_NOT_AUTHORIZED")
            self.assertFalse(any(kindle.glob(".kja-fill-*")))
            self.assertIs(store.load().approvals["write_authorization"], True)

    def test_archive_rejects_parent_traversal_before_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "payload.zip"
            staging = base / "staging"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escaped.txt", "unsafe")

            with self.assertRaises(ValueError):
                inspect_archive(archive, staging)

            self.assertFalse((base / "escaped.txt").exists())
            self.assertFalse(staging.exists())

    def test_archive_rejects_dot_path_segment_before_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "payload.zip"
            staging = base / "staging"
            self._write_zip(archive, {"safe/./payload.bin": b"unsafe-name"})

            with self.assertRaises(ValueError):
                inspect_archive(
                    archive,
                    staging,
                    required_files=("safe/./payload.bin",),
                )

            self.assertFalse(staging.exists())

    def test_archive_rejects_absolute_paths_links_and_missing_required_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cases: list[tuple[str, Path]] = []

            zip_absolute = base / "zip-absolute.zip"
            self._write_zip(zip_absolute, {"/absolute.txt": b"unsafe"})
            cases.append(("zip absolute", zip_absolute))

            zip_windows_absolute = base / "zip-windows-absolute.zip"
            self._write_zip(zip_windows_absolute, {"C:\\escaped.txt": b"unsafe"})
            cases.append(("zip Windows absolute", zip_windows_absolute))

            zip_link = base / "zip-link.zip"
            with zipfile.ZipFile(zip_link, "w") as bundle:
                member = zipfile.ZipInfo("outside-link")
                member.create_system = 3
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(member, "../../outside")
            cases.append(("zip symlink", zip_link))

            tar_absolute = base / "tar-absolute.tar"
            with tarfile.open(tar_absolute, "w") as bundle:
                member = tarfile.TarInfo("/absolute.txt")
                member.size = 6
                bundle.addfile(member, io.BytesIO(b"unsafe"))
            cases.append(("tar absolute", tar_absolute))

            tar_parent = base / "tar-parent.tar"
            with tarfile.open(tar_parent, "w") as bundle:
                member = tarfile.TarInfo("../escaped.txt")
                member.size = 6
                bundle.addfile(member, io.BytesIO(b"unsafe"))
            cases.append(("tar parent", tar_parent))

            tar_link = base / "tar-link.tar"
            with tarfile.open(tar_link, "w") as bundle:
                member = tarfile.TarInfo("outside-link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                bundle.addfile(member)
            cases.append(("tar symlink", tar_link))

            missing_required = base / "missing-required.zip"
            self._write_zip(missing_required, {"other.txt": b"safe"})
            cases.append(("missing required", missing_required))

            for index, (label, archive) in enumerate(cases):
                staging = base / f"staging-{index}"
                with self.subTest(case=label):
                    with self.assertRaises(ValueError):
                        inspect_archive(
                            archive,
                            staging,
                            required_files=("payload.bin",),
                        )
                    self.assertFalse(staging.exists())

    def test_backup_is_read_only_and_checksum_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            (kindle / "documents" / "book.txt").write_bytes(b"book-data")
            (kindle / ".kindle-hidden").write_bytes(b"keep-hidden")
            (kindle / ".Trashes").mkdir()
            (kindle / ".Trashes" / "host-trash").write_bytes(b"skip")
            source_before = {
                path.relative_to(kindle).as_posix(): path.read_bytes()
                for path in kindle.rglob("*")
                if path.is_file()
            }
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=True,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            events: list[ProgressEvent] = []

            backup = backup_visible_storage(
                device,
                base / "backups",
                session_store=store,
                timestamp="20260903T120000Z",
                progress=events.append,
            )

            self.assertEqual(backup.name, "20260903T120000Z")
            content = backup / "content"
            self.assertEqual((content / "documents" / "book.txt").read_bytes(), b"book-data")
            self.assertEqual((content / ".kindle-hidden").read_bytes(), b"keep-hidden")
            self.assertFalse((content / ".Trashes").exists())
            manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
            book_entry = next(
                item for item in manifest["entries"] if item["path"] == "documents/book.txt"
            )
            self.assertEqual(
                set(book_entry), {"path", "type", "size", "sha256"}
            )
            self.assertEqual(book_entry["type"], "file")
            self.assertEqual(book_entry["size"], len(b"book-data"))
            self.assertRegex(book_entry["sha256"], r"^[0-9a-f]{64}$")
            verify_manifest(kindle, backup)
            source_after = {
                path.relative_to(kindle).as_posix(): path.read_bytes()
                for path in kindle.rglob("*")
                if path.is_file()
            }
            self.assertEqual(source_after, source_before)
            self.assertTrue(events)
            self.assertTrue(all(isinstance(event, ProgressEvent) for event in events))

            changed = bytearray((content / "documents" / "book.txt").read_bytes())
            changed[0] ^= 1
            (content / "documents" / "book.txt").write_bytes(changed)
            with self.assertRaises(ValueError):
                verify_manifest(kindle, backup)

    def test_backup_refuses_to_overwrite_existing_timestamp_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            (kindle / "documents" / "book.txt").write_bytes(b"book")
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=False,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            existing = base / "backups" / "20260903T120000Z"
            existing.mkdir(parents=True)
            marker = existing / "keep.txt"
            marker.write_bytes(b"do-not-overwrite")

            with self.assertRaises(ValueError):
                backup_visible_storage(
                    device,
                    base / "backups",
                    session_store=store,
                    timestamp="20260903T120000Z",
                )

            self.assertEqual(marker.read_bytes(), b"do-not-overwrite")

    def test_backup_source_swap_never_copies_outside_root_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            source = kindle / "documents" / "book.txt"
            source.write_bytes(b"inside")
            outside = base / "outside-secret.txt"
            outside.write_bytes(b"outside-secret")
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=True,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            from kindle_jailbreak_lib import storage_safety
            original_open = storage_safety.os.open
            swapped = False
            source_open_count = 0

            def swap_before_source_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped, source_open_count
                if path == "book.txt" and dir_fd is not None and not flags & os.O_CREAT:
                    source_open_count += 1
                if source_open_count == 2 and not swapped:
                    source.unlink()
                    source.symlink_to(outside)
                    swapped = True
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.os.open",
                side_effect=swap_before_source_open,
            ):
                try:
                    backup_visible_storage(
                        device,
                        base / "backups",
                        session_store=store,
                        timestamp="20260903T120001Z",
                    )
                except (OSError, ValueError):
                    pass

            copied = [
                path.read_bytes()
                for path in (base / "backups").rglob("*")
                if path.is_file()
            ]
            self.assertTrue(swapped)
            self.assertNotIn(b"outside-secret", copied)

    def test_backup_interruption_resumes_only_same_session_then_publishes_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            (kindle / "documents" / "one.txt").write_bytes(b"one")
            (kindle / "documents" / "two.txt").write_bytes(b"two")
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=True,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            from kindle_jailbreak_lib import storage_safety

            original_copy = storage_safety.copy_file_exclusive
            copy_count = 0

            def interrupt_second_copy(*args, **kwargs):
                nonlocal copy_count
                copy_count += 1
                if copy_count == 2:
                    raise OSError("simulated backup interruption")
                return original_copy(*args, **kwargs)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.copy_file_exclusive",
                side_effect=interrupt_second_copy,
            ):
                with self.assertRaises((OSError, ValueError)):
                    backup_visible_storage(
                        device,
                        base / "backups",
                        session_store=store,
                        timestamp="20260903T120002Z",
                    )

            final = base / "backups" / "20260903T120002Z"
            partials = list((base / "backups").glob(".*.partial"))
            self.assertFalse(final.exists())
            self.assertEqual(len(partials), 1)
            status = json.loads(
                (partials[0] / "backup-status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(status["session_id"], store.load().session_id)
            self.assertEqual(status["state"], "copying")

            other_store = SessionStore(base / "other-session")
            other_store.create(device)
            with self.assertRaises(ValueError):
                backup_visible_storage(
                    device,
                    base / "backups",
                    session_store=other_store,
                    timestamp="20260903T120002Z",
                )

            published = backup_visible_storage(
                device,
                base / "backups",
                session_store=store,
                timestamp="20260903T120002Z",
            )
            self.assertEqual(published, final.resolve())
            self.assertFalse(partials[0].exists())
            completion = json.loads(
                (published / "backup-complete.json").read_text(encoding="utf-8")
            )
            self.assertEqual(completion["state"], "complete")
            self.assertEqual(
                (published / "content" / "documents" / "one.txt").read_bytes(),
                b"one",
            )
            with self.assertRaises(ValueError):
                backup_visible_storage(
                    device,
                    base / "backups",
                    session_store=store,
                    timestamp="20260903T120002Z",
                )

    def test_backup_resumes_file_interrupted_after_prefix_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            expected = b"prefix-and-the-rest-of-the-file"
            (kindle / "documents" / "book.bin").write_bytes(expected)
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=True,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            from kindle_jailbreak_lib import storage_safety

            interrupted = False

            def write_prefix_then_interrupt(
                source_root,
                source_entry,
                destination_root,
                destination_relative,
            ):
                nonlocal interrupted
                with storage_safety.open_snapshot(source_root, source_entry) as source:
                    with storage_safety.create_file_exclusive(
                        destination_root, destination_relative
                    ) as destination:
                        destination.write(source.read(7))
                        destination.flush()
                        os.fsync(destination.fileno())
                interrupted = True
                raise OSError("simulated mid-file interruption")

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.copy_file_exclusive",
                side_effect=write_prefix_then_interrupt,
            ):
                with self.assertRaises(ValueError):
                    backup_visible_storage(
                        device,
                        base / "backups",
                        session_store=store,
                        timestamp="20260903T120003Z",
                    )

            self.assertTrue(interrupted)
            self.assertFalse((base / "backups" / "20260903T120003Z").exists())

            published = backup_visible_storage(
                device,
                base / "backups",
                session_store=store,
                timestamp="20260903T120003Z",
            )

            self.assertEqual(
                (published / "content" / "documents" / "book.bin").read_bytes(),
                expected,
            )
            verify_manifest(kindle, published)

    def test_backup_publication_race_preserves_concurrent_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            (kindle / "documents" / "book.bin").write_bytes(b"payload")
            device = DeviceInfo(
                transport="usbms",
                root=str(kindle),
                serial="G090TESTDEVICE001",
                model="PW3",
                firmware="5.16.2.1.1",
                read_only=True,
                free_bytes=512 * MIB,
            )
            store = SessionStore(base / "session")
            store.create(device)
            from kindle_jailbreak_lib import storage_backup

            original_publish = storage_backup._publish_no_replace
            raced = False
            concurrent_inode: int | None = None

            def create_destination_before_publish(source: Path, destination: Path):
                nonlocal raced, concurrent_inode
                destination.mkdir()
                concurrent_inode = destination.stat().st_ino
                raced = True
                return original_publish(source, destination)

            with mock.patch(
                "kindle_jailbreak_lib.storage_backup._publish_no_replace",
                side_effect=create_destination_before_publish,
            ):
                with self.assertRaises(ValueError):
                    backup_visible_storage(
                        device,
                        base / "backups",
                        session_store=store,
                        timestamp="20260903T120004Z",
                    )

            destination = base / "backups" / "20260903T120004Z"
            self.assertTrue(raced)
            self.assertEqual(destination.stat().st_ino, concurrent_inode)
            self.assertEqual(list(destination.iterdir()), [])

    def test_fill_refuses_springbreak_and_unsafe_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)

            with self.assertRaises(ValueError):
                fill_storage(
                    device,
                    store,
                    self._policy(filler="forbidden"),
                    device_probe=lambda: device,
                    chunk_bytes=4096,
                    free_space=lambda _root: 80 * MIB + 4096,
                )
            self.assertFalse(any(kindle.glob(".kja-fill-*")))

            unsafe = base / "not-a-kindle"
            unsafe.mkdir()
            unsafe_device = DeviceInfo(
                transport="usbms",
                root=str(unsafe),
                serial=device.serial,
                model=device.model,
                firmware=device.firmware,
                read_only=False,
                free_bytes=device.free_bytes,
            )
            with self.assertRaises(ValueError):
                fill_storage(
                    unsafe_device,
                    store,
                    self._policy(),
                    device_probe=lambda: unsafe_device,
                    chunk_bytes=4096,
                    free_space=lambda _root: 80 * MIB + 4096,
                )
            self.assertEqual(list(unsafe.iterdir()), [])

    def test_write_rejects_different_full_serial_with_same_public_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, original = self._make_session(base, kindle)
            impostor = DeviceInfo(
                transport=original.transport,
                root=original.root,
                serial="OTHER-DEVICE-E001",
                model=original.model,
                firmware=original.firmware,
                read_only=False,
                free_bytes=original.free_bytes,
            )

            with self.assertRaises(ValueError):
                fill_storage(
                    impostor,
                    store,
                    self._policy(),
                    device_probe=lambda: impostor,
                    chunk_bytes=4096,
                    free_space=lambda _root: 80 * MIB,
                )

            self.assertFalse(any(kindle.glob(".kja-fill-*")))

    def test_fill_writes_real_zero_chunks_and_keeps_eighty_mibibytes_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            chunk_bytes = 4096
            initial_free = 80 * MIB + 2 * chunk_bytes
            events: list[ProgressEvent] = []

            def simulated_free(_root) -> int:
                used = sum(
                    path.stat().st_size
                    for path in kindle.glob(".kja-fill-*/*")
                    if path.is_file()
                )
                return initial_free - used

            created = fill_storage(
                device,
                store,
                self._policy(),
                device_probe=lambda: device,
                chunk_bytes=chunk_bytes,
                free_space=simulated_free,
                progress=events.append,
            )

            self.assertEqual(len(created), 2)
            self.assertEqual(simulated_free(kindle), 80 * MIB)
            self.assertTrue(all(path.read_bytes() == bytes(chunk_bytes) for path in created))
            state = store.load()
            self.assertTrue(
                all(
                    path.relative_to(kindle.resolve()).as_posix() in state.created_files
                    for path in created
                )
            )
            created_manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            self.assertEqual(created_manifest["session_id"], state.session_id)
            self.assertEqual(
                [entry["path"] for entry in created_manifest["entries"] if entry["type"] == "file"],
                [path.relative_to(kindle.resolve()).as_posix() for path in created],
            )
            self.assertTrue(events)
            self.assertEqual(events[-1].stage, Stage.PREPARE)

    def test_fill_uses_retained_root_capacity_after_lexical_root_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            original_root = base / "original-kindle"
            replacement_root = self._make_kindle(base / "replacement")
            chunk_bytes = 4096
            initial_free = 80 * MIB + chunk_bytes
            swapped = False
            probed_inodes: list[int] = []

            def retained_free(root) -> int:
                nonlocal swapped
                probed_inodes.append(root.inode)
                if not swapped:
                    kindle.rename(original_root)
                    kindle.symlink_to(replacement_root, target_is_directory=True)
                    swapped = True
                used = sum(
                    path.stat().st_size
                    for path in original_root.glob(".kja-fill-*/*.bin")
                    if path.is_file()
                )
                return initial_free - used

            with self.assertRaises(ValueError):
                fill_storage(
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    chunk_bytes=chunk_bytes,
                    free_space=retained_free,
                )

            self.assertTrue(swapped)
            self.assertTrue(probed_inodes)
            self.assertEqual(len(set(probed_inodes)), 1)
            written = sum(
                path.stat().st_size
                for path in original_root.glob(".kja-fill-*/*.bin")
            )
            self.assertEqual(written, chunk_bytes)
            self.assertFalse(any(replacement_root.glob(".kja-fill-*")))
            self.assertEqual(initial_free - written, 80 * MIB)

    def test_posix_retained_capacity_uses_fstatvfs_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            from kindle_jailbreak_lib import storage_safety

            seen: list[int] = []

            def fake_fstatvfs(descriptor: int):
                seen.append(descriptor)
                return SimpleNamespace(f_bavail=7, f_frsize=4096)

            with storage_safety.retain_safe_root(kindle) as retained:
                with mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.fstatvfs",
                    side_effect=fake_fstatvfs,
                ):
                    available = storage_safety.retained_free_bytes(retained)

                self.assertEqual(seen, [retained.descriptor])
                self.assertEqual(available, 7 * 4096)

    def test_fill_io_error_records_partial_file_and_enters_recoverable_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)

            with mock.patch(
                "kindle_jailbreak_lib.storage_payload._write_zeros",
                side_effect=OSError("simulated full disk"),
            ):
                with self.assertRaises(ValueError) as caught:
                    fill_storage(
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        chunk_bytes=4096,
                        free_space=lambda _root: 80 * MIB + 4096,
                    )
                self.assertEqual(getattr(caught.exception, "code", None), "KJA_FILL_FAILED")
                self.assertIsInstance(caught.exception.__cause__, OSError)

            state = store.load()
            self.assertEqual(state.stage, Stage.RECOVERABLE_ERROR)
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            file_entries = [entry for entry in manifest["entries"] if entry["type"] == "file"]
            self.assertEqual(len(file_entries), 1)
            self.assertTrue((kindle / file_entries[0]["path"]).exists())

    def test_fill_journal_failure_before_create_leaves_no_device_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            original_replace = os.replace

            def fail_first_journal_replace(source, destination):
                if Path(destination).name == "created-files.json":
                    raise OSError("simulated journal failure before create")
                return original_replace(source, destination)

            with mock.patch("os.replace", side_effect=fail_first_journal_replace):
                with self.assertRaises((OSError, ValueError)):
                    fill_storage(
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        chunk_bytes=4096,
                        free_space=lambda _root: 80 * MIB + 4096,
                    )

            self.assertFalse(any(kindle.glob(".kja-fill-*")))

    def test_fill_journal_failure_after_create_keeps_pending_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            original_replace = os.replace

            def fail_created_transition(source, destination):
                if (
                    Path(destination).name == "created-files.json"
                    and any(kindle.glob(".kja-fill-*/*.bin"))
                ):
                    raise OSError("simulated journal failure after create")
                return original_replace(source, destination)

            with mock.patch("os.replace", side_effect=fail_created_transition):
                with self.assertRaises((OSError, ValueError)):
                    fill_storage(
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        chunk_bytes=4096,
                        free_space=lambda _root: 80 * MIB + 4096,
                    )

            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            file_entries = [entry for entry in manifest["entries"] if entry["type"] == "file"]
            self.assertEqual(len(file_entries), 1)
            self.assertEqual(file_entries[0]["state"], "pending_create")
            self.assertTrue((kindle / file_entries[0]["path"]).exists())

    def test_stage_verifies_payload_and_only_removes_new_target_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload/payload.bin": b"verified-payload"})
            unrelated_sidecar = kindle / "._user-file"
            unrelated_sidecar.write_bytes(b"keep")
            original_copy = __import__(
                "kindle_jailbreak_lib.storage_safety", fromlist=["copy_file_exclusive"]
            ).copy_file_exclusive

            def copy_with_sidecar(source_root, source, destination_root, destination_relative):
                result = original_copy(
                    source_root, source, destination_root, destination_relative
                )
                destination_base = getattr(destination_root, "path", destination_root)
                destination = destination_base / destination_relative
                destination.with_name(f"._{destination.name}").write_bytes(b"host-sidecar")
                return result

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.copy_file_exclusive",
                side_effect=copy_with_sidecar,
            ):
                created = stage_archive(
                    archive,
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    required_files=("payload/payload.bin",),
                )

            payload = kindle.resolve() / "payload" / "payload.bin"
            self.assertIn(payload, created)
            self.assertEqual(payload.read_bytes(), b"verified-payload")
            self.assertFalse((kindle / "payload" / "._payload.bin").exists())
            self.assertEqual(unrelated_sidecar.read_bytes(), b"keep")

    def test_stage_refuses_preexisting_destination_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"documents/user-book.txt": b"replacement"})
            existing = kindle / "documents" / "user-book.txt"
            existing.write_bytes(b"user-content")

            with self.assertRaises(ValueError):
                stage_archive(
                    archive,
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    required_files=("documents/user-book.txt",),
                )

            self.assertEqual(existing.read_bytes(), b"user-content")
            self.assertFalse((store.root / "created-files.json").exists())

    def test_stage_fat32_preflight_rejects_illegal_names_without_partial_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for index, name in enumerate(("bad?.bin", "CON.txt", "trailing. ", "bad\x1f.bin")):
                case = base / f"case-{index}"
                kindle = self._make_kindle(case)
                store, device = self._make_session(case, kindle)
                archive = case / "payload.zip"
                self._write_zip(archive, {name: b"payload"})

                with self.subTest(name=repr(name)):
                    with self.assertRaises(ValueError):
                        stage_archive(
                            archive,
                            device,
                            store,
                            self._policy(),
                            device_probe=lambda: device,
                            required_files=(name,),
                        )
                    self.assertEqual(
                        sorted(path.name for path in kindle.iterdir()),
                        ["documents"],
                    )
                    self.assertFalse((store.root / "created-files.json").exists())

    def test_stage_fat32_preflight_rejects_casefold_and_nfc_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            collisions = (
                ("Payload.bin", "payload.bin"),
                ("caf\u00e9.bin", unicodedata.normalize("NFD", "caf\u00e9.bin")),
            )
            for index, names in enumerate(collisions):
                case = base / f"collision-{index}"
                kindle = self._make_kindle(case)
                store, device = self._make_session(case, kindle)
                archive = case / "payload.zip"
                self._write_zip(archive, {names[0]: b"one", names[1]: b"two"})

                with self.subTest(names=names):
                    with self.assertRaises(ValueError):
                        stage_archive(
                            archive,
                            device,
                            store,
                            self._policy(),
                            device_probe=lambda: device,
                            required_files=(names[0],),
                        )
                    self.assertFalse((store.root / "created-files.json").exists())

    def test_stage_fat32_preflight_rejects_large_file_and_low_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)

            large_case = base / "large"
            kindle = self._make_kindle(large_case)
            store, device = self._make_session(large_case, kindle)
            archive = large_case / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"small"})
            from kindle_jailbreak_lib import storage_safety

            original_scan = storage_safety.scan_tree

            def report_oversized_file(root: Path, **kwargs):
                entries = original_scan(root, **kwargs)
                if Path(root).name == "extracted":
                    return [
                        replace(entry, size=0x1_0000_0000)
                        if entry.kind == "file"
                        else entry
                        for entry in entries
                    ]
                return entries

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.scan_tree",
                side_effect=report_oversized_file,
            ):
                with self.assertRaises(ValueError):
                    stage_archive(
                        archive,
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        required_files=("payload.bin",),
                    )
            self.assertFalse((kindle / "payload.bin").exists())
            self.assertFalse((store.root / "created-files.json").exists())

            capacity_case = base / "capacity"
            kindle = self._make_kindle(capacity_case)
            store, device = self._make_session(capacity_case, kindle)
            archive = capacity_case / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"payload"})
            with self.assertRaises(ValueError):
                stage_archive(
                    archive,
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    required_files=("payload.bin",),
                    free_space=lambda _root: 80 * MIB + len(b"payload") - 1,
                )
            self.assertFalse((kindle / "payload.bin").exists())
            self.assertFalse((store.root / "created-files.json").exists())

    def test_stage_rejects_in_root_directory_symlink_without_touching_user_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload/owned.bin": b"payload"})
            (kindle / "payload").symlink_to(kindle / "documents", target_is_directory=True)

            with self.assertRaises(ValueError):
                stage_archive(
                    archive,
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: device,
                    required_files=("payload/owned.bin",),
                )

            self.assertFalse((kindle / "documents" / "owned.bin").exists())
            self.assertTrue((kindle / "payload").is_symlink())

    def test_stage_destination_swap_never_overwrites_user_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"payload"})
            destination = kindle.resolve() / "payload.bin"
            user_file = kindle / "documents" / "user-book.txt"
            user_file.write_bytes(b"user-content")
            from kindle_jailbreak_lib import storage_safety
            original_open = storage_safety._open_file_descriptor
            swapped = False

            def swap_before_destination_open(name, flags, parent_fd, mode=0o600):
                nonlocal swapped
                if name == "payload.bin" and flags & os.O_CREAT and not swapped:
                    destination.symlink_to(user_file)
                    swapped = True
                return original_open(name, flags, parent_fd, mode)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety._open_file_descriptor",
                side_effect=swap_before_destination_open,
            ):
                try:
                    stage_archive(
                        archive,
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        required_files=("payload.bin",),
                    )
                except (OSError, ValueError):
                    pass

            self.assertTrue(swapped)
            self.assertEqual(user_file.read_bytes(), b"user-content")

    def test_stage_retains_original_root_when_mount_path_is_swapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"payload"})
            original_root = base / "original-kindle"
            replacement_root = base / "replacement-root"
            replacement_root.mkdir()
            original_copy = __import__(
                "kindle_jailbreak_lib.storage_safety", fromlist=["copy_file_exclusive"]
            ).copy_file_exclusive
            swapped = False

            def swap_root_before_copy(*args, **kwargs):
                nonlocal swapped
                kindle.rename(original_root)
                kindle.symlink_to(replacement_root, target_is_directory=True)
                swapped = True
                return original_copy(*args, **kwargs)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.copy_file_exclusive",
                side_effect=swap_root_before_copy,
            ):
                try:
                    stage_archive(
                        archive,
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        required_files=("payload.bin",),
                    )
                except ValueError:
                    pass

            self.assertTrue(swapped)
            self.assertFalse((replacement_root / "payload.bin").exists())

    def test_stage_device_change_before_mutation_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"payload"})
            other = DeviceInfo(
                transport=device.transport,
                root=device.root,
                serial="G090OTHERDEVICE999",
                model=device.model,
                firmware=device.firmware,
                read_only=False,
                free_bytes=device.free_bytes,
            )
            observations = iter((device, other))

            with self.assertRaises(ValueError) as caught:
                stage_archive(
                    archive,
                    device,
                    store,
                    self._policy(),
                    device_probe=lambda: next(observations),
                    required_files=("payload.bin",),
                )

            self.assertEqual(getattr(caught.exception, "code", None), "KJA_DEVICE_MISMATCH")
            self.assertFalse((kindle / "payload.bin").exists())
            self.assertFalse((store.root / "created-files.json").exists())

    def test_stage_fails_closed_when_nofollow_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            archive = base / "payload.zip"
            self._write_zip(archive, {"payload.bin": b"payload"})
            from kindle_jailbreak_lib.storage_safety import StorageError

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety._require_nofollow",
                side_effect=StorageError(
                    "KJA_NOFOLLOW_UNAVAILABLE",
                    "当前平台无法排除链接竞态，已安全停止",
                ),
            ):
                with self.assertRaises(ValueError) as caught:
                    stage_archive(
                        archive,
                        device,
                        store,
                        self._policy(),
                        device_probe=lambda: device,
                        required_files=("payload.bin",),
                    )

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_NOFOLLOW_UNAVAILABLE",
            )
            self.assertFalse((kindle / "payload.bin").exists())
            self.assertFalse((store.root / "created-files.json").exists())

    def test_windows_usbms_capability_accepts_only_non_reparse_fat_family(self):
        from kindle_jailbreak_lib import storage_safety

        accepted = ("FAT", "FAT32", "exFAT")
        for filesystem in accepted:
            with self.subTest(filesystem=filesystem):
                self.assertTrue(storage_safety.windows_volume_is_safe(filesystem, 0))
        for filesystem, flags in (
            ("NTFS", 0),
            ("", 0),
            ("unknown", 0),
            ("FAT32", 0x80),
            ("exFAT", 0x80),
        ):
            with self.subTest(filesystem=filesystem, flags=flags):
                self.assertFalse(
                    storage_safety.windows_volume_is_safe(filesystem, flags)
                )

        root = Path("X:/")
        self.assertEqual(
            storage_safety.require_windows_safe_volume(
                root,
                probe=lambda _root: ("FAT32", 0),
            ),
            ("FAT32", 0),
        )
        with self.assertRaises(ValueError) as caught:
            storage_safety.require_windows_safe_volume(
                root,
                probe=lambda _root: ("NTFS", 0x80),
            )
        self.assertEqual(
            getattr(caught.exception, "code", None),
            "KJA_WINDOWS_FILESYSTEM_UNSAFE",
        )

    def test_windows_retained_volume_guid_does_not_follow_drive_reassignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume_a = self._make_kindle(base / "volume-a")
            volume_b = self._make_kindle(base / "volume-b")
            drive = Path("X:/")
            mapping = {str(drive): volume_a}
            from kindle_jailbreak_lib import storage_safety

            with storage_safety.retain_windows_fat_root(
                drive,
                volume_probe=lambda _root: ("FAT32", 0),
                volume_guid_resolver=lambda root: mapping[str(root)],
            ) as retained:
                mapping[str(drive)] = volume_b
                with storage_safety.create_file_exclusive(
                    retained,
                    Path("payload.bin"),
                ) as handle:
                    handle.write(b"payload")
                    handle.flush()
                    os.fsync(handle.fileno())

                self.assertFalse(retained.path_is_original())

            self.assertEqual((volume_a / "payload.bin").read_bytes(), b"payload")
            self.assertFalse((volume_b / "payload.bin").exists())

    def test_windows_retained_volume_guid_fails_if_original_volume_disappears(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume_a = self._make_kindle(base / "volume-a")
            volume_b = self._make_kindle(base / "volume-b")
            offline = base / "offline-volume-a"
            drive = Path("X:/")
            mapping = {str(drive): volume_a}
            from kindle_jailbreak_lib import storage_safety

            with storage_safety.retain_windows_fat_root(
                drive,
                volume_probe=lambda _root: ("exFAT", 0),
                volume_guid_resolver=lambda root: mapping[str(root)],
            ) as retained:
                volume_a.rename(offline)
                mapping[str(drive)] = volume_b
                with self.assertRaises((OSError, ValueError)):
                    with storage_safety.create_file_exclusive(
                        retained,
                        Path("payload.bin"),
                    ):
                        pass

            self.assertFalse((volume_b / "payload.bin").exists())

    def test_windows_re_resolves_same_guid_after_probing_guid(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume_a = self._make_kindle(base / "volume-a")
            volume_b = self._make_kindle(base / "volume-b")
            drive = Path("X:/")
            resolutions = iter((volume_a, volume_b))
            probed: list[Path] = []
            from kindle_jailbreak_lib import storage_safety

            def probe_guid(root: Path) -> tuple[str, int]:
                probed.append(root)
                return "FAT32", 0

            with self.assertRaises(ValueError) as caught:
                with storage_safety.retain_windows_fat_root(
                    drive,
                    volume_probe=probe_guid,
                    volume_guid_resolver=lambda _root: next(resolutions),
                ):
                    self.fail("盘符换卷后不得返回 retained backend")

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_WINDOWS_VOLUME_CHANGED",
            )
            self.assertEqual(probed, [volume_a])
            self.assertFalse((volume_a / "payload.bin").exists())
            self.assertFalse((volume_b / "payload.bin").exists())

            unsafe_probes: list[Path] = []
            with self.assertRaises(ValueError) as unsafe:
                with storage_safety.retain_windows_fat_root(
                    drive,
                    volume_probe=lambda root: unsafe_probes.append(root) or ("NTFS", 0x80),
                    volume_guid_resolver=lambda _root: volume_a,
                ):
                    self.fail("NTFS GUID 不得返回 retained backend")
            self.assertEqual(
                getattr(unsafe.exception, "code", None),
                "KJA_WINDOWS_FILESYSTEM_UNSAFE",
            )
            self.assertEqual(unsafe_probes, [volume_a])

    def test_windows_capacity_probe_uses_retained_volume_guid(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume_a = self._make_kindle(base / "volume-a")
            volume_b = self._make_kindle(base / "volume-b")
            drive = Path("X:/")
            mapping = {str(drive): volume_a}
            probed: list[Path] = []
            from kindle_jailbreak_lib import storage_safety, storage_windows

            with storage_safety.retain_windows_fat_root(
                drive,
                volume_probe=lambda _root: ("FAT32", 0),
                volume_guid_resolver=lambda root: mapping[str(root)],
            ) as retained:
                mapping[str(drive)] = volume_b
                available = storage_windows.free_bytes(
                    retained,
                    probe=lambda guid: probed.append(guid) or 123456,
                )

            self.assertEqual(available, 123456)
            self.assertEqual(probed, [volume_a])

    def test_windows_quarantine_reclaims_file_by_verified_handle(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume = self._make_kindle(base / "volume")
            target = volume / "quarantined.bin"
            target.write_bytes(b"temporary")
            from kindle_jailbreak_lib import storage_safety, storage_windows

            with storage_safety.retain_windows_fat_root(
                Path("X:/"),
                volume_probe=lambda _root: ("FAT32", 0),
                volume_guid_resolver=lambda _root: volume,
            ) as retained:
                observed = storage_windows.inspect_path(retained, Path("quarantined.bin"))
                assert observed is not None
                with mock.patch.object(
                    Path,
                    "unlink",
                    side_effect=AssertionError("Windows quarantine 不得按名称删除"),
                ) as unlink:
                    reclaimed = storage_safety.delete_quarantined(retained, observed)

            unlink.assert_not_called()
            self.assertEqual(reclaimed.size, 0)
            self.assertEqual(target.read_bytes(), b"")

    def test_windows_quarantine_preserves_residual_without_handle_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            volume = self._make_kindle(base / "volume")
            target = volume / "quarantined.bin"
            target.write_bytes(b"temporary")
            from kindle_jailbreak_lib import storage_safety, storage_windows

            with storage_safety.retain_windows_fat_root(
                Path("X:/"),
                volume_probe=lambda _root: ("FAT32", 0),
                volume_guid_resolver=lambda _root: volume,
            ) as retained:
                observed = storage_windows.inspect_path(retained, Path("quarantined.bin"))
                assert observed is not None
                with mock.patch(
                    "kindle_jailbreak_lib.storage_windows.os.open",
                    side_effect=OSError("simulated missing handle access"),
                ):
                    with self.assertRaises(ValueError) as caught:
                        storage_safety.delete_quarantined(retained, observed)

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_QUARANTINE_RESIDUAL",
            )
            self.assertEqual(target.read_bytes(), b"temporary")

    def test_cleanup_preserves_preexisting_user_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            owned_directory = kindle / ".kja-session"
            owned_directory.mkdir()
            owned_file = owned_directory / "owned.bin"
            owned_file.write_bytes(b"owned")
            preexisting = owned_directory / "user-book.txt"
            preexisting.write_bytes(b"keep")
            self._write_created_journal(store, kindle, [
                {
                    "path": ".kja-session",
                    "type": "directory",
                    "state": "created",
                    "size": 0,
                    "sha256": None,
                    "ownership_nonce": "owned-directory",
                },
                {
                    "path": ".kja-session/owned.bin",
                    "type": "file",
                    "state": "created",
                    "size": 5,
                    "sha256": hashlib.sha256(b"owned").hexdigest(),
                    "ownership_nonce": "owned-file",
                },
            ])

            removed = cleanup_created_files(
                device,
                store,
                device_probe=lambda: device,
            )

            self.assertEqual(removed, [Path(".kja-session/owned.bin")])
            self.assertFalse(owned_file.exists())
            self.assertTrue(preexisting.exists())
            self.assertTrue(owned_directory.exists())

    def test_cleanup_rejects_manifest_symlink_without_deleting_its_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            user_file = kindle / "documents" / "user-book.txt"
            user_file.write_bytes(b"keep")
            link = kindle / "owned.bin"
            link.symlink_to(user_file)
            self._write_created_journal(store, kindle, [{
                "path": "owned.bin",
                "type": "file",
                "state": "created",
                "size": 4,
                "sha256": hashlib.sha256(b"keep").hexdigest(),
                "ownership_nonce": "symlink-file",
            }])

            with self.assertRaises(ValueError):
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(user_file.read_bytes(), b"keep")
            self.assertTrue(link.is_symlink())

    def test_cleanup_preserves_replacement_that_no_longer_matches_created_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"user-data")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": len(b"original!"),
                "sha256": hashlib.sha256(b"original!").hexdigest(),
                "ownership_nonce": "owner-1",
            }])

            with self.assertRaises(ValueError):
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(target.read_bytes(), b"user-data")

    def test_cleanup_uses_created_identity_for_same_content_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"same-data")
            original = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"same-data").hexdigest(),
                "ownership_nonce": "same-content-owner",
                "created_identity": {
                    "device": original.st_dev,
                    "inode": original.st_ino,
                    "mode": stat.S_IFMT(original.st_mode),
                    "modified_ns": original.st_mtime_ns,
                    "changed_ns": original.st_ctime_ns,
                },
            }])
            target.unlink()
            target.write_bytes(b"same-data")

            with self.assertRaises(ValueError) as caught:
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            self.assertEqual(target.read_bytes(), b"same-data")

    def test_cleanup_rejects_matching_inode_with_different_creation_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"same-data")
            current = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"same-data").hexdigest(),
                "ownership_nonce": "timestamp-owner",
                "created_identity": {
                    "device": current.st_dev,
                    "inode": current.st_ino,
                    "mode": stat.S_IFMT(current.st_mode),
                    "modified_ns": current.st_mtime_ns - 1,
                    "changed_ns": current.st_ctime_ns - 1,
                },
            }])

            with self.assertRaises(ValueError) as caught:
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            self.assertEqual(target.read_bytes(), b"same-data")

    def test_cleanup_uses_created_identity_for_recreated_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary-directory"
            target.mkdir()
            original = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary-directory",
                "type": "directory",
                "state": "created",
                "size": 0,
                "sha256": None,
                "ownership_nonce": "directory-owner",
                "created_identity": {
                    "device": original.st_dev,
                    "inode": original.st_ino,
                    "mode": stat.S_IFMT(original.st_mode),
                    "modified_ns": original.st_mtime_ns,
                    "changed_ns": original.st_ctime_ns,
                },
            }])
            target.rmdir()
            target.mkdir()

            with self.assertRaises(ValueError) as caught:
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            self.assertTrue(target.is_dir())

    def test_cleanup_journal_failure_before_delete_preserves_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "owner-2",
            }])
            original_replace = os.replace

            def fail_deleting_transition(source, destination):
                if Path(destination).name == "created-files.json":
                    payload = json.loads(Path(source).read_text(encoding="utf-8"))
                    if any(entry.get("state") == "deleting" for entry in payload["entries"]):
                        raise OSError("simulated journal failure before delete")
                return original_replace(source, destination)

            with mock.patch("os.replace", side_effect=fail_deleting_transition):
                with self.assertRaises((OSError, ValueError)):
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(target.read_bytes(), b"temporary")

    def test_cleanup_file_keeps_zero_tombstone_without_unlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "owner-3",
            }])

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.os.unlink",
                side_effect=AssertionError("quarantine 文件不得按名称 unlink"),
            ) as unlink:
                removed = cleanup_created_files(
                    device,
                    store,
                    device_probe=lambda: device,
                )

            self.assertEqual(removed, [Path("temporary.bin")])
            self.assertFalse(target.exists())
            unlink.assert_not_called()
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            tombstone = next(
                entry for entry in manifest["entries"]
                if entry.get("ownership_nonce") == "owner-3"
            )
            self.assertEqual(tombstone["state"], "tombstone")
            quarantine_file = kindle / tombstone["quarantine_path"]
            self.assertEqual(quarantine_file.read_bytes(), b"")
            self.assertTrue(any(
                entry.get("purpose") == "quarantine_directory"
                and (kindle / entry["path"]).is_dir()
                for entry in manifest["entries"]
            ))

    def test_cleanup_replay_never_reclaims_tombstone_or_replacement_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "replay-tombstone-owner",
            }])

            cleanup_created_files(device, store, device_probe=lambda: device)
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            tombstone = next(
                entry for entry in manifest["entries"]
                if entry.get("ownership_nonce") == "replay-tombstone-owner"
            )
            quarantine_file = kindle / tombstone["quarantine_path"]

            with (
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.ftruncate",
                    side_effect=AssertionError("tombstone replay 不得再次截断"),
                ) as truncate,
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.unlink",
                    side_effect=AssertionError("tombstone replay 不得删除"),
                ) as unlink,
            ):
                self.assertEqual(
                    cleanup_created_files(device, store, device_probe=lambda: device),
                    [],
                )
            truncate.assert_not_called()
            unlink.assert_not_called()
            self.assertEqual(quarantine_file.read_bytes(), b"")

            quarantine_file.unlink()
            quarantine_file.write_bytes(b"replacement")
            with (
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.ftruncate",
                    side_effect=AssertionError("replacement 不得被截断"),
                ) as truncate,
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.unlink",
                    side_effect=AssertionError("replacement 不得被删除"),
                ) as unlink,
            ):
                with self.assertRaises(ValueError) as caught:
                    cleanup_created_files(device, store, device_probe=lambda: device)
            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            truncate.assert_not_called()
            unlink.assert_not_called()
            self.assertEqual(quarantine_file.read_bytes(), b"replacement")

    def test_cleanup_stops_on_existing_deleting_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "deleting",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "owner-4",
                "observed": {
                    "type": "file",
                    "size": 9,
                    "sha256": hashlib.sha256(b"temporary").hexdigest(),
                },
            }])

            with self.assertRaises(ValueError):
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(target.read_bytes(), b"temporary")

    def test_cleanup_preserves_replacement_after_deleting_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "owner-5",
            }])
            original_replace = os.replace
            swapped = False

            def swap_after_deleting_transition(source, destination):
                nonlocal swapped
                if Path(destination).name == "created-files.json":
                    payload = json.loads(Path(source).read_text(encoding="utf-8"))
                    if any(entry.get("state") == "deleting" for entry in payload["entries"]):
                        result = original_replace(source, destination)
                        target.unlink()
                        target.write_bytes(b"user-data")
                        swapped = True
                        return result
                return original_replace(source, destination)

            with mock.patch("os.replace", side_effect=swap_after_deleting_transition):
                with self.assertRaises(ValueError):
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(swapped)
            self.assertEqual(target.read_bytes(), b"user-data")

    def test_cleanup_quarantine_restores_file_swapped_at_final_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            metadata = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "file-race-owner",
                "created_identity": {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IFMT(metadata.st_mode),
                    "modified_ns": metadata.st_mtime_ns,
                    "changed_ns": metadata.st_ctime_ns,
                },
            }])
            from kindle_jailbreak_lib import storage_safety
            original_rename = storage_safety._rename_at
            swapped = False

            def swap_before_quarantine(source, destination, *args, **kwargs):
                nonlocal swapped
                if source == "temporary.bin" and not swapped:
                    target.unlink()
                    target.write_bytes(b"user-data")
                    swapped = True
                return original_rename(source, destination, *args, **kwargs)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety._rename_at",
                side_effect=swap_before_quarantine,
            ):
                with self.assertRaises(ValueError):
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(swapped)
            self.assertEqual(target.read_bytes(), b"user-data")

    def test_cleanup_quarantine_restores_directory_swapped_at_final_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary-directory"
            target.mkdir()
            metadata = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary-directory",
                "type": "directory",
                "state": "created",
                "size": 0,
                "sha256": None,
                "ownership_nonce": "directory-race-owner",
                "created_identity": {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IFMT(metadata.st_mode),
                    "modified_ns": metadata.st_mtime_ns,
                    "changed_ns": metadata.st_ctime_ns,
                },
            }])
            from kindle_jailbreak_lib import storage_safety
            original_rename = storage_safety._rename_at
            swapped = False

            def swap_before_quarantine(source, destination, *args, **kwargs):
                nonlocal swapped
                if source == "temporary-directory" and not swapped:
                    target.rmdir()
                    target.mkdir()
                    swapped = True
                return original_rename(source, destination, *args, **kwargs)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety._rename_at",
                side_effect=swap_before_quarantine,
            ):
                with self.assertRaises(ValueError):
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(swapped)
            self.assertTrue(target.is_dir())

    def test_cleanup_uses_fresh_journaled_quarantine_not_preexisting_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            session_id = store.load().session_id
            preexisting = kindle / f".kja-quarantine-{session_id[:8]}-{'a' * 32}"
            preexisting.mkdir()
            (preexisting / "user.txt").write_bytes(b"keep")
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "fresh-directory-owner",
            }])
            from kindle_jailbreak_lib import storage_safety

            original_move = storage_safety.quarantine_move
            used_directories: list[Path] = []
            journaled_at_move: list[bool] = []

            def record_quarantine(root, expected, directory, name):
                used_directories.append(directory)
                payload = json.loads(
                    (store.root / "created-files.json").read_text(encoding="utf-8")
                )
                journaled_at_move.append(any(
                    entry.get("path") == directory.as_posix()
                    and entry.get("state") == "created"
                    and isinstance(entry.get("created_identity"), dict)
                    for entry in payload["entries"]
                ))
                return original_move(root, expected, directory, name)

            with (
                mock.patch(
                    "kindle_jailbreak_lib.storage_payload.uuid.uuid4",
                    side_effect=(
                        SimpleNamespace(hex="a" * 32),
                        SimpleNamespace(hex="b" * 32),
                        SimpleNamespace(hex="c" * 32),
                        SimpleNamespace(hex="d" * 32),
                    ),
                ),
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.quarantine_move",
                    side_effect=record_quarantine,
                ),
            ):
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(used_directories)
            self.assertNotEqual(used_directories[0], preexisting.relative_to(kindle))
            self.assertEqual(journaled_at_move, [True])
            self.assertEqual((preexisting / "user.txt").read_bytes(), b"keep")

    def test_cleanup_skips_preexisting_quarantine_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            session_id = store.load().session_id
            preexisting = kindle / f".kja-quarantine-{session_id[:8]}-{'a' * 32}"
            preexisting.write_bytes(b"keep")
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "fresh-file-owner",
            }])

            with mock.patch(
                "kindle_jailbreak_lib.storage_payload.uuid.uuid4",
                side_effect=(
                    SimpleNamespace(hex="a" * 32),
                    SimpleNamespace(hex="b" * 32),
                    SimpleNamespace(hex="c" * 32),
                    SimpleNamespace(hex="d" * 32),
                ),
            ):
                cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertEqual(preexisting.read_bytes(), b"keep")
            self.assertFalse(target.exists())

    def test_cleanup_quarantine_rename_collision_preserves_both_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "rename-collision-owner",
            }])
            from kindle_jailbreak_lib import storage_safety

            original_rename = storage_safety._rename_at
            collision_path: Path | None = None
            collided = False

            def collide_before_rename(source, destination, *args):
                nonlocal collision_path, collided
                quarantine = next(kindle.glob(".kja-quarantine-*"))
                candidate = quarantine / destination
                candidate.write_bytes(b"preexisting-quarantine-object")
                collision_path = candidate
                collided = True
                return original_rename(source, destination, *args)

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety._rename_at",
                side_effect=collide_before_rename,
            ):
                with self.assertRaises(ValueError):
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(collided)
            self.assertEqual(target.read_bytes(), b"temporary")
            self.assertIsNotNone(collision_path)
            assert collision_path is not None
            self.assertEqual(
                collision_path.read_bytes(),
                b"preexisting-quarantine-object",
            )

    def test_cleanup_final_quarantine_handle_swap_retains_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary.bin"
            target.write_bytes(b"temporary")
            self._write_created_journal(store, kindle, [{
                "path": "temporary.bin",
                "type": "file",
                "state": "created",
                "size": 9,
                "sha256": hashlib.sha256(b"temporary").hexdigest(),
                "ownership_nonce": "final-delete-owner",
            }])
            from kindle_jailbreak_lib import storage_safety

            original_ftruncate = os.ftruncate
            replacement_path: Path | None = None
            retained_original: int | None = None
            swapped = False

            def swap_after_handle_verification(descriptor: int, length: int):
                nonlocal replacement_path, retained_original, swapped
                if not swapped:
                    manifest = json.loads(
                        (store.root / "created-files.json").read_text(encoding="utf-8")
                    )
                    deleting = next(
                        entry for entry in manifest["entries"]
                        if entry.get("state") == "deleting"
                    )
                    candidate = kindle / deleting["quarantine_path"]
                    retained_original = os.dup(descriptor)
                    candidate.unlink()
                    candidate.write_bytes(b"replacement")
                    replacement_path = candidate
                    swapped = True
                return original_ftruncate(descriptor, length)

            try:
                with mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.ftruncate",
                    side_effect=swap_after_handle_verification,
                ):
                    with self.assertRaises(ValueError) as caught:
                        cleanup_created_files(device, store, device_probe=lambda: device)

                self.assertTrue(swapped)
                self.assertEqual(
                    getattr(caught.exception, "code", None),
                    "KJA_OWNERSHIP_AMBIGUOUS",
                )
                self.assertFalse(target.exists())
                self.assertIsNotNone(replacement_path)
                assert replacement_path is not None
                self.assertEqual(replacement_path.read_bytes(), b"replacement")
                self.assertIsNotNone(retained_original)
                assert retained_original is not None
                self.assertEqual(os.fstat(retained_original).st_size, 0)
                manifest = json.loads(
                    (store.root / "created-files.json").read_text(encoding="utf-8")
                )
                tombstone = next(
                    entry for entry in manifest["entries"]
                    if entry.get("ownership_nonce") == "final-delete-owner"
                )
                self.assertEqual(tombstone["state"], "tombstone")
            finally:
                if retained_original is not None:
                    os.close(retained_original)

    def test_cleanup_empty_directory_keeps_tombstone_without_rmdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary-directory"
            target.mkdir()
            metadata = target.stat()
            self._write_created_journal(store, kindle, [{
                "path": "temporary-directory",
                "type": "directory",
                "state": "created",
                "size": 0,
                "sha256": None,
                "ownership_nonce": "directory-tombstone-owner",
                "created_identity": {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IFMT(metadata.st_mode),
                    "modified_ns": metadata.st_mtime_ns,
                    "changed_ns": metadata.st_ctime_ns,
                },
            }])

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.os.rmdir",
                side_effect=AssertionError("quarantine 目录不得按名称 rmdir"),
            ) as rmdir:
                removed = cleanup_created_files(
                    device,
                    store,
                    device_probe=lambda: device,
                )

            self.assertEqual(removed, [Path("temporary-directory")])
            self.assertFalse(target.exists())
            rmdir.assert_not_called()
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            tombstone = next(
                entry for entry in manifest["entries"]
                if entry.get("ownership_nonce") == "directory-tombstone-owner"
            )
            self.assertEqual(tombstone["state"], "tombstone")
            quarantined = kindle / tombstone["quarantine_path"]
            self.assertTrue(quarantined.is_dir())
            self.assertEqual(list(quarantined.iterdir()), [])
            tombstone_metadata = quarantined.stat()
            self.assertEqual(
                tombstone["tombstone_identity"]["modified_ns"],
                tombstone_metadata.st_mtime_ns,
            )
            self.assertEqual(
                tombstone["tombstone_identity"]["changed_ns"],
                tombstone_metadata.st_ctime_ns,
            )

            manifest_before_replay = (store.root / "created-files.json").read_bytes()
            identity_before_replay = quarantined.stat()
            with (
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.rmdir",
                    side_effect=AssertionError("目录 tombstone replay 不得 rmdir"),
                ) as replay_rmdir,
                mock.patch(
                    "kindle_jailbreak_lib.storage_safety.os.unlink",
                    side_effect=AssertionError("目录 tombstone replay 不得 unlink"),
                ) as replay_unlink,
            ):
                self.assertEqual(
                    cleanup_created_files(device, store, device_probe=lambda: device),
                    [],
                )
            replay_rmdir.assert_not_called()
            replay_unlink.assert_not_called()
            self.assertEqual(
                (store.root / "created-files.json").read_bytes(),
                manifest_before_replay,
            )
            identity_after_replay = quarantined.stat()
            self.assertEqual(
                (
                    identity_after_replay.st_dev,
                    identity_after_replay.st_ino,
                    stat.S_IFMT(identity_after_replay.st_mode),
                    identity_after_replay.st_mtime_ns,
                    identity_after_replay.st_ctime_ns,
                ),
                (
                    identity_before_replay.st_dev,
                    identity_before_replay.st_ino,
                    stat.S_IFMT(identity_before_replay.st_mode),
                    identity_before_replay.st_mtime_ns,
                    identity_before_replay.st_ctime_ns,
                ),
            )
            self.assertEqual(list(quarantined.iterdir()), [])

    def test_cleanup_directory_rejects_file_inserted_after_first_empty_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary-directory"
            target.mkdir()
            self._write_created_journal(store, kindle, [{
                "path": "temporary-directory",
                "type": "directory",
                "state": "created",
                "size": 0,
                "sha256": None,
                "ownership_nonce": "directory-first-check-race",
            }])
            original_listdir = os.listdir
            inserted = False
            late_file: Path | None = None

            def insert_after_empty_check(directory):
                nonlocal inserted, late_file
                children = original_listdir(directory)
                if not inserted and not children and isinstance(directory, int):
                    manifest = json.loads(
                        (store.root / "created-files.json").read_text(encoding="utf-8")
                    )
                    deleting_entries = [
                        entry for entry in manifest["entries"]
                        if entry.get("ownership_nonce") == "directory-first-check-race"
                        and entry.get("state") == "deleting"
                    ]
                    if not deleting_entries:
                        return children
                    deleting = deleting_entries[0]
                    candidate = kindle / deleting["quarantine_path"]
                    if os.fstat(directory).st_ino == candidate.stat().st_ino:
                        candidate_file = candidate / "late-user-file.txt"
                        candidate_file.write_bytes(b"keep")
                        late_file = candidate_file
                        inserted = True
                return children

            with mock.patch(
                "kindle_jailbreak_lib.storage_safety.os.listdir",
                side_effect=insert_after_empty_check,
            ):
                with self.assertRaises(ValueError) as caught:
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(inserted)
            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            self.assertIsNotNone(late_file)
            assert late_file is not None
            self.assertEqual(late_file.read_bytes(), b"keep")
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            entry = next(
                item for item in manifest["entries"]
                if item.get("ownership_nonce") == "directory-first-check-race"
            )
            self.assertNotEqual(entry["state"], "tombstone")

    def test_cleanup_directory_rejects_file_inserted_after_journal_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            kindle = self._make_kindle(base)
            store, device = self._make_session(base, kindle)
            target = kindle / "temporary-directory"
            target.mkdir()
            self._write_created_journal(store, kindle, [{
                "path": "temporary-directory",
                "type": "directory",
                "state": "created",
                "size": 0,
                "sha256": None,
                "ownership_nonce": "directory-final-check-race",
            }])
            from kindle_jailbreak_lib.storage_manifest import CreatedFilesJournal

            original_mark_tombstone = CreatedFilesJournal.mark_tombstone
            inserted = False
            late_file: Path | None = None

            def insert_after_journal(
                journal: CreatedFilesJournal,
                nonce: str,
                observed,
            ) -> None:
                nonlocal inserted, late_file
                original_mark_tombstone(journal, nonce, observed)
                candidate_file = kindle / observed.relative / "late-user-file.txt"
                candidate_file.write_bytes(b"keep")
                late_file = candidate_file
                inserted = True

            with mock.patch.object(
                CreatedFilesJournal,
                "mark_tombstone",
                autospec=True,
                side_effect=insert_after_journal,
            ):
                with self.assertRaises(ValueError) as caught:
                    cleanup_created_files(device, store, device_probe=lambda: device)

            self.assertTrue(inserted)
            self.assertEqual(
                getattr(caught.exception, "code", None),
                "KJA_OWNERSHIP_AMBIGUOUS",
            )
            self.assertIsNotNone(late_file)
            assert late_file is not None
            self.assertEqual(late_file.read_bytes(), b"keep")
            manifest = json.loads(
                (store.root / "created-files.json").read_text(encoding="utf-8")
            )
            entry = next(
                item for item in manifest["entries"]
                if item.get("ownership_nonce") == "directory-final-check-race"
            )
            self.assertNotEqual(entry["state"], "tombstone")


if __name__ == "__main__":
    unittest.main()

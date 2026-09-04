"""可崩溃恢复的 ``created-files.json`` 操作日志。"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .session import SessionStore
from .storage_safety import (
    EntrySnapshot,
    RootReference,
    SafeRootHandle,
    StorageError,
    lexical_path,
)


_MANIFEST_NAME = "created-files.json"
_VALID_STATES = frozenset({"pending_create", "created", "deleting", "tombstone"})
_VALID_TYPES = frozenset({"file", "directory"})
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class CreatedFilesJournal:
    """以持久化状态转换包围每一次设备端创建与删除。"""

    def __init__(self, store: SessionStore, device_root: RootReference):
        self.store = store
        self.root = device_root
        self.device_root = (
            device_root.path if isinstance(device_root, SafeRootHandle) else device_root
        )
        self.path = store.root / _MANIFEST_NAME

    def entries(self, *, create: bool = False) -> list[dict[str, Any]]:
        return list(self._load(create=create)["entries"])

    def begin_create(
        self,
        relative: Path,
        entry_type: str,
        *,
        size: int,
        sha256: str | None,
        purpose: str | None = None,
    ) -> str:
        key = self._validate_relative(relative)
        if entry_type not in _VALID_TYPES:
            raise StorageError("KJA_JOURNAL_INVALID", "创建日志包含无效对象类型")
        self._validate_expected(entry_type, size, sha256)
        payload = self._load(create=True)
        if any(entry["path"] == key for entry in payload["entries"]):
            raise StorageError("KJA_JOURNAL_AMBIGUOUS", "创建目标已存在于当前会话日志")
        nonce = uuid.uuid4().hex
        entry: dict[str, Any] = {
            "path": key,
            "type": entry_type,
            "state": "pending_create",
            "size": size,
            "sha256": sha256,
            "ownership_nonce": nonce,
        }
        if purpose is not None:
            entry["purpose"] = purpose
        payload["entries"].append(entry)
        self._persist(payload)
        return nonce

    def mark_created(self, nonce: str, observed: EntrySnapshot) -> None:
        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        if entry["state"] != "pending_create":
            raise StorageError("KJA_JOURNAL_INVALID", "对象不处于待创建状态")
        if entry["path"] != observed.relative.as_posix() or entry["type"] != observed.kind:
            raise StorageError("KJA_JOURNAL_AMBIGUOUS", "创建后的对象身份与日志不一致")
        if observed.size != entry["size"] or observed.sha256 != entry["sha256"]:
            raise StorageError("KJA_CHECKSUM_MISMATCH", "创建后的对象内容与预期不一致")
        entry["state"] = "created"
        entry["created_identity"] = {
            "device": observed.device,
            "inode": observed.inode,
            "mode": observed.mode,
        }
        self._persist(payload)

    def mark_deleting(
        self,
        nonce: str,
        observed: EntrySnapshot,
        quarantine_path: Path,
    ) -> None:
        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        if entry["state"] != "created":
            raise StorageError("KJA_JOURNAL_AMBIGUOUS", "对象不处于可删除状态")
        self._assert_expected_matches(entry, observed)
        self._assert_created_identity(entry, observed)
        entry["state"] = "deleting"
        entry["quarantine_path"] = self._validate_relative(quarantine_path)
        entry["observed"] = {
            "type": observed.kind,
            "size": observed.size,
            "sha256": observed.sha256,
            "device": observed.device,
            "inode": observed.inode,
            "mode": observed.mode,
            "modified_ns": observed.modified_ns,
            "changed_ns": observed.changed_ns,
        }
        self._persist(payload)

    def finish(self, nonce: str) -> None:
        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        payload["entries"].remove(entry)
        self._persist(payload)

    def mark_tombstone(self, nonce: str, observed: EntrySnapshot) -> None:
        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        if entry["state"] != "deleting":
            raise StorageError("KJA_JOURNAL_INVALID", "对象不处于隔离回收状态")
        quarantine_path = entry.get("quarantine_path")
        if quarantine_path != observed.relative.as_posix():
            raise StorageError("KJA_JOURNAL_AMBIGUOUS", "tombstone 路径与删除日志不一致")
        entry["state"] = "tombstone"
        entry["tombstone_identity"] = {
            "type": observed.kind,
            "size": observed.size,
            "sha256": observed.sha256,
            "device": observed.device,
            "inode": observed.inode,
            "mode": observed.mode,
            "modified_ns": observed.modified_ns,
            "changed_ns": observed.changed_ns,
        }
        self._persist(payload)

    def retain_deleting(self, nonce: str) -> None:
        """末端复核含糊时撤销 success tombstone，保留可安全重放的 deleting。"""

        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        if entry["state"] == "deleting":
            return
        if entry["state"] != "tombstone":
            raise StorageError("KJA_JOURNAL_INVALID", "对象不处于可撤销的 tombstone 状态")
        entry["state"] = "deleting"
        entry.pop("tombstone_identity", None)
        self._persist(payload)

    def clear_missing_replay_entry(self, nonce: str) -> None:
        payload = self._load(create=False)
        entry = self._find(payload, nonce)
        if entry["state"] not in {"pending_create", "deleting"}:
            raise StorageError("KJA_JOURNAL_INVALID", "仅可重放未完成的日志项")
        payload["entries"].remove(entry)
        self._persist(payload)

    def _load(self, *, create: bool) -> dict[str, Any]:
        state = self.store.load()
        if not self.path.exists():
            if not create:
                raise FileNotFoundError(f"未找到创建文件日志：{self.path}")
            return {
                "schema_version": 1,
                "session_id": state.session_id,
                "device_fingerprint": state.device_fingerprint,
                "device_root": str(self.device_root),
                "entries": [],
            }
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志不是有效 JSON") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志版本无效")
        if payload.get("session_id") != state.session_id:
            raise StorageError("KJA_JOURNAL_SESSION", "创建文件日志属于其他会话")
        if payload.get("device_fingerprint") != state.device_fingerprint:
            raise StorageError("KJA_JOURNAL_DEVICE", "创建文件日志属于其他设备")
        try:
            recorded_root = Path(str(payload["device_root"]))
        except KeyError as exc:
            raise StorageError("KJA_JOURNAL_INVALID", "日志中的设备根目录不可用") from exc
        if recorded_root != self.device_root:
            raise StorageError("KJA_JOURNAL_DEVICE", "创建文件日志指向其他设备根目录")
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志条目必须是数组")
        seen_paths: set[str] = set()
        seen_nonces: set[str] = set()
        for entry in entries:
            self._validate_entry(entry)
            if entry["path"] in seen_paths or entry["ownership_nonce"] in seen_nonces:
                raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志包含重复条目")
            seen_paths.add(entry["path"])
            seen_nonces.add(entry["ownership_nonce"])
        return payload

    def _persist(self, payload: dict[str, Any]) -> None:
        _atomic_write_json(self.path, payload)
        state = self.store.load()
        state.created_files = [str(entry["path"]) for entry in payload["entries"]]
        self.store.save(state)

    def _validate_entry(self, entry: object) -> None:
        if not isinstance(entry, dict):
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志条目无效")
        key = self._validate_relative(Path(str(entry.get("path", ""))))
        if key != entry.get("path"):
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志路径不是规范相对路径")
        entry_type = entry.get("type")
        if entry_type not in _VALID_TYPES or entry.get("state") not in _VALID_STATES:
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志状态或类型无效")
        nonce = entry.get("ownership_nonce")
        if not isinstance(nonce, str) or not nonce:
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志缺少所有权随机值")
        self._validate_expected(entry_type, entry.get("size"), entry.get("sha256"))
        if entry.get("state") in {"created", "deleting", "tombstone"}:
            identity = entry.get("created_identity")
            if not isinstance(identity, dict) or set(identity) != {
                "device", "inode", "mode",
            }:
                raise StorageError("KJA_JOURNAL_INVALID", "创建日志缺少初始对象身份")

    def _validate_relative(self, relative: Path) -> str:
        lexical_path(self.root, relative)
        return relative.as_posix()

    @staticmethod
    def _validate_expected(entry_type: object, size: object, digest: object) -> None:
        if not isinstance(size, int) or size < 0:
            raise StorageError("KJA_JOURNAL_INVALID", "创建文件日志大小无效")
        if entry_type == "directory":
            if size != 0 or digest is not None:
                raise StorageError("KJA_JOURNAL_INVALID", "目录日志不能包含文件哈希")
        elif not isinstance(digest, str) or not _HASH_RE.fullmatch(digest):
            raise StorageError("KJA_JOURNAL_INVALID", "文件日志缺少有效 SHA-256")

    @staticmethod
    def _find(payload: dict[str, Any], nonce: str) -> dict[str, Any]:
        for entry in payload["entries"]:
            if entry["ownership_nonce"] == nonce:
                return entry
        raise StorageError("KJA_JOURNAL_INVALID", "未找到对应的所有权日志项")

    @staticmethod
    def _assert_expected_matches(entry: dict[str, Any], observed: EntrySnapshot) -> None:
        if (
            entry["path"] != observed.relative.as_posix()
            or entry["type"] != observed.kind
            or entry["size"] != observed.size
            or entry["sha256"] != observed.sha256
        ):
            raise StorageError("KJA_JOURNAL_AMBIGUOUS", "当前对象与创建日志不一致，拒绝删除")

    @staticmethod
    def _assert_created_identity(
        entry: dict[str, Any],
        observed: EntrySnapshot,
    ) -> None:
        identity = entry.get("created_identity")
        if not isinstance(identity, dict) or (
            identity.get("device") != observed.device
            or identity.get("inode") != observed.inode
            or identity.get("mode") != observed.mode
        ):
            raise StorageError(
                "KJA_OWNERSHIP_AMBIGUOUS",
                "当前对象无法证明为本会话最初创建的对象，拒绝删除",
            )


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

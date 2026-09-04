"""Kindle 可见存储的可恢复备份与内容清单校验。"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import DeviceInfo, Stage
from .progress import ProgressEvent
from .session import SessionStore
from . import storage_safety as safety


_BACKUP_MANIFEST = "manifest.json"
_BACKUP_CONTENT = "content"
_BACKUP_STATUS = "backup-status.json"
_BACKUP_COMPLETE = "backup-complete.json"
_HOST_METADATA_DIRECTORIES = frozenset({
    ".Trashes", ".Spotlight-V100", ".fseventsd",
})
_TIMESTAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")

ProgressCallback = Callable[[ProgressEvent], None]


def backup_visible_storage(
    device: DeviceInfo,
    backup_parent: str | Path,
    *,
    session_store: SessionStore,
    timestamp: str | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    """在会话专属 partial 中可恢复复制，验收后一次性发布备份。"""

    if device.root is None:
        raise safety.StorageError("KJA_DEVICE_UNAVAILABLE", "设备没有文件系统根目录")
    with safety.retain_safe_root(device.root, device=device) as source_root:
        state = session_store.load()
        safety.assert_session_device(state, device, source_root.path)
        return _backup_retained(
            source_root,
            device,
            backup_parent,
            session_store,
            state.session_id,
            state.device_fingerprint,
            timestamp,
            progress,
        )


def _backup_retained(
    source_root: safety.SafeRootHandle,
    device: DeviceInfo,
    backup_parent: str | Path,
    session_store: SessionStore,
    session_id: str,
    device_fingerprint: str,
    timestamp: str | None,
    progress: ProgressCallback | None,
) -> Path:
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not _TIMESTAMP_RE.fullmatch(stamp):
        raise safety.StorageError("KJA_BACKUP_TIMESTAMP", "备份时间戳格式必须为 YYYYMMDDTHHMMSSZ")

    parent = Path(backup_parent).expanduser().resolve(strict=False)
    destination = parent / stamp
    if _is_within(destination, source_root.path):
        raise safety.StorageError("KJA_BACKUP_TARGET", "备份目录必须位于 Kindle 之外")
    parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise safety.StorageError("KJA_BACKUP_EXISTS", "同名完整备份已存在，拒绝覆盖")
    partial = parent / f".{stamp}.{session_id}.partial"
    other_partials = [
        path for path in parent.glob(f".{stamp}.*.partial") if path != partial
    ]
    if other_partials:
        raise safety.StorageError("KJA_BACKUP_SESSION", "同一备份时间戳属于其他会话")

    source_entries = safety.scan_tree(
        source_root,
        skipped_names=_HOST_METADATA_DIRECTORIES,
    )
    expected_entries = _manifest_entries(source_entries)
    content_root = _open_or_create_partial(
        partial,
        source_root.path,
        session_id,
        device_fingerprint,
        stamp,
        expected_entries,
    )
    with safety.retain_root(content_root) as retained_content:
        _copy_or_resume_entries(
            source_root,
            retained_content,
            source_entries,
            progress,
        )
        _atomic_write_json(
            partial / _BACKUP_MANIFEST,
            {
                "schema_version": 1,
                "source_root": str(source_root.path),
                "created_at": stamp,
                "entries": expected_entries,
            },
        )
        _verify_manifest_against_roots(
            source_root,
            retained_content,
            expected_entries,
        )
    _atomic_write_json(
        partial / _BACKUP_COMPLETE,
        {
            "schema_version": 1,
            "state": "complete",
            "session_id": session_id,
            "device_fingerprint": device_fingerprint,
        },
    )
    _publish_no_replace(partial, destination)
    safety.assert_retained_root(source_root)
    return destination.resolve(strict=True)


def _copy_or_resume_entries(
    source_root: safety.SafeRootHandle,
    content_root: safety.SafeRootHandle,
    source_entries: list[safety.EntrySnapshot],
    progress: ProgressCallback | None,
) -> None:
    existing_entries = safety.scan_tree(content_root)
    existing_by_path = {entry.relative.as_posix(): entry for entry in existing_entries}
    expected_by_path = {entry.relative.as_posix(): entry for entry in source_entries}
    if not set(existing_by_path).issubset(expected_by_path):
        raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 含有未知路径")
    for key, existing in list(existing_by_path.items()):
        expected = expected_by_path[key]
        if _same_content(existing, expected):
            continue
        if existing.kind != "file" or expected.kind != "file":
            raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 目录结构不一致")
        existing_by_path[key] = _safely_restart_partial_file(
            source_root,
            expected,
            content_root,
            existing,
        )

    file_count = sum(1 for entry in source_entries if entry.kind == "file")
    copied = sum(1 for entry in existing_by_path.values() if entry.kind == "file")
    for entry in source_entries:
        existing = existing_by_path.get(entry.relative.as_posix())
        if entry.kind == "directory":
            if existing is None:
                safety.mkdir_exclusive(content_root, entry.relative)
            continue
        if existing is None:
            safety.copy_file_exclusive(
                source_root,
                entry,
                content_root,
                entry.relative,
            )
            copied += 1
            _emit_progress(progress, copied, file_count)


def _safely_restart_partial_file(
    source_root: safety.SafeRootHandle,
    expected: safety.EntrySnapshot,
    content_root: safety.SafeRootHandle,
    existing: safety.EntrySnapshot,
) -> safety.EntrySnapshot:
    digest = hashlib.sha256()
    copied = 0
    with safety.open_snapshot(source_root, expected) as source:
        with safety.open_snapshot_for_update(content_root, existing) as destination:
            os.ftruncate(destination.fileno(), 0)
            while True:
                chunk = source.read(safety.MIB)
                if not chunk:
                    break
                destination.write(chunk)
                digest.update(chunk)
                copied += len(chunk)
            destination.flush()
            os.fsync(destination.fileno())
    if copied != expected.size or digest.hexdigest() != expected.sha256:
        raise safety.StorageError("KJA_SOURCE_CHANGED", "备份重启期间来源内容发生变化")
    rewritten = safety.inspect_path(content_root, existing.relative)
    if rewritten is None or not _same_content(rewritten, expected):
        raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 重写结果不一致")
    return rewritten


def verify_manifest(source_root: str | Path, backup_root: str | Path) -> bool:
    """重新读取源和备份内容，并按清单核对类型、大小与 SHA-256。"""

    with safety.retain_safe_root(source_root) as source:
        backup = Path(backup_root).expanduser().resolve(strict=True)
        if not backup.is_dir():
            raise safety.StorageError("KJA_BACKUP_VERIFY", "备份根路径不是目录")
        content = backup / _BACKUP_CONTENT
        if content.is_symlink() or not content.is_dir():
            raise safety.StorageError("KJA_BACKUP_VERIFY", "备份内容目录缺失或不安全")
        payload = _read_json_object(backup / _BACKUP_MANIFEST)
        entries = payload.get("entries")
        if payload.get("schema_version") != 1 or not isinstance(entries, list):
            raise safety.StorageError("KJA_BACKUP_VERIFY", "备份清单格式无效")
        with safety.retain_root(content) as retained_content:
            _verify_manifest_against_roots(source, retained_content, entries)
        safety.assert_retained_root(source)
        return True


def _verify_manifest_against_roots(
    source: safety.SafeRootHandle,
    content: safety.RootReference,
    entries: list[object] | list[dict[str, object]],
) -> None:
    manifest_by_path: dict[str, dict[str, object]] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "path", "type", "size", "sha256",
        }:
            raise safety.StorageError("KJA_BACKUP_VERIFY", "备份清单条目无效")
        relative = _manifest_relative(raw_entry.get("path"))
        key = relative.as_posix()
        if key in manifest_by_path:
            raise safety.StorageError("KJA_BACKUP_VERIFY", "备份清单含重复路径")
        manifest_by_path[key] = raw_entry

    source_snapshots = safety.scan_tree(
        source,
        skipped_names=_HOST_METADATA_DIRECTORIES,
    )
    target_snapshots = safety.scan_tree(content)
    source_by_path = {entry.relative.as_posix(): entry for entry in source_snapshots}
    target_by_path = {entry.relative.as_posix(): entry for entry in target_snapshots}
    manifest_types = {key: entry.get("type") for key, entry in manifest_by_path.items()}
    if (
        {key: entry.kind for key, entry in source_by_path.items()} != manifest_types
        or {key: entry.kind for key, entry in target_by_path.items()} != manifest_types
    ):
        raise safety.StorageError("KJA_BACKUP_VERIFY", "备份路径或类型与清单不一致")
    for key, entry in manifest_by_path.items():
        source_entry = source_by_path[key]
        target_entry = target_by_path[key]
        if (
            source_entry.size != entry["size"]
            or target_entry.size != entry["size"]
            or source_entry.sha256 != entry["sha256"]
            or target_entry.sha256 != entry["sha256"]
        ):
            raise safety.StorageError("KJA_CHECKSUM_MISMATCH", f"备份内容校验失败：{key}")


def _open_or_create_partial(
    partial: Path,
    source_root: Path,
    session_id: str,
    fingerprint: str,
    stamp: str,
    expected_entries: list[dict[str, object]],
) -> Path:
    if partial.exists() or partial.is_symlink():
        if partial.is_symlink() or not partial.is_dir():
            raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 路径不安全")
        status = _read_json_object(partial / _BACKUP_STATUS)
        if (
            status.get("schema_version") != 1
            or status.get("state") != "copying"
            or status.get("session_id") != session_id
            or status.get("device_fingerprint") != fingerprint
            or status.get("source_root") != str(source_root)
            or status.get("entries") != expected_entries
        ):
            raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 与当前会话或来源不一致")
        content = partial / _BACKUP_CONTENT
        if content.is_symlink() or not content.is_dir():
            raise safety.StorageError("KJA_BACKUP_PARTIAL", "备份 partial 缺少安全内容目录")
        return content.resolve(strict=True)

    partial.mkdir(exist_ok=False)
    content = partial / _BACKUP_CONTENT
    content.mkdir()
    _atomic_write_json(
        partial / _BACKUP_STATUS,
        {
            "schema_version": 1,
            "state": "copying",
            "session_id": session_id,
            "device_fingerprint": fingerprint,
            "source_root": str(source_root),
            "timestamp": stamp,
            "entries": expected_entries,
        },
    )
    return content.resolve(strict=True)


def _manifest_entries(
    snapshots: list[safety.EntrySnapshot],
) -> list[dict[str, object]]:
    return [
        {
            "path": entry.relative.as_posix(),
            "type": entry.kind,
            "size": entry.size,
            "sha256": entry.sha256,
        }
        for entry in snapshots
    ]


def _same_content(left: safety.EntrySnapshot, right: safety.EntrySnapshot) -> bool:
    return (
        left.kind == right.kind
        and left.size == right.size
        and left.sha256 == right.sha256
    )


def _manifest_relative(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise safety.StorageError("KJA_BACKUP_VERIFY", "备份清单路径无效")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise safety.StorageError("KJA_BACKUP_VERIFY", "备份清单路径越界")
    return relative


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise safety.StorageError("KJA_BACKUP_METADATA", "备份状态或清单不可读取") from exc
    if not isinstance(payload, dict):
        raise safety.StorageError("KJA_BACKUP_METADATA", "备份状态或清单不是 JSON 对象")
    return payload


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path: str | None = temporary
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary_path = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _emit_progress(
    callback: ProgressCallback | None,
    done: int,
    total: int,
) -> None:
    if callback is not None:
        callback(ProgressEvent(
            event="progress",
            stage=Stage.BACKUP,
            message="正在复制 Kindle 可见内容",
            done=done,
            total=total,
            unit="files",
            user_action=None,
        ))


def _publish_no_replace(source: Path, destination: Path) -> None:
    """用平台原子原语发布目录，目标并发出现时绝不替换。"""

    if sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        rename_exclusive = library.renamex_np
        rename_exclusive.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(os.fsencode(source), os.fsencode(destination), 0x4)
        if result == 0:
            return
        _raise_publish_error(ctypes.get_errno())

    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        try:
            rename_no_replace = library.renameat2
        except AttributeError as exc:
            raise safety.StorageError(
                "KJA_ATOMIC_PUBLISH_UNAVAILABLE",
                "当前 Linux 运行库不支持原子 no-replace 发布",
            ) from exc
        rename_no_replace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            0x1,
        )
        if result == 0:
            return
        _raise_publish_error(ctypes.get_errno())

    if sys.platform == "win32":
        try:
            os.rename(source, destination)
        except FileExistsError as exc:
            raise safety.StorageError(
                "KJA_BACKUP_EXISTS",
                "备份发布目标并发出现，已有目录已保留",
            ) from exc
        return

    raise safety.StorageError(
        "KJA_ATOMIC_PUBLISH_UNAVAILABLE",
        "当前平台没有安全的原子 no-replace 发布能力",
    )


def _raise_publish_error(error_number: int) -> None:
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise safety.StorageError(
            "KJA_BACKUP_EXISTS",
            "备份发布目标并发出现，已有目录已保留",
        )
    if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
        raise safety.StorageError(
            "KJA_ATOMIC_PUBLISH_UNAVAILABLE",
            "当前文件系统不支持原子 no-replace 发布",
        )
    raise OSError(error_number, os.strerror(error_number))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True

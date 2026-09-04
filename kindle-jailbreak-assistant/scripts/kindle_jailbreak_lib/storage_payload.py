"""占位、归档预检、载荷暂存与精确清理生命周期。"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tarfile
import tempfile
import unicodedata
import uuid
import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, BinaryIO

from .models import DeviceInfo, Stage
from .progress import ProgressEvent
from .routing import MethodPolicy
from .session import SessionStore
from .storage_manifest import CreatedFilesJournal
from . import storage_safety as safety


MIB = 1024 * 1024
DEFAULT_RESERVE_BYTES = 80 * MIB
DEFAULT_FILL_CHUNK_BYTES = 100 * MIB
_FAT32_MAX_FILE_BYTES = 0xFFFF_FFFF
_FAT32_FORBIDDEN_CHARACTERS = frozenset('<>:"/\\|?*')
_STAGING_AUTOMATION = frozenset({
    "guided-assets",
    "guided-assets-or-browser",
    "guided-assets-and-browser",
    "guided-assets-and-store",
    "guided-update-package",
})

ProgressCallback = Callable[[ProgressEvent], None]
DeviceProbe = Callable[[], DeviceInfo]
FreeSpaceProbe = Callable[[safety.SafeRootHandle], int]


def fill_storage(
    device: DeviceInfo,
    session_store: SessionStore,
    policy: MethodPolicy,
    *,
    device_probe: DeviceProbe,
    reserve_bytes: int = DEFAULT_RESERVE_BYTES,
    chunk_bytes: int = DEFAULT_FILL_CHUNK_BYTES,
    free_space: FreeSpaceProbe | None = None,
    progress: ProgressCallback | None = None,
    authorization_key: str | None = None,
) -> list[Path]:
    """在策略允许时写入当前会话独占的真实零数据占位文件。"""

    if reserve_bytes < DEFAULT_RESERVE_BYTES:
        raise safety.StorageError("KJA_SPACE_POLICY", "占位操作必须至少保留 80 MiB")
    if chunk_bytes <= 0:
        raise safety.StorageError("KJA_INVALID_ARGUMENT", "占位分块大小必须为正数")
    if policy.generic_filler != "required-by-guide":
        raise safety.StorageError("KJA_POLICY_DENIED", "当前越狱方法禁止普通磁盘占位")

    with safety.authorized_device_root(
        device, session_store, device_probe, authorization_key=authorization_key
    ) as (root, state):
        return _fill_retained(
            root,
            state.session_id,
            device,
            session_store,
            device_probe,
            reserve_bytes,
            chunk_bytes,
            free_space,
            progress,
        )


def _fill_retained(
    root: safety.SafeRootHandle,
    session_id: str,
    device: DeviceInfo,
    session_store: SessionStore,
    device_probe: DeviceProbe,
    reserve_bytes: int,
    chunk_bytes: int,
    free_space: FreeSpaceProbe | None,
    progress: ProgressCallback | None,
) -> list[Path]:
    filler_relative = Path(f".kja-fill-{session_id}")
    journal = CreatedFilesJournal(session_store, root)
    entries = journal.entries(create=True)
    owned = {entry["path"]: entry for entry in entries}
    created_files: list[Path] = []
    try:
        directory_entry = owned.get(filler_relative.as_posix())
        if directory_entry is None:
            nonce = journal.begin_create(
                filler_relative, "directory", size=0, sha256=None
            )
            observed = safety.mkdir_exclusive(root, filler_relative)
            journal.mark_created(nonce, observed)
        else:
            observed = safety.inspect_path(root, filler_relative)
            if directory_entry["state"] != "created" or observed is None:
                raise safety.StorageError("KJA_JOURNAL_AMBIGUOUS", "占位目录状态不明确")
            _assert_entry_matches(directory_entry, observed)

        next_index = _next_chunk_index(journal.entries(), filler_relative)
        written = 0
        while True:
            safety.assert_same_device(device, device_probe())
            available = _retained_free_bytes(root, free_space)
            if available < reserve_bytes + chunk_bytes:
                break
            relative = filler_relative / f"chunk-{next_index:06d}.bin"
            expected_digest = _zero_sha256(chunk_bytes)
            nonce = journal.begin_create(
                relative,
                "file",
                size=chunk_bytes,
                sha256=expected_digest,
            )
            with safety.create_file_exclusive(root, relative) as handle:
                _write_zeros(handle, chunk_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            observed = safety.inspect_path(root, relative)
            if observed is None:
                raise safety.StorageError("KJA_CREATE_FAILED", "占位文件创建后消失")
            journal.mark_created(nonce, observed)
            safety.assert_same_device(device, device_probe())
            created_files.append(root.path / relative)
            written += chunk_bytes
            next_index += 1
            _emit_progress(
                progress,
                Stage.PREPARE,
                "正在创建当前方法要求的占位文件",
                written,
                None,
                "bytes",
            )
        if _retained_free_bytes(root, free_space) < reserve_bytes:
            raise safety.StorageError("KJA_INSUFFICIENT_SPACE", "可用空间低于 80 MiB 安全线")
        safety.assert_same_device(device, device_probe())
        safety.assert_retained_root(root)
        return created_files
    except (OSError, ValueError):
        _enter_recoverable_error(session_store)
        raise


def inspect_archive(
    archive: str | Path,
    staging_root: str | Path,
    *,
    required_files: Iterable[str] = (),
) -> list[Path]:
    """完整预检 ZIP/TAR 后，手工解压到尚不存在的主机暂存目录。"""

    try:
        archive_path = Path(archive).expanduser().resolve(strict=True)
    except OSError as exc:
        raise safety.StorageError("KJA_ARCHIVE_INVALID", "归档文件不可用") from exc
    if not archive_path.is_file() or archive_path.is_symlink():
        raise safety.StorageError("KJA_ARCHIVE_INVALID", "归档必须是普通文件")
    staging = Path(staging_root).expanduser()
    if staging.exists() or staging.is_symlink():
        raise safety.StorageError("KJA_STAGE_EXISTS", "主机暂存目录已存在")
    if not staging.parent.exists() or not staging.parent.is_dir():
        raise safety.StorageError("KJA_STAGE_INVALID", "主机暂存目录的父目录不可用")
    staging = staging.resolve(strict=False)
    required = {_safe_relative_path(item).as_posix() for item in required_files}

    if zipfile.is_zipfile(archive_path):
        members = _inspect_zip(archive_path, staging)
        _require_archive_files(required, members)
        return _extract_zip(archive_path, staging, members)
    if tarfile.is_tarfile(archive_path):
        members = _inspect_tar(archive_path, staging)
        _require_archive_files(required, members)
        return _extract_tar(archive_path, staging, members)
    raise safety.StorageError("KJA_ARCHIVE_INVALID", "归档格式不支持或内容已损坏")


def stage_archive(
    archive: str | Path,
    device: DeviceInfo,
    session_store: SessionStore,
    policy: MethodPolicy,
    *,
    device_probe: DeviceProbe,
    required_files: Iterable[str],
    purpose: str | None = None,
    reserve_bytes: int = DEFAULT_RESERVE_BYTES,
    free_space: FreeSpaceProbe | None = None,
    progress: ProgressCallback | None = None,
    authorization_key: str | None = None,
) -> list[Path]:
    """先在主机检查归档，再逐文件复制、校验并记录设备端新文件。"""

    if policy.automation not in _STAGING_AUTOMATION:
        raise safety.StorageError("KJA_POLICY_DENIED", "当前越狱方法禁止直接暂存归档")
    required = tuple(required_files)
    if not required:
        raise safety.StorageError("KJA_REQUIRED_FILES", "暂存前必须指定至少一个关键文件")
    with safety.authorized_device_root(
        device, session_store, device_probe, authorization_key=authorization_key
    ) as (root, _state):
        return _stage_retained(
            archive,
            root,
            device,
            session_store,
            device_probe,
            required,
            purpose,
            reserve_bytes,
            free_space,
            progress,
        )


def _stage_retained(
    archive: str | Path,
    root: safety.SafeRootHandle,
    device: DeviceInfo,
    session_store: SessionStore,
    device_probe: DeviceProbe,
    required: tuple[str, ...],
    purpose: str | None,
    reserve_bytes: int,
    free_space: FreeSpaceProbe | None,
    progress: ProgressCallback | None,
) -> list[Path]:
    journal = CreatedFilesJournal(session_store, root)
    session_store.root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="kja-archive-", dir=session_store.root) as temporary:
        staging = Path(temporary) / "extracted"
        inspect_archive(archive, staging, required_files=required)
        staging = staging.resolve(strict=True)
        source_entries = safety.scan_tree(staging)
        _preflight_stage(
            root,
            source_entries,
            available_bytes=_retained_free_bytes(root, free_space),
            reserve_bytes=reserve_bytes,
        )
        file_total = sum(1 for entry in source_entries if entry.kind == "file")
        copied = 0
        created_files: list[Path] = []
        try:
            for entry in source_entries:
                relative = entry.relative
                safety.assert_same_device(device, device_probe())
                existing = safety.inspect_path(root, relative)
                if entry.kind == "directory":
                    if existing is not None:
                        continue
                    nonce = journal.begin_create(
                        relative, "directory", size=0, sha256=None, purpose=purpose
                    )
                    observed = safety.mkdir_exclusive(root, relative)
                    journal.mark_created(nonce, observed)
                    continue

                _create_parent_directories(relative.parent, root, journal, purpose=purpose)
                sidecar_relative = relative.with_name(f"._{relative.name}")
                sidecar_before = safety.inspect_path(root, sidecar_relative)
                nonce = journal.begin_create(
                    relative,
                    "file",
                    size=entry.size,
                    sha256=entry.sha256,
                    purpose=purpose,
                )
                size, digest = safety.copy_file_exclusive(staging, entry, root, relative)
                observed = safety.inspect_path(root, relative)
                if observed is None:
                    raise safety.StorageError("KJA_CREATE_FAILED", "载荷文件创建后消失")
                journal.mark_created(nonce, observed)
                if size != entry.size or digest != entry.sha256:
                    raise safety.StorageError("KJA_CHECKSUM_MISMATCH", "载荷复制校验失败")
                _remove_new_sidecar(root, sidecar_relative, sidecar_before)
                safety.assert_same_device(device, device_probe())
                created_files.append(root.path / relative)
                copied += 1
                _emit_progress(
                    progress,
                    Stage.PREPARE,
                    "正在复制并校验官方载荷",
                    copied,
                    file_total,
                    "files",
                )
            safety.assert_same_device(device, device_probe())
            safety.assert_retained_root(root)
            return created_files
        except (OSError, ValueError):
            _enter_recoverable_error(session_store)
            raise


def cleanup_created_files(
    device: DeviceInfo,
    session_store: SessionStore,
    *,
    device_probe: DeviceProbe,
    progress: ProgressCallback | None = None,
    authorization_key: str | None = None,
) -> list[Path]:
    """按日志状态倒序清理，并在所有权不明确时 fail-closed。"""

    with safety.authorized_device_root(
        device, session_store, device_probe, authorization_key=authorization_key
    ) as (root, _state):
        return _cleanup_retained(
            root,
            _state.session_id,
            device,
            session_store,
            device_probe,
            progress,
        )


def _cleanup_retained(
    root: safety.SafeRootHandle,
    session_id: str,
    device: DeviceInfo,
    session_store: SessionStore,
    device_probe: DeviceProbe,
    progress: ProgressCallback | None,
) -> list[Path]:
    manifest_path = session_store.root / "created-files.json"
    if not manifest_path.exists():
        safety.assert_same_device(device, device_probe())
        safety.assert_retained_root(root)
        return []
    journal = CreatedFilesJournal(session_store, root)
    entries = journal.entries()
    removed: list[Path] = []
    processed = 0
    try:
        for entry in reversed(entries):
            if entry.get("purpose") == "quarantine_directory":
                continue
            if entry.get("purpose") == "koreader":
                journal.finish(entry["ownership_nonce"])
                processed += 1
                continue
            relative = _safe_relative_path(entry["path"])
            safety.assert_same_device(device, device_probe())
            current = safety.inspect_path(root, relative)
            state = entry["state"]
            nonce = entry["ownership_nonce"]
            if state == "pending_create":
                if current is not None:
                    raise safety.StorageError(
                        "KJA_JOURNAL_AMBIGUOUS",
                        "未完成日志项仍有同名对象，拒绝自动删除",
                    )
                journal.clear_missing_replay_entry(nonce)
                processed += 1
                continue
            if state == "deleting":
                if current is not None:
                    raise safety.StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "删除中日志的原目标仍存在，拒绝自动处理",
                    )
                quarantine_value = entry.get("quarantine_path")
                if not isinstance(quarantine_value, str):
                    journal.clear_missing_replay_entry(nonce)
                    processed += 1
                    continue
                quarantine_relative = _safe_relative_path(quarantine_value)
                quarantined = safety.inspect_path(root, quarantine_relative)
                if quarantined is None:
                    raise safety.StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "删除中日志的隔离对象缺失，拒绝猜测回收结果",
                    )
                expected = _snapshot_from_observed(entry, quarantine_relative)
                if not _same_snapshot(expected, quarantined):
                    raise safety.StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "隔离区对象与删除日志不一致，拒绝回收",
                    )
                _reclaim_and_mark_tombstone(root, journal, nonce, quarantined)
                processed += 1
                continue
            if state == "tombstone":
                if current is not None:
                    raise safety.StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "tombstone 日志的原目标再次出现，拒绝自动处理",
                    )
                tombstone = _snapshot_from_tombstone(entry)
                _assert_tombstone_name(root, tombstone)
                processed += 1
                continue
            if current is None:
                journal.finish(nonce)
                processed += 1
                continue
            _assert_entry_matches(entry, current)
            if current.kind == "directory" and not safety.directory_is_empty(root, current):
                processed += 1
                continue
            quarantine_directory, _quarantine_nonce = _create_fresh_quarantine_directory(
                root,
                journal,
                session_id,
            )
            quarantine_name = f"{uuid.uuid4().hex}-{relative.name}"
            quarantine_relative = quarantine_directory / quarantine_name
            journal.mark_deleting(nonce, current, quarantine_relative)
            quarantined = safety.quarantine_move(
                root,
                current,
                quarantine_directory,
                quarantine_name,
            )
            _reclaim_and_mark_tombstone(root, journal, nonce, quarantined)
            removed.append(relative)
            processed += 1
            _emit_progress(
                progress,
                Stage.CLEANUP,
                "正在清理本次会话创建的临时文件",
                processed,
                len(entries),
                "paths",
            )
        safety.assert_same_device(device, device_probe())
        safety.assert_retained_root(root)
        return removed
    except (OSError, ValueError):
        _enter_recoverable_error(session_store)
        raise


def _create_fresh_quarantine_directory(
    root: safety.RootReference,
    journal: CreatedFilesJournal,
    session_id: str,
) -> tuple[Path, str]:
    for _attempt in range(8):
        relative = Path(
            f".kja-quarantine-{session_id[:8]}-{uuid.uuid4().hex}"
        )
        if safety.inspect_path(root, relative) is not None:
            continue
        nonce = journal.begin_create(
            relative,
            "directory",
            size=0,
            sha256=None,
            purpose="quarantine_directory",
        )
        observed = safety.mkdir_exclusive(root, relative)
        journal.mark_created(nonce, observed)
        return relative, nonce
    raise safety.StorageError(
        "KJA_OWNERSHIP_AMBIGUOUS",
        "无法取得新的 session quarantine 目录",
    )


def _delete_quarantined_or_retain(
    root: safety.RootReference,
    quarantined: safety.EntrySnapshot,
) -> safety.EntrySnapshot:
    return safety.delete_quarantined(root, quarantined)


def _reclaim_and_mark_tombstone(
    root: safety.RootReference,
    journal: CreatedFilesJournal,
    nonce: str,
    quarantined: safety.EntrySnapshot,
) -> None:
    if quarantined.kind == "file":
        reclaimed = _delete_quarantined_or_retain(root, quarantined)
        journal.mark_tombstone(nonce, reclaimed)
        _assert_tombstone_name(root, reclaimed)
        return
    with safety.retain_directory_lease(root, quarantined) as lease:
        try:
            reclaimed = lease.validate_empty_and_named()
            journal.mark_tombstone(nonce, reclaimed)
            lease.validate_empty_and_named()
        except (OSError, ValueError):
            journal.retain_deleting(nonce)
            raise


def _assert_tombstone_name(
    root: safety.RootReference,
    expected: safety.EntrySnapshot,
) -> None:
    current = safety.inspect_path(root, expected.relative)
    if current is None or not _same_tombstone_snapshot(expected, current):
        raise safety.StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine tombstone 名称已被替换；替换对象保持不动",
        )


def _snapshot_from_observed(
    entry: dict[str, Any],
    relative: Path,
) -> safety.EntrySnapshot:
    observed = entry.get("observed")
    if not isinstance(observed, dict):
        raise safety.StorageError("KJA_JOURNAL_INVALID", "删除日志缺少观察身份")
    try:
        return safety.EntrySnapshot(
            relative=relative,
            kind=str(observed["type"]),
            device=int(observed["device"]),
            inode=int(observed["inode"]),
            mode=int(observed["mode"]),
            size=int(observed["size"]),
            modified_ns=int(observed["modified_ns"]),
            changed_ns=int(observed.get("changed_ns", 0)),
            sha256=observed["sha256"] if observed["sha256"] is None else str(observed["sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise safety.StorageError("KJA_JOURNAL_INVALID", "删除日志观察身份无效") from exc


def _snapshot_from_tombstone(entry: dict[str, Any]) -> safety.EntrySnapshot:
    quarantine_value = entry.get("quarantine_path")
    if not isinstance(quarantine_value, str):
        raise safety.StorageError("KJA_JOURNAL_INVALID", "tombstone 日志缺少隔离路径")
    relative = _safe_relative_path(quarantine_value)
    observed = entry.get("tombstone_identity")
    if not isinstance(observed, dict):
        raise safety.StorageError("KJA_JOURNAL_INVALID", "tombstone 日志缺少验证身份")
    try:
        return safety.EntrySnapshot(
            relative=relative,
            kind=str(observed["type"]),
            device=int(observed["device"]),
            inode=int(observed["inode"]),
            mode=int(observed["mode"]),
            size=int(observed["size"]),
            modified_ns=int(observed["modified_ns"]),
            changed_ns=int(observed.get("changed_ns", 0)),
            sha256=(
                observed["sha256"]
                if observed["sha256"] is None
                else str(observed["sha256"])
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise safety.StorageError("KJA_JOURNAL_INVALID", "tombstone 日志验证身份无效") from exc


def _same_snapshot(left: safety.EntrySnapshot, right: safety.EntrySnapshot) -> bool:
    return (
        left.kind == right.kind
        and left.device == right.device
        and left.inode == right.inode
        and left.mode == right.mode
        and left.size == right.size
        and left.sha256 == right.sha256
    )


def _same_tombstone_snapshot(
    left: safety.EntrySnapshot,
    right: safety.EntrySnapshot,
) -> bool:
    same = _same_snapshot(left, right)
    if left.kind == "directory" and right.kind == "directory":
        return (
            same
            and left.modified_ns == right.modified_ns
            and left.changed_ns == right.changed_ns
        )
    return same


def _next_chunk_index(entries: list[dict[str, Any]], filler: Path) -> int:
    next_index = 0
    pattern = re.compile(re.escape(filler.as_posix()) + r"/chunk-(\d{6})\.bin")
    for entry in entries:
        match = pattern.fullmatch(str(entry["path"]))
        if match:
            next_index = max(next_index, int(match.group(1)) + 1)
    return next_index


def _retained_free_bytes(
    root: safety.SafeRootHandle,
    probe: FreeSpaceProbe | None,
) -> int:
    return int(probe(root)) if probe is not None else safety.retained_free_bytes(root)


def _preflight_stage(
    root: safety.RootReference,
    entries: list[safety.EntrySnapshot],
    *,
    available_bytes: int,
    reserve_bytes: int,
) -> None:
    if reserve_bytes < DEFAULT_RESERVE_BYTES:
        raise safety.StorageError("KJA_SPACE_POLICY", "载荷暂存必须至少保留 80 MiB")
    total_bytes = 0
    portable_paths: set[str] = set()
    for entry in entries:
        portable = unicodedata.normalize("NFC", entry.relative.as_posix()).casefold()
        if portable in portable_paths:
            raise safety.StorageError("KJA_FAT32_NAME", "载荷含有 FAT32 会冲突的路径")
        portable_paths.add(portable)
        if entry.kind == "file":
            if entry.size > _FAT32_MAX_FILE_BYTES:
                raise safety.StorageError("KJA_FAT32_SIZE", "单个载荷文件超过 FAT32 上限")
            total_bytes += entry.size
        existing = safety.inspect_path(root, entry.relative)
        if entry.kind == "file" and existing is not None:
            raise safety.StorageError("KJA_TARGET_EXISTS", "载荷目标已存在，拒绝覆盖")
        if entry.kind == "directory" and existing is not None and existing.kind != "directory":
            raise safety.StorageError("KJA_TARGET_EXISTS", "载荷目录目标被非目录占用")
    if available_bytes - reserve_bytes < total_bytes:
        raise safety.StorageError("KJA_INSUFFICIENT_SPACE", "设备空间不足，无法安全暂存载荷")


def _create_parent_directories(
    relative_parent: Path,
    root: safety.RootReference,
    journal: CreatedFilesJournal,
    *,
    purpose: str | None = None,
) -> None:
    if relative_parent == Path("."):
        return
    current = Path()
    for part in relative_parent.parts:
        current = current / part
        existing = safety.inspect_path(root, current)
        if existing is not None:
            if existing.kind != "directory":
                raise safety.StorageError("KJA_UNSAFE_PATH", "载荷父路径不是目录")
            continue
        nonce = journal.begin_create(
            current, "directory", size=0, sha256=None, purpose=purpose
        )
        observed = safety.mkdir_exclusive(root, current)
        journal.mark_created(nonce, observed)


def _remove_new_sidecar(
    root: safety.RootReference,
    relative: Path,
    before: safety.EntrySnapshot | None,
) -> None:
    after = safety.inspect_path(root, relative)
    if before is None and after is not None:
        if after.kind != "file":
            raise safety.StorageError("KJA_SIDECAR_UNSAFE", "新产生的 AppleDouble 旁文件类型异常")
        safety.unlink_snapshot(root, after)


def _assert_entry_matches(entry: dict[str, Any], observed: safety.EntrySnapshot) -> None:
    if (
        entry.get("path") != observed.relative.as_posix()
        or entry.get("type") != observed.kind
        or entry.get("size") != observed.size
        or entry.get("sha256") != observed.sha256
    ):
        raise safety.StorageError("KJA_JOURNAL_AMBIGUOUS", "当前对象与创建日志不一致，拒绝操作")


def _assert_created_identity(
    entry: dict[str, Any],
    observed: safety.EntrySnapshot,
) -> None:
    identity = entry.get("created_identity")
    if not isinstance(identity, dict) or (
        identity.get("device") != observed.device
        or identity.get("inode") != observed.inode
        or identity.get("mode") != observed.mode
        or identity.get("modified_ns") != observed.modified_ns
        or identity.get("changed_ns") != observed.changed_ns
    ):
        raise safety.StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine 目录所有权无法由当前会话证明",
        )


def _write_zeros(handle: BinaryIO, size: int) -> None:
    zeroes = bytes(min(MIB, size))
    remaining = size
    while remaining:
        block = zeroes if remaining >= len(zeroes) else bytes(remaining)
        written = handle.write(block)
        if written <= 0:
            raise OSError("zero-byte write")
        remaining -= written


def _zero_sha256(size: int) -> str:
    digest = hashlib.sha256()
    block = bytes(min(MIB, size))
    remaining = size
    while remaining:
        current = block if remaining >= len(block) else bytes(remaining)
        digest.update(current)
        remaining -= len(current)
    return digest.hexdigest()


def _safe_relative_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径不是安全相对路径")
    raw_parts = value.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径包含点分段或父目录穿越")
    if any(not part for part in raw_parts[:-1]):
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径包含空分段")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径不能是绝对路径")
    if any(part == ".." for part in posix.parts):
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径不能包含父目录穿越")
    parts = [part for part in posix.parts if part not in {"", "."}]
    if not parts:
        raise safety.StorageError("KJA_UNSAFE_PATH", "路径不能为空")
    for part in parts:
        if PureWindowsPath(part).is_reserved() or part.endswith((" ", ".")):
            raise safety.StorageError("KJA_FAT32_NAME", "路径包含 FAT32 保留名称")
        if any(character in _FAT32_FORBIDDEN_CHARACTERS for character in part):
            raise safety.StorageError("KJA_FAT32_NAME", "路径包含 FAT32 禁止字符")
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise safety.StorageError("KJA_FAT32_NAME", "路径包含控制字符")
    return Path(*parts)


def _require_archive_files(required: set[str], members) -> None:
    regular = {relative.as_posix() for relative, kind, _item in members if kind == "file"}
    missing = sorted(required.difference(regular))
    if missing:
        raise safety.StorageError("KJA_ARCHIVE_REQUIRED", "归档缺少指定关键文件")


def _inspect_zip(archive: Path, staging: Path):
    inspected = []
    seen: set[str] = set()
    portable_seen: set[str] = set()
    try:
        with zipfile.ZipFile(archive) as bundle:
            bad = bundle.testzip()
            if bad is not None:
                raise safety.StorageError("KJA_ARCHIVE_INVALID", "ZIP 完整性检查失败")
            for member in bundle.infolist():
                relative = _safe_relative_path(member.filename)
                key = relative.as_posix()
                portable = unicodedata.normalize("NFC", key).casefold()
                if key in seen or portable in portable_seen:
                    raise safety.StorageError("KJA_FAT32_NAME", "归档包含重复或 FAT32 冲突路径")
                seen.add(key)
                portable_seen.add(portable)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise safety.StorageError("KJA_ARCHIVE_LINK", "归档链接不允许解压")
                kind = "directory" if member.is_dir() else "file"
                safety.lexical_path(staging, relative)
                inspected.append((relative, kind, member))
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise safety.StorageError("KJA_ARCHIVE_INVALID", "ZIP 归档损坏或不可读取") from exc
    return inspected


def _inspect_tar(archive: Path, staging: Path):
    inspected = []
    seen: set[str] = set()
    portable_seen: set[str] = set()
    try:
        with tarfile.open(archive, "r:*") as bundle:
            for member in bundle.getmembers():
                relative = _safe_relative_path(member.name)
                key = relative.as_posix()
                portable = unicodedata.normalize("NFC", key).casefold()
                if key in seen or portable in portable_seen:
                    raise safety.StorageError("KJA_FAT32_NAME", "归档包含重复或 FAT32 冲突路径")
                seen.add(key)
                portable_seen.add(portable)
                if member.isdir():
                    kind = "directory"
                elif member.isfile():
                    kind = "file"
                    source = bundle.extractfile(member)
                    if source is None:
                        raise safety.StorageError("KJA_ARCHIVE_INVALID", "TAR 成员不可读取")
                    with source:
                        while source.read(MIB):
                            pass
                else:
                    raise safety.StorageError("KJA_ARCHIVE_LINK", "归档链接或特殊文件不允许解压")
                safety.lexical_path(staging, relative)
                inspected.append((relative, kind, member))
    except (tarfile.TarError, OSError) as exc:
        raise safety.StorageError("KJA_ARCHIVE_INVALID", "TAR 归档损坏或不可读取") from exc
    return inspected


def _extract_zip(archive: Path, staging: Path, members) -> list[Path]:
    created: list[Path] = []
    files: list[Path] = []
    try:
        staging.mkdir()
        created.append(staging)
        with zipfile.ZipFile(archive) as bundle:
            for relative, kind, member in members:
                destination = safety.lexical_path(staging, relative)
                if kind == "directory":
                    _mkdir_host_exact(destination, staging, created)
                    continue
                _mkdir_host_exact(destination.parent, staging, created)
                with bundle.open(member) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, length=MIB)
                    target.flush()
                    os.fsync(target.fileno())
                created.append(destination)
                files.append(destination)
    except Exception:
        _remove_host_exact(created)
        raise
    return files


def _extract_tar(archive: Path, staging: Path, members) -> list[Path]:
    created: list[Path] = []
    files: list[Path] = []
    try:
        staging.mkdir()
        created.append(staging)
        with tarfile.open(archive, "r:*") as bundle:
            by_name = {member.name: member for member in bundle.getmembers()}
            for relative, kind, original in members:
                destination = safety.lexical_path(staging, relative)
                if kind == "directory":
                    _mkdir_host_exact(destination, staging, created)
                    continue
                _mkdir_host_exact(destination.parent, staging, created)
                source = bundle.extractfile(by_name[original.name])
                if source is None:
                    raise safety.StorageError("KJA_ARCHIVE_INVALID", "TAR 成员不可读取")
                with source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, length=MIB)
                    target.flush()
                    os.fsync(target.fileno())
                created.append(destination)
                files.append(destination)
    except Exception:
        _remove_host_exact(created)
        raise
    return files


def _mkdir_host_exact(directory: Path, root: Path, created: list[Path]) -> None:
    missing: list[Path] = []
    cursor = directory
    while cursor != root and not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise safety.StorageError("KJA_STAGE_INVALID", "主机暂存父路径不安全")
    for item in reversed(missing):
        item.mkdir()
        created.append(item)


def _remove_host_exact(created: list[Path]) -> None:
    for path in reversed(created):
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        except FileNotFoundError:
            pass


def _enter_recoverable_error(store: SessionStore) -> None:
    state = store.load()
    if state.stage != Stage.RECOVERABLE_ERROR:
        state.transition(Stage.RECOVERABLE_ERROR)
        store.save(state)


def _emit_progress(
    callback: ProgressCallback | None,
    stage: Stage,
    message: str,
    done: int,
    total: int | None,
    unit: str,
) -> None:
    if callback is not None:
        callback(ProgressEvent(
            event="progress",
            stage=stage,
            message=message,
            done=done,
            total=total,
            unit=unit,
            user_action=None,
        ))

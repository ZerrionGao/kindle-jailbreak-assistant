"""Windows/Linux MTP 的安全 JSON 适配层与主流程文件操作。"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .models import DeviceInfo, EvidenceResult, Stage
from .progress import ProgressEvent
from .routing import MethodPolicy
from .session import SessionStore
from .storage_payload import DEFAULT_RESERVE_BYTES, inspect_archive
from .storage_safety import StorageError


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StorageError("KJA_UNSAFE_PATH", "MTP 相对路径无效")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise StorageError("KJA_UNSAFE_PATH", "MTP 相对路径越界")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts or any(":" in part for part in parts):
        raise StorageError("KJA_UNSAFE_PATH", "MTP 相对路径无效")
    return PurePosixPath(*parts).as_posix()


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _adapter_prefix() -> list[str]:
    test_adapter = os.environ.get("KJA_TEST_MTP_ADAPTER")
    if test_adapter:
        if os.environ.get("KJA_TEST_MODE") != "1":
            raise StorageError("KJA_MTP_UNAVAILABLE", "测试 MTP 适配器只允许隔离测试使用")
        path = Path(test_adapter).expanduser()
        try:
            path.resolve(strict=True).relative_to(Path(tempfile.gettempdir()).resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise StorageError("KJA_MTP_UNAVAILABLE", "测试 MTP 适配器必须位于临时目录") from exc
        return [sys.executable, str(path)]
    scripts = Path(__file__).resolve().parents[1]
    system = platform.system().lower()
    if system == "linux":
        return ["/bin/bash", str(scripts / "kindle_mtp_linux.sh")]
    if system == "windows":
        return [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-File",
            str(scripts / "kindle_mtp_windows.ps1"),
        ]
    raise StorageError("KJA_MTP_UNAVAILABLE", "当前平台没有已批准的 MTP 适配器")


def _invoke(device: DeviceInfo, action: str, *arguments: str) -> dict[str, object]:
    if device.transport != "mtp" or not device.transport_id:
        raise StorageError("KJA_DEVICE_IDENTITY", "MTP 设备缺少稳定传输身份")
    completed = subprocess.run(
        [*_adapter_prefix(), action, device.transport_id, *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    lines = completed.stdout.splitlines()
    try:
        payload = json.loads(lines[0]) if len(lines) == 1 else None
    except json.JSONDecodeError:
        payload = None
    if (
        completed.returncode != 0
        or not isinstance(payload, dict)
        or payload.get("ok") is not True
        or payload.get("action") != action
    ):
        code = payload.get("error_code") if isinstance(payload, dict) else None
        if code == "device_not_found":
            raise StorageError("KJA_DEVICE_UNAVAILABLE", "MTP Kindle 已断开或身份已改变")
        raise StorageError("KJA_MTP_OPERATION_FAILED", "MTP 适配器未返回可验证的成功结果")
    return payload


def _entries(device: DeviceInfo) -> list[dict[str, object]]:
    payload = _invoke(device, "list-files")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise StorageError("KJA_MTP_OPERATION_FAILED", "MTP 文件清单格式无效")
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise StorageError("KJA_MTP_OPERATION_FAILED", "MTP 文件清单格式无效")
        path = _safe_relative(raw.get("path")) if isinstance(raw.get("path"), str) else None
        kind = raw.get("kind")
        size = raw.get("size")
        key = _portable_key(path) if path is not None else ""
        if (
            path is None
            or key in seen
            or kind not in {"file", "directory"}
            or (kind == "file" and (not isinstance(size, int) or isinstance(size, bool) or size < 0))
            or (kind == "directory" and size is not None)
        ):
            raise StorageError("KJA_MTP_OPERATION_FAILED", "MTP 文件清单缺少安全路径或大小证据")
        seen.add(key)
        entries.append({"path": path, "kind": kind, "size": size})
    return entries


def list_paths(device: DeviceInfo) -> list[dict[str, object]]:
    return _entries(device)


def file_snapshot(device: DeviceInfo, remote: str) -> tuple[int, str]:
    remote = _safe_relative(remote)
    entry = next(
        (
            item for item in _entries(device)
            if item["path"] == remote and item["kind"] == "file"
        ),
        None,
    )
    if entry is None:
        raise StorageError("KJA_EVIDENCE_MISSING", "MTP 方法证据文件不存在")
    with tempfile.TemporaryDirectory(prefix="kja-mtp-evidence-") as temporary:
        size, digest = _remote_digest(device, remote, Path(temporary))
    if size != entry["size"]:
        raise StorageError("KJA_EVIDENCE_MISSING", "MTP 方法证据文件大小不稳定")
    return size, digest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy_from(device: DeviceInfo, remote: str, destination: Path) -> None:
    _invoke(device, "copy-from", _safe_relative(remote), str(destination))
    if not destination.is_file():
        raise StorageError("KJA_CHECKSUM_MISMATCH", "MTP 读取未生成本地文件")


def _remote_digest(device: DeviceInfo, remote: str, parent: Path) -> tuple[int, str]:
    target = parent / Path(remote).name
    _copy_from(device, remote, target)
    return target.stat().st_size, _sha256(target)


def _ensure_remote_directories(
    device: DeviceInfo,
    relative: str,
    existing: set[str],
    session_store: SessionStore,
    *,
    cleanup: bool,
) -> list[str]:
    created = []
    parents = list(PurePosixPath(relative).parents)
    for parent in reversed(parents[:-1]):
        value = parent.as_posix()
        if value in {".", ""}:
            continue
        if value in existing:
            record = _created_records(session_store).get(value)
            if isinstance(record, dict) and record.get("state") == "pending_create":
                observed = next(
                    (item for item in _entries(device) if item["path"] == value),
                    None,
                )
                if observed is None or observed.get("kind") != "directory":
                    raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 待提交目录的类型不一致")
                _mark_created(session_store, value)
            continue
        _begin_create(session_store, value, "directory", 0, None, cleanup=cleanup)
        _invoke(device, "mkdir", value)
        _mark_created(session_store, value)
        existing.add(value)
        created.append(value)
    return created


def _copy_to_verified(device: DeviceInfo, source: Path, remote: str) -> str:
    remote = _safe_relative(remote)
    _invoke(device, "copy-to", str(source), remote)
    with tempfile.TemporaryDirectory(prefix="kja-mtp-verify-") as temporary:
        size, digest = _remote_digest(device, remote, Path(temporary))
    if size != source.stat().st_size or digest != _sha256(source):
        raise StorageError("KJA_CHECKSUM_MISMATCH", "MTP 写入后的回读摘要不一致")
    return digest


def backup_visible_storage(
    device: DeviceInfo,
    backup_parent: Path,
    session_store: SessionStore,
    *,
    timestamp: str | None,
    progress,
) -> Path:
    state = session_store.load()
    entries = _entries(device)
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if len(stamp) != 16 or not stamp.endswith("Z"):
        raise StorageError("KJA_BACKUP_TIMESTAMP", "备份时间戳格式必须为 YYYYMMDDTHHMMSSZ")
    parent = backup_parent.expanduser().resolve(strict=False)
    destination = parent / stamp
    partial = parent / f".{stamp}.{state.session_id}.partial"
    parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or partial.exists():
        raise StorageError("KJA_BACKUP_EXISTS", "同名 MTP 备份已存在，拒绝覆盖")
    content = partial / "content"
    content.mkdir(parents=True)
    manifest_entries = []
    files = [entry for entry in entries if entry["kind"] == "file"]
    try:
        for index, entry in enumerate(files, start=1):
            relative = str(entry["path"])
            target = content / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_from(device, relative, target)
            size = target.stat().st_size
            digest = _sha256(target)
            if size != entry["size"]:
                raise StorageError("KJA_BACKUP_VERIFY", "MTP 备份大小与设备清单不一致")
            with tempfile.TemporaryDirectory(prefix="kja-mtp-backup-check-") as temporary:
                check_size, check_digest = _remote_digest(device, relative, Path(temporary))
            if check_size != size or check_digest != digest:
                raise StorageError("KJA_BACKUP_VERIFY", "MTP 备份回读摘要不稳定")
            manifest_entries.append({"path": relative, "kind": "file", "size": size, "sha256": digest})
            if progress:
                progress(ProgressEvent("progress", Stage.BACKUP, "正在复制并校验 MTP 可见内容", index, len(files), "files"))
        if _entries(device) != entries:
            raise StorageError("KJA_BACKUP_VERIFY", "MTP 备份期间设备文件清单发生变化")
        for entry in manifest_entries:
            relative = str(entry["path"])
            with tempfile.TemporaryDirectory(prefix="kja-mtp-final-backup-check-") as temporary:
                final_size, final_digest = _remote_digest(device, relative, Path(temporary))
            if final_size != entry["size"] or final_digest != entry["sha256"]:
                raise StorageError("KJA_BACKUP_VERIFY", "MTP 备份发布前内容发生变化")
        (partial / "manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "transport": "mtp",
            "created_at": stamp,
            "entries": manifest_entries,
        }, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
        (partial / "backup-complete.json").write_text(json.dumps({
            "schema_version": 1,
            "state": "complete",
            "session_id": state.session_id,
            "device_fingerprint": state.device_fingerprint,
        }, separators=(",", ":")) + "\n", encoding="utf-8")
        partial.rename(destination)
    except Exception:
        raise
    return destination


def _created_records(session_store: SessionStore) -> dict[str, object]:
    raw = session_store.load().evidence.get("mtp_created_records")
    return dict(raw) if isinstance(raw, dict) else {}


def _begin_create(
    session_store: SessionStore,
    path: str,
    kind: str,
    size: int,
    sha256: str | None,
    *,
    cleanup: bool,
) -> None:
    state = session_store.load()
    records = state.evidence.get("mtp_created_records")
    if not isinstance(records, dict):
        records = {}
    existing = records.get(path)
    expected = {
        "kind": kind,
        "size": size,
        "sha256": sha256,
        "cleanup": cleanup,
    }
    if isinstance(existing, dict):
        if any(existing.get(name) != value for name, value in expected.items()):
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 创建记录与当前操作不一致")
        return
    if path not in state.created_files:
        state.created_files.append(path)
    records[path] = {**expected, "state": "pending_create"}
    state.evidence["mtp_created_records"] = records
    session_store.save(state)


def _mark_created(session_store: SessionStore, path: str) -> None:
    state = session_store.load()
    records = state.evidence.get("mtp_created_records")
    if not isinstance(records, dict) or not isinstance(records.get(path), dict):
        raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 创建记录在提交结果前丢失")
    record = dict(records[path])
    if record.get("state") not in {"pending_create", "created"}:
        raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 创建记录状态无效")
    record["state"] = "created"
    records = dict(records)
    records[path] = record
    state.evidence["mtp_created_records"] = records
    session_store.save(state)


def fill_storage(device: DeviceInfo, session_store: SessionStore, *, chunk_bytes: int, progress) -> list[str]:
    free = _invoke(device, "free-bytes").get("free_bytes")
    if not isinstance(free, int) or isinstance(free, bool) or free < DEFAULT_RESERVE_BYTES:
        raise StorageError("KJA_INSUFFICIENT_SPACE", "MTP 可用空间证据不足")
    remaining = free
    created = []
    state = session_store.load()
    raw_records = state.evidence.get("mtp_created_records")
    records = raw_records if isinstance(raw_records, dict) else {}
    owned_fill = sorted(
        path for path, record in records.items()
        if path.startswith(f".kja-fill-{state.session_id[:8]}-")
        and isinstance(record, dict)
        and record.get("kind") == "file"
        and record.get("cleanup") is True
    )
    for path in owned_fill:
        record = records[path]
        exists = _invoke(device, "exists", path).get("exists") is True
        if not exists and record.get("state") != "pending_create":
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 已登记占位文件在恢复时消失")
        if not exists:
            with tempfile.TemporaryDirectory(prefix="kja-mtp-fill-resume-create-") as temporary:
                source = Path(temporary) / Path(path).name
                with source.open("wb") as handle:
                    handle.truncate(int(record["size"]))
                digest = _copy_to_verified(device, source, path)
            size = int(record["size"])
        else:
            with tempfile.TemporaryDirectory(prefix="kja-mtp-fill-resume-") as temporary:
                size, digest = _remote_digest(device, path, Path(temporary))
        if size != record.get("size") or digest != record.get("sha256"):
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 已登记占位文件在恢复时被替换")
        _mark_created(session_store, path)
        created.append(path)
    indices = []
    for path in owned_fill:
        try:
            indices.append(int(path.rsplit("-", 1)[1]))
        except ValueError:
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 占位记录编号无效") from None
    index = max(indices, default=0)
    while remaining > DEFAULT_RESERVE_BYTES:
        index += 1
        size = min(chunk_bytes, remaining - DEFAULT_RESERVE_BYTES)
        remote = f".kja-fill-{state.session_id[:8]}-{index:04d}"
        if _invoke(device, "exists", remote).get("exists") is not False:
            raise StorageError("KJA_TARGET_EXISTS", "MTP 占位目标已存在")
        with tempfile.TemporaryDirectory(prefix="kja-mtp-fill-") as temporary:
            source = Path(temporary) / Path(remote).name
            with source.open("wb") as handle:
                handle.truncate(size)
            expected_digest = _sha256(source)
            _begin_create(
                session_store, remote, "file", size, expected_digest, cleanup=True
            )
            digest = _copy_to_verified(device, source, remote)
        _mark_created(session_store, remote)
        created.append(remote)
        remaining -= size
        if progress:
            progress(ProgressEvent("progress", Stage.PREPARE, "正在创建并校验 MTP 占位文件", free - remaining, free - DEFAULT_RESERVE_BYTES, "bytes"))
    return created


def stage_archive(
    archive: str,
    device: DeviceInfo,
    session_store: SessionStore,
    policy: MethodPolicy,
    *,
    required_files: tuple[str, ...],
    purpose: str,
    progress,
) -> list[str]:
    if policy.automation not in {
        "guided-assets", "guided-assets-or-browser", "guided-assets-and-browser",
        "guided-assets-and-store", "guided-update-package",
    }:
        raise StorageError("KJA_POLICY_DENIED", "当前越狱方法禁止直接暂存归档")
    if not required_files:
        raise StorageError("KJA_REQUIRED_FILES", "暂存前必须指定至少一个关键文件")
    with tempfile.TemporaryDirectory(prefix="kja-mtp-archive-", dir=session_store.root) as temporary:
        staging = Path(temporary) / "extracted"
        inspect_archive(archive, staging, required_files=required_files)
        entries = _entries(device)
        existing = {str(entry["path"]) for entry in entries}
        existing_by_key = {_portable_key(path): path for path in existing}
        sources = sorted(path for path in staging.rglob("*") if path.is_file())
        state = session_store.load()
        raw_records = state.evidence.get("mtp_created_records")
        records = raw_records if isinstance(raw_records, dict) else {}
        free = _invoke(device, "free-bytes").get("free_bytes")
        required_bytes = sum(
            source.stat().st_size
            for source in sources
            if source.relative_to(staging).as_posix() not in existing
        )
        if (
            not isinstance(free, int)
            or isinstance(free, bool)
            or free - DEFAULT_RESERVE_BYTES < required_bytes
        ):
            raise StorageError("KJA_INSUFFICIENT_SPACE", "MTP 缺少保留安全空间后的可用容量证据")
        staged_paths = sorted(path for path in staging.rglob("*"))
        staged_keys: set[str] = set()
        for staged in staged_paths:
            relative = staged.relative_to(staging).as_posix()
            key = _portable_key(relative)
            if key in staged_keys:
                raise StorageError("KJA_FAT32_NAME", "MTP 归档包含大小写或 Unicode 规范化冲突")
            staged_keys.add(key)
            existing_path = existing_by_key.get(key)
            can_resume_file = (
                staged.is_file()
                and existing_path == relative
                and isinstance(records.get(relative), dict)
            )
            if existing_path is not None and not can_resume_file and (
                staged.is_file() or existing_path != relative
            ):
                raise StorageError("KJA_TARGET_EXISTS", "MTP 载荷目标与既有便携路径冲突")
        created: list[str] = []
        created_dirs: set[str] = set()
        for index, source in enumerate(sources, start=1):
            relative = source.relative_to(staging).as_posix()
            if relative in existing:
                record = records.get(relative)
                expected_digest = _sha256(source)
                if (
                    not isinstance(record, dict)
                    or record.get("state") not in {"pending_create", "created"}
                    or record.get("kind") != "file"
                    or record.get("size") != source.stat().st_size
                    or record.get("sha256") != expected_digest
                ):
                    raise StorageError("KJA_TARGET_EXISTS", "MTP 载荷目标已存在且不属于当前会话")
                with tempfile.TemporaryDirectory(prefix="kja-mtp-stage-resume-") as verify_dir:
                    size, digest = _remote_digest(device, relative, Path(verify_dir))
                if size != source.stat().st_size or digest != expected_digest:
                    raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 已登记载荷在恢复时被替换")
                _mark_created(session_store, relative)
                created.append(relative)
                if progress:
                    progress(ProgressEvent("progress", Stage.PREPARE, "正在核对已复制的 MTP 官方载荷", index, len(sources), "files"))
                continue
            for directory in _ensure_remote_directories(
                device,
                relative,
                existing,
                session_store,
                cleanup=purpose != "koreader",
            ):
                created_dirs.add(directory)
            expected_digest = _sha256(source)
            _begin_create(
                session_store,
                relative,
                "file",
                source.stat().st_size,
                expected_digest,
                cleanup=purpose != "koreader",
            )
            digest = _copy_to_verified(device, source, relative)
            _mark_created(session_store, relative)
            created.append(relative)
            if progress:
                progress(ProgressEvent("progress", Stage.PREPARE, "正在复制并校验 MTP 官方载荷", index, len(sources), "files"))
        return created


def verify_jailbreak(
    device: DeviceInfo,
    *,
    markers: tuple[str, ...],
    excluded: set[str],
    user_log: bool,
) -> EvidenceResult:
    entries = {str(entry["path"]): entry for entry in _entries(device)}
    observed = [
        marker for marker in markers
        if marker not in excluded and entries.get(marker, {}).get("kind") == "file"
    ]
    if user_log:
        observed.append(";log_user_report")
    return EvidenceResult(bool(observed), [] if observed else ["jailbreak_marker"], tuple(observed))


def verify_koreader(device: DeviceInfo) -> EvidenceResult:
    paths = [str(entry["path"]) for entry in _entries(device)]
    present = any(path == ".adds/koreader" or path.startswith(".adds/koreader/") for path in paths)
    missing = [] if present else ["koreader_files"]
    missing.append("user_visible_launch")
    return EvidenceResult(False, missing, ("koreader_files",) if present else ())


def unknown_ota_packages(device: DeviceInfo, records: dict[str, object]) -> list[str]:
    unknown = []
    for entry in _entries(device):
        path = str(entry["path"])
        if "/" in path or entry["kind"] != "file":
            continue
        lowered = path.lower()
        if lowered.endswith(".bin") or lowered.endswith(".tmp.partial"):
            record = records.get(path)
            if (
                not isinstance(record, dict)
                or record.get("kind") != "file"
                or record.get("state") != "created"
                or record.get("removed") is True
            ):
                unknown.append(path)
                continue
            with tempfile.TemporaryDirectory(prefix="kja-mtp-ota-check-") as temporary:
                size, digest = _remote_digest(device, path, Path(temporary))
            if size != record.get("size") or digest != record.get("sha256"):
                unknown.append(path)
    return sorted(unknown)


def cleanup_created_files(device: DeviceInfo, session_store: SessionStore, *, progress) -> list[str]:
    state = session_store.load()
    raw = state.evidence.get("mtp_created_records")
    records = raw if isinstance(raw, dict) else {}
    cleanup_paths = [
        path for path, record in records.items()
        if isinstance(record, dict)
        and record.get("cleanup") is True
        and record.get("removed") is not True
    ]
    files = [path for path in cleanup_paths if records[path].get("kind") == "file"]
    directories = sorted(
        (path for path in cleanup_paths if records[path].get("kind") == "directory"),
        key=lambda value: (value.count("/"), value),
        reverse=True,
    )
    removed = []
    for index, path in enumerate(files, start=1):
        record = records[path]
        exists = _invoke(device, "exists", path).get("exists") is True
        if not exists and record.get("state") == "deleting":
            _mark_removed(session_store, path)
            removed.append(path)
            continue
        if not exists:
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理目标已消失或被替换")
        with tempfile.TemporaryDirectory(prefix="kja-mtp-cleanup-check-") as temporary:
            size, digest = _remote_digest(device, path, Path(temporary))
        if size != record.get("size") or digest != record.get("sha256"):
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理目标内容已被替换")
        _mark_deleting(session_store, path)
        _invoke(device, "delete", path)
        if _invoke(device, "exists", path).get("exists") is not False:
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理后目标仍然存在")
        _mark_removed(session_store, path)
        removed.append(path)
        if progress:
            progress(ProgressEvent("progress", Stage.CLEANUP, "正在精确清理 MTP 临时文件", index, len(cleanup_paths), "paths"))
    for path in directories:
        current_entries = _entries(device)
        current_paths = {str(entry["path"]) for entry in current_entries}
        record = records[path]
        if path not in current_paths and record.get("state") == "deleting":
            _mark_removed(session_store, path)
            removed.append(path)
            continue
        if path not in current_paths:
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理目录已消失或被替换")
        current_entry = next(entry for entry in current_entries if entry["path"] == path)
        if current_entry.get("kind") != "directory":
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理目录已被同名非目录对象替换")
        prefix = path.rstrip("/") + "/"
        if any(candidate.startswith(prefix) for candidate in current_paths):
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理目录中出现非会话内容")
        _mark_deleting(session_store, path)
        _invoke(device, "delete", path)
        if _invoke(device, "exists", path).get("exists") is not False:
            raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理后目录仍然存在")
        _mark_removed(session_store, path)
        removed.append(path)
    return removed


def _mark_removed(session_store: SessionStore, path: str) -> None:
    state = session_store.load()
    raw = state.evidence.get("mtp_created_records")
    records = raw if isinstance(raw, dict) else {}
    record = records.get(path)
    if not isinstance(record, dict):
        raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理记录在提交删除结果前丢失")
    updated = dict(record)
    updated["removed"] = True
    records = dict(records)
    records[path] = updated
    state.evidence["mtp_created_records"] = records
    session_store.save(state)


def _mark_deleting(session_store: SessionStore, path: str) -> None:
    state = session_store.load()
    raw = state.evidence.get("mtp_created_records")
    records = raw if isinstance(raw, dict) else {}
    record = records.get(path)
    if not isinstance(record, dict) or record.get("state") not in {"created", "deleting"}:
        raise StorageError("KJA_CLEANUP_OWNERSHIP", "MTP 清理记录不处于可删除状态")
    updated = dict(record)
    updated["state"] = "deleting"
    records = dict(records)
    records[path] = updated
    state.evidence["mtp_created_records"] = records
    session_store.save(state)

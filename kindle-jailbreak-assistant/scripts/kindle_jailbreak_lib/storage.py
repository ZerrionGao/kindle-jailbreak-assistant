"""Kindle 存储公共接口 facade。"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TypeVar

from .models import DeviceInfo, EvidenceResult, PackageChoice
from .progress import ProgressEvent
from .routing import MethodPolicy
from .session import SessionStore
from .storage_backup import (
    backup_visible_storage as _backup_visible_storage,
    verify_manifest as _verify_manifest,
)
from .storage_payload import (
    DEFAULT_FILL_CHUNK_BYTES,
    DEFAULT_RESERVE_BYTES,
    cleanup_created_files as _cleanup_created_files,
    fill_storage as _fill_storage,
    inspect_archive as _inspect_archive,
    stage_archive as _stage_archive,
)
from .storage_post_jailbreak import (
    choose_koreader_package as _choose_koreader_package,
    verify_jailbreak as _verify_jailbreak,
    verify_koreader_files as _verify_koreader_files,
)
from .storage_safety import (
    SafeRootHandle,
    StorageError,
    assert_safe_root as _assert_safe_root,
)


ProgressCallback = Callable[[ProgressEvent], None]
DeviceProbe = Callable[[], DeviceInfo]
FreeSpaceProbe = Callable[[SafeRootHandle], int]
_T = TypeVar("_T")

__all__ = [
    "DEFAULT_FILL_CHUNK_BYTES",
    "DEFAULT_RESERVE_BYTES",
    "StorageError",
    "assert_safe_root",
    "backup_visible_storage",
    "cleanup_created_files",
    "choose_koreader_package",
    "fill_storage",
    "inspect_archive",
    "stage_archive",
    "verify_jailbreak",
    "verify_koreader_files",
    "verify_manifest",
]


def assert_safe_root(
    root: str | Path,
    *,
    device: DeviceInfo | None = None,
) -> Path:
    return _public_call(
        "KJA_UNSAFE_ROOT",
        "Kindle 根目录安全校验失败",
        _assert_safe_root,
        root,
        device=device,
    )


def backup_visible_storage(
    device: DeviceInfo,
    backup_parent: str | Path,
    *,
    session_store: SessionStore,
    timestamp: str | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    return _public_call(
        "KJA_BACKUP_FAILED",
        "Kindle 可见存储备份失败",
        _backup_visible_storage,
        device,
        backup_parent,
        session_store=session_store,
        timestamp=timestamp,
        progress=progress,
    )


def verify_manifest(source_root: str | Path, backup_root: str | Path) -> bool:
    return _public_call(
        "KJA_BACKUP_VERIFY",
        "备份内容校验失败",
        _verify_manifest,
        source_root,
        backup_root,
    )


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
    return _public_call(
        "KJA_FILL_FAILED",
        "Kindle 占位文件准备失败",
        _fill_storage,
        device,
        session_store,
        policy,
        device_probe=device_probe,
        reserve_bytes=reserve_bytes,
        chunk_bytes=chunk_bytes,
        free_space=free_space,
        progress=progress,
        authorization_key=authorization_key,
    )


def inspect_archive(
    archive: str | Path,
    staging_root: str | Path,
    *,
    required_files: Iterable[str] = (),
) -> list[Path]:
    return _public_call(
        "KJA_ARCHIVE_INVALID",
        "载荷归档检查失败",
        _inspect_archive,
        archive,
        staging_root,
        required_files=required_files,
    )


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
    return _public_call(
        "KJA_STAGE_FAILED",
        "Kindle 载荷暂存失败",
        _stage_archive,
        archive,
        device,
        session_store,
        policy,
        device_probe=device_probe,
        required_files=required_files,
        purpose=purpose,
        reserve_bytes=reserve_bytes,
        free_space=free_space,
        progress=progress,
        authorization_key=authorization_key,
    )


def cleanup_created_files(
    device: DeviceInfo,
    session_store: SessionStore,
    *,
    device_probe: DeviceProbe,
    progress: ProgressCallback | None = None,
    authorization_key: str | None = None,
) -> list[Path]:
    return _public_call(
        "KJA_CLEANUP_FAILED",
        "当前会话创建文件清理失败",
        _cleanup_created_files,
        device,
        session_store,
        device_probe=device_probe,
        progress=progress,
        authorization_key=authorization_key,
    )


def choose_koreader_package(
    device: DeviceInfo, official_rules: object
) -> PackageChoice:
    """按当前已验证的官方规则选择 KOReader 包，不回退到猜测包族。"""

    return _choose_koreader_package(device, official_rules)


def verify_jailbreak(
    root: str | Path,
    *,
    equivalent_markers: Iterable[str] = (),
    excluded_markers: Iterable[str] = (),
    user_log_evidence: bool = False,
) -> EvidenceResult:
    """只读核对越狱成功标记或用户记录的当前方法日志证据。"""

    return _verify_jailbreak(
        root,
        equivalent_markers=equivalent_markers,
        excluded_markers=excluded_markers,
        user_log_evidence=user_log_evidence,
    )


def verify_koreader_files(
    root: str | Path, *, user_visible_launch: bool = False
) -> EvidenceResult:
    """只读核对 KOReader 文件和用户实际启动证据。"""

    return _verify_koreader_files(root, user_visible_launch=user_visible_launch)


def _public_call(
    fallback_code: str,
    fallback_message: str,
    operation: Callable[..., _T],
    *args,
    **kwargs,
) -> _T:
    try:
        return operation(*args, **kwargs)
    except StorageError:
        raise
    except Exception as exc:
        raise StorageError(fallback_code, fallback_message) from exc

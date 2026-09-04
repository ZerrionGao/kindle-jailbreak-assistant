"""Windows FAT-family USBMS 的 Volume GUID 安全适配器。"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .storage_safety import EntrySnapshot, SafeRootHandle, StorageError


MIB = 1024 * 1024
VolumeProbe = Callable[[Path], tuple[str, int]]
VolumeGuidResolver = Callable[[Path], Path]
FreeSpaceProbe = Callable[[Path], int]
_REPARSE_FLAG = 0x80
_REPARSE_ATTRIBUTE = 0x400
_SAFE_FILESYSTEMS = frozenset({"FAT", "FAT32", "EXFAT"})


def volume_is_safe(filesystem: str, flags: int) -> bool:
    return (
        isinstance(filesystem, str)
        and filesystem.strip().upper() in _SAFE_FILESYSTEMS
        and isinstance(flags, int)
        and flags & _REPARSE_FLAG == 0
    )


def require_safe_volume(
    root: Path,
    *,
    probe: VolumeProbe | None = None,
) -> tuple[str, int]:
    volume_probe = probe or probe_volume
    try:
        filesystem, flags = volume_probe(root)
    except Exception as exc:
        raise StorageError(
            "KJA_WINDOWS_FILESYSTEM_UNVERIFIED",
            "无法验证 Windows Kindle 卷文件系统，已安全停止",
        ) from exc
    if not volume_is_safe(filesystem, flags):
        raise StorageError(
            "KJA_WINDOWS_FILESYSTEM_UNSAFE",
            "Windows Kindle 卷不是无重解析点的 FAT/FAT32/exFAT，拒绝写入",
        )
    return filesystem, flags


@contextmanager
def retain_fat_root(
    drive_root: Path,
    *,
    volume_probe: VolumeProbe,
    volume_guid_resolver: VolumeGuidResolver,
) -> Iterator[SafeRootHandle]:
    try:
        volume_path = Path(volume_guid_resolver(drive_root))
        require_safe_volume(volume_path, probe=volume_probe)
        confirmed_path = Path(volume_guid_resolver(drive_root))
        if path_key(confirmed_path) != path_key(volume_path):
            raise StorageError(
                "KJA_WINDOWS_VOLUME_CHANGED",
                "Windows 盘符在卷校验期间指向了另一卷，已安全停止",
            )
        metadata = volume_path.stat()
    except StorageError:
        raise
    except Exception as exc:
        raise StorageError(
            "KJA_WINDOWS_VOLUME_UNAVAILABLE",
            "Windows Kindle 稳定卷路径不可用",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "Windows Kindle 卷路径不是目录")
    marker = volume_path / "documents"
    try:
        marker_metadata = marker.lstat()
    except OSError as exc:
        raise StorageError("KJA_UNSAFE_ROOT", "Windows Kindle 卷缺少 documents 标记") from exc
    if is_reparse(marker_metadata) or not stat.S_ISDIR(marker_metadata.st_mode):
        raise StorageError("KJA_UNSAFE_ROOT", "Windows Kindle documents 标记不安全")
    yield SafeRootHandle(
        path=drive_root,
        descriptor=None,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        io_path=volume_path,
        backend="windows-fat",
        volume_identity=path_key(volume_path),
        volume_resolver=volume_guid_resolver,
    )


@contextmanager
def retain_host_root(root: Path) -> Iterator[SafeRootHandle]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "Windows 主机暂存根不可用") from exc
    if is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise StorageError("KJA_UNSAFE_ROOT", "Windows 主机暂存根是重解析对象或非目录")
    yield SafeRootHandle(
        path=root,
        descriptor=None,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        io_path=root,
        backend="windows-host",
    )


def scan_tree(
    root: SafeRootHandle,
    skipped_names: frozenset[str],
) -> list[EntrySnapshot]:
    snapshots: list[EntrySnapshot] = []

    def visit(directory: Path, relative_parent: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "Windows 稳定卷路径不可读取") from exc
        for child in children:
            if child.name in skipped_names:
                continue
            relative = relative_parent / child.name
            metadata = child.stat(follow_symlinks=False)
            if is_reparse(metadata):
                raise StorageError("KJA_UNSAFE_PATH", "Windows 路径意外包含重解析对象")
            if stat.S_ISDIR(metadata.st_mode):
                snapshots.append(
                    EntrySnapshot.from_stat(relative, "directory", metadata, None)
                )
                visit(Path(child.path), relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise StorageError("KJA_UNSAFE_PATH", "Windows 路径包含特殊对象")
            provisional = EntrySnapshot.from_stat(relative, "file", metadata, "")
            with open_snapshot(root, provisional) as handle:
                digest = hash_handle(handle)
                verified = os.fstat(handle.fileno())
            if not provisional.matches(verified):
                raise StorageError("KJA_SOURCE_CHANGED", "Windows 扫描期间文件发生变化")
            snapshots.append(
                EntrySnapshot.from_stat(relative, "file", verified, digest)
            )

    if root.io_path is None:
        raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "Windows 稳定卷路径缺失")
    visit(root.io_path, Path())
    return snapshots


@contextmanager
def open_snapshot(root: SafeRootHandle, snapshot: EntrySnapshot) -> Iterator[BinaryIO]:
    target = checked_path(root, snapshot.relative, allow_missing=False)
    before = target.lstat()
    if not snapshot.matches(before) or not stat.S_ISREG(before.st_mode):
        raise StorageError("KJA_SOURCE_CHANGED", "Windows 文件自扫描后发生变化")
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    after = os.fstat(descriptor)
    if not snapshot.matches(after) or not same_inode(before, after):
        os.close(descriptor)
        raise StorageError("KJA_SOURCE_CHANGED", "Windows 文件在打开时发生变化")
    with os.fdopen(descriptor, "rb") as handle:
        yield handle


@contextmanager
def create_file_exclusive(
    root: SafeRootHandle,
    relative: Path,
) -> Iterator[BinaryIO]:
    target = checked_path(root, relative, allow_missing=True)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise StorageError("KJA_UNSAFE_PATH", "Windows 新建目标不是普通文件")
    with os.fdopen(descriptor, "wb") as handle:
        yield handle


@contextmanager
def open_snapshot_for_update(
    root: SafeRootHandle,
    snapshot: EntrySnapshot,
) -> Iterator[BinaryIO]:
    target = checked_path(root, snapshot.relative, allow_missing=False)
    before = target.lstat()
    if not snapshot.matches(before) or not stat.S_ISREG(before.st_mode):
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "Windows 文件在读写打开前已被替换",
        )
    descriptor = os.open(
        target,
        os.O_RDWR | getattr(os, "O_BINARY", 0),
    )
    opened = os.fstat(descriptor)
    if not snapshot.matches(opened) or not same_inode(before, opened):
        os.close(descriptor)
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "Windows 文件在读写打开时已被替换",
        )
    with os.fdopen(descriptor, "r+b") as handle:
        yield handle


def inspect_path(root: SafeRootHandle, relative: Path) -> EntrySnapshot | None:
    target = checked_path(root, relative, allow_missing=True)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return None
    if is_reparse(metadata):
        raise StorageError("KJA_UNSAFE_PATH", "Windows 目标意外成为重解析对象")
    if stat.S_ISDIR(metadata.st_mode):
        return EntrySnapshot.from_stat(relative, "directory", metadata, None)
    if not stat.S_ISREG(metadata.st_mode):
        raise StorageError("KJA_UNSAFE_PATH", "Windows 目标不是普通文件或目录")
    provisional = EntrySnapshot.from_stat(relative, "file", metadata, "")
    with open_snapshot(root, provisional) as handle:
        digest = hash_handle(handle)
        verified = os.fstat(handle.fileno())
    return EntrySnapshot.from_stat(relative, "file", verified, digest)


def mkdir_exclusive(root: SafeRootHandle, relative: Path) -> EntrySnapshot:
    target = checked_path(root, relative, allow_missing=True)
    target.mkdir()
    metadata = target.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise StorageError("KJA_UNSAFE_PATH", "Windows 新建目录类型异常")
    return EntrySnapshot.from_stat(relative, "directory", metadata, None)


def unlink_snapshot(root: SafeRootHandle, expected: EntrySnapshot) -> None:
    target = checked_path(root, expected.relative, allow_missing=False)
    before = target.lstat()
    if not expected.matches(before) or not stat.S_ISREG(before.st_mode):
        raise StorageError("KJA_JOURNAL_AMBIGUOUS", "Windows 文件在删除前已被替换")
    target.unlink()


def directory_is_empty(root: SafeRootHandle, expected: EntrySnapshot) -> bool:
    target = checked_path(root, expected.relative, allow_missing=False)
    before = target.lstat()
    if not expected.matches(before):
        raise StorageError("KJA_JOURNAL_AMBIGUOUS", "Windows 目录在检查前已被替换")
    return not any(target.iterdir())


@contextmanager
def retain_directory_lease(
    root: SafeRootHandle,
    expected: EntrySnapshot,
) -> Iterator[Callable[[], EntrySnapshot]]:
    """尽可能保留目录句柄；运行库不支持目录 fd 时安全停止。"""

    if expected.kind != "directory":
        raise StorageError("KJA_JOURNAL_INVALID", "Windows 目录 lease 收到非目录身份")
    target = checked_path(root, expected.relative, allow_missing=False)
    before = target.lstat()
    if not expected.matches(before) or not stat.S_ISDIR(before.st_mode):
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "Windows quarantine 目录在 lease 打开前已发生变化",
        )
    try:
        descriptor = os.open(
            target,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
        )
    except OSError as exc:
        raise StorageError(
            "KJA_NOFOLLOW_UNAVAILABLE",
            "Windows 当前运行库无法保留目录句柄，已保留 quarantine 目录",
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not expected.matches(opened) or not same_inode(before, opened):
            raise StorageError(
                "KJA_OWNERSHIP_AMBIGUOUS",
                "Windows quarantine 目录在 lease 打开时已发生变化",
            )

        def validate() -> EntrySnapshot:
            try:
                opened_before = os.fstat(descriptor)
                named_before = target.lstat()
                children = list(target.iterdir())
                opened_after = os.fstat(descriptor)
                named_after = target.lstat()
            except FileNotFoundError as exc:
                raise StorageError(
                    "KJA_OWNERSHIP_AMBIGUOUS",
                    "Windows quarantine 目录名称在 lease 期间已消失",
                ) from exc
            snapshots = (opened_before, named_before, opened_after, named_after)
            if any(not expected.matches(metadata) for metadata in snapshots) or any(
                not same_inode(opened_before, metadata) for metadata in snapshots[1:]
            ):
                raise StorageError(
                    "KJA_OWNERSHIP_AMBIGUOUS",
                    "Windows quarantine 目录身份或时间元数据在 lease 期间发生变化",
                )
            if children:
                raise StorageError(
                    "KJA_OWNERSHIP_AMBIGUOUS",
                    "Windows quarantine 目录在 lease 期间不再为空，内容已保留",
                )
            return EntrySnapshot.from_stat(
                expected.relative,
                "directory",
                opened_after,
                None,
            )

        yield validate
    finally:
        os.close(descriptor)


def free_bytes(
    root: SafeRootHandle,
    *,
    probe: FreeSpaceProbe | None = None,
) -> int:
    if root.io_path is None:
        raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "Windows retained GUID 缺失")
    free_probe = probe or _get_disk_free_space
    try:
        return int(free_probe(root.io_path))
    except StorageError:
        raise
    except Exception as exc:
        raise StorageError(
            "KJA_WINDOWS_VOLUME_UNAVAILABLE",
            "无法从 Windows retained GUID 读取可用空间",
        ) from exc


def quarantine_move(
    root: SafeRootHandle,
    expected: EntrySnapshot,
    quarantine_directory: Path,
    quarantine_name: str,
) -> EntrySnapshot:
    source = checked_path(root, expected.relative, allow_missing=False)
    quarantine_relative = quarantine_directory / quarantine_name
    destination = checked_path(root, quarantine_relative, allow_missing=True)
    os.rename(source, destination)
    moved = inspect_path(root, quarantine_relative)
    if moved is None or not same_snapshot(expected, moved):
        restore_quarantine(root, expected.relative, quarantine_relative)
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "Windows 隔离对象与所有权记录不一致，已恢复并停止",
        )
    return moved


def restore_quarantine(
    root: SafeRootHandle,
    original: Path,
    quarantined: Path,
) -> None:
    original_path = checked_path(root, original, allow_missing=True)
    quarantine_path = checked_path(root, quarantined, allow_missing=False)
    if original_path.exists():
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "Windows 原路径已被占用，隔离对象保持不动",
        )
    os.rename(quarantine_path, original_path)


def checked_path(
    root: SafeRootHandle,
    relative: Path,
    *,
    allow_missing: bool,
) -> Path:
    if root.io_path is None or not root.io_path.is_dir():
        raise StorageError("KJA_WINDOWS_VOLUME_UNAVAILABLE", "原 Windows 卷已离线")
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise StorageError("KJA_UNSAFE_PATH", "Windows 目标不是安全相对路径")
    cursor = root.io_path
    for part in relative.parts:
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                return root.io_path / relative
            raise StorageError("KJA_UNSAFE_PATH", "Windows 目标路径不存在") from None
        if is_reparse(metadata):
            raise StorageError("KJA_UNSAFE_PATH", "Windows 路径包含重解析对象")
    return root.io_path / relative


def probe_volume(root: Path) -> tuple[str, int]:
    _require_windows()
    import ctypes
    from ctypes import wintypes

    filesystem_buffer = ctypes.create_unicode_buffer(32)
    flags = wintypes.DWORD()
    kernel32 = getattr(ctypes, "windll").kernel32
    result = kernel32.GetVolumeInformationW(
        wintypes.LPCWSTR(str(Path(root.anchor or str(root)))),
        None,
        0,
        None,
        None,
        ctypes.byref(flags),
        filesystem_buffer,
        len(filesystem_buffer),
    )
    if not result:
        raise getattr(ctypes, "WinError")()
    return filesystem_buffer.value, int(flags.value)


def resolve_volume_guid(root: Path) -> Path:
    _require_windows()
    import ctypes
    from ctypes import wintypes

    buffer = ctypes.create_unicode_buffer(64)
    kernel32 = getattr(ctypes, "windll").kernel32
    result = kernel32.GetVolumeNameForVolumeMountPointW(
        wintypes.LPCWSTR(str(root)),
        buffer,
        len(buffer),
    )
    if not result:
        raise getattr(ctypes, "WinError")()
    return Path(buffer.value)


def _get_disk_free_space(root: Path) -> int:
    _require_windows()
    import ctypes
    from ctypes import wintypes

    available = ctypes.c_ulonglong()
    total = ctypes.c_ulonglong()
    total_free = ctypes.c_ulonglong()
    kernel32 = getattr(ctypes, "windll").kernel32
    result = kernel32.GetDiskFreeSpaceExW(
        wintypes.LPCWSTR(str(root)),
        ctypes.byref(available),
        ctypes.byref(total),
        ctypes.byref(total_free),
    )
    if not result:
        raise getattr(ctypes, "WinError")()
    return int(available.value)


def is_reparse(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE != 0
    )


def same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def same_snapshot(left: EntrySnapshot, right: EntrySnapshot) -> bool:
    return (
        left.kind == right.kind
        and left.device == right.device
        and left.inode == right.inode
        and left.mode == right.mode
        and left.size == right.size
        and left.sha256 == right.sha256
    )


def hash_handle(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(MIB), b""):
        digest.update(chunk)
    return digest.hexdigest()


def path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _require_windows() -> None:
    if sys.platform != "win32":
        raise OSError("Windows API is unavailable on this platform")

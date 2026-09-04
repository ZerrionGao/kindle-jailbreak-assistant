"""存储层的词法路径、no-follow 文件访问和设备身份边界。"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, TypeAlias, TypeGuard

from .models import DeviceInfo
from .session import SessionState, SessionStore, device_fingerprint


MIB = 1024 * 1024
_SYSTEM_ROOTS = frozenset({
    "/System", "/Library", "/Applications", "/Users", "/Volumes",
    "/bin", "/boot", "/dev", "/etc", "/home", "/media", "/mnt",
    "/opt", "/private", "/private/tmp", "/proc", "/root", "/sbin",
    "/sys", "/tmp", "/usr", "/var",
})
_POSIX_NOFOLLOW_CAPABLE = (
    hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.listdir in os.supports_fd
    and os.mkdir in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
)


class StorageError(ValueError):
    """带稳定机器码、可直接展示中文说明的存储错误。"""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class EntrySnapshot:
    relative: Path
    kind: str
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str | None

    @classmethod
    def from_stat(
        cls,
        relative: Path,
        kind: str,
        metadata: os.stat_result,
        digest: str | None,
    ) -> "EntrySnapshot":
        return cls(
            relative=relative,
            kind=kind,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=stat.S_IFMT(metadata.st_mode),
            size=metadata.st_size if kind == "file" else 0,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            sha256=digest,
        )

    def matches(self, metadata: os.stat_result) -> bool:
        same_object = (
            self.device == metadata.st_dev
            and self.inode == metadata.st_ino
            and self.mode == stat.S_IFMT(metadata.st_mode)
        )
        if self.kind == "directory":
            return (
                same_object
                and stat.S_ISDIR(metadata.st_mode)
                and self.modified_ns == metadata.st_mtime_ns
                and self.changed_ns == metadata.st_ctime_ns
            )
        return (
            same_object
            and self.size == metadata.st_size
            and self.modified_ns == metadata.st_mtime_ns
        )


@dataclass(frozen=True)
class DirectoryLease:
    """保持同一目录对象与其父目录句柄，并执行可重复的判空/名称复核。"""

    relative: Path
    _validator: Callable[[], EntrySnapshot]

    def validate_empty_and_named(self) -> EntrySnapshot:
        return self._validator()


@dataclass
class SafeRootHandle:
    """在一次操作期间保持打开的根目录句柄。"""

    path: Path
    descriptor: int | None
    device: int
    inode: int
    io_path: Path | None = None
    backend: str = "posix"
    volume_identity: str | None = None
    volume_resolver: Callable[[Path], Path] | None = None

    def duplicate(self) -> int:
        if self.descriptor is None:
            raise StorageError("KJA_NOFOLLOW_UNAVAILABLE", "当前根目录没有 POSIX 目录句柄")
        return os.dup(self.descriptor)

    def path_is_original(self) -> bool:
        if self.backend == "windows-fat":
            if self.volume_identity is None or self.volume_resolver is None:
                return False
            try:
                current = self.volume_resolver(self.path)
            except Exception:
                return False
            return (
                _path_key(current) == self.volume_identity
                and self.io_path is not None
                and self.io_path.is_dir()
            )
        try:
            current = self.path.lstat()
        except OSError:
            return False
        return (
            not stat.S_ISLNK(current.st_mode)
            and not int(getattr(current, "st_file_attributes", 0)) & 0x400
            and current.st_dev == self.device
            and current.st_ino == self.inode
            and stat.S_ISDIR(current.st_mode)
        )


RootReference: TypeAlias = Path | SafeRootHandle
WindowsVolumeProbe: TypeAlias = Callable[[Path], tuple[str, int]]
WindowsVolumeGuidResolver: TypeAlias = Callable[[Path], Path]


def windows_volume_is_safe(filesystem: str, flags: int) -> bool:
    """纯函数裁决 Windows 卷是否属于无 reparse 的 FAT 系列。"""

    from .storage_windows import volume_is_safe

    return volume_is_safe(filesystem, flags)


def require_windows_safe_volume(
    root: Path,
    *,
    probe: WindowsVolumeProbe | None = None,
) -> tuple[str, int]:
    """通过可注入卷探测拒绝 NTFS、未知卷和 reparse-capable 卷。"""

    from .storage_windows import require_safe_volume

    return require_safe_volume(root, probe=probe)


@contextmanager
def retain_windows_fat_root(
    drive_root: Path,
    *,
    volume_probe: WindowsVolumeProbe,
    volume_guid_resolver: WindowsVolumeGuidResolver,
) -> Iterator[SafeRootHandle]:
    """把可复用盘符转换为稳定卷路径，并只允许无 reparse 的 FAT 系列。"""

    from .storage_windows import retain_fat_root

    with retain_fat_root(
        drive_root,
        volume_probe=volume_probe,
        volume_guid_resolver=volume_guid_resolver,
    ) as retained:
        yield retained


def _probe_windows_volume(root: Path) -> tuple[str, int]:
    from .storage_windows import probe_volume

    return probe_volume(root)


def _resolve_windows_volume_guid(root: Path) -> Path:
    from .storage_windows import resolve_volume_guid

    return resolve_volume_guid(root)


def assert_safe_root(
    root: str | Path,
    *,
    device: DeviceInfo | None = None,
) -> Path:
    """解析并校验一个明确的 Kindle USB 存储根目录。"""

    with retain_safe_root(root, device=device) as retained:
        return retained.path


@contextmanager
def retain_safe_root(
    root: str | Path,
    *,
    device: DeviceInfo | None = None,
) -> Iterator[SafeRootHandle]:
    """验证并保持一个 no-follow 根句柄，避免后续重新解析根路径。"""

    candidate = Path(root).expanduser()
    if not candidate.is_absolute():
        raise StorageError("KJA_UNSAFE_ROOT", "Kindle 根目录必须是绝对路径")
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot")
        if system_root and candidate.drive.casefold() == Path(system_root).drive.casefold():
            raise StorageError("KJA_UNSAFE_ROOT", "拒绝把 Windows 系统卷作为 Kindle")
        if candidate != Path(candidate.anchor):
            raise StorageError("KJA_UNSAFE_ROOT", "Windows Kindle 根目录必须是卷根目录")
        if device is not None:
            if device.transport != "usbms" or device.root is None:
                raise StorageError("KJA_UNSUPPORTED_TRANSPORT", "Windows 文件操作需要 USB 大容量存储")
            if os.path.normcase(os.path.abspath(device.root)) != os.path.normcase(
                os.path.abspath(candidate)
            ):
                raise StorageError("KJA_DEVICE_MISMATCH", "Windows 设备根目录与目标不一致")
        with retain_windows_fat_root(
            candidate,
            volume_probe=_probe_windows_volume,
            volume_guid_resolver=_resolve_windows_volume_guid,
        ) as retained:
            yield retained
        return
    lexical = Path(os.path.abspath(candidate))
    home = Path.home().resolve()
    if lexical == Path(lexical.anchor) or lexical == home:
        raise StorageError("KJA_UNSAFE_ROOT", "拒绝把系统根目录或用户主目录作为 Kindle")
    if _path_key(lexical) in _protected_root_keys():
        raise StorageError("KJA_UNSAFE_ROOT", "拒绝把系统目录作为 Kindle")
    try:
        root_metadata = candidate.lstat()
    except OSError as exc:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "Kindle 根目录不可用") from exc
    if stat.S_ISLNK(root_metadata.st_mode):
        raise StorageError("KJA_UNSAFE_ROOT", "Kindle 根目录不能是符号链接或重解析点")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "Kindle 根目录不可用") from exc
    if not resolved.is_dir():
        raise StorageError("KJA_UNSAFE_ROOT", "Kindle 根目录不是目录")
    if resolved == Path(resolved.anchor) or resolved == home:
        raise StorageError("KJA_UNSAFE_ROOT", "拒绝把系统根目录或用户主目录作为 Kindle")
    if _path_key(resolved) in _protected_root_keys():
        raise StorageError("KJA_UNSAFE_ROOT", "拒绝把系统目录作为 Kindle")
    if device is not None:
        if device.transport != "usbms":
            raise StorageError("KJA_UNSUPPORTED_TRANSPORT", "文件系统操作只支持 USB 大容量存储")
        if device.root is None:
            raise StorageError("KJA_DEVICE_UNAVAILABLE", "设备没有文件系统根目录")
        try:
            device_root = Path(device.root).expanduser().resolve(strict=True)
        except OSError as exc:
            raise StorageError("KJA_DEVICE_UNAVAILABLE", "设备根目录不可用") from exc
        if device_root != resolved:
            raise StorageError("KJA_DEVICE_MISMATCH", "设备根目录与操作目标不一致")
    expected = resolved.lstat()
    with retain_root(resolved, expected=expected) as retained:
        if retained.descriptor is None:
            raise StorageError("KJA_NOFOLLOW_UNAVAILABLE", "POSIX 根目录句柄不可用")
        try:
            marker_fd = _open_directory_chain(retained.descriptor, ("documents",))
        except OSError as exc:
            raise StorageError("KJA_UNSAFE_ROOT", "目录缺少安全的 Kindle documents 标记") from exc
        else:
            os.close(marker_fd)
        yield retained


@contextmanager
def authorized_device_root(
    device: DeviceInfo,
    session_store: SessionStore,
    device_probe: Callable[[], DeviceInfo],
    *,
    authorization_key: str | None = None,
) -> Iterator[tuple[SafeRootHandle, SessionState]]:
    """统一执行设备写入前的安全根、授权和身份门禁。"""

    if not callable(device_probe):
        raise StorageError("KJA_DEVICE_IDENTITY", "设备探测器不可用")
    if device.root is None:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "设备没有文件系统根目录")
    with retain_safe_root(device.root, device=device) as root:
        if device.read_only is not False:
            raise StorageError("KJA_DEVICE_READ_ONLY", "设备未确认可写")
        state = session_store.load()
        authorized = (
            isinstance(authorization_key, str)
            and authorization_key.startswith("write_once:")
            and state.approvals.get(authorization_key) is True
        )
        if not authorized:
            raise StorageError("KJA_WRITE_NOT_AUTHORIZED", "设备写入 API 缺少一次性操作授权")
        state.approvals.pop(authorization_key, None)
        session_store.save(state)
        assert_session_device(state, device, root.path)
        assert_same_device(device, device_probe())
        yield root, state

def assert_session_device(state: SessionState, device: DeviceInfo, root: Path) -> None:
    """用完整序列号指纹把当前设备绑定到已授权会话。"""

    if not device.serial:
        raise StorageError("KJA_DEVICE_IDENTITY", "完整设备序列号缺失，拒绝写入")
    if device_fingerprint(state.session_id, device.serial) != state.device_fingerprint:
        raise StorageError("KJA_DEVICE_MISMATCH", "完整设备序列号与当前会话不匹配")
    public = state.device_public
    if public.get("transport") != device.transport:
        raise StorageError("KJA_DEVICE_MISMATCH", "设备传输方式与当前会话不匹配")
    if public.get("root") is None:
        raise StorageError("KJA_DEVICE_IDENTITY", "会话没有记录设备根目录")
    try:
        session_root = Path(str(public["root"])).expanduser().resolve(strict=True)
    except OSError as exc:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "会话记录的设备根目录不可用") from exc
    if session_root != root:
        raise StorageError("KJA_DEVICE_MISMATCH", "设备根目录与当前会话不匹配")
    for field, label in (("model", "型号"), ("firmware", "固件版本")):
        expected = public.get(field)
        if expected is not None and expected != getattr(device, field):
            raise StorageError("KJA_DEVICE_MISMATCH", f"设备{label}与当前会话不匹配")


def assert_same_device(expected: DeviceInfo, observed: DeviceInfo) -> None:
    """在设备写入边界重新核对完整设备身份和可写状态。"""

    if not isinstance(observed, DeviceInfo):
        raise StorageError("KJA_DEVICE_IDENTITY", "设备探测返回了无效结果")
    if not expected.serial or not observed.serial:
        raise StorageError("KJA_DEVICE_IDENTITY", "写入前必须取得完整设备序列号")
    if expected.serial != observed.serial:
        raise StorageError("KJA_DEVICE_MISMATCH", "写入期间检测到另一台设备")
    if expected.transport != observed.transport:
        raise StorageError("KJA_DEVICE_MISMATCH", "写入期间设备传输方式发生变化")
    if observed.read_only is not False:
        raise StorageError("KJA_DEVICE_READ_ONLY", "设备当前未确认可写")
    if expected.root is None or observed.root is None:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "写入期间设备根目录消失")
    try:
        expected_root = Path(expected.root).expanduser().resolve(strict=True)
        observed_root = Path(observed.root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "写入期间设备根目录不可用") from exc
    if expected_root != observed_root:
        raise StorageError("KJA_DEVICE_MISMATCH", "写入期间设备根目录发生变化")
    for field, label in (("model", "型号"), ("firmware", "固件版本")):
        expected_value = getattr(expected, field)
        observed_value = getattr(observed, field)
        if expected_value is not None and expected_value != observed_value:
            raise StorageError("KJA_DEVICE_MISMATCH", f"写入期间设备{label}发生变化")


def assert_retained_root(root: SafeRootHandle) -> None:
    if not root.path_is_original():
        raise StorageError("KJA_DEVICE_MISMATCH", "写入期间设备根路径已被替换")


def retained_free_bytes(root: SafeRootHandle) -> int:
    """只从 retained fd 或 Volume GUID 获取可用空间。"""

    if _is_windows_backend(root):
        from .storage_windows import free_bytes as windows_free_bytes

        return windows_free_bytes(root)
    if root.descriptor is None:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "retained 根目录句柄不可用")
    usage = os.fstatvfs(root.descriptor)
    return int(usage.f_bavail * usage.f_frsize)


def lexical_path(root: RootReference, relative: Path) -> Path:
    """保留词法路径，并拒绝任何现存链接组件。"""

    if relative.is_absolute() or not relative.parts:
        raise StorageError("KJA_UNSAFE_PATH", "目标必须是非空相对路径")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise StorageError("KJA_UNSAFE_PATH", "目标路径包含不安全分段")
    root_path = _root_path(root)
    target = root_path.joinpath(relative)
    try:
        Path(os.path.abspath(target)).relative_to(root_path)
    except ValueError as exc:
        raise StorageError("KJA_UNSAFE_PATH", "目标路径超出允许根目录") from exc
    if isinstance(root, Path):
        cursor = root
        for part in relative.parts:
            cursor = cursor / part
            try:
                metadata = cursor.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
            ):
                raise StorageError("KJA_UNSAFE_PATH", "目标路径包含符号链接或重解析点")
    return target


def scan_tree(
    root: RootReference,
    *,
    skipped_names: frozenset[str] = frozenset(),
) -> list[EntrySnapshot]:
    """通过目录 fd 枚举目录，并记录后续打开时必须匹配的身份。"""

    if _is_windows_backend(root):
        from .storage_windows import scan_tree as scan_windows_tree

        return scan_windows_tree(root, skipped_names)
    with _borrow_root(root) as root_fd:
        snapshots: list[EntrySnapshot] = []
        _scan_directory(root_fd, Path(), snapshots, skipped_names)
        return snapshots


def copy_file_exclusive(
    source_root: RootReference,
    source: EntrySnapshot,
    destination_root: RootReference,
    destination_relative: Path,
) -> tuple[int, str]:
    """先安全打开并复核源，再以 exclusive/no-follow 方式创建并写入目标。"""

    if source.kind != "file" or source.sha256 is None:
        raise StorageError("KJA_SOURCE_CHANGED", "复制来源不是已扫描的普通文件")
    lexical_path(destination_root, destination_relative)
    with open_snapshot(source_root, source) as input_file:
        with create_file_exclusive(destination_root, destination_relative) as output_file:
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = input_file.read(MIB)
                if not chunk:
                    break
                digest.update(chunk)
                output_file.write(chunk)
                size += len(chunk)
            output_file.flush()
            os.fsync(output_file.fileno())
        if size != source.size or digest.hexdigest() != source.sha256:
            raise StorageError("KJA_SOURCE_CHANGED", "复制期间来源内容发生变化")
    return size, digest.hexdigest()


@contextmanager
def open_snapshot(root: RootReference, snapshot: EntrySnapshot) -> Iterator[BinaryIO]:
    """no-follow 打开扫描记录，并在读取任何字节前核对 lstat/fstat。"""

    if _is_windows_backend(root):
        from .storage_windows import open_snapshot as open_windows_snapshot

        with open_windows_snapshot(root, snapshot) as handle:
            yield handle
        return
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, snapshot.relative.parts[:-1])
        try:
            name = snapshot.relative.name
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise StorageError("KJA_SOURCE_CHANGED", "复制来源已变成链接或特殊文件")
            if not snapshot.matches(before):
                raise StorageError("KJA_SOURCE_CHANGED", "复制来源自扫描后发生变化")
            flags = os.O_RDONLY | os.O_NOFOLLOW
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            after = os.fstat(descriptor)
            if not snapshot.matches(after) or not _same_inode(before, after):
                os.close(descriptor)
                raise StorageError("KJA_SOURCE_CHANGED", "复制来源在打开时发生变化")
        except FileNotFoundError as exc:
            raise StorageError("KJA_SOURCE_CHANGED", "复制来源在打开前消失") from exc
        finally:
            os.close(parent_fd)
    with os.fdopen(descriptor, "rb") as handle:
        yield handle


@contextmanager
def create_file_exclusive(root: RootReference, relative: Path) -> Iterator[BinaryIO]:
    """通过父目录 fd 独占创建文件，绝不跟随最后一段链接。"""

    if _is_windows_backend(root):
        from .storage_windows import create_file_exclusive as create_windows_file

        with create_windows_file(root, relative) as handle:
            yield handle
        return
    lexical_path(root, relative)
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, relative.parts[:-1])
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = _open_file_descriptor(
                relative.name,
                flags,
                parent_fd,
                0o600,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(descriptor)
                raise StorageError("KJA_UNSAFE_PATH", "新建目标不是普通文件")
        finally:
            os.close(parent_fd)
    with os.fdopen(descriptor, "wb") as handle:
        yield handle


@contextmanager
def open_snapshot_for_update(
    root: RootReference,
    snapshot: EntrySnapshot,
) -> Iterator[BinaryIO]:
    """以 no-follow 读写句柄打开同一普通文件，并在交出句柄前核对身份。"""

    if snapshot.kind != "file":
        raise StorageError("KJA_JOURNAL_INVALID", "读写打开收到非文件身份")
    if _is_windows_backend(root):
        from .storage_windows import open_snapshot_for_update as open_windows_update

        with open_windows_update(root, snapshot) as handle:
            yield handle
        return
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, snapshot.relative.parts[:-1])
        try:
            before = os.stat(
                snapshot.relative.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if not snapshot.matches(before) or not stat.S_ISREG(before.st_mode):
                raise StorageError("KJA_OWNERSHIP_AMBIGUOUS", "文件在读写打开前已被替换")
            descriptor = _open_file_descriptor(
                snapshot.relative.name,
                os.O_RDWR | os.O_NOFOLLOW,
                parent_fd,
            )
            opened = os.fstat(descriptor)
            if not snapshot.matches(opened) or not _same_inode(before, opened):
                os.close(descriptor)
                raise StorageError("KJA_OWNERSHIP_AMBIGUOUS", "文件在读写打开时已被替换")
        finally:
            os.close(parent_fd)
    with os.fdopen(descriptor, "r+b") as handle:
        yield handle


def hash_snapshot(root: RootReference, snapshot: EntrySnapshot) -> str:
    with open_snapshot(root, snapshot) as handle:
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(MIB), b""):
            digest.update(chunk)
        return digest.hexdigest()


def inspect_path(root: RootReference, relative: Path) -> EntrySnapshot | None:
    """no-follow 读取当前对象身份；目标缺失时返回 ``None``。"""

    if _is_windows_backend(root):
        from .storage_windows import inspect_path as inspect_windows_path

        return inspect_windows_path(root, relative)
    lexical_path(root, relative)
    with _borrow_root(root) as root_fd:
        try:
            parent_fd = _open_directory_chain(root_fd, relative.parts[:-1])
        except FileNotFoundError:
            return None
        try:
            try:
                metadata = os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if (
                stat.S_ISLNK(metadata.st_mode)
                or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
            ):
                raise StorageError("KJA_UNSAFE_PATH", "目标是符号链接或重解析点")
            if stat.S_ISDIR(metadata.st_mode):
                descriptor = _open_directory_at(parent_fd, relative.name, metadata)
                try:
                    verified = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                return EntrySnapshot.from_stat(relative, "directory", verified, None)
            if not stat.S_ISREG(metadata.st_mode):
                raise StorageError("KJA_UNSAFE_PATH", "目标不是普通文件或目录")
            descriptor = _open_file_at(parent_fd, relative.name, metadata)
            try:
                digest = hashlib.sha256()
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    for chunk in iter(lambda: handle.read(MIB), b""):
                        digest.update(chunk)
                verified = os.fstat(descriptor)
                if not _same_metadata(metadata, verified):
                    raise StorageError("KJA_SOURCE_CHANGED", "读取期间目标发生变化")
            finally:
                os.close(descriptor)
            return EntrySnapshot.from_stat(relative, "file", verified, digest.hexdigest())
        finally:
            os.close(parent_fd)


def mkdir_exclusive(root: RootReference, relative: Path) -> EntrySnapshot:
    """通过父目录 fd 独占创建并同步目录。"""

    if _is_windows_backend(root):
        from .storage_windows import mkdir_exclusive as mkdir_windows

        return mkdir_windows(root, relative)
    lexical_path(root, relative)
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, relative.parts[:-1])
        try:
            os.mkdir(relative.name, 0o700, dir_fd=parent_fd)
            metadata = os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
            descriptor = _open_directory_at(parent_fd, relative.name, metadata)
            try:
                os.fsync(descriptor)
                verified = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    return EntrySnapshot.from_stat(relative, "directory", verified, None)


def unlink_snapshot(root: RootReference, expected: EntrySnapshot) -> None:
    """仅当当前普通文件仍与已观察身份一致时按目录 fd 删除名称。"""

    if expected.kind != "file":
        raise StorageError("KJA_JOURNAL_INVALID", "文件删除收到非文件身份")
    if _is_windows_backend(root):
        from .storage_windows import unlink_snapshot as unlink_windows

        unlink_windows(root, expected)
        return
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, expected.relative.parts[:-1])
        try:
            before = os.stat(
                expected.relative.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if not expected.matches(before) or not stat.S_ISREG(before.st_mode):
                raise StorageError("KJA_JOURNAL_AMBIGUOUS", "文件在删除前已被替换")
            descriptor = _open_file_at(parent_fd, expected.relative.name, before)
            os.close(descriptor)
            again = os.stat(
                expected.relative.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if not expected.matches(again):
                raise StorageError("KJA_JOURNAL_AMBIGUOUS", "文件在删除边界发生变化")
            os.unlink(expected.relative.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


@contextmanager
def retain_directory_lease(
    root: RootReference,
    expected: EntrySnapshot,
) -> Iterator[DirectoryLease]:
    """保持目录及其父目录句柄，供 journal 转换前后复核同一空目录。"""

    if expected.kind != "directory":
        raise StorageError("KJA_JOURNAL_INVALID", "目录 lease 收到非目录身份")
    if _is_windows_backend(root):
        from .storage_windows import retain_directory_lease as retain_windows_directory

        with retain_windows_directory(root, expected) as validator:
            yield DirectoryLease(expected.relative, validator)
        return
    lexical_path(root, expected.relative)
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, expected.relative.parts[:-1])
        descriptor: int | None = None
        try:
            try:
                named = os.stat(
                    expected.relative.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if not expected.matches(named):
                    raise StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "quarantine 目录在 lease 打开前已发生变化",
                    )
                descriptor = _open_directory_at(
                    parent_fd,
                    expected.relative.name,
                    named,
                )
                opened = os.fstat(descriptor)
                if not expected.matches(opened) or not _same_inode(named, opened):
                    raise StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "quarantine 目录在 lease 打开时已发生变化",
                    )
            except FileNotFoundError as exc:
                raise StorageError(
                    "KJA_OWNERSHIP_AMBIGUOUS",
                    "quarantine 目录在 lease 打开前已消失",
                ) from exc

            def validate() -> EntrySnapshot:
                assert descriptor is not None
                return _validate_retained_directory(
                    expected,
                    parent_fd,
                    descriptor,
                )

            yield DirectoryLease(expected.relative, validate)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)


def _validate_retained_directory(
    expected: EntrySnapshot,
    parent_fd: int,
    descriptor: int,
) -> EntrySnapshot:
    try:
        opened_before = os.fstat(descriptor)
        named_before = os.stat(
            expected.relative.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        children = os.listdir(descriptor)
        opened_after = os.fstat(descriptor)
        named_after = os.stat(
            expected.relative.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine 目录名称在 lease 期间已消失",
        ) from exc
    snapshots = (opened_before, named_before, opened_after, named_after)
    if any(not expected.matches(metadata) for metadata in snapshots) or any(
        not _same_inode(opened_before, metadata) for metadata in snapshots[1:]
    ):
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine 目录的身份、mtime 或 ctime 在 lease 期间发生变化",
        )
    if children:
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine 目录在 lease 期间不再为空，内容已保留",
        )
    return EntrySnapshot.from_stat(expected.relative, "directory", opened_after, None)


def directory_is_empty(root: RootReference, expected: EntrySnapshot) -> bool:
    """通过 no-follow 目录 fd 判断同一目录对象是否为空。"""

    if expected.kind != "directory":
        raise StorageError("KJA_JOURNAL_INVALID", "空目录检查收到非目录身份")
    if _is_windows_backend(root):
        from .storage_windows import directory_is_empty as windows_directory_is_empty

        return windows_directory_is_empty(root, expected)
    with _borrow_root(root) as root_fd:
        parent_fd = _open_directory_chain(root_fd, expected.relative.parts[:-1])
        try:
            before = os.stat(
                expected.relative.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if not expected.matches(before):
                raise StorageError("KJA_JOURNAL_AMBIGUOUS", "目录在检查前已被替换")
            descriptor = _open_directory_at(parent_fd, expected.relative.name, before)
            try:
                return not os.listdir(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_fd)


def quarantine_move(
    root: RootReference,
    expected: EntrySnapshot,
    quarantine_directory: Path,
    quarantine_name: str,
) -> EntrySnapshot:
    """原子移入同设备隔离目录；身份不匹配时恢复名称并停止。"""

    quarantine_relative = quarantine_directory / quarantine_name
    lexical_path(root, quarantine_relative)
    if _is_windows_backend(root):
        from .storage_windows import quarantine_move as quarantine_windows

        return quarantine_windows(
            root,
            expected,
            quarantine_directory,
            quarantine_name,
        )
    source_descriptor: int | None = None
    try:
        with _borrow_root(root) as root_fd:
            source_parent = _open_directory_chain(
                root_fd,
                expected.relative.parts[:-1],
            )
            quarantine_fd = _open_directory_chain(
                root_fd,
                quarantine_directory.parts,
            )
            try:
                before = os.stat(
                    expected.relative.name,
                    dir_fd=source_parent,
                    follow_symlinks=False,
                )
                if not expected.matches(before):
                    raise StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "隔离前的对象与已记录所有权不一致",
                    )
                if expected.kind == "file" and stat.S_ISREG(before.st_mode):
                    source_descriptor = _open_file_at(
                        source_parent,
                        expected.relative.name,
                        before,
                    )
                elif expected.kind == "directory" and stat.S_ISDIR(before.st_mode):
                    source_descriptor = _open_directory_at(
                        source_parent,
                        expected.relative.name,
                        before,
                    )
                else:
                    raise StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "隔离前的对象类型与已记录所有权不一致",
                    )
                opened = os.fstat(source_descriptor)
                if not expected.matches(opened):
                    raise StorageError(
                        "KJA_OWNERSHIP_AMBIGUOUS",
                        "隔离前打开的对象与已记录所有权不一致",
                    )
                _rename_at(
                    expected.relative.name,
                    quarantine_name,
                    source_parent,
                    quarantine_fd,
                )
                os.fsync(source_parent)
                os.fsync(quarantine_fd)
            finally:
                os.close(source_parent)
                os.close(quarantine_fd)
        retained = os.fstat(source_descriptor)
        moved = inspect_path(root, quarantine_relative)
        retained_identity_matches = (
            moved is not None
            and moved.device == retained.st_dev
            and moved.inode == retained.st_ino
            and moved.mode == stat.S_IFMT(retained.st_mode)
        )
        if (
            moved is None
            or not retained_identity_matches
            or not _same_snapshot_identity(expected, moved)
        ):
            _restore_quarantine(root, expected.relative, quarantine_relative)
            raise StorageError(
                "KJA_OWNERSHIP_AMBIGUOUS",
                "隔离后的对象与已记录所有权不一致，已恢复并停止",
            )
        return moved
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)


def delete_quarantined(
    root: RootReference,
    moved: EntrySnapshot,
) -> EntrySnapshot:
    """回收隔离文件内容并保留名称；空目录只验证并保留 tombstone。"""

    if moved.kind == "file":
        return _truncate_quarantined_file(root, moved)
    with retain_directory_lease(root, moved) as lease:
        return lease.validate_empty_and_named()


def _truncate_quarantined_file(
    root: RootReference,
    expected: EntrySnapshot,
) -> EntrySnapshot:
    try:
        with open_snapshot_for_update(root, expected) as handle:
            os.ftruncate(handle.fileno(), 0)
            handle.flush()
            os.fsync(handle.fileno())
            reclaimed = os.fstat(handle.fileno())
    except StorageError:
        raise
    except (AttributeError, OSError) as exc:
        if _is_windows_backend(root):
            raise StorageError(
                "KJA_QUARANTINE_RESIDUAL",
                "Windows 缺少安全句柄截断能力，已保留 quarantine 残余",
            ) from exc
        raise
    return EntrySnapshot.from_stat(
        expected.relative,
        "file",
        reclaimed,
        hashlib.sha256(b"").hexdigest(),
    )


def _restore_quarantine(
    root: RootReference,
    original: Path,
    quarantined: Path,
) -> None:
    if _is_windows_backend(root):
        from .storage_windows import restore_quarantine as restore_windows

        restore_windows(root, original, quarantined)
        return
    with _borrow_root(root) as root_fd:
        original_parent = _open_directory_chain(root_fd, original.parts[:-1])
        quarantine_parent = _open_directory_chain(root_fd, quarantined.parts[:-1])
        try:
            try:
                os.stat(original.name, dir_fd=original_parent, follow_symlinks=False)
            except FileNotFoundError:
                _rename_at(
                    quarantined.name,
                    original.name,
                    quarantine_parent,
                    original_parent,
                )
                os.fsync(quarantine_parent)
                os.fsync(original_parent)
                return
        finally:
            os.close(original_parent)
            os.close(quarantine_parent)
    raise StorageError(
        "KJA_OWNERSHIP_AMBIGUOUS",
        "原路径已被占用，隔离对象已保留且不会删除",
    )


def _same_snapshot_identity(left: EntrySnapshot, right: EntrySnapshot) -> bool:
    return (
        left.kind == right.kind
        and left.device == right.device
        and left.inode == right.inode
        and left.mode == right.mode
        and left.size == right.size
        and left.sha256 == right.sha256
    )


def _rename_at(
    source: str,
    destination: str,
    source_directory_fd: int,
    destination_directory_fd: int,
) -> None:
    if sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        rename_exclusive = library.renameatx_np
        rename_exclusive.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(
            source_directory_fd,
            os.fsencode(source),
            destination_directory_fd,
            os.fsencode(destination),
            0x4,
        )
        if result == 0:
            return
        _raise_quarantine_rename_error(ctypes.get_errno())
    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        try:
            rename_no_replace = library.renameat2
        except AttributeError as exc:
            raise StorageError(
                "KJA_ATOMIC_RENAME_UNAVAILABLE",
                "当前 Linux 运行库不支持 quarantine 原子 no-replace",
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
            source_directory_fd,
            os.fsencode(source),
            destination_directory_fd,
            os.fsencode(destination),
            0x1,
        )
        if result == 0:
            return
        _raise_quarantine_rename_error(ctypes.get_errno())
    raise StorageError(
        "KJA_ATOMIC_RENAME_UNAVAILABLE",
        "当前平台不支持 quarantine 原子 no-replace",
    )


def _raise_quarantine_rename_error(error_number: int) -> None:
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise StorageError(
            "KJA_OWNERSHIP_AMBIGUOUS",
            "quarantine 目标已存在，原对象与既有对象均保留",
        )
    if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
        raise StorageError(
            "KJA_ATOMIC_RENAME_UNAVAILABLE",
            "当前文件系统不支持 quarantine 原子 no-replace",
        )
    raise OSError(error_number, os.strerror(error_number))


def _scan_directory(
    directory_fd: int,
    relative_parent: Path,
    snapshots: list[EntrySnapshot],
    skipped_names: frozenset[str],
) -> None:
    for name in sorted(os.listdir(directory_fd)):
        if name in skipped_names:
            continue
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        relative = relative_parent / name
        if stat.S_ISLNK(metadata.st_mode):
            raise StorageError("KJA_UNSAFE_PATH", f"目录包含链接：{relative.as_posix()}")
        if stat.S_ISDIR(metadata.st_mode):
            snapshots.append(EntrySnapshot.from_stat(relative, "directory", metadata, None))
            child_fd = _open_directory_at(directory_fd, name, metadata)
            try:
                _scan_directory(child_fd, relative, snapshots, skipped_names)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise StorageError("KJA_UNSAFE_PATH", f"目录包含特殊文件：{relative.as_posix()}")
        descriptor = _open_file_at(directory_fd, name, metadata)
        try:
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                for chunk in iter(lambda: handle.read(MIB), b""):
                    digest.update(chunk)
            after = os.fstat(descriptor)
            if not _same_metadata(metadata, after):
                raise StorageError("KJA_SOURCE_CHANGED", "扫描期间来源文件发生变化")
        finally:
            os.close(descriptor)
        snapshots.append(EntrySnapshot.from_stat(relative, "file", metadata, digest.hexdigest()))


def _require_nofollow() -> None:
    if not _POSIX_NOFOLLOW_CAPABLE:
        raise StorageError(
            "KJA_NOFOLLOW_UNAVAILABLE",
            "当前平台无法排除链接竞态，已安全停止",
        )


@contextmanager
def retain_root(
    root: Path,
    *,
    expected: os.stat_result | None = None,
) -> Iterator[SafeRootHandle]:
    """不重新解析路径地打开并保持同一个根目录对象。"""

    if sys.platform == "win32":
        with _retain_windows_host_root(root) as retained:
            yield retained
        return
    _require_nofollow()
    before = expected or root.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise StorageError("KJA_UNSAFE_ROOT", "存储根目录不是普通目录")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        if not _same_inode(before, after):
            raise StorageError("KJA_UNSAFE_ROOT", "存储根目录在打开时发生变化")
        yield SafeRootHandle(
            path=root,
            descriptor=descriptor,
            device=after.st_dev,
            inode=after.st_ino,
            io_path=root,
        )
    finally:
        os.close(descriptor)


@contextmanager
def _retain_windows_host_root(root: Path) -> Iterator[SafeRootHandle]:
    from .storage_windows import retain_host_root

    with retain_host_root(root) as retained:
        yield retained


@contextmanager
def _borrow_root(root: RootReference) -> Iterator[int]:
    if isinstance(root, SafeRootHandle):
        descriptor = root.duplicate()
        try:
            yield descriptor
        finally:
            os.close(descriptor)
        return
    with retain_root(root) as retained:
        descriptor = retained.duplicate()
        try:
            yield descriptor
        finally:
            os.close(descriptor)


def _root_path(root: RootReference) -> Path:
    if isinstance(root, SafeRootHandle):
        return root.io_path or root.path
    return root


def _is_windows_backend(root: RootReference) -> TypeGuard[SafeRootHandle]:
    return isinstance(root, SafeRootHandle) and root.backend.startswith("windows-")


def _open_directory_chain(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for name in parts:
            before = os.stat(name, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise StorageError("KJA_UNSAFE_PATH", "路径父级包含链接或非目录")
            child = _open_directory_at(current, name, before)
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def _open_directory_at(parent_fd: int, name: str, before: os.stat_result) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    after = os.fstat(descriptor)
    if not _same_inode(before, after) or not stat.S_ISDIR(after.st_mode):
        os.close(descriptor)
        raise StorageError("KJA_UNSAFE_PATH", "目录组件在打开时发生变化")
    return descriptor


def _open_file_at(parent_fd: int, name: str, before: os.stat_result) -> int:
    descriptor = _open_file_descriptor(
        name,
        os.O_RDONLY | os.O_NOFOLLOW,
        parent_fd,
    )
    after = os.fstat(descriptor)
    if not _same_metadata(before, after) or not stat.S_ISREG(after.st_mode):
        os.close(descriptor)
        raise StorageError("KJA_SOURCE_CHANGED", "文件在打开时发生变化")
    return descriptor


def _open_file_descriptor(
    name: str,
    flags: int,
    parent_fd: int,
    mode: int = 0o600,
) -> int:
    return os.open(name, flags, mode, dir_fd=parent_fd)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _same_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_inode(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _protected_root_keys() -> set[str]:
    protected = {_path_key(Path(path)) for path in _SYSTEM_ROOTS}
    for variable in (
        "SystemRoot",
        "windir",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
    ):
        value = os.environ.get(variable)
        if value:
            protected.add(_path_key(Path(value)))
    return protected

"""三平台 Kindle 设备与传输能力探测。"""

from __future__ import annotations

import hashlib
import json
import plistlib
import posixpath
import re
import shutil
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable

from .models import DeviceInfo


Runner = Callable[[list[str]], Any]

_FIRMWARE_RE = re.compile(
    r"^\s*Kindle\s+([0-9]+(?:\.[0-9]+)+)\b", re.IGNORECASE | re.MULTILINE
)
_WINDOWS_VOLUME_COMMAND = (
    "$logicalDisks=@(Get-CimInstance Win32_LogicalDisk);"
    "$storageDisks=@(Get-CimInstance -Namespace Root/Microsoft/Windows/Storage "
    "-ClassName MSFT_Disk -ErrorAction SilentlyContinue);"
    "$results=@($logicalDisks|ForEach-Object{"
    "$logical=$_;"
    "$partitions=@(Get-CimAssociatedInstance -InputObject $logical "
    "-Association Win32_LogicalDiskToPartition);"
    "$physical=@($partitions|ForEach-Object{Get-CimAssociatedInstance "
    "-InputObject $_ -Association Win32_DiskDriveToDiskPartition});"
    "$groups=@($physical|Group-Object -Property PNPDeviceID);"
    "$disk=if($groups.Count -eq 1){$groups[0].Group[0]}else{$null};"
    "$readOnly=$null;$model=$null;$pnp=$null;$serial=$null;"
    "if($null -ne $disk){"
    "$model=$disk.Model;$pnp=$disk.PNPDeviceID;$serial=$disk.SerialNumber;"
    "$matches=@($storageDisks|Where-Object{[int]$_.Number -eq [int]$disk.Index});"
    "if($matches.Count -eq 1){$readOnly=[bool]$matches[0].IsReadOnly}"
    "};"
    "[pscustomobject]@{"
    "DeviceID=$logical.DeviceID;VolumeName=$logical.VolumeName;"
    "DriveType=$logical.DriveType;FreeSpace=$logical.FreeSpace;"
    "IsSystem=($logical.DeviceID -eq $env:SystemDrive);"
    "DiskModel=$model;PNPDeviceID=$pnp;SerialNumber=$serial;"
    "ReadOnly=$readOnly"
    "}"
    "});"
    "$results|ConvertTo-Json -Compress -Depth 4"
)


def redact_serial(serial: str) -> str:
    """只保留设备序列号的末四位。"""

    return f"…{serial[-4:]}" if serial else ""


def read_firmware(root: str | Path) -> str | None:
    """只读解析 Kindle 的固件版本文件。"""

    version_path = Path(root) / "system" / "version.txt"
    try:
        contents = version_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    match = _FIRMWARE_RE.search(contents)
    return match.group(1) if match else None


def probe_devices(system: str, runner: Runner) -> list[DeviceInfo]:
    """通过可注入命令执行器探测连接的 Kindle，不做挂载或写入。"""

    normalized = system.strip().lower()
    if normalized in {"darwin", "macos", "mac"}:
        devices = _probe_macos(runner)
        if devices:
            return devices
        return [DeviceInfo(
            transport="needs_official_tool_or_approval",
            root=None,
            serial=None,
            model=None,
            firmware=None,
            read_only=None,
            free_bytes=None,
        )]
    if normalized == "linux":
        return _probe_linux(runner) + _probe_mtp(
            runner, [str(_scripts_dir() / "kindle_mtp_linux.sh"), "list"]
        )
    if normalized in {"windows", "win32"}:
        usb_devices = _probe_windows(runner)
        mtp_devices = _probe_mtp(
            runner,
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(_scripts_dir() / "kindle_mtp_windows.ps1"),
                "list",
            ],
        )
        usb_identity_ids = {
            _opaque_device_id(_windows_identity_token(device.serial))
            for device in usb_devices
            if device.serial and _windows_identity_token(device.serial)
        }
        return usb_devices + [
            device for device in mtp_devices if device.transport_id not in usb_identity_ids
        ]
    return []


def _scripts_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def _local_root(runner: Runner, platform_root: str) -> Path:
    resolver = getattr(runner, "resolve_path", None)
    resolved = resolver(platform_root) if callable(resolver) else platform_root
    return Path(resolved)


def _safe_posix_mount(root: str, system: str) -> bool:
    if "\x00" in root or ".." in PurePosixPath(root).parts:
        return False
    try:
        normalized = Path(posixpath.normpath(root)).resolve(strict=False).as_posix()
    except (OSError, RuntimeError, ValueError):
        return False
    parts = PurePosixPath(normalized).parts
    if system == "macos":
        return len(parts) == 3 and parts[:2] == ("/", "Volumes")
    return (
        (len(parts) >= 3 and parts[:2] == ("/", "media"))
        or (len(parts) >= 4 and parts[:3] == ("/", "run", "media"))
        or (len(parts) >= 3 and parts[:2] == ("/", "mnt"))
    )


def _safe_windows_mount(root: str) -> bool:
    if "\x00" in root or ".." in PureWindowsPath(root).parts:
        return False
    path = PureWindowsPath(root)
    return bool(path.drive) and len(path.parts) == 1 and path.anchor.endswith("\\")


def _run(runner: Runner, argv: list[str]) -> tuple[int, str]:
    try:
        result = runner(argv)
    except (OSError, RuntimeError):
        return 1, ""
    if isinstance(result, str):
        return 0, result
    stdout = getattr(result, "stdout", "")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if not isinstance(stdout, str):
        stdout = ""
    returncode = getattr(result, "returncode", 0)
    return int(returncode) if isinstance(returncode, int) else 1, stdout


def _plist(stdout: str) -> dict[str, Any]:
    try:
        value = plistlib.loads(stdout.encode("utf-8"))
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return {}
    return value if isinstance(value, dict) else {}


def _mount_points(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        mount_point = value.get("MountPoint")
        if isinstance(mount_point, str):
            yield mount_point
        for item in value.values():
            yield from _mount_points(item)
    elif isinstance(value, list):
        for item in value:
            yield from _mount_points(item)


def _ioreg_identity_by_bsd(stdout: str) -> dict[str, dict[str, str]]:
    try:
        payload = plistlib.loads(stdout.encode("utf-8"))
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return {}
    roots = payload if isinstance(payload, list) else [payload]
    candidates: dict[str, list[dict[str, str]]] = {}
    for root in roots:
        if not isinstance(root, dict):
            continue
        product = str(root.get("USB Product Name") or "")
        vendor = str(root.get("USB Vendor Name") or "")
        serial = str(root.get("USB Serial Number") or "")
        if not _is_kindle_identity(product, vendor):
            continue
        identity = {"product": product, "vendor": vendor, "serial": serial}
        for bsd_name in _nested_string_values(root, "BSD Name"):
            candidates.setdefault(bsd_name, []).append(identity)
    return {
        bsd_name: identities[0]
        for bsd_name, identities in candidates.items()
        if len(identities) == 1
    }


def _nested_string_values(value: Any, key: str) -> Iterable[str]:
    if isinstance(value, dict):
        found = value.get(key)
        if isinstance(found, str) and found:
            yield found
        for child in value.values():
            yield from _nested_string_values(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from _nested_string_values(child, key)


def _probe_macos(runner: Runner) -> list[DeviceInfo]:
    _, list_output = _run(runner, ["diskutil", "list", "-plist"])
    _, ioreg_output = _run(
        runner, ["ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"]
    )
    identities = _ioreg_identity_by_bsd(ioreg_output)
    candidates: list[
        tuple[Path, dict[str, Any], str | None, dict[str, str] | None]
    ] = []

    seen: set[str] = set()
    for mount_text in _mount_points(_plist(list_output)):
        if mount_text in seen:
            continue
        seen.add(mount_text)
        if not _safe_posix_mount(mount_text, "macos"):
            continue
        local_root = _local_root(runner, mount_text)
        if not (local_root / "documents").is_dir():
            continue
        _, info_output = _run(runner, ["diskutil", "info", "-plist", mount_text])
        info = _plist(info_output)
        if info.get("MountPoint") != mount_text:
            continue
        if not _mac_external_usb(info):
            continue
        firmware = read_firmware(local_root)
        whole_disk = str(info.get("ParentWholeDisk") or "")
        usb_identity = identities.get(whole_disk)
        if firmware is None and usb_identity is None:
            continue
        candidates.append((Path(mount_text), info, firmware, usb_identity))

    results: list[DeviceInfo] = []
    for root, info, firmware, usb_identity in candidates:
        usb = usb_identity or {}
        results.append(DeviceInfo(
            transport="usbms",
            root=str(root),
            serial=usb.get("serial") or None,
            model=usb.get("product") or None,
            firmware=firmware,
            read_only=_optional_bool(info.get("ReadOnlyVolume")),
            free_bytes=_optional_int(info.get("VolumeFreeSpace")),
        ))
    return results


def _mac_external_usb(info: dict[str, Any]) -> bool:
    protocol = str(info.get("BusProtocol") or "").lower()
    internal = info.get("Internal")
    removable = info.get("Ejectable") is True or info.get("Removable") is True
    return protocol == "usb" and internal is False and removable


def _decode_mount_path(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _parse_properties(stdout: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            properties[key] = value
    return properties


def _probe_linux(runner: Runner) -> list[DeviceInfo]:
    _, mounts_output = _run(runner, ["cat", "/proc/mounts"])
    results: list[DeviceInfo] = []
    seen: set[str] = set()
    for line in mounts_output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        device, mount_value, _filesystem, options = fields[:4]
        root_text = _decode_mount_path(mount_value)
        if root_text in seen:
            continue
        seen.add(root_text)
        if not _safe_posix_mount(root_text, "linux"):
            continue
        local_root = _local_root(runner, root_text)
        if not (local_root / "documents").is_dir():
            continue
        _, udev_output = _run(
            runner,
            ["udevadm", "info", "--query=property", "--name", device],
        )
        properties = _parse_properties(udev_output)
        if not _linux_external_usb(properties):
            continue
        firmware = read_firmware(local_root)
        vendor = properties.get("ID_VENDOR", "")
        model_value = properties.get("ID_MODEL", "")
        if firmware is None and not _is_kindle_identity(vendor, model_value):
            continue
        model = model_value.replace("_", " ") or None
        results.append(DeviceInfo(
            transport="usbms",
            root=root_text,
            serial=properties.get("ID_SERIAL_SHORT") or None,
            model=model,
            firmware=firmware,
            read_only="ro" in options.split(","),
            free_bytes=_free_bytes(local_root),
        ))
    return results


def _linux_external_usb(properties: dict[str, str]) -> bool:
    bus = properties.get("ID_BUS", "").lower()
    path = properties.get("ID_PATH", "").lower()
    return bus == "usb" or "usb" in path


def _is_kindle_identity(*values: str) -> bool:
    combined = " ".join(values).lower()
    return "kindle" in combined or "amazon" in combined


def _free_bytes(root: Path) -> int | None:
    try:
        return shutil.disk_usage(root).free
    except OSError:
        return None


def _probe_windows(runner: Runner) -> list[DeviceInfo]:
    _, output = _run(
        runner,
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _WINDOWS_VOLUME_COMMAND,
        ],
    )
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return []
    volumes = payload if isinstance(payload, list) else [payload]
    results: list[DeviceInfo] = []
    for volume in volumes:
        if (
            not isinstance(volume, dict)
            or volume.get("DriveType") != 2
            or volume.get("IsSystem") is True
        ):
            continue
        root_text = volume.get("DeviceID")
        if not isinstance(root_text, str) or not root_text:
            continue
        if re.fullmatch(r"[A-Za-z]:", root_text):
            root_text += "\\"
        if not _safe_windows_mount(root_text):
            continue
        local_root = _local_root(runner, root_text)
        if not (local_root / "documents").is_dir():
            continue
        firmware = read_firmware(local_root)
        label = str(volume.get("VolumeName") or "")
        model_value = str(volume.get("DiskModel") or "")
        pnp_device_id = str(volume.get("PNPDeviceID") or "")
        has_usb_association = "usb" in pnp_device_id.lower()
        if firmware is None and (
            not has_usb_association
            or not _is_kindle_identity(label, model_value, pnp_device_id)
        ):
            continue
        results.append(DeviceInfo(
            transport="usbms",
            root=root_text,
            serial=_optional_string(volume.get("SerialNumber")),
            model=model_value or None,
            firmware=firmware,
            read_only=_optional_bool(volume.get("ReadOnly")),
            free_bytes=_optional_int(volume.get("FreeSpace")),
        ))
    return results


def _probe_mtp(runner: Runner, argv: list[str]) -> list[DeviceInfo]:
    _, output = _run(runner, argv)
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return []
    devices = payload.get("devices")
    if not isinstance(devices, list):
        return []
    results: list[DeviceInfo] = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        device_id = device.get("id")
        name = device.get("name")
        storage = device.get("storage")
        if not all(isinstance(value, str) and value for value in (
            device_id, name, storage,
        )):
            continue
        if not _is_kindle_identity(name):
            continue
        results.append(DeviceInfo(
            transport="mtp",
            root=None,
            serial=None,
            model=name,
            firmware=_optional_string(device.get("firmware")),
            read_only=_optional_bool(device.get("read_only")),
            free_bytes=_optional_int(device.get("free_bytes")),
            transport_id=device_id,
            device_code=_optional_string(device.get("device_code")),
        ))
    return results


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _windows_identity_token(instance_id: str) -> str:
    leaf = re.split(r"[\\/]", instance_id)[-1]
    return leaf.split("&", 1)[0].strip().upper()


def _opaque_device_id(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]

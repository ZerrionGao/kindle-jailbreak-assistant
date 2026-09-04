"""KOReader 包选择与后越狱只读证据核对。"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from .models import DeviceInfo, EvidenceResult, PackageChoice
from .routing import compare_versions


def choose_koreader_package(
    device: DeviceInfo, official_rules: object
) -> PackageChoice:
    """仅按调用时传入、已验证的官方规则选择包；绝不猜测相邻机型。"""

    if not isinstance(device.model, str) or not device.model:
        raise ValueError("Kindle 型号未知，不能猜测 KOReader 包")
    if not isinstance(device.firmware, str) or not device.firmware:
        raise ValueError("Kindle 固件未知，不能猜测 KOReader 包")

    packages = _parse_official_rules(official_rules)
    matches: list[PackageChoice] = []
    for package in packages:
        if device.model not in package["models"]:
            continue
        firmware = package["firmware"]
        try:
            in_range = (
                compare_versions(device.firmware, firmware["min"]) >= 0
                and compare_versions(device.firmware, firmware["max"]) <= 0
            )
        except ValueError as exc:
            raise ValueError("官方 KOReader 规则的固件格式无效") from exc
        if not in_range:
            continue
        matches.append(_package_choice(package))
    if not matches:
        raise ValueError("当前官方规则没有精确匹配的 KOReader 包")
    effective_choices = {
        (choice.asset_family, choice.install_method, choice.manual_fallback)
        for choice in matches
    }
    if len(effective_choices) != 1:
        raise ValueError("当前官方 KOReader 规则存在相互冲突的匹配结果")
    return matches[0]


def verify_jailbreak(
    root: str | Path,
    *,
    equivalent_markers: Iterable[str] = (),
    excluded_markers: Iterable[str] = (),
    user_log_evidence: bool = False,
) -> EvidenceResult:
    """只读取当前方法指定的越狱证据；脚本输出和错误文字不构成证据。"""

    kindle_root = _readable_root(root)
    excluded = {_safe_marker(marker).as_posix() for marker in excluded_markers}
    observed: list[str] = []
    for marker in equivalent_markers:
        relative = _safe_marker(marker)
        if relative.as_posix() not in excluded and _regular_file(kindle_root / relative):
            observed.append(relative.as_posix())
    if user_log_evidence is True:
        observed.append(";log_user_report")
    elif user_log_evidence is not False:
        raise ValueError("用户日志证据必须是布尔值")
    return EvidenceResult(
        complete=bool(observed),
        missing_evidence=[] if observed else ["jailbreak_marker"],
        observed_evidence=tuple(observed),
    )


def _package_choice(package: dict[str, Any]) -> PackageChoice:
    kpm = package["kpm"]
    if kpm["supported"] and kpm["integrity_verified"]:
        return PackageChoice(
            asset_family=package["asset_family"],
            source_rule=package["name"],
            install_method="kpm",
            manual_fallback=False,
        )
    manual = package["manual"]
    if manual["supported"] and manual["integrity_verified"]:
        return PackageChoice(
            asset_family=package["asset_family"],
            source_rule=package["name"],
            install_method="manual",
            manual_fallback=True,
        )
    raise ValueError("当前官方规则没有已验证可用的 KOReader 安装路径")


def verify_koreader_files(
    root: str | Path, *, user_visible_launch: bool = False
) -> EvidenceResult:
    """核对 KOReader 文件与用户实际启动证据，整个过程不写入设备。"""

    if not isinstance(user_visible_launch, bool):
        raise ValueError("用户实际启动证据必须是布尔值")
    kindle_root = _readable_root(root)
    markers = (
        ("koreader", kindle_root / "koreader"),
        (".adds/koreader", kindle_root / ".adds" / "koreader"),
    )
    observed = [name for name, path in markers if _regular_directory(path)]
    missing: list[str] = []
    if not observed:
        missing.append("koreader_files")
    if not user_visible_launch:
        missing.append("user_visible_launch")
    return EvidenceResult(
        complete=not missing,
        missing_evidence=missing,
        observed_evidence=tuple(observed),
    )


def _parse_official_rules(official_rules: object) -> list[dict[str, Any]]:
    if (
        not isinstance(official_rules, dict)
        or set(official_rules) != {"schema_version", "packages"}
        or official_rules["schema_version"] != 1
        or not isinstance(official_rules["packages"], list)
        or not official_rules["packages"]
    ):
        raise ValueError("官方 KOReader 规则未知或格式不支持")
    packages: list[dict[str, Any]] = []
    for package in official_rules["packages"]:
        if not isinstance(package, dict) or set(package) != {
            "name", "models", "firmware", "asset_family", "kpm", "manual",
        }:
            raise ValueError("官方 KOReader 包规则格式无效")
        if (
            not isinstance(package["name"], str) or not package["name"]
            or not isinstance(package["asset_family"], str)
            or not package["asset_family"]
            or not isinstance(package["models"], list)
            or not package["models"]
            or not all(isinstance(model, str) and model for model in package["models"])
            or not _valid_firmware_rule(package["firmware"])
            or not _valid_install_rule(package["kpm"])
            or not _valid_install_rule(package["manual"])
        ):
            raise ValueError("官方 KOReader 包规则字段无效")
        packages.append(package)
    return packages


def _valid_firmware_rule(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"min", "max"}:
        return False
    if not all(isinstance(value[key], str) and value[key] for key in ("min", "max")):
        return False
    try:
        return compare_versions(value["min"], value["max"]) <= 0
    except ValueError:
        return False


def _valid_install_rule(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"supported", "integrity_verified"}
        and isinstance(value["supported"], bool)
        and isinstance(value["integrity_verified"], bool)
    )


def _readable_root(root: str | Path) -> Path:
    candidate = Path(root)
    if not candidate.is_dir() or candidate.is_symlink():
        raise ValueError("Kindle 根目录不可读取")
    return candidate


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _regular_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


def _safe_marker(marker: str) -> Path:
    if not isinstance(marker, str) or not marker:
        raise ValueError("等价越狱标记无效")
    normalized = marker.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("等价越狱标记必须位于 Kindle 根目录内")
    return Path(*candidate.parts)

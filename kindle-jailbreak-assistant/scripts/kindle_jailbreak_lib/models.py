"""Kindle 越狱助手的基础数据模型。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Stage(str, Enum):
    """会话可以处于的阶段。"""

    DISCOVER = "DISCOVER"
    RISK_ACK = "RISK_ACK"
    ROUTE = "ROUTE"
    BACKUP = "BACKUP"
    PREPARE = "PREPARE"
    WAIT_RECONNECT = "WAIT_RECONNECT"
    WAIT_USER_EXPLOIT = "WAIT_USER_EXPLOIT"
    VERIFY_JAILBREAK = "VERIFY_JAILBREAK"
    INSTALL_KOREADER = "INSTALL_KOREADER"
    VERIFY_KOREADER = "VERIFY_KOREADER"
    CLEANUP = "CLEANUP"
    COMPLETE = "COMPLETE"
    RECOVERABLE_ERROR = "RECOVERABLE_ERROR"
    BLOCKED_UNSUPPORTED = "BLOCKED_UNSUPPORTED"
    BLOCKED_CONFLICT = "BLOCKED_CONFLICT"
    ABORTED_SAFE = "ABORTED_SAFE"


class TriState(str, Enum):
    """需要用户确认的布尔属性的三态值。"""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: "str | TriState") -> "TriState":
        """把用户或外部数据中的值解析为三态值。"""

        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"invalid tri-state value: {value!r}")

        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(f"invalid tri-state value: {value!r}") from exc


@dataclass(frozen=True)
class DeviceInfo:
    transport: str
    root: str | None
    serial: str | None
    model: str | None
    firmware: str | None
    read_only: bool | None
    free_bytes: int | None
    transport_id: str | None = None
    device_code: str | None = None

    def public_dict(self) -> dict[str, object]:
        """返回不含完整序列号的用户可见设备信息。"""

        serial_suffix = self.serial[-4:] if self.serial else None
        return {
            "transport": self.transport,
            "root": self.root,
            "serial_suffix": serial_suffix,
            "model": self.model,
            "firmware": self.firmware,
            "read_only": self.read_only,
            "free_bytes": self.free_bytes,
            "device_code": self.device_code,
        }


@dataclass(frozen=True)
class RouteCandidate:
    name: str
    url: str
    required_questions: tuple[str, ...]
    policy_name: str


@dataclass(frozen=True)
class PackageChoice:
    """当前官方规则裁决出的 KOReader 安装包与安装路径。"""

    asset_family: str
    source_rule: str
    install_method: str
    manual_fallback: bool


@dataclass(frozen=True)
class EvidenceResult:
    """只读证据核对结果，不承载账户、二维码或完整设备标识。"""

    complete: bool
    missing_evidence: list[str]
    observed_evidence: tuple[str, ...]

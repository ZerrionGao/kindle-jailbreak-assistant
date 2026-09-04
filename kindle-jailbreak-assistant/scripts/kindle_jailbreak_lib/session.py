"""可恢复的会话状态和原子 JSON 存储。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import DeviceInfo, Stage


_ACTIVE_STAGES = frozenset({
    Stage.DISCOVER,
    Stage.RISK_ACK,
    Stage.ROUTE,
    Stage.BACKUP,
    Stage.PREPARE,
    Stage.WAIT_USER_EXPLOIT,
    Stage.VERIFY_JAILBREAK,
    Stage.INSTALL_KOREADER,
    Stage.VERIFY_KOREADER,
    Stage.CLEANUP,
})
_TERMINAL_STAGES = frozenset({
    Stage.COMPLETE,
    Stage.BLOCKED_UNSUPPORTED,
    Stage.BLOCKED_CONFLICT,
    Stage.ABORTED_SAFE,
})
_SAFE_TERMINAL_STAGES = frozenset({
    Stage.BLOCKED_UNSUPPORTED,
    Stage.BLOCKED_CONFLICT,
    Stage.ABORTED_SAFE,
})
_MAIN_NEXT = {
    Stage.DISCOVER: Stage.RISK_ACK,
    Stage.RISK_ACK: Stage.ROUTE,
    Stage.ROUTE: Stage.BACKUP,
    Stage.BACKUP: Stage.PREPARE,
    Stage.PREPARE: Stage.WAIT_USER_EXPLOIT,
    Stage.WAIT_USER_EXPLOIT: Stage.VERIFY_JAILBREAK,
    Stage.VERIFY_JAILBREAK: Stage.INSTALL_KOREADER,
    Stage.INSTALL_KOREADER: Stage.VERIFY_KOREADER,
    Stage.VERIFY_KOREADER: Stage.CLEANUP,
    Stage.CLEANUP: Stage.COMPLETE,
}

_PRIVATE_RESUME_KEY = "__resume_stage"
_SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|auth[_-]?header|cookie|token|password|passwd|secret|credential|"
    r"qr[_-]?uid|qrcode[_-]?uid|api[_-]?key|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_SERIAL_KEY_RE = re.compile(r"^(?:serial|serial[_-]?number|device[_-]?serial)$", re.IGNORECASE)
_URL_SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|auth|cookie|token|password|passwd|secret|key|credential|session|"
    r"qr[_-]?uid|qrcode[_-]?uid|uid)",
    re.IGNORECASE,
)


def device_fingerprint(session_id: str, full_serial: str) -> str:
    """返回绑定会话标识和完整设备序列号的稳定短指纹。"""

    if not isinstance(session_id, str) or not session_id:
        raise ValueError("会话标识不能为空")
    if not isinstance(full_serial, str) or not full_serial:
        raise ValueError("完整设备序列号不能为空")
    return hashlib.sha256(
        session_id.encode("utf-8") + b":" + full_serial.encode("utf-8")
    ).hexdigest()[:16]


def _as_stage(value: Stage | str) -> Stage:
    if isinstance(value, Stage):
        return value
    try:
        return Stage(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid stage: {value!r}") from exc


def _redacted_serial(serial: str) -> str:
    """保留最多四位后缀，避免把完整序列号写入会话。"""

    return f"…{serial[-4:]}" if serial else ""


def _sanitize_url(value: str) -> str:
    """移除 URL userinfo 和查询串中可能承载的认证信息。"""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return value

    has_userinfo = "@" in parsed.netloc
    if not parsed.query and not has_userinfo:
        return value

    safe_netloc = parsed.netloc.rsplit("@", 1)[-1]
    safe_query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not _URL_SENSITIVE_KEY_RE.search(key)
    ]
    return urlunsplit((parsed.scheme, safe_netloc, parsed.path, urlencode(safe_query), ""))


def _sanitize_for_storage(value: Any, path: tuple[str, ...] = ()) -> Any:
    """在 JSON 落盘前递归清除凭据并脱敏序列号。"""

    if path == ("approvals",):
        if not isinstance(value, dict):
            raise TypeError("approvals must be an object")
        approvals: dict[str, bool] = {}
        for approval_name, approved in value.items():
            if not isinstance(approval_name, str):
                raise TypeError("approval names must be strings")
            if not isinstance(approved, bool):
                raise TypeError("approval values must be booleans")
            approvals[approval_name] = approved
        return approvals

    key = path[-1] if path else None
    if key is not None and _SENSITIVE_KEY_RE.search(key):
        return None
    if key is not None and _SERIAL_KEY_RE.match(key) and isinstance(value, str):
        return _redacted_serial(value)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            string_key = str(raw_key)
            if _SENSITIVE_KEY_RE.search(string_key):
                continue
            sanitized_value = _sanitize_for_storage(raw_value, path + (string_key,))
            sanitized[string_key] = sanitized_value
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_storage(item, path) for item in value]
    if isinstance(value, Stage):
        return value.value
    if isinstance(value, (str, int, float, bool)) or value is None:
        if key is not None and key.lower() in {"url", "source_url", "download_url"} and isinstance(value, str):
            return _sanitize_url(value)
        return value
    raise TypeError(f"value is not JSON serializable: {type(value).__name__}")


@dataclass
class SessionState:
    schema_version: int
    session_id: str
    device_fingerprint: str
    device_public: dict[str, object]
    stage: Stage
    target: str
    route: dict[str, object] | None
    approvals: dict[str, bool]
    evidence: dict[str, object]
    created_files: list[str]

    def transition(self, next_stage: Stage) -> None:
        """只允许状态图定义的前向、等待、恢复和安全终止迁移。"""

        next_stage = _as_stage(next_stage)
        current_stage = _as_stage(self.stage)
        self.stage = current_stage

        if current_stage in _TERMINAL_STAGES:
            raise ValueError(f"cannot transition from terminal stage {current_stage.value}")

        if next_stage in _SAFE_TERMINAL_STAGES:
            self.stage = next_stage
            return

        if next_stage == Stage.COMPLETE:
            if _MAIN_NEXT.get(current_stage) != Stage.COMPLETE:
                raise ValueError(
                    f"invalid transition: {current_stage.value} -> {next_stage.value}"
                )
            self.stage = next_stage
            return

        if current_stage in {Stage.WAIT_RECONNECT, Stage.RECOVERABLE_ERROR}:
            if (
                next_stage in {Stage.WAIT_RECONNECT, Stage.RECOVERABLE_ERROR}
                and next_stage != current_stage
            ):
                self.stage = next_stage
                return
            resume_value = self.evidence.get(_PRIVATE_RESUME_KEY)
            try:
                resume_stage = Stage(resume_value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"{current_stage.value} has no valid resume stage"
                ) from exc
            if next_stage != resume_stage:
                raise ValueError(
                    f"invalid resume transition: {current_stage.value} -> {next_stage.value}"
                )
            evidence = dict(self.evidence)
            evidence.pop(_PRIVATE_RESUME_KEY, None)
            self.evidence = evidence
            self.stage = next_stage
            return

        if next_stage in {Stage.WAIT_RECONNECT, Stage.RECOVERABLE_ERROR}:
            if current_stage not in _ACTIVE_STAGES:
                raise ValueError(
                    f"invalid transition: {current_stage.value} -> {next_stage.value}"
                )
            evidence = dict(self.evidence)
            evidence[_PRIVATE_RESUME_KEY] = current_stage.value
            self.evidence = evidence
            self.stage = next_stage
            return

        is_allowed_forward = (
            _MAIN_NEXT.get(current_stage) == next_stage
            or current_stage == Stage.DISCOVER and next_stage == Stage.ROUTE
        )
        if not is_allowed_forward:
            raise ValueError(
                f"invalid transition: {current_stage.value} -> {next_stage.value}"
            )
        self.stage = next_stage

    def to_dict(self) -> dict[str, object]:
        """转换成稳定的会话 JSON 结构。"""

        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "device_fingerprint": self.device_fingerprint,
            "device_public": self.device_public,
            "stage": self.stage.value,
            "target": self.target,
            "route": self.route,
            "approvals": self.approvals,
            "evidence": self.evidence,
            "created_files": self.created_files,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "SessionState":
        """从会话 JSON 结构恢复状态并校验必需字段。"""

        required = {
            "schema_version",
            "session_id",
            "device_fingerprint",
            "device_public",
            "stage",
            "target",
            "route",
            "approvals",
            "evidence",
            "created_files",
        }
        missing = sorted(required.difference(payload))
        if missing:
            raise ValueError(f"session is missing fields: {', '.join(missing)}")

        try:
            stage = Stage(payload["stage"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid session stage: {payload.get('stage')!r}") from exc

        if not isinstance(payload["device_public"], dict):
            raise ValueError("session device_public must be an object")
        if payload["route"] is not None and not isinstance(payload["route"], dict):
            raise ValueError("session route must be an object or null")
        if not isinstance(payload["approvals"], dict):
            raise ValueError("session approvals must be an object")
        if not all(
            isinstance(name, str) and isinstance(approved, bool)
            for name, approved in payload["approvals"].items()
        ):
            raise ValueError("session approvals must contain boolean values")
        if not isinstance(payload["evidence"], dict):
            raise ValueError("session evidence must be an object")
        if not isinstance(payload["created_files"], list):
            raise ValueError("session created_files must be an array")
        schema_version = payload["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise ValueError("session schema_version must be an integer")

        return cls(
            schema_version=schema_version,
            session_id=str(payload["session_id"]),
            device_fingerprint=str(payload["device_fingerprint"]),
            device_public=dict(payload["device_public"]),
            stage=stage,
            target=str(payload["target"]),
            route=dict(payload["route"]) if payload["route"] is not None else None,
            approvals=dict(payload["approvals"]),
            evidence=dict(payload["evidence"]),
            created_files=list(payload["created_files"]),
        )


class SessionStore:
    """把单个会话保存到目录中的 ``session.json``。"""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.session_path = self.root / "session.json"

    def create(self, device: DeviceInfo, target: str = "jailbreak+koreader") -> SessionState:
        """为设备创建新会话，并立即原子保存初始状态。"""

        if self.session_path.exists():
            raise FileExistsError(f"session already exists: {self.session_path}")

        session_id = uuid.uuid4().hex
        identity = device.serial or device.transport_id or "<unknown>"
        fingerprint = device_fingerprint(session_id, identity)
        state = SessionState(
            schema_version=1,
            session_id=session_id,
            device_fingerprint=fingerprint,
            device_public=device.public_dict(),
            stage=Stage.DISCOVER,
            target=target,
            route=None,
            approvals={},
            evidence={},
            created_files=[],
        )
        self.save(state)
        return state

    def load(self) -> SessionState:
        """读取并校验当前会话。"""

        try:
            payload = json.loads(self.session_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError(f"session not found: {self.session_path}") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid session JSON: {self.session_path}") from exc
        if not isinstance(payload, dict):
            raise ValueError("session JSON must be an object")
        return SessionState.from_dict(payload)

    def save(self, state: SessionState) -> None:
        """在同目录原子替换会话文件，不触碰其他备份文件。"""

        if not isinstance(state, SessionState):
            raise TypeError("state must be a SessionState")
        self.root.mkdir(parents=True, exist_ok=True)
        payload = _sanitize_for_storage(state.to_dict())
        temporary_path: str | None = None
        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=".session.", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.session_path)
            temporary_path = None
            try:
                directory_fd = os.open(self.root, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
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

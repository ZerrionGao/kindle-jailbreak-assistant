#!/usr/bin/env python3
"""Kindle 越狱助手命令行编排器。

稳定退出码：20 未授权；21 状态、设备或策略冲突；22 不支持；
23 可恢复错误；24 校验失败。设备写操作默认仅预演，必须显式传入
``--apply``，且当前会话已经记录写入授权。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from unittest import mock
from urllib.parse import unquote, urljoin, urlsplit

from kindle_jailbreak_lib.device import probe_devices
from kindle_jailbreak_lib import mtp as mtp_storage
from kindle_jailbreak_lib.models import DeviceInfo, Stage, TriState
from kindle_jailbreak_lib.progress import ProgressEvent
from kindle_jailbreak_lib.routing import (
    MethodPolicy,
    OfficialSourceSnapshot,
    RouteResult,
    fetch_official_source,
    load_cached_source,
    load_method_policy,
    load_policies,
    select_routes,
)
from kindle_jailbreak_lib.session import SessionState, SessionStore, device_fingerprint
from kindle_jailbreak_lib.storage_manifest import CreatedFilesJournal
from kindle_jailbreak_lib.storage import (
    StorageError,
    DEFAULT_FILL_CHUNK_BYTES,
    DEFAULT_RESERVE_BYTES,
    assert_safe_root,
    backup_visible_storage,
    cleanup_created_files,
    fill_storage,
    stage_archive,
    verify_jailbreak,
    verify_koreader_files,
)


EXIT_NOT_AUTHORIZED = 20
EXIT_CONFLICT = 21
EXIT_UNSUPPORTED = 22
EXIT_RECOVERABLE = 23
EXIT_VERIFICATION_FAILED = 24

_MODELS_URL = "https://kindlemodding.org/models.json"
_JAILBREAKS_URL = "https://kindlemodding.org/jailbreaks.json"
_FINDER_URL = "https://kindlemodding.org/jailbreakFinder.js"
_POLICIES_PATH = Path(__file__).resolve().parents[1] / "references" / "method-policies.json"
_SOURCE_KINDS = ("models", "jailbreaks", "finder", "method_page")
_RISK_NOTICE = (
    "越狱是非官方修改，可能造成数据丢失、系统异常、自动升级受阻，极端情况下设备无法启动。",
    "备份只覆盖电脑可见内容，不是完整系统镜像，不能保证恢复硬件级故障。",
    "Skill、脚本作者、越狱维护者和 Agent 不承担设备、账户或数据损失责任。",
    "你可以随时停止；助手会报告已写入内容，并提供清理或恢复入口。",
)
_VALIDATION_CODES = frozenset({
    "KJA_ARCHIVE_REQUIRED",
    "KJA_ARCHIVE_LINK",
    "KJA_ARCHIVE_INVALID",
    "KJA_REQUIRED_FILES",
    "KJA_UNSAFE_PATH",
    "KJA_FAT32_NAME",
    "KJA_FAT32_SIZE",
    "KJA_INSUFFICIENT_SPACE",
    "KJA_CHECKSUM_MISMATCH",
    "KJA_STAGE_INVALID",
    "KJA_STAGE_EXISTS",
    "KJA_TARGET_EXISTS",
})
_TERMINAL_STAGES = frozenset({
    Stage.COMPLETE,
    Stage.BLOCKED_UNSUPPORTED,
    Stage.BLOCKED_CONFLICT,
    Stage.ABORTED_SAFE,
})
_KOREADER_STAGING_POLICY = MethodPolicy(
    automation="guided-assets",
    generic_filler="not-applicable",
    forbid_nearest_firmware=True,
    separate_approval=(),
)
_fixture_probe_count = 0


class CLIError(RuntimeError):
    """可稳定映射到公开退出码的 CLI 错误。"""

    def __init__(self, exit_code: int, code: str, message: str):
        self.exit_code = exit_code
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class EventWriter:
    def __init__(self, json_mode: bool):
        self.json_mode = json_mode

    def emit(self, event: str, **fields: object) -> None:
        payload = {"event": event, **fields}
        if self.json_mode:
            print(
                "KJA_EVENT "
                + json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                flush=True,
            )
            return
        message = fields.get("message")
        print(message if isinstance(message, str) else event, flush=True)
        risks = fields.get("risks")
        if isinstance(risks, list):
            for risk in risks:
                if isinstance(risk, str):
                    print(f"- {risk}", flush=True)

    def progress(self, progress: ProgressEvent) -> None:
        payload: dict[str, object] = {
            "stage": progress.stage.value,
            "done": progress.done,
        }
        if progress.total is not None:
            payload["total"] = progress.total
        payload.update({
            "unit": progress.unit,
            "message": progress.message,
            "user_action": progress.user_action,
        })
        self.emit(progress.event, **payload)


def _shared_arguments() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    shared.add_argument("--session-dir", metavar="PATH", help="会话及备份状态目录")
    shared.add_argument("--device-root", metavar="PATH", help="已探测到的 Kindle 根目录")
    shared.add_argument("--json", action="store_true", help="输出 KJA_EVENT 单行 JSON")
    shared.add_argument("--dry-run", action="store_true", help="只预演设备写操作（默认）")
    shared.add_argument("--apply", action="store_true", help="执行已经授权的设备写操作")
    return shared


def build_parser() -> argparse.ArgumentParser:
    shared = _shared_arguments()
    parser = argparse.ArgumentParser(
        description="安全编排 Kindle 越狱准备、校验与断点续接",
        epilog=(
            "退出码：20 未授权；21 状态、设备或策略冲突；22 不支持；"
            "23 可恢复错误；24 校验失败。"
        ),
        parents=[shared],
        argument_default=argparse.SUPPRESS,
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    commands.add_parser("probe", help="只读探测 Kindle", parents=[shared])

    route = commands.add_parser("route", help="选择当前官方支持的路线", parents=[shared])
    route.add_argument(
        "--source-fixture-dir",
        metavar="PATH",
        help="隔离测试使用的四来源目录",
    )
    route.add_argument(
        "--confirm-source",
        action="append",
        default=[],
        metavar="KIND=SHA256",
        help="确认当次来源哈希，四类来源必须全部精确匹配",
    )
    route.add_argument("--registered", choices=("yes", "no", "unknown"), default="unknown")
    route.add_argument("--ads", choices=("yes", "no", "unknown"), default="unknown")
    route.add_argument(
        "--acknowledge-risk",
        action="store_true",
        help="记录已阅读并接受当前会话的风险说明",
    )
    route.add_argument(
        "--confirm-method-marker-rule",
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="确认当前方法页把该路径声明为正向成功标记",
    )
    route.add_argument(
        "--confirm-method-log-rule",
        action="store_true",
        help="确认当前方法页把 ;log 声明为正向成功证据",
    )

    ota = commands.add_parser("ota-check", help="核对离线状态和 OTA 升级风险", parents=[shared])
    ota.add_argument(
        "--offline-confirmed-by-user",
        action="store_true",
        help="记录用户已确认 Kindle 处于飞行模式或离线",
    )
    ota.add_argument(
        "--prevention-status",
        choices=("verified",),
        help="记录当前方法的 OTA 阻止状态",
    )

    backup = commands.add_parser("backup", help="备份电脑可见的 Kindle 内容", parents=[shared])
    backup.add_argument("--backup-dir", metavar="PATH", help="备份父目录")
    backup.add_argument("--timestamp", metavar="YYYYMMDDTHHMMSSZ", help=argparse.SUPPRESS)

    commands.add_parser("fill", help="按当前方法要求创建可恢复占位文件", parents=[shared])

    authorize = commands.add_parser(
        "authorize-write", help="授权下一项普通设备写入", parents=[shared]
    )
    authorize.add_argument(
        "--operation",
        required=True,
        choices=("fill", "stage-jailbreak", "stage-koreader", "cleanup"),
    )
    authorize.add_argument(
        "--confirmed-by-user",
        action="store_true",
        help="仅在用户明确同意这一个写入操作后记录",
    )

    stage = commands.add_parser("stage", help="检查并暂存官方载荷", parents=[shared])
    stage.add_argument("--archive", required=True, metavar="PATH", help="已下载的官方载荷归档")
    stage.add_argument(
        "--required-file",
        required=True,
        action="append",
        metavar="RELATIVE_PATH",
        help="官方说明要求归档包含的关键文件，可重复传入",
    )
    stage.add_argument(
        "--purpose",
        choices=("jailbreak", "koreader"),
        default="jailbreak",
        help="载荷用途（默认 jailbreak）",
    )

    payload = commands.add_parser(
        "record-payload", help="隔离测试记录载荷（生产使用 fetch-payload）", parents=[shared]
    )
    payload.add_argument("--archive", required=True, metavar="PATH")
    payload.add_argument("--final-url", required=True, metavar="HTTPS_URL")
    payload.add_argument("--release-version", required=True, metavar="VERSION")
    payload.add_argument("--expected-sha256", required=True, metavar="SHA256")
    payload.add_argument("--purpose", choices=("jailbreak", "koreader"), default="jailbreak")

    fetch_payload = commands.add_parser(
        "fetch-payload", help="从已确认的上游链接下载并记录载荷", parents=[shared]
    )
    fetch_payload.add_argument("--url", required=True, metavar="HTTPS_URL")
    fetch_payload.add_argument("--release-version", required=True, metavar="VERSION")
    fetch_payload.add_argument(
        "--purpose", choices=("jailbreak", "koreader"), default="jailbreak"
    )

    koreader_choice = commands.add_parser(
        "confirm-koreader-package",
        help="绑定当前设备经官方安装页确认的 KOReader 包族",
        parents=[shared],
    )
    koreader_choice.add_argument(
        "--asset-family",
        required=True,
        choices=("kindle", "kindlehf", "kindlepw2", "kindle-legacy"),
    )
    koreader_choice.add_argument("--source-sha256", required=True, metavar="SHA256")
    koreader_choice.add_argument("--confirmed-by-user", action="store_true")

    verify = commands.add_parser("verify", help="核对设备端成功证据", parents=[shared])
    verify.add_argument(
        "--kind",
        choices=("auto", "jailbreak", "koreader"),
        default="auto",
        help="要核对的证据类型（默认按当前阶段判断）",
    )

    checkpoint = commands.add_parser(
        "checkpoint", help="记录用户已完成的设备端检查点", parents=[shared]
    )
    checkpoint.add_argument(
        "--kind",
        choices=(
            "exploit-complete",
            "jailbreak-marker",
            "jailbreak-log",
            "koreader-visible-launch",
        ),
        required=True,
        help="用户已完成的设备端动作",
    )
    checkpoint.add_argument(
        "--confirmed-by-user",
        action="store_true",
        help="仅在用户明确确认所见设备端结果后记录",
    )
    checkpoint.add_argument(
        "--evidence-path",
        metavar="RELATIVE_PATH",
        help="用户确认由当前设备操作产生的方法专属标记",
    )

    commands.add_parser("cleanup", help="精确清理当前会话创建的文件", parents=[shared])
    commands.add_parser("status", help="显示当前会话状态", parents=[shared])
    commands.add_parser("resume", help="确认同一设备后恢复断点", parents=[shared])
    commands.add_parser("self-test", help="运行不接触真机的快速检查", parents=[shared])
    return parser


def _path_argument(args: argparse.Namespace, name: str, default: Path | None = None) -> Path | None:
    value = getattr(args, name, None)
    if value is None:
        return default
    return Path(value).expanduser()


def _session_store(args: argparse.Namespace) -> SessionStore:
    default = Path.home() / "Downloads" / "Kindle-Jailbreak-Sessions" / "current"
    root = _path_argument(args, "session_dir", default)
    assert root is not None
    return SessionStore(root)


def _run_host_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def _under_directory(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(parent.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", f"测试设备的 {field} 字段无效")
    return value


def _fixture_device(args: argparse.Namespace) -> DeviceInfo | None:
    global _fixture_probe_count

    if os.environ.get("KJA_TEST_MODE") != "1":
        return None
    fixture_value = os.environ.get("KJA_TEST_DEVICE_FIXTURE")
    if not fixture_value:
        return None
    fixture = Path(fixture_value).expanduser()
    temporary_root = Path(tempfile.gettempdir())
    if not _under_directory(fixture, temporary_root):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_SCOPE", "测试设备文件必须位于系统临时目录")
    try:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试设备文件不可用") from exc
    required = {
        "transport", "root", "serial", "model", "firmware", "read_only", "free_bytes",
    }
    optional = {"available", "disconnect_after", "transport_id", "device_code"}
    if (
        not isinstance(payload, dict)
        or not required.issubset(payload)
        or not set(payload).issubset(required | optional)
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试设备字段不完整")
    if payload.get("available", True) is not True:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "测试 Kindle 当前未连接")
    disconnect_after = payload.get("disconnect_after")
    if disconnect_after is not None and (
        not isinstance(disconnect_after, int)
        or isinstance(disconnect_after, bool)
        or disconnect_after < 1
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试设备断线计数无效")
    _fixture_probe_count += 1
    if disconnect_after is not None and _fixture_probe_count > disconnect_after:
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "测试 Kindle 在操作期间断开")
    root_value = _optional_string(payload["root"], "root")
    transport = _optional_string(payload["transport"], "transport") or ""
    transport_id = _optional_string(payload.get("transport_id"), "transport_id")
    device_code = _optional_string(payload.get("device_code"), "device_code")
    if transport == "mtp":
        if root_value is not None or transport_id is None or device_code is None:
            raise CLIError(
                EXIT_CONFLICT,
                "KJA_FIXTURE_INVALID",
                "测试 MTP 设备必须使用稳定传输身份且不能伪装成本地目录",
            )
    elif root_value is None or not _under_directory(Path(root_value), temporary_root):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_SCOPE", "测试设备根目录必须位于系统临时目录")
    read_only = payload["read_only"]
    if read_only is not None and not isinstance(read_only, bool):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试设备的 read_only 字段无效")
    free_bytes = payload["free_bytes"]
    if free_bytes is not None and (
        not isinstance(free_bytes, int) or isinstance(free_bytes, bool) or free_bytes < 0
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试设备的 free_bytes 字段无效")
    device = DeviceInfo(
        transport=transport,
        root=root_value,
        serial=_optional_string(payload["serial"], "serial"),
        model=_optional_string(payload["model"], "model"),
        firmware=_optional_string(payload["firmware"], "firmware"),
        read_only=read_only,
        free_bytes=free_bytes,
        transport_id=transport_id,
        device_code=device_code,
    )
    requested_root = _path_argument(args, "device_root")
    if (
        requested_root is not None
        and (
            root_value is None
            or requested_root.resolve(strict=False) != Path(root_value).resolve(strict=False)
        )
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_MISMATCH", "设备根目录与测试探测结果不一致")
    return device


def _test_device_identity(device: DeviceInfo) -> str:
    fixture_value = os.environ.get("KJA_TEST_DEVICE_FIXTURE")
    if os.environ.get("KJA_TEST_MODE") != "1" or not fixture_value:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_DEVICE_REQUIRED",
            "本地来源需要显式的临时模拟设备 fixture",
        )
    fixture = Path(fixture_value).expanduser()
    if not _under_directory(fixture, Path(tempfile.gettempdir())):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_DEVICE_REQUIRED",
            "模拟设备 fixture 必须位于系统临时目录",
        )
    identity_value = device.serial or device.transport_id
    if not identity_value or (device.transport != "mtp" and not device.root):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_DEVICE_REQUIRED",
            "模拟设备缺少完整身份",
        )
    identity = {
        "fixture": str(fixture.resolve(strict=True)),
        "root": str(Path(device.root).resolve(strict=True)) if device.root else None,
        "identity": identity_value,
        "transport": device.transport,
        "model": device.model,
        "firmware": device.firmware,
    }
    return hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _validated_test_device(args: argparse.Namespace) -> tuple[DeviceInfo, str]:
    device = _fixture_device(args)
    if device is None:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_DEVICE_REQUIRED",
            "本地来源需要显式的临时模拟设备 fixture",
        )
    if device.root is None and device.transport != "mtp":
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_DEVICE_REQUIRED",
            "模拟设备缺少临时根目录",
        )
    if device.root is not None:
        assert_safe_root(device.root, device=device)
    return device, _test_device_identity(device)


def _probe_one(
    args: argparse.Namespace,
    *,
    system: str | None = None,
    runner: Callable[[list[str]], object] | None = None,
) -> DeviceInfo:
    fixture = _fixture_device(args)
    if fixture is not None:
        if fixture.root is None and fixture.transport != "mtp":
            raise StorageError("KJA_DEVICE_UNAVAILABLE", "设备没有文件系统根目录")
        if fixture.root is not None:
            assert_safe_root(fixture.root, device=fixture)
        return fixture

    devices = probe_devices(system or platform.system(), runner or _run_host_command)
    requested_root = _path_argument(args, "device_root")
    if requested_root is not None:
        assert_safe_root(requested_root)
        requested = requested_root.resolve(strict=True)
        devices = [
            device
            for device in devices
            if device.root is not None
            and Path(device.root).expanduser().resolve(strict=False) == requested
        ]
    if not devices:
        raise CLIError(EXIT_UNSUPPORTED, "KJA_DEVICE_NOT_FOUND", "没有探测到受支持的 Kindle")
    if len(devices) != 1:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_CONFLICT", "探测到多台 Kindle，请只连接目标设备")
    device = devices[0]
    if device.transport == "mtp":
        if device.root is not None or not device.transport_id:
            raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_IDENTITY", "MTP 设备身份或路径形态无效")
        return device
    if device.root is None:
        return device
    assert_safe_root(device.root, device=device)
    return device


def _require_stage(state: SessionState, *allowed: Stage) -> None:
    if state.stage not in allowed:
        expected = "、".join(stage.value for stage in allowed)
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_STATE_CONFLICT",
            f"当前阶段 {state.stage.value} 不能执行此命令，需要先到达 {expected}",
        )


def _write_context(state: SessionState, operation: str) -> str:
    route = state.route if isinstance(state.route, dict) else {}
    payload = {
        "device_fingerprint": state.device_fingerprint,
        "operation": operation,
        "route_name": route.get("name"),
        "source_hashes": route.get("source_hashes"),
        "koreader_package_choice": (
            state.evidence.get("koreader_package_choice")
            if operation == "stage-koreader"
            else None
        ),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _write_approval_key(state: SessionState, operation: str) -> str:
    return f"write_once:{operation}:{_write_context(state, operation)[:24]}"


def _ota_context(state: SessionState) -> str:
    route = state.route if isinstance(state.route, dict) else {}
    payload = {
        "device_fingerprint": state.device_fingerprint,
        "route_name": route.get("name"),
        "source_hashes": route.get("source_hashes"),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _require_ota_gate(state: SessionState) -> None:
    gate = state.evidence.get("ota_gate")
    if not isinstance(gate, dict) or gate.get("context") != _ota_context(state):
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_OTA_CHECK_REQUIRED",
            "继续前必须重新核对飞行模式、OTA 阻止状态和未知升级包",
        )
    if state.route is not None and gate.get("prevention_status") != "verified":
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_OTA_CHECK_REQUIRED",
            "当前路线缺少可审计的 OTA 阻止状态",
        )


def _consume_write_guards(
    args: argparse.Namespace,
    store: SessionStore,
    state: SessionState,
    operation: str,
    device: DeviceInfo,
) -> str | None:
    if not bool(getattr(args, "apply", False)):
        return None
    key = _write_approval_key(state, operation)
    if state.approvals.get(key) is not True:
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_WRITE_NOT_AUTHORIZED",
            "当前设备、路线和单一操作尚未取得一次性写入授权",
        )
    _require_ota_gate(state)
    unknown = _unknown_ota_packages(state, device, store)
    if unknown:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_OTA_UNKNOWN_PACKAGE",
            "写入前复查发现未知 .bin 或 .tmp.partial；已保留原文件并停止",
        )
    gate = state.evidence.get("ota_gate")
    audit = state.evidence.get("ota_audit_log")
    if not isinstance(audit, list):
        audit = []
    audit.append({
        "phase": "pre-write",
        "operation": operation,
        "context": _ota_context(state),
        "offline_confirmed": True,
        "prevention_status": gate.get("prevention_status") if isinstance(gate, dict) else None,
        "unknown_packages": [],
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    state.evidence["ota_audit_log"] = audit
    state.evidence["last_ota_confirmation"] = dict(gate) if isinstance(gate, dict) else {}
    state.evidence.pop("ota_gate", None)
    store.save(state)
    return key


def _consume_mtp_authorization(store: SessionStore, key: str) -> None:
    state = store.load()
    if state.approvals.get(key) is not True:
        raise CLIError(EXIT_NOT_AUTHORIZED, "KJA_WRITE_NOT_AUTHORIZED", "MTP 一次性写入授权已失效")
    state.approvals.pop(key, None)
    store.save(state)


def _require_fixture_session(args: argparse.Namespace, state: SessionState) -> None:
    if not bool(getattr(args, "apply", False)):
        return
    route = state.route if isinstance(state.route, dict) else {}
    review_value = state.evidence.get("source_review")
    review = review_value if isinstance(review_value, dict) else {}
    route_mode = route.get("source_mode")
    review_mode = review.get("source_mode")
    if "isolated_fixture" not in {route_mode, review_mode}:
        return
    route_identity = route.get("test_device_identity")
    review_identity = review.get("test_device_identity")
    if (
        route_mode != "isolated_fixture"
        or review_mode != "isolated_fixture"
        or not isinstance(route_identity, str)
        or route_identity != review_identity
    ):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_SESSION",
            "隔离测试会话缺少模拟设备身份",
        )
    try:
        _device, current = _validated_test_device(args)
    except CLIError as exc:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_SESSION",
            "隔离测试会话只能在显式测试模式和原模拟设备上执行",
        ) from exc
    if current != route_identity:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_SESSION",
            "当前模拟设备 fixture 与路线确认时不一致",
        )


def _bound_device(
    args: argparse.Namespace,
    store: SessionStore,
    *,
    probe: Callable[[], DeviceInfo] | None = None,
) -> DeviceInfo:
    state = store.load()
    try:
        _require_fixture_session(args, state)
        device = probe() if probe is not None else _probe_one(args)
    except CLIError as exc:
        if exc.code == "KJA_DEVICE_NOT_FOUND":
            _enter_wait_reconnect(store)
            raise CLIError(
                EXIT_RECOVERABLE,
                "KJA_DEVICE_UNAVAILABLE",
                "当前会话绑定的 Kindle 未连接，请重新连接后继续",
            ) from exc
        raise
    except StorageError as exc:
        if exc.code == "KJA_DEVICE_UNAVAILABLE":
            _enter_wait_reconnect(store)
        raise
    if device.root is None and device.transport != "mtp":
        if (
            state.device_public.get("transport") == "usbms"
            and state.device_public.get("root") is not None
        ):
            _enter_wait_reconnect(store)
            raise CLIError(
                EXIT_RECOVERABLE,
                "KJA_DEVICE_UNAVAILABLE",
                "已连接设备没有原 USB 存储根目录，请重新连接后继续",
            )
        raise CLIError(
            EXIT_UNSUPPORTED,
            "KJA_TRANSPORT_UNSUPPORTED",
            "当前传输方式暂不支持安全文件操作",
        )
    identity_value = device.serial or device.transport_id
    if not identity_value:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_IDENTITY", "无法取得完整设备序列号，拒绝继续")
    if device_fingerprint(state.session_id, identity_value) != state.device_fingerprint:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_MISMATCH", "当前 Kindle 不是本会话绑定的设备")
    public = state.device_public
    for field in ("transport", "model", "firmware"):
        expected = public.get(field)
        if expected is not None and expected != getattr(device, field):
            raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_MISMATCH", "当前 Kindle 与会话记录不一致")
    recorded_root = public.get("root")
    if device.transport == "mtp":
        if recorded_root is not None or device.root is not None or not device.transport_id:
            raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_IDENTITY", "MTP 会话身份或路径形态无效")
        return device
    if recorded_root is None or device.root is None:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_IDENTITY", "会话缺少可核对的设备根目录")
    try:
        same_root = (
            Path(str(recorded_root)).expanduser().resolve(strict=True)
            == Path(device.root).expanduser().resolve(strict=True)
        )
    except OSError as exc:
        _enter_wait_reconnect(store)
        raise StorageError("KJA_DEVICE_UNAVAILABLE", "Kindle 根目录不可用") from exc
    if not same_root:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_MISMATCH", "当前 Kindle 根目录与会话记录不一致")
    return device


def _enter_wait_reconnect(store: SessionStore) -> None:
    try:
        state = store.load()
    except (FileNotFoundError, ValueError):
        return
    if state.stage in _TERMINAL_STAGES or state.stage == Stage.WAIT_RECONNECT:
        return
    state.transition(Stage.WAIT_RECONNECT)
    store.save(state)


def _enter_recoverable(store: SessionStore) -> None:
    try:
        state = store.load()
    except (FileNotFoundError, ValueError):
        return
    if state.stage in _TERMINAL_STAGES or state.stage in {
        Stage.RECOVERABLE_ERROR,
        Stage.WAIT_RECONNECT,
    }:
        return
    state.transition(Stage.RECOVERABLE_ERROR)
    store.save(state)


def _device_probe(
    args: argparse.Namespace,
    *,
    probe: Callable[[], DeviceInfo] | None = None,
) -> Callable[[], DeviceInfo]:
    def reprobe() -> DeviceInfo:
        try:
            device = probe() if probe is not None else _probe_one(args)
        except CLIError as exc:
            if exc.code == "KJA_DEVICE_NOT_FOUND":
                raise StorageError(
                    "KJA_DEVICE_UNAVAILABLE",
                    "写入期间 Kindle 已断开",
                ) from exc
            raise
        if device.root is None and device.transport != "mtp":
            raise StorageError(
                "KJA_DEVICE_UNAVAILABLE",
                "写入期间 Kindle 的 USB 存储根目录消失",
            )
        return device

    return reprobe


def _route_policy(state: SessionState) -> MethodPolicy:
    if not isinstance(state.route, dict):
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_MISSING", "当前会话尚未选择越狱路线")
    policy_name = state.route.get("policy_name")
    if not isinstance(policy_name, str) or not policy_name:
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_MISSING", "当前路线缺少安全策略")
    return load_method_policy(policy_name)


def _source_confirmations(args: argparse.Namespace) -> dict[str, str]:
    confirmations: dict[str, str] = {}
    for item in getattr(args, "confirm_source", []):
        name, separator, digest = item.partition("=")
        if (
            not separator
            or name not in _SOURCE_KINDS
            or name in confirmations
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise CLIError(
                EXIT_CONFLICT,
                "KJA_SOURCE_CONFIRMATION",
                "来源确认必须为不重复的 KIND=SHA256，且只包含四类当前来源",
            )
        confirmations[name] = digest
    return confirmations


def _source_fixture_directory(args: argparse.Namespace) -> Path | None:
    directory = _path_argument(args, "source_fixture_dir")
    if directory is None:
        return None
    if os.environ.get("KJA_TEST_MODE") != "1":
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_SCOPE", "本地来源只允许用于隔离测试")
    if bool(getattr(args, "apply", False)):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_FIXTURE_APPLY",
            "本地来源 fixture 不能与 --apply 同时使用",
        )
    if not _under_directory(directory, Path(tempfile.gettempdir())):
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_SCOPE", "本地来源目录必须位于系统临时目录")
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_INPUT", "本地四来源目录不可用") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_INPUT", "本地四来源目录必须是普通目录")
    return resolved


def _fixture_snapshot(
    source_kind: str,
    url: str,
    path: Path,
    confirmation: str | None,
    *,
    content: object = None,
    official_route_url: str | None = None,
) -> OfficialSourceSnapshot:
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read {source_kind} fixture") from exc
    if not body:
        raise ValueError(f"empty {source_kind} fixture")
    digest = hashlib.sha256(body).hexdigest()
    authority = (
        "kindlemodding"
        if urlsplit(url).hostname == "kindlemodding.org"
        else "external-route"
    )
    snapshot = OfficialSourceSnapshot(
        source_kind=source_kind,
        authority=authority,
        request_url=url,
        final_url=url,
        downloaded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        sha256=digest,
        raw_content_base64=base64.b64encode(body).decode("ascii"),
        content=content,
        official_route_url=official_route_url,
        confirmed_sha256=confirmation,
        current=True,
    )
    snapshot.raw_bytes()
    return snapshot


def _source_cache_path(cache: Path, url: str) -> Path:
    return cache / f"{hashlib.sha256(url.encode('utf-8')).hexdigest()}.json"


def _method_source(candidate_url: str) -> tuple[str, str | None]:
    parsed = urlsplit(candidate_url)
    if parsed.scheme:
        return candidate_url, candidate_url
    return urljoin("https://kindlemodding.org/", candidate_url), None


def _load_json_fixture(path: Path, source_kind: str) -> tuple[object, bytes]:
    try:
        body = path.read_bytes()
        content = json.loads(body.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {source_kind} fixture") from exc
    return content, body


def _route_context(
    args: argparse.Namespace,
    store: SessionStore,
    device: DeviceInfo,
    policies: dict[str, MethodPolicy],
) -> tuple[RouteResult, dict[str, OfficialSourceSnapshot], dict[str, str]]:
    confirmations = _source_confirmations(args)
    fixture = _source_fixture_directory(args)
    cache = store.root / "downloads" / "official-sources"

    if fixture is None:
        models_snapshot = fetch_official_source(
            _MODELS_URL,
            cache,
            source_kind="models",
            confirmed_sha256=confirmations.get("models"),
        )
        jailbreaks_snapshot = fetch_official_source(
            _JAILBREAKS_URL,
            cache,
            source_kind="jailbreaks",
            confirmed_sha256=confirmations.get("jailbreaks"),
        )
        cache_paths = {
            "models": str(_source_cache_path(cache, _MODELS_URL)),
            "jailbreaks": str(_source_cache_path(cache, _JAILBREAKS_URL)),
        }
    else:
        models, _models_body = _load_json_fixture(fixture / "models.json", "models")
        jailbreaks, _jailbreaks_body = _load_json_fixture(
            fixture / "jailbreaks.json", "jailbreaks"
        )
        models_snapshot = _fixture_snapshot(
            "models",
            _MODELS_URL,
            fixture / "models.json",
            confirmations.get("models"),
            content=models,
        )
        jailbreaks_snapshot = _fixture_snapshot(
            "jailbreaks",
            _JAILBREAKS_URL,
            fixture / "jailbreaks.json",
            confirmations.get("jailbreaks"),
            content=jailbreaks,
        )
        cache_paths = {
            "models": str(fixture / "models.json"),
            "jailbreaks": str(fixture / "jailbreaks.json"),
        }

    models = models_snapshot.content
    jailbreaks = jailbreaks_snapshot.content
    registered = TriState.parse(args.registered)
    ads = TriState.parse(args.ads)
    provisional = select_routes(
        models,
        jailbreaks,
        device.serial or device.device_code or "",
        device.firmware or "",
        registered,
        ads,
        policies,
    )
    if provisional.blocked_reason is not None or provisional.preferred is None:
        return provisional, {
            "models": models_snapshot,
            "jailbreaks": jailbreaks_snapshot,
        }, cache_paths

    method_url, official_route_url = _method_source(provisional.preferred.url)
    if fixture is None:
        finder_snapshot = fetch_official_source(
            _FINDER_URL,
            cache,
            source_kind="finder",
            confirmed_sha256=confirmations.get("finder"),
        )
        method_snapshot = fetch_official_source(
            method_url,
            cache,
            source_kind="method_page",
            official_route_url=official_route_url,
            confirmed_sha256=confirmations.get("method_page"),
        )
        cache_paths.update({
            "finder": str(_source_cache_path(cache, _FINDER_URL)),
            "method_page": str(_source_cache_path(cache, method_url)),
        })
    else:
        finder_snapshot = _fixture_snapshot(
            "finder",
            _FINDER_URL,
            fixture / "jailbreakFinder.js",
            confirmations.get("finder"),
        )
        method_snapshot = _fixture_snapshot(
            "method_page",
            method_url,
            fixture / "method-page.html",
            confirmations.get("method_page"),
            official_route_url=official_route_url,
        )
        cache_paths.update({
            "finder": str(fixture / "jailbreakFinder.js"),
            "method_page": str(fixture / "method-page.html"),
        })
    sources = {
        "models": models_snapshot,
        "jailbreaks": jailbreaks_snapshot,
        "finder": finder_snapshot,
        "method_page": method_snapshot,
    }
    return select_routes(
        models,
        jailbreaks,
        device.serial or device.device_code or "",
        device.firmware or "",
        registered,
        ads,
        policies,
        sources=sources,
    ), sources, cache_paths


def _command_probe(args: argparse.Namespace, writer: EventWriter) -> int:
    device = _probe_one(args)
    identity_value = device.serial or device.transport_id
    if not identity_value:
        raise CLIError(EXIT_UNSUPPORTED, "KJA_DEVICE_IDENTITY", "无法取得稳定设备身份")
    store = _session_store(args)
    if store.session_path.exists():
        state = store.load()
        if device_fingerprint(state.session_id, identity_value) != state.device_fingerprint:
            raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_MISMATCH", "当前 Kindle 不属于已有会话")
        if state.stage == Stage.DISCOVER:
            state.transition(Stage.RISK_ACK)
            store.save(state)
    else:
        state = store.create(device)
        state.transition(Stage.RISK_ACK)
        store.save(state)
    writer.emit(
        "device_detected",
        stage=state.stage.value,
        device=device.public_dict(),
        device_fingerprint=state.device_fingerprint,
        message="已只读识别 Kindle，下一步需要确认风险",
    )
    writer.emit(
        "risk_ack_required",
        stage=state.stage.value,
        risks=list(_RISK_NOTICE),
        message="继续前请完整阅读并明确确认四项风险说明",
    )
    return 0


def _persist_route_block(
    state: SessionState,
    store: SessionStore,
    stage: Stage,
) -> None:
    state.route = None
    state.transition(stage)
    store.save(state)


def _command_route(args: argparse.Namespace, writer: EventWriter) -> int:
    test_device_identity: str | None = None
    if _path_argument(args, "source_fixture_dir") is not None:
        _test_device, test_device_identity = _validated_test_device(args)
    source_mode = "isolated_fixture" if test_device_identity is not None else "live"
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.RISK_ACK)
    device = _bound_device(args, store)
    _require_ota_gate(state)
    if not (device.serial or device.device_code) or not device.firmware:
        raise CLIError(EXIT_UNSUPPORTED, "KJA_ROUTE_UNSUPPORTED", "缺少路由所需的设备代码或固件版本")
    policies = load_policies(_POLICIES_PATH)
    try:
        result, sources, cache_paths = _route_context(args, store, device, policies)
    except ValueError as exc:
        _persist_route_block(state, store, Stage.BLOCKED_CONFLICT)
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_ROUTE_CONFLICT",
            "官方来源内容或结构冲突，已停止自动选择",
        ) from exc
    if result.blocked_reason == Stage.BLOCKED_UNSUPPORTED.value:
        _persist_route_block(state, store, Stage.BLOCKED_UNSUPPORTED)
        raise CLIError(EXIT_UNSUPPORTED, "KJA_ROUTE_UNSUPPORTED", "当前设备和固件没有官方支持路线")
    if result.blocked_reason is not None:
        _persist_route_block(state, store, Stage.BLOCKED_CONFLICT)
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_CONFLICT", "官方路线数据互相冲突，已停止自动选择")
    if result.questions:
        writer.emit(
            "route_questions",
            stage=state.stage.value,
            questions=result.questions,
            message="需要补充会影响路线选择的设备状态",
        )
        return EXIT_RECOVERABLE
    if result.preferred is None:
        _persist_route_block(state, store, Stage.BLOCKED_CONFLICT)
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_CONFLICT", "官方路线没有唯一首选结果")
    if (
        set(sources) != set(_SOURCE_KINDS)
        or result.preferred.policy_name == "default"
        or not all(source.current and source.confirmed for source in sources.values())
    ):
        review_evidence = {
            "candidate": {
                "name": result.preferred.name,
                "url": result.preferred.url,
            },
            "source_hashes": result.source_hashes,
            "cache_paths": cache_paths,
            "source_mode": source_mode,
            "test_device_identity": test_device_identity,
        }
        state.route = None
        state.evidence["source_review"] = review_evidence
        store.save(state)
        writer.emit(
            "source_review_required",
            stage=state.stage.value,
            candidate=review_evidence["candidate"],
            source_hashes=result.source_hashes,
            cache_paths=cache_paths,
            message="请检查四个当前官方来源，并用四个 SHA-256 重新确认",
        )
        return EXIT_RECOVERABLE
    state.route = {
        "name": result.preferred.name,
        "url": result.preferred.url,
        "policy_name": result.preferred.policy_name,
        "source_hashes": result.source_hashes,
        "source_mode": source_mode,
        "test_device_identity": test_device_identity,
    }
    state.evidence["source_review"] = {
        "candidate": {
            "name": result.preferred.name,
            "url": result.preferred.url,
        },
        "source_hashes": result.source_hashes,
        "cache_paths": cache_paths,
        "confirmed": True,
        "source_mode": source_mode,
        "test_device_identity": test_device_identity,
    }
    policy = load_method_policy(result.preferred.policy_name)
    method_body = sources["method_page"].raw_bytes()
    requested_markers = tuple(dict.fromkeys(getattr(args, "confirm_method_marker_rule", [])))
    if any(
        marker not in policy.jailbreak_markers
        or marker.encode("utf-8") not in method_body
        for marker in requested_markers
    ):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_EVIDENCE_RULE_CONFLICT",
            "确认的成功标记不在本地安全允许列表或当前方法页原文中",
        )
    requested_log = bool(getattr(args, "confirm_method_log_rule", False))
    if requested_log and (
        not policy.jailbreak_user_log or b";log" not in method_body.lower()
    ):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_EVIDENCE_RULE_CONFLICT",
            "确认的日志规则不在本地安全允许列表或当前方法页原文中",
        )
    if not requested_markers and not requested_log:
        state.route = None
        state.evidence["source_review"]["evidence_rules_required"] = True
        store.save(state)
        writer.emit(
            "evidence_rule_review_required",
            stage=state.stage.value,
            route=result.preferred.name,
            message="当前方法没有已确认的结构化成功证据规则；保持只读审查",
        )
        return EXIT_RECOVERABLE
    state.evidence["method_evidence_rules"] = {
        "route_name": result.preferred.name,
        "method_page_sha256": result.source_hashes["method_page"],
        "markers": list(requested_markers),
        "user_log": requested_log,
    }
    if bool(getattr(args, "acknowledge_risk", False)):
        state.approvals["risk_acknowledged"] = True
    if state.approvals.get("risk_acknowledged") is not True:
        store.save(state)
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_RISK_NOT_ACKNOWLEDGED",
            "路线已确认，但继续前必须明确接受完整风险说明",
        )
    state.transition(Stage.ROUTE)
    state.transition(Stage.BACKUP)
    store.save(state)
    writer.emit(
        "route_selected",
        stage=state.stage.value,
        route={
            "name": result.preferred.name,
            "url": result.preferred.url,
            "policy_name": result.preferred.policy_name,
        },
        message="已选择当前官方路线，下一步先备份 Kindle 可见内容",
    )
    return 0


def _unknown_ota_packages(
    state: SessionState,
    device: DeviceInfo,
    store: SessionStore,
) -> list[str]:
    if device.transport == "mtp":
        records = state.evidence.get("mtp_created_records")
        return mtp_storage.unknown_ota_packages(
            device, records if isinstance(records, dict) else {}
        )
    if not device.root:
        raise CLIError(
            EXIT_UNSUPPORTED,
            "KJA_OTA_AUDIT_UNSUPPORTED",
            "当前传输方式无法安全审计 Kindle 根目录的 OTA 文件",
        )
    known_records: dict[str, object] = {}
    try:
        journal_entries = CreatedFilesJournal(store, Path(device.root)).entries()
    except (FileNotFoundError, StorageError, OSError, ValueError):
        journal_entries = []
    if journal_entries:
        known_records = {
            entry.get("path"): entry
            for entry in journal_entries
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
    try:
        entries = list(Path(device.root).iterdir())
    except OSError as exc:
        raise CLIError(
            EXIT_RECOVERABLE,
            "KJA_DEVICE_UNAVAILABLE",
            "无法读取 Kindle 根目录以检查 OTA 升级包",
        ) from exc
    unknown = []
    for entry in entries:
        relative = entry.name
        lowered = relative.lower()
        if not (lowered.endswith(".bin") or lowered.endswith(".tmp.partial")):
            continue
        record = known_records.get(relative)
        if not isinstance(record, dict) or record.get("state") != "created" or record.get("type") != "file":
            unknown.append(relative)
            continue
        try:
            size, digest = _archive_sha256(entry)
        except OSError:
            unknown.append(relative)
            continue
        if size != record.get("size") or digest != record.get("sha256"):
            unknown.append(relative)
    return sorted(unknown)


def _command_ota_check(args: argparse.Namespace, writer: EventWriter) -> int:
    if not bool(getattr(args, "offline_confirmed_by_user", False)):
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_OFFLINE_CONFIRMATION_REQUIRED",
            "必须由用户明确确认 Kindle 已进入飞行模式或离线",
        )
    store = _session_store(args)
    state = store.load()
    _require_stage(
        state,
        Stage.RISK_ACK,
        Stage.BACKUP,
        Stage.PREPARE,
        Stage.WAIT_USER_EXPLOIT,
        Stage.VERIFY_JAILBREAK,
        Stage.INSTALL_KOREADER,
        Stage.VERIFY_KOREADER,
        Stage.CLEANUP,
    )
    device = _bound_device(args, store)
    prevention_status = getattr(args, "prevention_status", None)
    if state.route is not None and prevention_status != "verified":
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_OTA_PREVENTION_REQUIRED",
            "已选择路线后必须核对当前方法的 OTA 阻止状态",
        )
    unknown = _unknown_ota_packages(state, device, store)
    if unknown:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_OTA_UNKNOWN_PACKAGE",
            "Kindle 根目录存在未知 .bin 或 .tmp.partial 升级文件；已保留原文件并停止",
        )
    gate = {
        "context": _ota_context(state),
        "offline_confirmed": True,
        "prevention_status": prevention_status or "pending-route",
        "unknown_packages": [],
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    state.evidence["ota_gate"] = gate
    audit = state.evidence.get("ota_audit_log")
    if not isinstance(audit, list):
        audit = []
    audit.append({"phase": "checkpoint", **gate})
    state.evidence["ota_audit_log"] = audit
    store.save(state)
    writer.emit(
        "ota_check_complete",
        stage=state.stage.value,
        prevention_status=prevention_status or "pending-route",
        message="已核对 Kindle 离线状态、OTA 阻止状态和根目录升级包",
    )
    return 0


_WRITE_OPERATION_STAGES = {
    "fill": (Stage.PREPARE,),
    "stage-jailbreak": (Stage.PREPARE,),
    "stage-koreader": (Stage.INSTALL_KOREADER,),
    "cleanup": (Stage.CLEANUP,),
}


def _command_authorize_write(args: argparse.Namespace, writer: EventWriter) -> int:
    if not bool(getattr(args, "confirmed_by_user", False)):
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_USER_CONFIRMATION_REQUIRED",
            "必须由用户明确同意这一项普通设备写入",
        )
    store = _session_store(args)
    state = store.load()
    _require_stage(state, *_WRITE_OPERATION_STAGES[args.operation])
    _bound_device(args, store)
    if state.evidence.get("backup_verified") is not True:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_BACKUP_REQUIRED",
            "取得普通写入授权前必须完成备份清单、哈希和逐文件差异核验",
        )
    route = state.route if isinstance(state.route, dict) else None
    if route is None or not isinstance(route.get("source_hashes"), dict):
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_MISSING", "当前会话没有已确认路线")
    key = _write_approval_key(state, args.operation)
    state.approvals = {
        name: value
        for name, value in state.approvals.items()
        if not name.startswith("write_once:")
    }
    state.approvals[key] = True
    store.save(state)
    writer.emit(
        "write_authorized",
        stage=state.stage.value,
        operation=args.operation,
        message="已记录仅供下一次对应操作使用的一次性写入授权",
    )
    return 0


def _dry_run(args: argparse.Namespace) -> bool:
    return not bool(getattr(args, "apply", False))


def _test_storage_limits(
    device: DeviceInfo,
) -> tuple[int, Callable[[object], int] | None]:
    raw_chunk = os.environ.get("KJA_TEST_FILL_CHUNK_BYTES")
    if raw_chunk is None:
        return DEFAULT_FILL_CHUNK_BYTES, None
    validation_args = argparse.Namespace(device_root=device.root)
    try:
        fixture_device, _identity = _validated_test_device(validation_args)
    except (CLIError, StorageError, OSError, ValueError) as exc:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_TEST_HOOK_DENIED",
            "测试容量 hook 需要已验证且与当前会话一致的临时模拟设备",
        ) from exc
    if not _same_device_for_test_hook(device, fixture_device):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_TEST_HOOK_DENIED",
            "测试容量 hook 的模拟设备与当前绑定设备不一致",
        )
    if device.free_bytes is None:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_TEST_HOOK_DENIED",
            "测试容量 hook 缺少模拟设备容量",
        )
    try:
        chunk_bytes = int(raw_chunk)
    except ValueError as exc:
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试占位分块大小无效") from exc
    if chunk_bytes <= 0:
        raise CLIError(EXIT_CONFLICT, "KJA_FIXTURE_INVALID", "测试占位分块大小无效")
    remaining = device.free_bytes

    def free_space(_root: object) -> int:
        nonlocal remaining
        current = remaining
        remaining = max(DEFAULT_RESERVE_BYTES, remaining - chunk_bytes)
        return current

    return chunk_bytes, free_space


def _same_device_for_test_hook(expected: DeviceInfo, observed: DeviceInfo) -> bool:
    expected_identity = expected.serial or expected.transport_id
    observed_identity = observed.serial or observed.transport_id
    if (
        not expected_identity
        or expected_identity != observed_identity
        or expected.transport != observed.transport
        or expected.model != observed.model
        or expected.firmware != observed.firmware
        or expected.read_only != observed.read_only
    ):
        return False
    if expected.transport == "mtp":
        return (
            expected.root is None
            and observed.root is None
            and expected.transport_id is not None
            and expected.transport_id == observed.transport_id
            and expected.device_code == observed.device_code
        )
    if expected.root is None or observed.root is None:
        return False
    try:
        return (
            Path(expected.root).expanduser().resolve(strict=True)
            == Path(observed.root).expanduser().resolve(strict=True)
        )
    except OSError:
        return False


def _command_backup(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.BACKUP)
    device = _bound_device(args, store)
    if _dry_run(args):
        writer.progress(ProgressEvent(
            event="progress",
            stage=Stage.BACKUP,
            message="预演：将复制并校验 Kindle 可见内容",
            done=0,
            total=None,
            unit="files",
            user_action=None,
        ))
        return 0
    backup_parent = _path_argument(args, "backup_dir", store.root / "backup")
    assert backup_parent is not None
    if device.transport == "mtp":
        destination = mtp_storage.backup_visible_storage(
            device,
            backup_parent,
            store,
            timestamp=getattr(args, "timestamp", None),
            progress=writer.progress,
        )
    else:
        destination = backup_visible_storage(
            device,
            backup_parent,
            session_store=store,
            timestamp=getattr(args, "timestamp", None),
            progress=writer.progress,
        )
    state = store.load()
    _require_stage(state, Stage.BACKUP)
    state.evidence["backup_path"] = str(destination)
    state.evidence["backup_verified"] = True
    baseline = []
    markers = tuple(dict.fromkeys((
        "documents/JAILBROKEN.txt",
        *_method_evidence_markers(state),
    )))
    if device.transport == "mtp":
        remote_paths = {str(entry["path"]) for entry in mtp_storage.list_paths(device)}
        baseline.extend(marker for marker in markers if marker in remote_paths)
    else:
        for marker in markers:
            if device.root and Path(device.root, marker).is_file():
                baseline.append(marker)
    state.evidence["jailbreak_evidence_baseline"] = baseline
    state.transition(Stage.PREPARE)
    store.save(state)
    writer.emit(
        "operation_complete",
        stage=state.stage.value,
        operation="backup",
        message="Kindle 可见内容已备份并校验",
    )
    return 0


def _command_fill(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.PREPARE)
    device = _bound_device(args, store)
    policy = _route_policy(state)
    if policy.generic_filler != "required-by-guide":
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_POLICY_DENIED",
            "当前越狱方法禁止普通磁盘占位",
        )
    authorization_key = _consume_write_guards(args, store, state, "fill", device)
    if _dry_run(args):
        writer.progress(ProgressEvent(
            event="progress",
            stage=Stage.PREPARE,
            message="预演：将按当前官方方法创建占位文件",
            done=0,
            total=None,
            unit="bytes",
            user_action=None,
        ))
        return 0
    chunk_bytes, free_space = _test_storage_limits(device)
    if device.transport == "mtp":
        assert authorization_key is not None
        _consume_mtp_authorization(store, authorization_key)
        created = mtp_storage.fill_storage(
            device, store, chunk_bytes=chunk_bytes, progress=writer.progress
        )
    else:
        created = fill_storage(
            device,
            store,
            policy,
            device_probe=_device_probe(args),
            chunk_bytes=chunk_bytes,
            free_space=free_space,
            progress=writer.progress,
            authorization_key=authorization_key,
        )
    state = store.load()
    state.evidence["fill_complete"] = True
    state.evidence["fill_files"] = len(created)
    store.save(state)
    writer.emit(
        "operation_complete",
        stage=state.stage.value,
        operation="fill",
        message="当前方法要求的占位步骤已完成",
    )
    return 0


def _command_stage(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    purpose = args.purpose
    expected_stage = Stage.PREPARE if purpose == "jailbreak" else Stage.INSTALL_KOREADER
    _require_stage(state, expected_stage)
    device = _bound_device(args, store)
    policy = _route_policy(state)
    if purpose == "jailbreak" and policy.automation not in {
        "guided-assets",
        "guided-assets-or-browser",
        "guided-assets-and-browser",
        "guided-assets-and-store",
        "guided-update-package",
    }:
        raise CLIError(EXIT_CONFLICT, "KJA_POLICY_DENIED", "当前越狱方法禁止直接暂存归档")
    if (
        purpose == "jailbreak"
        and policy.generic_filler == "required-by-guide"
        and state.evidence.get("fill_complete") is not True
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_FILL_REQUIRED", "当前官方方法要求先完成占位步骤")
    _require_payload_record(state, args.archive, purpose)
    authorization_key = _consume_write_guards(
        args, store, state, f"stage-{purpose}", device
    )
    if _dry_run(args):
        writer.progress(ProgressEvent(
            event="progress",
            stage=state.stage,
            message="预演：将检查并复制官方载荷",
            done=0,
            total=None,
            unit="files",
            user_action=None,
        ))
        return 0
    _chunk_bytes, free_space = _test_storage_limits(device)
    if device.transport == "mtp":
        assert authorization_key is not None
        _consume_mtp_authorization(store, authorization_key)
        created = mtp_storage.stage_archive(
            args.archive,
            device,
            store,
            policy if purpose == "jailbreak" else _KOREADER_STAGING_POLICY,
            required_files=tuple(args.required_file),
            purpose=purpose,
            progress=writer.progress,
        )
    else:
        created = stage_archive(
            args.archive,
            device,
            store,
            policy if purpose == "jailbreak" else _KOREADER_STAGING_POLICY,
            device_probe=_device_probe(args),
            required_files=tuple(args.required_file),
            purpose=purpose,
            free_space=free_space,
            progress=writer.progress,
            authorization_key=authorization_key,
        )
    state = store.load()
    evidence_key = "jailbreak_payload_files" if purpose == "jailbreak" else "koreader_payload_files"
    state.evidence[evidence_key] = len(created)
    state.transition(
        Stage.WAIT_USER_EXPLOIT if purpose == "jailbreak" else Stage.VERIFY_KOREADER
    )
    store.save(state)
    writer.emit(
        "operation_complete",
        stage=state.stage.value,
        operation=f"stage_{purpose}",
        message=(
            "越狱载荷已复制并校验，请按当前官方说明完成设备端操作"
            if purpose == "jailbreak"
            else "KOReader 载荷已复制并校验"
        ),
    )
    return 0


def _archive_sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _command_record_payload(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    route = state.route if isinstance(state.route, dict) else None
    if (
        os.environ.get("KJA_TEST_MODE") != "1"
        or route is None
        or route.get("source_mode") != "isolated_fixture"
    ):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_PAYLOAD_RECORD_TEST_ONLY",
            "生产会话必须使用 fetch-payload 下载并记录载荷",
        )
    expected_stage = Stage.PREPARE if args.purpose == "jailbreak" else Stage.INSTALL_KOREADER
    _require_stage(state, expected_stage)
    _bound_device(args, store)
    if route is None or not isinstance(route.get("source_hashes"), dict):
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_MISSING", "当前会话没有已确认路线")
    parsed = urlsplit(args.final_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_URL", "载荷最终地址必须是无凭据的 HTTPS URL")
    if not _method_page_references_payload(state, args.final_url):
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_SOURCE", "载荷最终地址未出现在已确认的方法页中")
    method_body = _method_page_bytes(state)
    method_digest = hashlib.sha256(method_body).hexdigest() if method_body is not None else None
    route_method_digest = route["source_hashes"].get("method_page")
    if method_digest is None or method_digest != route_method_digest:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_ROUTE_MISMATCH", "当前方法页与已确认路线摘要不一致")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) or not args.release_version:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_RECORD_INVALID", "载荷版本或 SHA-256 无效")
    try:
        size, actual_sha256 = _archive_sha256(Path(args.archive))
    except OSError as exc:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_UNAVAILABLE", "已核验载荷文件不可用") from exc
    if actual_sha256 != args.expected_sha256:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_HASH", "载荷 SHA-256 与已确认值不一致")
    records = state.evidence.get("payload_records")
    if not isinstance(records, dict):
        records = {}
    records[args.purpose] = {
        "route_name": route.get("name"), "source_hashes": route["source_hashes"],
        "method_page_sha256": method_digest,
        "final_url": args.final_url, "release_version": args.release_version,
        "size": size, "sha256": actual_sha256, "test_fixture": True,
    }
    state.evidence["payload_records"] = records
    store.save(state)
    writer.emit("payload_recorded", stage=state.stage.value, purpose=args.purpose, sha256=actual_sha256, size=size, message="已记录并核验当前路线的官方载荷")
    return 0


_PAYLOAD_REDIRECT_HOSTS = frozenset({
    "kindlemodding.org",
    "github.com",
    "release-assets.githubusercontent.com",
})


def _payload_url_allowed(
    state: SessionState,
    url: str,
    purpose: str,
    release_version: str,
) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    version_pattern = (
        r"v[0-9]{4}\.[0-9]{2}(?:\.[0-9]+)?"
        if purpose == "koreader"
        else r"v?[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)+"
    )
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or re.fullmatch(version_pattern, release_version) is None
    ):
        return False
    tag_match = re.search(r"/releases/download/([^/]+)/", parsed.path)
    if tag_match is not None:
        if unquote(tag_match.group(1)) != release_version:
            return False
    else:
        filename = unquote(PurePosixPath(parsed.path).name)
        if re.search(
            rf"(?<![A-Za-z0-9]){re.escape(release_version)}(?![A-Za-z0-9])",
            filename,
        ) is None:
            return False
    body = _confirmed_method_page_bytes(state)
    if body is None:
        return False
    if purpose == "jailbreak":
        return url in _method_page_links(state, body)
    official_repo_prefix = "/koreader/koreader/releases/download/"
    if parsed.hostname != "github.com" or not parsed.path.startswith(official_repo_prefix):
        return False
    filename = PurePosixPath(parsed.path).name
    choice = state.evidence.get("koreader_package_choice")
    if not isinstance(choice, dict):
        return False
    if (
        choice.get("device_fingerprint") != state.device_fingerprint
        or choice.get("model") != state.device_public.get("model")
        or choice.get("firmware") != state.device_public.get("firmware")
    ):
        return False
    asset_family = choice.get("asset_family")
    if asset_family not in {"kindle", "kindlehf", "kindlepw2", "kindle-legacy"}:
        return False
    if re.fullmatch(
        rf"koreader-{re.escape(str(asset_family))}-{re.escape(release_version)}\.zip",
        filename,
    ) is None:
        return False
    return True


def _download_payload(url: str, destination: Path) -> tuple[str, int, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "kindle-jailbreak-assistant/1"},
        method="GET",
    )
    try:
        response = urllib.request.urlopen(request, timeout=30)
        final_url = response.geturl()
        parsed = urlsplit(final_url)
        initial = urlsplit(url)
        same_exact_resource = (
            parsed.hostname == initial.hostname and parsed.path == initial.path
        )
        github_release_asset = (
            initial.hostname == "github.com"
            and initial.path.startswith("/koreader/koreader/releases/download/")
            and parsed.hostname == "release-assets.githubusercontent.com"
        ) or (
            initial.hostname == "github.com"
            and "/releases/download/" in initial.path
            and parsed.hostname == "release-assets.githubusercontent.com"
        )
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _PAYLOAD_REDIRECT_HOSTS
            or parsed.username
            or parsed.password
            or not (same_exact_resource or github_release_asset)
        ):
            raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_REDIRECT", "载荷重定向到了未批准的主机")
        digest = hashlib.sha256()
        size = 0
        with response, destination.open("xb") as output:
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    except CLIError:
        raise
    except (OSError, ValueError) as exc:
        raise CLIError(EXIT_RECOVERABLE, "KJA_PAYLOAD_DOWNLOAD", "上游载荷下载未完成") from exc
    if size == 0:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_DOWNLOAD", "上游载荷为空")
    return final_url, size, digest.hexdigest()


def _command_fetch_payload(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    expected_stage = Stage.PREPARE if args.purpose == "jailbreak" else Stage.INSTALL_KOREADER
    _require_stage(state, expected_stage)
    device = _bound_device(args, store)
    route = state.route if isinstance(state.route, dict) else None
    if route is None or not isinstance(route.get("source_hashes"), dict):
        raise CLIError(EXIT_CONFLICT, "KJA_ROUTE_MISSING", "当前会话没有已确认路线")
    _require_ota_gate(state)
    if _unknown_ota_packages(state, device, store):
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_OTA_UNKNOWN_PACKAGE",
            "下载前复查发现未知 .bin 或 .tmp.partial；已保留原文件并停止",
        )
    audit = state.evidence.get("ota_audit_log")
    if not isinstance(audit, list):
        audit = []
    audit.append({
        "phase": "pre-download",
        "context": _ota_context(state),
        "offline_confirmed": True,
        "prevention_status": "verified",
        "unknown_packages": [],
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    state.evidence["ota_audit_log"] = audit
    store.save(state)
    if not _payload_url_allowed(state, args.url, args.purpose, args.release_version):
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_SOURCE", "载荷 URL 或版本未由当前上游页面明确授权")
    method_body = _confirmed_method_page_bytes(state)
    assert method_body is not None
    method_digest = hashlib.sha256(method_body).hexdigest()
    download_dir = store.root / "downloads" / "payloads"
    download_dir.mkdir(parents=True, exist_ok=True)
    temporary = download_dir / f".{args.purpose}.{os.getpid()}.partial"
    if temporary.exists():
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_DOWNLOAD", "载荷临时路径已存在")
    try:
        final_url, size, digest = _download_payload(args.url, temporary)
        archive = download_dir / f"{args.purpose}-{digest}.archive"
        if archive.exists():
            if _archive_sha256(archive) != (size, digest):
                raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_HASH", "既有下载与当前载荷摘要冲突")
            temporary.unlink()
        else:
            temporary.rename(archive)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    records = state.evidence.get("payload_records")
    if not isinstance(records, dict):
        records = {}
    records[args.purpose] = {
        "route_name": route.get("name"),
        "source_hashes": route["source_hashes"],
        "method_page_sha256": method_digest,
        "request_url": args.url,
        "final_url": final_url,
        "release_version": args.release_version,
        "size": size,
        "sha256": digest,
        "downloaded_by_cli": True,
        "archive_path": str(archive),
    }
    if args.purpose == "koreader":
        choice = state.evidence.get("koreader_package_choice")
        records[args.purpose]["asset_family"] = (
            choice.get("asset_family") if isinstance(choice, dict) else None
        )
        records[args.purpose]["koreader_choice"] = (
            dict(choice) if isinstance(choice, dict) else None
        )
    state.evidence["payload_records"] = records
    store.save(state)
    writer.emit(
        "payload_downloaded",
        stage=state.stage.value,
        purpose=args.purpose,
        archive=str(archive),
        size=size,
        sha256=digest,
        message="已从当前上游授权链接下载并记录载荷",
    )
    return 0


_KOREADER_INSTALLATION_SOURCE = (
    "https://github.com/koreader/koreader/wiki/Installation-on-Kindle-devices"
)


def _command_confirm_koreader_package(args: argparse.Namespace, writer: EventWriter) -> int:
    if not bool(getattr(args, "confirmed_by_user", False)):
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_USER_CONFIRMATION_REQUIRED",
            "必须由用户确认已按当前 KOReader 官方安装页选择包族",
        )
    if re.fullmatch(r"[0-9a-f]{64}", args.source_sha256) is None:
        raise CLIError(EXIT_CONFLICT, "KJA_SOURCE_CONFIRMATION", "KOReader 安装页 SHA-256 无效")
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.INSTALL_KOREADER)
    device = _bound_device(args, store)
    if not device.model or not device.firmware:
        raise CLIError(EXIT_CONFLICT, "KJA_DEVICE_IDENTITY", "缺少 KOReader 包选择所需的型号或固件")
    _require_ota_gate(state)
    if _unknown_ota_packages(state, device, store):
        raise CLIError(EXIT_CONFLICT, "KJA_OTA_UNKNOWN_PACKAGE", "读取 KOReader 官方页前发现未知升级包")
    request = urllib.request.Request(
        _KOREADER_INSTALLATION_SOURCE,
        headers={"User-Agent": "kindle-jailbreak-assistant/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final_url = response.geturl().rstrip("/")
            if final_url != _KOREADER_INSTALLATION_SOURCE:
                raise CLIError(EXIT_CONFLICT, "KJA_SOURCE_REDIRECT", "KOReader 官方安装页发生未知重定向")
            body = response.read(5 * 1024 * 1024 + 1)
    except CLIError:
        raise
    except (OSError, ValueError) as exc:
        raise CLIError(EXIT_RECOVERABLE, "KJA_SOURCE_FETCH", "无法读取 KOReader 官方安装页") from exc
    if len(body) > 5 * 1024 * 1024 or hashlib.sha256(body).hexdigest() != args.source_sha256:
        raise CLIError(EXIT_CONFLICT, "KJA_SOURCE_CONFIRMATION", "KOReader 安装页内容与确认摘要不一致")
    records = state.evidence.get("payload_records")
    if isinstance(records, dict) and "koreader" in records:
        records = dict(records)
        records.pop("koreader", None)
        state.evidence["payload_records"] = records
    state.approvals = {
        name: value
        for name, value in state.approvals.items()
        if not name.startswith("write_once:stage-koreader:")
    }
    state.evidence["koreader_package_choice"] = {
        "device_fingerprint": state.device_fingerprint,
        "model": device.model,
        "firmware": device.firmware,
        "asset_family": args.asset_family,
        "source_url": _KOREADER_INSTALLATION_SOURCE,
        "source_sha256": args.source_sha256,
        "confirmed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    store.save(state)
    writer.emit(
        "koreader_package_confirmed",
        stage=state.stage.value,
        asset_family=args.asset_family,
        source_url=_KOREADER_INSTALLATION_SOURCE,
        message="已把 KOReader 官方安装页确认的包族绑定到当前设备与固件",
    )
    return 0


def _method_page_references_payload(state: SessionState, final_url: str) -> bool:
    body = _confirmed_method_page_bytes(state)
    if body is None:
        return False
    return final_url in _method_page_links(state, body)


def _method_page_bytes(state: SessionState) -> bytes | None:
    review = state.evidence.get("source_review")
    if not isinstance(review, dict):
        return None
    paths = review.get("cache_paths")
    method_path = paths.get("method_page") if isinstance(paths, dict) else None
    if not isinstance(method_path, str):
        return None
    try:
        if review.get("source_mode") == "isolated_fixture":
            body = Path(method_path).read_bytes()
        else:
            body = load_cached_source(method_path).raw_bytes()
    except (OSError, ValueError):
        return None
    return body


def _confirmed_method_page_bytes(state: SessionState) -> bytes | None:
    body = _method_page_bytes(state)
    route = state.route if isinstance(state.route, dict) else None
    hashes = route.get("source_hashes") if route is not None else None
    expected = hashes.get("method_page") if isinstance(hashes, dict) else None
    if body is None or not isinstance(expected, str):
        return None
    return body if hashlib.sha256(body).hexdigest() == expected else None


def _method_page_links(state: SessionState, body: bytes) -> set[str]:
    from html.parser import HTMLParser

    class LinkParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.links: set[str] = set()

        def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.links.add(value)

    parser = LinkParser()
    try:
        parser.feed(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return set()
    route = state.route if isinstance(state.route, dict) else {}
    base = route.get("url")
    base_url = urljoin("https://kindlemodding.org/", base) if isinstance(base, str) else ""
    return {urljoin(base_url, link) for link in parser.links}


def _method_evidence_rules(state: SessionState) -> tuple[tuple[str, ...], bool]:
    body = _confirmed_method_page_bytes(state)
    if body is None:
        return (), False
    rules = state.evidence.get("method_evidence_rules")
    route = state.route if isinstance(state.route, dict) else None
    if not isinstance(rules, dict) or route is None:
        return (), False
    if (
        rules.get("route_name") != route.get("name")
        or rules.get("method_page_sha256") != hashlib.sha256(body).hexdigest()
    ):
        return (), False
    policy = _route_policy(state)
    raw_markers = rules.get("markers")
    if not isinstance(raw_markers, list) or not all(isinstance(item, str) for item in raw_markers):
        return (), False
    markers = tuple(
        marker for marker in raw_markers
        if marker in policy.jailbreak_markers and marker.encode("utf-8") in body
    )
    log_allowed = (
        rules.get("user_log") is True
        and policy.jailbreak_user_log
        and b";log" in body.lower()
    )
    return markers, log_allowed


def _method_evidence_markers(state: SessionState) -> tuple[str, ...]:
    return _method_evidence_rules(state)[0]


def _require_payload_record(state: SessionState, archive_value: str, purpose: str) -> None:
    records = state.evidence.get("payload_records")
    record = records.get(purpose) if isinstance(records, dict) else None
    route = state.route if isinstance(state.route, dict) else None
    if not isinstance(record, dict) or route is None:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_RECORD_REQUIRED", "暂存前必须记录当前路线已核验的官方载荷")
    if record.get("downloaded_by_cli") is not True and record.get("test_fixture") is not True:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_RECORD_REQUIRED", "载荷记录缺少可验证的下载来源")
    if purpose == "koreader" and record.get("downloaded_by_cli") is True:
        choice = state.evidence.get("koreader_package_choice")
        if not isinstance(choice, dict) or record.get("koreader_choice") != choice:
            raise CLIError(
                EXIT_CONFLICT,
                "KJA_PAYLOAD_ROUTE_MISMATCH",
                "KOReader 载荷记录不属于当前设备、固件、来源摘要和包族选择",
            )
    if record.get("route_name") != route.get("name") or record.get("source_hashes") != route.get("source_hashes"):
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_ROUTE_MISMATCH", "载荷记录不属于当前已确认路线")
    method_body = _method_page_bytes(state)
    method_digest = hashlib.sha256(method_body).hexdigest() if method_body is not None else None
    route_hashes = route.get("source_hashes")
    route_method_digest = route_hashes.get("method_page") if isinstance(route_hashes, dict) else None
    if (
        method_digest is None
        or record.get("method_page_sha256") != method_digest
        or route_method_digest != method_digest
    ):
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_ROUTE_MISMATCH", "载荷记录的方法页摘要已过期或不匹配")
    try:
        size, actual_sha256 = _archive_sha256(Path(archive_value))
    except OSError as exc:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_UNAVAILABLE", "已核验载荷文件不可用") from exc
    if record.get("size") != size or record.get("sha256") != actual_sha256:
        raise CLIError(EXIT_CONFLICT, "KJA_PAYLOAD_HASH", "暂存归档与已核验载荷记录不一致")


def _verification_failure(store: SessionStore, message: str) -> CLIError:
    _enter_recoverable(store)
    return CLIError(EXIT_VERIFICATION_FAILED, "KJA_VERIFICATION_FAILED", message)


def _evidence_file_snapshot(device: DeviceInfo, marker: str) -> tuple[int, str]:
    if device.transport == "mtp":
        return mtp_storage.file_snapshot(device, marker)
    if not device.root:
        raise CLIError(EXIT_RECOVERABLE, "KJA_DEVICE_UNAVAILABLE", "Kindle 根目录不可用")
    target = Path(device.root, marker)
    try:
        if target.is_symlink() or not target.is_file():
            raise CLIError(EXIT_CONFLICT, "KJA_EVIDENCE_MISSING", "方法证据文件当前不存在")
        return _archive_sha256(target)
    except OSError as exc:
        raise CLIError(EXIT_RECOVERABLE, "KJA_DEVICE_UNAVAILABLE", "无法稳定读取方法证据文件") from exc


def _command_verify(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    device = _bound_device(args, store)
    if device.root is None and device.transport != "mtp":
        raise CLIError(EXIT_RECOVERABLE, "KJA_DEVICE_UNAVAILABLE", "Kindle 根目录不可用")
    root = Path(device.root) if device.root else None
    kind = args.kind
    if state.stage in {Stage.WAIT_USER_EXPLOIT, Stage.VERIFY_JAILBREAK}:
        if kind not in {"auto", "jailbreak"}:
            raise CLIError(EXIT_CONFLICT, "KJA_STATE_CONFLICT", "当前阶段只能核对越狱证据")
        if state.stage == Stage.WAIT_USER_EXPLOIT:
            state.transition(Stage.VERIFY_JAILBREAK)
            store.save(state)
        baseline = state.evidence.get("jailbreak_evidence_baseline")
        excluded = set(baseline) if isinstance(baseline, list) else set()
        excluded.update(state.created_files)
        allowed_markers = _method_evidence_markers(state)
        _markers, log_allowed = _method_evidence_rules(state)
        user_log = state.evidence.get("jailbreak_user_log_evidence") is True
        marker_record = state.evidence.get("jailbreak_user_marker_evidence")
        confirmed_marker = marker_record.get("path") if isinstance(marker_record, dict) else None
        markers = (
            (confirmed_marker,)
            if isinstance(confirmed_marker, str) and confirmed_marker in allowed_markers
            else ()
        )
        if markers:
            try:
                observed_size, observed_digest = _evidence_file_snapshot(device, markers[0])
            except (CLIError, StorageError):
                markers = ()
            else:
                if (
                    not isinstance(marker_record, dict)
                    or marker_record.get("size") != observed_size
                    or marker_record.get("sha256") != observed_digest
                ):
                    markers = ()
        if not markers and not (log_allowed and user_log):
            raise _verification_failure(store, "当前方法页没有可核对的越狱成功标记，已停止")
        if device.transport == "mtp":
            jailbreak = mtp_storage.verify_jailbreak(
                device,
                markers=markers,
                excluded=excluded,
                user_log=log_allowed and user_log,
            )
        else:
            assert root is not None
            jailbreak = verify_jailbreak(
                root,
                equivalent_markers=markers,
                excluded_markers=excluded,
                user_log_evidence=log_allowed and user_log,
            )
        if not jailbreak.complete:
            raise _verification_failure(store, "尚未找到当前方法要求的越狱成功证据")
        state = store.load()
        state.evidence["jailbreak_verified"] = True
        state.transition(Stage.INSTALL_KOREADER)
        store.save(state)
        writer.emit(
            "verification_complete",
            stage=state.stage.value,
            check="jailbreak",
            message="已核对越狱成功证据",
        )
        return 0
    if state.stage == Stage.VERIFY_KOREADER:
        if kind not in {"auto", "koreader"}:
            raise CLIError(EXIT_CONFLICT, "KJA_STATE_CONFLICT", "当前阶段只能核对 KOReader 证据")
        if device.transport == "mtp":
            koreader = mtp_storage.verify_koreader(device)
        else:
            assert root is not None
            koreader = verify_koreader_files(root, user_visible_launch=False)
        if "koreader_files" in koreader.missing_evidence:
            raise _verification_failure(store, "尚未找到 KOReader 安装证据")
        state.evidence["koreader_files_verified"] = True
        store.save(state)
        writer.emit(
            "verification_pending",
            stage=state.stage.value,
            check="koreader",
            missing_evidence=koreader.missing_evidence,
            message=(
                "已核对 KOReader 文件；请在 Kindle 主页实际启动，"
                "再打开一本本地书进入阅读后确认"
            ),
        )
        return 0
    raise CLIError(EXIT_CONFLICT, "KJA_STATE_CONFLICT", "当前阶段没有可执行的设备证据校验")


def _command_checkpoint(args: argparse.Namespace, writer: EventWriter) -> int:
    """记录用户明确陈述的设备端结果；不以此替代主机侧文件或标记校验。"""

    if args.confirmed_by_user is not True:
        raise CLIError(EXIT_NOT_AUTHORIZED, "KJA_USER_CONFIRMATION_REQUIRED", "必须由用户明确确认设备端结果")
    store = _session_store(args)
    state = store.load()
    device = _bound_device(args, store)
    if args.kind == "exploit-complete":
        _require_stage(state, Stage.PREPARE)
        policy = _route_policy(state)
        if policy.automation != "guided-browser":
            raise CLIError(EXIT_CONFLICT, "KJA_CHECKPOINT_DENIED", "当前路线不能用设备端浏览器检查点代替载荷暂存")
        if (
            policy.generic_filler == "required-by-guide"
            and state.evidence.get("fill_complete") is not True
        ):
            raise CLIError(EXIT_CONFLICT, "KJA_FILL_REQUIRED", "当前官方方法要求先完成占位步骤")
        state.evidence["user_exploit_checkpoint"] = True
        state.transition(Stage.WAIT_USER_EXPLOIT)
        message = "已记录用户完成当前方法的设备端步骤；接下来只核对越狱标记或日志"
    elif args.kind == "jailbreak-marker":
        _require_stage(state, Stage.WAIT_USER_EXPLOIT, Stage.VERIFY_JAILBREAK)
        marker = getattr(args, "evidence_path", None)
        allowed_markers = _method_evidence_markers(state)
        baseline = state.evidence.get("jailbreak_evidence_baseline")
        excluded = set(baseline) if isinstance(baseline, list) else set()
        excluded.update(state.created_files)
        if not isinstance(marker, str) or marker not in allowed_markers or marker in excluded:
            raise CLIError(
                EXIT_CONFLICT,
                "KJA_CHECKPOINT_DENIED",
                "用户确认的标记不属于当前方法、本次新增证据或由主机暂存创建",
            )
        size, digest = _evidence_file_snapshot(device, marker)
        state.evidence["jailbreak_user_marker_evidence"] = {
            "path": marker,
            "size": size,
            "sha256": digest,
            "confirmed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        message = "已记录用户确认该方法专属标记由本次设备端操作产生；接下来核对文件"
    elif args.kind == "jailbreak-log":
        _require_stage(state, Stage.WAIT_USER_EXPLOIT, Stage.VERIFY_JAILBREAK)
        _markers, log_allowed = _method_evidence_rules(state)
        if not log_allowed:
            raise CLIError(
                EXIT_CONFLICT,
                "KJA_CHECKPOINT_DENIED",
                "当前方法页没有声明可用用户日志作为越狱成功证据",
            )
        state.evidence["jailbreak_user_log_evidence"] = True
        message = "已记录用户看到当前方法声明的 ;log 成功证据；仍将核对会话与路线绑定"
    else:
        _require_stage(state, Stage.VERIFY_KOREADER)
        if state.evidence.get("koreader_files_verified") is not True:
            raise CLIError(EXIT_CONFLICT, "KJA_KOREADER_FILES_REQUIRED", "须先核对 KOReader 文件")
        state.evidence["koreader_user_visible_launch"] = True
        state.transition(Stage.CLEANUP)
        message = "已记录用户实际启动 KOReader 并打开本地书进入阅读；可清理临时文件"
    store.save(state)
    writer.emit(
        "user_checkpoint_recorded",
        stage=state.stage.value,
        check=args.kind,
        message=message,
    )
    return 0


def _command_cleanup(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.CLEANUP)
    device = _bound_device(args, store)
    authorization_key = _consume_write_guards(args, store, state, "cleanup", device)
    if _dry_run(args):
        writer.progress(ProgressEvent(
            event="progress",
            stage=Stage.CLEANUP,
            message="预演：将只清理当前会话记录的临时文件",
            done=0,
            total=None,
            unit="paths",
            user_action=None,
        ))
        return 0
    if device.transport == "mtp":
        assert authorization_key is not None
        _consume_mtp_authorization(store, authorization_key)
        removed = mtp_storage.cleanup_created_files(
            device, store, progress=writer.progress
        )
    else:
        removed = cleanup_created_files(
            device,
            store,
            device_probe=_device_probe(args),
            progress=writer.progress,
            authorization_key=authorization_key,
        )
    state = store.load()
    _require_stage(state, Stage.CLEANUP)
    confirmation = state.evidence.get("last_ota_confirmation")
    if (
        not isinstance(confirmation, dict)
        or confirmation.get("context") != _ota_context(state)
        or confirmation.get("prevention_status") != "verified"
    ):
        raise CLIError(
            EXIT_NOT_AUTHORIZED,
            "KJA_OTA_CHECK_REQUIRED",
            "进入 COMPLETE 前缺少当前路线的 OTA 离线与阻止状态证据",
        )
    unknown = _unknown_ota_packages(state, device, store)
    if unknown:
        raise CLIError(
            EXIT_CONFLICT,
            "KJA_OTA_UNKNOWN_PACKAGE",
            "收尾复查发现未知 .bin 或 .tmp.partial；已保留原文件并停止",
        )
    audit = state.evidence.get("ota_audit_log")
    if not isinstance(audit, list):
        audit = []
    audit.append({
        "phase": "pre-complete",
        "context": _ota_context(state),
        "offline_confirmed": True,
        "prevention_status": "verified",
        "unknown_packages": [],
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    state.evidence["ota_audit_log"] = audit
    state.evidence["cleanup_paths"] = len(removed)
    state.transition(Stage.COMPLETE)
    store.save(state)
    writer.emit(
        "operation_complete",
        stage=state.stage.value,
        operation="cleanup",
        message="当前会话记录的临时文件已完成安全清理",
    )
    return 0


def _command_status(args: argparse.Namespace, writer: EventWriter) -> int:
    state = _session_store(args).load()
    writer.emit(
        "status",
        stage=state.stage.value,
        device=state.device_public,
        route=state.route,
        approvals=state.approvals,
        evidence=state.evidence,
        created_files=state.created_files,
        message=f"当前会话阶段：{state.stage.value}",
    )
    return 0


def _command_resume(args: argparse.Namespace, writer: EventWriter) -> int:
    store = _session_store(args)
    state = store.load()
    _require_stage(state, Stage.WAIT_RECONNECT, Stage.RECOVERABLE_ERROR)
    _bound_device(args, store)
    state = store.load()
    resume_value = state.evidence.get("__resume_stage")
    if not isinstance(resume_value, str):
        raise CLIError(EXIT_CONFLICT, "KJA_RESUME_INVALID", "会话没有可恢复的阶段")
    state.transition(Stage(resume_value))
    store.save(state)
    writer.emit(
        "session_resumed",
        stage=state.stage.value,
        message=f"已确认同一台 Kindle，从 {state.stage.value} 继续",
    )
    return 0


def _self_test_device_probe() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary:
        kindle = Path(temporary) / "kindle"
        (kindle / "documents").mkdir(parents=True)
        (kindle / "system").mkdir()
        (kindle / "system" / "version.txt").write_text(
            "Kindle 5.16.2.1.1 (self-test)\n", encoding="utf-8"
        )
        serial = "SELFTEST-SERIAL-0001"
        fixture = Path(temporary) / "device.json"
        fixture.write_text(json.dumps({
            "transport": "usbms",
            "root": str(kindle),
            "serial": serial,
            "model": "self-test",
            "firmware": "5.16.2.1.1",
            "read_only": False,
            "free_bytes": 0,
        }), encoding="utf-8")
        args = argparse.Namespace(device_root=str(kindle))
        with mock.patch.dict(os.environ, {
            "KJA_TEST_MODE": "1",
            "KJA_TEST_DEVICE_FIXTURE": str(fixture),
        }):
            device = _probe_one(args)
        public = device.public_dict()
        if serial in json.dumps(public) or public.get("serial_suffix") != "0001":
            raise AssertionError("device redaction failed")
        return {"serial_redacted": True, "safe_root_checked": True}


def _confirmed_fixture_snapshot(
    source_kind: str,
    url: str,
    path: Path,
    *,
    content: object = None,
) -> OfficialSourceSnapshot:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return _fixture_snapshot(
        source_kind,
        url,
        path,
        digest,
        content=content,
    )


def _self_test_routing_schema() -> dict[str, object]:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    models_path = fixtures / "models.json"
    jailbreaks_path = fixtures / "jailbreaks.json"
    models = json.loads(models_path.read_text(encoding="utf-8"))
    jailbreaks = json.loads(jailbreaks_path.read_text(encoding="utf-8"))
    policies = load_policies(_POLICIES_PATH)
    with tempfile.TemporaryDirectory() as temporary:
        source_root = Path(temporary)
        finder = source_root / "jailbreakFinder.js"
        method_page = source_root / "method-page.html"
        finder.write_text("const selfTestRouting = true;\n", encoding="utf-8")
        method_page.write_text("<html>WinterBreak2 self-test</html>\n", encoding="utf-8")
        sources = {
            "models": _confirmed_fixture_snapshot(
                "models", _MODELS_URL, models_path, content=models
            ),
            "jailbreaks": _confirmed_fixture_snapshot(
                "jailbreaks", _JAILBREAKS_URL, jailbreaks_path, content=jailbreaks
            ),
            "finder": _confirmed_fixture_snapshot("finder", _FINDER_URL, finder),
            "method_page": _confirmed_fixture_snapshot(
                "method_page",
                "https://kindlemodding.org/jailbreaking/WinterBreak2/",
                method_page,
            ),
        }
        confirmed = select_routes(
            models,
            jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            policies,
            sources=sources,
        )
        if confirmed.preferred is None or confirmed.preferred.policy_name != "WinterBreak2":
            raise AssertionError("confirmed route did not enable named policy")
        invalid_models = json.loads(json.dumps(models))
        invalid_models[0]["unexpected"] = True
        rejected = select_routes(
            invalid_models,
            jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            policies,
        )
        if rejected.blocked_reason != Stage.BLOCKED_CONFLICT.value:
            raise AssertionError("routing schema drift was not blocked")
    return {"confirmed_route": True, "invalid_schema_blocked": True}


def _self_test_safe_paths() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary:
        kindle = Path(temporary) / "kindle"
        (kindle / "documents").mkdir(parents=True)
        if assert_safe_root(kindle) != kindle.resolve(strict=True):
            raise AssertionError("safe root mismatch")
        rejected: list[bool] = []
        for unsafe in (Path("/"), kindle / ".."):
            try:
                assert_safe_root(unsafe)
            except StorageError:
                rejected.append(True)
            else:
                rejected.append(False)
        if rejected != [True, True]:
            raise AssertionError("unsafe root accepted")
    return {"protected_root_rejected": True, "traversal_rejected": True}


def _self_test_session_atomicity() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary:
        store = SessionStore(Path(temporary) / "session")
        state = store.create(DeviceInfo(
            transport="usbms",
            root=None,
            serial="SELFTEST-SERIAL-0001",
            model="self-test",
            firmware="5.0.0",
            read_only=True,
            free_bytes=0,
        ))
        if store.load().session_id != state.session_id:
            raise AssertionError("session round trip failed")
        original_target = state.target
        state.target = "changed-by-failed-save"
        try:
            with mock.patch(
                "kindle_jailbreak_lib.session.os.replace",
                side_effect=OSError("self-test replace failure"),
            ):
                store.save(state)
        except OSError:
            pass
        else:
            raise AssertionError("failed replace injection did not fail")
        if store.load().target != original_target:
            raise AssertionError("failed replace damaged previous session")
        return {"round_trip": True, "failed_replace_preserved": True}


def _command_self_test(_args: argparse.Namespace, writer: EventWriter) -> int:
    checks: tuple[tuple[str, Callable[[], dict[str, object]]], ...] = (
        ("device_probe", _self_test_device_probe),
        ("routing_schema", _self_test_routing_schema),
        ("safe_paths", _self_test_safe_paths),
        ("session_atomicity", _self_test_session_atomicity),
    )
    failed = False
    for name, check in checks:
        try:
            details = check()
        except Exception:
            failed = True
            writer.emit(
                "self_test",
                check=name,
                ok=False,
                message=f"自检失败：{name}",
            )
        else:
            writer.emit(
                "self_test",
                check=name,
                ok=True,
                message=f"自检通过：{name}",
                **details,
            )
    return EXIT_RECOVERABLE if failed else 0


_COMMANDS: dict[str, Callable[[argparse.Namespace, EventWriter], int]] = {
    "probe": _command_probe,
    "ota-check": _command_ota_check,
    "route": _command_route,
    "backup": _command_backup,
    "authorize-write": _command_authorize_write,
    "fill": _command_fill,
    "record-payload": _command_record_payload,
    "fetch-payload": _command_fetch_payload,
    "confirm-koreader-package": _command_confirm_koreader_package,
    "stage": _command_stage,
    "verify": _command_verify,
    "checkpoint": _command_checkpoint,
    "cleanup": _command_cleanup,
    "status": _command_status,
    "resume": _command_resume,
    "self-test": _command_self_test,
}


def _storage_exit_code(code: str) -> int:
    if code == "KJA_WRITE_NOT_AUTHORIZED":
        return EXIT_NOT_AUTHORIZED
    if code in {
        "KJA_DEVICE_MISMATCH",
        "KJA_DEVICE_IDENTITY",
        "KJA_POLICY_DENIED",
        "KJA_UNSAFE_ROOT",
        "KJA_FILL_REQUIRED",
    }:
        return EXIT_CONFLICT
    if code in {"KJA_UNSUPPORTED_TRANSPORT", "KJA_NOFOLLOW_UNAVAILABLE"}:
        return EXIT_UNSUPPORTED
    if code == "KJA_BACKUP_VERIFY" or code in _VALIDATION_CODES:
        return EXIT_VERIFICATION_FAILED
    return EXIT_RECOVERABLE


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(getattr(args, "apply", False)) and bool(getattr(args, "dry_run", False)):
        parser.error("--apply 与 --dry-run 不能同时使用")
    writer = EventWriter(bool(getattr(args, "json", False)))
    try:
        return _COMMANDS[args.command](args, writer)
    except CLIError as exc:
        writer.emit("error", code=exc.code, message=exc.message)
        return exc.exit_code
    except StorageError as exc:
        exit_code = _storage_exit_code(exc.code)
        store = _session_store(args)
        if exc.code == "KJA_DEVICE_UNAVAILABLE":
            _enter_wait_reconnect(store)
        elif exit_code == EXIT_RECOVERABLE:
            _enter_recoverable(store)
        writer.emit("error", code=exc.code, message=exc.message)
        return exit_code
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        writer.emit(
            "error",
            code="KJA_SESSION_ERROR",
            message="会话或输入数据不可用，请保留现状后重试",
            detail=type(exc).__name__,
        )
        return EXIT_RECOVERABLE
    except Exception as exc:
        writer.emit(
            "error",
            code="KJA_INTERNAL_ERROR",
            message="操作未完成，请保留会话后重试",
            detail=type(exc).__name__,
        )
        return EXIT_RECOVERABLE


if __name__ == "__main__":
    raise SystemExit(main())

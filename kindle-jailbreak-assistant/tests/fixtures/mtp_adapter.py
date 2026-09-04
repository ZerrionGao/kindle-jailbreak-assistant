#!/usr/bin/env python3
"""仅供 CLI 集成测试使用的 MTP JSON 协议模拟器。"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path, PurePosixPath


def emit(payload: dict[str, object], code: int = 0) -> None:
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    raise SystemExit(code)


def fail(action: str, error_code: str, message: str) -> None:
    emit({"ok": False, "action": action, "error_code": error_code, "message": message}, 1)


def safe_relative(value: str, *, allow_empty: bool = False) -> Path:
    pure = PurePosixPath(value.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or "\x00" in value:
        raise ValueError("unsafe path")
    parts = tuple(part for part in pure.parts if part not in ("", "."))
    if not parts and not allow_empty:
        raise ValueError("empty path")
    return Path(*parts)


action = sys.argv[1] if len(sys.argv) > 1 else ""
arguments = sys.argv[2:]
fixture_path = os.environ.get("KJA_MTP_FIXTURE_PATH")
if not fixture_path:
    fail(action, "mtp_unavailable", "缺少测试 MTP 配置")
fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
if fixture.get("available") is False:
    fail(action, "device_not_found", "测试 MTP 设备已断开")
device_id = fixture["id"]
root = Path(fixture["root"])

if action == "list":
    emit({
        "ok": True,
        "action": action,
        "devices": [{
            "id": device_id,
            "name": fixture["name"],
            "storage": "Internal Storage",
            "device_code": fixture["device_code"],
            "firmware": fixture["firmware"],
            "free_bytes": fixture["free_bytes"],
            "read_only": False,
        }],
    })

if not arguments or arguments[0] != device_id:
    fail(action, "device_not_found", "未找到指定的 MTP 设备")

try:
    if action == "list-files" and len(arguments) == 1:
        entries = []
        for candidate in sorted(root.rglob("*")):
            relative = candidate.relative_to(root).as_posix()
            entries.append({
                "path": relative,
                "kind": "directory" if candidate.is_dir() else "file",
                "size": None if candidate.is_dir() else candidate.stat().st_size,
            })
        emit({"ok": True, "action": action, "entries": entries})
    if action == "free-bytes" and len(arguments) == 1:
        emit({"ok": True, "action": action, "free_bytes": fixture["free_bytes"]})
    if action == "exists" and len(arguments) == 2:
        target = root / safe_relative(arguments[1])
        emit({"ok": True, "action": action, "exists": target.exists()})
    if action == "mkdir" and len(arguments) == 2:
        target = root / safe_relative(arguments[1])
        target.mkdir(parents=False, exist_ok=False)
        emit({"ok": True, "action": action})
    if action == "copy-from" and len(arguments) == 3:
        if fixture.get("fail_copy_from_once") == arguments[1]:
            fixture["fail_copy_from_once"] = None
            Path(fixture_path).write_text(json.dumps(fixture), encoding="utf-8")
            fail(action, "device_not_found", "测试 MTP 设备在回读前断开")
        source = root / safe_relative(arguments[1])
        destination = Path(arguments[2])
        shutil.copyfile(source, destination)
        emit({"ok": True, "action": action, "size": destination.stat().st_size})
    if action == "copy-to" and len(arguments) == 3:
        copy_count = fixture.get("copy_to_count", 0)
        fail_after = fixture.get("fail_copy_to_after")
        if isinstance(fail_after, int) and copy_count >= fail_after:
            fail(action, "device_not_found", "测试 MTP 设备在复制期间断开")
        fixture["copy_to_count"] = copy_count + 1
        Path(fixture_path).write_text(json.dumps(fixture), encoding="utf-8")
        source = Path(arguments[1])
        destination = root / safe_relative(arguments[2])
        shutil.copyfile(source, destination)
        emit({"ok": True, "action": action, "size": destination.stat().st_size})
    if action == "delete" and len(arguments) == 2:
        target = root / safe_relative(arguments[1])
        if target.is_dir():
            target.rmdir()
        else:
            target.unlink()
        if fixture.get("fail_after_delete_once") == arguments[1]:
            fixture["fail_after_delete_once"] = None
            Path(fixture_path).write_text(json.dumps(fixture), encoding="utf-8")
            fail(action, "device_not_found", "测试 MTP 设备在删除后断开")
        emit({"ok": True, "action": action})
except (OSError, ValueError):
    fail(action, "mtp_operation_failed", "测试 MTP 操作失败")

fail(action, "invalid_arguments", "MTP 命令参数无效")

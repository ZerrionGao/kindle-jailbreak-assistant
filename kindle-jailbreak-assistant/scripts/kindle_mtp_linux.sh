#!/usr/bin/env bash

set -u

ACTION="${1:-}"
if [ "$#" -gt 0 ]; then
  shift
fi

emit_error() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys
print(json.dumps({
    "ok": False,
    "action": sys.argv[1],
    "error_code": sys.argv[2],
    "message": sys.argv[3],
}, ensure_ascii=False, separators=(",", ":")))
PY
}

emit_ok() {
  python3 - "$1" <<'PY'
import json
import sys
print(json.dumps({"ok": True, "action": sys.argv[1]}, separators=(",", ":")))
PY
}

discover() {
  local mode="$1"
  local requested_id="${2:-}"
  local discovery
  if ! command -v gio >/dev/null 2>&1; then
    return 127
  fi
  if ! discovery="$(gio mount -li 2>/dev/null)"; then
    return 1
  fi
  GIO_DISCOVERY="$discovery" python3 - "$mode" "$requested_id" <<'PY'
import hashlib
import json
import os
import re
import sys

matches = re.findall(
    r"^\s*Mount\(\d+\):\s*(.*?)\s*->\s*(mtp://\S+)",
    os.environ.get("GIO_DISCOVERY", ""),
    flags=re.MULTILINE,
)
devices = []
def stable_identity(uri):
    match = re.search(r"(?<![A-Z0-9])(G[A-Z0-9]{15})(?![A-Z0-9])", uri.upper())
    if match:
        return match.group(1)
    match = re.search(r"(?:^|[_/])([0-9A-F]{16})(?:$|[_/])", uri.upper())
    if match:
        return match.group(1)
    return None

def device_code(identity):
    return identity[3:6] if identity.startswith("G") else identity[2:4]

for name, uri in matches:
    uri = uri.rstrip("/")
    if "kindle" not in name.lower() and "amazon" not in uri.lower():
        continue
    identity = stable_identity(uri)
    if identity is None:
        continue
    device_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    devices.append({
        "id": device_id,
        "name": name.strip(),
        "storage": "Internal Storage",
        "uri": uri,
        "device_code": device_code(identity),
    })

if sys.argv[1] == "list":
    public = [{key: item[key] for key in ("id", "name", "storage", "device_code")} for item in devices]
    print(json.dumps(
        {"ok": True, "action": "list", "devices": public},
        ensure_ascii=False,
        separators=(",", ":"),
    ))
else:
    requested = sys.argv[2]
    match = next((item for item in devices if item["id"] == requested), None)
    if match is None:
        raise SystemExit(3)
    print(match["uri"])
PY
}

remote_path() {
  python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import quote

uri, value = sys.argv[1:]
parts = []
for part in value.replace("\\", "/").split("/"):
    if not part or part == ".":
        continue
    if part == ".." or "\x00" in part:
        raise SystemExit(2)
    parts.append(quote(part, safe=""))
print(uri.rstrip("/") + ("/" + "/".join(parts) if parts else ""))
PY
}

remote_parent() {
  python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import quote

uri, value = sys.argv[1:]
parts = [part for part in value.replace("\\", "/").split("/") if part and part != "."]
if not parts or any(part == ".." or "\x00" in part for part in parts):
    raise SystemExit(2)
encoded = [quote(part, safe="") for part in parts[:-1]]
print(uri.rstrip("/") + ("/" + "/".join(encoded) if encoded else ""))
PY
}

remote_leaf() {
  python3 - "$1" <<'PY'
import sys

parts = [part for part in sys.argv[1].replace("\\", "/").split("/") if part and part != "."]
if not parts or any(part == ".." or "\x00" in part for part in parts):
    raise SystemExit(2)
print(parts[-1])
PY
}

case "$ACTION" in
  list)
    if [ "$#" -ne 0 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! public_json="$(discover list)"; then
      emit_error "$ACTION" "mtp_unavailable" "未检测到可用的 MTP 传输能力"
      exit 1
    fi
    metadata_lines=""
    while IFS= read -r device_id; do
      [ -n "$device_id" ] || continue
      if ! device_uri="$(discover resolve "$device_id")"; then
        emit_error "$ACTION" "mtp_unavailable" "未检测到可用的 MTP 传输能力"
        exit 1
      fi
      firmware=""
      if version_text="$(gio cat "$(remote_path "$device_uri" "system/version.txt")" 2>/dev/null)"; then
        firmware="$(VERSION_TEXT="$version_text" python3 - <<'PY'
import os
import re
match = re.search(r"(?:Kindle\s+)?([0-9]+(?:\.[0-9]+){1,4})", os.environ.get("VERSION_TEXT", ""))
print(match.group(1) if match else "")
PY
)"
      fi
      free_bytes=""
      if info="$(gio info -a filesystem::free "$device_uri" 2>/dev/null)"; then
        free_bytes="$(GIO_INFO="$info" python3 - <<'PY'
import os
import re
match = re.search(r"filesystem::free:\s*([0-9]+)", os.environ.get("GIO_INFO", ""))
print(match.group(1) if match else "")
PY
)"
      fi
      metadata_lines="${metadata_lines}${device_id}|${firmware}|${free_bytes}"$'\n'
    done < <(PUBLIC_JSON="$public_json" python3 - <<'PY'
import json
import os
for device in json.loads(os.environ["PUBLIC_JSON"])["devices"]:
    print(device["id"])
PY
)
    PUBLIC_JSON="$public_json" METADATA_LINES="$metadata_lines" python3 - <<'PY'
import json
import os
payload = json.loads(os.environ["PUBLIC_JSON"])
metadata = {}
for line in os.environ.get("METADATA_LINES", "").splitlines():
    device_id, firmware, free = line.split("|", 2)
    metadata[device_id] = (firmware or None, int(free) if free else None)
for device in payload["devices"]:
    firmware, free = metadata.get(device["id"], (None, None))
    device["firmware"] = firmware
    device["free_bytes"] = free
    device["read_only"] = False if free is not None else None
print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
PY
    ;;
  list-files)
    if [ "$#" -ne 1 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! DEVICE_URI="$device_uri" python3 - "$ACTION" <<'PY'
import json
import os
import subprocess
import sys
from urllib.parse import quote

root = os.environ["DEVICE_URI"].rstrip("/")
queue = [("", root)]
entries = []
while queue:
    relative_parent, uri = queue.pop(0)
    completed = subprocess.run(
        ["gio", "list", "-h", "-l", "-a", "standard::name,standard::type,standard::size", uri],
        text=True, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(1)
    for line in completed.stdout.splitlines():
        parts = line.rsplit("\t", 2)
        if len(parts) != 3:
            raise SystemExit(1)
        name, size_text, kind_text = parts
        if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
            raise SystemExit(1)
        relative = f"{relative_parent}/{name}" if relative_parent else name
        if kind_text == "(directory)":
            entries.append({"path": relative, "kind": "directory", "size": None})
            queue.append((relative, uri + "/" + quote(name, safe="")))
        elif kind_text == "(regular)":
            entries.append({"path": relative, "kind": "file", "size": int(size_text)})
        else:
            raise SystemExit(1)
entries.sort(key=lambda item: item["path"])
print(json.dumps({"ok": True, "action": sys.argv[1], "entries": entries}, ensure_ascii=False, separators=(",", ":")))
PY
    then
      emit_error "$ACTION" "mtp_operation_failed" "无法取得安全的 MTP 文件清单"
      exit 1
    fi
    ;;
  copy-to)
    if [ "$#" -ne 3 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! destination="$(remote_path "$device_uri" "$3")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if gio copy -- "$2" "$destination" >/dev/null 2>&1; then
      emit_ok "$ACTION"
    else
      emit_error "$ACTION" "mtp_operation_failed" "MTP 复制失败"
      exit 1
    fi
    ;;
  copy-from)
    if [ "$#" -ne 3 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! source="$(remote_path "$device_uri" "$2")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if gio copy -- "$source" "$3" >/dev/null 2>&1; then
      emit_ok "$ACTION"
    else
      emit_error "$ACTION" "mtp_operation_failed" "MTP 复制失败"
      exit 1
    fi
    ;;
  exists)
    if [ "$#" -ne 2 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! target="$(remote_path "$device_uri" "$2")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if gio info "$target" >/dev/null 2>&1; then
      python3 - "$ACTION" <<'PY'
import json
import sys
print(json.dumps({
    "ok": True,
    "action": sys.argv[1],
    "exists": True,
}, separators=(",", ":")))
PY
      exit 0
    fi
    if ! parent="$(remote_parent "$device_uri" "$2")" || \
       ! leaf="$(remote_leaf "$2")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if ! listing="$(gio list "$parent" 2>/dev/null)"; then
      emit_error "$ACTION" "mtp_operation_failed" "无法确认 MTP 路径状态"
      exit 1
    fi
    if GIO_LIST="$listing" TARGET_NAME="$leaf" python3 - <<'PY'
import os

names = os.environ.get("GIO_LIST", "").splitlines()
raise SystemExit(0 if os.environ.get("TARGET_NAME") in names else 1)
PY
    then
      emit_error "$ACTION" "mtp_operation_failed" "无法确认 MTP 路径状态"
      exit 1
    fi
    python3 - "$ACTION" <<'PY'
import json
import sys
print(json.dumps({
    "ok": True,
    "action": sys.argv[1],
    "exists": False,
}, separators=(",", ":")))
PY
    ;;
  free-bytes)
    if [ "$#" -ne 1 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! info="$(gio info -a filesystem::free "$device_uri" 2>/dev/null)"; then
      emit_error "$ACTION" "mtp_operation_failed" "无法读取 MTP 可用空间"
      exit 1
    fi
    if ! free_bytes="$(GIO_INFO="$info" python3 - <<'PY'
import os
import re

match = re.search(r"filesystem::free:\s*([0-9]+)", os.environ.get("GIO_INFO", ""))
if match is None:
    raise SystemExit(2)
print(match.group(1))
PY
    )"; then
      emit_error "$ACTION" "mtp_operation_failed" "无法读取 MTP 可用空间"
      exit 1
    fi
    python3 - "$ACTION" "$free_bytes" <<'PY'
import json
import sys
print(json.dumps({
    "ok": True,
    "action": sys.argv[1],
    "free_bytes": int(sys.argv[2]),
}, separators=(",", ":")))
PY
    ;;
  mkdir)
    if [ "$#" -ne 2 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! target="$(remote_path "$device_uri" "$2")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if gio mkdir "$target" >/dev/null 2>&1; then
      emit_ok "$ACTION"
    else
      emit_error "$ACTION" "mtp_operation_failed" "MTP 目录创建失败"
      exit 1
    fi
    ;;
  delete)
    if [ "$#" -ne 2 ]; then
      emit_error "$ACTION" "invalid_arguments" "MTP 命令参数无效"
      exit 2
    fi
    if ! device_uri="$(discover resolve "$1")"; then
      emit_error "$ACTION" "device_not_found" "未找到指定的 MTP 设备"
      exit 1
    fi
    if ! target="$(remote_path "$device_uri" "$2")"; then
      emit_error "$ACTION" "invalid_path" "MTP 路径无效"
      exit 2
    fi
    if gio remove "$target" >/dev/null 2>&1; then
      emit_ok "$ACTION"
    else
      emit_error "$ACTION" "mtp_operation_failed" "MTP 精确清理失败"
      exit 1
    fi
    ;;
  *)
    emit_error "${ACTION:-unknown}" "invalid_action" "不支持的 MTP 操作"
    exit 2
    ;;
esac

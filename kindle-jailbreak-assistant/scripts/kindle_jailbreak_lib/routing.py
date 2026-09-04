"""基于 KindleModding 官方数据的动态越狱路线选择。"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from .models import RouteCandidate, TriState


_MODEL_FIELDS = {
    "release_year",
    "release_firmware",
    "amazon_name",
    "last_firmware",
    "platform",
    "board",
    "jailbreak",
    "generation_nickname",
    "nicknames",
    "serial_version",
    "device_codes",
}
_DEVICE_CODE_FIELDS = {"kindletool_name", "amazon_model_id"}
_JAILBREAK_FIELDS = {"name", "url", "registration", "ads", "models", "firmwares"}
_FIRMWARE_FIELDS = {"models", "min", "max", "outliers"}
_OUTLIER_FIELDS = {"accepted", "denied"}
_POLICY_REQUIRED_FIELDS = {
    "automation",
    "generic_filler",
    "forbid_nearest_firmware",
    "separate_approval",
}
_POLICY_OPTIONAL_FIELDS = {"jailbreak_markers", "jailbreak_user_log"}
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_USER_FIRMWARE_RE = re.compile(r"^\d{1,2}(?:\.\d{1,2}){1,5}$")
_DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[2] / "references" / "method-policies.json"
)


@dataclass(frozen=True)
class MethodPolicy:
    """单个越狱方法的操作安全语义。"""

    automation: str
    generic_filler: str
    forbid_nearest_firmware: bool
    separate_approval: tuple[str, ...]
    jailbreak_markers: tuple[str, ...] = ()
    jailbreak_user_log: bool = False


@dataclass(frozen=True)
class RouteResult:
    """动态路由的裁决结果。"""

    preferred: RouteCandidate | None
    alternatives: tuple[RouteCandidate, ...]
    questions: list[str]
    source_hashes: dict[str, str]
    blocked_reason: str | None


@dataclass(frozen=True)
class OfficialSourceSnapshot:
    """可由缓存内容独立验证的官方来源快照。"""

    source_kind: str
    authority: str
    request_url: str
    final_url: str
    downloaded_at: str
    sha256: str
    raw_content_base64: str
    content: object
    official_route_url: str | None = None
    confirmed_sha256: str | None = None
    current: bool = True

    def raw_bytes(self) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("official source hash is invalid")
        try:
            body = base64.b64decode(self.raw_content_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("official source body is not valid base64") from exc
        if not body:
            raise ValueError("official source body is empty")
        if hashlib.sha256(body).hexdigest() != self.sha256:
            raise ValueError("official source body hash mismatch")
        return body

    @property
    def confirmed(self) -> bool:
        return self.confirmed_sha256 == self.sha256


class _MethodPolicyMap(dict[str, MethodPolicy]):
    def __init__(
        self,
        methods: dict[str, MethodPolicy],
        default: MethodPolicy,
    ) -> None:
        super().__init__(methods)
        self.default = default

    def __missing__(self, key: str) -> MethodPolicy:
        return self.default


def parse_device_code(serial: str) -> str:
    """按官方向导规则从序列号或短代码中提取设备代码。"""

    if not isinstance(serial, str):
        raise ValueError("serial must be a string")
    normalized = serial.upper().replace(" ", "")
    if len(normalized) in {2, 3}:
        return normalized
    if normalized.startswith("G"):
        if len(normalized) < 6:
            raise ValueError("serial number is too short")
        return normalized[3:6]
    if normalized and normalized[0] in "0123456789ABCDEF":
        if len(normalized) < 4:
            raise ValueError("serial number is too short")
        return normalized[2:4]
    raise ValueError("invalid serial number")


def compare_versions(a: str, b: str) -> int:
    """逐段按数字比较固件版本，缺失段按零处理。"""

    left = _version_parts(a)
    right = _version_parts(b)
    width = max(len(left), len(right))
    left.extend([0] * (width - len(left)))
    right.extend([0] * (width - len(right)))
    if left > right:
        return 1
    if left < right:
        return -1
    return 0


def select_routes(
    models: object,
    jailbreaks: object,
    serial: str,
    firmware: str,
    registered: TriState,
    ads: TriState,
    policies: dict[str, MethodPolicy],
    *,
    sources: dict[str, OfficialSourceSnapshot] | None = None,
) -> RouteResult:
    """依照官方数据顺序选择兼容路线，并对未知条件提出必要问题。"""

    source_hashes = {
        "models": _json_hash(models),
        "jailbreaks": _json_hash(jailbreaks),
    }
    if not _valid_models(models) or not _valid_jailbreaks(jailbreaks):
        return _blocked("BLOCKED_CONFLICT", source_hashes)

    try:
        device_code = parse_device_code(serial)
        _user_firmware_parts(firmware)
        registration_state = TriState.parse(registered)
        ads_state = TriState.parse(ads)
    except ValueError:
        return _blocked("BLOCKED_CONFLICT", source_hashes)

    model_name = _find_model(models, device_code)
    if model_name is None:
        return _blocked("BLOCKED_UNSUPPORTED", source_hashes)

    candidates: list[RouteCandidate] = []
    for method in jailbreaks:
        if model_name not in method["models"]:
            continue
        if not any(
            _firmware_matches(rule, model_name, firmware)
            for rule in method["firmwares"]
        ):
            continue
        if method["registration"] and registration_state is TriState.NO:
            continue
        if method["ads"] and ads_state is TriState.NO:
            continue

        required_questions: list[str] = []
        if method["registration"] and registration_state is TriState.UNKNOWN:
            required_questions.append("registered")
        if method["ads"] and ads_state is TriState.UNKNOWN:
            required_questions.append("ads")
        try:
            candidate_url = _route_url_info(method["url"])[1]
        except ValueError:
            return _blocked("BLOCKED_CONFLICT", source_hashes)
        candidates.append(RouteCandidate(
            name=method["name"],
            url=candidate_url,
            required_questions=tuple(required_questions),
            policy_name="default",
        ))

    if not candidates:
        return _blocked("BLOCKED_UNSUPPORTED", source_hashes)

    first = candidates[0]
    if first.required_questions:
        return RouteResult(
            preferred=None,
            alternatives=(),
            questions=list(first.required_questions),
            source_hashes=source_hashes,
            blocked_reason=None,
        )
    source_state, source_hashes = _source_context_state(
        models,
        jailbreaks,
        first,
        sources,
        source_hashes,
    )
    if source_state == "conflict":
        return _blocked("BLOCKED_CONFLICT", source_hashes)
    policy_name = (
        first.name
        if source_state == "confirmed" and first.name in policies
        else "default"
    )
    preferred = RouteCandidate(
        name=first.name,
        url=first.url,
        required_questions=first.required_questions,
        policy_name=policy_name,
    )
    return RouteResult(
        preferred=preferred,
        alternatives=tuple(candidates[1:]),
        questions=[],
        source_hashes=source_hashes,
        blocked_reason=None,
    )


def fetch_official_json(url: str, cache_dir: str | Path) -> dict | list:
    """下载官方 JSON 并保存可审计缓存；网络失败时不会使用旧缓存。"""

    snapshot = fetch_official_source(
        url,
        cache_dir,
        source_kind=_json_source_kind(_validated_official_json_url(url)),
    )
    if not isinstance(snapshot.content, (dict, list)):
        raise ValueError("official response must contain a JSON object or array")
    return snapshot.content


def fetch_official_source(
    url: str,
    cache_dir: str | Path,
    *,
    source_kind: str | None = None,
    official_route_url: str | None = None,
    confirmed_sha256: str | None = None,
) -> OfficialSourceSnapshot:
    """下载经授权的官方来源并创建含原始响应的可验证快照。"""

    kind = source_kind or _infer_source_kind(url)
    request_url, authority, approved_route = _validated_source_url(
        url,
        kind,
        official_route_url,
    )
    with urllib.request.urlopen(request_url, timeout=20) as response:
        final_url, final_authority, final_route = _validated_source_url(
            response.geturl(),
            kind,
            official_route_url,
        )
        if (
            not _source_urls_equivalent(
                request_url,
                final_url,
                kind,
                authority,
            )
            or final_authority != authority
            or final_route != approved_route
        ):
            raise ValueError("official source redirect changed the approved endpoint")
        body = response.read()
    if not isinstance(body, bytes):
        raise ValueError("official response must be bytes")

    content: object = None
    if kind in {"models", "jailbreaks"}:
        try:
            content = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("official response is not valid UTF-8 JSON") from exc
        if not isinstance(content, (dict, list)):
            raise ValueError("official response must contain a JSON object or array")
    if confirmed_sha256 is not None and not re.fullmatch(
        r"[0-9a-f]{64}", confirmed_sha256
    ):
        raise ValueError("invalid confirmed source hash")

    snapshot = OfficialSourceSnapshot(
        source_kind=kind,
        authority=authority,
        request_url=request_url,
        final_url=final_url,
        downloaded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        sha256=hashlib.sha256(body).hexdigest(),
        raw_content_base64=base64.b64encode(body).decode("ascii"),
        content=content,
        official_route_url=approved_route,
        confirmed_sha256=confirmed_sha256,
    )
    snapshot.raw_bytes()
    _write_source_cache(snapshot, cache_dir)
    return snapshot


def load_cached_source(path: str | Path) -> OfficialSourceSnapshot:
    """读取诊断缓存，并在返回前验证原始响应字节的完整性。"""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("unable to load official source cache") from exc
    expected_fields = {
        "cache_version",
        "source_kind",
        "authority",
        "downloaded_at",
        "request_url",
        "final_url",
        "sha256",
        "raw_content_base64",
        "content",
        "official_route_url",
        "confirmed_sha256",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_fields
        or payload["cache_version"] != 1
    ):
        raise ValueError("unsupported official source cache schema")
    for key in (
        "source_kind",
        "authority",
        "downloaded_at",
        "request_url",
        "final_url",
        "sha256",
        "raw_content_base64",
    ):
        if not isinstance(payload[key], str):
            raise ValueError("invalid official source cache value")
    if payload["confirmed_sha256"] is not None and not isinstance(
        payload["confirmed_sha256"], str
    ):
        raise ValueError("invalid official source confirmation")
    if payload["official_route_url"] is not None and not isinstance(
        payload["official_route_url"], str
    ):
        raise ValueError("invalid official route URL")

    request_url, authority, approved_route = _validated_source_url(
        payload["request_url"],
        payload["source_kind"],
        payload["official_route_url"],
    )
    final_url, final_authority, final_route = _validated_source_url(
        payload["final_url"],
        payload["source_kind"],
        payload["official_route_url"],
    )
    if (
        not _source_urls_equivalent(
            request_url,
            final_url,
            payload["source_kind"],
            authority,
        )
        or authority != final_authority
        or authority != payload["authority"]
        or approved_route != final_route
    ):
        raise ValueError("official source cache URL mismatch")
    snapshot = OfficialSourceSnapshot(
        source_kind=payload["source_kind"],
        authority=payload["authority"],
        request_url=request_url,
        final_url=final_url,
        downloaded_at=payload["downloaded_at"],
        sha256=payload["sha256"],
        raw_content_base64=payload["raw_content_base64"],
        content=payload["content"],
        official_route_url=approved_route,
        confirmed_sha256=payload["confirmed_sha256"],
        current=False,
    )
    body = snapshot.raw_bytes()
    if snapshot.source_kind in {"models", "jailbreaks"}:
        try:
            parsed_content = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cached official JSON is invalid") from exc
        if parsed_content != snapshot.content:
            raise ValueError("cached official JSON content mismatch")
    return snapshot


def _validated_official_json_url(url: object) -> str:
    kind = _infer_source_kind(url)
    if kind not in {"models", "jailbreaks"}:
        raise ValueError("unapproved official JSON URL")
    validated, authority, _ = _validated_source_url(url, kind, None)
    if authority != "kindlemodding":
        raise ValueError("unapproved official JSON authority")
    return validated


def _json_source_kind(url: str) -> str:
    return "models" if urlsplit(url).path == "/models.json" else "jailbreaks"


def _infer_source_kind(url: object) -> str:
    if not isinstance(url, str):
        raise ValueError("official source URL must be a string")
    path = urlsplit(url).path
    if path == "/models.json":
        return "models"
    if path == "/jailbreaks.json":
        return "jailbreaks"
    if path == "/jailbreakFinder.js":
        return "finder"
    if path.startswith("/jailbreaking/"):
        return "method_page"
    raise ValueError("unable to infer official source kind")


def _validated_source_url(
    url: object,
    source_kind: object,
    official_route_url: object,
) -> tuple[str, str, str | None]:
    if not isinstance(url, str) or source_kind not in {
        "models",
        "jailbreaks",
        "finder",
        "method_page",
    }:
        raise ValueError("invalid official source")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.netloc != parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not _safe_source_path(parsed.path)
    ):
        raise ValueError("unapproved official source URL")

    normalized = parsed.geturl()
    if parsed.hostname == "kindlemodding.org":
        if parsed.query:
            raise ValueError("internal source URL must not contain a query")
        allowed_path = {
            "models": "/models.json",
            "jailbreaks": "/jailbreaks.json",
            "finder": "/jailbreakFinder.js",
        }.get(source_kind)
        if source_kind == "method_page":
            if not parsed.path.startswith("/jailbreaking/"):
                raise ValueError("unapproved method page path")
        elif parsed.path != allowed_path:
            raise ValueError("unapproved official source path")
        if official_route_url is not None:
            raise ValueError("internal source must not declare an external route")
        return normalized, "kindlemodding", None

    if source_kind != "method_page" or not isinstance(official_route_url, str):
        raise ValueError("external source is not an official route")
    approved_route = _validated_external_route_url(official_route_url)
    if _validated_external_route_url(normalized) != approved_route:
        raise ValueError("external source does not match the official route")
    return normalized, "external-route", approved_route


def _safe_source_path(path: str) -> bool:
    decoded = unquote(path)
    return (
        path.startswith("/")
        and "\\" not in decoded
        and "\x00" not in decoded
        and all(part not in {".", ".."} for part in decoded.split("/"))
    )


def _validated_external_route_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.netloc != parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not _safe_source_path(parsed.path)
    ):
        raise ValueError("invalid external official route URL")
    if (
        parsed.hostname != "www.mobileread.com"
        or parsed.path != "/forums/showthread.php"
        or not re.fullmatch(r"p=[0-9]+", parsed.query)
    ):
        raise ValueError("unsupported external official route locator")
    return parsed.geturl()


def _source_urls_equivalent(
    request_url: str,
    final_url: str,
    source_kind: object,
    authority: str,
) -> bool:
    if request_url == final_url:
        return True
    if source_kind != "method_page" or authority != "kindlemodding":
        return False
    request = urlsplit(request_url)
    final = urlsplit(final_url)
    return (
        request.scheme == final.scheme == "https"
        and request.netloc == final.netloc == "kindlemodding.org"
        and not request.query
        and not final.query
        and not request.fragment
        and not final.fragment
        and not request.path.endswith("/")
        and f"{request.path}/" == final.path
    )


def _write_source_cache(
    snapshot: OfficialSourceSnapshot,
    cache_dir: str | Path,
) -> None:
    destination = Path(cache_dir)
    destination.mkdir(parents=True, exist_ok=True)
    cache_name = (
        f"{hashlib.sha256(snapshot.request_url.encode('utf-8')).hexdigest()}.json"
    )
    cache_payload = {
        "cache_version": 1,
        "source_kind": snapshot.source_kind,
        "authority": snapshot.authority,
        "downloaded_at": snapshot.downloaded_at,
        "request_url": snapshot.request_url,
        "final_url": snapshot.final_url,
        "sha256": snapshot.sha256,
        "raw_content_base64": snapshot.raw_content_base64,
        "content": snapshot.content,
        "official_route_url": snapshot.official_route_url,
        "confirmed_sha256": snapshot.confirmed_sha256,
    }
    (destination / cache_name).write_text(
        json.dumps(cache_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _route_url_info(route_url: object) -> tuple[str, str, bool]:
    if not isinstance(route_url, str) or not route_url:
        raise ValueError("invalid jailbreak route URL")
    parsed = urlsplit(route_url)
    if not parsed.scheme and not parsed.netloc:
        if (
            parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/jailbreaking/")
            or not _safe_source_path(parsed.path)
        ):
            raise ValueError("invalid internal jailbreak route URL")
        absolute = urljoin("https://kindlemodding.org/", parsed.path)
        return absolute, parsed.path, False
    validated = _validated_external_route_url(route_url)
    return validated, validated, True


def _source_context_state(
    models: object,
    jailbreaks: object,
    preferred: RouteCandidate,
    sources: dict[str, OfficialSourceSnapshot] | None,
    fallback_hashes: dict[str, str],
) -> tuple[str, dict[str, str]]:
    if sources is None:
        return "review", fallback_hashes
    if not isinstance(sources, dict):
        return "conflict", fallback_hashes

    expected_keys = {"models", "jailbreaks", "finder", "method_page"}
    if not set(sources).issubset(expected_keys):
        return "conflict", fallback_hashes
    hashes = {
        key: snapshot.sha256
        for key, snapshot in sources.items()
        if isinstance(snapshot, OfficialSourceSnapshot)
    }
    if set(sources) != expected_keys:
        return "review", hashes or fallback_hashes
    if not all(
        isinstance(snapshot, OfficialSourceSnapshot)
        for snapshot in sources.values()
    ):
        return "conflict", hashes or fallback_hashes

    try:
        for key, snapshot in sources.items():
            body = snapshot.raw_bytes()
            if snapshot.source_kind != key:
                raise ValueError("source kind mismatch")
            request_url, authority, approved_route = _validated_source_url(
                snapshot.request_url,
                key,
                snapshot.official_route_url,
            )
            final_url, final_authority, final_route = _validated_source_url(
                snapshot.final_url,
                key,
                snapshot.official_route_url,
            )
            if (
                not _source_urls_equivalent(
                    request_url,
                    final_url,
                    key,
                    authority,
                )
                or authority != final_authority
                or authority != snapshot.authority
                or approved_route != final_route
            ):
                raise ValueError("source URL mismatch")
            if key in {"models", "jailbreaks"}:
                parsed = json.loads(body.decode("utf-8"))
                expected = models if key == "models" else jailbreaks
                if parsed != expected or snapshot.content != expected:
                    raise ValueError("source content mismatch")

        finder = sources["finder"]
        if finder.request_url != "https://kindlemodding.org/jailbreakFinder.js":
            raise ValueError("finder source mismatch")
        expected_page, _, external = _route_url_info(preferred.url)
        method_page = sources["method_page"]
        if not _source_urls_equivalent(
            expected_page,
            method_page.request_url,
            "method_page",
            method_page.authority,
        ):
            raise ValueError("preferred method page mismatch")
        if external:
            if (
                method_page.authority != "external-route"
                or method_page.official_route_url != expected_page
            ):
                raise ValueError("external method page authority mismatch")
            return "review", hashes
        if method_page.authority != "kindlemodding":
            raise ValueError("internal method page authority mismatch")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return "conflict", hashes or fallback_hashes

    if not all(
        snapshot.current and snapshot.confirmed
        for snapshot in sources.values()
    ):
        return "review", hashes
    return "confirmed", hashes


def load_policies(path: str | Path) -> dict[str, MethodPolicy]:
    """加载并严格校验方法安全策略。"""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("unable to load method policies") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "default", "methods"}
        or payload["schema_version"] != 1
        or not isinstance(payload["methods"], dict)
        or not payload["methods"]
    ):
        raise ValueError("unsupported method policy schema")

    default = _parse_policy(payload["default"])
    methods: dict[str, MethodPolicy] = {}
    for name, raw_policy in payload["methods"].items():
        if not isinstance(name, str) or not name:
            raise ValueError("method policy names must be non-empty strings")
        methods[name] = _parse_policy(raw_policy)
    return _MethodPolicyMap(methods, default)


def load_method_policy(name: str) -> MethodPolicy:
    """按名称加载方法策略；新方法安全降级为只读引导复核。"""

    policies = load_policies(_DEFAULT_POLICY_PATH)
    default = _policy_default(policies)
    return policies.get(name, default)


def _version_parts(version: str) -> list[int]:
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid firmware version: {version!r}")
    return [int(part) for part in version.split(".")]


def _user_firmware_parts(version: str) -> list[int]:
    if not isinstance(version, str) or not _USER_FIRMWARE_RE.fullmatch(version):
        raise ValueError(f"invalid firmware version: {version!r}")
    parts = [int(part) for part in version.split(".")]
    if parts[0] > 5:
        raise ValueError(f"invalid firmware version: {version!r}")
    return parts


def _json_hash(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b"invalid-json"
    return hashlib.sha256(encoded).hexdigest()


def _blocked(reason: str, source_hashes: dict[str, str]) -> RouteResult:
    return RouteResult(
        preferred=None,
        alternatives=(),
        questions=[],
        source_hashes=source_hashes,
        blocked_reason=reason,
    )


def _is_string_list(value: object, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or bool(value))
        and all(isinstance(item, str) for item in value)
    )


def _valid_models(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for model in value:
        if not isinstance(model, dict) or set(model) != _MODEL_FIELDS:
            return False
        if not isinstance(model["release_year"], int) or isinstance(
            model["release_year"], bool
        ):
            return False
        for key in (
            "release_firmware",
            "amazon_name",
            "last_firmware",
            "platform",
            "board",
            "jailbreak",
            "generation_nickname",
        ):
            if not isinstance(model[key], str):
                return False
        if not _is_string_list(model["nicknames"], nonempty=True):
            return False
        if model["serial_version"] not in {0, 1} or isinstance(
            model["serial_version"], bool
        ):
            return False
        if not isinstance(model["device_codes"], dict) or not model["device_codes"]:
            return False
        for code, details in model["device_codes"].items():
            if (
                not isinstance(code, str)
                or not isinstance(details, dict)
                or set(details) != _DEVICE_CODE_FIELDS
                or not isinstance(details["kindletool_name"], str)
                or details["amazon_model_id"] is not None
                and not isinstance(details["amazon_model_id"], str)
            ):
                return False
    return True


def _valid_jailbreaks(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for method in value:
        if not isinstance(method, dict) or set(method) != _JAILBREAK_FIELDS:
            return False
        if (
            not isinstance(method["name"], str)
            or not method["name"]
            or not isinstance(method["url"], str)
            or not isinstance(method["registration"], bool)
            or not isinstance(method["ads"], bool)
            or not _is_string_list(method["models"], nonempty=True)
            or not isinstance(method["firmwares"], list)
            or not method["firmwares"]
        ):
            return False
        try:
            _route_url_info(method["url"])
        except ValueError:
            return False
        for rule in method["firmwares"]:
            if not isinstance(rule, dict) or set(rule) != _FIRMWARE_FIELDS:
                return False
            if (
                not _is_string_list(rule["models"], nonempty=True)
                or not isinstance(rule["min"], str)
                or not isinstance(rule["max"], str)
                or not isinstance(rule["outliers"], dict)
                or set(rule["outliers"]) != _OUTLIER_FIELDS
                or not _is_string_list(rule["outliers"]["accepted"])
                or not _is_string_list(rule["outliers"]["denied"])
            ):
                return False
            try:
                _version_parts(rule["min"])
                _version_parts(rule["max"])
                for version in (
                    rule["outliers"]["accepted"]
                    + rule["outliers"]["denied"]
                ):
                    _version_parts(version)
            except ValueError:
                return False
    return True


def _find_model(models: list[dict[str, Any]], device_code: str) -> str | None:
    serial_version = 1 if len(device_code) == 3 else 0
    for model in models:
        if model["serial_version"] < serial_version:
            continue
        if device_code in model["device_codes"]:
            return model["generation_nickname"]
    return None


def _firmware_matches(
    rule: dict[str, Any],
    model_name: str,
    firmware: str,
) -> bool:
    if "all" not in rule["models"] and model_name not in rule["models"]:
        return False
    outliers = rule["outliers"]
    if firmware in outliers["denied"]:
        return False
    if firmware in outliers["accepted"]:
        return True
    return (
        compare_versions(firmware, rule["min"]) >= 0
        and compare_versions(firmware, rule["max"]) <= 0
    )


def _parse_policy(value: object) -> MethodPolicy:
    if (
        not isinstance(value, dict)
        or not _POLICY_REQUIRED_FIELDS.issubset(value)
        or not set(value).issubset(_POLICY_REQUIRED_FIELDS | _POLICY_OPTIONAL_FIELDS)
    ):
        raise ValueError("invalid method policy")
    if (
        not isinstance(value["automation"], str)
        or not value["automation"]
        or not isinstance(value["generic_filler"], str)
        or not value["generic_filler"]
        or not isinstance(value["forbid_nearest_firmware"], bool)
        or not _is_string_list(value["separate_approval"])
        or not _is_string_list(value.get("jailbreak_markers", []))
        or not isinstance(value.get("jailbreak_user_log", False), bool)
    ):
        raise ValueError("invalid method policy")
    return MethodPolicy(
        automation=value["automation"],
        generic_filler=value["generic_filler"],
        forbid_nearest_firmware=value["forbid_nearest_firmware"],
        separate_approval=tuple(value["separate_approval"]),
        jailbreak_markers=tuple(value.get("jailbreak_markers", [])),
        jailbreak_user_log=value.get("jailbreak_user_log", False),
    )


def _policy_default(policies: dict[str, MethodPolicy]) -> MethodPolicy:
    default = getattr(policies, "default", None)
    if isinstance(default, MethodPolicy):
        return default
    return MethodPolicy(
        automation="guided-review",
        generic_filler="review-official-guide",
        forbid_nearest_firmware=True,
        separate_approval=(),
    )

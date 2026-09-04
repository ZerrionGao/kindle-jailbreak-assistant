import base64
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock
from urllib.error import URLError

from kindle_jailbreak_lib.models import TriState
from kindle_jailbreak_lib.routing import (
    OfficialSourceSnapshot,
    compare_versions,
    fetch_official_json,
    load_method_policy,
    load_policies,
    parse_device_code,
    select_routes,
)


SKILL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _snapshot(
    source_kind,
    url,
    body,
    *,
    content=None,
    authority="kindlemodding",
    official_route_url=None,
    confirmed=True,
):
    digest = hashlib.sha256(body).hexdigest()
    return OfficialSourceSnapshot(
        source_kind=source_kind,
        authority=authority,
        request_url=url,
        final_url=url,
        downloaded_at="2026-09-03T12:00:00Z",
        sha256=digest,
        raw_content_base64=base64.b64encode(body).decode("ascii"),
        content=content,
        official_route_url=official_route_url,
        confirmed_sha256=digest if confirmed else None,
    )


class _Response:
    def __init__(self, body, final_url):
        self._body = body
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self._body

    def geturl(self):
        return self._final_url


class _OrderedResponse(_Response):
    def __init__(self, body, final_url, events):
        super().__init__(body, final_url)
        self._events = events

    def read(self):
        self._events.append("read")
        return super().read()

    def geturl(self):
        self._events.append("geturl")
        return super().geturl()


class RoutingTest(unittest.TestCase):
    def setUp(self):
        self.models = _fixture("models.json")
        self.jailbreaks = _fixture("jailbreaks.json")
        self.policies = load_policies(
            SKILL_ROOT / "references" / "method-policies.json"
        )

    def _source_context(self, jailbreaks=None, method_url=None):
        jailbreaks = self.jailbreaks if jailbreaks is None else jailbreaks
        method_url = (
            "https://kindlemodding.org/jailbreaking/WinterBreak2/"
            if method_url is None
            else method_url
        )
        models_body = json.dumps(
            self.models, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        jailbreaks_body = json.dumps(
            jailbreaks, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return {
            "models": _snapshot(
                "models",
                "https://kindlemodding.org/models.json",
                models_body,
                content=self.models,
            ),
            "jailbreaks": _snapshot(
                "jailbreaks",
                "https://kindlemodding.org/jailbreaks.json",
                jailbreaks_body,
                content=jailbreaks,
            ),
            "finder": _snapshot(
                "finder",
                "https://kindlemodding.org/jailbreakFinder.js",
                b"confirmed finder semantics",
            ),
            "method_page": _snapshot(
                "method_page",
                method_url,
                b"confirmed preferred method guide",
            ),
        }

    def test_pw3_516211_uses_official_first_match(self):
        result = select_routes(
            self.models,
            self.jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(parse_device_code("G090KB03"), "0KB")
        self.assertEqual(result.preferred.name, "WinterBreak2")
        self.assertEqual(result.questions, [])
        self.assertEqual(
            [candidate.name for candidate in result.alternatives],
            ["WinterBreak",],
        )
        self.assertIsNone(result.blocked_reason)
        self.assertEqual(set(result.source_hashes), {"models", "jailbreaks"})
        for digest in result.source_hashes.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_version_comparison_is_numeric_and_zero_padded(self):
        self.assertGreater(compare_versions("5.16.10", "5.16.3"), 0)
        self.assertEqual(compare_versions("5.16.3", "5.16.3.0"), 0)
        self.assertLess(compare_versions("5.6.1.1", "5.16.1"), 0)

    def test_official_firmware_format_rejects_ambiguous_versions(self):
        for firmware in (
            "05.016.003",
            "5",
            "5.1.2.3.4.5.6",
            "6.1",
            "5.123",
        ):
            with self.subTest(firmware=firmware):
                result = select_routes(
                    self.models,
                    self.jailbreaks,
                    "G090KB03",
                    firmware,
                    TriState.UNKNOWN,
                    TriState.UNKNOWN,
                    self.policies,
                )
                self.assertEqual(result.blocked_reason, "BLOCKED_CONFLICT")
                self.assertIsNone(result.preferred)

    def test_official_range_sentinel_does_not_relax_user_firmware_format(self):
        jailbreaks = json.loads(json.dumps(self.jailbreaks))
        jailbreaks[0]["firmwares"][0]["max"] = "999.0.0"

        valid = select_routes(
            self.models,
            jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )
        invalid = select_routes(
            self.models,
            jailbreaks,
            "G090KB03",
            "999.0.0",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(valid.preferred.name, "WinterBreak2")
        self.assertIsNone(valid.blocked_reason)
        self.assertEqual(invalid.blocked_reason, "BLOCKED_CONFLICT")

    def test_legacy_serial_uses_two_character_official_device_code(self):
        self.assertEqual(parse_device_code("B008 1234"), "08")

    def test_denied_outlier_wins_over_range(self):
        result = select_routes(
            self.models,
            self.jailbreaks,
            "G090KB03",
            "5.16.2.1.2",
            TriState.YES,
            TriState.NO,
            self.policies,
        )

        self.assertEqual(result.preferred.name, "WinterBreak")
        self.assertNotIn(
            "WinterBreak2",
            [result.preferred.name, *(item.name for item in result.alternatives)],
        )

    def test_accepted_outlier_can_bypass_range(self):
        result = select_routes(
            self.models,
            self.jailbreaks,
            "G090KB03",
            "5.16.5",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(result.preferred.name, "WinterBreak2")
        self.assertEqual(result.questions, [])

    def test_unknown_registration_prompts_only_when_route_requires_it(self):
        springbreak = [
            route for route in self.jailbreaks if route["name"] == "SpringBreak"
        ]

        unresolved = select_routes(
            self.models,
            springbreak,
            "G090KB03",
            "5.16.4",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )
        rejected = select_routes(
            self.models,
            springbreak,
            "G090KB03",
            "5.16.4",
            TriState.NO,
            TriState.UNKNOWN,
            self.policies,
        )
        accepted = select_routes(
            self.models,
            springbreak,
            "G090KB03",
            "5.16.4",
            TriState.YES,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(unresolved.questions, ["registered"])
        self.assertIsNone(unresolved.preferred)
        self.assertEqual(rejected.blocked_reason, "BLOCKED_UNSUPPORTED")
        self.assertEqual(accepted.preferred.name, "SpringBreak")
        self.assertEqual(accepted.questions, [])

    def test_known_registration_conflict_prevents_unneeded_ads_question(self):
        adbreak = [
            route for route in self.jailbreaks if route["name"] == "AdBreak"
        ]

        result = select_routes(
            self.models,
            adbreak,
            "G090KB03",
            "5.18.2",
            TriState.NO,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(result.questions, [])
        self.assertEqual(result.blocked_reason, "BLOCKED_UNSUPPORTED")

    def test_unknown_ads_prompts_after_registration_requirement_is_satisfied(self):
        adbreak = [
            route for route in self.jailbreaks if route["name"] == "AdBreak"
        ]

        unresolved = select_routes(
            self.models,
            adbreak,
            "G090KB03",
            "5.18.2",
            TriState.YES,
            TriState.UNKNOWN,
            self.policies,
        )
        accepted = select_routes(
            self.models,
            adbreak,
            "G090KB03",
            "5.18.2",
            TriState.YES,
            TriState.YES,
            self.policies,
        )

        self.assertEqual(unresolved.questions, ["ads"])
        self.assertIsNone(unresolved.preferred)
        self.assertEqual(accepted.preferred.name, "AdBreak")

    def test_schema_drift_blocks_instead_of_guessing(self):
        cases = []
        models = _fixture("models.json")
        models[0]["unexpected"] = True
        cases.append((models, self.jailbreaks))
        jailbreaks = _fixture("jailbreaks.json")
        jailbreaks[0]["firmwares"][0]["outliers"]["maybe"] = []
        cases.append((self.models, jailbreaks))
        cases.append(({"models": self.models}, self.jailbreaks))
        jailbreaks = _fixture("jailbreaks.json")
        unsafe_route = json.loads(json.dumps(jailbreaks[0]))
        unsafe_route["models"] = ["OTHER"]
        unsafe_route["url"] = "http://evil.example/guide"
        jailbreaks.append(unsafe_route)
        cases.append((self.models, jailbreaks))

        for models_data, jailbreak_data in cases:
            with self.subTest(models=type(models_data).__name__):
                result = select_routes(
                    models_data,
                    jailbreak_data,
                    "G090KB03",
                    "5.16.2.1.1",
                    TriState.UNKNOWN,
                    TriState.UNKNOWN,
                    self.policies,
                )
                self.assertIsNone(result.preferred)
                self.assertEqual(result.blocked_reason, "BLOCKED_CONFLICT")

    def test_method_policies_preserve_all_thirteen_safety_decisions(self):
        expected = {
            "WinterBreak2": ("guided-browser", "required-by-guide", ()),
            "Véra": ("guided-browser", "required-by-guide", ()),
            "SpiderCat": (
                "guided-assets-or-browser", "required-by-guide", (),
            ),
            "Nosebleed": (
                "guided-assets-and-browser", "required-by-guide", (),
            ),
            "Sanctuary": ("guided-browser", "required-by-guide", ()),
            "WinterBreak": (
                "guided-assets-and-store", "required-by-guide", (),
            ),
            "SpringBreak": ("official-helper", "forbidden", ()),
            "AdBreak": (
                "guided-assets",
                "required-by-guide",
                ("amazon-region", "payment-method", "ad-state", "factory-reset"),
            ),
            "NiLuJe K2/DX/DXG/K3 Jailbreak": (
                "guided-update-package", "not-required", (),
            ),
            "NiLuJe K4 Jailbreak": (
                "guided-update-package", "not-required", (),
            ),
            "NiLuJe K5 Jailbreak": (
                "guided-update-package", "not-required", (),
            ),
            "LEGACY": ("guided-review", "review-official-guide", ()),
            "Android Jailbreak Methods": (
                "external-guide-review", "not-applicable", (),
            ),
        }

        self.assertEqual(set(self.policies), set(expected))
        for name, values in expected.items():
            with self.subTest(name=name):
                policy = self.policies[name]
                self.assertEqual(
                    (policy.automation, policy.generic_filler,
                     policy.separate_approval),
                    values,
                )
                self.assertTrue(policy.forbid_nearest_firmware)

    def test_unknown_method_uses_read_only_default_policy(self):
        policy = load_method_policy("FutureMethod")

        self.assertEqual(policy.automation, "guided-review")
        self.assertEqual(policy.generic_filler, "review-official-guide")
        self.assertTrue(policy.forbid_nearest_firmware)
        self.assertEqual(policy.separate_approval, ())

    def test_batch_policy_lookup_resolves_unknown_route_to_safe_default(self):
        future_method = json.loads(json.dumps(self.jailbreaks[0]))
        future_method["name"] = "FutureMethod"

        result = select_routes(
            self.models,
            [future_method],
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
        )

        self.assertEqual(result.preferred.policy_name, "default")
        self.assertEqual(
            self.policies[result.preferred.policy_name].automation,
            "guided-review",
        )

    def test_confirmed_four_source_context_enables_method_policy(self):
        sources = self._source_context()

        result = select_routes(
            self.models,
            self.jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
            sources=sources,
        )

        self.assertEqual(result.preferred.name, "WinterBreak2")
        self.assertEqual(result.preferred.policy_name, "WinterBreak2")
        self.assertEqual(
            result.source_hashes,
            {name: snapshot.sha256 for name, snapshot in sources.items()},
        )

    def test_missing_or_unconfirmed_semantic_source_forces_guided_review(self):
        cases = {
            "missing-all": None,
            "missing-method-page": {
                key: value
                for key, value in self._source_context().items()
                if key != "method_page"
            },
            "unconfirmed-finder": {
                **self._source_context(),
                "finder": replace(
                    self._source_context()["finder"],
                    confirmed_sha256=None,
                ),
            },
            "changed-finder": {
                **self._source_context(),
                "finder": replace(
                    self._source_context()["finder"],
                    confirmed_sha256="0" * 64,
                ),
            },
        }

        for label, sources in cases.items():
            with self.subTest(label=label):
                result = select_routes(
                    self.models,
                    self.jailbreaks,
                    "G090KB03",
                    "5.16.2.1.1",
                    TriState.UNKNOWN,
                    TriState.UNKNOWN,
                    self.policies,
                    sources=sources,
                )
                self.assertEqual(result.preferred.name, "WinterBreak2")
                self.assertEqual(result.preferred.policy_name, "default")
                self.assertEqual(
                    self.policies[result.preferred.policy_name].automation,
                    "guided-review",
                )

    def test_offline_cached_sources_cannot_enable_automatic_route(self):
        sources = {
            key: replace(snapshot, current=False)
            for key, snapshot in self._source_context().items()
        }

        result = select_routes(
            self.models,
            self.jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
            sources=sources,
        )

        self.assertEqual(result.preferred.name, "WinterBreak2")
        self.assertEqual(result.preferred.policy_name, "default")
        self.assertEqual(
            self.policies[result.preferred.policy_name].automation,
            "guided-review",
        )

    def test_source_content_or_method_page_mismatch_blocks_routing(self):
        bad_models = self._source_context()
        bad_models["models"] = _snapshot(
            "models",
            "https://kindlemodding.org/models.json",
            b"[]",
            content=[],
        )
        wrong_page = self._source_context()
        wrong_page["method_page"] = _snapshot(
            "method_page",
            "https://kindlemodding.org/jailbreaking/SpringBreak/",
            b"confirmed different method guide",
        )

        for label, sources in (
            ("models", bad_models),
            ("method-page", wrong_page),
        ):
            with self.subTest(label=label):
                result = select_routes(
                    self.models,
                    self.jailbreaks,
                    "G090KB03",
                    "5.16.2.1.1",
                    TriState.UNKNOWN,
                    TriState.UNKNOWN,
                    self.policies,
                    sources=sources,
                )
                self.assertEqual(result.blocked_reason, "BLOCKED_CONFLICT")
                self.assertIsNone(result.preferred)

    def test_external_official_route_keeps_locator_and_is_guided_review_only(self):
        external = json.loads(json.dumps(self.jailbreaks[0]))
        external["name"] = "Android Jailbreak Methods"
        external["url"] = (
            "https://www.mobileread.com/forums/showthread.php?p=4087697"
        )
        jailbreaks = [external]
        method_url = external["url"]
        sources = self._source_context(jailbreaks, method_url)
        sources["method_page"] = _snapshot(
            "method_page",
            method_url,
            b"confirmed external guide",
            authority="external-route",
            official_route_url=method_url,
        )

        result = select_routes(
            self.models,
            jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
            sources=sources,
        )

        self.assertEqual(result.preferred.name, "Android Jailbreak Methods")
        self.assertEqual(result.preferred.url, method_url)
        self.assertEqual(result.preferred.policy_name, "default")
        self.assertEqual(
            self.policies[result.preferred.policy_name].automation,
            "guided-review",
        )

    def test_source_context_accepts_internal_canonical_page_redirect(self):
        vera = json.loads(json.dumps(self.jailbreaks[0]))
        vera["name"] = "Véra"
        vera["url"] = "/jailbreaking/Vera"
        jailbreaks = [vera]
        request_url = "https://kindlemodding.org/jailbreaking/Vera"
        final_url = f"{request_url}/"
        sources = self._source_context(jailbreaks, request_url)
        sources["method_page"] = replace(
            sources["method_page"],
            final_url=final_url,
        )

        result = select_routes(
            self.models,
            jailbreaks,
            "G090KB03",
            "5.16.2.1.1",
            TriState.UNKNOWN,
            TriState.UNKNOWN,
            self.policies,
            sources=sources,
        )

        self.assertEqual(result.preferred.name, "Véra")
        self.assertEqual(result.preferred.policy_name, "Véra")
        self.assertIsNone(result.blocked_reason)

    def test_fetch_caches_final_url_hash_time_and_content(self):
        body = b'[{"name":"WinterBreak2"}]'
        final_url = "https://kindlemodding.org/jailbreaks.json"
        response = _Response(body, final_url)

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                return_value=response,
            ):
                data = fetch_official_json(
                    "https://kindlemodding.org/jailbreaks.json", Path(tmp)
                )

            files = list(Path(tmp).glob("*.json"))
            self.assertEqual(data, [{"name": "WinterBreak2"}])
            self.assertEqual(len(files), 1)
            cached = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(
                cached["request_url"],
                "https://kindlemodding.org/jailbreaks.json",
            )
            self.assertEqual(cached["final_url"], final_url)
            self.assertEqual(cached["sha256"], hashlib.sha256(body).hexdigest())
            raw_body = base64.b64decode(
                cached["raw_content_base64"], validate=True
            )
            self.assertEqual(raw_body, body)
            self.assertEqual(
                hashlib.sha256(raw_body).hexdigest(),
                cached["sha256"],
            )
            self.assertEqual(cached["content"], data)
            self.assertRegex(
                cached["downloaded_at"],
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$",
            )

    def test_fetch_does_not_treat_offline_cache_as_current(self):
        body = b'[{"name":"WinterBreak2"}]'
        url = "https://kindlemodding.org/jailbreaks.json"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                return_value=_Response(body, url),
            ):
                fetch_official_json(url, Path(tmp))

            with mock.patch(
                "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                side_effect=URLError("offline"),
            ):
                with self.assertRaises(URLError):
                    fetch_official_json(url, Path(tmp))

    def test_cached_source_detects_raw_body_tampering(self):
        from kindle_jailbreak_lib.routing import load_cached_source

        body = b'[{"name":"WinterBreak2"}]'
        url = "https://kindlemodding.org/jailbreaks.json"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                return_value=_Response(body, url),
            ):
                fetch_official_json(url, Path(tmp))

            cache_path = next(Path(tmp).glob("*.json"))
            snapshot = load_cached_source(cache_path)
            self.assertEqual(snapshot.raw_bytes(), body)
            self.assertFalse(snapshot.current)

            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            cached["raw_content_base64"] = base64.b64encode(
                b'tampered'
            ).decode("ascii")
            cache_path.write_text(json.dumps(cached), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash"):
                load_cached_source(cache_path)

    def test_fetch_rejects_untrusted_or_sensitive_url_before_caching(self):
        body = b'[{"name":"WinterBreak2"}]'
        invalid_urls = (
            "http://kindlemodding.org/jailbreaks.json",
            "https://user:secret@kindlemodding.org/jailbreaks.json",
            "https://kindlemodding.org/jailbreaks.json?token=secret",
            "https://kindlemodding.org/jailbreaks.json#fragment",
            "https://evil.example/jailbreaks.json",
            "https://kindlemodding.org/unreviewed.json",
        )

        for url in invalid_urls:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmp:
                with mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=_Response(body, url),
                ):
                    with self.assertRaises(ValueError):
                        fetch_official_json(url, Path(tmp))
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_fetch_rejects_cross_domain_redirect_before_caching(self):
        body = b'[{"name":"WinterBreak2"}]'
        request_url = "https://kindlemodding.org/jailbreaks.json"

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                return_value=_Response(
                    body,
                    "https://evil.example/jailbreaks.json?token=secret",
                ),
            ):
                with self.assertRaises(ValueError):
                    fetch_official_json(request_url, Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_internal_method_page_allows_canonical_trailing_slash_redirect(self):
        from kindle_jailbreak_lib.routing import (
            fetch_official_source,
            load_cached_source,
        )

        request_url = "https://kindlemodding.org/jailbreaking/Vera"
        final_url = "https://kindlemodding.org/jailbreaking/Vera/"
        body = b"<html><h1>Vera</h1></html>"
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=_Response(body, final_url),
        ):
            snapshot = fetch_official_source(
                request_url,
                Path(tmp),
                source_kind="method_page",
            )

            self.assertEqual(snapshot.request_url, request_url)
            self.assertEqual(snapshot.final_url, final_url)
            self.assertEqual(snapshot.raw_bytes(), body)
            cached = load_cached_source(next(Path(tmp).glob("*.json")))
            self.assertEqual(cached.request_url, request_url)
            self.assertEqual(cached.final_url, final_url)

    def test_redirect_is_validated_before_response_body_is_read(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        request_url = "https://kindlemodding.org/jailbreaking/Vera"
        bad_final_urls = (
            "https://evil.example/jailbreaking/Vera/",
            "http://kindlemodding.org/jailbreaking/Vera/",
            "https://kindlemodding.org/jailbreaking/SpiderCat/",
        )
        for final_url in bad_final_urls:
            with self.subTest(final_url=final_url):
                events = []
                response = _OrderedResponse(b"must-not-read", final_url, events)
                with tempfile.TemporaryDirectory() as tmp, mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=response,
                ):
                    with self.assertRaises(ValueError):
                        fetch_official_source(
                            request_url,
                            Path(tmp),
                            source_kind="method_page",
                        )
                    self.assertEqual(events, ["geturl"])
                    self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_canonical_redirect_does_not_allow_trailing_slash_removal(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        request_url = "https://kindlemodding.org/jailbreaking/Vera/"
        final_url = "https://kindlemodding.org/jailbreaking/Vera"
        events = []
        response = _OrderedResponse(b"must-not-read", final_url, events)
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=response,
        ):
            with self.assertRaises(ValueError):
                fetch_official_source(
                    request_url,
                    Path(tmp),
                    source_kind="method_page",
                )
            self.assertEqual(events, ["geturl"])
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_canonical_redirect_rejects_double_slash_before_body_read(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        cases = (
            (
                "https://kindlemodding.org/jailbreaking/Vera/",
                "https://kindlemodding.org/jailbreaking/Vera//",
            ),
            (
                "https://kindlemodding.org/jailbreaking/Vera//",
                "https://kindlemodding.org/jailbreaking/Vera/",
            ),
            (
                "https://kindlemodding.org/jailbreaking/Vera//",
                "https://kindlemodding.org/jailbreaking/Vera///",
            ),
        )
        for request_url, final_url in cases:
            with self.subTest(request_url=request_url, final_url=final_url):
                events = []
                response = _OrderedResponse(b"must-not-read", final_url, events)
                with tempfile.TemporaryDirectory() as tmp, mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=response,
                ):
                    with self.assertRaises(ValueError):
                        fetch_official_source(
                            request_url,
                            Path(tmp),
                            source_kind="method_page",
                        )
                    self.assertEqual(events, ["geturl"])
                    self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_external_route_preserves_bound_numeric_post_locator(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        route_url = (
            "https://www.mobileread.com/forums/showthread.php?p=4087697"
        )
        body = b"<html><h1>MobileRead post</h1></html>"
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=_Response(body, route_url),
        ):
            snapshot = fetch_official_source(
                route_url,
                Path(tmp),
                source_kind="method_page",
                official_route_url=route_url,
            )

            cache_path = next(Path(tmp).glob("*.json"))
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            self.assertEqual(snapshot.request_url, route_url)
            self.assertEqual(snapshot.final_url, route_url)
            self.assertEqual(snapshot.official_route_url, route_url)
            self.assertEqual(cached["request_url"], route_url)
            self.assertEqual(cached["official_route_url"], route_url)

    def test_external_route_rejects_unbound_or_sensitive_query(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        invalid_urls = (
            "https://www.mobileread.com/forums/showthread.php?p=abc",
            "https://www.mobileread.com/forums/showthread.php?p=1&p=2",
            "https://www.mobileread.com/forums/showthread.php?p=1&x=2",
            "https://www.mobileread.com/forums/showthread.php?token=secret",
            "https://www.mobileread.com/forums/showthread.php?p=1#secret",
            "https://user:secret@www.mobileread.com/forums/"
            "showthread.php?p=1",
        )
        for url in invalid_urls:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmp:
                with mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=_Response(b"unexpected", url),
                ):
                    with self.assertRaises(ValueError):
                        fetch_official_source(
                            url,
                            Path(tmp),
                            source_kind="method_page",
                            official_route_url=url,
                        )
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_external_redirect_must_keep_authority_and_bound_locator(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        route_url = (
            "https://www.mobileread.com/forums/showthread.php?p=4087697"
        )
        invalid_final_urls = (
            "https://www.mobileread.com/forums/showthread.php?p=4087698",
            "https://www.mobileread.com/forums/"
            "showthread.php?p=4087697&token=secret",
            "http://www.mobileread.com/forums/showthread.php?p=4087697",
            "https://evil.example/forums/showthread.php?p=4087697",
        )
        for final_url in invalid_final_urls:
            with self.subTest(final_url=final_url):
                events = []
                response = _OrderedResponse(b"must-not-read", final_url, events)
                with tempfile.TemporaryDirectory() as tmp, mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=response,
                ):
                    with self.assertRaises(ValueError):
                        fetch_official_source(
                            route_url,
                            Path(tmp),
                            source_kind="method_page",
                            official_route_url=route_url,
                        )
                    self.assertEqual(events, ["geturl"])
                    self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_source_fetch_covers_finder_internal_page_and_external_route(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        cases = (
            (
                "finder",
                "https://kindlemodding.org/jailbreakFinder.js",
                b"function versions(a, b) { return 0; }",
                None,
                "kindlemodding",
            ),
            (
                "method_page",
                "https://kindlemodding.org/jailbreaking/WinterBreak2/",
                b"<html><h1>WinterBreak2</h1></html>",
                None,
                "kindlemodding",
            ),
            (
                "method_page",
                "https://www.mobileread.com/forums/"
                "showthread.php?p=4087697",
                b"<html><h1>Android Jailbreak Methods</h1></html>",
                "https://www.mobileread.com/forums/showthread.php?p=4087697",
                "external-route",
            ),
        )

        for kind, url, body, route_url, authority in cases:
            with self.subTest(kind=kind, authority=authority):
                with tempfile.TemporaryDirectory() as tmp, mock.patch(
                    "kindle_jailbreak_lib.routing.urllib.request.urlopen",
                    return_value=_Response(body, url),
                ):
                    snapshot = fetch_official_source(
                        url,
                        Path(tmp),
                        source_kind=kind,
                        official_route_url=route_url,
                        confirmed_sha256=hashlib.sha256(body).hexdigest(),
                    )

                    self.assertEqual(snapshot.source_kind, kind)
                    self.assertEqual(snapshot.authority, authority)
                    self.assertEqual(snapshot.request_url, url)
                    self.assertEqual(snapshot.raw_bytes(), body)
                    self.assertTrue(snapshot.confirmed)
                    self.assertTrue(snapshot.current)
                    self.assertEqual(len(list(Path(tmp).glob("*.json"))), 1)

    def test_source_fetch_rejects_external_page_without_official_route(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        url = "https://www.mobileread.com/forums/showthread.php"
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=_Response(b"external", url),
        ):
            with self.assertRaises(ValueError):
                fetch_official_source(
                    url,
                    Path(tmp),
                    source_kind="method_page",
                )
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_source_fetch_rejects_encoded_path_traversal(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        url = (
            "https://kindlemodding.org/jailbreaking/"
            "%2e%2e/jailbreakFinder.js"
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=_Response(b"unexpected", url),
        ):
            with self.assertRaises(ValueError):
                fetch_official_source(
                    url,
                    Path(tmp),
                    source_kind="method_page",
                )
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_source_fetch_rejects_empty_semantic_source(self):
        from kindle_jailbreak_lib.routing import fetch_official_source

        url = "https://kindlemodding.org/jailbreakFinder.js"
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "kindle_jailbreak_lib.routing.urllib.request.urlopen",
            return_value=_Response(b"", url),
        ):
            with self.assertRaises(ValueError):
                fetch_official_source(
                    url,
                    Path(tmp),
                    source_kind="finder",
                )
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()

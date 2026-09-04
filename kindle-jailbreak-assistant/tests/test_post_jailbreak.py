"""后越狱证据与 KOReader 包选择的纯本地回归测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kindle_jailbreak_lib.models import DeviceInfo
from kindle_jailbreak_lib.storage import (
    choose_koreader_package,
    verify_jailbreak,
    verify_koreader_files,
)


OFFICIAL_RULE_FIXTURE = {
    "schema_version": 1,
    "packages": [
        {
            "name": "PW3 current official KPM",
            "models": ["PW3"],
            "firmware": {"min": "5.16.0", "max": "5.16.99"},
            "asset_family": "kindlepw2",
            "kpm": {"supported": True, "integrity_verified": True},
            "manual": {"supported": True, "integrity_verified": True},
        },
        {
            "name": "modern manual fallback",
            "models": ["PW4"],
            "firmware": {"min": "5.16.0", "max": "5.16.99"},
            "asset_family": "kindlepw2",
            "kpm": {"supported": False, "integrity_verified": False},
            "manual": {"supported": True, "integrity_verified": True},
        },
        {
            "name": "legacy official package",
            "models": ["K2"],
            "firmware": {"min": "2.5.0", "max": "2.5.99"},
            "asset_family": "kindlek2",
            "kpm": {"supported": False, "integrity_verified": False},
            "manual": {"supported": True, "integrity_verified": True},
        },
    ],
}


def _device(model: str | None, firmware: str | None) -> DeviceInfo:
    return DeviceInfo(
        transport="usbms",
        root="/tmp/Kindle",
        serial=None,
        model=model,
        firmware=firmware,
        read_only=False,
        free_bytes=2_000_000_000,
    )


class PostJailbreakTest(unittest.TestCase):
    def test_modern_device_prefers_verified_kpm(self):
        choice = choose_koreader_package(_device("PW3", "5.16.2.1.1"), OFFICIAL_RULE_FIXTURE)

        self.assertEqual(choice.asset_family, "kindlepw2")
        self.assertEqual(choice.install_method, "kpm")
        self.assertFalse(choice.manual_fallback)
        self.assertEqual(choice.source_rule, "PW3 current official KPM")

    def test_manual_fallback_and_legacy_package_follow_official_rule(self):
        fallback = choose_koreader_package(_device("PW4", "5.16.2.1.1"), OFFICIAL_RULE_FIXTURE)
        legacy = choose_koreader_package(_device("K2", "2.5.8"), OFFICIAL_RULE_FIXTURE)

        self.assertEqual(fallback.install_method, "manual")
        self.assertTrue(fallback.manual_fallback)
        self.assertEqual(legacy.asset_family, "kindlek2")
        self.assertEqual(legacy.install_method, "manual")

    def test_pw3_uses_kindlepw2_and_requires_visible_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / ".adds" / "koreader").mkdir(parents=True)

            choice = choose_koreader_package(
                _device("PW3", "5.16.2.1.1"), OFFICIAL_RULE_FIXTURE
            )
            files_only = verify_koreader_files(
                kindle_root, user_visible_launch=False
            )

            self.assertEqual(choice.asset_family, "kindlepw2")
            self.assertFalse(files_only.complete)
            self.assertEqual(files_only.missing_evidence, ["user_visible_launch"])

    def test_unknown_or_unmatched_official_data_refuses_to_guess_package(self):
        cases = (
            (_device(None, "5.16.2.1.1"), OFFICIAL_RULE_FIXTURE),
            (_device("PW3", None), OFFICIAL_RULE_FIXTURE),
            (_device("PW3", "5.16.2.1.1"), {}),
            (_device("PW3", "5.18.0"), OFFICIAL_RULE_FIXTURE),
        )

        for device, rules in cases:
            with self.subTest(device=device, rules=rules):
                with self.assertRaises(ValueError):
                    choose_koreader_package(device, rules)

    def test_overlapping_official_rules_with_different_effective_packages_fail_closed(self):
        conflicting_rules = {
            "schema_version": 1,
            "packages": [
                OFFICIAL_RULE_FIXTURE["packages"][0],
                {
                    "name": "conflicting overlapping manual package",
                    "models": ["PW3"],
                    "firmware": {"min": "5.16.0", "max": "5.16.99"},
                    "asset_family": "kindlek2",
                    "kpm": {"supported": False, "integrity_verified": False},
                    "manual": {"supported": True, "integrity_verified": True},
                },
            ],
        }

        with self.assertRaisesRegex(ValueError, "冲突"):
            choose_koreader_package(
                _device("PW3", "5.16.2.1.1"), conflicting_rules
            )

    def test_identical_overlapping_official_rules_are_accepted(self):
        duplicate_rules = {
            "schema_version": 1,
            "packages": [
                OFFICIAL_RULE_FIXTURE["packages"][0],
                OFFICIAL_RULE_FIXTURE["packages"][0],
            ],
        }

        choice = choose_koreader_package(
            _device("PW3", "5.16.2.1.1"), duplicate_rules
        )

        self.assertEqual(choice.asset_family, "kindlepw2")
        self.assertEqual(choice.install_method, "kpm")
        self.assertFalse(choice.manual_fallback)

    def test_jailbreak_requires_marker_or_explicit_equivalent_user_log_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / "documents").mkdir(parents=True)
            (kindle_root / "documents" / "script-output.txt").write_text(
                "Application Error", encoding="utf-8"
            )
            before = sorted(path.relative_to(kindle_root).as_posix() for path in kindle_root.rglob("*"))

            missing = verify_jailbreak(kindle_root)
            via_log = verify_jailbreak(kindle_root, user_log_evidence=True)
            after_log = sorted(path.relative_to(kindle_root).as_posix() for path in kindle_root.rglob("*"))
            (kindle_root / "documents" / "JAILBROKEN.txt").write_text("ok", encoding="utf-8")
            before_marker = sorted(path.relative_to(kindle_root).as_posix() for path in kindle_root.rglob("*"))
            marker = verify_jailbreak(
                kindle_root, equivalent_markers=("documents/JAILBROKEN.txt",)
            )
            after = sorted(path.relative_to(kindle_root).as_posix() for path in kindle_root.rglob("*"))

            self.assertFalse(missing.complete)
            self.assertEqual(missing.missing_evidence, ["jailbreak_marker"])
            self.assertTrue(via_log.complete)
            self.assertTrue(marker.complete)
            self.assertEqual(before, after_log)
            self.assertEqual(before_marker, after)

    def test_jailbreak_does_not_accept_default_marker_unless_method_allows_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / "documents").mkdir(parents=True)
            (kindle_root / "documents" / "JAILBROKEN.txt").write_text(
                "old marker", encoding="utf-8"
            )

            result = verify_jailbreak(
                kindle_root,
                equivalent_markers=("documents/CUSTOM-JB.txt",),
            )

            self.assertFalse(result.complete)
            self.assertEqual(result.missing_evidence, ["jailbreak_marker"])

    def test_jailbreak_rejects_a_marker_present_before_this_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / "documents").mkdir(parents=True)
            (kindle_root / "documents" / "JAILBROKEN.txt").write_text(
                "old marker", encoding="utf-8"
            )

            result = verify_jailbreak(
                kindle_root, excluded_markers=("documents/JAILBROKEN.txt",)
            )

            self.assertFalse(result.complete)
            self.assertEqual(result.missing_evidence, ["jailbreak_marker"])

    def test_koreader_verification_is_read_only_and_needs_files_and_visible_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / "documents").mkdir(parents=True)
            before = {
                path.relative_to(kindle_root).as_posix(): path.read_bytes()
                for path in kindle_root.rglob("*") if path.is_file()
            }

            missing = verify_koreader_files(kindle_root, user_visible_launch=True)
            (kindle_root / "koreader").mkdir()
            files_only = verify_koreader_files(kindle_root, user_visible_launch=False)
            complete = verify_koreader_files(kindle_root, user_visible_launch=True)
            after = {
                path.relative_to(kindle_root).as_posix(): path.read_bytes()
                for path in kindle_root.rglob("*") if path.is_file()
            }

            self.assertEqual(missing.missing_evidence, ["koreader_files"])
            self.assertEqual(files_only.missing_evidence, ["user_visible_launch"])
            self.assertTrue(complete.complete)
            self.assertEqual(before, after)

    def test_optional_miuread_is_not_downloaded_or_counted_by_local_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            kindle_root = Path(tmp) / "Kindle"
            (kindle_root / ".adds" / "koreader").mkdir(parents=True)

            result = verify_koreader_files(kindle_root, user_visible_launch=True)

            self.assertTrue(result.complete)
            self.assertFalse((kindle_root / ".adds" / "miuread").exists())
            self.assertNotIn("miuread", result.observed_evidence)


if __name__ == "__main__":
    unittest.main()

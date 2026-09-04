import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from kindle_jailbreak import (
    CLIError,
    _bound_device,
    _download_payload,
    _payload_url_allowed,
    _device_probe,
    _probe_one,
    _storage_exit_code,
    _test_storage_limits,
    main,
)
from kindle_jailbreak_lib.models import DeviceInfo, Stage
from kindle_jailbreak_lib.session import SessionStore


PROJECT = Path(__file__).resolve().parents[1]
CLI = PROJECT / "scripts" / "kindle_jailbreak.py"
FIXTURES = PROJECT / "tests" / "fixtures"
MIB = 1024 * 1024


class CLITest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.kindle = self.base / "kindle"
        (self.kindle / "documents").mkdir(parents=True)
        (self.kindle / "system").mkdir()
        (self.kindle / "system" / "version.txt").write_text(
            "Kindle 5.16.2.1.1 (fixture)\n", encoding="utf-8"
        )
        self.session_dir = self.base / "session"
        self.device_fixture = self.base / "device.json"
        self.source_fixture = self.base / "sources"
        self.full_serial = "G090KB0TESTX05TK"
        self.extra_environment = {}
        self.default_include_device = True
        self._write_device_fixture()
        self._write_source_fixture()

    def _device(self, *, serial=None, root=None, read_only=False, firmware=None):
        return DeviceInfo(
            transport="usbms",
            root=str(self.kindle if root is None else root),
            serial=self.full_serial if serial is None else serial,
            model="PW3",
            firmware="5.16.2.1.1" if firmware is None else firmware,
            read_only=read_only,
            free_bytes=256 * MIB,
        )

    def _write_device_fixture(
        self,
        *,
        serial=None,
        root=None,
        read_only=False,
        firmware=None,
        free_bytes=256 * MIB,
        available=True,
        disconnect_after=None,
    ):
        device = self._device(
            serial=serial,
            root=root,
            read_only=read_only,
            firmware=firmware,
        )
        payload = {
            "transport": device.transport,
            "root": device.root,
            "serial": device.serial,
            "model": device.model,
            "firmware": device.firmware,
            "read_only": device.read_only,
            "free_bytes": free_bytes,
        }
        if not available:
            payload["available"] = False
        if disconnect_after is not None:
            payload["disconnect_after"] = disconnect_after
        self.device_fixture.write_text(json.dumps(payload), encoding="utf-8")

    def _write_source_fixture(self, *, models=None, jailbreaks=None):
        self.source_fixture.mkdir(exist_ok=True)
        if models is None:
            models = json.loads((FIXTURES / "models.json").read_text(encoding="utf-8"))
        if jailbreaks is None:
            jailbreaks = json.loads(
                (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
            )
        (self.source_fixture / "models.json").write_text(
            json.dumps(models, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        (self.source_fixture / "jailbreaks.json").write_text(
            json.dumps(jailbreaks, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        (self.source_fixture / "jailbreakFinder.js").write_text(
            "const fixtureRoutingSemantics = true;\n", encoding="utf-8"
        )
        (self.source_fixture / "method-page.html").write_text(
            '<html><a href="https://github.com/example/kindle-release.zip">Release</a> '
            '成功标记 documents/JAILBROKEN.txt；成功证据 ;log。</html>\n',
            encoding="utf-8",
        )

    def _source_arguments(self):
        return ("--source-fixture-dir", str(self.source_fixture))

    def _confirmation_arguments(self, review_event):
        arguments = []
        for name in ("models", "jailbreaks", "finder", "method_page"):
            arguments.extend((
                "--confirm-source",
                f"{name}={review_event['source_hashes'][name]}",
            ))
        return tuple(arguments)

    def _run(
        self,
        *arguments,
        include_device=None,
        json_mode=True,
        test_mode=True,
        include_device_fixture=True,
        extra_environment=None,
    ):
        command = [
            sys.executable,
            str(CLI),
            "--session-dir",
            str(self.session_dir),
        ]
        if include_device is None:
            include_device = self.default_include_device
        if include_device:
            command.extend(["--device-root", str(self.kindle)])
        if json_mode:
            command.append("--json")
        command.extend(arguments)
        environment = os.environ.copy()
        if test_mode:
            environment["KJA_TEST_MODE"] = "1"
        else:
            environment.pop("KJA_TEST_MODE", None)
        if include_device_fixture:
            environment["KJA_TEST_DEVICE_FIXTURE"] = str(self.device_fixture)
        else:
            environment.pop("KJA_TEST_DEVICE_FIXTURE", None)
        environment["KJA_TEST_FILL_CHUNK_BYTES"] = "4096"
        if extra_environment is not None:
            environment.update(extra_environment)
        environment.update(self.extra_environment)
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def _use_mtp_fixture(self):
        adapter = self.base / "mtp_adapter.py"
        shutil.copy2(FIXTURES / "mtp_adapter.py", adapter)
        adapter.chmod(0o700)
        mtp_fixture = self.base / "mtp.json"
        mtp_fixture.write_text(json.dumps({
            "id": "0123456789abcdef01234567",
            "root": str(self.kindle),
            "name": "Kindle Paperwhite 3",
            "device_code": "0KB",
            "firmware": "5.16.2.1.1",
            "free_bytes": 80 * MIB + 4096,
            "available": True,
        }), encoding="utf-8")
        self.device_fixture.write_text(json.dumps({
            "transport": "mtp",
            "root": None,
            "serial": None,
            "transport_id": "0123456789abcdef01234567",
            "device_code": "0KB",
            "model": "PW3",
            "firmware": "5.16.2.1.1",
            "read_only": False,
            "free_bytes": 80 * MIB + 4096,
        }), encoding="utf-8")
        self.extra_environment.update({
            "KJA_TEST_MTP_ADAPTER": str(adapter),
            "KJA_MTP_FIXTURE_PATH": str(mtp_fixture),
        })
        self.default_include_device = False
        return mtp_fixture

    def _mtp_prepare_for_assets(self):
        mtp_fixture = self._use_mtp_fixture()
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        self._write_source_fixture(
            jailbreaks=[route for route in jailbreaks if route["name"] == "WinterBreak"]
        )
        store = self._backup_to_prepare("WinterBreak")
        state = store.load()
        state.evidence["fill_complete"] = True
        store.save(state)
        return store, mtp_fixture

    def _events(self, result):
        events = []
        for line in result.stdout.splitlines():
            if line.startswith("KJA_EVENT "):
                events.append(json.loads(line.removeprefix("KJA_EVENT ")))
        return events

    def _probe_then_review_route(self, *, registered="unknown"):
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        ota = self._ota_check()
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        review = self._run(
            "route",
            *self._source_arguments(),
            "--registered", registered,
        )
        self.assertEqual(review.returncode, 23, review.stdout + review.stderr)
        event = next(
            item for item in self._events(review)
            if item["event"] == "source_review_required"
        )
        return event

    def _confirm_route(
        self,
        *,
        registered="unknown",
        acknowledge_risk=True,
        evidence_marker="documents/JAILBROKEN.txt",
        confirm_log=True,
    ):
        review = self._probe_then_review_route(registered=registered)
        arguments = [
            "route",
            *self._source_arguments(),
            *self._confirmation_arguments(review),
            "--registered", registered,
        ]
        if acknowledge_risk:
            arguments.append("--acknowledge-risk")
        if evidence_marker is not None:
            arguments.extend(["--confirm-method-marker-rule", evidence_marker])
        if confirm_log:
            arguments.append("--confirm-method-log-rule")
        result = self._run(*arguments)
        return result, review

    def _ota_check(self, *, prevention_status=None):
        arguments = ["ota-check", "--offline-confirmed-by-user"]
        if prevention_status is not None:
            arguments.extend(["--prevention-status", prevention_status])
        return self._run(*arguments)

    def _authorize(self, operation):
        ota = self._ota_check(prevention_status="verified")
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        result = self._run(
            "authorize-write", "--operation", operation, "--confirmed-by-user"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def _make_session(self, stage, *, authorized=True, device=None):
        store = SessionStore(self.session_dir)
        state = store.create(self._device() if device is None else device)
        main_path = [
            Stage.RISK_ACK,
            Stage.ROUTE,
            Stage.BACKUP,
            Stage.PREPARE,
            Stage.WAIT_USER_EXPLOIT,
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
            Stage.VERIFY_KOREADER,
            Stage.CLEANUP,
        ]
        if stage == Stage.WAIT_RECONNECT:
            for next_stage in main_path[:3]:
                state.transition(next_stage)
            state.transition(Stage.WAIT_RECONNECT)
        elif stage != Stage.DISCOVER:
            for next_stage in main_path:
                state.transition(next_stage)
                if next_stage == stage:
                    break
        if authorized:
            state.approvals["write_authorization"] = True
        store.save(state)
        return store

    def _route_to_backup(
        self,
        method="WinterBreak2",
        *,
        method_page=None,
        evidence_marker="documents/JAILBROKEN.txt",
        confirm_log=True,
    ):
        if method not in {"WinterBreak", "WinterBreak2"}:
            if evidence_marker == "documents/JAILBROKEN.txt":
                evidence_marker = None
            confirm_log = False
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        selected = [route for route in jailbreaks if route["name"] == method]
        self.assertEqual(len(selected), 1)
        self._write_source_fixture(jailbreaks=selected)
        if method_page is not None:
            (self.source_fixture / "method-page.html").write_text(
                method_page, encoding="utf-8"
            )
        if method == "SpringBreak":
            self._write_device_fixture(firmware="5.16.4")
        result, _review = self._confirm_route(
            registered="yes",
            evidence_marker=evidence_marker,
            confirm_log=confirm_log,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        store = SessionStore(self.session_dir)
        state = store.load()
        self.assertEqual(state.stage, Stage.BACKUP)
        route = state.route
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route["policy_name"], method)
        return store

    def _backup_to_prepare(
        self,
        method="WinterBreak2",
        *,
        method_page=None,
        evidence_marker="documents/JAILBROKEN.txt",
        confirm_log=True,
    ):
        store = self._route_to_backup(
            method,
            method_page=method_page,
            evidence_marker=evidence_marker,
            confirm_log=confirm_log,
        )
        result = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "helper-backup"),
            "--timestamp", "20260903T110000Z",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(store.load().stage, Stage.PREPARE)
        return store

    def _record_payload(self, archive, *, purpose="jailbreak"):
        digest = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
        result = self._run(
            "record-payload", "--archive", str(archive),
            "--final-url", "https://github.com/example/kindle-release.zip",
            "--release-version", "fixture-1", "--expected-sha256", digest,
            "--purpose", purpose,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_help_lists_public_commands_without_internal_class_names(self):
        result = subprocess.run(
            [sys.executable, str(CLI), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "probe", "ota-check", "route", "backup", "authorize-write",
            "record-payload", "fetch-payload", "confirm-koreader-package",
            "fill", "stage", "verify", "checkpoint", "cleanup",
            "status", "resume", "self-test",
        ):
            self.assertIn(command, result.stdout)
        self.assertNotIn("SessionState", result.stdout)
        self.assertNotIn("DeviceInfo", result.stdout)

    def test_payload_downloader_hashes_the_bytes_returned_by_the_authorized_url(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://release-assets.githubusercontent.com/asset.zip?sig=redacted"

        destination = self.base / "downloaded.archive"
        with mock.patch(
            "kindle_jailbreak.urllib.request.urlopen",
            return_value=Response(b"downloaded upstream bytes"),
        ):
            final_url, size, digest = _download_payload(
                "https://github.com/example/releases/download/v1/asset.zip",
                destination,
            )

        self.assertEqual(
            final_url,
            "https://release-assets.githubusercontent.com/asset.zip?sig=redacted",
        )
        self.assertEqual(size, 25)
        self.assertEqual(digest, hashlib.sha256(b"downloaded upstream bytes").hexdigest())
        self.assertEqual(destination.read_bytes(), b"downloaded upstream bytes")

    def test_payload_downloader_rejects_unrelated_same_host_redirect(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://github.com/unrelated/repo/releases/download/wrong/other.zip"

        destination = self.base / "redirected.archive"
        with mock.patch(
            "kindle_jailbreak.urllib.request.urlopen",
            return_value=Response(b"unrelated bytes"),
        ):
            with self.assertRaisesRegex(CLIError, "重定向"):
                _download_payload(
                    "https://github.com/example/repo/releases/download/v1.0/asset.zip",
                    destination,
                )
        self.assertFalse(destination.exists())

    def test_archive_and_payload_validation_codes_map_to_verification_failure(self):
        validation_codes = (
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
        )
        for code in validation_codes:
            with self.subTest(code=code):
                self.assertEqual(_storage_exit_code(code), 24)

        self.assertEqual(_storage_exit_code("KJA_WRITE_NOT_AUTHORIZED"), 20)
        self.assertEqual(_storage_exit_code("KJA_DEVICE_MISMATCH"), 21)
        self.assertEqual(_storage_exit_code("KJA_DEVICE_UNAVAILABLE"), 23)

    def test_probe_output_is_structured_and_redacted(self):
        result = self._run("probe")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('KJA_EVENT {"event":"device_detected"', result.stdout)
        self.assertNotIn(self.full_serial, result.stdout + result.stderr)
        event = self._events(result)[0]
        self.assertEqual(event["device"]["serial_suffix"], "05TK")
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.RISK_ACK)
        risk_events = [
            item for item in self._events(result)
            if item["event"] == "risk_ack_required"
        ]
        self.assertTrue(risk_events, result.stdout)
        risk = risk_events[0]
        self.assertEqual(len(risk["risks"]), 4)
        self.assertIn("非官方修改", risk["risks"][0])
        self.assertIn("不是完整系统镜像", risk["risks"][1])
        self.assertIn("不承担", risk["risks"][2])
        self.assertIn("随时停止", risk["risks"][3])

    def test_probe_human_output_prints_every_disclaimer_item(self):
        result = self._run("probe", json_mode=False)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for phrase in (
            "非官方修改",
            "不是完整系统镜像",
            "不承担",
            "随时停止",
        ):
            self.assertIn(phrase, result.stdout)

    def test_route_requires_four_source_review_then_exact_confirmation(self):
        review = self._probe_then_review_route()
        expected_hashes = {
            "models": hashlib.sha256(
                (self.source_fixture / "models.json").read_bytes()
            ).hexdigest(),
            "jailbreaks": hashlib.sha256(
                (self.source_fixture / "jailbreaks.json").read_bytes()
            ).hexdigest(),
            "finder": hashlib.sha256(
                (self.source_fixture / "jailbreakFinder.js").read_bytes()
            ).hexdigest(),
            "method_page": hashlib.sha256(
                (self.source_fixture / "method-page.html").read_bytes()
            ).hexdigest(),
        }
        self.assertEqual(review["source_hashes"], expected_hashes)
        self.assertEqual(set(review["cache_paths"]), set(expected_hashes))
        waiting = SessionStore(self.session_dir).load()
        self.assertEqual(waiting.stage, Stage.RISK_ACK)
        self.assertIsNone(waiting.route)
        review_evidence = waiting.evidence["source_review"]
        self.assertIsInstance(review_evidence, dict)
        assert isinstance(review_evidence, dict)
        self.assertEqual(review_evidence["source_hashes"], expected_hashes)
        self.assertEqual(review_evidence.get("source_mode"), "isolated_fixture")
        test_device_identity = review_evidence.get("test_device_identity")
        self.assertIsInstance(test_device_identity, str)
        assert isinstance(test_device_identity, str)
        self.assertRegex(test_device_identity, r"^[0-9a-f]{64}$")

        confirmed = self._run(
            "route",
            *self._source_arguments(),
            *self._confirmation_arguments(review),
            "--acknowledge-risk",
            "--confirm-method-marker-rule", "documents/JAILBROKEN.txt",
            "--confirm-method-log-rule",
        )

        self.assertEqual(confirmed.returncode, 0, confirmed.stdout + confirmed.stderr)
        state = SessionStore(self.session_dir).load()
        self.assertEqual(state.stage, Stage.BACKUP)
        route = state.route
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route["policy_name"], "WinterBreak2")
        self.assertEqual(route.get("source_mode"), "isolated_fixture")
        self.assertEqual(
            route.get("test_device_identity"),
            test_device_identity,
        )
        self.assertIs(state.approvals["risk_acknowledged"], True)
        self.assertFalse(any(name.startswith("write_once:") for name in state.approvals))

    def test_local_source_fixture_cannot_be_combined_with_apply(self):
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        ota = self._ota_check()
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)

        result = self._run("--apply", "route", *self._source_arguments())

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_FIXTURE_APPLY")
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.RISK_ACK)

    def test_route_requires_a_current_pre_route_ota_check(self):
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)

        result = self._run("route", *self._source_arguments())

        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_CHECK_REQUIRED")
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.RISK_ACK)

    def test_ota_check_blocks_unknown_upgrade_files_without_deleting_them(self):
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        unknown = self.kindle / "update-kindle-5.99.bin"
        partial = self.kindle / "update.tmp.partial"
        unknown.write_bytes(b"unknown firmware")
        partial.write_bytes(b"partial")

        result = self._ota_check()

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_UNKNOWN_PACKAGE")
        self.assertTrue(unknown.is_file())
        self.assertTrue(partial.is_file())
        state = SessionStore(self.session_dir).load()
        self.assertNotIn("ota_gate", state.evidence)

    def test_source_fixture_without_device_fixture_never_falls_back_to_host_probe(self):
        store = self._make_session(Stage.RISK_ACK)

        result = self._run(
            "route",
            *self._source_arguments(),
            include_device_fixture=False,
            extra_environment={"PATH": ""},
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(
            self._events(result)[-1]["code"],
            "KJA_FIXTURE_DEVICE_REQUIRED",
        )
        self.assertEqual(store.load().stage, Stage.RISK_ACK)

    def test_fixture_session_rejects_a_different_device_fixture_on_later_apply(self):
        store = self._route_to_backup()
        different_fixture = self.base / "different-device-fixture.json"
        different_fixture.write_bytes(self.device_fixture.read_bytes())
        self.device_fixture = different_fixture
        backup_parent = self.base / "wrong-fixture-backup"

        result = self._run(
            "--apply", "backup", "--backup-dir", str(backup_parent)
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_FIXTURE_SESSION")
        self.assertEqual(store.load().stage, Stage.BACKUP)
        self.assertFalse(backup_parent.exists())

    def test_fixture_session_cannot_apply_without_explicit_test_mode(self):
        store = self._route_to_backup()
        backup_parent = self.base / "real-probe-backup"

        result = self._run(
            "--apply", "backup", "--backup-dir", str(backup_parent),
            test_mode=False,
            include_device_fixture=False,
            extra_environment={"PATH": ""},
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_FIXTURE_SESSION")
        self.assertEqual(store.load().stage, Stage.BACKUP)
        self.assertFalse(backup_parent.exists())

    def test_fixture_review_evidence_keeps_apply_fail_closed_if_route_mode_is_missing(self):
        store = self._route_to_backup()
        state = store.load()
        route = state.route
        self.assertIsNotNone(route)
        assert route is not None
        route.pop("source_mode")
        store.save(state)
        backup_parent = self.base / "missing-route-mode-backup"

        result = self._run(
            "--apply", "backup", "--backup-dir", str(backup_parent),
            test_mode=False,
            include_device_fixture=False,
            extra_environment={"PATH": ""},
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_FIXTURE_SESSION")
        self.assertEqual(store.load().stage, Stage.BACKUP)
        self.assertFalse(backup_parent.exists())

    def test_route_stays_in_review_when_one_confirmation_is_wrong(self):
        review = self._probe_then_review_route()
        confirmations = list(self._confirmation_arguments(review))
        finder_value = confirmations.index(
            f"finder={review['source_hashes']['finder']}"
        )
        confirmations[finder_value] = f"finder={'0' * 64}"

        result = self._run(
            "route",
            *self._source_arguments(),
            *confirmations,
            "--acknowledge-risk",
        )

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        state = SessionStore(self.session_dir).load()
        self.assertEqual(state.stage, Stage.RISK_ACK)
        self.assertIsNone(state.route)
        self.assertNotIn("risk_acknowledged", state.approvals)
        self.assertFalse(any(name.startswith("write_once:") for name in state.approvals))

    def test_route_rejects_the_removed_preapproval_flag(self):
        review = self._probe_then_review_route()

        result = self._run(
            "route",
            *self._source_arguments(),
            *self._confirmation_arguments(review),
            "--approve-write",
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        state = SessionStore(self.session_dir).load()
        self.assertEqual(state.stage, Stage.RISK_ACK)
        self.assertIsNot(state.approvals.get("risk_acknowledged"), True)
        self.assertFalse(any(name.startswith("write_once:") for name in state.approvals))

    def test_risk_ack_can_advance_route_without_granting_write_authorization(self):
        result, _review = self._confirm_route()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = SessionStore(self.session_dir).load()
        self.assertEqual(state.stage, Stage.BACKUP)
        self.assertIs(state.approvals["risk_acknowledged"], True)
        self.assertFalse(any(name.startswith("write_once:") for name in state.approvals))

    def test_default_dry_run_never_writes_or_invents_a_percentage(self):
        store = self._backup_to_prepare()

        result = self._run("fill")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))
        progress = next(event for event in self._events(result) if event["event"] == "progress")
        self.assertEqual(progress["done"], 0)
        self.assertNotIn("total", progress)
        self.assertNotIn("percent", progress)
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_route_without_structured_success_evidence_stays_read_only(self):
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        self._write_source_fixture(
            jailbreaks=[route for route in jailbreaks if route["name"] == "SpringBreak"]
        )
        self._write_device_fixture(firmware="5.16.4")

        result, _review = self._confirm_route(
            registered="yes", evidence_marker=None, confirm_log=False
        )

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))
        self.assertEqual(
            self._events(result)[-1]["event"], "evidence_rule_review_required"
        )
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.RISK_ACK)

    def test_backup_is_read_only_and_does_not_require_write_authorization(self):
        self._route_to_backup()

        backup_parent = self.base / "read-only-backup"
        result = self._run(
            "--apply", "backup", "--backup-dir", str(backup_parent),
            "--timestamp", "20260903T101500Z",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((backup_parent / "20260903T101500Z" / "manifest.json").is_file())

    def test_write_authorization_is_unavailable_before_backup_and_consumed_once(self):
        store = self._route_to_backup("WinterBreak")

        early = self._run(
            "authorize-write", "--operation", "fill", "--confirmed-by-user"
        )
        self.assertEqual(early.returncode, 21, early.stdout + early.stderr)
        self.assertEqual(self._events(early)[-1]["code"], "KJA_STATE_CONFLICT")

        backup = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "auth-backup"),
            "--timestamp", "20260903T101600Z",
        )
        self.assertEqual(backup.returncode, 0, backup.stdout + backup.stderr)
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)

        first = self._run("--apply", "fill")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self._run("--apply", "fill")

        self.assertEqual(second.returncode, 20, second.stdout + second.stderr)
        self.assertEqual(self._events(second)[-1]["code"], "KJA_WRITE_NOT_AUTHORIZED")
        self.assertFalse(any(name.startswith("write_once:") for name in store.load().approvals))

    def test_device_write_requires_a_post_route_ota_gate(self):
        store = self._backup_to_prepare("WinterBreak")
        authorized = self._run(
            "authorize-write", "--operation", "fill", "--confirmed-by-user"
        )
        self.assertEqual(authorized.returncode, 0, authorized.stdout + authorized.stderr)
        self._write_device_fixture(free_bytes=80 * MIB + 4096)

        result = self._run("--apply", "fill")

        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_CHECK_REQUIRED")
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))
        self.assertTrue(any(name.startswith("write_once:") for name in store.load().approvals))

    def test_device_write_rescans_for_unknown_ota_package_after_the_gate(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        unknown = self.kindle / "arrived-after-check.bin"
        unknown.write_bytes(b"unknown update")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)

        result = self._run("--apply", "fill")

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_UNKNOWN_PACKAGE")
        self.assertTrue(unknown.is_file())
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))
        self.assertTrue(any(name.startswith("write_once:") for name in store.load().approvals))

    def test_ota_check_rejects_a_session_bin_replaced_after_staging(self):
        self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "known-update.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("known-update.bin", b"known payload")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "known-update.bin",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        (self.kindle / "known-update.bin").write_bytes(b"replaced update")

        result = self._ota_check(prevention_status="verified")

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_UNKNOWN_PACKAGE")
        self.assertEqual((self.kindle / "known-update.bin").read_bytes(), b"replaced update")

    def test_ota_check_does_not_trust_created_file_journal_from_other_session(self):
        self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "foreign-journal.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("known-update.bin", b"known payload")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "known-update.bin",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        journal_path = self.session_dir / "created-files.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["session_id"] = "different-session"
        journal_path.write_text(json.dumps(journal), encoding="utf-8")

        result = self._ota_check(prevention_status="verified")

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_OTA_UNKNOWN_PACKAGE")
        self.assertTrue((self.kindle / "known-update.bin").is_file())

    def test_write_authorization_cannot_be_replayed_after_route_context_changes(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        state = store.load()
        assert state.route is not None
        state.route["source_hashes"] = dict(state.route["source_hashes"])
        state.route["source_hashes"]["models"] = "0" * 64
        store.save(state)
        ota = self._ota_check(prevention_status="verified")
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        self._write_device_fixture(free_bytes=80 * MIB + 4096)

        result = self._run("--apply", "fill")

        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_WRITE_NOT_AUTHORIZED")
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))

    def test_stage_cannot_skip_backup_or_prepare_state(self):
        self._route_to_backup("WinterBreak")
        archive = self.base / "payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"official fixture")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertFalse((self.kindle / "payload.bin").exists())
        self.assertEqual(self._events(result)[-1]["code"], "KJA_STATE_CONFLICT")

    def test_stage_requires_a_route_bound_payload_record(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "unrecorded-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"unrecorded official fixture")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(
            self._events(result)[-1]["code"], "KJA_PAYLOAD_RECORD_REQUIRED"
        )
        self.assertFalse((self.kindle / "payload.bin").exists())
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_payload_record_rejects_a_url_missing_from_confirmed_method_page(self):
        store = self._backup_to_prepare("WinterBreak")
        archive = self.base / "wrong-source.zip"
        archive.write_bytes(b"fixture payload")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        result = self._run(
            "record-payload", "--archive", str(archive),
            "--final-url", "https://example.invalid/not-in-method-page.zip",
            "--release-version", "fixture-1", "--expected-sha256", digest,
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_PAYLOAD_SOURCE")
        self.assertNotIn("payload_records", store.load().evidence)

    def test_payload_record_uses_exact_links_not_url_substrings(self):
        store = self._backup_to_prepare(
            "WinterBreak",
            method_page=(
                '<html><a href="https://github.com/example/kindle-release.zip.extra">'
                'Release</a> success marker documents/JAILBROKEN.txt</html>\n'
            ),
            confirm_log=False,
        )
        archive = self.base / "substring-payload.zip"
        archive.write_bytes(b"fixture")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        result = self._run(
            "record-payload", "--archive", str(archive),
            "--final-url", "https://github.com/example/kindle-release.zip",
            "--release-version", "fixture-1", "--expected-sha256", digest,
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_PAYLOAD_SOURCE")
        self.assertNotIn("payload_records", store.load().evidence)

    def test_payload_url_requires_exact_release_tag_and_exact_koreader_asset_link(self):
        jailbreak_url = "https://github.com/example/repo/releases/download/v1.0/payload-v1.0.zip"
        koreader_url = (
            "https://github.com/koreader/koreader/releases/download/"
            "v2026.07/koreader-kindlepw2-v2026.07.zip"
        )
        wrong_koreader_url = (
            "https://github.com/koreader/koreader/releases/download/"
            "v2026.07/koreader-kindle-legacy-v2026.07.zip"
        )
        store = self._backup_to_prepare(
            "WinterBreak",
            method_page=(
                f'<html><a href="{jailbreak_url}">payload</a>'
                f'<a href="{koreader_url}">KOReader PW2</a>'
                f'<a href="{wrong_koreader_url}">KOReader legacy</a>'
                ' success marker documents/JAILBROKEN.txt</html>\n'
            ),
            confirm_log=False,
        )
        state = store.load()
        state.evidence["koreader_package_choice"] = {
            "device_fingerprint": state.device_fingerprint,
            "model": state.device_public["model"],
            "firmware": state.device_public["firmware"],
            "asset_family": "kindlepw2",
        }
        store.save(state)

        self.assertFalse(_payload_url_allowed(state, jailbreak_url, "jailbreak", "/"))
        self.assertTrue(_payload_url_allowed(state, jailbreak_url, "jailbreak", "v1.0"))
        self.assertTrue(_payload_url_allowed(state, koreader_url, "koreader", "v2026.07"))
        self.assertFalse(
            _payload_url_allowed(state, wrong_koreader_url, "koreader", "v2026.07")
        )

    def test_koreader_stage_rejects_payload_record_from_previous_package_choice(self):
        store = self._backup_to_prepare("WinterBreak")
        state = store.load()
        state.evidence["fill_complete"] = True
        for stage in (
            Stage.WAIT_USER_EXPLOIT,
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
        ):
            state.transition(stage)
        old_choice = {
            "device_fingerprint": state.device_fingerprint,
            "model": state.device_public["model"],
            "firmware": state.device_public["firmware"],
            "asset_family": "kindle-legacy",
            "source_url": "https://github.com/koreader/koreader/wiki/Installation-on-Kindle-devices",
            "source_sha256": "1" * 64,
        }
        state.evidence["koreader_package_choice"] = old_choice
        archive = self.base / "old-koreader.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(".adds/koreader/reader.lua", b"return true")
        size = archive.stat().st_size
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        assert state.route is not None
        method_digest = state.route["source_hashes"]["method_page"]
        state.evidence["payload_records"] = {
            "koreader": {
                "route_name": state.route["name"],
                "source_hashes": state.route["source_hashes"],
                "method_page_sha256": method_digest,
                "release_version": "v2026.07",
                "size": size,
                "sha256": digest,
                "downloaded_by_cli": True,
                "asset_family": "kindle-legacy",
                "koreader_choice": old_choice,
            }
        }
        state.evidence["koreader_package_choice"] = {
            **old_choice,
            "asset_family": "kindlepw2",
            "source_sha256": "2" * 64,
        }
        store.save(state)
        self._authorize("stage-koreader")

        result = self._run(
            "--apply", "stage", "--purpose", "koreader",
            "--archive", str(archive),
            "--required-file", ".adds/koreader/reader.lua",
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_PAYLOAD_ROUTE_MISMATCH")

    def test_confirm_koreader_package_fetches_source_and_binds_device_context(self):
        store = self._backup_to_prepare("WinterBreak")
        state = store.load()
        for stage in (
            Stage.WAIT_USER_EXPLOIT,
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
        ):
            state.transition(stage)
        store.save(state)
        ota = self._ota_check(prevention_status="verified")
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        source_body = b"official KOReader install page fixture"
        source_digest = hashlib.sha256(source_body).hexdigest()

        class Response(io.BytesIO):
            def geturl(self):
                return "https://github.com/koreader/koreader/wiki/Installation-on-Kindle-devices"

        output = io.StringIO()
        environment = {
            "KJA_TEST_MODE": "1",
            "KJA_TEST_DEVICE_FIXTURE": str(self.device_fixture),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch(
                "kindle_jailbreak.urllib.request.urlopen",
                return_value=Response(source_body),
            ):
                with contextlib.redirect_stdout(output):
                    returncode = main([
                        "--session-dir", str(self.session_dir),
                        "--device-root", str(self.kindle),
                        "--json", "confirm-koreader-package",
                        "--asset-family", "kindlepw2",
                        "--source-sha256", source_digest,
                        "--confirmed-by-user",
                    ])

        self.assertEqual(returncode, 0, output.getvalue())
        choice = store.load().evidence["koreader_package_choice"]
        self.assertEqual(choice["asset_family"], "kindlepw2")
        self.assertEqual(choice["model"], "PW3")
        self.assertEqual(choice["firmware"], "5.16.2.1.1")
        self.assertEqual(choice["source_sha256"], source_digest)

    def test_fetch_payload_command_records_the_downloaded_bytes_and_route_context(self):
        payload_url = "https://github.com/example/repo/releases/download/v1.0/payload-v1.0.zip"
        store = self._backup_to_prepare(
            "WinterBreak",
            method_page=(
                f'<html><a href="{payload_url}">payload</a> '
                'success marker documents/JAILBROKEN.txt</html>\n'
            ),
            confirm_log=False,
        )
        ota = self._ota_check(prevention_status="verified")
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)

        class Response(io.BytesIO):
            def geturl(self):
                return "https://release-assets.githubusercontent.com/payload?sig=redacted"

        output = io.StringIO()
        environment = {
            "KJA_TEST_MODE": "1",
            "KJA_TEST_DEVICE_FIXTURE": str(self.device_fixture),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch(
                "kindle_jailbreak.urllib.request.urlopen",
                return_value=Response(b"downloaded archive bytes"),
            ):
                with contextlib.redirect_stdout(output):
                    returncode = main([
                        "--session-dir", str(self.session_dir),
                        "--device-root", str(self.kindle),
                        "--json", "fetch-payload",
                        "--url", payload_url,
                        "--release-version", "v1.0",
                    ])

        self.assertEqual(returncode, 0, output.getvalue())
        record = store.load().evidence["payload_records"]["jailbreak"]
        self.assertIs(record["downloaded_by_cli"], True)
        self.assertEqual(record["release_version"], "v1.0")
        self.assertEqual(record["sha256"], hashlib.sha256(b"downloaded archive bytes").hexdigest())
        self.assertEqual(Path(record["archive_path"]).read_bytes(), b"downloaded archive bytes")

    def test_production_session_cannot_self_sign_a_local_payload_record(self):
        self._backup_to_prepare("WinterBreak")
        archive = self.base / "self-signed.zip"
        archive.write_bytes(b"self signed")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        result = self._run(
            "record-payload", "--archive", str(archive),
            "--final-url", "https://github.com/example/kindle-release.zip",
            "--release-version", "fixture-1", "--expected-sha256", digest,
            test_mode=False,
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(
            self._events(result)[-1]["code"], "KJA_PAYLOAD_RECORD_TEST_ONLY"
        )

    def test_payload_record_is_bound_to_the_confirmed_method_page_digest(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "recorded-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"official fixture")
        self._record_payload(archive)
        record = store.load().evidence["payload_records"]["jailbreak"]
        expected_method_digest = hashlib.sha256(
            (self.source_fixture / "method-page.html").read_bytes()
        ).hexdigest()
        self.assertEqual(record["method_page_sha256"], expected_method_digest)

        with (self.source_fixture / "method-page.html").open("a", encoding="utf-8") as stream:
            stream.write("<!-- changed after confirmation -->\n")
        self._authorize("stage-jailbreak")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_PAYLOAD_ROUTE_MISMATCH")
        self.assertFalse((self.kindle / "payload.bin").exists())

    def test_route_rejects_different_device_before_routing(self):
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        store = SessionStore(self.session_dir)
        self._write_device_fixture(serial="G090ZZZ609605TK")

        result = self._run("route", *self._source_arguments())

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_DEVICE_MISMATCH")
        self.assertEqual(store.load().stage, Stage.RISK_ACK)

    def test_route_returns_unsupported_code_for_unmatched_firmware(self):
        self._write_device_fixture(firmware="5.19.0")
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        ota = self._ota_check()
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        store = SessionStore(self.session_dir)

        result = self._run("route", *self._source_arguments())

        self.assertEqual(result.returncode, 22, result.stdout + result.stderr)
        self.assertEqual(store.load().stage, Stage.BLOCKED_UNSUPPORTED)

    def test_route_schema_conflict_persists_blocked_conflict(self):
        models = json.loads((FIXTURES / "models.json").read_text(encoding="utf-8"))
        models[0]["unexpected_schema_field"] = True
        self._write_source_fixture(models=models)
        probe = self._run("probe")
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        ota = self._ota_check()
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)

        result = self._run("route", *self._source_arguments())

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_ROUTE_CONFLICT")
        self.assertEqual(
            SessionStore(self.session_dir).load().stage,
            Stage.BLOCKED_CONFLICT,
        )

    def test_disconnect_enters_wait_reconnect_and_returns_recoverable_code(self):
        store = self._route_to_backup()
        disconnected = self.base / "disconnected-kindle"
        self.kindle.rename(disconnected)
        self._write_device_fixture(root=self.kindle)

        result = self._run("--apply", "backup", "--backup-dir", str(self.base / "backups"))

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_RECONNECT)

    def test_no_injected_device_without_device_root_enters_wait_reconnect(self):
        store = self._route_to_backup()
        self._write_device_fixture(available=False)

        result = self._run(
            "backup", "--backup-dir", str(self.base / "backups"),
            include_device=False,
        )

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        state = store.load()
        self.assertEqual(state.stage, Stage.WAIT_RECONNECT)
        self.assertEqual(state.evidence["__resume_stage"], "BACKUP")

    def test_macos_no_root_placeholder_is_a_disconnect_for_existing_usbms_session(self):
        store = self._make_session(Stage.BACKUP)
        args = argparse.Namespace()

        def runner(_argv):
            return SimpleNamespace(returncode=0, stdout="")

        def probe():
            return _probe_one(args, system="Darwin", runner=runner)

        with mock.patch.dict(os.environ, {"KJA_TEST_MODE": ""}, clear=False):
            try:
                _bound_device(args, store, probe=probe)
            except CLIError as exc:
                self.assertEqual(exc.exit_code, 23)
                self.assertEqual(exc.code, "KJA_DEVICE_UNAVAILABLE")
            except TypeError as exc:
                self.fail(f"CLI 设备探测尚不支持注入 runner/platform：{exc}")
            else:
                self.fail("macOS 无根占位不应被已有 USBMS 会话接受")

        state = store.load()
        self.assertEqual(state.stage, Stage.WAIT_RECONNECT)
        self.assertEqual(state.evidence["__resume_stage"], "BACKUP")

    def test_real_mtp_probe_does_not_validate_the_opaque_id_as_a_local_root(self):
        observed = DeviceInfo(
            transport="mtp",
            root=None,
            serial=None,
            model="PW3",
            firmware="5.16.2.1.1",
            read_only=False,
            free_bytes=256 * MIB,
            transport_id="0123456789abcdef01234567",
            device_code="0KB",
        )
        args = argparse.Namespace()

        with mock.patch.dict(os.environ, {"KJA_TEST_MODE": ""}, clear=False):
            with mock.patch("kindle_jailbreak.probe_devices", return_value=[observed]):
                result = _probe_one(args, system="Linux")

        self.assertIs(result, observed)
        self.assertIsNone(result.root)

    def test_fill_write_reprobe_converts_macos_placeholder_to_wait_reconnect(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        host_args = argparse.Namespace()

        def runner(_argv):
            return SimpleNamespace(returncode=0, stdout="")

        observations = 0

        def injected_probe():
            nonlocal observations
            observations += 1
            if observations == 1:
                return self._device()
            with mock.patch.dict(os.environ, {"KJA_TEST_MODE": ""}, clear=False):
                return _probe_one(host_args, system="Darwin", runner=runner)

        try:
            write_probe = _device_probe(host_args, probe=injected_probe)
        except TypeError as exc:
            self.fail(f"写入期 probe 尚不能注入 macOS placeholder：{exc}")

        environment = {
            "KJA_TEST_MODE": "1",
            "KJA_TEST_DEVICE_FIXTURE": str(self.device_fixture),
            "KJA_TEST_FILL_CHUNK_BYTES": "4096",
        }
        output = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch("kindle_jailbreak._device_probe", return_value=write_probe):
                with contextlib.redirect_stdout(output):
                    returncode = main([
                        "--session-dir", str(self.session_dir),
                        "--device-root", str(self.kindle),
                        "--json", "--apply", "fill",
                    ])

        self.assertEqual(returncode, 23, output.getvalue())
        self.assertIn('"code":"KJA_DEVICE_UNAVAILABLE"', output.getvalue())
        state = store.load()
        self.assertEqual(state.stage, Stage.WAIT_RECONNECT)
        self.assertEqual(state.evidence["__resume_stage"], "PREPARE")

    def test_storage_limit_hook_rejects_unvalidated_or_mismatched_test_device(self):
        host_device = self._device()
        mismatched_host = self._device(serial="DIFFERENT-HOST-DEVICE")
        cases = (
            (
                "missing-test-mode",
                {"KJA_TEST_FILL_CHUNK_BYTES": "4096"},
                host_device,
            ),
            (
                "missing-device-fixture",
                {
                    "KJA_TEST_MODE": "1",
                    "KJA_TEST_FILL_CHUNK_BYTES": "4096",
                },
                host_device,
            ),
            (
                "invalid-device-fixture",
                {
                    "KJA_TEST_MODE": "1",
                    "KJA_TEST_DEVICE_FIXTURE": str(FIXTURES / "models.json"),
                    "KJA_TEST_FILL_CHUNK_BYTES": "4096",
                },
                host_device,
            ),
            (
                "mismatched-device-fixture",
                {
                    "KJA_TEST_MODE": "1",
                    "KJA_TEST_DEVICE_FIXTURE": str(self.device_fixture),
                    "KJA_TEST_FILL_CHUNK_BYTES": "4096",
                },
                mismatched_host,
            ),
        )

        for label, environment, bound_device in cases:
            with self.subTest(case=label):
                with mock.patch.dict(os.environ, environment, clear=True):
                    try:
                        _test_storage_limits(bound_device)
                    except CLIError as exc:
                        self.assertEqual(exc.code, "KJA_TEST_HOOK_DENIED")
                    else:
                        self.fail("测试容量 hook 不应作用于未经绑定的 host probe 设备")

    def test_mid_stage_disconnect_keeps_original_resume_stage(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "disconnect-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"disconnect after write")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        self._write_device_fixture(
            free_bytes=80 * MIB + 4096,
            disconnect_after=3,
        )

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        waiting = store.load()
        self.assertEqual(waiting.stage, Stage.WAIT_RECONNECT)
        self.assertEqual(waiting.evidence["__resume_stage"], "PREPARE")

        self._write_device_fixture()
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_resume_rejects_same_model_with_different_serial_then_accepts_same_device(self):
        store = self._make_session(Stage.WAIT_RECONNECT)
        self._write_device_fixture(serial="DIFFERENT-DEVICE-05TK")

        conflict = self._run("resume")

        self.assertEqual(conflict.returncode, 21, conflict.stdout + conflict.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_RECONNECT)
        self.assertNotIn("DIFFERENT-DEVICE-05TK", conflict.stdout + conflict.stderr)

        self._write_device_fixture()
        resumed = self._run("resume")

        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(store.load().stage, Stage.BACKUP)

    def test_missing_jailbreak_evidence_returns_verification_failed(self):
        store = self._make_session(Stage.WAIT_USER_EXPLOIT)

        result = self._run("verify")

        self.assertEqual(result.returncode, 24, result.stdout + result.stderr)
        self.assertEqual(store.load().stage, Stage.RECOVERABLE_ERROR)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_VERIFICATION_FAILED")

    def test_koreader_files_without_visible_launch_stay_pending(self):
        store = self._make_session(Stage.VERIFY_KOREADER)
        (self.kindle / ".adds" / "koreader").mkdir(parents=True)

        result = self._run("verify", "--kind", "koreader")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = store.load()
        self.assertEqual(state.stage, Stage.VERIFY_KOREADER)
        self.assertTrue(state.evidence["koreader_files_verified"])
        self.assertNotIn("user_visible_launch", state.evidence)
        event = self._events(result)[-1]
        self.assertEqual(event["event"], "verification_pending")
        self.assertEqual(event["missing_evidence"], ["user_visible_launch"])
        self.assertIn("打开一本本地书", event["message"])

    def test_koreader_cli_rejects_forged_visible_launch_flag(self):
        store = self._make_session(Stage.VERIFY_KOREADER)
        (self.kindle / ".adds" / "koreader").mkdir(parents=True)

        result = self._run(
            "verify", "--kind", "koreader", "--user-visible-launch"
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        state = store.load()
        self.assertEqual(state.stage, Stage.VERIFY_KOREADER)
        self.assertNotIn("koreader_files_verified", state.evidence)
        self.assertNotIn("user_visible_launch", state.evidence)
        self.assertIn("unrecognized arguments: --user-visible-launch", result.stderr)

    def test_koreader_checkpoint_requires_user_confirmation_after_file_check(self):
        store = self._make_session(Stage.VERIFY_KOREADER)
        (self.kindle / ".adds" / "koreader").mkdir(parents=True)
        verified = self._run("verify", "--kind", "koreader")
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

        missing_confirmation = self._run(
            "checkpoint", "--kind", "koreader-visible-launch"
        )
        self.assertEqual(missing_confirmation.returncode, 20)
        self.assertEqual(
            self._events(missing_confirmation)[-1]["code"],
            "KJA_USER_CONFIRMATION_REQUIRED",
        )
        self.assertEqual(store.load().stage, Stage.VERIFY_KOREADER)

        confirmed = self._run(
            "checkpoint", "--kind", "koreader-visible-launch", "--confirmed-by-user"
        )
        self.assertEqual(confirmed.returncode, 0, confirmed.stdout + confirmed.stderr)
        self.assertEqual(store.load().stage, Stage.CLEANUP)

    def test_exploit_checkpoint_rejects_a_route_that_can_stage_payloads(self):
        store = self._backup_to_prepare("WinterBreak")

        checkpoint = self._run(
            "checkpoint", "--kind", "exploit-complete", "--confirmed-by-user"
        )

        self.assertEqual(checkpoint.returncode, 21, checkpoint.stdout + checkpoint.stderr)
        self.assertEqual(
            self._events(checkpoint)[-1]["code"], "KJA_CHECKPOINT_DENIED"
        )
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_exploit_checkpoint_requires_the_route_filler(self):
        store = self._backup_to_prepare("WinterBreak2")

        checkpoint = self._run(
            "checkpoint", "--kind", "exploit-complete", "--confirmed-by-user"
        )

        self.assertEqual(checkpoint.returncode, 21, checkpoint.stdout + checkpoint.stderr)
        self.assertEqual(
            self._events(checkpoint)[-1]["code"], "KJA_FILL_REQUIRED"
        )
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_method_declared_user_log_can_verify_jailbreak(self):
        store = self._backup_to_prepare("WinterBreak2")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        checkpoint = self._run(
            "checkpoint", "--kind", "exploit-complete", "--confirmed-by-user"
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stdout + checkpoint.stderr)

        log = self._run(
            "checkpoint", "--kind", "jailbreak-log", "--confirmed-by-user"
        )
        self.assertEqual(log.returncode, 0, log.stdout + log.stderr)
        verified = self._run("verify", "--kind", "jailbreak")

        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(store.load().stage, Stage.INSTALL_KOREADER)

    def test_host_staged_method_marker_cannot_verify_jailbreak(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "forged-marker.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("documents/JAILBROKEN.txt", b"host staged")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "documents/JAILBROKEN.txt",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)

        marker = self._run(
            "checkpoint", "--kind", "jailbreak-marker",
            "--evidence-path", "documents/JAILBROKEN.txt", "--confirmed-by-user",
        )
        self.assertEqual(marker.returncode, 21, marker.stdout + marker.stderr)
        self.assertEqual(self._events(marker)[-1]["code"], "KJA_CHECKPOINT_DENIED")

        verified = self._run("verify", "--kind", "jailbreak")

        self.assertEqual(verified.returncode, 24, verified.stdout + verified.stderr)
        self.assertEqual(store.load().stage, Stage.RECOVERABLE_ERROR)

    def test_structured_method_marker_simulates_new_device_evidence(self):
        store = self._backup_to_prepare(
            "WinterBreak2",
            method_page=(
                '<html><a href="https://github.com/example/kindle-release.zip">Release</a> '
                '成功标记 documents/JAILBROKEN.txt</html>\n'
            ),
            confirm_log=False,
        )
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        checkpoint = self._run(
            "checkpoint", "--kind", "exploit-complete", "--confirmed-by-user"
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stdout + checkpoint.stderr)
        premature = self._run(
            "checkpoint", "--kind", "jailbreak-marker",
            "--evidence-path", "documents/JAILBROKEN.txt", "--confirmed-by-user",
        )
        self.assertEqual(premature.returncode, 21, premature.stdout + premature.stderr)
        (self.kindle / "documents" / "JAILBROKEN.txt").write_text(
            "created on device", encoding="utf-8"
        )
        marker = self._run(
            "checkpoint", "--kind", "jailbreak-marker",
            "--evidence-path", "documents/JAILBROKEN.txt", "--confirmed-by-user",
        )
        self.assertEqual(marker.returncode, 0, marker.stdout + marker.stderr)

        verified = self._run("verify", "--kind", "jailbreak")

        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(store.load().stage, Stage.INSTALL_KOREADER)

    def test_negative_method_text_cannot_declare_marker_or_log_evidence(self):
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        self._write_source_fixture(
            jailbreaks=[route for route in jailbreaks if route["name"] == "WinterBreak2"]
        )
        (self.source_fixture / "method-page.html").write_text(
            "<html>Failure: documents/FAILED.txt is not success evidence. "
            "Do not use ;log as success evidence.</html>\n",
            encoding="utf-8",
        )

        result, _review = self._confirm_route(
            registered="yes", evidence_marker=None, confirm_log=False
        )

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(
            self._events(result)[-1]["event"], "evidence_rule_review_required"
        )
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.RISK_ACK)

    def test_backup_emits_real_file_progress_and_advances_state(self):
        store = self._route_to_backup()
        (self.kindle / "documents" / "book.txt").write_text("book", encoding="utf-8")

        result = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "backups"),
            "--timestamp", "20260903T120000Z",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        progress = [event for event in self._events(result) if event["event"] == "progress"]
        self.assertTrue(progress)
        self.assertEqual(progress[-1]["done"], progress[-1]["total"])
        self.assertEqual(progress[-1]["unit"], "files")
        self.assertEqual(store.load().stage, Stage.PREPARE)
        self.assertTrue((self.base / "backups" / "20260903T120000Z" / "manifest.json").is_file())

    def test_stage_uses_real_archive_and_advances_to_user_action(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        archive = self.base / "payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"official fixture")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.kindle / "payload.bin").read_bytes(), b"official fixture")
        self.assertEqual(store.load().stage, Stage.WAIT_USER_EXPLOIT)
        progress = [event for event in self._events(result) if event["event"] == "progress"]
        self.assertEqual(progress[-1]["total"], 1)

    def test_stage_target_collision_returns_verification_failure_without_overwrite(self):
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        existing = self.kindle / "payload.dat"
        existing.write_bytes(b"user content")
        archive = self.base / "collision-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.dat", b"official payload")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.dat",
        )

        self.assertEqual(result.returncode, 24, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_TARGET_EXISTS")
        self.assertEqual(existing.read_bytes(), b"user content")
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_subprocess_flow_uses_confirmed_route_before_backup_fill_and_stage(self):
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        winterbreak = [
            route for route in jailbreaks if route["name"] == "WinterBreak"
        ]
        self._write_source_fixture(jailbreaks=winterbreak)

        routed, _review = self._confirm_route(registered="yes")
        self.assertEqual(routed.returncode, 0, routed.stdout + routed.stderr)
        routed_state = SessionStore(self.session_dir).load()
        self.assertEqual(routed_state.stage, Stage.BACKUP)
        route = routed_state.route
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route["policy_name"], "WinterBreak")

        (self.kindle / "documents" / "book.txt").write_text("book", encoding="utf-8")
        backup = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "flow-backup"),
            "--timestamp", "20260903T130000Z",
        )
        self.assertEqual(backup.returncode, 0, backup.stdout + backup.stderr)
        self.assertEqual(SessionStore(self.session_dir).load().stage, Stage.PREPARE)

        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        self.assertTrue(any(self.kindle.glob(".kja-fill-*")))

        archive = self.base / "flow-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.bin", b"confirmed official fixture")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        stage = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.bin",
        )
        self.assertEqual(stage.returncode, 0, stage.stdout + stage.stderr)
        self.assertEqual(
            SessionStore(self.session_dir).load().stage,
            Stage.WAIT_USER_EXPLOIT,
        )
        self.assertEqual(
            (self.kindle / "payload.bin").read_bytes(),
            b"confirmed official fixture",
        )

    def test_pw3_winterbreak2_simulated_flow_keeps_physical_evidence_external(self):
        routed, _review = self._confirm_route()
        self.assertEqual(routed.returncode, 0, routed.stdout + routed.stderr)
        store = SessionStore(self.session_dir)
        self.assertEqual(store.load().stage, Stage.BACKUP)

        (self.kindle / "documents" / "book.txt").write_text("book", encoding="utf-8")
        backup = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "pw3-backup"),
            "--timestamp", "20260903T160000Z",
        )
        self.assertEqual(backup.returncode, 0, backup.stdout + backup.stderr)
        self.assertEqual(store.load().stage, Stage.PREPARE)
        self.assertTrue((self.base / "pw3-backup" / "20260903T160000Z" / "manifest.json").is_file())

        self._authorize("fill")
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)
        self.assertTrue(store.load().evidence["fill_complete"])

        jailbreak_archive = self.base / "pw3-jailbreak.zip"
        with zipfile.ZipFile(jailbreak_archive, "w") as bundle:
            bundle.writestr("payload.bin", b"official fixture")
        staged = self._run(
            "--apply", "stage", "--archive", str(jailbreak_archive),
            "--required-file", "payload.bin",
        )
        self.assertEqual(staged.returncode, 21, staged.stdout + staged.stderr)
        self.assertEqual(self._events(staged)[-1]["code"], "KJA_POLICY_DENIED")
        self.assertFalse((self.kindle / "payload.bin").exists())
        self.assertEqual(store.load().stage, Stage.PREPARE)
        checkpoint = self._run(
            "checkpoint", "--kind", "exploit-complete", "--confirmed-by-user"
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stdout + checkpoint.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_USER_EXPLOIT)

        disconnected = self.base / "disconnected-kindle"
        self.kindle.rename(disconnected)
        waiting = self._run("verify")
        self.assertEqual(waiting.returncode, 23, waiting.stdout + waiting.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_RECONNECT)
        disconnected.rename(self.kindle)
        self._write_device_fixture(free_bytes=80 * MIB + 4096)
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_USER_EXPLOIT)

        (self.kindle / "documents" / "JAILBROKEN.txt").write_text("ok", encoding="utf-8")
        marker = self._run(
            "checkpoint", "--kind", "jailbreak-marker",
            "--evidence-path", "documents/JAILBROKEN.txt", "--confirmed-by-user",
        )
        self.assertEqual(marker.returncode, 0, marker.stdout + marker.stderr)
        verified = self._run("verify", "--kind", "jailbreak")
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(store.load().stage, Stage.INSTALL_KOREADER)

        koreader_archive = self.base / "pw3-koreader.zip"
        with zipfile.ZipFile(koreader_archive, "w") as bundle:
            bundle.writestr(".adds/koreader/reader.lua", b"return true")
        self._record_payload(koreader_archive, purpose="koreader")
        self._authorize("stage-koreader")
        koreader = self._run(
            "--apply", "stage", "--purpose", "koreader",
            "--archive", str(koreader_archive),
            "--required-file", ".adds/koreader/reader.lua",
        )
        self.assertEqual(koreader.returncode, 0, koreader.stdout + koreader.stderr)
        self.assertEqual(store.load().stage, Stage.VERIFY_KOREADER)
        pending = self._run("verify", "--kind", "koreader")
        self.assertEqual(pending.returncode, 0, pending.stdout + pending.stderr)
        self.assertEqual(store.load().stage, Stage.VERIFY_KOREADER)
        self.assertIn("打开一本本地书", self._events(pending)[-1]["message"])

        checkpoint = self._run(
            "checkpoint", "--kind", "koreader-visible-launch", "--confirmed-by-user"
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stdout + checkpoint.stderr)
        self.assertEqual(store.load().stage, Stage.CLEANUP)
        self._authorize("cleanup")
        cleanup = self._run("--apply", "cleanup")
        self.assertEqual(cleanup.returncode, 0, cleanup.stdout + cleanup.stderr)
        self.assertEqual(store.load().stage, Stage.COMPLETE)
        self.assertFalse(any(self.kindle.glob(".kja-fill-*")))
        self.assertTrue((self.kindle / ".adds" / "koreader" / "reader.lua").is_file())

    def test_linux_mtp_simulated_cli_flow_uses_adapter_without_treating_id_as_path(self):
        self._use_mtp_fixture()
        jailbreaks = json.loads(
            (FIXTURES / "jailbreaks.json").read_text(encoding="utf-8")
        )
        self._write_source_fixture(
            jailbreaks=[route for route in jailbreaks if route["name"] == "WinterBreak"]
        )
        (self.kindle / "documents" / "book.txt").write_text("book", encoding="utf-8")

        routed, _review = self._confirm_route(registered="yes")
        self.assertEqual(routed.returncode, 0, routed.stdout + routed.stderr)
        store = SessionStore(self.session_dir)
        self.assertEqual(store.load().device_public["root"], None)
        self.assertNotIn("0123456789abcdef01234567", routed.stdout)

        backup = self._run(
            "--apply", "backup", "--backup-dir", str(self.base / "mtp-backup"),
            "--timestamp", "20260903T170000Z",
        )
        self.assertEqual(backup.returncode, 0, backup.stdout + backup.stderr)
        self.assertTrue(
            (self.base / "mtp-backup" / "20260903T170000Z" / "manifest.json").is_file()
        )

        self._authorize("fill")
        fill = self._run("--apply", "fill")
        self.assertEqual(fill.returncode, 0, fill.stdout + fill.stderr)

        jailbreak_archive = self.base / "mtp-jailbreak.zip"
        with zipfile.ZipFile(jailbreak_archive, "w") as bundle:
            bundle.writestr("payload.dat", b"official MTP fixture")
        self._record_payload(jailbreak_archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(jailbreak_archive),
            "--required-file", "payload.dat",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        self.assertEqual((self.kindle / "payload.dat").read_bytes(), b"official MTP fixture")

        (self.kindle / "documents" / "JAILBROKEN.txt").write_text("ok", encoding="utf-8")
        marker = self._run(
            "checkpoint", "--kind", "jailbreak-marker",
            "--evidence-path", "documents/JAILBROKEN.txt", "--confirmed-by-user",
        )
        self.assertEqual(marker.returncode, 0, marker.stdout + marker.stderr)
        verified = self._run("verify", "--kind", "jailbreak")
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

        koreader_archive = self.base / "mtp-koreader.zip"
        with zipfile.ZipFile(koreader_archive, "w") as bundle:
            bundle.writestr(".adds/koreader/reader.lua", b"return true")
        self._record_payload(koreader_archive, purpose="koreader")
        self._authorize("stage-koreader")
        koreader = self._run(
            "--apply", "stage", "--purpose", "koreader",
            "--archive", str(koreader_archive),
            "--required-file", ".adds/koreader/reader.lua",
        )
        self.assertEqual(koreader.returncode, 0, koreader.stdout + koreader.stderr)
        pending = self._run("verify", "--kind", "koreader")
        self.assertEqual(pending.returncode, 0, pending.stdout + pending.stderr)
        checkpoint = self._run(
            "checkpoint", "--kind", "koreader-visible-launch", "--confirmed-by-user"
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stdout + checkpoint.stderr)
        self._authorize("cleanup")
        cleanup = self._run("--apply", "cleanup")

        self.assertEqual(cleanup.returncode, 0, cleanup.stdout + cleanup.stderr)
        self.assertEqual(store.load().stage, Stage.COMPLETE)
        self.assertFalse((self.kindle / "payload.dat").exists())
        self.assertTrue((self.kindle / ".adds" / "koreader" / "reader.lua").is_file())

    def test_mtp_disconnect_preserves_stage_and_requires_the_same_stable_identity(self):
        self._use_mtp_fixture()
        store = self._backup_to_prepare("WinterBreak")
        self._authorize("fill")
        fixture = json.loads(self.device_fixture.read_text(encoding="utf-8"))
        fixture["available"] = False
        self.device_fixture.write_text(json.dumps(fixture), encoding="utf-8")

        disconnected = self._run("--apply", "fill")

        self.assertEqual(disconnected.returncode, 23, disconnected.stdout + disconnected.stderr)
        waiting = store.load()
        self.assertEqual(waiting.stage, Stage.WAIT_RECONNECT)
        self.assertEqual(waiting.evidence["__resume_stage"], "PREPARE")

        fixture["available"] = True
        fixture["transport_id"] = "ffffffffffffffffffffffff"
        self.device_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        wrong = self._run("resume")
        self.assertEqual(wrong.returncode, 21, wrong.stdout + wrong.stderr)
        self.assertEqual(store.load().stage, Stage.WAIT_RECONNECT)

        fixture["transport_id"] = "0123456789abcdef01234567"
        self.device_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(store.load().stage, Stage.PREPARE)

    def test_mtp_fixture_rejects_missing_stable_identity_before_session_creation(self):
        self._use_mtp_fixture()
        fixture = json.loads(self.device_fixture.read_text(encoding="utf-8"))
        fixture["transport_id"] = None
        self.device_fixture.write_text(json.dumps(fixture), encoding="utf-8")

        result = self._run("probe")

        self.assertEqual(result.returncode, 21, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_FIXTURE_INVALID")
        self.assertFalse((self.session_dir / "session.json").exists())

    def test_mtp_stage_fails_closed_without_verified_reserve_space(self):
        store, mtp_fixture = self._mtp_prepare_for_assets()
        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture["free_bytes"] = 80 * MIB
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        device = json.loads(self.device_fixture.read_text(encoding="utf-8"))
        device["free_bytes"] = 80 * MIB
        self.device_fixture.write_text(json.dumps(device), encoding="utf-8")
        archive = self.base / "too-large-for-reserve.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.dat", b"payload")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.dat",
        )

        self.assertEqual(result.returncode, 24, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_INSUFFICIENT_SPACE")
        self.assertFalse((self.kindle / "payload.dat").exists())

    def test_mtp_stage_rejects_casefold_collision_before_copy(self):
        self._mtp_prepare_for_assets()
        (self.kindle / "Payload.dat").write_bytes(b"user file")
        archive = self.base / "case-collision.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload.dat", b"official")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")

        result = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload.dat",
        )

        self.assertEqual(result.returncode, 24, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_TARGET_EXISTS")
        self.assertEqual((self.kindle / "Payload.dat").read_bytes(), b"user file")

    def test_mtp_cleanup_refuses_nonempty_created_directory(self):
        store, _fixture = self._mtp_prepare_for_assets()
        archive = self.base / "nested-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload-dir/payload.dat", b"official")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "payload-dir/payload.dat",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        state = store.load()
        for stage in (
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
            Stage.VERIFY_KOREADER,
            Stage.CLEANUP,
        ):
            state.transition(stage)
        store.save(state)
        personal = self.kindle / "payload-dir" / "personal.txt"
        personal.write_text("keep me", encoding="utf-8")
        self._authorize("cleanup")

        result = self._run("--apply", "cleanup")

        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(self._events(result)[-1]["code"], "KJA_CLEANUP_OWNERSHIP")
        self.assertTrue(personal.is_file())
        self.assertTrue(personal.parent.is_dir())

        personal.unlink()
        personal.parent.rmdir()
        personal.parent.write_text("replacement file", encoding="utf-8")
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self._authorize("cleanup")
        replaced = self._run("--apply", "cleanup")
        self.assertEqual(replaced.returncode, 23, replaced.stdout + replaced.stderr)
        self.assertEqual(personal.parent.read_text(encoding="utf-8"), "replacement file")

        personal.parent.unlink()
        personal.parent.mkdir()
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self._authorize("cleanup")
        completed = self._run("--apply", "cleanup")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(store.load().stage, Stage.COMPLETE)
        self.assertFalse(personal.parent.exists())

    def test_mtp_stage_resumes_verified_files_after_mid_copy_disconnect(self):
        store, mtp_fixture = self._mtp_prepare_for_assets()
        archive = self.base / "resumable-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("first.dat", b"first")
            bundle.writestr("second.dat", b"second")
        self._record_payload(archive)
        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture["fail_copy_to_after"] = 1
        fixture["copy_to_count"] = 0
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        self._authorize("stage-jailbreak")

        interrupted = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "first.dat", "--required-file", "second.dat",
        )

        self.assertEqual(interrupted.returncode, 23, interrupted.stdout + interrupted.stderr)
        self.assertTrue((self.kindle / "first.dat").is_file())
        self.assertFalse((self.kindle / "second.dat").exists())
        self.assertEqual(store.load().stage, Stage.WAIT_RECONNECT)

        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture.pop("fail_copy_to_after", None)
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self._authorize("stage-jailbreak")
        completed = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "first.dat", "--required-file", "second.dat",
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual((self.kindle / "first.dat").read_bytes(), b"first")
        self.assertEqual((self.kindle / "second.dat").read_bytes(), b"second")
        self.assertEqual(store.load().stage, Stage.WAIT_USER_EXPLOIT)

    def test_mtp_stage_recovers_copy_landed_before_ownership_commit(self):
        store, mtp_fixture = self._mtp_prepare_for_assets()
        archive = self.base / "pending-ownership.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("landed.dat", b"landed")
        self._record_payload(archive)
        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture["fail_copy_from_once"] = "landed.dat"
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        self._authorize("stage-jailbreak")

        interrupted = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "landed.dat",
        )

        self.assertEqual(interrupted.returncode, 23, interrupted.stdout + interrupted.stderr)
        self.assertEqual((self.kindle / "landed.dat").read_bytes(), b"landed")
        record = store.load().evidence["mtp_created_records"]["landed.dat"]
        self.assertEqual(record["state"], "pending_create")

        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture.pop("fail_copy_from_once", None)
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self._authorize("stage-jailbreak")
        completed = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "landed.dat",
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(
            store.load().evidence["mtp_created_records"]["landed.dat"]["state"],
            "created",
        )

    def test_mtp_cleanup_recovers_delete_landed_before_result_commit(self):
        store, mtp_fixture = self._mtp_prepare_for_assets()
        archive = self.base / "delete-pending.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("cleanup-me.dat", b"temporary")
        self._record_payload(archive)
        self._authorize("stage-jailbreak")
        staged = self._run(
            "--apply", "stage", "--archive", str(archive),
            "--required-file", "cleanup-me.dat",
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        state = store.load()
        for stage in (
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
            Stage.VERIFY_KOREADER,
            Stage.CLEANUP,
        ):
            state.transition(stage)
        store.save(state)
        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture["fail_after_delete_once"] = "cleanup-me.dat"
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        self._authorize("cleanup")

        interrupted = self._run("--apply", "cleanup")

        self.assertEqual(interrupted.returncode, 23, interrupted.stdout + interrupted.stderr)
        self.assertFalse((self.kindle / "cleanup-me.dat").exists())
        record = store.load().evidence["mtp_created_records"]["cleanup-me.dat"]
        self.assertEqual(record["state"], "deleting")

        fixture = json.loads(mtp_fixture.read_text(encoding="utf-8"))
        fixture.pop("fail_after_delete_once", None)
        mtp_fixture.write_text(json.dumps(fixture), encoding="utf-8")
        resumed = self._run("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self._authorize("cleanup")
        completed = self._run("--apply", "cleanup")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(store.load().stage, Stage.COMPLETE)

    def test_cleanup_without_created_files_is_safe_and_completes(self):
        store = self._backup_to_prepare()
        state = store.load()
        for stage in (
            Stage.WAIT_USER_EXPLOIT,
            Stage.VERIFY_JAILBREAK,
            Stage.INSTALL_KOREADER,
            Stage.VERIFY_KOREADER,
            Stage.CLEANUP,
        ):
            state.transition(stage)
        store.save(state)
        ota = self._ota_check(prevention_status="verified")
        self.assertEqual(ota.returncode, 0, ota.stdout + ota.stderr)
        missing = self._run("--apply", "cleanup")
        self.assertEqual(missing.returncode, 20, missing.stdout + missing.stderr)
        self.assertEqual(self._events(missing)[-1]["code"], "KJA_WRITE_NOT_AUTHORIZED")
        self.assertEqual(store.load().stage, Stage.CLEANUP)
        self._authorize("cleanup")

        result = self._run("--apply", "cleanup")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(store.load().stage, Stage.COMPLETE)
        self.assertFalse((self.session_dir / "created-files.json").exists())

    def test_status_is_structured_and_does_not_disclose_serial(self):
        self._make_session(Stage.BACKUP)

        result = self._run("status")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._events(result)[0]["stage"], "BACKUP")
        self.assertNotIn(self.full_serial, result.stdout + result.stderr)

    def test_self_test_reports_four_offline_checks(self):
        result = subprocess.run(
            [sys.executable, str(CLI), "self-test", "--json"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checks = {
            event["check"]: event["ok"]
            for event in self._events(result)
            if event["event"] == "self_test"
        }
        self.assertEqual(checks, {
            "device_probe": True,
            "routing_schema": True,
            "safe_paths": True,
            "session_atomicity": True,
        })
        events = {
            event["check"]: event
            for event in self._events(result)
            if event["event"] == "self_test"
        }
        self.assertIs(events["device_probe"].get("serial_redacted"), True)
        self.assertIs(events["routing_schema"].get("confirmed_route"), True)
        self.assertIs(events["routing_schema"].get("invalid_schema_blocked"), True)
        self.assertIs(events["safe_paths"].get("protected_root_rejected"), True)
        self.assertIs(events["safe_paths"].get("traversal_rejected"), True)
        self.assertIs(events["session_atomicity"].get("failed_replace_preserved"), True)


if __name__ == "__main__":
    unittest.main()

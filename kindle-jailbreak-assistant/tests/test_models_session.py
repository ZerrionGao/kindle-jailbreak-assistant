import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast
from unittest import mock

from kindle_jailbreak_lib.models import DeviceInfo, RouteCandidate, Stage, TriState
from kindle_jailbreak_lib.progress import ProgressEvent
from kindle_jailbreak_lib.session import SessionStore, device_fingerprint


class ModelsSessionTest(unittest.TestCase):
    def test_device_fingerprint_binds_session_to_full_serial(self):
        first = device_fingerprint("session-1", "AAAA-SAME")

        self.assertEqual(first, device_fingerprint("session-1", "AAAA-SAME"))
        self.assertNotEqual(first, device_fingerprint("session-1", "BBBB-SAME"))
        self.assertNotEqual(first, device_fingerprint("session-2", "AAAA-SAME"))
        with self.assertRaises(ValueError):
            device_fingerprint("session-1", "")

    def test_session_redacts_serial_and_rejects_backward_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp))
            state = store.create(DeviceInfo(
                transport="usbms", root="/Volumes/Kindle",
                serial="G090KB0TESTX05TK", model="PW3",
                firmware="5.16.2.1.1", read_only=False, free_bytes=2_000_000_000,
            ))
            payload = json.loads((Path(tmp) / "session.json").read_text())
            self.assertNotIn("G090KB0TESTX05TK", json.dumps(payload))
            self.assertRegex(payload["device_fingerprint"], r"^[0-9a-f]{16}$")
            self.assertIsNone(payload["route"])
            state.transition(Stage.ROUTE)
            with self.assertRaises(ValueError):
                state.transition(Stage.DISCOVER)

    def test_tristate_only_prompts_when_required(self):
        self.assertEqual(TriState.parse("unknown"), TriState.UNKNOWN)
        self.assertEqual(TriState.parse("yes"), TriState.YES)

    def test_device_public_dict_redacts_serial_without_losing_identity_hint(self):
        device = DeviceInfo(
            transport="usbms", root="/Volumes/Kindle", serial="G090KB0TESTX05TK",
            model="PW3", firmware="5.16.2.1.1", read_only=False, free_bytes=123,
        )

        public = device.public_dict()

        self.assertNotIn(device.serial, json.dumps(public))
        self.assertEqual(public["serial_suffix"], "05TK")
        self.assertEqual(public["transport"], "usbms")

    def test_waiting_and_recovery_stages_resume_after_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp))
            state = store.create(DeviceInfo(
                transport="usbms", root="/Volumes/Kindle", serial=None,
                model="PW3", firmware="5.16.2.1.1", read_only=False, free_bytes=None,
            ))
            state.transition(Stage.RISK_ACK)
            state.transition(Stage.ROUTE)
            state.transition(Stage.BACKUP)
            state.transition(Stage.WAIT_RECONNECT)
            store.save(state)

            waiting = SessionStore(Path(tmp)).load()

            self.assertEqual(waiting.stage, Stage.WAIT_RECONNECT)
            self.assertIsNone(waiting.route)
            waiting.transition(Stage.BACKUP)
            waiting.transition(Stage.RECOVERABLE_ERROR)
            store.save(waiting)

            recovery = SessionStore(Path(tmp)).load()

            self.assertEqual(recovery.stage, Stage.RECOVERABLE_ERROR)
            self.assertIsNone(recovery.route)
            recovery.transition(Stage.BACKUP)
            self.assertEqual(recovery.session_id, state.session_id)
            self.assertEqual(recovery.device_fingerprint, state.device_fingerprint)

    def test_disconnect_after_recoverable_error_preserves_original_resume_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp))
            state = store.create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))
            for stage in (
                Stage.RISK_ACK,
                Stage.ROUTE,
                Stage.BACKUP,
                Stage.PREPARE,
                Stage.RECOVERABLE_ERROR,
            ):
                state.transition(stage)

            try:
                state.transition(Stage.WAIT_RECONNECT)
            except ValueError as exc:
                self.fail(f"断线状态不能覆盖原恢复阶段：{exc}")
            store.save(state)

            resumed = SessionStore(Path(tmp)).load()
            self.assertEqual(resumed.stage, Stage.WAIT_RECONNECT)
            resumed.transition(Stage.PREPARE)
            self.assertEqual(resumed.stage, Stage.PREPARE)

    def test_session_accepts_complete_legal_main_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SessionStore(Path(tmp)).create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))

            for stage in (
                Stage.RISK_ACK,
                Stage.ROUTE,
                Stage.BACKUP,
                Stage.PREPARE,
                Stage.WAIT_USER_EXPLOIT,
                Stage.VERIFY_JAILBREAK,
                Stage.INSTALL_KOREADER,
                Stage.VERIFY_KOREADER,
                Stage.CLEANUP,
                Stage.COMPLETE,
            ):
                state.transition(stage)

            self.assertEqual(state.stage, Stage.COMPLETE)

    def test_session_rejects_cross_stage_jumps(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SessionStore(Path(tmp)).create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))

            with self.assertRaises(ValueError):
                state.transition(Stage.BACKUP)
            state.transition(Stage.ROUTE)
            with self.assertRaises(ValueError):
                state.transition(Stage.PREPARE)

    def test_terminal_states_reject_further_transitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SessionStore(Path(tmp)).create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))

            with self.assertRaises(ValueError):
                state.transition(Stage.COMPLETE)

            state.transition(Stage.BLOCKED_UNSUPPORTED)
            with self.assertRaises(ValueError):
                state.transition(Stage.DISCOVER)

    def test_route_candidate_and_progress_event_have_stable_value_types(self):
        route = RouteCandidate(
            name="SpringBreak", url="https://example.invalid/route",
            required_questions=("registered",), policy_name="springbreak",
        )
        event = ProgressEvent(
            event="stage_started", stage=Stage.ROUTE,
            message="正在读取官方路线", done=1, total=2, unit="source",
            user_action=None,
        )

        self.assertEqual(route.required_questions, ("registered",))
        self.assertEqual(event.stage, Stage.ROUTE)
        self.assertEqual(event.total, 2)

    def test_device_fingerprint_uses_random_salt_and_storage_removes_secrets(self):
        serial = "G090KB0TESTX05TK"
        device = DeviceInfo(
            transport="usbms", root="/Volumes/Kindle", serial=serial,
            model="PW3", firmware="5.16.2.1.1", read_only=False,
            free_bytes=123,
        )
        with tempfile.TemporaryDirectory() as tmp:
            first_store = SessionStore(Path(tmp) / "first")
            second_store = SessionStore(Path(tmp) / "second")
            first = first_store.create(device)
            second = second_store.create(device)
            first.route = {
                "name": "official",
                "url": (
                    "https://url-user-secret:password-secret@example.invalid/file"
                ),
                "source_url": (
                    "https://example.invalid/file?source=official&token=url-secret"
                ),
                "authorization": "Bearer auth-secret",
                "cookie": "cookie-secret",
                "qr_uid": "qr-secret",
                "headers": {
                    "Accept": "application/octet-stream",
                    "Authorization": "Bearer header-auth-secret",
                    "X-Api-Key": "header-secret",
                },
            }
            first.evidence = {
                "nested": {"api_token": "api-secret", "serial": serial},
            }
            first_store.save(first)

            stored = first_store.session_path.read_text(encoding="utf-8")
            payload = json.loads(stored)

            self.assertNotEqual(first.device_fingerprint, second.device_fingerprint)
            for secret in (
                serial, "url-secret", "auth-secret", "cookie-secret",
                "qr-secret", "api-secret", "url-user-secret",
                "password-secret", "header-auth-secret", "header-secret",
            ):
                self.assertNotIn(secret, stored)
            self.assertEqual(
                payload["route"]["url"],
                "https://example.invalid/file",
            )
            self.assertEqual(
                payload["route"]["source_url"],
                "https://example.invalid/file?source=official",
            )
            self.assertEqual(
                payload["route"]["headers"],
                {"Accept": "application/octet-stream"},
            )

    def test_approvals_round_trip_preserves_authorization_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp))
            state = store.create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))
            state.approvals = {
                "write_authorization": True,
                "risk_acknowledged": False,
            }

            store.save(state)
            payload = json.loads(store.session_path.read_text(encoding="utf-8"))
            loaded = SessionStore(Path(tmp)).load()

            self.assertEqual(payload["approvals"], state.approvals)
            self.assertEqual(loaded.approvals, state.approvals)

    def test_approvals_reject_non_boolean_values_on_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp))
            state = store.create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))
            state.approvals = cast(Any, {"write_authorization": "yes"})

            with self.assertRaises(TypeError):
                store.save(state)

            payload = json.loads(store.session_path.read_text(encoding="utf-8"))
            payload["approvals"] = {"write_authorization": "yes"}
            store.session_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                SessionStore(Path(tmp)).load()

    def test_session_schema_version_rejects_boolean_and_non_integer_values(self):
        for invalid_schema_version in (True, "1", 1.0, None):
            with self.subTest(schema_version=invalid_schema_version):
                with tempfile.TemporaryDirectory() as tmp:
                    store = SessionStore(Path(tmp))
                    store.create(DeviceInfo(
                        transport="usbms", root=None, serial=None, model=None,
                        firmware=None, read_only=None, free_bytes=None,
                    ))
                    payload = json.loads(store.session_path.read_text(encoding="utf-8"))
                    payload["schema_version"] = invalid_schema_version
                    store.session_path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(ValueError):
                        SessionStore(Path(tmp)).load()

    def test_failed_atomic_save_preserves_previous_session_and_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = SessionStore(root)
            state = store.create(DeviceInfo(
                transport="usbms", root=None, serial=None, model=None,
                firmware=None, read_only=None, free_bytes=None,
            ))
            previous_session = store.session_path.read_bytes()
            backup_path = root / "session.json.bak"
            backup_path.write_text("existing backup\n", encoding="utf-8")
            state.target = "changed-target"

            with mock.patch(
                "kindle_jailbreak_lib.session.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaisesRegex(OSError, "simulated replace failure"):
                    store.save(state)

            self.assertEqual(store.session_path.read_bytes(), previous_session)
            self.assertEqual(
                backup_path.read_text(encoding="utf-8"), "existing backup\n"
            )
            self.assertEqual(list(root.glob(".session.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()

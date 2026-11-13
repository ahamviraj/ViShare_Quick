import json
import tempfile
import time
import unittest
from pathlib import Path

from vishare_quick.consent import ConsentRequest, FileOffer
from vishare_quick.ui_service import ReceiveService, WebPrompter, _Prompt


class TestWebPrompter(unittest.TestCase):
    def test_timeout_fails_pin_and_consent_closed(self):
        ended = []
        prompter = WebPrompter(
            on_prompt=lambda prompt: None,
            on_end=lambda kind, decision: ended.append((kind, decision)),
            timeout_seconds=0.02,
        )
        request = ConsentRequest(
            pin="1234",
            files=(FileOffer(1, "a.txt", 3, "text/plain", "FILE"),),
            total_size=3,
        )
        self.assertIsNone(prompter.ask_pin("1234"))
        self.assertFalse(prompter.request_consent(request))
        self.assertEqual(ended, [("pin", None), ("consent", None)])

    def test_cancel_closes_current_and_future_prompts(self):
        prompter = WebPrompter(
            on_prompt=lambda prompt: None,
            on_end=lambda kind, decision: None,
            timeout_seconds=5.0,
        )
        prompter.cancel()
        self.assertFalse(prompter.resolve(True))
        self.assertIsNone(prompter.ask_pin("4321"))
        request = ConsentRequest(
            pin="4321",
            files=(FileOffer(1, "a.txt", 3, "text/plain", "FILE"),),
            total_size=3,
        )
        self.assertFalse(prompter.request_consent(request))

    def test_timeout_cannot_be_overtaken_by_a_late_accept(self):
        ended = []
        prompter = WebPrompter(
            on_prompt=lambda prompt: None,
            on_end=lambda kind, decision: ended.append((kind, decision)),
        )
        prompt = _Prompt(
            kind="pin",
            deadline=time.monotonic() - 1,
            decision=True,
        )
        self.assertIsNone(prompter._finish(prompt, timed_out=True))
        self.assertEqual(ended, [("pin", None)])

    def test_explicit_resolution_is_returned(self):
        prompter = None  # type: WebPrompter | None
        decision = {"value": True}

        def on_prompt(prompt):
            assert prompter is not None
            prompter.resolve(decision["value"])

        prompter = WebPrompter(
            on_prompt=on_prompt,
            on_end=lambda kind, value: None,
            timeout_seconds=5.0,
        )
        self.assertEqual(prompter.ask_pin("9876"), "9876")
        request = ConsentRequest(
            pin="9876",
            files=(FileOffer(1, "a.txt", 3, "text/plain", "FILE"),),
            total_size=3,
        )
        self.assertTrue(prompter.request_consent(request))

        decision["value"] = False
        self.assertIsNone(prompter.ask_pin("9876"))
        self.assertFalse(prompter.request_consent(request))

    def test_first_resolution_wins(self):
        prompter = None  # type: WebPrompter | None

        def on_prompt(prompt):
            assert prompter is not None
            self.assertTrue(prompter.resolve(True))
            self.assertFalse(prompter.resolve(False))

        prompter = WebPrompter(
            on_prompt=on_prompt,
            on_end=lambda kind, value: None,
        )
        self.assertEqual(prompter.ask_pin("1234"), "1234")

    def test_resolve_without_pending_prompt_returns_false(self):
        prompter = WebPrompter(
            on_prompt=lambda prompt: None,
            on_end=lambda kind, value: None,
        )
        self.assertFalse(prompter.resolve(True))


class TestReceiveServiceSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = ReceiveService(Path(self.temp.name) / "incoming")

    def tearDown(self):
        self.temp.cleanup()

    def _consent_prompt(self):
        return _Prompt(
            kind="consent",
            deadline=time.monotonic() + 60,
            request=ConsentRequest(
                pin="5678",
                files=(
                    FileOffer(
                        payload_id=987654321,
                        name="photo.jpg",
                        size=123456,
                        mime_type="image/jpeg",
                        type_name="IMAGE",
                    ),
                    FileOffer(
                        payload_id=123456789,
                        name="notes.txt",
                        size=10,
                        mime_type="text/plain",
                        type_name="FILE",
                    ),
                ),
                total_size=123466,
            ),
        )

    def test_consent_snapshot_never_exposes_payload_ids(self):
        self.service._on_prompt(self._consent_prompt())
        snapshot = self.service.snapshot()
        serialized = json.dumps(snapshot)
        self.assertEqual(snapshot["phase"], "consent")
        self.assertEqual(
            [item["name"] for item in snapshot["request"]["files"]],
            ["photo.jpg", "notes.txt"],
        )
        self.assertNotIn("payload", serialized)
        self.assertNotIn("987654321", serialized)
        self.assertNotIn("123456789", serialized)
        self.assertEqual(
            set(snapshot["request"]["files"][0]),
            {"index", "name", "size", "mime", "kind"},
        )

    def test_progress_updates_are_mapped_by_index_only(self):
        self.service._on_prompt(self._consent_prompt())
        self.service._on_progress(987654321, 600, 123456)
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot["progress"]["files"][0]["received"], 600)
        self.assertNotIn("payload", json.dumps(snapshot))
        self.assertNotIn("987654321", json.dumps(snapshot))

    def test_dismiss_only_leaves_final_screens(self):
        self.service._on_prompt(self._consent_prompt())
        self.assertEqual(self.service.snapshot()["phase"], "consent")
        self.service.dismiss_result()
        self.assertEqual(self.service.snapshot()["phase"], "consent")

        self.service._on_event(
            {
                "type": "session",
                "status": "completed",
                "pin_verified": True,
                "consent": "accepted",
                "files": [
                    {"name": "photo.jpg", "saved_name": "photo.jpg", "size": 123456}
                ],
            }
        )
        self.assertEqual(self.service.snapshot()["phase"], "completed")
        self.service.dismiss_result()
        self.assertEqual(self.service.snapshot()["phase"], "idle")

    def test_device_name_validation(self):
        self.assertTrue(self.service.set_device_name("  Desk PC  "))
        self.assertEqual(self.service.snapshot()["device_name"], "Desk PC")
        self.assertFalse(self.service.set_device_name("   "))
        self.assertFalse(self.service.set_device_name("x" * 256))

    def test_decisions_without_a_pending_prompt_are_refused(self):
        self.assertFalse(self.service.resolve_pin(True))
        self.assertFalse(self.service.resolve_consent(True))
        self.assertFalse(self.service.cancel_transfer())
        self.assertEqual(self.service.snapshot()["phase"], "idle")


if __name__ == "__main__":
    unittest.main()

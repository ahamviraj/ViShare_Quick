import io
import unittest
from pathlib import Path
from unittest.mock import patch

from vishare_quick import windows_share
from vishare_quick.send_service import SendService


class TestSendServiceFiles(unittest.TestCase):
    def setUp(self):
        self.service = SendService()

    def tearDown(self):
        self.service.stop()

    def add(self, name, data):
        return self.service.add_upload(io.BytesIO(data), name, len(data))

    def test_uploads_are_staged_with_safe_unique_names(self):
        self.add("../first.txt", b"abc")
        self.add("first.txt", b"de")
        snapshot = self.service.snapshot()
        self.assertEqual(
            [item["name"] for item in snapshot["files"]],
            ["first.txt", "first (1).txt"],
        )
        self.assertEqual(snapshot["total_size"], 5)
        self.assertEqual(snapshot["phase"], "idle")

    def test_empty_and_truncated_uploads_leave_no_files(self):
        with self.assertRaises(ValueError):
            self.service.add_upload(io.BytesIO(b""), "empty.txt", 0)
        with self.assertRaises(ValueError):
            self.service.add_upload(io.BytesIO(b"ab"), "short.txt", 5)
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot["files"], [])
        staging = self.service._staging_dir
        if staging is not None:
            self.assertEqual(list(staging.iterdir()), [])

    def test_clear_files_removes_the_staging_directory(self):
        self.add("one.txt", b"123")
        staging = self.service._staging_dir
        self.assertIsNotNone(staging)
        self.assertTrue(Path(staging).exists())
        self.assertTrue(self.service.clear_files())
        self.assertFalse(Path(staging).exists())
        self.assertEqual(self.service.snapshot()["files"], [])

    def test_device_name_is_validated_and_updated(self):
        self.assertTrue(self.service.set_device_name("  Desk  "))
        self.assertEqual(self.service.snapshot()["device_name"], "Desk")
        self.assertFalse(self.service.set_device_name("   "))
        self.assertEqual(self.service.snapshot()["device_name"], "Desk")

    def test_windows_share_requires_a_selection(self):
        self.assertFalse(self.service.share_via_windows())
        self.assertEqual(
            self.service.snapshot()["error"],
            "Select at least one file to share.",
        )

    def test_windows_share_hands_staged_files_to_the_share_sheet(self):
        self.add("hello.txt", b"abc")
        staged = self.service._files[0]["path"]
        with patch.object(windows_share, "share_files") as share_files:
            self.assertTrue(self.service.share_via_windows())

        share_files.assert_called_once_with([staged])
        snapshot = self.service.snapshot()
        self.assertIsNone(snapshot["error"])
        self.assertEqual(snapshot["events"][-1]["text"], "Opened the Windows share sheet.")

    def test_windows_share_surfaces_unavailable_reason(self):
        self.add("hello.txt", b"abc")
        with patch.object(
            windows_share,
            "share_files",
            side_effect=windows_share.WindowsShareError("Not available here."),
        ):
            self.assertFalse(self.service.share_via_windows())

        snapshot = self.service.snapshot()
        self.assertEqual(snapshot["error"], "Not available here.")
        self.assertEqual(snapshot["events"][-1]["text"], "Windows sharing is unavailable.")


if __name__ == "__main__":
    unittest.main()

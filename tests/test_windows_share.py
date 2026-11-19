import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vishare_quick import windows_share


class FakeDeferral:
    def __init__(self):
        self.completed = False

    def complete(self):
        self.completed = True


class FakeProperties:
    def __init__(self):
        self.title = None
        self.description = None


class FakeData:
    def __init__(self):
        self.items = None
        self.properties = FakeProperties()

    def set_storage_items(self, items):
        self.items = list(items)


class FakeRequest:
    def __init__(self):
        self.data = FakeData()
        self.deferral = FakeDeferral()
        self.failure = None

    def get_deferral(self):
        return self.deferral

    def fail_with_display_text(self, text):
        self.failure = text


class FakeArgs:
    def __init__(self):
        self.request = FakeRequest()


class FakeStorageFile:
    @staticmethod
    async def get_file_from_path_async(path):
        return Path(path)


class FakeManager:
    def __init__(self):
        self.token = None
        self.removed = None

    def add_data_requested(self, handler):
        self.token = handler
        return "token-1"

    def remove_data_requested(self, token):
        self.removed = token


class FakeInterop:
    def __init__(self):
        self.manager = FakeManager()
        self.window = None
        self.shown = []
        self.error = None

    def get_for_window(self, hwnd):
        self.window = hwnd
        return self.manager

    def show_share_ui_for_window(self, hwnd):
        self.shown.append(hwnd)
        if self.error is not None:
            raise self.error
        if self.manager.token is not None:
            self.manager.token(None, FakeArgs())


class TestWindowsShareStatus(unittest.TestCase):
    def setUp(self):
        windows_share._reset_for_tests()

    def tearDown(self):
        windows_share._reset_for_tests()

    def test_non_windows_status_is_hidden(self):
        with patch.object(windows_share.os, "name", "posix"):
            result = windows_share.status(refresh=True)

        self.assertFalse(result["supported"])
        self.assertFalse(result["available"])
        self.assertEqual(result["label"], "Windows Nearby Sharing")
        self.assertIn("only available on Windows", result["reason"])

    def test_missing_winrt_is_unavailable(self):
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=None
        ):
            result = windows_share.status(refresh=True)

        self.assertTrue(result["supported"])
        self.assertFalse(result["available"])
        self.assertIn("not installed", result["reason"])

    def test_disabled_nearby_sharing_is_unavailable(self):
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=(object(), object())
        ), patch.object(
            windows_share,
            "_nearby_sharing_enabled",
            return_value=(False, "Turn it on."),
        ):
            result = windows_share.status(refresh=True)

        self.assertTrue(result["supported"])
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "Turn it on.")

    def test_available_requires_an_app_window(self):
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=(object(), object())
        ), patch.object(
            windows_share,
            "_nearby_sharing_enabled",
            return_value=(True, "Ready."),
        ), patch(
            "vishare_quick.windows_background.find_window", return_value=None
        ):
            result = windows_share.status(refresh=True)

        self.assertFalse(result["available"])
        self.assertIn("app window", result["reason"])

    def test_available_with_settings_and_window(self):
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=(object(), object())
        ), patch.object(
            windows_share,
            "_nearby_sharing_enabled",
            return_value=(True, "Ready."),
        ), patch(
            "vishare_quick.windows_background.find_window", return_value=42
        ):
            result = windows_share.status(refresh=True)

        self.assertTrue(result["available"])
        self.assertEqual(result["reason"], "Ready.")


class TestWindowsShareHandoff(unittest.TestCase):
    def setUp(self):
        windows_share._reset_for_tests()
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "hello.txt"
        self.path.write_text("hello", encoding="utf-8")

    def tearDown(self):
        windows_share._reset_for_tests()
        self.directory.cleanup()

    def test_non_windows_handoff_is_rejected(self):
        with patch.object(windows_share.os, "name", "posix"):
            with self.assertRaises(windows_share.WindowsShareError):
                windows_share.share_files([self.path])

    def test_empty_selection_is_rejected(self):
        with patch.object(windows_share.os, "name", "nt"):
            with self.assertRaises(windows_share.WindowsShareError):
                windows_share.share_files([])

    def test_missing_file_is_rejected(self):
        missing = Path(self.directory.name) / "missing.txt"
        with patch.object(windows_share.os, "name", "nt"):
            with self.assertRaises(windows_share.WindowsShareError):
                windows_share.share_files([missing])

    def test_data_requested_sets_files_and_completes_deferral(self):
        args = FakeArgs()
        manager = FakeManager()
        session = windows_share._ShareSession(
            manager, "token-1", (self.path,), FakeStorageFile
        )

        session.data_requested(None, args)

        self.assertEqual(args.request.data.items, [self.path])
        self.assertEqual(args.request.data.properties.title, "ViShare Quick")
        self.assertIsNone(args.request.failure)
        self.assertTrue(args.request.deferral.completed)
        self.assertTrue(session.finished.is_set())

    def test_data_requested_reports_preparation_failure(self):
        class BrokenStorageFile:
            @staticmethod
            async def get_file_from_path_async(path):
                raise OSError("no access")

        args = FakeArgs()
        session = windows_share._ShareSession(
            FakeManager(), "token-1", (self.path,), BrokenStorageFile
        )

        session.data_requested(None, args)

        self.assertIn("could not prepare", args.request.failure)
        self.assertTrue(args.request.deferral.completed)

    def test_handoff_uses_the_app_window_and_retains_the_session(self):
        interop = FakeInterop()
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=(interop, FakeStorageFile)
        ), patch(
            "vishare_quick.windows_background.find_window", return_value=123
        ):
            windows_share.share_files([self.path])

        self.assertEqual(interop.window, 123)
        self.assertEqual(interop.shown, [123])
        self.assertIsNotNone(windows_share._session)
        self.assertEqual(windows_share._session.paths, (self.path,))

    def test_show_error_is_translated_and_cleans_up(self):
        interop = FakeInterop()
        interop.error = RuntimeError("no share")
        with patch.object(windows_share.os, "name", "nt"), patch.object(
            windows_share, "_load_winrt", return_value=(interop, FakeStorageFile)
        ), patch(
            "vishare_quick.windows_background.find_window", return_value=123
        ):
            with self.assertRaises(windows_share.WindowsShareError):
                windows_share.share_files([self.path])

        self.assertIsNone(windows_share._session)
        self.assertEqual(interop.manager.removed, "token-1")

    def test_runs_storage_async_operations(self):
        async def operation():
            return await FakeStorageFile.get_file_from_path_async(self.path)

        self.assertEqual(asyncio.run(operation()), self.path)


if __name__ == "__main__":
    unittest.main()

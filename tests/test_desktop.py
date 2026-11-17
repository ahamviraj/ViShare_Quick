import sys
import threading
import types
import unittest
from unittest.mock import patch

from vishare_quick.desktop import WindowUnavailable, run_app_window


class FakeWindow:
    def __init__(self):
        self.destroyed = False

    def destroy(self):
        self.destroyed = True


class FakeServer:
    def __init__(self):
        self.stop_event = threading.Event()


class TestDesktopWindow(unittest.TestCase):
    def test_raises_when_webview_is_unavailable(self):
        server = FakeServer()
        with patch.dict(sys.modules, {"webview": None}):
            with self.assertRaises(WindowUnavailable):
                run_app_window(server, "http://127.0.0.1:1/")

    def test_creates_window_and_watches_server_stop(self):
        server = FakeServer()
        window = FakeWindow()
        module = types.ModuleType("webview")
        calls = []

        def create_window(title, url, **options):
            calls.append((title, url, options))
            return window

        def start(**options):
            calls.append(("start", options))
            server.stop_event.set()

        module.create_window = create_window
        module.start = start
        with patch.dict(sys.modules, {"webview": module}):
            run_app_window(server, "http://127.0.0.1:1/")

        self.assertEqual(calls[0][0], "ViShare Quick")
        self.assertEqual(calls[0][1], "http://127.0.0.1:1/")
        self.assertTrue(calls[0][2]["text_select"])
        self.assertEqual(calls[1][0], "start")

    def test_start_failure_is_reported(self):
        server = FakeServer()
        window = FakeWindow()
        module = types.ModuleType("webview")
        module.create_window = lambda *args, **kwargs: window

        def start(**options):
            raise RuntimeError("backend crashed")

        module.start = start
        with patch.dict(sys.modules, {"webview": module}):
            with self.assertRaises(WindowUnavailable):
                run_app_window(server, "http://127.0.0.1:1/")


if __name__ == "__main__":
    unittest.main()

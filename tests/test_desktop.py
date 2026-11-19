import sys
import threading
import types
import unittest
from unittest.mock import patch

from vishare_quick.desktop import WindowUnavailable, run_app_window


class FakeEvent:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self

    def wait(self, timeout=None):
        return True


class FakeEvents:
    def __init__(self):
        self.closing = FakeEvent()
        self.loaded = FakeEvent()


class FakeWindow:
    def __init__(self):
        self.destroyed = False
        self.hidden = False
        self.shown = 0
        self.restored = 0
        self.events = FakeEvents()

    def destroy(self):
        self.destroyed = True

    def hide(self):
        self.hidden = True

    def show(self):
        self.shown += 1
        self.hidden = False

    def restore(self):
        self.restored += 1


class FakeServer:
    def __init__(self):
        self.stop_event = threading.Event()


class FakeTray:
    instances = []

    def __init__(self, on_open, on_quit):
        self.on_open = on_open
        self.on_quit = on_quit
        self.started = True
        self.stopped = False
        FakeTray.instances.append(self)

    def start(self):
        return self.started

    def stop(self):
        self.stopped = True


class FakeHotkey:
    instances = []

    def __init__(self, callback):
        self.callback = callback
        self.started = False
        self.stopped = False
        FakeHotkey.instances.append(self)

    def start(self):
        self.started = True
        return True

    def stop(self):
        self.stopped = True


class FakeSingleInstance:
    instances = []
    allow = True

    def __init__(self):
        self.released = False
        self.show_callback = None
        FakeSingleInstance.instances.append(self)

    def acquire(self, on_show):
        self.show_callback = on_show
        return self.allow

    def release(self):
        self.released = True


def background_module(tray_started=True, primary=True):
    module = types.ModuleType("vishare_quick.windows_background")
    module.SingleInstance = FakeSingleInstance
    module.TrayIcon = FakeTray
    module.GlobalHotkey = FakeHotkey
    module.hide_console_if_owned = lambda: False
    FakeTray.instances.clear()
    FakeHotkey.instances.clear()
    FakeSingleInstance.instances.clear()
    FakeSingleInstance.allow = primary
    FakeTray.start = lambda self: tray_started
    return module


class TestDesktopWindow(unittest.TestCase):
    def setUp(self):
        FakeTray.instances.clear()
        FakeHotkey.instances.clear()
        FakeSingleInstance.instances.clear()

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

    def test_background_close_hides_and_tray_quit_exits(self):
        server = FakeServer()
        window = FakeWindow()
        module = types.ModuleType("webview")
        close_results = []

        def start(**options):
            close_results.append(window.events.closing.handlers[0]())
            self.assertTrue(window.hidden)
            FakeTray.instances[0].on_open()
            self.assertGreater(window.shown, 0)
            FakeTray.instances[0].on_quit()
            FakeHotkey.instances[0].callback()
            self.assertGreaterEqual(window.shown, 1)

        module.create_window = lambda *args, **kwargs: window
        module.start = start
        background = background_module()
        with patch.dict(
            sys.modules,
            {
                "webview": module,
                "vishare_quick.windows_background": background,
            },
        ):
            run_app_window(
                server,
                "http://127.0.0.1:1/",
                enable_background=True,
            )

        self.assertEqual(close_results, [False])
        self.assertTrue(server.stop_event.is_set())
        self.assertTrue(window.destroyed)
        self.assertTrue(FakeTray.instances[0].stopped)
        self.assertTrue(FakeHotkey.instances[0].stopped)
        self.assertTrue(FakeSingleInstance.instances[0].released)

    def test_background_start_can_begin_hidden(self):
        server = FakeServer()
        window = FakeWindow()
        module = types.ModuleType("webview")
        options_seen = {}

        def create_window(title, url, **options):
            options_seen.update(options)
            return window

        def start(**options):
            FakeTray.instances[0].on_quit()

        module.create_window = create_window
        module.start = start
        background = background_module()
        with patch.dict(
            sys.modules,
            {
                "webview": module,
                "vishare_quick.windows_background": background,
            },
        ):
            run_app_window(
                server,
                "http://127.0.0.1:1/",
                start_hidden=True,
                enable_background=True,
            )

        self.assertTrue(options_seen["hidden"])

    def test_second_launch_does_not_create_a_window(self):
        server = FakeServer()
        module = types.ModuleType("webview")
        module.create_window = lambda *args, **kwargs: self.fail(
            "second launch must not create a window"
        )
        module.start = lambda **options: None
        background = background_module(primary=False)
        with patch.dict(
            sys.modules,
            {
                "webview": module,
                "vishare_quick.windows_background": background,
            },
        ):
            run_app_window(
                server,
                "http://127.0.0.1:1/",
                enable_background=True,
            )

        self.assertFalse(FakeSingleInstance.instances[0].released)


if __name__ == "__main__":
    unittest.main()

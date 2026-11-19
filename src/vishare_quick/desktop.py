"""Native desktop window for the local ViShare Quick interface.

The interface is still the same loopback-only HTML application. This module
only wraps it in a platform webview so the default launch does not leave the
application for a browser tab. Importing :mod:`webview` is deliberately lazy:
headless commands, tests, and Linux systems without GTK/WebKit keep working,
and :func:`run_app_window` reports a fallback instead of crashing.
"""
from __future__ import annotations

import threading
from typing import Any

WINDOW_TITLE = "ViShare Quick"
WINDOW_SIZE = (560, 840)
WINDOW_MIN_SIZE = (420, 600)
WINDOW_BACKGROUND = "#1e1e26"


class WindowUnavailable(RuntimeError):
    """The platform webview could not be started."""


def run_app_window(
    server: Any,
    url: str,
    *,
    start_hidden: bool = False,
    enable_background: bool = False,
) -> None:
    """Show ``url`` in an app window and block until the window closes.

    ``server.stop_event`` is set when the interface stops itself from the
    Settings page. Watching that event closes the window as well, so stopping
    the interface never leaves an empty shell behind.

    With ``enable_background`` on Windows, a tray icon and the ``Ctrl+Alt+V``
    global hotkey stay available while the window is hidden. Closing the window
    then hides it instead of exiting; the tray Quit action and Settings stop
    path still shut the interface down completely.

    Raises :class:`WindowUnavailable` when no supported webview backend is
    installed or when the backend fails before the window is usable.
    """
    try:
        import webview
    except Exception as exc:  # noqa: BLE001 - platform backend varies by OS
        raise WindowUnavailable("No supported app window backend is available.") from exc

    if not enable_background:
        start_hidden = False

    window_holder: list[Any] = []
    quitting = threading.Event()
    tray = None
    hotkey = None
    single_instance = None
    windows_background = None

    def show_window() -> None:
        if not window_holder:
            return
        window = window_holder[0]
        for action_name in ("show", "restore"):
            try:
                action = getattr(window, action_name, None)
                if action is not None:
                    action()
            except Exception:  # noqa: BLE001 - alternate backend/window shape
                pass

    def request_quit() -> None:
        quitting.set()
        server.stop_event.set()
        if window_holder:
            try:
                window_holder[0].destroy()
            except Exception:  # noqa: BLE001 - the window may already be closed
                pass

    if enable_background:
        try:
            from vishare_quick import windows_background as background_module
        except Exception:  # noqa: BLE001 - non-Windows or missing helpers
            background_module = None
        windows_background = background_module
        if windows_background is not None:
            single_instance = windows_background.SingleInstance()
            if not single_instance.acquire(show_window):
                return

    window_options = {
        "width": WINDOW_SIZE[0],
        "height": WINDOW_SIZE[1],
        "min_size": WINDOW_MIN_SIZE,
        "background_color": WINDOW_BACKGROUND,
        "text_select": True,
    }
    if start_hidden:
        window_options["hidden"] = True
    try:
        window = webview.create_window(
            WINDOW_TITLE,
            url,
            **window_options,
        )
    except Exception as exc:  # noqa: BLE001 - platform backend varies by OS
        if single_instance is not None:
            single_instance.release()
        raise WindowUnavailable("The app window could not be created.") from exc
    window_holder.append(window)

    if windows_background is not None:
        tray = windows_background.TrayIcon(show_window, request_quit)
        if not tray.start():
            print("Notification-area icon is unavailable.", flush=True)
            tray = None
        else:
            def hide_on_close() -> bool:
                if quitting.is_set() or server.stop_event.is_set():
                    return True
                try:
                    window.hide()
                except Exception:  # noqa: BLE001 - backend may not support hide
                    return True
                windows_background.hide_console_if_owned()
                return False

            try:
                window.events.closing += hide_on_close
            except Exception:  # noqa: BLE001 - backend without closing event
                tray.stop()
                tray = None

        hotkey = windows_background.GlobalHotkey(show_window)
        if not hotkey.start():
            print("Global shortcut Ctrl+Alt+V is unavailable.", flush=True)
        if start_hidden:
            windows_background.hide_console_if_owned()
            if tray is None:
                def reveal_after_load() -> None:
                    try:
                        window.events.loaded.wait(10)
                        window.show()
                    except Exception:  # noqa: BLE001 - last-resort reveal
                        pass

                threading.Thread(
                    target=reveal_after_load,
                    name="vishare-quick-window-reveal",
                    daemon=True,
                ).start()

    def close_when_interface_stops() -> None:
        server.stop_event.wait()
        try:
            window.events.loaded.wait(15)
        except Exception:  # noqa: BLE001 - alternate backend/window shape
            pass
        try:
            window.destroy()
        except Exception:  # noqa: BLE001 - the window may already be closed
            pass

    threading.Thread(
        target=close_when_interface_stops,
        name="vishare-quick-window-close",
        daemon=True,
    ).start()

    try:
        webview.start(debug=False)
    except Exception as exc:  # noqa: BLE001 - platform backend varies by OS
        raise WindowUnavailable("The app window could not be started.") from exc
    finally:
        if hotkey is not None:
            hotkey.stop()
        if tray is not None:
            tray.stop()
        if single_instance is not None:
            single_instance.release()

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


def run_app_window(server: Any, url: str) -> None:
    """Show ``url`` in an app window and block until the window closes.

    ``server.stop_event`` is set when the interface stops itself from the
    Settings page. Watching that event closes the window as well, so stopping
    the interface never leaves an empty shell behind.

    Raises :class:`WindowUnavailable` when no supported webview backend is
    installed or when the backend fails before the window is usable.
    """
    try:
        import webview
    except Exception as exc:  # noqa: BLE001 - platform backend varies by OS
        raise WindowUnavailable("No supported app window backend is available.") from exc

    try:
        window = webview.create_window(
            WINDOW_TITLE,
            url,
            width=WINDOW_SIZE[0],
            height=WINDOW_SIZE[1],
            min_size=WINDOW_MIN_SIZE,
            background_color=WINDOW_BACKGROUND,
            text_select=True,
        )
    except Exception as exc:  # noqa: BLE001 - platform backend varies by OS
        raise WindowUnavailable("The app window could not be created.") from exc

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

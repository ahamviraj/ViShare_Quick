"""Windows-only handoff to the system share sheet.

Windows Nearby Sharing is a different protocol from Google Quick Share. This
module does not claim to receive or discover Quick Share peers; it only lets a
user hand staged files to the Windows share sheet, where Nearby Sharing is one
of the available destinations.

The WinRT imports and registry checks are deliberately lazy so the rest of
ViShare Quick still imports on Linux and in headless test environments.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterable

LABEL = "Windows Nearby Sharing"
_CDP_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage"
_POLICY_VALUE = "NearShareChannelUserAuthzPolicy"
_BLUETOOTH_OFF_VALUE = "BluetoothLastDisabledNearShare"
_WIFI_OFF_VALUE = "WifiLastDisabledNearShare"
_STATUS_TTL_SECONDS = 5.0

_status_lock = threading.Lock()
_status_cache: tuple[float, dict[str, Any]] | None = None
_winrt_lock = threading.Lock()
_winrt_modules: tuple[Any, Any] | None | bool = False
_session_lock = threading.RLock()
_session: _ShareSession | None = None


class WindowsShareError(RuntimeError):
    """The Windows share sheet could not be opened."""


def _load_winrt() -> tuple[Any, Any] | None:
    """Return the interop module and StorageFile class, or ``None``."""
    global _winrt_modules
    with _winrt_lock:
        if _winrt_modules is not False:
            return _winrt_modules  # type: ignore[return-value]
        try:
            from winrt.windows.applicationmodel.datatransfer import (  # noqa: PLC0415
                interop,
            )
            from winrt.windows.storage import StorageFile  # noqa: PLC0415

            _winrt_modules = (interop, StorageFile)
        except Exception:  # noqa: BLE001 - optional Windows integration
            _winrt_modules = None
    return _winrt_modules  # type: ignore[return-value]


def _nearby_sharing_enabled() -> tuple[bool, str]:
    try:
        import winreg  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - not Windows
        return False, "Windows Nearby Sharing is only available on Windows."
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CDP_SETTINGS) as key:
            policy = int(winreg.QueryValueEx(key, _POLICY_VALUE)[0])
            bluetooth_off = int(
                winreg.QueryValueEx(key, _BLUETOOTH_OFF_VALUE)[0]
            )
            wifi_off = int(winreg.QueryValueEx(key, _WIFI_OFF_VALUE)[0])
    except FileNotFoundError:
        return False, "Turn on Nearby Sharing in Windows Settings to use this option."
    except (OSError, TypeError, ValueError):
        return False, "Windows Nearby Sharing settings could not be read."
    if policy <= 0:
        return False, "Nearby Sharing is turned off in Windows Settings."
    if bluetooth_off or wifi_off:
        return (
            False,
            "Nearby Sharing is turned off for Bluetooth or Wi-Fi in Windows Settings.",
        )
    return True, "Open the Windows share sheet, then choose the nearby device."


def status(*, refresh: bool = False) -> dict[str, Any]:
    """Return a JSON-safe availability description for the Send page."""
    global _status_cache
    now = time.monotonic()
    with _status_lock:
        if (
            not refresh
            and _status_cache is not None
            and now - _status_cache[0] < _STATUS_TTL_SECONDS
        ):
            return dict(_status_cache[1])

    supported = os.name == "nt"
    result: dict[str, Any] = {
        "label": LABEL,
        "supported": supported,
        "available": False,
        "reason": "Windows Nearby Sharing is only available on Windows.",
    }
    if supported:
        if _load_winrt() is None:
            result["reason"] = (
                "Windows share support is not installed in this build."
            )
        else:
            enabled, reason = _nearby_sharing_enabled()
            result["reason"] = reason
            if enabled:
                try:
                    from vishare_quick.windows_background import (  # noqa: PLC0415
                        find_window,
                    )

                    window = find_window()
                except Exception:  # noqa: BLE001 - optional Windows integration
                    window = None
                if window is None:
                    result["reason"] = (
                        "Open ViShare Quick in its app window to use Windows sharing."
                    )
                else:
                    result["available"] = True

    with _status_lock:
        _status_cache = (now, dict(result))
    return result


class _ShareSession:
    """Keep the WinRT manager and handler alive while the sheet is open."""

    def __init__(
        self,
        manager: Any,
        token: Any,
        paths: tuple[Path, ...],
        storage_file: Any,
    ) -> None:
        self.manager = manager
        self.token = token
        self.paths = paths
        self.storage_file = storage_file
        self.finished = threading.Event()

    def data_requested(self, _manager: Any, args: Any) -> None:
        request = args.request
        deferral = request.get_deferral()
        try:
            items = [
                asyncio.run(
                    self.storage_file.get_file_from_path_async(str(path))
                )
                for path in self.paths
            ]
            request.data.set_storage_items(items)
            request.data.properties.title = "ViShare Quick"
            request.data.properties.description = (
                "Files shared from ViShare Quick"
            )
        except Exception:  # noqa: BLE001 - the share sheet owns the UI
            try:
                request.fail_with_display_text(
                    "ViShare Quick could not prepare these files."
                )
            except Exception:  # noqa: BLE001 - fail closed for the sheet
                pass
        finally:
            try:
                deferral.complete()
            except Exception:  # noqa: BLE001 - the sheet may have closed
                pass
            self.finished.set()

    def close(self) -> None:
        try:
            self.manager.remove_data_requested(self.token)
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass


def share_files(
    paths: Iterable[str | Path], *, window_handle: int | None = None
) -> None:
    """Open the Windows share sheet for ``paths``.

    Raises :class:`WindowsShareError` with a user-facing message when the
    handoff is unavailable or the system rejects the window.
    """
    global _session
    if os.name != "nt":
        raise WindowsShareError("Windows Nearby Sharing is only available on Windows.")
    selected = tuple(Path(path) for path in paths)
    if not selected:
        raise WindowsShareError("Select at least one file to share.")
    if any(not path.is_file() for path in selected):
        raise WindowsShareError("The selected files are no longer available.")
    modules = _load_winrt()
    if modules is None:
        raise WindowsShareError(
            "Windows share support is not installed in this build."
        )
    interop, StorageFile = modules
    if window_handle is None:
        try:
            from vishare_quick.windows_background import find_window  # noqa: PLC0415

            window_handle = find_window()
        except Exception:  # noqa: BLE001 - optional Windows integration
            window_handle = None
    if not window_handle:
        raise WindowsShareError(
            "Open ViShare Quick in its app window to use Windows sharing."
        )
    try:
        manager = interop.get_for_window(int(window_handle))
        session = _ShareSession(manager, None, selected, StorageFile)
        session.token = manager.add_data_requested(session.data_requested)
        with _session_lock:
            previous = _session
            _session = session
        if previous is not None:
            previous.close()
        try:
            interop.show_share_ui_for_window(int(window_handle))
        except Exception:
            with _session_lock:
                if _session is session:
                    _session = None
            session.close()
            raise
        if not session.finished.wait(5.0):
            with _session_lock:
                if _session is session:
                    _session = None
            session.close()
            raise WindowsShareError(
                "The Windows share sheet did not open. Start the installed "
                "app directly instead of from another program."
            )
    except WindowsShareError:
        raise
    except Exception as exc:  # noqa: BLE001 - translated for the local UI
        raise WindowsShareError(
            "The Windows share sheet could not be opened."
        ) from exc


def shutdown() -> None:
    """Release the retained WinRT session, if any."""
    global _session
    with _session_lock:
        session = _session
        _session = None
    if session is not None:
        session.close()


def _reset_for_tests() -> None:
    global _status_cache, _winrt_modules
    shutdown()
    with _status_lock:
        _status_cache = None
    with _winrt_lock:
        _winrt_modules = False

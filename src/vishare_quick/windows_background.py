"""Windows-only tray, hotkey, and single-instance helpers.

The functions in this module are deliberately optional. On Linux, or when the
tray dependencies are missing, the desktop wrapper keeps its previous
close-to-exit behaviour. All Win32 setup is lazy so importing the package never
requires Windows.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

APP_ID = "ViShareQuick"
TRAY_TITLE = "ViShare Quick"
HOTKEY_LABEL = "Ctrl+Alt+V"

_MUTEX_NAME = "Local\\ViShareQuick.SingleInstance"
_SHOW_EVENT_NAME = "Local\\ViShareQuick.Show"
_STOP_EVENT_NAME = "Local\\ViShareQuick.Stop"
_ERROR_ALREADY_EXISTS = 183
_EVENT_MODIFY_STATE = 0x0002
_INFINITE = 0xFFFFFFFF
_WAIT_OBJECT_0 = 0

_WM_CLOSE = 0x0010
_WM_DESTROY = 0x0002
_WM_HOTKEY = 0x0312
_MOD_ALT = 0x0001
_MOD_CONTROL = 0x0002
_MOD_NOREPEAT = 0x4000
_VK_V = 0x56
_SW_HIDE = 0

_kernel32: Any = None
_user32: Any = None


def _kernel() -> Any:
    global _kernel32
    if _kernel32 is None:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.OpenEventW.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.OpenEventW.restype = wintypes.HANDLE
        kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        kernel32.SetEvent.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.WaitForMultipleObjects.argtypes = [
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetConsoleWindow.restype = wintypes.HWND
        kernel32.GetConsoleProcessList.argtypes = [
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        kernel32.GetConsoleProcessList.restype = wintypes.DWORD
        kernel32.GetCurrentProcessId.argtypes = []
        kernel32.GetCurrentProcessId.restype = wintypes.DWORD
        _kernel32 = kernel32
    return _kernel32


def _user() -> Any:
    global _user32
    if _user32 is None:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.RegisterClassW.argtypes = [ctypes.c_void_p]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.RegisterHotKey.argtypes = [
            wintypes.HWND,
            ctypes.c_int,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.RegisterHotKey.restype = wintypes.BOOL
        user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.UnregisterHotKey.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.TranslateMessage.argtypes = [ctypes.c_void_p]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t
        user32.GetMessageW.argtypes = [
            ctypes.c_void_p,
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.GetMessageW.restype = ctypes.c_int
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.EnumWindows.argtypes = [
            ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
            ),
            wintypes.LPARAM,
        ]
        user32.EnumWindows.restype = wintypes.BOOL
        user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextW.argtypes = [
            wintypes.HWND,
            wintypes.LPWSTR,
            ctypes.c_int,
        ]
        user32.GetWindowTextW.restype = ctypes.c_int
        _user32 = user32
    return _user32


def find_window(title: str = TRAY_TITLE) -> int | None:
    """Return this process's top-level window with exactly ``title``."""
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        kernel32 = _kernel()
        user32 = _user()
        callback_type = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        pid = kernel32.GetCurrentProcessId()
        found: list[int] = []

        def inspect(hwnd: int, _lparam: int) -> bool:
            owner = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value != pid:
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            if buffer.value.strip() != title:
                return True
            found.append(int(hwnd))
            return False

        callback = callback_type(inspect)
        user32.EnumWindows(callback, 0)
        return found[0] if found else None
    except Exception:  # noqa: BLE001 - optional Windows integration
        return None


def hide_console_if_owned() -> bool:
    """Hide a console created for this process, but not a shared terminal."""
    if os.name != "nt":
        return False
    try:
        from ctypes import wintypes

        kernel32 = _kernel()
        console = kernel32.GetConsoleWindow()
        if not console:
            return False
        processes = (wintypes.DWORD * 2)()
        count = kernel32.GetConsoleProcessList(processes, 2)
        if count > 1:
            return False
        _user().ShowWindow(console, _SW_HIDE)
        return True
    except Exception:  # noqa: BLE001 - optional Windows integration
        return False


class SingleInstance:
    """Forward a second launch to the running window, or become primary."""

    def __init__(self) -> None:
        self._mutex = None
        self._show_event = None
        self._stop_event = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def acquire(self, on_show: Callable[[], None]) -> bool:
        """Return True for the primary instance, False after showing it."""
        if os.name != "nt":
            return True
        try:
            kernel32 = _kernel()
            ctypes.set_last_error(0)
            self._mutex = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
            if not self._mutex:
                return True
            if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
                self._signal_existing()
                kernel32.CloseHandle(self._mutex)
                self._mutex = None
                return False
            self._show_event = kernel32.CreateEventW(
                None, False, False, _SHOW_EVENT_NAME
            )
            self._stop_event = kernel32.CreateEventW(
                None, True, False, _STOP_EVENT_NAME
            )
            if not self._show_event or not self._stop_event:
                self.release()
                return True
            self._thread = threading.Thread(
                target=self._watch,
                args=(on_show,),
                name="vishare-quick-single-instance",
                daemon=True,
            )
            self._thread.start()
            return True
        except Exception:  # noqa: BLE001 - never block startup on this helper
            self.release()
            return True

    def _signal_existing(self) -> None:
        try:
            kernel32 = _kernel()
            event = kernel32.OpenEventW(
                _EVENT_MODIFY_STATE, False, _SHOW_EVENT_NAME
            )
            if event:
                kernel32.SetEvent(event)
                kernel32.CloseHandle(event)
        except Exception:  # noqa: BLE001 - best-effort foreground request
            pass

    def _watch(self, on_show: Callable[[], None]) -> None:
        try:
            from ctypes import wintypes

            kernel32 = _kernel()
            handles = (wintypes.HANDLE * 2)(
                self._show_event, self._stop_event
            )
            while True:
                result = kernel32.WaitForMultipleObjects(
                    2, handles, False, _INFINITE
                )
                if result != _WAIT_OBJECT_0:
                    return
                try:
                    on_show()
                except Exception:  # noqa: BLE001 - callback belongs to caller
                    pass
        except Exception:  # noqa: BLE001 - optional background helper
            return

    def release(self) -> None:
        if self._closed:
            return
        self._closed = True
        kernel32 = None
        try:
            kernel32 = _kernel()
            if self._stop_event:
                kernel32.SetEvent(self._stop_event)
        except Exception:  # noqa: BLE001 - process exit cleans up handles
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if kernel32 is not None:
            for handle in (self._show_event, self._stop_event, self._mutex):
                if handle:
                    try:
                        kernel32.CloseHandle(handle)
                    except Exception:  # noqa: BLE001 - best-effort cleanup
                        pass
        self._show_event = None
        self._stop_event = None
        self._mutex = None


class TrayIcon:
    """Small notification-area icon with Open and Quit actions."""

    def __init__(
        self,
        on_open: Callable[[], None],
        on_quit: Callable[[], None],
    ) -> None:
        self._on_open = on_open
        self._on_quit = on_quit
        self._icon: Any = None

    def start(self) -> bool:
        if os.name != "nt":
            return False
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception:  # noqa: BLE001 - tray is optional
            return False
        try:
            menu = pystray.Menu(
                pystray.MenuItem(
                    "Open ViShare Quick", self._open, default=True
                ),
                pystray.MenuItem("Quit ViShare Quick", self._quit),
            )
            self._icon = pystray.Icon(
                APP_ID,
                _tray_image(Image, ImageDraw),
                TRAY_TITLE,
                menu,
            )
            self._icon.run_detached()
            return True
        except Exception:  # noqa: BLE001 - a failed tray must not hide the app
            self._icon = None
            return False

    def _open(self, _icon: Any = None, _item: Any = None) -> None:
        self._on_open()

    def _quit(self, _icon: Any = None, _item: Any = None) -> None:
        self._on_quit()

    def stop(self) -> None:
        icon = self._icon
        self._icon = None
        if icon is not None:
            try:
                icon.stop()
            except Exception:  # noqa: BLE001 - closing during shutdown
                pass


class GlobalHotkey:
    """Register ``Ctrl+Alt+V`` to bring the existing window forward."""

    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._wndproc: Any = None
        self.registered = False

    def start(self) -> bool:
        if os.name != "nt":
            return False
        self._thread = threading.Thread(
            target=self._run,
            name="vishare-quick-global-hotkey",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait(timeout=2.0)
        return bool(self._hwnd and self.registered)

    def stop(self) -> None:
        hwnd = self._hwnd
        if hwnd:
            try:
                _user().PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            except Exception:  # noqa: BLE001 - closing during shutdown
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        try:
            from ctypes import wintypes

            kernel32 = _kernel()
            user32 = _user()
            class_name = f"ViShareQuickHotkey{os.getpid()}"
            wndproc_type = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t,
                wintypes.HWND,
                wintypes.UINT,
                wintypes.WPARAM,
                wintypes.LPARAM,
            )

            def window_proc(hwnd, message, wparam, lparam):
                if message == _WM_HOTKEY:
                    try:
                        self._callback()
                    except Exception:  # noqa: BLE001 - callback belongs to caller
                        pass
                    return 0
                if message == _WM_CLOSE:
                    user32.DestroyWindow(hwnd)
                    return 0
                if message == _WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, message, wparam, lparam)

            wndproc = wndproc_type(window_proc)
            self._wndproc = wndproc

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", wintypes.UINT),
                    ("lpfnWndProc", wndproc_type),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE),
                    ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR),
                    ("lpszClassName", wintypes.LPCWSTR),
                ]

            instance = kernel32.GetModuleHandleW(None)
            window_class = WNDCLASSW()
            window_class.lpfnWndProc = wndproc
            window_class.hInstance = instance
            window_class.lpszClassName = class_name
            if not user32.RegisterClassW(ctypes.byref(window_class)):
                self._ready.set()
                return
            hwnd = user32.CreateWindowExW(
                0,
                class_name,
                class_name,
                0,
                0,
                0,
                0,
                0,
                None,
                None,
                instance,
                None,
            )
            if not hwnd:
                self._ready.set()
                return
            self._hwnd = hwnd
            self.registered = bool(
                user32.RegisterHotKey(
                    hwnd,
                    1,
                    _MOD_CONTROL | _MOD_ALT | _MOD_NOREPEAT,
                    _VK_V,
                )
            )
            self._ready.set()
            message = wintypes.MSG()
            while user32.GetMessageW(
                ctypes.byref(message), None, 0, 0
            ) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
            if self.registered:
                user32.UnregisterHotKey(hwnd, 1)
                self.registered = False
        except Exception:  # noqa: BLE001 - hotkey is optional
            self._ready.set()
        finally:
            self._hwnd = None


def _tray_image(image_module: Any, draw_module: Any) -> Any:
    icon_path = _resource_path("installer/vishare-quick.ico")
    if icon_path.is_file():
        try:
            image = image_module.open(icon_path)
            if image.mode != "RGBA":
                image = image.convert("RGBA")
            return image
        except Exception:  # noqa: BLE001 - fall back to a generated icon
            pass
    image = image_module.new("RGBA", (64, 64), (30, 30, 38, 255))
    draw = draw_module.Draw(image)
    draw.ellipse((8, 8, 56, 56), fill=(122, 92, 255, 255))
    draw.ellipse((20, 20, 44, 44), fill=(255, 255, 255, 255))
    return image


def _resource_path(relative: str) -> Path:
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        return Path(bundle_root) / relative
    return Path(__file__).resolve().parents[2] / relative

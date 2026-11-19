"""Loopback-only interface for the ViShare Quick receiver and sender.

The interface is intentionally plain: a local HTTP server serves a small set of
static screens and a JSON API to the app window or the user's own browser. The
server binds to ``127.0.0.1`` only, every API call needs a fresh per-run token,
and cross-origin requests are neither allowed nor advertised.

The screens render only what
:class:`vishare_quick.ui_service.ReceiveService` exposes. Peer payload
identifiers, key material, and payload bytes never cross this boundary.
"""
from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import secrets
import socket
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from vishare_quick import __version__
from vishare_quick.send_service import SendService
from vishare_quick.ui import STATIC_DIR
from vishare_quick.ui_service import ReceiveService

MAX_BODY_BYTES = 8 * 1024
MAX_UPLOAD_BYTES = 1 << 40  # 1 TiB, mirroring the sender's declared-size bound
_LOOPBACK_HOST = "127.0.0.1"
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_ASSET_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
}
_PAGES = frozenset(
    {
        "index.html",
        "receive-main.html",
        "receive-request.html",
        "receive-receiving.html",
        "receive-received.html",
        "send-send.html",
        "send-sending.html",
        "send-failed.html",
        "settings.html",
        "under-construction.html",
    }
)
_CSP = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'"
)


def _normalized_host(header: str | None) -> str | None:
    """Return a Host-header name without its port, or ``None``."""
    if not header:
        return None
    value = header.strip().lower()
    if not value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        return value[: end + 1]
    if ":" in value:
        return value.rsplit(":", 1)[0]
    return value


def _safe_static_path(request_path: str) -> Path | None:
    """Map an allowed static URL to a file inside the package directory."""
    if request_path == "/app.js":
        relative = "app.js"
    elif request_path.startswith("/styles/") or request_path.startswith("/assets/"):
        folder, _, name = request_path.lstrip("/").partition("/")
        if not name or "/" in name or "\\" in name or name in {".", ".."}:
            return None
        relative = f"{folder}/{name}"
    else:
        return None
    if Path(relative).suffix.lower() not in _ASSET_TYPES:
        return None
    if relative.startswith("styles/") and Path(relative).suffix.lower() != ".css":
        return None
    candidate = (STATIC_DIR / relative).resolve()
    static_root = STATIC_DIR.resolve()
    if candidate == static_root or static_root not in candidate.parents:
        return None
    return candidate


class UiHTTPServer(ThreadingHTTPServer):
    """Threaded loopback server carrying the service and API token."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        *,
        service: ReceiveService,
        send_service: SendService,
        token: str,
    ) -> None:
        self.service = service
        self.send_service = send_service
        self.token = token
        self.stop_event = threading.Event()
        super().__init__(server_address, request_handler)

    def shutdown(self) -> None:
        """Stop the serve loop and wake the desktop window watcher."""
        super().shutdown()
        self.stop_event.set()

    def snapshot(self) -> dict[str, Any]:
        """Merge the receiver and sender snapshots for the local pages."""
        state = dict(self.service.snapshot())
        state["send"] = self.send_service.snapshot()
        return state

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(
            error,
            (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, socket.timeout),
        ):
            return
        super().handle_error(request, client_address)


class UiRequestHandler(BaseHTTPRequestHandler):
    """Serve the static interface and the token-protected action API."""

    server: UiHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "ViShareQuickUI"
    sys_version = ""

    # ---------------------------------------------------------------- plumbing
    def log_message(self, format: str, *args: Any) -> None:
        """Keep the terminal quiet; the page has its own activity list."""

    def _host_allowed(self) -> bool:
        return _normalized_host(self.headers.get("Host")) in _ALLOWED_HOSTS

    def _token_allowed(self) -> bool:
        supplied = self.headers.get("X-ViShare-Token", "")
        return hmac.compare_digest(
            supplied.encode("utf-8"), self.server.token.encode("utf-8")
        )

    def _common_headers(self) -> None:
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")

    def _send_bytes(
        self,
        status: HTTPStatus | int,
        body: bytes,
        content_type: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _send_error_json(
        self, status: int, message: str, *, close: bool = False
    ) -> None:
        if close:
            # An unread POST body would otherwise be parsed as the next request
            # on a keep-alive connection.
            self.close_connection = True
        self._send_json(status, {"ok": False, "error": message})

    def _read_json_body(self) -> dict[str, Any] | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return {}
        try:
            length = int(raw_length)
        except ValueError:
            self._send_error_json(400, "Invalid Content-Length.", close=True)
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_error_json(413, "Request body is too large.", close=True)
            return None
        if length == 0:
            return {}
        try:
            raw = self.rfile.read(length)
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_error_json(400, "Request body must be JSON.", close=True)
            return None
        if not isinstance(parsed, dict):
            self._send_error_json(
                400, "Request body must be a JSON object.", close=True
            )
            return None
        return parsed

    def _reply_state(self, ok: bool = True, status: int = 200) -> None:
        self._send_json(status, {"ok": ok, "state": self.server.snapshot()})

    def _require_api_access(self) -> bool:
        if not self._host_allowed():
            self._send_error_json(
                403, "This interface only accepts loopback requests.", close=True
            )
            return False
        if not self._token_allowed():
            self._send_error_json(
                401, "Missing or invalid interface token.", close=True
            )
            return False
        return True

    # -------------------------------------------------------------------- GET
    def do_GET(self) -> None:
        if not self._host_allowed():
            self._send_error_json(403, "This interface only accepts loopback requests.")
            return
        path = urlsplit(self.path).path
        if path == "/" or path == "/index.html":
            self._serve_page("index.html")
            return
        if path.lstrip("/") in _PAGES:
            self._serve_page(path.lstrip("/"))
            return
        if path == "/favicon.ico":
            self._serve_asset(STATIC_DIR / "assets" / "vishare-quick-icon-squircle.svg")
            return
        if path == "/api/state":
            if not self._token_allowed():
                self._send_error_json(401, "Missing or invalid interface token.")
                return
            self._send_json(200, self.server.snapshot())
            return
        static_file = _safe_static_path(path)
        if static_file is not None:
            self._serve_asset(static_file)
            return
        self._send_error_json(404, "Not found.")

    def _serve_page(self, name: str) -> None:
        if name not in _PAGES:
            self._send_error_json(404, "Not found.")
            return
        try:
            template = (STATIC_DIR / name).read_text(encoding="utf-8")
        except OSError:
            self._send_error_json(500, "The interface files are missing.")
            return
        document = (
            template.replace("__VISHARE_TOKEN__", self.server.token)
            .replace("__VISHARE_VERSION__", __version__)
            .encode("utf-8")
        )
        self._send_bytes(HTTPStatus.OK, document, "text/html; charset=utf-8")

    def _serve_asset(self, file_path: Path) -> None:
        try:
            data = file_path.read_bytes()
        except OSError:
            self._send_error_json(404, "Not found.")
            return
        content_type = _ASSET_TYPES.get(
            file_path.suffix.lower(),
            mimetypes.guess_type(str(file_path))[0] or "application/octet-stream",
        )
        self._send_bytes(HTTPStatus.OK, data, content_type)

    # ------------------------------------------------------------------- POST
    def _read_upload(self) -> tuple[str, int] | None:
        """Validate the raw-file upload headers and return name and length."""
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_error_json(411, "Content-Length is required.", close=True)
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._send_error_json(400, "Invalid Content-Length.", close=True)
            return None
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            self._send_error_json(413, "That file size is not supported.", close=True)
            return None
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        if content_type.strip().lower() != "application/octet-stream":
            self._send_error_json(
                415, "File uploads must be application/octet-stream.", close=True
            )
            return None
        encoded_name = self.headers.get("X-ViShare-Filename")
        if not encoded_name:
            self._send_error_json(400, "A file name is required.", close=True)
            return None
        try:
            filename = unquote(encoded_name, encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            self._send_error_json(400, "The file name is not valid UTF-8.", close=True)
            return None
        return filename, length

    def _handle_send_upload(self) -> None:
        headers = self._read_upload()
        if headers is None:
            return
        filename, length = headers
        try:
            self.server.send_service.add_upload(self.rfile, filename, length)
        except ValueError as exc:
            self.close_connection = True
            self._send_json(
                409,
                {"ok": False, "error": str(exc), "state": self.server.snapshot()},
            )
            return
        except OSError:
            self._send_error_json(
                500, "The file could not be saved to the staging area.", close=True
            )
            return
        self._reply_state()

    def do_POST(self) -> None:
        if not self._require_api_access():
            return
        path = urlsplit(self.path).path
        if path == "/api/send/add-file":
            self._handle_send_upload()
            return
        body = self._read_json_body()
        if body is None:
            return
        service = self.server.service
        sender = self.server.send_service

        if path == "/api/send/discover":
            started = sender.start_discovery()
            self._reply_state(ok=started, status=200 if started else 409)
            return
        if path == "/api/send/start":
            peer_key = body.get("peer")
            if peer_key is not None and not isinstance(peer_key, str):
                self._send_error_json(400, "peer must be a string.")
                return
            started = sender.start_send(peer_key)
            self._reply_state(ok=started, status=200 if started else 409)
            return
        if path == "/api/send/pin":
            match = body.get("match")
            if not isinstance(match, bool):
                self._send_error_json(400, "match must be true or false.")
                return
            resolved = sender.resolve_pin(match)
            self._reply_state(ok=resolved, status=200 if resolved else 409)
            return
        if path == "/api/send/cancel":
            cancelled = sender.cancel()
            self._reply_state(ok=cancelled, status=200 if cancelled else 409)
            return
        if path == "/api/send/clear-files":
            cleared = sender.clear_files()
            self._reply_state(ok=cleared, status=200 if cleared else 409)
            return
        if path == "/api/send/dismiss":
            sender.dismiss_result()
            self._reply_state()
            return
        if path == "/api/send/reset":
            reset = sender.reset()
            self._reply_state(ok=reset, status=200 if reset else 409)
            return

        if path == "/api/start":
            started = service.start()
            self._reply_state(ok=started)
            return
        if path == "/api/stop":
            service.stop()
            self._reply_state()
            return
        if path == "/api/pin":
            match = body.get("match")
            if not isinstance(match, bool):
                self._send_error_json(400, "match must be true or false.")
                return
            resolved = service.resolve_pin(match)
            self._reply_state(ok=resolved, status=200 if resolved else 409)
            return
        if path == "/api/consent":
            accept = body.get("accept")
            if not isinstance(accept, bool):
                self._send_error_json(400, "accept must be true or false.")
                return
            resolved = service.resolve_consent(accept)
            self._reply_state(ok=resolved, status=200 if resolved else 409)
            return
        if path == "/api/cancel":
            cancelled = service.cancel_transfer()
            self._reply_state(ok=cancelled, status=200 if cancelled else 409)
            return
        if path == "/api/dismiss":
            service.dismiss_result()
            self._reply_state()
            return
        if path == "/api/device-name":
            name = body.get("name")
            if not isinstance(name, str):
                self._send_error_json(400, "name must be a string.")
                return
            updated = service.set_device_name(name)
            if updated:
                sender.set_device_name(name)
            self._reply_state(ok=updated, status=200 if updated else 409)
            return
        if path == "/api/open-downloads":
            opened = service.open_download_folder()
            self._reply_state(ok=opened, status=200 if opened else 500)
            return
        if path == "/api/shutdown":
            self._reply_state()
            threading.Thread(
                target=self._shutdown,
                name="vishare-quick-ui-shutdown",
                daemon=True,
            ).start()
            return
        self._send_error_json(404, "Not found.")

    def _shutdown(self) -> None:
        # Give the response a moment to leave the socket before stopping.
        threading.Event().wait(0.15)
        try:
            self.server.send_service.stop()
            self.server.service.stop()
        finally:
            self.server.shutdown()


def create_server(
    service: ReceiveService,
    *,
    send_service: SendService | None = None,
    host: str = _LOOPBACK_HOST,
    port: int = 0,
) -> UiHTTPServer:
    """Create (but do not start) a loopback-only UI server."""
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("The local interface only binds to a loopback address.")
    if port < 0 or port > 65535:
        raise ValueError("Port must be between 0 and 65535.")
    token = secrets.token_urlsafe(32)
    if send_service is None:
        send_service = SendService(
            device_name=getattr(service, "device_name", "ViShare Quick")
        )
    return UiHTTPServer(
        (host, port),
        UiRequestHandler,
        service=service,
        send_service=send_service,
        token=token,
    )


def default_download_dir() -> Path:
    """Return the same default destination as the CLI receiver."""
    return Path.home() / "Downloads"


def run_ui(
    *,
    port: int = 0,
    download_dir: str | None = None,
    device_name: str = "ViShare Quick",
    open_browser: bool = False,
    use_window: bool = True,
    background: bool = False,
) -> int:
    """Serve the interface in an app window, browser, or headless mode."""
    background = background and use_window and not open_browser
    if background:
        from vishare_quick.windows_background import hide_console_if_owned

        hide_console_if_owned()
    service = ReceiveService(
        download_dir if download_dir is not None else default_download_dir(),
        device_name,
    )
    send_service = SendService(device_name=service.device_name)
    server = create_server(service, send_service=send_service, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    server_thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.25},
        name="vishare-quick-ui-server",
        daemon=True,
    )
    server_thread.start()
    print(f"ViShare Quick interface: {url}", flush=True)
    print(f"Downloads folder: {service.download_dir}", flush=True)
    try:
        if use_window and not open_browser:
            print("Close the app window or press Ctrl+C to stop.", flush=True)
            from vishare_quick.desktop import WindowUnavailable, run_app_window

            try:
                run_app_window(
                    server,
                    url,
                    start_hidden=background,
                    enable_background=sys.platform == "win32",
                )
                return 0
            except WindowUnavailable as exc:
                print(f"In-app window unavailable: {exc}", flush=True)
                print("Falling back to the default browser.", flush=True)
                webbrowser.open(url)
        else:
            print(
                "Keep this window open while receiving. Press Ctrl+C to stop.",
                flush=True,
            )
            if open_browser:
                threading.Timer(0.4, lambda: webbrowser.open(url)).start()
        server_thread.join()
    except KeyboardInterrupt:
        print("\nStopping ViShare Quick.")
    finally:
        send_service.stop()
        service.stop()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2.0)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the UI as a standalone command."""
    parser = argparse.ArgumentParser(
        prog="vishare ui",
        description="Open the local graphical interface in an app window.",
    )
    parser.add_argument(
        "--port", type=int, default=0, help="local TCP port (0 chooses one)"
    )
    display = parser.add_mutually_exclusive_group()
    display.add_argument(
        "--browser",
        action="store_true",
        help="open the interface in the default browser instead of an app window",
    )
    display.add_argument(
        "--no-browser",
        action="store_true",
        help="run the local server without opening an app window or browser",
    )
    display.add_argument(
        "--background",
        action="store_true",
        help="start hidden in the Windows notification area",
    )
    parser.add_argument(
        "--download-dir", metavar="DIR", help="destination directory for received files"
    )
    parser.add_argument("--name", default="ViShare Quick", help="visible device name")
    args = parser.parse_args(argv)
    if args.port < 0 or args.port > 65535:
        parser.error("--port must be between 0 and 65535")
    if not args.name.strip():
        parser.error("--name cannot be empty")
    if args.background and sys.platform != "win32":
        parser.error("--background is only supported on Windows")
    try:
        return run_ui(
            port=args.port,
            download_dir=args.download_dir,
            device_name=args.name.strip(),
            open_browser=args.browser,
            use_window=not (args.browser or args.no_browser),
            background=args.background,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Interface failed to start: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

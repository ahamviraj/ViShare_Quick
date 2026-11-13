"""State and consent bridge for the local ViShare Quick interface.

The interface is a loopback-only web app. This module owns the receiver state
that the UI polls and translates button presses into the explicit human
decisions required by :mod:`vishare_quick.consent`.

Security properties:

* The 4-digit code is shown only while a PIN comparison is pending.
* There is no API that accepts a transfer without an explicit positive call.
* Prompt timeouts and cancellation fail closed (reject).
* Peer payload identifiers never leave this module; the UI only sees file
  indices, names, sizes, and MIME types.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from vishare_quick import __version__
from vishare_quick.advertise import AdvertiserControl, run_advertiser
from vishare_quick.consent import ConsentRequest, Prompter

PROMPT_TIMEOUT_SECONDS = 300.0
MAX_ACTIVITY_EVENTS = 80

_PHASE_FINAL = frozenset({"completed", "rejected", "failed", "cancelled"})

_ERROR_MESSAGES = {
    "local-implementation-error": (
        "The computer could not write the files. Check the download folder and "
        "free space, then try again."
    ),
    "invalid-payload-structure": (
        "The device sent data that did not match the expected Quick Share "
        "structure, so the transfer was stopped."
    ),
    "unexpected-message-order": (
        "The device stopped responding at an unexpected point. Nothing was kept."
    ),
}

_REJECTION_MESSAGES = {
    "unsupported-introduction": (
        "This share contained text, Wi-Fi credentials, an app, or a stream. "
        "This build accepts file attachments only, so it was declined."
    ),
    "pin-verification-failed": (
        "The codes did not match. The request was declined and no files were saved."
    ),
    "consent-rejected": (
        "The request was declined. No files were saved."
    ),
    "not-enough-space": (
        "There is not enough free space for these files. Nothing was saved."
    ),
}


@dataclass
class _Prompt:
    kind: str
    deadline: float
    event: threading.Event = field(default_factory=threading.Event)
    decision: bool | None = None
    code: str | None = None
    request: ConsentRequest | None = None


class WebPrompter(Prompter):
    """Prompter that waits for the UI while the session keeps running.

    The wait is bounded. A timeout, a cancelled service, or a disconnected UI
    resolves to rejection, never acceptance.
    """

    def __init__(
        self,
        on_prompt: Callable[[_Prompt], None],
        on_end: Callable[[str, bool | None], None],
        timeout_seconds: float = PROMPT_TIMEOUT_SECONDS,
    ) -> None:
        self._on_prompt = on_prompt
        self._on_end = on_end
        self._timeout = float(timeout_seconds)
        self._lock = threading.Lock()
        self._prompt: _Prompt | None = None
        self._cancelled = False

    def _begin(self, kind: str, **fields: Any) -> _Prompt | None:
        with self._lock:
            if self._cancelled:
                return None
            prompt = _Prompt(
                kind=kind,
                deadline=time.monotonic() + self._timeout,
                **fields,
            )
            self._prompt = prompt
        self._on_prompt(prompt)
        return prompt

    def _finish(self, prompt: _Prompt, *, timed_out: bool) -> bool | None:
        with self._lock:
            if self._prompt is prompt:
                self._prompt = None
            if timed_out:
                # A decision arriving after the wait expired must not turn a
                # timeout into an acceptance.
                prompt.decision = None
            decision = prompt.decision
        self._on_end(prompt.kind, decision)
        return decision

    def ask_pin(self, code: str) -> str | None:
        prompt = self._begin("pin", code=code)
        if prompt is None:
            return None
        signalled = prompt.event.wait(self._timeout)
        decision = self._finish(prompt, timed_out=not signalled)
        return code if decision is True else None

    def request_consent(self, request: ConsentRequest) -> bool:
        prompt = self._begin("consent", request=request)
        if prompt is None:
            return False
        signalled = prompt.event.wait(self._timeout)
        return self._finish(prompt, timed_out=not signalled) is True

    def resolve(self, decision: bool) -> bool:
        """Resolve the current prompt. Returns False when none is pending."""
        with self._lock:
            prompt = self._prompt
            if prompt is None or self._cancelled or prompt.event.is_set():
                return False
            prompt.decision = bool(decision)
            prompt.event.set()
            return True

    def cancel(self) -> None:
        """Fail the current and every future prompt closed."""
        with self._lock:
            self._cancelled = True
            prompt = self._prompt
            if prompt is not None:
                prompt.decision = False
                prompt.event.set()


class ReceiveService:
    """Run the advertiser on a worker thread and expose a JSON-safe snapshot."""

    def __init__(
        self,
        download_dir: str | os.PathLike[str],
        device_name: str = "ViShare Quick",
    ) -> None:
        self._lock = threading.RLock()
        self._download_dir = Path(download_dir).expanduser()
        self._device_name = device_name
        self._thread: threading.Thread | None = None
        self._control: AdvertiserControl | None = None
        self._prompter: WebPrompter | None = None
        self._phase = "idle"
        self._active = False
        self._endpoint: dict[str, Any] | None = None
        self._pin: dict[str, Any] | None = None
        self._request: dict[str, Any] | None = None
        self._progress: dict[str, Any] | None = None
        self._result: dict[str, Any] | None = None
        self._error: str | None = None
        self._events: deque[dict[str, str]] = deque(maxlen=MAX_ACTIVITY_EVENTS)
        self._payload_index: dict[int, int] = {}
        self._cancel_requested = False

    # ------------------------------------------------------------------ state
    @property
    def download_dir(self) -> Path:
        """The destination directory shown to the local user."""
        return self._download_dir

    def _log(self, text: str) -> None:
        self._events.append(
            {"time": time.strftime("%H:%M:%S"), "text": text}
        )

    def _set_phase(self, phase: str) -> None:
        self._phase = phase

    def snapshot(self) -> dict[str, Any]:
        """Return everything the UI may render. Never includes payload IDs."""
        with self._lock:
            pin = None
            if self._pin is not None:
                remaining = max(
                    0, int(round(self._pin["deadline"] - time.monotonic()))
                )
                pin = {
                    "code": self._pin["code"],
                    "seconds_remaining": remaining,
                }
            progress = None
            if self._progress is not None:
                total = int(self._progress["total_bytes"])
                received = int(self._progress["received_bytes"])
                progress = {
                    "total_bytes": total,
                    "received_bytes": received,
                    "percent": (
                        100 if total <= 0 else min(100, received * 100 // total)
                    ),
                    "files": [dict(item) for item in self._progress["files"]],
                }
            return {
                "version": __version__,
                "phase": self._phase,
                "active": self._active,
                "advertising": self._active,
                "device_name": self._device_name,
                "download_dir": str(self._download_dir),
                "endpoint": dict(self._endpoint) if self._endpoint else None,
                "pin": pin,
                "request": (
                    {
                        "files": [dict(item) for item in self._request["files"]],
                        "total_size": self._request["total_size"],
                        "identity_verified": False,
                    }
                    if self._request is not None
                    else None
                ),
                "progress": progress,
                "result": self._result,
                "error": self._error,
                "events": list(self._events),
            }

    # --------------------------------------------------------------- lifecycle
    def start(self) -> bool:
        """Start advertising. Returns False when already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            try:
                self._download_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._set_phase("failed")
                self._error = (
                    "The download folder could not be created. Choose another "
                    "folder with --download-dir."
                )
                self._log(f"Download folder error: {exc.__class__.__name__}.")
                return False

            self._phase = "starting"
            self._active = False
            self._endpoint = None
            self._pin = None
            self._request = None
            self._progress = None
            self._result = None
            self._error = None
            self._payload_index = {}
            self._cancel_requested = False
            self._control = AdvertiserControl()
            self._prompter = WebPrompter(
                self._on_prompt, self._on_prompt_end
            )
            self._log(f"Starting to advertise as {self._device_name}.")
            self._thread = threading.Thread(
                target=self._run,
                name="vishare-quick-advertiser",
                daemon=True,
            )
            self._thread.start()
        return True

    def _run(self) -> None:
        control = self._control
        prompter = self._prompter
        try:
            run_advertiser(
                device_name=self._device_name,
                duration_seconds=None,
                ukey2_handshake=True,
                receive_files=True,
                download_dir=str(self._download_dir),
                prompter=prompter,
                progress=self._on_progress,
                control=control,
                observer=self._on_event,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the local UI only
            with self._lock:
                self._active = False
                self._endpoint = None
                self._set_phase("failed")
                self._error = (
                    "The receiver could not start. Check that no other Quick "
                    "Share receiver is using this network interface."
                )
                self._log(f"Receiver error: {exc.__class__.__name__}.")
        finally:
            with self._lock:
                self._active = False
                self._endpoint = None

    def stop(self) -> bool:
        """Stop advertising and cancel any pending prompt or active transfer."""
        with self._lock:
            control = self._control
            prompter = self._prompter
            thread = self._thread
        if prompter is not None:
            prompter.cancel()
        if control is not None:
            control.request_stop()
            control.cancel_active_connection()
        if thread is not None and thread.is_alive():
            thread.join(timeout=8.0)
        with self._lock:
            self._active = False
            self._endpoint = None
            self._pin = None
            self._request = None
            self._progress = None
            self._payload_index = {}
            self._set_phase("idle")
            self._log("Stopped advertising.")
        return True

    def dismiss_result(self) -> None:
        """Return from a finished/rejected screen while staying advertised."""
        with self._lock:
            if self._phase not in _PHASE_FINAL:
                return
            self._result = None
            self._error = None
            self._progress = None
            self._pin = None
            self._request = None
            self._set_phase("advertising" if self._active else "idle")

    def set_device_name(self, name: str) -> bool:
        name = name.strip()
        if not name or len(name.encode("utf-8")) > 255:
            return False
        with self._lock:
            if self._active:
                return False
            self._device_name = name
            self._log("Device name updated.")
        return True

    # --------------------------------------------------------------- decisions
    def resolve_pin(self, match: bool) -> bool:
        with self._lock:
            if self._phase != "pin" or self._prompter is None:
                return False
            self._pin = None
        return self._prompter.resolve(bool(match))

    def resolve_consent(self, accept: bool) -> bool:
        with self._lock:
            if self._phase != "consent" or self._prompter is None:
                return False
            self._request = None
        return self._prompter.resolve(bool(accept))

    def cancel_transfer(self) -> bool:
        with self._lock:
            if self._phase != "receiving" or self._control is None:
                return False
            self._cancel_requested = True
        self._log("Cancelling the transfer and removing partial files.")
        self._control.cancel_active_connection()
        return True

    def open_download_folder(self) -> bool:
        path = self._download_dir
        try:
            path.mkdir(parents=True, exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
            return True
        except (OSError, AttributeError):
            return False

    # ---------------------------------------------------------------- prompter
    def _on_prompt(self, prompt: _Prompt) -> None:
        if prompt.kind == "pin":
            with self._lock:
                self._pin = {
                    "code": prompt.code,
                    "deadline": prompt.deadline,
                }
                self._request = None
                self._set_phase("pin")
            self._log("PIN comparison requested.")
            return
        request = prompt.request
        if request is None:
            return
        files = [
            {
                "index": index,
                "name": offer.name,
                "size": offer.size,
                "mime": offer.mime_type,
                "kind": offer.type_name,
            }
            for index, offer in enumerate(request.files)
        ]
        with self._lock:
            self._payload_index = {
                offer.payload_id: index
                for index, offer in enumerate(request.files)
            }
            self._request = {
                "files": files,
                "total_size": request.total_size,
            }
            self._progress = {
                "total_bytes": request.total_size,
                "received_bytes": 0,
                "files": [
                    {
                        "index": item["index"],
                        "name": item["name"],
                        "size": item["size"],
                        "received": 0,
                        "done": item["size"] == 0,
                    }
                    for item in files
                ],
            }
            self._pin = None
            self._set_phase("consent")
        self._log(
            f"Request for {len(files)} file(s), {request.total_size} bytes."
        )

    def _on_prompt_end(self, kind: str, decision: bool | None) -> None:
        with self._lock:
            if decision is None:
                if kind == "pin":
                    self._pin = None
                    self._log("PIN comparison timed out.")
                else:
                    self._request = None
                    self._progress = None
                    self._log("Consent request timed out.")
                return
            if kind == "pin":
                if decision:
                    self._set_phase("verifying")
                    self._log("Codes confirmed; waiting for the file list.")
                else:
                    self._log("Codes rejected.")
                return
            if decision:
                self._set_phase("receiving")
                self._log("Consent accepted; receiving files.")
            else:
                self._log("Request declined.")

    # ------------------------------------------------------------------ events
    def _on_event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "ready":
            with self._lock:
                self._active = True
                self._endpoint = {
                    "local_ip": event.get("local_ip"),
                    "port": event.get("port"),
                }
                self._set_phase("advertising")
            self._log(
                "Ready to receive on "
                f"{event.get('local_ip')}:{event.get('port')}."
            )
            return
        if kind == "connection":
            with self._lock:
                self._pin = None
                self._request = None
                self._progress = None
                self._result = None
                self._error = None
                self._cancel_requested = False
                self._set_phase("connecting")
            self._log("A device connected.")
            return
        if kind == "authenticated":
            self._log("Encrypted session established.")
            return
        if kind == "session":
            self._handle_session(event)
            return
        if kind == "session-failed":
            with self._lock:
                cancelled = self._cancel_requested
                self._cancel_requested = False
                self._pin = None
                self._request = None
                self._set_phase("cancelled" if cancelled else "failed")
                if cancelled:
                    self._error = "The transfer was cancelled. Partial files were removed."
                else:
                    self._error = _ERROR_MESSAGES.get(
                        event.get("category"),
                        "The transfer stopped before it finished. No partial files were kept.",
                    )
            self._log(
                "Transfer cancelled." if cancelled else "Transfer failed."
            )
            return
        if kind == "error":
            with self._lock:
                cancelled = self._cancel_requested
                self._cancel_requested = False
                if cancelled:
                    self._set_phase("cancelled")
                    self._error = "The transfer was cancelled. Partial files were removed."
                elif self._phase not in _PHASE_FINAL:
                    self._set_phase("failed")
                    self._error = _ERROR_MESSAGES.get(
                        event.get("category"),
                        "The connection ended before a transfer could start.",
                    )
            self._log(
                "Connection cancelled." if cancelled
                else "Connection ended before a transfer started."
            )
            return
        if kind == "closed":
            with self._lock:
                if self._phase == "connecting":
                    self._set_phase(
                        "advertising" if self._active else "idle"
                    )
                    self._log("The device disconnected.")
                elif self._phase in {"pin", "consent", "verifying", "receiving"}:
                    cancelled = self._cancel_requested
                    self._cancel_requested = False
                    self._set_phase("cancelled" if cancelled else "failed")
                    self._error = (
                        "The transfer was cancelled. Partial files were removed."
                        if cancelled
                        else "The device disconnected during the transfer. "
                        "No partial files were kept."
                    )
                    self._log(
                        "Transfer cancelled." if cancelled
                        else "The device disconnected during the transfer."
                    )
            return
        if kind == "stopped":
            with self._lock:
                self._active = False
                self._endpoint = None
                if self._phase not in _PHASE_FINAL:
                    self._set_phase("idle")
            self._log("Advertising stopped.")
            return

    def _handle_session(self, event: dict[str, Any]) -> None:
        status = event.get("status")
        files = list(event.get("files") or [])
        with self._lock:
            self._pin = None
            self._request = None
            self._payload_index = {}
            if status == "completed":
                total = sum(int(item.get("size", 0)) for item in files)
                self._result = {
                    "status": "completed",
                    "files": [
                        {
                            "name": item.get("name"),
                            "saved_name": item.get("saved_name"),
                            "size": item.get("size", 0),
                        }
                        for item in files
                    ],
                    "total_size": total,
                    "download_dir": str(self._download_dir),
                    "pin_verified": True,
                    "consent": "accepted",
                }
                self._error = None
                self._set_phase("completed")
            else:
                self._result = {
                    "status": status,
                    "files": [],
                    "total_size": 0,
                    "download_dir": str(self._download_dir),
                    "pin_verified": bool(event.get("pin_verified")),
                    "consent": event.get("consent"),
                }
                self._error = _REJECTION_MESSAGES.get(
                    status,
                    "The request could not be accepted. No files were saved.",
                )
                self._set_phase("rejected")
        if status == "completed":
            self._log(
                f"Received {len(files)} file(s), "
                f"{self._result['total_size']} bytes."
            )
            self._log(f"Saved to {self._download_dir}.")
        else:
            self._log("Request declined; no files were saved.")

    def _on_progress(self, payload_id: int, received: int, total: int) -> None:
        with self._lock:
            index = self._payload_index.get(payload_id)
            if index is None or self._progress is None:
                return
            entries = self._progress["files"]
            if index >= len(entries):
                return
            entry = entries[index]
            if entry["done"]:
                return
            entry["received"] = max(entry["received"], int(received))
            if entry["received"] >= int(total):
                entry["received"] = int(total)
                entry["done"] = True
                self._log(f"File {index + 1} of {len(entries)} received.")
            self._progress["received_bytes"] = sum(
                item["received"] for item in entries
            )
            if self._phase == "consent":
                self._set_phase("receiving")

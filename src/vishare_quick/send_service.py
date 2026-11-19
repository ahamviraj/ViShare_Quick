"""Sender state bridge for the local ViShare Quick interface.

The browser pages never touch sockets or local paths. They upload selected
files to a private staging directory over the loopback API, choose one
discovered receiver, and poll a presentation-only snapshot. This module owns
the sender thread, the explicit PIN gate, progress, results, and cleanup.

Security properties:

* The 4-digit code is exposed only while a PIN comparison is pending.
* A timeout, a closed interface, or a cancelled send fails closed.
* Uploads are streamed to disk; the browser never learns a local path.
* Peer payload identifiers and key material never enter the snapshot.
* Staged copies and partial uploads are removed on cancel, clear, reset, or
  shutdown.
"""
from __future__ import annotations

import mimetypes
import os
import shutil
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, BinaryIO

from vishare_quick import __version__, windows_share
from vishare_quick.file_transfer import safe_filename
from vishare_quick.peer_discovery import DiscoveryError, Peer, PeerBrowser
from vishare_quick.sender import (
    MAX_TOTAL_BYTES,
    SenderCancelled,
    SenderError,
    prepare_files,
    send_files,
)

DISCOVERY_SECONDS = 8.0
PIN_TIMEOUT_SECONDS = 300.0
LINGER_SECONDS = 3.0
MAX_STAGED_FILES = 64
MAX_ACTIVITY_EVENTS = 80
_UPLOAD_CHUNK = 1024 * 1024

_SEND_ACTIVE = frozenset(
    {
        "connecting",
        "handshake",
        "offering",
        "pin",
        "waiting",
        "sending",
        "finishing",
    }
)
_SEND_FINAL = frozenset({"completed", "failed", "cancelled"})

def _peer_view(peer: Peer) -> dict[str, Any]:
    """Return only the presentation fields the send pages need."""
    data = peer.to_dict()
    return {
        "name": data["name"],
        "device_type": data["device_type"],
        "device_type_label": data["device_type_label"],
        "host": data["host"],
        "port": data["port"],
        "key": data["key"],
    }


_STAGE_PHASES = {
    "connecting": "connecting",
    "handshake": "handshake",
    "offering": "offering",
    "pin-pending": "pin",
    "awaiting-acceptance": "waiting",
    "sending": "sending",
    "finishing": "finishing",
}


class SendService:
    """Run one outbound transfer and expose a JSON-safe snapshot."""

    def __init__(self, device_name: str = "ViShare Quick") -> None:
        self._lock = threading.RLock()
        self._device_name = device_name
        self._staging_dir: Path | None = None
        self._files: list[dict[str, Any]] = []
        self._next_file_id = 1
        self._reserved_bytes = 0
        self._reserved_paths: set[Path] = set()
        self._phase = "idle"
        self._selected_peer: Peer | None = None
        self._peers: dict[str, Peer] = {}
        self._discovering = False
        self._discovery_thread: threading.Thread | None = None
        self._discovery_stop = threading.Event()
        self._send_thread: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._pin: dict[str, Any] | None = None
        self._pin_event: threading.Event | None = None
        self._pin_decision: bool | None = None
        self._progress: dict[str, Any] | None = None
        self._result: dict[str, Any] | None = None
        self._error: str | None = None
        self._events: deque[dict[str, str]] = deque(maxlen=MAX_ACTIVITY_EVENTS)

    # ------------------------------------------------------------------ state
    @property
    def active(self) -> bool:
        with self._lock:
            return self._phase in _SEND_ACTIVE

    def set_device_name(self, name: str) -> bool:
        stripped = name.strip()
        if not stripped:
            return False
        with self._lock:
            self._device_name = stripped
        return True

    def _log(self, text: str) -> None:
        self._events.append({"time": time.strftime("%H:%M:%S"), "text": text})

    def snapshot(self) -> dict[str, Any]:
        """Return everything the send pages may render."""
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
                sent = int(self._progress["sent_bytes"])
                progress = {
                    "total_bytes": total,
                    "sent_bytes": sent,
                    "percent": 100 if total <= 0 else min(100, sent * 100 // total),
                    "files": [dict(item) for item in self._progress["files"]],
                }
            files = [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "size": item["size"],
                    "mime": item["mime"],
                }
                for item in self._files
            ]
            return {
                "version": __version__,
                "phase": self._phase,
                "active": self._phase in _SEND_ACTIVE,
                "discovering": self._discovering,
                "device_name": self._device_name,
                "nearby_share": windows_share.status(),
                "files": files,
                "total_size": sum(item["size"] for item in self._files),
                "peers": [
                    _peer_view(self._peers[key]) for key in sorted(self._peers)
                ],
                "peer": (
                    _peer_view(self._selected_peer)
                    if self._selected_peer is not None
                    else None
                ),
                "pin": pin,
                "progress": progress,
                "result": self._result,
                "error": self._error,
                "events": list(self._events),
            }

    # ------------------------------------------------------------------- files
    def _ensure_staging(self) -> Path:
        if self._staging_dir is None:
            self._staging_dir = Path(
                tempfile.mkdtemp(prefix="vishare-quick-send-")
            )
        return self._staging_dir

    def _unique_target(self, name: str) -> Path:
        directory = self._ensure_staging()
        candidate = directory / name
        stem, suffix = candidate.stem, candidate.suffix
        counter = 1
        while candidate.exists() or candidate in self._reserved_paths:
            candidate = directory / f"{stem} ({counter}){suffix}"
            counter += 1
        return candidate

    def add_upload(
        self, source: BinaryIO, filename: str, length: int
    ) -> dict[str, Any]:
        """Stream one browser upload to the private staging directory.

        The HTTP handler passes exactly ``length`` body bytes. Raises
        :class:`ValueError` with a safe message when the request is rejected.
        """
        name = safe_filename(filename, fallback="")
        if not name:
            raise ValueError("That file name cannot be used.")
        if not isinstance(length, int) or length <= 0:
            raise ValueError("Choose a non-empty file to send.")
        if length > MAX_TOTAL_BYTES:
            raise ValueError("That file is larger than this build supports.")

        with self._lock:
            if self._phase in _SEND_ACTIVE:
                raise ValueError("Wait for the current send to finish.")
            if len(self._files) + len(self._reserved_paths) >= MAX_STAGED_FILES:
                raise ValueError("Too many files are selected for one send.")
            total = sum(item["size"] for item in self._files) + self._reserved_bytes
            if total + length > MAX_TOTAL_BYTES:
                raise ValueError("The selection exceeds the supported total size.")
            target = self._unique_target(name)
            self._reserved_paths.add(target)
            self._reserved_bytes += length
            self._error = None
            if self._phase in _SEND_FINAL:
                self._phase = "idle"

        temp_path = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        written = 0
        try:
            with temp_path.open("wb") as handle:
                remaining = length
                while remaining > 0:
                    chunk = source.read(min(_UPLOAD_CHUNK, remaining))
                    if not chunk:
                        raise ValueError("The file upload ended early.")
                    handle.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
            if written != length:
                raise ValueError("The file upload ended early.")
            os.replace(temp_path, target)
        except (OSError, ValueError):
            for path in (temp_path, target):
                try:
                    path.unlink()
                except OSError:
                    pass
            with self._lock:
                self._reserved_paths.discard(target)
                self._reserved_bytes -= length
            raise
        except BaseException:
            try:
                temp_path.unlink()
            except OSError:
                pass
            with self._lock:
                self._reserved_paths.discard(target)
                self._reserved_bytes -= length
            raise

        with self._lock:
            self._reserved_paths.discard(target)
            self._reserved_bytes -= length
            item = {
                "id": self._next_file_id,
                "name": target.name,
                "path": target,
                "size": length,
                "mime": mimetypes.guess_type(target.name)[0]
                or "application/octet-stream",
            }
            self._next_file_id += 1
            self._files.append(item)
            if self._phase in _SEND_FINAL:
                self._phase = "idle"
            self._log(f"Added {target.name} ({length} bytes) to the selection.")
        return {"id": item["id"], "name": item["name"], "size": item["size"]}

    def clear_files(self) -> bool:
        """Remove every staged file. Refuses during an active send or upload."""
        with self._lock:
            if self._phase in _SEND_ACTIVE:
                return False
            if self._reserved_bytes:
                return False
            self._files = []
            self._progress = None
            self._result = None
            self._error = None
            self._pin = None
            self._next_file_id = 1
            staging = self._staging_dir
            self._staging_dir = None
            if self._phase in _SEND_FINAL:
                self._phase = "idle"
            self._log("Selection cleared.")
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        return True

    # --------------------------------------------------------------- discovery
    def start_discovery(self, seconds: float = DISCOVERY_SECONDS) -> bool:
        """Browse for nearby receivers and keep the snapshot updated."""
        with self._lock:
            if self._phase in _SEND_ACTIVE or self._discovering:
                return False
            if not 0 < seconds <= 120:
                return False
            self._discovering = True
            self._peers = {}
            self._error = None
            self._discovery_stop = threading.Event()
            self._discovery_thread = threading.Thread(
                target=self._run_discovery,
                args=(float(seconds), self._discovery_stop),
                name="vishare-quick-send-discovery",
                daemon=True,
            )
            thread = self._discovery_thread
        thread.start()
        return True

    def _run_discovery(self, seconds: float, stop: threading.Event) -> None:
        browser: PeerBrowser | None = None
        try:
            browser = PeerBrowser(self._on_peers)
            browser.start()
            deadline = time.monotonic() + seconds
            while not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                stop.wait(min(0.2, remaining))
        except DiscoveryError as exc:
            with self._lock:
                self._error = str(exc)
                self._log("Device discovery is unavailable.")
        except Exception:
            with self._lock:
                self._error = (
                    "Nearby devices could not be listed. Check the local network."
                )
                self._log("Device discovery failed.")
        finally:
            if browser is not None:
                browser.stop()
            with self._lock:
                self._discovering = False
                self._discovery_thread = None
                self._log(
                    "Device discovery finished: "
                    f"{len(self._peers)} receiver(s) found."
                )

    def stop_discovery(self, timeout: float = 3.0) -> None:
        with self._lock:
            stop = self._discovery_stop
            thread = self._discovery_thread
        if stop is not None:
            stop.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    def _on_peers(self, peers: tuple[Peer, ...]) -> None:
        with self._lock:
            self._peers = {peer.key: peer for peer in peers}

    # -------------------------------------------------------------------- send
    def start_send(self, peer_key: str | None = None) -> bool:
        """Start one send to a discovered receiver. Requires staged files."""
        with self._lock:
            if self._phase in _SEND_ACTIVE:
                return False
            if self._reserved_bytes:
                self._error = "Wait for the selected files to finish uploading."
                return False
            paths = [item["path"] for item in self._files]
            if not paths:
                self._error = "Select at least one file to send."
                return False
            peer: Peer | None = None
            if peer_key:
                peer = self._peers.get(peer_key)
            elif len(self._peers) == 1:
                peer = next(iter(self._peers.values()))
            if peer is None:
                self._error = "Select one nearby device first."
                return False
            try:
                prepared = prepare_files(paths)
            except SenderError as exc:
                self._error = str(exc)
                return False
            total = sum(item.size for item in prepared)
            self._selected_peer = peer
            self._cancel_event = threading.Event()
            self._pin = None
            self._pin_event = None
            self._pin_decision = None
            self._result = None
            self._error = None
            self._progress = {
                "total_bytes": total,
                "sent_bytes": 0,
                "files": [
                    {
                        "name": item.name,
                        "size": item.size,
                        "sent": 0,
                        "done": item.size == 0,
                    }
                    for item in prepared
                ],
            }
            self._phase = "connecting"
            stop = self._discovery_stop
            if stop is not None:
                stop.set()
            self._send_thread = threading.Thread(
                target=self._run_send,
                args=(peer, paths),
                name="vishare-quick-sender-ui",
                daemon=True,
            )
            thread = self._send_thread
            self._log(
                f"Offering {len(prepared)} file(s) to {peer.device_name}."
            )
        thread.start()
        return True

    def share_via_windows(self) -> bool:
        """Hand the staged files to the Windows share sheet."""
        with self._lock:
            if self._phase in _SEND_ACTIVE:
                self._error = "Wait for the current send to finish."
                return False
            if self._reserved_bytes:
                self._error = "Wait for the selected files to finish uploading."
                return False
            paths = [item["path"] for item in self._files]
            if not paths:
                self._error = "Select at least one file to share."
                return False
            self._error = None
        try:
            windows_share.share_files(paths)
        except windows_share.WindowsShareError as exc:
            with self._lock:
                self._error = str(exc)
                self._log("Windows sharing is unavailable.")
            return False
        except Exception:  # noqa: BLE001 - surfaced to the local UI only
            with self._lock:
                self._error = "The Windows share sheet could not be opened."
                self._log("Windows sharing failed.")
            return False
        with self._lock:
            self._error = None
            self._log("Opened the Windows share sheet.")
        return True

    def _run_send(self, peer: Peer, paths: list[Path]) -> None:
        try:
            result = send_files(
                peer,
                paths,
                device_name=self._device_name,
                on_stage=self._on_stage,
                on_pin=self._on_pin,
                on_progress=self._on_progress,
                cancel_event=self._cancel_event,
                linger_timeout=LINGER_SECONDS,
            )
        except SenderCancelled as exc:
            with self._lock:
                self._phase = "cancelled"
                self._error = str(exc) or "The send was cancelled."
                self._pin = None
                self._pin_event = None
                self._log("Send cancelled.")
        except SenderError as exc:
            with self._lock:
                self._phase = "failed"
                self._error = str(exc)
                self._pin = None
                self._pin_event = None
                self._log("Send failed.")
        except Exception as exc:  # noqa: BLE001 - surfaced to the local UI only
            with self._lock:
                self._phase = "failed"
                self._error = "The send stopped unexpectedly. No file was resent."
                self._pin = None
                self._pin_event = None
                self._log(f"Sender error: {exc.__class__.__name__}.")
        else:
            with self._lock:
                self._phase = "completed"
                self._result = {
                    "peer_name": result.peer_name,
                    "host": result.host,
                    "port": result.port,
                    "files": list(result.files),
                    "total_bytes": result.total_bytes,
                    "files_sent": result.files_sent,
                    "duration_seconds": result.duration_seconds,
                    "pin_compared": result.pin_compared,
                }
                self._error = None
                self._pin = None
                self._pin_event = None
                self._log(
                    f"Sent {result.files_sent} file(s), "
                    f"{result.total_bytes} bytes."
                )
        finally:
            with self._lock:
                self._send_thread = None

    def _on_stage(self, name: str) -> None:
        phase = _STAGE_PHASES.get(name)
        if phase is None:
            return
        with self._lock:
            if self._phase in _SEND_FINAL:
                return
            self._phase = phase

    def _on_pin(self, code: str) -> bool:
        with self._lock:
            if self._cancel_event.is_set():
                return False
            event = threading.Event()
            self._pin_event = event
            self._pin_decision = None
            self._pin = {
                "code": code,
                "deadline": time.monotonic() + PIN_TIMEOUT_SECONDS,
            }
            self._phase = "pin"
            self._log("PIN comparison requested.")
        signalled = event.wait(PIN_TIMEOUT_SECONDS)
        with self._lock:
            decision = self._pin_decision if signalled else None
            if self._pin_event is event:
                self._pin_event = None
            self._pin = None
            if decision is not True:
                self._log(
                    "PIN comparison timed out."
                    if not signalled
                    else "Codes rejected."
                )
        return decision is True

    def _on_progress(self, item: Any, sent: int, total: int) -> None:
        with self._lock:
            if self._progress is None:
                return
            name = getattr(item, "name", None)
            for entry in self._progress["files"]:
                if entry["name"] != name or entry["done"]:
                    continue
                entry["sent"] = max(entry["sent"], int(sent))
                if entry["sent"] >= int(total) or total == 0:
                    entry["sent"] = int(total)
                    entry["done"] = True
                break
            self._progress["sent_bytes"] = sum(
                entry["sent"] for entry in self._progress["files"]
            )

    # --------------------------------------------------------------- decisions
    def resolve_pin(self, match: bool) -> bool:
        with self._lock:
            event = self._pin_event
            if event is None or self._pin is None:
                return False
            self._pin_decision = bool(match)
            event.set()
            return True

    def cancel(self) -> bool:
        with self._lock:
            if self._phase not in _SEND_ACTIVE:
                return False
            self._cancel_event.set()
            event = self._pin_event
            if event is not None:
                self._pin_decision = False
                event.set()
            self._log("Cancelling the send.")
        return True

    def dismiss_result(self) -> None:
        """Return to the send screen while keeping the staged selection."""
        with self._lock:
            if self._phase not in _SEND_FINAL:
                return
            self._result = None
            self._error = None
            self._progress = None
            self._pin = None
            self._phase = "idle"

    def reset(self) -> bool:
        """Clear the selection, peers, progress, and result."""
        with self._lock:
            if self._phase in _SEND_ACTIVE:
                return False
            if self._reserved_bytes:
                return False
        self.stop_discovery()
        with self._lock:
            self._files = []
            self._progress = None
            self._result = None
            self._error = None
            self._pin = None
            self._peers = {}
            self._selected_peer = None
            self._phase = "idle"
            self._next_file_id = 1
            staging = self._staging_dir
            self._staging_dir = None
            self._log("Send screen reset.")
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        return True

    def stop(self) -> None:
        """Fail closed and remove staged data when the interface stops."""
        with self._lock:
            event = self._pin_event
            if event is not None:
                self._pin_decision = False
                event.set()
            self._cancel_event.set()
            thread = self._send_thread
        self.stop_discovery()
        if thread is not None and thread.is_alive():
            thread.join(timeout=8.0)
        with self._lock:
            self._files = []
            self._progress = None
            self._result = None
            self._pin = None
            self._peers = {}
            self._selected_peer = None
            self._phase = "idle"
            staging = self._staging_dir
            self._staging_dir = None
        windows_share.shutdown()
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)

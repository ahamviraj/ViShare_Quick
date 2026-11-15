"""Outbound Quick Share sender session.

The sender is the UKEY2 client and the mDNS browser. It offers a list of
regular files to one discovered receiver, waits for that receiver's human to
accept, streams the declared bytes, and disconnects.

Safety rules enforced here:

* Nothing is sent automatically. The caller supplies a PIN-confirmation
  callback; a declined comparison cancels the session before any file byte is
  read.
* File bytes are read only after the peer returns ``RESPONSE ACCEPT``.
* Only regular files are accepted. Symlinks, directories, and special files are
  rejected during preparation.
* Only basenames go on the wire; local absolute paths never leave the process.
* A file that changes size or modification time during the send aborts the
  transfer.
* Cancellation is checked between chunks and while waiting for the peer, and
  closes the socket instead of leaving partial sender state.
"""
from __future__ import annotations

import mimetypes
import os
import queue
import secrets
import socket
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from vishare_quick.file_transfer import safe_filename
from vishare_quick.peer_discovery import Peer
from vishare_quick.pin_verification import four_digit_code
from vishare_quick.protocol import (
    FrameError,
    PeerDisconnected,
    PeerRejectedConnection,
    encode_connection_response_accept,
    parse_connection_response,
    read_frame,
)
from vishare_quick.secure_channel import (
    SecureChannelError,
    SendKeys,
    ReceiveKeys,
    authenticate_and_inspect_frame,
    derive_client_to_server_send_keys,
    derive_server_to_client_receive_keys,
    encode_secure_message,
)
from vishare_quick.sender_protocol import (
    IntroductionFile,
    PAIRED_KEY_RESULT_UNABLE,
    RESPONSE_ACCEPT,
    RESPONSE_NOT_ENOUGH_SPACE,
    RESPONSE_REJECT,
    RESPONSE_TIMED_OUT,
    RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE,
    encode_connection_request,
    encode_disconnection,
    encode_introduction,
    encode_keep_alive,
    encode_paired_key_encryption,
    encode_paired_key_result,
    encode_payload_chunk,
    encode_sharing_payload,
    frame_payload,
    FILE_TYPE_ANDROID_APP,
    FILE_TYPE_AUDIO,
    FILE_TYPE_CONTACT_CARD,
    FILE_TYPE_DOCUMENT,
    FILE_TYPE_IMAGE,
    FILE_TYPE_UNKNOWN,
    FILE_TYPE_VIDEO,
    PAYLOAD_TYPE_FILE,
)
from vishare_quick.ukey2 import HandshakeError, Ukey2ClientHandshake

CHUNK_SIZE = 512 * 1024
KEEP_ALIVE_INTERVAL_SECONDS = 10.0
MAX_TOTAL_BYTES = 1 << 40  # 1 TiB, mirroring the receiver's declared-size bound
PROGRESS_MIN_STEP_BYTES = 8 * 1024 * 1024


class SenderError(Exception):
    """A safe-to-report sender failure."""

    error_category = "sender-error"


class SenderUnavailable(SenderError):
    """The peer could not be reached or closed the connection."""

    error_category = "peer-unavailable"


class SenderCancelled(SenderError):
    """The local human cancelled, or the PIN comparison was declined."""

    error_category = "cancelled"


class SenderRejected(SenderError):
    """The receiver declined the transfer or reported a failure status."""

    error_category = "rejected"


class SenderTimedOut(SenderError):
    """A protocol stage exceeded its local deadline."""

    error_category = "timed-out"


class SenderFileError(SenderError):
    """A local file cannot be sent as declared."""

    error_category = "local-file-error"


@dataclass(frozen=True)
class OutgoingFile:
    """A validated local file and the metadata offered to the peer."""

    path: Path
    name: str
    size: int
    mime_type: str
    file_type: int
    payload_id: int
    modified_ns: int


@dataclass(frozen=True)
class SendResult:
    peer_name: str
    host: str
    port: int
    files: tuple[str, ...]
    total_bytes: int
    files_sent: int
    duration_seconds: float
    pin_compared: bool


def file_type_for_mime(mime_type: str) -> int:
    if mime_type.startswith("image/"):
        return FILE_TYPE_IMAGE
    if mime_type.startswith("video/"):
        return FILE_TYPE_VIDEO
    if mime_type.startswith("audio/"):
        return FILE_TYPE_AUDIO
    if mime_type == "application/vnd.android.package-archive":
        return FILE_TYPE_ANDROID_APP
    if mime_type == "text/x-vcard" or mime_type == "text/vcard":
        return FILE_TYPE_CONTACT_CARD
    if mime_type.startswith("text/") or mime_type in {
        "application/pdf",
        "application/zip",
        "application/json",
        "application/xml",
    }:
        return FILE_TYPE_DOCUMENT
    return FILE_TYPE_UNKNOWN


def _regular_file(path: Path) -> os.stat_result:
    try:
        info = path.stat()
    except OSError as exc:
        raise SenderFileError(f"Cannot read '{path.name}'.") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SenderFileError(f"'{path.name}' is not a regular file.")
    return info


def prepare_files(paths: Sequence[str | Path]) -> tuple[OutgoingFile, ...]:
    """Validate the local selection and build the Introduction metadata."""
    if not paths:
        raise SenderFileError("Select at least one file to send.")
    prepared: list[OutgoingFile] = []
    used_ids: set[int] = set()
    total = 0
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise SenderFileError(f"'{path.name}' is a link and cannot be sent.")
        if not path.exists():
            raise SenderFileError(f"'{path.name}' does not exist.")
        if path.is_dir():
            raise SenderFileError(f"'{path.name}' is a directory, not a file.")
        info = _regular_file(path)
        name = safe_filename(path.name, fallback="file")
        if not name:
            raise SenderFileError("A selected file has no usable name.")
        if info.st_size == 0:
            # Android Quick Share drops the whole offer when a 0-byte file is
            # in the Introduction, before it shows the accept sheet. Refuse it
            # locally instead of starting a transfer the peer will abandon.
            raise SenderFileError(
                f"'{name}' is empty. Android Quick Share does not accept empty files."
            )
        total += info.st_size
        if total > MAX_TOTAL_BYTES:
            raise SenderFileError("The selection exceeds the supported total size.")
        mime_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        payload_id = secrets.randbelow((1 << 62) - 1) + 1
        while payload_id in used_ids:
            payload_id = secrets.randbelow((1 << 62) - 1) + 1
        used_ids.add(payload_id)
        prepared.append(
            OutgoingFile(
                path=path,
                name=name,
                size=info.st_size,
                mime_type=mime_type,
                file_type=file_type_for_mime(mime_type),
                payload_id=payload_id,
                modified_ns=info.st_mtime_ns,
            )
        )
    return tuple(prepared)


_UKEY2_ALERT_NAMES = {
    1: "bad message",
    2: "bad message type",
    3: "incorrect message",
    4: "bad message data",
    100: "bad version",
    101: "bad random",
    102: "bad handshake cipher",
    103: "bad next protocol",
    104: "bad public key",
    200: "internal error",
}


def _safe_peer_text(value: bytes, limit: int = 120) -> str:
    """Reduce peer-supplied alert text to one short printable line."""
    text = value.decode("utf-8", "replace")
    cleaned = "".join(character if 32 <= ord(character) < 127 else " " for character in text)
    return " ".join(cleaned.split())[:limit]


def decode_ukey2_alert(payload: bytes) -> str | None:
    """Describe a bare ``Ukey2Alert`` frame, or return ``None``.

    Android sends a failed UKEY2 negotiation as an unwrapped ``Ukey2Alert``
    (field 1 alert type, field 2 error text) instead of a ``Ukey2Message``.
    A ``ServerInit`` always carries fields 3 and 4, so their absence plus a
    known alert type is a safe discriminator.
    """
    from vishare_quick.protocol import _field_occurrences

    try:
        occurrences = _field_occurrences(payload)
    except Exception:
        return None
    fields: dict[int, list[object]] = {}
    for number, item in occurrences:
        fields.setdefault(number, []).append(item)
    if set(fields) - {1, 2}:
        return None
    numbers = fields.get(1)
    if not numbers or len(numbers) != 1:
        return None
    alert_type = getattr(numbers[0], "value", None)
    if not isinstance(alert_type, int) or alert_type not in _UKEY2_ALERT_NAMES:
        return None
    label = _UKEY2_ALERT_NAMES[alert_type]
    texts = fields.get(2)
    if not texts or not isinstance(getattr(texts[0], "value", None), bytes):
        return None
    raw = texts[0].value
    # A ServerInit also uses field 1 = 3, but its field 2 is a nested
    # protobuf, never a printable sentence. Requiring printable text keeps
    # this helper from mislabelling a valid ServerInit.
    if not raw or not all(32 <= byte < 127 for byte in raw):
        return None
    detail = _safe_peer_text(raw)
    if not detail:
        return None
    return f"{label} ({alert_type}): {detail}"


def _response_description(status: int | None) -> str:
    return {
        RESPONSE_ACCEPT: "accepted",
        RESPONSE_REJECT: "declined",
        RESPONSE_NOT_ENOUGH_SPACE: "not enough space on the device",
        RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE: "unsupported attachment type",
        RESPONSE_TIMED_OUT: "timed out on the device",
    }.get(status, "no usable response")


class _PeerClosed:
    """Sentinel pushed by the reader when the peer disconnects."""


class _Channel:
    """Authenticated send/receive channel with independent sequence counters."""

    def __init__(self, sock: socket.socket, send_keys: SendKeys, receive_keys: ReceiveKeys) -> None:
        self.sock = sock
        self.send_keys = send_keys
        self.receive_keys = receive_keys
        self._send_lock = threading.Lock()
        self._send_sequence = 0

    def send_offline(self, payload: bytes) -> None:
        with self._send_lock:
            self._send_sequence += 1
            wire = encode_secure_message(payload, self.send_keys, self._send_sequence)
            self.sock.sendall(wire)

    def send_sharing(self, sharing_frame: bytes) -> None:
        payload_id = secrets.randbelow((1 << 62) - 1) + 1
        first, last = encode_sharing_payload(payload_id, sharing_frame)
        self.send_offline(first)
        self.send_offline(last)


class _InboundReader(threading.Thread):
    """Authenticate inbound frames off the main thread and queue summaries."""

    def __init__(self, channel: _Channel, output: "queue.Queue[object]") -> None:
        super().__init__(name="vishare-send-reader", daemon=True)
        self._channel = channel
        self._output = output

    def run(self) -> None:
        sequence = 1
        while True:
            try:
                frame = read_frame(self._channel.sock, classify=False)
                summary = authenticate_and_inspect_frame(
                    frame, self._channel.receive_keys, expected_sequence=sequence
                )
                sequence += 1
            except PeerDisconnected:
                self._output.put(_PeerClosed())
                return
            except (FrameError, SecureChannelError, OSError):
                self._output.put(_PeerClosed())
                return
            if summary.offline_type == "KEEP_ALIVE":
                if not summary.keep_alive_ack:
                    try:
                        self._channel.send_offline(encode_keep_alive(ack=True))
                    except OSError:
                        pass
                continue
            if summary.offline_type == "DISCONNECTION":
                self._output.put(_PeerClosed())
                return
            self._output.put(summary)


class _KeepAlive(threading.Thread):
    def __init__(self, channel: _Channel, interval: float = KEEP_ALIVE_INTERVAL_SECONDS) -> None:
        super().__init__(name="vishare-send-keepalive", daemon=True)
        self._channel = channel
        self._interval = interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._channel.send_offline(encode_keep_alive(ack=False))
            except OSError:
                return


class _Session:
    def __init__(
        self,
        peer: Peer,
        files: tuple[OutgoingFile, ...],
        *,
        device_name: str,
        endpoint_id: str,
        on_stage: Callable[[str], None] | None,
        on_pin: Callable[[str], bool] | None,
        on_progress: Callable[[OutgoingFile, int, int], None] | None,
        cancel_event: threading.Event,
        connect_timeout: float,
        handshake_timeout: float,
        acceptance_timeout: float,
        linger_timeout: float,
        handshake_only: bool,
    ) -> None:
        self.peer = peer
        self.files = files
        self.device_name = device_name
        self.endpoint_id = endpoint_id
        self.on_stage = on_stage
        self.on_pin = on_pin
        self.on_progress = on_progress
        self.cancel_event = cancel_event
        self.connect_timeout = connect_timeout
        self.handshake_timeout = handshake_timeout
        self.acceptance_timeout = acceptance_timeout
        self.linger_timeout = linger_timeout
        self.handshake_only = handshake_only

        self._sock: socket.socket | None = None
        self._channel: _Channel | None = None
        self._reader: _InboundReader | None = None
        self._keep_alive: _KeepAlive | None = None
        self._inbound: "queue.Queue[object]" = queue.Queue()

    # -- lifecycle -----------------------------------------------------

    def _stage(self, name: str) -> None:
        if self.on_stage is None:
            return
        try:
            self.on_stage(name)
        except Exception:
            pass

    def _check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise SenderCancelled("The send was cancelled.")

    def run(self) -> SendResult:
        started = time.monotonic()
        total_bytes = sum(item.size for item in self.files)
        try:
            self._connect()
            pin = self._handshake()
            self._introduce()
            compared = self._confirm_pin(pin)
            self._await_acceptance()
            sent = 0 if self.handshake_only else self._stream_files()
            if not self.handshake_only:
                self._linger()
            self._stage("complete")
            return SendResult(
                peer_name=self.peer.device_name,
                host=self.peer.host,
                port=self.peer.port,
                files=tuple(item.name for item in self.files),
                total_bytes=total_bytes,
                files_sent=sent,
                duration_seconds=time.monotonic() - started,
                pin_compared=compared,
            )
        finally:
            self._close()

    def _connect(self) -> None:
        self._check_cancel()
        self._stage("connecting")
        try:
            sock = socket.create_connection(
                (self.peer.host, self.peer.port), timeout=self.connect_timeout
            )
        except OSError as exc:
            raise SenderUnavailable(
                "Could not connect to the selected device on the local network."
            ) from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(self.handshake_timeout)
        self._sock = sock

    def _send_framed(self, wire: bytes) -> None:
        """Send bytes that already carry the four-byte big-endian length prefix."""
        assert self._sock is not None
        self._sock.sendall(wire)

    def _send_payload(self, payload: bytes) -> None:
        """Send one protobuf payload, adding the TCP length prefix.

        Every encoder in :mod:`vishare_quick.sender_protocol` returns an
        unframed protobuf, exactly like the receiver-side parsers expect.
        Mixing framed and unframed writes makes Android wait for a short frame
        and then drop the connection, so the framing lives in one place.
        """
        self._send_framed(frame_payload(payload))

    def _read_plain(self) -> bytes:
        assert self._sock is not None
        return read_frame(self._sock, classify=False).payload

    def _handshake(self) -> str:
        self._stage("handshake")
        request = encode_connection_request(
            self.endpoint_id,
            self.device_name,
            _endpoint_info(self.device_name),
        )
        try:
            self._send_payload(request)
            client = Ukey2ClientHandshake()
            self._send_framed(client.create_client_init())
            server_init = self._read_plain()
            try:
                client_finish, secrets = client.receive_server_init(server_init)
            except HandshakeError:
                alert = decode_ukey2_alert(server_init)
                if alert is not None:
                    raise SenderRejected(
                        f"The device rejected the handshake: {alert}."
                    ) from None
                raise
            self._send_framed(client_finish)
            self._send_framed(encode_connection_response_accept())
            peer_payload = self._read_plain()
            status = parse_connection_response(peer_payload)
        except PeerRejectedConnection as exc:
            raise SenderRejected("The device rejected the connection.") from exc
        except PeerDisconnected as exc:
            raise SenderUnavailable(
                "The device closed the connection during the handshake. It may be "
                "refusing new connections for a moment; close and reopen the Quick "
                "Share panel on the device and retry."
            ) from exc
        except (HandshakeError, FrameError, OSError) as exc:
            raise SenderUnavailable("The device did not complete the handshake.") from exc
        if status != "ACCEPT":
            raise SenderRejected("The device rejected the connection.")

        assert self._sock is not None
        self._channel = _Channel(
            self._sock,
            derive_client_to_server_send_keys(secrets.next_secret),
            derive_server_to_client_receive_keys(secrets.next_secret),
        )
        self._reader = _InboundReader(self._channel, self._inbound)
        self._reader.start()
        self._keep_alive = _KeepAlive(self._channel)
        self._keep_alive.start()
        self._exchange_pairing()
        return four_digit_code(secrets.auth_string)

    def _exchange_pairing(self) -> None:
        assert self._channel is not None
        try:
            self._channel.send_sharing(
                encode_paired_key_encryption(os.urandom(72), os.urandom(6))
            )
            self._receive_until("PAIRED_KEY_ENCRYPTION", self.handshake_timeout)
            self._channel.send_sharing(encode_paired_key_result(PAIRED_KEY_RESULT_UNABLE))
            self._receive_until("PAIRED_KEY_RESULT", self.handshake_timeout)
        except OSError as exc:
            raise SenderUnavailable("The device disconnected during pairing.") from exc

    def _receive_until(self, sharing_type: str, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            self._check_cancel()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SenderTimedOut(f"The device did not send {sharing_type} in time.")
            try:
                item = self._inbound.get(timeout=min(0.5, remaining))
            except queue.Empty:
                continue
            if isinstance(item, _PeerClosed):
                raise SenderUnavailable("The device disconnected.")
            summary = item
            if getattr(summary, "sharing_type", None) == sharing_type:
                return summary
            if getattr(summary, "sharing_type", None) == "CANCEL":
                raise SenderRejected("The device cancelled the transfer.")

    def _confirm_pin(self, pin: str) -> bool:
        if self.on_pin is None:
            raise SenderCancelled("A PIN comparison is required before sending.")
        self._stage("pin-pending")
        try:
            confirmed = bool(self.on_pin(pin))
        except Exception as exc:  # a broken prompt must fail closed
            raise SenderCancelled("The PIN comparison was not completed.") from exc
        if not confirmed:
            raise SenderCancelled("The PIN comparison was declined.")
        return True

    def _introduce(self) -> None:
        assert self._channel is not None
        self._stage("offering")
        introduction = encode_introduction(
            [
                IntroductionFile(
                    name=item.name,
                    payload_id=item.payload_id,
                    size=item.size,
                    mime_type=item.mime_type,
                    file_type=item.file_type,
                )
                for item in self.files
            ]
        )
        try:
            self._channel.send_sharing(introduction)
        except OSError as exc:
            raise SenderUnavailable("The device disconnected before the offer.") from exc

    def _await_acceptance(self) -> None:
        self._stage("awaiting-acceptance")
        summary = self._receive_until("RESPONSE", self.acceptance_timeout)
        metadata = summary.connection_response
        status = None if metadata is None else metadata.status
        if status != RESPONSE_ACCEPT:
            if status == RESPONSE_REJECT:
                raise SenderRejected("The device declined the transfer.")
            raise SenderRejected(
                f"The device did not accept the transfer: {_response_description(status)}."
            )

    def _stream_files(self) -> int:
        assert self._channel is not None
        self._stage("sending")
        sent_files = 0
        for item in self.files:
            self._send_one(item)
            sent_files += 1
        return sent_files

    def _send_one(self, item: OutgoingFile) -> None:
        assert self._channel is not None
        try:
            before = item.path.stat()
        except OSError as exc:
            raise SenderFileError(f"'{item.name}' disappeared before it could be sent.") from exc
        if before.st_size != item.size or before.st_mtime_ns != item.modified_ns:
            raise SenderFileError(f"'{item.name}' changed before it could be sent.")

        offset = 0
        last_report = 0
        try:
            with item.path.open("rb") as handle:
                while offset < item.size:
                    self._check_cancel()
                    chunk = handle.read(min(CHUNK_SIZE, item.size - offset))
                    if not chunk:
                        raise SenderFileError(f"'{item.name}' ended before its declared size.")
                    self._channel.send_offline(
                        encode_payload_chunk(
                            item.payload_id,
                            PAYLOAD_TYPE_FILE,
                            item.size,
                            offset,
                            chunk,
                            last_chunk=False,
                            file_name=item.name,
                        )
                    )
                    offset += len(chunk)
                    if (
                        offset - last_report >= PROGRESS_MIN_STEP_BYTES
                        or offset == item.size
                    ) and self.on_progress is not None:
                        last_report = offset
                        try:
                            self.on_progress(item, offset, item.size)
                        except Exception:
                            pass
                extra = handle.read(1)
                if extra:
                    raise SenderFileError(f"'{item.name}' grew while it was being sent.")
        except OSError as exc:
            if isinstance(exc, SenderError):
                raise
            raise SenderUnavailable("The connection closed while sending.") from exc

        try:
            after = item.path.stat()
        except OSError as exc:
            raise SenderFileError(f"'{item.name}' disappeared while it was being sent.") from exc
        if after.st_size != item.size or after.st_mtime_ns != item.modified_ns:
            raise SenderFileError(f"'{item.name}' changed while it was being sent.")

        self._channel.send_offline(
            encode_payload_chunk(
                item.payload_id,
                PAYLOAD_TYPE_FILE,
                item.size,
                item.size,
                b"",
                last_chunk=True,
                file_name=item.name,
            )
        )

    def _linger(self) -> None:
        """Stay connected briefly after the last chunk so the receiver can finish."""
        self._stage("finishing")
        deadline = time.monotonic() + self.linger_timeout
        while time.monotonic() < deadline:
            self._check_cancel()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                item = self._inbound.get(timeout=min(0.5, remaining))
            except queue.Empty:
                continue
            if isinstance(item, _PeerClosed):
                return

    def _close(self) -> None:
        if self._keep_alive is not None:
            self._keep_alive.stop()
            self._keep_alive = None
        channel = self._channel
        if channel is not None:
            try:
                channel.send_offline(encode_disconnection())
            except (OSError, SecureChannelError):
                pass
        self._channel = None
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def _endpoint_info(device_name: str, device_type: int = 3) -> bytes:
    """Endpoint-info blob: flags, 16 random bytes, length-prefixed name."""
    name = device_name.encode("utf-8")[:255]
    flags = (1 << 5) | ((device_type & 0x07) << 1)
    return bytes([flags]) + os.urandom(16) + bytes([len(name)]) + name


def send_files(
    peer: Peer,
    paths: Sequence[str | Path],
    *,
    device_name: str = "ViShare Quick",
    endpoint_id: str | None = None,
    on_stage: Callable[[str], None] | None = None,
    on_pin: Callable[[str], bool] | None = None,
    on_progress: Callable[[OutgoingFile, int, int], None] | None = None,
    cancel_event: threading.Event | None = None,
    connect_timeout: float = 10.0,
    handshake_timeout: float = 20.0,
    acceptance_timeout: float = 180.0,
    linger_timeout: float = 15.0,
    handshake_only: bool = False,
) -> SendResult:
    """Send ``paths`` to one discovered peer.

    ``on_pin`` receives the derived four-digit code and must return ``True``
    only after a human compared it with the receiving device's screen. It is
    called after the Introduction is offered and before any file byte is read.
    """
    if not isinstance(peer.port, int) or not 0 < peer.port <= 65535:
        raise SenderUnavailable("The selected device has no usable port.")
    files = prepare_files(paths)
    if not endpoint_id:
        endpoint_id = "".join(
            secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(4)
        )
    session = _Session(
        peer,
        files,
        device_name=device_name,
        endpoint_id=endpoint_id,
        on_stage=on_stage,
        on_pin=on_pin,
        on_progress=on_progress,
        cancel_event=cancel_event or threading.Event(),
        connect_timeout=connect_timeout,
        handshake_timeout=handshake_timeout,
        acceptance_timeout=acceptance_timeout,
        linger_timeout=linger_timeout,
        handshake_only=handshake_only,
    )
    return session.run()

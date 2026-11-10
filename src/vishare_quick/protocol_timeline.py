"""Sanitized chronological diagnostics for the opt-in Quick Share protocol stages.

The timeline is deliberately metadata-only. It never accepts or renders frame
bytes, plaintext, keys, signatures, certificates, payload bodies, QR data, or
full secret identifiers. Byte values are rendered as their length; field values
are restricted to names, counts, offsets, sizes, flags, and documented enum
names. Diagnostics must never change protocol behavior, so every rendering
helper is defensive and any formatting failure falls back to a safe marker.
"""
from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Callable

from vishare_quick.protocol import (
    Frame,
    FrameTimeout,
    MalformedFrame,
    PeerDisconnected,
    PeerRejectedConnection,
    TruncatedFrame,
    UnexpectedMessageType,
    UnrecognizedMessage,
)
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    InvalidPayloadStructure,
    PayloadTransferMetadata,
    SecureChannelError,
    SecureMessageAuthenticationError,
    SecureMessageDecryptionError,
    UnexpectedSequence,
    _parse_offline_frame,
)
from vishare_quick.ukey2 import HandshakeError

# Stable, machine-readable categories. The device-side experiment can quote
# these without needing to interpret free-form exception text.
ERROR_CATEGORIES = (
    "peer-disconnected",
    "truncated-frame",
    "read-timeout",
    "unexpected-message-type",
    "unexpected-message-order",
    "unexpected-sequence",
    "authentication-failure",
    "decryption-failure",
    "invalid-protobuf-or-framing",
    "invalid-payload-structure",
    "peer-rejected-connection",
    "handshake-failure",
    "socket-reset-or-closed",
    "socket-error",
    "local-implementation-error",
    "unclassified-error",
)

_RESULT_STATUS_NAMES = {
    0: "UNKNOWN",
    1: "SUCCESS",
    2: "FAIL",
    3: "UNABLE",
}
_PAYLOAD_TYPE_NAMES = {
    0: "UNKNOWN",
    1: "BYTES",
    2: "FILE",
    3: "STREAM",
}
_MEDIUM_NAMES = {
    0: "UNKNOWN",
    2: "BLUETOOTH",
    3: "WIFI_HOTSPOT",
    4: "BLE",
    5: "WIFI_LAN",
    6: "WIFI_AWARE",
    7: "NFC",
    8: "WIFI_DIRECT",
    9: "WEB_RTC",
    10: "BLE_L2CAP",
    11: "USB",
    12: "WEB_RTC_NON_CELLULAR",
    13: "AWDL",
    14: "WIFI_AWARE_R4",
}
_MAX_TEXT = 140
# A long uninterrupted token is more likely to be key/signature/hash material
# than useful diagnostic text. Redact it even if a future caller accidentally
# places sensitive material in an exception message.
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{40,}")


def _safe_text(value: str) -> str:
    text = " ".join(str(value).split())
    text = _LONG_TOKEN.sub("<redacted>", text)
    if len(text) > _MAX_TEXT:
        text = text[: _MAX_TEXT - 3] + "..."
    return text or "<empty>"


def _format_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Contents are never rendered, even for short values.
        return f"<{len(value)} bytes>"
    return f"<{type(value).__name__}>"


def error_category(exc: BaseException) -> str:
    """Map an exception to one stable, non-leaking diagnostic category."""
    declared = getattr(exc, "error_category", None)
    if isinstance(declared, str) and declared in ERROR_CATEGORIES:
        return declared
    # Order matters: TruncatedFrame subclasses PeerDisconnected, and
    # FrameTimeout is not an OSError.
    if isinstance(exc, TruncatedFrame):
        return "truncated-frame"
    if isinstance(exc, PeerDisconnected):
        return "peer-disconnected"
    if isinstance(exc, (FrameTimeout, socket.timeout)):
        return "read-timeout"
    if isinstance(exc, (UnexpectedMessageType, UnrecognizedMessage)):
        return "unexpected-message-type"
    if isinstance(exc, PeerRejectedConnection):
        return "peer-rejected-connection"
    if isinstance(exc, MalformedFrame):
        return "invalid-protobuf-or-framing"
    if isinstance(exc, SecureMessageAuthenticationError):
        return "authentication-failure"
    if isinstance(exc, SecureMessageDecryptionError):
        return "decryption-failure"
    if isinstance(exc, UnexpectedSequence):
        return "unexpected-sequence"
    if isinstance(exc, HandshakeError):
        return "handshake-failure"
    if isinstance(exc, (ValueError, TypeError, AssertionError)):
        return "local-implementation-error"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "socket-reset-or-closed"
    if isinstance(exc, OSError):
        return "socket-error"
    if isinstance(exc, SecureChannelError):
        return "invalid-protobuf-or-framing"
    return "unclassified-error"


def safe_error_detail(exc: BaseException) -> str:
    """One-line, length-bounded exception text with token-shaped data redacted."""
    return _safe_text(str(exc) or type(exc).__name__)


def _payload_fields(meta: PayloadTransferMetadata | None) -> dict[str, object]:
    if meta is None:
        return {}
    return {
        "payload_id": meta.payload_id,
        "payload_type": _PAYLOAD_TYPE_NAMES.get(meta.payload_type, f"enum{meta.payload_type}"),
        "total_size": meta.total_size,
        "offset": meta.chunk_offset,
        "length": meta.chunk_body_length,
        "last_chunk": meta.is_last_chunk,
        "complete": meta.complete_sharing_frame,
    }


def _pke_field_text(summary: AuthenticatedFrameSummary) -> str | None:
    if not summary.paired_key_fields:
        return None
    parts = []
    for item in summary.paired_key_fields:
        if item.present:
            parts.append(f"{item.name}=present({item.length}B)")
        else:
            parts.append(f"{item.name}=absent")
    return " ".join(parts)


def _transport_control_fields(
    offline_type: str,
    keep_alive_ack: bool | None,
    retry_mediums: tuple[int, ...],
    retry_is_request: bool | None,
) -> dict[str, object]:
    """Safe metadata for KEEP_ALIVE and BANDWIDTH_UPGRADE_RETRY frames."""
    fields: dict[str, object] = {}
    if keep_alive_ack is not None:
        fields["keep_alive_ack"] = keep_alive_ack
    if retry_is_request is not None:
        fields["retry_is_request"] = retry_is_request
    if offline_type == "BANDWIDTH_UPGRADE_RETRY":
        fields["retry_mediums"] = (
            ",".join(
                _MEDIUM_NAMES.get(medium, f"enum{medium}")
                for medium in retry_mediums
            )
            or "none"
        )
    return fields


@dataclass
class ProtocolTimeline:
    """Append-only, elapsed-time protocol timeline.

    ``printer`` receives one already-sanitized line per event. Tests inject a
    collector and a deterministic clock; production uses ``print`` and
    ``time.monotonic``.
    """

    printer: Callable[[str], None] = print
    clock: Callable[[], float] = time.monotonic
    _start: float | None = None

    def _elapsed(self) -> float:
        if self._start is None:
            self._start = self.clock()
        return max(0.0, self.clock() - self._start)

    def _emit(self, direction: str, event: str, fields: dict[str, object]) -> None:
        parts = [f"[+{self._elapsed():.3f}s]", f"{direction:<5}", event]
        for key, value in fields.items():
            if value is None:
                continue
            parts.append(f"{key}={_format_value(value)}")
        try:
            self.printer(" ".join(parts))
        except Exception:
            # A diagnostic printer must never take down the protocol stage.
            pass

    def event(self, direction: str, event: str, **fields: object) -> None:
        self._emit(direction, event, fields)

    # ------------------------------------------------------------- sockets
    def tcp_connected(self, remote: str) -> None:
        self.event("SOCKET", "TCP_CONNECTED", remote=remote)

    def tcp_closed(self, reason: str) -> None:
        self.event("SOCKET", "SOCKET_CLOSED", reason=reason)

    # ------------------------------------------------------------- plaintext
    def inbound_plaintext(self, frame: Frame) -> None:
        family = frame.family
        if family.startswith("OfflineFrame"):
            layer = "OFFLINE_FRAME"
        elif family.startswith("UKEY2"):
            layer = "UKEY2"
        else:
            layer = "FRAME"
        self.event(
            "IN",
            layer,
            type=frame.message_type,
            bytes=frame.declared_length,
            parsed=True,
            authenticated=False,
        )

    def outbound_plaintext(
        self, layer: str, message_type: str, wire_length: int, **fields: object
    ) -> None:
        values: dict[str, object] = {
            "type": message_type,
            "bytes": wire_length,
            "parsed": True,
            "authenticated": False,
        }
        values.update(fields)
        self.event("OUT", layer, **values)

    # ------------------------------------------------------------- encrypted
    def inbound_secure_failure(
        self, frame_length: int, *, stage: str, exc: BaseException | None = None
    ) -> None:
        """Report where an inbound SecureMessage failed.

        HMAC failure means neither authenticated nor decrypted. A padding
        failure means authenticated but not decrypted. Sequence and payload
        structure failures occur after authentication and decryption. A
        generic SecureChannelError may occur before or after decryption, so the
        decrypted state is left unstated rather than guessed.
        """
        authenticated: bool = False
        decrypted: bool | None = False
        if isinstance(exc, SecureMessageAuthenticationError):
            authenticated, decrypted = False, False
        elif isinstance(exc, SecureMessageDecryptionError):
            authenticated, decrypted = True, False
        elif isinstance(exc, (UnexpectedSequence, InvalidPayloadStructure)):
            authenticated, decrypted = True, True
        elif isinstance(exc, SecureChannelError):
            authenticated, decrypted = True, None
        self.event(
            "IN",
            "SECURE_MESSAGE",
            bytes=frame_length,
            authenticated=authenticated,
            decrypted=decrypted,
            stage=stage,
        )

    def inbound_authenticated(
        self, summary: AuthenticatedFrameSummary, *, stage: str | None = None
    ) -> None:
        self.event(
            "IN",
            "SECURE_MESSAGE",
            seq=summary.sequence,
            authenticated=True,
            decrypted=True,
            stage=stage,
        )
        fields: dict[str, object] = {"offline": summary.offline_type}
        if summary.sharing_type is not None:
            fields["sharing"] = summary.sharing_type
        if summary.paired_key_result_status is not None:
            fields["result_status"] = _RESULT_STATUS_NAMES.get(
                summary.paired_key_result_status,
                f"enum{summary.paired_key_result_status}",
            )
        fields.update(_payload_fields(summary.payload_transfer))
        fields.update(
            _transport_control_fields(
                summary.offline_type,
                summary.keep_alive_ack,
                summary.bandwidth_upgrade_retry_mediums,
                summary.bandwidth_upgrade_retry_is_request,
            )
        )
        self.event("IN", "FRAME", **fields)
        field_text = _pke_field_text(summary)
        if field_text is not None:
            self.event("IN", "PAIRED_KEY_FIELDS", fields=field_text)

    def skipped_transport_frame(
        self, summary: AuthenticatedFrameSummary, *, stage: str
    ) -> None:
        """Report an authenticated transport-control frame intentionally skipped."""
        fields: dict[str, object] = {
            "offline": summary.offline_type,
            "authenticated": True,
            "decrypted": True,
            "stage": stage,
            "reason": "transport-control",
        }
        fields.update(
            _transport_control_fields(
                summary.offline_type,
                summary.keep_alive_ack,
                summary.bandwidth_upgrade_retry_mediums,
                summary.bandwidth_upgrade_retry_is_request,
            )
        )
        self.event("IN", "SKIP", **fields)

    def outbound_authenticated(
        self, sequence: int, offline_frame: bytes, *, stage: str | None = None
    ) -> None:
        self.event(
            "OUT",
            "SECURE_MESSAGE",
            seq=sequence,
            encrypted=True,
            stage=stage,
        )
        try:
            parsed = _parse_offline_frame(offline_frame)
        except SecureChannelError:
            # The local builder produced something this diagnostic parser does
            # not understand; report only the safe failure, never the bytes.
            self.event("OUT", "FRAME", metadata="unavailable")
            return
        fields: dict[str, object] = {"offline": parsed.offline_type}
        if parsed.sharing_type is not None:
            fields["sharing"] = parsed.sharing_type
        if parsed.paired_key_result_status is not None:
            fields["result_status"] = _RESULT_STATUS_NAMES.get(
                parsed.paired_key_result_status,
                f"enum{parsed.paired_key_result_status}",
            )
        fields.update(_payload_fields(parsed.payload_transfer))
        fields.update(
            _transport_control_fields(
                parsed.offline_type,
                parsed.keep_alive_ack,
                parsed.bandwidth_upgrade_retry_mediums,
                parsed.bandwidth_upgrade_retry_is_request,
            )
        )
        self.event("OUT", "FRAME", **fields)
        if parsed.paired_key_fields:
            parts = [
                f"{item.name}=present({item.length}B)"
                if item.present
                else f"{item.name}=absent"
                for item in parsed.paired_key_fields
            ]
            self.event("OUT", "PAIRED_KEY_FIELDS", fields=" ".join(parts))

    # ------------------------------------------------------------- states/errors
    def state(self, name: str) -> None:
        self.event("STATE", name)

    def error(self, exc: BaseException, *, stage: str | None = None) -> str:
        category = error_category(exc)
        self.event(
            "ERROR",
            "PROTOCOL_ERROR",
            category=category,
            stage=stage,
            detail=safe_error_detail(exc),
        )
        return category

"""Explicit no-credential paired-key response for the observed Android sender flow.

The laptop has no Google-account-provisioned Quick Share certificate, so it
cannot produce a meaningful ``signed_data`` signature or a ``secret_id_hash``
that Android could match against a trusted contact certificate. This module
therefore sends the protocol's documented no-credential fallback: a
``PairedKeyEncryptionFrame`` carrying 72 random placeholder bytes in
``signed_data`` and 6 random placeholder bytes in ``secret_id_hash``, followed
by ``PairedKeyResultFrame.UNABLE``.

The placeholders assert no identity. They are the same fallback Google's own
``PairedKeyVerificationRunner`` uses when no private certificate is available
(``kNearbyShareNumBytesRandomSignature = 72`` and a 6-byte authentication-token
hash), and the independent NearDrop, NearShare, and squick-share clients do the
same. ``optional_signed_data``, ``qr_code_handshake_data``, and
``supports_provisioning`` stay absent. No certificate, signature, hash, or
identity material is fabricated or copied, and the local result is always
``UNABLE``. The bytes are protected by the existing directional
UKEY2/SecureMessage session keys.

Wire order implemented (server/laptop POV), corroborated by NearDrop,
squick-share, NearShare, and Chromium's ``PairedKeyVerificationRunner``:

    Android -> laptop : PKE DATA chunk
    Android -> laptop : PKE LAST_CHUNK terminator
    laptop -> Android : no-credential PKE DATA + terminator  (send sequences 1, 2)
    laptop -> Android : PKE RESULT UNABLE + terminator       (send sequences 3, 4)
    Android -> laptop : transport control frames may interleave here; a
                        KEEP_ALIVE is acknowledged and bandwidth-control
                        frames are ignored
    Android -> laptop : PKE RESULT DATA + terminator
    Android -> laptop : INTRODUCTION (optional observation only)

DeviceToDeviceMessage sequence numbers are transport-wide. They advance for
every authenticated frame, including skipped control frames, so the code never
assumes that an application message has a fixed sequence number.

No consent response, file transfer, or identity claim is implemented here.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Protocol

from vishare_quick.protocol import (
    FrameError,
    FrameTimeout,
    PeerDisconnected,
    TruncatedFrame,
    _encode_bytes_field,
    _encode_varint_field,
    read_frame,
)
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    PayloadTransferMetadata,
    ReceiveKeys,
    SecureChannelError,
    SendKeys,
    authenticate_and_inspect_frame,
    encode_secure_message,
)

PAIRED_KEY_RESULT_UNKNOWN = 0
PAIRED_KEY_RESULT_SUCCESS = 1
PAIRED_KEY_RESULT_FAIL = 2
PAIRED_KEY_RESULT_UNABLE = 3
_VALID_RESULT_STATUSES = (
    PAIRED_KEY_RESULT_UNKNOWN,
    PAIRED_KEY_RESULT_SUCCESS,
    PAIRED_KEY_RESULT_FAIL,
    PAIRED_KEY_RESULT_UNABLE,
)

# Deterministic, positive payload IDs chosen by this receiver for its own
# outbound BYTES payloads. They are independent of the IDs Android chose for
# its inbound PKE payload.
_PKE_PAYLOAD_ID = 1
_PKR_PAYLOAD_ID = 2

# Outbound payload IDs already consumed by this stage. A later outbound payload
# in the same connection (for example the sharing RESPONSE) must pick a fresh
# ID rather than reusing one Android has already acknowledged.
PAIRED_KEY_OUTBOUND_PAYLOAD_IDS = frozenset({_PKE_PAYLOAD_ID, _PKR_PAYLOAD_ID})

# Google's documented no-credential fallback sizes. These are fresh random
# placeholder bytes, not a signature or a certificate-derived hash, and the
# local result remains UNABLE.
_PKE_SIGNED_DATA_LENGTH = 72
_PKE_SECRET_ID_HASH_LENGTH = 6

# Authenticated transport-control frames that may legally interleave with the
# paired-key conversation. All three independent receivers reviewed for this
# stage (NearShare, NearDrop, squick-share) ignore these while waiting for the
# next sharing-layer message. They still consume a DeviceToDeviceMessage
# sequence number because the sequence is transport-wide, not per message type.
_TRANSPORT_CONTROL_TYPES = frozenset(
    {
        "KEEP_ALIVE",
        "BANDWIDTH_UPGRADE_NEGOTIATION",
        "BANDWIDTH_UPGRADE_RETRY",
        "AUTO_RESUME",
        "AUTO_RECONNECT",
    }
)
# Bounds memory/CPU if a peer floods control frames. The response stage itself
# is already bounded by the caller's socket deadline.
_MAX_SKIPPED_TRANSPORT_FRAMES = 16

_MAX_INT64 = (1 << 63) - 1


class PairedKeyResponseError(SecureChannelError):
    """Unexpected authenticated message order or invalid response transition."""

    error_category = "unexpected-message-order"


class PairedKeyMessageError(PairedKeyResponseError):
    """An authenticated frame had the wrong sharing-layer message type."""

    error_category = "unexpected-message-type"


class PairedKeyStructureError(PairedKeyResponseError):
    """An authenticated payload/chunk did not have the required structure."""

    error_category = "invalid-payload-structure"


class PairedKeySequenceError(PairedKeyResponseError):
    """Locally detected sequence violation.

    Transport sequence validation itself lives in
    ``secure_channel.authenticate_and_inspect_frame`` and raises
    ``UnexpectedSequence``; this class is retained for callers that classify a
    paired-key-specific sequence failure.
    """

    error_category = "unexpected-sequence"


class PairedKeyStateError(PairedKeyResponseError):
    """A message arrived in a locally impossible state-transition slot."""

    error_category = "unexpected-message-order"


class PairedKeySendError(PairedKeyResponseError):
    """The local writer failed while sending the response."""

    error_category = "socket-error"


class FrameWriter(Protocol):
    def sendall(self, data: bytes) -> None: ...


@dataclass(frozen=True)
class PairedKeyResponseResult:
    offer: AuthenticatedFrameSummary
    offer_terminator: AuthenticatedFrameSummary
    peer_result: AuthenticatedFrameSummary
    peer_result_terminator: AuthenticatedFrameSummary
    introduction: AuthenticatedFrameSummary | None
    status: str
    # A peer RESPONSE can arrive in the optional Introduction slot. It is a
    # distinct observed state, not an error and not consent.
    peer_response: AuthenticatedFrameSummary | None = None
    # Transport-wide counters after this stage. A continuation must reuse them
    # rather than restarting at 1; the peer validates a single monotonic
    # sequence per direction.
    next_inbound_sequence: int = 1
    next_outbound_sequence: int = 1


def build_paired_key_encryption_frame() -> bytes:
    """Build the no-credential ``PairedKeyEncryptionFrame`` sharing message.

    ``signed_data`` and ``secret_id_hash`` carry fresh random placeholder bytes
    of the sizes used by Google's implementation when no certificate is
    available. They are not a signature, certificate, identity, or actual
    secret-ID hash; they are random protocol placeholders. The remaining
    optional fields (``optional_signed_data``, ``qr_code_handshake_data``,
    ``supports_provisioning``) stay absent.
    """
    body = (
        _encode_bytes_field(1, secrets.token_bytes(_PKE_SIGNED_DATA_LENGTH))
        + _encode_bytes_field(2, secrets.token_bytes(_PKE_SECRET_ID_HASH_LENGTH))
    )
    v1 = _encode_varint_field(1, 3) + _encode_bytes_field(4, body)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def build_paired_key_result_frame(status: int = PAIRED_KEY_RESULT_UNABLE) -> bytes:
    """Build a ``PairedKeyResultFrame`` sharing message with a validated status."""
    if not isinstance(status, int) or status not in _VALID_RESULT_STATUSES:
        raise ValueError("Unsupported PairedKeyResultFrame status.")
    body = _encode_varint_field(1, status)
    v1 = _encode_varint_field(1, 4) + _encode_bytes_field(5, body)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def build_keep_alive_frame(*, ack: bool = False) -> bytes:
    """Build a KEEP_ALIVE OfflineFrame.

    ``V1Frame.type`` 5 is KEEP_ALIVE and its body field is 6; the
    ``KeepAliveFrame.ack`` flag is field 1. A receiver answers a peer's
    keep-alive with ``ack=True``. Both directions also send unsolicited
    ``ack=False`` keep-alives on an idle connection, as Google's sender and all
    reviewed clients do, so that the peer's idle timer does not expire while a
    human is deciding or while data is being flushed.
    """
    keep_alive = _encode_varint_field(1, 1 if ack else 0)
    v1 = _encode_varint_field(1, 5) + _encode_bytes_field(6, keep_alive)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def build_keep_alive_ack_frame() -> bytes:
    """Build a KEEP_ALIVE OfflineFrame acknowledging the peer's keep-alive."""
    return build_keep_alive_frame(ack=True)


def _wrap_payload_transfer(header: bytes, chunk: bytes) -> bytes:
    transfer = (
        _encode_varint_field(1, 1)  # PayloadTransferFrame.DATA
        + _encode_bytes_field(2, header)
        + _encode_bytes_field(3, chunk)
    )
    offline_v1 = _encode_varint_field(1, 3) + _encode_bytes_field(4, transfer)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, offline_v1)


def build_bytes_payload_messages(
    sharing_frame: bytes, payload_id: int
) -> tuple[bytes, bytes]:
    """Return the documented DATA + zero-length LAST_CHUNK OfflineFrames."""
    if not isinstance(sharing_frame, bytes) or not sharing_frame:
        raise ValueError("A sharing Frame must be non-empty bytes.")
    if not isinstance(payload_id, int) or not 0 <= payload_id <= _MAX_INT64:
        raise ValueError("Payload ID must be a non-negative int64.")
    # PayloadHeader: id=1, type=2 (BYTES), total_size=3.
    header = (
        _encode_varint_field(1, payload_id)
        + _encode_varint_field(2, 1)
        + _encode_varint_field(3, len(sharing_frame))
    )
    # PayloadChunk: flags=1, offset=2, body=3. Android ends negotiation
    # payloads with flags=LAST_CHUNK, offset=total_size, and no body field.
    data_chunk = (
        _encode_varint_field(1, 0)
        + _encode_varint_field(2, 0)
        + _encode_bytes_field(3, sharing_frame)
    )
    last_chunk = _encode_varint_field(1, 1) + _encode_varint_field(2, len(sharing_frame))
    return _wrap_payload_transfer(header, data_chunk), _wrap_payload_transfer(header, last_chunk)


def build_paired_key_response_messages() -> tuple[bytes, bytes, bytes, bytes]:
    """Build the four outbound OfflineFrames in wire order."""
    pke_data, pke_last = build_bytes_payload_messages(
        build_paired_key_encryption_frame(), _PKE_PAYLOAD_ID
    )
    result_data, result_last = build_bytes_payload_messages(
        build_paired_key_result_frame(), _PKR_PAYLOAD_ID
    )
    return pke_data, pke_last, result_data, result_last


def _describe_payload(meta: PayloadTransferMetadata | None) -> str:
    """Safe metadata only: never payload bytes or identity material."""
    if meta is None:
        return "payload=none"
    return (
        f"payload_id={meta.payload_id} payload_type={meta.payload_type} "
        f"total_size={meta.total_size} offset={meta.chunk_offset} "
        f"body={meta.chunk_body_length} "
        f"last_chunk={'true' if meta.is_last_chunk else 'false'} "
        f"complete={'true' if meta.complete_sharing_frame else 'false'}"
    )


def _describe_summary(summary: AuthenticatedFrameSummary) -> str:
    return (
        f"offline={summary.offline_type} "
        f"sharing={summary.sharing_type or 'none'} "
        + _describe_payload(summary.payload_transfer)
    )


def _require_complete_bytes(summary: AuthenticatedFrameSummary, label: str) -> PayloadTransferMetadata:
    meta = summary.payload_transfer
    if (summary.offline_type != "PAYLOAD_TRANSFER" or meta is None
            or meta.packet_type != 1 or meta.payload_type != 1
            or not meta.complete_sharing_frame):
        raise PairedKeyStructureError(
            f"Expected a complete BYTES payload for the {label}; "
            f"received {_describe_summary(summary)}."
        )
    return meta


def _require_terminator(
    summary: AuthenticatedFrameSummary,
    expected: PayloadTransferMetadata,
    label: str,
) -> None:
    meta = summary.payload_transfer
    if (summary.offline_type != "PAYLOAD_TRANSFER" or summary.sharing_type is not None
            or meta is None or meta.packet_type != 1 or meta.payload_type != 1
            or not meta.is_last_chunk or meta.chunk_body_length != 0
            or meta.chunk_offset != meta.total_size
            or meta.payload_id != expected.payload_id
            or meta.total_size != expected.total_size):
        raise PairedKeyStructureError(
            f"Expected the zero-length LAST_CHUNK terminator for the {label}; "
            f"received {_describe_summary(summary)}."
        )


class PairedKeyResponseState:
    """Strict state machine for the no-credential paired-key response."""

    def __init__(self) -> None:
        self.state = "awaiting-offer"
        self._offer: AuthenticatedFrameSummary | None = None
        self._peer_result: AuthenticatedFrameSummary | None = None

    def accept_offer(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-offer":
            raise PairedKeyStateError("Paired-key offer arrived in an invalid state.")
        if summary.sharing_type != "PAIRED_KEY_ENCRYPTION":
            raise PairedKeyMessageError(
                "Expected authenticated PAIRED_KEY_ENCRYPTION; "
                f"received {_describe_summary(summary)}."
            )
        meta = _require_complete_bytes(summary, "paired-key offer")
        if meta.chunk_offset != 0 or meta.is_last_chunk:
            raise PairedKeyStructureError(
                "Paired-key offer must be an unterminated DATA chunk; "
                f"received {_describe_summary(summary)}."
            )
        self._offer = summary
        self.state = "awaiting-offer-terminator"

    def accept_offer_terminator(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-offer-terminator" or self._offer is None:
            raise PairedKeyStateError("Offer terminator arrived in an invalid state.")
        _require_terminator(summary, self._offer.payload_transfer, "paired-key offer")
        self.state = "ready-to-send"

    def mark_sent(self) -> None:
        if self.state != "ready-to-send":
            raise PairedKeyStateError("Paired-key response cannot be sent in the current state.")
        self.state = "awaiting-peer-result"

    def accept_peer_result(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-peer-result":
            raise PairedKeyStateError("Peer paired-key result arrived in an invalid state.")
        if summary.sharing_type != "PAIRED_KEY_RESULT":
            raise PairedKeyMessageError(
                "Expected authenticated PAIRED_KEY_RESULT; "
                f"received {_describe_summary(summary)}."
            )
        _require_complete_bytes(summary, "peer paired-key result")
        self._peer_result = summary
        self.state = "awaiting-peer-result-terminator"

    def accept_peer_result_terminator(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-peer-result-terminator" or self._peer_result is None:
            raise PairedKeyStateError("Peer result terminator arrived in an invalid state.")
        _require_terminator(summary, self._peer_result.payload_transfer, "peer paired-key result")
        self.state = "awaiting-introduction"

    def accept_introduction(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-introduction":
            raise PairedKeyStateError("Introduction arrived in an invalid state.")
        if summary.sharing_type != "INTRODUCTION":
            raise PairedKeyMessageError(
                "Expected authenticated INTRODUCTION; "
                f"received {_describe_summary(summary)}."
            )
        _require_complete_bytes(summary, "introduction")
        self.state = "complete"

    def accept_response_without_introduction(
        self, summary: AuthenticatedFrameSummary
    ) -> None:
        """Record a peer RESPONSE that arrived instead of an Introduction.

        Android has been observed emitting its scripted sharing RESPONSE after
        the paired-key result even when it does not send an Introduction. The
        response is a legitimate authenticated message, so it is classified as
        a distinct terminal state rather than an ``unexpected-message-type``
        error. It is never treated as consent: no transfer or response follows.
        """
        if self.state != "awaiting-introduction":
            raise PairedKeyStateError("Peer response arrived in an invalid state.")
        if summary.sharing_type != "RESPONSE":
            raise PairedKeyMessageError(
                "Expected authenticated INTRODUCTION or RESPONSE; "
                f"received {_describe_summary(summary)}."
            )
        _require_complete_bytes(summary, "peer response")
        self.state = "complete"

    def finish_without_introduction(self, status: str) -> None:
        if self.state != "awaiting-introduction" or status not in (
            "introduction-timeout",
            "introduction-disconnect",
        ):
            raise PairedKeyStateError("Response cannot finish in the current state.")
        self.state = "complete"


def _read_authenticated(
    reader,
    receive_keys: ReceiveKeys,
    expected_sequence: int,
    stage: str,
    timeline: ProtocolTimeline | None = None,
) -> AuthenticatedFrameSummary:
    """Authenticate one inbound frame, preserving type with stage context.

    Timeout/disconnect context is diagnostic only; the exception class is kept
    so callers (including the optional Introduction wait) can still distinguish
    a timed-out wait from an active disconnect.
    """
    try:
        frame = read_frame(reader, classify=False)
    except FrameTimeout as exc:
        raise FrameTimeout(
            f"Timed out waiting for authenticated inbound sequence "
            f"{expected_sequence} ({stage})."
        ) from exc
    except TruncatedFrame as exc:
        raise TruncatedFrame(
            f"Peer disconnected during authenticated inbound sequence "
            f"{expected_sequence} ({stage})."
        ) from exc
    except PeerDisconnected as exc:
        raise PeerDisconnected(
            f"Peer disconnected before authenticated inbound sequence "
            f"{expected_sequence} ({stage})."
        ) from exc

    try:
        summary = authenticate_and_inspect_frame(
            frame, receive_keys, expected_sequence=expected_sequence
        )
    except (FrameError, SecureChannelError) as exc:
        if timeline is not None:
            timeline.inbound_secure_failure(
                frame.declared_length, stage=stage, exc=exc
            )
        raise
    if timeline is not None:
        timeline.inbound_authenticated(summary, stage=stage)
    return summary


def _read_next_application_frame(
    read_next: Callable[[str], AuthenticatedFrameSummary],
    send_keep_alive_ack: Callable[[], None],
    stage: str,
    timeline: ProtocolTimeline | None,
) -> AuthenticatedFrameSummary:
    """Read until an application PAYLOAD_TRANSFER, skipping transport control.

    Android interleaves authenticated transport frames (notably
    BANDWIDTH_UPGRADE_RETRY) with the paired-key conversation. Every
    authenticated frame consumes one transport sequence number, so this helper
    uses the caller's single monotonic counter and never assumes that an
    application message has a fixed sequence. KEEP_ALIVE is acknowledged;
    bandwidth-control frames are ignored, matching NearShare, NearDrop, and
    squick-share. DISCONNECTION is reported as a peer disconnect rather than as
    a paired-key message error.
    """
    skipped = 0
    while True:
        summary = read_next(stage)
        if summary.offline_type == "DISCONNECTION":
            raise PeerDisconnected(f"Peer sent DISCONNECTION while waiting for {stage}.")
        if summary.offline_type == "PAYLOAD_TRANSFER":
            return summary
        if summary.offline_type in _TRANSPORT_CONTROL_TYPES:
            skipped += 1
            if skipped > _MAX_SKIPPED_TRANSPORT_FRAMES:
                raise PairedKeyStructureError(
                    f"Too many transport control frames ({skipped}) while waiting "
                    f"for {stage}."
                )
            if summary.offline_type == "KEEP_ALIVE" and summary.keep_alive_ack is not True:
                send_keep_alive_ack()
            if timeline is not None:
                timeline.skipped_transport_frame(summary, stage=stage)
            continue
        raise PairedKeyMessageError(
            f"Expected {stage}; received {_describe_summary(summary)}."
        )


def run_paired_key_response(
    reader,
    writer: FrameWriter,
    receive_keys: ReceiveKeys,
    send_keys: SendKeys,
    *,
    read_introduction: bool = True,
    timeline: ProtocolTimeline | None = None,
) -> PairedKeyResponseResult:
    """Receive the Android PKE offer, send the no-identity response, then observe.

    No outbound bytes are written until the offer and its terminator have both
    authenticated and passed strict structural checks. If anything fails before
    that point, the peer receives nothing.

    Authenticated transport-control frames are transparently skipped. The
    inbound and outbound DeviceToDeviceMessage sequence counters are
    transport-wide and are never reset or renumbered by a skipped frame.
    """
    state = PairedKeyResponseState()
    next_inbound = 1
    next_outbound = 1

    def read_next(stage: str) -> AuthenticatedFrameSummary:
        nonlocal next_inbound
        summary = _read_authenticated(
            reader, receive_keys, next_inbound, stage, timeline
        )
        next_inbound += 1
        return summary

    def send_offline(offline_frame: bytes, stage: str) -> None:
        nonlocal next_outbound
        wire = encode_secure_message(offline_frame, send_keys, next_outbound)
        try:
            writer.sendall(wire)
        except OSError as exc:
            raise PairedKeySendError(f"Failed to send {stage}.") from exc
        if timeline is not None:
            timeline.outbound_authenticated(
                next_outbound, offline_frame, stage=stage
            )
        next_outbound += 1

    def send_keep_alive_ack() -> None:
        send_offline(build_keep_alive_ack_frame(), "keep-alive acknowledgement")

    def read_application(stage: str) -> AuthenticatedFrameSummary:
        return _read_next_application_frame(
            read_next, send_keep_alive_ack, stage, timeline
        )

    offer = read_application("Android paired-key offer")
    state.accept_offer(offer)
    if timeline is not None:
        timeline.state("PAIRED_KEY_OFFER_AUTHENTICATED")
    offer_terminator = read_application("Android paired-key offer terminator")
    state.accept_offer_terminator(offer_terminator)
    if timeline is not None:
        timeline.state("PAIRED_KEY_OFFER_TERMINATOR_AUTHENTICATED")

    for message in build_paired_key_response_messages():
        send_offline(message, "paired-key response")
    state.mark_sent()
    if timeline is not None:
        timeline.state("PAIRED_KEY_RESPONSE_SENT")

    peer_result = read_application("peer paired-key result")
    state.accept_peer_result(peer_result)
    if timeline is not None:
        timeline.state("PEER_PAIRED_KEY_RESULT_AUTHENTICATED")
    peer_result_terminator = read_application(
        "peer paired-key result terminator"
    )
    state.accept_peer_result_terminator(peer_result_terminator)
    if timeline is not None:
        timeline.state("PEER_PAIRED_KEY_RESULT_TERMINATED")

    introduction: AuthenticatedFrameSummary | None = None
    peer_response: AuthenticatedFrameSummary | None = None
    status = "peer-paired-key-result-received"
    if read_introduction:
        try:
            candidate = read_application("optional Introduction")
        except FrameTimeout:
            state.finish_without_introduction("introduction-timeout")
            status = "introduction-timeout"
            if timeline is not None:
                timeline.state("INTRODUCTION_TIMEOUT")
        except (PeerDisconnected, TruncatedFrame):
            state.finish_without_introduction("introduction-disconnect")
            status = "introduction-disconnect"
            if timeline is not None:
                timeline.state("INTRODUCTION_DISCONNECT")
        else:
            if candidate.sharing_type == "INTRODUCTION":
                state.accept_introduction(candidate)
                introduction = candidate
                status = "introduction-received"
                if timeline is not None:
                    timeline.state("INTRODUCTION_RECEIVED")
            elif candidate.sharing_type == "RESPONSE":
                state.accept_response_without_introduction(candidate)
                peer_response = candidate
                status = "response-before-introduction"
                if timeline is not None:
                    timeline.state("RESPONSE_BEFORE_INTRODUCTION")
            else:
                # Preserve the existing strict error for every other type.
                state.accept_introduction(candidate)

    return PairedKeyResponseResult(
        offer=offer,
        offer_terminator=offer_terminator,
        peer_result=peer_result,
        peer_result_terminator=peer_result_terminator,
        introduction=introduction,
        status=status,
        peer_response=peer_response,
        next_inbound_sequence=next_inbound,
        next_outbound_sequence=next_outbound,
    )

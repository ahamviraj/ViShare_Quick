"""Receiver-side sharing session after the paired-key exchange.

Flow (laptop/receiver point of view), corroborated by NearDrop, NearShare, and
squick-share:

    Android -> laptop : authenticated INTRODUCTION (already read by the PKE stage)
    laptop            : parse metadata, derive the 4-digit UKEY2 code
    laptop user       : compare the code with Android's screen and confirm
    laptop user       : accept or reject the listed files
    laptop -> Android : sharing RESPONSE ACCEPT / REJECT / NOT_ENOUGH_SPACE /
                        UNSUPPORTED_ATTACHMENT_TYPE
    Android -> laptop : authenticated FILE payload chunks
    laptop -> Android : authenticated DISCONNECTION after every file is complete

There is no wire message for the PIN. It is a deterministic function of the
UKEY2 auth string and is compared by the humans on both screens. Consent is a
separate, explicit local decision. This module never synthesizes either one.

Android also emits its own sharing ``RESPONSE`` after the Introduction. That
message is peer state, not local consent, and is consumed during the file stage
without changing the user's decision.

Both ends of the reviewed clients run an unsolicited keep-alive sender while a
session is open, in addition to answering the peer's keep-alives. The outbound
keep-alive thread here shares one lock with the session thread so that a
keep-alive can never interleave its bytes with a RESPONSE or reuse a transport
sequence number.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from vishare_quick.consent import (
    RESPONSE_ACCEPT,
    RESPONSE_NOT_ENOUGH_SPACE,
    RESPONSE_REJECT,
    RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE,
    ConsentRequest,
    FileOffer,
    Prompter,
    build_connection_response_frame,
    build_disconnection_frame,
)
from vishare_quick.file_transfer import (
    DEFAULT_RESERVED_BYTES,
    FileReceiver,
    FileTransferError,
    ReceivedFile,
    check_free_space,
    safe_filename,
)
from vishare_quick.introduction import Introduction, IntroductionError, parse_introduction
from vishare_quick.paired_key_response import (
    PAIRED_KEY_OUTBOUND_PAYLOAD_IDS,
    FrameWriter,
    _read_authenticated,
    _read_next_application_frame,
    build_bytes_payload_messages,
    build_keep_alive_ack_frame,
    build_keep_alive_frame,
)
from vishare_quick.pin_verification import PinVerification
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    ReceiveKeys,
    SendKeys,
    encode_secure_message,
)

_MAX_INT64 = (1 << 63) - 1

# Matches the observed Android cadence (about five seconds) and is well below
# the reviewed clients' idle timeouts. A slow human PIN comparison or a stalled
# filesystem therefore cannot expire the peer's idle timer.
KEEP_ALIVE_INTERVAL_SECONDS = 5.0


class SharingSessionError(Exception):
    """The post-Introduction sharing session failed a local invariant."""

    error_category = "invalid-payload-structure"


class SharingSessionStateError(SharingSessionError):
    """A message arrived in an impossible local state."""

    error_category = "unexpected-message-order"


@dataclass(frozen=True)
class ReceiveSessionResult:
    introduction: Introduction | None
    pin_code: str | None
    pin_verified: bool
    consent: str
    files: tuple[ReceivedFile, ...]
    status: str


class ProgressReporter(Protocol):
    def __call__(self, payload_id: int, received: int, total: int) -> None: ...


class _OutboundChannel:
    """Serialize encrypted frames together with their sequence numbers.

    The proactive keep-alive thread and the session thread share one socket and
    one monotonic outbound sequence. Taking this lock for the whole
    encode-and-send operation means the two writers can never interleave bytes
    or consume the same sequence number twice.
    """

    def __init__(
        self,
        writer: FrameWriter,
        send_keys: SendKeys,
        next_sequence: int,
        timeline: ProtocolTimeline | None,
    ) -> None:
        self._writer = writer
        self._send_keys = send_keys
        self._sequence = next_sequence
        self._timeline = timeline
        self._lock = threading.Lock()
        self._sealed = False

    def seal(self) -> None:
        """Refuse every further frame except the one that closes the session.

        ``DISCONNECTION`` must be the last outbound frame. Stopping the
        keep-alive thread is not quite enough: a keep-alive that had already
        left its wait loop could still be queued behind the closing frame. The
        seal makes that race harmless because any such send is dropped.
        """
        with self._lock:
            self._sealed = True

    def send(self, offline_frame: bytes, stage: str, *, closing: bool = False) -> None:
        with self._lock:
            if self._sealed and not closing:
                raise SharingSessionError(
                    "The connection is closing; no further frames may be sent."
                )
            sequence = self._sequence
            wire = encode_secure_message(offline_frame, self._send_keys, sequence)
            try:
                self._writer.sendall(wire)
            except OSError as exc:
                raise SharingSessionError(f"Failed to send {stage}.") from exc
            if self._timeline is not None:
                self._timeline.outbound_authenticated(
                    sequence, offline_frame, stage=stage
                )
            self._sequence += 1


class _ProactiveKeepAlive:
    """Send unsolicited ``ack=False`` keep-alives until stopped."""

    def __init__(
        self, send: Callable[[bytes, str], None], interval: float
    ) -> None:
        if not isinstance(interval, (int, float)) or interval <= 0:
            raise ValueError("Keep-alive interval must be positive.")
        self._send = send
        self._interval = float(interval)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="vishare-quick-keepalive",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._send(
                    build_keep_alive_frame(ack=False), "proactive keep-alive"
                )
            except Exception:
                # The read side reports the authoritative socket failure. A
                # diagnostic keep-alive must never take down the process or
                # mask that error.
                return

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)


def _choose_response_payload_id(
    introduction: Introduction,
    *,
    reserved_payload_ids: frozenset[int] = PAIRED_KEY_OUTBOUND_PAYLOAD_IDS,
) -> int:
    """Pick a fresh positive id for our RESPONSE payload.

    The paired-key stage already used payload IDs 1 and 2 in this connection,
    so reusing them would make Android see a second payload under an ID it has
    finished acknowledging. Introduced file IDs and preview IDs are also
    avoided, including negative two's-complement IDs.
    """
    used = {item.payload_id for item in introduction.files}
    used.update(introduction.preview_payload_ids)
    used.update(reserved_payload_ids)
    candidate = 1
    while candidate in used and candidate <= _MAX_INT64:
        candidate += 1
    if candidate > _MAX_INT64:
        raise SharingSessionError("No free payload ID is available for the response.")
    return candidate


def _display_offers(introduction: Introduction) -> tuple[FileOffer, ...]:
    return tuple(
        FileOffer(
            payload_id=item.payload_id,
            name=safe_filename(item.name),
            size=item.size,
            mime_type=item.mime_type,
            type_name=item.type_name,
        )
        for item in introduction.files
    )


def run_receive_session(
    reader,
    writer: FrameWriter,
    receive_keys: ReceiveKeys,
    send_keys: SendKeys,
    auth_string: bytes,
    *,
    introduction_summary: AuthenticatedFrameSummary | None,
    parsed_introduction: Introduction | None = None,
    next_inbound_sequence: int,
    next_outbound_sequence: int,
    download_dir: Path,
    prompter: Prompter,
    timeline: ProtocolTimeline | None = None,
    progress: ProgressReporter | None = None,
    reserved_bytes: int = DEFAULT_RESERVED_BYTES,
    keep_alive_interval_seconds: float = KEEP_ALIVE_INTERVAL_SECONDS,
) -> ReceiveSessionResult:
    """Parse Introduction, verify the PIN by human comparison, ask consent, receive files."""
    if introduction_summary is None:
        raise SharingSessionError("No authenticated Introduction is available.")
    if parsed_introduction is None and introduction_summary.payload_body is None:
        raise SharingSessionError("Authenticated Introduction carried no payload body.")

    next_inbound = next_inbound_sequence
    channel = _OutboundChannel(
        writer, send_keys, next_outbound_sequence, timeline
    )

    def read_next(stage: str) -> AuthenticatedFrameSummary:
        nonlocal next_inbound
        summary = _read_authenticated(
            reader, receive_keys, next_inbound, stage, timeline
        )
        next_inbound += 1
        return summary

    def send_offline(offline_frame: bytes, stage: str) -> None:
        channel.send(offline_frame, stage)

    def send_keep_alive_ack() -> None:
        send_offline(build_keep_alive_ack_frame(), "keep-alive acknowledgement")

    def send_sharing(sharing_frame: bytes, payload_id: int, stage: str) -> None:
        data, last = build_bytes_payload_messages(sharing_frame, payload_id)
        send_offline(data, stage)
        send_offline(last, stage)

    keep_alive_holder: list[_ProactiveKeepAlive] = []

    def stop_keep_alive() -> None:
        for sender in keep_alive_holder:
            sender.stop()
        keep_alive_holder.clear()

    def best_effort_disconnect(stage: str) -> None:
        # The final DISCONNECTION must be the last outbound frame; sealing
        # rejects any keep-alive that was already unblocking when we stopped.
        stop_keep_alive()
        channel.seal()
        try:
            channel.send(build_disconnection_frame(), stage, closing=True)
        except (OSError, SharingSessionError):
            pass

    try:
        if parsed_introduction is None:
            introduction = parse_introduction(introduction_summary.payload_body)
            if timeline is not None:
                timeline.state("INTRODUCTION_PARSED")
        else:
            introduction = parsed_introduction
    except IntroductionError:
        if timeline is not None:
            timeline.state("INTRODUCTION_PARSE_FAILED")
        raise

    if not introduction.is_supported_file_transfer or introduction.expect_more:
        status = (
            RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE
            if not introduction.is_supported_file_transfer
            else RESPONSE_REJECT
        )
        try:
            send_sharing(
                build_connection_response_frame(status),
                _choose_response_payload_id(introduction),
                "unsupported-introduction response",
            )
            best_effort_disconnect("unsupported-introduction disconnect")
        finally:
            if timeline is not None:
                timeline.state("CONSENT_REJECTED")
        return ReceiveSessionResult(
            introduction=introduction,
            pin_code=None,
            pin_verified=False,
            consent="unsupported",
            files=(),
            status="unsupported-introduction",
        )

    verification = PinVerification(auth_string)

    def complete_session() -> ReceiveSessionResult:
        """Run the human decision and transfer while keep-alives stay active."""
        if timeline is not None:
            timeline.state("PIN_VERIFICATION_PENDING")
        entered = prompter.ask_pin(verification.code)
        if entered is None or not verification.verify(entered):
            if timeline is not None:
                timeline.state("PIN_VERIFICATION_FAILED")
            try:
                send_sharing(
                    build_connection_response_frame(RESPONSE_REJECT),
                    _choose_response_payload_id(introduction),
                    "PIN-rejected response",
                )
                best_effort_disconnect("PIN-rejected disconnect")
            finally:
                if timeline is not None:
                    timeline.state("CONSENT_REJECTED")
            return ReceiveSessionResult(
                introduction=introduction,
                pin_code=verification.code,
                pin_verified=False,
                consent="pin-rejected",
                files=(),
                status="pin-verification-failed",
            )
        if timeline is not None:
            timeline.state("PIN_VERIFICATION_SUCCEEDED")

        offers = _display_offers(introduction)
        total_size = introduction.total_size
        if not check_free_space(Path(download_dir), total_size, reserved_bytes):
            send_sharing(
                build_connection_response_frame(RESPONSE_NOT_ENOUGH_SPACE),
                _choose_response_payload_id(introduction),
                "not-enough-space response",
            )
            best_effort_disconnect("not-enough-space disconnect")
            if timeline is not None:
                timeline.state("TRANSFER_FAILED")
            return ReceiveSessionResult(
                introduction=introduction,
                pin_code=verification.code,
                pin_verified=True,
                consent="not-enough-space",
                files=(),
                status="not-enough-space",
            )

        request = ConsentRequest(
            pin=verification.code,
            files=offers,
            total_size=total_size,
            identity_verified=False,
            transfer_id=introduction.transfer_id,
        )
        if timeline is not None:
            timeline.state("CONSENT_PENDING")
        accepted = prompter.request_consent(request)
        if not accepted:
            if timeline is not None:
                timeline.state("CONSENT_REJECTED")
            send_sharing(
                build_connection_response_frame(RESPONSE_REJECT),
                _choose_response_payload_id(introduction),
                "consent-rejected response",
            )
            best_effort_disconnect("consent-rejected disconnect")
            return ReceiveSessionResult(
                introduction=introduction,
                pin_code=verification.code,
                pin_verified=True,
                consent="rejected",
                files=(),
                status="consent-rejected",
            )

        if timeline is not None:
            timeline.state("CONSENT_ACCEPTED")

        receiver = FileReceiver(
            Path(download_dir),
            introduction,
            progress=progress,
            reserved_bytes=reserved_bytes,
        )
        try:
            receiver.prepare()
        except FileTransferError:
            # A local prepare failure is not a claim about the declared size:
            # the up-front free-space check already handled that case. Tell the
            # sender this endpoint declined rather than that the disk is full.
            receiver.abort()
            send_sharing(
                build_connection_response_frame(RESPONSE_REJECT),
                _choose_response_payload_id(introduction),
                "prepare-failed response",
            )
            best_effort_disconnect("prepare-failed disconnect")
            if timeline is not None:
                timeline.state("TRANSFER_FAILED")
            raise

        response_id = _choose_response_payload_id(introduction)
        try:
            send_sharing(
                build_connection_response_frame(RESPONSE_ACCEPT),
                response_id,
                "consent-accepted response",
            )
            if timeline is not None:
                timeline.state("TRANSFER_STARTED")

            while receiver.pending_payload_ids:
                summary = _read_next_application_frame(
                    read_next, send_keep_alive_ack, "file payload", timeline
                )
                meta = summary.payload_transfer
                if meta is None:
                    raise SharingSessionStateError(
                        "File stage received no payload metadata."
                    )
                if meta.packet_type == 3:
                    # PAYLOAD_ACK acknowledges our RESPONSE payload; it carries
                    # no file bytes and must not reset progress.
                    continue
                if meta.packet_type == 2:
                    if meta.control_event in (1, 2):
                        raise SharingSessionError(
                            "Peer cancelled or errored the payload transfer."
                        )
                    continue
                if meta.packet_type != 1:
                    raise SharingSessionStateError(
                        "Unexpected PayloadTransferFrame packet type."
                    )
                if meta.payload_type == 2:
                    if summary.payload_body is None:
                        raise SharingSessionStateError(
                            "FILE chunk had no authenticated body."
                        )
                    receiver.write_chunk(
                        meta.payload_id,
                        total_size=meta.total_size,
                        offset=meta.chunk_offset,
                        body=summary.payload_body,
                        is_last_chunk=meta.is_last_chunk,
                    )
                elif meta.payload_type == 1:
                    if summary.sharing_type == "CANCEL":
                        raise SharingSessionError(
                            "Peer sent sharing CANCEL during transfer."
                        )
                    # The sender's own RESPONSE, PROGRESS_UPDATE, and other
                    # BYTES control frames are not consent and not file content.
                    continue
                else:
                    raise SharingSessionError(
                        f"Unsupported payload type {meta.payload_type} during transfer."
                    )
        except BaseException:
            # Includes send failures and interrupts. No partially received file
            # may survive, and the peer should learn that this side stopped.
            receiver.abort()
            if timeline is not None:
                timeline.state("TRANSFER_FAILED")
            best_effort_disconnect("transfer-failed disconnect")
            raise

        # Every declared payload is complete. Remove any defensive leftovers
        # before telling the peer this side is finished.
        receiver.abort()
        best_effort_disconnect("transfer-complete disconnect")
        if timeline is not None:
            timeline.state("TRANSFER_COMPLETED")
        return ReceiveSessionResult(
            introduction=introduction,
            pin_code=verification.code,
            pin_verified=True,
            consent="accepted",
            files=receiver.finished,
            status="completed",
        )

    keep_alive = _ProactiveKeepAlive(send_offline, keep_alive_interval_seconds)
    keep_alive_holder.append(keep_alive)
    keep_alive.start()
    try:
        return complete_session()
    finally:
        stop_keep_alive()

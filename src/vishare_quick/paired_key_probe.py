"""Read-only, one-shot diagnostic for the authenticated paired-key exchange stage."""
from __future__ import annotations

import socket
from dataclasses import dataclass

from vishare_quick.protocol import FrameTimeout, PeerDisconnected, TruncatedFrame, read_frame
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    ReceiveKeys,
    SecureChannelError,
    authenticate_and_inspect_frame,
)


class PairedKeyProbeError(SecureChannelError):
    """Unexpected authenticated message order or invalid probe transition."""


@dataclass(frozen=True)
class PairedKeyProbeResult:
    offer: AuthenticatedFrameSummary
    followup: AuthenticatedFrameSummary | None
    followup_status: str


class PairedKeyProbeState:
    """Require an authenticated PKE offer, then allow one observed follow-up only."""

    def __init__(self) -> None:
        self.state = "awaiting-paired-key-offer"

    def accept_offer(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-paired-key-offer":
            raise PairedKeyProbeError("Paired-key offer arrived in an invalid probe state.")
        if (summary.sequence != 1 or summary.offline_type != "PAYLOAD_TRANSFER"
                or summary.sharing_type != "PAIRED_KEY_ENCRYPTION"):
            self.state = "failed"
            raise PairedKeyProbeError("Expected authenticated sequence-1 PAIRED_KEY_ENCRYPTION.")
        self.state = "awaiting-one-followup"

    def accept_followup(self, summary: AuthenticatedFrameSummary) -> None:
        if self.state != "awaiting-one-followup":
            raise PairedKeyProbeError("Follow-up arrived in an invalid probe state.")
        if summary.sequence != 2:
            self.state = "failed"
            raise PairedKeyProbeError("Expected authenticated sequence-2 follow-up.")
        self.state = "complete"

    def finish_without_followup(self, status: str) -> None:
        if self.state != "awaiting-one-followup" or status not in ("timeout", "disconnect"):
            raise PairedKeyProbeError("Probe cannot finish in the current state.")
        self.state = "complete"


def run_paired_key_probe(
    reader,
    receive_keys: ReceiveKeys,
    *,
    timeline: ProtocolTimeline | None = None,
) -> PairedKeyProbeResult:
    """Read/authenticate one PKE offer and at most one follow-up; never write to reader."""
    state = PairedKeyProbeState()
    first_frame = read_frame(reader, classify=False)
    try:
        offer = authenticate_and_inspect_frame(first_frame, receive_keys, expected_sequence=1)
    except SecureChannelError as exc:
        if timeline is not None:
            timeline.inbound_secure_failure(
                first_frame.declared_length,
                stage="Android paired-key offer",
                exc=exc,
            )
        raise
    if timeline is not None:
        timeline.inbound_authenticated(offer, stage="Android paired-key offer")
    state.accept_offer(offer)
    if timeline is not None:
        timeline.state("PAIRED_KEY_OFFER_AUTHENTICATED")

    try:
        next_frame = read_frame(reader, classify=False)
    except FrameTimeout:
        state.finish_without_followup("timeout")
        if timeline is not None:
            timeline.state("PROBE_FOLLOWUP_TIMEOUT")
        return PairedKeyProbeResult(offer, None, "timeout")
    except (PeerDisconnected, TruncatedFrame):
        state.finish_without_followup("disconnect")
        if timeline is not None:
            timeline.state("PROBE_FOLLOWUP_DISCONNECT")
        return PairedKeyProbeResult(offer, None, "disconnect")
    except socket.timeout:
        state.finish_without_followup("timeout")
        if timeline is not None:
            timeline.state("PROBE_FOLLOWUP_TIMEOUT")
        return PairedKeyProbeResult(offer, None, "timeout")

    try:
        followup = authenticate_and_inspect_frame(
            next_frame, receive_keys, expected_sequence=2
        )
    except SecureChannelError as exc:
        if timeline is not None:
            timeline.inbound_secure_failure(
                next_frame.declared_length,
                stage="paired-key follow-up",
                exc=exc,
            )
        raise
    if timeline is not None:
        timeline.inbound_authenticated(followup, stage="paired-key follow-up")
    state.accept_followup(followup)
    return PairedKeyProbeResult(offer, followup, "received-without-local-paired-key-response")

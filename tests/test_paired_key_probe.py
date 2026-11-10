"""Synthetic state and framing tests; fixtures are not captured Android traffic."""
from __future__ import annotations

import socket
import unittest
from dataclasses import replace

from vishare_quick.paired_key_probe import (
    PairedKeyProbeError,
    PairedKeyProbeState,
    run_paired_key_probe,
)
from vishare_quick.protocol import FrameTimeout
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import SecureChannelError, authenticate_and_inspect_frame
from test_secure_channel import blob, synthetic_frame, vint


class ScriptedReader:
    def __init__(self, frames, *, timeout_after=False):
        self.buffer = bytearray(b"".join(frame.wire_bytes for frame in frames))
        self.timeout_after = timeout_after

    def recv(self, size):
        if not self.buffer:
            if self.timeout_after:
                raise socket.timeout()
            return b""
        chunk = bytes(self.buffer[:size])
        del self.buffer[:size]
        return chunk


class PairedKeyProbeSyntheticTests(unittest.TestCase):
    def test_valid_synthetic_offer_reports_only_field_metadata(self):
        frame, keys = synthetic_frame()
        summary = authenticate_and_inspect_frame(frame, keys)
        self.assertEqual(summary.sharing_type, "PAIRED_KEY_ENCRYPTION")
        fields = {item.name: (item.present, item.length) for item in summary.paired_key_fields}
        self.assertEqual(fields["signed_data"], (True, 7))
        self.assertEqual(fields["secret_id_hash"], (True, 11))
        self.assertEqual(fields["optional_signed_data"], (False, None))
        self.assertEqual(fields["qr_code_handshake_data"], (False, None))

    def test_malformed_synthetic_duplicate_paired_key_field_is_rejected(self):
        frame, keys = synthetic_frame(paired_key_body_override=blob(1, b"a") + blob(1, b"b"))
        with self.assertRaisesRegex(SecureChannelError, "duplicated"):
            authenticate_and_inspect_frame(frame, keys)

    def test_malformed_synthetic_paired_key_wire_type_is_rejected(self):
        frame, keys = synthetic_frame(paired_key_body_override=vint(1, 7))
        with self.assertRaisesRegex(SecureChannelError, "wire type"):
            authenticate_and_inspect_frame(frame, keys)

    def test_unexpected_first_message_order_is_rejected(self):
        state = PairedKeyProbeState()
        with self.assertRaisesRegex(PairedKeyProbeError, "sequence-1 PAIRED_KEY_ENCRYPTION"):
            state.accept_offer(replace(
                authenticate_and_inspect_frame(*synthetic_frame()), sharing_type="INTRODUCTION"
            ))

    def test_timeout_after_authenticated_offer_is_reported_without_response(self):
        frame, keys = synthetic_frame()
        result = run_paired_key_probe(ScriptedReader([frame], timeout_after=True), keys)
        self.assertEqual(result.followup_status, "timeout")
        self.assertIsNone(result.followup)

    def test_disconnect_after_authenticated_offer_is_reported(self):
        frame, keys = synthetic_frame()
        result = run_paired_key_probe(ScriptedReader([frame]), keys)
        self.assertEqual(result.followup_status, "disconnect")
        self.assertIsNone(result.followup)

    def test_invalid_authentication_stops_probe(self):
        frame, keys = synthetic_frame()
        damaged = frame.payload[:-1] + bytes([frame.payload[-1] ^ 1])
        from vishare_quick.protocol import Frame
        invalid = Frame(damaged, len(damaged), "unknown", "unknown", "unclassified",
                        len(damaged).to_bytes(4, "big") + damaged)
        with self.assertRaises(SecureChannelError):
            run_paired_key_probe(ScriptedReader([invalid]), keys)

    def test_one_followup_is_authenticated_and_later_transitions_are_forbidden(self):
        first, keys = synthetic_frame(sequence=1)
        second, _ = synthetic_frame(sequence=2)
        result = run_paired_key_probe(ScriptedReader([first, second]), keys)
        self.assertEqual(result.followup.sequence, 2)
        self.assertEqual(result.followup_status, "received-without-local-paired-key-response")

        state = PairedKeyProbeState()
        summary = authenticate_and_inspect_frame(first, keys)
        with self.assertRaises(PairedKeyProbeError):
            state.accept_followup(summary)
        state.accept_offer(summary)
        followup = authenticate_and_inspect_frame(second, keys, expected_sequence=2)
        state.accept_followup(followup)
        with self.assertRaises(PairedKeyProbeError):
            state.accept_followup(followup)

    def test_android_zero_length_last_chunk_after_offer_is_accepted(self):
        # Android follows each negotiation BYTES payload with a zero-length
        # LAST_CHUNK frame that omits PayloadChunk.body (field 3).
        offer, keys = synthetic_frame(sequence=1)
        terminator, _ = synthetic_frame(sequence=2, terminator=True)
        result = run_paired_key_probe(ScriptedReader([offer, terminator]), keys)
        self.assertEqual(result.offer.sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertEqual(result.followup.sequence, 2)
        self.assertIsNone(result.followup.sharing_type)
        self.assertEqual(result.followup_status, "received-without-local-paired-key-response")

    def test_offer_and_terminator_with_negative_signed_id_are_accepted(self):
        # PayloadHeader.id is a signed int64; a negative id must not be
        # mistaken for an invalid/oversized header.
        payload_id = -(2**63)
        offer, keys = synthetic_frame(sequence=1, payload_id=payload_id)
        terminator, _ = synthetic_frame(sequence=2, terminator=True, payload_id=payload_id)
        result = run_paired_key_probe(ScriptedReader([offer, terminator]), keys)
        self.assertEqual(result.offer.payload_transfer.payload_id, payload_id)
        self.assertEqual(result.followup.payload_transfer.payload_id, payload_id)
        self.assertEqual(result.followup.sequence, 2)
        self.assertIsNone(result.followup.sharing_type)

    def test_timeline_records_authenticated_offer_and_terminator(self):
        offer, keys = synthetic_frame(sequence=1)
        terminator, _ = synthetic_frame(sequence=2, terminator=True)
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        run_paired_key_probe(
            ScriptedReader([offer, terminator]), keys, timeline=timeline
        )
        rendered = "\n".join(lines)
        self.assertIn("IN    SECURE_MESSAGE seq=1 authenticated=true decrypted=true", rendered)
        self.assertIn("IN    SECURE_MESSAGE seq=2 authenticated=true decrypted=true", rendered)
        self.assertIn("offline=PAYLOAD_TRANSFER", rendered)
        self.assertIn("last_chunk=true", rendered)
        self.assertIn("STATE PAIRED_KEY_OFFER_AUTHENTICATED", rendered)


if __name__ == "__main__":
    unittest.main()

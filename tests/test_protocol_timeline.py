"""Sanitized timeline tests; fixtures are synthetic, not captured Android traffic."""
from __future__ import annotations

import socket
import unittest

from vishare_quick.paired_key_response import (
    PairedKeyMessageError,
    PairedKeyStructureError,
    build_paired_key_encryption_frame,
    build_paired_key_response_messages,
)
from vishare_quick.protocol import (
    FrameTimeout,
    MalformedFrame,
    PeerDisconnected,
    TruncatedFrame,
    UnexpectedMessageType,
    UnrecognizedMessage,
)
from vishare_quick.protocol_timeline import (
    ERROR_CATEGORIES,
    ProtocolTimeline,
    error_category,
    safe_error_detail,
)
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    InvalidPayloadStructure,
    PairedKeyFieldMetadata,
    PayloadTransferMetadata,
    SecureChannelError,
    SecureMessageAuthenticationError,
    SecureMessageDecryptionError,
    UnexpectedSequence,
)
from vishare_quick.ukey2 import HandshakeError


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _summary(sequence=1, offline="PAYLOAD_TRANSFER", sharing="PAIRED_KEY_ENCRYPTION"):
    meta = PayloadTransferMetadata(
        packet_type=1,
        payload_id=7,
        payload_type=1,
        total_size=76,
        chunk_flags=0,
        chunk_offset=0,
        chunk_body_length=76,
        is_last_chunk=False,
        complete_sharing_frame=True,
    )
    fields = (
        PairedKeyFieldMetadata("signed_data", True, 70),
        PairedKeyFieldMetadata("secret_id_hash", True, 6),
        PairedKeyFieldMetadata("optional_signed_data", False, None),
        PairedKeyFieldMetadata("qr_code_handshake_data", False, None),
    )
    return AuthenticatedFrameSummary(sequence, offline, sharing, fields, meta, None)


class ProtocolTimelineFormattingTests(unittest.TestCase):
    def test_elapsed_time_direction_and_fields(self):
        clock = FakeClock()
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=clock)
        timeline.state("START")
        clock.value += 0.25
        timeline.tcp_connected("192.168.43.39:48246")
        self.assertEqual(lines[0], "[+0.000s] STATE START")
        self.assertEqual(
            lines[1],
            "[+0.250s] SOCKET TCP_CONNECTED remote=192.168.43.39:48246",
        )

    def test_bytes_and_long_tokens_are_never_rendered(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        secret = b"do-not-print-this-value"
        token = "A" * 64
        timeline.event("IN", "TEST", secret=secret, token=token)
        rendered = lines[0]
        self.assertIn(f"<{len(secret)} bytes>", rendered)
        self.assertNotIn("do-not-print-this-value", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn(token, rendered)

    def test_printer_failure_never_breaks_protocol(self):
        def broken(_line):
            raise RuntimeError("printer failed")

        timeline = ProtocolTimeline(printer=broken, clock=lambda: 0.0)
        timeline.state("SAFE")  # must not raise

    def test_error_detail_is_bounded_and_token_redacted(self):
        detail = safe_error_detail(RuntimeError("prefix " + "f" * 80 + " suffix"))
        self.assertIn("<redacted>", detail)
        self.assertNotIn("f" * 80, detail)
        self.assertLessEqual(len(detail), 140)


class ProtocolTimelineFrameTests(unittest.TestCase):
    def test_inbound_authenticated_reports_metadata_and_field_presence(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        timeline.inbound_authenticated(_summary(), stage="Android paired-key offer")
        rendered = "\n".join(lines)
        self.assertIn("IN    SECURE_MESSAGE seq=1 authenticated=true decrypted=true", rendered)
        self.assertIn("stage=Android paired-key offer", rendered)
        self.assertIn("offline=PAYLOAD_TRANSFER", rendered)
        self.assertIn("sharing=PAIRED_KEY_ENCRYPTION", rendered)
        self.assertIn("payload_id=7 payload_type=BYTES total_size=76", rendered)
        self.assertIn("offset=0 length=76 last_chunk=false complete=true", rendered)
        self.assertIn("signed_data=present(70B)", rendered)
        self.assertIn("secret_id_hash=present(6B)", rendered)
        self.assertIn("optional_signed_data=absent", rendered)

    def test_keep_alive_frame_is_reported_without_sharing_or_payload(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        summary = AuthenticatedFrameSummary(3, "KEEP_ALIVE", None)
        timeline.inbound_authenticated(summary, stage="peer paired-key result")
        frame_line = [line for line in lines if " FRAME " in f" {line} "][0]
        self.assertIn("offline=KEEP_ALIVE", frame_line)
        self.assertNotIn("sharing=", frame_line)
        self.assertNotIn("payload_id=", frame_line)

    def test_outbound_authenticated_uses_actual_builder_metadata_only(self):
        pke_data, pke_last, result_data, result_last = build_paired_key_response_messages()
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        timeline.outbound_authenticated(1, pke_data)
        timeline.outbound_authenticated(2, pke_last)
        timeline.outbound_authenticated(3, result_data)
        timeline.outbound_authenticated(4, result_last)
        rendered = "\n".join(lines)
        self.assertIn("OUT   SECURE_MESSAGE seq=1 encrypted=true", rendered)
        self.assertIn("OUT   FRAME offline=PAYLOAD_TRANSFER sharing=PAIRED_KEY_ENCRYPTION", rendered)
        pke_size = len(build_paired_key_encryption_frame())
        self.assertIn(
            f"payload_id=1 payload_type=BYTES total_size={pke_size} offset=0 length={pke_size}",
            rendered,
        )
        self.assertIn("signed_data=present(72B)", rendered)
        self.assertIn("secret_id_hash=present(6B)", rendered)
        self.assertIn("optional_signed_data=absent", rendered)
        self.assertIn("sharing=PAIRED_KEY_RESULT", rendered)
        self.assertIn("result_status=UNABLE", rendered)
        self.assertIn("last_chunk=true", rendered)

    def test_inbound_secure_failure_is_labelled_unauthenticated(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        timeline.inbound_secure_failure(123, stage="peer paired-key result")
        self.assertIn("SECURE_MESSAGE bytes=123 authenticated=false decrypted=false", lines[0])
        self.assertIn("stage=peer paired-key result", lines[0])

    def test_secure_failure_labels_never_overstate_or_understate_auth(self):
        cases = [
            (
                SecureMessageAuthenticationError("x"),
                "authenticated=false decrypted=false",
            ),
            (
                SecureMessageDecryptionError("x"),
                "authenticated=true decrypted=false",
            ),
            (UnexpectedSequence("x"), "authenticated=true decrypted=true"),
            (InvalidPayloadStructure("x"), "authenticated=true decrypted=true"),
            (SecureChannelError("x"), "authenticated=true"),
        ]
        for exc, expected in cases:
            with self.subTest(exception=type(exc).__name__):
                lines: list[str] = []
                timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
                timeline.inbound_secure_failure(50, stage="test", exc=exc)
                self.assertIn(expected, lines[0])
                if type(exc) is SecureChannelError:
                    # Generic failures may occur before or after decryption;
                    # the timeline must not guess.
                    self.assertNotIn("decrypted=", lines[0])


class ErrorCategoryTests(unittest.TestCase):
    def test_distinct_categories(self):
        cases = [
            (TruncatedFrame("x"), "truncated-frame"),
            (PeerDisconnected("x"), "peer-disconnected"),
            (FrameTimeout("x"), "read-timeout"),
            (socket.timeout(), "read-timeout"),
            (UnexpectedMessageType("x"), "unexpected-message-type"),
            (UnrecognizedMessage("x"), "unexpected-message-type"),
            (PairedKeyMessageError("x"), "unexpected-message-type"),
            (MalformedFrame("x"), "invalid-protobuf-or-framing"),
            (SecureMessageAuthenticationError("x"), "authentication-failure"),
            (SecureMessageDecryptionError("x"), "decryption-failure"),
            (UnexpectedSequence("x"), "unexpected-sequence"),
            (PairedKeyStructureError("x"), "invalid-payload-structure"),
            (HandshakeError("x"), "handshake-failure"),
            (ValueError("x"), "local-implementation-error"),
            (ConnectionResetError("x"), "socket-reset-or-closed"),
            (RuntimeError("x"), "unclassified-error"),
        ]
        for exc, expected in cases:
            with self.subTest(exception=type(exc).__name__):
                self.assertEqual(error_category(exc), expected)
                self.assertIn(expected, ERROR_CATEGORIES)

    def test_error_event_returns_category_and_includes_stage(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        category = timeline.error(
            PairedKeyMessageError("Expected authenticated sequence-3 PAIRED_KEY_RESULT."),
            stage="paired-key response",
        )
        self.assertEqual(category, "unexpected-message-type")
        self.assertIn("ERROR PROTOCOL_ERROR", lines[0])
        self.assertIn("category=unexpected-message-type", lines[0])
        self.assertIn("stage=paired-key response", lines[0])
        self.assertIn("Expected authenticated sequence-3 PAIRED_KEY_RESULT.", lines[0])

    def test_tcp_closed_is_reported(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        timeline.tcp_closed(reason="peer-disconnected")
        self.assertEqual(lines[0], "[+0.000s] SOCKET SOCKET_CLOSED reason=peer-disconnected")


if __name__ == "__main__":
    unittest.main()

import socket
import unittest
from io import StringIO

from vishare_quick.protocol import (
    ConnectionResponseExchange, FrameTimeout, MalformedFrame, PeerDisconnected,
    PeerRejectedConnection, TruncatedFrame, UnexpectedMessageType,
    UnrecognizedMessage, encode_connection_response_accept,
    inspect_securemessage_envelope, make_frame_hex_dump_callback,
    parse_connection_response, read_frame,
)


def wire_frame(payload):
    return len(payload).to_bytes(4, "big") + payload


def securemessage_outer(header_and_body=b"simulated-header-and-ciphertext", signature=b"simulated-mac"):
    # Simulated schema-derived SecureMessage outer fields; not captured traffic.
    return b"\x0a" + protobuf_varint(len(header_and_body)) + header_and_body + b"\x12" + protobuf_varint(len(signature)) + signature


def protobuf_varint(value):
    encoded = bytearray()
    while value > 0x7f:
        encoded.append((value & 0x7f) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def offline_connection_request():
    # OfflineFrame(version=V1, v1=V1Frame(type=CONNECTION_REQUEST, request={})).
    v1 = b"\x08\x01\x12\x00"
    return b"\x08\x01\x12" + bytes((len(v1),)) + v1


def offline_connection_response(response=1, legacy_status=0):
    # Simulated schema-derived OfflineFrame; response enum 1=ACCEPT, 2=REJECT.
    body = b""
    if legacy_status is not None:
        body += b"\x08" + protobuf_varint(legacy_status)
    if response is not None:
        body += b"\x18" + protobuf_varint(response)
    v1 = b"\x08\x02\x1a" + protobuf_varint(len(body)) + body
    return b"\x08\x01\x12" + protobuf_varint(len(v1)) + v1


def ukey2_client_init(
    version=1, random=b"R" * 32, *, commitments=True, cipher=100,
    commitment=b"C" * 64, next_protocol=b"AES_256_CBC-HMAC_SHA256",
):
    # Simulated schema-derived fixture; not captured Android traffic.
    inner = b"\x08" + bytes((version,))
    if random is not None:
        inner += b"\x12" + bytes((len(random),)) + random
    if commitments:
        nested = b"\x08" + bytes((cipher,))
        nested += b"\x12" + bytes((len(commitment),)) + commitment
        inner += b"\x1a" + bytes((len(nested),)) + nested
    if next_protocol is not None:
        inner += b"\x22" + bytes((len(next_protocol),)) + next_protocol
    return b"\x08\x02\x12" + protobuf_varint(len(inner)) + inner


class ChoppySocket:
    def __init__(self, data, max_chunk=2):
        self.data = bytearray(data)
        self.max_chunk = max_chunk

    def recv(self, size):
        take = min(size, self.max_chunk, len(self.data))
        result = bytes(self.data[:take])
        del self.data[:take]
        return result


class TestProtocol(unittest.TestCase):
    def test_connection_response_encoder_matches_schema_derived_vector(self):
        expected = bytes.fromhex(
            "00000012 0801 120e 0802 1a0a 0800 1801 22020803 2800"
        )
        wire = encode_connection_response_accept(os_type=3)
        self.assertEqual(wire, expected)
        frame = read_frame(ChoppySocket(wire))
        self.assertEqual((frame.family, frame.message_type), ("OfflineFrame v1", "CONNECTION_RESPONSE"))
        self.assertEqual(parse_connection_response(frame.payload), "ACCEPT")

    def test_peer_connection_response_accepts_enum_or_legacy_success(self):
        self.assertEqual(parse_connection_response(offline_connection_response()), "ACCEPT")
        self.assertEqual(
            parse_connection_response(offline_connection_response(response=None)), "ACCEPT"
        )

    def test_peer_connection_response_rejects_rejection_and_invalid_statuses(self):
        with self.assertRaises(PeerRejectedConnection):
            parse_connection_response(offline_connection_response(response=2, legacy_status=None))
        with self.assertRaises(MalformedFrame):
            parse_connection_response(offline_connection_response(response=None, legacy_status=7))
        for invalid in (
            offline_connection_response(response=0, legacy_status=None),
            offline_connection_response(response=3, legacy_status=None),
            offline_connection_response(response=None, legacy_status=None),
            offline_connection_response(response=1, legacy_status=7),
            offline_connection_response(response=2, legacy_status=0),
        ):
            with self.subTest(payload=invalid), self.assertRaises(MalformedFrame):
                parse_connection_response(invalid)

    def test_peer_connection_response_rejects_malformed_or_duplicate_fields(self):
        valid = offline_connection_response()
        with self.assertRaises(MalformedFrame):
            parse_connection_response(valid[:-1])
        duplicated_body = b"\x08\x00\x08\x00\x18\x01"
        v1 = b"\x08\x02\x1a" + protobuf_varint(len(duplicated_body)) + duplicated_body
        duplicate_payload = b"\x08\x01\x12" + protobuf_varint(len(v1)) + v1
        with self.assertRaisesRegex(MalformedFrame, "duplicated"):
            parse_connection_response(duplicate_payload)

    def test_connection_response_exchange_state_and_duplicate_transitions(self):
        exchange = ConnectionResponseExchange()
        with self.assertRaises(MalformedFrame):
            exchange.receive_peer_response(offline_connection_response())
        self.assertEqual(exchange.state, "ready")
        self.assertEqual(len(exchange.send_accept(os_type=3)), 22)
        self.assertEqual(exchange.state, "awaiting-peer-response")
        with self.assertRaisesRegex(MalformedFrame, "already sent"):
            exchange.send_accept(os_type=3)
        self.assertEqual(exchange.receive_peer_response(offline_connection_response()), "ACCEPT")
        self.assertEqual(exchange.state, "complete")
        with self.assertRaisesRegex(MalformedFrame, "duplicate"):
            exchange.receive_peer_response(offline_connection_response())

    def test_connection_response_exchange_records_peer_rejection(self):
        exchange = ConnectionResponseExchange()
        exchange.send_accept(os_type=3)
        with self.assertRaises(PeerRejectedConnection):
            exchange.receive_peer_response(
                offline_connection_response(response=2, legacy_status=None)
            )
        self.assertEqual(exchange.state, "rejected")
        with self.assertRaisesRegex(MalformedFrame, "Unexpected or duplicate"):
            exchange.receive_peer_response(offline_connection_response())

    def test_valid_offline_frame_connection_request(self):
        frame = read_frame(ChoppySocket(wire_frame(offline_connection_request())))
        self.assertEqual(frame.family, "OfflineFrame v1")
        self.assertEqual(frame.message_type, "CONNECTION_REQUEST")

    def test_valid_ukey2_client_init_and_nested_validation(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init())))
        self.assertEqual(frame.family, "UKEY2")
        self.assertEqual(frame.message_type, "CLIENT_INIT")
        self.assertIn("version=supported(1)", frame.validation)
        self.assertIn("random=valid(32 bytes)", frame.validation)
        self.assertIn("cipher_commitments=1", frame.validation)
        self.assertIn("100(P256_SHA512; local-support-unverified)", frame.validation)
        self.assertIn("commitment=64 bytes", frame.validation)
        self.assertIn("matches-documented-reference-value=yes", frame.validation)
        self.assertNotIn("R" * 10, frame.validation)
        self.assertNotIn("C" * 10, frame.validation)
        self.assertNotIn("AES_256_CBC-HMAC_SHA256", frame.validation)

    def test_client_init_invalid_version_and_random_are_reported_without_values(self):
        wrong_version = read_frame(ChoppySocket(wire_frame(ukey2_client_init(version=2))))
        self.assertIn("version=unsupported(2)", wrong_version.validation)
        short_random = read_frame(ChoppySocket(wire_frame(ukey2_client_init(random=b"Q"))))
        self.assertIn("random=invalid-length(1; expected 32)", short_random.validation)
        self.assertNotIn("Q", short_random.validation)

    def test_client_init_missing_random_is_reported(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(random=None))))
        self.assertIn("random=missing-or-malformed", frame.validation)

    def test_client_init_missing_commitment_and_next_protocol_are_reported(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(commitments=False, next_protocol=None))))
        self.assertIn("cipher_commitments=0", frame.validation)
        self.assertIn("cipher commitments missing", frame.validation)
        self.assertIn("next_protocol=missing-or-malformed", frame.validation)

    def test_unsupported_cipher_identifier_is_not_called_supported(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(cipher=101))))
        self.assertIn("101(unsupported-identifier)", frame.validation)
        self.assertNotIn("local-support-unverified", frame.validation)

    def test_unsupported_next_protocol_is_reported_without_raw_value(self):
        protocol = b"unknown-test-protocol"
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(next_protocol=protocol))))
        self.assertIn(f"next_protocol=present({len(protocol)} bytes)", frame.validation)
        self.assertIn("matches-documented-reference-value=no", frame.validation)
        self.assertNotIn(protocol.decode(), frame.validation)

    def test_malformed_next_protocol_utf8_is_reported(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(next_protocol=b"\xff"))))
        self.assertIn("malformed-UTF8(1 bytes)", frame.validation)

    def test_invalid_random_length_and_commitment_length_are_reported(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init(random=b"short", commitment=b"D"))))
        self.assertIn("random=invalid-length(5; expected 32)", frame.validation)
        self.assertIn("commitment=1 bytes", frame.validation)
        self.assertIn("length is not 64 bytes", frame.validation)

    def test_duplicate_singular_fields_and_cipher_entries_are_reported(self):
        base = ukey2_client_init()
        # Duplicate next_protocol (field 4) and append a second commitment with same cipher.
        inner = base[5:]
        duplicate_protocol = b"\x22\x01x"
        # Existing inner is encoded as the outer field 2 body; append within that body.
        inner = inner + duplicate_protocol
        inner = inner + b"\x1a\x44\x08\x64\x12\x40" + b"E" * 64
        payload = b"\x08\x02\x12" + protobuf_varint(len(inner)) + inner
        frame = read_frame(ChoppySocket(wire_frame(payload)))
        self.assertIn("next_protocol duplicated", frame.validation)
        self.assertIn("cipher identifier 100 duplicated", frame.validation)

    def test_ukey2_missing_message_type_or_message_data(self):
        missing_type = read_frame(ChoppySocket(wire_frame(b"\x12\x00")))
        self.assertEqual(missing_type.message_type, "unknown")
        self.assertIn("message_type is missing", missing_type.validation)
        missing_data = read_frame(ChoppySocket(wire_frame(b"\x08\x02")))
        self.assertEqual(missing_data.message_type, "CLIENT_INIT")
        self.assertIn("message_data is missing", missing_data.validation)

    def test_malformed_client_init_data_is_not_dumped_or_misclassified(self):
        malformed = wire_frame(b"\x08\x02\x12\x01\x00")
        frame = read_frame(ChoppySocket(malformed))
        self.assertEqual(frame.message_type, "CLIENT_INIT")
        self.assertIn("ClientInit invalid", frame.validation)

    def test_unsupported_ukey2_enum(self):
        with self.assertRaises(UnexpectedMessageType):
            read_frame(ChoppySocket(wire_frame(b"\x08\x05\x12\x00")))

    def test_malformed_protobuf(self):
        with self.assertRaises(MalformedFrame):
            read_frame(ChoppySocket(wire_frame(b"\x00")))

    def test_ukey2_classification_when_offlineframe_does_not_match(self):
        frame = read_frame(ChoppySocket(wire_frame(ukey2_client_init())))
        self.assertEqual((frame.family, frame.message_type), ("UKEY2", "CLIENT_INIT"))

    def test_unrecognized_message_family(self):
        with self.assertRaises(UnrecognizedMessage):
            read_frame(ChoppySocket(wire_frame(b"\x30\x00")))

    def test_partial_reads_and_multiple_frames(self):
        sock = ChoppySocket(wire_frame(offline_connection_request()) + wire_frame(ukey2_client_init()))
        self.assertEqual(read_frame(sock).message_type, "CONNECTION_REQUEST")
        self.assertEqual(read_frame(sock).message_type, "CLIENT_INIT")
        with self.assertRaises(PeerDisconnected):
            read_frame(sock)

    def test_truncated_header_and_payload(self):
        with self.assertRaises(TruncatedFrame):
            read_frame(ChoppySocket(b"\x00\x00"))
        with self.assertRaises(TruncatedFrame):
            read_frame(ChoppySocket(b"\x00\x00\x00\x05\x08"))

    def test_invalid_and_oversized_lengths(self):
        with self.assertRaises(MalformedFrame):
            read_frame(ChoppySocket(b"\x00\x00\x00\x00"))
        with self.assertRaises(MalformedFrame):
            read_frame(ChoppySocket(b"\x00\x00\x00\x09"), max_frame_length=8)

    def test_timeout(self):
        class TimeoutSocket:
            def recv(self, size):
                raise socket.timeout()
        with self.assertRaises(FrameTimeout):
            read_frame(TimeoutSocket())

    def test_unclassified_bounded_frame_retains_exact_wire_without_rendering_bytes(self):
        wire = wire_frame(securemessage_outer())
        frame = read_frame(ChoppySocket(wire), classify=False)
        self.assertEqual(frame.wire_bytes, wire)
        self.assertEqual(frame.payload, wire[4:])
        self.assertNotIn("simulated-mac", repr(frame))

    def test_simulated_securemessage_outer_fields_are_retained_but_unauthenticated(self):
        wire = wire_frame(securemessage_outer())
        frame = read_frame(ChoppySocket(wire), classify=False)
        envelope = inspect_securemessage_envelope(frame)
        self.assertEqual(envelope.wire_bytes, wire)
        self.assertEqual(envelope.header_and_body, b"simulated-header-and-ciphertext")
        self.assertEqual(envelope.signature, b"simulated-mac")
        self.assertNotIn("simulated", repr(envelope))

    def test_simulated_tampering_and_invalid_padding_or_sequence_are_not_interpreted(self):
        # The inspector deliberately does not inspect header/body bytes before a verified MAC.
        opaque = b"\xffinvalid-inner-protobuf-padding-sequence=999"
        for signature in (b"original-mac", b"tampered-mac"):
            with self.subTest(signature=signature):
                frame = read_frame(
                    ChoppySocket(wire_frame(securemessage_outer(opaque, signature))), classify=False
                )
                envelope = inspect_securemessage_envelope(frame)
                self.assertEqual(envelope.header_and_body, opaque)
                self.assertEqual(envelope.signature, signature)
                self.assertNotIn("authenticated", repr(envelope))

    def test_malformed_simulated_securemessage_outer_protobuf_is_rejected(self):
        for payload in (
            b"\x0a\x02x",  # truncated field
            b"\x0a\x01x\x0a\x01y\x12\x01z",  # duplicate header_and_body
            b"\x0a\x01x",  # missing signature
            b"\x08\x01\x12\x01z",  # wrong wire type for required field 1
        ):
            with self.subTest(payload=payload):
                frame = read_frame(ChoppySocket(wire_frame(payload)), classify=False)
                with self.assertRaises(MalformedFrame):
                    inspect_securemessage_envelope(frame)

    def test_unclassified_frame_still_reports_timeout_and_disconnect(self):
        class TimeoutSocket:
            def recv(self, size):
                raise socket.timeout()

        with self.assertRaises(FrameTimeout):
            read_frame(TimeoutSocket(), classify=False)
        with self.assertRaises(PeerDisconnected):
            read_frame(ChoppySocket(b""), classify=False)

    def test_hex_dump_selects_second_frame_only_and_includes_prefix(self):
        output = StringIO()
        callback = make_frame_hex_dump_callback(2, output.write)
        sock = ChoppySocket(wire_frame(offline_connection_request()) + wire_frame(ukey2_client_init()))
        read_frame(sock, on_wire_frame=callback)
        read_frame(sock, on_wire_frame=callback)
        rendered = output.getvalue()
        self.assertIn("Frame #2 wire hex", rendered)
        self.assertIn("includes 4-byte big-endian length prefix", rendered)
        self.assertNotIn("Frame #1", rendered)
        self.assertIn("showing at most 96 bytes", rendered)
        self.assertIn("truncated;", rendered)


if __name__ == "__main__":
    unittest.main()

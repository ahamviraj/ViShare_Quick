"""Round-trip tests for the outbound sender encoders.

Every encoder in :mod:`vishare_quick.sender_protocol` is checked against the
receiver-side parsers already shipped in this project (``protocol``,
``secure_channel``, ``introduction``, ``sharing_response``). A passing test
therefore proves our own encoder and our own decoder agree; it is not an
Android interoperability vector.
"""
from __future__ import annotations

import unittest

from vishare_quick.introduction import parse_introduction
from vishare_quick.protocol import (
    decode_payload,
    encode_connection_response_accept,
    parse_connection_response,
)
from vishare_quick.secure_channel import (
    _parse_offline_frame,
    parse_sharing_frame_envelope,
)
from vishare_quick.sender_protocol import (
    FILE_TYPE_DOCUMENT,
    FILE_TYPE_IMAGE,
    PAYLOAD_TYPE_BYTES,
    PAYLOAD_TYPE_FILE,
    RESPONSE_ACCEPT,
    IntroductionFile,
    encode_connection_request,
    encode_disconnection,
    encode_introduction,
    encode_keep_alive,
    encode_paired_key_encryption,
    encode_paired_key_result,
    encode_payload_chunk,
    encode_sharing_payload,
    frame_payload,
)


def fields(data: bytes) -> dict[int, list[tuple[int, object]]]:
    from vishare_quick.protocol import _field_occurrences

    out: dict[int, list[tuple[int, object]]] = {}
    for number, item in _field_occurrences(data):
        out.setdefault(number, []).append((item.wire, item.value))
    return out


class ConnectionRequestTests(unittest.TestCase):
    def test_request_round_trips_through_the_receiver_classifier(self):
        endpoint_info = b"\x26" + b"\x11" * 16 + bytes([6]) + b"Laptop"
        wire = encode_connection_request("AB12", "My Laptop", endpoint_info)

        frame = decode_payload(wire)
        self.assertEqual(frame.family, "OfflineFrame v1")
        self.assertEqual(frame.message_type, "CONNECTION_REQUEST")

        body = fields(wire)  # outer OfflineFrame fields
        self.assertEqual(body[1][0][1], 1)
        parsed = _parse_offline_frame(wire)
        self.assertEqual(parsed.offline_type, "CONNECTION_REQUEST")

    def test_request_fields_match_the_schema(self):
        endpoint_info = b"\x26" + b"\x22" * 16 + bytes([4]) + b"Host"
        body = encode_connection_request("Z9Y8", "Host", endpoint_info)
        # Strip OfflineFrame{version, v1} -> V1Frame{type, request}
        outer = fields(body)
        v1 = outer[2][0][1]
        assert isinstance(v1, bytes)
        inner = fields(v1)
        self.assertEqual(inner[1][0][1], 1)
        request = inner[2][0][1]
        assert isinstance(request, bytes)
        request_fields = fields(request)
        self.assertEqual(request_fields[1][0][1], b"Z9Y8")
        self.assertEqual(request_fields[2][0][1], b"Host")
        self.assertEqual(request_fields[5][0][1], 5)
        self.assertEqual(request_fields[6][0][1], endpoint_info)

    def test_request_rejects_bad_endpoint_id_and_name(self):
        with self.assertRaises(ValueError):
            encode_connection_request("", "Host", b"\x26")
        with self.assertRaises(ValueError):
            encode_connection_request("ABCDE", "Host", b"\x26")
        with self.assertRaises(ValueError):
            encode_connection_request("AB12", "", b"\x26")
        with self.assertRaises(ValueError):
            encode_connection_request("AB12", "Host", b"")


class KeepAliveAndDisconnectionTests(unittest.TestCase):
    def test_keep_alive_types(self):
        ping = decode_payload(encode_keep_alive(ack=False))
        self.assertEqual(ping.message_type, "KEEP_ALIVE")
        self.assertIs(_parse_offline_frame(encode_keep_alive(ack=False)).keep_alive_ack, False)
        ack = _parse_offline_frame(encode_keep_alive(ack=True))
        self.assertIs(ack.keep_alive_ack, True)

    def test_disconnection_has_the_empty_documented_body(self):
        wire = encode_disconnection()
        self.assertEqual(decode_payload(wire).message_type, "DISCONNECTION")
        self.assertEqual(_parse_offline_frame(wire).offline_type, "DISCONNECTION")


class PayloadChunkTests(unittest.TestCase):
    def test_file_chunk_round_trips(self):
        wire = encode_payload_chunk(
            42,
            PAYLOAD_TYPE_FILE,
            10,
            4,
            b"abcdef",
            last_chunk=False,
            file_name="report.txt",
        )
        metadata = _parse_offline_frame(wire).payload_transfer
        assert metadata is not None
        self.assertEqual(metadata.payload_id, 42)
        self.assertEqual(metadata.payload_type, 2)
        self.assertEqual(metadata.total_size, 10)
        self.assertEqual(metadata.chunk_offset, 4)
        self.assertEqual(metadata.chunk_body_length, 6)
        self.assertFalse(metadata.is_last_chunk)
        self.assertEqual(metadata.packet_type, 1)

    def test_last_chunk_is_empty_and_at_the_end(self):
        wire = encode_payload_chunk(
            42,
            PAYLOAD_TYPE_FILE,
            10,
            10,
            b"",
            last_chunk=True,
            file_name="report.txt",
        )
        metadata = _parse_offline_frame(wire).payload_transfer
        assert metadata is not None
        self.assertTrue(metadata.is_last_chunk)
        self.assertEqual(metadata.chunk_offset, 10)
        self.assertEqual(metadata.chunk_body_length, 0)

    def test_bytes_payload_carries_no_name(self):
        from vishare_quick.sender_protocol import SHARING_CANCEL, encode_sharing_frame

        control = encode_sharing_frame(SHARING_CANCEL)
        wire = encode_payload_chunk(
            7, PAYLOAD_TYPE_BYTES, len(control), 0, control, last_chunk=False
        )
        metadata = _parse_offline_frame(wire).payload_transfer
        assert metadata is not None
        self.assertEqual(metadata.payload_type, 1)

    def test_encoder_rejects_oversized_or_named_bytes_chunks(self):
        with self.assertRaises(ValueError):
            encode_payload_chunk(1, PAYLOAD_TYPE_FILE, 3, 0, b"abcd", last_chunk=False)
        with self.assertRaises(ValueError):
            encode_payload_chunk(
                1, PAYLOAD_TYPE_BYTES, 3, 0, b"abc", last_chunk=True, file_name="x"
            )
        with self.assertRaises(ValueError):
            encode_payload_chunk(
                1, PAYLOAD_TYPE_FILE, 3, 0, b"abc", last_chunk=True, file_name="a/b"
            )


class SharingFrameTests(unittest.TestCase):
    def test_sharing_payload_is_a_data_chunk_then_last_chunk(self):
        from vishare_quick.sender_protocol import SHARING_CANCEL, encode_sharing_frame

        control = encode_sharing_frame(SHARING_CANCEL)
        first, last = encode_sharing_payload(11, control)
        first_meta = _parse_offline_frame(first).payload_transfer
        last_meta = _parse_offline_frame(last).payload_transfer
        assert first_meta is not None and last_meta is not None
        self.assertEqual(first_meta.payload_id, 11)
        self.assertEqual(first_meta.payload_type, PAYLOAD_TYPE_BYTES)
        self.assertEqual(first_meta.chunk_offset, 0)
        self.assertEqual(first_meta.chunk_body_length, len(control))
        self.assertFalse(first_meta.is_last_chunk)
        self.assertEqual(last_meta.payload_id, 11)
        self.assertEqual(last_meta.chunk_offset, len(control))
        self.assertTrue(last_meta.is_last_chunk)

    def test_paired_key_encryption_round_trips(self):
        frame = encode_paired_key_encryption(b"\x01" * 72, b"\x02" * 6)
        name, body = parse_sharing_frame_envelope(frame)
        self.assertEqual(name, "PAIRED_KEY_ENCRYPTION")
        parsed = fields(body)
        self.assertEqual(parsed[1][0][1], b"\x01" * 72)
        self.assertEqual(parsed[2][0][1], b"\x02" * 6)

    def test_paired_key_result_is_unable(self):
        name, body = parse_sharing_frame_envelope(encode_paired_key_result())
        self.assertEqual(name, "PAIRED_KEY_RESULT")
        self.assertEqual(fields(body)[1][0][1], 3)

    def test_introduction_round_trips_through_the_receiver_parser(self):
        files = [
            IntroductionFile("photo.jpg", 10, 1024, "image/jpeg", FILE_TYPE_IMAGE),
            IntroductionFile("notes.txt", 11, 0, "text/plain", FILE_TYPE_DOCUMENT),
        ]
        parsed = parse_introduction(encode_introduction(files))
        self.assertEqual([item.name for item in parsed.files], ["photo.jpg", "notes.txt"])
        self.assertEqual([item.payload_id for item in parsed.files], [10, 11])
        self.assertEqual([item.size for item in parsed.files], [1024, 0])
        self.assertEqual([item.file_type for item in parsed.files], [1, 5])

    def test_introduction_rejects_non_basename_and_empty(self):
        with self.assertRaises(ValueError):
            encode_introduction([])
        with self.assertRaises(ValueError):
            encode_introduction(
                [IntroductionFile("a/b", 1, 1, "text/plain", FILE_TYPE_DOCUMENT)]
            )


class ConnectionResponseTests(unittest.TestCase):
    def test_our_accept_is_accepted_by_our_parser(self):
        framed = encode_connection_response_accept()
        self.assertEqual(parse_connection_response(framed[4:]), "ACCEPT")
        self.assertEqual(RESPONSE_ACCEPT, 1)


class FramingTests(unittest.TestCase):
    def test_frame_payload_adds_the_big_endian_length_prefix(self):
        payload = encode_keep_alive(ack=False)
        framed = frame_payload(payload)
        self.assertEqual(int.from_bytes(framed[:4], "big"), len(payload))
        self.assertEqual(framed[4:], payload)
        with self.assertRaises(ValueError):
            frame_payload(b"")

    def test_connection_request_is_unframed_payload(self):
        request = encode_connection_request("AB12", "Host", b"\x26" + b"\x00" * 17)
        # The first field must be OfflineFrame.version, not a length prefix.
        self.assertEqual(request[:2], b"\x08\x01")
        framed = frame_payload(request)
        self.assertEqual(int.from_bytes(framed[:4], "big"), len(request))


class SendFilePreparationTests(unittest.TestCase):
    def test_regular_files_are_prepared_with_basename_only(self):
        import tempfile
        from pathlib import Path

        from vishare_quick.sender import file_type_for_mime, prepare_files

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "note.txt"
            path.write_bytes(b"hello")
            prepared = prepare_files([path])
            self.assertEqual(len(prepared), 1)
            self.assertEqual(prepared[0].name, "note.txt")
            self.assertEqual(prepared[0].size, 5)
            self.assertEqual(prepared[0].file_type, FILE_TYPE_DOCUMENT)
            self.assertGreater(prepared[0].payload_id, 0)
            self.assertNotIn(directory, prepared[0].name)

        self.assertEqual(file_type_for_mime("image/png"), FILE_TYPE_IMAGE)
        self.assertEqual(file_type_for_mime("video/mp4"), 2)
        self.assertEqual(file_type_for_mime("audio/mpeg"), 4)
        self.assertEqual(file_type_for_mime("text/plain"), FILE_TYPE_DOCUMENT)
        self.assertEqual(file_type_for_mime("application/octet-stream"), 0)

    def test_directories_and_missing_paths_are_rejected(self):
        import tempfile
        from pathlib import Path

        from vishare_quick.sender import SenderFileError, prepare_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(SenderFileError):
                prepare_files([root])
            with self.assertRaises(SenderFileError):
                prepare_files([root / "absent.bin"])
        with self.assertRaises(SenderFileError):
            prepare_files([])

    def test_symlinks_are_rejected_when_the_platform_allows_creating_one(self):
        import os
        import tempfile
        from pathlib import Path

        from vishare_quick.sender import SenderFileError, prepare_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.txt"
            target.write_bytes(b"x")
            link = root / "link.txt"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("this environment cannot create symlinks")
            with self.assertRaises(SenderFileError):
                prepare_files([link])

    def test_missing_extension_falls_back_to_octet_stream(self):
        import tempfile
        from pathlib import Path

        from vishare_quick.sender import prepare_files

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blob"
            path.write_bytes(b"data")
            prepared = prepare_files([path])
            self.assertEqual(prepared[0].mime_type, "application/octet-stream")
            self.assertEqual(prepared[0].file_type, 0)

    def test_empty_files_are_rejected_before_connecting(self):
        import tempfile
        from pathlib import Path

        from vishare_quick.sender import SenderFileError, prepare_files

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_bytes(b"")
            with self.assertRaises(SenderFileError) as caught:
                prepare_files([path])
            self.assertIn("empty", str(caught.exception))
            self.assertIn("empty.txt", str(caught.exception))


class Ukey2AlertTests(unittest.TestCase):
    def test_known_alerts_are_described_without_logging_raw_material(self):
        from vishare_quick.protocol import _encode_bytes_field, _encode_varint_field
        from vishare_quick.sender import decode_ukey2_alert

        def alert(kind: int, message: str) -> bytes:
            return _encode_varint_field(1, kind) + _encode_bytes_field(
                2, message.encode()
            )

        self.assertEqual(
            decode_ukey2_alert(alert(100, "ClientInit version mismatch.")),
            "bad version (100): ClientInit version mismatch.",
        )
        self.assertEqual(
            decode_ukey2_alert(alert(103, "Incorrect next protocol")),
            "bad next protocol (103): Incorrect next protocol",
        )
        self.assertIsNone(decode_ukey2_alert(b"\xde\xad\xbe\xef"))
        self.assertIsNone(decode_ukey2_alert(b""))

    def test_a_real_server_init_is_not_mistaken_for_an_alert(self):
        from vishare_quick.sender import decode_ukey2_alert
        from vishare_quick.ukey2 import Ukey2ClientHandshake, Ukey2ServerHandshake

        client = Ukey2ClientHandshake()
        server = Ukey2ServerHandshake()
        server_init = server.respond_to_client_init(client.create_client_init()[4:])
        self.assertIsNone(decode_ukey2_alert(server_init[4:]))


if __name__ == "__main__":
    unittest.main()

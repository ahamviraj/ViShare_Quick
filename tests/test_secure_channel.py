"""Synthetic schema-derived SecureMessage tests; not Android traffic vectors."""
from __future__ import annotations

import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vishare_quick.protocol import DEFAULT_MAX_FRAME_LENGTH, Frame
from vishare_quick.secure_channel import (
    SecureChannelError,
    SecureMessageAuthenticationError,
    SecureMessageDecryptionError,
    UnexpectedSequence,
    _parse_offline_frame,
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
)


def varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def vint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


_MAX_UINT64 = (1 << 64) - 1


def signed_varint(value: int) -> bytes:
    """Encode a negative int64 using protobuf's ten-byte two's-complement form."""
    return varint(value & _MAX_UINT64)


def vint_signed(number: int, value: int) -> bytes:
    return varint(number << 3) + signed_varint(value)


def blob(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def synthetic_frame(*, sequence=1, metadata_type=13, version=1,
                    plaintext_override=None, signature_scheme=1,
                    encryption_scheme=2, malformed_inner=False,
                    invalid_padding=False, paired_key_body_override=None,
                    terminator=False, payload_id=7) -> tuple[Frame, object]:
    """Build one deterministic, synthetic test packet from documented schemas."""
    keys = derive_client_to_server_receive_keys(b"synthetic next secret 1234567890")
    iv = bytes(range(16))

    # Sharing Frame v1 PAIRED_KEY_ENCRYPTION body (type=3, body field=4).
    sharing_body = (blob(1, b"fixture") + blob(2, b"secret-hash")
                    if paired_key_body_override is None else paired_key_body_override)
    sharing_v1 = vint(1, 3) + blob(4, sharing_body)
    sharing = vint(1, 1) + blob(2, sharing_v1)
    if malformed_inner:
        sharing = b"\x00"
    # Nearby OfflineFrame v1 PAYLOAD_TRANSFER / DATA / BYTES payload.
    # PayloadHeader.id is a signed int64; negative values use two's complement.
    encoded_id = vint(1, payload_id) if payload_id >= 0 else vint_signed(1, payload_id)
    payload_header = encoded_id + vint(2, 1) + vint(3, len(sharing))
    # Google schema: PayloadChunk.offset=2 and body=3 (flags=1 omitted).
    # Android also sends a zero-length LAST_CHUNK terminator with body omitted.
    if terminator:
        payload_chunk = vint(1, 1) + vint(2, len(sharing))
    else:
        payload_chunk = vint(2, 0) + blob(3, sharing)
    transfer = vint(1, 1) + blob(2, payload_header) + blob(3, payload_chunk)
    offline_v1 = vint(1, 3) + blob(4, transfer)
    offline = vint(1, 1) + blob(2, offline_v1)
    plaintext = plaintext_override or (blob(1, offline) + vint(2, sequence))

    if invalid_padding:
        padded = b"\x00" * 16
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(keys.encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    metadata = vint(1, metadata_type)
    if version is not None:
        metadata += vint(2, version)
    header = (vint(1, signature_scheme) + vint(2, encryption_scheme)
              + blob(5, iv) + blob(6, metadata))
    header_and_body = blob(1, header) + blob(2, ciphertext)
    signature = hmac.new(keys.hmac_key, header_and_body, hashlib.sha256).digest()
    payload = blob(1, header_and_body) + blob(2, signature)
    wire = len(payload).to_bytes(4, "big") + payload
    return Frame(payload, len(payload), "unknown", "unknown", "unclassified", wire), keys


def _offline_frame_with_explicit_schema_chunk(chunk: bytes) -> bytes:
    """Wrap a literal schema-numbered PayloadChunk in an OfflineFrame.

    The chunk fixtures below are hand-encoded from Google's published
    offline_wire_formats.proto and do not use synthetic_frame's chunk builder.
    """
    # PayloadHeader: id=1, type=2 (BYTES), total_size=3.
    header = bytes.fromhex("08 07 10 01 18 0a")
    transfer = bytes.fromhex("08 01") + blob(2, header) + blob(3, chunk)
    offline_v1 = bytes.fromhex("08 03") + blob(4, transfer)
    return bytes.fromhex("08 01") + blob(2, offline_v1)


def _offline_bytes_frame(sharing: bytes, *, payload_id: int = 7) -> bytes:
    """Wrap a sharing Frame in a BYTES DATA PayloadTransferFrame."""
    header = vint(1, payload_id) + vint(2, 1) + vint(3, len(sharing))
    chunk = vint(2, 0) + blob(3, sharing)
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))


class SharingEnvelopeFieldNumberTests(unittest.TestCase):
    """Field numbers from Google's published ``sharing.proto``.

    The V1Frame body field is not uniformly ``type + 1``: ``progress_update``
    is field 7 while its type is also 7, and CANCEL has no body field. An
    Android XPad sender emits exactly the progress_update form right after the
    receiver's ACCEPT, so a wrong mapping stalls the transfer.
    """

    def test_progress_update_body_is_field_seven(self):
        sharing = vint(1, 1) + blob(2, vint(1, 7) + blob(7, vint(2, 1)))
        result = _parse_offline_frame(_offline_bytes_frame(sharing))
        self.assertEqual(result.offline_type, "PAYLOAD_TRANSFER")
        self.assertEqual(result.sharing_type, "PROGRESS_UPDATE")

    def test_progress_update_body_in_field_eight_is_rejected(self):
        sharing = vint(1, 1) + blob(2, vint(1, 7) + blob(8, vint(2, 1)))
        with self.assertRaisesRegex(SecureChannelError, "sharing Frame body"):
            _parse_offline_frame(_offline_bytes_frame(sharing))

    def test_cancel_type_alone_is_recognized(self):
        sharing = vint(1, 1) + blob(2, vint(1, 6))
        result = _parse_offline_frame(_offline_bytes_frame(sharing))
        self.assertEqual(result.sharing_type, "CANCEL")

    def test_cancel_with_a_body_field_is_rejected(self):
        sharing = vint(1, 1) + blob(2, vint(1, 6) + blob(7, b""))
        with self.assertRaisesRegex(SecureChannelError, "CANCEL"):
            _parse_offline_frame(_offline_bytes_frame(sharing))

    def test_bindings_body_is_field_eight(self):
        sharing = vint(1, 1) + blob(2, vint(1, 8) + blob(8, vint(1, 1)))
        result = _parse_offline_frame(_offline_bytes_frame(sharing))
        self.assertEqual(result.sharing_type, "BINDINGS")


class SecureChannelSyntheticTests(unittest.TestCase):
    def test_schema_numbered_bytes_payload_chunk_is_recognized(self):
        # PayloadChunk: offset=2 (0), body=3 (10-byte sharing Frame).
        # 0x10 is field 2 / varint; 0x1a is field 3 / length-delimited.
        sharing = bytes.fromhex("08 01 12 06 08 03 22 02 0a 00")
        chunk = bytes.fromhex("10 00 1a 0a") + sharing
        offline = _offline_frame_with_explicit_schema_chunk(chunk)

        result = _parse_offline_frame(offline)
        self.assertEqual(
            (result.offline_type, result.sharing_type),
            ("PAYLOAD_TRANSFER", "PAIRED_KEY_ENCRYPTION"),
        )
        self.assertIsNotNone(result.payload_transfer)
        self.assertTrue(result.payload_transfer.complete_sharing_frame)

    def test_schema_numbered_bytes_payload_chunk_without_body_is_incomplete(self):
        # Body is optional on the wire. An absent body is a zero-length chunk;
        # without the complete declared size it must not be decoded as a
        # sharing Frame, but it is not a protobuf-shape error.
        result = _parse_offline_frame(_offline_frame_with_explicit_schema_chunk(b"\x10\x00"))
        self.assertEqual(
            (result.offline_type, result.sharing_type, result.paired_key_fields),
            ("PAYLOAD_TRANSFER", None, ()),
        )
        self.assertFalse(result.payload_transfer.complete_sharing_frame)

    def test_schema_numbered_zero_length_last_chunk_without_body_is_accepted(self):
        # Documented Android negotiation behavior ends with flags=LAST_CHUNK,
        # offset=total_size, and no body field.
        chunk = vint(1, 1) + vint(2, 10)
        result = _parse_offline_frame(_offline_frame_with_explicit_schema_chunk(chunk))
        self.assertEqual(
            (result.offline_type, result.sharing_type, result.paired_key_fields),
            ("PAYLOAD_TRANSFER", None, ()),
        )
        self.assertTrue(result.payload_transfer.is_last_chunk)
        self.assertEqual(result.payload_transfer.chunk_body_length, 0)

    def test_schema_numbered_bytes_payload_chunk_rejects_duplicate_body(self):
        sharing = bytes.fromhex("08 01 12 06 08 03 22 02 0a 00")
        body = bytes.fromhex("1a 0a") + sharing
        chunk = bytes.fromhex("10 00") + body + body
        with self.assertRaisesRegex(SecureChannelError, r"body \(field 3\) must be present exactly once"):
            _parse_offline_frame(_offline_frame_with_explicit_schema_chunk(chunk))

    def test_schema_numbered_bytes_payload_chunk_rejects_wrong_body_wire_type(self):
        # Field 3 encoded as a varint instead of the schema's bytes field.
        with self.assertRaisesRegex(SecureChannelError, "wrong protobuf wire type"):
            _parse_offline_frame(_offline_frame_with_explicit_schema_chunk(b"\x18\x01"))

    def test_valid_synthetic_securemessage_authenticates_and_classifies(self):
        frame, keys = synthetic_frame()
        result = authenticate_and_inspect_frame(frame, keys)
        self.assertEqual(result.sequence, 1)
        self.assertEqual(result.offline_type, "PAYLOAD_TRANSFER")
        self.assertEqual(result.sharing_type, "PAIRED_KEY_ENCRYPTION")

    def test_synthetic_bad_mac_is_rejected_before_decryption(self):
        frame, keys = synthetic_frame()
        tampered = frame.payload[:-1] + bytes([frame.payload[-1] ^ 1])
        wire = len(tampered).to_bytes(4, "big") + tampered
        candidate = Frame(tampered, len(tampered), "unknown", "unknown", "unclassified", wire)
        with self.assertRaises(SecureMessageAuthenticationError):
            authenticate_and_inspect_frame(candidate, keys)

    def test_synthetic_authenticated_invalid_padding_is_rejected(self):
        frame, keys = synthetic_frame(invalid_padding=True)
        with self.assertRaises(SecureMessageDecryptionError):
            authenticate_and_inspect_frame(frame, keys)

    def test_synthetic_unsupported_metadata_is_rejected(self):
        frame, keys = synthetic_frame(metadata_type=12)
        with self.assertRaisesRegex(SecureChannelError, "metadata"):
            authenticate_and_inspect_frame(frame, keys)

    def test_synthetic_missing_metadata_version_is_rejected(self):
        frame, keys = synthetic_frame(version=None)
        with self.assertRaisesRegex(SecureChannelError, "version"):
            authenticate_and_inspect_frame(frame, keys)

    def test_synthetic_wrong_sequence_is_rejected(self):
        frame, keys = synthetic_frame(sequence=2)
        with self.assertRaises(UnexpectedSequence):
            authenticate_and_inspect_frame(frame, keys)

    def test_synthetic_malformed_authenticated_inner_protobuf_is_rejected(self):
        frame, keys = synthetic_frame(malformed_inner=True)
        with self.assertRaises(SecureChannelError):
            authenticate_and_inspect_frame(frame, keys)

    def test_synthetic_unsupported_algorithms_are_rejected(self):
        frame, keys = synthetic_frame(signature_scheme=99)
        with self.assertRaisesRegex(SecureChannelError, "algorithm"):
            authenticate_and_inspect_frame(frame, keys)


def _offline_frame_with_explicit_header(header: bytes, chunk: bytes) -> bytes:
    """Wrap literal schema-numbered PayloadHeader/PayloadChunk bytes.

    Hand-encoded from Google's published offline_wire_formats.proto:
    PayloadTransferFrame.packet_type=1, payload_header=2, payload_chunk=3;
    OfflineFrame.version=1, v1=2; V1Frame.type=1, payload_transfer=4.
    """
    transfer = bytes.fromhex("08 01") + blob(2, header) + blob(3, chunk)
    offline_v1 = bytes.fromhex("08 03") + blob(4, transfer)
    return bytes.fromhex("08 01") + blob(2, offline_v1)


_SHARING_PKE = bytes.fromhex("08 01 12 06 08 03 22 02 0a 00")


def _header(payload_id=7, payload_type=1, total_size=10, *, omit=(), extra=b""):
    """Hand-encode PayloadHeader: id=1 int64, type=2 enum, total_size=3 int64."""
    parts = []
    if 1 not in omit:
        parts.append(
            vint_signed(1, payload_id) if payload_id < 0 else vint(1, payload_id)
        )
    if 2 not in omit:
        parts.append(vint(2, payload_type))
    if 3 not in omit:
        parts.append(
            vint_signed(3, total_size) if total_size < 0 else vint(3, total_size)
        )
    return b"".join(parts) + extra


def _data_chunk(body=_SHARING_PKE, offset=0, flags=None, index=None, omit_body=False):
    """Hand-encode PayloadChunk: flags=1 int32, offset=2 int64, body=3, index=4."""
    parts = []
    if flags is not None:
        parts.append(vint_signed(1, flags) if flags < 0 else vint(1, flags))
    if offset is not None:
        parts.append(vint_signed(2, offset) if offset < 0 else vint(2, offset))
    if not omit_body:
        parts.append(blob(3, body))
    if index is not None:
        parts.append(vint_signed(4, index) if index < 0 else vint(4, index))
    return b"".join(parts)


class PayloadHeaderSchemaTests(unittest.TestCase):
    """Hand-encoded PayloadHeader/PayloadChunk fixtures from the published schema."""

    def _parse(self, header, chunk):
        return _parse_offline_frame(_offline_frame_with_explicit_header(header, chunk))

    def test_valid_bytes_header_with_max_positive_int64_id(self):
        result = self._parse(_header(2**63 - 1), _data_chunk())
        self.assertEqual(result.sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertEqual(result.payload_transfer.payload_id, 2**63 - 1)

    def test_valid_bytes_header_with_min_negative_int64_id(self):
        result = self._parse(_header(-(2**63)), _data_chunk())
        self.assertEqual(result.sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertEqual(result.payload_transfer.payload_id, -(2**63))

    def test_valid_bytes_header_with_negative_one_id(self):
        # A negative id is a valid signed int64 and may appear on the wire.
        result = self._parse(_header(-1), _data_chunk())
        self.assertEqual(result.payload_transfer.payload_id, -1)
        self.assertEqual(result.sharing_type, "PAIRED_KEY_ENCRYPTION")

    def test_missing_total_size_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "total_size must be present exactly once"):
            self._parse(_header(omit={3}), _data_chunk())

    def test_missing_id_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "id must be present exactly once"):
            self._parse(_header(omit={1}), _data_chunk())

    def test_duplicate_id_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "id must be present exactly once"):
            self._parse(_header(extra=vint(1, 8)), _data_chunk())

    def test_wrong_wire_type_id_is_rejected(self):
        header = blob(1, b"x") + vint(2, 1) + vint(3, 10)
        with self.assertRaisesRegex(SecureChannelError, "wrong protobuf wire type"):
            self._parse(header, _data_chunk())

    def test_unsupported_payload_type_enum_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "unsupported type enum 4"):
            self._parse(_header(payload_type=4), _data_chunk())

    def test_negative_total_size_for_bytes_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "total_size -1 is negative"):
            self._parse(_header(total_size=-1), _data_chunk())

    def test_oversized_64_bit_varint_is_rejected(self):
        # Ten varint bytes whose value exceeds 2**64-1 is not a valid int64.
        header = b"\x08" + b"\xff" * 9 + b"\x7f" + vint(2, 1) + vint(3, 10)
        with self.assertRaisesRegex(SecureChannelError, "not a valid 64-bit protobuf varint"):
            self._parse(header, _data_chunk())

    def test_indeterminate_stream_size_is_accepted_as_metadata(self):
        # Google's transport uses -1 only for an indeterminate STREAM size.
        result = self._parse(_header(payload_type=3, total_size=-1), _data_chunk())
        self.assertIsNone(result.sharing_type)
        self.assertEqual(result.payload_transfer.payload_type, 3)
        self.assertEqual(result.payload_transfer.total_size, -1)
        self.assertFalse(result.payload_transfer.complete_sharing_frame)

    def test_declared_size_above_frame_cap_is_not_a_frame_size_error(self):
        # total_size is a declared payload size, not the transport frame limit.
        huge = DEFAULT_MAX_FRAME_LENGTH + 1
        result = self._parse(_header(total_size=huge), _data_chunk())
        self.assertIsNone(result.sharing_type)
        self.assertEqual(result.payload_transfer.total_size, huge)
        self.assertFalse(result.payload_transfer.complete_sharing_frame)

    def test_boundary_declared_size_at_frame_cap_is_accepted(self):
        result = self._parse(
            _header(total_size=DEFAULT_MAX_FRAME_LENGTH), _data_chunk()
        )
        self.assertEqual(result.payload_transfer.total_size, DEFAULT_MAX_FRAME_LENGTH)

    def test_multi_chunk_bytes_payload_chunks_are_reported_incomplete(self):
        total = len(_SHARING_PKE)
        first = self._parse(_header(total_size=total), _data_chunk(body=_SHARING_PKE[:5]))
        second = self._parse(
            _header(total_size=total),
            _data_chunk(body=_SHARING_PKE[5:], offset=5, index=1),
        )
        self.assertFalse(first.payload_transfer.complete_sharing_frame)
        self.assertFalse(second.payload_transfer.complete_sharing_frame)
        self.assertEqual(second.payload_transfer.chunk_offset, 5)
        self.assertEqual(second.payload_transfer.chunk_body_length, total - 5)

    def test_bodyless_last_chunk_terminator_with_negative_id_is_accepted(self):
        total = len(_SHARING_PKE)
        result = self._parse(
            _header(-1, total_size=total),
            _data_chunk(offset=total, flags=1, omit_body=True),
        )
        self.assertTrue(result.payload_transfer.is_last_chunk)
        self.assertEqual(result.payload_transfer.chunk_offset, total)
        self.assertEqual(result.payload_transfer.chunk_body_length, 0)
        self.assertIsNone(result.sharing_type)

    def test_negative_chunk_offset_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "PayloadChunk offset"):
            self._parse(_header(), _data_chunk(offset=-1))

    def test_negative_chunk_index_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "index .* negative"):
            self._parse(_header(), _data_chunk(index=-1))

    def test_negative_chunk_flags_are_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "flags .* negative"):
            self._parse(_header(), _data_chunk(flags=-1))

    def test_synthetic_authenticated_offer_with_negative_id(self):
        frame, keys = synthetic_frame(payload_id=-(2**63))
        summary = authenticate_and_inspect_frame(frame, keys)
        self.assertEqual(summary.payload_transfer.payload_id, -(2**63))
        self.assertEqual(summary.sharing_type, "PAIRED_KEY_ENCRYPTION")


if __name__ == "__main__":
    unittest.main()

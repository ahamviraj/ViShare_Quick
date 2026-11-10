"""Synthetic tests for the no-credential paired-key response stage.

These fixtures are constructed from the published protobuf schemas. They are
not captured Android traffic and do not prove Android interoperability.
"""
from __future__ import annotations

import hashlib
import hmac
import socket
import unittest
from unittest.mock import call, patch

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vishare_quick.paired_key_response import (
    PAIRED_KEY_RESULT_FAIL,
    PAIRED_KEY_RESULT_SUCCESS,
    PAIRED_KEY_RESULT_UNABLE,
    PairedKeyMessageError,
    PairedKeyResponseError,
    PairedKeyStructureError,
    build_bytes_payload_messages,
    build_keep_alive_ack_frame,
    build_paired_key_encryption_frame,
    build_paired_key_response_messages,
    build_paired_key_result_frame,
    run_paired_key_response,
)
from vishare_quick.protocol import Frame, FrameTimeout, PeerDisconnected
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import (
    ReceiveKeys,
    SecureChannelError,
    SecureMessageAuthenticationError,
    _parse,
    _parse_offline_frame,
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
    derive_server_to_client_send_keys,
)
from test_secure_channel import blob, vint

NEXT_SECRET = b"synthetic next secret 1234567890"


def varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _wrap_transfer(sharing: bytes, payload_id: int, *, terminator: bool) -> bytes:
    header = vint(1, payload_id) + vint(2, 1) + vint(3, len(sharing))
    if terminator:
        chunk = vint(1, 1) + vint(2, len(sharing))
    else:
        chunk = vint(1, 0) + vint(2, 0) + blob(3, sharing)
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    offline_v1 = vint(1, 3) + blob(4, transfer)
    return vint(1, 1) + blob(2, offline_v1)


def _pke_sharing() -> bytes:
    body = blob(1, b"fixture-signed-data") + blob(2, b"secret-hash")
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, body))


def _result_sharing(status: int) -> bytes:
    return vint(1, 1) + blob(2, vint(1, 4) + blob(5, vint(1, status)))


def _keep_alive_offline() -> bytes:
    # OfflineFrame v1 -> V1Frame type=KEEP_ALIVE(5), body field 6 (empty frame).
    return vint(1, 1) + blob(2, vint(1, 5) + blob(6, b""))


def _bandwidth_upgrade_retry_offline(
    *, is_request: bool = True, mediums: tuple[int, ...] = (5, 8)
) -> bytes:
    # V1Frame type=12 BANDWIDTH_UPGRADE_RETRY, body field 13. The body is
    # BandwidthUpgradeRetryFrame: repeated Medium supported_medium=1,
    # optional bool is_request=2.
    body = b"".join(vint(1, medium) for medium in mediums)
    body += vint(2, 1 if is_request else 0)
    return vint(1, 1) + blob(2, vint(1, 12) + blob(13, body))


def _disconnection_offline() -> bytes:
    # V1Frame type=6 DISCONNECTION, body field 7.
    return vint(1, 1) + blob(2, vint(1, 6) + blob(7, b""))


def _partial_bytes_transfer(*, payload_id: int = 7, total_size: int = 100) -> bytes:
    """A syntactically valid but incomplete BYTES DATA chunk (multi-chunk case)."""
    header = vint(1, payload_id) + vint(2, 1) + vint(3, total_size)
    chunk = vint(1, 0) + vint(2, 0) + blob(3, b"\x08\x01")
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))


def _client_frame(offline: bytes, sequence: int, *, iv: bytes | None = None) -> Frame:
    """Encrypt one synthetic Android -> laptop SecureMessage."""
    keys = derive_client_to_server_receive_keys(NEXT_SECRET)
    iv = bytes(range(16)) if iv is None else iv
    plaintext = blob(1, offline) + vint(2, sequence)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(keys.encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    metadata = vint(1, 13) + vint(2, 1)
    header = vint(1, 1) + vint(2, 2) + blob(5, iv) + blob(6, metadata)
    header_and_body = blob(1, header) + blob(2, ciphertext)
    signature = hmac.new(keys.hmac_key, header_and_body, hashlib.sha256).digest()
    payload = blob(1, header_and_body) + blob(2, signature)
    wire = len(payload).to_bytes(4, "big") + payload
    return Frame(payload, len(payload), "unknown", "unknown", "unclassified", wire)


def _inbound_exchange(
    *,
    offer: Frame | None = None,
    states: tuple[int, ...] = (3,),
    offer_terminator: Frame | None = None,
    peer_sequence_start: int = 3,
) -> list[Frame]:
    pke = _pke_sharing()
    frames = [offer if offer is not None else _client_frame(_wrap_transfer(pke, 7, terminator=False), 1)]
    frames.append(
        offer_terminator
        if offer_terminator is not None
        else _client_frame(_wrap_transfer(pke, 7, terminator=True), 2)
    )
    for index, status in enumerate(states):
        sequence = peer_sequence_start + index * 2
        frames.append(
            _client_frame(_wrap_transfer(_result_sharing(status), 7, terminator=False), sequence)
        )
        frames.append(
            _client_frame(_wrap_transfer(_result_sharing(status), 7, terminator=True), sequence + 1)
        )
    return frames


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


class CollectingWriter:
    def __init__(self):
        self.buffer = bytearray()

    def sendall(self, data):
        self.buffer.extend(data)


def _split_frames(data: bytes) -> list[Frame]:
    frames = []
    position = 0
    while position < len(data):
        length = int.from_bytes(data[position:position + 4], "big")
        payload = data[position + 4:position + 4 + length]
        wire = data[position:position + 4 + length]
        frames.append(
            Frame(payload, length, "unknown", "unknown", "unclassified", wire)
        )
        position += 4 + length
    return frames


class PairedKeyResponseBuilderTests(unittest.TestCase):
    def test_paired_key_frame_uses_random_no_credential_placeholders(self):
        pke = build_paired_key_encryption_frame()
        data, _ = build_bytes_payload_messages(pke, 1)
        parsed = _parse_offline_frame(data)
        self.assertEqual(parsed.offline_type, "PAYLOAD_TRANSFER")
        self.assertEqual(parsed.sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertTrue(parsed.payload_transfer.complete_sharing_frame)
        fields = {field.name: field for field in parsed.paired_key_fields}
        self.assertEqual(len(fields), 4)
        self.assertTrue(fields["signed_data"].present)
        self.assertEqual(fields["signed_data"].length, 72)
        self.assertTrue(fields["secret_id_hash"].present)
        self.assertEqual(fields["secret_id_hash"].length, 6)
        # No identity-bearing optional fields are emitted.
        self.assertFalse(fields["optional_signed_data"].present)
        self.assertFalse(fields["qr_code_handshake_data"].present)
        self.assertEqual(parsed.payload_transfer.total_size, len(pke))

    def test_paired_key_placeholders_are_fresh_each_call(self):
        self.assertNotEqual(
            build_paired_key_encryption_frame(),
            build_paired_key_encryption_frame(),
        )

    def test_paired_key_placeholders_come_from_secrets_token_bytes(self):
        signed_data = b"\xAA" * 72
        secret_id_hash = b"\xBB" * 6
        with patch(
            "vishare_quick.paired_key_response.secrets.token_bytes",
            side_effect=[signed_data, secret_id_hash],
        ) as token_bytes:
            pke = build_paired_key_encryption_frame()
        self.assertEqual(token_bytes.call_args_list, [call(72), call(6)])
        self.assertIn(signed_data, pke)
        self.assertIn(secret_id_hash, pke)

    def test_paired_key_frame_omits_untracked_optional_fields(self):
        # The schema also has optional_signed_data=3, qr_code_handshake_data=4,
        # and supports_provisioning=5. Only signed_data=1 and
        # secret_id_hash=2 may be present.
        pke = build_paired_key_encryption_frame()
        frame = _parse(pke, "Frame")
        v1 = _parse(frame[2][0].value, "V1Frame")
        body = v1[4][0].value
        fields = _parse(body, "PairedKeyEncryptionFrame")
        self.assertEqual(set(fields), {1, 2})

    def test_result_frame_encoding_matches_schema_status(self):
        for status in (0, 1, 2, 3):
            frame = build_paired_key_result_frame(status)
            data, _ = build_bytes_payload_messages(frame, 2)
            parsed = _parse_offline_frame(data)
            self.assertEqual(parsed.sharing_type, "PAIRED_KEY_RESULT")
            self.assertEqual(parsed.paired_key_result_status, status)

    def test_result_builder_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            build_paired_key_result_frame(9)

    def test_keep_alive_ack_builder_matches_schema(self):
        parsed = _parse_offline_frame(build_keep_alive_ack_frame())
        self.assertEqual(parsed.offline_type, "KEEP_ALIVE")
        self.assertTrue(parsed.keep_alive_ack)
        self.assertIsNone(parsed.sharing_type)

    def test_bandwidth_upgrade_retry_metadata_is_parsed_without_body(self):
        parsed = _parse_offline_frame(
            _bandwidth_upgrade_retry_offline(is_request=True, mediums=(5, 8))
        )
        self.assertEqual(parsed.offline_type, "BANDWIDTH_UPGRADE_RETRY")
        self.assertEqual(parsed.bandwidth_upgrade_retry_mediums, (5, 8))
        self.assertTrue(parsed.bandwidth_upgrade_retry_is_request)
        self.assertIsNone(parsed.sharing_type)
        self.assertIsNone(parsed.payload_transfer)

    def test_bytes_payload_emits_data_then_zero_length_last_chunk(self):
        sharing = _pke_sharing()
        data, last = build_bytes_payload_messages(sharing, 9)
        parsed_data = _parse_offline_frame(data)
        parsed_last = _parse_offline_frame(last)
        self.assertTrue(parsed_data.payload_transfer.complete_sharing_frame)
        self.assertFalse(parsed_data.payload_transfer.is_last_chunk)
        self.assertEqual(parsed_data.payload_transfer.payload_id, 9)
        self.assertFalse(parsed_last.payload_transfer.complete_sharing_frame)
        self.assertTrue(parsed_last.payload_transfer.is_last_chunk)
        self.assertEqual(parsed_last.payload_transfer.payload_id, 9)
        self.assertEqual(parsed_last.payload_transfer.chunk_body_length, 0)
        self.assertEqual(parsed_last.payload_transfer.chunk_offset, len(sharing))

    def test_response_schedule_is_four_messages(self):
        pke_data, pke_last, result_data, result_last = build_paired_key_response_messages()
        self.assertEqual(_parse_offline_frame(pke_data).sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertTrue(_parse_offline_frame(pke_last).payload_transfer.is_last_chunk)
        self.assertEqual(_parse_offline_frame(result_data).sharing_type, "PAIRED_KEY_RESULT")
        self.assertTrue(_parse_offline_frame(result_last).payload_transfer.is_last_chunk)

    def test_directional_keys_are_independent_and_deterministic(self):
        receive = derive_client_to_server_receive_keys(NEXT_SECRET)
        send = derive_server_to_client_send_keys(NEXT_SECRET)
        self.assertNotEqual(receive.encryption_key, send.encryption_key)
        self.assertNotEqual(receive.hmac_key, send.hmac_key)
        self.assertEqual(receive.encryption_key, derive_client_to_server_receive_keys(NEXT_SECRET).encryption_key)
        self.assertEqual(send.encryption_key, derive_server_to_client_send_keys(NEXT_SECRET).encryption_key)


class PairedKeyResponseStageTests(unittest.TestCase):
    def setUp(self):
        self.receive_keys = derive_client_to_server_receive_keys(NEXT_SECRET)
        self.send_keys = derive_server_to_client_send_keys(NEXT_SECRET)

    def test_valid_exchange_sends_four_authenticated_frames(self):
        reader = ScriptedReader(_inbound_exchange())
        writer = CollectingWriter()
        result = run_paired_key_response(
            reader, writer, self.receive_keys, self.send_keys, read_introduction=False
        )
        self.assertEqual(result.status, "peer-paired-key-result-received")
        self.assertEqual(result.offer.sequence, 1)
        self.assertEqual(result.offer_terminator.sequence, 2)
        self.assertEqual(result.peer_result.paired_key_result_status, PAIRED_KEY_RESULT_UNABLE)
        self.assertIsNone(result.introduction)

        outbound = _split_frames(bytes(writer.buffer))
        self.assertEqual(len(outbound), 4)
        outbound_keys = ReceiveKeys(
            self.send_keys.encryption_key, self.send_keys.hmac_key
        )
        summaries = [
            authenticate_and_inspect_frame(frame, outbound_keys, expected_sequence=index)
            for index, frame in enumerate(outbound, start=1)
        ]
        self.assertEqual(summaries[0].sharing_type, "PAIRED_KEY_ENCRYPTION")
        outbound_pke_fields = {
            field.name: field for field in summaries[0].paired_key_fields
        }
        self.assertEqual(outbound_pke_fields["signed_data"].length, 72)
        self.assertEqual(outbound_pke_fields["secret_id_hash"].length, 6)
        self.assertFalse(outbound_pke_fields["optional_signed_data"].present)
        self.assertFalse(outbound_pke_fields["qr_code_handshake_data"].present)
        self.assertTrue(summaries[1].payload_transfer.is_last_chunk)
        self.assertEqual(summaries[2].sharing_type, "PAIRED_KEY_RESULT")
        self.assertEqual(summaries[2].paired_key_result_status, PAIRED_KEY_RESULT_UNABLE)
        self.assertTrue(summaries[3].payload_transfer.is_last_chunk)

    def test_success_status_is_still_observed_not_claimed_locally(self):
        reader = ScriptedReader(_inbound_exchange(states=(PAIRED_KEY_RESULT_SUCCESS,)))
        writer = CollectingWriter()
        result = run_paired_key_response(
            reader, writer, self.receive_keys, self.send_keys, read_introduction=False
        )
        self.assertEqual(result.peer_result.paired_key_result_status, PAIRED_KEY_RESULT_SUCCESS)
        outbound = _split_frames(bytes(writer.buffer))
        summaries = [
            authenticate_and_inspect_frame(
                frame,
                ReceiveKeys(self.send_keys.encryption_key, self.send_keys.hmac_key),
                expected_sequence=index,
            )
            for index, frame in enumerate(outbound, start=1)
        ]
        self.assertEqual(summaries[2].paired_key_result_status, PAIRED_KEY_RESULT_UNABLE)

    def test_fail_status_is_reported(self):
        reader = ScriptedReader(_inbound_exchange(states=(PAIRED_KEY_RESULT_FAIL,)))
        writer = CollectingWriter()
        result = run_paired_key_response(
            reader, writer, self.receive_keys, self.send_keys, read_introduction=False
        )
        self.assertEqual(result.peer_result.paired_key_result_status, PAIRED_KEY_RESULT_FAIL)

    def test_missing_offer_writes_nothing(self):
        reader = ScriptedReader([])
        writer = CollectingWriter()
        with self.assertRaises(PeerDisconnected):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_wrong_first_sequence_writes_nothing(self):
        offer = _client_frame(_wrap_transfer(_pke_sharing(), 7, terminator=False), 2)
        reader = ScriptedReader([offer])
        writer = CollectingWriter()
        with self.assertRaisesRegex(SecureChannelError, "sequence"):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_offer_as_last_chunk_is_rejected_before_send(self):
        # A complete DATA body that also sets the LAST_CHUNK flag is not a
        # valid offer: the terminator must be a separate zero-length chunk.
        sharing = _pke_sharing()
        header = vint(1, 7) + vint(2, 1) + vint(3, len(sharing))
        chunk = vint(1, 1) + vint(2, 0) + blob(3, sharing)
        transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
        offline = vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))
        offer = _client_frame(offline, 1)
        reader = ScriptedReader([offer])
        writer = CollectingWriter()
        with self.assertRaisesRegex(PairedKeyResponseError, "unterminated DATA chunk"):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_terminator_offer_is_rejected_before_send(self):
        offer = _client_frame(_wrap_transfer(_pke_sharing(), 7, terminator=True), 1)
        reader = ScriptedReader([offer])
        writer = CollectingWriter()
        with self.assertRaises(PairedKeyResponseError):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_missing_offer_terminator_writes_nothing(self):
        offer = _client_frame(_wrap_transfer(_pke_sharing(), 7, terminator=False), 1)
        reader = ScriptedReader([offer])
        writer = CollectingWriter()
        with self.assertRaisesRegex(
            PeerDisconnected, r"sequence 2 \(Android paired-key offer terminator\)"
        ):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_terminator_with_wrong_payload_id_writes_nothing(self):
        pke = _pke_sharing()
        offer = _client_frame(_wrap_transfer(pke, 7, terminator=False), 1)
        bad_terminator = _client_frame(_wrap_transfer(pke, 8, terminator=True), 2)
        reader = ScriptedReader([offer, bad_terminator])
        writer = CollectingWriter()
        with self.assertRaisesRegex(PairedKeyResponseError, "LAST_CHUNK terminator"):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(bytes(writer.buffer), b"")

    def test_peer_result_sequence_mismatch_fails_after_sending(self):
        frames = _inbound_exchange(peer_sequence_start=4)
        reader = ScriptedReader(frames)
        writer = CollectingWriter()
        with self.assertRaisesRegex(SecureChannelError, "sequence"):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_peer_result_timeout_reports_stage_after_sending(self):
        # The offer and terminator are valid, so all four response messages are
        # written; the diagnostic then identifies which inbound sequence stalled.
        reader = ScriptedReader(_inbound_exchange()[:2], timeout_after=True)
        writer = CollectingWriter()
        with self.assertRaisesRegex(
            FrameTimeout, r"sequence 3 \(peer paired-key result\)"
        ):
            run_paired_key_response(reader, writer, self.receive_keys, self.send_keys)
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_sequence_3_bandwidth_upgrade_retry_is_skipped_and_result_accepted(self):
        # The real Infinix XPad run authenticated BANDWIDTH_UPGRADE_RETRY at
        # inbound sequence 3. It is a transport-control frame, not a paired-key
        # rejection. NearShare, NearDrop, and squick-share ignore it.
        frames = _inbound_exchange()[:2]
        frames.append(
            _client_frame(
                _bandwidth_upgrade_retry_offline(is_request=True, mediums=(5, 8)), 3
            )
        )
        frames.extend(_inbound_exchange(peer_sequence_start=4)[2:])
        writer = CollectingWriter()
        result = run_paired_key_response(
            ScriptedReader(frames), writer, self.receive_keys, self.send_keys,
            read_introduction=False,
        )
        self.assertEqual(result.status, "peer-paired-key-result-received")
        self.assertEqual(result.peer_result.sequence, 4)
        self.assertEqual(result.peer_result_terminator.sequence, 5)
        self.assertEqual(
            result.peer_result.paired_key_result_status, PAIRED_KEY_RESULT_UNABLE
        )
        # Ignoring the retry must not add a wire reply.
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_sequence_3_keep_alive_is_skipped_and_acknowledged(self):
        frames = _inbound_exchange()[:2]
        frames.append(_client_frame(_keep_alive_offline(), 3))
        frames.extend(_inbound_exchange(peer_sequence_start=4)[2:])
        writer = CollectingWriter()
        result = run_paired_key_response(
            ScriptedReader(frames), writer, self.receive_keys, self.send_keys,
            read_introduction=False,
        )
        self.assertEqual(result.peer_result.sequence, 4)
        self.assertEqual(result.peer_result_terminator.sequence, 5)

        outbound = _split_frames(bytes(writer.buffer))
        self.assertEqual(len(outbound), 5)
        summaries = [
            authenticate_and_inspect_frame(
                frame,
                ReceiveKeys(self.send_keys.encryption_key, self.send_keys.hmac_key),
                expected_sequence=index,
            )
            for index, frame in enumerate(outbound, start=1)
        ]
        self.assertEqual(summaries[4].offline_type, "KEEP_ALIVE")
        self.assertTrue(summaries[4].keep_alive_ack)

    def test_multiple_transport_frames_consume_one_global_sequence(self):
        frames = _inbound_exchange()[:2]
        frames.append(
            _client_frame(
                _bandwidth_upgrade_retry_offline(is_request=True, mediums=(8,)), 3
            )
        )
        frames.append(_client_frame(_keep_alive_offline(), 4))
        frames.append(
            _client_frame(
                _bandwidth_upgrade_retry_offline(is_request=False, mediums=()), 5
            )
        )
        frames.extend(_inbound_exchange(peer_sequence_start=6)[2:])
        writer = CollectingWriter()
        result = run_paired_key_response(
            ScriptedReader(frames), writer, self.receive_keys, self.send_keys,
            read_introduction=False,
        )
        self.assertEqual(result.peer_result.sequence, 6)
        self.assertEqual(result.peer_result_terminator.sequence, 7)
        # Four response frames plus one keep-alive acknowledgement; the two
        # bandwidth-control frames are ignored without a reply.
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 5)

    def test_transport_control_flood_is_bounded(self):
        frames = _inbound_exchange()[:2]
        for index in range(17):
            frames.append(
                _client_frame(
                    _bandwidth_upgrade_retry_offline(is_request=True), 3 + index
                )
            )
        writer = CollectingWriter()
        with self.assertRaisesRegex(
            PairedKeyStructureError, "Too many transport control frames"
        ):
            run_paired_key_response(
                ScriptedReader(frames), writer, self.receive_keys, self.send_keys
            )
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_disconnection_while_waiting_is_not_reported_as_result(self):
        frames = _inbound_exchange()[:2]
        frames.append(_client_frame(_disconnection_offline(), 3))
        writer = CollectingWriter()
        with self.assertRaisesRegex(PeerDisconnected, "DISCONNECTION"):
            run_paired_key_response(
                ScriptedReader(frames), writer, self.receive_keys, self.send_keys
            )
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_unexpected_sequence_3_partial_payload_reports_incomplete(self):
        frames = _inbound_exchange()[:2]
        frames.append(_client_frame(_partial_bytes_transfer(), 3))
        writer = CollectingWriter()
        with self.assertRaisesRegex(
            PairedKeyMessageError,
            r"offline=PAYLOAD_TRANSFER.*sharing=none.*total_size=100.*complete=false",
        ):
            run_paired_key_response(
                ScriptedReader(frames), writer, self.receive_keys, self.send_keys
            )
        self.assertEqual(len(_split_frames(bytes(writer.buffer))), 4)

    def test_timeline_records_transport_skips_and_later_result(self):
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        frames = _inbound_exchange()[:2]
        frames.append(
            _client_frame(
                _bandwidth_upgrade_retry_offline(is_request=True, mediums=(5, 8)), 3
            )
        )
        frames.append(_client_frame(_keep_alive_offline(), 4))
        frames.extend(_inbound_exchange(peer_sequence_start=5)[2:])
        writer = CollectingWriter()
        result = run_paired_key_response(
            ScriptedReader(frames),
            writer,
            self.receive_keys,
            self.send_keys,
            read_introduction=False,
            timeline=timeline,
        )
        self.assertEqual(result.peer_result.sequence, 5)
        rendered = "\n".join(lines)
        self.assertIn("IN    SECURE_MESSAGE seq=1 authenticated=true decrypted=true", rendered)
        self.assertIn("IN    SECURE_MESSAGE seq=2 authenticated=true decrypted=true", rendered)
        self.assertIn("IN    SECURE_MESSAGE seq=5 authenticated=true decrypted=true", rendered)
        self.assertIn("IN    SKIP offline=BANDWIDTH_UPGRADE_RETRY", rendered)
        self.assertIn("retry_is_request=true", rendered)
        self.assertIn("retry_mediums=WIFI_LAN,WIFI_DIRECT", rendered)
        self.assertIn("IN    SKIP offline=KEEP_ALIVE", rendered)
        self.assertIn("keep_alive_ack=false", rendered)
        self.assertIn("OUT   FRAME offline=KEEP_ALIVE keep_alive_ack=true", rendered)
        for sequence in (1, 2, 3, 4):
            self.assertIn(f"OUT   SECURE_MESSAGE seq={sequence} encrypted=true", rendered)
        self.assertIn("sharing=PAIRED_KEY_ENCRYPTION", rendered)
        self.assertIn("sharing=PAIRED_KEY_RESULT", rendered)
        self.assertIn("result_status=UNABLE", rendered)
        self.assertIn("STATE PAIRED_KEY_RESPONSE_SENT", rendered)
        # Raw synthetic sharing contents must never appear in the timeline.
        self.assertNotIn("fixture-signed-data", rendered)
        self.assertNotIn("secret-hash", rendered)

    def test_timeline_labels_authentication_failure_as_unauthenticated(self):
        offer = _client_frame(_wrap_transfer(_pke_sharing(), 7, terminator=False), 1)
        damaged = offer.payload[:-1] + bytes([offer.payload[-1] ^ 1])
        wire = len(damaged).to_bytes(4, "big") + damaged
        bad = Frame(damaged, len(damaged), "unknown", "unknown", "unclassified", wire)
        lines: list[str] = []
        timeline = ProtocolTimeline(printer=lines.append, clock=lambda: 0.0)
        writer = CollectingWriter()
        with self.assertRaises(SecureMessageAuthenticationError):
            run_paired_key_response(
                ScriptedReader([bad]),
                writer,
                self.receive_keys,
                self.send_keys,
                timeline=timeline,
            )
        rendered = "\n".join(lines)
        self.assertIn("IN    SECURE_MESSAGE bytes=", rendered)
        self.assertIn("authenticated=false decrypted=false", rendered)
        self.assertIn("stage=Android paired-key offer", rendered)
        self.assertEqual(bytes(writer.buffer), b"")


if __name__ == "__main__":
    unittest.main()

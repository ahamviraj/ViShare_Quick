"""Synthetic receiver tests that replay the live XPad frame order.

The frame order and message shapes are derived from the published protobuf
schemas and the observed XPad run; they are not captured traffic. These tests
exercise the real ``run_receive_session`` path: the responder's own RESPONSE,
a keep-alive ack, FILE chunks, and the final DISCONNECTION.
"""
from __future__ import annotations

import hashlib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from vishare_quick.consent import (
    RESPONSE_ACCEPT,
    RESPONSE_NOT_ENOUGH_SPACE,
    RESPONSE_REJECT,
    build_cancel_frame,
    build_disconnection_frame,
)
from vishare_quick.file_transfer import (
    FileTransferError,
    FileTransferIOError,
    FileReceiver,
)
from vishare_quick.introduction import parse_introduction
from vishare_quick.paired_key_response import (
    PAIRED_KEY_OUTBOUND_PAYLOAD_IDS,
    PAIRED_KEY_RESULT_UNABLE,
    build_keep_alive_frame,
    run_paired_key_response,
)
from vishare_quick.pin_verification import PinVerification
from vishare_quick.secure_channel import (
    ReceiveKeys,
    _parse_offline_frame,
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
    derive_server_to_client_send_keys,
)
from vishare_quick.sharing_session import (
    KEEP_ALIVE_INTERVAL_SECONDS,
    SharingSessionError,
    _OutboundChannel,
    _ProactiveKeepAlive,
    _choose_response_payload_id,
    run_receive_session,
)
from test_introduction import file_metadata, introduction_body, sharing_frame
from test_paired_key_response import (
    NEXT_SECRET,
    CollectingWriter,
    ScriptedReader,
    _bandwidth_upgrade_retry_offline,
    _client_frame,
    _inbound_exchange,
    _keep_alive_offline,
    _response_sharing,
    _split_frames,
)
from test_secure_channel import blob, vint, vint_signed

# Android senders pick signed int64 payload IDs and often choose negative
# values. These synthetic constants keep that exact two's-complement shape.
INTRODUCTION_PAYLOAD_ID = -(1 << 62) - 7
PEER_RESPONSE_PAYLOAD_ID = -(1 << 61) - 11
PEER_PROGRESS_PAYLOAD_ID = -(1 << 60) - 13
AUTH_STRING = b"0123456789abcdef0123456789abcdef"  # exactly 32 bytes
INCOMING_FILE_NAME = "synthetic-note.txt"
SYNTHETIC_FILE_CONTENT = b"ViShare Quick live-order test payload\n" * 2


def _int64_field(number: int, value: int) -> bytes:
    return vint_signed(number, value) if value < 0 else vint(number, value)


def _wrap_transfer_signed(sharing: bytes, payload_id: int, *, terminator: bool) -> bytes:
    """Like the shared helper, but keeps negative introductions exact."""
    header = (
        _int64_field(1, payload_id)
        + vint(2, 1)  # PayloadHeader.BYTES
        + vint(3, len(sharing))
    )
    if terminator:
        chunk = vint(1, 1) + vint(2, len(sharing))
    else:
        chunk = vint(1, 0) + vint(2, 0) + blob(3, sharing)
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))


def _file_data_offline(
    payload_id: int,
    total_size: int,
    offset: int,
    body: bytes,
    *,
    last: bool,
) -> bytes:
    """Build a DATA PayloadTransferFrame carrying FILE payload bytes."""
    header = (
        _int64_field(1, payload_id)
        + vint(2, 2)  # PayloadHeader.FILE
        + vint(3, total_size)
    )
    chunk = vint(1, 1 if last else 0) + vint(2, offset)
    if body:
        chunk += blob(3, body)
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))


def _introduction_sharing(
    *, payload_id: int = INTRODUCTION_PAYLOAD_ID, size: int = len(SYNTHETIC_FILE_CONTENT)
) -> bytes:
    return sharing_frame(
        1,
        introduction_body(
            files=[
                file_metadata(
                    name=INCOMING_FILE_NAME,
                    file_type=1,
                    payload_id=payload_id,
                    size=size,
                    mime_type="text/plain",
                )
            ]
        ),
    )


def _progress_sharing() -> bytes:
    """Sharing ``PROGRESS_UPDATE``: type 7 with its body in field 7.

    The deprecated ``progress_update`` field is number 7, not 8. The sender
    emits this after the receiver's ACCEPT and before the first FILE chunk.
    """
    return sharing_frame(7, vint(2, 1))


def _application_frames(
    intro_sharing: bytes,
    payload_id: int,
    content: bytes,
    *,
    chunk_plan: str = "single-last",
    include_peer_response: bool = True,
    include_bandwidth: bool = True,
    include_keep_alive: bool = True,
    include_progress: bool = True,
) -> list:
    """Replay the live order: terminator, peer RESPONSE, retry, keep-alive, progress, FILE."""
    frames = [
        _client_frame(
            _wrap_transfer_signed(intro_sharing, payload_id, terminator=True), 6
        )
    ]
    sequence = 7
    if include_peer_response:
        frames.append(
            _client_frame(
                _wrap_transfer_signed(_response_sharing(1), PEER_RESPONSE_PAYLOAD_ID, terminator=False),
                sequence,
            )
        )
        sequence += 1
        frames.append(
            _client_frame(
                _wrap_transfer_signed(_response_sharing(1), PEER_RESPONSE_PAYLOAD_ID, terminator=True),
                sequence,
            )
        )
        sequence += 1
    if include_bandwidth:
        frames.append(
            _client_frame(_bandwidth_upgrade_retry_offline(is_request=False), sequence)
        )
        sequence += 1
    if include_keep_alive:
        frames.append(_client_frame(_keep_alive_offline(), sequence))
        sequence += 1
    if include_progress:
        # Observed as one complete BYTES DATA chunk before the first FILE chunk.
        frames.append(
            _client_frame(
                _wrap_transfer_signed(
                    _progress_sharing(), PEER_PROGRESS_PAYLOAD_ID, terminator=False
                ),
                sequence,
            )
        )
        sequence += 1

    if chunk_plan == "single-last":
        frames.append(
            _client_frame(
                _file_data_offline(payload_id, len(content), 0, content, last=True),
                sequence,
            )
        )
    elif chunk_plan == "data-plus-terminator":
        split = max(1, len(content) // 2)
        for chunk, offset in (
            (content[:split], 0),
            (content[split:], split),
        ):
            frames.append(
                _client_frame(
                    _file_data_offline(
                        payload_id, len(content), offset, chunk, last=False
                    ),
                    sequence,
                )
            )
            sequence += 1
        frames.append(
            _client_frame(
                _file_data_offline(payload_id, len(content), len(content), b"", last=True),
                sequence,
            )
        )
    elif chunk_plan == "live-512k":
        # The XPad advances in 524,288-byte chunks. Its final data chunk may be
        # short and still carry last_chunk=false, followed by a zero-length
        # LAST_CHUNK at offset == total_size.
        chunk_size = 524_288
        offset = 0
        while offset < len(content):
            chunk = content[offset : offset + chunk_size]
            frames.append(
                _client_frame(
                    _file_data_offline(
                        payload_id, len(content), offset, chunk, last=False
                    ),
                    sequence,
                )
            )
            sequence += 1
            offset += len(chunk)
        frames.append(
            _client_frame(
                _file_data_offline(payload_id, len(content), len(content), b"", last=True),
                sequence,
            )
        )
    else:
        raise ValueError(f"Unknown chunk plan {chunk_plan!r}.")
    return frames


class CapturePrompter:
    """Scripted human. ``pin=None`` declines; ``pin='echo'`` confirms locally."""

    def __init__(self, *, pin: str | None = "echo", accept: bool = True) -> None:
        self.pin = pin
        self.accept = accept
        self.local_code = None
        self.request = None
        self.consent_calls = 0

    def ask_pin(self, code: str) -> str | None:
        self.local_code = code
        if self.pin == "echo":
            return code
        return self.pin

    def request_consent(self, request) -> bool:
        self.request = request
        self.consent_calls += 1
        return self.accept


class FailingWriter:
    """Fail every write, to prove local temp files are removed."""

    def sendall(self, data: bytes) -> None:
        raise OSError("synthetic write failure")


class SharingSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receive_keys = derive_client_to_server_receive_keys(NEXT_SECRET)
        self.send_keys = derive_server_to_client_send_keys(NEXT_SECRET)
        self.code = PinVerification(AUTH_STRING).code

    # ------------------------------------------------------------- helpers
    def _summary(self, intro_sharing: bytes, payload_id: int):
        frame = _client_frame(
            _wrap_transfer_signed(intro_sharing, payload_id, terminator=False), 5
        )
        return authenticate_and_inspect_frame(
            frame, self.receive_keys, expected_sequence=5
        )

    def _outbound(self, writer, first_sequence: int = 5):
        frames = _split_frames(bytes(writer.buffer))
        keys = ReceiveKeys(self.send_keys.encryption_key, self.send_keys.hmac_key)
        return [
            authenticate_and_inspect_frame(
                frame, keys, expected_sequence=first_sequence + index
            )
            for index, frame in enumerate(frames)
        ]

    def _run(
        self,
        intro_sharing: bytes,
        frames,
        prompter,
        download_dir,
        *,
        payload_id: int = INTRODUCTION_PAYLOAD_ID,
        writer=None,
        keep_alive_interval_seconds: float = 60.0,
    ):
        writer = writer if writer is not None else CollectingWriter()
        result = run_receive_session(
            ScriptedReader(frames),
            writer,
            self.receive_keys,
            self.send_keys,
            AUTH_STRING,
            introduction_summary=self._summary(intro_sharing, payload_id),
            next_inbound_sequence=6,
            next_outbound_sequence=5,
            download_dir=Path(download_dir),
            prompter=prompter,
            keep_alive_interval_seconds=keep_alive_interval_seconds,
        )
        return result, self._outbound(writer)

    def _response_summaries(self, outbound):
        return [
            summary
            for summary in outbound
            if summary.sharing_type == "RESPONSE"
            and summary.payload_transfer is not None
            and not summary.payload_transfer.is_last_chunk
        ]

    def _assert_no_partials(self, directory) -> None:
        self.assertEqual(
            list(Path(directory).glob(".vishare-partial-*")),
            [],
            "temporary receive files were not removed",
        )

    # ------------------------------------------------------- live re-order
    def test_paired_key_stage_composes_with_receive_session(self):
        """The two stages must share one inbound and one outbound sequence."""
        intro = _introduction_sharing()
        frames = _inbound_exchange(states=(PAIRED_KEY_RESULT_UNABLE,))
        # _inbound_exchange ends at inbound sequence 4.
        frames.append(
            _client_frame(
                _wrap_transfer_signed(intro, INTRODUCTION_PAYLOAD_ID, terminator=False),
                5,
            )
        )
        frames.extend(
            _application_frames(
                intro,
                INTRODUCTION_PAYLOAD_ID,
                SYNTHETIC_FILE_CONTENT,
                chunk_plan="single-last",
            )
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            reader = ScriptedReader(frames)
            writer = CollectingWriter()
            paired = run_paired_key_response(
                reader,
                writer,
                self.receive_keys,
                self.send_keys,
                timeline=None,
            )
            self.assertEqual(paired.status, "introduction-received")
            self.assertEqual(paired.next_inbound_sequence, 6)
            self.assertEqual(paired.next_outbound_sequence, 5)

            result = run_receive_session(
                reader,
                writer,
                self.receive_keys,
                self.send_keys,
                AUTH_STRING,
                introduction_summary=paired.introduction,
                next_inbound_sequence=paired.next_inbound_sequence,
                next_outbound_sequence=paired.next_outbound_sequence,
                download_dir=Path(temp),
                prompter=prompter,
                keep_alive_interval_seconds=60.0,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                Path(result.files[0].path).read_bytes(), SYNTHETIC_FILE_CONTENT
            )

        outbound = self._outbound(writer, first_sequence=1)
        self.assertEqual(len(outbound), 8)
        self.assertEqual(outbound[0].sharing_type, "PAIRED_KEY_ENCRYPTION")
        self.assertTrue(outbound[1].payload_transfer.is_last_chunk)
        self.assertEqual(outbound[2].sharing_type, "PAIRED_KEY_RESULT")
        self.assertTrue(outbound[3].payload_transfer.is_last_chunk)
        self.assertEqual(outbound[4].sharing_type, "RESPONSE")
        self.assertEqual(
            outbound[4].connection_response.status, RESPONSE_ACCEPT
        )
        self.assertEqual(outbound[4].payload_transfer.payload_id, 3)
        self.assertEqual(outbound[6].offline_type, "KEEP_ALIVE")
        self.assertIs(outbound[6].keep_alive_ack, True)
        self.assertEqual(outbound[7].offline_type, "DISCONNECTION")

    def test_live_frame_order_receives_exact_bytes_and_cleans_up(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(intro, frames, prompter, temp)

            self.assertEqual(result.status, "completed")
            self.assertTrue(result.pin_verified)
            self.assertEqual(result.consent, "accepted")
            self.assertEqual(prompter.local_code, self.code)
            self.assertEqual(prompter.consent_calls, 1)
            self.assertEqual(len(result.files), 1)
            received = result.files[0]
            self.assertEqual(Path(received.path).read_bytes(), SYNTHETIC_FILE_CONTENT)
            self.assertEqual(received.size, len(SYNTHETIC_FILE_CONTENT))
            self.assertEqual(
                received.sha256, hashlib.sha256(SYNTHETIC_FILE_CONTENT).hexdigest()
            )
            self.assertEqual(received.payload_id, INTRODUCTION_PAYLOAD_ID)
            self.assertEqual(received.path.parent, Path(temp).resolve())
            self._assert_no_partials(temp)

        responses = self._response_summaries(outbound)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].connection_response.status, RESPONSE_ACCEPT)
        response_id = responses[0].payload_transfer.payload_id
        # The paired-key stage already used 1 and 2 in this direction.
        self.assertNotIn(response_id, PAIRED_KEY_OUTBOUND_PAYLOAD_IDS)
        self.assertEqual(response_id, 3)
        self.assertTrue(
            any(
                summary.offline_type == "KEEP_ALIVE"
                and summary.keep_alive_ack is True
                for summary in outbound
            )
        )
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_split_chunks_and_zero_length_last_chunk_are_accepted(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro,
            INTRODUCTION_PAYLOAD_ID,
            SYNTHETIC_FILE_CONTENT,
            chunk_plan="data-plus-terminator",
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            result, _ = self._run(intro, frames, prompter, temp)
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                Path(result.files[0].path).read_bytes(), SYNTHETIC_FILE_CONTENT
            )

    def test_live_512k_chunk_plan_with_short_tail_is_accepted(self):
        # One full 524,288-byte chunk plus a short tail: the observed XPad
        # shape, with every data chunk marked last_chunk=false and a separate
        # zero-length terminator at offset == total_size.
        content = bytes(range(256)) * 2048 + b"synthetic-tail"
        self.assertGreater(len(content), 524_288)
        intro = _introduction_sharing(size=len(content))
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, content, chunk_plan="live-512k"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(intro, frames, prompter, temp)
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.files), 1)
            self.assertEqual(result.files[0].size, len(content))
            self.assertEqual(Path(result.files[0].path).read_bytes(), content)
            self._assert_no_partials(temp)

        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_negative_introduction_payload_id_is_preserved(self):
        payload_id = -(1 << 62) - 12345
        intro = _introduction_sharing(payload_id=payload_id)
        frames = _application_frames(
            intro, payload_id, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(
                intro,
                frames,
                prompter,
                temp,
                payload_id=payload_id,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.files[0].payload_id, payload_id)
            self.assertEqual(
                Path(result.files[0].path).read_bytes(), SYNTHETIC_FILE_CONTENT
            )
            self.assertEqual(
                self._response_summaries(outbound)[0].payload_transfer.payload_id, 3
            )

    def test_peer_response_accept_is_not_local_consent(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter(accept=False)

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)

        self.assertEqual(result.status, "consent-rejected")
        self.assertTrue(result.pin_verified)
        self.assertEqual(prompter.consent_calls, 1)
        self.assertEqual(result.files, ())
        responses = self._response_summaries(outbound)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].connection_response.status, RESPONSE_REJECT)
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_response_payload_id_avoids_introduced_and_paired_key_ids(self):
        intro = parse_introduction(
            _introduction_sharing(payload_id=3)
        )
        self.assertEqual(_choose_response_payload_id(intro), 4)

        intro_with_reserved = parse_introduction(_introduction_sharing(payload_id=1))
        self.assertEqual(_choose_response_payload_id(intro_with_reserved), 3)

    def test_peer_ack_and_progress_frames_are_ignored_during_transfer(self):
        intro = _introduction_sharing()
        progress = sharing_frame(7, vint(1, 1))
        frames = [
            _client_frame(
                _wrap_transfer_signed(
                    intro, INTRODUCTION_PAYLOAD_ID, terminator=True
                ),
                6,
            ),
            _client_frame(build_keep_alive_frame(ack=True), 7),
            _client_frame(
                _wrap_transfer_signed(progress, 88001, terminator=False), 8
            ),
            _client_frame(
                _file_data_offline(
                    INTRODUCTION_PAYLOAD_ID,
                    len(SYNTHETIC_FILE_CONTENT),
                    0,
                    SYNTHETIC_FILE_CONTENT,
                    last=True,
                ),
                9,
            ),
        ]
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(intro, frames, prompter, temp)
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                Path(result.files[0].path).read_bytes(), SYNTHETIC_FILE_CONTENT
            )

        # An ack=true keep-alive must not be answered again (no ack loops).
        self.assertFalse(
            any(summary.offline_type == "KEEP_ALIVE" for summary in outbound)
        )
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    # ------------------------------------------------------------- rejects
    def test_wrong_pin_sends_reject_and_writes_no_file(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        wrong = f"{(int(self.code) + 1) % 10000:04d}"
        prompter = CapturePrompter(pin=wrong)

        with tempfile.TemporaryDirectory() as temp:
            result, outbound = self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)

        self.assertEqual(result.status, "pin-verification-failed")
        self.assertFalse(result.pin_verified)
        self.assertEqual(result.files, ())
        self.assertEqual(prompter.consent_calls, 0)
        responses = self._response_summaries(outbound)
        self.assertEqual(responses[0].connection_response.status, RESPONSE_REJECT)
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_blank_pin_declines_without_consent(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter(pin=None)

        with tempfile.TemporaryDirectory() as temp:
            result, _ = self._run(intro, frames, prompter, temp)

        self.assertEqual(result.status, "pin-verification-failed")
        self.assertEqual(prompter.consent_calls, 0)

    def test_not_enough_space_reports_the_documented_status(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp, patch(
            "vishare_quick.sharing_session.check_free_space", return_value=False
        ):
            result, outbound = self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)

        self.assertEqual(result.status, "not-enough-space")
        self.assertTrue(result.pin_verified)
        self.assertEqual(result.files, ())
        self.assertEqual(prompter.consent_calls, 0)
        responses = self._response_summaries(outbound)
        self.assertEqual(
            responses[0].connection_response.status, RESPONSE_NOT_ENOUGH_SPACE
        )
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_prepare_failure_declines_and_sends_disconnection(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp, patch.object(
            FileReceiver, "prepare", side_effect=FileTransferError("synthetic")
        ):
            with self.assertRaises(FileTransferError):
                self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)

    # ------------------------------------------------------------ failures
    def test_send_failure_removes_temporary_files(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(SharingSessionError):
                self._run(
                    intro,
                    frames,
                    prompter,
                    temp,
                    writer=FailingWriter(),
                )
            self._assert_no_partials(temp)

    def test_mid_transfer_write_failure_aborts_and_disconnects(self):
        intro = _introduction_sharing()
        frames = _application_frames(
            intro, INTRODUCTION_PAYLOAD_ID, SYNTHETIC_FILE_CONTENT, chunk_plan="single-last"
        )
        prompter = CapturePrompter()
        writer = CollectingWriter()

        with tempfile.TemporaryDirectory() as temp, patch.object(
            FileReceiver,
            "write_chunk",
            side_effect=FileTransferIOError("synthetic write failure"),
        ):
            with self.assertRaises(FileTransferIOError):
                self._run(intro, frames, prompter, temp, writer=writer)
            self._assert_no_partials(temp)

        outbound = self._outbound(writer)
        self.assertEqual(outbound[-1].offline_type, "DISCONNECTION")

    def test_peer_cancel_aborts_and_removes_partial_file(self):
        intro = _introduction_sharing()
        cancel = build_cancel_frame()
        frames = [
            _client_frame(_wrap_transfer_signed(intro, INTRODUCTION_PAYLOAD_ID, terminator=True), 6),
            _client_frame(_wrap_transfer_signed(cancel, 99001, terminator=False), 7),
        ]
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(SharingSessionError):
                self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)

    def test_unknown_file_payload_id_is_a_strict_error(self):
        intro = _introduction_sharing()
        frames = [
            _client_frame(_wrap_transfer_signed(intro, INTRODUCTION_PAYLOAD_ID, terminator=True), 6),
            _client_frame(
                _file_data_offline(
                    424242, len(SYNTHETIC_FILE_CONTENT), 0, SYNTHETIC_FILE_CONTENT, last=True
                ),
                7,
            ),
        ]
        prompter = CapturePrompter()

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileTransferError):
                self._run(intro, frames, prompter, temp)
            self._assert_no_partials(temp)


class OutboundChannelSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.send_keys = derive_server_to_client_send_keys(NEXT_SECRET)

    def test_sealed_channel_allows_only_the_closing_frame(self):
        writer = CollectingWriter()
        channel = _OutboundChannel(writer, self.send_keys, 5, None)
        channel.send(build_keep_alive_frame(ack=False), "proactive keep-alive")
        before = len(writer.buffer)

        channel.seal()
        with self.assertRaises(SharingSessionError):
            channel.send(build_keep_alive_frame(ack=False), "proactive keep-alive")
        self.assertEqual(len(writer.buffer), before)

        channel.send(build_disconnection_frame(), "disconnect", closing=True)
        self.assertGreater(len(writer.buffer), before)

    def test_closing_frame_after_seal_is_the_last_outbound_frame(self):
        writer = CollectingWriter()
        channel = _OutboundChannel(writer, self.send_keys, 5, None)
        channel.seal()
        channel.send(build_disconnection_frame(), "disconnect", closing=True)

        receive_keys = ReceiveKeys(
            self.send_keys.encryption_key, self.send_keys.hmac_key
        )
        summaries = [
            authenticate_and_inspect_frame(
                frame, receive_keys, expected_sequence=5 + index
            )
            for index, frame in enumerate(_split_frames(bytes(writer.buffer)))
        ]
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].offline_type, "DISCONNECTION")


class ProactiveKeepAliveTests(unittest.TestCase):
    def test_sends_ack_false_keep_alive_and_stops(self):
        sent = []
        first = threading.Event()

        def send(frame: bytes, stage: str) -> None:
            sent.append((frame, stage))
            first.set()

        sender = _ProactiveKeepAlive(send, 0.01)
        sender.start()
        try:
            self.assertTrue(first.wait(2.0), "no proactive keep-alive was sent")
        finally:
            sender.stop()

        self.assertFalse(sender._thread.is_alive())
        self.assertGreaterEqual(len(sent), 1)
        parsed = _parse_offline_frame(sent[0][0])
        self.assertEqual(parsed.offline_type, "KEEP_ALIVE")
        self.assertIs(parsed.keep_alive_ack, False)

    def test_invalid_interval_is_rejected(self):
        with self.assertRaises(ValueError):
            _ProactiveKeepAlive(lambda frame, stage: None, 0)

    def test_default_interval_is_below_reviewed_idle_timeouts(self):
        self.assertGreater(KEEP_ALIVE_INTERVAL_SECONDS, 0)
        self.assertLessEqual(KEEP_ALIVE_INTERVAL_SECONDS, 10.0)


if __name__ == "__main__":
    unittest.main()

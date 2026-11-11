"""Synthetic tests for live Introduction diagnostics, capture, and observation.

These fixtures are authenticated with the same synthetic SecureMessage keys as
the paired-key response tests. They are not captured Android traffic.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vishare_quick.introduction_diagnostics import (
    DEFAULT_CAPTURE_DIRECTORY,
    IntroductionCaptureError,
    handle_authenticated_introduction,
    observe_after_introduction,
    resolve_capture_directory,
    sanitize_filename_for_log,
    save_introduction_capture,
)
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    PayloadTransferMetadata,
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
    derive_server_to_client_send_keys,
)
from vishare_quick.sharing_session import run_receive_session
from test_introduction import file_metadata, introduction_body, sharing_frame, text_metadata
from test_paired_key_response import (
    NEXT_SECRET,
    CollectingWriter,
    ScriptedReader,
    _client_frame,
    _disconnection_offline,
    _inbound_exchange,
    _keep_alive_offline,
    _wrap_transfer,
    run_paired_key_response,
)
from test_secure_channel import blob


def _timeline() -> tuple[ProtocolTimeline, list[str]]:
    lines: list[str] = []
    return ProtocolTimeline(printer=lines.append, clock=lambda: 0.0), lines


def _summary_for_sharing(
    sharing: bytes,
    *,
    sequence: int = 5,
    complete: bool = True,
    sharing_type: str | None = "INTRODUCTION",
) -> AuthenticatedFrameSummary:
    return AuthenticatedFrameSummary(
        sequence=sequence,
        offline_type="PAYLOAD_TRANSFER",
        sharing_type=sharing_type,
        payload_transfer=PayloadTransferMetadata(
            packet_type=1,
            payload_id=7,
            payload_type=1,
            total_size=len(sharing),
            chunk_flags=0,
            chunk_offset=0,
            chunk_body_length=len(sharing),
            is_last_chunk=False,
            complete_sharing_frame=complete,
        ),
        payload_body=sharing,
    )


def _summary_for_body(body: bytes, **kwargs) -> AuthenticatedFrameSummary:
    return _summary_for_sharing(sharing_frame(1, body), **kwargs)


class AuthenticatedExtractionTests(unittest.TestCase):
    def test_complete_body_is_extracted_and_parsed_without_changing_the_wire_path(self):
        body = introduction_body(
            files=[
                file_metadata(
                    name="photo.jpg",
                    file_type=1,
                    payload_id=7,
                    size=1234,
                    mime_type="image/jpeg",
                )
            ]
        )
        sharing = sharing_frame(1, body)
        offline = _wrap_transfer(sharing, 7, terminator=False)
        frame = _client_frame(offline, 5)
        summary = authenticate_and_inspect_frame(
            frame,
            derive_client_to_server_receive_keys(NEXT_SECRET),
            expected_sequence=5,
        )

        self.assertEqual(summary.sequence, 5)
        self.assertEqual(summary.sharing_type, "INTRODUCTION")
        self.assertTrue(summary.payload_transfer.complete_sharing_frame)
        self.assertEqual(summary.payload_body, sharing)

        timeline, lines = _timeline()
        result = handle_authenticated_introduction(
            summary, timeline=timeline, printer=lines.append
        )
        self.assertTrue(result.parsed)
        self.assertIsNotNone(result.introduction)
        self.assertEqual(len(result.introduction.files), 1)
        self.assertEqual(result.introduction.files[0].name, "photo.jpg")
        self.assertEqual(result.pin_verification, "not-attempted")
        self.assertIsNone(result.capture_path)
        rendered = "\n".join(lines)
        self.assertIn("Introduction parsed: files=1", rendered)
        self.assertIn("PIN verification: not performed", rendered)
        self.assertNotIn("photo.jpg", rendered)
        timeline_text = "\n".join(lines)
        self.assertIn("INTRODUCTION_PARSED", timeline_text)
        self.assertIn("INTRODUCTION parsed=true", timeline_text)

    def test_live_paired_key_stage_returns_the_introduction_summary(self):
        body = introduction_body(
            files=[file_metadata(name="report.pdf", file_type=5, payload_id=7, size=99)]
        )
        sharing = sharing_frame(1, body)
        frames = _inbound_exchange(states=(3,))
        frames.append(
            _client_frame(_wrap_transfer(sharing, 7, terminator=False), 5)
        )

        result = run_paired_key_response(
            ScriptedReader(frames),
            CollectingWriter(),
            derive_client_to_server_receive_keys(NEXT_SECRET),
            derive_server_to_client_send_keys(NEXT_SECRET),
        )

        self.assertEqual(result.status, "introduction-received")
        self.assertIsNotNone(result.introduction)
        self.assertEqual(result.introduction.payload_body, sharing)
        parsed = handle_authenticated_introduction(
            result.introduction, printer=lambda line: None
        )
        self.assertTrue(parsed.parsed)
        self.assertEqual(parsed.introduction.files[0].name, "report.pdf")


class ReceiveSessionIntegrationTests(unittest.TestCase):
    def test_preparsed_introduction_is_reused_without_a_second_parse(self):
        body = introduction_body(extra=blob(2, text_metadata()))
        summary = _summary_for_body(body)
        parsed = handle_authenticated_introduction(
            summary, printer=lambda line: None
        )
        self.assertTrue(parsed.parsed)

        with tempfile.TemporaryDirectory() as temp, patch(
            "vishare_quick.sharing_session.parse_introduction"
        ) as mocked_parse:
            result = run_receive_session(
                ScriptedReader([]),
                CollectingWriter(),
                derive_client_to_server_receive_keys(NEXT_SECRET),
                derive_server_to_client_send_keys(NEXT_SECRET),
                b"synthetic auth string",
                introduction_summary=summary,
                parsed_introduction=parsed.introduction,
                next_inbound_sequence=6,
                next_outbound_sequence=5,
                download_dir=Path(temp),
                prompter=object(),
            )
        mocked_parse.assert_not_called()
        self.assertEqual(result.status, "unsupported-introduction")
        self.assertFalse(result.pin_verified)


class MalformedIntroductionTests(unittest.TestCase):
    def test_malformed_body_is_reported_without_raising(self):
        timeline, lines = _timeline()
        result = handle_authenticated_introduction(
            _summary_for_sharing(b"\x08"), timeline=timeline, printer=lines.append
        )

        self.assertFalse(result.parsed)
        self.assertIsNone(result.introduction)
        self.assertIn("Introduction parse failed", "\n".join(lines))
        timeline_text = "\n".join(lines)
        self.assertIn("INTRODUCTION_PARSE_FAILED", timeline_text)
        self.assertIn("PROTOCOL_ERROR", timeline_text)
        self.assertIn("invalid-payload-structure", timeline_text)

    def test_partial_payload_is_refused_before_parsing(self):
        sharing = sharing_frame(1, introduction_body(files=[file_metadata()]))
        summary = _summary_for_sharing(sharing, complete=False)
        result = handle_authenticated_introduction(summary, printer=lambda line: None)
        self.assertFalse(result.parsed)
        self.assertIn("complete BYTES payload", result.error)

    def test_non_introduction_summary_is_refused(self):
        sharing = sharing_frame(1, introduction_body(files=[file_metadata()]))
        summary = _summary_for_sharing(sharing, sharing_type="PAIRED_KEY_RESULT")
        result = handle_authenticated_introduction(summary, printer=lambda line: None)
        self.assertFalse(result.parsed)
        self.assertIn("not an Introduction", result.error)

    def test_missing_payload_body_is_refused(self):
        summary = _summary_for_sharing(b"")
        summary = AuthenticatedFrameSummary(
            sequence=5,
            offline_type="PAYLOAD_TRANSFER",
            sharing_type="INTRODUCTION",
            payload_transfer=summary.payload_transfer,
            payload_body=None,
        )
        result = handle_authenticated_introduction(summary, printer=lambda line: None)
        self.assertFalse(result.parsed)
        self.assertIn("no payload body", result.error)


class SafeMetadataTests(unittest.TestCase):
    def test_negative_payload_id_is_parsed_and_preserved_by_live_handler(self):
        payload_id = -(1 << 62) - 12345
        body = introduction_body(
            files=[file_metadata(payload_id=payload_id, size=55)]
        )
        result = handle_authenticated_introduction(
            _summary_for_body(body), printer=lambda line: None
        )
        self.assertTrue(result.parsed)
        self.assertEqual(result.introduction.files[0].payload_id, payload_id)

    def test_unsupported_attachment_families_are_reported(self):
        body = introduction_body(
            files=[file_metadata()],
            extra=blob(4, b"") + blob(5, b"") + blob(7, b""),
        )
        lines: list[str] = []
        result = handle_authenticated_introduction(
            _summary_for_body(body), printer=lines.append
        )
        rendered = "\n".join(lines)
        self.assertTrue(result.parsed)
        self.assertFalse(result.introduction.is_supported_file_transfer)
        self.assertIn(
            "unsupported_attachments=wifi_credentials(1),app(1),stream(1)", rendered
        )
        self.assertIn("supported_file_transfer=false", rendered)

    def test_text_only_introduction_is_parsed_but_not_supported(self):
        body = introduction_body(extra=blob(2, text_metadata()))
        lines: list[str] = []
        result = handle_authenticated_introduction(
            _summary_for_body(body), printer=lines.append
        )
        self.assertTrue(result.parsed)
        self.assertEqual(result.introduction.text_entries, 1)
        self.assertFalse(result.introduction.is_supported_file_transfer)
        self.assertIn("unsupported_attachments=text(1)", "\n".join(lines))

    def test_transfer_id_value_is_never_logged(self):
        body = introduction_body(
            files=[file_metadata()],
            extra=blob(10, b"super-secret-transfer-id"),
        )
        timeline, lines = _timeline()
        result = handle_authenticated_introduction(
            _summary_for_body(body), timeline=timeline, printer=lines.append
        )
        self.assertTrue(result.parsed)
        rendered = "\n".join(lines)
        self.assertIn("transfer_id=present", rendered)
        self.assertNotIn("super-secret-transfer-id", rendered)

    def test_filenames_are_redacted_by_default(self):
        body = introduction_body(
            files=[file_metadata(name="secret\nphoto\u202e.jpg")]
        )
        lines: list[str] = []
        handle_authenticated_introduction(
            _summary_for_body(body), printer=lines.append
        )
        rendered = "\n".join(lines)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("photo", rendered)
        self.assertNotIn("\u202e", rendered)

    def test_filename_logging_requires_explicit_opt_in_and_is_sanitized(self):
        body = introduction_body(
            files=[file_metadata(name="secret\nphoto\u202e.jpg")]
        )
        timeline, timeline_lines = _timeline()
        lines: list[str] = []
        handle_authenticated_introduction(
            _summary_for_body(body),
            timeline=timeline,
            log_filenames=True,
            printer=lines.append,
        )
        rendered = "\n".join(lines)
        self.assertIn("secret?photo?.jpg", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("name=secret\n", rendered)
        # The structured timeline never includes filenames, even when console
        # filename logging is explicitly enabled.
        self.assertNotIn("secret", "\n".join(timeline_lines))

    def test_filename_sanitizer_removes_path_separators_and_controls(self):
        rendered = sanitize_filename_for_log("a/b\\c\x1b[31m\u202e.txt")
        self.assertNotIn("/", rendered)
        self.assertNotIn("\\", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("a_b_c", rendered)


class CaptureDefaultTests(unittest.TestCase):
    def test_capture_is_disabled_by_default(self):
        body = introduction_body(files=[file_metadata()])
        with patch(
            "vishare_quick.introduction_diagnostics.save_introduction_capture"
        ) as mocked_save:
            timeline, _lines = _timeline()
            result = handle_authenticated_introduction(
                _summary_for_body(body), timeline=timeline, printer=lambda line: None
            )
        mocked_save.assert_not_called()
        self.assertIsNone(result.capture_path)
        self.assertIsNone(result.capture_error)
        self.assertNotIn(
            "INTRODUCTION_CAPTURED", "\n".join(_lines)
        )

    def test_default_capture_directory_is_predictable(self):
        self.assertEqual(
            resolve_capture_directory(None), DEFAULT_CAPTURE_DIRECTORY.resolve()
        )
        self.assertEqual(
            resolve_capture_directory(""), DEFAULT_CAPTURE_DIRECTORY.resolve()
        )
        self.assertTrue(
            str(DEFAULT_CAPTURE_DIRECTORY).endswith(
                str(Path(".vishare-quick") / "introductions")
            )
        )


class CaptureEnabledTests(unittest.TestCase):
    def test_explicit_capture_saves_exact_body_and_not_the_envelope(self):
        body = introduction_body(
            files=[file_metadata(name="private.txt", payload_id=7, size=12)]
        )
        sharing = sharing_frame(1, body)
        with tempfile.TemporaryDirectory() as temp:
            timeline, lines = _timeline()
            result = handle_authenticated_introduction(
                _summary_for_sharing(sharing),
                timeline=timeline,
                capture_directory=temp,
                printer=lines.append,
            )
            self.assertTrue(result.parsed)
            self.assertIsNotNone(result.capture_path)
            self.assertEqual(
                result.capture_path.parent, Path(temp).resolve()
            )
            self.assertEqual(result.capture_path.read_bytes(), sharing)
            self.assertTrue(
                result.capture_path.name.startswith("introduction-")
            )
            self.assertTrue(result.capture_path.name.endswith(".bin"))
            self.assertIn("INTRODUCTION_CAPTURED", "\n".join(lines))

    def test_malformed_body_can_still_be_captured_for_analysis(self):
        malformed = b"\x08"
        with tempfile.TemporaryDirectory() as temp:
            result = handle_authenticated_introduction(
                _summary_for_sharing(malformed),
                capture_directory=temp,
                printer=lambda line: None,
            )
            self.assertFalse(result.parsed)
            self.assertIsNotNone(result.capture_path)
            self.assertEqual(result.capture_path.read_bytes(), malformed)

    def test_missing_capture_directory_is_created(self):
        body = b"\x08\x01"
        with tempfile.TemporaryDirectory() as temp:
            target_directory = Path(temp) / "nested" / "captures"
            target = save_introduction_capture(
                body, target_directory, filename="capture.bin"
            )
            self.assertEqual(target, target_directory.resolve() / "capture.bin")
            self.assertEqual(target.read_bytes(), body)

    def test_capture_failure_does_not_block_parsing(self):
        body = introduction_body(files=[file_metadata()])
        with tempfile.TemporaryDirectory() as temp:
            not_a_directory = Path(temp) / "file"
            not_a_directory.write_bytes(b"x")
            timeline, lines = _timeline()
            result = handle_authenticated_introduction(
                _summary_for_body(body),
                timeline=timeline,
                capture_directory=not_a_directory,
                printer=lines.append,
            )
        self.assertTrue(result.parsed)
        self.assertIsNone(result.capture_path)
        self.assertIn("not a directory", result.capture_error)
        self.assertIn("INTRODUCTION_CAPTURE_FAILED", "\n".join(lines))


class CapturePathSafetyTests(unittest.TestCase):
    def test_parent_directory_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(IntroductionCaptureError, "must not contain"):
                resolve_capture_directory(Path(temp) / ".." / "escape")

    def test_filename_traversal_is_rejected(self):
        body = b"\x08\x01"
        with tempfile.TemporaryDirectory() as temp:
            for filename in ("../escape.bin", "sub\\escape.bin", "sub/escape.bin"):
                with self.assertRaises(IntroductionCaptureError):
                    save_introduction_capture(body, temp, filename=filename)
            self.assertFalse((Path(temp).parent / "escape.bin").exists())

    def test_control_characters_in_explicit_filename_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(IntroductionCaptureError, "control"):
                save_introduction_capture(b"\x08\x01", temp, filename="bad\nname.bin")

    def test_existing_capture_is_never_overwritten_without_explicit_permission(self):
        body = b"\x08\x01"
        with tempfile.TemporaryDirectory() as temp:
            target = save_introduction_capture(body, temp, filename="capture.bin")
            with self.assertRaisesRegex(IntroductionCaptureError, "already exists"):
                save_introduction_capture(body, temp, filename="capture.bin")
            self.assertEqual(target.read_bytes(), body)

            save_introduction_capture(
                b"\x08\x02", temp, filename="capture.bin", overwrite=True
            )
            self.assertEqual(target.read_bytes(), b"\x08\x02")


class ObservationTests(unittest.TestCase):
    def test_observation_reads_without_sending_and_stops_on_disconnection(self):
        frame = _client_frame(_disconnection_offline(), 6)
        timeline, lines = _timeline()
        result = observe_after_introduction(
            ScriptedReader([frame]),
            derive_client_to_server_receive_keys(NEXT_SECRET),
            6,
            timeline=timeline,
            printer=lines.append,
        )
        self.assertEqual(result.status, "peer-disconnected")
        self.assertEqual(result.frames_observed, 1)
        self.assertEqual(result.next_inbound_sequence, 7)
        self.assertEqual(result.last_offline_type, "DISCONNECTION")
        rendered = "\n".join(lines)
        self.assertIn("Post-Introduction frame 1", rendered)
        self.assertIn("no response sent", rendered)
        self.assertIn("SECURE_MESSAGE", rendered)

    def test_observation_times_out_cleanly(self):
        result = observe_after_introduction(
            ScriptedReader([], timeout_after=True),
            derive_client_to_server_receive_keys(NEXT_SECRET),
            6,
            printer=lambda line: None,
        )
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.frames_observed, 0)
        self.assertEqual(result.next_inbound_sequence, 6)

    def test_observation_authentication_failure_is_bounded(self):
        frame = _client_frame(_keep_alive_offline(), 6)
        timeline, lines = _timeline()
        result = observe_after_introduction(
            ScriptedReader([frame]),
            derive_client_to_server_receive_keys(NEXT_SECRET),
            7,
            timeline=timeline,
            printer=lines.append,
        )
        self.assertEqual(result.status, "authentication-error")
        self.assertEqual(result.frames_observed, 0)
        self.assertEqual(result.next_inbound_sequence, 7)
        self.assertIn("PROTOCOL_ERROR", "\n".join(lines))

    def test_observation_honours_the_frame_limit(self):
        frames = [
            _client_frame(_keep_alive_offline(), 6),
            _client_frame(_keep_alive_offline(), 7),
        ]
        result = observe_after_introduction(
            ScriptedReader(frames),
            derive_client_to_server_receive_keys(NEXT_SECRET),
            6,
            max_frames=1,
            printer=lambda line: None,
        )
        self.assertEqual(result.status, "frame-limit")
        self.assertEqual(result.frames_observed, 1)
        self.assertEqual(result.next_inbound_sequence, 7)

    def test_observation_rejects_non_positive_frame_limit(self):
        with self.assertRaises(ValueError):
            observe_after_introduction(
                ScriptedReader([]),
                derive_client_to_server_receive_keys(NEXT_SECRET),
                6,
                max_frames=0,
            )


if __name__ == "__main__":
    unittest.main()

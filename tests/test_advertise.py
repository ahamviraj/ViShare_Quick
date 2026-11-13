import base64
import unittest
from vishare_quick.advertise import (
    PROGRESS_MIN_STEP_BYTES,
    SERVICE_TYPE,
    AdvertiserControl,
    _emit,
    _human_byte_rate,
    make_endpoint_info,
    make_instance_name,
    make_progress_reporter,
    run_advertiser,
)


class TestAdvertise(unittest.TestCase):
    def test_instance_name_shape(self):
        name, endpoint_id = make_instance_name()
        self.assertEqual(len(endpoint_id), 4)
        self.assertTrue(name.endswith(SERVICE_TYPE))
        payload = name.split(".", 1)[0]
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        self.assertEqual(len(raw), 10)
        self.assertEqual(raw[0], 0x23)
        self.assertEqual(raw[1:5].decode("ascii"), endpoint_id)
        self.assertEqual(raw[5:8], bytes.fromhex("FC9F5E"))
        self.assertEqual(raw[8:10], b"\x00\x00")

    def test_endpoint_info_includes_visible_name(self):
        raw = make_endpoint_info("ViShare Quick")
        self.assertEqual(len(raw[1:17]), 16)
        self.assertEqual(raw[17], len("ViShare Quick".encode("utf-8")))
        self.assertEqual(raw[18:].decode("utf-8"), "ViShare Quick")

    def test_endpoint_info_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            make_endpoint_info("")

    def test_paired_key_response_requires_ukey2_handshake(self):
        with self.assertRaisesRegex(ValueError, "requires --ukey2-handshake"):
            run_advertiser(duration_seconds=1, paired_key_response=True)

    def test_paired_key_response_is_mutually_exclusive(self):
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            run_advertiser(
                duration_seconds=1,
                ukey2_handshake=True,
                paired_key_response=True,
                paired_key_probe=True,
            )
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            run_advertiser(
                duration_seconds=1,
                ukey2_handshake=True,
                paired_key_response=True,
                inspect_encrypted_frame=True,
            )

    def test_protocol_timeline_requires_ukey2_handshake(self):
        with self.assertRaisesRegex(ValueError, "requires --ukey2-handshake"):
            run_advertiser(duration_seconds=1, protocol_timeline=True)

    def test_introduction_diagnostics_require_paired_key_response(self):
        with self.assertRaisesRegex(ValueError, "require --paired-key-response"):
            run_advertiser(
                duration_seconds=1,
                ukey2_handshake=True,
                capture_introduction=True,
            )
        with self.assertRaisesRegex(ValueError, "require --paired-key-response"):
            run_advertiser(
                duration_seconds=1,
                ukey2_handshake=True,
                log_introduction_filenames=True,
            )

    def test_capture_directory_requires_capture_flag(self):
        with self.assertRaisesRegex(ValueError, "requires --capture-introduction"):
            run_advertiser(
                duration_seconds=1,
                ukey2_handshake=True,
                paired_key_response=True,
                capture_introduction_dir="C:\\Temp\\captures",
            )

    def test_capture_directory_rejects_parent_traversal(self):
        # Check both separator styles so the Windows-style path is also rejected
        # when the test suite runs on POSIX, where "\" is not a separator.
        for candidate in ("captures\\..\\escape", "captures/../escape"):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ValueError, "must not contain"):
                    run_advertiser(
                        duration_seconds=1,
                        ukey2_handshake=True,
                        paired_key_response=True,
                        capture_introduction=True,
                        capture_introduction_dir=candidate,
                    )

    def test_invalid_duration_still_rejected(self):
        for duration in (0, -1, 3601):
            with self.subTest(duration=duration):
                with self.assertRaisesRegex(ValueError, "Duration"):
                    run_advertiser(duration_seconds=duration)


class AdvertiserControlTests(unittest.TestCase):
    def test_stop_event_and_active_cancellation(self):
        control = AdvertiserControl()
        cancelled = []
        control.set_active_connection(lambda: cancelled.append("cancel"))
        control.cancel_active_connection()
        self.assertEqual(cancelled, ["cancel"])
        control.request_stop()
        self.assertTrue(control.stop_event.is_set())

        control.set_active_connection(None)
        control.cancel_active_connection()
        self.assertEqual(cancelled, ["cancel"])

    def test_cancellation_ignores_socket_errors(self):
        control = AdvertiserControl()

        def closed_socket():
            raise OSError("already closed")

        control.set_active_connection(closed_socket)
        control.cancel_active_connection()

    def test_observer_faults_never_escape(self):
        events = []
        _emit(events.append, {"type": "ready"})
        self.assertEqual(events, [{"type": "ready"}])

        def broken_observer(event):
            raise RuntimeError("presentation bug")

        _emit(broken_observer, {"type": "ready"})
        _emit(None, {"type": "ready"})


class ProgressReporterTests(unittest.TestCase):
    def _reporter(self):
        lines: list[str] = []
        now = [0.0]
        report = make_progress_reporter(
            printer=lines.append, clock=lambda: now[0]
        )
        return report, lines, now

    def test_small_file_reports_only_completion(self):
        report, lines, _ = self._reporter()
        report(7, 55, 55)
        self.assertEqual(len(lines), 1)
        self.assertIn("55/55 bytes", lines[0])
        self.assertNotIn("7", lines[0])  # payload ID is never rendered

    def test_progress_is_throttled_for_a_multi_gigabyte_file(self):
        report, lines, now = self._reporter()
        total = 2_251_000_000
        chunk = 524_288
        payload_id = -(1 << 62) - 99
        received = 0
        while received < total:
            now[0] += 0.1
            received = min(received + chunk, total)
            report(payload_id, received, total)

        # 20ish updates plus completion, not one per 512 KiB chunk (~4300).
        self.assertLessEqual(len(lines), 25)
        self.assertIn("File transfer complete", lines[-1])
        self.assertIn("MiB/s", lines[-1])
        for line in lines:
            self.assertNotIn(str(payload_id), line)
            self.assertNotIn(str(abs(payload_id)), line)

    def test_completion_is_reported_once(self):
        report, lines, _ = self._reporter()
        report(1, 100, 100)
        report(1, 100, 100)
        self.assertEqual(sum("complete" in line for line in lines), 1)

    def test_every_file_in_a_multi_file_share_gets_a_completion_line(self):
        report, lines, now = self._reporter()
        for payload_id, size in ((11, 398_508), (12, 46), (13, 3_033_256)):
            now[0] += 0.2
            report(payload_id, size, size)
        completions = [line for line in lines if "complete" in line]
        self.assertEqual(len(completions), 3)
        self.assertEqual(
            [line.split(":")[1].split(" bytes")[0].strip() for line in completions],
            ["398508/398508", "46/46", "3033256/3033256"],
        )

    def test_throttling_state_is_independent_per_payload(self):
        report, lines, now = self._reporter()
        now[0] += 0.1
        report(1, PROGRESS_MIN_STEP_BYTES, 10 * PROGRESS_MIN_STEP_BYTES)
        now[0] += 0.1
        report(2, PROGRESS_MIN_STEP_BYTES, 10 * PROGRESS_MIN_STEP_BYTES)
        # Both payloads cross the floor independently.
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("Receiving file" in line for line in lines))

    def test_minimum_step_applies_to_moderate_files(self):
        report, lines, _ = self._reporter()
        total = 3 * PROGRESS_MIN_STEP_BYTES
        report(1, 1024, total)
        self.assertEqual(lines, [])
        report(1, PROGRESS_MIN_STEP_BYTES, total)
        self.assertEqual(len(lines), 1)
        self.assertIn("%", lines[0])

    def test_byte_rate_formatting(self):
        self.assertEqual(_human_byte_rate(0), "0.0 B/s")
        self.assertEqual(_human_byte_rate(2048), "2.0 KiB/s")
        self.assertEqual(_human_byte_rate(3 * 1024 * 1024), "3.0 MiB/s")


if __name__ == "__main__":
    unittest.main()

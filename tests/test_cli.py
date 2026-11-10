import unittest
from io import StringIO
from contextlib import redirect_stdout
from unittest.mock import patch

from vishare_quick import __version__
from vishare_quick.cli import main
from vishare_quick.diagnostics import run_diagnostics


class TestViShareQuickCLI(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, "alpha_0.4-dev")

    def test_diagnostics_include_required_fields(self):
        diagnostics = dict(run_diagnostics())
        self.assertEqual(diagnostics["Application"], "ViShare_Quick")
        self.assertEqual(diagnostics["Version"], "alpha_0.4-dev")
        self.assertIn("Python version", diagnostics)
        self.assertIn("OS family", diagnostics)

    def test_doctor_command(self):
        output = StringIO()
        with redirect_stdout(output):
            result = main(["doctor"])
        self.assertEqual(result, 0)
        self.assertIn("Operating system:", output.getvalue())

    def test_no_command_prints_help(self):
        output = StringIO()
        with redirect_stdout(output):
            result = main([])
        self.assertEqual(result, 0)
        self.assertIn("usage:", output.getvalue())

    @patch("vishare_quick.advertise.run_advertiser")
    def test_advertise_command_preserves_default_and_inspection_option(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["advertise", "--seconds", "1", "--inspect-frames"])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["inspect_frames"])
        self.assertFalse(mocked_advertiser.call_args.kwargs["dump_first_frame_hex"])

    def test_help_lists_existing_commands_and_frame_option(self):
        from vishare_quick.cli import build_parser
        help_text = build_parser().format_help()
        self.assertIn("doctor", help_text)
        self.assertIn("mdns-check", help_text)
        self.assertIn("advertise", help_text)

    def test_advertise_help_describes_opt_in_ukey2_responder(self):
        from vishare_quick.cli import build_parser
        help_text = build_parser()._subparsers._group_actions[0].choices["advertise"].format_help()
        self.assertIn("--ukey2-handshake", help_text)
        self.assertIn("--inspect-encrypted-frame", help_text)
        self.assertIn("--paired-key-probe", help_text)
        self.assertIn("--paired-key-response", help_text)
        self.assertIn("--protocol-timeline", help_text)
        self.assertIn("file transfer", help_text)

    @patch("vishare_quick.advertise.run_advertiser")
    def test_encrypted_frame_inspection_is_explicit_and_requires_handshake(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main([
                "advertise", "--seconds", "1", "--ukey2-handshake", "--inspect-encrypted-frame"
            ])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["ukey2_handshake"])
        self.assertTrue(mocked_advertiser.call_args.kwargs["inspect_encrypted_frame"])

        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main(["advertise", "--seconds", "1", "--inspect-encrypted-frame"])
        self.assertEqual(raised.exception.code, 2)

    @patch("vishare_quick.advertise.run_advertiser")
    def test_paired_key_probe_is_opt_in_requires_handshake_and_is_separate(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([
                "advertise", "--seconds", "1", "--ukey2-handshake", "--paired-key-probe"
            ]), 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["paired_key_probe"])
        self.assertIn("sends no paired-key response", output.getvalue())

        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main(["advertise", "--seconds", "1", "--paired-key-probe"])
        self.assertEqual(raised.exception.code, 2)
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main([
                "advertise", "--seconds", "1", "--ukey2-handshake",
                "--paired-key-probe", "--inspect-encrypted-frame",
            ])
        self.assertEqual(raised.exception.code, 2)

    @patch("vishare_quick.advertise.run_advertiser")
    def test_paired_key_response_is_opt_in_requires_handshake_and_is_separate(
        self, mocked_advertiser
    ):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([
                "advertise", "--seconds", "1", "--ukey2-handshake", "--paired-key-response"
            ]), 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["paired_key_response"])
        self.assertFalse(mocked_advertiser.call_args.kwargs["paired_key_probe"])
        rendered = output.getvalue()
        self.assertIn("no-credential paired-key response", rendered)
        self.assertIn("UNABLE", rendered)

        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main(["advertise", "--seconds", "1", "--paired-key-response"])
        self.assertEqual(raised.exception.code, 2)
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main([
                "advertise", "--seconds", "1", "--ukey2-handshake",
                "--paired-key-response", "--paired-key-probe",
            ])
        self.assertEqual(raised.exception.code, 2)
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main([
                "advertise", "--seconds", "1", "--ukey2-handshake",
                "--paired-key-response", "--inspect-encrypted-frame",
            ])
        self.assertEqual(raised.exception.code, 2)

    @patch("vishare_quick.advertise.run_advertiser")
    def test_ukey2_handshake_mode_is_explicit_and_separate_from_inspection(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["advertise", "--seconds", "1", "--ukey2-handshake"])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["ukey2_handshake"])
        self.assertIn("sends a protocol response", output.getvalue())

    @patch("vishare_quick.advertise.run_advertiser")
    def test_protocol_timeline_is_opt_in_requires_handshake(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main([
                "advertise", "--seconds", "1", "--ukey2-handshake",
                "--paired-key-response", "--protocol-timeline",
            ])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["protocol_timeline"])
        self.assertTrue(mocked_advertiser.call_args.kwargs["paired_key_response"])

        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main(["advertise", "--seconds", "1", "--protocol-timeline"])
        self.assertEqual(raised.exception.code, 2)

    @patch("vishare_quick.advertise.run_advertiser")
    def test_hex_dump_option_enables_inspection_and_is_opt_in(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["advertise", "--seconds", "1", "--dump-first-frame-hex"])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["inspect_frames"])
        self.assertTrue(mocked_advertiser.call_args.kwargs["dump_first_frame_hex"])

    @patch("vishare_quick.advertise.run_advertiser")
    def test_indexed_hex_dump_option_selects_second_frame(self, mocked_advertiser):
        mocked_advertiser.return_value = {
            "instance_name": "instance", "endpoint_id": "abcd", "local_ip": "127.0.0.1",
            "port": 1234, "tcp_connections": 0,
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["advertise", "--seconds", "1", "--dump-frame-hex-index", "2"])
        self.assertEqual(result, 0)
        self.assertTrue(mocked_advertiser.call_args.kwargs["inspect_frames"])
        self.assertEqual(mocked_advertiser.call_args.kwargs["dump_frame_hex_index"], 2)

    @patch("vishare_quick.cli.probe_mdns")
    def test_mdns_check_command(self, mocked_probe):
        mocked_probe.return_value = {
            "duration_seconds": 8.0, "services_seen": 0, "services": [],
            "service_type": "_FC9F5ED42C8A._tcp.local.", "note": "test note",
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["mdns-check", "--seconds", "8"])
        self.assertEqual(result, 0)
        self.assertIn("Services observed: 0", output.getvalue())

    @patch("vishare_quick.cli.probe_mdns")
    def test_mdns_check_prints_resolved_service_details(self, mocked_probe):
        mocked_probe.return_value = {
            "duration_seconds": 8.0, "services_seen": 1,
            "services": [{
                "name": "example._FC9F5ED42C8A._tcp.local.", "resolved": True,
                "addresses": ["192.168.43.42"], "port": 12345, "server": "example.local.",
                "txt_records": {"n": "sample-metadata"},
                "resolution_note": "Service details resolved from mDNS.",
            }],
            "service_type": "_FC9F5ED42C8A._tcp.local.", "note": "test note",
        }
        output = StringIO()
        with redirect_stdout(output):
            result = main(["mdns-check", "--seconds", "8"])
        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("192.168.43.42", rendered)
        self.assertIn("TCP port: 12345", rendered)
        self.assertIn("n=sample-metadata", rendered)


if __name__ == "__main__":
    unittest.main()

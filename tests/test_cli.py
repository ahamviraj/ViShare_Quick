import unittest
from io import StringIO
from contextlib import redirect_stdout
from unittest.mock import patch

from vishare_quick import __version__
from vishare_quick.cli import main
from vishare_quick.diagnostics import run_diagnostics


class TestViShareQuickCLI(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, "alpha_0.3-dev")

    def test_diagnostics_include_required_fields(self):
        diagnostics = dict(run_diagnostics())
        self.assertEqual(diagnostics["Application"], "ViShare_Quick")
        self.assertEqual(diagnostics["Version"], "alpha_0.3-dev")
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

import unittest
from io import StringIO
from contextlib import redirect_stdout

from vishare_quick import __version__
from vishare_quick.cli import main
from vishare_quick.diagnostics import run_diagnostics


class TestViShareQuickCLI(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, "alpha_0.1")

    def test_diagnostics_include_required_fields(self):
        diagnostics = dict(run_diagnostics())
        self.assertEqual(diagnostics["Application"], "ViShare_Quick")
        self.assertEqual(diagnostics["Version"], "alpha_0.1")
        self.assertIn("Python version", diagnostics)
        self.assertIn("OS family", diagnostics)

    def test_doctor_command(self):
        output = StringIO()
        with redirect_stdout(output):
            result = main(["doctor"])
        self.assertEqual(result, 0)
        self.assertIn("Operating system:", output.getvalue())
        self.assertIn("not implemented", output.getvalue())

    def test_no_command_prints_help(self):
        output = StringIO()
        with redirect_stdout(output):
            result = main([])
        self.assertEqual(result, 0)
        self.assertIn("usage:", output.getvalue())


if __name__ == "__main__":
    unittest.main()

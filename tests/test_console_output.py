"""Interactive-prompt console coordination tests.

The receive session prints protocol diagnostics from its keep-alive thread
while the prompting thread is blocked in ``input()``. On Windows that write can
split the typed line and submit a partial answer, so diagnostics must be
buffered for the duration of a prompt.
"""
from __future__ import annotations

import threading
import unittest

from vishare_quick.consent import ConsentRequest, ConsolePrompter, FileOffer
from vishare_quick.console_output import MAX_BUFFERED_LINES, ConsoleGate


class GateTests(unittest.TestCase):
    def test_diagnostics_are_buffered_during_a_prompt_and_flushed_after(self):
        lines: list[str] = []
        gate = ConsoleGate(output=lines.append)

        with gate.paused():
            gate.write("[+1.000s] OUT  KEEP_ALIVE")
            gate.write("[+2.000s] OUT  KEEP_ALIVE")
            self.assertEqual(lines, [])

        self.assertEqual(
            lines,
            ["[+1.000s] OUT  KEEP_ALIVE", "[+2.000s] OUT  KEEP_ALIVE"],
        )

    def test_outside_a_prompt_diagnostics_print_immediately(self):
        lines: list[str] = []
        gate = ConsoleGate(output=lines.append)
        gate.write("immediate")
        self.assertEqual(lines, ["immediate"])

    def test_background_writer_does_not_block_on_an_open_prompt(self):
        lines: list[str] = []
        gate = ConsoleGate(output=lines.append)
        writing = threading.Event()

        def background() -> None:
            gate.write("keep-alive")
            writing.set()

        with gate.paused():
            thread = threading.Thread(target=background, daemon=True)
            thread.start()
            # The writer must finish while the prompt is still open.
            self.assertTrue(writing.wait(2.0))
            thread.join(2.0)
            self.assertEqual(lines, [])

        self.assertEqual(lines, ["keep-alive"])

    def test_prompt_and_typed_answer_are_never_split(self):
        """Simulate the exact failure: a diagnostic arriving mid-answer."""
        transcript: list[str] = []
        gate = ConsoleGate(output=lambda line: transcript.append("LOG " + line))
        observed: list[str] = []

        def fake_input(prompt: str) -> str:
            # The user sees the prompt, then a keep-alive fires before Enter.
            observed.append("PROMPT " + prompt)
            gate.write("KEEP_ALIVE ack=false")
            observed.append("ANSWER 0059")
            return "0059"

        prompter = ConsolePrompter(
            input_fn=fake_input,
            output=lambda line: observed.append("OUT " + line),
            gate=gate,
        )
        self.assertEqual(prompter.ask_pin("0059"), "0059")

        # No log line may appear between the prompt and the answer.
        self.assertEqual(
            observed[-2:],
            ["PROMPT Type the 4-digit PIN shown on Android (blank to reject): ",
             "ANSWER 0059"],
        )
        self.assertEqual(transcript, ["LOG KEEP_ALIVE ack=false"])

    def test_consent_prompt_also_holds_the_gate(self):
        transcript: list[str] = []
        gate = ConsoleGate(output=transcript.append)
        seen: list[str] = []

        def fake_input(_prompt: str) -> str:
            gate.write("KEEP_ALIVE ack=false")
            seen.append("asked")
            return "1"

        prompter = ConsolePrompter(
            input_fn=fake_input, output=lambda line: None, gate=gate
        )
        request = ConsentRequest(
            pin="0059",
            files=(
                FileOffer(
                    payload_id=7,
                    name="note.txt",
                    size=12,
                    mime_type="text/plain",
                    type_name="DOCUMENT",
                ),
            ),
            total_size=12,
            identity_verified=False,
            transfer_id=None,
        )
        self.assertTrue(prompter.request_consent(request))
        self.assertEqual(seen, ["asked"])
        self.assertEqual(transcript, ["KEEP_ALIVE ack=false"])

    def test_buffer_is_bounded(self):
        lines: list[str] = []
        gate = ConsoleGate(output=lines.append)
        with gate.paused():
            for index in range(MAX_BUFFERED_LINES + 5):
                gate.write(f"line {index}")

        self.assertEqual(len(lines), MAX_BUFFERED_LINES + 1)
        self.assertEqual(lines[0], "line 0")
        self.assertIn("omitted while prompting", lines[-1])

    def test_printer_failure_is_never_fatal(self):
        def broken(_line: str) -> None:
            raise RuntimeError("synthetic printer failure")

        gate = ConsoleGate(output=broken)
        gate.write("before")
        with gate.paused():
            gate.write("during")

    def test_timeline_default_printer_is_gated(self):
        from vishare_quick.console_output import console_gate
        from vishare_quick.protocol_timeline import ProtocolTimeline

        self.assertEqual(ProtocolTimeline.printer, console_gate.write)


if __name__ == "__main__":
    unittest.main()

"""Serialize background diagnostics around interactive prompts.

The receive session runs an unsolicited keep-alive sender, and the protocol
timeline is printed from that background thread. The prompting thread blocks in
``input()``. If a diagnostic line is printed then, it lands inside the typed
line; on Windows the injected newline can even submit the partial answer, which
is indistinguishable from the user typing a wrong PIN.

Diagnostics are therefore buffered for the duration of a prompt and flushed
afterwards. Prompt text itself is written by the prompting thread and is never
buffered. A background writer only takes the lock for the few microseconds it
needs to append to (or print) one line, so it never blocks on the human.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator

# Bounded so a prompt left open for hours cannot grow without limit. Keep-alive
# lines arrive about every five seconds, so this holds well over half an hour.
MAX_BUFFERED_LINES = 512


class ConsoleGate:
    """Buffer diagnostic lines while a prompt owns the console."""

    def __init__(self, output: Callable[[str], None] = print) -> None:
        self._output = output
        self._lock = threading.Lock()
        self._depth = 0
        self._pending: list[str] = []
        self._dropped = 0

    # ---------------------------------------------------------- diagnostics
    def write(self, line: str) -> None:
        """Print one diagnostic line, or buffer it while a prompt is open."""
        with self._lock:
            if self._depth:
                if len(self._pending) < MAX_BUFFERED_LINES:
                    self._pending.append(line)
                else:
                    self._dropped += 1
                return
            self._emit(line)

    def _emit(self, line: str) -> None:
        try:
            self._output(line)
        except Exception:
            # A diagnostic printer must never take down the protocol stage.
            pass

    # --------------------------------------------------------------- prompts
    @contextmanager
    def paused(self) -> Iterator[None]:
        """Hold diagnostics while a blocking prompt is on screen."""
        with self._lock:
            self._depth += 1
        pending: list[str] = []
        dropped = 0
        try:
            yield
        finally:
            with self._lock:
                self._depth -= 1
                if self._depth == 0:
                    pending, self._pending = self._pending, []
                    dropped, self._dropped = self._dropped, 0
        for line in pending:
            self._emit(line)
        if dropped:
            self._emit(
                f"... {dropped} protocol diagnostic line(s) omitted while prompting"
            )


console_gate = ConsoleGate()

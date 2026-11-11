"""Explicit user consent and protocol-valid sharing-layer responses.

After the sender's authenticated ``IntroductionFrame``, the receiving side
answers with a sharing ``Frame`` of type ``RESPONSE`` whose
``ConnectionResponseFrame.status`` is one of the documented values:

    1 ACCEPT
    2 REJECT
    3 NOT_ENOUGH_SPACE
    4 UNSUPPORTED_ATTACHMENT_TYPE
    5 TIMED_OUT

NearDrop, NearShare, and squick-share all send exactly ``status`` (no OS info,
no attachment map) inside a BYTES payload, then wait for FILE payloads. None of
them accepts on the user's behalf: each asks a human first. This module keeps
that property. There is deliberately no API that returns ACCEPT without an
explicit positive decision from the injected prompter.
"""
from __future__ import annotations

import sys
from contextlib import nullcontext
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol

from vishare_quick.console_output import ConsoleGate, console_gate
from vishare_quick.protocol import _encode_bytes_field, _encode_varint_field

RESPONSE_UNKNOWN = 0
RESPONSE_ACCEPT = 1
RESPONSE_REJECT = 2
RESPONSE_NOT_ENOUGH_SPACE = 3
RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE = 4
RESPONSE_TIMED_OUT = 5

_RESPONSE_STATUSES = frozenset(
    {
        RESPONSE_UNKNOWN,
        RESPONSE_ACCEPT,
        RESPONSE_REJECT,
        RESPONSE_NOT_ENOUGH_SPACE,
        RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE,
        RESPONSE_TIMED_OUT,
    }
)

RESPONSE_STATUS_NAMES = {
    RESPONSE_UNKNOWN: "UNKNOWN",
    RESPONSE_ACCEPT: "ACCEPT",
    RESPONSE_REJECT: "REJECT",
    RESPONSE_NOT_ENOUGH_SPACE: "NOT_ENOUGH_SPACE",
    RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE: "UNSUPPORTED_ATTACHMENT_TYPE",
    RESPONSE_TIMED_OUT: "TIMED_OUT",
}

# OfflineFrame V1Frame DISCONNECTION has type 6 and body field 7.
_DISCONNECTION_BODY_FIELD = 7


class ConsentError(Exception):
    """A locally invalid consent decision or response status."""


class ConsentDecision(Enum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass(frozen=True)
class FileOffer:
    """One file as presented to the local user, already sanitized for display."""

    payload_id: int
    name: str
    size: int
    mime_type: str
    type_name: str = "UNKNOWN"


@dataclass(frozen=True)
class ConsentRequest:
    """Everything the local user needs before deciding, and nothing secret."""

    pin: str
    files: tuple[FileOffer, ...]
    total_size: int
    identity_verified: bool = False
    transfer_id: str | None = None

    @property
    def identity_note(self) -> str:
        return (
            "paired-key identity verified"
            if self.identity_verified
            else "paired-key identity NOT verified (PAIRED_KEY_RESULT UNABLE); "
            "the PIN is the only out-of-band check"
        )


class Prompter(Protocol):
    """Injected human interface. Implementations must never auto-accept."""

    def ask_pin(self, code: str) -> str | None:
        """Show the local code and return the code the user read on the sender.

        Returning ``None`` means the user rejected or could not confirm.
        """

    def request_consent(self, request: ConsentRequest) -> bool:
        """Return True only after an explicit positive local decision."""


class ConsolePrompter:
    """Interactive terminal prompter with no defaults that accept.

    If stdin is unavailable (EOF) or not a terminal, both methods decline. A
    scripted or backgrounded run therefore fails closed.
    """

    def __init__(
        self,
        input_fn: Callable[[str], str] | None = None,
        output: Callable[[str], None] | None = None,
        gate: ConsoleGate | None = None,
    ) -> None:
        self._input = input_fn or input
        self._output = output or print
        self._require_tty = input_fn is None
        if gate is not None:
            self._gate: ConsoleGate | None = gate
        elif input_fn is None and output is None:
            # Production terminal: buffer the background protocol timeline so
            # its keep-alive lines cannot land inside the typed answer.
            self._gate = console_gate
        else:
            self._gate = None

    def _paused(self):
        return self._gate.paused() if self._gate is not None else nullcontext()

    def _read(self, prompt: str) -> str | None:
        if self._require_tty and not is_interactive_terminal():
            return None
        try:
            return self._input(prompt)
        except (EOFError, KeyboardInterrupt):
            return None

    def ask_pin(self, code: str) -> str | None:
        with self._paused():
            self._output("")
            self._output("Quick Share PIN verification")
            self._output(
                "Both devices derive this code from the authenticated UKEY2 handshake."
            )
            self._output(f"Local protocol code: {code}")
            self._output(
                "Compare it with the PIN shown on the Android device. Do not continue "
                "if the codes differ or you did not initiate/expect this transfer."
            )
            entered = self._read(
                "Type the 4-digit PIN shown on Android (blank to reject): "
            )
            if entered is None or not entered.strip():
                return None
            return entered

    def request_consent(self, request: ConsentRequest) -> bool:
        with self._paused():
            self._output("")
            self._output("Incoming Quick Share request")
            self._output(f"Identity: {request.identity_note}")
            if request.transfer_id:
                self._output(f"Transfer ID: {request.transfer_id}")
            self._output(f"PIN: {request.pin}")
            self._output(f"Files: {len(request.files)}")
            for index, item in enumerate(request.files, start=1):
                self._output(
                    f"  {index}. {item.name} — {item.size} bytes — {item.mime_type}"
                )
            self._output(f"Total size: {request.total_size} bytes")
            self._output("1. Accept")
            self._output("2. Reject")
            answer = self._read("Choice (accept only with 1/accept/yes): ")
            if answer is None:
                return False
            return answer.strip().lower() in {"1", "accept", "a", "yes", "y"}


def build_connection_response_frame(status: int) -> bytes:
    """Build the sharing ``Frame`` carrying a ``ConnectionResponseFrame``.

    Only the documented status enum is emitted. The caller wraps this in the
    authenticated BYTES payload schedule (DATA + LAST_CHUNK).
    """
    if not isinstance(status, int) or isinstance(status, bool) or status not in _RESPONSE_STATUSES:
        raise ConsentError("Unsupported ConnectionResponseFrame status.")
    body = _encode_varint_field(1, status)
    v1 = _encode_varint_field(1, 2) + _encode_bytes_field(3, body)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def build_cancel_frame() -> bytes:
    """Build the sharing ``V1Frame`` type ``CANCEL``.

    The published schema defines only the type enum value 6; it has no
    ``cancel`` body field. NearDrop's sender likewise sets ``v1.type = .cancel``
    and nothing else, so an extra field here would be a progress update on the
    wire rather than a cancellation.
    """
    v1 = _encode_varint_field(1, 6)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def build_disconnection_frame() -> bytes:
    """Build an authenticated OfflineFrame DISCONNECTION (type 6, body field 7)."""
    v1 = _encode_varint_field(1, 6) + _encode_bytes_field(_DISCONNECTION_BODY_FIELD, b"")
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def is_interactive_terminal() -> bool:
    """True only for a real interactive prompt; used by the CLI refusal path."""
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False

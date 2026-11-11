"""Four-digit Quick Share verification code derived from the UKEY2 token.

Protocol evidence
-----------------
Google's ``sharing/share_session.cc`` converts the raw Nearby Connections
authentication token into the user-visible code:

    std::string TokenToFourDigitString(const std::vector<uint8_t>& bytes) {
      constexpr int kHashModulo = 9973;
      constexpr int kHashBaseMultiplier = 31;
      int hash = 0;
      int multiplier = 1;
      for (uint8_t byte : bytes) {
        // Java bytes are signed two's complement ...
        hash = (hash + static_cast<int8_t>(byte) * multiplier) % kHashModulo;
        multiplier = (multiplier * kHashBaseMultiplier) % kHashModulo;
      }
      return absl::StrFormat("%04d", std::abs(hash));
    }

NearDrop implements the same function over its UKEY2 ``authString``
(``pinCodeFromAuthKey``), and NearShare exposes the derived value as
``D2DCipher.pin`` while telling the receiver to compare it with the PIN shown
on the phone. Google's own unit test uses the token ``{0, 1, 2}`` and expects
``"1953"``.

Consequently the code is *not* random, application-chosen, or a paired-key
value. It is a deterministic 4-digit encoding of the 32-byte UKEY2
``auth_string`` this project already derives. Both endpoints compute it
locally; no PIN is sent on the wire. The sender's screen and the receiver's
screen must show the same value for a human to compare.

The comparison is intentionally a human action. ``PinVerification`` never
approves itself and never treats ``PAIRED_KEY_RESULT UNABLE`` as identity
proof.
"""
from __future__ import annotations

import hmac

HASH_MODULO = 9973
HASH_BASE_MULTIPLIER = 31
AUTH_TOKEN_LENGTH = 32


class PinVerificationError(Exception):
    """The local PIN verification state machine was used incorrectly."""


def _truncating_remainder(value: int, modulus: int) -> int:
    """Match C++/Java ``%`` semantics (the sign follows the dividend)."""
    remainder = abs(value) % modulus
    return -remainder if value < 0 else remainder


def four_digit_code(auth_string: bytes) -> str:
    """Return the protocol-defined four-digit code for a UKEY2 auth string.

    ``auth_string`` is the 32-byte ``HandshakeSecrets.auth_string`` produced by
    ``ukey2.Ukey2ServerHandshake``. The conversion is byte-for-byte identical to
    Google's ``TokenToFourDigitString`` (signed bytes, truncating remainder,
    modulo 9973, base multiplier 31, zero-padded to four digits).
    """
    if not isinstance(auth_string, (bytes, bytearray, memoryview)):
        raise TypeError("UKEY2 auth token must be bytes.")
    data = bytes(auth_string)
    if not data:
        raise ValueError("UKEY2 auth token must not be empty.")
    hash_value = 0
    multiplier = 1
    for value in data:
        signed = value - 256 if value >= 128 else value
        hash_value = _truncating_remainder(
            hash_value + signed * multiplier, HASH_MODULO
        )
        multiplier = (multiplier * HASH_BASE_MULTIPLIER) % HASH_MODULO
    return f"{abs(hash_value):04d}"


def normalize_entered_pin(value: str) -> str:
    """Keep only ASCII digits; the protocol code is exactly four of them."""
    if not isinstance(value, str):
        raise TypeError("Entered PIN must be text.")
    return "".join(character for character in value if "0" <= character <= "9")


class PinVerification:
    """Explicit, non-automatic comparison of the derived four-digit code.

    States: ``pending`` -> ``succeeded`` or ``failed``. There is no transition
    that marks the code verified without a caller-supplied value that equals
    the derived code. A blank value is treated as a rejection by the CLI layer,
    not as acceptance here.
    """

    def __init__(self, auth_string: bytes) -> None:
        if not isinstance(auth_string, (bytes, bytearray, memoryview)):
            raise TypeError("UKEY2 auth token must be bytes.")
        if len(bytes(auth_string)) != AUTH_TOKEN_LENGTH:
            raise ValueError(
                f"UKEY2 auth token must be {AUTH_TOKEN_LENGTH} bytes, "
                f"got {len(bytes(auth_string))}."
            )
        self._code = four_digit_code(auth_string)
        self.state = "pending"

    @property
    def code(self) -> str:
        """The code both devices must display; safe to show to the local user."""
        return self._code

    @property
    def is_pending(self) -> bool:
        return self.state == "pending"

    def verify(self, entered: str) -> bool:
        """Compare a user-entered code in constant time and record the result."""
        if self.state != "pending":
            raise PinVerificationError(
                "PIN verification has already reached a terminal state."
            )
        candidate = normalize_entered_pin(entered)
        if len(candidate) != 4:
            self.state = "failed"
            return False
        matched = hmac.compare_digest(candidate, self._code)
        self.state = "succeeded" if matched else "failed"
        return matched

    def reject(self) -> None:
        """Record an explicit user rejection without attempting a comparison."""
        if self.state != "pending":
            raise PinVerificationError(
                "PIN verification has already reached a terminal state."
            )
        self.state = "failed"

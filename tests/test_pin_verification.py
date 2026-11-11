"""Protocol-derived tests for the four-digit UKEY2 verification code."""
from __future__ import annotations

import unittest

from vishare_quick.pin_verification import (
    AUTH_TOKEN_LENGTH,
    PinVerification,
    PinVerificationError,
    four_digit_code,
    normalize_entered_pin,
)


class FourDigitCodeTests(unittest.TestCase):
    def test_google_unit_test_vector(self):
        # share_session.cc's TokenToFourDigitString test uses {0, 1, 2} and
        # expects "1953".
        self.assertEqual(four_digit_code(bytes([0, 1, 2])), "1953")

    def test_signed_byte_semantics(self):
        # 0x80 is -128 as a Java/C++ signed byte. The truncating remainder
        # keeps the negative sign and the final abs() yields 128.
        self.assertEqual(four_digit_code(bytes([0x80])), "0128")
        self.assertEqual(four_digit_code(bytes([0xFF])), "0001")

    def test_multiplier_is_modular(self):
        self.assertEqual(four_digit_code(bytes([0x80, 0x01])), "0097")

    def test_zero_padding(self):
        self.assertEqual(four_digit_code(bytes([0x00] * 31 + [0x01])), "0830")
        self.assertEqual(len(four_digit_code(bytes(range(32)))), 4)

    def test_deterministic(self):
        token = bytes(range(32))
        self.assertEqual(four_digit_code(token), four_digit_code(token))

    def test_rejects_non_bytes_and_empty(self):
        with self.assertRaises(TypeError):
            four_digit_code("not-bytes")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            four_digit_code(b"")


class NormalizeEnteredPinTests(unittest.TestCase):
    def test_keeps_only_ascii_digits(self):
        self.assertEqual(normalize_entered_pin(" 12-34 "), "1234")
        self.assertEqual(normalize_entered_pin("１２３４"), "")

    def test_rejects_non_text(self):
        with self.assertRaises(TypeError):
            normalize_entered_pin(1234)  # type: ignore[arg-type]


class PinVerificationTests(unittest.TestCase):
    def setUp(self):
        self.token = bytes(range(32))
        self.code = four_digit_code(self.token)

    def test_starts_pending_and_exposes_only_the_derived_code(self):
        verification = PinVerification(self.token)
        self.assertTrue(verification.is_pending)
        self.assertEqual(verification.state, "pending")
        self.assertEqual(verification.code, self.code)

    def test_correct_code_succeeds(self):
        verification = PinVerification(self.token)
        self.assertTrue(verification.verify(self.code))
        self.assertEqual(verification.state, "succeeded")
        self.assertFalse(verification.is_pending)

    def test_correct_code_with_surrounding_text_succeeds(self):
        verification = PinVerification(self.token)
        self.assertTrue(verification.verify(f"PIN {self.code}!"))

    def test_wrong_code_fails(self):
        wrong = "0000" if self.code != "0000" else "0001"
        verification = PinVerification(self.token)
        self.assertFalse(verification.verify(wrong))
        self.assertEqual(verification.state, "failed")

    def test_blank_and_short_codes_fail(self):
        for value in ("", "   ", "123", "12345"):
            with self.subTest(value=value):
                verification = PinVerification(self.token)
                self.assertFalse(verification.verify(value))
                self.assertEqual(verification.state, "failed")

    def test_explicit_rejection_fails_without_comparison(self):
        verification = PinVerification(self.token)
        verification.reject()
        self.assertEqual(verification.state, "failed")

    def test_terminal_state_cannot_be_reused(self):
        verification = PinVerification(self.token)
        verification.verify(self.code)
        with self.assertRaises(PinVerificationError):
            verification.verify(self.code)
        with self.assertRaises(PinVerificationError):
            verification.reject()

    def test_no_auto_approval_path(self):
        # Constructing or merely reading the code must never verify it.
        for _ in range(16):
            verification = PinVerification(self.token)
            self.assertEqual(verification.state, "pending")
            _ = verification.code
            self.assertEqual(verification.state, "pending")

    def test_auth_token_length_is_enforced_by_the_verifier(self):
        with self.assertRaises(ValueError):
            PinVerification(b"short")
        with self.assertRaises(ValueError):
            PinVerification(b"\x00" * (AUTH_TOKEN_LENGTH + 1))


if __name__ == "__main__":
    unittest.main()

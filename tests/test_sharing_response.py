"""Schema-derived tests for safe ``ConnectionResponseFrame`` inspection.

Field numbers follow the authoritative ``sharing/proto/wire_format.proto``:

* ``status`` = 1 (enum, int32 semantics)
* ``attachment_details`` = 2 (``map<int64, AttachmentDetails>``)
* ``stream_metadata`` = 3 (repeated ``StreamMetadata``)

The fixtures are synthetic and contain no captured peer data. Map keys,
attachment details, and stream metadata are counted only; the parser and the
safe renderer must never expose their values.
"""
from __future__ import annotations

import unittest

from vishare_quick.secure_channel import (
    ConnectionResponseMetadata,
    SecureChannelError,
    _parse_offline_frame,
)
from vishare_quick.sharing_response import (
    connection_response_status_name,
    describe_connection_response,
)
from test_secure_channel import blob, vint, vint_signed


def sharing_response(
    status: int | None = 1,
    *,
    attachment_details: tuple[bytes, ...] = (),
    stream_metadata: tuple[bytes, ...] = (),
    unknown: bytes = b"",
) -> bytes:
    """Build a sharing ``Frame`` whose V1Frame type is RESPONSE (2)."""
    body = b"" if status is None else vint(1, status)
    for entry in attachment_details:
        body += blob(2, entry)
    for entry in stream_metadata:
        body += blob(3, entry)
    body += unknown
    return vint(1, 1) + blob(2, vint(1, 2) + blob(3, body))


def wrap_complete_bytes(sharing: bytes, *, payload_id: int = 9) -> bytes:
    """Wrap a sharing frame in a complete BYTES PAYLOAD_TRANSFER."""
    header = vint(1, payload_id) + vint(2, 1) + vint(3, len(sharing))
    chunk = vint(2, 0) + blob(3, sharing)
    transfer = vint(1, 1) + blob(2, header) + blob(3, chunk)
    return vint(1, 1) + blob(2, vint(1, 3) + blob(4, transfer))


def attachment_entry(key: int, *, attachment_type: int = 1) -> bytes:
    """One map entry: key=key, value=AttachmentDetails{type=attachment_type}."""
    if key < 0:
        encoded_key = vint_signed(1, key)
    else:
        encoded_key = vint(1, key)
    return encoded_key + blob(2, vint(1, attachment_type))


class ConnectionResponseParsingTests(unittest.TestCase):
    def _parse(self, sharing: bytes):
        return _parse_offline_frame(wrap_complete_bytes(sharing))

    def test_all_documented_statuses_are_decoded(self):
        for status in range(6):
            parsed = self._parse(sharing_response(status))
            self.assertEqual(parsed.sharing_type, "RESPONSE")
            self.assertIsNotNone(parsed.connection_response)
            self.assertEqual(parsed.connection_response.status, status)

    def test_absent_status_is_reported_as_none(self):
        parsed = self._parse(sharing_response(status=None))
        self.assertIsNotNone(parsed.connection_response)
        self.assertIsNone(parsed.connection_response.status)
        self.assertEqual(
            connection_response_status_name(parsed.connection_response.status),
            "absent",
        )

    def test_future_status_value_is_preserved_as_enum(self):
        parsed = self._parse(sharing_response(7))
        self.assertEqual(parsed.connection_response.status, 7)
        self.assertEqual(connection_response_status_name(7), "enum7")

    def test_attachment_details_are_counted_not_decoded(self):
        parsed = self._parse(
            sharing_response(
                attachment_details=(
                    attachment_entry(0),
                    attachment_entry(-123456789),
                )
            )
        )
        self.assertEqual(parsed.connection_response.attachment_details_count, 2)

    def test_stream_metadata_is_counted(self):
        parsed = self._parse(
            sharing_response(stream_metadata=(b"", b"\x08\x01"))
        )
        self.assertEqual(parsed.connection_response.stream_metadata_count, 2)

    def test_unknown_fields_are_reported_by_number(self):
        parsed = self._parse(sharing_response(unknown=vint(9, 1) + blob(10, b"x")))
        self.assertEqual(
            parsed.connection_response.unknown_field_numbers, (9, 10)
        )

    def test_duplicate_status_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "exactly once"):
            self._parse(sharing_response(1, unknown=vint(1, 2)))

    def test_wrong_status_wire_type_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "wire type"):
            self._parse(sharing_response(status=None, unknown=blob(1, b"x")))

    def test_wrong_attachment_details_wire_type_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "wire type"):
            self._parse(sharing_response(1, unknown=vint(2, 1)))

    def test_wrong_stream_metadata_wire_type_is_rejected(self):
        with self.assertRaisesRegex(SecureChannelError, "wire type"):
            self._parse(sharing_response(1, unknown=vint(3, 1)))


class ConnectionResponseDescriptionTests(unittest.TestCase):
    def test_description_contains_status_and_counts_only(self):
        metadata = ConnectionResponseMetadata(
            status=1,
            attachment_details_count=1,
            stream_metadata_count=0,
            unknown_field_numbers=(9,),
        )
        rendered = describe_connection_response(metadata)
        self.assertEqual(
            rendered,
            "status=ACCEPT; attachment_details=1; "
            "stream_metadata=0; unknown_fields=1",
        )

    def test_description_never_renders_attachment_hash_values(self):
        key = -123456789
        parsed = _parse_offline_frame(
            wrap_complete_bytes(
                sharing_response(attachment_details=(attachment_entry(key),))
            )
        )
        rendered = describe_connection_response(parsed.connection_response)
        self.assertIn("status=ACCEPT", rendered)
        self.assertIn("attachment_details=1", rendered)
        self.assertNotIn(str(key), rendered)
        self.assertNotIn(str(key & ((1 << 64) - 1)), rendered)

    def test_missing_metadata_is_reported_without_raw_values(self):
        rendered = describe_connection_response(None)
        self.assertIn("status=not-parsed", rendered)
        self.assertIn("attachment_details=unknown", rendered)


if __name__ == "__main__":
    unittest.main()

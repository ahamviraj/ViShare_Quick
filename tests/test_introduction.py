"""Schema-derived tests for the bounded Introduction parser.

Fixtures are hand-encoded from Google's published
``sharing/proto/wire_format.proto``. They are synthetic, not captured Android
traffic. Field numbers and wire types below follow the schema exactly:
``FileMetadata`` uses plain ``int64`` (not ``sint64`` or ``uint64``) for
``payload_id``, ``size``, ``id``, and ``attachment_hash``, so negative values
use protobuf's ten-byte two's-complement varint.

Negative payload IDs are valid identifiers: the schema declares ``int64``,
NearDrop's sender chooses from the full ``Int64.min...Int64.max`` range, and
squick-share only rejects duplicate IDs or negative sizes. XPad captures show
real negative IDs on wire, so the parser must preserve their exact signed value.
"""
from __future__ import annotations

import unittest

from vishare_quick.introduction import (
    MAX_DECLARED_TOTAL_BYTES,
    MAX_FILES,
    MAX_MIME_LENGTH,
    MAX_NAME_LENGTH,
    MAX_PREVIEW_IDS,
    IntroductionError,
    parse_introduction,
)
from test_secure_channel import blob, varint, vint, vint_signed


_SHARING_BODY_FIELDS = {1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 7: 7, 8: 8}


def sharing_frame(type_id: int, body: bytes) -> bytes:
    """Frame{version=1, v1=V1Frame{type, body}} using the schema field numbers.

    Body field numbers are not ``type + 1`` for every type: ``progress_update``
    is field 7 (same number as its type), and ``CANCEL`` (6) has no body field.
    """
    v1 = vint(1, type_id)
    if type_id == 6:
        if body:
            raise ValueError("CANCEL has no body field.")
    else:
        # Unknown type numbers are intentionally passed through as type+1 so
        # callers can assert that the parser rejects them.
        v1 += blob(_SHARING_BODY_FIELDS.get(type_id, type_id + 1), body)
    return vint(1, 1) + blob(2, v1)


def file_metadata(
    *,
    name: str | None = "photo.jpg",
    file_type: int | None = 1,
    payload_id: int | None = 7,
    size: int | None = 1234,
    mime_type: str | None = "image/jpeg",
    attachment_id: int | None = None,
    parent_folder: str | None = None,
    attachment_hash: int | None = None,
    sensitive: bool | int | None = None,
    extra: bytes = b"",
) -> bytes:
    parts = bytearray()
    if name is not None:
        parts += blob(1, name.encode("utf-8"))
    if file_type is not None:
        parts += vint(2, file_type)
    if payload_id is not None:
        parts += vint_signed(3, payload_id) if payload_id < 0 else vint(3, payload_id)
    if size is not None:
        parts += vint_signed(4, size) if size < 0 else vint(4, size)
    if mime_type is not None:
        parts += blob(5, mime_type.encode("utf-8"))
    if attachment_id is not None:
        parts += vint(6, attachment_id)
    if parent_folder is not None:
        parts += blob(7, parent_folder.encode("utf-8"))
    if attachment_hash is not None:
        parts += vint(8, attachment_hash)
    if sensitive is not None:
        parts += vint(9, int(sensitive))
    return bytes(parts) + extra


def text_metadata(
    *,
    title: str | None = "hello",
    text_type: int | None = 1,
    payload_id: int | None = 9,
    size: int | None = 5,
    extra: bytes = b"",
) -> bytes:
    parts = bytearray()
    if title is not None:
        parts += blob(2, title.encode("utf-8"))
    if text_type is not None:
        parts += vint(3, text_type)
    if payload_id is not None:
        parts += vint_signed(4, payload_id) if payload_id < 0 else vint(4, payload_id)
    if size is not None:
        parts += vint_signed(5, size) if size < 0 else vint(5, size)
    return bytes(parts) + extra


def introduction_body(*, files: list[bytes] | None = None, extra: bytes = b"") -> bytes:
    body = b"".join(blob(1, item) for item in (files or []))
    return body + extra


class ValidIntroductionTests(unittest.TestCase):
    def test_file_metadata_all_documented_fields(self):
        body = introduction_body(
            files=[
                file_metadata(
                    name="Cookbook.pdf",
                    file_type=5,
                    payload_id=42,
                    size=987654,
                    mime_type="application/pdf",
                    attachment_id=123,
                    parent_folder="Recipes",
                    attachment_hash=456,
                    sensitive=True,
                )
            ],
            extra=(
                blob(3, b"com.example.app")
                + vint(6, 1)
                + vint(8, 1)
                + blob(10, b"transfer-abc")
                + vint(11, 1)
                + vint(12, 1)
                + vint(9, 42)
            ),
        )
        parsed = parse_introduction(sharing_frame(1, body))

        self.assertEqual(len(parsed.files), 1)
        item = parsed.files[0]
        self.assertEqual(item.name, "Cookbook.pdf")
        self.assertEqual(item.file_type, 5)
        self.assertEqual(item.type_name, "DOCUMENT")
        self.assertEqual(item.payload_id, 42)
        self.assertEqual(item.size, 987654)
        self.assertEqual(item.mime_type, "application/pdf")
        self.assertEqual(item.attachment_id, 123)
        self.assertEqual(item.parent_folder, "Recipes")
        self.assertEqual(item.attachment_hash, 456)
        self.assertTrue(item.is_sensitive_content)
        self.assertEqual(item.unknown_field_numbers, ())

        self.assertEqual(parsed.total_size, 987654)
        self.assertEqual(parsed.required_package, "com.example.app")
        self.assertTrue(parsed.start_transfer)
        self.assertEqual(parsed.use_case, 1)
        self.assertEqual(parsed.transfer_id, "transfer-abc")
        self.assertTrue(parsed.continuation)
        self.assertTrue(parsed.expect_more)
        self.assertEqual(parsed.preview_payload_ids, (42,))
        self.assertTrue(parsed.is_supported_file_transfer)

    def test_optional_fields_use_schema_defaults(self):
        body = introduction_body(
            files=[file_metadata(name=None, file_type=None, mime_type=None)]
        )
        parsed = parse_introduction(sharing_frame(1, body))

        item = parsed.files[0]
        self.assertEqual(item.name, "")
        self.assertEqual(item.file_type, 0)
        self.assertEqual(item.type_name, "UNKNOWN")
        self.assertEqual(item.mime_type, "application/octet-stream")
        self.assertIsNone(item.attachment_id)
        self.assertIsNone(item.parent_folder)
        self.assertIsNone(item.attachment_hash)
        self.assertFalse(item.is_sensitive_content)
        self.assertIsNone(parsed.required_package)
        self.assertFalse(parsed.start_transfer)
        self.assertEqual(parsed.use_case, 0)
        self.assertIsNone(parsed.transfer_id)
        self.assertFalse(parsed.continuation)
        self.assertFalse(parsed.expect_more)
        self.assertEqual(parsed.preview_payload_ids, ())

    def test_multiple_files_and_total_size(self):
        body = introduction_body(
            files=[
                file_metadata(name="a", payload_id=1, size=10),
                file_metadata(name="b", payload_id=2, size=20),
                file_metadata(name="c", payload_id=3, size=0),
            ]
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual([item.payload_id for item in parsed.files], [1, 2, 3])
        self.assertEqual(parsed.total_size, 30)

    def test_unknown_enum_values_are_preserved_for_forward_compatibility(self):
        body = introduction_body(
            files=[file_metadata(file_type=99)],
            extra=vint(8, 42),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].file_type, 99)
        self.assertEqual(parsed.files[0].type_name, "enum99")
        self.assertEqual(parsed.use_case, 42)


class PreviewPayloadIdEncodingTests(unittest.TestCase):
    """``repeated int64`` must accept unpacked and packed protobuf encodings."""

    def test_unpacked_preview_ids(self):
        body = introduction_body(
            files=[file_metadata(payload_id=7)],
            extra=vint(9, 7) + vint(9, 8) + vint(9, 9),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, (7, 8, 9))

    def test_packed_preview_ids(self):
        # A packed repeated int64 field carries one length-delimited field whose
        # payload is the concatenation of the individual varints.
        body = introduction_body(
            files=[file_metadata(payload_id=7)],
            extra=blob(9, b"".join(varint(value) for value in (7, 8, 9))),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, (7, 8, 9))

    def test_mixed_packed_and_unpacked_preview_ids(self):
        body = introduction_body(
            files=[file_metadata(payload_id=7)],
            extra=vint(9, 7) + blob(9, varint(8) + varint(9)),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, (7, 8, 9))

    def test_empty_packed_preview_ids_are_accepted(self):
        body = introduction_body(files=[file_metadata()], extra=blob(9, b""))
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, ())

    def test_malformed_packed_varint_is_rejected(self):
        body = introduction_body(files=[file_metadata()], extra=blob(9, b"\x80"))
        with self.assertRaisesRegex(IntroductionError, "malformed packed varint"):
            parse_introduction(sharing_frame(1, body))

    def test_packed_negative_int64_is_preserved(self):
        # -1 as a plain int64 is the ten-byte two's-complement varint.
        body = introduction_body(
            files=[file_metadata(payload_id=7)],
            extra=blob(9, varint((1 << 64) - 1)),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, (-1,))

    def test_negative_preview_ids_in_both_encodings_are_preserved(self):
        packed = varint((1 << 64) - 2)
        body = introduction_body(
            files=[file_metadata(payload_id=7)],
            extra=vint_signed(9, -1) + blob(9, packed),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.preview_payload_ids, (-1, -2))


class UnknownFieldTests(unittest.TestCase):
    def test_unknown_numbers_are_retained_without_values(self):
        # Field 10 (varint) and 11 (bytes) are not in the published
        # FileMetadata schema; field 13 is not in IntroductionFrame.
        body = introduction_body(
            files=[file_metadata(extra=vint(10, 7) + blob(11, b"private"))],
            extra=vint(13, 1),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].unknown_field_numbers, (10, 11))
        self.assertEqual(parsed.unknown_field_numbers, (13,))

    def test_unknown_only_body_is_an_empty_introduction(self):
        parsed = parse_introduction(sharing_frame(1, vint(13, 1)))
        self.assertEqual(parsed.files, ())
        self.assertEqual(parsed.unknown_field_numbers, (13,))
        self.assertFalse(parsed.is_supported_file_transfer)


class EmptyIntroductionTests(unittest.TestCase):
    def test_empty_introduction_frame(self):
        parsed = parse_introduction(sharing_frame(1, b""))
        self.assertEqual(parsed.files, ())
        self.assertEqual(parsed.text_entries, 0)
        self.assertEqual(parsed.total_size, 0)
        self.assertFalse(parsed.is_supported_file_transfer)

    def test_empty_outer_frame_is_rejected(self):
        with self.assertRaises(IntroductionError):
            parse_introduction(b"")


class NonIntroductionTests(unittest.TestCase):
    def test_response_frame_is_rejected(self):
        with self.assertRaisesRegex(IntroductionError, "Expected an INTRODUCTION"):
            parse_introduction(sharing_frame(2, vint(1, 1)))

    def test_unsupported_outer_type_is_rejected(self):
        with self.assertRaises(IntroductionError):
            parse_introduction(sharing_frame(99, b""))

    def test_conflicting_outer_body_is_rejected(self):
        # V1Frame type=INTRODUCTION (1) but both body fields 2 and 3 set.
        v1 = vint(1, 1) + blob(2, b"") + blob(3, b"")
        with self.assertRaises(IntroductionError):
            parse_introduction(vint(1, 1) + blob(2, v1))


class MalformedProtobufTests(unittest.TestCase):
    def test_truncated_outer_frame(self):
        with self.assertRaises(IntroductionError):
            parse_introduction(b"\x08")

    def test_truncated_body_field(self):
        with self.assertRaises(IntroductionError):
            parse_introduction(sharing_frame(1, b"\x0a\x05ab"))

    def test_wrong_wire_type_for_payload_id(self):
        body = introduction_body(
            files=[blob(3, b"not-an-int") + vint(4, 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "wire type"):
            parse_introduction(sharing_frame(1, body))

    def test_duplicate_scalar_field_is_rejected(self):
        body = introduction_body(
            files=[vint(3, 1) + vint(3, 2) + vint(4, 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "exactly once"):
            parse_introduction(sharing_frame(1, body))

    def test_non_boolean_value_is_rejected(self):
        body = introduction_body(files=[file_metadata(sensitive=2)])
        with self.assertRaisesRegex(IntroductionError, "boolean"):
            parse_introduction(sharing_frame(1, body))

    def test_invalid_utf8_name_is_rejected(self):
        body = introduction_body(
            files=[blob(1, b"\xff\xfe") + vint(3, 1) + vint(4, 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "not valid UTF-8"):
            parse_introduction(sharing_frame(1, body))

    def test_invalid_utf8_required_package_is_rejected(self):
        body = introduction_body(files=[file_metadata()], extra=blob(3, b"\xff"))
        with self.assertRaisesRegex(IntroductionError, "not valid UTF-8"):
            parse_introduction(sharing_frame(1, body))


class SizeAndCountLimitTests(unittest.TestCase):
    def test_implementation_name_length_limit(self):
        body = introduction_body(
            files=[file_metadata(name="a" * (MAX_NAME_LENGTH + 1))]
        )
        with self.assertRaisesRegex(IntroductionError, "exceeding"):
            parse_introduction(sharing_frame(1, body))

    def test_implementation_mime_length_limit(self):
        body = introduction_body(
            files=[file_metadata(mime_type="x" * (MAX_MIME_LENGTH + 1))]
        )
        with self.assertRaisesRegex(IntroductionError, "exceeding"):
            parse_introduction(sharing_frame(1, body))

    def test_implementation_file_count_limit(self):
        body = introduction_body(
            files=[
                file_metadata(name="f", payload_id=index, size=0)
                for index in range(MAX_FILES + 1)
            ]
        )
        with self.assertRaisesRegex(IntroductionError, "exceeding"):
            parse_introduction(sharing_frame(1, body))

    def test_implementation_single_file_size_limit(self):
        body = introduction_body(
            files=[file_metadata(size=MAX_DECLARED_TOTAL_BYTES + 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "local bound"):
            parse_introduction(sharing_frame(1, body))

    def test_implementation_total_size_limit(self):
        body = introduction_body(
            files=[
                file_metadata(payload_id=1, size=(MAX_DECLARED_TOTAL_BYTES // 2) + 1),
                file_metadata(payload_id=2, size=(MAX_DECLARED_TOTAL_BYTES // 2) + 1),
            ]
        )
        with self.assertRaisesRegex(IntroductionError, "total-size bound"):
            parse_introduction(sharing_frame(1, body))

    def test_implementation_preview_id_limit(self):
        body = introduction_body(
            files=[file_metadata()],
            extra=b"".join(vint(9, index) for index in range(MAX_PREVIEW_IDS + 1)),
        )
        with self.assertRaisesRegex(IntroductionError, "preview"):
            parse_introduction(sharing_frame(1, body))


class InvalidIdentifierAndSizeTests(unittest.TestCase):
    def test_missing_payload_id_is_rejected(self):
        body = introduction_body(files=[file_metadata(payload_id=None)])
        with self.assertRaisesRegex(IntroductionError, "payload_id is required"):
            parse_introduction(sharing_frame(1, body))

    def test_missing_size_is_rejected(self):
        body = introduction_body(files=[file_metadata(size=None)])
        with self.assertRaisesRegex(IntroductionError, "size is required"):
            parse_introduction(sharing_frame(1, body))

    def test_negative_size_is_rejected(self):
        body = introduction_body(files=[file_metadata(size=-1)])
        with self.assertRaisesRegex(IntroductionError, "negative"):
            parse_introduction(sharing_frame(1, body))

    def test_out_of_range_payload_id_varint_is_rejected(self):
        # A ten-byte varint can encode a mathematical value above 2**64 - 1;
        # such a value is not a valid signed or unsigned int64.
        body = introduction_body(
            files=[vint(3, (1 << 64) + 1) + vint(4, 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "64-bit"):
            parse_introduction(sharing_frame(1, body))

    def test_malformed_payload_id_varint_is_rejected(self):
        body = introduction_body(
            files=[vint(3, 1)[:1] + b"\x80" * 10 + vint(4, 1)]
        )
        with self.assertRaisesRegex(IntroductionError, "Malformed"):
            parse_introduction(sharing_frame(1, body))

    def test_duplicate_file_payload_id_is_rejected(self):
        # squick-share rejects an introduction entry whose payload ID is already
        # in its outstanding set; the receiver's ID map would otherwise be
        # ambiguous.
        body = introduction_body(
            files=[
                file_metadata(name="a", payload_id=1),
                file_metadata(name="b", payload_id=1),
            ]
        )
        with self.assertRaisesRegex(IntroductionError, "repeats a file payload_id"):
            parse_introduction(sharing_frame(1, body))


class SignedPayloadIdTests(unittest.TestCase):
    """Signed int64 payload IDs are protocol identifiers, not unsigned values."""

    def test_negative_payload_id_is_preserved(self):
        body = introduction_body(files=[file_metadata(payload_id=-1)])
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].payload_id, -1)

    def test_typical_android_negative_payload_id_is_preserved(self):
        # Nine-byte two's-complement varint, the shape emitted by the XPad.
        payload_id = -(1 << 62) - 12345
        body = introduction_body(
            files=[vint_signed(3, payload_id) + vint(4, 55)]
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].payload_id, payload_id)

    def test_minimum_signed_int64_payload_id_is_preserved(self):
        minimum = -(1 << 63)
        body = introduction_body(
            files=[vint_signed(3, minimum) + vint(4, 1)]
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].payload_id, minimum)

    def test_maximum_signed_int64_payload_id_is_preserved(self):
        maximum = (1 << 63) - 1
        body = introduction_body(files=[vint(3, maximum) + vint(4, 1)])
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files[0].payload_id, maximum)

    def test_mixed_positive_and_negative_payload_ids_keep_order_and_sign(self):
        identifiers = [-1, 2, -(1 << 62), (1 << 62)]
        body = introduction_body(
            files=[
                file_metadata(name=f"f{index}", payload_id=value, size=index)
                for index, value in enumerate(identifiers)
            ]
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(
            [item.payload_id for item in parsed.files], identifiers
        )

    def test_positive_and_negative_same_magnitude_are_distinct(self):
        body = introduction_body(
            files=[
                file_metadata(name="negative", payload_id=-1),
                file_metadata(name="positive", payload_id=1),
            ],
            extra=blob(2, text_metadata(payload_id=2)),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(
            [item.payload_id for item in parsed.files], [-1, 1]
        )
        self.assertEqual(parsed.text_entries, 1)

    def test_duplicate_negative_payload_id_is_rejected(self):
        body = introduction_body(
            files=[
                file_metadata(name="a", payload_id=-7),
                file_metadata(name="b", payload_id=-7),
            ]
        )
        with self.assertRaisesRegex(IntroductionError, "repeats a file payload_id"):
            parse_introduction(sharing_frame(1, body))

    def test_negative_text_payload_id_is_preserved(self):
        body = introduction_body(extra=blob(2, text_metadata(payload_id=-9)))
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.text_entries, 1)

    def test_duplicate_negative_text_payload_id_is_rejected(self):
        body = introduction_body(
            extra=blob(2, text_metadata(payload_id=-9))
            + blob(2, text_metadata(payload_id=-9))
        )
        with self.assertRaisesRegex(IntroductionError, "duplicated"):
            parse_introduction(sharing_frame(1, body))

    def test_file_and_text_negative_payload_id_collision_is_rejected(self):
        body = introduction_body(
            files=[file_metadata(payload_id=-9)],
            extra=blob(2, text_metadata(payload_id=-9)),
        )
        with self.assertRaisesRegex(IntroductionError, "file and text"):
            parse_introduction(sharing_frame(1, body))


class TextIntroductionTests(unittest.TestCase):
    def test_text_only_introduction_parses_but_is_not_supported(self):
        body = introduction_body(extra=blob(2, text_metadata()))
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.files, ())
        self.assertEqual(parsed.text_entries, 1)
        self.assertFalse(parsed.is_supported_file_transfer)

    def test_text_missing_payload_id_is_rejected(self):
        body = introduction_body(extra=blob(2, text_metadata(payload_id=None)))
        with self.assertRaisesRegex(IntroductionError, "payload_id is required"):
            parse_introduction(sharing_frame(1, body))

    def test_text_negative_size_is_rejected(self):
        body = introduction_body(extra=blob(2, text_metadata(size=-1)))
        with self.assertRaisesRegex(IntroductionError, "negative"):
            parse_introduction(sharing_frame(1, body))

    def test_duplicate_text_payload_id_is_rejected(self):
        body = introduction_body(
            extra=blob(2, text_metadata(payload_id=5)) + blob(2, text_metadata(payload_id=5))
        )
        with self.assertRaisesRegex(IntroductionError, "duplicated"):
            parse_introduction(sharing_frame(1, body))

    def test_file_and_text_payload_id_collision_is_rejected(self):
        body = introduction_body(
            files=[file_metadata(payload_id=5)],
            extra=blob(2, text_metadata(payload_id=5)),
        )
        with self.assertRaisesRegex(IntroductionError, "file and text"):
            parse_introduction(sharing_frame(1, body))

    def test_unsupported_attachment_families_are_counted_and_rejected(self):
        body = introduction_body(
            files=[file_metadata()],
            extra=blob(4, b"") + blob(5, b"") + blob(7, b""),
        )
        parsed = parse_introduction(sharing_frame(1, body))
        self.assertEqual(parsed.wifi_credentials_entries, 1)
        self.assertEqual(parsed.app_entries, 1)
        self.assertEqual(parsed.stream_entries, 1)
        self.assertFalse(parsed.is_supported_file_transfer)


if __name__ == "__main__":
    unittest.main()

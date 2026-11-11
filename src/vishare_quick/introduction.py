"""Bounded parsing of the authenticated Quick Share ``IntroductionFrame``.

Schema
------
``sharing/proto/wire_format.proto`` defines the sending side's introduction:

    message IntroductionFrame {
      repeated FileMetadata file_metadata = 1;
      repeated TextMetadata text_metadata = 2;
      optional string required_package = 3;
      repeated WifiCredentialsMetadata wifi_credentials_metadata = 4;
      repeated AppMetadata app_metadata = 5;
      optional bool start_transfer = 6;
      repeated StreamMetadata stream_metadata = 7;
      optional SharingUseCase use_case = 8;
      repeated int64 preview_payload_ids = 9;
      optional string transfer_id = 10;
      optional bool continuation = 11;
      optional bool expect_more = 12;
    }

    message FileMetadata {
      optional string name = 1;
      optional Type type = 2;
      optional int64 payload_id = 3;
      optional int64 size = 4;
      optional string mime_type = 5;
      optional int64 id = 6;
      optional string parent_folder = 7;
      optional int64 attachment_hash = 8;
      optional bool is_sensitive_content = 9;
    }

Parsing is deliberately split from presentation. Unknown fields are retained
as field numbers (never values) so a newer sender does not break the parser and
so diagnostics can say that unknown data was present. Peer-supplied names,
MIME types, and folders remain untrusted text; destination names are sanitized
separately in :mod:`vishare_quick.file_transfer`.

``payload_id`` and ``preview_payload_ids`` are signed ``int64`` identifiers.
Android may emit negative values (NearDrop's sender picks from the full
``Int64.min...Int64.max`` range, and XPad captures confirm negative IDs), so the
parser preserves the exact signed value and never applies ``abs()`` or unsigned
reinterpretation. Sizes remain non-negative lengths.
"""
from __future__ import annotations

from dataclasses import dataclass

from vishare_quick.protocol import (
    DEFAULT_MAX_FRAME_LENGTH,
    MalformedFrame,
    _Field,
    _varint,
)
from vishare_quick.secure_channel import (
    SecureChannelError,
    _one,
    _parse,
    _signed_int64,
    parse_sharing_frame_envelope,
)

# Bounds are local policy, not schema limits. They keep a hostile Introduction
# from turning into unbounded per-entry work or pathological UI output.
MAX_FILES = 1000
MAX_TEXT_ENTRIES = 1000
MAX_DECLARED_TOTAL_BYTES = 1 << 40  # 1 TiB
MAX_NAME_LENGTH = 4096
MAX_MIME_LENGTH = 255
MAX_FOLDER_LENGTH = 1024
MAX_PACKAGE_LENGTH = 512
MAX_TRANSFER_ID_LENGTH = 256
MAX_PREVIEW_IDS = 1000

FILE_TYPES = {
    0: "UNKNOWN",
    1: "IMAGE",
    2: "VIDEO",
    3: "ANDROID_APP",
    4: "AUDIO",
    5: "DOCUMENT",
    6: "CONTACT_CARD",
}
USE_CASES = {0: "UNKNOWN", 1: "NEARBY_SHARE", 2: "REMOTE_COPY", 9: "TAP_TO_SHARE", 10: "FILE_SYNC"}

_KNOWN_INTRODUCTION_FIELDS = frozenset(range(1, 13))
_KNOWN_FILE_FIELDS = frozenset(range(1, 10))
_KNOWN_TEXT_FIELDS = frozenset(range(2, 9))


class IntroductionError(SecureChannelError):
    """Authenticated Introduction content is malformed or exceeds local bounds."""

    error_category = "invalid-payload-structure"


@dataclass(frozen=True)
class FileMetadata:
    name: str
    file_type: int
    payload_id: int
    size: int
    mime_type: str
    attachment_id: int | None = None
    parent_folder: str | None = None
    attachment_hash: int | None = None
    is_sensitive_content: bool = False
    unknown_field_numbers: tuple[int, ...] = ()

    @property
    def type_name(self) -> str:
        return FILE_TYPES.get(self.file_type, f"enum{self.file_type}")


@dataclass(frozen=True)
class Introduction:
    files: tuple[FileMetadata, ...]
    text_entries: int = 0
    wifi_credentials_entries: int = 0
    app_entries: int = 0
    stream_entries: int = 0
    required_package: str | None = None
    start_transfer: bool = False
    use_case: int = 0
    transfer_id: str | None = None
    continuation: bool = False
    expect_more: bool = False
    preview_payload_ids: tuple[int, ...] = ()
    unknown_field_numbers: tuple[int, ...] = ()

    @property
    def total_size(self) -> int:
        return sum(item.size for item in self.files)

    @property
    def is_supported_file_transfer(self) -> bool:
        """Only plain file attachments are implemented by this receiver.

        Text, Wi-Fi credentials, apps, and streams have different payload
        semantics and are explicitly rejected rather than guessed at.
        """
        return (
            bool(self.files)
            and self.text_entries == 0
            and self.wifi_credentials_entries == 0
            and self.app_entries == 0
            and self.stream_entries == 0
        )


def _decode_utf8(raw: bytes, label: str, max_length: int) -> str:
    if len(raw) > max_length:
        raise IntroductionError(
            f"{label} is {len(raw)} bytes, exceeding the {max_length}-byte bound."
        )
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntroductionError(f"{label} is not valid UTF-8.") from exc


def _optional_string(
    fields: dict[int, list[_Field]], number: int, label: str, max_length: int
) -> str | None:
    raw = _one(fields, number, 2, label, required=False)
    if raw is None:
        return None
    if not isinstance(raw, bytes):
        raise IntroductionError(f"{label} is malformed.")
    return _decode_utf8(raw, label, max_length)


def _optional_int64(
    fields: dict[int, list[_Field]], number: int, label: str
) -> int | None:
    raw = _one(fields, number, 0, label, required=False)
    if raw is None:
        return None
    return _signed_int64(raw, label, fields)


def _optional_bool(
    fields: dict[int, list[_Field]], number: int, label: str
) -> bool:
    value = _optional_int64(fields, number, label)
    if value is None:
        return False
    if value not in (0, 1):
        raise IntroductionError(f"{label} is not a boolean value.")
    return bool(value)


def _repeated_messages(
    fields: dict[int, list[_Field]], number: int, label: str
) -> list[bytes]:
    entries = fields.get(number, [])
    result: list[bytes] = []
    for entry in entries:
        if entry.wire != 2 or not isinstance(entry.value, bytes):
            raise IntroductionError(f"{label} entry has the wrong protobuf wire type.")
        result.append(entry.value)
    return result


def _repeated_int64(
    fields: dict[int, list[_Field]], number: int, label: str
) -> list[int]:
    """Decode a repeated int64 field in unpacked or packed wire form.

    ``preview_payload_ids`` is declared as proto2 ``repeated int64`` without an
    explicit ``[packed=true]``. Conforming senders emit one varint per field,
    but protobuf parsers are required to accept the packed form too. Both are
    therefore decoded here; each value uses plain int64 (two's complement)
    semantics, not ``sint64`` or ``uint64``.
    """
    values: list[int] = []
    for entry in fields.get(number, []):
        if entry.wire == 0 and isinstance(entry.value, int):
            values.append(_signed_int64(entry.value, label, fields))
            continue
        if entry.wire == 2 and isinstance(entry.value, bytes):
            position = 0
            while position < len(entry.value):
                try:
                    raw, position = _varint(entry.value, position)
                except MalformedFrame as exc:
                    raise IntroductionError(
                        f"{label} contains a malformed packed varint."
                    ) from exc
                values.append(_signed_int64(raw, label, fields))
            continue
        raise IntroductionError(f"{label} entry is malformed.")
    return values


def _parse_file_metadata(data: bytes, index: int) -> FileMetadata:
    label = f"Introduction file_metadata[{index}]"
    fields = _parse(data, label)
    name = _optional_string(fields, 1, f"{label}.name", MAX_NAME_LENGTH) or ""
    raw_type = _optional_int64(fields, 2, f"{label}.type")
    file_type = 0 if raw_type is None else raw_type
    if file_type < 0 or file_type > (1 << 31) - 1:
        raise IntroductionError(f"{label}.type is outside the signed 32-bit range.")
    raw_payload_id = _one(fields, 3, 0, f"{label}.payload_id", required=False)
    if raw_payload_id is None:
        raise IntroductionError(f"{label}.payload_id is required.")
    # ``payload_id`` is a signed int64. Android generates IDs across the full
    # int64 range (NearDrop's sender uses Int64.min...Int64.max), so a negative
    # value is valid protocol data, not a malformed unsigned magnitude. Keep the
    # exact signed value for later payload matching; never take abs() or
    # reinterpret it as uint64.
    payload_id = _signed_int64(raw_payload_id, f"{label}.payload_id", fields)
    raw_size = _one(fields, 4, 0, f"{label}.size", required=False)
    if raw_size is None:
        raise IntroductionError(f"{label}.size is required.")
    size = _signed_int64(raw_size, f"{label}.size", fields)
    if size < 0:
        raise IntroductionError(f"{label}.size is negative.")
    if size > MAX_DECLARED_TOTAL_BYTES:
        raise IntroductionError(
            f"{label}.size exceeds the {MAX_DECLARED_TOTAL_BYTES}-byte local bound."
        )
    mime_type = (
        _optional_string(fields, 5, f"{label}.mime_type", MAX_MIME_LENGTH)
        or "application/octet-stream"
    )
    attachment_id = _optional_int64(fields, 6, f"{label}.id")
    parent_folder = _optional_string(
        fields, 7, f"{label}.parent_folder", MAX_FOLDER_LENGTH
    )
    attachment_hash = _optional_int64(fields, 8, f"{label}.attachment_hash")
    sensitive = _optional_bool(fields, 9, f"{label}.is_sensitive_content")
    unknown = tuple(
        sorted(number for number in fields if number not in _KNOWN_FILE_FIELDS)
    )
    return FileMetadata(
        name=name,
        file_type=file_type,
        payload_id=payload_id,
        size=size,
        mime_type=mime_type,
        attachment_id=attachment_id,
        parent_folder=parent_folder,
        attachment_hash=attachment_hash,
        is_sensitive_content=sensitive,
        unknown_field_numbers=unknown,
    )


def _text_payload_ids(
    fields: dict[int, list[_Field]],
) -> tuple[set[int], int]:
    """Validate text entries enough to detect payload-ID collisions.

    Text transfer itself is not implemented, but a text entry must still be
    structurally sane so an introduction cannot smuggle a duplicate ID past the
    file map.
    """
    entries = _repeated_messages(fields, 2, "Introduction text_metadata")
    if len(entries) > MAX_TEXT_ENTRIES:
        raise IntroductionError(
            f"Introduction has {len(entries)} text entries, exceeding "
            f"the {MAX_TEXT_ENTRIES}-entry bound."
        )
    ids: set[int] = set()
    total = 0
    for index, data in enumerate(entries):
        label = f"Introduction text_metadata[{index}]"
        item = _parse(data, label)
        raw_payload_id = _one(item, 4, 0, f"{label}.payload_id", required=False)
        if raw_payload_id is None:
            raise IntroductionError(f"{label}.payload_id is required.")
        # Text payload IDs share the same signed int64 identifier space as file
        # payload IDs, so negative values are preserved exactly.
        payload_id = _signed_int64(raw_payload_id, f"{label}.payload_id", item)
        if payload_id in ids:
            raise IntroductionError(f"{label}.payload_id is duplicated.")
        ids.add(payload_id)
        raw_size = _one(item, 5, 0, f"{label}.size", required=False)
        size = 0 if raw_size is None else _signed_int64(raw_size, f"{label}.size", item)
        if size < 0:
            raise IntroductionError(f"{label}.size is negative.")
        total += size
        if total > MAX_DECLARED_TOTAL_BYTES:
            raise IntroductionError(
                "Introduction text sizes exceed the local declared-size bound."
            )
        unknown = [number for number in item if number not in _KNOWN_TEXT_FIELDS]
        if unknown:
            # Unknown text fields are tolerated; the entry is not accepted for
            # transfer anyway. No value is inspected or logged.
            pass
    return ids, len(entries)


def parse_introduction(sharing_frame: bytes) -> Introduction:
    """Parse an authenticated sharing ``Frame`` whose ``V1Frame`` is INTRODUCTION.

    ``sharing_frame`` is the complete decrypted BYTES payload body. The caller
    must already have authenticated the enclosing SecureMessage and verified
    that the sharing type is ``INTRODUCTION``.
    """
    if not isinstance(sharing_frame, (bytes, bytearray, memoryview)):
        raise TypeError("sharing_frame must be bytes.")
    data = bytes(sharing_frame)
    if not data:
        raise IntroductionError("Introduction sharing Frame is empty.")
    if len(data) > DEFAULT_MAX_FRAME_LENGTH:
        raise IntroductionError("Introduction sharing Frame exceeds the parser size limit.")
    try:
        name, body = parse_sharing_frame_envelope(data)
        if name != "INTRODUCTION":
            raise IntroductionError(f"Expected an INTRODUCTION frame, got {name}.")
        fields = _parse(body, "IntroductionFrame")
        return _parse_introduction_fields(fields)
    except IntroductionError:
        raise
    except SecureChannelError as exc:
        raise IntroductionError(str(exc)) from exc


def _parse_introduction_fields(fields: dict[int, list[_Field]]) -> Introduction:
    file_entries = _repeated_messages(fields, 1, "Introduction file_metadata")
    if len(file_entries) > MAX_FILES:
        raise IntroductionError(
            f"Introduction has {len(file_entries)} files, exceeding the "
            f"{MAX_FILES}-file local bound."
        )
    files = tuple(
        _parse_file_metadata(data, index)
        for index, data in enumerate(file_entries)
    )

    text_ids, text_count = _text_payload_ids(fields)
    file_ids = [item.payload_id for item in files]
    if len(set(file_ids)) != len(file_ids):
        raise IntroductionError("Introduction repeats a file payload_id.")
    if set(file_ids) & text_ids:
        raise IntroductionError("Introduction reuses a payload_id for file and text content.")

    total = sum(item.size for item in files)
    if total > MAX_DECLARED_TOTAL_BYTES:
        raise IntroductionError(
            "Introduction declared file sizes exceed the local total-size bound."
        )

    wifi_entries = _repeated_messages(
        fields, 4, "Introduction wifi_credentials_metadata"
    )
    app_entries = _repeated_messages(fields, 5, "Introduction app_metadata")
    stream_entries = _repeated_messages(fields, 7, "Introduction stream_metadata")
    if len(wifi_entries) > MAX_FILES or len(app_entries) > MAX_FILES or len(stream_entries) > MAX_FILES:
        raise IntroductionError("Introduction contains too many unsupported attachments.")

    required_package = _optional_string(
        fields, 3, "Introduction required_package", MAX_PACKAGE_LENGTH
    )
    start_transfer = _optional_bool(fields, 6, "Introduction start_transfer")
    raw_use_case = _optional_int64(fields, 8, "Introduction use_case")
    use_case = 0 if raw_use_case is None else raw_use_case
    if use_case < 0 or use_case > (1 << 31) - 1:
        raise IntroductionError("Introduction use_case is outside the signed 32-bit range.")
    transfer_id = _optional_string(
        fields, 10, "Introduction transfer_id", MAX_TRANSFER_ID_LENGTH
    )
    continuation = _optional_bool(fields, 11, "Introduction continuation")
    expect_more = _optional_bool(fields, 12, "Introduction expect_more")

    preview_ids = _repeated_int64(
        fields, 9, "Introduction preview_payload_id"
    )
    if len(preview_ids) > MAX_PREVIEW_IDS:
        raise IntroductionError("Introduction has too many preview payload IDs.")
    # Preview IDs reference the same signed int64 payload identifier space and
    # may be negative. Preserve them exactly.

    unknown = tuple(
        sorted(
            number
            for number in fields
            if number not in _KNOWN_INTRODUCTION_FIELDS
        )
    )
    return Introduction(
        files=files,
        text_entries=text_count,
        wifi_credentials_entries=len(wifi_entries),
        app_entries=len(app_entries),
        stream_entries=len(stream_entries),
        required_package=required_package,
        start_transfer=start_transfer,
        use_case=use_case,
        transfer_id=transfer_id,
        continuation=continuation,
        expect_more=expect_more,
        preview_payload_ids=tuple(preview_ids),
        unknown_field_numbers=unknown,
    )

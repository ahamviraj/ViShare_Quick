"""Wire encoders for the outbound Quick Share sender role.

Every field number here is taken from Google's published/derived protobuf
schemas and cross-checked against the receiving parsers in this repository:
``secure_channel`` validates ``OfflineFrame`` and payload structures,
``introduction`` validates ``IntroductionFrame`` and ``FileMetadata``, and
``sharing_response`` names the sharing status enum.

Nothing in this module touches a socket, reads a file, or keeps state. The
stateful session lives in :mod:`vishare_quick.sender`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from vishare_quick.protocol import _encode_bytes_field, _encode_varint_field

# OfflineFrame V1Frame type ids.
FRAME_CONNECTION_REQUEST = 1
FRAME_CONNECTION_RESPONSE = 2
FRAME_PAYLOAD_TRANSFER = 3
FRAME_KEEP_ALIVE = 5
FRAME_DISCONNECTION = 6

# ConnectionRequestFrame.mediums value for a Wi-Fi LAN socket.
MEDIUM_WIFI_LAN = 5

# PayloadTransferFrame.PayloadHeader.type
PAYLOAD_TYPE_BYTES = 1
PAYLOAD_TYPE_FILE = 2

# PayloadTransferFrame.packet_type
PACKET_TYPE_DATA = 1

# PayloadChunk.flags
FLAG_LAST_CHUNK = 0x01

# sharing.V1Frame type ids and their body field numbers.
SHARING_INTRODUCTION = 1
SHARING_RESPONSE = 2
SHARING_PAIRED_KEY_ENCRYPTION = 3
SHARING_PAIRED_KEY_RESULT = 4
SHARING_CANCEL = 6

_SHARING_BODY_FIELDS = {
    SHARING_INTRODUCTION: 2,
    SHARING_RESPONSE: 3,
    SHARING_PAIRED_KEY_ENCRYPTION: 4,
    SHARING_PAIRED_KEY_RESULT: 5,
}

# FileMetadata.Type
FILE_TYPE_UNKNOWN = 0
FILE_TYPE_IMAGE = 1
FILE_TYPE_VIDEO = 2
FILE_TYPE_ANDROID_APP = 3
FILE_TYPE_AUDIO = 4
FILE_TYPE_DOCUMENT = 5
FILE_TYPE_CONTACT_CARD = 6

# PairedKeyResultFrame.Status
PAIRED_KEY_RESULT_UNABLE = 3

# sharing.ConnectionResponseFrame.Status
RESPONSE_ACCEPT = 1
RESPONSE_REJECT = 2
RESPONSE_NOT_ENOUGH_SPACE = 3
RESPONSE_UNSUPPORTED_ATTACHMENT_TYPE = 4
RESPONSE_TIMED_OUT = 5


def encode_offline_frame(type_id: int, body: bytes) -> bytes:
    """Wrap one ``OfflineFrame`` v1 body at the schema's ``type + 1`` field.

    The result is an unframed protobuf payload. Callers add the four-byte
    big-endian TCP length prefix with :func:`frame_payload`.
    """
    if type_id < 1:
        raise ValueError("OfflineFrame type id must be positive.")
    v1 = _encode_varint_field(1, type_id) + _encode_bytes_field(type_id + 1, body)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def frame_payload(payload: bytes) -> bytes:
    """Add the four-byte big-endian TCP length prefix to one protobuf message.

    Mixing framed and unframed writes on the same socket makes the peer treat
    the start of a protobuf as a length prefix, wait for a short read, and then
    drop the connection. All sender writes go through this helper.
    """
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("A frame payload must be non-empty bytes.")
    return len(payload).to_bytes(4, "big") + payload


def encode_connection_request(
    endpoint_id: str,
    endpoint_name: str,
    endpoint_info: bytes,
    mediums: Iterable[int] = (MEDIUM_WIFI_LAN,),
) -> bytes:
    """Build the plaintext ``CONNECTION_REQUEST`` that opens a session."""
    endpoint_id_bytes = endpoint_id.encode("ascii")
    if not 1 <= len(endpoint_id_bytes) <= 4:
        raise ValueError("Endpoint ID must be 1 to 4 ASCII characters.")
    if not endpoint_name:
        raise ValueError("Endpoint name cannot be empty.")
    if not isinstance(endpoint_info, bytes) or not 1 <= len(endpoint_info) <= 1024:
        raise ValueError("Endpoint info must be between 1 and 1024 bytes.")
    body = (
        _encode_bytes_field(1, endpoint_id_bytes)
        + _encode_bytes_field(2, endpoint_name.encode("utf-8"))
    )
    for medium in mediums:
        body += _encode_varint_field(5, medium)
    body += _encode_bytes_field(6, endpoint_info)
    return encode_offline_frame(FRAME_CONNECTION_REQUEST, body)


def encode_keep_alive(*, ack: bool) -> bytes:
    """Build a ``KEEP_ALIVE`` frame; ``ack`` answers an unsolicited ping."""
    return encode_offline_frame(FRAME_KEEP_ALIVE, _encode_varint_field(1, 1 if ack else 0))


def encode_disconnection() -> bytes:
    """Build a ``DISCONNECTION`` frame with the empty documented body."""
    return encode_offline_frame(FRAME_DISCONNECTION, b"")


def encode_payload_chunk(
    payload_id: int,
    payload_type: int,
    total_size: int,
    offset: int,
    body: bytes,
    *,
    last_chunk: bool,
    file_name: str | None = None,
) -> bytes:
    """Build one ``PAYLOAD_TRANSFER`` DATA frame.

    ``payload_type`` is BYTES for negotiation messages and FILE for file data.
    Only FILE payloads carry a name, and it must already be a safe basename.
    """
    if payload_id == 0:
        raise ValueError("Payload ID must be non-zero.")
    if total_size < 0 or offset < 0:
        raise ValueError("Payload sizes and offsets cannot be negative.")
    if payload_type not in (PAYLOAD_TYPE_BYTES, PAYLOAD_TYPE_FILE):
        raise ValueError("Unsupported payload type.")
    if offset + len(body) > total_size:
        raise ValueError("Chunk would write past the declared payload size.")
    if payload_type == PAYLOAD_TYPE_BYTES and file_name is not None:
        raise ValueError("BYTES payloads must not carry a file name.")

    header = (
        _encode_varint_field(1, payload_id)
        + _encode_varint_field(2, payload_type)
        + _encode_varint_field(3, total_size)
    )
    if file_name is not None:
        if not file_name or any(character in file_name for character in "/\\"):
            raise ValueError("Payload file name must be a non-empty basename.")
        header += _encode_bytes_field(5, file_name.encode("utf-8"))

    chunk = _encode_varint_field(1, FLAG_LAST_CHUNK if last_chunk else 0)
    chunk += _encode_varint_field(2, offset)
    if body:
        chunk += _encode_bytes_field(3, body)

    frame_body = (
        _encode_varint_field(1, PACKET_TYPE_DATA)
        + _encode_bytes_field(2, header)
        + _encode_bytes_field(3, chunk)
    )
    return encode_offline_frame(FRAME_PAYLOAD_TRANSFER, frame_body)


def encode_sharing_frame(type_id: int, body: bytes | None = None) -> bytes:
    """Wrap one ``sharing.Frame`` v1 message, including its body field."""
    if type_id not in (SHARING_INTRODUCTION, SHARING_RESPONSE,
                       SHARING_PAIRED_KEY_ENCRYPTION, SHARING_PAIRED_KEY_RESULT,
                       SHARING_CANCEL):
        raise ValueError("Unsupported sharing frame type.")
    v1 = _encode_varint_field(1, type_id)
    if type_id == SHARING_CANCEL:
        if body:
            raise ValueError("CANCEL must not carry a body.")
    else:
        if body is None:
            raise ValueError("This sharing frame type requires a body.")
        v1 += _encode_bytes_field(_SHARING_BODY_FIELDS[type_id], body)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)


def encode_sharing_payload(payload_id: int, sharing_frame: bytes) -> tuple[bytes, bytes]:
    """Return the two ``OfflineFrame`` payloads for one sharing message.

    Android sends control messages as a complete DATA chunk followed by an
    empty ``LAST_CHUNK`` marker with the same header and a final offset.
    """
    if not sharing_frame:
        raise ValueError("Sharing frame bytes cannot be empty.")
    size = len(sharing_frame)
    first = encode_payload_chunk(
        payload_id, PAYLOAD_TYPE_BYTES, size, 0, sharing_frame, last_chunk=False
    )
    last = encode_payload_chunk(
        payload_id, PAYLOAD_TYPE_BYTES, size, size, b"", last_chunk=True
    )
    return first, last


def encode_paired_key_encryption(signed_data: bytes, secret_id_hash: bytes) -> bytes:
    """Build the no-credential ``PAIRED_KEY_ENCRYPTION`` placeholder."""
    if len(signed_data) != 72:
        raise ValueError("signed_data must be 72 bytes for the placeholder.")
    if len(secret_id_hash) != 6:
        raise ValueError("secret_id_hash must be 6 bytes for the placeholder.")
    body = (
        _encode_bytes_field(1, signed_data)
        + _encode_bytes_field(2, secret_id_hash)
    )
    return encode_sharing_frame(SHARING_PAIRED_KEY_ENCRYPTION, body)


def encode_paired_key_result(status: int = PAIRED_KEY_RESULT_UNABLE) -> bytes:
    if status not in (0, 1, 2, 3):
        raise ValueError("Unsupported paired-key result status.")
    return encode_sharing_frame(
        SHARING_PAIRED_KEY_RESULT, _encode_varint_field(1, status)
    )


@dataclass(frozen=True)
class IntroductionFile:
    """One file offered to the receiver."""

    name: str
    payload_id: int
    size: int
    mime_type: str
    file_type: int


def encode_introduction(files: Sequence[IntroductionFile]) -> bytes:
    """Build an ``IntroductionFrame`` carrying only regular file offers."""
    if not files:
        raise ValueError("An Introduction must offer at least one file.")
    body = b""
    for item in files:
        if not item.name or any(character in item.name for character in "/\\"):
            raise ValueError("Offered file names must be non-empty basenames.")
        if item.payload_id == 0:
            raise ValueError("Offered payload IDs must be non-zero.")
        if item.size < 0:
            raise ValueError("Offered file sizes cannot be negative.")
        metadata = (
            _encode_bytes_field(1, item.name.encode("utf-8"))
            + _encode_varint_field(2, item.file_type)
            + _encode_varint_field(3, item.payload_id)
            + _encode_varint_field(4, item.size)
            + _encode_bytes_field(5, item.mime_type.encode("ascii", "replace"))
        )
        body += _encode_bytes_field(1, metadata)
    return encode_sharing_frame(SHARING_INTRODUCTION, body)

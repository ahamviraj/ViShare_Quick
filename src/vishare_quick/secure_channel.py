"""Read-only authentication and inspection for the observed UKEY2 SecureMessage channel."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vishare_quick.protocol import (
    DEFAULT_MAX_FRAME_LENGTH,
    Frame,
    MalformedFrame,
    _Field,
    _encode_bytes_field,
    _encode_varint_field,
    _field_occurrences,
    inspect_securemessage_envelope,
)

_HMAC_SHA256 = 1
_AES_256_CBC = 2
_DEVICE_TO_DEVICE_MESSAGE = 13
_MAX_INT32 = (1 << 31) - 1
_MAX_UINT64 = (1 << 64) - 1
_PAYLOAD_TYPES = {0, 1, 2, 3}
_OFFLINE_TYPES = {
    1: "CONNECTION_REQUEST", 2: "CONNECTION_RESPONSE", 3: "PAYLOAD_TRANSFER",
    4: "BANDWIDTH_UPGRADE_NEGOTIATION", 5: "KEEP_ALIVE", 6: "DISCONNECTION",
    7: "PAIRED_KEY_ENCRYPTION", 8: "AUTHENTICATION_MESSAGE", 9: "AUTHENTICATION_RESULT",
    10: "AUTO_RESUME", 11: "AUTO_RECONNECT", 12: "BANDWIDTH_UPGRADE_RETRY",
}
_SHARING_TYPES = {
    1: "INTRODUCTION", 2: "RESPONSE", 3: "PAIRED_KEY_ENCRYPTION",
    4: "PAIRED_KEY_RESULT", 5: "CERTIFICATE_INFO", 6: "CANCEL",
    7: "PROGRESS_UPDATE",
}


class SecureChannelError(Exception):
    """Safe-to-report authenticated-channel validation failure."""

    error_category = "invalid-protobuf-or-framing"


class SecureMessageAuthenticationError(SecureChannelError):
    """HMAC did not authenticate the exact received header_and_body bytes."""

    error_category = "authentication-failure"


class SecureMessageDecryptionError(SecureChannelError):
    """Authenticated ciphertext could not be decrypted as valid AES-CBC/PKCS#7."""

    error_category = "decryption-failure"


class UnexpectedSequence(SecureChannelError):
    """The authenticated DeviceToDeviceMessage sequence was not the expected one."""

    error_category = "unexpected-sequence"


class InvalidPayloadStructure(SecureChannelError):
    """An authenticated payload header/chunk or sharing body is structurally invalid."""

    error_category = "invalid-payload-structure"


@dataclass(frozen=True, repr=False)
class ReceiveKeys:
    encryption_key: bytes = field(repr=False)
    hmac_key: bytes = field(repr=False)


@dataclass(frozen=True, repr=False)
class SendKeys:
    encryption_key: bytes = field(repr=False)
    hmac_key: bytes = field(repr=False)


@dataclass(frozen=True)
class PairedKeyFieldMetadata:
    name: str
    present: bool
    length: int | None


@dataclass(frozen=True)
class PayloadTransferMetadata:
    """Safe transport metadata for one authenticated PAYLOAD_TRANSFER frame."""

    packet_type: int
    payload_id: int
    payload_type: int
    total_size: int
    chunk_flags: int | None
    chunk_offset: int
    chunk_body_length: int
    is_last_chunk: bool
    complete_sharing_frame: bool


@dataclass(frozen=True)
class AuthenticatedFrameSummary:
    sequence: int
    offline_type: str
    sharing_type: str | None
    paired_key_fields: tuple[PairedKeyFieldMetadata, ...] = ()
    payload_transfer: PayloadTransferMetadata | None = None
    paired_key_result_status: int | None = None
    # Safe transport-control metadata. Values are documented enum numbers and
    # booleans only; no frame body, key, or identity material is retained.
    keep_alive_ack: bool | None = None
    bandwidth_upgrade_retry_mediums: tuple[int, ...] = ()
    bandwidth_upgrade_retry_is_request: bool | None = None


def _derive_securemessage_keys(next_secret: bytes, role: bytes) -> tuple[bytes, bytes]:
    if not isinstance(next_secret, bytes) or len(next_secret) != 32:
        raise SecureChannelError("UKEY2 next_secret must be 32 bytes.")
    if role not in (b"client", b"server"):
        raise SecureChannelError("SecureMessage role must be client or server.")
    d2d_salt = hashlib.sha256(b"D2D").digest()
    securemessage_salt = hashlib.sha256(b"SecureMessage").digest()
    d2d_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=d2d_salt, info=role
    ).derive(next_secret)
    encryption_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=securemessage_salt, info=b"ENC:2"
    ).derive(d2d_key)
    hmac_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=securemessage_salt, info=b"SIG:1"
    ).derive(d2d_key)
    return encryption_key, hmac_key


def derive_client_to_server_receive_keys(next_secret: bytes) -> ReceiveKeys:
    """Derive only Android-client -> laptop-server SecureMessage receive keys.

    The schedule is cross-checked against NearShare and NearDrop. The transport
    caller must pass the UKEY2 next_secret from the validated handshake state.
    """
    return ReceiveKeys(*_derive_securemessage_keys(next_secret, b"client"))


def derive_server_to_client_send_keys(next_secret: bytes) -> SendKeys:
    """Derive only laptop-server -> Android-client SecureMessage send keys.

    This is the opposite D2D role from the receive schedule. The two directions
    must never share counters or keys.
    """
    return SendKeys(*_derive_securemessage_keys(next_secret, b"server"))


def _parse(data: bytes, label: str) -> dict[int, list[_Field]]:
    if len(data) > DEFAULT_MAX_FRAME_LENGTH:
        raise SecureChannelError(f"{label} exceeds the parser size limit.")
    try:
        occurrences = _field_occurrences(data)
    except MalformedFrame as exc:
        raise SecureChannelError(f"Malformed {label} protobuf.") from exc
    result: dict[int, list[_Field]] = {}
    for number, item in occurrences:
        result.setdefault(number, []).append(item)
    return result


def _field_diagnostic(fields: dict[int, list[_Field]]) -> str:
    """Describe only field numbers, wire types, and occurrence counts (never values)."""
    parts = []
    for number, items in sorted(fields.items()):
        counts: dict[int, int] = {}
        for item in items:
            counts[item.wire] = counts.get(item.wire, 0) + 1
        wires = ", ".join(f"wire{wire}x{count}" for wire, count in sorted(counts.items()))
        parts.append(f"field{number}({wires})")
    return "[" + "; ".join(parts) + "]" if parts else "[]"


def _one(
    fields: dict[int, list[_Field]], number: int, wire: int, name: str, *, required: bool = True
) -> bytes | int | None:
    items = fields.get(number, [])
    if not items and not required:
        return None
    if len(items) != 1:
        raise SecureChannelError(
            f"{name} must be present exactly once "
            f"(occurrences={len(items)}; field={number}; expected_wire={wire}; "
            f"present_fields={_field_diagnostic(fields)})."
        )
    item = items[0]
    if item.wire != wire:
        raise SecureChannelError(
            f"{name} has the wrong protobuf wire type "
            f"(received_wire={item.wire}; expected_wire={wire}; "
            f"present_fields={_field_diagnostic(fields)})."
        )
    return item.value


def _signed_int64(value: int, name: str, fields: dict[int, list[_Field]]) -> int:
    """Interpret a protobuf varint as a signed ``int64`` (proto2 semantics).

    ``_field_occurrences`` returns the unsigned varint magnitude. A negative
    int64 is encoded on the wire as the ten-byte two's-complement value, so
    magnitudes at or above 2**63 represent negative numbers. Treating them as
    unsigned is what made valid peer headers look "invalid or oversized".
    """
    if not isinstance(value, int) or value < 0 or value > _MAX_UINT64:
        raise SecureChannelError(
            f"{name} is not a valid 64-bit protobuf varint "
            f"(present_fields={_field_diagnostic(fields)})."
        )
    if value >= 1 << 63:
        return value - (1 << 64)
    return value


def _signed_int32(value: int, name: str, fields: dict[int, list[_Field]]) -> int:
    """Interpret a protobuf varint as a signed ``int32`` and range-check it."""
    widened = _signed_int64(value, name, fields)
    if not -(1 << 31) <= widened <= _MAX_INT32:
        raise SecureChannelError(
            f"{name} is outside the signed 32-bit protobuf range "
            f"(present_fields={_field_diagnostic(fields)})."
        )
    return widened


def _parse_sharing_frame(
    data: bytes,
) -> tuple[str, tuple[PairedKeyFieldMetadata, ...], int | None]:
    frame = _parse(data, "sharing Frame")
    version = _one(frame, 1, 0, "sharing Frame version")
    v1_bytes = _one(frame, 2, 2, "sharing Frame v1")
    if version != 1 or not isinstance(v1_bytes, bytes):
        raise SecureChannelError("Unsupported or malformed sharing Frame version.")
    v1 = _parse(v1_bytes, "sharing V1Frame")
    type_id = _one(v1, 1, 0, "sharing Frame type")
    if not isinstance(type_id, int) or type_id not in _SHARING_TYPES:
        raise SecureChannelError("Unsupported sharing Frame type.")
    body_field = type_id + 1
    body = _one(v1, body_field, 2, "sharing Frame body")
    if not isinstance(body, bytes):
        raise SecureChannelError("Malformed sharing Frame body.")
    body_fields = [n for n in range(2, 16) if n in v1]
    if body_fields != [body_field]:
        raise SecureChannelError("Sharing Frame has a missing or conflicting body.")
    body_message = _parse(body, "sharing message")
    name = _SHARING_TYPES[type_id]
    if type_id == 4:
        status = _one(
            body_message, 1, 0, "PairedKeyResultFrame status", required=False
        )
        if status is not None and (not isinstance(status, int) or status not in (0, 1, 2, 3)):
            raise SecureChannelError("Unsupported PairedKeyResultFrame status.")
        return name, (), status
    if type_id != 3:
        return name, (), None

    names = {
        1: "signed_data",
        2: "secret_id_hash",
        3: "optional_signed_data",
        4: "qr_code_handshake_data",
    }
    summaries: list[PairedKeyFieldMetadata] = []
    for number, field_name in names.items():
        entries = body_message.get(number, [])
        if len(entries) > 1:
            raise SecureChannelError(f"PairedKeyEncryptionFrame {field_name} is duplicated.")
        if not entries:
            summaries.append(PairedKeyFieldMetadata(field_name, False, None))
            continue
        entry = entries[0]
        if entry.wire != 2 or not isinstance(entry.value, bytes):
            raise SecureChannelError(f"PairedKeyEncryptionFrame {field_name} has the wrong wire type.")
        summaries.append(PairedKeyFieldMetadata(field_name, True, len(entry.value)))
    return name, tuple(summaries), None


@dataclass(frozen=True)
class _ParsedOfflineFrame:
    offline_type: str
    sharing_type: str | None
    paired_key_fields: tuple[PairedKeyFieldMetadata, ...]
    payload_transfer: PayloadTransferMetadata | None
    paired_key_result_status: int | None
    keep_alive_ack: bool | None = None
    bandwidth_upgrade_retry_mediums: tuple[int, ...] = ()
    bandwidth_upgrade_retry_is_request: bool | None = None


def _parse_offline_frame(data: bytes) -> _ParsedOfflineFrame:
    frame = _parse(data, "OfflineFrame")
    version = _one(frame, 1, 0, "OfflineFrame version")
    v1_bytes = _one(frame, 2, 2, "OfflineFrame v1")
    if version != 1 or not isinstance(v1_bytes, bytes):
        raise SecureChannelError("Unsupported or malformed OfflineFrame version.")
    v1 = _parse(v1_bytes, "OfflineFrame v1")
    type_id = _one(v1, 1, 0, "OfflineFrame type")
    if not isinstance(type_id, int) or type_id not in _OFFLINE_TYPES:
        raise SecureChannelError("Unsupported OfflineFrame type.")
    body_field = type_id + 1
    body = _one(v1, body_field, 2, "OfflineFrame body")
    if not isinstance(body, bytes):
        raise SecureChannelError("Malformed OfflineFrame body.")
    body_fields = [n for n in range(2, 16) if n in v1]
    if body_fields != [body_field]:
        raise SecureChannelError("OfflineFrame has a missing or conflicting type body.")
    offline_type = _OFFLINE_TYPES[type_id]
    if type_id == 5:
        keep_alive = _parse(body, "KeepAliveFrame")
        raw_ack = _one(keep_alive, 1, 0, "KeepAliveFrame ack", required=False)
        if raw_ack is not None and raw_ack not in (0, 1):
            raise SecureChannelError("KeepAliveFrame ack is not a boolean.")
        return _ParsedOfflineFrame(
            offline_type,
            None,
            (),
            None,
            None,
            keep_alive_ack=bool(raw_ack) if raw_ack is not None else False,
        )
    if type_id == 12:
        # BandwidthUpgradeRetryFrame: repeated Medium supported_medium=1,
        # optional bool is_request=2. Only enum numbers and the boolean are
        # retained for diagnostics.
        retry = _parse(body, "BandwidthUpgradeRetryFrame")
        mediums: list[int] = []
        for item in retry.get(1, []):
            if item.wire != 0 or not isinstance(item.value, int):
                raise SecureChannelError(
                    "BandwidthUpgradeRetryFrame supported_medium is malformed."
                )
            mediums.append(item.value)
        raw_request = _one(
            retry, 2, 0, "BandwidthUpgradeRetryFrame is_request", required=False
        )
        if raw_request is not None and raw_request not in (0, 1):
            raise SecureChannelError(
                "BandwidthUpgradeRetryFrame is_request is not a boolean."
            )
        return _ParsedOfflineFrame(
            offline_type,
            None,
            (),
            None,
            None,
            bandwidth_upgrade_retry_mediums=tuple(mediums),
            bandwidth_upgrade_retry_is_request=(
                bool(raw_request) if raw_request is not None else False
            ),
        )
    if type_id != 3:
        _parse(body, f"{offline_type} body")
        return _ParsedOfflineFrame(offline_type, None, (), None, None)

    payload = _parse(body, "PayloadTransferFrame")
    packet_type = _one(payload, 1, 0, "PayloadTransferFrame packet_type")
    header_bytes = _one(payload, 2, 2, "PayloadTransferFrame payload_header")
    chunk_bytes = _one(payload, 3, 2, "PayloadTransferFrame payload_chunk")
    if 4 in payload:
        raise InvalidPayloadStructure("Unexpected control message in DATA packet.")
    if packet_type != 1 or not isinstance(header_bytes, bytes) or not isinstance(chunk_bytes, bytes):
        raise InvalidPayloadStructure("Malformed or unsupported PayloadTransferFrame packet.")

    header = _parse(header_bytes, "PayloadHeader")
    raw_id = _one(header, 1, 0, "PayloadHeader id")
    raw_type = _one(header, 2, 0, "PayloadHeader type")
    raw_total_size = _one(header, 3, 0, "PayloadHeader total_size")

    # Google's offline_wire_formats.proto declares all three as signed integer
    # fields: id=int64 (1), type=PayloadType enum (2), total_size=int64 (3).
    # id and total_size may therefore be negative on the wire (two's-complement
    # varint), and total_size is a declared payload size, not a transport frame
    # size. It must not be compared with DEFAULT_MAX_FRAME_LENGTH; actual bytes
    # remain bounded by the frame reader and by the chunk body length.
    payload_id = _signed_int64(raw_id, "PayloadHeader id", header)
    payload_type = _signed_int32(raw_type, "PayloadHeader type", header)
    total_size = _signed_int64(raw_total_size, "PayloadHeader total_size", header)

    problems: list[str] = []
    if payload_type not in _PAYLOAD_TYPES:
        problems.append(f"unsupported type enum {payload_type} (expected 0..3)")
    # Google's transport uses -1 ("indeterminate") only for STREAM payloads
    # whose size is unknown (outgoing_payload_manager.cc). BYTES and FILE must
    # declare a non-negative size.
    if total_size < 0 and not (total_size == -1 and payload_type in (0, 3)):
        problems.append(
            f"total_size {total_size} is negative and is not an indeterminate STREAM size"
        )
    if problems:
        raise InvalidPayloadStructure(
            "PayloadHeader is invalid: "
            + "; ".join(problems)
            + f" [id={payload_id}; type={payload_type}; total_size={total_size}; "
            + f"present_fields={_field_diagnostic(header)}]."
        )

    # Field numbers follow Google's PayloadChunk schema: flags=1, offset=2,
    # body=3, index=4. In particular, body is not field 2. The body is optional
    # on the wire. Documented reverse-engineered Android behavior sends
    # negotiation bytes as a complete DATA chunk followed by a zero-length
    # LAST_CHUNK chunk with body omitted.
    chunk = _parse(chunk_bytes, "PayloadTransferFrame.payload_chunk (PayloadChunk)")
    raw_flags = _one(chunk, 1, 0, "PayloadChunk flags (field 1)", required=False)
    raw_offset = _one(chunk, 2, 0, "PayloadChunk offset (field 2)", required=False)
    body_bytes = _one(chunk, 3, 2, "PayloadChunk body (field 3)", required=False)
    raw_index = _one(chunk, 4, 0, "PayloadChunk index (field 4)", required=False)
    flags = None if raw_flags is None else _signed_int32(raw_flags, "PayloadChunk flags (field 1)", chunk)
    offset = 0 if raw_offset is None else _signed_int64(raw_offset, "PayloadChunk offset (field 2)", chunk)
    index = None if raw_index is None else _signed_int32(raw_index, "PayloadChunk index (field 4)", chunk)
    if body_bytes is None:
        body_bytes = b""
    if flags is not None and flags < 0:
        raise InvalidPayloadStructure(
            f"PayloadChunk flags (field 1) is negative [flags={flags}; "
            f"present_fields={_field_diagnostic(chunk)}]."
        )
    if index is not None and index < 0:
        raise InvalidPayloadStructure(
            f"PayloadChunk index (field 4) is negative [index={index}; "
            f"present_fields={_field_diagnostic(chunk)}]."
        )
    if offset < 0 or not isinstance(body_bytes, bytes):
        raise InvalidPayloadStructure(
            f"PayloadChunk offset (field 2) or body (field 3) is malformed "
            f"[offset={offset}; body_present={bool(body_bytes)}; "
            f"present_fields={_field_diagnostic(chunk)}]."
        )
    is_last_chunk = bool(flags is not None and flags & 1)
    complete = payload_type == 1 and offset == 0 and len(body_bytes) == total_size
    metadata = PayloadTransferMetadata(
        packet_type=packet_type,
        payload_id=payload_id,
        payload_type=payload_type,
        total_size=total_size,
        chunk_flags=flags,
        chunk_offset=offset,
        chunk_body_length=len(body_bytes),
        is_last_chunk=is_last_chunk,
        complete_sharing_frame=complete,
    )
    if not complete:
        return _ParsedOfflineFrame(offline_type, None, (), metadata, None)
    sharing_type, paired_key_fields, result_status = _parse_sharing_frame(body_bytes)
    return _ParsedOfflineFrame(
        offline_type, sharing_type, paired_key_fields, metadata, result_status
    )


def authenticate_and_inspect_frame(
    frame: Frame, receive_keys: ReceiveKeys, *, expected_sequence: int = 1
) -> AuthenticatedFrameSummary:
    """Authenticate, decrypt, and safely classify one received SecureMessage.

    The MAC is checked over the exact received `header_and_body` byte string before
    any nested field is parsed or any ciphertext is decrypted. No raw values escape.
    """
    if not 1 <= expected_sequence <= _MAX_INT32:
        raise SecureChannelError("Expected D2D sequence is outside the supported range.")
    if len(receive_keys.encryption_key) != 32 or len(receive_keys.hmac_key) != 32:
        raise SecureChannelError("Receive keys have invalid lengths.")
    if len(frame.wire_bytes) > DEFAULT_MAX_FRAME_LENGTH + 4:
        raise SecureChannelError("SecureMessage frame exceeds the configured size limit.")
    envelope = inspect_securemessage_envelope(frame)
    if len(envelope.signature) != 32:
        raise SecureMessageAuthenticationError("SecureMessage HMAC has an invalid length.")
    expected_mac = hmac.new(receive_keys.hmac_key, envelope.header_and_body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, envelope.signature):
        raise SecureMessageAuthenticationError("SecureMessage HMAC authentication failed.")

    header_and_body = _parse(envelope.header_and_body, "HeaderAndBody")
    header_bytes = _one(header_and_body, 1, 2, "HeaderAndBody header")
    ciphertext = _one(header_and_body, 2, 2, "HeaderAndBody body")
    if not isinstance(header_bytes, bytes) or not isinstance(ciphertext, bytes):
        raise SecureChannelError("Malformed HeaderAndBody.")
    header = _parse(header_bytes, "SecureMessage Header")
    signature_scheme = _one(header, 1, 0, "Header signature_scheme")
    encryption_scheme = _one(header, 2, 0, "Header encryption_scheme")
    iv = _one(header, 5, 2, "Header IV")
    metadata_bytes = _one(header, 6, 2, "Header public_metadata")
    if signature_scheme != _HMAC_SHA256 or encryption_scheme != _AES_256_CBC:
        raise SecureChannelError("Unsupported SecureMessage algorithm identifiers.")
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise SecureChannelError("SecureMessage IV is malformed.")
    if not isinstance(metadata_bytes, bytes):
        raise SecureChannelError("SecureMessage public metadata is malformed.")
    metadata = _parse(metadata_bytes, "GcmMetadata")
    metadata_type = _one(metadata, 1, 0, "GcmMetadata type")
    metadata_version = _one(metadata, 2, 0, "GcmMetadata version")
    if metadata_type != _DEVICE_TO_DEVICE_MESSAGE or metadata_version != 1:
        raise SecureChannelError("Unsupported SecureMessage public metadata.")
    if not ciphertext or len(ciphertext) % 16:
        raise SecureChannelError("AES-CBC ciphertext has an invalid block length.")

    decryptor = Cipher(algorithms.AES(receive_keys.encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise SecureMessageDecryptionError(
            "Authenticated AES-CBC plaintext has invalid PKCS#7 padding."
        ) from exc

    d2d = _parse(plaintext, "DeviceToDeviceMessage")
    message = _one(d2d, 1, 2, "DeviceToDeviceMessage message")
    sequence = _one(d2d, 2, 0, "DeviceToDeviceMessage sequence_number")
    if not isinstance(message, bytes) or not isinstance(sequence, int):
        raise SecureChannelError("Malformed DeviceToDeviceMessage.")
    if sequence != expected_sequence:
        raise UnexpectedSequence("Unexpected DeviceToDeviceMessage sequence number.")
    parsed = _parse_offline_frame(message)
    return AuthenticatedFrameSummary(
        sequence,
        parsed.offline_type,
        parsed.sharing_type,
        parsed.paired_key_fields,
        parsed.payload_transfer,
        parsed.paired_key_result_status,
        keep_alive_ack=parsed.keep_alive_ack,
        bandwidth_upgrade_retry_mediums=parsed.bandwidth_upgrade_retry_mediums,
        bandwidth_upgrade_retry_is_request=parsed.bandwidth_upgrade_retry_is_request,
    )


def encode_secure_message(
    offline_frame: bytes,
    send_keys: SendKeys,
    sequence: int,
    *,
    iv: bytes | None = None,
) -> bytes:
    """Encode one authenticated server-to-client SecureMessage frame.

    The caller owns the independent send counter and must pass strictly
    increasing sequence numbers. The IV is fresh per frame unless a
    deterministic IV is supplied by a synthetic test.
    """
    if not isinstance(offline_frame, bytes) or not offline_frame:
        raise SecureChannelError("OfflineFrame payload must be non-empty bytes.")
    if len(offline_frame) > DEFAULT_MAX_FRAME_LENGTH:
        raise SecureChannelError("OfflineFrame payload exceeds the configured size limit.")
    if not 1 <= sequence <= _MAX_INT32:
        raise SecureChannelError("D2D send sequence is outside the supported range.")
    if (not isinstance(send_keys.encryption_key, bytes) or len(send_keys.encryption_key) != 32
            or not isinstance(send_keys.hmac_key, bytes) or len(send_keys.hmac_key) != 32):
        raise SecureChannelError("Send keys have invalid lengths.")
    if iv is None:
        iv = secrets.token_bytes(16)
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise SecureChannelError("SecureMessage IV must be 16 bytes.")

    d2d = _encode_bytes_field(1, offline_frame) + _encode_varint_field(2, sequence)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(d2d) + padder.finalize()
    encryptor = Cipher(algorithms.AES(send_keys.encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    metadata = _encode_varint_field(1, _DEVICE_TO_DEVICE_MESSAGE) + _encode_varint_field(2, 1)
    header = (
        _encode_varint_field(1, _HMAC_SHA256)
        + _encode_varint_field(2, _AES_256_CBC)
        + _encode_bytes_field(5, iv)
        + _encode_bytes_field(6, metadata)
    )
    header_and_body = _encode_bytes_field(1, header) + _encode_bytes_field(2, ciphertext)
    signature = hmac.new(send_keys.hmac_key, header_and_body, hashlib.sha256).digest()
    payload = _encode_bytes_field(1, header_and_body) + _encode_bytes_field(2, signature)
    if len(payload) > DEFAULT_MAX_FRAME_LENGTH:
        raise SecureChannelError("Encoded SecureMessage exceeds the configured size limit.")
    return len(payload).to_bytes(4, "big") + payload

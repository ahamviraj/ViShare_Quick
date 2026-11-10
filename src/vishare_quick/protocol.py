"""Bounded, read-only inspection for Nearby OfflineFrame and UKEY2 messages."""
from __future__ import annotations

import socket
import platform
from dataclasses import dataclass, field
from typing import Callable, Protocol

DEFAULT_MAX_FRAME_LENGTH = 1024 * 1024
MAX_FRAME_HEX_BYTES = 96
OFFLINE_FRAME_TYPES = {
    1: "CONNECTION_REQUEST", 2: "CONNECTION_RESPONSE", 3: "PAYLOAD_TRANSFER",
    4: "BANDWIDTH_UPGRADE_NEGOTIATION", 5: "KEEP_ALIVE", 6: "DISCONNECTION",
    7: "PAIRED_KEY_ENCRYPTION", 8: "AUTHENTICATION_MESSAGE",
    9: "AUTHENTICATION_RESULT", 10: "AUTO_RESUME", 11: "AUTO_RECONNECT",
    12: "BANDWIDTH_UPGRADE_RETRY",
}
OFFLINE_SUBFRAME_FIELDS = {kind: kind + 1 for kind in OFFLINE_FRAME_TYPES}
UKEY2_TYPES = {1: "ALERT", 2: "CLIENT_INIT", 3: "SERVER_INIT", 4: "CLIENT_FINISH"}
UKEY2_CIPHERS = {100: "P256_SHA512", 200: "CURVE25519_SHA512"}
UKEY2_DOCUMENTED_NEXT_PROTOCOL = b"AES_256_CBC-HMAC_SHA256"


class FrameError(Exception):
    """Base class for framing or safe inspection failures."""


class PeerDisconnected(FrameError):
    pass


class TruncatedFrame(PeerDisconnected):
    pass


class MalformedFrame(FrameError):
    pass


class FrameTimeout(FrameError):
    pass


class UnexpectedMessageType(FrameError):
    pass


class UnrecognizedMessage(FrameError):
    pass


class PeerRejectedConnection(FrameError):
    """The peer sent a recognized Nearby rejection status."""


class SocketReader(Protocol):
    def recv(self, size: int) -> bytes: ...


@dataclass(frozen=True)
class Frame:
    payload: bytes = field(repr=False)
    declared_length: int
    family: str
    message_type: str
    validation: str
    wire_bytes: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, repr=False)
class SecureMessageEnvelope:
    """Exact SecureMessage bytes retained for MAC verification before child parsing."""

    wire_bytes: bytes = field(repr=False)
    header_and_body: bytes = field(repr=False)
    signature: bytes = field(repr=False)


def inspect_securemessage_envelope(frame: Frame) -> SecureMessageEnvelope:
    """Validate and retain SecureMessage's required outer fields without interpreting them.

    The exact framed bytes, authenticated header_and_body serialization, and signature are
    retained in memory. This helper alone does not authenticate or interpret the contents.
    """
    if frame.declared_length < 1 or frame.declared_length > DEFAULT_MAX_FRAME_LENGTH:
        raise MalformedFrame("SecureMessage frame exceeds the configured size limit.")
    expected_wire = frame.declared_length.to_bytes(4, "big") + frame.payload
    if len(frame.payload) != frame.declared_length or frame.wire_bytes != expected_wire:
        raise MalformedFrame("SecureMessage frame bytes are incomplete or inconsistent.")
    try:
        fields = _field_occurrences(frame.payload)
    except MalformedFrame as exc:
        raise MalformedFrame("Malformed SecureMessage outer protobuf.") from exc

    values: dict[int, list[_Field]] = {}
    for number, item in fields:
        values.setdefault(number, []).append(item)
    parts: list[bytes] = []
    for number, name in ((1, "header_and_body"), (2, "signature")):
        entries = values.get(number, [])
        if len(entries) != 1:
            raise MalformedFrame(f"SecureMessage {name} must be present exactly once.")
        item = entries[0]
        if item.wire != 2 or not isinstance(item.value, bytes):
            raise MalformedFrame(f"SecureMessage {name} has the wrong protobuf wire type.")
        parts.append(item.value)

    # Do not inspect/re-encode header_and_body or report the envelope as authentic.
    return SecureMessageEnvelope(frame.wire_bytes, parts[0], parts[1])


@dataclass(frozen=True)
class _Field:
    wire: int
    value: bytes | int


def _read_exact(sock: SocketReader, size: int, *, header: bool) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            part = sock.recv(size - len(chunks))
        except socket.timeout as exc:
            raise FrameTimeout("Timed out while reading a frame.") from exc
        if not part:
            if not chunks and header:
                raise PeerDisconnected("Peer disconnected between frames.")
            raise TruncatedFrame("Peer disconnected during a frame.")
        chunks.extend(part)
    return bytes(chunks)


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data) and shift < 70:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
    raise MalformedFrame("Malformed protobuf varint.")


def _field_occurrences(data: bytes) -> list[tuple[int, _Field]]:
    """Parse protobuf wire fields, preserving repetitions for schema validation."""
    fields: list[tuple[int, _Field]] = []
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise MalformedFrame("Invalid protobuf field number.")
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, pos = _varint(data, pos)
                end = pos + length
            else:
                end = pos + (8 if wire == 1 else 4)
            if end > len(data):
                raise MalformedFrame("Truncated protobuf field.")
            value, pos = data[pos:end], end
        else:
            raise MalformedFrame("Unsupported protobuf wire type.")
        fields.append((number, _Field(wire, value)))
    return fields


def _fields(data: bytes) -> dict[int, _Field]:
    """Parse protobuf fields into a last-value map for existing envelope checks."""
    return dict(_field_occurrences(data))


def _bytes_field(fields: dict[int, _Field], number: int) -> bytes | None:
    field = fields.get(number)
    if field is None or field.wire != 2 or not isinstance(field.value, bytes):
        return None
    return field.value


def _varint_field(fields: dict[int, _Field], number: int) -> int | None:
    field = fields.get(number)
    if field is None or field.wire != 0 or not isinstance(field.value, int):
        return None
    return field.value


def _inspect_client_init(data: bytes) -> str:
    """Summarize schema-backed ClientInit metadata without exposing field contents."""
    occurrences = _field_occurrences(data)
    by_number: dict[int, list[_Field]] = {}
    for number, field in occurrences:
        by_number.setdefault(number, []).append(field)

    issues: list[str] = []

    def singular(number: int, name: str) -> _Field | None:
        values = by_number.get(number, [])
        if len(values) > 1:
            issues.append(f"{name} duplicated")
        return values[0] if values else None

    version_field = singular(1, "version")
    if version_field is None or version_field.wire != 0 or not isinstance(version_field.value, int):
        version_result = "missing-or-malformed"
        issues.append("version missing or malformed")
    elif version_field.value == 1:
        version_result = "supported(1)"
    else:
        version_result = f"unsupported({version_field.value})"
        issues.append("unsupported version")

    random_field = singular(2, "random")
    if random_field is None or random_field.wire != 2 or not isinstance(random_field.value, bytes):
        random_result = "missing-or-malformed"
        issues.append("random missing or malformed")
    elif len(random_field.value) != 32:
        random_result = f"invalid-length({len(random_field.value)}; expected 32)"
        issues.append("invalid random length")
    else:
        random_result = "valid(32 bytes)"

    commitments = by_number.get(3, [])
    commitment_parts: list[str] = []
    seen_ciphers: set[int] = set()
    if not commitments:
        issues.append("cipher commitments missing")
    for index, outer in enumerate(commitments, start=1):
        if outer.wire != 2 or not isinstance(outer.value, bytes):
            commitment_parts.append(f"#{index}=malformed-entry")
            issues.append(f"cipher commitment #{index} malformed")
            continue
        nested_occurrences = _field_occurrences(outer.value)
        nested: dict[int, list[_Field]] = {}
        for number, field in nested_occurrences:
            nested.setdefault(number, []).append(field)
        cipher_values = nested.get(1, [])
        digest_values = nested.get(2, [])
        if len(cipher_values) > 1:
            issues.append(f"cipher commitment #{index} cipher duplicated")
        if len(digest_values) > 1:
            issues.append(f"cipher commitment #{index} digest duplicated")
        cipher_field = cipher_values[0] if cipher_values else None
        digest_field = digest_values[0] if digest_values else None

        if cipher_field is None or cipher_field.wire != 0 or not isinstance(cipher_field.value, int):
            cipher_result = "missing-or-malformed"
            issues.append(f"cipher commitment #{index} cipher missing or malformed")
            cipher_id = None
        else:
            cipher_id = cipher_field.value
            cipher_name = UKEY2_CIPHERS.get(cipher_id)
            if cipher_name is None:
                cipher_result = f"{cipher_id}(unsupported-identifier)"
                issues.append(f"cipher commitment #{index} has unsupported identifier")
            else:
                # Recognition is schema-backed; it is not a local support claim.
                cipher_result = f"{cipher_id}({cipher_name}; local-support-unverified)"
                if cipher_id in seen_ciphers:
                    issues.append(f"cipher identifier {cipher_id} duplicated")
                seen_ciphers.add(cipher_id)

        if digest_field is None or digest_field.wire != 2 or not isinstance(digest_field.value, bytes):
            digest_result = "missing-or-malformed"
            issues.append(f"cipher commitment #{index} bytes missing or malformed")
        else:
            digest_length = len(digest_field.value)
            digest_result = f"{digest_length} bytes"
            if cipher_id in UKEY2_CIPHERS and digest_length != 64:
                issues.append(f"cipher commitment #{index} length is not 64 bytes for SHA-512")
        commitment_parts.append(f"#{index} cipher={cipher_result}, commitment={digest_result}")

    next_field = singular(4, "next_protocol")
    if next_field is None or next_field.wire != 2 or not isinstance(next_field.value, bytes):
        next_result = "missing-or-malformed"
        issues.append("next_protocol missing or malformed")
    else:
        try:
            next_field.value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            next_result = f"malformed-UTF8({len(next_field.value)} bytes)"
            issues.append("next_protocol malformed UTF-8")
        else:
            supported_match = next_field.value == UKEY2_DOCUMENTED_NEXT_PROTOCOL
            next_result = (
                f"present({len(next_field.value)} bytes), "
                f"matches-documented-reference-value={'yes' if supported_match else 'no'}"
            )
            if not supported_match:
                issues.append("next_protocol unsupported by documented reference value")

    commitment_result = "; ".join(commitment_parts) if commitment_parts else "none"
    issue_result = "; ".join(issues) if issues else "none"
    return (
        f"ClientInit version={version_result}; random={random_result}; "
        f"cipher_commitments={len(commitments)} [{commitment_result}]; "
        f"next_protocol={next_result}; issues={issue_result}; sensitive values omitted"
    )


def _decode_offline(payload: bytes) -> Frame | None:
    fields = _fields(payload)
    version = _varint_field(fields, 1)
    v1_bytes = _bytes_field(fields, 2)
    if version != 1 or v1_bytes is None:
        return None
    v1 = _fields(v1_bytes)
    kind = _varint_field(v1, 1)
    if kind is None:
        raise MalformedFrame("OfflineFrame v1 has no valid frame type.")
    name = OFFLINE_FRAME_TYPES.get(kind)
    if name is None:
        raise UnexpectedMessageType(f"Unrecognized OfflineFrame type number {kind}.")
    expected_body = OFFLINE_SUBFRAME_FIELDS[kind]
    bodies = [field_number for field_number in range(2, 14) if field_number in v1]
    if bodies != [expected_body] or _bytes_field(v1, expected_body) is None:
        raise MalformedFrame(f"OfflineFrame {name} is missing its documented body field.")
    return Frame(payload, len(payload), "OfflineFrame v1", name, "outer envelope recognized")


def _decode_ukey2(payload: bytes) -> Frame | None:
    fields = _fields(payload)
    raw_type = _varint_field(fields, 1)
    data = _bytes_field(fields, 2)

    # A valid enum value or a message_data-shaped field is enough to report a
    # UKEY2 envelope candidate, but never to invent a missing/unsupported type.
    if raw_type is None and data is None:
        return None
    name = UKEY2_TYPES.get(raw_type) if raw_type is not None else None
    if name is None:
        if raw_type is not None:
            raise UnexpectedMessageType(f"Unrecognized UKEY2 message type number {raw_type}.")
        return Frame(payload, len(payload), "UKEY2 envelope", "unknown", "message_type is missing or has the wrong wire type")
    if data is None:
        return Frame(payload, len(payload), "UKEY2", name, "message_data is missing or has the wrong wire type")
    if name != "CLIENT_INIT":
        return Frame(payload, len(payload), "UKEY2", name, "outer envelope recognized; message_data present")

    try:
        validation = _inspect_client_init(data)
    except MalformedFrame as exc:
        return Frame(payload, len(payload), "UKEY2", name, f"ClientInit invalid: {exc}")
    return Frame(payload, len(payload), "UKEY2", name, validation)


def decode_payload(payload: bytes) -> Frame:
    """Recognize documented outer envelopes without guessing unknown families."""
    offline_error: FrameError | None = None
    try:
        offline = _decode_offline(payload)
        if offline is not None:
            return offline
    except FrameError as exc:
        offline_error = exc
        if isinstance(exc, UnexpectedMessageType):
            raise

    try:
        ukey = _decode_ukey2(payload)
        if ukey is not None:
            return ukey
    except FrameError:
        raise

    if offline_error is not None:
        raise offline_error
    raise UnrecognizedMessage("Complete frame is neither a recognized OfflineFrame v1 nor UKEY2 envelope.")


def format_frame_hex(wire_bytes: bytes, limit: int = MAX_FRAME_HEX_BYTES) -> str:
    """Bounded hex rendering; input includes the four-byte length prefix."""
    if limit < 0:
        raise ValueError("limit cannot be negative")
    shown = wire_bytes[:limit]
    suffix = "" if len(shown) == len(wire_bytes) else f" ... (truncated; {len(wire_bytes)} total bytes)"
    return shown.hex(" ") + suffix


def make_frame_hex_dump_callback(index: int, printer: Callable[[str], None] = print) -> Callable[[bytes], None]:
    """Create a callback that emits only the selected complete frame as bounded hex."""
    if index < 1:
        raise ValueError("index must be at least 1")
    current = 0

    def dump(wire_bytes: bytes) -> None:
        nonlocal current
        current += 1
        if current == index:
            printer(
                f"Frame #{index} wire hex (includes 4-byte big-endian length prefix; "
                f"showing at most {MAX_FRAME_HEX_BYTES} bytes): {format_frame_hex(wire_bytes)}"
            )

    return dump


def read_frame(
    sock: SocketReader,
    max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH,
    *,
    on_wire_frame: Callable[[bytes], None] | None = None,
    classify: bool = True,
) -> Frame:
    """Read one bounded length-prefixed frame; classify=False leaves its payload opaque."""
    if max_frame_length < 1:
        raise ValueError("max_frame_length must be positive")
    header = _read_exact(sock, 4, header=True)
    length = int.from_bytes(header, "big")
    if length == 0:
        raise MalformedFrame("Zero-length frames are not valid.")
    if length > max_frame_length:
        raise MalformedFrame(f"Declared frame length exceeds {max_frame_length} bytes.")
    payload = _read_exact(sock, length, header=False)
    wire_bytes = header + payload
    if on_wire_frame is not None:
        on_wire_frame(wire_bytes)
    if not classify:
        return Frame(payload, length, "unclassified", "unclassified", "payload not parsed", wire_bytes)
    decoded = decode_payload(payload)
    return Frame(payload, length, decoded.family, decoded.message_type, decoded.validation, wire_bytes)


def _encode_varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7f:
        encoded.append((value & 0x7f) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _encode_varint_field(number: int, value: int) -> bytes:
    return _encode_varint(number << 3) + _encode_varint(value)


def _encode_bytes_field(number: int, value: bytes) -> bytes:
    return _encode_varint((number << 3) | 2) + _encode_varint(len(value)) + value


def encode_connection_response_accept(os_type: int | None = None) -> bytes:
    """Build a framed Nearby v1 ACCEPT response with documented status fields.

    This is used only by the explicitly opted-in response mode. The old
    integer status is retained alongside the enum response, as Google's
    current Nearby encoder does for compatibility.
    """
    if os_type is None:
        os_type = {"Windows": 3, "Linux": 100}.get(platform.system(), 0)
    if os_type not in (0, 1, 2, 3, 4, 100):
        raise ValueError("Unsupported OfflineFrame OsInfo type.")
    os_info = _encode_varint_field(1, os_type)
    connection_response = (
        _encode_varint_field(1, 0)  # Deprecated STATUS_OK.
        + _encode_varint_field(3, 1)  # ResponseStatus.ACCEPT.
        + _encode_bytes_field(4, os_info)
        + _encode_varint_field(5, 0)  # No multiplex socket support.
    )
    v1 = _encode_varint_field(1, 2) + _encode_bytes_field(3, connection_response)
    payload = _encode_varint_field(1, 1) + _encode_bytes_field(2, v1)
    return len(payload).to_bytes(4, "big") + payload


def parse_connection_response(payload: bytes) -> str:
    """Validate an OfflineFrame v1 CONNECTION_RESPONSE and return ACCEPT/REJECT."""
    try:
        outer = _field_occurrences(payload)
        outer_fields: dict[int, list[_Field]] = {}
        for number, item in outer:
            outer_fields.setdefault(number, []).append(item)
        version_values = outer_fields.get(1, [])
        v1_values = outer_fields.get(2, [])
        if (len(version_values) != 1 or version_values[0].wire != 0
                or version_values[0].value != 1):
            raise MalformedFrame("OfflineFrame version is missing, duplicated, or unsupported.")
        if len(v1_values) != 1 or v1_values[0].wire != 2:
            raise MalformedFrame("OfflineFrame v1 body is missing or duplicated.")

        v1_fields: dict[int, list[_Field]] = {}
        for number, item in _field_occurrences(v1_values[0].value):
            v1_fields.setdefault(number, []).append(item)
        types = v1_fields.get(1, [])
        bodies = v1_fields.get(3, [])
        if (len(types) != 1 or types[0].wire != 0 or types[0].value != 2
                or len(bodies) != 1 or bodies[0].wire != 2):
            raise MalformedFrame("Expected one CONNECTION_RESPONSE type and body.")
        if any(number in v1_fields for number in (2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)):
            raise MalformedFrame("CONNECTION_RESPONSE contains a conflicting OfflineFrame body.")

        response_fields: dict[int, list[_Field]] = {}
        for number, item in _field_occurrences(bodies[0].value):
            response_fields.setdefault(number, []).append(item)
        response_wire_types = {1: 0, 2: 2, 3: 0, 4: 2, 5: 0, 6: 0, 7: 0, 8: 2, 9: 0, 10: 2}
        for number, values in response_fields.items():
            if number in response_wire_types:
                if len(values) != 1:
                    raise MalformedFrame("CONNECTION_RESPONSE field is duplicated.")
                if values[0].wire != response_wire_types[number]:
                    raise MalformedFrame("CONNECTION_RESPONSE field has the wrong wire type.")
        os_info_values = response_fields.get(4, [])
        if os_info_values:
            os_info_fields: dict[int, list[_Field]] = {}
            for number, item in _field_occurrences(os_info_values[0].value):
                os_info_fields.setdefault(number, []).append(item)
            os_type_values = os_info_fields.get(1, [])
            if os_type_values and (
                len(os_type_values) != 1
                or os_type_values[0].wire != 0
                or os_type_values[0].value not in (0, 1, 2, 3, 4, 100)
            ):
                raise MalformedFrame("CONNECTION_RESPONSE OsInfo type is malformed or unsupported.")
        legacy_values = response_fields.get(1, [])
        enum_values = response_fields.get(3, [])
        if len(legacy_values) > 1 or len(enum_values) > 1:
            raise MalformedFrame("CONNECTION_RESPONSE status field is duplicated.")
        legacy: int | None = None
        response: int | None = None
        if legacy_values:
            item = legacy_values[0]
            if item.wire != 0 or not isinstance(item.value, int):
                raise MalformedFrame("Legacy CONNECTION_RESPONSE status is malformed.")
            legacy = item.value
        if enum_values:
            item = enum_values[0]
            if item.wire != 0 or not isinstance(item.value, int):
                raise MalformedFrame("CONNECTION_RESPONSE response enum is malformed.")
            response = item.value
            if response not in (1, 2):
                raise MalformedFrame("CONNECTION_RESPONSE response enum is unsupported.")
        if legacy is None and response is None:
            raise MalformedFrame("CONNECTION_RESPONSE has no status field.")
        if response == 1:
            if legacy not in (None, 0):
                raise MalformedFrame("CONNECTION_RESPONSE status fields conflict.")
            return "ACCEPT"
        if response == 2:
            if legacy == 0:
                raise MalformedFrame("CONNECTION_RESPONSE status fields conflict.")
            raise PeerRejectedConnection("Peer rejected the Nearby connection.")
        if legacy == 0:
            return "ACCEPT"
        raise MalformedFrame("Legacy CONNECTION_RESPONSE status is non-success or unsupported.")
    except MalformedFrame as exc:
        if isinstance(exc, PeerRejectedConnection):
            raise
        raise


class ConnectionResponseExchange:
    """One-shot plaintext response exchange performed after validated UKEY2."""

    def __init__(self) -> None:
        self._state = "ready"

    @property
    def state(self) -> str:
        return self._state

    def send_accept(self, os_type: int | None = None) -> bytes:
        if self._state != "ready":
            raise MalformedFrame("CONNECTION_RESPONSE accept was already sent.")
        wire = encode_connection_response_accept(os_type)
        self._state = "awaiting-peer-response"
        return wire

    def receive_peer_response(self, payload: bytes) -> str:
        if self._state != "awaiting-peer-response":
            raise MalformedFrame("Unexpected or duplicate peer CONNECTION_RESPONSE.")
        try:
            result = parse_connection_response(payload)
        except PeerRejectedConnection:
            self._state = "rejected"
            raise
        except FrameError:
            self._state = "failed"
            raise
        self._state = "complete"
        return result

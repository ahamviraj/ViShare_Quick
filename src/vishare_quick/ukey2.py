"""Experimental UKEY2 responder for the observed P256_SHA512 offer.

Only the UKEY2 exchange is implemented. It does not authenticate a user's
identity out of band or implement the subsequent secure/Quick Share protocol.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vishare_quick.protocol import (
    MalformedFrame,
    UKEY2_DOCUMENTED_NEXT_PROTOCOL,
    _Field,
    _field_occurrences,
)

P256_SHA512 = 100
UKEY2_VERSION = 1
AUTH_SALT = b"UKEY2 v1 auth"
NEXT_SALT = b"UKEY2 v1 next"


class HandshakeError(Exception):
    """A safe-to-report UKEY2 state or validation failure."""


@dataclass(frozen=True, repr=False)
class HandshakeSecrets:
    """Derived material kept out of repr/logging; values are never sent here."""

    auth_string: bytes = field(repr=False)
    next_secret: bytes = field(repr=False)


def _varint(value: int) -> bytes:
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _vfield(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _bfield(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _parse_fields(payload: bytes) -> dict[int, list[_Field]]:
    try:
        occurrences = _field_occurrences(payload)
    except MalformedFrame as exc:
        raise HandshakeError("Malformed protobuf message.") from exc
    fields: dict[int, list[_Field]] = {}
    for number, item in occurrences:
        fields.setdefault(number, []).append(item)
    return fields


def _singular(fields: dict[int, list[_Field]], number: int, name: str, wire: int) -> bytes | int:
    values = fields.get(number, [])
    if len(values) != 1:
        raise HandshakeError(f"{name} must be present exactly once.")
    item = values[0]
    if item.wire != wire:
        raise HandshakeError(f"{name} has the wrong protobuf wire type.")
    return item.value


def _outer_message(payload: bytes, expected_type: int) -> bytes:
    outer = _parse_fields(payload)
    message_type = _singular(outer, 1, "UKEY2 message_type", 0)
    message_data = _singular(outer, 2, "UKEY2 message_data", 2)
    if message_type != expected_type:
        raise HandshakeError("Unexpected UKEY2 message type for the current handshake state.")
    if not isinstance(message_data, bytes):
        raise HandshakeError("UKEY2 message_data is malformed.")
    return message_data


def _client_init_offer(payload: bytes) -> bytes:
    """Validate ClientInit and return the selected P256/SHA512 commitment."""
    data = _outer_message(payload, 2)
    init = _parse_fields(data)
    version = _singular(init, 1, "ClientInit version", 0)
    if version != UKEY2_VERSION:
        raise HandshakeError("Unsupported UKEY2 version.")
    random = _singular(init, 2, "ClientInit random", 2)
    if not isinstance(random, bytes) or len(random) != 32:
        raise HandshakeError("ClientInit random must be 32 bytes.")
    next_protocol = _singular(init, 4, "ClientInit next_protocol", 2)
    if not isinstance(next_protocol, bytes):
        raise HandshakeError("ClientInit next_protocol is malformed.")
    try:
        next_protocol.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HandshakeError("ClientInit next_protocol is malformed UTF-8.") from exc
    if next_protocol != UKEY2_DOCUMENTED_NEXT_PROTOCOL:
        raise HandshakeError("ClientInit next_protocol is not supported by this responder.")

    commitments = init.get(3, [])
    if not commitments:
        raise HandshakeError("ClientInit contains no cipher commitments.")
    seen: set[int] = set()
    selected: bytes | None = None
    for index, entry in enumerate(commitments, start=1):
        if entry.wire != 2 or not isinstance(entry.value, bytes):
            raise HandshakeError(f"Cipher commitment {index} is malformed.")
        fields = _parse_fields(entry.value)
        cipher = _singular(fields, 1, f"Cipher commitment {index} cipher", 0)
        commitment = _singular(fields, 2, f"Cipher commitment {index} bytes", 2)
        if not isinstance(cipher, int) or not isinstance(commitment, bytes):
            raise HandshakeError(f"Cipher commitment {index} is malformed.")
        if cipher in seen:
            raise HandshakeError("ClientInit repeats a cipher commitment.")
        seen.add(cipher)
        if cipher == P256_SHA512:
            if len(commitment) != hashlib.sha512().digest_size:
                raise HandshakeError("P256_SHA512 commitment must be 64 bytes.")
            selected = commitment
    if selected is None:
        raise HandshakeError("ClientInit does not offer the supported P256_SHA512 cipher.")
    return selected


def _encode_generic_p256(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    # SecureMessage's minimal positive big-endian two's-complement encoding.
    # A leading zero is needed only when the high bit would otherwise mark a
    # coordinate negative (the result is then 33 bytes).
    def encode_coordinate(value: int) -> bytes:
        raw = value.to_bytes(32, "big")
        return b"\x00" + raw if raw[0] & 0x80 else raw

    x = encode_coordinate(numbers.x)
    y = encode_coordinate(numbers.y)
    ec_point = _bfield(1, x) + _bfield(2, y)
    return _vfield(1, 1) + _bfield(2, ec_point)


def _encode_server_init(random: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
    generic_public_key = _encode_generic_p256(public_key)
    server_init = (
        _vfield(1, UKEY2_VERSION)
        + _bfield(2, random)
        + _vfield(3, P256_SHA512)
        + _bfield(4, generic_public_key)
    )
    return _vfield(1, 3) + _bfield(2, server_init)


def _decode_generic_p256(encoded: bytes) -> ec.EllipticCurvePublicKey:
    generic = _parse_fields(encoded)
    key_type = _singular(generic, 1, "GenericPublicKey type", 0)
    if key_type != 1:
        raise HandshakeError("Client public key is not EC_P256.")
    point_bytes = _singular(generic, 2, "GenericPublicKey ec_p256_public_key", 2)
    if not isinstance(point_bytes, bytes):
        raise HandshakeError("Client P-256 public key is malformed.")
    if 3 in generic or 4 in generic:
        raise HandshakeError("Client public key contains an unsupported key structure.")
    point = _parse_fields(point_bytes)
    x_bytes = _singular(point, 1, "P-256 public key x", 2)
    y_bytes = _singular(point, 2, "P-256 public key y", 2)
    if not isinstance(x_bytes, bytes) or not isinstance(y_bytes, bytes):
        raise HandshakeError("Client P-256 coordinates are malformed.")

    def coordinate(encoded_coordinate: bytes, name: str) -> int:
        if not encoded_coordinate or len(encoded_coordinate) > 33:
            raise HandshakeError(f"Client P-256 coordinate {name} has an invalid length.")
        if len(encoded_coordinate) == 33 and encoded_coordinate[0] != 0:
            raise HandshakeError(f"Client P-256 coordinate {name} has invalid signed encoding.")
        value = int.from_bytes(encoded_coordinate, "big", signed=True)
        if value <= 0:
            raise HandshakeError(f"Client P-256 coordinate {name} is invalid.")
        return value

    try:
        numbers = ec.EllipticCurvePublicNumbers(
            coordinate(x_bytes, "x"), coordinate(y_bytes, "y"), ec.SECP256R1()
        )
        return numbers.public_key()
    except (ValueError, TypeError) as exc:
        raise HandshakeError("Client P-256 public point is invalid.") from exc


class Ukey2ServerHandshake:
    """Single-use P256_SHA512 UKEY2 responder state machine."""

    def __init__(self) -> None:
        self._state = "start"
        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._client_init: bytes | None = None
        self._server_init: bytes | None = None
        self._client_commitment: bytes | None = None

    @property
    def state(self) -> str:
        return self._state

    def respond_to_client_init(
        self,
        client_init_payload: bytes,
        *,
        private_key: ec.EllipticCurvePrivateKey | None = None,
        random_bytes: bytes | None = None,
    ) -> bytes:
        if self._state != "start":
            raise HandshakeError("UKEY2 responder is not in the ClientInit state.")
        if not isinstance(client_init_payload, bytes):
            raise HandshakeError("ClientInit payload must be bytes.")
        commitment = _client_init_offer(client_init_payload)
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise HandshakeError("Responder private key must be an elliptic-curve private key.")
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise HandshakeError("Responder private key must use NIST P-256.")
        nonce = secrets.token_bytes(32) if random_bytes is None else random_bytes
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise HandshakeError("Responder random must be 32 bytes.")
        payload = _encode_server_init(nonce, private_key.public_key())
        if len(payload) > 1024 * 1024:
            raise HandshakeError("ServerInit exceeds the configured frame limit.")

        # The Google UKEY2 API hashes/stores the serialized Ukey2Message
        # protobuf. Its transport shell adds/removes the 4-byte TCP prefix
        # outside this API, so these transcript messages exclude that prefix.
        self._client_init = bytes(client_init_payload)
        self._server_init = payload
        self._client_commitment = commitment
        self._private_key = private_key
        self._state = "waiting-for-client-finish"
        return len(payload).to_bytes(4, "big") + payload

    def receive_client_finish(self, client_finish_payload: bytes) -> HandshakeSecrets:
        if self._state != "waiting-for-client-finish":
            raise HandshakeError("UKEY2 responder is not waiting for ClientFinish.")
        if self._private_key is None or self._client_init is None or self._server_init is None:
            raise HandshakeError("UKEY2 responder state is incomplete.")
        if self._client_commitment is None:
            raise HandshakeError("Client commitment is unavailable.")
        if not isinstance(client_finish_payload, bytes):
            raise HandshakeError("ClientFinish payload must be bytes.")

        # Validate the message envelope/type before applying the selected
        # cipher's commitment hash to its serialized Ukey2Message bytes.
        data = _outer_message(client_finish_payload, 4)
        actual = hashlib.sha512(client_finish_payload).digest()
        if not hmac.compare_digest(actual, self._client_commitment):
            raise HandshakeError("ClientFinish commitment verification failed.")

        finish = _parse_fields(data)
        encoded_public_key = _singular(finish, 1, "ClientFinish public_key", 2)
        if not isinstance(encoded_public_key, bytes):
            raise HandshakeError("ClientFinish public key is malformed.")
        peer_public_key = _decode_generic_p256(encoded_public_key)
        try:
            raw_dh = self._private_key.exchange(ec.ECDH(), peer_public_key)
        except ValueError as exc:
            raise HandshakeError("P-256 key agreement failed.") from exc

        # The Google Android implementation's KeyAgreementSha256 hashes the
        # raw ECDH result with SHA-256; its CryptoOps::Hkdf is HKDF-SHA256.
        dh_secret = hashlib.sha256(raw_dh).digest()
        transcript = self._client_init + self._server_init
        auth_string = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=AUTH_SALT, info=transcript
        ).derive(dh_secret)
        next_secret = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=NEXT_SALT, info=transcript
        ).derive(dh_secret)
        self._state = "verification-needed"
        self._private_key = None
        self._client_commitment = None
        return HandshakeSecrets(auth_string, next_secret)

"""Synthetic deterministic UKEY2 vectors; these are not Android captures."""
import hashlib
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vishare_quick.protocol import UKEY2_DOCUMENTED_NEXT_PROTOCOL, read_frame
from vishare_quick.ukey2 import HandshakeError, Ukey2ServerHandshake


def varint(value):
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def vfield(number, value):
    return varint(number << 3) + varint(value)


def bfield(number, value):
    return varint((number << 3) | 2) + varint(len(value)) + value


def framed(payload):
    return len(payload).to_bytes(4, "big") + payload


def generic_p256(public_key):
    numbers = public_key.public_numbers()
    def encode(value):
        raw = value.to_bytes(32, "big")
        return b"\x00" + raw if raw[0] & 0x80 else raw
    x = encode(numbers.x)
    y = encode(numbers.y)
    return vfield(1, 1) + bfield(2, bfield(1, x) + bfield(2, y))


def client_finish_payload(private_key):
    finish = bfield(1, generic_p256(private_key.public_key()))
    return vfield(1, 4) + bfield(2, finish)


def client_init_payload(finish_payload, *, cipher=100, next_protocol=UKEY2_DOCUMENTED_NEXT_PROTOCOL):
    commitment = hashlib.sha512(finish_payload).digest()
    offer = b"" if cipher is None else bfield(3, vfield(1, cipher) + bfield(2, commitment))
    init = vfield(1, 1) + bfield(2, b"C" * 32) + offer
    if next_protocol is not None:
        init += bfield(4, next_protocol)
    return vfield(1, 2) + bfield(2, init)


class ChoppySocket:
    def __init__(self, data):
        self.data = bytearray(data)

    def recv(self, size):
        count = min(size, 7, len(self.data))
        result = bytes(self.data[:count])
        del self.data[:count]
        return result


class TestUkey2ServerHandshake(unittest.TestCase):
    def setUp(self):
        self.client_key = ec.derive_private_key(0x123456789ABCDEF, ec.SECP256R1())
        self.server_key = ec.derive_private_key(3, ec.SECP256R1())
        self.client_finish = client_finish_payload(self.client_key)
        self.client_init = client_init_payload(self.client_finish)

    def test_valid_synthetic_p256_exchange_and_hkdf_outputs(self):
        responder = Ukey2ServerHandshake()
        server_wire = responder.respond_to_client_init(
            self.client_init, private_key=self.server_key, random_bytes=b"S" * 32
        )
        self.assertEqual(responder.state, "waiting-for-client-finish")
        server_frame = read_frame(ChoppySocket(server_wire))
        self.assertEqual(server_frame.message_type, "SERVER_INIT")
        self.assertEqual(server_frame.declared_length, 117)
        self.assertEqual(server_wire[:4], (117).to_bytes(4, "big"))

        secrets = responder.receive_client_finish(self.client_finish)
        self.assertEqual(responder.state, "verification-needed")
        self.assertEqual(len(secrets.auth_string), 32)
        self.assertEqual(len(secrets.next_secret), 32)
        self.assertNotIn(secrets.auth_string.hex(), repr(secrets))
        self.assertNotIn(secrets.next_secret.hex(), repr(secrets))

        # Independently derive from the client's side; transcript messages are
        # serialized Ukey2Message protobufs without the TCP length prefixes.
        shared = self.client_key.exchange(ec.ECDH(), self.server_key.public_key())
        dh_secret = hashlib.sha256(shared).digest()
        transcript = self.client_init + server_frame.payload
        expected_auth = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"UKEY2 v1 auth", info=transcript
        ).derive(dh_secret)
        expected_next = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"UKEY2 v1 next", info=transcript
        ).derive(dh_secret)
        self.assertEqual(secrets.auth_string, expected_auth)
        self.assertEqual(secrets.next_secret, expected_next)

    def test_client_finish_commitment_is_over_ukey2_message_without_tcp_prefix(self):
        wrong_commitment = hashlib.sha512(framed(self.client_finish)).digest()
        init = client_init_payload(self.client_finish)
        # Replace the test fixture's commitment with the prefix-inclusive variant.
        init_data = bfield(2, b"C" * 32) + bfield(3, vfield(1, 100) + bfield(2, wrong_commitment))
        init_data += bfield(4, UKEY2_DOCUMENTED_NEXT_PROTOCOL)
        init = vfield(1, 2) + bfield(2, vfield(1, 1) + init_data)
        responder = Ukey2ServerHandshake()
        responder.respond_to_client_init(
            init, private_key=self.server_key, random_bytes=b"S" * 32
        )
        with self.assertRaisesRegex(HandshakeError, "commitment verification failed"):
            responder.receive_client_finish(self.client_finish)

    def test_invalid_commitment_and_unexpected_states_fail(self):
        responder = Ukey2ServerHandshake()
        with self.assertRaisesRegex(HandshakeError, "not waiting"):
            responder.receive_client_finish(self.client_finish)
        responder.respond_to_client_init(self.client_init, private_key=self.server_key, random_bytes=b"S" * 32)
        with self.assertRaisesRegex(HandshakeError, "commitment verification failed"):
            responder.receive_client_finish(self.client_finish + vfield(5, 1))

    def test_invalid_or_unsupported_client_init_is_rejected_before_response(self):
        cases = [
            (client_init_payload(self.client_finish, cipher=None), "no cipher commitments"),
            (client_init_payload(self.client_finish, cipher=101), "does not offer"),
            (client_init_payload(self.client_finish, next_protocol=None), "next_protocol"),
            (client_init_payload(self.client_finish, next_protocol=b"unsupported"), "next_protocol"),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(HandshakeError, message):
                    Ukey2ServerHandshake().respond_to_client_init(
                        payload, private_key=self.server_key, random_bytes=b"S" * 32
                    )

    def test_invalid_peer_point_is_rejected_after_valid_commitment(self):
        invalid_generic = vfield(1, 1) + bfield(2, bfield(1, b"\x00\x01") + bfield(2, b"\x00\x01"))
        finish = vfield(1, 4) + bfield(2, bfield(1, invalid_generic))
        init = client_init_payload(finish)
        responder = Ukey2ServerHandshake()
        responder.respond_to_client_init(init, private_key=self.server_key, random_bytes=b"S" * 32)
        with self.assertRaisesRegex(HandshakeError, "public point is invalid"):
            responder.receive_client_finish(finish)

    def test_invalid_response_random_and_non_p256_server_key_rejected(self):
        with self.assertRaisesRegex(HandshakeError, "random must be 32"):
            Ukey2ServerHandshake().respond_to_client_init(
                self.client_init, private_key=self.server_key, random_bytes=b"short"
            )
        other_curve = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaisesRegex(HandshakeError, "must use NIST P-256"):
            Ukey2ServerHandshake().respond_to_client_init(
                self.client_init, private_key=other_curve, random_bytes=b"S" * 32
            )


if __name__ == "__main__":
    unittest.main()

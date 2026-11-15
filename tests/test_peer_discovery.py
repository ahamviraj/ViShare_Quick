"""Parsing tests for discovery records.

Fixtures here are hand-encoded from the documented shapes in
``docs/ALPHA_0.6_SENDER_RESEARCH.md``. They are not captures from a specific
device; the goal is to pin the bit layout, the optional-name rule, and the
display sanitisation that keeps peer input harmless in a terminal or browser.
"""
from __future__ import annotations

import base64
import ipaddress
import unittest

from vishare_quick.peer_discovery import (
    SERVICE_TYPE,
    DiscoveryError,
    Peer,
    decode_endpoint_info,
    decode_instance_name,
    fallback_display_name,
    peer_from_service_info,
    sanitize_display_name,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def endpoint_info(flags: int, name: str | None = None) -> bytes:
    blob = bytes([flags]) + bytes(range(16))
    if name is not None:
        raw = name.encode("utf-8")
        blob += bytes([len(raw)]) + raw
    return blob


def instance_name(endpoint_id: str, *, prefix: int = 0x23) -> str:
    payload = bytes([prefix]) + endpoint_id.encode("ascii") + bytes.fromhex("FC9F5E") + b"\x00\x00"
    return f"{b64url(payload)}.{SERVICE_TYPE}"


class EndpointInfoTests(unittest.TestCase):
    def test_flags_unpack_version_visibility_and_device_type(self):
        # version=2, visible=0, device_type=2 (tablet) -> 0100 0100
        decoded = decode_endpoint_info(endpoint_info(0b01000100, "ViruDaya's tablet"))
        self.assertEqual(decoded.version, 2)
        self.assertFalse(decoded.visible)
        self.assertEqual(decoded.device_type, 2)
        self.assertEqual(decoded.device_name, "ViruDaya's tablet")

    def test_fixed_header_only_is_valid_and_has_no_name(self):
        decoded = decode_endpoint_info(endpoint_info(0b00000010))
        self.assertEqual(decoded.device_type, 1)
        self.assertIsNone(decoded.device_name)

    def test_truncated_name_segment_is_ignored(self):
        blob = endpoint_info(0b00000100) + bytes([10]) + b"short"
        decoded = decode_endpoint_info(blob)
        self.assertIsNone(decoded.device_name)

    def test_non_utf8_name_is_ignored(self):
        blob = endpoint_info(0b00000100) + bytes([2]) + b"\xff\xfe"
        self.assertIsNone(decode_endpoint_info(blob).device_name)

    def test_short_input_is_rejected(self):
        with self.assertRaises(DiscoveryError):
            decode_endpoint_info(b"\x00" * 16)
        with self.assertRaises(DiscoveryError):
            decode_endpoint_info(b"")


class InstanceNameTests(unittest.TestCase):
    def test_documented_instance_shape_yields_the_endpoint_id(self):
        self.assertEqual(decode_instance_name(instance_name("5W3R")), "5W3R")

    def test_real_capture_instance_decodes(self):
        # Instance observed from the XPad during alpha_0.6 development.
        self.assertEqual(decode_instance_name("IzVXM1L8n14AAA"), "5W3R")

    def test_foreign_shapes_are_rejected(self):
        self.assertIsNone(decode_instance_name("not-a-real-instance"))
        self.assertIsNone(decode_instance_name(instance_name("5W3R", prefix=0x24)))
        self.assertIsNone(decode_instance_name(instance_name("5W3!")))
        foreign = b64url(bytes([0x23]) + b"AB12" + b"\x00\x00\x00" + b"\x00\x00")
        self.assertIsNone(decode_instance_name(f"{foreign}.{SERVICE_TYPE}"))


class DisplayNameTests(unittest.TestCase):
    def test_sanitize_collapses_whitespace_and_strips_control_characters(self):
        self.assertEqual(sanitize_display_name("  Viru \x00\tDaya  "), "Viru Daya")
        self.assertIsNone(sanitize_display_name("\x00\x01"))
        self.assertIsNone(sanitize_display_name(None))

    def test_long_names_are_bounded(self):
        cleaned = sanitize_display_name("x" * 500)
        assert cleaned is not None
        self.assertEqual(len(cleaned), 64)

    def test_fallback_uses_device_label_and_endpoint_id(self):
        self.assertEqual(fallback_display_name(2, "5W3R"), "Tablet (5W3R)")
        self.assertEqual(fallback_display_name(99, None), "Device")


class FakeServiceInfo:
    def __init__(self, name, addresses, port, properties):
        self.name = name
        self.addresses = addresses
        self.port = port
        self.properties = properties


class ServiceInfoTests(unittest.TestCase):
    def test_peer_is_built_from_txt_and_instance(self):
        info = FakeServiceInfo(
            instance_name("5W3R"),
            [ipaddress.ip_address("192.168.43.39").packed],
            53601,
            {b"n": b64url(endpoint_info(0b01000100)).encode("ascii")},
        )
        peer = peer_from_service_info(info)
        assert peer is not None
        self.assertEqual(peer.host, "192.168.43.39")
        self.assertEqual(peer.port, 53601)
        self.assertEqual(peer.endpoint_id, "5W3R")
        self.assertEqual(peer.device_name, "Tablet (5W3R)")
        self.assertFalse(peer.name_is_advertised)

    def test_advertised_name_wins_over_the_fallback(self):
        info = FakeServiceInfo(
            instance_name("AB12"),
            [ipaddress.ip_address("10.0.0.9").packed],
            1234,
            {b"n": b64url(endpoint_info(0b00000110, "Desk Laptop")).encode("ascii")},
        )
        peer = peer_from_service_info(info)
        assert peer is not None
        self.assertEqual(peer.device_name, "Desk Laptop")
        self.assertEqual(peer.device_type, 3)
        self.assertTrue(peer.name_is_advertised)

    def test_missing_ipv4_or_port_returns_none(self):
        no_ipv4 = FakeServiceInfo(
            instance_name("AB12"),
            [ipaddress.ip_address("::1").packed],
            1234,
            {},
        )
        self.assertIsNone(peer_from_service_info(no_ipv4))
        no_port = FakeServiceInfo(instance_name("AB12"), [b"\x0a\x00\x00\x01"], 0, {})
        self.assertIsNone(peer_from_service_info(no_port))

    def test_bad_txt_payload_falls_back_without_raising(self):
        info = FakeServiceInfo(
            instance_name("AB12"),
            [ipaddress.ip_address("10.0.0.9").packed],
            1234,
            {b"n": b"!!!not-base64!!!"},
        )
        peer = peer_from_service_info(info)
        assert peer is not None
        self.assertEqual(peer.device_name, "Device (AB12)")

    def test_key_is_host_and_port(self):
        peer = Peer("i", "AB12", "Name", 2, "10.0.0.9", 1234, True)
        self.assertEqual(peer.key, "10.0.0.9:1234")


if __name__ == "__main__":
    unittest.main()

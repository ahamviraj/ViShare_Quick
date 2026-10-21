"""Experimental Quick Share-compatible mDNS endpoint advertisement.

This module implements the documented DNS-SD advertisement shape only. It does not
implement the Quick Share/UKEY2 handshake, file transfer, or BLE trigger advertisement.
"""
from __future__ import annotations

import base64
import os
import secrets
import socket
import string
import threading
import time
from typing import Any


SERVICE_TYPE = "_FC9F5ED42C8A._tcp.local."
SERVICE_ID_BYTES = bytes.fromhex("FC9F5E")
ENDPOINT_ID_ALPHABET = string.ascii_letters + string.digits


def _base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def make_instance_name() -> tuple[str, str]:
    """Return (service instance name, four-character endpoint ID)."""
    endpoint_id = "".join(secrets.choice(ENDPOINT_ID_ALPHABET) for _ in range(4))
    instance_payload = bytes([0x23]) + endpoint_id.encode("ascii") + SERVICE_ID_BYTES + b"\x00\x00"
    instance = _base64url_no_padding(instance_payload)
    return f"{instance}.{SERVICE_TYPE}", endpoint_id


def make_endpoint_info(device_name: str) -> bytes:
    """Encode the public, visible endpoint-info TXT payload based on the published protocol notes."""
    name_bytes = device_name.encode("utf-8")
    if not name_bytes or len(name_bytes) > 255:
        raise ValueError("Device name must be 1–255 UTF-8 bytes.")
    # First byte: version=1, visible=0, device type=laptop(3), reserved=0.
    # Layout from NearDrop's published protocol description.
    flags = (1 << 5) | (3 << 1)
    metadata = os.urandom(16)
    return bytes([flags]) + metadata + bytes([len(name_bytes)]) + name_bytes


def _get_local_ipv4() -> str:
    """Best-effort local IPv4 address selection for the zeroconf record."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect does not send application data; it asks the OS route table
        # which local interface would be used for this destination.
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def run_advertiser(device_name: str = "ViShare Quick", port: int = 0, duration_seconds: float = 120.0) -> dict[str, Any]:
    """Advertise an experimental endpoint and accept TCP connections until timeout/Ctrl+C."""
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError as exc:
        raise RuntimeError(
            "The 'zeroconf' dependency is missing. Install project dependencies with "
            "`python -m pip install -e .` and try again."
        ) from exc

    if not device_name.strip():
        raise ValueError("Device name cannot be empty.")
    if port < 0 or port > 65535:
        raise ValueError("Port must be between 0 and 65535.")
    if duration_seconds <= 0 or duration_seconds > 3600:
        raise ValueError("Duration must be greater than 0 and at most 3600 seconds.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    server.settimeout(1.0)
    actual_port = server.getsockname()[1]
    local_ip = _get_local_ipv4()

    instance_name, endpoint_id = make_instance_name()
    endpoint_info = _base64url_no_padding(make_endpoint_info(device_name))
    properties = {b"n": endpoint_info.encode("ascii")}
    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=instance_name,
        addresses=[socket.inet_aton(local_ip)],
        port=actual_port,
        properties=properties,
        server=(socket.gethostname().replace(" ", "-") + ".local."),
    )
    zc = Zeroconf()
    accepted = 0
    started = time.monotonic()
    try:
        zc.register_service(info)
        try:
            while time.monotonic() - started < duration_seconds:
                try:
                    conn, peer = server.accept()
                except socket.timeout:
                    continue
                accepted += 1
                try:
                    print(f"TCP connection #{accepted} from {peer[0]}:{peer[1]}")
                    conn.settimeout(2.0)
                    # Intentionally do not send a fake protocol response.
                    # A native Quick Share client expects the real offline-frame/UKEY2 handshake.
                    try:
                        data = conn.recv(64)
                        if data:
                            print(f"Received {len(data)} initial bytes; protocol handshake is not implemented yet.")
                    except socket.timeout:
                        pass
                finally:
                    conn.close()
        finally:
            zc.unregister_service(info)
    finally:
        zc.close()
        server.close()

    return {
        "instance_name": instance_name,
        "endpoint_id": endpoint_id,
        "local_ip": local_ip,
        "port": actual_port,
        "duration_seconds": time.monotonic() - started,
        "tcp_connections": accepted,
    }

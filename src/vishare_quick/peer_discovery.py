"""Discovery of Quick Share receivers on the local network.

The receiver side advertises in :mod:`vishare_quick.advertise`. This module is
the sender-side counterpart: it browses the same DNS-SD service type and turns
each resolved record into a display-safe :class:`Peer`.

Wire facts used here (see ``docs/ALPHA_0.6_SENDER_RESEARCH.md``):

* The service instance name is base64url (no padding) of ten bytes: ``0x23``,
  a four-character endpoint ID, ``FC 9F 5E``, and two zero bytes.
* The TXT record ``n`` is base64url of an endpoint-info blob: one flag byte,
  sixteen device-identification bytes, and an optional length-prefixed name.
* The name is only present when the visibility bit is clear. Android devices
  often advertise without a name even in "Everyone" mode, so a friendly
  fallback built from the device type and endpoint ID is required.

Discovery is presentation only. A name, device type, or address learned here is
never treated as identity, and nothing in this module connects to a peer.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

SERVICE_TYPE = "_FC9F5ED42C8A._tcp.local."
PCP_P2P_CLUSTER = 0x23
SERVICE_ID_BYTES = bytes.fromhex("FC9F5E")
INSTANCE_PAYLOAD_LENGTH = 10
ENDPOINT_INFO_MIN_LENGTH = 17
MAX_DISPLAY_NAME = 64

DEVICE_TYPE_LABELS = {
    0: "Device",
    1: "Phone",
    2: "Tablet",
    3: "Computer",
    4: "Car",
    5: "Foldable",
    6: "XR device",
}

# C0/C1 controls, bidi overrides, and zero-width separators are unsafe in a
# terminal, a browser, or a log line.
_UNSAFE_DISPLAY = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


class DiscoveryError(Exception):
    """An mDNS browse could not be started or is unavailable."""


@dataclass(frozen=True)
class EndpointInfo:
    """Decoded endpoint-info blob with the name kept optional."""

    version: int
    visible: bool
    device_type: int
    device_name: str | None


@dataclass(frozen=True)
class Peer:
    """One resolved Quick Share receiver."""

    instance: str
    endpoint_id: str | None
    device_name: str
    device_type: int
    host: str
    port: int
    name_is_advertised: bool

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        """Presentation-only mapping for the local interface."""
        return {
            "instance": self.instance,
            "endpoint_id": self.endpoint_id,
            "name": self.device_name,
            "device_type": self.device_type,
            "device_type_label": DEVICE_TYPE_LABELS.get(self.device_type, "Device"),
            "host": self.host,
            "port": self.port,
            "key": self.key,
            "name_is_advertised": self.name_is_advertised,
        }


def _base64url_decode(value: str) -> bytes:
    text = value.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sanitize_display_name(value: str | None) -> str | None:
    """Reduce a peer-supplied name to a short, single-line display label."""
    if not isinstance(value, str):
        return None
    cleaned = _UNSAFE_DISPLAY.sub("", value)
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    return cleaned[:MAX_DISPLAY_NAME].strip()


def decode_endpoint_info(data: bytes) -> EndpointInfo:
    """Decode the ``n`` TXT payload; tolerate a missing name segment."""
    if not isinstance(data, bytes):
        raise DiscoveryError("Endpoint info must be bytes.")
    if len(data) < ENDPOINT_INFO_MIN_LENGTH:
        raise DiscoveryError("Endpoint info is shorter than the fixed header.")
    flags = data[0]
    version = (flags >> 5) & 0x07
    visible = bool((flags >> 4) & 0x01)
    device_type = (flags >> 1) & 0x07
    name: str | None = None
    if len(data) > ENDPOINT_INFO_MIN_LENGTH:
        length = data[ENDPOINT_INFO_MIN_LENGTH]
        start = ENDPOINT_INFO_MIN_LENGTH + 1
        end = start + length
        if length and end <= len(data):
            try:
                name = sanitize_display_name(data[start:end].decode("utf-8"))
            except UnicodeDecodeError:
                name = None
    return EndpointInfo(
        version=version,
        visible=visible,
        device_type=device_type,
        device_name=name,
    )


def decode_instance_name(instance: str) -> str | None:
    """Return the four-character endpoint ID, or ``None`` for a foreign shape."""
    bare = instance
    if bare.endswith("." + SERVICE_TYPE):
        bare = bare[: -(len(SERVICE_TYPE) + 1)]
    elif bare.endswith(SERVICE_TYPE):
        bare = bare[: -len(SERVICE_TYPE)].rstrip(".")
    try:
        raw = _base64url_decode(bare)
    except (ValueError, base64.binascii.Error):
        return None
    if len(raw) != INSTANCE_PAYLOAD_LENGTH:
        return None
    if raw[0] != PCP_P2P_CLUSTER or raw[5:8] != SERVICE_ID_BYTES:
        return None
    try:
        endpoint_id = raw[1:5].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not endpoint_id.isalnum():
        return None
    return endpoint_id


def fallback_display_name(device_type: int, endpoint_id: str | None) -> str:
    label = DEVICE_TYPE_LABELS.get(device_type, "Device")
    if endpoint_id:
        return f"{label} ({endpoint_id})"
    return label


def local_ipv4_addresses() -> set[str]:
    """Best-effort set of this machine's IPv4 addresses for self-filtering.

    A UDP connect asks the route table which source address would be used; no
    packet is sent. Hostname resolution and loopback are added best-effort.
    """
    addresses = {"127.0.0.1"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            addresses.add(probe.getsockname()[0])
    except OSError:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    return addresses


def peer_from_service_info(info: Any) -> Peer | None:
    """Build a :class:`Peer` from a resolved ``zeroconf.ServiceInfo``.

    Returns ``None`` when the record has no usable IPv4 address or port. The
    advertised name is sanitised; a missing name falls back to a type label.
    """
    addresses = []
    for raw in getattr(info, "addresses", None) or []:
        try:
            addresses.append(str(ipaddress.ip_address(raw)))
        except (ValueError, TypeError):
            continue
    ipv4 = [value for value in addresses if ":" not in value]
    if not ipv4:
        return None
    port = getattr(info, "port", None)
    if not isinstance(port, int) or not 0 < port <= 65535:
        return None

    properties = getattr(info, "properties", None) or {}
    encoded = properties.get(b"n")
    device_name: str | None = None
    device_type = 0
    if isinstance(encoded, bytes):
        try:
            decoded = decode_endpoint_info(_base64url_decode(encoded.decode("ascii")))
        except (DiscoveryError, ValueError, UnicodeDecodeError, base64.binascii.Error):
            decoded = None
        if decoded is not None:
            device_name = decoded.device_name
            device_type = decoded.device_type

    instance = getattr(info, "name", "")
    endpoint_id = decode_instance_name(instance)
    advertised = device_name is not None
    if device_name is None:
        device_name = fallback_display_name(device_type, endpoint_id)
    return Peer(
        instance=instance,
        endpoint_id=endpoint_id,
        device_name=device_name,
        device_type=device_type,
        host=ipv4[0],
        port=port,
        name_is_advertised=advertised,
    )


class PeerBrowser:
    """Long-lived mDNS browser that keeps a deduplicated peer list.

    ``on_change`` receives the current tuple of peers after every addition or
    removal. It runs on the zeroconf thread, so callbacks must be short and
    thread-safe. ``include_self`` exists for diagnostics and tests only.
    """

    def __init__(
        self,
        on_change: Callable[[tuple[Peer, ...]], None] | None = None,
        *,
        include_self: bool = False,
        resolve_timeout_ms: int = 2500,
    ) -> None:
        self._on_change = on_change
        self._include_self = include_self
        self._resolve_timeout_ms = resolve_timeout_ms
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._zeroconf = None
        self._browser = None
        self._local_addresses: set[str] = set()

    @property
    def peers(self) -> tuple[Peer, ...]:
        with self._lock:
            return tuple(self._peers[key] for key in sorted(self._peers))

    def start(self) -> None:
        if self._zeroconf is not None:
            return
        try:
            from zeroconf import ServiceBrowser, Zeroconf
        except ImportError as exc:
            raise DiscoveryError(
                "The 'zeroconf' dependency is missing. Install project dependencies "
                "with `python -m pip install -e .` and try again."
            ) from exc

        self._local_addresses = local_ipv4_addresses()
        self._zeroconf = Zeroconf()
        listener = _BrowserListener(self)
        self._browser = ServiceBrowser(self._zeroconf, SERVICE_TYPE, listener)

    def stop(self) -> None:
        browser, zeroconf = self._browser, self._zeroconf
        self._browser = None
        self._zeroconf = None
        if browser is not None:
            try:
                browser.cancel()
            except Exception:
                pass
        if zeroconf is not None:
            try:
                zeroconf.close()
            except Exception:
                pass
        with self._lock:
            self._peers.clear()

    def _notify(self) -> None:
        callback = self._on_change
        if callback is None:
            return
        peers = self.peers
        try:
            callback(peers)
        except Exception:
            # Presentation callbacks must never break discovery.
            pass

    def _add(self, name: str) -> None:
        zeroconf = self._zeroconf
        if zeroconf is None:
            return
        try:
            info = zeroconf.get_service_info(
                SERVICE_TYPE, name, timeout=self._resolve_timeout_ms
            )
        except Exception:
            return
        if info is None:
            return
        peer = peer_from_service_info(info)
        if peer is None:
            return
        if not self._include_self and peer.host in self._local_addresses:
            return
        with self._lock:
            previous = self._peers.get(peer.key)
            self._peers[peer.key] = peer
        if previous != peer:
            self._notify()

    def _remove(self, name: str) -> None:
        with self._lock:
            stale = [key for key, peer in self._peers.items() if peer.instance == name]
            for key in stale:
                del self._peers[key]
        if stale:
            self._notify()


class _BrowserListener:
    """Adapter implementing the zeroconf listener protocol."""

    def __init__(self, browser: PeerBrowser) -> None:
        self._browser = browser

    def add_service(self, zc, service_type, name):  # noqa: ANN001 - zeroconf API
        self._browser._add(name)

    def update_service(self, zc, service_type, name):  # noqa: ANN001
        self._browser._add(name)

    def remove_service(self, zc, service_type, name):  # noqa: ANN001
        self._browser._remove(name)


def discover_peers(
    duration_seconds: float = 8.0, *, include_self: bool = False
) -> tuple[Peer, ...]:
    """Browse for ``duration_seconds`` and return the resolved peers."""
    if not 0 < duration_seconds <= 120:
        raise ValueError("Browse duration must be greater than 0 and at most 120 seconds.")
    browser = PeerBrowser(include_self=include_self)
    browser.start()
    try:
        deadline = time.monotonic() + duration_seconds
        while time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        return browser.peers
    finally:
        browser.stop()


def browse_peers(duration_seconds: float = 8.0, *, include_self: bool = False) -> dict[str, Any]:
    """Browse for ``duration_seconds`` and return the peers seen.

    This is the one-shot form used by the ``peers`` command. It never connects
    to a peer and never changes any advertised state.
    """
    started = time.monotonic()
    peers = discover_peers(duration_seconds, include_self=include_self)
    return {
        "duration_seconds": time.monotonic() - started,
        "service_type": SERVICE_TYPE,
        "peers": [peer.to_dict() for peer in peers],
        "note": (
            "Passive discovery only. Names and addresses are not identity, and no "
            "connection was opened."
        ),
    }

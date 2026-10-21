"""Passive Quick Share mDNS service discovery and inspection."""
from __future__ import annotations
import ipaddress
import time
from typing import Any

QUICK_SHARE_SERVICE_TYPE = "_FC9F5ED42C8A._tcp.local."

def _format_address(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return repr(value)

def probe_mdns(duration_seconds: float = 8.0) -> dict[str, Any]:
    """Browse for Quick Share services and resolve their advertised details."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError as exc:
        raise RuntimeError(
            "The optional 'zeroconf' package is missing. Install project dependencies with "
            "`python -m pip install -e .` and try again."
        ) from exc

    discovered: dict[str, dict[str, Any]] = {}
    zc = Zeroconf()

    class Listener:
        def add_service(self, zc_instance, service_type, name):
            self._resolve(zc_instance, service_type, name)

        def update_service(self, zc_instance, service_type, name):
            self._resolve(zc_instance, service_type, name)

        def remove_service(self, zc_instance, service_type, name):
            discovered.pop(name, None)

        @staticmethod
        def _resolve(zc_instance, service_type, name):
            info = zc_instance.get_service_info(service_type, name, timeout=2500)
            if info is None:
                discovered[name] = {
                    "name": name, "resolved": False, "addresses": [], "port": None,
                    "server": None, "txt_records": {},
                    "resolution_note": "Service was announced but details could not be resolved.",
                }
                return
            addresses = sorted({_format_address(addr) for addr in (info.addresses or [])})
            txt_records: dict[str, str] = {}
            for key, value in (info.properties or {}).items():
                key_text = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
                if isinstance(value, bytes):
                    value_text = value.decode("utf-8", errors="replace")
                elif value is None:
                    value_text = ""
                else:
                    value_text = str(value)
                txt_records[key_text] = value_text
            discovered[name] = {
                "name": name, "resolved": True, "addresses": addresses,
                "port": info.port, "server": info.server, "txt_records": txt_records,
                "resolution_note": "Service details resolved from mDNS.",
            }

    listener = Listener()
    browser = ServiceBrowser(zc, QUICK_SHARE_SERVICE_TYPE, listener)
    started = time.monotonic()
    try:
        time.sleep(duration_seconds)
    finally:
        browser.cancel()
        zc.close()
    services = [discovered[name] for name in sorted(discovered)]
    return {
        "duration_seconds": time.monotonic() - started,
        "services_seen": len(services),
        "services": services,
        "service_type": QUICK_SHARE_SERVICE_TYPE,
        "note": (
            "Passive mDNS inspection only. This does not open a TCP connection or validate "
            "Quick Share protocol compatibility. Advertisements may change or disappear."
        ),
    }

"""Command-line interface for ViShare_Quick alpha_0.2-dev."""

import argparse
import sys

from vishare_quick import __version__
from vishare_quick.diagnostics import run_diagnostics
from vishare_quick.mdns_probe import probe_mdns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vishare",
        description=(
            "ViShare_Quick: cross-platform CLI research build for future "
            "Android Quick Share interoperability."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "doctor",
        help="show basic Python and operating-system diagnostics",
        description="Display basic environment diagnostics. No network scan is performed.",
    )
    mdns = subparsers.add_parser(
        "mdns-check",
        help="check whether an mDNS browse operation can run on this machine",
        description=(
            "Browse specifically for the known Quick Share mDNS service type. "
            "This does not advertise this laptop as a Quick Share endpoint."
        ),
    )
    mdns.add_argument("--seconds", type=float, default=8.0, help="browse duration (default: 8 seconds)")

    advertise = subparsers.add_parser(
        "advertise",
        help="experimentally advertise this laptop as a Quick Share-style endpoint",
        description=(
            "Publish an experimental mDNS endpoint and listen for TCP connections. "
            "The UKEY2 handshake, file transfer, and BLE trigger are not implemented."
        ),
    )
    advertise.add_argument("--name", default="ViShare Quick", help="visible device name")
    advertise.add_argument("--port", type=int, default=0, help="TCP port (0 chooses an available port)")
    advertise.add_argument("--seconds", type=float, default=120.0, help="advertisement duration (default: 120 seconds)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        for label, value in run_diagnostics():
            print(f"{label}: {value}")
        print("\nThis research build does not yet implement Quick Share discovery or file transfer.")
        return 0

    if args.command == "advertise":
        if args.seconds <= 0 or args.seconds > 3600:
            parser.error("--seconds must be greater than 0 and at most 3600")
        try:
            from vishare_quick.advertise import run_advertiser
            print("Starting experimental Quick Share-style mDNS advertisement.")
            print("This is not a complete Quick Share receiver; BLE trigger and UKEY2 handshake are not implemented.")
            result = run_advertiser(args.name, args.port, args.seconds)
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Advertisement failed: {exc}", file=sys.stderr)
            return 2
        print("Advertisement stopped.")
        print(f"Service instance: {result['instance_name']}")
        print(f"Endpoint ID: {result['endpoint_id']}")
        print(f"Local IPv4: {result['local_ip']}")
        print(f"TCP port: {result['port']}")
        print(f"TCP connections observed: {result['tcp_connections']}")
        return 0

    if args.command == "mdns-check":
        if args.seconds <= 0 or args.seconds > 60:
            parser.error("--seconds must be greater than 0 and at most 60")
        try:
            result = probe_mdns(args.seconds)
        except RuntimeError as exc:
            print(f"mDNS check failed: {exc}", file=sys.stderr)
            return 2
        print("mDNS browse completed.")
        print(f"Browse duration: {result['duration_seconds']:.1f} seconds")
        print(f"Service type queried: {result['service_type']}")
        print(f"Services observed: {result['services_seen']}")
        for index, service in enumerate(result["services"], start=1):
            print(f"\nService {index}: {service['name']}")
            print(f"  Resolved: {'yes' if service['resolved'] else 'no'}")
            print(f"  IP addresses: {', '.join(service['addresses']) if service['addresses'] else '(none resolved)'}")
            print(f"  TCP port: {service['port'] if service['port'] is not None else '(unavailable)'}")
            if service.get("server"):
                print(f"  Hostname: {service['server']}")
            if service["txt_records"]:
                print("  TXT records:")
                for key, value in sorted(service["txt_records"].items()):
                    print(f"    {key}={value}")
            else:
                print("  TXT records: (none)")
            print(f"  Resolution: {service['resolution_note']}")
        print(f"\nNote: {result['note']}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

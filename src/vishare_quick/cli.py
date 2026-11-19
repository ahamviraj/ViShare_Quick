"""Command-line interface for ViShare_Quick alpha_0.9."""

import argparse
import sys
import threading

from vishare_quick import __version__
from vishare_quick.diagnostics import run_diagnostics
from vishare_quick.mdns_probe import probe_mdns
from vishare_quick.peer_discovery import (
    DiscoveryError,
    Peer,
    browse_peers,
    discover_peers,
)
from vishare_quick.sender import (
    OutgoingFile,
    SenderCancelled,
    SenderError,
    prepare_files,
    send_files,
)


_SEND_STAGE_TEXT = {
    "connecting": "Connecting to the device…",
    "handshake": "Negotiating encryption…",
    "offering": "Offering the file list…",
    "pin-pending": "Waiting for you to compare the code…",
    "awaiting-acceptance": "Waiting for the device to accept…",
    "sending": "Sending files…",
    "finishing": "Waiting for the device to finish…",
    "complete": "Complete.",
}


def _human_size(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = max(float(value), 0.0)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


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

    peers = subparsers.add_parser(
        "peers",
        help="list Quick Share receivers currently visible on the local network",
        description=(
            "Browse the Quick Share mDNS service type and list the receivers that "
            "answer. This is passive discovery only: no connection is opened, no "
            "file is offered, and a discovered name is never treated as identity."
        ),
    )
    peers.add_argument(
        "--seconds", type=float, default=8.0, help="browse duration (default: 8 seconds)"
    )
    peers.add_argument(
        "--include-self",
        action="store_true",
        help="also list this machine's own advertisements (diagnostics)",
    )

    send = subparsers.add_parser(
        "send",
        help="send files to a discovered Quick Share receiver",
        description=(
            "Discover or select one Quick Share receiver, complete the UKEY2 "
            "handshake, offer the files, and require an explicit PIN comparison "
            "plus the receiver's acceptance before any file byte is read. Only "
            "regular files are accepted and only basenames are sent."
        ),
    )
    send.add_argument("paths", nargs="+", metavar="FILE", help="files to send")
    send.add_argument(
        "--peer",
        metavar="HOST:PORT",
        help="connect to this receiver instead of discovering one",
    )
    send.add_argument(
        "--seconds", type=float, default=8.0, help="discovery duration (default: 8 seconds)"
    )
    send.add_argument("--name", default="ViShare Quick", help="visible device name")
    send.add_argument(
        "--handshake-only",
        action="store_true",
        help="stop after the receiver accepts, before any file byte is read",
    )

    ui = subparsers.add_parser(
        "ui",
        help="open the local graphical interface in an app window",
        description=(
            "Start the loopback-only receiver and sender interface in a native app "
            "window. If no webview backend is available, it falls back to the "
            "default browser. The interface advertises the same Quick Share "
            "endpoint as 'advertise --receive-files' and requires the same explicit "
            "PIN comparison and file consent. The server binds to 127.0.0.1 and "
            "uses a per-run token; it never accepts a transfer automatically."
        ),
    )
    ui.add_argument("--port", type=int, default=0, help="local TCP port (0 chooses an available port)")
    display = ui.add_mutually_exclusive_group()
    display.add_argument(
        "--browser",
        action="store_true",
        help="open the interface in the default browser instead of an app window",
    )
    display.add_argument(
        "--no-browser",
        action="store_true",
        help="run the local server without opening an app window or browser",
    )
    display.add_argument(
        "--background",
        action="store_true",
        help="start hidden in the Windows notification area with a tray icon",
    )
    ui.add_argument(
        "--download-dir",
        metavar="DIR",
        help="destination directory for received files (default: ~/Downloads)",
    )
    ui.add_argument("--name", default="ViShare Quick", help="visible device name")

    advertise = subparsers.add_parser(
        "advertise",
        help="experimentally advertise this laptop as a Quick Share-style endpoint",
        description=(
            "Publish an experimental mDNS endpoint and listen for TCP connections. "
            "UKEY2 response is disabled unless --ukey2-handshake is selected; the BLE trigger "
            "is not implemented and file transfer requires --receive-files. The opt-in mode "
            "sends a plaintext Nearby CONNECTION_RESPONSE exchange, then closes before encrypted "
            "traffic unless a separate --inspect-encrypted-frame, --paired-key-probe, "
            "--paired-key-response, or --receive-files mode is selected."
        ),
    )
    advertise.add_argument("--name", default="ViShare Quick", help="visible device name")
    advertise.add_argument("--port", type=int, default=0, help="TCP port (0 chooses an available port)")
    advertise.add_argument("--seconds", type=float, default=120.0, help="advertisement duration (default: 120 seconds)")
    mode_group = advertise.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--inspect-frames", action="store_true", help="read and classify length-prefixed frames without replying"
    )
    advertise.add_argument(
        "--inspect-encrypted-frame",
        action="store_true",
        help=(
            "with --ukey2-handshake, authenticate and inspect one bounded post-accept "
            "frame; never sends encrypted data"
        ),
    )
    advertise.add_argument(
        "--paired-key-probe",
        action="store_true",
        help=(
            "with --ukey2-handshake, inspect one authenticated paired-key offer and at most "
            "one follow-up; sends no paired-key message"
        ),
    )
    advertise.add_argument(
        "--paired-key-response",
        action="store_true",
        help=(
            "with --ukey2-handshake, reply to the authenticated paired-key offer with a "
            "72-byte/6-byte random no-credential placeholder PKE and PairedKeyResultFrame "
            "UNABLE; experimental, no identity material. Add --receive-files to continue "
            "through Introduction, PIN comparison, consent, and file reception"
        ),
    )
    advertise.add_argument(
        "--receive-files",
        action="store_true",
        help=(
            "with --ukey2-handshake, continue the paired-key response stage through "
            "Introduction parsing, explicit PIN comparison, explicit consent, and streaming "
            "reception of the offered files; never accepts automatically"
        ),
    )
    advertise.add_argument(
        "--download-dir",
        metavar="DIR",
        help=(
            "destination directory for --receive-files (default: ~/Downloads); "
            "existing files are never overwritten"
        ),
    )
    advertise.add_argument(
        "--capture-introduction",
        nargs="?",
        const="",
        metavar="DIR",
        help=(
            "with --paired-key-response or --receive-files, save the raw authenticated "
            "Introduction body for analysis (default: ~/.vishare-quick/introductions); "
            "never saves keys or envelopes, refuses '..' paths, and never overwrites"
        ),
    )
    advertise.add_argument(
        "--log-introduction-filenames",
        action="store_true",
        help=(
            "with --paired-key-response or --receive-files, include sanitized offered "
            "filenames in Introduction diagnostics (disabled by default)"
        ),
    )
    advertise.add_argument(
        "--protocol-timeline",
        action="store_true",
        help=(
            "with --ukey2-handshake, print a sanitized chronological timeline of protocol "
            "events (metadata only; never keys, payload bytes, or identity material)"
        ),
    )
    mode_group.add_argument(
        "--ukey2-handshake",
        action="store_true",
        help=(
            "opt in to experimental P256_SHA512 UKEY2 and plaintext CONNECTION_RESPONSE; "
            "no encrypted response or file transfer"
        ),
    )
    dump_group = advertise.add_mutually_exclusive_group()
    dump_group.add_argument(
        "--dump-first-frame-hex",
        action="store_true",
        help="opt in to a maximum 96-byte hex dump of frame 1 (includes length prefix)",
    )
    dump_group.add_argument(
        "--dump-frame-hex-index",
        type=int,
        metavar="N",
        help="opt in to a maximum 96-byte hex dump of complete frame N (includes length prefix)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        for label, value in run_diagnostics():
            print(f"{label}: {value}")
        print("\nThis research build does not yet implement Quick Share discovery or file transfer.")
        return 0

    if args.command == "ui":
        if args.port < 0 or args.port > 65535:
            parser.error("--port must be between 0 and 65535")
        if not args.name.strip():
            parser.error("--name cannot be empty")
        if args.background and sys.platform != "win32":
            parser.error("--background is only supported on Windows")
        try:
            from vishare_quick.ui_server import run_ui

            return run_ui(
                port=args.port,
                download_dir=args.download_dir,
                device_name=args.name.strip(),
                open_browser=args.browser,
                use_window=not (args.browser or args.no_browser),
                background=args.background,
            )
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Interface failed to start: {exc}", file=sys.stderr)
            return 2

    if args.command == "advertise":
        if args.seconds <= 0 or args.seconds > 3600:
            parser.error("--seconds must be greater than 0 and at most 3600")
        if args.dump_frame_hex_index is not None and args.dump_frame_hex_index < 1:
            parser.error("--dump-frame-hex-index must be at least 1")
        if args.inspect_encrypted_frame and not args.ukey2_handshake:
            parser.error("--inspect-encrypted-frame requires --ukey2-handshake")
        if args.paired_key_probe and not args.ukey2_handshake:
            parser.error("--paired-key-probe requires --ukey2-handshake")
        if args.paired_key_probe and args.inspect_encrypted_frame:
            parser.error("--paired-key-probe cannot be combined with --inspect-encrypted-frame")
        if args.paired_key_response and not args.ukey2_handshake:
            parser.error("--paired-key-response requires --ukey2-handshake")
        if args.paired_key_response and args.inspect_encrypted_frame:
            parser.error("--paired-key-response cannot be combined with --inspect-encrypted-frame")
        if args.paired_key_response and args.paired_key_probe:
            parser.error("--paired-key-response cannot be combined with --paired-key-probe")
        if args.receive_files and not args.ukey2_handshake:
            parser.error("--receive-files requires --ukey2-handshake")
        if args.receive_files and args.inspect_encrypted_frame:
            parser.error("--receive-files cannot be combined with --inspect-encrypted-frame")
        if args.receive_files and args.paired_key_probe:
            parser.error("--receive-files cannot be combined with --paired-key-probe")
        if args.download_dir is not None and not args.receive_files:
            parser.error("--download-dir requires --receive-files")
        introduction_mode = args.paired_key_response or args.receive_files
        if args.capture_introduction is not None and not introduction_mode:
            parser.error(
                "--capture-introduction requires --paired-key-response or --receive-files"
            )
        if args.log_introduction_filenames and not introduction_mode:
            parser.error(
                "--log-introduction-filenames requires --paired-key-response "
                "or --receive-files"
            )
        if args.protocol_timeline and not args.ukey2_handshake:
            parser.error("--protocol-timeline requires --ukey2-handshake")
        try:
            from vishare_quick.advertise import run_advertiser
            print("Starting experimental Quick Share-style mDNS advertisement.")
            if args.capture_introduction is not None:
                print(
                    "WARNING: raw Introduction capture is enabled. The saved body is the "
                    "decrypted protocol message and may contain private sender, filename, "
                    "folder, and transfer metadata. Store it securely and do not commit it."
                )
            if args.log_introduction_filenames:
                print(
                    "WARNING: sanitized offered filenames will be printed with Introduction "
                    "diagnostics. Disable --log-introduction-filenames for redacted output."
                )
            if args.ukey2_handshake:
                if args.receive_files:
                    print(
                        "WARNING: experimental Quick Share file reception. After the "
                        "authenticated paired-key stage this parses the Introduction, derives the "
                        "4-digit PIN from the UKEY2 auth string for you to compare with Android, "
                        "and requires you to confirm the codes match plus explicit consent before "
                        "any file bytes are accepted. Files are saved under --download-dir "
                        "(default: ~/Downloads) and never overwrite existing files. Paired-key "
                        "identity remains UNABLE and unverified; received files are never executed."
                    )
                elif args.paired_key_probe:
                    print(
                        "WARNING: experimental UKEY2 mode sends SERVER_INIT and plaintext "
                        "CONNECTION_RESPONSE ACCEPT. Paired-key probe authenticates one inbound "
                        "offer and may read one follow-up; it sends no paired-key response, "
                        "consent decision, or file data."
                    )
                elif args.paired_key_response:
                    print(
                        "WARNING: experimental no-credential paired-key response. After the "
                        "authenticated Android offer this sends a PairedKeyEncryptionFrame with "
                        "fresh random 72-byte signed_data and 6-byte secret_id_hash placeholders "
                        "(no certificate, signature, or QR data) and a PairedKeyResultFrame UNABLE. "
                        "It does not claim a verified identity, request consent, or transfer files. "
                        "Add --receive-files to enable the separate consent and reception stage. "
                        "Android acceptance is unverified."
                    )
                elif args.inspect_encrypted_frame:
                    print(
                        "WARNING: experimental UKEY2 mode sends SERVER_INIT and plaintext "
                        "CONNECTION_RESPONSE ACCEPT. It then reads at most one encrypted frame "
                        "and attempts authenticated inspection without sending an encrypted "
                        "response; pairing, consent, and file transfer are not implemented."
                    )
                else:
                    print(
                        "WARNING: UKEY2 handshake mode sends a protocol response. It is experimental; "
                        "it accepts the connection after UKEY2 and closes before encrypted messaging; "
                        "peer authentication and file transfer are not implemented."
                    )
            else:
                print("This is not a complete Quick Share receiver; BLE trigger and file transfer are not implemented.")
            result = run_advertiser(
                args.name,
                args.port,
                args.seconds,
                inspect_frames=args.inspect_frames or args.dump_first_frame_hex or args.dump_frame_hex_index is not None,
                dump_first_frame_hex=args.dump_first_frame_hex,
                dump_frame_hex_index=args.dump_frame_hex_index,
                ukey2_handshake=args.ukey2_handshake,
                inspect_encrypted_frame=args.inspect_encrypted_frame,
                paired_key_probe=args.paired_key_probe,
                paired_key_response=args.paired_key_response,
                protocol_timeline=args.protocol_timeline,
                receive_files=args.receive_files,
                download_dir=args.download_dir,
                capture_introduction=args.capture_introduction is not None,
                capture_introduction_dir=args.capture_introduction or None,
                log_introduction_filenames=args.log_introduction_filenames,
            )
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

    if args.command == "peers":
        if args.seconds <= 0 or args.seconds > 120:
            parser.error("--seconds must be greater than 0 and at most 120")
        try:
            result = browse_peers(args.seconds, include_self=args.include_self)
        except (DiscoveryError, RuntimeError, ValueError) as exc:
            print(f"Peer discovery failed: {exc}", file=sys.stderr)
            return 2
        print("Peer discovery completed.")
        print(f"Browse duration: {result['duration_seconds']:.1f} seconds")
        print(f"Service type queried: {result['service_type']}")
        print(f"Receivers found: {len(result['peers'])}")
        for index, peer in enumerate(result["peers"], start=1):
            print(f"\nPeer {index}: {peer['name']}")
            print(f"  Address: {peer['host']}:{peer['port']}")
            print(
                f"  Device type: {peer['device_type_label']} "
                f"({peer['device_type']})"
            )
            print(f"  Endpoint ID: {peer['endpoint_id'] or '(unavailable)'}")
            print(
                "  Name advertised: "
                + ("yes" if peer["name_is_advertised"] else "no (type label used)")
            )
        if not result["peers"]:
            print(
                "\nNo receiver answered. Android devices advertise only while their "
                "Quick Share sheet is open, so open it on the phone and retry."
            )
        print(f"\nNote: {result['note']}")
        return 0

    if args.command == "send":
        if args.seconds <= 0 or args.seconds > 120:
            parser.error("--seconds must be greater than 0 and at most 120")
        # Validate the local selection before any discovery or connection so a
        # missing, empty, or special file fails immediately and visibly.
        try:
            prepare_files(args.paths)
        except SenderError as exc:
            print(f"Send failed: {exc}", file=sys.stderr)
            return 2
        print(
            "WARNING: experimental Quick Share sender. It connects only on the local "
            "network, sends basenames only, and requires you to compare the 4-digit "
            "code with the receiving device before any file byte is read."
        )
        if args.peer:
            host, separator, port_text = args.peer.rpartition(":")
            try:
                port = int(port_text)
            except ValueError:
                separator = ""
                port = 0
            if not separator or not host or not 0 < port <= 65535:
                print("send failed: --peer must be HOST:PORT", file=sys.stderr)
                return 2
            peer = Peer(
                instance=args.peer,
                endpoint_id=None,
                device_name=args.peer,
                device_type=0,
                host=host,
                port=port,
                name_is_advertised=False,
            )
        else:
            try:
                candidates = discover_peers(args.seconds)
            except (DiscoveryError, RuntimeError, ValueError) as exc:
                print(f"send failed: {exc}", file=sys.stderr)
                return 2
            if not candidates:
                print(
                    "send failed: no Quick Share receiver answered. Open the Quick Share "
                    "sheet on the device and retry.",
                    file=sys.stderr,
                )
                return 2
            if len(candidates) > 1:
                print(
                    "send failed: more than one receiver answered; choose one with --peer:",
                    file=sys.stderr,
                )
                for item in candidates:
                    print(f"  {item.device_name}  {item.host}:{item.port}", file=sys.stderr)
                return 2
            peer = candidates[0]

        print(f"Device: {peer.device_name} at {peer.host}:{peer.port}")
        cancel_event = threading.Event()
        last_stage: list[str | None] = [None]

        def report_stage(name: str) -> None:
            if name == last_stage[0]:
                return
            last_stage[0] = name
            print(_SEND_STAGE_TEXT.get(name, name))

        def confirm_pin(code: str) -> bool:
            print(f"\nVerification code: {code}")
            print(f"Compare this code with the one shown on {peer.device_name}.")
            try:
                answer = input("Type 'yes' only if both codes match: ")
            except EOFError:
                return False
            return answer.strip().lower() in {"yes", "y"}

        buckets: dict[int, int] = {}

        def report_progress(item: OutgoingFile, sent: int, total: int) -> None:
            percent = 100 if total == 0 else int(sent * 100 / total)
            bucket = percent // 10 * 10
            if buckets.get(item.payload_id) == bucket and percent != 100:
                return
            buckets[item.payload_id] = bucket
            print(
                f"  {item.name}: {percent}% "
                f"({_human_size(sent)} of {_human_size(total)})"
            )

        try:
            result = send_files(
                peer,
                args.paths,
                device_name=args.name,
                on_stage=report_stage,
                on_pin=confirm_pin,
                on_progress=report_progress,
                cancel_event=cancel_event,
                handshake_only=args.handshake_only,
            )
        except SenderCancelled as exc:
            print(f"Send cancelled: {exc}")
            return 130
        except SenderError as exc:
            print(f"Send failed: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            cancel_event.set()
            print("\nSend cancelled.")
            return 130

        if result.pin_compared:
            print("PIN comparison confirmed locally.")
        if args.handshake_only:
            print(
                "Handshake-only run complete: the device accepted the offer and no "
                "file byte was read."
            )
        else:
            print(
                f"Sent {result.files_sent} file(s), {_human_size(result.total_bytes)}, "
                f"in {result.duration_seconds:.1f} seconds."
            )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

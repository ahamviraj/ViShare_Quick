"""Experimental Quick Share-compatible mDNS endpoint advertisement.

This module implements the documented DNS-SD advertisement shape and an opt-in experimental
P256_SHA512 UKEY2 responder. It does not implement file transfer or BLE trigger advertisement.
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
from vishare_quick.protocol import (
    ConnectionResponseExchange,
    FrameError,
    FrameTimeout,
    PeerDisconnected,
    TruncatedFrame,
    make_frame_hex_dump_callback,
    read_frame,
)
from vishare_quick.secure_channel import (
    SecureChannelError,
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
    derive_server_to_client_send_keys,
)
from vishare_quick.paired_key_probe import PairedKeyProbeError, run_paired_key_probe
from vishare_quick.paired_key_response import (
    PairedKeyResponseError,
    run_paired_key_response,
)
from vishare_quick.protocol_timeline import ProtocolTimeline
from vishare_quick.ukey2 import HandshakeError, Ukey2ServerHandshake


SERVICE_TYPE = "_FC9F5ED42C8A._tcp.local."
SERVICE_ID_BYTES = bytes.fromhex("FC9F5E")
ENDPOINT_ID_ALPHABET = string.ascii_letters + string.digits


def _base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _describe_authenticated_payload(summary) -> str:
    """Format safe transport metadata for a validated frame; never payload bytes."""
    meta = summary.payload_transfer
    if meta is None:
        return f"sequence={summary.sequence}; payload metadata unavailable"
    return (
        f"sequence={summary.sequence}; payload_id={meta.payload_id}; "
        f"total_size={meta.total_size}; offset={meta.chunk_offset}; "
        f"body={meta.chunk_body_length} bytes; last_chunk={meta.is_last_chunk}"
    )


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


def run_advertiser(
    device_name: str = "ViShare Quick",
    port: int = 0,
    duration_seconds: float = 120.0,
    inspect_frames: bool = False,
    dump_first_frame_hex: bool = False,
    dump_frame_hex_index: int | None = None,
    ukey2_handshake: bool = False,
    inspect_encrypted_frame: bool = False,
    paired_key_probe: bool = False,
    paired_key_response: bool = False,
    protocol_timeline: bool = False,
) -> dict[str, Any]:
    """Advertise an endpoint; inspection is read-only, UKEY2 response is opt-in."""
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
    if dump_frame_hex_index is not None and dump_frame_hex_index < 1:
        raise ValueError("Frame hex index must be at least 1.")
    if inspect_encrypted_frame and not ukey2_handshake:
        raise ValueError("Encrypted frame inspection requires --ukey2-handshake.")
    if paired_key_probe and not ukey2_handshake:
        raise ValueError("Paired-key probing requires --ukey2-handshake.")
    if paired_key_probe and inspect_encrypted_frame:
        raise ValueError("Paired-key probing cannot be combined with --inspect-encrypted-frame.")
    if paired_key_response and not ukey2_handshake:
        raise ValueError("Paired-key response requires --ukey2-handshake.")
    if paired_key_response and inspect_encrypted_frame:
        raise ValueError("Paired-key response cannot be combined with --inspect-encrypted-frame.")
    if paired_key_response and paired_key_probe:
        raise ValueError("Paired-key response cannot be combined with --paired-key-probe.")
    if protocol_timeline and not ukey2_handshake:
        raise ValueError("Protocol timeline requires --ukey2-handshake.")

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
                connection_timeline = ProtocolTimeline() if protocol_timeline else None
                close_reason = "local-close"
                try:
                    if connection_timeline is not None:
                        connection_timeline.tcp_connected(f"{peer[0]}:{peer[1]}")
                    print(f"TCP connection #{accepted} from {peer[0]}:{peer[1]}")
                    conn.settimeout(2.0)
                    if inspect_frames or ukey2_handshake:
                        deadline = time.monotonic() + 10.0
                        selected_dump = dump_frame_hex_index or (1 if dump_first_frame_hex else None)
                        dump_callback = (
                            make_frame_hex_dump_callback(selected_dump) if selected_dump is not None else None
                        )

                        class BoundedReader:
                            def recv(self, size):
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise socket.timeout()
                                conn.settimeout(remaining)
                                return conn.recv(size)

                        if ukey2_handshake:
                            try:
                                request = read_frame(BoundedReader(), on_wire_frame=dump_callback)
                                print(
                                    f"Received frame: {request.declared_length} bytes; family={request.family}; "
                                    f"type={request.message_type}; validation={request.validation}; values omitted."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.inbound_plaintext(request)
                                if (request.family, request.message_type) != (
                                    "OfflineFrame v1", "CONNECTION_REQUEST"
                                ):
                                    raise HandshakeError("Expected Nearby CONNECTION_REQUEST before UKEY2.")

                                client_init = read_frame(BoundedReader(), on_wire_frame=dump_callback)
                                print(
                                    f"Received frame: {client_init.declared_length} bytes; family={client_init.family}; "
                                    f"type={client_init.message_type}; validation={client_init.validation}; values omitted."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.inbound_plaintext(client_init)
                                if (client_init.family, client_init.message_type) != ("UKEY2", "CLIENT_INIT"):
                                    raise HandshakeError("Expected UKEY2 CLIENT_INIT after CONNECTION_REQUEST.")

                                handshake = Ukey2ServerHandshake()
                                server_init_wire = handshake.respond_to_client_init(client_init.payload)
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise socket.timeout()
                                conn.settimeout(remaining)
                                conn.sendall(server_init_wire)
                                print("Sent UKEY2 SERVER_INIT (P256_SHA512; sensitive key material omitted).")
                                if connection_timeline is not None:
                                    connection_timeline.outbound_plaintext(
                                        "UKEY2", "SERVER_INIT", len(server_init_wire)
                                    )

                                client_finish = read_frame(BoundedReader(), on_wire_frame=dump_callback)
                                print(
                                    f"Received frame: {client_finish.declared_length} bytes; family={client_finish.family}; "
                                    f"type={client_finish.message_type}; validation={client_finish.validation}; values omitted."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.inbound_plaintext(client_finish)
                                if (client_finish.family, client_finish.message_type) != ("UKEY2", "CLIENT_FINISH"):
                                    raise HandshakeError("Expected UKEY2 CLIENT_FINISH after SERVER_INIT.")
                                secrets = handshake.receive_client_finish(client_finish.payload)
                                print(
                                    "UKEY2 CLIENT_FINISH commitment verified; P-256 ECDH and HKDF completed "
                                    f"(auth={len(secrets.auth_string)} bytes, next-secret={len(secrets.next_secret)} bytes; "
                                    "values omitted). Out-of-band peer authentication is not confirmed; "
                                    "no subsequent protocol or file transfer is implemented."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.state("UKEY2_AUTHENTICATED")

                                response_exchange = ConnectionResponseExchange()
                                response_wire = response_exchange.send_accept()
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise socket.timeout()
                                conn.settimeout(remaining)
                                conn.sendall(response_wire)
                                print(
                                    "Sent Nearby CONNECTION_RESPONSE ACCEPT (plaintext; "
                                    "encrypted messaging and file transfer are not implemented)."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.outbound_plaintext(
                                        "OFFLINE_FRAME",
                                        "CONNECTION_RESPONSE",
                                        len(response_wire),
                                        status="ACCEPT",
                                    )

                                peer_response = read_frame(BoundedReader(), on_wire_frame=dump_callback)
                                print(
                                    f"Received frame: {peer_response.declared_length} bytes; "
                                    f"family={peer_response.family}; type={peer_response.message_type}; "
                                    "values omitted."
                                )
                                if connection_timeline is not None:
                                    connection_timeline.inbound_plaintext(peer_response)
                                response_status = response_exchange.receive_peer_response(peer_response.payload)
                                if connection_timeline is not None:
                                    connection_timeline.state(
                                        f"CONNECTION_RESPONSE_{response_status}"
                                    )
                                print(
                                    f"Peer CONNECTION_RESPONSE {response_status} validated; "
                                    + ("starting opt-in paired-key probe." if paired_key_probe else
                                       "starting experimental no-credential paired-key response." if paired_key_response else
                                       "waiting for one encrypted frame for read-only inspection." if inspect_encrypted_frame else
                                       "closing before encrypted traffic (not implemented).")
                                )
                                if paired_key_probe:
                                    try:
                                        receive_keys = derive_client_to_server_receive_keys(secrets.next_secret)
                                        probe = run_paired_key_probe(
                                            BoundedReader(),
                                            receive_keys,
                                            timeline=connection_timeline,
                                        )
                                    except (FrameError, SecureChannelError, PairedKeyProbeError) as exc:
                                        close_reason = (
                                            connection_timeline.error(exc, stage="paired-key probe")
                                            if connection_timeline is not None
                                            else "error"
                                        )
                                        print(f"Paired-key probe stopped: {exc}")
                                    else:
                                        offer = probe.offer
                                        print(
                                            f"Authenticated {offer.offline_type} → {offer.sharing_type}; "
                                            f"sequence={offer.sequence}."
                                        )
                                        for item in offer.paired_key_fields:
                                            if item.present:
                                                print(f"Paired-key field {item.name}: present ({item.length} bytes).")
                                            else:
                                                print(f"Paired-key field {item.name}: absent (schema optional).")
                                        print(
                                            "No paired-key response sent: the reviewed fallback examples "
                                            "use random placeholder values and this probe has no verified "
                                            "identity material; PKE parsing does not authenticate identity."
                                        )
                                        if probe.followup is None:
                                            print(f"Paired-key follow-up wait ended: {probe.followup_status}.")
                                        else:
                                            followup = probe.followup
                                            print(
                                                f"Authenticated follow-up: {followup.offline_type} → "
                                                f"{followup.sharing_type or 'no sharing frame'}; "
                                                f"sequence={followup.sequence}; received without a local "
                                                "paired-key response; probe stopped."
                                            )
                                elif inspect_encrypted_frame:
                                    try:
                                        encrypted = read_frame(BoundedReader(), classify=False)
                                    except FrameError as exc:
                                        close_reason = (
                                            connection_timeline.error(
                                                exc, stage="encrypted frame inspection"
                                            )
                                            if connection_timeline is not None
                                            else "error"
                                        )
                                        if isinstance(exc, FrameTimeout):
                                            print("Encrypted frame inspection stopped: read timed out.")
                                        elif isinstance(exc, (PeerDisconnected, TruncatedFrame)):
                                            print(f"Encrypted frame inspection stopped: {exc}")
                                        else:
                                            print(f"Encrypted frame inspection stopped: {exc}")
                                    else:
                                        print(
                                            f"Captured one length-prefixed frame: {encrypted.declared_length} bytes; "
                                            "payload retained in memory only."
                                        )
                                        try:
                                            receive_keys = derive_client_to_server_receive_keys(secrets.next_secret)
                                            summary = authenticate_and_inspect_frame(encrypted, receive_keys)
                                        except (FrameError, SecureChannelError) as exc:
                                            close_reason = (
                                                connection_timeline.error(
                                                    exc, stage="encrypted frame inspection"
                                                )
                                                if connection_timeline is not None
                                                else "error"
                                            )
                                            print(f"Encrypted frame authentication/inspection failed: {exc}")
                                        else:
                                            if connection_timeline is not None:
                                                connection_timeline.inbound_authenticated(
                                                    summary, stage="encrypted frame inspection"
                                                )
                                            print(
                                                f"Encrypted frame authenticated and decrypted; "
                                                f"sequence={summary.sequence}; "
                                                f"Nearby={summary.offline_type}; "
                                                f"sharing={summary.sharing_type or 'not decoded'}; "
                                                "no encrypted response sent."
                                            )
                                elif paired_key_response:
                                    # A fresh bounded stage: the earlier handshake
                                    # deadline may already be nearly spent.
                                    response_deadline = time.monotonic() + 15.0

                                    class ResponseReader:
                                        def recv(self, size):
                                            remaining = response_deadline - time.monotonic()
                                            if remaining <= 0:
                                                raise socket.timeout()
                                            conn.settimeout(remaining)
                                            return conn.recv(size)

                                    class BoundedWriter:
                                        def sendall(self, data):
                                            remaining = response_deadline - time.monotonic()
                                            if remaining <= 0:
                                                raise socket.timeout()
                                            conn.settimeout(remaining)
                                            conn.sendall(data)

                                    try:
                                        receive_keys = derive_client_to_server_receive_keys(
                                            secrets.next_secret
                                        )
                                        send_keys = derive_server_to_client_send_keys(
                                            secrets.next_secret
                                        )
                                        paired = run_paired_key_response(
                                            ResponseReader(),
                                            BoundedWriter(),
                                            receive_keys,
                                            send_keys,
                                            timeline=connection_timeline,
                                        )
                                    except (
                                        FrameError,
                                        SecureChannelError,
                                        PairedKeyResponseError,
                                        OSError,
                                    ) as exc:
                                        close_reason = (
                                            connection_timeline.error(
                                                exc, stage="paired-key response"
                                            )
                                            if connection_timeline is not None
                                            else "error"
                                        )
                                        print(f"Paired-key response stopped: {exc}")
                                    else:
                                        if connection_timeline is not None:
                                            connection_timeline.state("PAIRED_KEY_STAGE_COMPLETE")
                                        print(
                                            "Authenticated Android PKE offer: "
                                            + _describe_authenticated_payload(paired.offer) + "."
                                        )
                                        for item in paired.offer.paired_key_fields:
                                            state = (
                                                f"present ({item.length} bytes)"
                                                if item.present
                                                else "absent (schema optional)"
                                            )
                                            print(f"Paired-key offer field {item.name}: {state}.")
                                        print(
                                            "Authenticated PKE offer terminator: "
                                            + _describe_authenticated_payload(paired.offer_terminator) + "."
                                        )
                                        print(
                                            "Sent outbound secure messages: sequence 1 PKE DATA; "
                                            "sequence 2 PKE LAST_CHUNK; sequence 3 RESULT UNABLE DATA; "
                                            "sequence 4 RESULT LAST_CHUNK (independent server-to-client keys)."
                                        )
                                        status_name = {
                                            0: "UNKNOWN", 1: "SUCCESS", 2: "FAIL", 3: "UNABLE"
                                        }.get(paired.peer_result.paired_key_result_status, "absent")
                                        print(
                                            "Authenticated peer paired-key result: "
                                            + _describe_authenticated_payload(paired.peer_result)
                                            + f"; status={status_name}; response stage={paired.status}."
                                        )
                                        print(
                                            "Authenticated peer result terminator: "
                                            + _describe_authenticated_payload(paired.peer_result_terminator)
                                            + "."
                                        )
                                        if paired.introduction is None:
                                            print(
                                                "No Introduction observed within the response stage; "
                                                "no consent response or file transfer is implemented."
                                            )
                                        else:
                                            print(
                                                "Authenticated Introduction observed: "
                                                + _describe_authenticated_payload(paired.introduction)
                                                + "; no consent response or file transfer is implemented; closing."
                                            )
                            except (HandshakeError, FrameError, socket.timeout, OSError) as exc:
                                close_reason = (
                                    connection_timeline.error(
                                        exc, stage="ukey2/connection exchange"
                                    )
                                    if connection_timeline is not None
                                    else "error"
                                )
                                print(f"UKEY2/connection exchange stopped: {exc}")
                        else:
                            while True:
                                try:
                                    frame = read_frame(BoundedReader(), on_wire_frame=dump_callback)
                                except TruncatedFrame as exc:
                                    print(f"Frame inspection stopped: {exc}")
                                    break
                                except PeerDisconnected:
                                    print("Peer disconnected between frames.")
                                    break
                                except FrameError as exc:
                                    print(f"Frame inspection stopped: {exc}")
                                    break
                                print(
                                    f"Received frame: {frame.declared_length} bytes; family={frame.family}; "
                                    f"type={frame.message_type}; validation={frame.validation}; values omitted."
                                )
                    else:
                        try:
                            data = conn.recv(64)
                            if data:
                                print(f"Received {len(data)} initial bytes; protocol handshake is not implemented yet.")
                        except socket.timeout:
                            pass
                finally:
                    if connection_timeline is not None:
                        connection_timeline.tcp_closed(reason=close_reason)
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

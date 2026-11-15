"""Loopback sender↔receiver integration tests.

These run the real :func:`vishare_quick.sender.send_files` protocol against a
minimal in-process peer that performs a genuine UKEY2 handshake with
:class:`Ukey2ServerHandshake` and then authenticates every encrypted frame with
the receiver-side key schedule. The peer is a test double, not a shipping
receiver; the value here is that it exercises the same wire helpers the
receiver uses, so framing, sequence, payload and end-of-file mistakes show up.

No network access beyond ``127.0.0.1`` and no Android device is required.
"""
from __future__ import annotations

import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from vishare_quick.consent import build_connection_response_frame
from vishare_quick.introduction import parse_introduction
from vishare_quick.paired_key_response import (
    build_bytes_payload_messages,
    build_keep_alive_ack_frame,
)
from vishare_quick.peer_discovery import Peer
from vishare_quick.protocol import (
    encode_connection_response_accept,
    parse_connection_response,
    read_frame,
)
from vishare_quick.secure_channel import (
    authenticate_and_inspect_frame,
    derive_client_to_server_receive_keys,
    derive_server_to_client_send_keys,
    encode_secure_message,
)
from vishare_quick.sender import SenderCancelled, send_files
from vishare_quick.sender_protocol import (
    PAYLOAD_TYPE_FILE,
    encode_paired_key_encryption,
    encode_paired_key_result,
)
from vishare_quick.ukey2 import Ukey2ServerHandshake


class MockReceiver(threading.Thread):
    """One-shot loopback peer that behaves like an accepting receiver."""

    def __init__(self, *, stop_after_files: int | None = None) -> None:
        super().__init__(name="vishare-test-peer", daemon=True)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.port = self.listener.getsockname()[1]

        self.error: BaseException | None = None
        self.introduction = None
        self.chunks: dict[int, list[bytes]] = {}
        self.closed_early = False
        self._stop_after_files = stop_after_files

    def peer(self) -> Peer:
        return Peer(
            instance="test.local. _FC9F5ED42C8A._tcp.local.",
            endpoint_id="AB12",
            device_name="Mock Tablet",
            device_type=2,
            host="127.0.0.1",
            port=self.port,
            name_is_advertised=True,
        )

    def run(self) -> None:
        try:
            connection, _ = self.listener.accept()
            connection.settimeout(20)
            with connection:
                self._serve(connection)
        except BaseException as exc:  # surfaced by the test
            self.error = exc
        finally:
            self.listener.close()

    def _serve(self, conn: socket.socket) -> None:
        read_frame(conn)  # CONNECTION_REQUEST
        client_init = read_frame(conn)
        server = Ukey2ServerHandshake()
        conn.sendall(server.respond_to_client_init(client_init.payload))
        client_finish = read_frame(conn)
        secrets = server.receive_client_finish(client_finish.payload)
        conn.sendall(encode_connection_response_accept())
        peer_response = read_frame(conn)
        assert parse_connection_response(peer_response.payload) == "ACCEPT"

        receive_keys = derive_client_to_server_receive_keys(secrets.next_secret)
        send_keys = derive_server_to_client_send_keys(secrets.next_secret)
        sequence_in = 1
        sequence_out = 1
        response_payload_id = 1
        finished_files = 0

        def send_offline(offline_frame: bytes) -> None:
            nonlocal sequence_out
            conn.sendall(encode_secure_message(offline_frame, send_keys, sequence_out))
            sequence_out += 1

        def send_sharing(sharing_frame: bytes, payload_id: int) -> None:
            data, last = build_bytes_payload_messages(sharing_frame, payload_id)
            send_offline(data)
            send_offline(last)

        while True:
            try:
                frame = read_frame(conn)
            except Exception:
                self.closed_early = True
                return
            summary = authenticate_and_inspect_frame(
                frame, receive_keys, expected_sequence=sequence_in
            )
            sequence_in += 1

            if summary.keep_alive_ack is not None:
                send_offline(build_keep_alive_ack_frame())
                continue
            if summary.sharing_type == "PAIRED_KEY_ENCRYPTION":
                send_sharing(
                    encode_paired_key_encryption(os.urandom(72), os.urandom(6)),
                    response_payload_id,
                )
                response_payload_id += 1
                continue
            if summary.sharing_type == "PAIRED_KEY_RESULT":
                send_sharing(encode_paired_key_result(), response_payload_id)
                response_payload_id += 1
                continue
            if summary.sharing_type == "INTRODUCTION":
                self.introduction = parse_introduction(summary.payload_body)
                send_sharing(
                    build_connection_response_frame(1), response_payload_id
                )
                response_payload_id += 1
                continue
            if summary.sharing_type == "CANCEL":
                return

            metadata = summary.payload_transfer
            if metadata is None or metadata.payload_type != PAYLOAD_TYPE_FILE:
                continue
            body = summary.payload_body or b""
            bucket = self.chunks.setdefault(metadata.payload_id, [])
            if body:
                if metadata.chunk_offset != sum(len(part) for part in bucket):
                    raise AssertionError("file chunks arrived out of order")
                bucket.append(body)
            if metadata.is_last_chunk:
                finished_files += 1
                if (
                    self._stop_after_files is not None
                    and finished_files >= self._stop_after_files
                ):
                    return


class SendFilesIntegrationTests(unittest.TestCase):
    def _payloads(self, chunks: dict[int, list[bytes]]) -> dict[int, bytes]:
        return {key: b"".join(parts) for key, parts in chunks.items()}

    def test_multi_file_transfer_round_trips_over_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "alpha.bin"
            first.write_bytes(bytes(range(256)) * 2_800)  # crosses 512 KiB twice
            second = root / "beta note.txt"
            second.write_bytes(b"second file body\n")

            receiver = MockReceiver()
            receiver.start()
            result = send_files(
                receiver.peer(),
                [first, second],
                on_pin=lambda code: code.isdigit() and len(code) == 4,
                linger_timeout=0.2,
                handshake_timeout=10.0,
                acceptance_timeout=10.0,
            )
            receiver.join(10)
            self.assertFalse(receiver.is_alive())
            self.assertIsNone(receiver.error)

            self.assertEqual(result.files_sent, 2)
            self.assertEqual(result.files, ("alpha.bin", "beta note.txt"))
            self.assertTrue(result.pin_compared)
            self.assertIsNotNone(receiver.introduction)
            offers = receiver.introduction.files
            self.assertEqual([offer.name for offer in offers], ["alpha.bin", "beta note.txt"])
            self.assertEqual([offer.size for offer in offers], [first.stat().st_size, second.stat().st_size])
            for offer in offers:
                self.assertNotIn(directory, offer.name)
                self.assertNotIn("/", offer.name)
                self.assertNotIn("\\", offer.name)

            payloads = self._payloads(receiver.chunks)
            by_name = {offer.name: offer.payload_id for offer in offers}
            self.assertEqual(payloads[by_name["alpha.bin"]], first.read_bytes())
            self.assertEqual(payloads[by_name["beta note.txt"]], second.read_bytes())

    def test_cancel_stops_streaming_without_completing_the_transfer(self):
        import vishare_quick.sender as sender_module

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.bin"
            path.write_bytes(os.urandom(300_000))

            receiver = MockReceiver()
            receiver.start()
            cancel = threading.Event()
            sent_offsets: list[int] = []

            def progress(item, sent, total):
                sent_offsets.append(sent)
                cancel.set()

            original_chunk = sender_module.CHUNK_SIZE
            original_step = sender_module.PROGRESS_MIN_STEP_BYTES
            sender_module.CHUNK_SIZE = 32 * 1024
            sender_module.PROGRESS_MIN_STEP_BYTES = 32 * 1024
            try:
                with self.assertRaises(SenderCancelled):
                    send_files(
                        receiver.peer(),
                        [path],
                        on_pin=lambda code: True,
                        on_progress=progress,
                        cancel_event=cancel,
                        linger_timeout=0.2,
                        handshake_timeout=10.0,
                        acceptance_timeout=10.0,
                        connect_timeout=5.0,
                    )
            finally:
                sender_module.CHUNK_SIZE = original_chunk
                sender_module.PROGRESS_MIN_STEP_BYTES = original_step
            receiver.join(10)
            self.assertFalse(receiver.is_alive())
            self.assertIsNone(receiver.error)
            # At least one chunk may have been written before cancellation was
            # observed, but the loop must not have finished the file.
            self.assertTrue(sent_offsets)
            self.assertLess(sent_offsets[0], path.stat().st_size)

    def test_peer_disconnect_after_accept_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "note.txt"
            path.write_bytes(b"hi")

            class DroppingReceiver(MockReceiver):
                def _serve(self, conn):
                    read_frame(conn)
                    client_init = read_frame(conn)
                    server = Ukey2ServerHandshake()
                    conn.sendall(server.respond_to_client_init(client_init.payload))
                    client_finish = read_frame(conn)
                    server.receive_client_finish(client_finish.payload)
                    conn.sendall(encode_connection_response_accept())
                    read_frame(conn)
                    # Close before any encrypted frame is accepted.

            receiver = DroppingReceiver()
            receiver.start()
            with self.assertRaises(Exception) as caught:
                send_files(
                    receiver.peer(),
                    [path],
                    on_pin=lambda code: True,
                    linger_timeout=0.2,
                    handshake_timeout=10.0,
                    acceptance_timeout=10.0,
                    connect_timeout=5.0,
                )
            receiver.join(10)
            self.assertIsNone(receiver.error)
            self.assertNotIsInstance(caught.exception, AssertionError)


if __name__ == "__main__":
    unittest.main()

# Alpha 0.6 sender research

Status: working notes and implementation plan for the first outbound Quick Share milestone.
Scope: sending local files from this laptop to an Android device over the same Wi-Fi LAN,
without a Google account, cloud relay, or internet dependency.

This document records what the sender role requires, what this repository already has, what
must be added, and what was observed on real hardware. It is a plan, not a claim of
interoperability. No peer identity verification is added by this milestone.

## 1. Sources

| Source | What it is | Used for |
|---|---|---|
| [Grishka/NearDrop `PROTOCOL.md`](https://github.com/grishka/NearDrop/blob/master/PROTOCOL.md) | Reverse-engineered description of the LAN Quick Share flow; documentation only | Message order, framing, endpoint info, payload layer, keep-alive |
| [Dhiva-Labs/NearShare](https://github.com/Dhiva-Labs/NearShare) (MIT) | Maintained Python client that sends and receives, GTK/CLI | Behavioural reference for the sender state machine and timing |
| [Google UKEY2](https://android.googlesource.com/platform/external/ukey2/) | Google's reference key exchange | Client-init/commitment rules, auth string, next secret |
| This repository | Receiver implementation verified in alpha_0.4/alpha.5 | Framing, protobuf helpers, SecureMessage, Introduction parsing, file writes |

Licensing: NearDrop's document is read as documentation and NearShare is MIT-licensed, but no
source code is copied into this project. Every encoder and state machine here is written against
the field numbers and transition rules, using the existing ViShare modules and helpers.

## 2. Roles

A transfer is unidirectional, so the two peers have different jobs:

- **Receiver = server.** Listens on TCP, advertises mDNS, chooses the medium, prompts its human,
  receives chunks.
- **Sender = client.** Browses mDNS, connects, initiates UKEY2, offers the file list, waits for the
  human on the receiver, streams chunks, disconnects.

The sender is therefore not "the receiver reversed". The mDNS direction, the UKEY2 role, the
paired-key role, the Introduction author, and the payload direction are all inverted. What carries
over is the framing, the encryption primitives, and most validation and sanitisation rules.

## 3. Sender wire sequence

Frame shell: every message on the TCP stream is a 4-byte big-endian length followed by that many
bytes. Plaintext frames are `OfflineFrame` or `Ukey2Message`; everything after the two
`CONNECTION_RESPONSE` frames is one `SecureMessage` per `OfflineFrame`.

```
sender (client)                                  receiver (server, Android)
  TCP connect  ------------------------------------>
  OfflineFrame CONNECTION_REQUEST  ---------------->   endpoint_id, endpoint_name,
                                                       endpoint_info, mediums=[WIFI_LAN]
  Ukey2Message CLIENT_INIT  ----------------------->   version=1, 32-byte random,
                                                       commitment=SHA512(CLIENT_FINISH),
                                                       next_protocol="AES_256_CBC-HMAC_SHA256"
                              <------------------  Ukey2Message SERVER_INIT
                                                       version, 32-byte random, cipher=100,
                                                       GenericPublicKey(EC_P256)
  Ukey2Message CLIENT_FINISH  --------------------->   GenericPublicKey(EC_P256)
                                                       both sides derive auth_string +
                                                       next_secret from M1|M2
                              <------------------  OfflineFrame CONNECTION_RESPONSE
  OfflineFrame CONNECTION_RESPONSE  --------------->   status=0, response=ACCEPT, os_info
  --- all following frames are SecureMessage(AES-256-CBC + HMAC-SHA256, D2D seq from 1) ---
  sharing PAIRED_KEY_ENCRYPTION  ------------------>   signed_data=72 random bytes,
                                                       secret_id_hash=6 random bytes
                              <------------------  sharing PAIRED_KEY_ENCRYPTION
  sharing PAIRED_KEY_RESULT UNABLE  --------------->   status=3 (UNABLE)
                              <------------------  sharing PAIRED_KEY_RESULT
  sharing INTRODUCTION  --------------------------->   one FileMetadata per file:
                                                       name, type, payload_id, size,
                                                       mime_type
                              <------------------  sharing RESPONSE
                                                       ACCEPT / REJECT / NOT_ENOUGH_SPACE /
                                                       UNSUPPORTED_ATTACHMENT_TYPE
  PAYLOAD_TRANSFER FILE chunks  ------------------->   512 KiB chunks, offsets ascending
  PAYLOAD_TRANSFER FILE LAST_CHUNK (empty body) --->   flags bit 0 set, offset == size
  ...                                                (repeat per file)
  OfflineFrame DISCONNECTION  --------------------->   then close TCP
```

Notes that matter for implementation:

1. The sender sends `CONNECTION_RESPONSE ACCEPT` immediately after `CLIENT_FINISH`, without waiting
   for the receiver's response. The receiver's response is then read and must also be ACCEPT.
   `protocol.encode_connection_response_accept()` already emits this shape.
2. The UKEY2 commitment is over the serialized `CLIENT_FINISH` `Ukey2Message` bytes, excluding the
   TCP length prefix. `CLIENT_FINISH` is built before `CLIENT_INIT`, because the commitment is
   `SHA512(M3)`.
3. Session keys: `auth_string = HKDF(dhs, "UKEY2 v1 auth", M1|M2)` and
   `next_secret = HKDF(dhs, "UKEY2 v1 next", M1|M2)`, where
   `dhs = SHA256(ECDH-P256 x-coordinate)`. The client uses the `client` D2D key to encrypt and the
   `server` key to decrypt; the server does the opposite. This is exactly the inverse of the
   receiver path already implemented in `secure_channel.py`.
4. The 4-digit code is `four_digit_code(auth_string)` from `pin_verification.py`. It is never sent
   on the wire. The sender must display it and require an explicit human comparison before it
   treats the transfer as agreed.
5. Every sharing control message (PKE, PKR, Introduction, Response) is a `BYTES` payload: one DATA
   frame carrying the whole serialized `sharing.Frame`, followed by an empty `LAST_CHUNK` frame with
   the same payload ID and `offset == len(body)`.
6. File payload IDs come from the sender and must be positive signed int64 values (Android rejects
   negative IDs in the sender role). Control payload IDs are independent and may reuse the shared
   ID space, so a positive random value in `1..2^62` is safe.
7. After the last `LAST_CHUNK` the sender must linger rather than hang up instantly. Android can
   mark a transfer failed if the sender closes while the receiver is still flushing. NearShare
   waits up to 15 seconds for the peer to disconnect, answering keep-alives. This project should
   linger with a bounded timeout and still be interruptible by cancel.
8. Keep-alives: an `OfflineFrame` `KEEP_ALIVE` every 10 seconds in both directions, `ack=false` for
   an unsolicited ping and `ack=true` in reply. Silence longer than about 30 seconds ends the
   connection. The sender needs its own keep-alive task during the wait for human acceptance and
   during streaming.

## 4. Field schemas used by the sender

Offline frames (field numbers as used by the existing decoder in `secure_channel.py`):

| Message | Field | Type | Value |
|---|---|---|---|
| `OfflineFrame` | 1 | varint | version = 1 |
| | 2 | message | `V1Frame` |
| `V1Frame` | 1 | varint | type: 1 request, 2 response, 3 payload, 5 keep-alive, 6 disconnect |
| `ConnectionRequestFrame` | 1 | string | endpoint ID (4 alphanumerics) |
| | 2 | string | endpoint name (visible device name) |
| | 5 | repeated enum | mediums; 5 = WIFI_LAN |
| | 6 | bytes | endpoint info blob |
| `ConnectionResponseFrame` | 1 | varint | legacy status (0 = OK) |
| | 3 | varint | response enum: 1 ACCEPT, 2 REJECT |
| | 4 | message | `OsInfo{1: type}`; 3 = Windows, 100 = Linux |
| `KeepAliveFrame` | 1 | bool | ack |
| `PayloadTransferFrame` | 1 | message | `PayloadHeader` |
| | 2 | message | `PayloadChunk` |
| `PayloadHeader` | 1 | int64 | payload ID |
| | 2 | enum | 1 BYTES, 2 FILE, 3 STREAM |
| | 3 | int64 | total size |
| | 5 | string | file name (senders only) |
| `PayloadChunk` | 1 | varint | flags; bit 0 = LAST_CHUNK |
| | 2 | int64 | offset |
| | 3 | bytes | body |

Sharing frames (body field numbers from `secure_channel._SHARING_BODY_FIELDS`):

| Message | Field | Type | Value |
|---|---|---|---|
| `sharing.Frame` | 1 | varint | version = 1 |
| | 2 | message | `V1Frame` |
| `sharing.V1Frame` | 1 | varint | type: 1 intro, 2 response, 3 PKE, 4 PKR, 6 cancel |
| | 2 | message | introduction |
| | 3 | message | connection response |
| | 4 | message | paired key encryption |
| | 5 | message | paired key result |
| `IntroductionFrame` | 1 | repeated | `FileMetadata` |
| `FileMetadata` | 1 | string | basename only |
| | 2 | enum | 0 UNKNOWN, 1 IMAGE, 2 VIDEO, 3 ANDROID_APP, 4 AUDIO, 5 DOCUMENT, 6 CONTACT_CARD |
| | 3 | int64 | payload ID |
| | 4 | int64 | size |
| | 5 | string | MIME type |
| `PairedKeyEncryptionFrame` | 1 | bytes | `signed_data`, 72 random bytes |
| | 2 | bytes | `secret_id_hash`, 6 random bytes |
| `PairedKeyResultFrame` | 1 | enum | 3 = UNABLE |
| `ConnectionResponseFrame` (sharing) | 1 | enum | status: 1 ACCEPT, 2 REJECT, 3 NOT_ENOUGH_SPACE, 4 UNSUPPORTED_ATTACHMENT_TYPE, 5 TIMED_OUT |

Every schema above already exists in the receiving code as a validator, so the sender encoders can
be tested against our own parser in both directions.

## 5. Discovery

Service type: `_FC9F5ED42C8A._tcp.local.`. The instance name is base64url (no padding) of ten bytes:
`0x23`, a 4-character endpoint ID, `FC 9F 5E`, and `00 00`. The TXT record `n` is base64url of an
endpoint-info blob:

- byte 0: bits 7..5 version, bit 4 visibility, bits 3..1 device type (0 unknown, 1 phone, 2 tablet,
  3 laptop, 4 car, 5 foldable, 6 XR), bit 0 reserved.
- bytes 1..16: device-identification material. This project sends random bytes; no Google account
  is involved.
- optional byte 17: name length, followed by UTF-8 bytes. **Only present when the visibility bit is
  0.** Android in "Everyone" mode may still advertise with the visible bit set and no name.
- optional TLVs follow the name (type 1 QR data, type 2 vendor ID).

Observed on this LAN (XPad, Quick Share sheet open):

```
instance  IzVXM1L8n14AAA._FC9F5ED42C8A._tcp.local.
host      Android_S4TVHA62.local.    port 53601
address   192.168.43.39 (A) plus link-local and global IPv6 (AAAA)
txt       IPv4=192.168.43.39   f=5805   n=NI9sp9KsbSUTlILLgPYHxLg
n decoded 17 bytes: 34 8f 6c a7 d2 ac 6d 25 13 94 82 cb 80 f6 07 c4 b8
          version=1, visibility=1, device type=2 (tablet), no name segment
```

Consequences for discovery:

- The device name is not always available from mDNS. The UI must fall back to
  `Tablet (IzVX)`-style labels built from the device type and endpoint ID, and must never treat a
  discovered name as identity.
- `f` is an undocumented feature bitmap. It is ignored for now and must not gate behaviour.
- Filter out our own advertisements by local IPv4 address, not just by instance name, because each
  run uses a fresh random instance.
- The phone answers only while the Quick Share sheet is open. When the panel closes, mDNS goes
  silent even though the device still answers ping. Absence of a peer is therefore normal and the
  UI needs a refresh action rather than an error.

## 6. Existing code map

| Need | Existing | Gap |
|---|---|---|
| TCP frame read/write | `protocol.read_frame`, `Frame`, `FrameError` | writer + plaintext `OfflineFrame` encoders for request/keep-alive/disconnect |
| UKEY2 responder | `ukey2.Ukey2ServerHandshake` | `Ukey2ClientHandshake` (ClientInit, commitment, ServerInit parsing, ClientFinish) |
| Session key schedule | `secure_channel.derive_client_to_server_receive_keys`, `derive_server_to_client_send_keys` | client-role pair (send = client, receive = server) |
| SecureMessage | `secure_channel.encode_secure_message` (send), `authenticate_and_inspect_frame` (receive) | decrypt path that returns `payload_body` and can answer keep-alives in one loop |
| Connection response | `protocol.encode_connection_response_accept`, `parse_connection_response` | reuse as-is |
| PIN | `pin_verification.four_digit_code` | reuse as-is |
| Introduction | `introduction.parse_introduction` | encoder for our own file list |
| Response | `sharing_response` names, `secure_channel` parser | map ACCEPT/REJECT and wait for it |
| Payload transfer | receiver-side validation in `file_transfer` | chunk encoder with offsets, `LAST_CHUNK`, progress |
| mDNS | `advertise.run_advertiser`, `mdns_probe.probe_mdns` | endpoint-info parser with missing-name handling, self-filter, long-lived browser |
| UI | `ui_service`, `ui_server`, receive pages | Send page, peer list, file staging, send state machine |

## 7. Sender state machine

States, all fail-closed:

```
idle -> discovering -> peer-selected -> connecting -> handshake
     -> pin-pending (human compares) -> awaiting-acceptance (human on phone)
     -> sending -> finishing -> complete
     \-> cancelled | rejected | timed-out | failed
```

Rules:

- No file byte is read before the human confirms the PIN match **and** the phone returns ACCEPT.
- The PIN is shown only in `pin-pending`; it is never logged, never stored, and never included in a
  result payload.
- Cancel in any state stops reading and writing immediately, closes the socket, and reports
  `cancelled`. A peer that disconnects at any point is a failure, not a success.
- A stage timeout is a failure. Suggested bounds: connect 10 s, handshake 20 s, PIN 120 s,
  acceptance 120 s, silence 30 s, linger after last chunk 15 s.
- Only regular files are sent. Symlinks, directories, devices, sockets, and FIFOs are rejected
  before the Introduction is sent.
- Each file is opened read-only, its size is captured, and the size is re-checked after the last
  chunk. A file that changes size or disappears aborts the transfer.
- Only `Path.name` is put on the wire. Local absolute paths never leave the process, including in
  logs and error messages.
- File names are advertised with a MIME type guessed from the suffix and a file type enum. Unknown
  suffixes use `application/octet-stream` and `UNKNOWN`.
- Multi-file sends use one payload ID per file and stream them sequentially. Zero-byte files still
  get a `LAST_CHUNK`.

## 8. Security decisions for this milestone

1. The mDNS name is presentation only. The 4-digit code is the only out-of-band check.
2. The sender still displays the PAIRED_KEY_RESULT `UNABLE` path honestly: no identity claim.
3. Loopback-only UI, per-run token, CSP, no CORS, no absolute paths, no peer payload IDs in logs.
4. The Send page must state that files go only to the selected device on the local network and that
   the PIN must match before anything is sent.
5. The interface must never auto-select a peer and never auto-send on discovery.
6. The receiver may decline; the sender must show the schema status and stop.

## 9. Device test plan

Ready now:

1. Confirm discovery with the XPad's Quick Share sheet open: instance, endpoint ID, device type,
   address, port. **Done — see section 5.**
2. Confirm the peer disappears when the sheet closes. **Done.**
3. Confirm unicast TCP reachability to the advertised port. **Done (ping and connect).**

Next, in order:

1. Handshake-only: connect, request, UKEY2, both responses, PKE/PKR, Introduction, then wait for
   the phone's response and stop before bytes. **Done.**
   - XPad shows the file list and a 4-digit code.
   - The laptop prints the same code.
   - Accept on the phone returns ACCEPT; Decline returns REJECT; timeout returns TIMED_OUT.
2. Small single file (a few KiB), then a 1 MiB file. **Done: 18 B and 1,258,291 B.**
3. Multi-file set, including one file with a space in its name. **Done.** A zero-byte file is
   rejected locally instead: Android drops the offer before showing its accept sheet.
4. A file larger than 2 GiB to exercise offsets. **Not yet run.**
5. Cancel during streaming: the phone reports a cancelled/failed transfer and shows no partial file.
   **Covered by the loopback test; device run not yet logged.**
6. Airplane-mode or Wi-Fi drop mid-transfer: fail closed on both sides. **Loopback disconnect test
   passes; device run not yet logged.**
7. Repeat on Windows and Linux builds, and on a second Android device if available. **Windows
   verified; Linux asset not yet run.**
8. Confirm no local path appears in UI, logs, or peer display, and that the PIN is absent after the
   comparison screen is left. **Preparation and loopback tests assert basenames only.**

## 10. Open questions

1. Does the XPad accept the random 72-byte `signed_data` / 6-byte `secret_id_hash` PKE placeholder
   from a sender, as NearShare reports, or does it require certificate material when it is the
   receiver? **Answered: it accepts the placeholder and proceeds to the Introduction.**
2. Does the XPad's receiver require an `Introduction` field we are not sending (for example
   `use_case` or `transfer_id`)? **Answered: no, for regular files it accepts name, type, payload
   id, size, and MIME type alone.**
3. Does the phone send its own `sharing.RESPONSE ACCEPT` before or after the human taps? Treat any
   peer response as peer state, never as local consent. **Observed after the tap; still peer state.**
4. What exactly triggers Android's terminal keep-alive timeout, and is 10 s in both directions
   sufficient during the acceptance wait? **10 s worked for short waits; long waits remain untested.**
5. Does a 15-second linger after the last chunk reliably prevent a false failure on this Android
   version? **Short runs completed with the default linger; longer files still to confirm.**
6. How are negative payload IDs treated when we are the sender? NearShare uses positive values for
   this reason; this project will do the same. **Implemented: positive `1..2^62`.**

## 11. Sequence for alpha_0.6

1. Research document (this file).
2. Discovery-only: `vishare peers` plus a device list on the Send page. No connection.
3. Handshake-only sender: `vishare send --dry-run FILE...`, stop before file bytes.
4. File streaming: 512 KiB chunks, `LAST_CHUNK`, keep-alives, progress, cancel, linger, disconnect.
5. Send UI: peer list, file selection and staging, PIN comparison, acceptance wait, progress,
   cancel, result, logs.
6. Hardening: unit tests for every encoder against our parser, loopback end-to-end tests, real
   device runs, README and release notes, tag `alpha_0.6`.

## 12. Device results and decisions (alpha_0.6)

### Root cause of the first handshake failure

The first sender build wrote the plaintext `ConnectionRequest` without the 4-byte big-endian TCP
length prefix, while `ClientInit` and `ClientFinish` were framed. Android therefore read the first
four protobuf bytes as a length and waited for a much shorter frame, then dropped the connection.
Framing is now centralized: `sender_protocol.frame_payload` adds the prefix, and `_Session` has
exactly one framed-write helper for payloads and one for pre-framed handshake messages.

### Verified on the Android 14 XPad

All runs used the tablet's current mDNS port while its Quick Share sheet was open. PINs matched on
both screens every time.

| Run | Payload | Result |
|---|---|---|
| 1 | `vishare-test.txt` (18 B) | Received; content `hello from vishare` |
| 2 | `vishare-big.bin` (1,258,291 B) | Received intact; 3 chunks of 512 KiB |
| 3 | `vishare-big.bin` + `vishare name with spaces.txt` | Both received with correct names and sizes |
| 4 | `vishare name with spaces.txt` alone | Received; spaces preserved |
| 5 | `vishare-empty.txt` (0 B) | Sender now refuses locally |

Repeated copies seen on the tablet were from repeated test runs, not duplicate sends: the same file
was sent once alone and once as part of the two-file set.

### Zero-byte files are rejected locally

A lone 0-byte file made the tablet disconnect before showing its accept sheet, even when the sender
emitted an empty DATA chunk before the `LAST_CHUNK` (mirroring NearDrop's chunk loop). Android does
not accept this offer shape. `prepare_files` now fails before connecting with a clear message, so
the user is not left waiting for a prompt that cannot appear.

### Loopback coverage

`tests/test_sender_integration.py` runs the real `send_files` against an in-process peer that
performs the server side of UKEY2 and authenticates every frame with the receiver key schedule. It
covers a two-file transfer (one file crossing two 512 KiB boundaries), cancel during streaming, and
a peer disconnect after `ACCEPT`. `tests/test_peer_discovery.py` pins endpoint-info flags, instance
name decoding, display sanitisation, and service-record fallbacks.

### Send UI deferred

The working sender is CLI-only for `alpha_0.6`. The Send page remains the existing placeholder; a
peer list, browser file staging, PIN comparison, progress, and cancel belong to the next milestone,
where they can reuse `PeerBrowser` and `send_files` directly.

### Remaining device checks

- Multi-gigabyte file offsets and long-running keep-alives.
- Mid-transfer Wi-Fi loss and a receiver-initiated `CANCEL`.
- Repeat on the Linux asset and a second Android device.
- Confirm the receiver never leaves a `.vishare-partial` file after a sender-side abort.

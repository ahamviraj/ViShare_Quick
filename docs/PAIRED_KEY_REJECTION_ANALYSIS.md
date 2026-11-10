# Paired-key rejection analysis

> **Historical analysis — superseded (2026-11-10).** This document records the
> state before the approved no-credential placeholder change. The current
> `--paired-key-response` flow no longer sends an empty PKE: it sends fresh
> random 72-byte `signed_data` and 6-byte `secret_id_hash` placeholders (the
> other optional fields absent) and still reports `UNABLE`. References below to
> an empty PKE and to avoiding random placeholders describe the earlier design
> and are retained for history.

## 1. Current protocol flow

The observed flow is implemented in `src/vishare_quick/advertise.py`,
`src/vishare_quick/ukey2.py`, `src/vishare_quick/secure_channel.py`, and
`src/vishare_quick/paired_key_response.py`. Sequence numbers below are from the
laptop receiver's point of view.

1. TCP connect from the Android sender.
2. Android → laptop: plaintext `OfflineFrame v1` `CONNECTION_REQUEST`.
3. Android → laptop: UKEY2 `CLIENT_INIT`; laptop → Android: `SERVER_INIT`;
   Android → laptop: `CLIENT_FINISH`.
4. The laptop verifies the CLIENT_FINISH commitment and derives directional
   SecureMessage keys from the UKEY2 `next_secret`.
5. Laptop → Android: plaintext `OfflineFrame v1` `CONNECTION_RESPONSE ACCEPT`;
   Android → laptop: the reciprocal plaintext ACCEPT.
6. Android → laptop, inbound SecureMessage sequence 1: `PAYLOAD_TRANSFER` →
   BYTES → sharing `PAIRED_KEY_ENCRYPTION` (the offer).
7. Android → laptop, inbound sequence 2: the offer's zero-length `LAST_CHUNK`.
8. Laptop → Android, outbound sequences 1–4: empty PKE DATA, PKE LAST_CHUNK,
   `PAIRED_KEY_RESULT.UNABLE` DATA, result LAST_CHUNK.
9. Android → laptop, inbound sequence 3: authenticated
   `BANDWIDTH_UPGRADE_RETRY` transport-control frame (not a paired-key
   message).
10. The laptop acknowledges a `KEEP_ALIVE` when present and ignores
    bandwidth-control frames, then continues waiting for the reciprocal
    `PAIRED_KEY_RESULT` and its terminator at the next transport sequence
    numbers, followed by an optional `INTRODUCTION`.

### What the real-device timeline actually showed

The run of
`python -m vishare_quick advertise --ukey2-handshake --paired-key-response --protocol-timeline --seconds 60`
produced this end state:

```text
[+0.714s] IN    SECURE_MESSAGE seq=3 authenticated=true decrypted=true stage=peer paired-key result
[+0.715s] IN    FRAME offline=BANDWIDTH_UPGRADE_RETRY
[+0.715s] ERROR PROTOCOL_ERROR category=unexpected-message-type stage=paired-key response detail=Expected authenticated sequence-3 PAIRED_KEY_RESULT; received offline=BANDWIDTH_UPGRADE_RETRY sharing=none payload=none.
[+0.715s] SOCKET SOCKET_CLOSED reason=unexpected-message-type
```

The frame was authenticated and decrypted. It was an `OfflineFrame` of type
`BANDWIDTH_UPGRADE_RETRY`, so this was **not**:

- an Android identity rejection,
- a malformed or unauthenticated message,
- a read timeout or socket disconnect, or
- a `KEEP_ALIVE` (also a transport frame, but a different type).

The earlier failure was therefore a local classification bug: the paired-key
state machine treated a legal transport-control frame as a fatal sharing-layer
message.

## 2. Exact outbound paired-key response structure

`build_paired_key_response_messages()` returns four length-prefixed
OfflineFrames. The sharing-layer bytes are:

- PKE sharing Frame: 8 bytes
  `Frame{version=1, v1{type=PAIRED_KEY_ENCRYPTION(3), paired_key_encryption=field 4{}}}`
  with all four schema-optional identity fields absent.
- Result sharing Frame: 10 bytes
  `Frame{version=1, v1{type=PAIRED_KEY_RESULT(4), paired_key_result=field 5{status=UNABLE(3)}}}`.

Each sharing Frame is carried as a Nearby BYTES payload:

| Outbound sequence | Offline frame content | Payload header | Payload chunk |
|---|---|---|---|
| 1 | `PAYLOAD_TRANSFER`, packet_type DATA | id=1, type BYTES(1), total_size=8 | flags=0, offset=0, body=PKE sharing Frame |
| 2 | `PAYLOAD_TRANSFER`, packet_type DATA | id=1, type BYTES(1), total_size=8 | flags=LAST_CHUNK(1), offset=8, body omitted |
| 3 | `PAYLOAD_TRANSFER`, packet_type DATA | id=2, type BYTES(1), total_size=10 | flags=0, offset=0, body=result sharing Frame |
| 4 | `PAYLOAD_TRANSFER`, packet_type DATA | id=2, type BYTES(1), total_size=10 | flags=LAST_CHUNK(1), offset=10, body omitted |

If the peer sends `KEEP_ALIVE` without `ack=true`, the response stage adds one
further outbound SecureMessage containing a `KEEP_ALIVE` OfflineFrame with
`ack=true` (outbound sequence 5 in the observed run). It does not reply to
`BANDWIDTH_UPGRADE_RETRY` or other bandwidth-control frames.

Each OfflineFrame is encrypted in one SecureMessage with the server-to-client
keys:

- `Header.signature_scheme=HMAC_SHA256(1)`
- `Header.encryption_scheme=AES_256_CBC(2)`
- 16-byte fresh IV in field 5
- `GcmMetadata.type=DEVICE_TO_DEVICE_MESSAGE(13)`, `version=1` in field 6
- AES-256-CBC with PKCS#7 padding
- HMAC-SHA256 over the exact serialized `HeaderAndBody` bytes
- D2D `message` = serialized OfflineFrame, `sequence_number` = transport
  sequence

The send keys are derived from `next_secret` with
`HKDF-SHA256(salt=SHA256("D2D"), info=b"server")`, then
`HKDF-SHA256(salt=SHA256("SecureMessage"), info=b"ENC:2")` and
`info=b"SIG:1")`. Receive keys use `info=b"client"`. Send and receive
counters are independent and both start at 1.

## 3. Reference implementation comparison

The relevant reference behavior is consistent on the transport envelope and on
transport-control handling.

- **Google `offline_wire_formats.proto` / `offline_frames.cc`**: confirms
  `PayloadTransferFrame.packet_type=1`, `payload_header=2`, `payload_chunk=3`;
  `PayloadHeader.id=1` (int64), `type=2`, `total_size=3`;
  `PayloadChunk.flags=1`, `offset=2`, `body=3`, `index=4`; LAST_CHUNK is flag
  bit 1. The encoder in this project matches those field numbers and types.
  `V1Frame.FrameType.BANDWIDTH_UPGRADE_RETRY = 12` and its body field is 13.
- **Google `BandwidthUpgradeRetryFrame`**: `repeated Medium supported_medium=1`
  and `optional bool is_request=2`. The schema documents that when
  `is_request` is true the remote endpoint should send back its latest
  supported medium list. The retry frame observed here carried no diagnostic
  `is_request` value in the timeline (the parser treats an absent value as
  false), so no reply was sent.
- **Google SecureMessage schema**: confirms outer `SecureMessage(1,2)`,
  `HeaderAndBody(1,2)`, `Header.signature_scheme=1`, `encryption_scheme=2`,
  `iv=5`, `public_metadata=6`, `HMAC_SHA256=1`, `AES_256_CBC=2`. The project's
  HMAC-before-decrypt and exact-byte MAC handling match this structure.
- **NearDrop `PROTOCOL.md` and `InboundNearbyConnection.swift`**: both sides
  send a PKE and a result; the receiver's framing accepts a sharing Frame only
  after assembling BYTES chunks by payload ID until LAST_CHUNK. Unhandled
  offline frames are ignored rather than treated as a paired-key failure. Its
  no-cert fallback sends random 72-byte `signed_data` and random 6-byte
  `secret_id_hash`, then reports `UNABLE`.
- **NearShare `core/connection.py`**: `_recv_encrypted()` explicitly answers
  and skips interleaved `KEEP_ALIVE` frames while waiting for application
  data. `_recv_sharing_frame()` skips non-`PAYLOAD_TRANSFER` frames and
  accumulates chunk bodies per payload ID until LAST_CHUNK. Its inbound
  handshake waits for the phone's PKE, sends its own PKE, waits for the
  phone's result, then sends its own `UNABLE` result.
- **squick-share `InboundSession.swift`**: sends its own PKE after the
  handshake, handles `.keepAlive` in the main frame loop by sending an ack,
  reassembles BYTES payloads with `BytesPayloadAssembler`, replies to PKE with
  a paired-key result, and enters introduction only after the peer result. Its
  `default:` branch logs that it is ignoring an unhandled frame instead of
  failing the paired-key stage.
- **Chromium `PairedKeyVerificationRunner::Run()`**: always sends a local PKE
  and a local result, then waits for the peer's reciprocal PKE and result.
  With no private certificate it fills `signed_data`/`secret_id_hash` with
  random placeholder bytes and normally reports `UNABLE`. The project
  deliberately does not copy that random-filler pattern.

### Question-by-question findings

| # | Question | Finding |
|---|---|---|
| 1 | SecureMessage header/body/HMAC/AES/serialization correct? | Matches the published schema and the independent implementations reviewed. No proven encoding or crypto defect. No external known-answer vector was available. |
| 2 | Directional keys and counters correct? | Matches NearShare, NearDrop, and squick-share role/salt/info labels. Send/receive counters are independent and start at 1. No proven defect. |
| 3 | OfflineFrame/PayloadTransferFrame/PayloadHeader/PayloadChunk/LAST_CHUNK correct? | Field numbers, wire types, BYTES enum, offsets, flags, and body omission match the published schema and observed Android terminator pattern. No proven defect. |
| 4 | Payload IDs/sizes/offsets/terminators valid? | Yes: positive int64 IDs 1 and 2, declared BYTES sizes 8 and 10, DATA at offset 0, LAST_CHUNK at offset=total_size with no body. IDs are valid independently in each direction; Nearby payload maps are direction-separate. |
| 5 | Is the empty PKE semantically valid? | It is schema-valid because all four PKE bytes fields are optional. It is not the no-certificate representation used by NearDrop, NearShare, or Chromium, which send random placeholder bytes. Android's acceptance of the empty variant is still unverified. |
| 6 | Is UNABLE correct without identity? | Yes as a status meaning this receiver cannot verify a paired identity. It is not proof of pairing and does not by itself make the connection succeed. |
| 7 | Does response ordering match references? | Not exactly. NearShare sends its PKE, waits for the peer result, then sends its result. Chromium sends PKE and result before waiting for the peer's reciprocal messages. This project sends PKE and result together after the Android offer. This difference is not a proven defect. |
| 8 | Is inbound sequence-3 PAIRED_KEY_RESULT expected? | It is an expected application message, but it is not required to be the immediate next authenticated frame. The confirmed sequence-3 frame was `BANDWIDTH_UPGRADE_RETRY`, so transport traffic can interleave before the result. |
| 9 | Could Android expect other messages or a different continuation? | It may send transport-level `KEEP_ALIVE` and bandwidth-upgrade control frames, or deliver the result in more than one BYTES chunk. Those are normal interleavings, not new application messages. |
| 10 | Does the implementation assume a response Android does not require? | It previously assumed a single-frame, unfragmented, immediately-next result. That assumption was disproved by the observed `BANDWIDTH_UPGRADE_RETRY`. |
| 11 | What does Chromium do without certificate/identity material? | It still sends a PKE with random 72-byte `signed_data` and random 6-byte `secret_id_hash`, then reports `UNABLE`. This project intentionally refuses to present random bytes as identity material. |

## 4. Confirmed protocol behavior, implementation behavior, and defects

### 4.1 Confirmed protocol behavior

- Both peers exchange a paired-key offer and a paired-key result inside BYTES
  payloads carried by encrypted `PAYLOAD_TRANSFER` frames.
- Android's negotiation payloads observed so far use a full DATA chunk plus a
  zero-length LAST_CHUNK terminator.
- Authenticated transport-control frames can interleave with the paired-key
  conversation. The observed Android sender sent `BANDWIDTH_UPGRADE_RETRY` at
  inbound sequence 3.
- `BANDWIDTH_UPGRADE_RETRY` is `V1Frame.type=12` with body field 13. Its body
  is `BandwidthUpgradeRetryFrame{supported_medium=1, is_request=2}`.
- Independent receivers ignore unhandled transport frames while waiting for
  the next application message, and acknowledge `KEEP_ALIVE`.
- Independent receivers accumulate BYTES chunks by payload ID until
  LAST_CHUNK; a sharing Frame is not assumed to fit in one chunk.

### 4.2 Confirmed implementation behavior after the fix

- The laptop writes exactly four outbound SecureMessages only after the
  Android offer and its terminator have authenticated and passed strict
  structural checks.
- The outbound bytes and sizes listed in section 2 are produced by the current
  builders and are covered by synthetic schema-derived tests.
- Inbound sequence numbers come from one transport-wide monotonic counter.
  Every authenticated frame advances it, including skipped control frames.
- A transport-control frame is parsed for safe metadata
  (`KEEP_ALIVE.ack`, retry media, `is_request`), reported as a `SKIP` timeline
  event, and does not fail the paired-key stage.
- `KEEP_ALIVE` without `ack=true` is answered with a schema-valid
  `KEEP_ALIVE{ack=true}` frame.
- `DISCONNECTION` is reported as a peer disconnect, not as a paired-key result
  or a message-type error.
- A peer that floods control frames is bounded at 16 skipped frames per
  application-message wait.

### 4.3 Proven defect and fix

The proven defect was local: `run_paired_key_response()` assigned fixed
sequence numbers to application messages and passed the next authenticated
frame directly to `accept_peer_result()`. A legal authentic
`BANDWIDTH_UPGRADE_RETRY` at sequence 3 therefore raised
`PairedKeyMessageError` and closed the socket.

No defect has been proven in the outbound SecureMessage envelope, directional
key schedule, sequence counters, OfflineFrame schema, payload header/chunk
fields, offsets, sizes, or terminators. The fix is limited to inbound
transport-control handling; the four outbound paired-key frames are unchanged.

### 4.4 Remaining unverified behavior

1. **Whether Android continues after the fix (unverified).** The next inbound
   application message could be the reciprocal `PAIRED_KEY_RESULT`, a chunked
   result, a `DISCONNECTION`, or another control frame. Only a real-device run
   can confirm it.
2. **Whether Android expects a reply to `BANDWIDTH_UPGRADE_RETRY.is_request=true`
   (unverified).** The schema documents such a reply, but the observed frame's
   `is_request` was not reported as `true`, and all reviewed receivers ignore
   the frame at this stage. No reply is sent in this iteration.
3. **Whether the empty PKE is accepted by Android (unverified).** This frame
   did not reject it; the later result/Introduction is still required to show
   acceptance.
4. **Multi-chunk BYTES result reassembly (still unimplemented).** A result
   split across chunks would currently fail the strict single-chunk structure
   check. The timeline would show it as `complete=false`.

## 5. Unverified hypotheses (detail)

The old hypotheses about the sequence-3 frame are now resolved: it was
`BANDWIDTH_UPGRADE_RETRY`, not `KEEP_ALIVE`, `DISCONNECTION`, or a chunked
`PAIRED_KEY_RESULT`. The remaining uncertainty is about Android's next step:

- If the reciprocal `PAIRED_KEY_RESULT` arrives next, the peer accepted the
  no-identity response at least through the paired-key stage.
- If another `BANDWIDTH_UPGRADE_RETRY` arrives with `is_request=true`, Android
  may expect the schema-documented supported-medium reply.
- If the socket closes or a `DISCONNECTION` arrives, Android may have rejected
  the empty PKE or the no-consent state.
- If no frame arrives before the deadline, the sender may be waiting for a
  message or UI action not implemented here.

## 6. Most likely explanation, with confidence

The sequence-3 failure is **confirmed** to be a local classification bug.
Confidence: **high**, because the timeline reported an authenticated and
decrypted `offline=BANDWIDTH_UPGRADE_RETRY` frame and independent receivers
treat that frame as ignorable transport traffic.

Android acceptance/rejection of the no-identity paired-key response remains
**unverified**. The observed frame does not show that Android rejected the
empty PKE; it shows only that Android was willing to continue the transport
conversation.

## 7. Whether legitimate identity material is required

- For a genuine paired-contact `SUCCESS` result, **yes**. That requires
  Google-account-provisioned Quick Share identity material: a private key and
  certificate, a secret ID, and the authoritative construction and validation
  rules for `signed_data` and `secret_id_hash`. This repository does not have
  that material and must not fabricate it.
- For an `UNABLE` fallback, NearDrop, NearShare, and Chromium use random
  placeholder bytes, which are not identity proof. This project deliberately
  uses an empty schema-valid PKE instead.
- If a later device run shows that Android rejects or closes on the empty
  PKE, then a legitimate no-identity construction must be established from an
  authoritative source, or real identity provisioning must be implemented.
  Random placeholder values presented as identity data are not an acceptable
  substitute.
- The confirmed `BANDWIDTH_UPGRADE_RETRY` frame does not, by itself, prove that
  identity material is required.

## 8. What the current implementation can and cannot do

Can do:

- Advertise mDNS and accept TCP connections.
- Complete the observed UKEY2 P-256 handshake and derive directional keys.
- Exchange plaintext `CONNECTION_RESPONSE ACCEPT`.
- Authenticate and decrypt inbound SecureMessages.
- Structurally parse PKE offers and results without logging contents.
- Send a schema-valid empty PKE and `PAIRED_KEY_RESULT.UNABLE`.
- Skip authenticated transport-control frames, acknowledge `KEEP_ALIVE`, and
  keep waiting for the reciprocal paired-key messages.
- Authenticate a peer result and optional Introduction when they arrive.
- Produce a sanitized protocol timeline with distinct error categories.

Cannot do:

- Prove or claim a paired identity.
- Produce a `SUCCESS` paired-key result.
- Reply to `BANDWIDTH_UPGRADE_RETRY` requests with a supported-medium list.
- Reassemble a multi-chunk BYTES result in this stage.
- Parse Introduction metadata into a user-facing offer, request consent, or
  transfer files.
- Claim Android UI acceptance or Quick Share interoperability.

## 9. Single best next real-device experiment

Run exactly one diagnostic attempt:

```powershell
python -m vishare_quick advertise --ukey2-handshake --paired-key-response --protocol-timeline --seconds 60
```

Expected timeline shape after the fix:

```text
[+...] IN    SECURE_MESSAGE seq=3 authenticated=true decrypted=true stage=peer paired-key result
[+...] IN    FRAME offline=BANDWIDTH_UPGRADE_RETRY
[+...] IN    SKIP offline=BANDWIDTH_UPGRADE_RETRY ... reason=transport-control
[+...] IN    SECURE_MESSAGE seq=4 authenticated=true decrypted=true stage=peer paired-key result
[+...] IN    FRAME offline=PAYLOAD_TRANSFER sharing=PAIRED_KEY_RESULT ...
[+...] IN    SECURE_MESSAGE seq=5 authenticated=true decrypted=true stage=peer paired-key result terminator
[+...] IN    SECURE_MESSAGE seq=6 authenticated=true decrypted=true stage=optional Introduction
[+...] IN    FRAME offline=PAYLOAD_TRANSFER sharing=INTRODUCTION ...
[+...] STATE INTRODUCTION_RECEIVED
```

The exact sequence numbers may differ if additional control frames interleave.
Report back:

- the full `IN SKIP` line for the retry frame,
- the next `IN SECURE_MESSAGE` and `IN FRAME` lines after it,
- whether `sharing=PAIRED_KEY_RESULT` appears and its `result_status`,
- the `STATE` lines through `PEER_PAIRED_KEY_RESULT_*` and `INTRODUCTION_*`,
- any `ERROR`/`SOCKET_CLOSED` lines,
- the Android UI state (e.g. still "Connecting", consent prompt, error).

If Android repeats `BANDWIDTH_UPGRADE_RETRY` with `retry_is_request=true` or
stalls, do not repeat the run blindly: the next iteration should implement the
schema-documented `BANDWIDTH_UPGRADE_RETRY` reply with `is_request=false` and
no supported media, without fabricating identity material.

## 10. Exact files and functions involved

Implemented for the confirmed `BANDWIDTH_UPGRADE_RETRY` finding:

- `src/vishare_quick/paired_key_response.py`
  - `_read_next_application_frame()`: transport-control skip loop,
    `KEEP_ALIVE` acknowledgement, `DISCONNECTION` handling, 16-frame cap.
  - `run_paired_key_response()`: single transport-wide inbound/outbound
    sequence counters.
  - `build_keep_alive_ack_frame()`: schema-valid `KEEP_ALIVE{ack=true}`.
- `src/vishare_quick/secure_channel.py`
  - `_parse_offline_frame()`: parses `KEEP_ALIVE.ack`,
    `BandwidthUpgradeRetryFrame.supported_medium`, and `is_request` into safe
    metadata.
  - `AuthenticatedFrameSummary`: carries that metadata.
- `src/vishare_quick/protocol_timeline.py`
  - `skipped_transport_frame()`, medium-name rendering, and keep-alive/retry
    fields for `SKIP` and `FRAME` events.
- Tests:
  - `tests/test_paired_key_response.py`: retry skip, keep-alive ack, global
    sequence, flood cap, disconnection, and timeline assertions.
  - `tests/test_secure_channel.py`, `tests/test_protocol_timeline.py`,
    `tests/test_cli.py`, `tests/test_advertise.py`: parsing, sanitization, and
    opt-in flag coverage.

Contingency only, not implemented:

- If Android expects a retry reply: add a
  `build_bandwidth_upgrade_retry_reply()` that encodes
  `V1Frame.type=12`, body field 13, `BandwidthUpgradeRetryFrame.is_request=0`
  and no `supported_medium` entries, send it when
  `bandwidth_upgrade_retry_is_request is True`, and add a test for the exact
  field shape. Do not include fabricated identity material.
- If Android sends a multi-chunk result: add a per-payload BYTES accumulator
  keyed by payload ID with contiguous offsets, consistent total size, and
  LAST_CHUNK checks. NearShare `_recv_sharing_frame()` and squick-share
  `BytesPayloadAssembler` are the reference patterns.
- If Android rejects the empty PKE: do not add random placeholder identity.
  Document the required Google identity provisioning/certificate source and
  validation rules first; a new identity module and authoritative test vectors
  would be required.

# Paired-Key State Machine Analysis

Read-only investigation of the Android sender stall observed at the paired-key
stage of the ViShare Quick recipient flow. No protocol behavior, sequence
counter, cryptography, timeout, or wire frame was changed by this investigation.

Observation being explained (Infinix XPad, Android 14, `--ukey2-handshake
--paired-key-response --protocol-timeline --seconds 30`):

```text
+0.200  IN  seq 1  PAIRED_KEY_ENCRYPTION (Android offer, DATA)
+0.201  IN  seq 2  PAIRED_KEY_ENCRYPTION terminator (LAST_CHUNK)
+0.203  OUT seq 1  empty PAIRED_KEY_ENCRYPTION (DATA)
+0.205  OUT seq 2  PKE terminator
+0.205  OUT seq 3  PAIRED_KEY_RESULT UNABLE (DATA)
+0.207  OUT seq 4  PKR terminator
+0.698  IN  seq 3  BANDWIDTH_UPGRADE_RETRY retry_is_request=false (skipped)
+5.132  IN  seq 4  KEEP_ALIVE ack=false                -> acked
+10.181 IN  seq 5  KEEP_ALIVE ack=false                -> acked
+15.133 IN  seq 6  KEEP_ALIVE ack=false                -> acked
+15.145 ERROR       timed out waiting for inbound seq 7 (peer paired-key result)
```

Legend used throughout:

- **[Confirmed]** directly visible in the inspected source or in the captured
  timeline.
- **[Inferred]** a conclusion drawn from those facts but not directly provable
  from the available code (in particular, anything about GmsCore, whose sender
  implementation is not public).

---

## 1. Exact ViShare state machine

### 1.1 Code locations

| Concern | File / function |
| --- | --- |
| PKE builder | `src/vishare_quick/paired_key_response.py:151` `build_paired_key_encryption_frame()` |
| PKR builder | `src/vishare_quick/paired_key_response.py:163` `build_paired_key_result_frame()` |
| BYTES payload chunking | `src/vishare_quick/paired_key_response.py:194` `build_bytes_payload_messages()` |
| Four outbound frames | `src/vishare_quick/paired_key_response.py:219` `build_paired_key_response_messages()` |
| State object | `src/vishare_quick/paired_key_response.py:281` `PairedKeyResponseState` |
| Transport-control skipping | `src/vishare_quick/paired_key_response.py:401` `_read_next_application_frame()` |
| Orchestration | `src/vishare_quick/paired_key_response.py:442` `run_paired_key_response()` |
| Stage deadline | `src/vishare_quick/advertise.py:378` `response_deadline = time.monotonic() + 15.0` |
| Socket teardown | `src/vishare_quick/advertise.py:504-507` `finally: conn.close()` |
| Accept loop | `src/vishare_quick/advertise.py:165-169` |

### 1.2 States

`PairedKeyResponseState` (`paired_key_response.py:281-352`) is a strict serial
machine:

```text
awaiting-offer
  -> accept_offer(summary)                  requires sharing_type == PAIRED_KEY_ENCRYPTION,
                                            complete BYTES payload, offset 0, not LAST_CHUNK
awaiting-offer-terminator
  -> accept_offer_terminator(summary)       LAST_CHUNK, empty body, offset == total_size,
                                            same payload_id and total_size
ready-to-send
  -> mark_sent()                            after all four outbound frames are written
awaiting-peer-result
  -> accept_peer_result(summary)            requires sharing_type == PAIRED_KEY_RESULT,
                                            complete BYTES payload
awaiting-peer-result-terminator
  -> accept_peer_result_terminator(...)     structural LAST_CHUNK check
awaiting-introduction
  -> accept_introduction(...)               optional; or finish_without_introduction()
complete
```

### 1.3 Exact wire order produced by ViShare

`run_paired_key_response()` (`paired_key_response.py:494-518`):

1. Read inbound application frame 1: Android PKE DATA.
2. Read inbound application frame 2: Android PKE LAST_CHUNK.
3. Send four outbound frames without reading anything between them
   (`for message in build_paired_key_response_messages()` at line 503):
   - own PKE DATA (payload id 1),
   - own PKE LAST_CHUNK,
   - own PKR UNABLE DATA (payload id 2),
   - own PKR LAST_CHUNK.
4. Read inbound application frame 3: peer PKR DATA.
5. Read inbound application frame 4: peer PKR LAST_CHUNK.
6. Optionally read the Introduction; failure here is non-fatal
   (`introduction-timeout` / `introduction-disconnect`).

So the **local order** is:

```text
peer PKE  ->  local PKE  ->  local result  ->  peer result  ->  Introduction (read)
```

The two important properties:

- ViShare does **not** send its own PKE until the peer's PKE and terminator have
  both authenticated. This is a serialization choice: it defers its local PKE.
- ViShare sends its own PKR **before** reading the peer's PKR.

### 1.4 Transport-control handling

`_read_next_application_frame()` (`paired_key_response.py:401-439`) consumes any
authenticated non-`PAYLOAD_TRANSFER` frame while waiting for a sharing message:

- `DISCONNECTION` -> `PeerDisconnected`.
- `KEEP_ALIVE` with `ack != true` -> send a `KEEP_ALIVE ack=true` frame.
- `KEEP_ALIVE`, `BANDWIDTH_UPGRADE_NEGOTIATION`, `BANDWIDTH_UPGRADE_RETRY`,
  `AUTO_RESUME`, `AUTO_RECONNECT` -> skip (bounded at 16 frames).
- Any other type -> `PairedKeyMessageError`.

Every authenticated frame advances the single transport-wide inbound sequence
counter (`next_inbound`, lines 465-471), including skipped frames. This is why
the observed sequence numbers are 1, 2, 3, 4, 5, 6 and the awaited result is
sequence 7. **[Confirmed]**

The prior fix that made `BANDWIDTH_UPGRADE_RETRY` non-fatal is present and
correct; nothing in this investigation proposes changing it.

---

## 2. Exact reference implementation state machines

### 2.1 Google reference (`nearby-src/sharing/paired_key_verification_runner.cc`)

`PairedKeyVerificationRunner::Run` (`:115-134`):

1. `SendPairedKeyEncryptionFrame()` (`:121`).
2. `frames_reader_.ReadFrame(V1Frame::PAIRED_KEY_ENCRYPTION, ...)` (`:122-133`).

`OnReadPairedKeyEncryptionFrame` (`:136-189`):

1. `VerifyAuthTokenHashWithPrivateCertificates` (`:144`).
2. `VerifyPairedKeyEncryptionFrame` to compute `local_result` (`:161-162`).
3. `SendPairedKeyResultFrame(local_result)` (`:175`).
4. `frames_reader_.ReadFrame(V1Frame::PAIRED_KEY_RESULT, ...)` (`:177-188`).

`OnReadPairedKeyResultFrame` (`:191-214`) combines the peer status and invokes
the callback.

`SendPairedKeyEncryptionFrame` (`:244-297`) **always** populates both identity
fields:

- `signed_data` = signature, or `GenerateRandomBytes(72)` when no signature is
  available (`:258-263`, constant at `:56-59`: "consistent with the GmsCore
  implementation").
- `secret_id_hash` = certificate hash, or `GenerateRandomBytes(6)` when no
  certificate is available (`:265-272`).

There is no branch that emits an empty `PairedKeyEncryptionFrame`.

After verification, the incoming service waits for the Introduction with the
same timeout (`nearby_sharing_service_impl.cc:2687-2703`,
`kReadFramesTimeout` at `constants.h:48`, 15 s). The outgoing service sends the
Introduction (`:2719-2723`). `ProcessKeyVerificationResult`
(`share_session.cc:210-241`) treats `kUnable` as "continue, clear self-share"
and only `kFail` as fatal.

### 2.2 Chromium (`chromium_pkvr.cc`)

`Run` (`:148-181`): send local PKE, then read peer PKE.
`OnReadPairedKeyEncryptionFrame` (`:183-238`):

- Verify remote public certificate (`:196-198`).
- **If it returns `kFail`, invoke callback and return without sending a result**
  (`:203-209`); if contacts-only and unverifiable, same early return
  (`:210-221`).
- Otherwise compute `local_result` (`:223-224`), send it (`:230`), then read the
  peer result (`:232-237`).

`OnReadPairedKeyResultFrame` (`:240-263`) merges results.

The early-return path at `:203-209` is the one reference code path in which a
rejected peer PKE produces **no reciprocal `PAIRED_KEY_RESULT`**. The transport
is not closed by that path itself; the caller decides what to do next.

### 2.3 NearDrop

Inbound (`neardrop_inbound.swift`):

- After sending the plaintext `CONNECTION_RESPONSE` it immediately sends a PKE
  with random 72-byte `signedData` and 6-byte `secretIDHash` (`:251-260`).
- On peer PKE it sends `PAIRED_KEY_RESULT.unable` (`:266-276`).
- On peer result it transitions to the Introduction (`:278-281`).

Outbound (`neardrop_outbound.swift`): same shape, PKE sent immediately after the
peer's `CONNECTION_RESPONSE` accept (`:235-250`), result after peer PKE
(`:253-263`), Introduction after peer result (`:265-270`).

### 2.4 NearShare (`nearshare/core/connection.py`)

Inbound (`:385-405`) is the outlier:

1. Read peer PKE (`:388-390`).
2. Send own PKE (`:391-396`).
3. Read peer result (`:398-400`).
4. Send own result (`:401-405`).

Outbound (`:681-698`) is conventional: send own PKE (`:681-686`), read peer PKE
(`:687-689`), send own result (`:691-695`), read peer result (`:696-698`).

Transport control: `_recv_encrypted` answers keep-alives transparently
(`:210-230`); `_recv_sharing_frame` skips every non-`PAYLOAD_TRANSFER` frame
(`:272-279`). Keep-alive constants are 10 s interval / 30 s read timeout
(`:37-38`).

The code comment at `:385-387` states that, holding no Google-account
certificate, NearShare sends random signed data, reports `UNABLE`, and "The
phone then falls back to PIN-based verification."

### 2.5 squick-share

Inbound (`squick_inbound.swift`): sends own PKE before entering
`awaitingPairedKeyEncryption` (`:74-75`); on peer PKE sends its result
(`:215-223`); on peer result enters `awaitingIntroduction` (`:224-228`).

Outbound (`squick_outbound.swift`): sends own PKE (`:89-90`); on peer PKE sends
its result (`:122-127`); on peer result sends the Introduction (`:128-134`).

Transport control is handled in `handleCommon` before sharing-frame dispatch
(keep-alive ack, bandwidth upgrade failure/ignore). Stage timeouts:
`pairedKeyTimeout = 15` s, `introductionTimeout = 15` s
(`Transport/Framing.swift:18-21`).

### 2.6 Common property

**[Confirmed]** None of the reviewed implementations treats transport-control
frames as paired-key messages, and none requires the peer's result before
sending its own result except NearShare inbound. Google's frame reader caches
an out-of-order frame rather than dropping it
(`incoming_frames_reader.cc:200-206`), so a locally early result cannot be lost
by a Google-style reader.

---

## 3. Side-by-side message ordering

### 3.1 Full sequences

| Implementation (role) | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| **ViShare (receiver)** | read peer PKE | read peer PKE terminator | **send local PKE** | **send local result** | read peer result -> read Introduction |
| **Google PKVR (any)** | **send local PKE** | read peer PKE | **send local result** | read peer result | incoming: read Introduction; outgoing: send Introduction |
| **Chromium PKVR** | **send local PKE** | read peer PKE | **send local result** | read peer result | callback (no Introduction here) |
| **NearDrop inbound** | **send local PKE** (after ConnectionResponse) | read peer PKE | **send local result** | read peer result | read Introduction |
| **NearDrop outbound** | **send local PKE** | read peer PKE | **send local result** | read peer result | send Introduction |
| **NearShare inbound** | read peer PKE | send local PKE | read peer result | send local result | read Introduction |
| **NearShare outbound** | **send local PKE** | read peer PKE | **send local result** | read peer result | send Introduction |
| **squick inbound** | **send local PKE** | read peer PKE | **send local result** | read peer result | read Introduction |
| **squick outbound** | **send local PKE** | read peer PKE | **send local result** | read peer result | send Introduction |

### 3.2 The two questions that matter

**Does ViShare send its result too early (before the peer result)?**

No. **[Confirmed]** Google (`paired_key_verification_runner.cc:175-188`),
Chromium (`chromium_pkvr.cc:230-237`), NearDrop (inbound `:274`, outbound
`:261`) and squick (inbound `:222`, outbound `:126`) all send their local result
immediately after reading the peer PKE and only then read the peer result.
NearShare inbound (`:398-405`) is the only implementation that waits for the
peer result first. ViShare's "local result before peer result" is therefore the
majority behavior, not an error.

**Does ViShare send its own PKE too late?**

It is a deviation, but a benign one. **[Confirmed]** Every other implementation
sends its PKE eagerly after the plaintext connection response, without waiting
for the peer PKE. ViShare instead reads the peer PKE and terminator first. This
changes concurrency, not the per-peer read order: each side still sees the
peer's PKE before the peer's result. No reference requires the peer to have
received a local PKE before sending its own.

**Transport control between stages:** all references ignore keep-alives and
bandwidth frames while waiting. **[Confirmed]** ViShare's behavior matches.

---

## 4. Empty PKE semantic analysis

### 4.1 What ViShare actually sends

During the investigation that produced this document,
`build_paired_key_encryption_frame()` emitted an 8-byte sharing frame with all
four `PairedKeyEncryptionFrame` fields absent:

```text
Frame{ version: V1,
       v1: V1Frame{ type: PAIRED_KEY_ENCRYPTION,
                    paired_key_encryption: {} } }
```

That is the frame the Android stall was observed with. Following approval, the
builder now emits the reference no-credential shape described in section 8:
fresh random 72-byte `signed_data`, fresh random 6-byte `secret_id_hash`, the
other three optional fields absent, and a `PairedKeyResultFrame.UNABLE`. The
schema and semantic analysis below still applies to the empty variant and
explains why it was replaced.

### 4.2 Schema validity versus semantic acceptance

**[Confirmed] schema-valid.** `sharing/proto/wire_format.proto:383-402` declares
every field of `PairedKeyEncryptionFrame` as `optional` (`signed_data`,
`secret_id_hash`, `optional_signed_data`, `qr_code_handshake_data`,
`supports_provisioning`). A present-but-empty submessage parses successfully and
sets `has_paired_key_encryption()`.

**[Confirmed] not used by any reviewed implementation.** Every reference
populates the frame, even when it has no identity:

| Implementation | `signed_data` | `secret_id_hash` | Result |
| --- | --- | --- | --- |
| Google PKVR | signature, else **random 72 bytes** | cert hash, else **random 6 bytes** | `UNABLE` when unverifiable |
| NearDrop | **random 72** | **random 6** | `UNABLE` |
| NearShare | **random 72** | **random 6** | `UNABLE` |
| squick inbound/outbound | `SharingFrames.pairedKeyEncryption()` (populated) | populated | `UNABLE` |
| Chromium | signature / placeholder builder | computed | `UNABLE` / `FAIL` |

Google's own comment ties the 72-byte fallback to GmsCore
(`paired_key_verification_runner.cc:56-59`), and `SendPairedKeyEncryptionFrame`
unconditionally calls `set_signed_data(...)` and `set_secret_id_hash(...)`
(`:280`, `:293-294`). There is no empty-frame path in the reference
implementation.

### 4.3 Consequence when a receiver does have a certificate

**[Confirmed]** `VerifyPairedKeyEncryptionFrame`
(`paired_key_verification_runner.cc:334-375`):

- no local certificate -> `kUnable` (`:337-342`);
- signature verification fails and no `optional_signed_data` -> `kFail`
  (`:350-356`).

An empty `signed_data` therefore cannot verify. With a certificate present it is
`kFail`; without one it is `kUnable`. A `kFail` at the remote-certificate stage
in Chromium returns without sending any result (`chromium_pkvr.cc:203-209`).

**[Inferred]** GmsCore likely has an equivalent "cannot even attempt
verification" path for a frame whose `signed_data` is absent, and it is
plausible that this path suppresses the reciprocal result while leaving the
Nearby Connections transport alive. The exact GmsCore branch is not public, so
this remains an inference, not a proven fact.

### 4.4 Policy note

Sending 72/6 random bytes is not an identity claim. It is the protocol's
documented no-credential fallback: no certificate, no signature, no secret, and
an explicit `UNABLE` result. Google's production reference does exactly this,
and two independent clients that report working Android interoperability
(NearDrop, NearShare) do the same. It must still be explicitly labelled as
random placeholder data in code and documentation, and it must not be copied
from any real device.

---

## 5. Interpretation of the repeated Android KEEP_ALIVE messages

What the log proves **[Confirmed]**:

- The TCP connection is open.
- UKEY2/SecureMessage authentication and decryption still succeed for inbound
  sequences 4, 5 and 6.
- ViShare's acknowledgements (outbound 5, 6, 7) are accepted; Android keeps
  using the session.
- The sharing layer has produced no `PAIRED_KEY_RESULT` for roughly 15 s.

What the log does **not** prove: that Android accepted the PKE, or that it is
waiting specifically for the reciprocal result.

Hypotheses and the source support for each:

| Hypothesis | Support | Verdict |
| --- | --- | --- |
| H1. Android is waiting for the reciprocal result | Google/Chromium/NearDrop/squick send their result immediately after reading the peer PKE, so a healthy Android would have sent it within milliseconds of ViShare's PKE. Absence is abnormal. | Plausible as a *symptom*, not a root cause |
| H2. Android rejected the empty PKE and stopped before sending a result | All references populate `signed_data`; empty data cannot verify; Chromium has a confirmed no-result early-return path. | **Strongest supported hypothesis** |
| H3. Android is blocked on transport control (`BANDWIDTH_UPGRADE_RETRY`) | `retry_is_request=false` is a response, not a request; references never gate sharing frames on it; keep-alives continue. | Weak |
| H4. Android is waiting for user interaction | The PIN/consent decision belongs to the receiver, and the sender only waits for acceptance after sending the Introduction, which has not happened. | Weak |
| H5. Android is waiting for a different protocol message (e.g. Introduction from ViShare) | The Introduction is sender-originated; a receiver never sends one. | Very weak |
| H6. Android's sharing layer aborted on the empty frame while the connection layer stayed alive | Consistent with no result plus continued keep-alives; no public code to confirm. | Plausible companion to H2 |

Keep-alives are generic liveness traffic (squick default 5 s
`keepAliveInterval`, NearShare 10 s, NearDrop acks them). Their presence rules
out a dead socket; it does not rule out a stalled or rejected sharing-layer
state. **[Confirmed]**

---

## 6. Timeout and reconnection analysis

### 6.1 Where the 15 s comes from

`advertise.py:376-378`:

```python
# A fresh bounded stage: the earlier handshake
# deadline may already be nearly spent.
response_deadline = time.monotonic() + 15.0
```

This is local and deliberate, not inherited from the handshake deadline.
`ResponseReader.recv` and `BoundedWriter.sendall` (`:380-394`) enforce it on
every read and write, and the same deadline covers the initial PKE exchange, the
peer-result wait and the optional Introduction wait.

It is reference-consistent:

| Implementation | Paired-key stage timeout |
| --- | --- |
| ViShare | 15 s hardcoded (`advertise.py:378`) |
| Google | `kReadFramesTimeout = 15 s` (`constants.h:48`), used for both PKE reads and the Introduction read (`share_session.cc:206`, `nearby_sharing_service_impl.cc:2702`) |
| squick | `pairedKeyTimeout = 15 s`, `introductionTimeout = 15 s` (`Framing.swift:18-21`) |
| NearShare | no paired-key stage timer; 30 s per read (`connection.py:38`) |
| NearDrop | no fixed stage timeout; blocking reads |

Extending the timeout is not justified by protocol evidence. The peer had
already had 15 s of uninterrupted, authenticated, keep-alive-acknowledged
transport; a longer local wait would only mask the missing result.

### 6.2 Why the first connection closes and a second appears

**[Confirmed]** On timeout, `FrameTimeout` propagates out of
`run_paired_key_response`, is classified at `advertise.py:416-423`, and the
`finally` at `advertise.py:504-507` closes the socket. The outer accept loop
(`:165-169`) continues for the remaining `--seconds` window and accepts the next
connection.

**[Inferred]** The second TCP connection is the Android client retrying after
observing the first connection close. ViShare has no reconnect logic and never
initiates a second connection itself.

---

## 7. Most likely explanation for the stall, with confidence

**Most likely explanation:** the empty `PairedKeyEncryptionFrame` is the
anomalous input. The ordering ViShare uses is reference-consistent, the
transport-control handling is reference-consistent, and the timeout is
reference-consistent; the only remaining protocol-level deviation was that
ViShare sent a PKE with no `signed_data` and no `secret_id_hash`, which no
reviewed implementation emits, including Google's own no-certificate fallback
(that frame has since been replaced; see section 8).
Android's sender-side verification therefore never reaches the point of emitting
its reciprocal `PAIRED_KEY_RESULT`, while the Nearby Connections transport
continues to send keep-alives.

**Confidence: moderate (~60%).**

Why it is not higher:

- GmsCore's sender implementation is not public. The observed "no result, but
  keep-alives continue" state is consistent with a rejected PKE, but the exact
  branch cannot be confirmed.
- The Google runner still sends a result on `kFail` at the local-verification
  stage; only the remote-certificate `kFail` in Chromium returns without a
  result. If Android follows the former shape, an empty PKE alone would produce
  a result (`UNABLE`/`FAIL`), not silence.
- No packet capture proves Android decoded ViShare's PKE payload as a sharing
  frame. Authentication success proves the SecureMessage layer, not the sharing
  layer.

What is ruled out with high confidence:

- **Ordering**: sending the local result before the peer result is the majority
  behavior (Google, Chromium, NearDrop, squick). **[Confirmed]**
- **Transport-control skipping**: `BANDWIDTH_UPGRADE_RETRY` is correctly skipped
  and must stay non-fatal. **[Confirmed]**
- **Timeout too short**: 15 s matches Google and squick. **[Confirmed]**
- **ViShare retry loop causing the second connection**: the accept loop simply
  continues; the reconnect is client-side. **[Inferred, strong]**

---

## 8. The single most useful next implementation change

**Status: implemented (approved).** The investigation recommended replacing the
empty PKE body with the reference-shaped no-credential PKE, and that change is
now in `build_paired_key_encryption_frame()`:

```text
PairedKeyEncryptionFrame {
  signed_data: 72 fresh random bytes   (secrets.token_bytes)
  secret_id_hash: 6 fresh random bytes (secrets.token_bytes)
  // optional_signed_data, qr_code_handshake_data, supports_provisioning absent
}
```

with `PairedKeyResultFrame.UNABLE` unchanged. This mirrors
`PairedKeyVerificationRunner::SendPairedKeyEncryptionFrame`
(`:258-294`), NearDrop (`neardrop_inbound.swift:257-258`), NearShare
(`connection.py:394-395`, `:684-685`) and squick, and is the only untested
variable for which every reference provides positive evidence.

Why this shape and not a fabricated identity:

- The bytes are generated per call with `secrets.token_bytes(...)`; they are
  never hardcoded, copied from a device, or derived from a real certificate.
- They are documented and tested as random placeholders, not as a signature,
  hash, identity, or certificate.
- The receiver still reports `UNABLE`, so no verification claim is made.
- `optional_signed_data`, `qr_code_handshake_data`, and `supports_provisioning`
  remain absent.

What deliberately did **not** change:

- The state machine, inbound/outbound sequence counters, and strict structural
  checks.
- The 15 s stage deadline.
- The transport-control skip, including the non-fatal
  `BANDWIDTH_UPGRADE_RETRY` handling.
- The opt-in `--paired-key-response` gate; the default advertisement never sends
  this frame.

The test suite asserts the two placeholder lengths, the absence of the
identity-bearing optional fields, and that two calls produce different bytes.
It never asserts a specific random value.

If the placeholder still stalls on a real device, the next diagnostic is not
another protocol change; it is a single run that captures the Android UI state
at the stall. See section 9.

---

## 9. What still requires real-device verification

These cannot be settled from source alone:

1. **Does Android send `PAIRED_KEY_RESULT` when ViShare sends a populated
   placeholder PKE?** This is the direct test of the implemented change. One run
   is sufficient.
2. **What is the Android UI doing during the stall?** A PIN dialog, a
   "waiting for acceptance" screen, a silent spinner, or an error would
   distinguish "verification rejected" (H2/H6) from "waiting on another stage"
   (H3/H5).
3. **Does Android retry the whole exchange on the second connection, or resume a
   different stage?** The second connection was observed but not analysed; its
   inbound sequence 1 should show whether it repeats the PKE offer.
4. **Does eager PKE (send before reading the peer PKE) change anything?** This
   isolates ordering from content. It is not recommended as a fix, only as a
   diagnostic if the placeholder PKE still stalls.
5. **Does the Introduction arrive after a successful placeholder exchange, and
   does the PIN/consent flow proceed?** This confirms the stage transition past
   paired-key verification.
6. **Does a peer result arriving near the 15 s boundary leave enough time for the
   Introduction?** The current single deadline covers both waits; a late result
   would leave no time for the Introduction, which may deserve a separate
   follow-up if it is observed.

Until at least item 1 is run, the root cause remains an inference. A connected
socket and authenticated keep-alives do not prove that Android accepted the
paired-key exchange.

---

## Appendix A. Evidence inspected

ViShare:

- `src/vishare_quick/paired_key_response.py`
- `src/vishare_quick/advertise.py`
- `src/vishare_quick/secure_channel.py`
- `src/vishare_quick/protocol.py`

References (local copies under
`C:\Users\testt\AppData\Local\Temp\opencode\`):

- Google: `nearby-src/sharing/paired_key_verification_runner.cc`,
  `share_session.cc`, `nearby_sharing_service_impl.cc`,
  `incoming_frames_reader.cc`, `constants.h`, `sharing/proto/wire_format.proto`.
- Chromium: `refsrc/chromium_pkvr.cc`, `refsrc/chromium_pkvr.h`.
- NearDrop: `refsrc/neardrop_inbound.swift`, `refsrc/neardrop_outbound.swift`,
  `refsrc/neardrop_nearby.swift`.
- NearShare: `refsrc/nearshare_connection.py`.
- squick-share: `refsrc/squick_inbound.swift`, `refsrc/squick_outbound.swift`,
  `refsrc/squick_frames.swift`, `refsrc/squick_framing.swift`,
  `refsrc/squick_publictypes.swift`.
- Schema: `refsrc/google_wire_format.proto`,
  `refsrc/google_offline.proto`.

## Appendix B. Repository state

The read-only investigation added only `docs/PAIRED_KEY_STATE_MACHINE_ANALYSIS.md`
and made no source, test, configuration, sequence, cryptographic, or timeout
change.

After explicit approval, the follow-up implementation change replaced the empty
PKE with the random 72-byte `signed_data` / 6-byte `secret_id_hash` no-credential
placeholder. The state machine, sequence counters, 15 s timeout,
transport-control skip, and `UNABLE` result are unchanged. The README, CLI
warning, and tests were updated to match. Validation is reported in the final
response.

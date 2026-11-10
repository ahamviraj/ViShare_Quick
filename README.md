# ViShare_Quick

**Package:** `alpha_0.4-dev` (research build)\
**Target:** Windows / Linux · Python 3.10+

This build advances the experimental Alpha 0.3 mDNS advertiser with a read-only TCP frame
inspector and a separate, opt-in UKEY2 plus plaintext Nearby connection-response experiment. It reads four-byte big-endian
length-prefixed frames, enforces a 1 MiB limit,
and recognizes documented Nearby Connections `OfflineFrame` v1 and UKEY2 outer envelopes. For
UKEY2 ClientInit it reports schema-backed version, random length, cipher commitment metadata, and
next-protocol validation without printing field values. Inspection is the default and sends no
response. The experimental mode sends `SERVER_INIT`, verifies `CLIENT_FINISH`, sends and validates
the plaintext `CONNECTION_RESPONSE` ACCEPT exchange, then closes before encrypted traffic unless
the separate `--inspect-encrypted-frame` option is selected. That option reads one bounded frame,
authenticates the exact SecureMessage bytes using Android-to-laptop receive keys derived from the
UKEY2 result, then decrypts and validates the D2D sequence and inner Nearby framing. The additional
`--paired-key-probe` mode checks the authenticated paired-key structure and waits for at most one
more inbound frame. It sends no paired-key response because the available implementations do not
provide trustworthy, identity-valid response material for this project. The separate
`--paired-key-response` mode is an explicit no-credential fallback: after the
authenticated Android offer and terminator it sends the protocol's random
72-byte `signed_data` / 6-byte `secret_id_hash` placeholder
`PairedKeyEncryptionFrame` plus `PairedKeyResultFrame.UNABLE`, then observes the
peer result. None of these modes implements
consent or file transfer.

## Commands

```powershell
python -m vishare_quick --version
python -m vishare_quick doctor
python -m vishare_quick mdns-check --seconds 30
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --inspect-frames
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --inspect-encrypted-frame
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --paired-key-probe
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --paired-key-response
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --dump-first-frame-hex
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --dump-frame-hex-index 2
```

`advertise` publishes `_FC9F5ED42C8A._tcp.local.` and opens a TCP listener. Without
`--inspect-frames`, it retains the original initial-byte diagnostic behavior. With the option, it
reports frame lengths, message families, recognized outer types, and safe validation status, then closes on timeout, malformed input,
or peer disconnect. Use on a trusted local network. `--ukey2-handshake` opts into a response
mode; it expects the observed connection request, ClientInit, ClientFinish, and peer
`CONNECTION_RESPONSE` sequence. It accepts the Nearby connection in this explicit experimental
mode and closes after validating the peer's plaintext ACCEPT.
`--inspect-encrypted-frame` requires `--ukey2-handshake`. It waits for one more frame within the
same bounded timeout and 1 MiB frame limit, then stops. It verifies HMAC-SHA256 over the exact
received `header_and_body` bytes before parsing metadata or decrypting AES-256-CBC. It validates
algorithms, public metadata, PKCS#7 padding, D2D sequence (first inbound sequence is 1), and the
authenticated inner Nearby framing. When the BYTES payload contains a complete sharing Frame, it
reports the frame type without its contents. Authentication failure stops processing; it does not
try another key direction. No encrypted data is sent.
`--paired-key-probe` is a separate opt-in diagnostic and cannot be combined with
`--inspect-encrypted-frame`. It requires an authenticated first PAIRED_KEY_ENCRYPTION frame, reports
only the four schema field presence/lengths, and waits for at most one additional authenticated
frame (sequence 2). It sends no paired-key message. A peer follow-up without a local response is
reported as such; it is not treated as a successful pairing transition.
`--paired-key-response` requires `--ukey2-handshake` and cannot be combined with either probe or
encrypted inspection. It waits for the authenticated Android PKE offer (sequence 1) and its
zero-length `LAST_CHUNK` terminator (sequence 2) before writing anything. It then sends an empty
`PairedKeyEncryptionFrame` (all schema-optional identity bytes absent, not random placeholders) and
`PairedKeyResultFrame.UNABLE` as outbound sequences 1–4, using independent server-to-client keys.
It authenticates the peer result (sequences 3–4) and an optional Introduction (sequence 5). It does
not claim a verified identity, request consent, or transfer files. Whether Android accepts the empty
PKE variant is unverified; Chromium's own no-certificate fallback uses random bytes instead, which
this project deliberately does not copy.
`--dump-first-frame-hex` and `--dump-frame-hex-index N` opt in to a maximum 96-byte hexadecimal
prefix of the selected complete frame, including the four-byte length prefix. No other frames are
dumped, and bytes are not decoded as text.

## UKEY2 status

Two Android 14 XPad diagnostic runs identified a `CONNECTION_REQUEST` followed by a UKEY2
`CLIENT_INIT`: version 1, a 32-byte random, one cipher commitment for ID 100 (`P256_SHA512`)
with a 64-byte commitment, and a 23-byte `next_protocol` matching the documented Android 14
reference value. The parser reports these fields without printing their contents. These
observations establish offer metadata only, not commitment validity or peer authentication.

`--ukey2-handshake` opts into a responder implementation for version 1, cipher 100
(`P256_SHA512`), and the documented `AES_256_CBC-HMAC_SHA256` next-protocol offer. It validates
the offer, sends a schema-encoded `SERVER_INIT`, verifies `CLIENT_FINISH`, derives the reference
implementation's verification and next-secret material without logging the values, then exchanges
plaintext Nearby `CONNECTION_RESPONSE` ACCEPT frames. This does not complete peer identity
verification or the subsequent sharing protocol. The UKEY2 transcript and directional SecureMessage
key schedule have been cross-checked against NearShare and NearDrop source code, and the SecureMessage
processing order against squick-share. No external byte-for-byte known-answer vector is available.
Tests use deterministic synthetic fixtures and do not establish XPad interoperability. A user-reported
XPad frame was 214 bytes on wire (177-byte `header_and_body`, 32-byte signature), but its raw bytes are
not available in the repository; the latest user-reported real-device output says that frame
authenticated and decrypted as `PAYLOAD_TRANSFER` → `PAIRED_KEY_ENCRYPTION`, sequence 1. This reported
runtime result is separate from synthetic tests and is not independently reproducible from the raw
capture here. The no-credential response mode has only synthetic tests; Android acceptance is
unverified. Android still showed Connecting → Failed. No pairing, successful connection, or file
transfer has been demonstrated. Use
this experimental response mode only for a controlled real-device test. Details are in
[the Alpha 0.4 research notes](docs/ALPHA_0.4_RESEARCH.md) and [encrypted protocol research](docs/ALPHA_0.4_ENCRYPTED_PROTOCOL_RESEARCH.md).

## Install and test

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
python -m pytest -q
python -m unittest discover -s tests -v
```

## Protocol investigation

See [docs/ALPHA_0.4_RESEARCH.md](docs/ALPHA_0.4_RESEARCH.md) for sources, license notes, verified
framing facts, and remaining uncertainties. Google Nearby's published schema is used only to
identify the outer frame type; the Quick Share flow is not treated as a stable public specification.
The encrypted-frame diagnostic and its limitations are described in
[docs/ALPHA_0.4_ENCRYPTED_PROTOCOL_RESEARCH.md](docs/ALPHA_0.4_ENCRYPTED_PROTOCOL_RESEARCH.md).

## Build sequence

- `alpha_0.1`: CLI foundation
- `alpha_0.2`: passive Android Quick Share mDNS discovery
- `alpha_0.3`: experimental mDNS advertisement; Android discovery observed on one Infinix XPad
- `alpha_0.4`: bounded inspection and an opt-in experimental P256_SHA512 UKEY2 plus plaintext Nearby connection-response exchange; an experimental no-credential paired-key response (random 72-byte `signed_data` + 6-byte `secret_id_hash` placeholder PKE + UNABLE) is available but unverified, and encrypted consent/file transfer remain unimplemented
- Future milestone: implement and validate the complete receiver handshake and file reception
- Later milestone: implement and validate sending

No release tag or Alpha 0.4 release has been created. A successful file transfer has not been
demonstrated.

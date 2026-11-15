# ViShare_Quick

**Package:** `alpha_0.6` (research build)\
**Target:** Windows / Linux · Python 3.10+

## Download

Prebuilt single-file executables are attached to the release:

- Windows x64: `vishare-quick.exe`
- Linux x64: `vishare-quick` (x86_64, glibc 2.35 or newer)

Both are self-contained PyInstaller builds of the same receiver and use the same explicit PIN
confirmation and consent prompts. Launch the executable with no arguments (or double-click it on
Windows) to open the local graphical interface. The command-line commands below remain available
for scripted and diagnostic use.

Linux downloads do not keep the executable bit, so set it once:

```bash
chmod +x vishare-quick
./vishare-quick --version
./vishare-quick ui
./vishare-quick advertise --ukey2-handshake --receive-files
```

Windows (PowerShell):

```powershell
.\vishare-quick.exe --version
.\vishare-quick.exe ui
.\vishare-quick.exe advertise --ukey2-handshake --receive-files
```

This build packages the receiver as a local, multi-page interface while keeping the experimental CLI
and protocol diagnostics. Launching the executable with no arguments opens the interface: choose
**Receive files**, let the app advertise as a Quick Share endpoint, compare the 4-digit code shown on
both devices, and approve the sanitized file list before anything is saved. Progress and the final
result stay on screen, and a timeout, decline, cancellation, or disconnect fails closed and removes
partial files.

The command line remains available for scripted and diagnostic use, including bounded frame
inspection, the opt-in P256_SHA512 UKEY2 handshake, encrypted-frame inspection, paired-key probes,
the consent-gated `--receive-files` receiver, and the `peers`/`send` Quick Share sender.

## Highlights in `alpha_0.6`

- **Send files from the CLI**: `vishare peers` lists visible receivers, and `vishare send FILE...`
  discovers one, completes the UKEY2 handshake, offers the files, and streams them after the
  receiver accepts.
- **Explicit human PIN check before any file byte**: the sender prints its 4-digit code and sends
  nothing until you type `yes` after comparing it with the receiving device's screen.
- **Local-only sender**: it connects directly to the advertised LAN address, uses no Google account,
  cloud relay, or internet service, and puts only basenames on the wire.
- **Regular files only**: symlinks, directories, special files, empty files, and files that change
  size or modification time are rejected instead of being sent.
- **Fail-closed sender**: cancellation, timeout, disconnect, rejection, or a file that changes closes
  the connection and leaves no partial sender state.
- **Verified on device**: single-file, multi-file, chunked 1.2 MiB, and spaced-name transfers were
  received by an Android 14 XPad with matching PINs. The Send page remains a placeholder in this
  build; the sender is CLI-only for now.

## Highlights in `alpha_0.5`

- **Local multi-page interface**: Home, Receive, PIN/consent, progress, result, Settings, and a Send
  placeholder, using the bundled design and the Varela Round font.
- **Receive files in the browser**: advertising starts from the Receive screen, and the result
  screen offers the download folder, a retry on failure, and the activity log.
- **Explicit human PIN check**: the derived 4-digit code is shown only while the comparison is
  pending. The consent screen and logs never repeat it.
- **Explicit consent**: the sanitized file list and total size are shown before acceptance. There is
  no auto-accept.
- **Fail-closed cleanup**: timeouts, declines, leaving the request screen, cancellation, and
  disconnects reject the transfer and remove partial files.
- **Functional Settings**: change the visible device name while idle, open the download folder, stop
  receiving, or stop the interface.
- **Offline and local-only**: the server binds to `127.0.0.1`, requires a per-run token, sends a
  restrictive CSP, and ships every page, style, script, icon, and font.
- **CLI unchanged**: existing commands and diagnostics still work, including `--receive-files`.

## Local interface (`ui`)

`vishare ui` starts the receiver and serves the interface at `http://127.0.0.1:<port>/`. The
executable opens it automatically when launched without arguments; `--no-browser` suppresses the
tab. The server binds only to loopback, uses a fresh random token for each run, sends a restrictive
Content-Security-Policy, and never enables CORS. Every page, stylesheet, script, icon, and the
Varela Round font is bundled, so the interface works without an internet connection.

Pages:

- **Home**: the visible device name, current receiver state, Receive files, Send files (under
  construction), and Settings.
- **Receive**: starts advertising when opened, shows whether the laptop is visible, and offers
  **See Logs** and **Stop receiving**.
- **Request**: the 4-digit PIN comparison, followed by the file list and explicit Accept/Decline.
  The PIN is removed before consent is shown. Leaving the page declines the pending request.
- **Receiving**: per-file progress and a Cancel action that confirms before removing partial files.
- **Result**: completed, declined, failed, or cancelled state, saved file names and sizes, **See
  Logs**, **Open in Files**, and retry or back navigation.
- **Settings**: device name (while idle), download folder, **Stop receiving**, and **Stop
  interface**.

The activity panel is status text only; it never shows peer payload IDs, keys, or file contents.
Closing the browser tab does not stop advertising: use **Settings → Stop interface** or press
Ctrl+C in the terminal that launched the app.

Useful options:

```powershell
python -m vishare_quick ui --download-dir D:\Incoming
python -m vishare_quick ui --name "Desk PC" --port 8765 --no-browser
```

## Commands

```powershell
python -m vishare_quick --version
python -m vishare_quick doctor
python -m vishare_quick mdns-check --seconds 30
python -m vishare_quick ui
python -m vishare_quick ui --download-dir D:\Incoming
python -m vishare_quick ui --no-browser --port 8765
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --inspect-frames
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --inspect-encrypted-frame
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --paired-key-probe
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --paired-key-response
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --receive-files
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --ukey2-handshake --receive-files --download-dir D:\Incoming
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --dump-first-frame-hex
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120 --dump-frame-hex-index 2
python -m vishare_quick peers --seconds 8
python -m vishare_quick send --seconds 8 "C:\Users\me\Pictures\photo.jpg"
python -m vishare_quick send --peer 192.168.43.39:53601 FILE1 FILE2
python -m vishare_quick send --handshake-only FILE
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
zero-length `LAST_CHUNK` terminator (sequence 2) before writing anything. It then sends a
`PairedKeyEncryptionFrame` carrying fresh random 72-byte `signed_data` and 6-byte `secret_id_hash`
placeholders (the other identity fields are absent) plus `PairedKeyResultFrame.UNABLE` as outbound
sequences 1–4, using independent server-to-client keys. It authenticates the peer result
(sequences 3–4) and an optional Introduction (sequence 5). It does not claim a verified identity.
The placeholders are not real signatures or known-peer identifiers, so Android's acceptance is
still not a claim of identity verification.
`--dump-first-frame-hex` and `--dump-frame-hex-index N` opt in to a maximum 96-byte hexadecimal
prefix of the selected complete frame, including the four-byte length prefix. No other frames are
dumped, and bytes are not decoded as text.

## File reception (`--receive-files`)

`--receive-files` requires `--ukey2-handshake` and implies the paired-key response stage. The local
interface uses the same receiver and the same fail-closed rules. After the authenticated
Introduction it:

1. Derives the 4-digit code from the UKEY2 auth string and displays it as `Local code: NNNN`.
2. Asks the user to compare that code with the PIN shown on Android and type `y` to confirm a match
   or `n` to reject. A blank line, end of input, or any other answer fails closed; there is no
   automatic acceptance.
3. Shows the sanitized file list and total size, then requires an explicit accept (`1`, `accept`,
   `a`, `yes`, or `y`) before any file bytes are accepted.
4. Sends the sharing `RESPONSE`, streams each FILE payload to disk, and sends `DISCONNECTION` when
   the transfer ends.

### Destination and filenames

The default destination is `~/Downloads` (the user's home Downloads folder). Use
`--download-dir PATH` to choose another directory; the path may be absolute or relative to the
current directory and is created if it does not exist. `--download-dir` is only valid together with
`--receive-files`.

Peer-supplied names are reduced to a bare basename: path separators, traversal segments, control
and formatting characters, Windows-invalid characters, reserved device names, and leading/trailing
dots are removed. Files are never overwritten. If a name already exists, the receiver chooses
`name (1).ext`, `name (2).ext`, and so on. Bytes are streamed to a hidden
`.vishare-partial-*.part` file and atomically renamed only after the declared size and chunk
boundaries are satisfied; any failure closes and removes the temporary file.

### Integrity and limits

There is no end-to-end file digest in the reviewed Introduction or payload schema, so the receiver
reports a local SHA-256 for the user but does not claim it as peer verification. The integrity
statement is the declared size plus strict chunk offsets, and the final zero-length `LAST_CHUNK`.
Chunked (multi-frame) BYTES sharing payloads are not reassembled, and text-only shares are not
saved as files. Received files are never executed.

## Sending files (`send`)

`vishare peers --seconds N` browses the same mDNS service type as the receiver and prints the
receivers that answer. A discovered name, endpoint ID, and address are presentation only; they are
never treated as identity.

`vishare send FILE...` discovers exactly one receiver (or uses `--peer HOST:PORT`), connects
directly on the local network, performs the UKEY2 client handshake, offers the files in an
`Introduction`, and waits for the receiver's response. It:

1. Prints the derived 4-digit code and asks you to compare it with the code shown on the receiving
   device. Only an explicit `yes`/`y` continues; a blank line, end of input, `n`, or any other answer
   cancels before any file byte is read.
2. Requires the receiver's `RESPONSE ACCEPT` before opening any selected file.
3. Streams each file in 512 KiB chunks with a zero-length `LAST_CHUNK` terminator, sends periodic
   keep-alives, shows progress, and lingers briefly after the last chunk so the receiver can finish.

`--handshake-only` stops right after the receiver accepts the offer, so you can check the PIN and
the offered file list without reading a file byte. It is useful for controlled device tests.

Safety behavior:

- Only regular files are accepted. Symlinks, junctions, directories, and special files are rejected.
- Empty (0-byte) files are rejected locally, because Android Quick Share drops the whole offer
  before showing its accept sheet when one is included.
- Peer-visible names are bare sanitized basenames; local absolute paths never reach the peer.
- Each selected file's size and modification time are checked before and after streaming. A change
  aborts the transfer.
- Ctrl+C, a timeout, a rejected response, or a disconnect closes the connection and sends
  `DISCONNECTION`; the sender keeps no partial transfer state.
- The receiver may still have to discard a partially received file; the sender never claims a
  partial transfer succeeded.
- There is no resume, no cloud relay, and no Google account or internet dependency.

Sending is CLI-only in this build. The Send page in the local interface remains a placeholder.
Use the sender only on a trusted local network, with the receiving device's Quick Share sheet open
so it advertises its current port.

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
plaintext Nearby `CONNECTION_RESPONSE` ACCEPT frames. It can then run the paired-key response and,
with `--receive-files`, the consent-gated reception described above. Peer identity is still not
verified: the paired-key result is `UNABLE`, so the PIN comparison is the only out-of-band check.
The UKEY2 transcript and directional SecureMessage
key schedule have been cross-checked against NearShare and NearDrop source code, and the SecureMessage
processing order against squick-share. No external byte-for-byte known-answer vector is available.
Tests use deterministic synthetic fixtures. Live Android 14 XPad runs on a trusted local network
completed end-to-end reception for small image and document payloads, confirming the sender's
524,288-byte chunks and zero-length `LAST_CHUNK` terminator. A multi-gigabyte movie transfer was
reported by the user but not logged in this repository. Raw captures and peer filenames are not
stored here. The client role is implemented as well: `vishare send` performs the initiator
handshake, the no-credential paired-key exchange, the `Introduction`, and authenticated file
streaming. Single-file, multi-file, and chunked transfers have been received by an Android 14 XPad
on a trusted local network. Use the sender only in controlled real-device tests. Details are in
[the Alpha 0.4 research notes](docs/ALPHA_0.4_RESEARCH.md), [encrypted protocol research](docs/ALPHA_0.4_ENCRYPTED_PROTOCOL_RESEARCH.md),
and [the Alpha 0.6 sender notes](docs/ALPHA_0.6_SENDER_RESEARCH.md).

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
- `alpha_0.4`: bounded inspection, opt-in P256_SHA512 UKEY2, plaintext Nearby connection-response exchange, no-credential paired-key response (random-placeholder PKE + UNABLE), and a consent-gated streaming file receiver verified on one Android 14 XPad; peer identity verification remains unimplemented
- `alpha_0.5`: multi-page local interface for the same receiver (home, receive, PIN/consent, progress, result, settings), bundled offline assets, token-protected loopback server, explicit PIN and consent screens, progress/cancel/retry, activity log, saved-file result view, and functional settings; no protocol changes
- `alpha_0.6`: CLI Quick Share sender (`peers`, `send`, `--handshake-only`), UKEY2 client role, sender key schedule, mDNS peer discovery, explicit PIN gate, 512 KiB authenticated streaming, keep-alives, progress, cancel, linger, and fail-closed cleanup; verified single-file, multi-file, chunked, and spaced-name transfers on one Android 14 XPad; Send page remains a placeholder
- Future milestone: verify multi-file and text-only shares across more devices and display formats
- Later milestone: Send page in the local interface and broader sender hardening

Released as `alpha_0.6`. File reception and sending have been demonstrated on one trusted local
network; this is not a claim of peer identity verification or broad interoperability.

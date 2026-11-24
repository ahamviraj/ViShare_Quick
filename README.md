# ViShare_Quick

**Package:** `beta_0.9.1`\
**Target:** Windows / Linux · Python 3.10+

## Download

The latest published release is
[`beta_0.9.1`](https://github.com/ahamviraj/ViShare_Quick/releases/tag/beta_0.9.1).
Its prebuilt installers and portable packages are:

- Windows x64 installer: `ViShare-Quick-Setup-beta_0.9.1.exe`
- Windows x64 portable: `vishare-quick.exe`
- Linux x64 installer: `vishare-quick_0.9.1_amd64.deb`
- Linux x64 portable: `vishare-quick` (x86_64, glibc 2.35 or newer)

The Windows installer installs per-user without an administrator prompt, adds a searchable Start
Menu entry named **ViShare Quick**, and registers an uninstaller under **Settings → Apps**. The
installer starts the app in the background at sign-in by default and can open the app list so you
can pin the app manually. Windows does not allow installers to pin apps to Start or the taskbar, so
pinning remains a user action. The portable executable remains available for users who do not want
an installation.

The Linux `deb` package installs `/usr/bin/vishare-quick`, adds a searchable application-menu entry
named **ViShare Quick**, and registers normal package-manager uninstall metadata. Its dependencies
include GTK 3 and WebKitGTK for the native window; if those are unavailable, the app falls back to
the browser. The portable Linux binary can be run directly without installing.

Both platforms bundle Python and the application runtime with the same local interface and
command-line features. They use the same explicit PIN confirmation and consent prompts. Launch the
executable with no arguments (or double-click it on Windows) to open the local graphical interface.
The command-line commands below remain available for scripted and diagnostic use.

Linux (Debian/Ubuntu):

```bash
sudo apt install ./vishare-quick_0.9.0_amd64.deb
vishare-quick ui
vishare-quick --version
```

Linux portable downloads do not keep the executable bit, so set it once:

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

This build packages the receiver and sender as a local, multi-page interface while keeping the
experimental CLI and protocol diagnostics. Launching the executable with no arguments opens the
interface: choose **Receive files** to advertise as a Quick Share endpoint, or **Send files** to
stage local files and offer them to a nearby receiver. Both flows compare the 4-digit code on both
devices and require an explicit decision before file bytes move. Progress and the final result stay
on screen, and a timeout, decline, cancellation, or disconnect fails closed and removes partial
files.

The command line remains available for scripted and diagnostic use, including bounded frame
inspection, the opt-in P256_SHA512 UKEY2 handshake, encrypted-frame inspection, paired-key probes,
the consent-gated `--receive-files` receiver, and the `peers`/`send` Quick Share sender. The local
interface also sends files through the **Send** page.

## Highlights in `beta_0.9.1`

- **Windows Nearby Sharing handoff**: after staging files on the Send page, the Windows build shows
  a **Windows Nearby Sharing** card. **Send via Windows** opens the system share sheet, where Nearby
  Sharing can be selected as the destination.
- **Availability is explicit**: the card reports whether Nearby Sharing is enabled in Windows
  Settings and whether the app window is available. The button stays disabled with the reason when
  the handoff cannot be used.
- **Different protocols, no false claims**: this is a send-only Windows handoff. It does not discover
  cross-network Google Quick Share devices and does not add a Windows receiver. LAN Quick Share
  discovery, PIN confirmation, progress, and fail-closed cleanup are unchanged.
- **No false success**: if the system share sheet does not open, the Send page reports the failure
  instead of claiming that files were handed off. Launching the installed app directly is required
  when another program started it as a child process.
- **Verification**: 427 unit tests, including availability detection, share-session lifetime,
  service handoff, and the loopback API. The Windows app-window handoff was exercised through the
  real send API, and the frozen Windows build reported Nearby Sharing available and opened the
  share sheet when launched directly by Explorer. The installer still needs release verification.

## Highlights in `alpha_0.9`

- **Windows background mode**: the installed app starts hidden at sign-in, keeps running in the
  notification area, and reopens from the tray icon or with **Ctrl+Alt+V**.
- **Close to tray**: closing the Windows window hides it and keeps the local server available;
  **Quit ViShare Quick** in the tray menu or **Settings → Stop interface** shuts it down completely.
- **Single instance**: launching the app again brings the existing window forward instead of
  starting a second server.
- **Autostart and pinning help**: the Windows installer enables background startup at sign-in by
  default and offers to open the app list for manual **Pin to Start** or **Pin to taskbar**.
  **Ctrl+Alt+V** is a global shortcut while the app is running.
- **Explicit background launch**: `vishare ui --background` starts the Windows app hidden. The
  option is Windows-only; Linux keeps its existing close-to-exit behavior.
- **Verification**: 411 unit tests plus Windows tray, hotkey, close-to-tray, second-launch, and
  packaged-build checks.

## Highlights in `alpha_0.8`

- **Native app window**: `vishare ui` and the no-argument executable launch the local interface in a
  window instead of opening a browser tab. Linux falls back to the browser when GTK/WebKit is not
  available, and `--browser` preserves the previous browser mode.
- **Windows installer**: installs per-user without administrator rights, creates a searchable
  **ViShare Quick** Start Menu entry, adds an optional desktop shortcut, and registers an uninstaller.
- **Linux installer**: a Debian/Ubuntu `deb` package installs the application, icon, and searchable
  application-menu entry. Portable executables remain available for both platforms.
- **Clean shutdown**: closing the app window stops advertising and shuts down the local server;
  **Settings → Stop interface** also closes the window.
- **Verification**: 405 unit tests, packaged Windows and Linux builds, Windows installer
  install/launch/uninstall checks, and Linux package checks.

## Highlights in `alpha_0.7`

- **Send from the local interface**: the Home **Send** card now opens a complete sender flow instead
  of a placeholder.
- **Browser file staging**: select multiple files with the browser picker or drop them onto the
  page. Uploads stream to a private staging directory, and the browser never learns a local path.
- **Nearby receiver list**: discovery starts when the Send page opens and can be refreshed. The list
  exposes only presentation fields; peer endpoint IDs and instance names stay out of snapshots.
- **Same explicit PIN gate**: the derived 4-digit code appears only while comparison is pending. No
  file byte is read until you confirm a match and the receiver accepts the offer.
- **Progress, cancel, and retry**: per-file progress, cancel from connection through streaming, a
  dedicated failure page with **Try again**, and a completed state with **Send more files**.
- **Fail-closed cleanup**: staged copies and partial uploads are removed on clear, reset,
  cancellation, or interface shutdown. A timeout or disconnect never reports success.
- **Bounded selection**: sanitized unique names, non-empty files only, up to 64 staged files, and the
  sender's existing total-size limit.
- **Verification**: 398 unit tests, loopback HTTP smoke tests, and a Playwright end-to-end send
  through a mock receiver. A real Android run of the browser sender remains a follow-up check.

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
  received by an Android 14 XPad with matching PINs. This validation used the CLI sender; the local
  **Send** page was added in `alpha_0.7`.

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

`vishare ui` starts the local interface at `http://127.0.0.1:<port>/` and serves both the receiver
and sender pages in a native app window. The executable opens the same window when launched without
arguments. Use `--browser` to open the interface in the default browser instead, or `--no-browser` to
run the local server without opening either. The server binds only to loopback, uses a fresh random
token for each run, sends a restrictive Content-Security-Policy, and never enables CORS. Every page,
stylesheet, script, icon, and the Varela Round font is bundled, so the interface works without an
internet connection.

The app window uses Edge WebView2 on Windows; current Windows 10/11 installations normally provide
it already. Linux in-app windows require GTK 3 and WebKitGTK. If the webview backend is unavailable,
the default launch falls back to the browser instead of failing.

On Windows, every UI launch keeps a tray icon and the **Ctrl+Alt+V** global shortcut available.
Closing the window hides it instead of stopping the interface; choose **Open ViShare Quick** or press
**Ctrl+Alt+V** to bring it back. Choose **Quit ViShare Quick** from the tray menu or **Settings →
Stop interface** to stop advertising and the local server. `vishare ui --background` starts hidden,
which is what the installer's sign-in entry uses. The Windows installer cannot pin the app itself;
its optional final task opens the app list so you can right-click **ViShare Quick** and choose
**Pin to Start** or **Pin to taskbar**.

Pages:

- **Home**: the visible device name, current receiver state, Receive files, Send files, and Settings.
- **Receive**: starts advertising when opened, shows whether the laptop is visible, and offers
  **See Logs** and **Stop receiving**.
- **Request**: the 4-digit PIN comparison, followed by the file list and explicit Accept/Decline.
  The PIN is removed before consent is shown. Leaving the page declines the pending request.
- **Receiving**: per-file progress and a Cancel action that confirms before removing partial files.
- **Result**: completed, declined, failed, or cancelled state, saved file names and sizes, **See
  Logs**, **Open in Files**, and retry or back navigation.
- **Send**: choose files with the browser picker or drag and drop, upload them to a private staging
  directory, browse nearby Quick Share receivers, and start a send. Files never leave the local
  machine until you select a device and confirm the PIN.
- **Sending**: the derived PIN comparison, receiver acceptance, per-file progress, cancel, and the
  completed state with **Send more files**.
- **Send failed**: the safe error, the selected files, and **Try again** or **Main** navigation.
- **Settings**: device name (while idle), download folder, **Stop receiving**, and **Stop
  interface**.

The activity panel is status text only; it never shows peer payload IDs, keys, or file contents.
On Linux, closing the app window stops advertising and shuts down the local server. On Windows,
closing the window hides it to the tray; quit from the tray menu to stop the server. In browser or
headless mode, closing the tab does not stop advertising: use **Settings → Stop interface** or press
Ctrl+C in the terminal that launched the app.

Useful options:

```powershell
python -m vishare_quick ui --download-dir D:\Incoming
python -m vishare_quick ui --browser
python -m vishare_quick ui --name "Desk PC" --port 8765 --no-browser
python -m vishare_quick ui --background
```

`--background` is available on Windows only. It starts the window hidden and keeps the tray icon and
global shortcut active.

## Commands

```powershell
python -m vishare_quick --version
python -m vishare_quick doctor
python -m vishare_quick mdns-check --seconds 30
python -m vishare_quick ui
python -m vishare_quick ui --download-dir D:\Incoming
python -m vishare_quick ui --browser
python -m vishare_quick ui --no-browser --port 8765
python -m vishare_quick ui --background
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

The local **Send** page uses the same sender after uploading the selected files to a private
staging directory with the browser picker or drag and drop; it never opens a native file dialog.
It accepts up to 64 files per selection, rejects empty files, sanitizes names, and streams each
upload to disk before the page enables **Send**. The staged copies are removed when the send is
cleared, reset, cancelled, or the interface stops. The CLI sender remains available for scripted
and diagnostic runs. Use either sender only on a trusted local network, with the receiving device's
Quick Share sheet open so it advertises its current port. Implementation and verification details
are in [the Alpha 0.7 send-interface notes](docs/ALPHA_0.7_SEND_INTERFACE.md).

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
- `alpha_0.6`: CLI Quick Share sender (`peers`, `send`, `--handshake-only`), UKEY2 client role, sender key schedule, mDNS peer discovery, explicit PIN gate, 512 KiB authenticated streaming, keep-alives, progress, cancel, linger, and fail-closed cleanup; verified single-file, multi-file, chunked, and spaced-name transfers on one Android 14 XPad
- `alpha_0.7`: local **Send** page with browser file picker and drag/drop staging, nearby receiver list, explicit PIN confirmation, per-file progress, cancel, retry, failure routing, and fail-closed cleanup; sender device name follows Settings
- `alpha_0.8`: native app window for the local interface, browser fallback and explicit `--browser`/headless modes, clean window-close shutdown, per-user Windows installer with searchable Start Menu entry, and a Debian/Ubuntu package with a searchable application-menu entry
- `alpha_0.9`: Windows background mode with tray icon, global **Ctrl+Alt+V** shortcut, close-to-tray, single-instance foregrounding, sign-in autostart, and optional pinning help; Linux window-close behavior is unchanged
- `beta_0.9.1`: send-only Windows Nearby Sharing handoff from the Send page through the system share sheet, with explicit availability and failure reporting; Google Quick Share LAN discovery and sending remain unchanged
- Future milestone: verify multi-file and text-only shares across more devices and display formats, including the browser sender on a real Android device
- Later milestone: broader sender hardening

The latest published release is `beta_0.9.1`. File reception and sending have been demonstrated on
one trusted local network; this is not a claim of peer identity verification or broad
interoperability.

# Alpha 0.7: Local Send Interface

`alpha_0.7` exposes the verified Quick Share sender through the bundled local interface. The
protocol implementation is unchanged; the release adds the browser-facing sender workflow, its
loopback API, cleanup rules, and the documentation and tests for that path.

- CLI and interface share `sender.send_files` and `prepare_files`.
- The interface is still loopback-only, token protected, CSP restricted, and offline.
- No cloud relay, Google account, or internet dependency was added.

## Implemented features

### Home and navigation

- The Home **Send** card opens `send-send.html` instead of the under-construction page.
- The send flow uses three pages: `send-send.html` (selection and discovery),
  `send-sending.html` (connection, PIN, acceptance, progress, result), and `send-failed.html`
  (safe failure with retry).
- Completed sends stay on the sending page. Failed and cancelled sends route to the failure page.
- Device-name changes in Settings update both the receiver and the sender name.

### Browser file staging

- The page uses `<input type="file" multiple>` and a drag/drop zone. No native file dialog is opened
  by the server, and the browser never receives a local path.
- Each selected file is uploaded to the loopback API as a raw `application/octet-stream` body.
- The HTTP handler requires `Content-Length`, a `X-ViShare-Filename` header encoded as URL-escaped
  UTF-8, and a non-empty body.
- Uploads are streamed in 1 MiB reads to a hidden `.part` file in a private staging directory; the
  final name is committed with `os.replace` only after the declared length is read.
- Names are sanitized with the receiver's `safe_filename` rules. Duplicate selections become
  `name (1).ext`, `name (2).ext`, and so on.
- Empty files and files above the sender's 1 TiB total-size bound are rejected. A selection may
  contain at most 64 staged files.
- The selected-file list updates from the snapshot and offers **Clear files**. Clearing removes the
  staging directory.

### Receiver discovery

- Opening the Send page starts an 8-second `PeerBrowser` browse unless another send is busy.
- **Refresh nearby devices** starts another browse.
- The snapshot exposes only each peer's display name, device type, host, port, and transient key.
  Endpoint IDs, advertised instance names, and `name_is_advertised` are stripped.
- A single discovered peer can be selected automatically; with several peers the page requires an
  explicit choice.

### PIN, acceptance, and streaming

- Starting a send calls `send_files` with the same device name used by the receiver.
- The derived 4-digit code appears only while the comparison is pending, with a 300-second limit.
  The code is not included in logs or results.
- **Codes match** continues; **Codes differ** fails closed. A timeout or cancellation also fails
  closed.
- No file byte is read until the PIN matches and the receiver returns `RESPONSE ACCEPT`.
- Progress is reported per file and in total, using the existing 512 KiB authenticated streaming
  path. The sender lingers for 3 seconds after the last chunk so the receiver can finish.
- **Cancel** is available during connection, handshake, PIN wait, acceptance wait, and streaming.
- Failure keeps the staged selection so **Try again** can start another send. The failure page never
  claims that a partial transfer succeeded.

### Lifecycle and cleanup

- `dismiss_result` returns to the Send page while keeping the staged files.
- `clear_files` removes the selection and staging directory when no upload or send is active.
- `reset` stops discovery and removes files, peers, progress, results, and staging data.
- `SendService.stop` cancels any pending PIN wait or active send, joins the worker briefly, and
  removes staging data when the interface shuts down.
- A partial upload is removed on error, and reserved names or bytes are released so a retry can
  reuse the same filename.

## Loopback API

All routes require the per-run `X-ViShare-Token`. JSON bodies are limited to 8 KiB. Browser uploads
are the only route that accepts a larger body.

| Route | Purpose |
|---|---|
| `POST /api/send/add-file` | Raw file upload with `X-ViShare-Filename` and `Content-Length` |
| `POST /api/send/discover` | Start an 8-second nearby-receiver browse |
| `POST /api/send/start` | Start a send to `{"peer": "<snapshot key>"}` |
| `POST /api/send/pin` | Resolve the PIN comparison with `{"match": true|false}` |
| `POST /api/send/cancel` | Cancel the active send |
| `POST /api/send/clear-files` | Remove the staged selection |
| `POST /api/send/dismiss` | Return from a final result while keeping files |
| `POST /api/send/reset` | Reset the whole send screen and staging directory |

`GET /api/state` includes a merged `"send"` snapshot alongside the receiver state. The send snapshot
contains version, phase, active/discovering flags, device name, staged file metadata, total size,
peer presentation data, selected peer, PIN remaining time, progress, result, safe error text, and
bounded activity events.

## Safety properties

- The interface still binds to `127.0.0.1`, rejects non-loopback `Host` headers, uses no CORS, and
  serves a restrictive CSP. Pages are token-stamped before delivery.
- Uploads are validated before the body is read: method, token, length, content type, and filename.
- Local absolute paths and peer payload identifiers never enter the browser snapshot.
- PIN values are transient and exist only while the comparison is pending.
- Peer-visible names are sanitized basenames.
- Only regular files accepted by `prepare_files` are sent. Empty files, symlinks, directories,
  special files, and files that change during transfer are rejected.
- The sender keeps its existing fail-closed behavior on timeout, rejection, disconnect, cancel, and
  file mutation.

## Verification

- `python -m unittest discover -s tests -q` passes 398 tests.
- `node --check src\vishare_quick\ui\static\app.js` passes.
- The loopback HTTP smoke test loads all four pages and the send CSS, app script, and image assets,
  then uploads and clears a file through the API.
- Playwright interaction tests cover the picker, selected-file list, clear action, and page routing
  without console errors. The drag/drop handler uses the same upload function but is not separately
  exercised by an automated test.
- A Playwright end-to-end test starts an in-process `MockReceiver`, discovers it from the send page,
  uploads a file, starts the send, accepts the PIN, observes **Sent**, and confirms the receiver's
  payload bytes and filename match.
- Both release executables were smoke-tested with `--version` and with the UI upload/clear API. The
  Linux build was produced on Ubuntu 22.04 against glibc 2.35.

## Known follow-ups

- Run the browser sender against a real Android Quick Share receiver. The protocol sender was
  verified on device in `alpha_0.6`, but the `alpha_0.7` browser flow has only been verified against
  the loopback mock so far.
- Long-running sends, multi-gigabyte offsets, mid-transfer Wi-Fi loss, and receiver-initiated
  cancellation remain device checks.
- The sending page intentionally shows both the selected-file list and the progress list. This is
  presentation-only and does not duplicate transfers.
- Upload progress is not displayed; files are staged before the page enables **Send**.

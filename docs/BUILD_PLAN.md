# ViShare_Quick Build Plan

| Build | Status | Target |
|---|---|---|
| Alpha 0.1 | Foundation | CLI and GitHub workflow |
| Alpha 0.2 | Research validated | Passive Android Quick Share mDNS discovery |
| Alpha 0.3 | Experimental | mDNS advertisement; discovery observed on one Android 14 Infinix XPad |
| Alpha 0.4 | Released | Bounded read-only inspection by default; opt-in experimental P256_SHA512 UKEY2 and plaintext Nearby CONNECTION_RESPONSE exchange; consent-gated streaming file receiver |
| Alpha 0.5 | Released | Multi-page local interface for the file receiver: home, receive, PIN/consent, progress, result, settings, activity log, and finished result view |
| Alpha 0.6 | Current | CLI sender: peer discovery, UKEY2 client role, explicit PIN gate, authenticated 512 KiB streaming, multi-file and chunked transfers, cancel, linger, and fail-closed cleanup |
| Future receiver milestone | Not started | Verified peer identity and broader device/file-format coverage |
| Later sender milestone | Not started | Send page in the local interface and broader sender hardening |

The current build can advertise and inspect length-prefixed TCP frames from the CLI. The local
interface runs the same receiver: it advertises as a Quick Share endpoint, requires an explicit
4-digit PIN comparison, requires explicit consent after showing the sanitized file list and total
size, streams received files to disk, and removes partial files on failure. The interface is
loopback-only, token protected, and fully bundled for offline use.

`alpha_0.6` adds the sender as a separate protocol role. `vishare peers` browses the same mDNS
service type without connecting. `vishare send FILE...` performs the UKEY2 client handshake,
offers regular files, requires a local human PIN comparison and the receiver's `RESPONSE ACCEPT`,
then streams authenticated 512 KiB chunks with keep-alives and a final `LAST_CHUNK`. It sends
basenames only, rejects empty files (Android drops the whole offer), rejects symlinks, directories,
special files, and files that change during transfer, and closes on cancel, timeout, rejection, or
disconnect. Sending is CLI-only in this build; the Send page is still a placeholder.

The protocol implementation still does not verify peer identity, and chunked (multi-frame) BYTES
payloads and text-only shares are not reassembled by the receiver into files.

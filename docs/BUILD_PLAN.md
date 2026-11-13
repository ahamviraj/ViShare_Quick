# ViShare_Quick Build Plan

| Build | Status | Target |
|---|---|---|
| Alpha 0.1 | Foundation | CLI and GitHub workflow |
| Alpha 0.2 | Research validated | Passive Android Quick Share mDNS discovery |
| Alpha 0.3 | Experimental | mDNS advertisement; discovery observed on one Android 14 Infinix XPad |
| Alpha 0.4 | Released | Bounded read-only inspection by default; opt-in experimental P256_SHA512 UKEY2 and plaintext Nearby CONNECTION_RESPONSE exchange; consent-gated streaming file receiver |
| Alpha 0.5 | Current | Multi-page local interface for the file receiver: home, receive, PIN/consent, progress, result, settings, activity log, and finished result view |
| Future receiver milestone | Not started | Verified peer identity and broader device/file-format coverage |
| Later sender milestone | Not started | Complete verified sender protocol |

The current build can advertise and inspect length-prefixed TCP frames from the CLI. The local
interface runs the same receiver: it advertises as a Quick Share endpoint, requires an explicit
4-digit PIN comparison, requires explicit consent after showing the sanitized file list and total
size, streams received files to disk, and removes partial files on failure. The interface is
loopback-only, token protected, and fully bundled for offline use.

The protocol implementation still does not verify peer identity, and sending remains
unimplemented. Chunked (multi-frame) BYTES payloads and text-only shares are not reassembled into
files.

# ViShare_Quick Build Plan

| Build | Status | Target |
|---|---|---|
| Alpha 0.1 | Foundation | CLI and GitHub workflow |
| Alpha 0.2 | Research validated | Passive Android Quick Share mDNS discovery |
| Alpha 0.3 | Experimental | mDNS advertisement; discovery observed on one Android 14 Infinix XPad |
| Alpha 0.4 | In progress | Bounded read-only inspection by default; opt-in experimental P256_SHA512 UKEY2 and plaintext Nearby CONNECTION_RESPONSE exchange; no encrypted messaging or transfer |
| Future receiver milestone | Not started | Complete verified receiver protocol and save received files |
| Later sender milestone | Not started | Complete verified sender protocol |

The current development build can advertise and inspect length-prefixed TCP frames. An explicit
`--ukey2-handshake` option performs the experimental P256_SHA512 UKEY2 exchange, sends a plaintext
Nearby CONNECTION_RESPONSE ACCEPT, and validates the peer's response. It then closes before the
encrypted SecureMessage layer. It does not perform out-of-band peer authentication, paired-key
verification, sharing negotiation, or file I/O. Unit tests use simulated fixtures; the response
exchange still needs an actual device interoperability run. The XPad discovery and UKEY2 logs do
not demonstrate that Android displays a successful connection or that a file transfer works. Do
not publish or tag Alpha 0.4 until protocol stages and device behavior have been validated.

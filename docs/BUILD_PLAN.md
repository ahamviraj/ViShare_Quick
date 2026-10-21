# ViShare_Quick Build Plan

| Build | Release | Target |
|---|---|---|
| Build 1 | `alpha_0.1` | Foundation, CLI and GitHub workflow |
| Build 2 | `alpha_0.2` | Laptop discovers Android Quick Share devices |
| Build 3 | `alpha_0.3` | Android Quick Share discovers laptop |
| Build 4 | `alpha_0.4` | Receive files and save under `ViShare Quick/download` |
| Build 5 | `alpha_0.5` | Select and send files to Android Quick Share recipient |

This ZIP is a research build for `alpha_0.3`. It advertises a protocol-shaped mDNS endpoint but does
not implement BLE trigger advertising, the UKEY2 handshake, or transfer. Validate actual Android
discovery before publishing the official `alpha_0.3` release.

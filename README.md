# ViShare_Quick

**Package:** `alpha_0.3-dev` (research build)  
**Target:** Windows 11 / Linux · Python 3.10+

This research build adds an experimental Quick Share-style mDNS advertisement for investigating
whether Android Quick Share can discover the laptop. It does not yet implement the BLE trigger,
UKEY2 handshake, or file transfer, so discovery is not guaranteed.

## Commands

```powershell
python -m vishare_quick --version
python -m vishare_quick doctor
python -m vishare_quick mdns-check --seconds 30
python -m vishare_quick advertise --name "ViShare Quick" --seconds 120
```

`advertise` publishes `_FC9F5ED42C8A._tcp.local.` with a visible endpoint-info TXT record and opens
a TCP listener. It logs incoming TCP connections but deliberately does not pretend to implement the
Quick Share handshake. Use only on a trusted local network.

## Install

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Build sequence

- `alpha_0.1`: foundation (published)
- `alpha_0.2`: laptop discovers Android Quick Share devices (research validated; official release pending)
- `alpha_0.3`: Android Quick Share discovers the laptop (this research build)
- `alpha_0.4`: receive and save files under `ViShare Quick/download`
- `alpha_0.5`: send files to an Android Quick Share recipient

Do not tag this development package as a release until the intended milestone is tested on an actual Android Quick Share device.

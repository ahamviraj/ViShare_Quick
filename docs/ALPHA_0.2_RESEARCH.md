# Alpha 0.2 Research / Validation Build

This ZIP is a **development research package**, not the official `alpha_0.2` release.
It adds a passive mDNS browse command so the Windows network environment can be investigated
before any Quick Share endpoint is advertised.

## Current scope

- `vishare doctor`: platform diagnostics
- `vishare mdns-check`: browse for DNS-SD enumeration records for a bounded period
- No Quick Share service advertisement
- No Bluetooth LE advertising
- No file receiving or sending
- No claim that Android Quick Share will discover this computer

## Why this is not yet alpha_0.2

The target acceptance criterion is that an actual Android device running native Quick Share
displays the Windows laptop as a recipient. A generic mDNS browse is only a network diagnostic.
It does not establish protocol compatibility.

## Reference implementations to audit

- Packet: https://github.com/nozwock/packet
- NearDrop protocol notes: https://github.com/grishka/NearDrop/blob/master/PROTOCOL.md
- NearShare: https://github.com/Dhiva-Labs/NearShare

Before reusing code, review the exact repository license and all dependency licenses. NearShare's
Linux-specific BlueZ/D-Bus components cannot be assumed to work on Windows unchanged.

## Windows test environment

The known test setup is:
- Windows 11
- Intel(R) Wireless Bluetooth(R)
- Infinix XPad running Android 14
- Both devices connected to an OPPO A5s 2.4 GHz hotspot
- Laptop IPv4 address: `192.168.43.80`
- Gateway: `192.168.43.1`

## Run the diagnostic

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m vishare_quick doctor
.\.venv\Scripts\python.exe -m vishare_quick mdns-check
```

`mdns-check` waits for eight seconds by default and browses specifically for
`_FC9F5ED42C8A._tcp.local.`. This only detects matching advertisements already visible on the
local network; it does not advertise this laptop as a Quick Share endpoint. Zero results do not
prove mDNS is blocked or that Quick Share is incompatible.

## Next engineering decisions

1. Verify multicast behavior on the hotspot with a known service or packet capture.
2. Determine the exact Quick Share mDNS service record and endpoint metadata required by current Android.
3. Determine whether Windows can advertise the required BLE trigger payload.
4. Implement and test only the verified protocol pieces.


## Service inspection update

The `mdns-check` command attempts to resolve each discovered service's IP addresses, TCP port,
hostname, and TXT records. This is passive inspection only: it does not advertise this laptop,
open a TCP connection, or validate Quick Share protocol compatibility.

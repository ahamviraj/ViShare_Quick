# Alpha 0.3 Research Build

## Scope
- Experimental mDNS advertisement using `_FC9F5ED42C8A._tcp.local.`
- URL-safe Base64 endpoint instance name with a random 4-character endpoint ID
- Visible endpoint-info TXT record (`n`) with a random 16-byte metadata field and device name
- TCP listener that logs accepted connections without claiming protocol compatibility

## Explicit limitations
- No BLE trigger advertisement
- No Quick Share/UKEY2 handshake
- No file transfer
- Native Android discovery may not occur automatically until BLE discovery is implemented.
- The random metadata field is only a protocol-shape experiment, not a verified Google identity/certificate implementation.

## Test
Keep the laptop and XPad on the same trusted hotspot. Open Quick Share on the XPad in **Send mode**
and set visibility to Everyone if available. On the laptop, run:

```powershell
.\.venv\Scripts\python.exe -m vishare_quick advertise --name "ViShare Quick" --seconds 120
```

Observe whether the laptop appears in the XPad's recipient list. Stop with Ctrl+C if needed. If it does not
appear, this is not conclusive evidence that mDNS is wrong: the BLE trigger may be required, and endpoint
metadata may need additional protocol-correct fields. Do not connect to unknown endpoints or use this
experimental listener on public Wi-Fi.

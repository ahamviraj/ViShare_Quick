# ViShare_Quick Build Plan

| Build | Status | Target |
|---|---|---|
| Alpha 0.1 | Foundation | CLI and GitHub workflow |
| Alpha 0.2 | Research validated | Passive Android Quick Share mDNS discovery |
| Alpha 0.3 | Experimental | mDNS advertisement; discovery observed on one Android 14 Infinix XPad |
| Alpha 0.4 | Released | Bounded read-only inspection by default; opt-in experimental P256_SHA512 UKEY2 and plaintext Nearby CONNECTION_RESPONSE exchange; consent-gated streaming file receiver |
| Alpha 0.5 | Released | Multi-page local interface for the file receiver: home, receive, PIN/consent, progress, result, settings, activity log, and finished result view |
| Alpha 0.6 | Released | CLI sender: peer discovery, UKEY2 client role, explicit PIN gate, authenticated 512 KiB streaming, multi-file and chunked transfers, cancel, linger, and fail-closed cleanup |
| Alpha 0.7 | Released | Local Send interface: browser and drag/drop staging, nearby receiver list, PIN gate, per-file progress, cancel, retry, and fail-closed cleanup |
| Alpha 0.8 | Released | Native app window for the local interface, with `--browser` and headless modes plus a browser fallback; per-user Windows installer and Debian/Ubuntu package with searchable menu entries |
| Alpha 0.9 | Released | Windows background mode: tray icon, global `Ctrl+Alt+V` shortcut, close-to-tray, single-instance foregrounding, sign-in autostart, and optional pinning help |
| Beta 0.9.1 | Released | Send-only Windows Nearby Sharing handoff through the system share sheet, with explicit availability and failure reporting |
| Future receiver milestone | Not started | Verified peer identity and broader device/file-format coverage |
| Later sender milestone | Not started | Broader sender hardening |

The current build can advertise and inspect length-prefixed TCP frames from the CLI. The local
interface runs the same receiver and sender: it advertises as a Quick Share endpoint, requires an
explicit 4-digit PIN comparison, requires explicit consent after showing the sanitized file list and
total size, streams received files to disk, and removes partial files on failure. The interface is
loopback-only, token protected, and fully bundled for offline use.

`alpha_0.6` adds the sender as a separate protocol role. `vishare peers` browses the same mDNS
service type without connecting. `vishare send FILE...` performs the UKEY2 client handshake,
offers regular files, requires a local human PIN comparison and the receiver's `RESPONSE ACCEPT`,
then streams authenticated 512 KiB chunks with keep-alives and a final `LAST_CHUNK`. It sends
basenames only, rejects empty files (Android drops the whole offer), rejects symlinks, directories,
special files, and files that change during transfer, and closes on cancel, timeout, rejection, or
disconnect.

`alpha_0.7` exposes the same sender through the local Send page. The browser picker or drag and drop
uploads selected files to a private staging directory, with raw-body streaming, sanitized unique
names, empty-file rejection, a 64-file cap, and the sender's total-size bound. The page lists
discovered receivers, keeps the explicit PIN gate, shows per-file progress, and routes failures to a
retry page. Staged copies and partial uploads are removed on clear, reset, cancel, or shutdown. The
implementation and verification record are in
[docs/ALPHA_0.7_SEND_INTERFACE.md](ALPHA_0.7_SEND_INTERFACE.md).

`alpha_0.8` wraps the loopback interface in a native app window, using Edge WebView2 on Windows
and GTK/WebKitGTK on Linux when available. The window owns the foreground; the HTTP server runs on a
background thread and shuts down when the window closes or **Stop interface** is selected.
`--browser` restores the previous external-browser behavior, `--no-browser` remains headless, and
launch falls back to the browser if no webview backend can start. The Windows installer places the
frozen executable under the current user's local application data, creates a **ViShare Quick** Start
Menu shortcut for Windows Search, and registers an uninstaller. The Linux `deb` package installs the
binary under `/usr/bin`, adds a desktop entry and icon for application-menu search, and uses the
normal package-manager uninstall path. Release builds produce installers and portable executables
for both platforms.

`alpha_0.9` adds the Windows background lifecycle. The window can start hidden, closing it hides it
to the notification area, and a global `Ctrl+Alt+V` shortcut or the tray **Open ViShare Quick** item
brings it back. The tray **Quit ViShare Quick** item and **Stop interface** still shut down
advertising and the local server. A named mutex forwards a second launch to the existing window. The
Windows installer enables sign-in autostart by default and offers to open the app list because
Windows does not permit installers to pin apps to Start or the taskbar. The option is
`vishare ui --background`, and it remains Windows-only; Linux close-to-exit behavior is unchanged.

`beta_0.9.1` adds a send-only handoff from the Send page to the Windows system share sheet. The
staged files are exposed as WinRT storage items, and the user chooses **Nearby Sharing** or another
destination in the Windows UI. The Send page reports whether Nearby Sharing is enabled in Windows
Settings and whether the app window is available, and it fails rather than reporting success if the
share sheet does not open. This is not a Google Quick Share integration: Windows Nearby Sharing uses
a different protocol, the handoff cannot receive files, and cross-network Google Quick Share
discovery is unchanged and still requires LAN visibility.

The protocol implementation still does not verify peer identity, and chunked (multi-frame) BYTES
payloads and text-only shares are not reassembled by the receiver into files.

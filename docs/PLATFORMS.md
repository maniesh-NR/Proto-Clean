# Proto Clean across platforms

Proto Clean ships for **Windows, macOS, Linux and Android**. The account
logic — backend-browser login, free-only server list, config creation and
caching, blocklists, NAT-PMP, fastest-server scoring — is identical
everywhere; only the *network plumbing* is per-OS, behind the
`proto_clean/platforms/` layer (desktop) and the Android services.

## Feature matrix

| Feature | Linux | Windows | macOS | Android |
| --- | :-: | :-: | :-: | :-: |
| Backend-browser login (+ TOTP / CAPTCHA window) | ✅ Playwright Chromium | ✅ Playwright Chromium | ✅ Playwright Chromium | ✅ real WebView (visible, doubles as CAPTCHA fallback) |
| Free-only server list (tier 0, paid excluded) | ✅ | ✅ | ✅ | ✅ |
| Fastest-server auto-connect (Proton Score) | ✅ | ✅ | ✅ | ✅ |
| WireGuard tunnel | ✅ `wg-quick` | ✅ official `wireguard.exe` service | ✅ `wg-quick` (brew) | ✅ `wireguard-go` (GoBackend) |
| **OpenVPN tunnel (TCP/UDP, TUN/TAP)** | ✅ `openvpn` daemon (optional package) | ➖ WireGuard only — clear error at connect | ✅ `openvpn` daemon (optional, brew) | ➖ WireGuard only — choice shown disabled |
| Protocol selection + per-protocol page options | ✅ | ✅ (download side) | ✅ | ✅ (download side; WireGuard tunnel) |
| Advanced: alternative routing / custom DNS / NAT type | ✅ | ✅ | ✅ | ✅ (custom DNS via config edit; leak protection via system lockdown) |
| IPv6 support (v6 through the tunnel) | ✅ config keeps `::/0` / `route-ipv6 ::/0` | ✅ (WireGuard) | ✅ | ✅ (config edit, GoBackend) |
| IPv6 leak protection (block v6 outside the tunnel) | ✅ ip6tables `PROTO_CLEAN_V6` chain | ✅ `ProtoCleanV6` firewall group (physical adapters) | ✅ `proto_clean.v6` pf anchor | ⚠️ system "Block connections without VPN" lockdown |
| Allow LAN while the kill switch is on | ✅ KS allow-list | ✅ KS allow-list | ✅ KS allow-list | ✅ LAN ranges carved out of AllowedIPs |
| Local config cache, re-download only on failure | ✅ | ✅ | ✅ | ✅ (WireGuard configs) |
| Ad/malware blocking (local blocklists) | ✅ in-path (iptables redirect :53 → :5353) | ✅ in-path (config DNS = `127.0.0.1`, blocker binds :53) | ✅ in-path (root relay :53 → :5353 + `networksetup`) | ⚠️ **standalone mode** (DNS-filter VPN; see below) |
| Blocklist manager (add / remove / enable / update) | ✅ | ✅ | ✅ | ✅ |
| Split tunneling — apps | ✅ cgroup v2 + fwmark policy routing | ➖ needs a kernel driver; **IP ranges** instead | ➖ not available to user space; **IP ranges** instead | ✅ native (`excludedApplications`) |
| Split tunneling — IP ranges | ✅ AllowedIPs subtraction | ✅ AllowedIPs subtraction | ✅ AllowedIPs subtraction | ✅ (via app exclusion + full-tunnel routes) |
| Kill switch | ✅ iptables/ip6tables OUTPUT | ✅ per-physical-adapter firewall blocks (endpoint + LAN carved out) | ✅ pf anchor (auto-added/restored in `pf.conf`) | ✅ full-route tunnel (0.0.0.0/0 + ::/0); system lockdown detected |
| NAT-PMP port forwarding (paid) | ✅ | ✅ | ✅ | ✅ |
| VPN Accelerator / Moderate NAT (page toggles) | ✅ | ✅ | ✅ | ✅ |
| Credential storage | ✅ keyring / chmod-600 file | ✅ keyring / DPAPI-backed file | ✅ keyring | ✅ EncryptedSharedPreferences |
| Privilege mechanism | sudo helper + NOPASSWD sudoers | in-process when elevated, else **one UAC prompt per connect** | sudo helper + NOPASSWD sudoers | none needed (VpnService consent) |

✅ full · ⚠️ with a documented caveat · ➖ not possible for user space on that OS

### Why Android's ad-block is a separate mode

The desktop apps intercept DNS *in-path* with OS firewall rules (Linux
iptables, macOS pf, Windows "config DNS = 127.0.0.1"). Android offers no
packet hook to user space, and the WireGuard tunnel library (GoBackend)
hands the tun fd straight to wireguard-go — so nothing can sit between the
system resolver and the tunnel while it is up. Android also allows **one
VpnService per app**. Proto Clean therefore ships a second, DNS-only
VpnService (`DnsFilterVpnService`, the personalDNSfilter/Intra design): a
virtual address that is also the DNS server, a /32 route so *only* DNS
enters the tun, blocklist verdicts answered locally, everything else
forwarded over DoH (`https://1.1.1.1/dns-query`, IP-pinned). The Blocklists
tab toggles it; connecting the VPN switches it off automatically (and
vice-versa). While the tunnel is up, DNS uses Proton's in-tunnel resolver
(`10.2.0.1`).

---

## Linux

```bash
bash scripts/install.sh          # deps + helper + sudoers + desktop entry
python3 -m proto_clean             # GUI
```

Requirements: cgroup v2 (for app split tunneling), `wg`/`wg-quick`,
`iptables`, `ip`. Everything else is in `requirements.txt`.

**OpenVPN protocol** (optional): `sudo apt install openvpn` — the helper
`ovpn-up tun|tap` runs `openvpn --config /etc/openvpn/proto-clean/proto-clean.ovpn
--dev proto_clean0 --dev-type <driver> --daemon --writepid
/var/run/protoclean-openvpn.pid --log-append /var/log/protoclean-openvpn.log`;
status reads the pidfile + `/sys/class/net/proto_clean0` counters; the kill
switch allows the endpoint over TCP or UDP as the config says; the
`PROTO_CLEAN_V6` ip6tables chain provides IPv6 leak protection.

Paths: `~/.config/proto-clean`, `~/.cache/proto-clean`, `~/.local/state/proto-clean`.

## macOS

```bash
brew install wireguard-tools
bash scripts/install_macos.sh    # deps + helper + sudoers + ~/Applications/Proto Clean.app
open ~/Applications/Proto Clean.app
```

How the plumbing differs from Linux (all inside `helper/proto-clean-helper`,
same verbs):

* **Kill switch — pf.** `ks-on` writes an anchor
  (`pass out quick` for lo0, the tunnel's utun, the OpenVPN interface, the
  VPN endpoint over **its own transport** (UDP or TCP, as the config says)
  and optionally LAN, then `block drop out quick all`) and inserts a
  marker-guarded `anchor "proto-clean"` + `anchor "proto_clean.v6"` pair into
  `/etc/pf.conf` (original backed up to `pf.conf.proto-clean-bak`, fully
  reverted on `ks-off`). pf is enabled only if it was off (recorded, and
  reverted on teardown).
* **IPv6 leak protection — pf.** `v6-on` loads a second anchor,
  `proto_clean.v6` (`pass out quick on lo0 inet6`, `pass out quick on
proto_clean0 inet6`, then `block drop out quick inet6`); `v6-off` flushes
  it. For tunneled IPv6 combine IPv6 support with the kill switch.
* **Tunnel interface.** wg-quick maps the tunnel name to a dynamic `utunN`;
  the helper finds ours by matching the installed config's peer public key
  against `wg show all dump`.
* **DNS.** The helper forks a root relay that binds `127.0.0.1:53`, drops
  to your uid, and forwards to the in-app blocker on `:5353`
  (macOS reserves ports < 1024 for root). It then points the primary
  network service's DNS at `127.0.0.1` via `networksetup -setdnsservers`
  (restored to *Empty* on `dns-off`). Upstream is still Proton DoH / in-tunnel
  UDP from the app.
* **Split tunneling.** Per-app routing is not available to user space on
  macOS — the Settings tab shows this and offers IP-range exclusions
  (removed from AllowedIPs, so those destinations keep the original route).
* **OpenVPN protocol** (optional): `brew install openvpn` — the same
  `ovpn-*` verbs as Linux drive the brew binary with the TUN/TAP driver
  from Settings → Advanced.

Paths: `~/Library/Application Support/Proto Clean`, `~/Library/Caches/Proto Clean`.

## Windows

Requirements: [WireGuard for Windows](https://download.wireguard.com/windows/)
(`wireguard.exe` + `wg.exe` — in `C:\Program Files\WireGuard` or on PATH),
Python ≥ 3.10 for the from-source run.

```powershell
pip install -r requirements.txt
python -m playwright install chromium
python -m proto_clean                  # GUI (run as Administrator to skip UAC)
```

* **Privileges.** No sudo on Windows: the verbs live in
  `proto_clean/helper_win.py`. When the app is elevated they run in-process;
  otherwise each **batch** is executed through a single UAC prompt
  (`ShellExecuteW("runas")`, results via a temp JSON file) — a whole
  connect is one batch, so you see one prompt, not six.
* **Tunnel.** `wireguard.exe /installtunnelservice <conf>` /
  `/uninstalltunnelservice proto-clean`; status from `wg.exe show proto-clean
  dump`. The handshake wait runs inside the elevated helper
  (`wait-handshake`) so polling does not spam UAC; a non-elevated app
  shows the freshest status any elevated verb reported. **OpenVPN is not
  supported on Windows** (no bundled OpenVPN driver): the `ovpn-*` verbs
  validate but return a clear "not supported" error, and the Protocol tab
  explains it — keep WireGuard selected.
* **IPv6 leak protection.** `v6-on` adds outbound IPv6 BLOCK rules for
  `::/0` on every *physical* adapter (group `ProtoCleanV6`, removed by
  `v6-off`); the WireGuard tunnel adapter is virtual and untouched, so
  IPv6 inside the tunnel still flows.
* **Kill switch.** Windows Firewall block rules beat allow rules, so each
  per-physical-adapter BLOCK rule carries a remote-address list of
  "everything except the endpoint (+LAN if chosen)" — computed by CIDR
  subtraction from `0.0.0.0/0` and `::/0`. The WireGuard adapter is
  virtual, never enumerated as physical, so tunneled traffic is untouched.
  All rules live in the removable group `ProtoCleanKS`.
* **DNS.** No firewall rule needed: Windows lets any user bind port 53, so
  the embedded blocker binds `127.0.0.1:53` and the config's DNS line is
  rewritten to `127.0.0.1` before install (only on the installed copy —
  the cached file keeps Proton's original bytes).
* **Split tunneling.** App-based routing needs a WFP kernel driver
  (out of scope); IP-range exclusions work via AllowedIPs subtraction.

Paths: `%APPDATA%\proto-clean` (config), `%LOCALAPPDATA%\proto-clean` (cache,
state), `%ProgramData%\Proto Clean` (staged tunnel config).

## Android

Source tree: [`android/`](../android/) — Kotlin + Jetpack Compose, built on
the official `com.wireguard.android:tunnel` (GoBackend) library. See
[`android/README.md`](../android/README.md) for build instructions.

Highlights and how they map to the desktop:

* **Login** — a real, visible WebView on `account.protonvpn.com`; stored
  credentials (EncryptedSharedPreferences) are auto-filled by the same
  two-step script (`#username` → Continue → `#password` → Sign in), the
  optional TOTP secret answers 2FA, and CAPTCHA is completed by hand in
  the same window. The session cookie jar is persisted and restored.
* **Servers / config** — the same in-page automation against the downloads
  page (logicals fetch with the page's session, platform radio
  `#wg-platform-Android`, `#feature-PortForwarding` / `#feature-SplitTCP`
  toggles, "Free server configs" category, server search, Create click,
  reading the resulting certificate textarea). Configs are cached per
  server and re-downloaded **only when the saved one fails** — the
  handshake check uses GoBackend's statistics.
* **Split tunneling** — native: excluded package names go into
  `Config.excludedApplications` → `VpnService.addDisallowedApplication`.
* **Kill switch** — the tunnel is always full-route (0.0.0.0/0 + ::/0,
  single peer), which Android blocks from bypassing; GoBackend's
  `isLockdownEnabled` tells you if the system "Block connections without
  VPN" is armed.
* **Port forwarding** — the same RFC 6886 NAT-PMP client in Kotlin
  (10.2.0.1:5351, 60 s lease, refreshed at ~45 s).
* **Ad-blocker** — `DnsFilterVpnService` as described above, fed by the
  same blocklist manager (presets, add/remove/update, suffix matching,
  NXDOMAIN/0.0.0.0 answers).

---

## Packaging / builds

| Platform | Command | Output |
| --- | --- | --- |
| Windows | `pyinstaller packaging/windows/proto-clean.spec` (or `packaging/windows/build.ps1`) | `dist\ProtoClean.exe` |
| macOS | `bash packaging/macos/build.sh` | `dist/Proto Clean.app` (ad-hoc signed) |
| Linux | `bash packaging/linux/build.sh` | `dist/proto-clean/` (+ optional AppImage) |
| Android | `cd android && ./gradlew assembleDebug` | `app/build/outputs/apk/debug/app-debug.apk` |

Notes:

* Desktop bundles do **not** embed the Playwright Chromium; it is installed
  per-user on first run (or pre-seed with `python -m playwright install
  chromium`).
* On frozen Windows builds the exe re-executes itself with
  `--protoclean-helper-win` to run the privileged verbs through UAC — the
  dispatch lives in `proto_clean/__main__.py`.

## Testing

```bash
python -m pytest tests/ -q     # 90 tests: platforms, wgconf CIDR math,
                               # Windows helper validation (runs anywhere),
                               # controller flow, config cache, blocklists,
                               # DNS server (live), NAT-PMP, TOTP, selectors
```
## Link bonding per platform

* **Linux / Windows / macOS**: pure userspace — adapter-bound sockets
  need no privileges. Interface discovery uses `ip -j` / PowerShell
  `Get-NetIPAddress` / `ifconfig`; manual names or IPs always work.
* **Android**: the bonding VPN (one VPN at a time — Android's rule, same
  as net-merge) uses Wi-Fi + mobile data simultaneously without root;
  member sockets are `VpnService.protect`ed and bound to their
  `Network`. The upstream selector can instead route the tun through
  the bundled lantern-box samizdat engine.
* The bond server runs anywhere Python does — including on the Android
  phone itself via Termux if you want to bond a phone's links for
  another device.


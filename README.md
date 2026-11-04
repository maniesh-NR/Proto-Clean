# Proto Clean

<p align="center">
  <img src="docs/logo.png" width="128" alt="Proto Clean logo">
</p>

A clean-room client for **ProtonVPN** — **Linux, Windows, macOS and
Android** — built around your own Proton account:

- **Backend-browser login with saved credentials** — Proto Clean drives a
  bundled Chromium (Playwright) to log into `account.protonvpn.com`.
  Save your credentials once (**Log in… → Remember me**) and every launch
  — and every session expiry mid-connect — logs in automatically.
  Credentials live in your system keyring (or a chmod-600 file), together
  with an optional TOTP secret that answers 2FA prompts by itself.
- **CAPTCHA relayed to you** — when Proton challenges the automatic login
  with a CAPTCHA / human verification, a **browser window opens on exactly
  that step**, and Proto Clean tells you what's going on: a banner in the
  main window, a status-bar message and a desktop notification. Finish the
  verification in the window and login continues by itself — no restart,
  no re-typing (credentials are pre-filled in the window). You can also
  start a login *in the browser* on purpose (Login dialog → “Log in in
  browser…”).
- **Server list with live loads — free servers only** — after login it
  scrapes the Downloads page and shows every **free** server with its
  current load and features. Paid (Plus/Secure Core) servers are excluded
  from the list and from selection, exactly like the page's own
  "Free server configs" category.
- **Fastest server, one toggle** — the toggle at the top auto-connects to
  the fastest available free server using Proton's own live server score.
- **Protocol choice: WireGuard or OpenVPN** — Settings → Protocol picks
  which config Proto Clean downloads from the Proton page. **WireGuard**
  (default) shows the NAT-PMP (Port Forwarding) and VPN Accelerator
  toggles, both on by default. **OpenVPN** adds a TCP/UDP transport
  choice, and the network driver is selectable in Advanced: **TUN**
  (routes traffic between networks — faster, more stable) or **TAP**
  (bridges network traffic — slower, needed for some legacy setups).
  Both protocols are cached, tunneled and kill-switched identically on
  Linux/macOS; Windows/Android tunnel WireGuard only (see Known limits).
- **Advanced settings (Proton-style)** — Alternative routing (mirror API
  hosts when the direct ones are blocked), Allow LAN connections, Custom
  DNS servers (your resolvers instead of Proton's, via the embedded DNS
  blocker), NAT type (Moderate NAT), and IPv6 controls: **IPv6 support**
  routes `::/0` through the tunnel for better v6-site compatibility,
  **IPv6 leak protection** (on by default) blocks any IPv6 that would
  bypass the tunnel — independently of the kill switch.
- **WireGuard, seamlessly — with local config caching** — configs are
  downloaded once and cached per server (per protocol!); later connects
  reuse the saved config without touching the browser. A cached config is
  re-downloaded **only when it fails** (tunnel won't come up or the handshake
  never completes, e.g. the certificate was revoked). Existing configs on
  your account page — WireGuard and OpenVPN sections alike — are harvested
  automatically to warm the cache.
- **Local NetShield (ad/malware blocking)** — an in-process DNS server
  filters every DNS query against locally-maintained blocklists. The
  **Blocklists ▾ menu** (and the full manager dialog) lets you add, remove,
  enable/disable and update lists — StevenBlack by default, with HaGeZi,
  OISD, 1Hosts and Peter Lowe as one-click presets. No Proton DNS feature
  needed — works on the free plan.
- **Split tunneling** — excluded **IP ranges** work on every platform
  (they are carved out of the tunnel's AllowedIPs); excluded **apps** run
  outside the tunnel via cgroup-v2 fwmark routing on Linux and via
  Android's native VpnService app exclusion.
- **Kill switch** — Linux: nftables/iptables; Windows: per-physical-adapter
  firewall blocks with the endpoint carved out; macOS: pf; Android:
  full-route tunnel (+ system lockdown detection). Traffic outside the
  tunnel is blocked while connected on every platform. The endpoint rule
  follows the protocol's transport (UDP for WireGuard, TCP *or* UDP for
  OpenVPN).
- **Port forwarding** — ticks the NAT-PMP option on the download page and
  keeps the mapping alive (gateway `10.2.0.1`, ~60 s lease, refreshed at
  45 s) once connected. *(paid plans only — Proton's restriction)*
- **VPN Accelerator** — toggled on the download page in the backend
  browser exactly as you set it. *(the only VPN option available on the
  free plan)*
- **Dark, light and system themes** — the **Theme ▾** menu in the bottom
  bar (or Settings → Appearance) switches between **Dark mode** (the
  original look), **Light mode** (bright surfaces, same violet accent)
  and **System theme**, which follows the desktop color scheme and
  live-switches when the system flips between light and dark. The choice
  is remembered across launches (legacy `prefer_dark_theme` settings
  migrate automatically).
- **Link bonding — all your adapters as one pipe** — traffic to the
  same server is split across two or more network adapters (Wi-Fi +
  Ethernet + tethering) and **rejoined at your bond server**, so one
  download uses the combined bandwidth of every link (Speedify-style
  channel bonding, userspace). *Per-connection balancing* spreads many
  connections across adapters net-merge-style. On Android the bonding
  VPN uses **Wi-Fi + mobile data simultaneously, no root**. Works with
  the other engines: Xray and samizdat *ride the bond* automatically
  (Settings → Link bonding).

Per-OS plumbing, packaging and limitations: **[docs/PLATFORMS.md](docs/PLATFORMS.md)**
(Android app: **[android/README.md](android/README.md)**).

Proto Clean is an independent client. It is not affiliated with or endorsed
by Proton AG. Automating the account web app is a convenience for *your
own account*; if Proton changes their UI, the scrapers may need updating
(they log debug screenshots to `~/.cache/proto-clean/screenshots` when a
step fails). Check Proton's terms of service before relying on it.

---

## Requirements (desktop)

- Linux: `wg`, `wg-quick` (wireguard-tools), `ip`, `iptables`, cgroup v2
  (only for app-based split tunneling) — any modern distro works.
  Optional: `openvpn` for the OpenVPN protocol (`sudo apt install openvpn`),
  `xray` (Xray-core) for the v2ray proxy feature and `lantern-box` for
  samizdat.
- macOS: `brew install wireguard-tools` (`pfctl`/`networksetup` are built
  in). Optional: `brew install openvpn`, `brew install xray`.
- Windows 7+ (use the `-win7-` legacy builds) / Windows 10+ (modern
  builds): [WireGuard for Windows](https://download.wireguard.com/windows/)
  (`wireguard.exe` + `wg.exe`) — WireGuard protocol only. Optional:
  Xray-core for the proxy feature.
- Python ≥ 3.8 from source (the packaged builds bundle their own Python)
- A Proton account (free plan works: free servers, VPN Accelerator and
  local ad-blocking; port forwarding / NetShield / Moderate NAT need paid)
- An Xray (v2ray) server of your own for the proxy feature — see below

## Install

**Linux**

```bash
cd proto-clean
bash scripts/install.sh
```

**macOS**

```bash
brew install wireguard-tools
bash scripts/install_macos.sh
```

**Windows** (from source)

```powershell
pip install -r requirements.txt
python -m playwright install chromium
python -m proto_clean
```

**Android** — build the APK from [`android/`](android/) with
`./gradlew assembleDebug` (details in the Android README).

The Linux/macOS installers:

1. installs Python dependencies (+ Chromium for Playwright, ~170 MB, once)
2. installs the privileged helper to `/usr/local/bin/proto-clean-helper`
3. adds a **sudoers entry limited to that single binary** — no blanket
   sudo: `youruser ALL=(root) NOPASSWD: /usr/local/bin/proto-clean-helper`

Uninstall with `bash scripts/uninstall.sh`.

On **Windows** there is no sudo: when the app is elevated the privileged
verbs run in-process; otherwise each connect shows **one UAC prompt**
(the whole sequence is a single elevated batch).

## Run

```bash
python3 -m proto_clean            # GUI
python3 -m proto_clean --cli      # headless environment check
python3 -m proto_clean -v         # debug logging
```

First launch: the **login dialog** opens by itself. Enter your Proton
username and password, keep **Remember me** checked (default) and Proto Clean
auto-logs-in from then on — at launch and whenever the session expires.
Optionally store your **TOTP secret** so two-factor prompts are answered
automatically; if Proton shows a CAPTCHA, finish it in the window that
opens and login continues. Prefer typing in a real browser? Use **Log in
in browser…**.

### Daily use

- The **Fastest server** toggle at the top connects to the best free
  server by Proton's live score; click any row to pick a server instead.
  Only free servers are listed — paid servers are excluded everywhere.
- **Blocklists ▾** (bottom bar) manages the ad-blocking lists: update all,
  enable/disable each list, add (with presets), remove, and a full
  manager dialog with domain counts and update times. Changes hot-swap
  into the running DNS blocker — no reconnect needed.
- **Theme ▾** (bottom bar) switches Dark / Light / System instantly —
  no restart; System keeps following the desktop scheme.
- The tray icon gives you connect/disconnect/quit; closing the window
  keeps Proto Clean in the tray.
- While connected you get live stats (handshake age, up/down bytes,
  endpoint) and, on paid plans, the forwarded external port.
- Configs are cached in `~/.cache/proto-clean/configs/`; connect twice to
  the same server and the second attempt skips the download entirely.

## How each feature works

| Feature | Mechanism |
| --- | --- |
| Login | Playwright Chromium; two-step form (`#username` → Continue → `#password`); storage-state cached in `~/.config/proto-clean/browser-state.json`; login dialog with **Remember me** (keyring / chmod-600 file + optional TOTP secret); CAPTCHA/2FA → visible window for that step only, relayed to you via banner + notification |
| Server list (free only) | the logged-in page's own logicals XHR (Load/Score/Tier/Features), filtered to Tier 0 → fallback: same-origin fetch by the page (with **alternative routing**: mirror hosts `api.protonvpn.com` / `vpn-api.proton.me`) → fallback: scrape of the rendered "Free server configs" country tables (`#section-wireguard-configuration`, 121 free servers verified against the real page) |
| Fastest | min `Score` among online free-tier logicals (Proton's own metric); local load-based heuristic if Score is missing; saturated (>90%) servers deprioritised |
| Protocol | Settings → Protocol: WireGuard (default) or OpenVPN. **WireGuard**: NAT-PMP (Port Forwarding) + VPN Accelerator toggles (both on by default) — set on the page via `#feature-PortForwarding` / `#feature-SplitTCP`. **OpenVPN**: the page section `#section-openvpn-configuration` with layered selector candidates, TCP or UDP transport radios, same Linux platform / free-category / exact-row Create flow; the TUN/TAP driver is a *local* choice applied at `ovpn-up` |
| Config | Platform=GNU/Linux radio, option toggles by id, "Free server configs" category, exact-match server row → Create → capture (XHR body, the new certificate's textarea, or the Download file); WireGuard configs look like `[Interface]`+`PrivateKey`, OpenVPN captures require a `remote` line |
| Config cache | per-server cache in `~/.cache/proto-clean/configs/` keyed by server + protocol + transport + option fingerprint (`wg-acc1-nat0`, `ovpn-tcp-acc1-nat1`, …) — a lookup never crosses protocols; connect flow: cached config → tunnel up → **handshake verified**; on failure the entry is invalidated and the config re-downloaded once; existing certificates (both sections) are harvested from the page to warm the cache |
| Tunnel (WireGuard) | captured config validated (hooks like `PostUp` are refused) → staged (`/etc/wireguard/proto_clean.conf`, 0600) → `wg-quick up` (Linux/macOS) or `wireguard.exe /installtunnelservice` (Windows) — all through the same verb whitelist |
| Tunnel (OpenVPN) | `.ovpn` validated (must have `remote`; `up`/`down`/`script-security` shell hooks refused — same stance as WireGuard's PostUp) → staged to `/etc/openvpn/proto-clean/proto-clean.ovpn` (0600, dir 0700) → helper `ovpn-up tun|tap` runs `openvpn --config … --dev proto_clean0 --dev-type <driver> --daemon --writepid` → status via pidfile + interface counters (reports a live "handshake" to the app's liveness check); `ovpn-down` SIGTERMs the pid |
| Advanced: custom DNS | the embedded DNS blocker answers system-wide and forwards to your servers (ordered fallback) — works identically over WireGuard and OpenVPN; when ad blocking is off it runs with an empty filter |
| Advanced: IPv6 | **support on**: WireGuard config keeps `::/0` (OpenVPN gets `route-ipv6 ::/0` + `tun-ipv6` for TUN); **support off**: IPv6 is stripped from the config so it never enters the tunnel. **Leak protection on** (default): `v6-on` verb adds an ip6tables chain (macOS: `proto_clean.v6` pf anchor; Windows: `ProtoCleanV6` firewall group) blocking IPv6 except loopback, both tunnel interfaces and the split-tunnel mark — independent of the kill switch, armed before tunnel-up |
| Ad blocking | DNS server (dnslib) on loopback — port 5353 on Linux/macOS, port 53 on Windows; port-53 traffic is redirected there (Linux: iptables REDIRECT; macOS: root relay + `networksetup`; Windows: the config's DNS is rewritten to `127.0.0.1`); upstream = DoH to Proton's `doh.protonvpn.ch` through the tunnel, plain-UDP `10.2.0.1` (or your custom DNS servers) as fallback; blocked names → NXDOMAIN or `0.0.0.0` |
| Blocklist management | per-list cache files (`~/.cache/proto-clean/blocklists/<slug>.txt` + metadata); add / remove / enable / update-one / update-all; enabled lists merged into `merged.json` → hot-swapped into the live DNS filter (answer cache flushed) |
| Split tunnel | **IP ranges (all desktop OSes):** the CIDRs are subtracted from the tunnel's AllowedIPs, so they keep the original route. **Apps (Linux):** excluded apps live in the root-level cgroup `proto_clean_split`; an iptables mangle rule fwmarks their packets (mark 42); `ip rule fwmark 42 → table 51821` routes them via your original gateway. **Apps (Android):** native `excludedApplications` |
| Kill switch | Linux: iptables/ip6tables OUTPUT chain (allow lo + both tunnel interfaces + the endpoint over **its own transport, udp or tcp** (+LAN) + fwmark 42, drop the rest); Windows: per-physical-adapter block rules with the endpoint (+LAN) carved out by CIDR subtraction (group `ProtoCleanKS`); macOS: pf anchor with the same allow list, auto-added and reverted in `/etc/pf.conf`; Android: full-route tunnel + lockdown detection |
| Port forwarding | NAT-PMP MAP-UDP (RFC 6886) to `10.2.0.1:5351`, lease kept alive at ~75 %; on free plans Proton answers "not authorized" and the UI reports it |
| 2FA | stored TOTP secret → RFC 6238 code generated locally (no network); otherwise a dialog asks for the code |
| Theme | `ui/theme.py` ships two full stylesheets (`DARK_QSS`, `LIGHT_QSS`) + matching `QPalette`s; `apply_theme(app, mode)` resolves `system` via Qt's `colorScheme` hint (Qt ≥ 6.5), the GNOME `color-scheme` gsettings key, or palette lightness; in system mode `colorSchemeChanged` re-applies live. Persisted as `settings.theme`; legacy `prefer_dark_theme: false` migrates to `light`. Runtime painters ask `theme.is_dark()` (load-bar tracks, icons) |
| Login events | the backend browser relays `captcha` / `interactive_open` / `interactive_done` / `totp_needed` / `bad_credentials` / `credentials_needed` through the controller → bridge → banner + tray notification; wrong or missing credentials re-open the login dialog pre-filled |

## Xray / v2ray proxy (VLESS REALITY + Trojan)

Besides WireGuard/OpenVPN tunnels, Proto Clean can run an
[Xray-core](https://github.com/XTLS/Xray-core) proxy locally and route
apps through it — useful on networks where VPN protocols are blocked:

- **VLESS + REALITY with SNI masking** — the connection is disguised as
  ordinary HTTPS to a decoy site you choose (the *masked SNI*), complete
  with a uTLS browser fingerprint (`chrome`, `firefox`, …). Deep packet
  inspection sees a normal TLS handshake to that site, not a proxy.
- **Trojan** — the classic password-authenticated TLS proxy protocol,
  also with configurable SNI.

How to use it:

1. Install the Xray-core binary (not bundled) and put `xray` on `PATH`
   (or point `PROTO_CLEAN_XRAY_BIN` at it):
   ```bash
   # Linux (deb/rpm releases at github.com/XTLS/Xray-core/releases)
   sudo install -m755 xray /usr/local/bin/xray
   # macOS
   brew install xray
   # Windows: unzip the release next to ProtoClean.exe or anywhere on PATH
   ```
2. Open **Settings → Xray proxy** and paste your share URL with
   **Import share URL…** —
   `vless://<uuid>@host:443?security=reality&sni=…&pbk=…&sid=…&fp=chrome`
   or `trojan://<password>@host:8443?sni=…`, or fill the fields by hand.
3. Pick a mode: **automatic** (the system proxy is switched to the local
   inbounds while the proxy runs and restored on stop) or **manual**
   ( SOCKS `127.0.0.1:10808` / HTTP `127.0.0.1:10809` for you to point
   apps at).
4. Start/stop from the settings tab or the tray's **Xray proxy** item.

Platform notes: the system-proxy switch uses per-user `gsettings` on
Linux (GNOME/Cinnamon/MATE — what Linux Mint ships), the WinINET registry
on Windows (no elevation) and `networksetup` through the privileged
helper on macOS. The generated Xray config (which contains your
credentials) is stored `chmod 600` in `~/.cache/proto-clean/xray/` and
never leaves the machine. The proxy is independent of the WireGuard/
OpenVPN Connect button — you can run either, or both.

## Samizdat (Lantern) — proxy through DPI that blocks everything else

[Samizdat](https://github.com/getlantern/samizdat) is the Lantern
project's censorship-resistance protocol, built for nation-state DPI
(Russian TSPU-class): it makes proxy traffic look like **a browser
visiting a real website over HTTP/2** — a single TLS 1.3 layer with a
uTLS Chrome fingerprint (no TLS-over-TLS), HTTP/2 CONNECT tunnels
multiplexed on one connection, PSK authentication hidden in the TLS
SessionID, Geneva-style ClientHello fragmentation, padding and timing
jitter. When an active probe connects without valid auth, the server
transparently forwards to the real *cover site*, so it is
indistinguishable from the genuine domain.

How to use it in Proto Clean:

1. Install **[lantern-box](https://github.com/getlantern/lantern-box)**
   (Lantern's sing-box fork — the binary that implements samizdat; not
   bundled) and put it on `PATH` or set `PROTO_CLEAN_BOX_BIN`.
2. **Settings → Proxy → engine "Samizdat (Lantern)"**, then fill the
   profile from your server operator (or **Import samizdat:// URL** with
   `samizdat://server:443?pbk=<64-hex>&sid=<16-hex>&sni=ok.ru`).
3. Start — a local **mixed inbound** (SOCKS5 + HTTP on one port,
   default 127.0.0.1:10810) comes up, and (in system mode) the OS proxy
   is switched to it while it runs, exactly like the Xray engine.

### Interop with the rest of Proto Clean

* **Reaching Proton when it is censored** — Settings → Proxy →
  *Reaching Proton & blocklists* offers **through the running proxy**
  (auto: rides the Xray/samizdat inbounds) or **custom** (any local
  proxy, e.g. Lantern itself: run
  `lantern-headless-client start --http-proxy-addr 127.0.0.1:8787
  --socks-proxy-addr 127.0.0.1:8788` and point Proto Clean at
  127.0.0.1:8787). The backend-browser login, config downloads and
  blocklist updates all flow through it.
* **Fallback fetching, Lantern-style** — blocklist downloads that fail
  directly are retried through the configured proxy, so your ad-blocker
  keeps updating on censored networks.
* Both engines share the tray toggle, system-proxy switching
  (gsettings / WinINET / networksetup) and the local-only, `chmod 600`
  config storage.

**Licensing:** Proto Clean is **GPL-3.0-or-later**. Lantern,
samizdat and lantern-box are **GPL-3 projects by the Lantern team** —
because the licenses are now compatible, the official releases **bundle
lantern-box binaries built from the Lantern source at release time**
(the `lantern-box` you get ships inside every package; set
`PROTO_CLEAN_BOX_BIN` to use your own). The Python code drives the
binary through its *documented* client config format — no Lantern
source is copied into this repository's codebase — and your profile
credentials never leave your machine.

## Protocols — 25+ engines, one app

The Protocols manager (Settings → Protocols, or the tray menu) runs every
protocol below behind one lifecycle, one SOCKS5 front-end and one
system-proxy switch. Import from the **clipboard**, **QR on screen**,
**QR images**, **config files** or **subscription URLs**; share any saved
profile as a QR code.

| Protocol | Engine | Chainable | Notes |
| --- | --- | --- | --- |
| Shadowsocks (AEAD + 2022) | built-in Python | yes | aes-gcm / chacha20-poly1305, SIP002 links, plugins via lantern-box |
| ShadowsocksR | lantern-box | yes | SSR links + Clash import |
| VMess (V2ray / V2fly) | lantern-box | yes | ws / grpc / h2 transports, uTLS fingerprints, vmess:// links |
| VLESS + REALITY / Trojan | Xray-core | yes | SNI masking (see the Xray section) |
| Hysteria 2 | built-in (aioquic) | yes | official wire protocol, salamander obfs, port hopping |
| TUIC v5 | built-in (aioquic) | via lantern-box | token auth via lantern-box; built-in engine for wire testing |
| MASQUE (RFC 9298) | built-in (aioquic) | yes | CONNECT-UDP over HTTP/3 |
| NaïveProxy | lantern-box / naive | via lantern-box | Chromium-padding proxy |
| OpenVPN over Cloak | ck-client + openvpn | no | TLS-masked OpenVPN composite |
| AmneziaWG 1.5 / 2.0 | lantern-box endpoint | first hop only | junk packets + magic headers; vpn:// Amnezia links |
| WireGuard | built-in (Proton) | first hop only | Proton configs + WG conf import |
| IKEv2 | system (strongSwan / rasdial / Apple) | first hop only | EAP / PSK |
| Tor | tor binary | yes | bridges (obfs4 / snowflake / webtunnel), NEWNYM, Tor-over-Xray |
| Obscura relays | Obscura API + WG | first hop only | relay → exit multihop |
| Lantern samizdat | lantern-box | yes | DPI-resistant HTTP/2 (see the samizdat section) |
| Lantern radiance / lampshade | lantern-box probe | yes | via capability-probed outbounds |
| Reflex / WATER / Outline / ALGeneva | lantern-box | yes | censorship-evasion add-ons |
| Cloudflare WARP | lantern-box (WG) | both ends | oblivion/warp-plus registration |
| Clash configs | converted on import | per proxy | YAML proxies → concrete profiles |
| V2ray / V2fly / sing-box JSON | converted or raw | per proxy | raw sing-box passthrough keeps everything verbatim |
| Chains | ChainEngine | — | any combination, e.g. WARP → VMess → Tor |

### Cloudflare WARP hops (oblivion-style)

WARP registers a device with Cloudflare (the same API the
[bepass-org/oblivion](https://github.com/bepass-org/oblivion) client
uses) and runs the WireGuard tunnel through lantern-box. In the
Protocols manager select a profile → **Chain…**:

* **WARP → profile** — the protocol server is reached *through* WARP
  (your IP towards the server is a Cloudflare IP).
* **profile → WARP** — you reach the server, the internet sees a
  Cloudflare IP as the exit.

### Multiprotocol chains

**Chain… → Custom chain** composes any engines in order
(`client → hop1 → hop2 → internet`); each hop dials through the previous
hop's local SOCKS. QUIC engines tunnel through SOCKS5 UDP relays, Xray
uses `dialerProxy`, lantern-box uses outbound `detour`. Full-tunnel
engines (WireGuard family, IKEv2) must be the first — and only — hop.

## Link bonding — two or more adapters as one connection

Speedify's headline feature, in userspace and with **your own server**.
Each bonded TCP stream is split into sequenced chunks; one *member*
connection per selected adapter carries the chunks (every socket bound
to its adapter's address); the bond server reorders and rejoins them.
Responses are split the same way in reverse — one download can use the
combined bandwidth of Wi-Fi + Ethernet + a phone tether.

1. **Run the bond server** on any reachable host (a VPS, a home box):

   ```bash
   pip install proto-clean        # or clone the repo
   python3 -m proto_clean.bondserver --listen 0.0.0.0:10820 --token s3cret
   ```

2. **Settings → Link bonding** in the app: enter the server, pick the
   adapters (they are detected; manual names or IPs work too) and press
   *Start bonding*. The local SOCKS5 frontend listens on
   `127.0.0.1:10811`.

Two modes:

* **Stream bonding** — every stream rides *all* adapters at once
  (maximum bandwidth for a single connection).
* **Per-connection balancing** — each new stream is assigned to one
  adapter, round-robin (net-merge behaviour; great for many parallel
  downloads).

A dropped adapter is removed from the schedule and its share moves to
the survivors mid-stream — the stream keeps flowing (chunks are
sequence-numbered, so re-ordering across links is free). Per-adapter
stats (up/down bytes, alive) are shown in the settings tab.

**Interoperability** — the bond composes with everything else:

* **Xray / samizdat ride the bond**: with *Ride the bond* enabled
  (default), their outbound dials through the bond's SOCKS frontend, so
  the VLESS/REALITY or masqueraded HTTP/2 tunnel itself is split across
  your adapters (Xray `proxySettings` chaining / sing-box `detour`).
* The browser-routing **auto** mode uses the running proxy, or the bond
  directly when nothing else is up.
* The wire protocol (PCB — Proto Clean Bond) is spoken identically by
  the desktop (Python) and Android (Kotlin) clients: any client can use
  any `proto_clean.bondserver`.

**Android** — the bonding VPN (Settings → Link bonding) captures all
traffic, forwards every TCP flow through Wi-Fi **and** mobile data at
the same time (no root: member sockets are `VpnService.protect`ed and
bound to their network), and answers DNS through a protected socket.
Android allows one VPN at a time, so bonding replaces the
tunnel/ad-blocker while it runs. The *Upstream* selector can send the
TUN traffic through the **bundled lantern-box samizdat engine** instead
of the bond server — Lantern's masquerade on Android, no root.

**Limits** — TCP only (UDP stays on one adapter or is dropped inside the
bonding VPN); the userspace TCP responder on Android is deliberately
minimal (no retransmit pacing); one bond server per client config.

## Security notes

- Credentials: system keyring preferred; the fallback file is `~/.config/proto-clean/credentials.json`, `chmod 600`, and never logged. (Windows: DPAPI-backed keyring / protected file. Android: EncryptedSharedPreferences.)
- The helper runs as root but only accepts a fixed verb list with
  strict argument validation (interfaces, IPs, ports, uid/gids are
  regex/IP-validated; config files must parse as WireGuard configs with
  no shell hooks). Review `helper/proto-clean-helper` (Linux/macOS) and
  `proto_clean/helper_win.py` (Windows) yourself.
- The kill switch is installed *before* the tunnel comes up, so there is
  no leak window during connect; it is removed on disconnect/quit.
- WireGuard configs are root-readable only (Linux/macOS:
  `/etc/wireguard/proto_clean.conf`, 0600). OpenVPN configs likewise
  (`/etc/openvpn/proto-clean/proto-clean.ovpn`, 0600, dir 0700) — and the
  helper refuses `.ovpn` files carrying `up`/`down`/`script-security`
  shell hooks, exactly as it refuses `PreUp`/`PostUp` in wg-quick files.

## Layout

```
proto_clean/
├── proto_clean/
│   ├── account/       # backend browser: login + downloads-page scraping
│   ├── platforms/     # per-OS backends: factory, capabilities, Linux
│   │                  # (sudo/iptables/cgroup), Windows (UAC/firewall),
│   │                  # macOS (sudo/pf/networksetup)
│   ├── servers/       # logical-server model, store, fastest selection
│   ├── vpn/           # wg-quick + OpenVPN config handling, config cache,
│   │                  # tunnel, kill switch, split tunnel, NAT-PMP, monitor,
│   │                  # helper facade
│   ├── netshield/     # blocklist manager + embedded DNS server
│   ├── ui/            # PySide6: main window, blocklists manager, settings,
│   │                  # tray, theme, icons
│   ├── controller.py  # state machine orchestrating everything
│   ├── helper_win.py  # Windows privileged verbs (UAC batch executor)
│   ├── credentials.py # keyring/file storage
│   ├── settings.py    # settings.json (per-OS paths)
│   └── totp.py        # RFC 6238 codes for automatic 2FA
├── helper/proto-clean-helper  # privileged verb-whitelisted helper (root,
│                           # Linux + macOS implementations)
├── android/           # Android app: Kotlin + Compose + GoBackend +
│                      # DNS-filter VpnService (see android/README.md)
├── packaging/         # PyInstaller specs + build scripts (win/mac/linux)
├── scripts/           # install.sh, install_macos.sh, uninstall.sh,
│                      # dev_smoke.py, ui_screenshot.py, verify_real_dom.py
├── tests/             # pytest suite (132 tests incl. live DNS + flow tests)
└── docs/ARCHITECTURE.md, docs/PLATFORMS.md
```

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -q                    # unit + live DNS + flow tests
python scripts/dev_smoke.py login-page        # selector check vs. live Proton
python scripts/dev_smoke.py blocklist         # blocklist download check
python scripts/verify_real_dom.py             # selectors vs. the real DOM dump
QT_QPA_PLATFORM=offscreen python scripts/ui_screenshot.py  # render the UI
```

`dev_smoke.py login-page` was verified against the live
`account.protonvpn.com` login page (Nov 2026): two-step
username → Continue → password flow confirmed.

`verify_real_dom.py` replays every WireGuard-section selector against the
real logged-in page DOM: the 121 free servers of the "Free server configs"
tables, the `#certificate-device-name` input, the `#feature-*` toggles,
the exact-match server rows and the existing-certificate textareas all
verified against a real dump (Nov 2026).

## Known limits

- Web-UI automation can break when Proton ships a redesign; debug
  screenshots land in `~/.cache/proto-clean/screenshots`. The OpenVPN
  section's ids are less stable than the WireGuard ones — Proto Clean uses
  layered selector candidates there, and a failure logs a screenshot.
- Free plan: no NAT-PMP port forwarding, no Proton-side NetShield and no
  Moderate NAT — Proton enforces this server-side. The local blocklist
  ad-blocker is the free-plan answer to NetShield.
- **Windows**: OpenVPN tunneling is not available (the bundled tunnel
  driver is WireGuard only) — selecting OpenVPN there shows a clear error
  at connect; keep WireGuard. **Android**: same — the tunnel runs
  WireGuard (GoBackend), so OpenVPN is shown disabled in the app's
  settings. The Xray and samizdat proxies are desktop-only for now
  (Android needs the Go cores — on the roadmap).
- The Xray proxy routes apps that honor the system proxy (or that you
  point at the SOCKS/HTTP inbounds); it is not a system-wide TUN device.
- Flatpak build: the sandbox cannot run the privileged helper, so
  WireGuard/OpenVPN tunnels are unavailable there (Xray proxy + DNS
  ad-blocker work).
- Windows/macOS: per-**app** split tunneling needs kernel support that is
  not available to user space — use IP-range exclusions there (the
  settings UI explains this). Linux and Android support apps fully.
- Android: local DNS filtering runs as the standalone Ad-blocker mode
  (Android allows one VpnService per app) — see docs/PLATFORMS.md.
- Split-tunneled apps share the system DNS path; their DNS may still be
  answered through the tunnel (by design of the system-wide redirect).
- IPv4 + IPv6 both routed/filtered; LAN access off by default while the
  kill switch is on. On macOS the IPv6-leak-protection pf anchor blocks
  all outbound IPv6 except loopback and the OpenVPN interface — for
  tunneled IPv6 on macOS combine IPv6 support with the kill switch.

## Download & install

Ready-made installers are on the
[Releases page](https://github.com/maniesh-NR/Proto-Clean/releases)
(built by the `Release` workflow on every tag). Every platform has a
**portable** build (extract & run, no installation):

| Platform | File | Install / run |
|---|---|---|
| Windows 7+ x64 (portable) | `Proto-Clean-…-win7-x64-portable.zip` | unzip, run `ProtoClean.exe` — Qt 5.15 legacy stack |
| Windows 7+ x86 / 32-bit (portable) | `Proto-Clean-…-win7-x86-portable.zip` | same, 32-bit |
| Windows 10/11 x64 (portable) | `Proto-Clean-…-win-x64-portable.zip` | modern Qt 6 build |
| Windows 10/11 x64 (setup) | `Proto-Clean-…-win-x64-setup.exe` | Inno Setup installer |
| macOS 10.15 Catalina+ (Intel) | `Proto-Clean-…-macos-10.15-catalina-x86_64-portable.zip` | unzip → /Applications |
| macOS 11+ (Apple Silicon) | `Proto-Clean-…-macos-11.0-arm64-portable.zip` | unzip → /Applications |
| Linux Mint 21 / Ubuntu 22.04 | `proto-clean_…-mint21-ubuntu22.04_amd64.deb` | `sudo apt install ./proto-clean_….deb` |
| Linux Mint 22 / Ubuntu 24.04 | `proto-clean_…-mint22-ubuntu24.04_amd64.deb` | same |
| LMDE 6 / Debian 12 | `proto-clean_…-debian12_amd64.deb` | same |
| Linux (portable) | `Proto-Clean-…-linux-x86_64-portable.tar.gz` | untar, run `proto-clean/proto-clean` |
| Linux (Flatpak) | `Proto-Clean-…-x86_64.flatpak` | `flatpak install --user Proto-Clean-….flatpak` |
| Android 8.0+ (armv7) | `Proto-Clean-…-android-armeabi-v7a.apk` | debug-signed APK; allow "install unknown apps" |
| Android 8.0+ (arm64) | `Proto-Clean-…-android-arm64-v8a.apk` | same |

The Linux portable/deb binaries are built on Ubuntu 22.04 so they run
on every current Mint base (21/22/LMDE 6) and newer. The Windows 7
legacy builds use Python 3.8 + Qt 5.15 — the last toolchains supporting
Windows 7 and 32-bit Windows; the modern builds use Qt 6. **Flatpak
note:** the sandbox cannot run the privileged WireGuard/OpenVPN helper —
use the Xray proxy and the ad-blocker DNS-filter mode there.

Or from source: `pip install -e .` and `python3 -m proto_clean` (plus
`bash scripts/install.sh` on Linux / `scripts/install_macos.sh` on macOS
for the privileged helper).

## Attribution

This project was developed with the assistance of **[GLM](https://z.ai),
a large language model by Z.ai** — the code, tests, packaging and CI in
this repository were generated and iterated with the model under human
direction. All AI-generated content is GPL-3.0-or-later-licensed like
the rest of the project.

Proto Clean builds on outstanding open-source work:

- [Qt](https://www.qt.io) via [PySide6](https://pypi.org/project/PySide6/)
  (and [PySide2](https://pypi.org/project/PySide2/) for the legacy
  Windows 7 / 32-bit builds) — © The Qt Company, LGPL/GPL
- [Playwright](https://playwright.dev) — browser automation for the
  backend-browser login (© Microsoft)
- [dnslib](https://pypi.org/project/dnslib/) — DNS wire format for the
  ad-blocker; [httpx](https://www.python-httpx.org) — HTTP client;
  [keyring](https://github.com/jaraco/keyring) — system keyring access
- [PyInstaller](https://pyinstaller.org) — the packaged builds;
  [Inno Setup](https://jrsoftware.org/isinfo.php) — the Windows installer
- [Xray-core](https://github.com/XTLS/Xray-core) (© XTLS project) — the
  optional proxy engine for the VLESS REALITY / Trojan feature (not
  bundled; install it separately)
- [Lantern](https://github.com/getlantern) — the samizdat
  censorship-resistance protocol, and **lantern-box**
  ([getlantern/lantern-box](https://github.com/getlantern/lantern-box),
  a sing-box fork) which the releases now **bundle as the samizdat
  engine** — GPL-3.0-or-later by the Lantern team (Brave New Software /
  getlantern), built from the pinned source tag in CI (see
  `LANTERN_BOX_VERSION` in `.github/workflows/release.yml`; the
  corresponding source is public at that repository). Proto Clean is
  GPL-3.0-or-later, so the combination complies with their license; the
  Python/Kotlin code here drives the binary through its documented
  client config format and contains no Lantern source. "Lantern" is a
  trademark of its owners; Proto Clean is not affiliated with the
  Lantern project.
- [WireGuard](https://www.wireguard.com) by Jason A. Donenfeld — "WireGuard"
  and the WireGuard logo are registered trademarks; Proto Clean is not
  affiliated with the WireGuard project and simply drives its tools
- "WireGuard" and the "WireGuard" logo are trademarks of Jason A.
  Donenfeld.

## Trademarks & legal

Proto Clean is an **independent, community project** and is **not
affiliated with, endorsed by, or sponsored by Proton AG**. "Proton VPN"
and "Proton" are trademarks of Proton AG; they are used here solely to
describe interoperability with a service the user has subscribed to
(nominative use). All artwork — the logo, icons, color palette and UI
styling in this repository — is **original Proto Clean branding**, created
for this project (GPL-3.0-or-later, see `LICENSE`); no Proton assets are
included or reproduced. The client talks to Proton's website only the
way your own browser would, using your own account.

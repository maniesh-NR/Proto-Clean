# Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ PySide6 UI (main thread)                                       │
│  MainWindow ─ SettingsDialog ─ Tray                            │
│      ▲ signals (queued)          │ method calls                │
│      │                           ▼                             │
│  ControllerBridge  ⇄  Controller (worker threads)              │
│                          │                                     │
│   ┌──────────────────────┼──────────────────────────────┐      │
│   ▼                      ▼                              ▼      │
│ AccountSession     TunnelManager              BlocklistManager │
│  (browser thread)   ├─ KillSwitch               + DnsBlocker   │
│  ├─ login (hybrid)  ├─ SplitTunnel                (threads)    │
│  └─ DownloadsPage   ├─ PortForwarder (thread)                  │
│     scrape/config   └─ TunnelMonitor (thread)                  │
│                          │                                     │
│                          ▼ sudo -n                             │
│                /usr/local/bin/proton-clean-helper (root)           │
│                  wg-quick · iptables · ip · cgroup              │
└────────────────────────────────────────────────────────────────┘
```

## Threads

| Thread | Owns |
| --- | --- |
| Qt main | all widgets; receives everything via queued signals |
| `proton-clean-browser` | the single Playwright sync session (jobs are queued through `BrowserWorker.submit`) |
| `proton-clean-login` / `proton-clean-connect` / `proton-clean-disconnect` / `proton-clean-servers` / `proton-clean-blocklists*` | one Controller operation each; guarded by an operation lock |
| `proton-clean-dns-*` pool | DNS query handling (thread per query, bounded pool) |
| `proton-clean-monitor` | polls helper `status` every 5 s |
| `proton-clean-natpmp` | NAT-PMP lease keep-alive |

The Controller is Qt-free (plain callbacks) so it can be exercised by the
test suite headlessly; `ControllerBridge` converts callbacks into
signals. The only blocking hand-off is the TOTP prompt: the login thread
calls `totp_provider()`, the bridge emits `totp_requested`, the UI shows
a dialog and calls `provide_totp(code)` which releases the event.

## Login flow (credentials, auto-login, CAPTCHA relay)

1. App start: stored credentials exist → `login_async()` (cached
   storage-state probe → headless login); none → the **login dialog**
   opens (`credentials_needed` event does the same when a connect needs
   credentials).
2. Login dialog: username + password (+ optional TOTP secret) with
   **Remember me**. Checked → credentials/TOTP are persisted (keyring or
   chmod-600 file) before the attempt, enabling auto-login forever;
   unchecked → used once, memory only. “Log in in browser…” starts the
   visible-window flow directly.
3. Freshly typed credentials **skip the cached session probe** — it may
   belong to a different account.
4. Headless login: two-step form, TOTP auto-answered from the stored
   secret (else a blocking UI dialog).
5. CAPTCHA / human verification → `captcha` event → **visible Chromium
   window opens on that step only**, credentials pre-filled; the session
   is captured automatically when it completes (5-minute window, with
   "still waiting" relays every minute).
6. Every step is relayed: `AccountSession.on_event` (browser thread) →
   `Controller._on_session_event` → `on_message` + status detail +
   `on_login_event` → bridge signal → **banner in the main window**
   (taskbar flash via `QApplication.alert`) + **tray notification**.
   `bad_credentials` re-opens the login dialog pre-filled.

## Connect sequence (leak-safe ordering, cache-first)

1. ensure logged in (cached storage state → headless login → interactive window)
2. refresh server list if empty (XHR capture → page-fetch — with
   *alternative routing*, Proton's mirror API hosts too — → free-category
   table scrape); **free (tier 0) servers only** — paid logicals are
   excluded from the list and from selection, mirroring the page's own
   "Free server configs" category
3. choose server: fastest (`min Score`, tier = 0, online, <90 % load) or
   manual (a paid/stale id falls back to fastest-free with a warning)
4. **cache lookup**: if `~/.cache/proton-clean/configs/` holds a config for
   the server *of the selected protocol* (exact option fingerprint
   preferred, any same-protocol variant accepted — an .ovpn is never
   served to a WireGuard lookup and vice versa), skip the browser
   entirely and jump to step 7
5. open the section for `settings.protocol` on the Downloads page —
   **WireGuard**: Platform=GNU/Linux radio, `#feature-SplitTCP`
   (VPN Accelerator), `#feature-PortForwarding` (NAT-PMP, paid), Moderate
   NAT (paid); **OpenVPN**: the OpenVPN section with the TCP/UDP
   transport radio from settings, the same Linux platform radio and
   option toggles. In both cases: config name, click the
   "Free server configs" category, click the exact server row's Create
6. Create → capture config (XHR response body → the new certificate's
   readonly textarea → the Download button's file; WireGuard captures
   must contain `[Interface]`+`PrivateKey`, OpenVPN captures a `remote`
   line) → store in the cache
7. validate config (WireGuard: no `PostUp`/`PreUp` hooks; OpenVPN: a
   `remote` line and no `up`/`down`/`script-security` hooks), install to
   `/etc/wireguard/proton_clean.conf` (or `/etc/openvpn/proton-clean/proton-clean.ovpn`)
8. **kill switch on** (before the tunnel exists — no leak window; the
   endpoint allow-rule uses the config's own transport: UDP for
   WireGuard, UDP/TCP for OpenVPN) and **IPv6 leak protection on**
   (default) via `v6-on`, then split-tunnel rules, then DNS redirect
   (your uid exempt)
9. tunnel up: `wg-quick up proton-clean` or helper `ovpn-up tun|tap`
   (`openvpn --config … --dev proton_clean0 --dev-type <driver> --daemon`)
10. **liveness verification**: wait for `latest-handshake > 0` (default
    25 s; the OpenVPN status verb reports "now" while the daemon is
    alive and its interface has an address). If a *cached* config fails
    here (revoked cert), the entry is invalidated, everything is torn
    down cleanly and the config is re-downloaded exactly once; a fresh
    download that fails verification reports a connection error.
11. start stats monitor + NAT-PMP keep-alive; mark the cache entry verified

Disconnect reverses: tunnel down (+ `ovpn-down`) → split rules off → DNS
redirect off → kill switch off → IPv6 leak protection off.

### Protocol & Advanced settings

- `settings.protocol`: `wireguard` (default) | `openvpn`, plus
  `openvpn_transport` (udp|tcp) and `openvpn_driver` (tun|tap) — unknown
  values normalize to the defaults on load.
- `settings.advanced`: `alternative_routing` (mirror API hosts + page
  load retry), `custom_dns_enabled` + `custom_dns_servers` (the embedded
  DNS blocker then answers system-wide and forwards to your servers, with
  an empty filter when ad blocking is off — this is how custom DNS works
  for both protocols), `ipv6_support` (off → v6 stripped from the config;
  on → `::/0` kept / `route-ipv6 ::/0` added) and `ipv6_leak_protection`
  (`v6-on`: block IPv6 outside the tunnel, independent of the kill
  switch).
- The Protocol tab of the settings dialog shows the WireGuard toggles
  (NAT-PMP → `port_forward.request_in_config`, VPN Accelerator →
  `vpn_options.vpn_accelerator`, both on by default) or the OpenVPN
  TCP/UDP radios, per the selection. The Advanced tab mirrors Proton's
  advanced settings: alternative routing, Allow LAN
  (`kill_switch.allow_lan`), custom DNS, NAT type
  (`vpn_options.moderate_nat`), the OpenVPN network driver with the
  TAP/TUN explanations, IPv6 support and IPv6 leak protection.

### Config cache (`~/.cache/proton-clean/configs/`)

- One `<server-slug>.<fingerprint>.conf|.ovpn` per server+protocol+options;
  `index.json` tracks created/verified/failures per entry.
- The fingerprint encodes protocol + transport + the options the page
  bakes into the file (`wg-acc1-nat0`, `ovpn-tcp-acc1-nat1`); lookups
  prefer an exact match but fall back only **within the requested
  protocol** (an .ovpn must never reach wg-quick). Options are
  comments/routing hints, not connection material; a mismatching entry
  is still used and reported in the UI as "different options".
- After a fresh login the controller **harvests** every existing
  certificate textarea on the Downloads page — **both the WireGuard and
  the OpenVPN section** — into the cache (protocol recovered from the
  text), so configs you created earlier (via Proton Clean or by hand) are
  reused without a download.
- `cache_configs = false` in settings disables the cache entirely.

## Blocklist management

- Sources live in `settings.json` as `netshield.blocklists:
  [{name, url, enabled}]`; legacy plain-URL `sources` migrate on load.
- Each list downloads to `~/.cache/proton-clean/blocklists/<sha1(url)[:16]>.txt`
  with a `.json` metadata sidecar (domain count, timestamp, last error).
- Enabled lists are merged (set union) into `merged.json` → `DomainFilter`.
- The controller exposes add / remove / enable-disable / update-one /
  update-all as worker-thread operations; every change persists to
  settings, rebuilds the merge and **hot-swaps the live DNS blocker's
  filter** (`DnsBlocker.reload_filter` replaces the filter object and
  flushes the answer cache — no reconnect needed).
- Removing a list deletes its cache files and rebuilds the merge; a
  failing download keeps the previous file so the filter never regresses.
- UI: the **Blocklists ▾** menu (update all, per-list enable toggles with
  Update/Remove submenus, add/remove/manage actions) plus a full manager
  dialog with domain counts, timestamps and per-row update buttons.

## Split tunnel details

- Root-level cgroup `proton_clean_split` (created by the helper; cgroup v2).
- `iptables -t mangle OUTPUT -m cgroup --path proton_clean_split -j MARK --set-mark 0x2a`
- `ip rule add fwmark 0x2a table 51821 priority 100` (evaluated before
  wg-quick's auto rules) → table 51821 holds a default route via the
  pre-tunnel gateway.
- The kill switch chain accepts mark 42 before its final DROP, so
  excluded traffic leaves via the physical interface.
- Apps enter the cgroup either by PID (`split-add-pid`) or by being
  launched into it (`split-launch uid gid -- cmd`).

## DNS interception details

- Server: dnslib, UDP+TCP on `127.0.0.1:5353` and `[::1]:5353`.
- `iptables -t nat OUTPUT`: `-m owner --uid-owner <app uid> RETURN`
  first (so Proton Clean's own upstream queries never loop), then
  `REDIRECT --to-ports 5353` for udp/tcp 53 (v4+v6).
- Upstream: DoH POST (`application/dns-message`) to
  `https://doh.protonvpn.ch/dns-query`, bootstrapped over plain UDP via
  `10.2.0.1`; falls back to plain UDP automatically. **Custom DNS**
  (Advanced settings) replaces the upstreams with your servers (ordered
  fallback, DoH disabled) — and when ad blocking is off the blocker
  runs with an empty filter purely as the custom-DNS forwarder.
- Blocked: suffix match on the merged blocklist → NXDOMAIN (or A
  `0.0.0.0`); whitelisted names (`localhost`, …) are never blocked.
- Positive answers cached up to 5 min.

## IPv6 handling

- **IPv6 support off** (default): IPv6 addresses/routes are stripped
  from the WireGuard config (`::/0` out of AllowedIPs, v6 out of
  Address/DNS); OpenVPN configs drop `route-ipv6`. IPv6 then keeps the
  physical route — or is blocked when leak protection is on.
- **IPv6 support on**: the config keeps `::/0` (OpenVPN gets
  `route-ipv6 ::/0`, plus `tun-ipv6` with the TUN driver) so v6 flows
  through the tunnel — better compatibility with v6-only sites.
- **IPv6 leak protection on** (default): the `v6-on` helper verb adds
  an ip6tables `PROTON_CLEAN_V6` OUTPUT chain (macOS: the `proton_clean.v6`
  pf anchor; Windows: the `ProtonCleanV6` firewall group) that blocks
  all IPv6 except loopback, both tunnel interfaces and the
  split-tunnel mark — armed **before** tunnel-up, independent of the
  kill switch, and torn down by `v6-off`.

## Helper hardening

- Single binary at `/usr/local/bin/proton-clean-helper`; sudoers grants
  NOPASSWD for exactly that path.
- Verbs are an exact allow-list; every argument is validated
  (interface regex, `ipaddress` parse, port/uid ranges, absolute paths).
- `install-config` only accepts sources under
  `~/.cache/proton-clean/` or `/tmp/protonclean-`, requires the file to parse
  as a WireGuard config and **rejects `PreUp`/`PostUp` hooks** so a
  crafted config can't run shell commands as root.
- `ovpn-install-config` applies the same rules to `.ovpn` files: source
  path allow-list, must contain a `remote` line, and **rejects
  `up`/`down`/`script-security`/`iproute`** (the OpenVPN equivalents of
  shell hooks). `ovpn-up` only accepts `tun` or `tap` as the driver;
  the daemon runs with a fixed interface name and a pidfile.
- `ks-on` validates its endpoint transport argument (`udp`|`tcp`) so a
  TCP OpenVPN endpoint can be allowed without opening UDP as well.
- `split-launch` re-executes with `setuid/setgid` back to the invoking
  user; `split-add-pid` refuses pid ≤ 1.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| CAPTCHA during headless login | `captcha` event → visible Chromium window (credentials pre-filled) + banner + desktop notification; session captured on completion |
| 2FA without stored secret | UI dialog (180 s) — enter the code, login continues |
| Proton UI redesign | `ScrapeError` with a debug screenshot in `~/.cache/proton-clean/screenshots`; server cache still serves the UI |
| Cached config revoked server-side | interface comes up but no handshake → entry invalidated, config re-downloaded once automatically |
| All blocklist sources fail | previous merged list stays in `~/.cache/proton-clean/blocklists/merged.json` |
| One blocklist source fails | others still merge; the entry shows the error in the manager; its old cache file (if any) keeps contributing |
| DoH upstream down | plain-UDP fallback to `10.2.0.1`; if that fails too, SERVFAIL |
| NAT-PMP "not authorized" (free plan) | one-shot message, no retries |
| OpenVPN selected on Windows/Android | clear error at connect ("not supported on this platform") — switch back to WireGuard |
| openvpn binary missing | helper fails with the install hint (apt/brew); WireGuard keeps working |
| OpenVPN daemon dies after connect | status verb reports down → UI shows "tunnel down"; reconnect re-verifies |
| Helper missing / sudoers absent | clear error, connect refused before touching the network |

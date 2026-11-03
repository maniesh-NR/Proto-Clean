# Proto Clean for Android

Clean, room-temperature ProtonVPN client for Android — the same clean-room
philosophy as the desktop apps, in Kotlin + Jetpack Compose, built on the
official [`com.wireguard.android:tunnel`](https://github.com/WireGuard/wireguard-android)
library (wireguard-go).

## Features

* **WebView login** on `account.protonvpn.com` — stored credentials are
  auto-filled (two-step form), the optional TOTP secret answers 2FA, and
  CAPTCHA is completed by hand in the same window. The session cookie jar
  is stored encrypted (EncryptedSharedPreferences) and restored on launch.
* **Free servers only** — the logicals list is fetched in-page (with the
  logged-in session), filtered to tier 0; paid servers are excluded
  everywhere.
* **Fastest-server toggle** — Proton's own `Score` (lower = better),
  online-only, saturated servers (>90 % load) deprioritised.
* **WireGuard tunnel** via GoBackend; the handshake is verified after
  connect — a cached config that never handshakes is invalidated and
  re-downloaded once (config cache lives in `filesDir/configs/`).
* **Config creation** through the real downloads page: platform radio
  `#wg-platform-Android`, NAT-PMP / VPN Accelerator toggles, "Free server
  configs" category, server search, Create — the resulting certificate
  textarea is read back (the same harvesting path as the desktop).
* **Split tunneling** — excluded apps (package names) use Android's native
  `VpnService.addDisallowedApplication`.
* **Port forwarding** — RFC 6886 NAT-PMP client (`10.2.0.1:5351`, lease
  refreshed at ~75 %), external port shown in the UI. Paid plans only.
* **Kill switch** — full-route tunnel (`0.0.0.0/0` + `::/0`, single peer);
  the app also reports whether the system's *Always-on VPN + Block
  connections without VPN* lockdown is armed (`GoBackend.isLockdownEnabled`).
* **Ad-blocker mode** — a standalone DNS-filtering VpnService
  (`DnsFilterVpnService`): a virtual DNS address whose /32 route is the
  only thing entering the tun; blocked names get NXDOMAIN / 0.0.0.0,
  everything else is forwarded over DoH (pinned `https://1.1.1.1/dns-query`).
  Blocklists are managed in-app (add / remove / enable / update, with the
  same presets as desktop: StevenBlack, HaGeZi, OISD, 1Hosts, Peter Lowe).
  Android allows one VpnService per app, so this runs when the WireGuard
  tunnel is down and is switched off automatically when you connect.

## Build

Requirements: Android Studio (or the command-line tools), JDK 17.

```bash
cd android
./gradlew assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug        # with a device connected
```

The WireGuard GoBackend loads `libwg-go.so` from the tunnel library's
packaged AAR — no extra setup needed.

## Project layout

```
app/src/main/java/app/protoclean/
├── ProtoCleanApp.kt        # application: settings, blocklists, config cache, channels
├── MainActivity.kt        # Compose host + bottom navigation + VPN consent
├── AppViewModel.kt        # state machine (the desktop Controller's analogue)
├── ui/                    # Compose screens: Login, Servers, Blocklists, Settings
├── data/                  # DataStore settings, credentials (+TOTP), blocklists, config cache
├── proton/                # WebView session, in-page automation, logical models + selection
├── vpn/                   # GoBackend service, tunnel manager (handshake verify), NAT-PMP
└── dns/                   # DNS-filter VpnService + IPv4/IPv6/UDP packet kit
```

## Notes & limitations

* Config creation and server fetching drive the real web UI, so a Proton
  redesign can break the selectors (same caveat as the desktop; the JS
  snippets live in `proton/ProtonWeb.kt`).
* While the tunnel is up, DNS uses Proton's in-tunnel resolver
  (`10.2.0.1`) — in-path local filtering is not possible on Android
  without owning the tun *and* the tunnel (see `docs/PLATFORMS.md` for the
  full explanation); the DNS-filter mode covers the VPN-off case.
* TCP DNS (port 53 over TCP) is dropped in DNS-filter mode — the system
  resolver falls back to UDP, which is handled.
* minSdk 29 (Android 10), targetSdk 34.

Proto Clean is an independent client; it is not affiliated with or endorsed
by Proton AG. Automating the account web app is a convenience for *your
own account* — check Proton's terms of service before relying on it.


## Link bonding (Speedify-style, no root)

Settings → **Link bonding**: the app runs a VPN that splits every TCP
stream across **Wi-Fi and mobile data at the same time** and rejoins
them at your bond server (run `python3 -m proto_clean.bondserver` —
part of the desktop app — on any reachable host). Per-connection
balancing spreads connections instead. Member sockets are protected
and network-bound, so both radios stay active; DNS is answered through
a protected socket. One VPN at a time (Android's rule): bonding
replaces the WireGuard tunnel / ad-blocker while it runs.

With **Upstream → Samizdat** the same VPN routes traffic through the
**bundled lantern-box engine** (shipped inside the APK as
`liblanternbox.so`, executed from the app's nativeLibraryDir — the
samizdat protocol on Android with no root and no separate app). Enter
the samizdat profile (server, pbk, sid, cover SNI) and start.

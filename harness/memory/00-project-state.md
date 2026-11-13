# Project State (living snapshot)

Last updated: 2026-11-13 (Material You + harness session)

## Identity

- **Project**: Proto Clean — clean-room, GPL-3.0 ProtonVPN client
  (Linux / Windows / macOS desktop + Android)
- **Repo**: `maniesh-NR/Proto-Clean`
- **Version**: 0.6.2 (released) — see `03-release-runbook.md`
- **Test baseline**: **700 tests** in CI per desktop leg
  (local sandbox: 696 passed + 4 platform skips; the 4 skips pass on CI
  runners which have capabilities the sandbox lacks). Any change must
  keep the suite green; new features add tests to the baseline.

## Feature inventory

- **Accounts**: Proton login (credentials + TOTP), guest mode
- **VPN cores**: WireGuard (wgconf), OpenVPN (ovpnconf), plus
  protocol covers via `vpn/protocols/` and `vpn/xray.py`
- **Link bonding** (`vpn/bond*.py`): multi-adapter "combine interfaces"
  VPN (bond + balance modes), self-hostable bond server
  (`proto-clean-bond-server` CLI), desktop-verified E2E on
  Linux/macOS/Windows (see session-log 2026-11-07)
- **Samizdat upstream** (`vpn/samizdat*.py`): lantern-box engine as an
  alternative bonding upstream
- **NetShield-style blocking** (`netshield/`): uBO-parity default
  blocklists (9 lists, matches uBlock Origin out-of-the-box set)
- **Kill switch, split tunneling, port forwarding, NAT-PMP,
  custom DNS, IPv6 leak protection, alternative routing**
- **Server list**: region-grouped tree UI, load/user indicators
- **Desktop UI**: PySide6 (PySide2-Qt5 fallback via `qtcompat`),
  Material Design 3 theme system (`ui/md3.py` + `ui/theme.py`) with
  HCT tonal palettes; **Material You dynamic color** (system/custom
  seed) as of 2026-11-13
- **Android UI**: Jetpack Compose + Material 3, dynamic color
  (Material You) on Android 12+, DataStore-backed settings
- **Packaging**: Linux (deb + portable + flatpak), Windows (Inno
  Setup installer), macOS (dmg), Android (release-signed APKs,
  Play-Protect-friendly)
- **CI** (`.github/workflows/ci.yml`): ubuntu/macos/windows ×
  Python 3.12 + legacy legs (Python 3.8, PySide2-Qt5 and
  PySide6-6.2), wheel build, Android compile check
- **Release** (`release.yml`): tag-push `v*` triggered, 13 assets

## Release history (short)

| Tag | Headline |
|---|---|
| v0.6.0 | interop hardening, perf/stability/memory pass (669 tests) |
| v0.6.1 | region-grouped server list, guest-mode fixes, release-signed APKs |
| v0.6.2 | uBO-parity default blocklists, region-tree expansion fix (684 tests) |
| main since | bonding failover fix, desktop bonding test matrix (700 tests), Material You UI, agent harness |

## Known open threads

- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

# Project State (living snapshot)

Last updated: 2026-11-15 (G1-iter4 iteration 1: no consensus — RT+Architect BLOCK, Steward PROCEED-WITH-FINDINGS; all findings remediated, backup v5 + hardened integrity check; iteration 2 re-judges the fix commit)

## Identity

- **Project**: Proto Clean — clean-room, GPL-3.0 ProtonVPN client
  (Linux / Windows / macOS desktop + Android)
- **Repo**: `maniesh-NR/Proto-Clean`
- **Version**: 0.6.2 (released) — see `03-release-runbook.md`
- **Test baseline**: local sandbox **723 passed + 9 skipped** after the
  G1-iter4 fix cycle (719+9 plus 4 new machine tests: production
  opt-in, github-spelling refusals, unreachable-remote alarm,
  FINAL-OUTCOME forgery suite). CI confirmed at `6324a4d`: 728 × 4
  POSIX legs, 604 passed + 124 skipped on windows. Expectation for
  the G1-iter4 fix commit: 732 × 4 POSIX, 605+127 windows — to be
  confirmed by CI at iteration 2. Any change must keep the suite
  green; new features add tests to the baseline.

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
  HCT tonal palettes; **Material You dynamic color** (brand / system
  accent / custom seed) as of 2026-11-13 — desktop defaults to the
  brand green, Android 12+ defaults to wallpaper dynamic color
  (decision #10)
- **Android UI**: Jetpack Compose + Material 3, dynamic color
  (Material You) on Android 12+, DataStore-backed settings
- **Packaging**: Linux (deb + portable + flatpak), Windows (Inno
  Setup installer), macOS (portable zip), Android (release-signed
  APKs, Play-Protect-friendly)
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle) |

## Known open threads

- **S1 gate: G1-iter4 in progress (2026-11-15)** — the owner ordered
  a fresh gate on the G1-iter3 remediation commit; iteration 1
  returned Red Team + Devil's Architect BLOCK (production-as-default,
  guard spelling bypass, unreachable-alarm, unscanned divergence
  merge, GIT_TRACE2, and the FINAL-OUTCOME check defeated by its own
  documentation) vs Ship Steward PROCEED-WITH-FINDINGS; every finding
  is remediated and execution-verified (backup v5; 20/20 scratch
  matrix; +4 machine tests) and iteration 2 re-judges the fix commit
  within the gate's cap.
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

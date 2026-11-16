# Project State (living snapshot)

Last updated: 2026-11-16 (G1-iter4 iteration 2 — NO CONSENSUS at the
iteration cap: Red Team BLOCK (github-subdomain guard bypass,
FINAL-OUTCOME backing still forgeable, main-push credential leak
under GIT_CURL_VERBOSE, partial-override isolation gap) vs Architect
+ Steward PROCEED-WITH-FINDINGS; all findings from both iterations
remediated and machine-covered in the remediation commit, which
carries the record; escalated to the project owner — a fresh gate on
the remediation commit is the owner's call)

## Identity

- **Project**: Proto Clean — clean-room, GPL-3.0 ProtonVPN client
  (Linux / Windows / macOS desktop + Android)
- **Repo**: `maniesh-NR/Proto-Clean`
- **Version**: 0.6.2 (released) — see `03-release-runbook.md`
- **Test baseline**: local sandbox **727 passed + 9 skipped** after the
  G1-iter4-i2 fix cycle (723+9 plus 4 new machine tests: partial-
  override + production-checkout refusals, subdomain guard
  spellings, main-push redaction + trace/config-env hygiene, union
  key-scrub heal). CI confirmed at `ad3b4e1`: 732 × 4
  POSIX legs, 605 passed + 127 skipped on windows. Expectation for
  the G1-iter4-i2 remediation commit: 736 × 4 POSIX, 605+131
  windows — to be confirmed by CI. Any change must keep the suite
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle), backup v6 + declaration-bound gate-record authority (727+9 local; G1-iter4-i2 fix cycle — escalated at the cap) |

## Known open threads

- **S1 gate: G1-iter4 cap exhausted (2026-11-16)** — iteration 2
  re-judged the iteration-1 fix commit `ad3b4e1`: Red Team BLOCK
  (2 criticals — the github-subdomain guard bypass, with
  `www.github.com` verified a live anonymous git endpoint for the
  production repo, and the FINAL-OUTCOME ☑ check still forgeable four
  ways; 2 majors — the `GIT_CURL_VERBOSE` raw-credential leak through
  the then-inline main push, and partial-override test runs polluting
  the production checkout's backup branch) vs Architect and Steward
  PROCEED-WITH-FINDINGS → **NO CONSENSUS at the 2-iteration cap →
  escalated to the project owner**. Every finding from both
  iterations is remediated and machine-covered in the remediation
  commit that carries the closed record
  (`memory/consensus-log/2026-11-15-S1-material-you-gate-iter4.md`).
  A fresh gate (G1-iter5) on the remediation commit is the owner's
  call — the G1 → G1-iter3 → G1-iter4 precedent.
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

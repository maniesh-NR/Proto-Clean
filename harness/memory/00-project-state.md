# Project State (living snapshot)

Last updated: 2026-11-19 (G1-iter6 IN FLIGHT — iteration 1 returned
NO CONSENSUS (Red Team BLOCK on six executed criticals: git-dir
identity redirects, remote-carried relative targets, pushInsteadOf
on direct operands — falsifying a frozen-residual claim —
percent-encoded hosts, `ext::` transports, six glyph-forgery
classes; Architect + Steward PROCEED-WITH-FINDINGS). Every finding
from all three roles remediated in the fix-cycle commit (backup v9,
16 integrity tests extended in place, matrices v5–v9 = 112 checks
all repo-resident, residual list corrected per findings, the harness
subsystem SPLIT into stage S8 with a property-based port exit
criterion — decision #19). **Iteration 2 (final) re-judges the fix
commit — no outcome pre-recorded.**)

## Identity

- **Project**: Proto Clean — clean-room, GPL-3.0 ProtonVPN client
  (Linux / Windows / macOS desktop + Android)
- **Repo**: `maniesh-NR/Proto-Clean`
- **Version**: 0.6.2 (released) — see `03-release-runbook.md`
- **Test baseline**: local sandbox **728 passed + 9 skipped** (16
  integrity tests; unchanged by the v8 cycle — all new coverage
  extended existing tests). CI **confirmed on `1f3d1cf`** (run
  44358063985, job-log-verified): **737 × 4 POSIX legs, 605 passed
  + 132 skipped on windows**, wheel + Android green; `517ad3f`
  (docs-only) 7/7 as well, its ubuntu leg 736+1 (the documented
  bond-desktop loopback-alias skip — runner variance, not drift).
  CONFIRMED on the G1-iter5 closing line (check-runs + job logs,
  G1-iter6 pre-gate verification): `a1607ce` and `32d822f` both
  7/7 legs — 737 × 4 POSIX, 605+132 windows, exact. Expectation for
  the G1-iter6 fix-cycle commit: unchanged (all new coverage
  extended existing tests in place). Any change must keep the suite
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle), backup v6 + declaration-bound gate-record authority (727+9 local; G1-iter4-i2 fix cycle — escalated at the cap), backup v7/v8 + mutation-covered integrity suite + decision #18 bounded-exit (728+9 local; G1-iter5 both iterations, 737×4 / 605+132 CI at `1f3d1cf` — closed NO CONSENSUS at the cap, escalated), backup v9 + glyph-rule hardening + repo-resident matrices + S8 split/decision #19 (728+9 local; G1-iter6 iteration 1 fix cycle) |

## Known open threads

- **S1 gate: G1-iter6 iteration 2 (final) pending** — iteration 1
  (2026-11-19, on `a1607ce`+`32d822f`): RT BLOCK / Architect PWF /
  Steward PWF → NO CONSENSUS; the fix cycle (backup v9, glyph-rule
  hardening, matrix check-in, S8 split) landed in the commit
  carrying the iter6 record; iteration 2 re-judges that commit.
  History: G1 → G1-iter5, five cap-exhaustions, all decided by
  backup/harness findings (records in `memory/consensus-log/`).
- **S8 (new, decision #19): harness subsystem hardening + Python
  port** — property-based exit criterion (TEST runs address only
  local scratch paths physically disjoint from production; allowlist
  inversion evaluated; identity single-sourced); gated before S2's
  stage gate; ledger #10 rides the port.
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

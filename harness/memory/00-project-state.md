# Project State (living snapshot)

Last updated: 2026-11-19 (G1-iter5 CLOSED — NO CONSENSUS at the
2-iteration cap: iteration 2's Red Team and Devil's Architect BLOCK
on convergent findings (the relative push-target base mismatch,
found and executed E2E independently by both, plus the
empty-authority `https:///github.com/…` spelling family and the
uncovered pushurl lane) vs Ship Steward PROCEED-WITH-FINDINGS.
Every finding from both iterations remediated and machine/matrix-
covered in the closing commit (backup v8, 16 integrity tests,
matrices v8/v7/v6/v5 = 86 checks). **Escalated to the project
owner: a fresh gate (G1-iter6) on the remediation commit is the
owner's call — the G1 → G1-iter3 → G1-iter4 → G1-iter5
precedent.**)

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
  Expectation for the G1-iter5 closing commit: unchanged —
  737 × 4 POSIX, 605+132 windows. Any change must keep the suite
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle), backup v6 + declaration-bound gate-record authority (727+9 local; G1-iter4-i2 fix cycle — escalated at the cap), backup v7/v8 + mutation-covered integrity suite + decision #18 bounded-exit (728+9 local; G1-iter5 both iterations, 737×4 / 605+132 CI at `1f3d1cf` — closed NO CONSENSUS at the cap, escalated) |

## Known open threads

- **S1 gate: G1-iter5 CLOSED at the cap (2026-11-19), escalated to
  the owner** — both iterations' records live in
  `memory/consensus-log/2026-11-19-S1-material-you-gate-iter5.md`
  (iteration 1: RT+Architect BLOCK vs Steward PWF — empty-credential
  spellings, logical-pwd symlink/`//` bypass, insteadOf evasion;
  iteration 2: RT+Architect BLOCK vs Steward PWF — the relative
  push-target base mismatch found independently by both, the
  empty-authority family, the double-@ ssh family, the uncovered
  pushurl lane). All findings from both iterations remediated in the
  closing commit (backup v8 + the extended machine/matrix coverage).
  The owner's decision: order a fresh gate (G1-iter6) on the closing
  commit, or another option in the escalation precedent. No
  outcome pre-recorded anywhere.
- Harness port scheduling (decision #18): bash capability-frozen;
  the merge/alarm/guard core ports to Python before S2's stage gate
  (ledger #10 rides the port for the glyph-check date-semantics
  residuals).
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

# Project State (living snapshot)

Last updated: 2026-11-19 (G1-iter5 iteration 1 — NO CONSENSUS:
Red Team BLOCK (2 criticals — empty-credential spelling bypass of the
github guard, symlink/`//` bypass of the production-checkout
compare; 1 major — insteadOf/config-file guard evasion) and Devil's
Architect BLOCK (2 majors — the push-target production-path lane
open, the trace-scrub machine test not mutation-covering) vs Ship
Steward PROCEED-WITH-FINDINGS (3 doc minors). Every finding
remediated and machine/matrix-covered in the v7 fix cycle that
lands in the commit carrying the record; iteration 2 re-judges the
remediation commit within this gate's cap of 2.)

## Identity

- **Project**: Proto Clean — clean-room, GPL-3.0 ProtonVPN client
  (Linux / Windows / macOS desktop + Android)
- **Repo**: `maniesh-NR/Proto-Clean`
- **Version**: 0.6.2 (released) — see `03-release-runbook.md`
- **Test baseline**: local sandbox **728 passed + 9 skipped** after
  the G1-iter5 fix cycle (727+9 plus one new structural test:
  index-rescan positions). CI confirmed at `c00f647`/`a02db67`:
  **736 × 4 POSIX legs, 605 passed + 131 skipped on windows**
  (job-log-verified by the G1-iter5 Steward). Expectation for the
  G1-iter5 remediation commit: 737 × 4 POSIX, 605+132 windows — to
  be confirmed by CI. Any change must keep the suite green; new
  features add tests to the baseline.

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

- **S1 gate: G1-iter5 in flight (2026-11-19)** — the owner-ordered
  fresh gate on the G1-iter4-i2 remediation line (`bf0c74e` →
  `c00f647` → `a02db67`; pre-gate verification: tree clean ==
  origin/main, 727+9 local exact, CI 7/7 both commits, backup seq 9
  faithful). Iteration 1 verdicts: Red Team BLOCK, Devil's Architect
  BLOCK, Ship Steward PROCEED-WITH-FINDINGS → no consensus (1 of 2).
  The v7 fix cycle (backup script v7 + declaration-bound check
  extensions + 16 machine tests + the v7 matrix + decision #18's
  bounded-exit adoption) lands in the commit carrying the iteration-1
  record; iteration 2 re-judges THAT commit. No outcome
  pre-recorded anywhere — the record is
  `memory/consensus-log/2026-11-19-S1-material-you-gate-iter5.md`.
- Harness port scheduling (decision #18): bash capability-frozen;
  the merge/alarm/guard core ports to Python before S2's stage gate.
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

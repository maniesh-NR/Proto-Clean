# Project State (living snapshot)

Last updated: 2026-11-19 (G1-iter6 CLOSED at the 2-iteration cap —
iteration 2, on the fix commit `0c4b8f9`: Red Team BLOCK on two
executed criticals (includeIf-conditional pushInsteadOf; the fetch
side of a named remote, 3× CONNECT github.com:443 at a local sink)
+ 1 major (symlinked .git) + 3 minors; Devil's Architect
PROCEED-WITH-FINDINGS (3 majors, all remediated: the allowlist
hedge → decision #20, the identity-derivation job finished, the
stale split docs fixed); Ship Steward PROCEED-WITH-FINDINGS (CI
confirmed exact on `0c4b8f9`, run 44458438836; 2 doc minors, fixed)
→ NO CONSENSUS at the cap, escalated to the project owner. The
closing v10 fix cycle — both-directions target judgment incl. the
URL-operand insteadOf sibling found by orchestrator analysis,
include/includeIf file-content refusal, symlinked-.git refusal +
git-dir containment, union-prefers-ours (collision audited), scp
redaction, exactly-once PROD derivation, matrices v10 E31–E35 +
v9 loud anchors/derived E30/loud skips (121 checks v5–v10), decision
#20, ledger #10→S8 + rows #11/#12, process item (f) extension +
record-before-fix-cycle rule — landed in the commit carrying the
iter6 record. **OWNER DISPOSITION RECORDED (2026-11-19, decision
#21): the owner instructed "Continue" — no override; the
decision-#19 split is operative. S1 closes on its deliverable via
a scoped closing gate (fresh-gate precedent, remediation line
`7a13645`+), scheduled 2026-11-20+ because the iter6-i2 record
(same date, NO CONSENSUS, declares S1) withdraws a same-date close
per the fail-safe tie rule; S8 is activated for its named pre-gate
deliverables. No gate outcome is pre-recorded.**)

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
  7/7 legs — 737 × 4 POSIX, 605+132 windows, exact. **CONFIRMED on
  the G1-iter6 fix-cycle commit `0c4b8f9`** (run 44458438836, all 7
  legs success, per-leg job-log-verified by the Ship Steward):
  737 × 4 POSIX, 605+132 windows, wheel + Android green — exact,
  expectation met. **CONFIRMED on the G1-iter6-i2 closing commit
  `7a13645`** (run 44462797163, all 7 legs success, per-leg
  job-log-verified): 737 × 4 POSIX, 605+132 windows, wheel + Android
  green — exact, expectation met. Any change must keep the suite
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle), backup v6 + declaration-bound gate-record authority (727+9 local; G1-iter4-i2 fix cycle — escalated at the cap), backup v7/v8 + mutation-covered integrity suite + decision #18 bounded-exit (728+9 local; G1-iter5 both iterations, 737×4 / 605+132 CI at `1f3d1cf` — closed NO CONSENSUS at the cap, escalated), backup v9 + glyph-rule hardening + repo-resident matrices + S8 split/decision #19 (728+9 local; G1-iter6 iteration 1 fix cycle, CI 7/7 exact at `0c4b8f9`), backup v10 + both-directions judgment + include-class refusal + decision #20 allowlist mandate (728+9 local; G1-iter6-i2 closing fix cycle — gate closed at the cap, escalated) |

## Known open threads

- **S1 gate: G1-iter6 CLOSED at the cap (both iterations); owner
  disposition RECORDED 2026-11-19 (decision #21)** — iteration 1 (`a1607ce`+`32d822f`): RT BLOCK /
  Architect PWF / Steward PWF; the v9 fix cycle landed at
  `0c4b8f9`. Iteration 2 (`0c4b8f9`): RT BLOCK (includeIf-conditional
  pushInsteadOf + the fetch side of a named remote, both executed
  E2E; symlinked .git major) / Architect PWF (3 majors, all
  remediated) / Steward PWF (CI confirmed exact) → NO CONSENSUS at
  the cap; the v10 closing fix cycle landed with the record. Per
  the owner-side escalation default the decision-#19 split is
  already recorded: S1 may close on its deliverable with the
  harness findings owned by S8 — DECIDED 2026-11-19 (decision
  #21): the owner instructed "Continue"; the S1-closing gate is
  scheduled 2026-11-20+ (the same-date close-withdrawal tie
  constraint). History: G1 → G1-iter6, six cap-exhaustions, all
  decided by backup/harness findings (records in
  `memory/consensus-log/`).
- **S8 (decision #19; ACTIVATED 2026-11-19 per decision #21):
  harness subsystem hardening + Python port** — property-based
  exit criterion (TEST runs address only local scratch paths
  physically disjoint from production; allowlist inversion
  MANDATED per decision #20; identity single-sourced); gated
  before S2's stage gate; ledger #10 rides the port. Pre-gate
  deliverables in preparation: the allowlist-inversion
  adopt/reject evaluation + re-verified consumer inventory
  (decision #20b) and the S8 execution plan.
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

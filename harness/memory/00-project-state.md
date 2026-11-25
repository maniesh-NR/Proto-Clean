# Project State (living snapshot)

Last updated: 2026-11-25 (**S1 CLOSED — the S1-closing gate
reached CONSENSUS at iteration 1 (all three roles
PROCEED-WITH-FINDINGS, zero criticals; record:
`memory/consensus-log/2026-11-25-S1-closing-gate.md`) and the S1
done-glyph flip + title narrowing (deferred #11) + harness-sub-bullet
removal landed in the same commit per the closure choreography.
Sequencing per decision #22 ("D1:a, d2:a", recorded at `5bf91ad`):
S8-PG1-iter3 (fresh pre-gate, own 2-iteration cap, on the
closing-remediation line `865580e`+) ran iteration 1 on `2ccb4fb`
(deliverables unchanged since `865580e`): **NO CONSENSUS — RT BLOCK
(2C: the 3a module-lookup gap; the later-materialized-alias
coverage overclaim, executed E2E) / Architect PWF / Steward PWF;
the coverage-table post-3b off-by-one (v6 22→23, total 122) found
independently by all three roles. All three confirmed the prior
iteration-2 criticals resolved in substance. Remediation LANDED (documents
only, per the record's resolution list: the $0-relative
module-lookup rule + copy sites; the honest alias-claim + residual
recording + the STAGE-4b push-time re-canonicalization commitment;
the coverage 122 correction; all majors/minors); iteration 2
re-runs within the cap. Record:
`memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`.** Then
S8's port + its own gate → S2 (full chain per decisions #18/#19).** Prior this
session: owner disposition of the S8-PG1 escalation recorded —
decision #22; the S1-closing gate ran first per D2:a, scoped per
decision #21 (deliverable closure + split boundary correctness +
disposition recording — NOT harness re-judgment; date constraint
satisfied, 2026-11-25 > 2026-11-19). Prior (2026-11-19): S8
pre-gate S8-PG1 CLOSED AT THE 2-ITERATION CAP — NO CONSENSUS,
escalated to the project owner (iteration 1 on `82fb63c`:
RT/Architect BLOCK + Steward PWF → remediation `eb459b1`;
iteration 2 on `eb459b1`: all three roles BLOCK on NEW
boundary-contradiction criticals — the 3a parity oracle
unsatisfiable via the five anchor-demo lanes, realpath-or-refuse
red-lining five resilience lanes, the transport-allowlist backstop
undeliverable as claimed — while all three CONFIRMED the
iteration-1 findings resolved in substance; closing remediation
landed with the record, documents only, no port code changed;
full record `memory/consensus-log/2026-11-19-s8-pre-gate.md`).
And prior: G1-iter6-i2 CLOSED at the cap — owner disposition #21
(2026-11-19, "Continue"): the decision-#19 split operative, S1
closing gate scheduled 2026-11-20+, S8 activated; closing v10 fix
cycle in `7a13645` (CI run 44462797163, 7/7 legs job-log-verified).)

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
  green — exact, expectation met. **CONFIRMED on the S1-closing line `5bf91ad` (run
45551538029, all 7 jobs success via the API, S1-closing-gate
Steward)**; the documents-only commits between are green except
`eb459b1` (run 44536786320 — macOS-latest 3.12 leg only, recovered
on the next push; S2 release-watch note, roadmap S2 row). Any change must keep the suite
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
| main since | bonding failover fix, desktop bonding test matrix (700/leg), Material You UI + agent harness (728/leg POSIX, 604+124 windows at `6324a4d`), backup v5 + hardened gate-record integrity (723+9 local; G1-iter4 fix cycle), backup v6 + declaration-bound gate-record authority (727+9 local; G1-iter4-i2 fix cycle — escalated at the cap), backup v7/v8 + mutation-covered integrity suite + decision #18 bounded-exit (728+9 local; G1-iter5 both iterations, 737×4 / 605+132 CI at `1f3d1cf` — closed NO CONSENSUS at the cap, escalated), backup v9 + glyph-rule hardening + repo-resident matrices + S8 split/decision #19 (728+9 local; G1-iter6 iteration 1 fix cycle, CI 7/7 exact at `0c4b8f9`), backup v10 + both-directions judgment + include-class refusal + decision #20 allowlist mandate (728+9 local; G1-iter6-i2 closing fix cycle — gate closed at the cap, escalated) 
| S1 closed | Material You deliverable closed by the S1-closing gate — CONSENSUS REACHED (728+9 local re-verified by all three roles; CI 7/7 on `5bf91ad`; matrices 121/0; residuals ledgered #13–#16; decision #22 sequencing: S8-PG1-iter3 next) |

## Known open threads

- **S1 CLOSED (2026-11-25 — the S1-closing gate reached CONSENSUS
  at iteration 1; record:
  `memory/consensus-log/2026-11-25-S1-closing-gate.md`)** — the
  scoped closing gate per decisions #21/#22 (deliverable closure +
  split boundary correctness + disposition recording — NOT harness
  re-judgment): all three roles PROCEED-WITH-FINDINGS, zero
  criticals; the roadmap glyph flipped ◐→☑ with the narrowed title
  and the harness sub-bullet removed (deferred #11 resolved in the
  same commit); RT-M1 (pre-S1 settings-loader crash) ledgered #13,
  RT-m1/m2 → #14/#15, Arch-m3/m4 → #16; residuals #1–#4+#7→S2,
  #5→S5. Gate history before the close: G1-iter6 CLOSED at the cap
  (both iterations); owner disposition RECORDED 2026-11-19
  (decision #21) — iteration 1 (`a1607ce`+`32d822f`): RT BLOCK /
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
  constraint); per decision #22 (2026-11-25, "d2:a") the closing
  gate runs FIRST — before S8-PG1-iter3, on 2026-11-25 — its
  outcome not pre-recorded at the disposition commit. History:
  G1 → G1-iter6, six cap-exhaustions, all decided by
  backup/harness findings (records in `memory/consensus-log/`).
- **S8 (decision #19; ACTIVATED 2026-11-19 per decision #21):
  harness subsystem hardening + Python port** — property-based
  exit criterion (TEST runs address only local scratch paths
  physically disjoint from production; allowlist inversion
  MANDATED per decision #20; identity single-sourced); gated
  before S2's stage gate. Pre-gate deliverables landed 2026-11-19
  (decision #20b evaluation + execution plan). **PRE-GATE S8-PG1
  RAN BOTH ITERATIONS AND CLOSED AT THE CAP (2026-11-19): iter 1
  on `82fb63c` NO CONSENSUS (RT BLOCK 2C/4M/4m + Architect BLOCK
  3C/6M/4m + Steward PWF 2C/5M/4m; remediation `eb459b1`); iter 2
  on `eb459b1` NO CONSENSUS (RT BLOCK 3C/4M/5m + Architect BLOCK
  2C/6M/6m + Steward BLOCK 2C/2M/6m) — the iteration-1 findings
  were all confirmed resolved in substance; the new BLOCKs were
  the same class: the 3a parity oracle (anchor-demo lanes), item-2
  realpath-or-refuse (resilience lanes), the transport backstop
  claim. Closing remediation landed with the record: the 3a edit
  list re-scoped (demo lanes re-home AT 3a; v6-E10/v7-E15
  de-hardcode at 3a), item 2 → ancestor-canonicalized containment,
  item 7 → bash-side `_git` wrapper with an honest network-only
  claim + recorded local-rewrite residual, STAGE 3c (merge/alarm/
  state.json cutover), STAGE 4 split 4a/4b, matrix retirement
  moved to/after STAGE 6, Seq field DEFERRED OUT of S8 (ledger #10
  updated), pattern-parity lanes pin the live bash scrub/sed,
  module location DECIDED (scripts/backup_core.py), seam protocol
  fail-closed, coverage table derivable. ESCALATED TO THE OWNER —
  disposition RECORDED (2026-11-25, decision #22, the owner
  instructed "D1:a, d2:a"): fresh gate S8-PG1-iter3 (its own
  2-iteration cap) ordered on the closing-remediation line
  `865580e`+, running AFTER the S1-closing gate; no fresh-gate
  outcome pre-recorded; no port work started (documents only
  throughout).**
- SHA-256 checksums in release body (proposed, not yet requested-done)
- Copilot PR review pass (instructions in place, unused so far)
- See `roadmap.md` for the consensus-gated forward plan

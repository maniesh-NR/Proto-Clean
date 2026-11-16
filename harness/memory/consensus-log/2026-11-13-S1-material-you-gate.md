# Consensus Gate — S1 "Material You + agent harness" (iteration 1)

Stage: S1

Date: 2026-11-13 · Gate ID: G1-iter1
Reviewed commits (pinned): `fd94450` (harness + backup v1), `a10369b`
(Material You) — both already on main; this was the first gate run under
the new process, executed immediately after landing (record reconstructed
honestly: the gate ran post-landing, pre-next-stage, as the process's
first exercise).

## Roles launched (independent, parallel, no shared context)

| Task | Role | Verdict |
|---|---|---|
| C-1 | Red Team (attacker) | **BLOCK** |
| C-2 | Devil's Architect (design critic) | PROCEED-WITH-FINDINGS |
| C-3 | Ship Steward (quality/release) | PROCEED-WITH-FINDINGS |

**Consensus: NOT reached** (one BLOCK). Per
`process/adversarial-consensus.md`: fix findings, re-run the gate.

## Critical findings (all three agents converged on #1)

1. **Live PATs in sandbox scripts would leak on first backup run**
   (Red C1, Steward C1, confirmed by Architect C1 indirectly).
   `/home/z/my-project/scripts/poll_release.py` + `poll_release_061.py`
   embedded 93-char GitHub PATs; the backup script rsyncs the whole
   sandbox scripts dir and pushes to the public repo. Nothing had leaked
   yet (manifest empty, branch absent on origin — verified), but the
   mandated first run would have leaked. → FIXED: scripts now source the
   token from env/`git remote`; backup script secret-scans (two layers)
   and hard-fails; `harness/sandbox/` gitignored. **PAT rotation is
   owner-actionable and still recommended as insurance.**
2. **Backup script v1 failure modes** (Red M2/M3, Architect C1/C2,
   Steward M3/M6): amend+force-push self-reference, unbound `SHA`,
   dirty-main-tree writes absorbed by release `git add -A`,
   fresh-clone non-FF push death, no concurrency lock, mislabeled
   `repo_head_on_main`. → FIXED: full rewrite (v2) — worktree-only
   writes, append-only commits (SHAs live in `git log` of the branch,
   manifest records timestamp+head+branch), fetch-or-create from origin,
   mkdir lock, two-layer secret scan.
3. **Mandated records didn't exist** (Architect C3, Steward M4):
   `session-log/`, `consensus-log/` empty despite references. → FIXED:
   this file + session logs are the first real entries; future gates get
   theirs before the stage proceeds.

## Major findings and resolutions

| Finding | Source | Resolution |
|---|---|---|
| Tray icons hardcoded brand colors, ignored the seed | Red M5, Steward M4 | FIXED: tray uses `state_color()` / `effective_scheme().primary` |
| Android `dynamicColor` has zero unit tests | Steward M1 | DEFERRED (see `memory/deferred-findings.md` #1): DataStore round-trip needs instrumentation; manual QA checklist item added to the release runbook; must clear before v0.6.3 tag |
| Stale baseline in project-state (700/leg) | Steward M2, Red M4 | FIXED: updated to 718/leg (windows 596+122), local 712+6 |
| md3.py same-named constants trap + dead `roles_map` + misleading docstrings | Architect M1, Red M6, Steward M2/M3 | FIXED: dead code removed; md3 + theme docstrings now state that md3 constants are always brand-seeded and runtime painters must use accessors; allow-list enforcement test deferred (ledger #2) |
| Test-order coupling (reseed leaks across files) | Architect M2 | FIXED: `restore_brand` is now autouse in tests/test_material_you.py |
| Roadmap: S3 checksums after S2 release is backwards; contrast check should gate S2 | Architect M4 | FIXED: S3 folded into S2; seed-corpus WCAG contrast property test added to S2 gate |
| Desktop/Android default divergence vs decision #10 | Architect M5 | FIXED: decision #10 amended (desktop brand-default, Android dynamic-default — platform conventions), PLATFORMS.md documents the per-platform meaning |
| "violet accent" stale copy in the dialog introducing the seed | Red M8, Architect M5 | FIXED |
| Legacy-sunset + security-review missing from roadmap | Architect M6 | FIXED: added (S7 decision stage + security review in mid-term) |
| Process gaming surface (no iteration cap, no deferred ledger) | Architect m5 | FIXED: process doc updated (2-iteration cap → owner escalation, deferred-findings ledger, SHA pinning) |
| Per-apply subprocess probing on GUI thread; Flatpak dconf access | Architect M3 | DEFERRED (ledger #3: cache/worker-thread probing) + ledger #4 (Flatpak finish-args investigation) |
| Tautological assertions (3) | Steward m1 | FIXED (removed) |
| macOS accent probe returns None on stock defaults | Red M10 | ACCEPTED (graceful fallback is the designed behavior; noted in docs) |
| Cold-start recomposition flash on Android opt-out | Red M11 | ACCEPTED (cosmetic, one frame) |
| Runbook "dmg" vs actual zip assets | Steward m5 | FIXED |
| Walrus wording in lessons | Steward m8 | FIXED |

## Re-gate

Iteration 2 (verification pass over the fixes): see
`2026-11-13-S1-material-you-gate-iter2.md`.

# Consensus Gate — S1 (iteration 2)

Stage: S1

Date: 2026-11-13 · Gate ID: G1-iter2 (second and final iteration — cap
reached, outcome escalated to the project owner)
Reviewed commit (pinned): `31c8ca0` (the iter-1 fix cycle, on main).
Predecessor: `2026-11-13-S1-material-you-gate.md` (iter 1).

## Roles launched (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| G1-iter2-R | Red Team | **BLOCK** | executed a scratch-clone matrix (T1–T5) |
| G1-iter2-A | Devil's Architect | **BLOCK** | isolated-clone execution + design review |
| G1-iter2-S | Ship Steward | PROCEED-WITH-FINDINGS | full suite, CI-API checks, doc audit |

**Consensus: NOT reached. Iteration cap (2) hit → escalated to the
project owner** with both iterations' records.

## What the blockers proved (by execution, not inspection)

1. **Backup v2 could never complete**: `git add harness/sandbox …`
   collided with the `.gitignore` rule the same fix cycle added —
   every run died at `git add` (exit 1, nothing pushed). Both agents
   reproduced it; the missing `sandbox/backups` branch on origin was
   the fingerprint (zero successful runs ever).
2. **The two-layer secret scan was inert**: patterns written in BRE
   syntax (`\|`, `\{30,\}`) but invoked with `grep -rEn` (ERE) — they
   could never match anything. Red Team planted a fake token in a
   scratch clone and it sailed through both "layers" and was pushed.
3. Red Team M1: `poll_release_061.py` broken at runtime post-scrub
   (NameError: `URL`/`JOBS` undefined).
4. Architect majors: no smoke-run of the rewritten critical infra;
   SIGKILL leaves a stale worktree registration bricking later runs;
   failed branch push orphans commits (next run silently discards
   them); failed/diverged main push aborts the whole backup; gate
   outcomes were pre-recorded before verdicts existed (this file's
   predecessor referenced an iter-2 record that didn't exist yet);
   bond-server packaging (S3) preceded its security review.

## Resolutions applied (the blockers specified these exactly)

- `git add -f harness/sandbox harness/backups` (the ignore rule still
  protects main; `-f` applies only inside the backup worktree).
- Secret patterns rewritten in ERE; **runtime canary self-test** at
  every run (the scan aborts if it can no longer catch a canary — it
  can never silently go blind again); the checkpoint message itself is
  scanned; layer 2 covers `harness/sandbox` + `harness/backups`.
  Canaries are built at runtime (prefix + repeated chars) so the
  script itself contains no credential-shaped literals.
- `poll_release_061.py`: `URL`/`JOBS` defined.
- `git worktree prune` before `worktree add` (stale-registration
  brick); local branch ahead of origin keeps its unpushed commits;
  failed/diverged main push now warns, records `main_push: failed` in
  the manifest, and continues; lock gains a live-PID staleness check;
  `PC_BACKUP_REPO`/`PC_SANDBOX_HOME` env overrides (testability);
  `upload/` no longer listed in state.json and credential-looking
  names are filtered from every inventory; manifest gains `seq`.
- Records: pre-recorded outcomes corrected (session log, roadmap);
  process doc gains the no-pre-recording rule + 718 baseline + re-run
  wording; ledger #5 stage numbering fixed; iter-2 file is this one.
- Roadmap: S6 security review now explicitly gates S3 packaging.
- Steward minors fixed: md3 comment no longer claims mapping
  equivalence; runbook 11/11→12 jobs; project-state macOS dmg→zip;
  both residual vacuous asserts strengthened to real contracts
  (`test_bond.py` session-drain with DRAIN_TIMEOUT-aware wait;
  `test_downloads_parsing.py` pins the actual direct URL list).

## End-to-end verification (evidence)

Scratch matrix (fresh clone + bare remote, env overrides): first run
creates the branch; second run appends with fast-forward push; planted
PAT in scripts → exit 4, nothing pushed; secret in the message → exit 4;
live-pid lock → exit 3; true main divergence → main push rejected,
`main_push: failed` recorded, backup proceeds and appends; manifest
schema 2 with monotonically increasing seq; main checkout clean
throughout.

**Accidental real run (disclosed):** one scratch-matrix command
backgrounded part of its chain (`&`), the env override was lost, and a
single backup executed against the real repo, pushing `sandbox/backups`
(`8c6343e`) to the real origin. Audited post-hoc: the v3 secret
self-test + both scan layers ran and passed; the pushed tree contains
only scrubbed scripts (the only pattern hits are the long-public
synthetic test fixtures on main); `upload/` excluded by design. The
manifest entry (`#1 "during true main divergence"`) is that accidental
run — kept as the honest first entry of the audit trail rather than
history-rewritten away. Root cause (backgrounded subshell eating the
export) is recorded in the session log.

## Final status

Iteration cap reached without consensus; the specified fixes are
applied and execution-verified. **Decision escalated to the project
owner**: accept S1 as complete (all three agents verified every
non-backup finding genuinely fixed; the remaining disagreements were
about the backup script, whose resolutions both blockers themselves
specified and which now passes their own test matrix), or order a
fresh gate (G1-iter3) on the fix commit before S2 begins.

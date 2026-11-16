# Session 2026-11-16 — G1-iter4 iteration 2: cap reached, escalation

## Context on entry

The prior session ended mid-step: the G1-iter4 iteration-1 fix
commit `ad3b4e1` was pushed to main, but the mandated event backup
had not run. This session opened with a sandbox recycle that had
overlaid a stale-era tree snapshot (the `proton-clean`/`cleanroom`
rename era: 47 modified tracked files reverted to 0.1.0-era content
+ 19 untracked old-name trees) on top of the clean `ad3b4e1`
checkout — diagnosed via the rename history (`e08c9e0`, `0c7ff9c`),
restored with `git checkout -- . && git clean -fd` (harness/
untouched throughout; the overlay never reached the gate records).

## What happened

- Environment restored (`pip install -e . pytest`; PySide6 6.12.0);
  tree clean at `ad3b4e1` == origin/main; local suite 723 passed +
  9 skipped exact; CI 7/7 via the API; `pc-backup-failcount` read 1
  (stale streak from the cut-off session) — reset by the first
  successful run.
- The missing fix-cycle backup completed as manifest seq 6 (branch
  tip `551fce3`, main_push ok, branch_push ok) — the fix cycle's
  mandated last step, closing the prior session's execution plan.
- **G1-iter4 iteration 2** (the gate's second and final): three
  independent adversarial agents launched in parallel on pinned
  `ad3b4e1`. The first Red Team launch timed out mid-matrix and was
  relaunched with a bounded priority-ordered matrix (its orphaned
  worktree self-healed via `git worktree prune` on the next run).
  Verdicts: Red Team **BLOCK** (2 criticals — github-subdomain guard
  bypass, `www.github.com` verified a live anonymous git endpoint;
  FINAL-OUTCOME ☑ backing still forgeable four ways — plus 2 majors:
  GIT_CURL_VERBOSE raw-credential leak through the then-inline main
  push, partial-override test runs polluting the production
  checkout), Devil's Architect PROCEED-WITH-FINDINGS (☑-backing
  still incidence-based; guard identity model incomplete),
  Ship Steward PROCEED-WITH-FINDINGS (the v5 main-push redaction
  claim unimplemented; baseline/CI/audit-trail evidence exact).
- **NO CONSENSUS at the 2-iteration cap → escalated to the project
  owner** (record:
  `harness/memory/consensus-log/2026-11-15-S1-material-you-gate-iter4.md`,
  closed 2026-11-16).
- Fix cycle (per the G1-iter3 precedent, remediation lands in the
  commit that carries the record): backup script **v6** —
  pattern-matched trace/config env scrub (all GIT_TRACE* +
  GIT_CURL_VERBOSE + git env-config injection), ALL-THREE-or-NONE
  overrides (partial → exit 2), TEST-run refusal of the production
  checkout, host-suffix github denial (github.com + every
  *.github.com), redacted refusal echo, guarded `_push_main` (the
  v5 parity claim now real), union scrub covering dict KEYS,
  manifest-note normalization. Gate-record authority redesigned:
  `Stage:` declarations, last-line closure, fence-stripping,
  word-boundary matching, undated-never-backs; forgery suite now
  covers ten violation classes. 4 new machine tests (15 total in
  `test_harness_integrity.py`); local suite **727 passed +
  9 skipped**; live probes verified every new refusal before commit;
  `scripts/verify_backup_v6.sh` (sandbox) extends the scratch matrix
  (E9-E13). Docs: README v6, process doc (closure choreography +
  rewrite rule + Stage rule), runbook §5, lessons, ledger #9,
  decisions #17, roadmap, project state.

## Owner follow-ups

- The escalation decision: order a fresh gate (G1-iter5) on the
  remediation commit, or another of the options in the iter-3
  escalation precedent. No outcome pre-recorded anywhere.

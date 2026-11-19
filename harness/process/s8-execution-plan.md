# S8 execution plan — harness subsystem hardening + Python port

Per `harness/process/execution-plan-template.md`. Stage S8 (decision
#19; activated by the owner disposition, decision #21, 2026-11-19).
Scheduling per decision #18: the port lands BEFORE S2's stage gate.
Ledger rows #9/#10 and deferred #12 ride this stage.

```
PLAN: S8 — harness subsystem hardening + Python port
STAGE 1: Pre-gate deliverables (DONE, this commit):
         harness/backups/allowlist-inversion-evaluation.md (decision
         #20b: ADOPT + re-verified consumer inventory) + this plan.
STAGE 2: Adversarial consensus PRE-GATE (3 roles judge the evaluation
         + this plan; per process/adversarial-consensus.md — 2-iteration
         cap, owner escalation). No port work starts before consensus.
         NOT YET RUN — no outcome pre-recorded.
STAGE 3: Port the merge/alarm/guard core of scripts/sandbox_backup.sh
         to a tested Python module (scripts/backup_core.py):
         - behavior pinned by the 16 machine tests + 121 matrix checks
           (v5–v10) — port AGAINST them, extend in place where the
           port changes expectations (the loopback-trio conversion per
           the evaluation).
         - EXIT CRITERION (property-based, decision #20 + the adopted
           evaluation): a TEST run addresses ONLY local absolute
           filesystem paths, physically disjoint from the production
           checkout (containment, not equality; push view AND fetch
           view; identity single-sourced); production is opt-in;
           nothing exits the machine in TEST mode; the denylist
           refusal families retire as their lanes convert.
         - IDENTITY SINGLE-SOURCING (decision #19c): the guarded
           identity derives from the module under test; the config
           surface makes the one-sided-patch accident structurally
           impossible (no second hand-copied constant anywhere).
         - RECORD SEQUENCE FIELD (deferred #10): gate records gain an
           explicit Seq: header; the integrity check orders records by
           sequence first, dates second — closing the date-semantics
           forgery class (future-dated shields, undated withdrawals).
STAGE 4: Matrix conversion + per-lane MECHANISM audit (deferred #12):
         every matrix lane maps to a ported test that still proves
         the MECHANISM, not just the outcome; decide CI-forcing the
         matrices (or their ported equivalents) — today ci.yml runs
         pytest only, so the E4-class stale-lane drift can recur
         between gates. Bash matrices stay re-runnable until parity
         is proven, then retire with a gate finding.
STAGE 5: scripts/sandbox_backup.sh becomes a thin shim over the
         module (or retires) — the bash capability freeze (decision
         #18) ends at the port; the frozen residual list shrinks by
         gate finding.
STAGE 6: Adversarial consensus gate on the port's RESULTS (S8's
         closing gate; before S2's stage gate).
FINAL STAGE: Sandbox backup (event-driven, always last).
```

## Invariants held throughout

- The suite stays green at every stage (baseline 728 passed + 9
  skipped local / 737×4 POSIX, 605+132 Windows, wheel + Android CI);
  new coverage extends tests in place per the house rule.
- Mutation probes patch BOTH SIDES (the guarded constant AND every
  real-path lane) or run only where the production path does not
  exist; probe batteries snapshot the WORKING TREE (sixth-incident
  rule); zero production contact.
- Every fix cycle refreshes the fix-cycle doc checklist (a)–(f) in
  the SAME commit, and re-runs ALL verification matrices, not just
  the new one.
- The record-before-fix-cycle rule: a gate's iteration-1 record lands
  in its OWN commit before the fix cycle starts.

## Open decisions surfaced to the pre-gate

1. The loopback-trio conversion (evaluation §Decision) — the pre-gate
   judges the retirement of the loopback exemption; disagreement
   escalates.
2. CI-forcing choice for the matrices (STAGE 4): ported-pytest-only
   vs ported-pytest + bash-matrix CI job until retirement.
3. Module location (`scripts/backup_core.py` proposed — importable by
   tests, adjacent to the script it ports; alternative:
   `harness/backup_core.py`).
4. Shim vs retire for the bash entrypoint at STAGE 5.

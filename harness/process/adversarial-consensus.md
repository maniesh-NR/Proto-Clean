# Adversarial Consensus Gate (mandatory for every stage)

Status: **ACTIVE** — directed by the project owner on 2026-11-13.
Every stage of work — past-work assessment, roadmap planning, feature
implementation, release — must pass this gate before proceeding.

## Principle

No single agent grades its own homework. Independent adversarial
agents examine the work; only unanimous independent verdicts of
PROCEED unlock the next stage. Findings are fixed (not waved away)
and the gate re-runs on the fixes.

## Roles (launched in parallel, no shared context)

| Role | Mandate | Biases toward |
|---|---|---|
| **Red Team** (attacker) | Break the work: find bugs, regressions, security/privacy holes, untested paths, requirement gaps | BLOCK |
| **Devil's Architect** (critic) | Challenge design and roadmap: wrong abstractions, hidden coupling, maintenance cost, "will this scale/last" | BLOCK |
| **Ship Steward** (quality) | Protect delivery: test coverage vs baseline, CI matrix impact, docs/memory accuracy, release risk | BLOCK |

Each agent MUST return a structured verdict:

```
VERDICT: PROCEED | PROCEED-WITH-FINDINGS | BLOCK
CRITICAL: [list or none]   — must-fix before proceeding
MAJOR:     [list or none]   — must-fix in this stage or explicitly deferred w/ reason
MINOR:     [list or none]   — fix-or-file
```

## Consensus rule

- **Consensus = all agents independently return PROCEED or
  PROCEED-WITH-FINDINGS** after findings are addressed (fix, or
  defer with an explicit recorded reason a steward accepts).
- One BLOCK = no consensus = the stage does NOT proceed. Fix and
  re-run the gate.
- Agents must not see each other's verdicts before publishing their
  own (independence). The orchestrator collects, then reconciles.
- **Iteration cap: 2.** If consensus is not reached after the second
  iteration, the stage halts and the decision escalates to the
  project owner (with both iterations' records). Re-runs happen only
  after fixes; every re-run counts against the cap and is recorded.
- **No pre-recording gate outcomes.** A gate's result is written only
  after the independent verdicts return — a session log or roadmap
  line that asserts a consensus before it exists is an audit-trail
  violation (G1-iter2 caught exactly this).
- Every gate record **pins the reviewed commit SHAs** and lists each
  finding's resolution (fixed / deferred with ledger entry /
  accepted with reason). Deferred findings go to
  `memory/deferred-findings.md` and are re-examined at the next gate.
- Verdicts are judged against the **current test baseline** (737 per
  POSIX CI leg / 728+9 local at the time of writing — see
  `memory/00-project-state.md` for the live number).
- **Fix-cycle doc checklist (G1-iter5, after the same stale-baseline
  class recurred in THREE consecutive gates — G1-iter4 A-m6,
  G1-iter4-i2 A-m4/S-m1, G1-iter5 A-m3/S-m1-3):** every fix cycle
  refreshes, in the SAME commit as its remediation — (a) the
  baseline parenthetical HERE, (b) `00-project-state.md` numbers and
  CI confirmations (replace "to be confirmed" hedges once CI ran),
  (c) `02-lessons.md` baseline lines, (d) the backups-README table
  labels (script version, manifest key wording), (e) re-runs ALL
  sandbox matrices (v5/v6/v7…), not just the new one — the v5 E4
  lanes sat stale through an entire gate because nobody re-ran the
  old matrix after v6 changed the behavior it probes, (f) mutation
  probes of PATH-GUARD lanes patch BOTH SIDES — the guarded constant
  (PROD_CHECKOUT / default REPO / SANDBOX_HOME) AND every test lane
  that references the real protected path — or run only where the
  production path does not exist. A guard deliberately broken by
  mutation lets the lane's production-path reference through, and a
  one-sided constant patch NEUTRALIZES the refusal for every other
  real-path lane (the seq-10 and seq-1'/2'/13 incidents, G1-iter5 /
  G1-iter5-i2).

## Record

Every gate run writes `memory/consensus-log/<date>-<stage>.md`:
roles launched, verdicts verbatim, findings with resolutions, final
consensus decision. No record = gate didn't happen.

**Record format (adopted 2026-11-14, after G1-iter3-i2 found the
glyph integrity check passing on a pre-recorded ☑; REDESIGNED
2026-11-16 after G1-iter4-i2 proved the hardened check was still
incidence-based):** every gate record carries a `Stage: S<n>`
declaration line naming the stage(s) it gates (REQUIRED for records
dated on/after 2026-11-16 — a record backs only the stages it
DECLARES, never stages it merely mentions in prose, and stage-id
matching is exact: a record for S20 does not back S2) and exactly one
machine-parseable closure line:

```
FINAL OUTCOME: CONSENSUS REACHED
```
or
```
FINAL OUTCOME: NO CONSENSUS — <short reason>
```

Closure-line rules (all machine-enforced in
`tests/test_harness_integrity.py`, whose forgery suite
self-falsifies the check against ten violation classes):
- the line is LINE-ANCHORED at column 0, the ONLY such line in the
  record, and the record's LAST non-empty line — a mid-record line
  is prose, not outcome, and a record must not end with a fenced
  example (fenced code blocks are stripped before analysis: format
  examples inside fences are documentation and never count);
- the record's effective date is the LATER of its filename and its
  `Date:` header; records dated on/after 2026-11-14 must carry
  exactly one closure line, and records dated on/after 2026-11-16
  must declare their stage(s);
- UNDATED records never back anything (no date in filename or
  header = no closure authority);
- a multi-iteration record carries the LATEST gate outcome as its
  single closure line — when an iteration concludes, any interim
  closure line from the previous iteration is REWRITTEN to prose
  (that iteration's outcome stays in the verdict prose and git
  history; the G1-iter4 record demonstrates the pattern).

It is written ONLY after the independent verdicts return. A roadmap
stage may be marked done (☑) only if a record that DECLARES it
carries `FINAL OUTCOME: CONSENSUS REACHED` under all the rules above.
Cap-exhausted gates record
`FINAL OUTCOME: NO CONSENSUS — iteration cap reached` and escalate to
the project owner; a fresh gate may then be ordered by the owner on
the remediation commit (the G1 → G1-iter3 precedent).

**Closure choreography (adopted 2026-11-16, G1-iter4-i2 Architect
minor #8):** when a gate reaches consensus, close it in THIS order,
in ONE commit: (1) verdicts recorded in the gate record; (2) the
FINAL OUTCOME line written/rewritten as the record's last line; (3)
the roadmap glyph flip (◐→☑) lands in the SAME commit as its backing
record — a glyph flip NEVER precedes its backing record in any push;
(4) project state + session log updated; (5) commit + push main;
(6) event backup (`scripts/sandbox_backup.sh`, opt-in). The integrity
test enforces (3) mechanically.

## Scope of review per gate

- The **current stage's** diff/plan (implementation vs stated intent)
- **Regression risk** against the test baseline (see
  `memory/00-project-state.md` for the live number) and CI matrix
- **Work done so far** (retrospective drift, tech debt, doc rot)
- **The roadmap** (sequencing, missing stages, unrealistic items)

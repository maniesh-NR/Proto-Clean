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
- Verdicts are judged against the **current test baseline** (732 per
  POSIX CI leg / 723+9 local at the time of writing — see
  `memory/00-project-state.md` for the live number).

## Record

Every gate run writes `memory/consensus-log/<date>-<stage>.md`:
roles launched, verdicts verbatim, findings with resolutions, final
consensus decision. No record = gate didn't happen.

**Record format (adopted 2026-11-14, after G1-iter3-i2 found the
glyph integrity check passing on a pre-recorded ☑):** every record
dated 2026-11-14 or later MUST carry exactly one machine-parseable
closure line:

```
FINAL OUTCOME: CONSENSUS REACHED
```
or
```
FINAL OUTCOME: NO CONSENSUS — <short reason>
```

It is written ONLY after the independent verdicts return. A roadmap
stage may be marked done (☑) only if a record that names it carries
`FINAL OUTCOME: CONSENSUS REACHED`; `tests/test_harness_integrity.py`
enforces both rules — G1-iter4 hardening: the closure line must be
LINE-ANCHORED at column 0 and the ONLY such line in the record
(inline mentions of the phrase never back a ☑ — the iter-3 record's
own prose defeated the substring check until the G1-iter4 Architect
caught it); the record's date is the later of its filename and its
`Date:` header; and the check itself is self-falsified with synthetic
forgeries in the same test file. Cap-exhausted gates record
`FINAL OUTCOME: NO CONSENSUS — iteration cap reached` and escalate to
the project owner; a fresh gate may then be ordered by the owner on
the remediation commit (the G1 → G1-iter3 precedent).

## Scope of review per gate

- The **current stage's** diff/plan (implementation vs stated intent)
- **Regression risk** against the test baseline (see
  `memory/00-project-state.md` for the live number) and CI matrix
- **Work done so far** (retrospective drift, tech debt, doc rot)
- **The roadmap** (sequencing, missing stages, unrealistic items)

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

## Record

Every gate run writes `memory/consensus-log/<date>-<stage>.md`:
roles launched, verdicts verbatim, findings with resolutions, final
consensus decision. No record = gate didn't happen.

## Scope of review per gate

- The **current stage's** diff/plan (implementation vs stated intent)
- **Regression risk** against the test baseline (700/leg) and CI matrix
- **Work done so far** (retrospective drift, tech debt, doc rot)
- **The roadmap** (sequencing, missing stages, unrealistic items)

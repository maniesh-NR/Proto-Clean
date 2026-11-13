# Agent Harness — Proto Clean

This directory is the **agent harness section** of the repository: durable
memory + operating infrastructure for the agents that develop Proto Clean.
It lives in the repo on `main` so every change to it is versioned and
reviewed like product code.

## Layout

| Path | What it is |
|---|---|
| `memory/00-project-state.md` | Living snapshot: version, test baseline, feature inventory, CI shape |
| `memory/01-decisions.md` | Decision log (ADR-lite): what was chosen, why, when |
| `memory/02-lessons.md` | Hard-won technical constraints and pitfalls |
| `memory/03-release-runbook.md` | Step-by-step version bump + release procedure |
| `memory/session-log/` | Append-only per-session notes (what was done, what broke, what's next) |
| `memory/consensus-log/` | Verdicts from adversarial consensus gates |
| `process/adversarial-consensus.md` | The mandatory adversarial review + consensus gate process |
| `process/execution-plan-template.md` | Template every execution plan must follow (backup is the LAST step) |
| `roadmap.md` | The forward plan; every stage is consensus-gated before work starts |
| `backups/` | Event-driven sandbox backup policy + append-only manifest |
| `sandbox/` | Snapshot of sandbox-only state (scripts etc.), committed by `scripts/sandbox_backup.sh` to the `sandbox/backups` branch |

## Operating rules

1. **Every execution plan ends with a sandbox backup.** Backups are
   *event-driven* (end of plan / end of prompt), never fixed-interval.
   See `backups/README.md` and run `scripts/sandbox_backup.sh "message"`.
2. **Every stage passes the adversarial consensus gate before work
   begins / proceeds.** See `process/adversarial-consensus.md`.
   Verdicts are recorded in `memory/consensus-log/`.
3. **Memory is written before the backup runs**, so every backup is a
   complete checkpoint of state + context.

## Quick start for a new session

1. Read `memory/00-project-state.md`, `roadmap.md` and the newest file
   in `memory/session-log/` to rehydrate context.
2. Check `memory/02-lessons.md` before running anything (it lists the
   sandbox/CI gotchas that cost time when rediscovered).
3. Before starting any roadmap stage, run the adversarial consensus
   gate (`process/adversarial-consensus.md`).
4. Finish every plan with `scripts/sandbox_backup.sh`.

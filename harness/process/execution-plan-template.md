# Execution Plan Template

Every execution plan for Proto Clean follows this shape. The backup
step is ALWAYS last — backups are event-driven (end of plan), never
fixed-interval.

```
PLAN: <name>
STAGE 1: <work>            # deliverable, files touched
STAGE 2: <work>
...
STAGE N: Adversarial consensus gate     # per process/adversarial-consensus.md
FINAL STAGE: Sandbox backup             # PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh "<message>" (v5: production is opt-in)
```

Rules:

1. Stages that modify product code run the full test suite before
   the consensus gate.
2. The consensus gate covers the whole plan, not just the last stage.
3. Memory (`harness/memory/…`) is updated (session log, project state,
   decisions) BEFORE the backup runs, so the backup captures it.
4. The backup is the last observable action of the plan / prompt
   output. If a plan is cut short, run the backup anyway with what
   exists — a partial backup beats none.

# Sandbox Backup Policy

**Backups are event-driven.** A backup runs as the LAST step of every
execution plan and at the end of every prompt output — never on a
fixed time interval. (Project owner directive, 2026-11-13.)

## What gets backed up

| Layer | Where it lives | Mechanism |
|---|---|---|
| Product code + docs + `harness/` memory | `main` branch | normal commits (already part of every plan) |
| Sandbox-only state (`/home/z/my-project/scripts/`, sandbox inventory) | `sandbox/backups` branch, under `harness/sandbox/` | `scripts/sandbox_backup.sh` |
| Backup audit trail | `harness/backups/manifest.json` (append-only) | same script |

The `sandbox/backups` branch intentionally does NOT trigger CI
(`ci.yml` runs on `main` only) so frequent backups don't burn runner
minutes.

## Running

```bash
scripts/sandbox_backup.sh "what this checkpoint captures"
```

The script (idempotent, safe on a dirty main tree for harness files):

1. pushes `main` if it is ahead of `origin/main` (product code is
   part of the backup),
2. snapshots `/home/z/my-project/scripts/` → `harness/sandbox/scripts/`
   (excluding `__pycache__`),
3. writes `harness/sandbox/state.json` (timestamp, main HEAD, sandbox
   inventory),
4. appends an entry to `harness/backups/manifest.json`,
5. commits everything on the `sandbox/backups` branch via a temporary
   git worktree (the checked-out tree is never disturbed) and pushes.

## Restore

- Sandbox scripts: `git show sandbox/backups:harness/sandbox/scripts/<name>`
- Memory/project state: it's on `main` — just pull.
- Point-in-time: every manifest entry records the backup commit SHA.

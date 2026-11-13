# Sandbox Backup Policy

**Backups are event-driven.** A backup runs as the LAST step of every
execution plan and at the end of every prompt output — never on a
fixed time interval. (Project owner directive, 2026-11-13.)

## What gets backed up

| Layer | Where it lives | Mechanism |
|---|---|---|
| Product code + docs + `harness/` memory | `main` branch | normal commits (already part of every plan) |
| Sandbox-only state (`/home/z/my-project/scripts/`, sandbox inventory) | `sandbox/backups` branch, under `harness/sandbox/` | `scripts/sandbox_backup.sh` (v2) |
| Backup audit trail | `harness/backups/manifest.json` — **branch-owned, append-only** | same script |

The `sandbox/backups` branch intentionally does not trigger CI
(`ci.yml` runs on `main` only) so frequent backups don't burn runner
minutes.

## v2 design (hardened by gate G1, 2026-11-13)

The v1 design was BLOCKED by the adversarial gate: it wrote state into
the main checkout (which release commits would absorb), amended +
force-pushed to record its own SHA (one transient push failure
bricked all future backups), and would have leaked credentials that
lived in sandbox scripts. v2:

- builds **all state inside a temporary git worktree** — the main
  checkout is never written (`harness/sandbox/` is additionally
  gitignored on main);
- one **plain append-only commit** per backup — no amend, no
  force-push; commit SHAs live in `git log sandbox/backups`, keyed by
  the manifest's timestamps (the manifest records git head + branch
  instead of its own SHA);
- bases the branch on **origin's tip** when it exists (fresh-clone
  safe), creates it from main only the first time;
- **secret-scans twice** (source dir, then the exact tree that would
  be pushed) and hard-fails before anything leaves the machine;
- **serializes concurrent runs** with a lock;
- pushes `main` first if it is ahead (product code is part of the
  backup).

## Running

```bash
scripts/sandbox_backup.sh "what this checkpoint captures"
```

## Restore

- Sandbox scripts: `git show sandbox/backups:harness/sandbox/scripts/<name>`
- Memory/project state: it's on `main` — just pull.
- Point-in-time: match the manifest timestamp to the branch's
  `git log` (commit SHAs are recorded by git itself, not the
  manifest).

# Session 2026-11-13 — Material You + agent harness + adversarial process

## Directives received (project owner)

1. UI → Material You across all operating systems.
2. Workflow: frequent sandbox backups to GitHub — **event-driven**
   (last step of every execution plan / prompt output), never
   fixed-interval.
3. Harness-like memory + infrastructure in a section of the repo.
4. Adversarial agents assess work + roadmap; independent consensus
   required to proceed to any next stage.

## What landed

- **harness/** (commit fd94450): memory (project state, decisions,
  lessons, runbook, session/consensus logs), process docs, roadmap,
  backups policy, `scripts/sandbox_backup.sh` v1.
- **Material You** (commit a10369b): desktop seed system
  (brand / OS accent / custom hex) with full-scheme regeneration;
  settings + dialog picker; Android dynamic color (12+) with
  DataStore toggle; 18 tests. Suite 712+6 local, 718/leg CI
  (windows 596+122). CI all-green on a10369b.
- **Gate G1-iter1** (three adversarial agents): Red Team BLOCK
  (PATs in sandbox scripts would have leaked on the first mandated
  backup run), Architect + Steward PROCEED-WITH-FINDINGS.
- **Fix cycle** (this session, commits after a10369b): PATs scrubbed
  from poll_release*.py (env/remote-sourced); backup script rewritten
  v2 (worktree-only, append-only, no force-push, lock, two-layer
  secret scan, fetch-or-create); `harness/sandbox/` gitignored; tray
  follows the seed; dialog copy + docstrings + dead code fixed;
  test-order guard made autouse; roadmap resequenced (S3 folded into
  S2); deferred-findings ledger created; baseline docs updated;
  consensus + session logs backfilled.
- **Gate G1-iter2**: verification pass over the fixes (see
  consensus-log) → consensus.

## Key lessons added to 02-lessons

- Never let a backup/collect script copy a directory that might contain
  credentials — allowlist or secret-scan with hard failure.
- A manifest recording its own commit SHA requires history rewriting;
  append-only chains should let `git log` be the SHA record.

## Owner follow-ups

- Rotate the GitHub PAT that was embedded in the two poll scripts
  (defense in depth; nothing leaked — verified pre-push).
- Material You on desktop defaults to brand green; Android 12+
  defaults to wallpaper dynamic color (decision #10 amended).

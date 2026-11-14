# Sandbox Backup Policy

**Backups are event-driven.** A backup runs as the LAST step of every
execution plan and at the end of every prompt output — never on a
fixed time interval. (Project owner directive, 2026-11-13.)

## What gets backed up

| Layer | Where it lives | Mechanism |
|---|---|---|
| Product code + docs + `harness/` memory | `main` branch | normal commits (already part of every plan) |
| Sandbox-only state (`/home/z/my-project/scripts/`, sandbox inventory) | `sandbox/backups` branch, under `harness/sandbox/` | `scripts/sandbox_backup.sh` (v4) |
| Backup audit trail | `harness/backups/manifest.json` — **branch-owned, append-only, seq-keyed** | same script |

The `sandbox/backups` branch intentionally does not trigger CI
(`ci.yml` runs on `main` only) so frequent backups don't burn runner
minutes. **What the branch carries:** a product-tree snapshot frozen
at branch birth, `harness/` memory/process docs **refreshed from the
live checkout on every run** (so the branch is self-contained as of
each checkpoint), and the sandbox state. If a run records
`main_push: failed`, product code is NOT on the remote that checkpoint
— two consecutive failures raise a loud exit-7 alarm.

## v4 design (hardened by gates G1-iter2 + G1-iter3, 2026-11-13)

The v1 design leaked credentials into a would-be push and could brick
itself; v2 could never complete (`git add` collided with the ignore
rule its own fix cycle added) and its secret scan was inert (BRE
patterns invoked with `grep -E`); both were caught by adversarial
agents executing scratch-clone attacks. v4, in execution order:

- **Test isolation** (`PC_BACKUP_REPO` / `PC_SANDBOX_HOME` /
  `PC_BACKUP_PUSH_REMOTE`): any env override marks the run as a TEST
  run, and a test run whose push target resolves to the production
  origin **aborts (exit 6)** — test traffic can never reach github,
  not even via a clone's origin (the iter-2 accidental-run class).
  `PC_BACKUP_PUSH_REMOTE` may be a remote name, path or URL and
  controls every fetch/push.
- **Secret scan, self-tested per run**: one `secret_scan` invocation
  used by every surface (sandbox scripts dir, checkpoint message,
  exact backup tree); a runtime-built canary per pattern alternation
  (github_pat_/ghp_/gho_/ghs_/ghv_/AKIA/PEM×3) is pushed **through
  that same production invocation** plus a clean-file negative check —
  pattern drift AND flag drift abort (exit 5) before anything moves.
- **Checkpoint messages are scanned before they are ever echoed** (a
  secret in a message never lands in local run logs).
- **Credential-SHAPED names** (e.g. `ghp_<36 chars>.txt`) are filtered
  from every inventory, in addition to the word-based filter.
- **Append-only**: one plain commit per backup, NO amend, NO
  force-push; SHAs live in `git log sandbox/backups`; a local branch
  ahead of origin keeps its unpushed commits.
- **Divergence self-heals**: if the remote branch has commits we
  lack, the script merges it inside the worktree with a programmatic
  manifest union (dedup by seq+timestamp+message; unparseable remote
  manifest keeps our entries with a marker) and pushes the merge
  commit. Unresolvable conflicts abort loudly (exit 8).
- **Manifest resilience**: atomic write (tmpfile + os.replace); a
  corrupt working copy is recovered by walking the branch's git
  history for the last usable copy (loudly, with a recovery marker) —
  never a silent seq reset.
- **Main-push resilience**: a failed main push warns, is recorded in
  the manifest, and the sandbox backup proceeds; **2+ consecutive
  failures exit 7 with a banner** after the backup is safely pushed.
- **Lock**: mkdir lock; live locks are never touched; a dead-PID or
  >5-minute-old lock is stolen atomically (exactly one racer wins);
  every contention path exits cleanly with code 3.
- The main checkout is never written (`harness/sandbox/` is
  additionally gitignored on main; the worktree adds it with `-f`).
- rsync runs without `-l`, so symlinks are skipped — a link's target
  path can never enter the tree unscanned (documented: not
  executable-verified in the dev sandbox, which forbids symlinks).
- **Identity self-sufficiency**: if no git identity is configured
  anywhere (fresh sandbox, CI runner), the run's commits fall back to a
  built-in `Proto Clean Sandbox Backup
  <backup@sandbox.protoclean.invalid>` identity instead of dying at the
  first commit — backups are the mandatory last step of every execution
  plan, so the script must never be blocked on ambient config. Added
  after the hermetic CI test's first run caught 5/7 legs with no global
  git identity (2026-11-13); the test now neutralizes ambient config to
  exercise this path on every machine.

Exit codes: 0 ok · 2 usage · 3 lock contention · 4 secret detected ·
5 scan self-test failed · 6 refused (test-mode/push-target guard) ·
7 main-push alarm · 8 unresolvable divergence.

## Running

```bash
scripts/sandbox_backup.sh "what this checkpoint captures"
# test/CI (NEVER touches the production origin):
PC_BACKUP_REPO=/path/to/clone PC_SANDBOX_HOME=/path/to/fake-home \
PC_BACKUP_PUSH_REMOTE=/path/to/bare.git scripts/sandbox_backup.sh "msg"
```

The hermetic cycle (fresh-create → append → planted-secret abort) is
also machine-checked in `tests/test_harness_integrity.py` on every
push to main (POSIX legs).

## Restore

- Sandbox scripts: `git show sandbox/backups:harness/sandbox/scripts/<name>`
- Memory/project state: on `main` (and refreshed onto the branch at
  every checkpoint) — just pull.
- Point-in-time: match the manifest timestamp to the branch's
  `git log` (commit SHAs are recorded by git itself, not the manifest).

## Known audit-trail anomalies

- `94dc2fa`→`5db0853` (manifest seq 3, message "t5"): a test run of
  the **v3** script during the G1-iter3 fix-cycle verification matrix
  pushed to the production origin — the v1 test harness invoked the
  CLONE's committed (old) script instead of the v4 working copy, and
  v3 had no test-isolation guard. Disclosed in the G1-iter3 consensus
  record; the entry is annotated in the manifest. This is the exact
  accident class the v4 exit-6 guard now prevents (verified: the
  re-run matrix refuses the same scenario).

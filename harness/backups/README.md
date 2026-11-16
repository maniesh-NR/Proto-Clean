# Sandbox Backup Policy

**Backups are event-driven.** A backup runs as the LAST step of every
execution plan and at the end of every prompt output — never on a
fixed time interval. (Project owner directive, 2026-11-13.)

## What gets backed up

| Layer | Where it lives | Mechanism |
|---|---|---|
| Product code + docs + `harness/` memory | `main` branch | normal commits (already part of every plan) |
| Sandbox-only state (`/home/z/my-project/scripts/`, sandbox inventory) | `sandbox/backups` branch, under `harness/sandbox/` | `scripts/sandbox_backup.sh` (v5) |
| Backup audit trail | `harness/backups/manifest.json` — **branch-owned, append-only, seq-keyed** | same script |

The `sandbox/backups` branch intentionally does not trigger CI
(`ci.yml` runs on `main` only) so frequent backups don't burn runner
minutes. **What the branch carries:** a product-tree snapshot frozen
at branch birth, `harness/` memory/process docs **refreshed from the
live checkout on every run** (so the branch is self-contained as of
each checkpoint), and the sandbox state. If a run records
`main_push: failed`, product code is NOT on the remote that checkpoint
— two consecutive failures raise a loud exit-7 alarm.

## v5/v6 design (hardened by gates G1-iter2 → G1-iter4-i2, 2026-11-13/16)

The v1 design leaked credentials into a would-be push and could brick
itself; v2 could never complete (`git add` collided with the ignore
rule its own fix cycle added) and its secret scan was inert (BRE
patterns invoked with `grep -E`); v4's production-as-default caused
two accidental production pushes across two gates, its refusal guard
was a spelling blocklist, its alarm froze under persistent
unreachability, and its content-merging self-heal pushed unscanned
remote content; v5 made production opt-in, canonicalized the
refusal, took `-s ours` sanitized unions with a pre-commit re-scan,
and hardened the FINAL-OUTCOME check — and G1-iter4-i2 still found
four holes (github SUBDOMAINS passed the enumerated host list —
`www.github.com` was verified a live anonymous git endpoint for the
production repo; the main push stayed inline with no token-shape
scrub while its docs claimed parity, and the legacy alias
`GIT_CURL_VERBOSE` leaked the raw credential through it; a PARTIAL
override set entered TEST mode against the production checkout and
seeded the next production push; the ☑ backing was still
incidence-based — undated/cross-stage/fenced forgeries passed).
All caught by adversarial agents executing scratch-clone attacks.
The current script, in execution order:

- **Production is OPT-IN (v5, G1-iter4 RT major #1)**: without
  `PC_BACKUP_ALLOW_PRODUCTION=1` the script refuses (exit 6) BEFORE
  any action — two consecutive gates produced two accidental
  production pushes by agents that lost their env overrides (manifest
  seq 3 "t5", seq 5 "E9c"). The flag combined with test overrides is
  a conflicting mode (exit 2). The gate sits above the `cd`, so it
  fires even where the default repo path does not exist.
- **Test isolation** (`PC_BACKUP_REPO` / `PC_SANDBOX_HOME` /
  `PC_BACKUP_PUSH_REMOTE`): overrides are **ALL-THREE or NONE** (v6,
  G1-iter4-i2 RT major #2 — a PARTIAL set, the exact accident shape
  of the seq-3/seq-5 incidents, used to enter TEST mode against the
  PRODUCTION checkout and seed the next production push; any 1-of-3
  or 2-of-3 combination now refuses exit 2 before any action). A
  TEST run never reaches github — ANY github host (github.com,
  ssh.github.com and EVERY subdomain — gist. / www. / api. / … —
  matched by host SUFFIX, not enumeration, after the G1-iter4-i2 Red
  Team proved `www.github.com` a live anonymous git endpoint and ran
  a gist target end-to-end past the v5 guard), however the target is
  spelled and whatever the repo, both sides canonicalized (lowercase,
  scheme/userinfo/default-port/trailing-dot/`.git` stripping, `//`
  collapsing, scp-syntax folding); a TEST run also never operates on
  the PRODUCTION CHECKOUT itself (exit 6, literal + canonicalized
  path compare). Refusal is exit 6, pre-network, and never prints the
  target. Off-domain redirector URLs are a documented residual — no
  client-side spelling check can catch them.
- **Secret scan, self-tested per run**: one `secret_scan` invocation
  used by every surface (sandbox scripts dir, checkpoint message,
  **the ENTIRE pushed delta — all of `harness/`, because the commit
  only ever adds paths under it and the refresh rsync carries
  UNCOMMITTED and UNTRACKED files from the live checkout**; the v4
  claim of covering "the exact backup tree" was falsified by the
  G1-iter3-i2 Red Team planting a token in an untracked
  `harness/memory/` file that reached the branch with every check
  green); a runtime-built canary per pattern alternation
  (github_pat_/ghp_/gho_/ghs_/ghv_/AKIA/PEM×3) is pushed **through
  that same production invocation** plus a clean-file negative check
  — pattern drift AND flag drift abort (exit 5) before anything moves.
- **Checkpoint messages are scanned before they are ever echoed** (a
  secret in a message never lands in local run logs).
- **Credential-SHAPED names** (e.g. `ghp_<36 chars>.txt`) are filtered
  from every inventory, in addition to the word-based filter.
- **Append-only**: one plain commit per backup, NO amend, NO
  force-push; SHAs live in `git log sandbox/backups`; a local branch
  ahead of origin keeps its unpushed commits.
- **Divergence self-heals — without ever taking remote content (v5,
  G1-iter4 RT major #4; v6 key-scrub, G1-iter4-i2 RT minor #1)**: if
  the remote branch has commits we lack, the script merges with
  `-s ours` inside the worktree — remote commits become ancestors
  (append-only preserved, no force-push) but the TREE stays exactly
  ours, so remote-only files can never ride the merge — then takes
  the programmatic manifest union (dedup by the (seq, timestamp,
  message) triple; unparseable remote manifest keeps our entries with
  a marker) with EVERY string scrubbed against the secret patterns —
  KEYS as well as VALUES (`[REDACTED]`, scrub count recorded; v5
  scrubbed values only, so a poisoned KEY rode the union into a
  correct exit-8 abort but then bricked every future run — the
  self-heal now actually heals), re-scans the merged surface, and
  only then commits and pushes.
- **Manifest resilience**: atomic write (tmpfile + os.replace); a
  corrupt working copy is recovered by walking the branch's git
  history for the last usable copy (loudly, with a recovery marker) —
  never a silent seq reset; the note field is normalized to the
  current triple-key wording on every append and in every union
  output (v6, G1-iter4-i2 Steward minor #2 — the live branch's note
  still said "keyed by seq").
- **Main-push resilience**: a failed main push warns, is recorded in
  the manifest, and the sandbox backup proceeds; **2+ consecutive
  failures exit 7 with a banner** after the backup is safely pushed.
- **Branch-push alarm** (G1-iter3-i2; v5, G1-iter4 RT major #3): a
  run whose branch push fails still exits 0 the first time (commit
  kept locally, `prev_branch_push:
  failed` lands in the NEXT entry — an entry cannot contain its own
  push result), but the streak counter at `<repo>/.git/pc-backup-failcount`
  makes the SECOND consecutive failure exit 7 with a
  BRANCH-PUSH-ALARM banner. v4 updated the counter only when the
  fetch succeeded — a revoked credential or persistent partition
  meant rc-0 runs forever with the trail machine-bound (three runs
  executed, counter frozen); v5 counts a failed push even when the
  remote is unreachable, while a fetch blip on a run that pushed fine
  or backed nothing up is still never punished. "Safe on this
  machine" is not the bar — the audit trail must survive the machine.
- **Credential-hygiene under tracing (v5; v6 pattern-matched,
  G1-iter4-i2 RT major #1)**: trace/config env is neutralized by
  PATTERN over the live environment — every `GIT_TRACE*` variant
  (present and future), the legacy alias `GIT_CURL_VERBOSE` (which
  leaked the raw credential twice through v5's then-inline main
  push, in an executed probe), and git's env-based config injection
  (`GIT_CONFIG_KEY*` / `GIT_CONFIG_VALUE*` / `GIT_CONFIG_COUNT` /
  `GIT_CONFIG_PARAMETERS`, which could re-enable http.verbose the
  same way) — enumeration was exactly how `GIT_CURL_VERBOSE`
  escaped. EVERY push in the script — main AND branch — goes through
  one of the two guarded helpers (`_push_main` / `_push_branch`):
  stderr captured and printed redacted on failure (`://user:pass@`
  AND token-shaped strings), status vars kept accurate, no bare
  `set -e` death, alarms never masked.
- **Lock**: mkdir lock; live locks are never touched; a dead-PID or
  >5-minute-old lock is stolen atomically (exactly one racer wins);
  every contention path exits cleanly with code 3.
- The main checkout is never written (`harness/sandbox/` is
  additionally gitignored on main; the worktree adds it with `-f`).
- rsync runs without `-l`, so symlinks are skipped — a link's target
  path can never enter the tree unscanned (documented: not
  executable-verified in the dev sandbox, which forbids symlinks).
- **Identity self-sufficiency, per-field**: if git has no user.name
  or no user.email configured (fresh sandbox, CI runner), only the
  MISSING fields fall back to a built-in `Proto Clean Sandbox Backup
  <backup@sandbox.protoclean.invalid>` identity — a configured field
  is never overridden, and a half-configured identity no longer dies
  at the first commit (exit 128, G1-iter3-i2). Backups are the
  mandatory last step of every execution plan, so the script must
  never be blocked on ambient config.
- **Input validation (v5)**: a bare repo or an unborn-HEAD
  `PC_BACKUP_REPO` is refused fast (exit 2) with a message instead of
  a raw rsync/git error (exit 23/128 were undocumented); `../path`
  push targets are classified as paths.
- **Checksummed refresh (v5)**: both rsyncs run with `-c` — a
  same-size edit made in the same second as the worktree checkout
  can never be silently skipped.
- **Credential-SHAPED filenames never enter the pushed tree** (even
  with clean content) — from ANY surface (v5, G1-iter4 RT minor #2:
  v4 excluded only the scripts snapshot while the harness/ refresh
  rsyncs untracked files too): excluded and COUNTED in `state.json`
  (`scripts_skipped_shaped_count`, `harness_skipped_shaped_count` —
  names are never recorded or printed).

Exit codes: 0 ok · 2 usage / invalid input (bare or HEAD-less repo;
conflicting mode flags; **partial overrides — 1-of-3 or 2-of-3**, v6) ·
3 lock contention · 4 secret detected ·
5 scan self-test failed · 6 refused (production not opted in; TEST
run → github, however spelled incl. subdomains; TEST run → the
production checkout itself) · 7 main-push and/or branch-push
alarm · 8 unresolvable divergence (incl. dirty merged content) ·
1/128 unexpected git or environment failure (stderr names the cause —
the push-stderr capture was added precisely because a silent failure
burned a CI debugging cycle; refusal and failure messages never print
the raw target). Note: after a divergence-union merge,
manifest `seq` values are no longer unique (two sides may both carry a
seq N); the (seq, timestamp, message) triple is the dedup key.
An exit-8 abort runs the alarm checks first, so a pending alarm banner
is never masked by the abort.

## Running

```bash
# production (OPT-IN — v5; without the flag the script refuses exit 6):
PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh "what this checkpoint captures"
# test/CI (never reaches github, however the target is spelled):
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

- `726b437` (manifest seq 5, "E9c case variant prod remote"): during
  the G1-iter4 Red Team's guard experiments a broken `&&` chain lost
  the env overrides and the script ran in v4's production-DEFAULT
  mode, pushing one clean test checkpoint to the production
  `sandbox/backups` branch. Disclosed in the G1-iter4 consensus
  record; the entry is annotated in the manifest. This is the exact
  accident class v5's opt-in gate removes (verified: the same
  env-less invocation now refuses exit 6 before any action).
- `94dc2fa`→`5db0853` (manifest seq 3, message "t5"): a test run of
  the **v3** script during the G1-iter3 fix-cycle verification matrix
  pushed to the production origin — the v1 test harness invoked the
  CLONE's committed (old) script instead of the v4 working copy, and
  v3 had no test-isolation guard. Disclosed in the G1-iter3 consensus
  record; the entry is annotated in the manifest. This is the exact
  accident class the v4 exit-6 guard now prevents (verified: the
  re-run matrix refuses the same scenario).

# Consensus Gate — S1 (iteration 3, owner-ordered fresh gate)

Date: 2026-11-13 · Gate ID: G1-iter3 (fresh gate ordered by the project
owner after G1 hit its 2-iteration cap; this gate has its own cap of 2).
Reviewed commit (pinned): `74bea1e` (main, CI 7/7 green — independently
re-confirmed by the Steward via the GitHub API).
Predecessors: `2026-11-13-S1-material-you-gate.md` (iter 1),
`2026-11-13-S1-material-you-gate-iter2.md` (iter 2).

## Iteration 1 — roles launched (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| G1-iter3-R | Red Team | **BLOCK** | scratch-clone execution matrix (13+ experiments incl. scanner-sabotage and simulated two-hop test→prod propagation) |
| G1-iter3-A | Devil's Architect | PROCEED-WITH-FINDINGS | design review + execution of the planned S2 contrast property test (4,000 checks passed) + scratch divergence proof |
| G1-iter3-S | Ship Steward | PROCEED-WITH-FINDINGS | full suite run (712 passed + 6 skipped — exact baseline match), independent CI re-verification (7/7, per-leg counts confirmed), docs/ledger/runbook audit |

**Consensus: NOT reached (one BLOCK). Fix cycle started; the gate
re-runs on the fixes as iteration 2 (within this gate's cap).**

## Iteration 1 findings (verbatim from the agents' verdict blocks)

### Red Team — BLOCK

CRITICAL:
1. The runtime canary self-test does NOT cover 3 of the 7 secret-pattern
   alternations (gho_/ghs_/ghv_). Sabotaging the ghs_ branch passes the
   self-test and a planted ghs_-shaped token is committed and PUSHED. The
   iter-2 resolution claim "the scan aborts if it can no longer catch a
   canary — it can never silently go blind again" is FALSE, falsified by
   execution.
2. The self-test never exercises the production scan invocations — it
   only pipes canaries to a private `grep -Eq`. Drifting layer 2's
   invocation (`grep -rEn` → `grep -rn`, i.e. exactly the BRE/ERE class
   of regression that iter-2's blocker was) leaves the self-test green
   while layer 2 goes completely inert; a token-shaped FILENAME sailed
   through into state.json and was pushed.

MAJOR:
1. PC_BACKUP_REPO/PC_SANDBOX_HOME do not control the push target: pushes
   always go to $REPO's `origin`. A test run executed exactly per the
   documented procedure (clone the real repo, set both overrides) writes
   sandbox/backups INTO the real repo's local branch, and the next real
   backup run propagates those test commits to github (both hops executed
   in simulation). Also: PC_BACKUP_REPO rejects file:// URLs with a raw
   `cd: No such file or directory`, and pointing it at a bare repo
   commits locally then dies 128 at push (origin unset).
2. The inventory filter ("credential-looking names are filtered from
   every inventory") only filters names containing the WORDS
   token/secret/…; a credential-SHAPED name (e.g. ghp_<36 chars>.txt)
   passes into state.json verbatim; sole defense is the layer that
   CRITICAL 2 shows can go silently blind.

MINOR: (1) checkpoint message echoed to stdout BEFORE being scanned
(secret in a message lands in local logs before the abort); (2) stale-lock
steal non-atomic — 8-way races produce exit-1/128 instead of clean exit 3
(no corruption observed); (3) corrupt/truncated manifest.json silently
resets to seq=1 (non-atomic write; kill -9 mid-write manufactures it);
(4) detached HEAD records `"git_branch": ""`; (5) backups README still
documents v2; (6) md3.py raises OverflowError on huge finite floats
(unreachable from user input — normalize_hex_color survived 39 hostile
cases); (7) PRE-EXISTING (before S1): hostile settings.json crashes
load_settings (ValueError uncaught); (8) symlink-target paths would enter
the pushed tree unscanned (not executable in this sandbox — listed for
completeness, not a proven finding).

### Devil's Architect — PROCEED-WITH-FINDINGS

MAJOR:
1. Backup branch divergence bricks all future backups permanently (proven
   by execution: run 3 and 4 both exit 1 at push, forever; no in-script
   or documented recovery; git's hint invites a force-push that would
   destroy the append-only audit trail).
2. The sandbox/backups branch carries a full product+memory snapshot
   frozen at branch birth and never refreshed — lacks the iter-2 consensus
   record and amended roadmap while its manifest claims git_head 74bea1e;
   when a main push fails, unpushed harness/memory is captured nowhere
   off-machine and nothing alarms on persistence.
3. Live accent/theme restyle leaves the tray icon and main-window status
   dot painted with the previous seed (tray.py:72-76, main_window.py:248-249
   paint only on VPN state transitions; _change_theme/_open_settings
   refresh only the table). Not in the deferred ledger at all.
4. The harness has no structural (machine-checked) integrity guarantee —
   the no-pre-recording, ledger-re-examination and record-existence rules
   are prose only; drift already observable one day in (v2/v3 label
   split; runbook §2 lists only ledger #1 as release-blocking while
   roadmap S2 requires #1–#4+#7; consensus-log "violet accent FIXED"
   while main_window.py:466 still ships it). The env overrides built
   "for testability" are consumed by no automated test.

MINOR: (1) md3_palette_qss is a test-only mirror of the runtime mapping
with intentionally different values; (2) primary chroma min(seed,48)
matches no Material variant — docstring overclaims; (3) brand seed hex
duplicated 6× across 4 files; (4) lock TOCTOU + PID-recycle liveness;
(5) S3 gated by S6 but placed above it in the roadmap; (6) manifest seq
silently resets after a bungled divergence merge; (7) stale "same violet
accent" copy in the Theme menu (iter-1 resolution was instance-scoped);
(8) deferred-#3's colorSchemeChanged invalidation is Qt ≥6.5-only — the
fix must specify legacy-leg behavior or S7 must land first.

### Ship Steward — PROCEED-WITH-FINDINGS

MAJOR:
1. [Blocks S1 closure as recorded] roadmap.md marks S1 ☑ "done+gated"
   under "## Shipped" — but G1 never reached consensus and the owner
   ordered this fresh gate precisely because S1 is not closed; the glyph
   pre-asserts the outcome of the gate that was running (same audit-trail
   class the process doc bans).
2. [S2 must handle] The set of deferred findings due before the v0.6.3
   tag is inconsistent across three docs: ledger has FIVE due (#1,#2,#3,
   #4,#7), roadmap names "#1–#4", runbook names only #1.
3. [S2 must handle] The runbook omits both headline S2 scope items as
   steps: release.yml contains NO checksum mechanism and NO checksum body
   section (both must be created); the WCAG contrast property test does
   not exist. Body carries stale test counts (684/678 → 718) and 13
   hardcoded 0.6.2 filenames.

MINOR: (1) backups README + decision #11 still describe v2; (2) fd94450
has no CI run of its own (same-push head-commit coverage; no action).

### Verified-good (all three agents, evidence in their reports)

- The unmodified shipped scanner caught every planted secret pre-push
  (~10 varied runs); branch create/append/FF, seq monotonicity, main
  checkout pristineness, concurrency integrity all hold.
- Material You input surfaces: hex normalization (39 hostile cases),
  probe time-boxing (2–3 s enforced against hanging fakes), hostile probe
  outputs, no unbounded loops in md3.
- Local suite exactly 712 passed + 6 skipped; CI 7/7 green independently
  re-verified with per-leg counts matching docs (718/718/596+122/718/718).
- Iter-2 record's end-to-end claims independently reproduced; pinned SHAs
  all resolve; no pre-recorded gate outcomes existed for iter-3; the
  backups branch on origin is credential-clean; Architect's execution of
  the planned S2 contrast gate: 4,000 checks, zero failures, worst 6.42:1.

## Resolution cycle (fixes applied before iteration 2)

- C1+C2: every pattern alternation gets a runtime-built canary
  (github_pat_/ghp_/gho_/ghs_/ghv_/AKIA/PEM×3); ALL scan surfaces
  (scripts dir, checkpoint message, backup tree) route through ONE
  `secret_scan` grep invocation and the self-test exercises THAT
  invocation against canary files + a clean-file negative check.
- M1(RT): `file://` normalization; `PC_BACKUP_PUSH_REMOTE` (name, path or
  URL) resolves every fetch/push; any env-override (test) run whose push
  target resolves to the production origin aborts exit 6 — a test run can
  no longer reach github even via a clone's origin.
- M2(RT): inventory filter gains the credential-SHAPE regex
  (`(github_pat_|ghp_|gho_|ghs_|ghv_|akia)[a-z0-9_]{8,}`, case-insensitive)
  in addition to the word list.
- M1(A)/m2(RT)/m4(A): atomic lock steal (single `mv` winner) + 5-minute
  age staleness (PID-recycle) + clean exit 3 on every contention path.
- M2(A): every run refreshes `harness/` (memory/process/roadmap/README —
  excluding branch-owned `sandbox/` and `backups/manifest.json`) from the
  live checkout so the branch is self-contained per checkpoint; ≥2
  consecutive `main_push: failed` manifest entries raise a loud exit-7
  alarm after the backup completes.
- M1(A): on branch-push failure the script reconciles inside the worktree
  — re-fetch, and if the remote has commits we lack, merge with a
  programmatic manifest union (dedup by seq+timestamp+message, sorted)
  and ours-for-state.json, then push the merge commit; append-only
  preserved, no force-push, no human in the loop; unresolvable conflicts
  abort loudly.
- m1(RT): the checkpoint message is scanned BEFORE it is ever echoed.
- m3(RT)/m6(A): manifest write is atomic (tmpfile + os.replace); a
  corrupt manifest is recovered by walking the branch's git history for
  the last parseable copy (marker recorded), never silently reset.
- m4(RT): detached HEAD records "detached".
- m5(RT)/m1(S)/m1(A): backups README rewritten for v4 (canaries,
  production-invocation self-test, push-target isolation, env overrides,
  divergence auto-reconcile, harness refresh, main-push alarm, seq,
  upload exclusion); decision #14 records v4.
- M3(A): `MainWindow._restyle()` re-paints the status dot and pokes the
  tray icon on every live theme/accent change (both restyle paths);
  ledger entry added and cleared in this cycle (with test).
- M4(A): `tests/test_harness_integrity.py` machine-checks the harness:
  roadmap glyph↔consensus-log coverage, ledger "Gate before" targets
  exist, .gitignore guard present, log-referenced records exist, and a
  hermetic backup-script execution test (fresh-create + append +
  planted-secret abort via PC_BACKUP_REPO/PC_SANDBOX_HOME — the overrides
  finally consumed by automation).
- M1(S): roadmap S1 glyph set to ◐ "G1-iter3 in progress" (out of
  "Shipped") — final state recorded only from this gate's actual outcome.
- M2(S)/M3(S): runbook blocker list now DERIVES from the ledger ("every
  entry whose Gate-before is this tag") and gains the checksum +
  contrast-gate steps and body-count corrections; roadmap S2 says
  "#1–#4 and #7".
- m5(A): S3 annotated "blocked by S6"; m7(A): stale violet-accent menu
  copy fixed; m8(A): the S2 plan for deferred #3 specifies legacy-leg
  cache behavior (no Qt-6.5 dependency); m2(A): chroma docstring
  corrected + divergence recorded in decision #10's lineage; m1(A):
  md3_palette_qss is now consumed by the runtime with an explicit
  overrides dict; m6(RT): md3 clamps absurd float magnitudes; m7(RT):
  load_settings catches ValueError (pre-existing); m8(RT): rsync runs
  without -l so symlinks are skipped, and the inventory records the skip.

## Fix-cycle completion (evidence, before iteration 2)

All resolutions above are applied and execution-verified:

- **Backup v4** (`scripts/sandbox_backup.sh`) passed a 39/39 scratch
  matrix replicating every gate experiment: baseline create+append
  (seq continuity), harness refresh lands on the branch, planted
  secret in scripts AND message aborts pre-push with the remote
  untouched, the message is never echoed before its scan, ALL SEVEN
  pattern-branch sabotages exit 5 (self-test), grep flag drift
  (`-rEn`→`-rn`) exits 5, credential-shaped filenames excluded from
  state.json, a test run against a clone whose origin IS the
  production repo exits 6 (without logging the remote URL), `file://`
  repo + bare-path push remote work, the TRUE divergence brick
  (local-ahead + foreign remote commit) self-heals via manifest-union
  merge (all three sides preserved, sorted, marker recorded, no
  force-push), 6 simultaneous runs produce only clean exit-3
  contention (no fatal/128 — after fixing a lock-steal availability
  gap the matrix itself exposed: moving a LIVE lock away let a third
  run start and overlap the owner; v4 never touches a live lock), a
  corrupt remote manifest is recovered loudly from git history with
  seq continuity, detached HEAD records "detached", the first failed
  main push completes rc=0 (recorded), the SECOND consecutive failure
  exits 7 with the alarm banner, and post-hook-removal the next run
  recovers.
- **Restyle** (`MainWindow._restyle`): status dot + tray + table
  repaint on live theme/accent change (both restyle paths wired);
  3 Qt-gated tests added (they skip in this sandbox, run on CI).
- **Harness integrity tests** (`tests/test_harness_integrity.py`, 7):
  ignore-guard, roadmap-glyph↔record coverage, ledger gate-targets,
  doc-reference resolution, backup-script syntax, version-string
  agreement across release files, and a hermetic backup cycle
  (fresh-create → append → planted-secret abort → clean checkout)
  that finally consumes the PC_* env overrides on every push to main.
- **Suite**: 719 passed + 9 skipped locally (was 712+6; +7 integrity
  tests, +3 restyle skips). CI verification of this commit pending —
  to be judged at iteration 2.
- Docs: backups README v4 (incl. exit-code table + known
  audit-trail anomalies), decisions #13/#14, roadmap S1 moved out of
  "Shipped" to ◐ pending this gate, S2 back to ☐ until its pre-gate,
  runbook §2 derives its blocker set from the ledger and carries the
  checksum/contrast-test/body-count steps, S3 annotated blocked-by-S6,
  S7 notes the legacy-leg requirement.

### Incident during fix-cycle verification (disclosed)

The first version of the verification matrix invoked
`bash scripts/sandbox_backup.sh` from inside a scratch CLONE — which
resolved to the clone's **committed v3 script**, not the v4 working
copy being tested. One experiment (a clone whose origin was the real
production repo, exercising exactly the Red Team M1 scenario) therefore
ran v3 — which has no isolation guard — and pushed one test commit
(`5db0853`, manifest seq 3 "t5") to the real `sandbox/backups` branch.
Post-hoc audit: the pushed tree contains only clean scratch content
(ok.py + the clone's committed harness docs); the v3 scan layers ran
and passed; no secrets involved — the damage is audit-trail pollution.
Remediation: annotated entry #3 as invalid via append-only commit
`3e69e36` (no history rewrite), documented in the backups README, and
the v1 matrix bug is the very failure mode the exit-6 guard now
refuses (verified in the corrected matrix: same scenario → exit 6,
remote untouched). Root cause recorded here: **when testing a script
from a repo clone, invoke the working copy by absolute path — a
relative invocation silently runs the committed (old) version.**

Iteration 2 outcome: **recorded below after the re-run — not before.**

## Addendum — CI break on the first fix-cycle commit (disclosed)

`7e54aa1` (iteration-1 fixes) went red on CI: **5/7 legs failed** —
all four POSIX legs (ubuntu, macos, both legacy) on
`test_backup_script_hermetic_cycle`, Windows on
`test_backup_script_syntax`. Root causes (neither in the shipped
backup script's logic):

1. The "hermetic" test was not hermetic: it relied on the ambient
   global git identity, which GitHub runners do not configure — the
   script's first `git commit` died (exit 128, "Author identity
   unknown"). It passed in the dev sandbox only because that machine
   carries a global identity — the same environment-blindness the
   39/39 scratch matrix shared (it, too, ran with ambient identity).
2. On Windows runners `bash` resolves to the WSL stub (no distro
   installed): `bash -n` exits 1 with a UTF-16 error — the syntax
   guard cannot execute there at all.

Fix-cycle extension (the commit carrying this addendum):

- `scripts/sandbox_backup.sh`: identity self-sufficiency — when no
  git identity is configured anywhere (fresh sandbox, CI runner), the
  run's commits fall back to a built-in `Proto Clean Sandbox Backup
  <backup@sandbox.protoclean.invalid>` identity. Backups are the
  mandatory last step of every execution plan, so the script must
  never be blocked on ambient config. An existing identity still
  authors commits as before (fallback is conditional).
- `tests/test_harness_integrity.py`: the hermetic cycle neutralizes
  ambient git config (GIT_CONFIG_GLOBAL/SYSTEM → /dev/null) inside
  every run — CI runners (no identity) and dev machines (identity)
  now execute the SAME path (the fallback). The syntax guard is
  POSIX-only, with the WSL-stub reason recorded.
- `harness/backups/README.md`: identity self-sufficiency bullet.

Local suite after the extension: **719 passed + 9 skipped** (baseline
exact). Iteration 2 pins the commit carrying this addendum and must
re-verify CI green on it before verdicts are recorded.

## Addendum 2 — the full CI-break chain, root-caused (disclosed)

Three stacked layers, each peeled by one red→green CI cycle. All
environment/test-side; the shipped backup script's own logic was
exonerated at every layer (and is what surfaced each cause):

1. **Ambient git identity** (140d9dc, 5/7 legs): fixed by the script's
   conditional identity fallback + config-neutralized test runs.
2. **Missing rsync in the legacy containers + swallowed push stderr**
   (3d51da9): rsync added to the container install set; the script now
   captures and prints push stderr on failure (main and branch
   pushes) — a silent push failure had burned a whole debugging cycle.
3. **Shallow CI checkout** (root cause of every "branch push failed"
   on POSIX legs): `actions/checkout` defaults to fetch-depth 1, the
   hermetic test's scratch clone inherits `.git/shallow` from it, and
   `git push` to the fresh bare is rejected — `! [remote rejected] …
   (shallow update not allowed)` — reproduced bit-for-bit in the
   sandbox via `file://` depth-1 clone → local clone → push. The
   script's exit-0 "commit kept locally" fallback then masked it.
   **CI-side fix: fetch-depth: 0** for the test and legacy checkouts.
   Additionally, the test's bare-ref checks used bare
   `git rev-parse <ref>`, which ECHOES an unknown ref name to stdout —
   a non-empty-output assert passed spuriously and hid the missing
   branch; both checks now use `show-ref --verify` (exit 1, no
   stdout) with the full run output in every failure message.

Lesson recorded: environment-dependent test assumptions (ambient
identity, ambient tool availability, checkout depth, rev-parse's
echo-unknown-refs behavior) are exactly the blind spots a dev sandbox
cannot catch — each fix makes the test assert the environment it
needs rather than assume it.

## Iteration 2 — [pending: launched on the fix-cycle extension commit]

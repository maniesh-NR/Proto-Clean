# S8 execution plan — harness subsystem hardening + Python port

Per `harness/process/execution-plan-template.md`. Stage S8 (decision
#19; activated by the owner disposition, decision #21, 2026-11-19).
Scheduling per decision #18: the port lands BEFORE S2's stage gate.
Ledger rows #9/#10 and deferred #12 ride this stage.
**AMENDED at S8-PG1 iteration 1 (2026-11-19, record
`memory/consensus-log/2026-11-19-s8-pre-gate.md`): every structural
change below cites its finding. The headline amendments: STAGE 3
splits into 3a (parity) / 3b (inversion); the module contract is
specified; the exit criterion gains its mechanism primitive; the Seq
field is specified and un-bundled; the Python floor / import seam /
Windows shape are pinned; coverage arithmetic is tracked; STAGE 6
gains a cap contingency.**

```
PLAN: S8 — harness subsystem hardening + Python port
STAGE 1: Pre-gate deliverables (DONE): harness/backups/
         allowlist-inversion-evaluation.md (decision #20b: ADOPT,
         family-by-family disposition + loopback QUARTET conversion
         — amended at S8-PG1) + this plan.
STAGE 2: Adversarial consensus PRE-GATE (3 roles judge the
         evaluation + this plan; per process/adversarial-
         consensus.md — 2-iteration cap, owner escalation).
         Iteration 1 (2026-11-19, on 82fb63c): NO CONSENSUS —
         RT BLOCK + Architect BLOCK + Steward PWF; this amendment
         is the remediation; iteration 2 re-judges. No port work
         starts before consensus. No outcome pre-recorded.
STAGE 3a: PARITY PORT + DELEGATION (own commit; S8-PG1 Arch-C2/
         M6, RT-M1/M2):
         - scripts/backup_core.py implements the merge/alarm/guard
           core BEHAVIOR-PRESERVING (denylist semantics unchanged).
         - scripts/sandbox_backup.sh DELEGATES its guard block to
           the module in the SAME commit (the bash PROD_CHECKOUT
           constant is DELETED; the module derives the guarded
           identity — decision #19c holds from this commit, not
           from a later shim).
         - tests/test_harness_integrity.py `_prod_checkout()` and
           matrix v9 E30 re-point at the module in the same commit
           (the exactly-once derivation follows the identity).
         - The 16 machine tests + 121 matrix checks pin the module
           TRANSITIVELY (they invoke the unchanged entrypoint).
           The ONLY expectation edits allowed in this commit are
           the loopback-QUARTET lanes' identity re-pointing — no
           semantic expectation changes (parity is the oracle: 137
           checks green with zero edits = proven equivalence).
STAGE 3b: INVERSION + LANE CONVERSION (own commit): the allowlist
         inversion lands per the amended evaluation (family-by-
         family; pushInsteadOf + include/includeIf content +
         symlinked-.git/git-dir containment SURVIVE; transport
         allowlist `protocol.*.allow=never` on every TEST-mode git
         invocation as defense-in-depth); the loopback QUARTET
         (v5 E3, v6 E11, v9 E28, machine-r2 — NOT a trio) converts
         per the evaluation's amended §conversion; the scrub
         unit-pin lands as a module unit test.
STAGE 4: Matrix conversion + per-lane MECHANISM audit (deferred
         #12): every matrix lane maps to a ported test that still
         proves the MECHANISM, not just the outcome; the per-lane
         table records each lane's post-conversion home (v5 E3's
         failed-push resilience → the v8/E8 hook-rejection class);
         v6 E10 and v7 E15 hand-copied PROD constants de-hardcode
         to the derived identity (S8-PG1 RT-M2); decide CI-forcing
         the ported suite (today ci.yml runs pytest only, so the
         E4-class stale-lane drift can recur between gates — the
         ported suite running IN CI closes exactly this). Bash
         matrices stay re-runnable until parity is proven, then
         retire with a gate finding.
STAGE 5: scripts/sandbox_backup.sh becomes a thin shim over the
         module (or retires — open decision 4, blast radius: every
         one of the 16 tests + 6 matrices invokes this entrypoint;
         retirement also deletes the last bash surface the README
         documents); the bash capability freeze (decision #18)
         ends at the port; the frozen residual list shrinks by
         gate finding. AT THE RETIREMENT COMMIT, checklist item
         (e) of process/adversarial-consensus.md AND the backups
         README are amended in the SAME commit to point at the
         ported suite (S8-PG1 Arch-M4 — otherwise every later fix
         cycle is checklist-noncompliant against a retired
         artifact).
STAGE 6: Adversarial consensus gate on the port's RESULTS (S8's
         closing gate; before S2's stage gate). CAP CONTINGENCY
         (S8-PG1 Steward-M5): at a 2-iteration cap-exhaustion,
         S8 escalates to the owner with the port results and named
         options — (a) further split (port vs matrix conversion),
         (b) owner-descoped S8→S2 ordering, (c) fresh gate on the
         remediation line (the G1→G1-iter3 precedent); an explicit
         deferral with reason is also acceptable. A control with
         no terminal state is an escalation ladder (lesson 02-255).
FINAL STAGE: Sandbox backup (event-driven, always last).
```

## Module contract (S8-PG1 Arch-C3 — a port without a specified API
is a rewrite with extra steps)

`scripts/backup_core.py` (location per open decision 3, floor and
import seam below), Python 3.8-compatible, stdlib-only:

- **Public functions** (the ported surface):
  - `judge_target(operand, *, config_ctx) -> Verdict` — the operand
    guard: both-directions resolution (push view per operand shape:
    typed spelling for URL/path, `remote get-url --push` for names;
    fetch view: `ls-remote --get-url` semantics), the allowlist
    type check, containment, and the retained content-level config
    scan (pushInsteadOf keys; include/includeIf file content across
    repo + global + XDG + system).
  - `resolve_prod_checkout() -> Path` — the single-source guarded
    identity (derived from the module; no hand-copied constant
    anywhere — #19c).
  - `sanitize_env(env) -> dict` — the env scrub (pure function;
    unit-pinned: drops `GIT_TRACE*` / `GIT_CURL_VERBOSE` /
    `GIT_CONFIG_*` / `GIT_DIR` families).
  - `redact(text) -> str` — the redaction filter (pure function;
    unit-pinned — the structural witness for the curl-verbose class
    after the loopback lanes convert).
  - `append_manifest(...)`, `merge_union(...)` — the merge core
    (already Python heredocs today: manifest append, divergence
    union).
  - `alarms_check(...) / alarm_raise(...)` — the alarm machinery +
    failcount.
- **Stays in bash** (unchanged): worktree/rsync/commit orchestration,
  the lock (or it moves with the alarm block if the port makes it
  trivial), CLI/env parsing at the entrypoint, the shim surface.
- **state.json heredoc disposition** (Arch-C3): the third Python
  heredoc (inventory/state serialization) MOVES into the module —
  leaving it inline would produce a mixed-paradigm script that
  shells to Python for merge/alarm/guard while inlining a Python
  heredoc for inventory, a worse shape than today.
- **Injection seams for the ported mechanism demos** (Arch-C3):
  today's mechanism lanes prove refusals load-bearing by patching
  bash SOURCE text (v5 E4 sed; v7 E18 instrumented copy; v8 E20
  identity patch; v9 E25/E29; v10 E31/E34 patched-TS). String-
  patching Python source is the wrong technique; the module takes
  injectable dependencies — target resolver, config reader, clock —
  so ported mechanism lanes STUB them instead (a stubbed resolver
  that lies = the ported equivalent of a sabotaged guard, caught by
  the same lanes).
- **Shim invocation**: `python3 scripts/backup_core.py <subcommand>`
  with JSON lines on stdout for the bash side's consumption; the
  bash script keeps the exit-code contract (0/2/6 semantics
  unchanged).

## Exit criterion — the mechanism primitive (S8-PG1 RT-M3/M4 /
Arch-M2; wording per decision #20 + the amended evaluation)

A TEST run addresses ONLY local absolute filesystem paths,
physically disjoint from the production checkout — enforced by:

1. **Judgment subject**: the RESOLVED EFFECTIVE targets of both
   directions (never the raw operand alone; clean remote names stay
   legal — their resolved targets must pass).
2. **Canonicalization, both sides**: the operand AND the guarded
   identity canonicalize (`realpath`); a non-existent operand
   REFUSES rather than silently degrading to literal-only judgment
   (the current `|| true` degradation is a weakening the port does
   not inherit).
3. **Containment**: equality-or-descendant-with-separator against
   the canonicalized identity; for the git-dir, the symlinked-.git
   refusal + git-dir containment check (retained per the
   evaluation's disposition table).
4. **Bind-mount reality** (RT-M3, demonstrated): realpath cannot
   see through `unshare -rm mount --bind`. The port either
   implements device/inode-identity containment (bind mounts
   preserve st_dev/st_ino — comparing the operand's
   device/inode-identity chain against the identity's catches the
   aliasing) or mount-namespace aliasing joins the frozen residual
   list by gate finding. Decided at STAGE 3b, recorded in the
   evaluation + README.
5. **Operand scope**: the same rule governs PC_BACKUP_PUSH_REMOTE,
   PC_BACKUP_REPO, and PC_SANDBOX_HOME.
6. **`file://` refused** — a behavior change for the REPO operand
   (today `file:///*` is accepted); stated here so the port's
   expectation edits are explicit, not silent.
7. **Transport allowlist**: every TEST-mode git invocation runs
   with non-file transports denied (`protocol.*.allow=never`) —
   the structural backstop for every push-time rewrite class.
8. **Exit criterion is LANE-CHECKED, not generator-based** (S8-PG1
   Arch-m1): decision #20's own wording — "feed a non-local
   operand, expect refusal — a matrix lane, not a prose argument".
   No hypothesis dependency (the legacy CI legs install no extras).

## Record sequence field (deferred #10; spec per S8-PG1 RT-m1 /
Arch-M3 — and UN-BUNDLED from the port stages)

- `Seq:` orders records; **dates keep backing authority** — a Seq
  header never backs a glyph or withdraws a close by itself.
- Seq-less records (all existing ones) sort by date BEFORE all
  Seq-ful records; a Seq-less non-consensus record keeps its
  date-semantics withdrawal behavior unchanged.
- Duplicate Seq = malformation (like multiple Date: headers);
  missing Seq after adoption = malformation for records dated after
  adoption (the GATE_RULE_ADOPTION pattern, tests L36–37).
- The forgery-suite extension (synthetic Seq classes: forged high
  Seq, duplicate Seq, Seq-less post-adoption) lands in the SAME
  commit as the field.
- **Sequencing (Arch-M3)**: the Seq field lands as an ISOLATED
  commit AFTER the port stages (or is deferred out of S8 by gate
  finding) — bundling a record-format change into a port stage
  repeats the bundling pattern that created S8 (decision #19's own
  diagnosis).

## Platform + packaging constraints (S8-PG1 Steward-M4 / Arch-M5)

- **Python 3.8 floor**: both legacy CI legs run all of `tests/` on
  3.8 (ci.yml L54–93, `pip install pytest` + `-e . --no-deps`, no
  extras) — `scripts/backup_core.py` and its tests are
  3.8-syntax-clean (no `match`/`case`, no `dict |`, no
  `str.removeprefix`; the documented trap, 02-lessons L338–340) and
  **stdlib-only**.
- **Import seam**: no conftest.py exists today and no test imports
  from `scripts/`; the port adds `tests/conftest.py` inserting the
  repo root (or an importlib spec loader) — decided at STAGE 3a,
  recorded in the commit.
- **Packaging**: `scripts/` is repo-only (the wheel packages
  `proto_clean*` only, pyproject L31–32) — no packaging impact;
  stated so nobody "fixes" it into the wheel.
- **Windows disposition**: the bash-gated integrity lanes skip on
  Windows today (10 skipif sites, the 132 skips); the pure-Python
  module is unit-testable on Windows. STAGE 3a ADDS the module's
  unit tests as Windows-runnable where path semantics allow
  (pure functions: sanitize_env, redact, judge_target on synthetic
  POSIX-style paths) and keeps an explicit `skipif` for
  filesystem-dependent containment tests — the Windows leg count
  will rise; the coverage table below tracks it.

## Coverage arithmetic (S8-PG1 Steward-M3 — tracked so checklist
item (e) always has a stable expected number)

| Surface | Today | Expected after STAGE 3b | Expected after STAGE 4/5 |
|---|---|---|---|
| Matrix checks (bash) | v5 20 · v6 22 · v7 25 · v8 19 · v9 26 · v10 9 = 121 | 121 unchanged (bash lanes unedited; quartet expectations edited only where they face the guard — recount at commit) | retired per-lane as ported equivalents land; final count = gate finding |
| Integrity suite | 16 tests (728+9 local; 737×4 POSIX; 605+132 Windows) | 16 + new module unit tests (count recorded at commit; POSIX legs +N; Windows +M unit-runnable) | matrix lanes absorbed; final counts recorded at the retirement gate |
| The quartet | E3, E11, E28 rc-0/exemption lanes; machine-r2 rc-0 | refusal lanes (E3/E28/r2 guard-facing) + local-filesystem success lane + local-filesystem failure lane + scrub unit-pin | ported per-lane equivalents |

Every stage commit records its actual numbers in this table; a
number that drifts without a lane map is the E4 class.

## Invariants held throughout

- The suite stays green at every stage (baseline 728 passed + 9
  skipped local / 737×4 POSIX, 605+132 Windows, wheel + Android
  CI); new coverage extends tests in place per the house rule.
- STAGE 3a is parity-only: the 137 existing checks green with zero
  semantic expectation edits (identity re-pointing aside) is the
  equivalence proof; STAGE 3b changes semantics in its own commit.
- Mutation probes patch BOTH SIDES (the guarded identity AND every
  real-path lane) or run only where the production path does not
  exist; probe batteries snapshot the WORKING TREE
  (sixth-incident rule); zero production contact. With the
  delegation at STAGE 3a there is exactly ONE guarded identity
  (the module's) — the both-sides rule is unambiguous from that
  commit.
- Every fix cycle refreshes the fix-cycle doc checklist (a)–(f) in
  the SAME commit, and re-runs ALL verification matrices, not just
  the new one (item (e) is amended at the STAGE 5 retirement
  commit to point at the ported suite).
- The record-before-fix-cycle rule: a gate's iteration-1 record
  lands in its OWN commit before the fix cycle starts (this plan's
  amendment cycle followed it: record `f422afe`, then this commit).

## Per-stage verification commands (S8-PG1 Steward-m4)

- STAGE 3a/3b/4/5 boundaries: `python -m pytest -q -p no:asyncio`
  (full suite) + `bash harness/backups/matrices/verify_backup_
  v5.sh` … `v10.sh` (all six) + the module unit tests; STAGE 3b
  additionally: the quartet lanes' new expectations + the scrub
  unit-pin; STAGE 4: the per-lane mechanism table complete;
  STAGE 5: the amended checklist (e) + README in the same commit.
- STAGE 6: pre-gate verification per the process doc (CI on the
  closing line, check-runs + job logs).

## Port-time notes (ledgered from S8-PG1 minors)

- sandbox_backup.sh L1132 cites "scripts/verify_backup_v7.sh" —
  stale since G1-iter6 (the matrix lives at
  harness/backups/matrices/); fix at STAGE 3a.
- Module Windows skip policy per the platform section above.

## Open decisions (updated at S8-PG1)

1. ~~The loopback-trio conversion~~ — DECIDED at S8-PG1: the QUARTET
   converts per the amended evaluation (all three roles converged;
   disagreement would have escalated).
2. CI-forcing choice for the matrices (STAGE 4): ported-pytest-only
   vs ported-pytest + bash-matrix CI job until retirement — still
   open; decided at STAGE 4.
3. Module location (`scripts/backup_core.py` proposed — adjacent to
   the script it ports; alternative `harness/backup_core.py`) —
   still open, now with the floor/import/packaging/Windows context
   above attached.
4. Shim vs retire for the bash entrypoint at STAGE 5 — still open,
   with the blast radius stated (all 137 checks invoke the
   entrypoint; retirement deletes the last documented bash surface).

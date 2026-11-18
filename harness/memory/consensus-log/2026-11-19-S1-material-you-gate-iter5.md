# Consensus Gate — S1 (iteration 5, owner-ordered fresh gate)

Stage: S1
Date: 2026-11-19 (iteration 1; iteration 2 pending — no outcome
pre-recorded)
Gate ID: G1-iter5 (fresh gate ordered by the project owner on
2026-11-19 per the standing continuation directive, after G1-iter4
exhausted its 2-iteration cap without consensus; this gate has its
own cap of 2).
Reviewed commits (pinned): the G1-iter4-i2 remediation line —
`bf0c74e` (backup v6 + declaration-bound gate-record authority + 4
machine tests), `c00f647` (CI identity fix for the new main-push
test), `a02db67` == origin/main (seq-7 incident disclosure). Local
suite 727 passed + 9 skipped exact; CI 7/7 success on both `c00f647`
and `a02db67` (check-runs API, orchestrator pre-gate verification);
backup manifest seq 9 faithful at `a02db67` (main_push ok,
prev_branch_push ok), failcount 0.
Predecessors: `2026-11-13-S1-material-you-gate.md` (G1-iter1),
`2026-11-13-S1-material-you-gate-iter2.md` (G1-iter2),
`2026-11-13-S1-material-you-gate-iter3.md` (G1-iter3),
`2026-11-15-S1-material-you-gate-iter4.md` (G1-iter4, both
iterations, closed NO CONSENSUS at cap).

## Iteration 1 — roles launched (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| G1-iter5-R | Red Team | **BLOCK** | ~30 bounded experiments in fresh `/tmp/g1i5-rt-scratch*` clones (md5-verified script copies; all runs via the sanctioned three-override pattern; github-shaped targets neutralized by a local 502-proxy or fake ssh — zero github traffic, zero pushes outside scratch; production checkout verified clean before/after): opt-in gate re-verified (env-less/=0/=yes/conflict/nonexistent-repo); 20-spelling guard matrix; empty-credential bypass family isolated and executed end-to-end (the critical); production-path spelling matrix incl. symlink ×3 and `//` (the second critical); env-scrub lanes incl. config-FILE injection; insteadOf executed twice with a real receive-pack attempt against git@github.com (the major); 11-case forgery matrix v2; TOCTOU mechanism proven by instrumented copy + 7 real single-shot races; `verify_backup_v6.sh` 22/22; integrity suite 15/15; full baseline 727+9 exact |
| G1-iter5-A | Devil's Architect | **BLOCK** | full v6 script read + `6324a4d..a02db67` claim map (16 rows, every remediation claim verified against its hunk); 6 mutation probes — 5 invert, 1 DOES NOT (the trace-scrub test survives removing the entire env scrub — the major #2); push-target production-path lane executed E2E with identity-patched constants (the major #1 — the v6 guard checked only the REPO operand while the script header claimed "test traffic can touch neither github nor the production repo, not even via a clone's origin"); scratch baseline 727+9 in 83.75 s; design critique of the declaration-bound model (sound — remaining forgeries are procedural, within the threat model); harness-exit-criterion recommendation (freeze bash, port before S2's stage gate, frozen residual list); doc cross-checks (stale baselines ×3, README table labels) |
| G1-iter5-S | Ship Steward | PROCEED-WITH-FINDINGS | full suite twice (727+9 in 93.89 s / 90.86 s, tree clean both times, 9 skips = Qt-binding-gated, verified); CI per-leg counts from all 7 downloaded job logs at `a02db67` (736 × 4 POSIX, 605+131 windows — EXACT vs the documented expectation; `c00f647` also verified); claim/code map of all 21 G1-iter4-i2 findings — ZERO mismatches (the S-M1 class checked first and hardest; "every push goes through one guarded helper" now literally true — exactly 2 `git push` sites, both in helpers); audit trail: manifest seq 1-9 monotonic, seq 3/5/7 invalid-annotated with faithful reasons, `c6f7e24` append-only, branch-tip harness byte-identical to main, failcount 0; docs/ledger/runbook audited (3 stale-baseline minors); release-surface consistency for S2 confirmed (13 assets, 12 release jobs, version strings agree) |

**Consensus: NOT reached (two BLOCKs — Red Team and Devil's
Architect). Iteration 1 of this gate's cap of 2: the fix cycle runs
now, and iteration 2 re-judges the remediation commit that carries
this record.**

### Red Team — BLOCK (verbatim from the verdict block)

CRITICAL:
- C1. Host-suffix github guard bypassed by empty-userinfo / empty-port
  spellings of the APEX host: `https://@github.com/…`,
  `https://github.com:/…`, `https://@github.com:/…`, scp
  `git@github.com:/…` — the `@`-strip required ≥1 char before the
  `@`, the port strips required content after the `:`, so the
  normalized host stayed `@github.com` / `github.com:` and matched
  neither `github.com` nor `*.github.com`. Executed: unit matrix on
  the verbatim extracted guard (13 spellings — the four bypass forms
  PASS-GUARD); full TEST-mode runs of the md5-verified HEAD copy —
  all four sailed past the guard (the scp variant via a configured
  remote name attempted a real `git-receive-pack` against
  git@github.com, blocked only by the fake ssh). Falsifies the README
  claim "matched by host SUFFIX … after canonicalization / however
  the target is spelled"; the machine test's 15-spelling matrix and
  verify matrix E9 all miss the family.
- C2. Production-checkout refusal defeated by symlinked and `//` path
  spellings: `cd "$REPO" && pwd` is bash's LOGICAL pwd (preserves
  symlinks and a leading `//`), so `PC_BACKUP_REPO=<symlink →
  production>`, `<symlinked parent>/cleanroom`, `file://<symlink>`
  and `//home/z/my-project/cleanroom` all compared unequal and the
  TEST run proceeded to `cd` into the production checkout and commit
  onto its local `sandbox/backups` — the exact seq-3/seq-5 accident
  class (next opt-in production run pushes it to github). Relative
  and `./` spellings ARE caught. The script comment and README
  explicitly claimed the canonicalized compare "catches symlinked
  spellings" — falsified by execution.

MAJOR:
- M1. The guard never resolves `url.*.insteadOf` rewrites for direct
  URL/path targets, and `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`
  escape the env scrub: a scratch clone whose config (or whose
  env-injected `GIT_CONFIG_GLOBAL` file) carries
  `[url "git@github.com:/…"] insteadOf = /tmp/…looks-local` lets a
  TEST run with the innocent-looking
  `PC_BACKUP_PUSH_REMOTE=/tmp/…looks-local` pass the guard while git
  actually attempted `git-receive-pack` against git@github.com
  (executed twice; remote-NAME targets were safe — `git remote
  get-url` applies insteadOf — but direct operands were inspected
  raw). Deliberate-attacker lane, but the README's "a TEST run never
  reaches github … whatever the repo" is falsified and the fix is
  cheap.

MINOR: m1 stale-consensus — a ☑ is not retracted by a NEWER
NO-CONSENSUS record for the same stage (executed synthetically; no
live impact — S1 is ◐); m2 roadmap done-claims without any stage id
skip the glyph check entirely (documented-intentional for Shipped
lines, but an unbacked done-claim lane anywhere else); m3 scan→add
TOCTOU — a file written into the worktree between the layer-2 scan
and `git add` rides the commit unscanned (mechanism PROVEN by
instrumented copy; 7 real single-shot races missed the sub-100 ms
window; [SPECULATIVE] a tuned concurrent racer could land it); m4
[ENVIRONMENT] no production contamination (orphaned worktree
self-pruned).

### Devil's Architect — BLOCK (findings)

MAJOR:
1. The test-isolation guard does not refuse the production checkout
   as a push TARGET; the script header claims it does
   ("test traffic can touch neither github nor the production repo,
   not even via a clone's origin"). Executed: TEST runs with
   `PC_BACKUP_PUSH_REMOTE` = the production path (plain, `file://`,
   and a clone's `origin` resolving to it) all passed the v6 guard —
   it resolves remote names via the FETCH url and compares only the
   github URL spelling, never the production PATH. E2E with
   identity-patched constants: a TEST run pushed a checkpoint into
   the "production" repo's local `sandbox/backups` and the next
   opt-in run propagated it — the v5 RT-M2 accident class
   resurrected through the exact lane the header names. No machine
   test or matrix block covers the push-target path lane.
2. The RT-M1 machine test is not mutation-covering: reverting the
   pattern env scrub (to the v4 enumeration, or removing it
   entirely) or reverting `_push_main`'s token-shape redaction
   leaves the test green — each defense layer absorbs the other's
   removal, git 2.47.3 self-redacts TRACE2, and the curl-verbose
   marker asserts are vacuous on this platform. The record's
   "machine-covered" claim for the RT-M1 surface is incidence-true,
   mutation-false.

MINOR: 1) `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` miss the env scrub
(config-by-FILE injection; the machine tests neutralize these vars
themselves, masking the gap); 2) pushurl/`pushInsteadOf` divergence —
remote names resolve via fetch URL only (beyond the accident threat
model; fold into a frozen residual list); 3) doc currency (process
baseline parenthetical stale a third time; README table says v5 +
"seq-keyed"; project-state CI hedge now resolved); 4) harness
exit-criterion scheduling — ledger #9's port at S6 leaves S2's gates
on the bash core; recommend a bash capability freeze now + port
pulled ahead of S2's stage gate + a frozen residual-threat list
(design recommendation, not a defect).

### Ship Steward — PROCEED-WITH-FINDINGS (findings)

MINOR: 1) project-state "to be confirmed by CI" hedge stale — the
remediation-line CI numbers are now confirmed on `c00f647` and
`a02db67` (job-log-verified in this audit); 2) process-doc baseline
parenthetical one cycle stale (third consecutive gate with this
stale-copy class); 3) backups-README "What gets backed up" table
still labels the script "(v5)" and the manifest "seq-keyed" (stale
since the v5 triple-key change).

### Verified-good (all three agents, evidence in their reports)

- Local suite 727 passed + 9 skipped exact (all three agents
  independently); CI 7/7 at `a02db67` with per-leg counts exact from
  the downloaded logs (736 × 4 POSIX, 605+131 windows), wheel +
  Android green; `c00f647` likewise.
- All G1-iter4-i2 remediation surfaces hold as implemented — every
  one re-verified by execution (Red Team and Architect
  independently): opt-in gate (all variants), all prior guard
  spellings (case/:443/:22///ssh/trailing-dot/.git/subdomains,
  plain + credentialed + remote-name), partial-override refusals (all
  six), unreachable-aware alarm (rc 0 → exit 7), `-s ours` divergence
  union + key-scrub heal, trace-family redaction under the 401
  server, shaped names, canary self-test, lock stealing,
  `verify_backup_v6.sh` 22/22 re-executed.
- The declaration-bound ☑ check is genuinely mutation-covering
  (Architect probe e); the v6 machine tests for opt-in / all-or-none
  / production-checkout refusal / host-suffix guard all invert on
  their targeted reverts (probes a, b, d, f).
- The forgery matrix v2 (11 synthetic cases): all prior classes
  rejected (inline, double, back-dated, fenced, undated, cross-stage,
  substring, non-terminal, undeclared, zero-width, indented Stage);
  CRLF behaves identically to LF; multi-stage declaration backs all
  declared stages (design-accepted).
- Manifest seq 6-9 faithful; seq 3/5/7 invalid-annotated; linear
  append-only branch history; no G1-iter5 pre-recording anywhere;
  ledger rows #1-#9 real; release surface internally consistent
  pre-v0.6.3; Material You surface untouched by the remediation line
  and sound at design level.

## Resolution cycle (fixes applied in THIS commit — every finding from all three roles)

- **RT-C1:** `_norm_url` normalizes empty-credential forms — the
  userinfo strip takes ZERO-or-more chars before the `@`
  (`[^/@]*@`), and an empty-port rule (`^([^/]+):(/|$)`) strips a
  colon with no content before the scp fold. All four bypass
  spellings now normalize to `github.com/…` and refuse exit 6.
  Machine test: 5 new spellings + the empty-path scp remote name.
  Matrix E14 (7 spellings + remote name + clean lane).
- **RT-C2 / A-M1:** both production-path compares are PHYSICAL —
  `pwd -P` (resolves symlinks) plus a leading-`//` collapse loop —
  AND the compare now covers the push TARGET as well as the repo
  operand, including the checkout's `.git` (the direct push-into-
  production lane). Machine test: literal spellings on any machine;
  symlink / symlinked-parent / `//` spellings where the checkout
  exists (dev sandbox). Matrix E15 (10 refusal lanes + clean lane).
- **RT-M1 / A-m1 / A-m2(i):** the push target is RESOLVED THE WAY
  GIT RESOLVES IT before it is judged — remote names via
  `git remote get-url --push` (pushurl-aware: a `pushurl` divergence
  no longer hides behind the fetch URL), URL/path operands via
  `git ls-remote --get-url` (applies `url.*.insteadOf`, so a
  config-FILE rewrite to github is refused even though the raw
  operand looks local) — AND `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`
  join the pattern env scrub, so config-by-FILE injection via env is
  inert (the push goes to the local bare it was addressed to).
  Machine test: repo-config insteadOf lane (refuse) + env-injected
  `GIT_CONFIG_GLOBAL` lane (inert, no push failures). Matrix E16.
  The tests' ambient-config neutralization convention moved from
  `GIT_CONFIG_GLOBAL=/dev/null` (which the script now scrubs before
  it can reach the runner's own git) to an empty `HOME` — identical
  identity-fallback path on every machine.
- **RT-m1:** stale-consensus withdrawal — a ☑ requires that the
  LATEST-dated record declaring the stage closes with CONSENSUS
  REACHED; any non-consensus record at the latest date withdraws the
  backing (a failed re-gate retracts the glyph machine-green;
  same-date ties withdraw — fail-safe under ambiguous ordering).
  Forgery suite extended with both directions (withdraw + the
  legitimate newer-consensus backs).
- **RT-m2:** a ☑ bullet with no stage id OUTSIDE the "Shipped"
  section is now a violation (id-less done-claims previously skipped
  the check entirely); non-bullet lines (the status legend) never
  count. Forgery suite extended (Near-term violation + Shipped
  positive + legend non-bullet).
- **RT-m3:** post-add INDEX re-scan — after every `git add` that
  precedes a push (the checkpoint commit AND the divergence merge),
  the staged content is re-scanned with the same secret patterns
  (`git grep --cached`): anything committed was staged, and anything
  staged was scanned — the sub-100 ms window closes STRUCTURALLY.
  Machine coverage is a structural POSITION test, honestly labeled
  (no deterministic behavioral lane exists for a sub-ms race — the
  RT's own 7 timed races all missed), plus the widened-window probe
  in matrix E18 (an instrumented copy plants a secret AFTER the
  worktree scan, deterministically — caught exit 4, "staged
  content"; negative control: a pre-scan plant is caught by the
  worktree scan).
- **A-M2:** the scrub gained a MUTATION-COVERING observability lane —
  a hostile `GIT_TRACE=1` clean-lane run must emit ZERO git trace
  lines (with the scrub removed, the Architect's probe measured 26
  leaking through unredirected git stderr; the new lane was
  mutation-verified in scratch before commit — reverting the whole
  scrub loop fails the test). The platform-calibrated 401-marker
  asserts remain as secondary evidence.
- **A-m2(ii):** `pushInsteadOf` on direct URL operands — documented
  in the FROZEN residual-threat list rather than the guard (the
  Architect's own recommendation: requires crafted config, beyond
  the accident threat model).
- **A-m3 / S-m1 / S-m2 / S-m3:** doc currency fixed in this commit —
  process-doc baseline parenthetical (737/728+9), project-state CI
  numbers confirmed (736 × 4, 605+131 at `c00f647`/`a02db67`),
  backups-README table labels (v7, triple-key). The fix-cycle doc
  checklist (process doc) makes the refresh mechanical: baseline
  parenthetical, project-state numbers + hedges, lessons baselines,
  README table labels, and a re-run of ALL sandbox matrices — the
  stale-matrix class below was found exactly by doing that.
- **A-m4 (design recommendation, ADOPTED):** decision #18 — bash
  capability freeze (refusal-class fixes + port prep only), the
  merge/alarm/guard core ports to a tested Python module BEFORE S2's
  stage gate, and the FROZEN residual-threat list (backups README:
  off-domain redirectors, pushInsteadOf on direct URLs, the
  structural TOCTOU ceiling, orchestrator file-write authority,
  config-level indirection beyond env) bounds what future gates
  judge against. Ledger row #9 amended accordingly.
- **RT-m4 (environment):** no code change — the orphaned worktree
  self-pruned; recorded for the audit trail.
- **RT partial-coverage disclosures:** punycode/IDN live probes,
  multi-level insteadOf chains, tuned multi-process TOCTOU racing —
  out of budget, none machine-blocked; the E18 instrumented-window
  probe covers the TOCTOU behavior deterministically.

## Fix-cycle completion (evidence, at this commit)

- **Script v7** (same single file, `scripts/sandbox_backup.sh`):
  empty-credential normalization, physical production-path compares
  (repo + push target + `.git`), insteadOf/pushurl-aware target
  resolution, `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` scrub, post-add
  index re-scan (both commit paths). `bash -n` clean; every new
  refusal lane executed live before commit (13/13 probes refuse, 2/2
  clean lanes pass).
- **Machine coverage:** `tests/test_harness_integrity.py` now runs
  16 tests (+1 structural index-rescan test; the guard/override/
  forgery/mainpush tests were extended in place). Local suite
  **728 passed + 9 skipped**. CI expectation for this commit:
  737 per POSIX leg, windows 605 passed + 132 skipped — to be
  confirmed by CI before iteration-2 verdicts are recorded.
- **Mutation coverage (executed in scratch clones, none on HEAD):**
  reverting (a) the entire env scrub → the trace lane FAILS;
  (b) the empty-credential normalization → the guard-spellings test
  FAILS; (c) `pwd -P` → the override test's symlink lanes FAIL;
  (d) the index re-scans → the structural test FAILS. Every v7
  surface's machine claim is mutation-verified, not
  incidence-claimed.
- **Sandbox matrices:** `scripts/verify_backup_v7.sh` (new, sandbox
  snapshot) — 25/25: E14 empty-credential spellings, E15 physical
  production-path compares (repo + push target), E16 insteadOf
  resolution + env-config inertness, E17 zero-trace-lines, E18
  widened-window TOCTOU + negative control. Re-ran ALL older
  matrices per the new checklist: **v6 22/22, v5 20/20 — after
  fixing the v5 E4 lanes, which had been silently stale since v6**
  (they probed the PRODUCTION checkout as a TEST repo, which v6's
  production-checkout refusal correctly blocks; nobody had re-run
  the old matrix in an entire gate — the stale-matrix lesson and
  the checklist item exist because of this).
- **Docs:** backups README v7 (+ frozen residual-threat list);
  process doc (baseline + fix-cycle doc checklist); decisions #18;
  lessons extended (empty-credential forms, logical-vs-physical pwd,
  raw-string guards vs config rewrites, mutation-covering vs
  incidence-true, re-run all matrices); ledger #9 amended; roadmap
  gate history; project state; session log
  `memory/session-log/2026-11-19-g1-iter5-iteration1.md`.

Iteration 2 outcome: recorded in this file when the re-run's
verdicts return — not before.

FINAL OUTCOME: NO CONSENSUS — iteration 1 of 2 (Red Team and Devil's Architect BLOCK); the v7 fix cycle above lands in this commit, which carries this record; iteration 2 re-judges the remediation commit within the gate's cap.

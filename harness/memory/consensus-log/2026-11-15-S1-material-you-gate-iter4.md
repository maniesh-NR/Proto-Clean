# Consensus Gate — S1 (iteration 4, owner-ordered fresh gate)

Stage: S1
Date: 2026-11-15 (iteration 1) · 2026-11-16 (iteration 2 and closure)
Gate ID: G1-iter4 (fresh gate ordered by the project
owner on 2026-11-15 after G1-iter3 exhausted its 2-iteration cap
without consensus; this gate has its own cap of 2).
Reviewed commit (pinned): `6324a4d` (main, CI 7/7 green — run
43549397493; per-leg 728 × 4 POSIX and 604 passed + 124 skipped on
windows, re-verified from the downloaded job logs by the Steward;
local suite 719 passed + 9 skipped, exact; production backup v4 debut
in manifest seq 4, branch tip `9ca065d` at gate open).
Predecessors: `2026-11-13-S1-material-you-gate.md` (G1-iter1),
`2026-11-13-S1-material-you-gate-iter2.md` (G1-iter2),
`2026-11-13-S1-material-you-gate-iter3.md` (G1-iter3, both iterations).

## Iteration 1 — roles launched (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| G1-iter4-R | Red Team | **BLOCK** | ~40 scratch experiments: planted secrets ×4 (untracked harness/memory/, binary, odd names), scan sabotages ×7, exit-6 guard probes ×6 + grep unit tests + anonymous reachability, hook-rejection double-run, unreachable ×3, two-hop propagation, divergence self-heal ×3 (incl. crafted poisoned manifests), GIT_TRACE/TRACE2 leak probes over a local HTTP git server, identity ×3, shaped filenames ×2, lock contention ×4, counter pre-seed, integrity-check gaming proof |
| G1-iter4-A | Devil's Architect | **BLOCK** | execution verification of every G1-iter3-i2 remediation claim, glyph-check falsification on `74bea1e` AND at HEAD (the critical), pre-recording probes, 13-spelling guard pattern probe, divergence / post-merge-push failure matrix, S2 contrast property re-run (2,952 checks, worst 5.46:1), Material You surface + drift audit |
| G1-iter4-S | Ship Steward | PROCEED-WITH-FINDINGS | full suite (719 passed + 9 skipped in 86.56s — exact), CI re-verification via the API + all 7 job logs (728 / 728 / 604+124 / 728 / 728 — exact), remediation-item evidence (the 9 expected files in `67df974..6324a4d`), docs/ledger/runbook/manifest audit, release-risk pass |

**Consensus: NOT reached (two BLOCKs). Fix cycle started; the gate
re-runs on the fixes as iteration 2 (within this gate's cap of 2).**

### Red Team — BLOCK (findings, from the verdict block)

MAJOR:
1. Production push is the script's DEFAULT — the exit-6 guard only
   inspects TEST runs; two consecutive gates, two accidental
   production pushes by agents losing the env (incl. incident
   `726b437`, manifest seq 5, disclosed below). Make production
   opt-in.
2. Exit-6 guard bypassable by URL spelling variants — "however
   spelled" falsified: a case-variant decoy executed end-to-end RC 0;
   the script's exact grep also misses `:443`, `//`, `git@GitHub.com:`
   spellings; all variants anonymously HTTP-200 on github's git
   endpoint.
3. BRANCH-PUSH-ALARM never fires under persistent unreachability
   (revoked credential / network partition): 3 runs, all rc 0,
   failcount frozen — the entire counter block was gated on
   FETCH_OK=1.
4. Divergence self-heal commits and pushes merged content with NO
   re-scan: an injected manifest token rode the union merge (RC 0,
   token in the PUSHED manifest); a token outside harness/ rode a
   clean merge (falsifying "the commit only ever adds paths under
   harness/"); the poisoned manifest then bricked every future run
   (exit-4 loop, append-only).
5. `GIT_TRACE2*` not unset + self-heal re-pushes uncaptured: the
   credentialed push URL printed 4× unredacted under `GIT_TRACE2=1`.

MINOR: (1) re-push failure at :582/:645 dies exit 1 via set -e, no
alarm, no graceful path; (2) shaped filenames enter the pushed tree
outside the scripts snapshot (an untracked `harness/memory/` shaped
file — README claim falsified); (3) excluded shaped names printed to
stdout by `find -print`; (4) no automated coverage of the exit-6
guard or the branch-push alarm; (5) FINAL-OUTCOME check gameable by
the record's author (proven in scratch; the real repo was clean);
(6) bare-repo input → raw rsync exit 23 (undocumented);
relative-path targets misclassified; (7) [SPECULATIVE] redirector
URLs evade any spelling check.

### Incident during iteration 1 (disclosed — Red Team error, production side-effect)

During E9c setup a broken `&&` chain lost the `PC_BACKUP_*` env
overrides and the next command executed the script in
production-default mode: a real backup ran against the production
checkout and pushed commit `726b437` (manifest seq 5, "E9c case
variant prod remote") to the production `sandbox/backups` branch. All
v4 scan layers ran and passed (no secrets; content = a clean harness
refresh); the damage is audit-trail pollution — the same class as the
G1-iter3 "t5" incident (seq 3), and the second accidental production
push in two gates. The main checkout stayed clean at `6324a4d`,
failcount 0. Remediation: entry #5 annotated invalid via an
append-only branch commit (the seq-3 precedent). Root cause is Red
Team major #1 — v4 made production the DEFAULT, so any invocation
hiccup is a production push; v5 makes production opt-in, removing the
entire accident class (verified: the same env-less invocation now
refuses exit 6 before any action).

### Devil's Architect — BLOCK (findings)

CRITICAL:
1. The FINAL-OUTCOME ☑ enforcement is defeated by its own
   documentation — flipping S1 ◐→☑ (or S2 ☐→☑) in a synthetic copy of
   `6324a4d` makes `test_roadmap_glyphs_backed_by_gate_records` PASS:
   the sole backing is the iter-3 record's own remediation prose (an
   inline code span describing the rule). The check tests substring
   presence anywhere in any record naming the stage, so the exact
   violation class the rule was adopted (2026-11-14) to machine-prevent
   — pre-recording a stage outcome during an open gate — passed CI
   silently, for ANY stage. Three documents (the process doc, the
   iter-3 record, decision #15) asserted a guarantee that did not
   exist at `6324a4d`.

MAJOR:
2. Unguarded post-merge pushes (script :582/:645) abort rc 1 and mask
   pending alarm banners + the failcount update — violating the
   README's "a pending alarm banner is never masked" invariant (which
   held only for the exit-8 paths, verified good).
3. Production-refusal guard spelling-fragile (`:443`/`:22`/
   trailing-dot/case/ssh — grep-isolated, zero network) — the same
   defect class as the G1-iter3-i2 guard finding, narrowed to
   non-canonical spellings.

MINOR: rsync same-second same-size refresh skip (observed live);
unborn-HEAD `PC_BACKUP_REPO` rc 128; stale baselines in the process
and state docs; the post-union manifest note says "keyed by seq";
runbook §2 tag-vs-stage derivation imprecise; the system
colorSchemeChanged flip bypasses `_restyle` (a third restyle path —
fold into ledger #3); consider porting the merge/alarm core to a
tested Python module at S6.

### Ship Steward — PROCEED-WITH-FINDINGS (findings)

MINOR: no session-log entry for the G1-iter3 cycle (covered by the
iter-3 record + decisions + project state, but the series was
incomplete); roadmap "Shipped (gated retroactively — G1)" header
overstated G1's grant (zero findings against the released line, but
no consensus); process-doc baseline parenthetical stale (718/leg,
712+6 local); exit-6 match case-sensitive (hardening nit — subsumed
by the fix cycle's guard normalization).

### Verified-good (all three agents, evidence in their reports)

- All six remediated G1-iter3-i2 surfaces hold as implemented —
  every one re-verified by execution, including the predecessor's
  exact untracked-file probe (exit 4, remote untouched) — Red Team
  and Architect independently.
- Local suite 719 passed + 9 skipped exact; CI 7/7 on `6324a4d`, all
  7 job conclusions and per-leg counts exact from the downloaded
  logs; every remediation item evidenced in the `67df974..6324a4d`
  diff.
- Manifest seq 4 faithful; the branch's refreshed harness/
  byte-identical to main@6324a4d (md5, 9 files); no pre-recording of
  G1-iter4 anywhere; ledger rows #1–#8 all name real targets; the
  release surface internally consistent pre-v0.6.3.
- Divergence self-heal (v4 content merge), hook-rejection alarm,
  per-field identity fallback, GIT_TRACE-family redaction,
  exit-8-with-alarms, recovery after mid-merge death — all
  execution-verified on v4.
- S2 contrast plan re-executed against md3's real API: 2,952 checks,
  0 failures, worst 5.46:1; the release.yml checksum gap is honest
  (the mechanism does not exist yet, exactly as the runbook says).

## Resolution cycle (fixes applied before iteration 2)

Every finding from all three roles, each resolved (numbering follows
the verdict blocks above):

- **RT-M1 (+ both incidents):** backup script v5 makes production
  OPT-IN — without `PC_BACKUP_ALLOW_PRODUCTION=1` the script refuses
  (exit 6) BEFORE any action (the gate sits above the `cd`, so it
  fires even where the default repo path does not exist, e.g. on CI
  runners); the flag combined with test overrides aborts (exit 2,
  conflicting mode). Manifest entry #5 annotated invalid (append-only
  branch commit, the seq-3 precedent).
- **RT-M2 / A-M3 / S-m4:** the test-run refusal is normalized and
  widened — both sides canonicalized (lowercase, scheme/userinfo/
  default-port/trailing-dot/`.git` stripping, `//` collapsing, scp
  syntax folding), and a TEST run now refuses ANY github.com /
  ssh.github.com host however spelled and whatever the repo, plus the
  canonical production compare as belt-and-braces. All RT spellings
  (case, `:443`, `:22`, `//`, trailing dot, scp, credentialed,
  other-repo, remote-name-resolved) refuse exit 6; the RT's
  local-decoy path refuses; the scratch bare passes.
- **RT-M3:** the branch-push streak counts a failed push even when
  the fetch fails (BRANCH_PUSH=failed + unreachable ⇒ increment;
  run 2 alarms exit 7). A fetch failure on a run that pushed fine, or
  backed nothing up, leaves the streak untouched — a blip is still
  never punished.
- **RT-M4:** the divergence self-heal is rewritten — `git merge -s
  ours --no-commit` (remote commits become ancestors, append-only
  preserved, but the TREE stays exactly ours so remote-only files can
  never enter), the manifest union scrubs EVERY string value against
  the secret patterns (`[REDACTED]`, `merge_scrubbed_entries` count
  recorded), and the merged surface is re-scanned BEFORE anything is
  committed or pushed (dirty ⇒ `merge --abort` + `_alarms` + exit 8 —
  nothing committed, nothing pushed, no brick).
- **RT-M5 / RT-m1 / A-M2:** the `GIT_TRACE2` family is unset, and
  EVERY branch push (including both post-merge re-pushes) goes
  through one guarded helper — stderr captured, credential-redacted
  (`://user:pass@` and token-shaped strings), BRANCH_PUSH kept
  accurate, no bare `set -e` death, alarms never masked. The main
  push's redaction gains the same token-shape scrub.
- **RT-m2 / RT-m3:** shaped-name exclusion widened from the scripts
  snapshot to the WHOLE harness/ refresh surface (one `find` over
  harness/, `-print0` + silent delete), counted in state.json as
  `harness_skipped_shaped_count`; names are never printed.
- **A-C1 / RT-m5:** the FINAL-OUTCOME check is hardened and
  self-falsified — the ☑ backing requires a LINE-ANCHORED
  `^FINAL OUTCOME: CONSENSUS REACHED$`; every record dated on/after
  2026-11-14 (by filename OR `Date:` header, whichever is later) must
  carry EXACTLY ONE closure line; the check is extracted into a
  helper and a new test feeds it synthetic forgeries (inline-only
  mention, double line, back-dated filename, unbacked glyph, proper
  closure) so it can never silently weaken — the canary philosophy
  applied to the check itself.
- **RT-m4:** the exit-6 guard and the branch-push alarm are now
  machine-covered: `test_backup_script_production_is_opt_in`,
  `test_backup_script_guard_refuses_github_spellings` (8 spellings +
  clean lane), `test_backup_script_alarm_survives_unreachable_remote`
  (run 1 rc 0 / run 2 exit 7), and the hermetic cycle gained the
  shaped-file-on-refresh-surface assertions.
- **RT-m6 / A-m5:** input validation — a bare repo and an unborn-HEAD
  repo are refused fast (exit 2) with a message instead of raw
  rsync/git errors; `../path` push targets are classified as paths.
- **A-m4:** both rsyncs run with `-c` (checksum) — a same-size edit
  made in the same second as the worktree checkout can never be
  silently skipped.
- **A-m6 / S-m3:** stale baselines updated (process doc + project
  state); the "to be confirmed by CI" hedge replaced with the
  confirmed `6324a4d` counts.
- **A-m7:** the manifest note now says entries are keyed by the
  (seq, timestamp, message) triple — seq may repeat after a
  divergence union.
- **A-m8:** runbook §2 derives its blocker set from "this tag or its
  stage" (the S2 ≡ v0.6.3 equivalence is now stated).
- **A-m9:** ledger #3 extended — the system light/dark flip path
  (colorSchemeChanged → apply_theme without `_restyle`) folds into
  the S2 deferred item.
- **A-m10:** roadmap S6 gains the note: consider porting the backup
  merge/alarm core from bash to a tested Python module.
- **S-m1:** session log 2026-11-15 covers the missing G1-iter3
  continuation and this gate.
- **S-m2:** roadmap "Shipped" header reworded — retrospectively
  assessed at G1 with zero findings against the released line (G1
  never reached consensus; the shipped items carry no stage id by
  design).
- **RT-m7 (speculative):** off-domain redirector targets are
  documented as a residual outside any client-side spelling check
  (backups README threat-model note).
- **RT incident root cause:** lessons entry — a script whose default
  action is a production push WILL eventually run by accident; the
  dangerous path must be opt-in (two gates, two accidents).

## Fix-cycle completion (evidence, before iteration 2)

- **Backup v5** passed a 20/20 scratch matrix
  (`scripts/verify_backup_v5.sh`, kept in the sandbox snapshot):
  E1 poisoned-remote-manifest divergence → union scrubbed
  ([REDACTED] in the pushed manifest, scrub-count marker recorded,
  push RC 0, the next run appends cleanly — no brick); E2 remote
  root-file token → absent from the merged tree (`-s ours`) and from
  the branch; E3 `GIT_TRACE2=1` + a credentialed unreachable URL → no
  credential, no userinfo fragment in the output; E4 canary sabotage
  (the `gho_` pattern branch and `-rEn`→`-rn` flag drift) → exit 5
  both; E5 bare-repo and unborn-HEAD inputs → clean exit 2 with
  messages; E6 same-size same-second edit → captured in the same
  checkpoint (`-c`); E7 untracked content secret in harness/memory/
  → exit 4, remote untouched (the iter-2 critical regression probe);
  E8 hook-rejection → run 1 rc 0 recorded, run 2 exit 7 with the
  BRANCH-PUSH-ALARM banner.
- **Machine coverage:** `tests/test_harness_integrity.py` now runs 11
  tests; the four new ones cover opt-in default-refusal +
  conflicting mode, all eight github-spelling refusals + the clean
  lane, the unreachable-remote alarm double-run, and the
  FINAL-OUTCOME forgery suite; the hermetic cycle gained the
  refresh-surface shaped-name assertions.
- **Suite:** 723 passed + 9 skipped locally (was 719+9; +4 new
  tests). CI expectation for this fix commit: 732 per POSIX leg,
  windows 605 passed + 127 skipped — to be confirmed by CI before
  iteration-2 verdicts are recorded.
- Docs: backups README rewritten for v5 (opt-in, normalized refusal,
  alarm semantics, `-s ours` sanitized union + pre-commit re-scan,
  trace hygiene, guarded pushes, shaped names on both surfaces,
  input validation, redirector residual, exit-code table); decisions
  #16; lessons extended; process doc + execution-plan template +
  runbook + roadmap + ledger + project state updated; session log
  2026-11-15 added.

Iteration 2 outcome: recorded below after the re-run — not before.

> Iteration-1 interim outcome (superseded by the gate outcome at the
> end of this record): NO CONSENSUS — Red Team and Devil's Architect
> BLOCK; all findings remediated and execution-verified; iteration 2
> re-judged the fix commit `ad3b4e1`.

## Iteration 2 — re-judgment of the fix commit `ad3b4e1` (2026-11-16)

Pre-gate verification (orchestrator, before the agents launched):
tree clean at `ad3b4e1` == origin/main; local suite 723 passed +
9 skipped exact; GitHub check-runs 7/7 success; the fix cycle's
mandated closing backup completed as manifest seq 6 (branch tip
`551fce3`, main_push ok, branch_push ok — the prior session was cut
off mid-step and the event backup ran as this session's first action
after cleaning a stale-era tree overlay left by the sandbox recycle).

Roles launched independently in parallel (no shared context). The
first Red Team launch timed out mid-matrix; its replacement ran a
fresh bounded priority-ordered matrix (see RT-m4 — the dead run left
an orphaned worktree that the next run's `git worktree prune`
self-healed).

| Task | Role | Verdict | Method |
|---|---|---|---|
| G1-iter4-i2-R | Red Team | **BLOCK** | ~35 bounded experiments in fresh `/tmp/rt-scratch2` clones (~20 full script runs, all via the sanctioned three-override pattern; md5-verified script; zero pushes outside scratch; production checkout verified clean before/after): P1 opt-in gate executed (env-less rc 6, `=0`/`=yes` rc 6, missing-default-repo sim rc 6, conflicting exit 2); P2 20-spelling guard matrix — 11 refused / 9 ALLOWED (the critical); P3 divergence ×3 (nested-value poison scrubbed rc 0, `-s ours` file isolation, key-poison exit 8 alarms-first); P4 hook-rejection double-run + the 401-challenge lane that produced M1 (raw token ×2); P5 10-scenario forgery matrix — 7 silent passes (the second critical); P6 alarm double-runs rc 0→7; P7 `verify_backup_v5.sh` 20/20 re-run; P8 shaped names; P9 canary sabotage / dead-PID lock / racer / message-scan |
| G1-iter4-i2-A | Devil's Architect | PROCEED-WITH-FINDINGS | full v5 script read (807 lines) + `6324a4d..ad3b4e1` (13 files, +1005/−195); scratch-clone baseline reproduced (723+9 in 88.6s, integrity 11/11); CI verified read-only (run 43721768665, 7/7); forgery matrix: unbacked flip caught, cross-stage/dateless/fenced silent (Major 1); three deliberate check weakenings each caught by the self-falsification suite (it genuinely pins what it covers); backup-script mutations: reverting opt-in / canonicalizer / unreachable-alarm each made its new machine test fail; offline guard probe: gist./api. ALLOWED, 8 spellings + `:8443`/`GitHub.Com.` refused; E2E partial-env-loss run pushed a test checkpoint rc 0 (Major 2); doc cross-checks found README:112/115, :45/:53/:189 falsified and runbook §5 / lessons stale |
| G1-iter4-i2-S | Ship Steward | PROCEED-WITH-FINDINGS | full suite twice (723+9 in 89.35s and 91.44s, tree clean before/after, 9 skips identified Qt-binding-gated); CI per-leg counts from all 7 downloaded job logs — 732 × 4 POSIX (ubuntu 87.54s, macos 78.34s, PySide2-Qt5 33.33s, PySide6-6.2 35.33s) + windows 605+127, all EXACT; all 21 iteration-1 resolution items mapped to hunks with exactly one claim/code mismatch (the major); test math confirmed (11 integrity tests, forgery suite = one test, 5 classes); 20/20 scratch matrix re-executed (8.5s); docs/ledger/runbook audited; audit trail verified (seq 6 faithful, seq 5 still invalid, failcount 0 after the seq-6 reset — investigated, no anomaly); release-risk pass: no technical blocker to an S2 pre-gate beyond the closeout ritual |

**Consensus: NOT reached (one BLOCK — Red Team). This was iteration 2
of 2: the gate's cap is exhausted and the decision escalates to the
project owner. Per the G1-iter3 precedent, every finding from both
iterations is remediated in this commit, which carries this record.**

### Red Team — BLOCK (verbatim from the verdict block)

CRITICAL:
- C1. The v5 github-refusal guard misses github SUBDOMAIN hosts —
  `www.github.com` is a live git endpoint for the production repo.
  The refusal case matched only `github.com`, `github.com/*`,
  `ssh.github.com`, `ssh.github.com/*`. Verbatim guard extraction +
  full runs show ALLOWED (rc 0) for `gist.github.com/<id>.git`,
  `www.github.com/maniesh-NR/Proto-Clean.git`, `api.github.com/x`,
  `education.github.com/x`, credentialed/scp/case/trailing-dot/:443//
  variants of all of these, and remote NAMES resolving to them.
  Reachability verified anonymously: `git ls-remote
  https://www.github.com/maniesh-NR/Proto-Clean` returned production
  HEAD `ad3b4e1` (git follows the 301); a gist target ran end-to-end
  rc 0 under a safe `url.insteadOf` rewrite. Falsifies the README
  "a TEST run never reaches github — ANY github host, however the
  target is spelled" and the machine test's docstring.
- C2. The hardened FINAL-OUTCOME ☑ check is still silently forgeable
  — four distinct silent passes executed (pytest green with an
  unbacked S2 ☐→☑ flip): undated records (no filename date, no
  `Date:` header — escapes the must-carry rule yet still backs
  glyphs, including with TWO closure lines and/or the line inside a
  fence); substring stage-id matching (`S20` backs `S2`); prose
  mention (a record for another stage that mentions S2); fenced
  documentation example at column 0. The self-falsification canary
  tests none of the four vectors — the A-C1 remediation claim
  ("hardened and self-falsified … can never silently weaken")
  falsified by execution.

MAJOR:
- M1. `GIT_CURL_VERBOSE` is not unset (the enumerated list covered
  GIT_TRACE*/TRACE2* but not the legacy alias) and the MAIN-push
  redaction lacks the token-shape scrub (inline at :309-312, unlike
  `_push_branch` :656) — executed raw-token leak: main-ahead lane +
  `GIT_CURL_VERBOSE=1` + credentialed local 401/500 server printed
  the raw token twice. README "the FULL trace families are unset" /
  "every push goes through one guarded helper" / "the main-push
  redaction gained the same token-shape scrub" all false.
- M2. Test-mode isolation guards only the push TARGET: a partial
  override set (PUSH_REMOTE set, REPO left default) entered TEST mode
  against the PRODUCTION checkout, committed an
  "ACCIDENTAL TEST CHECKPOINT" on its local `sandbox/backups` (rc 0,
  tree clean, no warning beyond a later "keeping them" echo), and the
  next production run pushed it to the production remote (simulated
  end-to-end). The E9c/t5 accident class is NOT removed — the
  env-less variant is, the partial-override variant is not.

MINOR: m1 union scrub covers string VALUES only — a token in a dict
KEY rode the union, correctly exit-8-aborted by the pre-commit
re-scan (nothing pushed) but the divergence could then never
self-heal (exit-8 loop, loud via BRANCH-PUSH-ALARM) until a human
repaired the remote manifest; m2 `api.github.com` /
`education.github.com` spellings pass the guard (anonymous contact
possible); m3 under `GIT_CURL_VERBOSE`, "Server auth using Basic with
user 'u'" prints even through the guarded branch-push helper; m4
[ENVIRONMENT] the timed-out first Red Team launch left an orphaned
worktree `/tmp/pc-backup.94wwVs` — pruned automatically on the next
run; no production contamination.

### Devil's Architect — PROCEED-WITH-FINDINGS (findings)

MAJOR:
1. The A-C1 defect class survives in the hardened ☑-check: backing
   is still incidence-based — a genuine `FINAL OUTCOME: CONSENSUS
   REACHED` record for stage S1 machine-blesses ☑ flips for any
   OTHER stage it mentions in prose (S2, S6 — proven in scratch by
   simulating this gate's own closure; arms the moment the first
   consensus record lands), dateless records back any stage, and a
   column-0 fenced example both satisfies exactly-one and backs a ☑
   (falsifying the process doc's "inline mentions never back a ☑").
   The self-falsification suite pins what it enumerates but its
   enumeration misses these three classes. Fix must land in the same
   commit that records this gate's outcome — before the first
   CONSENSUS REACHED record exists.
2. The v5 guard's production/github identity model is incomplete:
   github subdomains escape the any-host denylist (gist. is a real
   git-push endpoint), and production identity is the github spelling
   only — a partial env-override loss (two of three overrides set,
   PUSH_REMOTE forgotten, clone origin = the production checkout
   path) pushed a full test checkpoint RC 0 into the production repo
   (E2E-proven); the next production run's LOCAL_AHEAD logic
   propagates it to github. "Removing the entire accident class"
   overclaims. Recommend all-three-or-none overrides + host-suffix
   github deny + production-local-path compare.

MINOR: 1) README false claims about the main-push path (no shared
helper, no token scrub at :312); 2) invalid-remote exit-6 prints the
raw target (:141) vs README "never prints the target"; 3) runbook §5
close-out invocation stale (exits 6 under v5); 4) lessons baseline
still 712+6/718 (third stale copy); 5) exactly-one-closure-line
forces interim-line rewrites between iterations and implicitly bans
fenced format examples — neither documented; 6) the bash→Python port
hedge is an unleveraged "consider" note — make it a ledger row gated
at S6; [SPECULATIVE] each gate's remediation enlarges the harness
attack surface the next gate attacks (v2→v4→v5 each yielded new
criticals/majors), with no bounded exit criterion for the harness
subsystem; 7) S1's closure criterion is implicit and the closure
choreography (glyph flip vs closure-line record vs state-doc commit
order) is defined nowhere.

### Ship Steward — PROCEED-WITH-FINDINGS (findings)

MAJOR:
1. RT-M5's resolution claim "the main push's redaction gains the same
   token-shape scrub" (this record's Resolution cycle §RT-M5; repeated
   in the backups README) is not implemented at `ad3b4e1`:
   `scripts/sandbox_backup.sh:312` still scrubs only the userinfo form
   (byte-identical to `6324a4d` — zero diff hunks on the main-push
   path) while `_push_branch` :653 has the full token-shape scrub. A
   false remediation claim in the gate record + README is the
   documented-guarantee-vs-code class this process cannot carry
   silently.

MINOR: 1) stale baseline in `02-lessons.md` (712+6 / 718 / 596+122 vs
actual 723+9 / 732 / 605+127); 2) the live manifest note on
`sandbox/backups` still reads "keyed by seq" — the v5 script writes
the triple-key note only on fresh-create/migration, so A-m7's fix
reached the template but not the production artifact.

### Verified-good (all three agents, evidence in their reports)

- Local suite 723 passed + 9 skipped exact (Steward twice, Architect
  once); CI 7/7 on `ad3b4e1` with per-leg counts exact from the
  downloaded logs (732 × 4 POSIX, 605+127 windows); wheel +
  Android legs green.
- All six G1-iter3-i2 remediation surfaces verified-good at v5 by
  execution: opt-in gate (every variant), the eight machine-tested
  guard spellings + `:8443`/`GitHub.Com.`, unreachable-aware alarm
  (double-runs rc 0→7 both lanes), `-s ours` divergence union with
  value scrubbing (nested-value poison → `[REDACTED]`, no brick),
  remote-only files never enter, TRACE2/TRACE family redaction,
  hook-rejection handling, shaped names both surfaces (count 2, never
  printed), canary self-test (pattern+flag drift → exit 5), lock
  stealing (exactly one racer), message-scan (secret in message →
  exit 4 pre-echo), `verify_backup_v5.sh` exists on the branch and
  passes 20/20 (re-executed by RT and Steward independently).
- The three G1-iter4 machine tests are genuinely mutation-covering
  (Architect: reverting opt-in / canonicalizer / alarm each made its
  test fail); the pre-hardening forgery check genuinely pins what it
  enumerates (three deliberate weakenings all caught).
- Manifest seq 6 faithful; seq 5 still annotated invalid; seq 1-6
  monotonic append-only; failcount 0 (the seq-6 run reset the stale
  streak the cut-off session left); exactly one line-anchored FINAL
  OUTCOME line; no pre-recording anywhere; ledger rows #1-#8 real;
  roadmap/runbook/ledger S2 scope consistent; the release surface
  internally consistent pre-v0.6.3; Material You architecture
  untouched by the fix commit and sound at design level (Qt-free md3
  engine, accessor discipline, time-boxed probes with brand
  fallback).

## Resolution cycle (fixes applied in THIS commit — every finding from both iterations)

- **RT-C1 / A-M2(i) / RT-m2:** host-suffix denial — the guard now
  extracts the HOST from the normalized target and matches
  `github.com|*.github.com` (any subdomain: gist./www./api./
  education./…), replacing the enumerated list; enumeration was the
  hole. Machine test extended with 5 subdomain variants (plain,
  credentialed, remote-name).
- **RT-C2 / A-M1 (the Architect's condition honored: the fix lands in
  the same commit that records this outcome, before any CONSENSUS
  REACHED record exists):** backing redesigned — a record backs a ☑
  only when it DECLARES the stage (`Stage: S<n>` lines), is dated,
  and carries its closure as the LAST non-empty line after fenced
  code blocks are stripped; mention matching is word-boundary
  (`S20` no longer mentions `S2`); records dated on/after 2026-11-16
  must declare their stage(s). All four records carry `Stage: S1`
  (the 2026-11-13 ones voluntarily, for uniformity). Forgery suite
  extended: fenced, undated, cross-stage, substring, non-terminal,
  undeclared — 10 classes, each asserted caught, plus a positive
  proper-closure lane.
- **RT-M1 / A-m1 / S-M1:** trace/config env neutralized by PATTERN
  over the live environment (every `GIT_TRACE*` variant,
  `GIT_CURL_VERBOSE`, and git's env-config injection
  `GIT_CONFIG_KEY*`/`VALUE*`/`COUNT`/`PARAMETERS` — enumeration was
  exactly how the legacy alias escaped); the main push now goes
  through `_push_main` with the same userinfo + token-shape redaction
  as `_push_branch` (the parity the record and README claimed at v5
  is now real). Machine test: 401-server lane with the exact hostile
  env (CURL_VERBOSE + TRACE2 + TRACE + config injection) — raw token
  absent, verbose output absent, redaction label present.
- **RT-M2 / A-M2(ii):** overrides are ALL-THREE or NONE — a partial
  set (any 1-of-3 or 2-of-3 combination) refuses exit 2 before any
  action; a TEST run additionally refuses the production checkout
  itself (exit 6, literal + canonicalized path compare). Machine test
  covers all six partial combinations and three production-path
  spellings.
- **RT-m1:** the divergence-union scrub now covers dict KEYS as well
  as values — a poisoned key is neutralized to `[REDACTED]` and the
  branch heals on the spot instead of exit-8-looping. Machine test:
  full four-run scenario (healthy → poisoned remote → unreachable →
  union heal → clean append).
- **RT-m3:** covered by the pattern-matched env scrub (the leak
  printed only under curl verbose).
- **RT-m4 (environment):** no code change — the orphaned worktree was
  pruned automatically by the next run's `git worktree prune`
  (observed self-healing); recorded here for the audit trail.
- **A-m2 / RT echo:** the not-a-configured-remote refusal redacts the
  target it echoes (userinfo + token-shape). Machine test: scp-syntax
  credentialed target → exit 6 with `[REDACTED]`, never the raw
  target.
- **A-m3:** runbook §5 close-out invocation corrected to the opt-in
  form (`PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh
  "release vX.Y.Z"`).
- **A-m4 / S-m1:** lessons baseline updated (third stale copy).
- **S-m2:** the manifest note is normalized on every append AND in
  the union path (idempotent) — the live branch's "keyed by seq"
  note self-corrects at the next checkpoint.
- **A-m5:** the exactly-one rule's consequence — the interim closure
  line is rewritten at each iteration's conclusion (iteration
  outcomes remain in the verdict prose and git history; this record
  demonstrates the pattern) — is now documented in the process doc,
  along with the fenced-example ban.
- **A-m6 / A-m7 (speculative):** ledger row #9 — port the backup
  merge/alarm core to a tested Python module, gated at S6, with an
  explicit bounded exit criterion for the harness subsystem (the
  port + a frozen verification matrix); the speculative
  attack-surface-growth observation is recorded in the row.
- **A-m8:** closure choreography defined in the process doc: (1)
  verdicts recorded, (2) closure line written/rewritten as the last
  line, (3) roadmap glyph flip lands in the SAME commit, (4) state
  doc + session log, (5) commit + push main, (6) event backup. A
  glyph flip never precedes its backing record in any push.

## Fix-cycle completion (evidence, at this commit)

- **Script v6** (same single file, `scripts/sandbox_backup.sh`):
  pattern-matched env scrub, all-or-none overrides +
  production-checkout refusal, host-suffix github denial, redacted
  refusal echo, guarded `_push_main`, key-covering union scrub, note
  normalization. `bash -n` clean; live probes: gist/www/api targets
  exit 6, clean local lane rc 0, partial override exit 2,
  TEST-on-production-repo exit 6.
- **Machine coverage:** `tests/test_harness_integrity.py` now runs
  15 tests — the four new ones cover partial overrides +
  production-checkout refusal, subdomain spellings (5 new variants +
  remote name), main-push redaction + trace/config-env hygiene
  (401-server lane), and the union key-scrub heal; the guard and
  forgery suites were extended in place.
- **Suite:** 727 passed + 9 skipped locally (was 723+9; +4). CI
  expectation for this commit: 736 per POSIX leg, windows 605
  passed + 131 skipped — to be confirmed by CI before any further
  stage work.
- **Docs:** backups README rewritten for v6; process doc (closure
  choreography + rewrite rule + Stage-declaration rule); runbook §5;
  lessons; ledger #9; decisions #17; roadmap gate history; project
  state; session log
  `memory/session-log/2026-11-16-g1-iter4-iteration2.md`.
- **Scratch matrix:** `scripts/verify_backup_v6.sh` (sandbox
  snapshot) covers the new scenarios end-to-end: E9 subdomain
  refusal matrix, E10 partial-override refusals, E11
  CURL_VERBOSE/config-injection + main-push redaction lane, E12
  key-poison union heal, E13 refusal-echo redaction — 22/22 executed
  green before commit (E9 x8, E10 x8, E11 x1, E12 x4, E13 x1).
  First CI run on the remediation commit broke 4/7 legs: the new
  main-push test's `git commit --allow-empty` relied on ambient git
  identity (exit 128 on runners — the G1-iter3 lesson re-learned;
  windows/Android/wheel unaffected). Disclosed here; fixed with an
  inline identity in the follow-up commit that carries this note.

FINAL OUTCOME: NO CONSENSUS — iteration cap reached (2 of 2); Red Team BLOCK on two criticals (github-subdomain guard bypass, FINAL-OUTCOME backing still forgeable) and two majors (main-push credential leak under GIT_CURL_VERBOSE, partial-override isolation gap) vs Architect and Steward PROCEED-WITH-FINDINGS; every finding from both iterations remediated and machine-covered in this commit; escalated to the project owner — a fresh gate on this remediation commit is the owner's call (the G1 → G1-iter3 → G1-iter4 precedent).

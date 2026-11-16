# Consensus Gate — S1 (iteration 4, owner-ordered fresh gate)

Date: 2026-11-15 · Gate ID: G1-iter4 (fresh gate ordered by the project
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

FINAL OUTCOME: NO CONSENSUS (iteration 1 of 2) — Red Team and Devil's Architect BLOCK; all findings remediated and execution-verified; iteration 2 re-judges this fix commit.

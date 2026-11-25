# Consensus Gate — S8 pre-gate iteration 3 (owner-ordered fresh gate)

Stage: S8

Date: 2026-11-25 (iteration 1 concluded; remediation cycle pending —
iteration 2 re-judges the amended deliverables)
Gate ID: S8-PG1-iter3 — a FRESH pre-gate ordered by the project
owner per decision #22 (2026-11-25, "D1:a") after S8-PG1 closed at
its 2-iteration cap with NO CONSENSUS; this gate has its OWN cap of
2 (this is iteration 1). Predecessor context: decisions #19/#20/
#20b/#21/#22; the S8-PG1 record
(`memory/consensus-log/2026-11-19-s8-pre-gate.md`, both iterations
+ the closing remediation); S1 closed earlier today
(`memory/consensus-log/2026-11-25-S1-closing-gate.md`).
Reviewed commit (pinned): `2ccb4fb6f5881f2329dec01dca85fdaf6756f43c`
== origin/main. The deliverables under judgment:
`harness/backups/allowlist-inversion-evaluation.md` and
`harness/process/s8-execution-plan.md` — verified UNCHANGED since
the cap-closure remediation `865580e` by all three roles
(`git diff --stat 865580e..2ccb4fb -- <both files>` = empty; the
two commits between are the decision-#22 disposition and the S1
closure, documents-only). No port code has changed.

## Launch and verification (orchestrator)

Three roles launched in parallel as independent agents, no shared
context, no visibility into each other's verdicts before
publishing. All three pinned `2ccb4fb` and reported the working
tree clean except the known PROJECT_MEMORY.md post-commit-hook
refresh artifact (diff inspected: git-activity log rotation only).
Verification executed by the roles themselves (all TEST-mode,
scratch-only, zero network, no repo file modified, no incident):

- Full suite: **728 passed + 9 skipped, 0 failed** — all three
  roles ran it independently (98 s / 96.32 s / 96.09 s) — exact
  baseline match.
- Integrity suite: 16 passed — all three roles independently.
- Matrices: Red Team and Ship Steward each ran ALL SIX in full —
  **121 checks, 0 failed** (each reported the exact per-matrix
  counts 20/22/25/19/26/9). Disclosure (Red Team): a FIRST
  back-to-back run showed v5 15/5, non-reproducible — traced to
  stale `/tmp/pc-*-verify` scratch left by prior gate sessions
  (all matrices are scratch-only), NOT a repo finding; after
  cleaning, 3× consecutive clean runs 121/0. The Ship Steward's
  independent run was 121/0 outright.
- CI (public REST API, unauthenticated, no credentials
  reproduced): the Ship Steward verified the line — run 45554184443
  on `2ccb4fb` completed, conclusion success, 7/7 jobs success
  (including the macOS-latest 3.12 leg); run 45551538029 on
  `5bf91ad` 7/7; the carried `eb459b1` observation re-verified:
  run 44536786320 failed its macOS-latest 3.12 leg ONLY (6/7), and
  that leg is green on every subsequent run (44542518059,
  45551538029, 45554184443) — one-off documents-only flake,
  consistent with the S1-closing disposition.
- The Red Team executed scratch batteries under /tmp only
  (~29 MB, zero network, zero repo writes): a C-B predicate
  harness implementing the ancestor-canonicalized containment
  exactly per item 2 (resilience shapes legal; every prod-adjacent
  shape refused incl. symlinked-ancestor, `//`-prefix, dot-dot
  escape — no lexical/symlink/cwd bypass found); the
  later-materialized-alias E2E falsification (see RT-C2); C-C
  honesty probes (the retained pushInsteadOf refusal fires exit 6;
  a transport-blocked local rewrite still lands — the wrapper
  cannot see it, `protocol.file.allow=never` would break the
  legitimate push — the residual is structural and honestly
  claimed); post-3a module-lookup simulations (see RT-C1); static
  anchor audits of every 3a/3b/stays-in-bash site cited by the
  plan (all verified present as cited, incl. the four
  PROD-literal sites and the scrub/push/scan anchors); the
  consumer-inventory census (29 test hits / 34 matrix hits; the
  loopback QUARTET verified complete — no fifth consumer).
- The Ship Steward derived the coverage arithmetic independently:
  the After-3a cell derives (121, five 1:1 re-homes); the
  After-3b cell does NOT (see Steward-M1).

## Roles (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| S8I3-R | Red Team | **BLOCK** | executed specification attacks: post-3a module-lookup simulations; later-materialized-alias E2E falsification; C-B predicate harness; C-C honesty probes; anchor + inventory audits; matrices |
| S8I3-A | Devil's Architect | PROCEED-WITH-FINDINGS | full design review of both documents (stage boundaries, module contract, exit criterion, consistency with decisions/roadmap/ledger); anchor cross-check of the 3a edit list against the real PROD-literal inventory |
| S8I3-S | Ship Steward | PROCEED-WITH-FINDINGS | baseline exact; all six matrices 121/0; CI via public API incl. the line; coverage-arithmetic derivation; machine-compatibility anchor audit; docs accuracy |

**Consensus: NOT reached (one BLOCK). The fix cycle starts; the
gate re-runs on the fixes as iteration 2 (within this fresh gate's
cap of 2).**

## Verdicts (verbatim from the agents' verdict blocks)

### Red Team — BLOCK

CRITICAL:
1. **The STAGE-3a parity oracle is unsatisfiable as written — the
   bash→module invocation mechanism is unspecified, and the plan's
   own claims about it are mutually incompatible (the C-A
   boundary-contradiction class, in a form the closing remediation
   missed).** The plan deletes the bash `PROD_CHECKOUT` constant
   and delegates the guard to "python3 scripts/backup_core.py" (a
   cwd-relative path, per the shim-invocation spec), with the
   identity "derived from the module's own file location … no env
   override in TEST mode" — while simultaneously claiming "v5 E4
   and v7 E18 survive unedited" and "LEDGERED 3a EDIT LIST
   (exhaustive — nothing else changes)". But E4 (v5 L128–139) and
   E18 (v7 L179–224, L205–224) execute sed/cp **mutated copies**
   of the script placed in scratch lane dirs with **no module
   beside them**; the copies must pass the delegated guard to
   reach the self-test (exit 5) / index re-scan (exit 4). Executed
   simulation of every candidate resolution: (a) **$0-relative**
   module lookup (the only one consistent with
   identity-from-module-location + repo-residency + CI): the
   copies find no module → fail-closed exit 6 ≠ 5/4 → E4/E18 red
   at 3a with zero edits (mini post-3a harness: `rc=6 (E4 expects
   5, E18 expects 4)`); (b) **cwd-relative** (the plan's literal
   spelling): the module resolves to the TEST repo's own copy →
   identity = the scratch clone — a normal machine lane's repo
   operand equals the identity → refused (executed:
   `verdict=refuse` for the repo operand, i.e. 737×4 red), and a
   prod-spelled push operand is **ALLOWED** (executed:
   `verdict=allow` for an operand inside the stand-in production —
   the guard protects the wrong path); (c) absolute hard-coded
   module path: CI legs have no `/home/z/my-project/cleanroom` →
   every lane fail-closed. Additionally, the plan's own
   seam-anomaly lane ("a stubbed module that emits garbage →
   exit 6") implies $0-relative stubbing, which directly
   contradicts E4/E18's module-free copies. No resolution
   satisfies "the SURVIVING checks … green with zero expectation
   edits = the equivalence proof". Remediation is cheap (add the
   four copy sites to the ledgered 3a list — copy the module
   beside each mutated script or pin a module-path rule for
   probes) but as written the 3a commit cannot land green.
2. **The later-materialized-alias coverage claim in BOTH documents
   is false — executed E2E falsification: a symlink planted at a
   non-existent push-target suffix after judgment lands the
   checkpoint in the production .git with all guards green.** Plan
   exit-criterion item 2 and the evaluation's criterion paragraph
   both state the class "is covered at push time by the retained
   symlinked-.git + git-dir containment". Those checks are
   REPO-side, guard-time checks (sandbox_backup.sh L258–295 — the
   `$REPO/.git` symlink refusal and git-dir containment; the
   push-target containment at L594–611 also runs at guard time);
   **nothing re-validates the push target at push time**.
   Executed: operand `/tmp/rt-s8i3/scratch/nope.git` (non-existent
   at judgment → legal under today's literal-only degradation AND
   under the port's ancestor-canonicalized containment — deepest
   existing ancestor = scratch); an instrumented copy of the real
   script (PROD patched to a stand-in, both-sides rule) plants
   `ln -s standin-prod/checkout/.git scratch/nope.git` immediately
   after the guard; the run completes rc 0 ("branch push: ok") and
   the stand-in **production .git receives the full
   sandbox/backups checkpoint** (a994f45 on 2ccb4fb), with zero
   refusal/containment/symlink messages in the output. The frozen
   residual list (README item 3) documents the config-rewrite face
   of this multi-second window as a residual ("the guard resolves
   the target once, pre-action; the pushes re-resolve at push
   time… requires a concurrent writer") — the documents claim the
   strictly-worse filesystem-symlink face (which lands in
   production .git) is *covered*. This is the exact overclaim
   class that was C-C last round, now on the safety justification
   for keeping non-existent-under-scratch legal. Remediation:
   record the alias face as the filesystem face of frozen residual
   item 3 (by gate finding, per the residual-list governance) or
   specify a push-time re-canonicalization in the guarded push
   helpers.

MAJOR:
1. **The coverage table's post-3b cell is still not derivable from
   the ledgered 3b edit list (off-by-one) — the exact defect the
   cap closure claimed fixed ("coverage table made derivable —
   corrected at cap closure, Steward-M1").** The 3b edit list and
   the quartet row both specify E11 → a **two-lane** re-homing
   (success + hook-rejection failure), but the matrix row asserts
   v6 stays "(22 checks, re-shaped)" and "121 preserved". Verified
   by execution: v6 today = 22 PASS lines with E11 = exactly one
   check (line 17 of the PASS list). Replacing 1 check with 2 lanes
   gives v6=23 / total=122, contradicting the "unchanged 121"
   cell. Same class as the prior round's Steward-M1 (a major
   then); the derivability claim fails for this cell.

MINOR:
1. The 3b edit-list item (b) enumerates the message-anchored
   assert sites on retiring families as "tests L989/L1151/L1187"
   only; the matrix twins are unenumerated: v8 E20 L91 and v9 E29
   L242 grep "RELATIVE", v10 E32 L136 greps "fetch" (all retiring
   families). The token rule as phrased ("REQUIRED to carry the
   family keyword") covers them functionally — same tokens — but
   the "exhaustive" site enumeration undercounts.
2. The port-time note says the stale citation
   (sandbox_backup.sh ~L1132, "scripts/verify_backup_v7.sh" —
   verified present) is "fix at STAGE 3a", but the 3a edit list is
   declared "exhaustive — nothing else changes" and does not
   include that comment edit. Comment-only, no semantic effect; a
   bookkeeping inconsistency between two plan sections.

EXECUTED (summary): HEAD = `2ccb4fb`; integrity 16; full suite
728+9 (98 s); matrices 121/0 (3× clean after a disclosed
non-reproducible first-run v5 15/5 traced to stale /tmp scratch);
C-B predicate harness — resilience shapes legal, every
prod-adjacent shape refused, no bypass; alias falsification
executed E2E (rc 0, checkpoint in stand-in production .git); C-C
probes — retained refusal fires exit 6, local rewrite invisible to
the wrapper (residual structural and honestly claimed); post-3a
module-lookup simulations (three candidate resolutions, each
falsified); inventory census 29/34 hits, QUARTET complete, no
fifth consumer; static anchor audits — every cited 3a/3b/stays-in-
bash site present as cited.

NOTES (Red Team): C-A (3a parity oracle) NOT fully resolved — the
five-lane re-scope itself verifies (anchor enumeration accurate;
the module-seam stub + neutralization-hook design implementable at
module level) but the restated oracle is falsified by the
module-lookup gap (new critical 1). C-B (ancestor-canonicalized
containment) RESOLVED in substance (predicate implementable,
resilience lanes stay green, prod-adjacent shapes refused, no
lexical/symlink/cwd bypass; the E11 failure-lane re-spec verified
live via the v5-E8 shape) — except the *coverage claim attached to
it* (critical 2). C-C (transport backstop honesty) RESOLVED
(network-only scoping honest, execution-verified both halves;
retained families exist and fire). Consumer inventory complete at
this tree. Both criticals are narrow and cheaply remediable at
document level (C1: add the four copy sites to the ledgered 3a
edit list + pin the module-lookup rule; C2: re-word the alias
class as the filesystem face of frozen residual item 3 or add a
push-time re-check) — but this gate's function is to refuse
false/unsatisfiable specifications before port execution, and both
are of the boundary-contradiction/overclaim class that produced
every prior BLOCK.

### Devil's Architect — PROCEED-WITH-FINDINGS

CRITICAL: none.

MAJOR:
1. **The coverage-arithmetic table's post-3b cell is not derivable
   and is off by one — the residual of iter-2 Steward-M1, whose
   "corrected at cap closure" claim my derivation falsifies.**
   [Same finding as RT-M1 / Steward-M1 — three-role convergence.
   Derivation: E11 is exactly one `ok/bad` pair in v6 today
   (verify_backup_v6.sh L142–149); the 3b edit list and the quartet
   row commit to the two-lane re-homing INSIDE v6 ⇒ v6 = 22−1+2 =
   23, total = 122, not "121 preserved". The cell's parenthetical
   "(22 checks, re-shaped)" and "stays INSIDE v6" cannot both be
   true. The plan's own drift instrument carries a wrong expected
   number for 3b. Fix: one cell edit (v6 22→23, 121→122, with the
   −1/+2 lane map), or pin the E11 re-homing as 1-for-1 in-matrix
   plus one machine-suite lane and correct the "INSIDE v6"
   wording.]
2. **Exit-criterion item 2's closing clause overclaims coverage for
   the later-materialized-alias class — the retained mechanisms it
   cites are guard-time REPO-operand checks, not push-time
   PUSH-TARGET checks.** [Same finding as RT-C2, filed as a major
   here. The symlinked-.git refusal (sandbox_backup.sh L264–270)
   tests `$REPO/.git`; the git-dir containment (L283–294) tests the
   REPO's discovered git dir; both run at guard time; the push
   helpers (L745–770) perform no target re-check. No regression vs
   today (the physical compare's `cd … || true` at L592 skips
   non-existent targets today too; a pre-existing alias IS caught
   by canonicalization — an improvement), and exploitation needs a
   concurrent writer — the boundary the README's frozen residual
   item 3 already carries. The honest form: either specify a
   push-time target re-check in the module contract (the helpers
   can re-derive/re-compare the canonical target cheaply) or
   declare the class the README item-3 residual.]

MINOR:
1. **The refusal-neutralization test hook's delivery path through
   the bash entrypoint is unspecified** — the E20/E25/E29/E31-class
   lanes prove the incident end-to-end (neutralized refusal → the
   push lands in the rewrite target/sink), which requires the hook
   flag to reach the module *through*
   `scripts/sandbox_backup.sh`; the shim surface is pinned as
   `python3 scripts/backup_core.py <subcommand>` and the 3a list
   claims exhaustiveness while naming no pass-through (e.g. a
   `PC_*` env var honored only in TEST mode, translated by the
   shim). One clause fixes it.
2. **The 3b LEDGERED edit list ("exhaustive") omits the `_git`
   wrapper's bash-side rewiring** — wrapping every TEST-mode git
   invocation the script spawns is the largest bash edit of 3b; it
   is named in the STAGE 3b prose and the stays-in-bash list, so
   the stage is implementable, but the "exhaustive" label does not
   cover it.
3. **E34's pytest twin is mis-staged:** the after-3a cell commits
   to "the five demo re-homes' pytest twins" at 3a, but v10 E34's
   mechanism (union prefers OURS on a same-triple collision) is
   `merge_union` behavior, which does not exist in the module until
   STAGE 3c — E34's twin is naturally a 3c artifact (four of five
   twins are writable at 3a).
4. **The plan's STAGE 2 closing text is overtaken on the line
   under judgment** — "the next step is the owner's disposition
   (fresh gate on this line / further split / descope) — not
   pre-recorded here." Decision #22 has dispositioned D1:a; this
   fresh gate is running. One clause cures it.
5. **Evaluation citation imprecision:** "v9 E26 stays rc-0" — E26
   is a two-part lane; its scp-`:22:` sub-lane stays a refusal
   (correctly), only its plain-remote control sub-lane stays rc-0.
6. **STAGE 5's stated retirement blast radius is incomplete:** the
   named same-commit amendment set is checklist item (e) + the
   backups README, but the bash entrypoint is also invoked by the
   execution-plan template, the process doc's closure choreography
   step 6, the release runbook, and harness/README — all needing
   the same-commit re-point if the retire option is chosen (the
   shim option avoids it).

EXECUTED (summary): HEAD = `2ccb4fb`; deliverables unchanged since
`865580e` (diff empty); integrity 16; full suite 728+9 (96.32 s);
matrix counts re-derived from source = 121; read-only anchor audit
— every citation verified live (all test/sandbox/matrix anchors;
the 3a edit list covers every real PROD-literal site repo-wide:
v6 L99, v7 L92, v8 L114, v9 L132/L255/L303, v10 L93/L176; the five
anchor-patching lanes are exactly the right set; v5 E4 + v7 E18
correctly survive unedited; no integrity-suite lane hand-copies
the PROD path); inventory claims verify exactly.

NOTES (Devil's Architect): all iteration-2 Architect findings
verify RESOLVED in the amended documents (Arch-C1/C-A — resolved by
the 3a re-scope with the anchor inventory confirming the five-lane
set exactly right and complete; the merge/alarm/state.json cutover
— resolved by STAGE 3c with per-function pinning; the seam
protocol — resolved, fail-closed taxonomy; the
ancestor-canonicalization — resolved with all five resilience
lanes green by design; the module contract — resolved in substance
with minor #1 as the residual; the Seq deferral — resolved,
ledger #10 coherent; the retirement timing — resolved consistently
in 4a/6/table; the E10/E15 timing — resolved into 3a; all six
iter-2 minors resolved). Iteration-1 findings all resolved.
Design concurrence: the split is the right abstraction — the module
owns exactly the decidable, unit-testable core (3.8-clean,
stdlib-only, repo-only, fail-closed seam); bash retains exactly
what must be parent-side (env scrub before any spawn, push helpers
wrapping the actual spawns, scan/self-test, orchestration, lock);
the two-implementation drift surface is bounded to two pairs pinned
by live-extracted textual parity lanes + module unit pins + the
behaviorally-pinned re-homed failure lane; STAGE 3c deletes the
dual implementations in-commit. The two majors are one-sentence
document edits; neither blocks the port.

### Ship Steward — PROCEED-WITH-FINDINGS

CRITICAL: none.

MAJOR:
1. **Coverage-arithmetic off-by-one in the post-3b cell — the
   prior Steward-M1 class, only partially remediated.** [Same
   finding as RT-M1 / Arch-M1 — three-role convergence. The
   E11-is-one-check premise is execution-verified (v6 PASS-line
   census: E9=8, E10=8, E11=1, E12=4, E13=1 = 22); the strict
   derivation gives v6 = 23 / total = 122; the cell states 22 /
   "121 preserved", and "unchanged 121 through the STAGE-6 gate"
   propagates it. Not delivery-blocking: the 3a cell derives
   correctly and the 3b drift carries a lane map — but the wrong
   expected number invites a false E4-class alarm or pressure to
   collapse the two re-homed lanes. One-cell fix.]

MINOR:
1. **STAGE 3c wording: the alarm machinery is a bash function, not
   a heredoc.** Three Python heredocs exist (L895 state.json, L947
   manifest + exit-7 streak, L1168 merge union), but the alarm
   machinery proper is the bash function `_alarms`
   (sandbox_backup.sh L1052, invoked L1165/1263/1275/1284/1310) —
   "heredocs" understates the ~260-line function surface the 3c
   implementer must port.

EXECUTED (summary): HEAD = `2ccb4fb`; deliverables unchanged since
`865580e` (diff empty); full suite 728+9 (96.09 s); integrity 16;
all six matrices 20/22/25/19/26/9 = 121/0; CI via public API —
2ccb4fb run 45554184443 completed/success 7/7 (macOS leg green),
5bf91ad 45551538029 7/7, eb459b1 44536786320 macOS-leg-only
failure re-verified, that leg green on every subsequent run;
machine-compatibility anchor audit — every plan-cited test/sandbox/
matrix anchor verified live; coverage derivation — After-3a
derives (121), After-3b does not (122); docs accuracy — no doc
pre-asserts this gate's outcome (hedges only), ledger rows #9/#10/
#12 name real stages, the predecessor record closes NO CONSENSUS.

NOTES (Ship Steward): the macOS-leg carry observation re-verified
and carried (one-off flake on a documents-only push, recovered on
the next; S2 release-watch note stands). The `2ccb4fb` run status
reported exactly as the API returned it: completed / success 7/7.
Execution risk of the MAJOR is bounded: at the 3b commit the
implementer records ACTUAL beside EXPECTED with a lane map — the
record should carry the derivation so the 3b boundary reads 23 as
the correct number, not drift.

## Resolution state at iteration-1 close

The findings are NOT yet remediated at the moment this record
lands — per the record-before-fix-cycle rule the remediation cycle
starts in the NEXT commit. The remediation will address:

- **RT-C1**: the ledgered 3a edit list extended with the four
  mutated-copy probe sites (v5 E4 ×2, v7 E18 ×2) — each copy site
  gains a module-copy step (the module is copied beside the mutated
  script so $0-relative lookup resolves to the SEAM-CONSISTENT
  module) — and the module-lookup rule pinned explicitly
  ($0-relative, identity-from-module-location, fail-closed exit 6
  when absent), with the seam-anomaly lane's stubbing mechanism
  restated consistently (stub the module beside the copy).
- **RT-C2 ≡ Arch-M2**: the later-materialized-alias claim
  corrected in BOTH documents — the class is NOT covered at push
  time by the retained guard-time checks; it is recorded as the
  filesystem face of frozen residual item 3 (README, by this gate
  finding per the residual-list governance), AND the module
  contract gains a specified push-time target re-canonicalization
  in the guarded push helpers (a STAGE 4b commitment that closes
  this face at the port).
- **RT-M1 ≡ Arch-M1 ≡ Steward-M1** (three-role convergence): the
  coverage-arithmetic table corrected — v6 22→23 after 3b (E11
  −1/+2 lane map), matrix total 121→122, propagated through the
  "unchanged through STAGE-6" cells; the "INSIDE v6" wording made
  consistent; the state file's "coverage table derivable" claim
  re-anchored to the corrected cell.
- **RT-m1**: the 3b item-(b) enumeration gains the matrix twin
  sites (v8 E20 L91, v9 E29 L242, v10 E32 L136).
- **RT-m2**: the stale-citation comment edit added to the ledgered
  3a list (or its port-time note restated) so "exhaustive" holds.
- **Arch-m1**: the neutralization-hook delivery path specified
  through the bash entrypoint (a TEST-mode-only pass-through in
  the shim surface).
- **Arch-m2**: see RT-C2.
- **Arch-m3**: E34's pytest twin re-staged to 3c (four of five
  twins at 3a).
- **Arch-m4**: the STAGE 2 closing text gains the decision-#22
  supersession note.
- **Arch-m5**: the evaluation's v9 E26 wording corrected (the
  scp-`:22:` sub-lane stays a refusal; only the plain-remote
  control sub-lane stays rc-0).
- **Arch-m6**: the STAGE 5 retirement blast radius completed (the
  template/process-doc/runbook/harness-README invocation sites)
  with the shim leaned as the default.
- **Steward-m1**: the 3c wording corrected (the `_alarms` function
  surface, not just heredocs).

No S8 port work has started (documents only throughout). The gate
re-runs as iteration 2 on the remediation commit.

FINAL OUTCOME: NO CONSENSUS — iteration 1 of 2 (Red Team BLOCK: the 3a module-lookup gap and the later-materialized-alias coverage overclaim; fix cycle pending)

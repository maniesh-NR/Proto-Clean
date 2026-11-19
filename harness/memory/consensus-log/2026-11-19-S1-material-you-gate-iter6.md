# Consensus Gate — S1 (iteration 6, owner-ordered fresh gate)

Stage: S1
Date: 2026-11-19 (both iterations concluded — closed at the cap)
Gate ID: G1-iter6 (fresh gate ordered by the project owner on
2026-11-19 per the standing continuation directive, after G1-iter5
exhausted its 2-iteration cap without consensus; this gate has its
own cap of 2).
Reviewed commits (pinned): the G1-iter5 closing line — `a1607ce`
(G1-iter5 iteration-2 closing commit: backup v8, relative-target
refusal, empty-authority + multi-@ normalization, pushurl-divergent
machine lane, Shipped-signature + fenced-mention glyph rules,
corrected two-directional residual list, ledger #10) and `32d822f`
(seq-1'/2'/13 post-closure disclosure) == origin/main. Local suite
728 passed + 9 skipped; CI 7/7 legs on both commits (737 × 4 POSIX,
605+132 windows, exact — check-runs + job logs, pre-gate
verification); backup manifest seq 15 at `32d822f` (main_push ok,
prev_branch_push ok; the sixth-incident junk clusters — below — were
reset to `origin/sandbox/backups` and verified identical before the
fix cycle concluded).
Predecessors: `2026-11-13-S1-material-you-gate.md` (G1-iter1),
`2026-11-13-S1-material-you-gate-iter2.md` (G1-iter2),
`2026-11-13-S1-material-you-gate-iter3.md` (G1-iter3),
`2026-11-15-S1-material-you-gate-iter4.md` (G1-iter4),
`2026-11-19-S1-material-you-gate-iter5.md` (G1-iter5, both
iterations, closed NO CONSENSUS at cap).

## PROVENANCE DISCLOSURE (orchestrator — audit-trail faithfulness)

The session that orchestrated iteration 1 lost its context between
the verdicts returning and this record being written; the three
agents' full report texts were lost with it. This record is
RECONSTRUCTED from artifacts the lost session wrote after the
verdicts returned and before the context loss — the project-state
snapshot, the roadmap S1 entry, the fix-cycle code annotations
(every remediation cites its finding), the backups-README residual
corrections, and the lessons entries — all mutually consistent on
the verdicts (RT BLOCK / Architect PWF / Steward PWF) and the
finding classes below. The verbatim verdict blocks, the launch-table
method details, and any minors not cited by a remediation are NOT
recoverable. Iteration 2 judges the fix commit as committed, not
this reconstruction. Disclosed per the no-selective-omission rule
(the G1-iter5-i2 orchestration-slip precedent).

## Iteration 1 — three roles, independent, no shared context

Verdicts: **Red Team BLOCK** · **Devil's Architect
PROCEED-WITH-FINDINGS** · **Ship Steward PROCEED-WITH-FINDINGS** →
**NO CONSENSUS — iteration 1 of 2.**

### Red Team — BLOCK (six criticals, all executed E2E against v8)

- **C1 — git-dir identity redirects.** The REPO compares judged the
  operand's path SPELLING while git's DISCOVERY follows env
  redirection (GIT_DIR/GIT_WORK_TREE/…), a subdirectory, or a
  linked worktree into another checkout's .git; a full TEST run
  landed a checkpoint + self-heal merge inside a stand-in
  production with all guards green.
- **C2 — remote-carried relative targets.** A remote-carrying
  `harness/../../…` operand resolved at the push worktree's base
  and landed on an unjudged sink (v8 refused only `./`/`../`
  PREFIXES).
- **C3 — pushInsteadOf on direct operands** (falsified the
  G1-iter5-i2 frozen-residual "verified non-residual" claim): the
  iter5-i2 probe used the `file://` spelling — the ONE form git
  2.47.3 does not rewrite — while the plain-path form DOES rewrite
  direct push operands at push time; the typed operand's checkpoint
  landed in the reconfigured bare while the guard had judged only
  the typed spelling.
- **C4 — percent-encoded hosts.** `https://%67ithub.com/…` — curl
  percent-decodes the HOST before connecting (CONNECT
  github.com:443 observed at a local sink); the spelling denylist
  compared raw.
- **C5 — helper transports.** `ext::`/`fd::` (anything `::`) — the
  destination lives INSIDE the operand (`ext::git-receive-pack
  <prod>/.git` is an arbitrary-command channel); URL normalization
  cannot see it.
- **C6 — six glyph-forgery classes.** A backdated record carrying a
  Stage line + terminal closure machine-backed a ☑; multiple Date:
  headers parsed first-match; multi-id glyph lines verified only
  the first id; lookalike glyphs (✅/✔/✓) invisible; an id-less ◐
  skipped; a fenced addendum after the closure line hid a
  retraction.
- Majors/minors (as cited by remediations): **M1/m2** — the greedy
  host cut read `git@github.com:22:repo` as host `github.com:22`
  (no suffix match) while ssh handed off to github.com; trailing
  dots and raw-IP spellings in the same family. **m4** —
  transport-level indirection (`http.proxy`, `core.sshCommand`,
  ssh ProxyCommand) routing a benign-host push to github — modeled,
  residual item 1 extended.

### Devil's Architect — PROCEED-WITH-FINDINGS

- **Major #1 — identity coupling.** The guarded identity
  (PROD_CHECKOUT) was hand-copied in the integrity test lanes
  independent of the script's constant — the structural root cause
  of the seq-10 and seq-1'/2'/13 one-sided-patch incidents; a
  mutation probe patching the constant alone NEUTRALIZES the guard
  for every lane still referencing the real path.
- **Major #2 — exit-criterion shape.** The verification matrices
  lived only in the sandbox home, referenced by repo docs through
  paths that did not resolve in-repo, and went stale twice (v5 E4;
  v8 E20's patch anchor drifted silently through the v9 rework) —
  an exit criterion measured by an artifact nobody is forced to run
  is not a criterion.
- **Major #3 — gate convergence.** Five consecutive cap-exhaustions
  concentrated in the backup/harness subsystem while the stage's
  deliverable (Material You) stayed green — the monolithic stage
  let a subsystem hold the deliverable hostage; the re-gate ladder
  is how S1 accumulated five cap-exhaustions.
- **Minor #3** — five hand-copied brand-seed hex constants
  (`#2f6d3f`) drift independently across settings / theme /
  resources / settings_dialog.
- **Minor #5** — the account/auth chain (credential storage at
  rest, TOTP secret storage, session persistence, the
  browser-scrape login relay, API TLS verification) missing from
  the security stage's scope.

### Ship Steward — PROCEED-WITH-FINDINGS

- **Major #1 — stale/false session-log claim.** The G1-iter5
  closure session log claimed the relative-target mutation probe
  "patched BOTH … zero production contact" — contradicted by the
  post-closure audit (manifest seq 1'/2'/13, commit `32d822f`);
  the correction landed in the gate record at that commit but the
  session log was missed.
- Otherwise (as recorded pre-loss): claim map clean across the
  iteration's assertions, CI per-leg counts exact from job logs,
  audit trail faithful; remaining doc minors fixed in cycle.

### Verified-good (all three roles, per the pre-loss snapshot)

The S1 deliverable itself — desktop + Android dynamic color, seed
persistence, OS accent detection — green through all six gates; no
deliverable finding in any iteration of this gate.

## Resolution cycle (fixes applied in THIS commit — every finding from all three roles)

- RT-C1 → v9 scrubs the discovery-redirection env family
  (GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE/…) and verifies
  `git rev-parse --git-common-dir` physically equals the operand's
  own `.git`; the REPO and push-target compares become CONTAINMENT
  checks (the production checkout AND everything under it). [E27,
  E30; integrity lanes]
- RT-C2 → EVERY relative target refuses, prefix or interior. [E29 +
  worktree-base mechanism demo]
- RT-C3 → refuse ANY `url.*.pushInsteadOf` key in visible config
  (fail-closed — the class, not the rewrites). [E25 + rewrite
  mechanism demo]
- RT-C4 → refuse any `%` in the authority (the guard cannot
  canonicalize what the transport decodes). [E23]
- RT-C5 → refuse the `::` transport-prefix class, IPv6 literals
  with them. [E24 — direct AND remote-carried]
- RT-C6 → glyph rules on their teeth: backing adoption dates,
  single-Date enforcement, multi-id verification, the lookalike
  class (✅/✔/✓), id-less ◐, post-closure fence retraction.
  [integrity suite, extended in place]
- RT-M1/m2 → host cut at the FIRST colon after the last `@`;
  trailing dots collapse; raw-IP hosts refused (loopback exempt for
  the redaction lane's local sink). [E26, E28]
- RT-m4 → residual item 1 extended to transport-level indirection
  (documented, modeled — residual, not fixed).
- Arch-M1 → the integrity lanes DERIVE `PROD_CHECKOUT` from the
  script under test — a constant patch repoints the lanes
  automatically; the one-sided-patch accident class becomes
  structurally impossible in the machine suite.
- Arch-M2 → matrices REPO-RESIDENT
  (`harness/backups/matrices/`, ROOT self-derived, CI-visible);
  checklist item (e) re-runs ALL of them; decision #19b makes the
  port's exit criterion PROPERTY-based.
- Arch-M3 → the harness subsystem SPLIT into stage S8 (roadmap) +
  decision #19 + the owner-side escalation default (process doc).
- Arch-m3 → `PROTO_BRAND_SEED` single-sourced in `ui/md3.py`;
  settings / theme / resources / settings_dialog import it.
- Arch-m5 → S6 scope extended with the account/auth chain.
- Steward-M1 → CORRECTION annotation in the G1-iter5 closure
  session log (closed in this commit).
- Docs per the fix-cycle checklist: baseline parenthetical (process
  doc), project state, lessons (+8 entries), backups README (v9
  design, corrected residual list items 1/2/6, anomaly log).

## Fix-cycle completion (evidence, at this commit)

- Suite: **728 passed + 9 skipped** local (16 integrity tests,
  count unchanged — all new coverage extended existing tests in
  place). Re-verified on this tree by the continuation orchestrator
  before commit.
- Matrices: **v5 20/20 · v6 22/22 · v7 25/25 · v8 19/19 · v9
  26/26 — 112 checks, 0 failed**, all repo-resident, ALL re-run
  (checklist item (e)); totals re-verified by the continuation
  orchestrator.
- CI expectation for this commit: unchanged (737 × 4 POSIX /
  605+132 windows) — coverage extended existing tests; confirmed or
  annotated at the iteration-2 closing commit once the run lands.
- **Sixth accidental-checkpoint incident** (orchestrator error
  DURING this fix cycle, LOCAL-ONLY, cleaned by reset to
  `origin/sandbox/backups` and verified identical; reflog
  2026-11-19T03:34-03:35Z): the mutation-probe battery cloned from
  HEAD while the v9 identity-derivation fix was still uncommitted —
  the stale v8 test file's hand-copied lanes + the patched constant
  = the one-sided patch again, structurally; two junk clusters
  landed on the production checkout's LOCAL branch (the second from
  a debug re-run of the failing probe — itself production-touching).
  Origin never touched. Disclosed in the backups-README anomaly log
  with the corrected rule: probe from the tree that CONTAINS the
  fix; probe batteries snapshot the WORKING TREE (clone for history
  + rsync overlay), never bare HEAD; anchors verify LOUDLY; never
  debug-re-run a production-touching probe without re-checking
  containment. Session log:
  `memory/session-log/2026-11-19-g1-iter6-sixth-incident.md`
  (reconstructed — provenance disclosed there).

## Iteration 2 — re-judgment of the fix commit `0c4b8f9` (2026-11-19)

Three roles launched in one parallel round, independent, no shared
context — no orchestration slip this time, and no context loss: the
full verdict texts returned to the orchestrator and are condensed
below from the intact reports (no provenance caveat for this
iteration).

Verdicts: **Red Team BLOCK** · **Devil's Architect
PROCEED-WITH-FINDINGS** · **Ship Steward PROCEED-WITH-FINDINGS** →
**NO CONSENSUS — the 2-iteration cap is exhausted.**

### Red Team — BLOCK (2 criticals + 1 major, all executed E2E on stand-ins with all v9 guards green; 3 minors)

- **C1 — includeIf-conditional `pushInsteadOf` is invisible at guard
  time, active at push time** (reopens the closed C3 class; falsifies
  residual items 2/6 as written). The v9 refusal greps
  `git config --get-regexp` from the repo, which sits on `main` at
  guard time — but the branch pushes execute from the temporary
  worktree on `sandbox/backups`, where an
  `includeIf "onbranch:sandbox/backups"` include is ACTIVE. The key
  materialized exactly at push time; the full TEST checkpoint landed
  in the unjudged rewrite target (rc 0, zero refusals); with the
  rewrite value spelled as any github URL the TEST checkpoint
  reaches github with all guards green. The machine lane and matrix
  E25 set the key unconditionally (visible on main) — this shape had
  no coverage.
- **C2 — the fetch side of a named remote is never judged** (breaks
  the README's founding invariant "not even via a clone's origin").
  v9 resolved remote-name operands solely via
  `git remote get-url --push`; every fetch addresses
  `remote.<n>.url` — a URL no guard rule ever saw. Executed: a
  remote with url=<github-spelled> + pushurl=<local bare> ran rc 0
  with zero refusals while the clone's refs matched the fetch sink's
  marker commit; with the fetch URL spelled
  `https://github.com/maniesh-NR/Proto-Clean.git` and https egress
  forced through a local blackhole sink, **3× CONNECT
  github.com:443** were observed (fetch_main, fetch_branch, the
  alarm fetch) — anonymous, no credential, but TEST traffic reached
  github with all guards green.
- **M1 — a symlinked `.git` passes the v9 git-dir identity check.**
  `$REPO/.git` symlinked to another checkout's `.git` resolves BOTH
  compare sides through it to the same physical path — the equality
  held while the operand shared the stand-in's git state; the full
  TEST checkpoint + refs landed inside it (rc 0, zero refusals).
  Honest caveat stated by the RT: a constructed shape, no accident
  path identified — hence major, not critical.
- Minors: **m1** — the divergence union iterates (ours, theirs), so
  a same-triple collision lets the REMOTE variant overwrite the
  local ground truth (logic-demo executed: local
  `main_push:failed`/`git_head:aaaa` replaced by remote
  same-triple `main_push:ok` + a forged field); **m2** —
  `_prod_checkout` derives the FIRST `PROD_CHECKOUT=` match while
  bash executes the LAST — an insert-style mutation desynchronizes
  the lanes from the guard (demo executed), the one-sided-patch
  class the v9 fix claimed structurally dead; **m3** — a
  scheme-less scp operand `user:pass@host:path` echoes its password
  verbatim through the not-a-remote refusal.
- Verified-good (honest negatives): the glyph teeth held against
  CRLF closures, malformed Date headers, unbalanced/indented fences,
  pre-closure retractions, ☑-with-variant-selector and lookalikes;
  the host cut, percent/`::`/raw-IP/trailing-dot/relative/containment
  rules and the env scrub all behaved; the deliverable (Material
  You) outside the findings, consistent with six gates.

### Devil's Architect — PROCEED-WITH-FINDINGS (3 majors, 5 minors; no criticals)

- **Major #1 — the port exit criterion's keystone is hedged.**
  Decision #19b's "EVALUATE the allowlist inversion" re-opens what
  the criterion's first clause already decided (a TEST mode that can
  only address local absolute paths IS an allowlist); "nothing exits
  the machine" is mechanically testable only under the inversion;
  and the decision's own rationale concedes no consumer uses the
  any-host capability. Required: mandate it, or gate the evaluation
  as a named S8 pre-gate deliverable with a written accept/reject
  decision.
- **Major #2 — the identity-derivation job was unfinished.** (a) the
  derivation regex is first-match while bash is last-assignment-wins
  (convergent with RT-m2); (b) matrix E30 hand-copies the production
  path — the one-sided-patch coupling persisting in a repo-resident
  artifact the checklist forces every cycle to re-run; (c) the
  E25/E29 `PROD_CHECKOUT` patches use silent `str.replace` with no
  loud anchor check, violating the same commit's own loud-anchor
  rule (the E20 anchor-drift class).
- **Major #3 — the S1/S8 split left stale authoritative docs.**
  Ledger #10 gated at "S6 (harness port)" and the S6 bullet still
  said "decide whether to port … ledger row #9", contradicting
  decisions #18/#19 and S8's claim on #10.
- Minors: **m1** — S1's roadmap title must narrow at the ☑ flip
  (deferred #11); **m2** — the matrices are repo-resident but not
  CI-forced, and the port must per-lane audit lane mechanics
  (deferred #12); **m3** — E30's silent SKIP makes the check count
  machine-dependent; **m4** — add the rule: a gate record commits
  before its fix cycle starts (adopted this cycle, applies from the
  next gate); **m5** — the residual list covers indirection-to-
  github but not direct TEST egress to third-party hosts (added by
  this gate finding).
- Verified-good: the provenance disclosure honest — no laundering
  detected; every claimed remediation verifiable in the commit; the
  suite independently re-run (728+9 exact, integrity 16/16); the
  S1/S8 split sound (with the S8-fallback seam flagged for the
  owner); the bash freeze coherent; the record machinery
  load-bearing, consolidation due at the port.

### Ship Steward — PROCEED-WITH-FINDINGS (no criticals, no majors; 2 minors)

- Suite re-run: **728 passed + 9 skipped, exact** (737 collected;
  skip count unchanged); integrity suite 16/16.
- Matrices re-run (all five): **112 checks, 0 failed** (v5 20, v6
  22, v7 25, v8 19, v9 26); working tree clean before and after.
- Doc checklist (a)-(f): 5 of 6 fully verified in `0c4b8f9`;
  (d) PARTIAL — the README "What gets backed up" table still
  labeled the script "(v8)".
- Audit trail: the gate record's Stage/Date/pins/provenance/
  finding→resolution/closure-line all verified; the sixth-incident
  disclosure consistent across README + session log + record; the
  roadmap S1/S8 entries consistent with decision #19; the pushed
  manifest at seq 16 (main_push ok, prev_branch_push ok); HEAD
  clean.
- **CI CONFIRMED on `0c4b8f9`**: run 44458438836, all 7 legs
  success — 737 × 4 POSIX, 605+132 windows, wheel + Android green,
  per-leg counts from job logs (read-only, token never printed).
- Release risk: minimal — the product diff is a pure single-sourcing
  refactor (`PROTO_BRAND_SEED == "#2f6d3f"` value-identical,
  runtime-verified; `test_material_you.py` asserts the literal and
  would catch drift).
- Minors: **m1** — the stale "(v8)" label (checklist item (d));
  **m2** — the sixth-incident rule recorded in lessons/README/
  session log but not in the process doc's item (f).

### Resolution cycle (iteration-2 fixes applied in THIS commit — every finding from all three roles)

- RT-C1 → **include/includeIf class refusal by FILE CONTENT** — any
  `[include`/`[includeIf` section in the repo config, global config,
  XDG config or system config refuses a TEST run (content
  inspection, branch-condition-independent), inside `_judge_target`.
  [integrity lanes: includeIf + include + clean control; E31 +
  mechanism demo]
- RT-C2 + **the URL-operand insteadOf SIBLING (found by orchestrator
  analysis during this fix cycle, disclosed here)** → **both-directions
  judgment**: `_judge_target` extracted; the PUSH view (remote name
  → `get-url --push`; URL/path operand → the TYPED spelling) and the
  FETCH view (remote name → `get-url`; URL/path operand → the
  `ls-remote --get-url` insteadOf resolution) are each resolved and
  judged. The sibling: a typed github-spelled operand under an
  insteadOf rewrite resolves fetch-side to the clean rewrite while
  the push travels the typed github spelling — v9 judged only the
  fetch view. [integrity lanes: ghdiv + bothclean control +
  insteadOf-push-view; E32 + control]
- RT-M1 → **symlinked-.git refusal** (`[ -L "$REPO/.git" ]` exits
  6) + a **git-dir containment compare** against the production
  checkout (belt-and-braces). [E33; integrity lane]
- RT-m1 → **union prefers OURS**: the merge iterates (theirs, ours)
  so the local entry wins same-triple collisions, with
  `merge_triple_conflicts` audited in the merged doc and a loud
  stderr line. [E34 patched-TS mechanism demo]
- RT-m2 / Arch-M2a → `_prod_checkout` asserts **exactly one**
  `PROD_CHECKOUT` assignment (loud, never best-effort).
- RT-m3 → scp-syntax `user:pass@` redaction on all three refusal
  surfaces (not-a-remote message + both push helpers).
  [E35; integrity lane]
- Arch-M1 → **decision #20**: the allowlist inversion MANDATED as
  S8's exit criterion; the evaluation re-framed as a named S8
  pre-gate deliverable (a rejection requires an owner decision).
- Arch-M2b → matrix E30 **derives** PROD from the script under test
  (exactly-one, loud); Arch-M2c → E25/E29 and every v10 patch carry
  **loud anchors**; Arch-m3 → E30's skip **counted loudly** in the
  summary line.
- Arch-M3 → ledger #10's gate column → S8; the S6 bullet → S8
  (decisions #18/#19/#20); ledger #9's action refreshed.
- Arch-m1 → deferred row #11 (narrow the S1 title at the ☑ flip);
  Arch-m2 → deferred row #12 (per-lane mechanism audit + CI-forcing
  decision at the port); Arch-m4 → the **record-before-fix-cycle**
  rule adopted in the process doc (applies from the next gate);
  Arch-m5 → residual item 1 extended with the third-party-egress
  entry (a gate finding — the two-directional freeze working).
- Steward-m1 → README script label "(v8)" → "(v10)"; Steward-m2 →
  process doc item (f) extended with the sixth-incident
  snapshot-the-working-tree rule.
- Docs per the fix-cycle checklist: README (v5–v10 design section,
  matrix list, residual item 1), process doc, decisions #20,
  deferred findings #9/#10 refreshed + #11/#12 added, roadmap (S1
  narrative + S6 correction), lessons (+6), project state (CI
  confirmed on `0c4b8f9`), session log part 3, this record.

### Fix-cycle completion (evidence, at this commit)

- Suite: **728 passed + 9 skipped** local (16 integrity tests, count
  unchanged — all new coverage extended existing tests in place),
  re-run on this tree before commit.
- Matrices: **v5 20/20 · v6 22/22 · v7 25/25 · v8 19/19 · v9 26/26
  (0 skipped, production present) · v10 9/9 — 121 checks, 0
  failed**, all repo-resident, ALL re-run (checklist item (e)).
- Mutation probes (working-tree snapshots per the sixth-incident
  rule — clone for history + rsync overlay, loud anchors, zero
  production contact): **5/5 caught** — include-refusal removal,
  fetch-view removal, symlink-refusal removal, union-order revert
  and scp-redaction removal each fail their lane (the coverage is
  load-bearing, not vacuous).
- No accidental-checkpoint incident this cycle (containment held
  through the probe battery).
- CI **CONFIRMED** for this commit (run 44462797163, all 7 legs
  success, per-leg job-log-verified post-push): 737 × 4 POSIX,
  605+132 windows, wheel + Android green — the expectation met
  exactly.

FINAL OUTCOME: NO CONSENSUS — iteration cap reached (2 of 2): iteration 2's Red Team BLOCK (the includeIf-conditional pushInsteadOf and the never-judged fetch side of named remotes — both executed E2E on stand-ins with every v9 guard green — plus the symlinked-.git major) vs Devil's Architect and Ship Steward PROCEED-WITH-FINDINGS; every finding from both iterations remediated and machine/matrix-covered in this closing commit, which carries this record; escalated to the project owner — per the owner-side escalation default (adopted this gate, Architect major #3) the decision-#19 split is already recorded: S1 may close on its deliverable (Material You green through six gates, zero deliverable findings) with the harness findings owned by S8's own gate, unless the owner orders another gate; all six cap-exhaustions of this stage were decided by backup/harness-subsystem findings.

# Consensus Gate — S1 (iteration 6, owner-ordered fresh gate)

Stage: S1
Date: 2026-11-19 (iteration 1; iteration 2 pending — no outcome
pre-recorded)
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

## Iteration 2 (final) — pending

Re-judges THIS fix-cycle commit (SHA recorded in the iteration-2
section when its verdicts return). No outcome pre-recorded.

Iteration 2 outcome: recorded in this file when the re-run's
verdicts return — not before.

FINAL OUTCOME: NO CONSENSUS — iteration 1 of 2 (Red Team BLOCK on six executed criticals; Architect and Steward PROCEED-WITH-FINDINGS); the v9 fix cycle above lands in this commit, which carries this record; iteration 2 (final) re-judges this remediation commit within the gate's cap.

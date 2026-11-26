# Decision #23 packet — S8-PG1-iter3 cap-closure escalation (prepared 2026-11-26)

NO DISPOSITION RECORDED — awaiting decision #23; no outcome pre-recorded.

Self-contained owner packet for the S8-PG1-iter3 cap-closure
escalation, prepared by the owner-input-free roadmap session
(scheduled 20:00 UTC 2026-11-26) so the decision can be made from one
document. Sources (read in full this session): `harness/roadmap.md`
(the S8 row — verbatim re-tabled options), the cap-closure record
`harness/memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`,
`harness/process/adversarial-consensus.md` (owner-side escalation
rule, iteration cap, no-pre-recording rule),
`harness/memory/01-decisions.md` (#18–#22),
`harness/memory/00-project-state.md`,
`harness/memory/deferred-findings.md`, and the two STAGE-1
deliverables. Every claim below is traceable to those files; commit
SHAs and dates are cited as they appear there. This packet presents
trade-offs only — no option is recommended or favored anywhere in it.

## 1. What is escalated, and why

### The chain

1. **S8-PG1 closed at its 2-iteration cap (2026-11-19) — NO
   CONSENSUS, escalated.** Iteration 1 on `82fb63c`: Red Team BLOCK
   (2 criticals) + Devil's Architect BLOCK (3 criticals) + Ship
   Steward PROCEED-WITH-FINDINGS; remediation `eb459b1`. Iteration 2
   on `eb459b1`: all three roles BLOCK on NEW criticals of the same
   boundary-contradiction class (the 3a parity oracle unsatisfiable
   via the five anchor-demo lanes; realpath-or-refuse red-lining
   five resilience lanes; the transport-allowlist backstop
   undeliverable as claimed) while CONFIRMING the iteration-1
   findings resolved in substance. Closing remediation landed with
   the record at `865580e` — documents only, no port code changed.
2. **Decision #22 (2026-11-25; recorded at `5bf91ad`; owner
   instruction "D1:a, d2:a").** D1:a — a FRESH pre-gate
   **S8-PG1-iter3** with its OWN 2-iteration cap, re-judging the two
   STAGE-1 deliverables (`harness/backups/allowlist-inversion-evaluation.md`
   + `harness/process/s8-execution-plan.md`) as amended through the
   S8-PG1 closing remediation, pinned on the line `865580e`+.
   D2:a — the S1-closing gate runs FIRST. Decision #22's tail clause
   (verbatim): "No outcome for either gate is pre-recorded; if the
   fresh gate again exhausts its cap, the escalation returns to the
   owner with the split/descope options re-tabled per the owner-side
   escalation rule."
3. **S1 closed by consensus (2026-11-25)** — the S1-closing gate
   reached CONSENSUS at iteration 1, zero criticals; record
   `memory/consensus-log/2026-11-25-S1-closing-gate.md`; CI run
   45551538029 on `5bf91ad`.
4. **S8-PG1-iter3 ran both of its iterations.** Iteration 1
   (2026-11-25, on `2ccb4fb`, deliverables unchanged since
   `865580e`): NO CONSENSUS — Red Team BLOCK (2 criticals + 1 major:
   the 3a module-lookup gap; the later-materialized-alias coverage
   overclaim, executed E2E; the coverage-table post-3b off-by-one,
   found independently by ALL THREE roles) / Architect
   PROCEED-WITH-FINDINGS (the same two at major severity + 6 minors)
   / Steward PROCEED-WITH-FINDINGS (the off-by-one + 1 minor). All
   three roles confirmed the S8-PG1 iteration-2 criticals
   (C-A/C-B/C-C) resolved in substance. Remediation `7c3bd4b`
   (documents only). Iteration 2 (on `7c3bd4b`): Red Team BLOCK +
   Devil's Architect BLOCK on the SAME executed critical; Ship
   Steward PROCEED → **NO CONSENSUS AT THE FRESH GATE'S OWN
   2-ITERATION CAP** (commit `253e01c`, 2026-11-25); the closing
   remediation landed WITH the record (probe-dir relocations, the
   $0-relative seam spelling, the STAGE-4b deliverable + a ledgered
   planted-alias lane, the magnitude/scoping minors).

### The ONE executed critical still blocking consensus (iteration 2)

The iteration-1 remediation ("copy the module beside each mutated
script copy", 3a item (4) as it stood at `7c3bd4b`) re-homes the
location-derived identity onto the LANE AREA. Both BLOCKing roles
executed the same falsification independently:

- Under the copy-both shape, identity-from-module-location derives
  the identity FROM the lane directory — the guard then refuses the
  lanes' own operands (**rc 6 vs the expected 5/4** for E4/E18) and
  would ALLOW production-adjacent operands — the protection inverts.
- Red Team's structural statement: the three pinned constraints
  ($0-relative module lookup, identity-from-module-location, the
  mutated script copy beside its operands) are **jointly
  unsatisfiable** — the script copy must sit beside its operands, the
  $0-relative rule forces the module into that same directory, and
  any location-derived identity of a module there is an
  ancestor-or-equal of the operands → always refused.
- Consequence: the 3a parity oracle ("SURVIVING checks green with
  zero expectation edits") remains unsatisfiable as specified — the
  3a commit cannot land green as pinned.

**Three one-clause escape shapes, jointly identified by BOTH BLOCKing
roles** (recorded in the iteration-2 verdicts): (1) pin confinement
semantics for non-repo module placements + amend item 3's predicate;
or (2) a probe-only module-path rule + amend the pinned lookup; or
(3) re-home the four sites' guard-passing mechanism. The closing
remediation at `253e01c` re-ledgered the four mutated-copy sites as
**PROBE-DIR RELOCATIONS** (module + script into a probe subdir
disjoint from the operands) with an honest proof-scope statement —
the sabotage-detection mechanisms are what the lanes prove;
production protection is pinned by the repo-resident refusal lanes
and the module-seam lanes — and added the STAGE-4b push-time
re-canonicalization deliverable + a ledgered planted-alias lane.

**Narrower than the prior criticals.** All three roles confirmed the
S8-PG1 iteration-2 criticals (C-A/C-B/C-C) resolved in substance at
iteration 1; RT-i1-C2 (the alias overclaim), the coverage-122
correction, and all nine i1 minors were CONFIRMED RESOLVED at
iteration 2. A 2026-11-26 post-cap completeness check (this session)
verified the record's closing-remediation resolution list is landed
in the deliverables, with one coverage-table cross-reference
bookkeeping nit — landed the same day, documents only, per the
G1-iter6-i2/S8-PG1 landed-with-record precedent. What BOTH roles
recorded as correct even while BLOCKing: the four-site enumeration is
complete and correct (v5 E4 ×2, v7 E18 ×2 are exactly the copy sites
whose lanes survive 3a), and the 3a edit list remains exhaustive
against the real PROD-literal inventory.

### What is NOT in dispute

The property-based exit criterion (decision #19b); the allowlist
inversion MANDATE (decision #20 — a REJECTION would itself require an
owner decision at S8's gate, and no role disputes the inversion); the
module location (scripts/backup_core.py, decided); the coverage
arithmetic (122 checks post-3b — the Steward verified the table
"derives exactly"); the delivery contract; the port schedule (the
port lands before S2's stage gate, decisions #18/#19). **Documents
only throughout** — no port code has ever changed (`82fb63c` →
`253e01c`).

## 2. The options (verbatim from `harness/roadmap.md`, S8 row)

### Option (a) — further split

> (a) further split (land the converged spec fixes and start the
> port, where the parity-oracle question becomes an executed green/red
> fact per stage boundary, judged by the STAGE-6 closing gate)

- **What it unlocks immediately:** STAGE 3a port work
  (`scripts/backup_core.py`) per the cap-closure-amended plan; the
  escape shapes become executed facts at the per-stage boundary
  instead of pre-judged prose; the STAGE-6 closing gate judges the
  finished port.
- **Consequences / blast radius:** port code enters the tree for the
  first time (the 16 machine tests + the 121-check repo-resident
  matrices + the coverage table pin the behavior to port); the 3a
  commit must first resolve the jointly-unsatisfiable pinning into a
  lane design (the one-clause escape shapes above are the drafted
  material); S2 still waits for the port + its gate per decisions
  #18/#19.
- **Constraining decisions:** #18 (port before S2's stage gate),
  #19/#19b (property-based exit criterion; identity single-sourcing),
  #20 (inversion mandated), #22's tail clause (this escalation), and
  the owner-side escalation rule (this IS the split default's shape).

### Option (b) — another fresh gate

> (b) another fresh gate (must be justified against the split
> default — eight total cap-exhaustions across S1 + the S8 pre-gates)

- **What it unlocks:** another pre-gate round (cap 2) re-judging the
  two STAGE-1 deliverables as amended (now including the probe-dir
  relocations and the coverage cross-reference).
- **Consequences / blast radius:** documents-only again; but the
  iteration-2 BLOCK is a JOINTLY-UNSATISFIABLE-PINNING contradiction —
  a fresh gate re-judges the same deliverables unless the escape
  shapes are first landed INTO the spec, which is option (a)'s first
  half; the re-gate ladder is the pattern the escalation rule was
  adopted to break (decision #19's context: the re-gate ladder is how
  S1 accumulated its exhaustions). The eight: G1-iter3 (2026-11-14),
  G1-iter4 (2026-11-15), G1-iter4-i2 (2026-11-16), G1-iter5 +
  G1-iter5-i2 + G1-iter6-i2 (2026-11-19, the closing v10 fix-cycle
  line `7a13645`), S8-PG1 (2026-11-19, `865580e`), S8-PG1-iter3
  (2026-11-25, `253e01c`).
- **Constraining decisions:** the owner-side escalation rule itself —
  "a fresh gate may still be ordered, but it must be justified
  against the split default" (process doc, adopted G1-iter6).

### Option (c) — owner-descoped S8→S2 ordering

> (c) owner-descoped S8→S2 ordering

- **What it unlocks:** S2 (release v0.6.3 — SHA-256 asset checksums,
  the WCAG ≥ 4.5 contrast property test, deferred rows #1–#4, #7,
  #13, #14, #16) proceeds before/without the S8 port, at the owner's
  direction.
- **Consequences / blast radius:** decision #18's recorded schedule
  ("the port lands BEFORE S2's stage gate") is overridden BY THE
  OWNER — that schedule is itself a recorded decision, so only an
  owner disposition changes it; the S8 findings stay owned by S8's
  own gate (decision #21's split boundary is unchanged — the findings
  do not disappear, they wait); S2's adversarial pre-gate has never
  run and must still run before S2 work starts.
- **Constraining decisions:** #18 (the schedule being overridden),
  #21/#22 (S1 closed on its deliverable; the harness subsystem is
  S8-owned), #20 (the inversion mandate binds the port whenever it
  happens).

## 3. The verdict split (facts only)

- **Iteration 2:** Red Team BLOCK + Devil's Architect BLOCK — the
  SAME executed critical, with three one-clause escape shapes jointly
  identified; Ship Steward PROCEED with zero findings (the coverage
  table derives exactly; the delivery contract holds).
- **Iteration 1:** Red Team BLOCK (2C + 1M) / Architect
  PROCEED-WITH-FINDINGS (2M + 6m) / Steward PROCEED-WITH-FINDINGS
  (1M + 1m); the coverage off-by-one was found independently by all
  three roles; all three confirmed the prior gate's criticals
  resolved in substance.
- Both BLOCKing roles sketched concrete one-clause fixes and both
  confirmed the four-site enumeration and the 3a list's completeness.
- Neutral summary: two roles judge the PINNED SPEC self-contradictory
  on one point; one role judges the deliverable ready. The
  disagreement is about the spec's internal consistency at one
  boundary — not about the port's design, the exit criterion, or the
  inversion mandate.

## 4. Implications for S2 (v0.6.3) timing — NEUTRAL table

| Option | When S2's pre-gate can convene | What S2 inherits from S8 | Notes |
|---|---|---|---|
| (a) further split | After the port lands and passes its own gate (roadmap chain: S8-PG1-iter3 → port + its gate → S2; decisions #18/#19) | The frozen residual list with the item-3 FILESYSTEM face closed at STAGE-4b; the ported, tested core; ledger #12's per-lane mechanism audit rides S8's gate | The port starts only once the escape shapes are resolved into 3a's lane design |
| (b) another fresh gate | After another pre-gate round concludes (its own cap 2), then the port + its gate, then S2 | Unchanged from (a) | The BLOCKing contradiction must still be resolved in the spec first — the same work option (a) begins with |
| (c) S8→S2 descope | At the owner's direction — potentially immediately (S2's own pre-gate has never run) | Nothing from the port; the harness findings remain S8-owned per decision #21 and wait | Overrides decision #18's port-before-S2-stage-gate schedule by owner authority |

## 5. Precedent map

- **Decision #15** (2026-11-14, G1-iter3-i2): gate caps escalate;
  remediation does not equal closure; the owner ordered the fresh
  gate G1-iter4 on the remediation commit — the G1 → G1-iter3 fresh
  gate precedent.
- **Decision #19** (2026-11-19, G1-iter6): the S8 split (S1 closes on
  its deliverable; the harness subsystem becomes its own stage,
  gated before S2's stage gate) + the port's PROPERTY-based exit
  criterion; the owner-side escalation default recorded in the
  process doc.
- **Decision #21** (2026-11-19): the owner instructed "Continue" —
  no override; the split default took effect; the scoped S1-closing
  gate scheduled.
- **Decision #22** (2026-11-25): "D1:a, d2:a" — the fresh gate
  S8-PG1-iter3 on `865580e`+; the S1-closing gate first; the tail
  clause returns this escalation to the owner.
- **Process doc, owner-side escalation rule** (adopted G1-iter6):
  two consecutive subsystem-concentrated cap-exhaustions → the
  owner's options DEFAULT to splitting; a fresh gate must be
  justified against the default.

## 6. Status

NO DISPOSITION RECORDED — awaiting decision #23; no outcome
pre-recorded. No gate has been launched since the cap closure; no
port code has been written; the escalation record and the re-tabled
options are untouched.

## Appendix A — S7 memo (FUTURE OWNER DECISION — due by v0.7, informational only)

- Python 3.8 is EOL (`harness/roadmap.md`, S7 row). The legacy CI
  legs (Python 3.8, PySide2-Qt5, PySide6-6.2) exist per decision #2
  (PySide6 primary, PySide2-Qt5 fallback via `qtcompat`) to keep
  legacy distro Pythons supported.
- Every UI change pays the compat tax until the keep/drop decision;
  deferred finding #3's planned fix already specifies legacy-leg
  behavior that works without Qt ≥6.5 signals (S2 does not force the
  decision).
- The decision is keep/drop per leg and rides S7's own gate. Facts
  only — not requested now, recorded here so the v0.7 decision has
  its starting material in one place.

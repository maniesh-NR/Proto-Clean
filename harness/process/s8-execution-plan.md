# S8 execution plan — harness subsystem hardening + Python port

Per `harness/process/execution-plan-template.md`. Stage S8 (decision
#19; activated by the owner disposition, decision #21, 2026-11-19).
Scheduling per decision #18: the port lands BEFORE S2's stage gate.
Ledger rows #9 and deferred #12 ride this stage (#10 deferred out
— below). **AMENDED at S8-PG1 iteration 1 and at cap closure
(2026-11-19, record `memory/consensus-log/2026-11-19-s8-pre-gate.md`):
every structural change below cites its finding. Iteration-1
amendments: STAGE 3 split 3a/3b; module contract; exit-criterion
mechanism primitive; Seq spec; platform constraints; coverage
arithmetic; cap contingency. Cap-closure amendments (all three
roles BLOCKed on new criticals): the 3a edit list re-scoped (the
five anchor-demo lanes re-home AT 3a); exit-criterion item 2
re-specified as ancestor-canonicalized containment; item 7
re-scoped to a bash-side `_git` wrapper with an honest
network-only claim; STAGE 3c added (merge/alarm/state.json
cutover); STAGE 4 split 4a/4b; matrix retirement moved to/after
STAGE 6; the Seq field DEFERRED OUT of S8; pattern-parity lanes
pin the live bash scrub/sed; module location decided; coverage
table made derivable; the seam protocol
         fail-closed.** **AMENDED at S8-PG1-iter3 iteration 1
         (2026-11-25, record
         `memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md` —
         RT BLOCK 2C + 1M, the coverage off-by-one derived
         independently by ALL THREE roles): the 3a module-LOOKUP
         rule pinned $0-relative with module-copy steps at the
         four mutated-copy probe sites (RT-C1); exit-criterion
         item 2's later-materialized-alias claim corrected to the
         honest form — NOT covered at push time, recorded as the
         filesystem face of frozen residual item 3, closed at the
         port by the push helpers' push-time re-canonicalization
         (a STAGE 4b commitment) (RT-C2/Arch-M2); the coverage
         table corrected to 122 after 3b (v6 23) with the lane map
         (RT-M1/Arch-M1/Steward-M1); the 3b list gains the matrix
         twin sites (RT-m1) and the `_git` wrapper rewiring
         (Arch-m2); the neutralization-hook delivery path through
         the shim specified (Arch-m1); E34's pytest twin re-staged
         to 3c (Arch-m3); the STAGE-2 text superseded by decision
         #22 (Arch-m4); the STAGE-5 retirement blast radius
         completed (Arch-m6); the 3c alarm-surface wording
         corrected (Steward-m1); the stale-citation edit moved
         into the ledgered 3a list (RT-m2).**
**AMENDED at the S8-PG1-iter3 CAP CLOSURE (2026-11-25, same
commit as the iteration-2 record): the four mutated-copy sites
re-ledgered as PROBE-DIR RELOCATIONS with the honest
proof-scope statement (i2-RT-C1/i2-Arch-C1 — the copy-beside
shape was jointly unsatisfiable with the pinned lookup and
identity rules); the seam-protocol invocation re-spelled
$0-relative (i2-RT-M1); STAGE 4b gains the push-time
re-canonicalization as a named deliverable with a LEDGERED
planted-alias lane (i2-RT-m1/i2-Arch-M1); the `_alarms`
magnitude corrected to the 52-line function with the region
figure relabeled the combined 3c surface (i2-RT-m2/i2-Arch-m1);
the 3b "need NO edits" sentence scoped 3b-relative (i2-RT-m3).**

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
         RT BLOCK + Architect BLOCK + Steward PWF; remediation
         landed (eb459b1). Iteration 2 (2026-11-19, on eb459b1):
         NO CONSENSUS AT THE CAP — RT BLOCK (3C) + Architect
         BLOCK (2C) + Steward BLOCK (2C) on NEW criticals of the
         same boundary-contradiction class; all three roles
         confirmed the iteration-1 findings resolved in substance.
         The gate closed cap-exhausted and ESCALATED to the
         project owner; the closing remediation (this document's
         cap-closure amendments) landed with the record. No port
         work has started (documents only throughout); the next
         step was the owner's disposition — DISPOSITIONED
         2026-11-25 (decision #22, "D1:a"): the fresh gate
         S8-PG1-iter3 is running; its iteration 1 (2026-11-25)
         concluded NO CONSENSUS (RT BLOCK — remediation cycle per
         the record), iteration 2 re-judges the amended
         deliverables (record:
         `memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`).
STAGE 3a: PARITY PORT + DELEGATION (own commit; S8-PG1 Arch-C2/
         M6, RT-M1/M2; edit list RE-SCOPED at cap closure —
         RT-C2/Arch-C1/Steward-C1: the earlier "zero edits"
         oracle was unsatisfiable because the delegation breaks
         the five anchor-patching mechanism-demo lanes):
         - scripts/backup_core.py implements the GUARD + IDENTITY
           core BEHAVIOR-PRESERVING (denylist semantics unchanged;
           merge/alarm/state.json cut over at STAGE 3c).
         - scripts/sandbox_backup.sh DELEGATES its guard block to
           the module in the SAME commit (the bash PROD_CHECKOUT
           constant is DELETED; the module derives the guarded
           identity — decision #19c holds from this commit, not
           from a later shim). MODULE-LOOKUP RULE (PINNED at
           S8-PG1-iter3 — RT-C1: unspecified before, and no
           CI-compatible identity-correct resolution existed for
           module-free mutated copies): the script invokes the
           module $0-RELATIVE — "$(dirname "$0")/backup_core.py" —
           identity-from-module-location holds, repo-residency
           holds, CI legs resolve it (no absolute paths, no
           cwd-dependence); a missing module maps to the
           fail-closed refusal exit 6 (seam protocol).
         - LEDGERED 3a EDIT LIST (exhaustive — nothing else
           changes):
           (1) `_prod_checkout()` (tests) and matrix v9 E30
               re-point at the module (the exactly-once derivation
               follows the identity);
           (2) v6 E10 and v7 E15 de-hardcode their hand-copied
               PROD paths to the derived identity (moved here
               from STAGE 4 — Arch-M6: the identity moves at 3a;
               leaving hand-copies falsifies the single-identity
               invariant across the 3a→4 window);
           (3) the five anchor-patching mechanism-demo lanes
               (v8 E20, v9 E25, v9 E29, v10 E31, v10 E34) re-home
               to module-seam stub form IN THIS COMMIT — their
               bash anchors (the PROD literal + the refusal
               blocks) are exactly what the delegation deletes;
               the module contract's injection seams + test hook
               exist for this (Arch-C1/Steward-C1: deferring them
               to STAGE 4 leaves a window with ZERO mutation
               probes); v5 E4 and v7 E18's ASSERTIONS and script
               mutations survive unedited (their anchors stay in
               bash) — their lane scripts gain ONLY the
               probe-dir relocation of item (4) (the copy
               destination changes; nothing asserted changes).
           (4) (ADDED at S8-PG1-iter3 iteration 1; RE-LEDGERED at
               the iter3 cap closure — i2-RT-C1/i2-Arch-C1, both
               executed the same falsification: the iteration-1
               "copy the module BESIDE the mutated script copy"
               shape re-homes the location-derived identity onto
               the lane area, so the guard refuses the lanes' own
               operands (rc 6 ≠ the expected 5/4) and would allow
               production-adjacent operands from the re-homed
               probe — the three constraints ($0-relative lookup,
               identity-from-module-location,
               copy-beside-its-operands) are jointly
               unsatisfiable) the four mutated-copy probe sites
               (v5 E4's two sed/cp copies, v7 E18's two) re-locate
               as PROBE-DIR RELOCATIONS: the mutated script copy
               AND the module copy land together in a probe
               SUBDIRECTORY (e.g. $lane/probe/) that is DISJOINT
               from the lane's operands (the operands stay
               siblings — $lane/clone, $lane/nope.git, $lane/
               bare.git — NOT descendants of the probe dir), so
               the $0-relative lookup resolves the module AND the
               location-derived identity (the probe dir) never
               contains the operands → the guard passes them and
               the run reaches the sabotaged stage (E4's exit 5,
               E18's exit 4). PROOF-SCOPE, stated honestly (per
               i2-RT-C1(c), the inverted-protection finding):
               these lanes prove the SABOTAGE-DETECTION mechanisms
               — the self-test canary catch (E4) and the index
               re-scan (E18) — NOT the guard's production
               protection; production protection is pinned
               separately by the repo-resident script's refusal
               lanes (E10/E33 + the machine refusal lanes) and
               the re-homed module-seam lanes of item (3). The
               seam-anomaly lane stubs the SAME probe-dir shape
               (a garbage module in the probe dir beside a copy
               of the script → module found, crashes → exit 6)
               and asserts its label, keeping its observable
               distinct from the green-path exits.
           (5) (ADDED at S8-PG1-iter3 — RT-m2: the port-time note
               said "fix at 3a" but the exhaustive list omitted
               it) the stale citation comment at
               sandbox_backup.sh ~L1132
               ("scripts/verify_backup_v7.sh") is corrected in
               THIS commit.
         - PARITY ORACLE, restated honestly: the SURVIVING checks
           (everything except the ledgered re-homes above) green
           with zero expectation edits = the equivalence proof;
           the re-homed lanes prove the same mechanisms against
           the module (stubbed seam lying = sabotaged guard). No
           quartet lane needs a 3a edit (none references the
           guarded identity — RT-m2/Steward-m6).
STAGE 3b: INVERSION + LANE CONVERSION (own commit): the allowlist
         inversion lands per the amended evaluation (family-by-
         family; pushInsteadOf + include/includeIf content +
         symlinked-.git/git-dir containment SURVIVE; the
         transport-allowlist backstop lands as a BASH-SIDE `_git`
         wrapper per the cap-closure re-scope — see the module
         contract + exit-criterion item 7); the loopback QUARTET
         (v5 E3, v6 E11, v9 E28, machine-r2 — NOT a trio) converts
         per the evaluation's amended §conversion; the scrub and
         redaction unit-pins + the PATTERN-PARITY lanes land.
         LEDGERED 3b EDIT LIST (exhaustive — RT-M2/Steward-C2:
         the inversion's semantic-change surface, completed at
         cap closure): (a) the quartet lanes (URL operands
         refuse; E3/E28/r2 re-target refusal surfaces; E11's
         two-lane re-homing per the evaluation); (b) the
         message-anchored asserts on RETIRING families — tests
         L989 ("RELATIVE"), L1151 ("fetch"), L1187 ("push") AND
         their matrix twins (v8 E20 L91 and v9 E29 L242 grep
         "RELATIVE", v10 E32 L136 greps "fetch" — ADDED at
         S8-PG1-iter3, RT-m1: the "exhaustive" site enumeration
         undercounted; the same token rule covers them): the
         module's type-inversion refusal message is REQUIRED to
         carry the family keyword (message-token preservation by
         fiat) so the asserts stay green unedited — recorded as a
         3b pinned behavior, with the alternative (editing the
         asserts) rejected to keep 3b's diff surface minimal;
         (c) the file://-REPO behavior change (exit-criterion
         item 6): the file://+prod lane (tests L1364–1369) keeps
         its "production checkout" assertion — the file:// refusal
         message must also carry "production checkout" for
         prod-under-file:// spellings (same message-token rule);
         (d) the scrub/redaction parity lanes + unit pins; (e)
         (ADDED at S8-PG1-iter3 — Arch-m2: the "exhaustive" label
         did not cover it) the BASH-SIDE REWIRING for the `_git`
         wrapper — every TEST-mode git invocation the script
         spawns is re-routed through the wrapper (the largest
         bash edit of 3b; named in the STAGE 3b prose and the
         stays-in-bash list, now ledgered here too). The
         non-existent-operand resilience lanes (machine alarm,
         key-scrub run 2, v5 E4, v6 E12 run 2) need no 3B EDITS
         (scoped at the iter3 cap closure, i2-RT-m3: v5 E4's
         lane script already gains the 3a item-(4) probe-dir
         relocation — the 3b stage adds nothing to it): the
         corrected exit-criterion item 2 keeps them green by
         design (ancestor-canonicalized containment).
STAGE 3c: MERGE/ALARM/STATE.JSON CUTOVER (own commit; added at
         cap closure — Arch-M2: "transitively pinned" overstated;
         the per-function cutover was unnamed): append_manifest,
         merge_union, and the state.json serialization move from
         the three Python heredocs (L895/L947/L1168) into the
         module — AND the alarm machinery proper: the `_alarms`
         BASH FUNCTION (the function proper L1059–1110 = 52
         lines, invoked at L1165/1263/1275/1284/1310; the
         L1052→L1310 REGION the iteration-1 wording called ~260
         lines is the COMBINED 3c surface — the three heredocs
         217 lines + the function 52 — magnitude corrected at
         the iter3 cap closure, i2-RT-m2/i2-Arch-m1) plus the
         alarms_check/alarm_raise semantics; the existing
         machine tests that exercise
         merge/alarm/manifest behavior (the union-scrubs lanes,
         the alarm lane, the manifest lanes) pin the module
         functions from this commit — stated per-function: guard
         + identity pinned from 3a; merge/alarm/state.json
         pinned from 3c; the heredocs DELETE in this commit (no
         dual implementations).
STAGE 4a: Matrix conversion + per-lane MECHANISM audit (deferred
         #12): every matrix lane maps to a ported test that still
         proves the MECHANISM, not just the outcome; the per-lane
         table records each lane's post-conversion home (v5 E3's
         failed-push resilience → the v5-E8 hook-rejection class);
         the bash matrices STAY RE-RUNNABLE and green through the
         STAGE 6 closing gate (retirement moved to/after STAGE 6 —
         Arch-M5: retiring the outside-in oracle before the gate
         that needs it destroys the gate's independence; "retire
         with a gate finding" now means BY a finding of the
         STAGE-6 gate or later).
STAGE 4b: GUARDED-PUSHER HARDENING + CI-forcing decision (own
         commit; split from 4a at cap closure — Arch-m6; the
         first deliverable ADDED at the iter3 cap closure —
         i2-RT-m1/i2-Arch-M1: the push-time re-canonicalization
         was a prose-only commitment absent from this block):
         (1) the guarded push helpers gain the PUSH-TIME TARGET
         RE-CANONICALIZATION (see the module contract +
         exit-criterion item 2 — closes the later-materialized-
         alias filesystem face of residual item 3), LEDGERED as a
         lane: the planted-alias scenario (plant a suffix symlink
         at a non-existent scratch operand AFTER judgment;
         assert the push refuses exit 6 — the lane rides the 4b
         edit list and the coverage table's integrity row);
         (2) the CI-forcing decision: ported-pytest-only vs
         ported-pytest + bash-matrix CI job until retirement —
         today ci.yml runs pytest only, so the E4-class
         stale-lane drift can recur between gates; the ported
         suite running IN CI closes exactly this.
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
         artifact). Retirement blast radius COMPLETED at
         S8-PG1-iter3 (Arch-m6): the same-commit amendment set
         also re-points every OTHER invocation site of the bash
         entrypoint — execution-plan-template.md FINAL STAGE,
         the process doc's closure choreography step 6, the
         release runbook's event-backup step, and harness/README
         — all name scripts/sandbox_backup.sh and must flip to
         the ported equivalent in the SAME retire commit; the
         SHIM option (open decision 4's default lean) avoids the
         entire radius.
STAGE 6: Adversarial consensus gate on the port's RESULTS (S8's
         closing gate; before S2's stage gate). The bash matrices
         retire BY this gate's finding (or later) — never before
         it. CAP CONTINGENCY
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

`scripts/backup_core.py` (location DECIDED at cap closure — open
decision 3 resolved: adjacent to the script it ports, repo-only;
floor and import seam below), Python 3.8-compatible, stdlib-only:

- **Public functions** (the ported surface):
  - `judge_target(operand, *, config_ctx=None) -> Verdict` — the
    operand guard: both-directions resolution (push view per
    operand shape: typed spelling for URL/path, `remote get-url
    --push` for names; fetch view: `ls-remote --get-url`
    semantics), the allowlist type check, containment, and the
    retained content-level config scan (pushInsteadOf keys;
    include/includeIf file content across repo + global + XDG +
    system). **`config_ctx` semantics (pinned at cap closure —
    RT-M3/Arch-M3): the PRODUCTION path is the module-INTERNAL
    default reader (git-config-derived, all four scopes) — the
    bash shim passes ONLY the operand, never config content; a
    caller-supplied `config_ctx` (paths + an injectable reader,
    never pre-read content) exists ONLY as the test seam.** A
    lane pins the production wiring (a config file planted in the
    four scopes is seen by the default reader).
  - `resolve_prod_checkout() -> Path` — the single-source guarded
    identity, derived from the module's own file location (the
    E30 derivation pattern generalized; derivation source pinned
    at cap closure — Arch-m2; no env override in TEST mode).
  - `sanitize_env(env) -> dict` — the env scrub (pure function;
    unit-pinned: drops `GIT_TRACE*` / `GIT_CURL_VERBOSE` /
    `GIT_CONFIG_*` / `GIT_DIR` families).
  - `redact(text) -> str` — the redaction filter (pure function;
    unit-pinned — the structural witness for the curl-verbose
    class after the loopback lanes convert).
  - `append_manifest(...)`, `merge_union(...)` — the merge core
    (already Python heredocs today: manifest append, divergence
    union; cut over at STAGE 3c).
  - `alarms_check(...) / alarm_raise(...)` — the alarm machinery +
    failcount (cut over at STAGE 3c).
- **Stays in bash** (completed at cap closure — Steward-M2/RT-m1:
  the original list omitted three load-bearing surfaces):
  worktree/rsync/commit orchestration; the lock; CLI/env parsing
  at the entrypoint; the shim surface; **the secret scan +
  self-test** (v5 E4's sabotage lanes keep patching it there
  until matrix retirement); **the env-scrub loop** (L111–117 — a
  child cannot scrub the parent's env; it stays and is
  PARITY-PINNED to `sanitize_env` by the 3b pattern-parity
  lane); **the guarded push helpers** (L745–770 — their sed
  redaction stays and is PARITY-PINNED to `redact`; the label
  text is pinned by the re-homed failure lane; AND at STAGE 4b
  each helper gains the PUSH-TIME TARGET RE-CANONICALIZATION
  that closes the later-materialized-alias class — S8-PG1-iter3
  RT-C2/Arch-M2, see exit-criterion item 2); **the `_git`
  wrapper** (new at 3b — injects the transport allowlist flags on
  every TEST-mode git invocation it spawns; sabotage-pinned).
- **state.json heredoc disposition** (Arch-C3): the third Python
  heredoc (inventory/state serialization) MOVES into the module
  at STAGE 3c — leaving it inline would produce a
  mixed-paradigm script that shells to Python for
  merge/alarm/guard while inlining a Python heredoc for
  inventory, a worse shape than today.
- **Injection seams for the ported mechanism demos** (Arch-C3,
  extended at cap closure — Arch-M3): today's mechanism lanes
  prove refusals load-bearing by patching bash SOURCE text. The
  module takes injectable dependencies — target resolver,
  config reader, clock — AND an explicit **refusal-neutralization
  test hook** (a loud `--test-neutralize=<check>` flag, refused
  outside TEST mode, whose use is printed loudly in output): the
  ported E25/E29/E31/E34-class lanes neutralize ONE retained
  check through the hook and assert the incident reproduces —
  the exact ported equivalent of deleting a refusal block, with
  no source string-patching. DELIVERY PATH through the bash
  entrypoint (ADDED at S8-PG1-iter3 — Arch-m1: the hook flag
  must reach the module THROUGH scripts/sandbox_backup.sh for
  the end-to-end lanes): the shim surface translates a
  TEST-mode-only environment variable
  `PC_TEST_NEUTRALIZE=<check>` into the module flag — honored
  ONLY when the script itself is in TEST mode (never PROD;
  refuse otherwise), passed as one extra argv token on the
  delegation — so the E20/E25/E29/E31-class lanes drive the hook
  end-to-end through the real entrypoint.
- **Shim invocation + seam protocol** (pinned at cap closure —
  Arch-M1; invocation spelling CORRECTED at the iter3 cap
  closure — i2-RT-M1: the cwd-relative `python3 scripts/
  backup_core.py` form is the lookup candidate (b) the
  iteration-1 falsification rejected, and it would red v5 E5
  (cd / && run) — a SURVIVING check — at 3a; the $0-relative
  MODULE-LOOKUP RULE governs here too): the script invokes
  `python3 "$(dirname "$0")/backup_core.py" <subcommand>` with a
  FIXED-SCHEMA line protocol on stdout (one `key=value` pair per
  line — no jq dependency on the legacy legs; bash reads lines
  directly). **Fail-closed taxonomy: ANY seam anomaly — module
  crash (non-zero python exit), python3 missing (127),
  malformed/truncated output — maps to the refusal exit 6 with a
  loud seam-anomaly label.** The exit-code contract is the FULL
  documented set 0/2/3/4/5/6/7/8 (+1/128 pass-through, README
  L264–280) — not just 0/2/6; exit 7 is lane-asserted (v5 L188,
  tests L1313). A seam-anomaly lane pins the fail-closed
  behavior (a stubbed module that emits garbage → exit 6).

## Exit criterion — the mechanism primitive (S8-PG1 RT-M3/M4 /
Arch-M2; wording per decision #20 + the amended evaluation)

A TEST run addresses ONLY local absolute filesystem paths,
physically disjoint from the production checkout — enforced by:

1. **Judgment subject**: the RESOLVED EFFECTIVE targets of both
   directions (never the raw operand alone; clean remote names stay
   legal — their resolved targets must pass).
2. **Canonicalization, both sides — with
   ancestor-canonicalization for non-existent operands**
   (RE-SPECIFIED at cap closure — RT-C1/Steward-C2: the earlier
   "realpath-or-refuse for non-existent operands" red-lined five
   green resilience lanes): the operand AND the guarded identity
   canonicalize (`realpath`); for a NON-EXISTENT operand, the
   deepest EXISTING ancestor canonicalizes and the operand is
   judged against that ancestor's containment — a non-existent
   operand under a scratch ancestor stays LEGAL (the alarm /
   key-scrub / E4 / E12-run-2 resilience lanes keep their
   semantics); an operand whose existing ancestor resolves
   into/under production REFUSES; an ancestor that cannot be
   canonicalized at all REFUSES (no silent literal-only
   degradation — the current `|| true` weakening is not
   inherited); the later-materialized-alias class (a symlink
   planted at the non-existent suffix after judgment) is NOT
   covered at push time (CORRECTED at S8-PG1-iter3 — RT-C2/
   Arch-M2: the prior "covered at push time by the retained
   symlinked-.git + git-dir containment" claim was falsified by
   EXECUTED E2E — those checks are guard-time REPO-side checks;
   a planted symlink landed the full checkpoint in a stand-in
   production .git with rc 0 and zero refusal messages): the
   class is recorded as the FILESYSTEM face of frozen residual
   item 3 (README amended, by gate finding per the residual-list
   governance) — and it is CLOSED AT THE PORT (STAGE 4b): the
   guarded push helpers re-canonicalize the push target
   immediately before spawning each push (realpath of the
   operand's deepest existing ancestor AT PUSH TIME) and refuse
   exit 6 if it resolves into/under production or is a symlinked
   .git — the re-check rides with the push, closing the
   multi-second window for this class (config-rewrite faces
   remain item 3's documented residual).
3. **Containment**: equality-or-descendant-with-separator against
   the canonicalized identity; for the git-dir, the symlinked-.git
   refusal + git-dir containment check (retained per the
   evaluation's disposition table).
4. **Bind-mount reality** (RT-M3, demonstrated): realpath cannot
   see through `unshare -rm mount --bind`. The port either
   implements device/inode-identity containment (bind mounts
   preserve st_dev/st_ino — comparing the operand's canonical
   ancestor chain's (st_dev, st_ino) against the identity's,
   `lstat` for the symlink check and `stat` for components —
   mechanics pinned when the 3b lane is written, Arch-m5) or
   mount-namespace aliasing joins the frozen residual list by
   gate finding. Decided at STAGE 3b, recorded in the evaluation
   + README.
5. **Operand scope**: the same rule governs PC_BACKUP_PUSH_REMOTE,
   PC_BACKUP_REPO, and PC_SANDBOX_HOME.
6. **`file://` refused** — a behavior change for the REPO operand
   (today `file:///*` is accepted); stated here so the port's
   expectation edits are explicit, not silent.
7. **Transport allowlist** (RE-SCOPED at cap closure —
   RT-C3/Arch-C2): a BASH-SIDE `_git` wrapper prefixes every
   TEST-mode git invocation it spawns with the non-file
   transports denied (`protocol.*.allow=never`; `file` stays
   permitted — the legitimate TEST pushes are local paths),
   pinned by a wrapper-sabotage lane. Scope, stated honestly: a
   NETWORK-transport-rewrite backstop only; a rewrite to a LOCAL
   path is NOT subsumed (file must stay allowed) and rests solely
   on the retained config-level refusals — the recorded residual
   (see the evaluation's defense-in-depth paragraph).
8. **Exit criterion is LANE-CHECKED, not generator-based** (S8-PG1
   Arch-m1): decision #20's own wording — "feed a non-local
   operand, expect refusal — a matrix lane, not a prose argument".
   No hypothesis dependency (the legacy CI legs install no extras).

## Record sequence field (deferred #10; DEFERRED OUT OF S8 at cap
closure — Arch-M4: the spec as drafted was incoherent with its own
purpose)

The cap-closure finding: "dates keep backing authority" contradicted
"Seq-less records sort before all Seq-ful" (the sort changes which
record is 'latest' under the withdrawal logic); the withdrawal
predicate for Seq-ful records was unspecified; and #10's motivating
defect (a future-dated filename shielding a ☑) remained unsolved.
Rather than rush a record-format change inside a port stage (the
bundling pattern that created S8), the Seq field is **deferred out
of S8 entirely**: ledger row #10 stays deferred to "the next record
format change", with the cap-closure analysis recorded there as the
starting spec (ordering-only + never touching the withdrawal
predicate + exact sort key TBD + forgery-suite classes TBD). S8
ships without it; nothing in the port depends on it.

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

| Surface | Today | After 3a (expected) | After 3b (expected) | After 3c/4/5 |
|---|---|---|---|---|
| Matrix checks (bash) | v5 20 · v6 22 · v7 25 · v8 19 · v9 26 · v10 9 = 121 | 121 total preserved; the five re-homed demo lanes (v8 E20, v9 E25/E29, v10 E31/E34) re-point at module seams, still 121 | **122** total: quartet lanes re-shaped in place (E3/E28/r2 → refusal expectations); E11 → the two-lane re-homing, BOTH lanes INSIDE v6 — v6 = 22−1+2 = **23 checks** (lane map: −1 old E11, +1 success lane, +1 hook-rejection failure lane) — CORRECTED at S8-PG1-iter3, RT-M1/Arch-M1/Steward-M1: all three roles derived 122 and the prior "121 preserved / (22, re-shaped)" cell was off by one and underivable; message-token rule keeps L989/L1151/L1187 + the matrix twins green unedited | unchanged **122** through the STAGE-6 gate; retirement BY that gate's finding (or later), with the per-lane table as the count map |
| Integrity suite | 16 tests (728+9 local; 737×4 POSIX; 605+132 Windows) | 16 + module unit tests + the seam-anomaly lane + the demo re-homes' pytest twins — FOUR of the five at 3a; v10 E34's twin lands at 3c (its mechanism, merge_union's union-prefers-OURS, is 3c surface — S8-PG1-iter3 Arch-m3; counts recorded at each stage commit) | + scrub/redaction unit pins + pattern-parity lanes + the `_git`-wrapper sabotage lane (count recorded at the 3b commit) | 3c: unchanged count (heredoc cutover is behavior-preserving); Windows: +M unit-runnable (pure functions) per the platform section; the STAGE-4b planted-alias lane (count recorded at the 4b commit) |
| The quartet | E3, E11, E28 rc-0/exemption lanes; machine-r2 rc-0 | unchanged (no 3a edits — no quartet lane references the identity) | E3/E28/r2 → refusal lanes; E11 → v6 two-lane re-homing (success + hook-rejection failure); scrub unit-pin + parity lanes | ported per-lane equivalents at 4a |

Every stage commit records its ACTUAL numbers beside these expected
numbers; a number that drifts without a lane map is the E4 class
(the expected cells are derivable from the ledgered 3a/3b edit
lists — corrected at cap closure, Steward-M1, and again at
S8-PG1-iter3: the post-3b cell was off by one, RT-M1/Arch-M1/
Steward-M1 — derivation: E11 1→2 inside v6 ⇒ v6 23 ⇒ total 122).

## Invariants held throughout

- The suite stays green at every stage (baseline 728 passed + 9
  skipped local / 737×4 POSIX, 605+132 Windows, wheel + Android
  CI); new coverage extends tests in place per the house rule.
- STAGE 3a is parity-only: the SURVIVING checks (everything
  outside the ledgered 3a edit list — identity re-pointing,
  de-hardcoding, the five demo-lane re-homes) green with zero
  semantic expectation edits is the equivalence proof; STAGE 3b
  changes semantics in its own commit, against its own ledgered
  edit list.
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

- STAGE 3a/3b/3c/4a/4b/5 boundaries: `python -m pytest -q -p no:asyncio`
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
  harness/backups/matrices/); LEDGERED into the 3a edit list
  item (5) at S8-PG1-iter3 (RT-m2) — fixed at STAGE 3a.
- Module Windows skip policy per the platform section above.

## Open decisions (updated at cap closure)

1. ~~The loopback-trio conversion~~ — DECIDED at S8-PG1: the QUARTET
   converts per the amended evaluation (all three roles converged;
   disagreement would have escalated).
2. CI-forcing choice for the matrices (STAGE 4b): ported-pytest-only
   vs ported-pytest + bash-matrix CI job until retirement — still
   open; decided at STAGE 4b.
3. ~~Module location~~ — DECIDED at cap closure (RT-m5: the platform
   section already reasons from it; deciding before 3a):
   `scripts/backup_core.py` — adjacent to the script it ports,
   repo-only (not in the wheel), imported via tests/conftest.py;
   `harness/` rejected because the module is the ported
   implementation, not governance process documentation.
4. Shim vs retire for the bash entrypoint at STAGE 5 — still open,
   with the blast radius stated (all 137 checks invoke the
   entrypoint; retirement deletes the last documented bash surface).

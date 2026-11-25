# Decision Log (ADR-lite)

Format: **decision** — context — date. Newest last.

1. **Clean-room GPL-3.0 implementation** — the project re-implements
   ProtonVPN client behaviour from scratch (no upstream code), so
   GPL-3.0 with no proprietary dependencies. (project start)

2. **PySide6 primary, PySide2-Qt5 fallback via `qtcompat`** — keeps
   legacy distro Pythons (3.8) supported; CI has dedicated legacy legs.
   (early)

3. **Qt-free-at-import `ui/md3.py`** — the MD3 color engine works on
   plain hex strings/dicts so the test suite can validate color math
   headlessly (no Qt binding import needed). (v0.6.x theming work)

4. **HCT approximated via CIELAB** — Google's material-color-utilities
   is Apache-2.0 and its HCT solve is complex; we approximate HCT→sRGB
   as HCT→CIELAB→XYZ(D65)→sRGB with binary-search chroma clamping.
   Good perceptual fidelity, no dependency, GPL-clean. (v0.6.x)

5. **Blocklist defaults = uBlock Origin out-of-the-box set** — parity
   with the most widely-trusted consumer default; verified 1:1 against
   `gorhill/uAssets` assets.json. (v0.6.2, PR #2)

6. **Bond chunk retry on next member, seq advances only on confirmed
   send** — flushes out the "adapter dies mid-send kills the stream"
   bug; premature seq advance left a permanent reassembly gap.
   (2026-11-07, `53afc6c`)

7. **Desktop bond E2E strategy: real on Linux, discovery-replayed +
   real sessions on macOS/Windows, CI-native everywhere** — CI runners
   provide real sources on all three OSes (Windows via the
   primary-address fallback for its strong host model); skip counts
   compared before/after prove nothing silently skipped. (2026-11-07)

8. **Event-driven backups, not interval-driven** — backups run as the
   LAST step of every execution plan / prompt output, pushed to the
   `sandbox/backups` branch; `harness/` memory itself lives on `main`.
   (2026-11-13, per project owner directive)

9. **Adversarial consensus gate for every stage** — independent
   adversarial-agent roles must all return PROCEED (findings addressed)
   before any stage proceeds; verdicts recorded in
   `memory/consensus-log/`. (2026-11-13, per project owner directive)

10. **Material You = MD3 + dynamic color seed** — the desktop derives
    the whole scheme from a seed (brand green / OS accent / custom);
    Android uses `dynamicColorScheme()` on 12+ with the Proto palette
    as fallback. **Defaults diverge by platform, deliberately** (amended
    at gate G1): desktop defaults to brand green (OS accents are a
    weaker identity signal there and detection is DE-dependent);
    Android 12+ defaults to wallpaper dynamic color (the platform
    convention users expect). Either is a one-tap setting away.
    (2026-11-13)
11. **Backup script v2: append-only, worktree-isolated** — the first
    design (manifest self-recording its commit SHA via amend +
    force-push, writing state into the main checkout) was BLOCKED by
    the G1 gate: it could leak secrets, brick itself on one transient
    push failure, and dirty main's tree into release commits. v2
    builds all state inside a temporary worktree on the
    `sandbox/backups` branch, one plain commit per backup, never
    rewrites history, secret-scans twice, and serializes with a lock.
    (2026-11-13, G1)
12. **Credentials never live in scripts** — poll/release helpers read
    the token from `GITHUB_TOKEN` or the git remote. Any script that
    could be copied by a backup/collect flow gets a secret scan with
    hard failure. (2026-11-13, G1 — near-miss, nothing leaked)
13. **Chroma model is a deliberate M3 variant** — `scheme_from_seed`
    keeps muted seeds muted: primary chroma `min(seed_chroma, 48)`
    rather than Google tonal-spot's flat 36 (which would boost a muted
    seed like GNOME slate to full color). Contrast is tone-driven and
    unaffected (the G1-iter3 Architect ad-hoc ran the planned S2
    contrast property test: 4,000 checks, worst 6.42:1). Documented in
    the `scheme_from_seed` docstring. (2026-11-13, G1-iter3)
14. **Backup script v4: self-testing scan + test isolation** — G1-iter3
    proved by execution that v3's canary self-test missed 3 of 7
    pattern alternations and never exercised the production grep
    invocation (a flag drift left it blind), and that env overrides
    did not control the push target (a test run against a clone of the
    real repo pushed test commits toward github — reproduced
    accidentally during fix-cycle verification, disclosed in the
    consensus log). v4: one scan function everywhere, per-alternation
    canaries through that function, exit-6 production-origin guard for
    any override run, atomic locks, manifest recovery from git
    history, divergence auto-merge with manifest union, harness/
    refresh per checkpoint, 2+-failure main-push alarm. Machine-checked
    by tests/test_harness_integrity.py. (2026-11-13, G1-iter3)
15. **Gate caps escalate; remediation does not equal closure** —
    G1-iter3 exhausted its 2-iteration cap with a Red Team BLOCK on
    iteration 2 (scan-coverage critical on the harness/ refresh
    surface, proven by execution; plus isolation, alarm and GIT_TRACE
    majors). Per the process doc the stage halts and escalates to the
    owner; all findings were remediated and scratch-verified in the
    same cycle (full-harness scan coverage, any-target production
    refusal, branch-push streak alarm with `prev_branch_push` manifest
    field, GIT_TRACE unset + stderr redaction, per-field identity
    fallback, shaped-filename tree exclusion), but S1 is NOT closed: a
    fresh gate (G1-iter4) ordered by the owner must re-judge the
    remediation commit. Alongside: consensus records now carry a
    machine-parseable `FINAL OUTCOME:` line, and a roadmap ☑ requires
    a `FINAL OUTCOME: CONSENSUS REACHED` record naming the stage
    (enforced by tests/test_harness_integrity.py). (2026-11-14,
    G1-iter3-i2)
16. **Backup script v5: production is opt-in; the guard normalizes;
    the merge never takes remote content** — G1-iter4 proved by
    execution that v4's production-as-default caused two accidental
    production pushes across two gates (manifest seq 3 and 5), that
    the exit-6 guard was a spelling blocklist (case/:443///scp
    variants reached github in scratch), that the branch-push alarm
    froze under persistent unreachability, that the divergence
    content-merge pushed unscanned remote content (and a poisoned
    manifest then bricked every future run), and that the
    FINAL-OUTCOME machine check was satisfied by its own documentation
    prose. v5: production requires `PC_BACKUP_ALLOW_PRODUCTION=1`
    (refusal exit 6 before any action otherwise), TEST runs refuse
    every github host however spelled (canonicalized compare), the
    branch-push streak counts failed pushes even unreachable,
    divergence merges take `-s ours` + a sanitized manifest union +
    a pre-commit re-scan, every push is captured and
    credential-redacted (TRACE2 family unset), shaped names are
    excluded and counted across all of harness/, inputs are validated,
    both rsyncs are checksummed, and the FINAL-OUTCOME check is
    line-anchored, exactly-one and self-falsified. (2026-11-15,
    G1-iter4)

17. **Backup script v6 + gate-record authority model (G1-iter4-i2,
    2026-11-16).** Defenses are PATTERN-matched, never enumerated:
   the trace/config env scrub sweeps every `GIT_TRACE*` variant plus
   `GIT_CURL_VERBOSE` and git's env-config injection
   (`GIT_CONFIG_KEY*`/`VALUE*`/`COUNT`/`PARAMETERS`) off the live
   environment; the github refusal matches the target HOST against
   `github.com|*.github.com` (every subdomain) after canonicalization.
   Overrides are ALL-THREE or NONE (a partial set refuses exit 2) and
   a TEST run never operates on the production checkout. EVERY push
   — main and branch — goes through a guarded helper with userinfo +
   token-shape redaction. The divergence-union scrub covers dict keys
   as well as values. Gate-record authority is DECLARATION-bound: a
   record carries `Stage: S<n>` lines, its closure line is its last
   non-empty line after fence-stripping, undated records back
   nothing, and stage matching is exact — replacing the
   incidence-based check the G1-iter4-i2 Red Team forged four ways.
   Closure choreography (verdicts → closure line → same-commit glyph
   flip → state/session docs → push → event backup) is defined in
   `process/adversarial-consensus.md`. (2026-11-16, G1-iter4-i2)

18. **Backup script v7 + the harness subsystem's bounded exit
    criterion (G1-iter5, 2026-11-19).** The v7 remediations (every
    one executed end-to-end in scratch before commit):
    empty-credential URL spellings (`https://@github.com/…`,
    `github.com:/…`, scp `git@github.com:/…`) normalize away in
    `_norm_url`; the production-path compares are PHYSICAL (`pwd -P`
    + leading-`//` collapse) and cover the push TARGET (and its
    `.git`), not just the repo operand; the push target is RESOLVED
    the way git resolves it (`remote get-url --push` for remote
    names, `ls-remote --get-url` for URL/path operands —
    insteadOf-aware) before it is judged; `GIT_CONFIG_GLOBAL` and
    `GIT_CONFIG_SYSTEM` join the pattern env scrub (config-by-FILE
    injection via env is inert); every pre-push `git add` is followed
    by an INDEX re-scan (`git grep --cached` — anything committed was
    staged and scanned); the scrub is mutation-covered by a
    zero-trace-lines observability lane; and the ☑-backing check
    gained stale-consensus withdrawal (a newer non-consensus record
    retracts the glyph) plus the id-less-☑-outside-Shipped rule.
    Alongside (the Architect's bounded-exit recommendation, adopted):
    (a) the bash script's capability set is FROZEN — only
    refusal-class fixes and port prep until the port; (b) the
    merge/alarm/guard core ports to a tested Python module BEFORE
    S2's stage gate (the 16 machine tests + the 112 matrix checks
    across v5–v9 — repo-resident since G1-iter6 — pin the behavior
    to port better than it will ever be pinned again); (c) a FROZEN residual-threat list
    (backups README) bounds what future gates judge against — each
    gate no longer re-derives the attack surface from scratch, and
    adding to the list requires a gate finding. (2026-11-19,
    G1-iter5)

19. **Harness subsystem split + the port's PROPERTY-based exit
    criterion (G1-iter6, 2026-11-19).** Five consecutive S1 gates
    closed at their caps, every closing finding concentrated in the
    backup/harness subsystem while the stage's deliverable (Material
    You) stayed green and fully ledgered — the monolithic stage let a
    subsystem hold the deliverable hostage (G1-iter6 Devil's
    Architect major #3, remediated same cycle). (a) **S1 closes on
    its deliverable** (Material You verified green across five gates;
    residual items ledgered to S2/S5); the harness subsystem — the
    backup script port, its property re-specification, the matrix
    upkeep — becomes its own roadmap stage (**S8**), gated before
    S2's stage gate (the decision-#18 port schedule, now with its own
    gate). (b) **The port's exit criterion is PROPERTY-based, not
    behavior-preserving** (Architect major #2): a TEST run addresses
    ONLY local absolute filesystem paths, physically disjoint from
    the production checkout (containment, not equality); production
    is opt-in; nothing exits the machine in TEST mode. The port must
    EVALUATE the allowlist inversion (v9's denylist+refusal families
    exist because TEST mode retains any-host capability that no
    consumer uses — every legitimate TEST lane pushes to a local
    scratch bare); the frozen residual list then shrinks by gate
    finding. (c) **Identity single-sourcing is part of the exit**:
    the guarded identity derives from the script under test
    (machine lanes already do, G1-iter6; the port's config must make
    the one-sided-patch accident structurally impossible — Architect
    major #1). (d) The owner-side escalation default (split after two
    consecutive subsystem-concentrated cap-exhaustions) is recorded
    in `process/adversarial-consensus.md`. (2026-11-19, G1-iter6)

20. **The port ADOPTS the allowlist inversion — the evaluation
    becomes a named S8 pre-gate deliverable, not a clause
    (G1-iter6-i2, 2026-11-19).** Decision #19b's "EVALUATE the
    allowlist inversion" was a hedge (G1-iter6-i2 Devil's Architect
    major #1): the criterion's first clause — a TEST run addresses
    ONLY local absolute filesystem paths — already IS the inversion,
    semantically; "nothing exits the machine in TEST mode" is
    mechanically testable only under it (feed a non-local operand,
    expect refusal — a matrix lane, not a prose argument); and every
    denylist-family bypass across six gates (percent-encoded hosts,
    `ext::` transports, `:22:` spellings, raw-IP, trailing dots,
    multi-@ userinfo, pushInsteadOf, includeIf-conditional config,
    the fetch side of named remotes) was a spelling chase the
    inversion makes structurally impossible. (a) S8's exit criterion
    now MANDATES: TEST mode addresses ONLY local absolute filesystem
    paths, physically disjoint from the production checkout;
    production is opt-in; the denylist refusal families retire as
    their matrix lanes convert to allowlist lanes. (b) The evaluation
    survives as a NAMED S8 pre-gate deliverable: a written
    adopt/reject decision carrying the consumer inventory (the
    "every legitimate TEST lane pushes to a local scratch bare"
    claim, re-verified at the port) — a REJECTION requires an owner
    decision at S8's gate, not prose. (c) The v10 both-directions
    judgment and the residual list's third-party-egress entry
    (backups README item 1, added by the same gate finding) document
    exactly what the inversion closes. (2026-11-19, G1-iter6-i2)

21. **Owner disposition of the G1-iter6-i2 escalation — the split
    default takes effect; S1 closes on its deliverable via a scoped
    closing gate; S8 activates for its pre-gate deliverables
    (2026-11-19).** Presented with the escalation at the pstack
    handoff (commit `89b1d70`), the owner instructed "Continue" —
    no override of the split default was ordered, so per the
    owner-side escalation rule (process doc, adopted G1-iter6) the
    decision-#19 split is OPERATIVE: S1 closes on its deliverable
    (Material You green through six gates, zero deliverable
    findings; residuals ledgered to S2/S5), and the harness findings
    are owned by S8's own gate. (a) **Mechanics of the S1 close:**
    the done-glyph flip requires a backing record declaring S1 that
    closes CONSENSUS REACHED (decisions #15/#17/#18,
    machine-enforced), and that record must be dated STRICTLY AFTER
    2026-11-19 — the iter6-i2 record (same date, NO CONSENSUS,
    declares S1) withdraws a same-date close under the fail-safe tie
    rule (G1-iter5 RT minor #1). The S1-closing gate is therefore
    scheduled for 2026-11-20+ on the remediation line (`7a13645` and
    later), per the G1→G1-iter3 fresh-gate precedent, SCOPED to the
    split: S1's deliverable closure, the split's boundary
    correctness, and this disposition's recording — NOT a
    re-judgment of the harness findings (S8 owns those; the narrowed
    scope is the fresh gate's justification against the split
    default). The roadmap title narrows to the deliverable at the
    flip, same commit (deferred #11). (b) **S8 activates now** for
    its named pre-gate deliverables (decision #20b): the written
    allowlist-inversion adopt/reject evaluation carrying the
    re-verified consumer inventory, and the S8 execution plan (port
    design; property-based exit criterion; identity single-sourcing;
    per-lane mechanism audit + CI-forcing decision per deferred #12;
    record sequence field per deferred #10). No gate outcome is
    pre-recorded. (2026-11-19, owner disposition on the G1-iter6-i2
    escalation)

22. **Owner disposition of the S8-PG1 escalation — a fresh pre-gate
    is ordered on the closing-remediation line, and the S1-closing
    gate runs FIRST (2026-11-25).** Presented with the S8-PG1
    cap-closure escalation (commit `865580e`, closing remediation
    landed with the record — documents only, no port code changed)
    and its three tabled options — (a) a fresh gate on the
    closing-remediation line per the G1→G1-iter3 precedent, (b)
    further splitting S8 (spec line vs port implementation), (c)
    owner-descoped S8→S2 ordering — the owner instructed
    **"D1:a, d2:a"**: **D1 = option (a)** — S8-PG1-iter3, a fresh
    pre-gate with its OWN 2-iteration cap, re-judging the two
    STAGE-1 deliverables (the allowlist-inversion evaluation + the
    S8 execution plan) as amended through the S8-PG1 closing
    remediation, pinned on the line `865580e` and later; **D2 = the
    S1-closing gate runs FIRST** (the first-listed sequencing
    option: S1-close before the S8 fresh gate), so the execution
    order is S1-closing gate → S8-PG1-iter3 → S2. The S1-closing
    gate's scope stays exactly as decision #21 defines it (the
    deliverable's closure + the split's boundary correctness + the
    dispositions' recording — NOT a re-judgment of the harness
    findings, which S8's own gate owns); the date constraint is
    satisfied (2026-11-25 > 2026-11-19, the iter6-i2 record's
    date). No outcome for either gate is pre-recorded; if the
    fresh gate again exhausts its cap, the escalation returns to
    the owner with the split/descope options re-tabled per the
    owner-side escalation rule. (2026-11-25, owner disposition on
    the S8-PG1 escalation)

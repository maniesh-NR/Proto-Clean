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

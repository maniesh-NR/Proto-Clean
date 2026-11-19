# Roadmap (consensus-gated)

Every stage below requires an adversarial consensus gate BEFORE work
starts (see `process/adversarial-consensus.md`) and another covering
its results before the NEXT stage proceeds. Status legend:
☐ queued · ◐ gated/in-progress · ☑ done+gated.

## Shipped (retrospectively assessed at gate G1 — zero findings against the released line; see consensus-log)

- ☑ v0.6.0–v0.6.2 line: interop hardening, perf/stability pass,
  region-grouped servers, guest-mode fixes, uBO-parity blocklists
- ☑ Link bonding across desktop platforms (bond/balance, failover,
  self-host server) + E2E desktop test matrix + shutdown fixes

## In gate (outcome pending — no pre-recording)

- ◐ **S1. Material You across all OSes + agent harness + event-driven
  backups** — the DELIVERABLE (desktop + Android dynamic color, seed
  persistence, OS accent detection) shipped green in the first gate
  and has stayed green since; all five cap-exhaustions of this gate
  were decided by backup/harness-subsystem findings (full narratives:
  `memory/consensus-log/2026-11-13-S1-material-you-gate.md` and its
  iter2/iter3/iter4/iter5 successors). G1-iter6 (owner-ordered
  2026-11-19, on the G1-iter5 closing line `a1607ce` +
  `32d822f`): iteration 1 — Red Team BLOCK (git-dir identity
  redirects, remote-carried relative targets, pushInsteadOf on direct
  operands — falsifying a frozen-residual claim — percent-encoded
  hosts, `ext::` transports, six new glyph-forgery classes; all
  executed E2E) + Devil's Architect PROCEED-WITH-FINDINGS (identity
  coupling, port exit-criterion shape, gate convergence) + Ship
  Steward PROCEED-WITH-FINDINGS (claim map clean, CI exact, one
  stale-log major) → **NO CONSENSUS — iteration 1 of 2.** The fix
  cycle (backup v9: git-dir identity check + env-family scrub,
  every-relative refusal, pushInsteadOf/transport/percent/raw-IP
  refusals, first-colon + post-@ host cut, containment compares;
  glyph rules: backing adoption date, multi-Date, multi-id,
  lookalike glyphs, id-less ◐, post-closure fences; lanes derive the
  guarded identity; matrices repo-resident v5–v9 = 112 checks;
  residual list corrected per findings; the harness subsystem SPLIT
  into S8, decision #19) lands in the commit carrying the iter6
  record; **iteration 2 (2026-11-19, on the fix commit `0c4b8f9`):
  Red Team BLOCK** (2 executed criticals: includeIf-conditional
  pushInsteadOf — the key is invisible to the guard's context on
  main and materializes at push time in the worktree, the full TEST
  checkpoint landed in the unjudged rewrite target, rc 0; the FETCH
  side of a named remote never judged — a clone with
  url=<github-spelled> + pushurl=<local bare> fetched from github in
  TEST mode, 3× CONNECT github.com:443 at a local sink; 1 major:
  symlinked .git passes the identity compare — both sides resolve
  through it; 3 minors: union prefers the remote same-triple entry,
  the PROD derivation is first-match vs bash last-assignment, scp
  passwords echoed) vs Devil's Architect PROCEED-WITH-FINDINGS (3
  majors: the port exit criterion's allowlist hedge — resolved by
  decision #20; the identity-derivation job unfinished — lanes,
  matrix E30, anchors, all fixed; the split left stale ledger/S6
  docs — fixed) and Ship Steward PROCEED-WITH-FINDINGS (claim map
  clean, CI confirmed exact on `0c4b8f9` — run 44458438836, 737×4
  POSIX / 605+132 windows / wheel+Android green; 2 doc minors,
  fixed). **NO CONSENSUS at the 2-iteration cap — G1-iter6 closed,
  escalated to the project owner.** Every iteration-2 finding
  remediated and machine/matrix-covered in the closing commit
  (backup v10: both-directions judgment incl. the URL-operand
  insteadOf sibling found by orchestrator analysis; include/includeIf
  file-content refusal; symlinked-.git refusal + git-dir containment;
  union-prefers-ours with the collision audited; scp redaction;
  derived-exactly-once PROD; matrix v10 E31–E35 + v9 hardening
  (loud anchors, derived E30, loud skips); decision #20; ledger
  #10→S8 + rows #11/#12; process-doc item (f) extension +
  record-before-fix-cycle rule) — **OWNER DISPOSITION RECORDED
  (2026-11-19, decision #21): the owner instructed "Continue" — no
  override, so the decision-#19 split is operative. S1 closes on
  its deliverable via a scoped closing gate (fresh-gate precedent
  G1→G1-iter3, on the remediation line `7a13645`+; scope = the
  deliverable's closure + the split's boundary correctness + the
  disposition's recording — NOT a re-judgment of the harness
  findings, which S8's own gate owns). The done-glyph flip + title
  narrowing (deferred #11) land with that gate's backing record,
  scheduled 2026-11-20+ — the iter6-i2 record (2026-11-19, NO
  CONSENSUS, declares S1) withdraws a same-date close under the
  fail-safe tie rule. No closing-gate outcome is pre-recorded.**
  - Desktop: dynamic-color seed (brand / system accent / custom hex),
    OS accent detection (GNOME 47 accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation,
    settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+, DataStore toggle
  - Agent harness + event-driven backups (v6 remediated) + adversarial
    process

## Near term

- ◐ **S8. Harness subsystem hardening + Python port** (decision #19,
  split out of S1 at G1-iter6 after five subsystem-concentrated
  cap-exhaustions) — port the backup merge/alarm/guard core to a
  tested Python module against the PROPERTY-based exit criterion
  (a TEST run addresses ONLY local absolute filesystem paths,
  physically disjoint from the production checkout; production
  opt-in; nothing exits the machine in TEST mode; the allowlist
  inversion is MANDATED per decision #20 and its ADOPT evaluation
  is amended at S8-PG1 — family-by-family disposition: the
  pushInsteadOf / includeIf-content / symlinked-.git refusals
  SURVIVE the inversion; loopback QUARTET converts); single-source
  the guarded identity so the one-sided-patch accident class is
  structurally impossible; ledger #10 (glyph-check date-semantics
  residuals) DEFERRED OUT of S8 at the cap closure — next
  record-format change; keep the repo-resident
  matrices v5–v10 green (121 checks). **Its own gate before S2's
  stage gate** (the decision-#18 port schedule, now a stage).
  **Pre-gate S8-PG1 (2026-11-19): CLOSED AT THE 2-ITERATION CAP —
  NO CONSENSUS, escalated to the project owner.** Iteration 1 (on
  `82fb63c`): RT BLOCK (2 criticals) + Devil's Architect BLOCK (3
  criticals) + Ship Steward PROCEED-WITH-FINDINGS; remediation
  `eb459b1`. Iteration 2 (on `eb459b1`): all three roles BLOCK on
  new criticals of the same boundary-contradiction class (the 3a
  parity oracle unsatisfiable — the five anchor-patching demo
  lanes break at the delegation; realpath-or-refuse red-lining
  five resilience lanes; the transport-allowlist backstop
  undeliverable as claimed) while CONFIRMING the iteration-1
  findings resolved in substance. Closing remediation landed with
  the record (documents only; no port work started): 3a edit list
  re-scoped, ancestor-canonicalized containment, bash-side `_git`
  wrapper with the honest network-only claim, STAGE 3c added, 4
  split 4a/4b, matrix retirement moved to/after the STAGE-6 gate,
  Seq deferred out (ledger #10), pattern-parity lanes, module
  location decided, seam protocol fail-closed. **Owner
  disposition PENDING (fresh gate on the remediation line per the
  G1→G1-iter3 precedent / further split / descope) — not
  pre-recorded. Record:
  `memory/consensus-log/2026-11-19-s8-pre-gate.md`.**
- ☐ **S2. Release v0.6.3** — ship Material You + bonding fixes
  (runbook: `memory/03-release-runbook.md`; **adversarial pre-gate
  required before work starts — none has run yet**). Scope (folded in
  from old S3 per G1):
  - SHA-256 checksums of every asset in the release body
  - seed-corpus WCAG contrast property test (≥ 4.5 on the fixed tone
    pairs across ~200 seeds) gating the tag
  - clear every deferred-findings row gated at this tag: **#1–#4 and
    #7** (Android dynamicColor QA, accessor allow-list test,
    accent-probe caching — legacy-leg behavior specified, Flatpak
    dconf, raw-hex ban in painter modules) — the ledger is
    authoritative; runbook §2 derives from it
- ☐ **S3. Bond server packaging + docs** — one-command self-host
  (docker image or static binary), token guidance. **Blocked by S6**
  (security review): do not promote the attack surface before
  reviewing it.
- ☐ **S4. Split-tunneling parity on Android** (per-app exclusions
  exist; verify site/IP rules parity with desktop)

## Mid term (each gets its own gate before starting)

- ☐ **S5. Accessibility pass** — keyboard nav, screen-reader labels,
  "accent not detected" UX for KDE/XFCE (deferred finding #5)
- ☐ **S6. Security/threat-model review** — helper privileges, DNS
  server surface, blocklist download chain, **bond server exposure
  (must gate or accompany S3's packaging work — do not promote the
  attack surface before reviewing it)**, **the account/auth chain
  (G1-iter6 Architect minor #5): credential storage at rest (keyring
  + the chmod-0600 JSON fallback), TOTP secret storage, session
  persistence, the browser-scrape login relay, API TLS
  verification**; the bash→Python port of the backup
  merge/alarm/guard core is stage **S8** (split out at G1-iter6,
  decision #19; corrected at G1-iter6-i2 — Architect major #3):
  ledger row #9, the property-based exit criterion (decisions
  #19b/#20 — the allowlist inversion mandated), the repo-resident
  matrices, and ledger #10 ride S8's own gate
- ☐ **S7. Legacy-stack sunset decision** — Python 3.8 is EOL; decide
  keep/drop for the PySide2-Qt5 / PySide6-6.2 legs (every UI change
  pays the compat tax until decided). Decision due by v0.7 — S2's
  deferred-#3 fix must (and does, per its plan) specify legacy-leg
  behavior that works without Qt ≥6.5 signals.

## Long term / candidates

- ☐ WireGuard native kernel module support on Linux (performance)
- ☐ Multi-hop chaining (Proton Secure Core behaviour)
- ☐ Auto-updater story for desktop packages — deferred, but stale VPN
  clients are a **security** liability, not just convenience
  (deferred-findings #6); revisit after S7
- ☐ Localization (i18n) infrastructure

## Parking lot (explicitly deferred, with reasons)

- Copilot PR review automation — instructions staged, but no PRs to
  review yet; revisit when a PR arrives.
- Play Protect/Play Store listing — outside repo scope for now.

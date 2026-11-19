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
  record; **iteration 2 (final) re-judges the fix commit — no
  outcome pre-recorded.**
  - Desktop: dynamic-color seed (brand / system accent / custom hex),
    OS accent detection (GNOME 47 accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation,
    settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+, DataStore toggle
  - Agent harness + event-driven backups (v6 remediated) + adversarial
    process

## Near term

- ☐ **S8. Harness subsystem hardening + Python port** (decision #19,
  split out of S1 at G1-iter6 after five subsystem-concentrated
  cap-exhaustions) — port the backup merge/alarm/guard core to a
  tested Python module against the PROPERTY-based exit criterion
  (a TEST run addresses ONLY local absolute filesystem paths,
  physically disjoint from the production checkout; production
  opt-in; nothing exits the machine in TEST mode; the allowlist
  inversion is EVALUATED, not assumed away); single-source the
  guarded identity so the one-sided-patch accident class is
  structurally impossible; fold the glyph-check date-semantics
  residuals (ledger #10) into the port; keep the repo-resident
  matrices v5–v9 green. **Its own gate before S2's stage gate** (the
  decision-#18 port schedule, now a stage).
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
  verification**; also decide whether to port
  the backup merge/alarm/guard core from bash to a tested Python
  module — now ledger row #9, with the port + a frozen verification
  matrix as the harness subsystem's bounded exit criterion
  (G1-iter4-i2 Architect)
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

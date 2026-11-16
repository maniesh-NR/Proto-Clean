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
  backups** — gate history: G1 iter-1 BLOCK → iter-2 cap → owner-ordered
  fresh gate **G1-iter3** (cap 2): iter-1 BLOCK (canary/scan gaps) →
  fix cycle `7e54aa1` → CI broke 5/7 → three environment fix extensions
  (`140d9dc` identity fallback, `3d51da9` push-stderr capture + container
  rsync, `67df974` shallow-checkout fetch-depth; CI 7/7 green,
  728/leg POSIX · 604+124 windows) → **iter-2 (2026-11-14): Red Team
  BLOCK** (scan coverage gap on the harness/ refresh surface — proven
  exfiltration to the pushed branch — plus guard/alarm/GIT_TRACE
  majors) + Architect/Steward PROCEED-WITH-FINDINGS → **iteration cap
  reached, NO CONSENSUS — escalated to the project owner.** All
  iteration-2 findings remediated in the commit carrying the iter-2
  record (scan covers all of harness/, any-target production refusal,
  branch-push streak alarm + `prev_branch_push` manifest field,
  GIT_TRACE unset + stderr redaction, per-field identity fallback,
  shaped-filename tree exclusion, FINAL-OUTCOME-backed integrity
  check); each fix execution-verified in scratch. **S1 stays open: a
  fresh gate (G1-iter4) must re-judge the remediation commit before
  closure — per process, that re-gate is the owner's call.**
  **G1-iter4 (owner-ordered 2026-11-15): iteration 1 — Red Team BLOCK
  (production-as-default + guard-spelling bypass + unreachable-alarm
  + unscanned divergence merge + GIT_TRACE2) and Devil's Architect
  BLOCK (the FINAL-OUTCOME machine check defeated by its own
  documentation) vs Ship Steward PROCEED-WITH-FINDINGS; every finding
  remediated and execution-verified (backup v5, hardened +
  self-falsified integrity check, +4 machine tests, 20/20 scratch
  matrix) — iteration 2 re-judged the fix commit (record:
  `2026-11-15-S1-material-you-gate-iter4.md`).
  Iteration 2 (2026-11-16): Red Team BLOCK** (2 criticals: the
  github-SUBDOMAIN guard bypass — `www.github.com` verified a live
  anonymous git endpoint for the production repo, a gist target ran
  end-to-end past the guard; the FINAL-OUTCOME ☑ check still
  forgeable four ways — undated/cross-stage/substring/fenced) **+ 2
  majors (GIT_CURL_VERBOSE raw-credential leak through the
  then-inline main push; partial-override test runs polluting the
  production checkout) vs Architect + Steward
  PROCEED-WITH-FINDINGS → iteration cap reached, NO CONSENSUS —
  escalated to the project owner.** All findings from both
  iterations remediated and machine-covered in the remediation
  commit carrying the closed record (backup v6: pattern-matched
  trace/config env scrub, all-or-none overrides +
  production-checkout refusal, host-suffix github denial, guarded
  main push, union key-scrub, manifest-note normalization;
  declaration-bound gate-record authority — Stage: lines,
  last-line closure, fence-stripping; +4 machine tests, 727+9
  local). **A fresh gate (G1-iter5) on the remediation commit is
  the owner's call.**
  - Desktop: dynamic-color seed (brand / system accent / custom hex),
    OS accent detection (GNOME 47 accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation,
    settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+, DataStore toggle
  - Agent harness + event-driven backups (v6 remediated) + adversarial
    process

## Near term

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
  attack surface before reviewing it)**; also decide whether to port
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

# Roadmap (consensus-gated)

Every stage below requires an adversarial consensus gate BEFORE work
starts (see `process/adversarial-consensus.md`) and another covering
its results before the NEXT stage proceeds. Status legend:
☐ queued · ◐ gated/in-progress · ☑ done+gated.

## Shipped (gated retroactively 2026-11-13 — G1, see consensus-log)

- ☑ v0.6.0–v0.6.2 line: interop hardening, perf/stability pass,
  region-grouped servers, guest-mode fixes, uBO-parity blocklists
- ☑ Link bonding across desktop platforms (bond/balance, failover,
  self-host server) + E2E desktop test matrix + shutdown fixes

## In gate (outcome pending — no pre-recording)

- ◐ **S1. Material You across all OSes + agent harness + event-driven
  backups** — G1 iter-1 BLOCK (PAT near-miss) → iter-2 cap reached
  (BLOCK×2 proven by execution) → owner ordered fresh gate G1-iter3 on
  `74bea1e`: iteration 1 returned Red Team BLOCK (canary/scan gaps,
  proven by execution) + 2× PWF → fix cycle applied (backup v4,
  restyle repaint, harness integrity tests) → iteration 2 pending on
  the fix commit. Final state will be recorded ONLY from that gate's
  verdicts (see consensus-log/2026-11-13-S1-material-you-gate-iter3.md).
  - Desktop: dynamic-color seed (brand / system accent / custom hex),
    OS accent detection (GNOME 47 accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation,
    settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+, DataStore toggle
  - Agent harness + event-driven backups (v4) + adversarial process

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
  attack surface before reviewing it)**
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

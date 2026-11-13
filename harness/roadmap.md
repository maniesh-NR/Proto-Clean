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
- ☑ **S1. Material You across all OSes** (2026-11-13; gate G1:
  iter-1 BLOCK → fixes → iter-2 BLOCK x2/PWF x1 → blockers' specified
  resolutions applied + end-to-end verification; iteration cap
  reached, outcome escalated to the owner — see consensus-log)
  - Desktop: dynamic-color seed (brand / system accent / custom hex),
    OS accent detection (GNOME 47 accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation,
    settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+, DataStore toggle
  - Agent harness + event-driven backups (v3) + adversarial process

## Near term

- ◐ **S2. Release v0.6.3** — ship Material You + bonding fixes
  (runbook: `memory/03-release-runbook.md`). Scope now includes
  (folded in from old S3 per G1):
  - SHA-256 checksums of every asset in the release body
  - seed-corpus WCAG contrast property test (≥ 4.5 on the fixed tone
    pairs across ~200 seeds) gating the tag
  - clear deferred findings #1–#4 (Android dynamicColor QA,
    accessor allow-list test, accent-probe caching, Flatpak dconf)
- ☐ **S3. Bond server packaging + docs** — one-command self-host
  (docker image or static binary), token guidance
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
  pays the compat tax until decided)

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

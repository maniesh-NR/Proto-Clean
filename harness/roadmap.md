# Roadmap (consensus-gated)

Every stage below requires an adversarial consensus gate BEFORE work
starts (see `process/adversarial-consensus.md`) and another covering
its results before the NEXT stage proceeds. Status legend:
☐ queued · ◐ gated/in-progress · ☑ done+gated.

## Shipped (retrospective gate 2026-11-13, see consensus-log)

- ☑ v0.6.0–v0.6.2 line: interop hardening, perf/stability pass,
  region-grouped servers, guest-mode fixes, uBO-parity blocklists
- ☑ Link bonding across desktop platforms (bond/balance, failover,
  self-host server) + E2E desktop test matrix
- ☑ Agent harness + event-driven backups + adversarial process (this)

## Near term

- ◐ **S1. Material You across all OSes** (2026-11-13)
  - Desktop: dynamic-color seed setting (brand / system accent /
    custom hex), OS accent detection (GNOME accent-color, Windows DWM
    AccentColor, macOS AppleHighlightColor), full-scheme re-derivation
    (QSS + QPalette + state colors), settings UI + persistence
  - Android: `dynamicColorScheme()` on 12+ with Proto palette
    fallback, DataStore toggle
  - Gate: adversarial consensus on the implementation + tests
- ☐ **S2. Release v0.6.3** — ship Material You + bonding fixes
  (runbook: `memory/03-release-runbook.md`)
- ☐ **S3. Release-body checksums** — SHA-256 of every asset in the
  release notes (single workflow change + body template)

## Mid term (each gets its own gate before starting)

- ☐ **S4. Bond server packaging + docs** — one-command self-host
  (docker image or static binary), token guidance
- ☐ **S5. Split-tunneling parity on Android** (per-app exclusions
  exist; verify site/IP rules parity with desktop)
- ☐ **S6. Accessibility pass** — contrast verification of generated
    MD3 schemes (tonal pairs), keyboard nav, screen-reader labels

## Long term / candidates

- ☐ WireGuard native kernel module support on Linux (performance)
- ☐ Multi-hop chaining (Proton Secure Core behaviour)
- ☐ Auto-updater story for desktop packages
- ☐ Localization (i18n) infrastructure

## Parking lot (explicitly deferred, with reasons)

- Copilot PR review automation — instructions staged, but no PRs to
  review yet; revisit when a PR arrives.
- Play Protect/Play Store listing — outside repo scope for now.

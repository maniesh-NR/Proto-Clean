# Deferred findings ledger

Findings accepted-but-not-fixed at a gate. Every entry MUST be
re-examined at the next gate; entries carrying a "gate before" MUST be
cleared before that gate passes.

| # | Finding (source gate) | Deferred action | Gate before |
|---|---|---|---|
| 1 | Android `dynamicColor` DataStore key has no automated test (G1-iter1, Steward M1) | Instrumented/emulator test or documented manual QA pass: toggle in Settings, force-kill, relaunch, verify persisted + honored | **v0.6.3 tag (S2)** |
| 2 | No enforcement test that runtime painters use accessors instead of md3's always-brand constants (G1-iter1, Architect M1) | Add a test allow-listing which modules may import `DARK_SCHEME`/`STATE_COLORS`/`QSS` constants | S2 |
| 3 | `apply_theme` in system mode re-probes the OS accent via subprocess on the GUI thread on every apply (worst case ~5 s freeze on a hung dconf) (G1-iter1, Architect M3) | Cache probe result + invalidate on `colorSchemeChanged`; or probe on a worker thread and re-apply via signal | S2 (perf item) |
| 4 | Flatpak build grants no dconf access → "Follow my system accent" silently no-ops inside the Flatpak sandbox (G1-iter1, Architect M3) | Verify + fix finish-args (`--talk-name=ca.desrt.dconf` or settings portal) or document the limitation in the settings UI | S2 |
| 5 | Desktop OS-accent detection covers GNOME 47+/Windows/macOS only; KDE/XFCE fall back to brand silently (G1-iter1, Architect M3) | KDE `kdeglobals` accent parse or an explicit "not detected" hint in the settings dialog | S6 (accessibility/UX pass) |
| 6 | Auto-updater deferral (roadmap parking lot) — stale VPN clients are a security liability, not just inconvenience (G1-iter1, Architect m6) | Acknowledge risk explicitly in the parking-lot entry; revisit after S7 | — (standing) |

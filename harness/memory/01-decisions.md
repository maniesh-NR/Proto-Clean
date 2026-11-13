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
    as fallback. Preserves brand identity by default, Material You
    where the user asks for it. (2026-11-13)

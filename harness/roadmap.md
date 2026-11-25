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
- ☑ **S1. Material You across all OSes** — desktop dynamic-color seed
  (brand / system accent / custom hex), OS accent detection (GNOME 47
  accent-color, Windows DWM AccentColor, macOS AppleHighlightColor),
  full-scheme re-derivation, settings UI + persistence; Android
  `dynamicColorScheme()` on 12+ with a DataStore toggle (defaults:
  brand green desktop, wallpaper dynamic color Android 12+ — decision
  #10). The deliverable shipped green in the first gate iteration and
  stayed green through every re-verification since — the six G1-line
  cap-exhaustions were all decided by backup/harness-subsystem
  findings, split to S8 per decision #19; the deliverable itself never
  drew a finding. CLOSED by the S1-closing gate (2026-11-25, CONSENSUS
  REACHED — Red Team / Devil's Architect / Ship Steward all
  PROCEED-WITH-FINDINGS, zero criticals; record:
  `memory/consensus-log/2026-11-25-S1-closing-gate.md`; scope per
  decision #21 — deliverable closure + split boundary correctness +
  disposition recording, NOT harness re-judgment; ordered first per
  decision #22). Deliverable residuals ledgered: #1–#4 + #7 → S2
  (v0.6.3 tag), #5 → S5, #13–#16 → S2/S5. Title narrowed and the
  harness sub-bullet removed at this flip per deferred #11.
  Sequencing from here (decision #22, full chain per #18/#19):
  S8-PG1-iter3 (fresh pre-gate) → S8's port + its own gate → S2.

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
  disposition RECORDED (2026-11-25, decision #22 — the owner
  instructed "D1:a, d2:a"): a fresh gate S8-PG1-iter3 (its OWN
  2-iteration cap) is ordered on the closing-remediation line
  `865580e`+, re-judging the two STAGE-1 deliverables as amended;
  it ran after the S1-closing gate (D2:a — S1 closed 2026-11-25,
  CONSENSUS REACHED, record
  `memory/consensus-log/2026-11-25-S1-closing-gate.md`).
  **S8-PG1-iter3 iteration 1 (2026-11-25, on `2ccb4fb`; deliverables
  unchanged since `865580e`): NO CONSENSUS — Red Team BLOCK (2
  criticals: the 3a module-lookup gap — E4/E18's mutated script
  copies cannot resolve the module under any CI-compatible,
  identity-correct lookup, falsifying the "survive unedited +
  exhaustive" pair; the later-materialized-alias coverage overclaim
  — executed E2E falsification landing the checkpoint in a
  stand-in production .git with all guards green) + 1 major (the
  coverage-table post-3b off-by-one: v6 22→23, total 122 — found
  independently by ALL THREE roles) vs Architect PWF (2 majors —
  the same two findings at major severity; 6 minors) and Steward
  PWF (the same off-by-one major + 1 minor). All three roles
  confirmed the S8-PG1 iteration-2 criticals (C-A/C-B/C-C) resolved
  in substance — the new BLOCKs are narrower boundary defects of
  the same class. Remediation LANDED with the record's
  resolution list (documents only): RT-C1 — the 3a module-lookup
  rule pinned $0-relative with module-copy steps at the four
  mutated-copy probe sites (E4 ×2, E18 ×2) + the stale-citation
  edit ledgered (RT-m2); RT-C2/Arch-M2 — the later-materialized-
  alias claim corrected in BOTH documents to the honest
  not-covered form, recorded as the FILESYSTEM face of frozen
  residual item 3 (README amended by gate finding), closed at the
  port by the push helpers' push-time re-canonicalization (a
  STAGE 4b commitment); the coverage table corrected to 122 after
  3b (v6 23, lane map) — RT-M1/Arch-M1/Steward-M1; the 3b list
  gains the matrix twins (RT-m1) + the `_git` rewiring (Arch-m2);
  the neutralization-hook pass-through (Arch-m1); E34's twin to
  3c (Arch-m3); STAGE-2 supersession (Arch-m4); v9 E26 wording
  (Arch-m5); the STAGE-5 retirement radius (Arch-m6); the 3c
  `_alarms` surface wording (Steward-m1). **Iteration 2
  (on the remediation `7c3bd4b`): RT BLOCK + Architect BLOCK on
  the same executed critical (the copy-both module-lookup shape
  re-homes the location-derived identity onto the lane area —
  guard refuses the lanes' own operands, rc 6 ≠ 5/4; three
  one-clause escape shapes identified) + i2 majors (the
  two-headed invocation spelling; the STAGE-4b commitment
  prose-only) vs Steward PROCEED (the coverage table derives
  exactly; the delivery contract holds) — RT-i1-C2, the coverage
  122, and all nine i1 minors CONFIRMED RESOLVED. **THE FRESH
  GATE CLOSED AT ITS 2-ITERATION CAP — NO CONSENSUS, ESCALATED
  TO THE OWNER** per decision #22's tail clause; the closing
  remediation landed with the record (documents only): the four
  sites re-ledgered as PROBE-DIR RELOCATIONS with the honest
  proof-scope statement, the seam-protocol invocation re-spelled
  $0-relative, STAGE 4b gains the push-time re-canonicalization
  deliverable + a LEDGERED planted-alias lane, the `_alarms`
  magnitude corrected, the 3b sentence scoped. TWO consecutive
  cap-exhaustions on the same pre-gate → the owner-side
  escalation rule's SPLIT DEFAULT now applies: options re-tabled
  — (a) further split (land the converged spec fixes and start
  the port, where the parity-oracle question becomes an executed
  green/red fact per stage boundary, judged by the STAGE-6
  closing gate), (b) another fresh gate (must be justified
  against the split default — eight total cap-exhaustions
  across S1 + the S8 pre-gates), (c) owner-descoped S8→S2
  ordering. No disposition pre-recorded. Record:
  `memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`.**
  Predecessor record:
  `memory/consensus-log/2026-11-19-s8-pre-gate.md`.**
- ☐ **S2. Release v0.6.3** — ship Material You + bonding fixes
  (runbook: `memory/03-release-runbook.md`; **adversarial pre-gate
  required before work starts — none has run yet**). Scope (folded in
  from old S3 per G1):
  Release-watch (S1-closing gate, Steward minor #1, 2026-11-25): the
  macOS-latest 3.12 CI leg flaked once on the documents-only `eb459b1`
  (run 44536786320, sole failing leg; recovered on the next push) —
  watch that leg at the v0.6.3 tag.
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

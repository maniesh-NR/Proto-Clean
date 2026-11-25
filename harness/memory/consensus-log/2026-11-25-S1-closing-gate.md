# Consensus Gate — S1 closing gate (scoped closure per decisions #21/#22)

Stage: S1

Date: 2026-11-25 · Gate ID: S1CG (the S1-closing gate scheduled by
decision #21, ordered to run FIRST by decision #22; scope FIXED per
decision #21: S1's deliverable closure + the split's boundary
correctness + the dispositions' recording — NOT a re-judgment of the
harness findings, which S8's own gate owns. This gate has its own
cap of 2; it closed at iteration 1.)
Reviewed commit (pinned): `5bf91ad2cb03daec22dd5df4039f928552243221`
== origin/main (the disposition commit; the deliverable code is
unchanged since `7a13645` — everything after it is documents-only).
Predecessors: the seven G1-line records
(`2026-11-13-S1-material-you-gate.md` …
`2026-11-19-S1-material-you-gate-iter6.md`), the S8-PG1 record
(`2026-11-19-s8-pre-gate.md`), decisions #19–#22.
Date constraint verified: 2026-11-25 > 2026-11-19 (the iter6-i2
record, NO CONSENSUS, declares S1 — the tie rule is satisfied; a
same-date close would have been withdrawn).

## Launch and verification (orchestrator)

Three roles launched in parallel as independent agents, no shared
context, no visibility into each other's verdicts before publishing.
All three pinned `5bf91ad` and reported the working tree clean
except the known PROJECT_MEMORY.md post-commit-hook refresh
artifact (diff inspected by two roles: git-activity log rotation
only). Verification executed by the roles themselves (all
TEST-mode, scratch-only, zero production contact, no repo file
modified, no incident):

- Integrity suite: 16 passed — all three roles ran it independently
  (10.55 s / 11.03 s / 12.10 s reported).
- Full suite: **728 passed + 9 skipped, 0 failed** — all three roles
  ran it independently (97.10 s / 99.07 s / 95.91 s) — exact
  baseline match.
- Deliverable subset (test_material_you + test_md3 + test_theme +
  test_platforms): 62 passed, 9 skipped (the 9 = Qt-binding-absent
  environment skips; CI legs with Qt run them — 728+9=737
  consistent).
- Matrices: the Ship Steward ran ALL SIX in full from the repo root
  — v5 20/0, v6 22/0, v7 25/0, v8 19/0, v9 26/0 (0 skipped),
  v10 9/0 = **121 checks, 0 failed** (the standing contract holds).
- CI (public REST API, unauthenticated, no credentials
  reproduced): run 44462797163 on `7a13645` re-confirmed 7/7 jobs
  success; the documents-only line — `89b1d70` (run 44511555252,
  success), `82fb63c` (44515584641, success), `f422afe`
  (44536374810, success), `eb459b1` (44536786320, **failure —
  macOS-latest 3.12 leg only**, see Steward minor #1),
  `865580e` (44542518059, success) — and **the line under
  judgment `5bf91ad` (run 45551538029, completed, conclusion
  success, 7/7 jobs success via the jobs endpoint)**.
- Red Team executed scratch batteries (all in /tmp clones, HOME
  isolated): 8,720 scheme builds over the full 12-bit seed corpus
  + NaN/inf/±1e300 hostile HCT inputs (0 failures); 296 poisoned
  settings round-trip combos (2 failures = RT major #1); 30
  hostile/hung/jumbo OS-accent probe cases (no crash, worst-case
  ~7 s GUI-thread freeze on macOS/Windows — folded into ledger #3);
  a five-class close-forgery battery (D0–D5: pristine pass;
  legitimate 2026-11-25 close simulation passes 16/16; same-date
  2026-11-19 close REJECTED by the tie rule; unbacked glyph flip
  REJECTED; mid-record closure line REJECTED; wrong-stage
  declaration REJECTED). The closure machinery accepts only the
  legitimate post-2026-11-19 close.
- Record census: no consensus-log record dated 2026-11-20..24; no
  doc anywhere pre-asserts this gate's outcome (greps by all three
  roles; the latest S1-declaring record before this one is the
  2026-11-19 iter6-i2 record).

## Roles (independent, parallel, no shared context)

| Task | Role | Verdict | Method |
|---|---|---|---|
| S1CG-R | Red Team | **PROCEED-WITH-FINDINGS** | deliverable attack batteries (8,720 scheme builds, 296 poisoned round-trips, 30 probe cases) + close-forgery battery D0–D5 + split/ledger audit |
| S1CG-A | Devil's Architect | PROCEED-WITH-FINDINGS | full deliverable design review (md3/theme/settings/platforms/Android) + split-boundary + post-close roadmap audit |
| S1CG-S | Ship Steward | PROCEED-WITH-FINDINGS | baseline exact (728+9) + all six matrices 121/0 + CI via public API incl. the line's run + docs-accuracy + release-handoff audit |

**Consensus: REACHED — all three roles independently returned
PROCEED-WITH-FINDINGS (zero BLOCKs, zero criticals). Findings are
addressed below (fix in this commit, or defer with an explicit
ledger row).**

## Verdicts (verbatim from the agents' verdict blocks)

### Red Team — PROCEED-WITH-FINDINGS

CRITICAL: none

MAJOR:
1. **`load_settings()` crashes on a valid-JSON/wrong-top-type
   settings.json — uncaught `AttributeError` at app startup.**
   Executed in the /tmp scratch clone (battery B): a settings file
   whose top-level JSON is `[]` or `null` (valid JSON, not a decode
   error) escapes the `except (json.JSONDecodeError, OSError)` at
   `proto_clean/settings.py:500-503`, then `raw.get(...)` at
   `proto_clean/settings.py:504-513` raises `AttributeError`
   ('list'/'NoneType' object has no attribute 'get'). The exception
   propagates unhandled through `apply_saved_theme`
   (`proto_clean/ui/theme.py:299-303` →
   `proto_clean/__main__.py:86`, bare call at startup) → the app
   fails to launch until the config file is manually removed.
   Round-trip battery: 296 poisoned combos (29 hostile accent
   values × 11 hostile accent_source values + 6 file shapes) —
   every dict-shaped poisoned file loads/saves/loads green
   (normalization at `settings.py:512` and `:604` held); only the
   wrong-top-type class crashes. No test covers it
   (`tests/test_settings.py:155`
   `test_corrupt_file_falls_back_to_defaults` covers decode-error
   text only). Mitigating: the loader shape predates S1 (blamed to
   `80cff25`, 2026-11-01, pre-Material-You), so this is a
   pre-existing persistence-layer robustness defect the six gates
   missed, not a Material You regression; the seed round-trip claim
   itself is green. Disposition: one-line guard (`isinstance(raw,
   dict)` or broaden the except) in the closing cycle, or an
   explicit ledger row to S2 (settings/release hardening already
   owns #1–#4+#7).

MINOR:
1. **`md3._hex_to_rgb` hostile-input classes (executed, NOT
   production-reachable).** Direct calls in the scratch clone:
   `" #2f6d3f"` (whitespace before `#`) raises `ValueError`
   (`lstrip("#")` at `proto_clean/ui/md3.py:256` runs before
   `.strip()`, leaving the `#` in the parse); `"0x2f6d3f"`, `""`,
   `"#"`, `"rgb(1,2,3)"`, `"#2f6dzz"` raise; `"#2f 6d3f"` silently
   misparses to `(47, 6, 211)`; `"#-2f6d3f"` parses a negative
   channel. Every production entry point normalizes first (traced
   and verified: `set_accent` `theme.py:266`, `apply_theme`
   `theme.py:333`, `save_settings` `settings.py:604`,
   `load_settings` `settings.py:512`; OS accent probes emit only
   well-formed hex from fixed maps/format strings), so this is a
   latent defense-in-depth gap for future callers of the public
   `scheme_from_seed`/`md3_qss` bypassing `normalize_hex_color` —
   not a live defect.
2. **`_windows_accent_color` aborts its fallback chain on a
   hostile registry token.** Executed with a fake `reg.exe`: an
   `AccentColor` token like `0xZZZZZZZZ` raises `ValueError` inside
   the token loop (`proto_clean/ui/theme.py:189-193`), skipping the
   `ColorizationColor` fallback iteration; the
   `system_accent_color` wrapper (`theme.py:162-169`) swallows it →
   `None` → brand seed. Cosmetic fallback loss only; contrived
   (poisoned registry) — record as a note for a future hardening
   pass, not a gate item.

EXECUTED (summary): HEAD = `5bf91ad`; deliverable subset 62
passed/9 skipped; integrity 16 (12.10 s); full suite 728+9 (97.10
s); battery A 8,720 scheme builds + hostile HCT inputs → 0
failures (NaN/inf paths safe by execution, untested in the
committed suite — coverage gap only); battery B 296 combos → 2
failures (the MAJOR); battery C 30 probe cases → no crash, hangs
time-boxed ≤2.0 s per call; battery D close-forgery D0–D5 → the
machinery rejects every forgery class and accepts only the
legitimate post-2026-11-19 close; record census + pre-recording
greps → clean.

NOTES (Red Team): disposition recording verified clean across all
docs (decisions #21/#22 verbatim "D1:a, d2:a", sequencing, pin
line, date constraint); split boundary coherent (ledger #1–#4+#7→S2,
#5→S5, #6→standing, #8→S6, #9/#10/#12→S8, #11→this commit; no S1
deliverable residual misassigned); closing-commit obligations: (a)
#11 title narrowing is human-audited only — the machine check tests
glyph/id/backing, not title text — so the "Agent harness +
event-driven backups …" S1 sub-bullet must be dropped/reworded AT
the flip (DONE in this commit); (b) ledger row for the MAJOR (DONE:
#13); (c) ledger #3 magnitude update (DONE: worst-case ~7 s
macOS/Windows measured vs the recorded ~5 s); Android judged
statically only (cannot run — stated): Theme.kt dynamicColorScheme
on 12+ w/ Proto fallback, DataStore `dynamic_color` default true,
MainActivity collectAsState safe default — coherent with decision
#10, ledger #1 unchanged; S8-bound observations: none (backup
internals not attacked per scope; forgery suite all green).

### Devil's Architect — PROCEED-WITH-FINDINGS

CRITICAL: none. MAJOR: none.

MINOR:
1. **Ledger #11's narrowing action is incomplete — the roadmap S1
   row's third sub-bullet would survive a title-only flip.**
   Deferred #11 and every choreography doc mandate only the title
   narrowing: `roadmap.md:17–18` narrows, but `roadmap.md:88–89`
   still lists "Agent harness + event-driven backups (v6
   remediated) + adversarial process" as a sub-bullet of the S1
   row. A ☑ S1 row still carrying the harness bullet claims the
   harness subsystem closed with the deliverable — the exact
   mis-claim #11 exists to prevent; the machine check enforces
   glyph↔record, not row content. Remedy: extend #11's action (or
   the closing record's resolution list) to rehome/drop the harness
   sub-bullet in the SAME commit as the flip.
2. **The D2 sequence as recorded elides S8's own port execution
   and results-gate.** Decision #22, 00-project-state.md and
   roadmap.md all compress the order to "S1-closing gate →
   S8-PG1-iter3 → S2", while decisions #18/#19, roadmap.md:108-109
   ("Its own gate before S2's stage gate") and ledger #9 place the
   S8 port plus its own gate BEFORE S2's stage gate. A reader of
   the disposition alone could sequence S2 directly after the
   fresh pre-gate. Record the full chain (or a parenthetical "S8's
   port+gate ride between, per #18/#19") wherever D2 is restated.
3. **Dead QSS declaration in the generated `QLabel#Plan` block** —
   `proto_clean/ui/md3.py:669–677` emits `color: on_surface_variant`
   (line 671) and then `color: on_secondary_container` (line 673) in
   the same rule; only the last wins under the QSS cascade, so line
   671 is dead and a future-edit trap.
4. **Stale comment misdescribes the state-color tuple** —
   `proto_clean/ui/theme.py:433–434` says "State → (dot color, text
   color, label)" but the value is the 2-tuple (color, label)
   (md3.py:871–878; consumers use `[0]`/`[1]`, e.g. theme.py:313,
   main_window.py:490).

EXECUTED (summary): HEAD = `5bf91ad`; deliverable implementation
read in full (md3.py 897 lines, theme.py, qtcompat.py, settings.py
persistence, main_window/settings_dialog wiring, Android Theme.kt +
Settings.kt); deliverable subset 62/9; integrity 16; full suite
728+9 (95.91 s); dispositions cross-checked (decisions #19–#22 vs
roadmap rows vs ledger #1–#12 vs both disposition session logs vs
the s8-pre-gate record's tabled options — options (a)/(b)/(c) match
decision #22 verbatim); pre-recording greps clean.

NOTES (Devil's Architect): design concurrence — md3.py is
Qt-free-at-import with the headless test architecture built on it;
single scheme builder; brand seed single-sourced (md3.py:461–466);
seed ownership cleanly split (md3 owns the value, settings owns
persistence, theme owns resolution); compat layer degrades safely
(Qt≥6.5 colorSchemeChanged via getattr; legacy legs resolve at
apply-time — matching deferred #3's specified legacy-leg
semantics); every residual hunted is already ledgered with a hard
deadline (raw-hex painters still present in resources.py —
confirming S2's tag-gated test is genuinely needed); nothing must
precede the close because the close changes no code. Split boundary
coherent; the closing gate's own scope leaves nothing S1-essential
unjudged. Post-close roadmap: the S2-release dependency on
S8-PG1-iter3 convergence is a known, bounded, owner-decided risk
(contingency option-c properly recorded in decision #22); S3/S6/
S5/S7 dependencies acyclic and consistent; cosmetic note: the OS
accent probes live in ui/theme.py rather than platforms/ —
acceptable cohesion today; consider promoting to its own module
when S2's #3-caching and S5's #5 work grow that layer.

### Ship Steward — PROCEED-WITH-FINDINGS

CRITICAL: none. MAJOR: none.

MINOR:
1. CI run 44536786320 on documents-only commit `eb459b1` (full SHA
   eb459b184ce70208cd0f6737e4ecc0bc8672c3c6) concluded **failure**:
   sole failing leg "Test (macos-latest, Python 3.12)" (job id
   135604208151, 13:46:32Z→13:49:37Z); other 6/7 legs green. Not
   delivery-blocking: it is not the line under judgment (`5bf91ad`
   is green 7/7); the diff was documents-only (6 .md files); the
   same macOS leg is green on the immediately succeeding run
   44542518059 (`865580e`) and on the line's run 45551538029; and
   no repo doc asserts this run's color (the commit only claims
   "integrity 16 passed", reproduced locally), so nothing
   falsifies the close record. Root cause indeterminate via the
   public API (job-log download returned 403). Recorded as a fact:
   if a macOS-leg flake recurs it is an S2 release-watch item
   (v0.6.3 tag) and an observation for the S8-PG1-iter3 gate's
   steward.

EXECUTED (summary): HEAD = `5bf91ad`; env re-provisioned after a
sandbox recycle (pip install -r requirements.txt; no repo file
modified); full suite **728 passed, 9 skipped, 0 failed, 99.07 s**
(122 warnings, all pyOpenSSL/cryptography deprecation families) —
baseline EXACT; integrity 16 (11.03 s); all six matrices 20/22/25/
19/26/9 = **121/0**; CI via public API: 44462797163 on `7a13645`
7/7 success re-confirmed; documents-only line runs verified
(89b1d70 success, 82fb63c success, f422afe success, eb459b1
FAILURE-macOS-leg-only, 865580e success) and **the line's run
45551538029 on `5bf91ad` completed 7/7 jobs success**; docs read in
full + greps (no checksum/SHA-256 machinery in release.yml, no
WCAG contrast property test in tests/ — S2's to create).

NOTES (Ship Steward): docs accuracy — all five checks PASS: (a) the
S1 roadmap title still reads "+ agent harness + event-driven
backups" with ◐ (sole occurrence repo-wide) and the narrowing +
flip are correctly deferred to THIS commit; (b) deferred rows gated
at S2's tag are exactly #1–#4 and #7 (with #3's legacy-leg
semantics + third restyle path); (c) no doc pre-asserts this gate's
outcome; (d) the S2 pre-gate is correctly REQUIRED-but-not-yet-run;
(e) the execution order agrees across PROJECT_MEMORY, project
state, and roadmap; nothing found that would falsify a close record
written after this gate. Release-readiness handoff: runbook current
(5 sections; version-bump checklist 8 places; 12/12 release jobs,
13 assets); S2 must still create the SHA-256 checksums (workflow
publish job + release body) and the WCAG ≥ 4.5 contrast property
test gating the tag. S8-bound observations: all six matrices green
from the fixed tree — the standing 121-check contract holds; matrix
design is S8-owned, no design finding raised. Safety: checkout
untouched; no push/fetch/pull/config; zero production contact; no
remote URL reproduced.

## Findings and resolutions

All findings are addressed in this commit (fix) or deferred with an
explicit ledger row; none blocks the close.

1. **RT-M1 (settings loader wrong-top-type crash)** — DEFERRED
   with ledger row **#13** (S2, v0.6.3 tag): the defect is
   pre-S1 shared persistence-layer code (blamed to `80cff25`,
   2026-11-01, pre-Material-You — git-verified by the role), not a
   Material You regression; the S1 deliverable claim ("green
   through six gates, zero Material You deliverable findings")
   remains accurate. Fix shape recorded in the row: `isinstance(raw,
   dict)` guard or broadened except + regression test.
2. **RT-m1 (md3._hex_to_rgb hostile inputs, not
   production-reachable)** — DEFERRED with ledger row **#14**
   (S2, bundled with the #2/#7 accessor/hex hardening).
3. **RT-m2 (Windows accent fallback-chain abort on a hostile
   registry token)** — DEFERRED with ledger row **#15** (S5,
   accent-detection UX family with #5).
4. **RT-note / Arch-m1 (the S1 row's harness sub-bullet would
   survive a title-only flip)** — FIXED in this commit: the S1 row
   moves to Shipped as ☑ with the narrowed title "Material You
   across all OSes" AND the "Agent harness + event-driven backups +
   adversarial process" sub-bullet REMOVED (that subject is the S8
   row's, where it already lives). Ledger #11 row marked RESOLVED.
5. **Arch-m2 (D2 restatements elide S8's port + its own gate)** —
   FIXED in this commit: every D2 restatement (roadmap close note,
   project state, PROJECT_MEMORY playbook) now reads "S1-closing
   gate → S8-PG1-iter3 → S8's port + its own gate → S2" per
   decisions #18/#19 (roadmap.md's "Its own gate before S2's stage
   gate" was already correct).
6. **Arch-m3 (dead QSS `color:` declaration, md3.py:671)** and
   **Arch-m4 (stale state-color tuple comment, theme.py:433)** —
   DEFERRED with ledger row **#16** (S2 cosmetic code nits; the
   closing commit stays documents-only).
7. **Steward-m1 (eb459b1 macOS-leg CI failure, run 44536786320)** —
   ACCEPTED with reason: not the line under judgment (`5bf91ad` is
   green 7/7 via run 45551538029), documents-only diff, recovered
   on the immediately succeeding run, no doc asserts its color.
   Carried: an S2 release-watch note lands in the roadmap S2 row
   (macOS-leg flake watch at the v0.6.3 tag), and this fact is
   tabled to the S8-PG1-iter3 gate's steward.
8. **RT coverage observations** — recorded, no row needed: the
   NaN/inf HCT paths are safe by execution but untested in the
   committed suite (coverage gap; RT battery A results carried
   above), and ledger #3's magnitude is amended in this commit
   (worst-case GUI-thread freeze ~7 s on macOS/Windows, measured,
   vs the recorded ~5 s; Linux 3+2 s confirmed).

## Closure

S1 closes on its deliverable. The six G1-line cap-exhaustions were
all decided by backup/harness-subsystem findings now owned by S8's
own gate (decision #19/#21); the deliverable itself shipped green
in the first gate iteration and stayed green through this gate's
independent re-verification (zero deliverable criticals/majors
attributable to Material You code). Deliverable residuals are
ledgered: #1–#4 + #7 → S2 (v0.6.3 tag), #5 → S5, #13–#16 → S2/S5;
harness findings → S8. The glyph flip ◐→☑ + the title narrowing
(deferred #11) + the harness-sub-bullet removal land in THIS commit
per the closure choreography. Sequencing per decision #22: S8-PG1-
iter3 (fresh pre-gate, own 2-iteration cap) runs next, then S8's
port with its own gate before S2's stage gate, then S2.

FINAL OUTCOME: CONSENSUS REACHED

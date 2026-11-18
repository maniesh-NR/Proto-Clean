# Session 2026-11-19 — G1-iter5 iteration 2 + closure at the cap + v8 fix cycle

## Context on entry

Continuation of the G1-iter5 gate (iteration 1 + v7 fix cycle landed
at `1f3d1cf`, seq-10 incident disclosed at `517ad3f`; CI confirmed
737 × 4 POSIX / 605+132 windows on `1f3d1cf`; backups through seq 12,
failcount 0).

## What happened

- **Iteration 2 launched** — with an orchestration slip: the
  orchestrator launched Red Team and Ship Steward first and the
  Devil's Architect only after the first two returned (the mandate is
  three parallel launches). Independence held (the Architect saw
  neither verdict; no shared context), and the slip is disclosed in
  the gate record — the audit trail does not selectively omit
  orchestrator errors.
- **Verdicts: Red Team BLOCK** (2 criticals — RELATIVE push targets
  bypass the physical production-path compare: the guard judges at
  the repo's cwd while the push executes from the temporary worktree,
  executed E2E against a patched decoy AND with real constants via a
  logging git shim; the empty-AUTHORITY family `https:///github.com/…`
  reached github through v7's `//`-collapse, executed via a
  local 502-proxy with CONNECT github.com:443 observed. 1 major —
  double-`@` ssh spellings pass the guard (handoff executed, socket
  hop modeled). 5 minors incl. the phantom pushInsteadOf residual,
  Shipped-prefix smuggling, future-date shielding); **Devil's
  Architect BLOCK** (the SAME relative-base defect, found and
  executed E2E independently with patched constants — convergent with
  RT-C1; the pushurl half of the resolution claim mutation-false;
  4 minors incl. the fail-open empty-resolution wrapper and the
  one-directional residual-list freeze); **Ship Steward
  PROCEED-WITH-FINDINGS** (15/15 claim map ZERO mismatches, all four
  v7 mutation claims independently re-proven, CI exact on both
  commits, audit trail faithful through seq 12, incident handling
  verified complete; 2 doc minors).
- **NO CONSENSUS at the 2-iteration cap — G1-iter5 CLOSED, escalated
  to the project owner** (the G1-iter3/G1-iter4 precedent: all
  findings from both iterations remediated in the closing commit that
  carries the record).
- **v8 fix cycle** (every iteration-2 finding): relative push targets
  refused outright in TEST mode + fail-closed unresolvable targets;
  `_norm_url` leading-slash strip (empty-authority family) + a sed
  LOOP for the multi-@ userinfo family; the pushurl-divergent machine
  lane (mutation-verified); Shipped-signature requirement +
  fence-stripped ◐ mentions in the glyph check; the residual list
  corrected (pushInsteadOf phantom → verified non-residual, kept
  marked; resolution/use TOCTOU added; two-directional freeze);
  ledger row #10 (glyph-check date semantics, filed); docs per the
  checklist (project state, lessons baseline, README).
- **Verification:** suite 728 passed + 9 skipped (16 integrity tests,
  count unchanged — new coverage extended existing tests); mutation
  probes A-E in scratch clones (the relative-target probe patched
  BOTH the guarded constant and the test's production-path lane per
  the seq-10 rule — zero production contact) — all five caught;
  matrices: v8 19/19 (new: E19 spellings, E20 relative refusal + the
  stand-in mechanism demo, E21 pushurl divergence, E22 fail-closed),
  v7 25/25, v6 22/22, v5 20/20 — 86 checks total.

## Owner escalation (the pending decision)

G1-iter5 exhausted its cap without consensus — twice, on convergent
adversarial findings. The options per the escalation precedent:
(a) order a fresh gate (G1-iter6) on this closing commit; (b) accept
the remediated state under the Architect's bounded-exit framing
(decision #18 already freezes the bash surface and schedules the
Python port before S2's stage gate); (c) another option the owner
chooses. No outcome pre-recorded anywhere; the record at
`memory/consensus-log/2026-11-19-S1-material-you-gate-iter5.md`
carries both iterations verbatim.

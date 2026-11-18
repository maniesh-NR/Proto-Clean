# Session 2026-11-19 — G1-iter5: owner-ordered fresh gate, iteration 1 + v7 fix cycle

## Context on entry

Session opened from the standing continuation directive. The sandbox
had been recycled and — as on 2026-11-16 — overlaid a stale-era tree
snapshot (the proton-clean/cleanroom rename era: 47 modified tracked
files reverted to 0.1.0-era content + 19 untracked old-name trees) on
top of the clean `a02db67` checkout. Diagnosed via the 2026-11-16
session log's precedent (identical signature), restored with
`git checkout -- . && git clean -fd` (harness/ untouched — fully
tracked; the overlay never reached the gate records).

## What happened

- Environment restored (`pip install -q -e . pytest`); tree clean at
  `a02db67` == origin/main; local suite **727 passed + 9 skipped**
  exact; CI 7/7 success on both `c00f647` and `a02db67` (check-runs
  API); backup manifest seq 9 faithful at `a02db67`, failcount 0.
- **G1-iter5 ordered and opened** (the escalated owner decision from
  G1-iter4's cap — the G1 → G1-iter3 → G1-iter4 precedent; per the
  standing directive to continue without questions, the fresh gate on
  the remediation line is the ordered next step). Three independent
  adversarial agents launched in parallel on pinned
  `bf0c74e`→`c00f647`→`a02db67`, each with the incident-shaped safety
  rules (three-override TEST pattern only, no production intent, no
  credential echo, test from HEAD, bounded experiment budget after
  the G1-iter4-i2 first-launch timeout).
- Verdicts: **Red Team BLOCK** (2 criticals — empty-credential apex
  spellings executed end-to-end past the github guard incl. a real
  receive-pack attempt; symlink/`//` spellings past the
  production-checkout compare via logical pwd; 1 major — insteadOf
  config-file rewrites + unscrubbed `GIT_CONFIG_GLOBAL`; 3 minors —
  stale-consensus, id-less done-claims, scan→add TOCTOU proven by
  instrumented copy), **Devil's Architect BLOCK** (2 majors — the
  push TARGET never compared against the production path (header
  claim falsified E2E); the trace-scrub machine test not
  mutation-covering (whole-scrub revert leaves CI green); 4 minors
  incl. the bounded-exit design recommendation), **Ship Steward
  PROCEED-WITH-FINDINGS** (3 doc-currency minors; everything else
  exact: suite ×2, per-leg CI from job logs, 21/21 claim map clean,
  audit trail faithful).
- **No consensus — iteration 1 of 2.** Fix cycle ran immediately
  (every finding from all three roles): backup script **v7** —
  empty-credential normalization in `_norm_url`; PHYSICAL path
  compares (`pwd -P` + `//` collapse) covering the push TARGET and
  its `.git`, not just the repo; insteadOf/pushurl-aware target
  resolution (`get-url --push` / `ls-remote --get-url`);
  `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` scrub; post-add INDEX
  re-scan on both commit paths. Integrity suite → 16 tests (+
  structural index-rescan test; guard/override/forgery/mainpush
  extended in place; stale-consensus withdrawal + id-less-☑-outside-
  Shipped rules; zero-trace-lines mutation-covering lane; the tests'
  ambient-config convention moved to an empty `HOME` since the script
  now scrubs the config-file env itself). **728 passed + 9 skipped
  local.** Mutation probes in scratch clones: whole-scrub revert →
  trace lane fails; normalization revert → guard test fails; logical-
  pwd revert → symlink lanes fail; index-scan removal → structural
  test fails.
- **Matrices:** `verify_backup_v7.sh` written and green **25/25**
  (E14 spellings, E15 physical production-path compares, E16
  insteadOf + env-inert, E17 zero-trace-lines, E18 widened-window
  TOCTOU + negative control). Re-ran ALL older matrices per the new
  checklist: v6 22/22; v5 was 18/2 — **its E4 lanes had been silently
  stale since v6** (they probed the production checkout as a TEST
  repo, which v6's production-checkout refusal correctly blocks;
  nobody re-ran the old matrix for an entire gate). Fixed the E4
  lanes to use a scratch clone; v5 now 20/20. Lesson + fix-cycle
  checklist item recorded.
- **Decision #18 adopted** (the Architect's bounded-exit
  recommendation): bash capability freeze, the merge/alarm/guard
  Python port lands BEFORE S2's stage gate, frozen residual-threat
  list (backups README) bounds future gates. Ledger #9 amended.
- Docs: backups README v7 + residual list; process doc (baseline +
  doc checklist); decisions #18; lessons (5 new harness entries);
  roadmap gate history; project state; this log; the iteration-1
  gate record
  `memory/consensus-log/2026-11-19-S1-material-you-gate-iter5.md`
  (interim closure line — iteration 2 rewrites it).

## Next (iteration 2 — the gate's second and final)

- CI confirmation for this remediation commit (expectation: 737 × 4
  POSIX, 605+132 windows) BEFORE iteration-2 verdicts are recorded.
- Event backup (this commit) as the fix cycle's mandated last step.
- Launch three fresh independent agents re-judging THIS commit; no
  outcome pre-recorded anywhere. Consensus → closure choreography
  (close-out ritual in the process doc); no consensus at the cap →
  escalate to the owner with both iterations' records.

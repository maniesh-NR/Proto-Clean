#!/usr/bin/env python3
"""S8-PG1-iter3 iteration-1 remediation (documents only).

Applies the resolution list of
harness/memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md to:
  - harness/process/s8-execution-plan.md (P8-P15)
  - harness/backups/allowlist-inversion-evaluation.md (E1-E4)
  - harness/backups/README.md (R1)
Run from the repo root. Idempotent per-edit: each anchor is
asserted unique before replacement; prints the applied edit ids.
"""
from pathlib import Path

PLAN = Path("harness/process/s8-execution-plan.md")
EVAL = Path("harness/backups/allowlist-inversion-evaluation.md")
README = Path("harness/backups/README.md")


def apply(doc, edits):
    t = doc.read_text()
    done = []
    for eid, old, new in edits:
        n = t.count(old)
        if n != 1:
            raise SystemExit(f"ANCHOR FAIL {eid}: count={n}")
        t = t.replace(old, new)
        done.append(eid)
    doc.write_text(t)
    print(f"{doc}: applied {done}")


# ---------------- PLAN P8-P15 ----------------
plan_edits = []

# P8: exit-criterion item 2 — the later-materialized-alias claim (RT-C2/Arch-M2)
plan_edits.append((
    "P8",
    """   inherited); the later-materialized-alias class (a symlink
   planted at the non-existent suffix after judgment) is covered
   at push time by the retained symlinked-.git + git-dir
   containment.""",
    """   inherited); the later-materialized-alias class (a symlink
   planted at the non-existent suffix after judgment) is NOT
   covered at push time (CORRECTED at S8-PG1-iter3 — RT-C2/
   Arch-M2: the prior "covered at push time by the retained
   symlinked-.git + git-dir containment" claim was falsified by
   EXECUTED E2E — those checks are guard-time REPO-side checks;
   a planted symlink landed the full checkpoint in a stand-in
   production .git with rc 0 and zero refusal messages): the
   class is recorded as the FILESYSTEM face of frozen residual
   item 3 (README amended, by gate finding per the residual-list
   governance) — and it is CLOSED AT THE PORT (STAGE 4b): the
   guarded push helpers re-canonicalize the push target
   immediately before spawning each push (realpath of the
   operand's deepest existing ancestor AT PUSH TIME) and refuse
   exit 6 if it resolves into/under production or is a symlinked
   .git — the re-check rides with the push, closing the
   multi-second window for this class (config-rewrite faces
   remain item 3's documented residual).""",
))

# P9: module contract — push helpers gain the push-time re-canonicalization
plan_edits.append((
    "P9",
    """  lane); **the guarded push helpers** (L745–770 — their sed
  redaction stays and is PARITY-PINNED to `redact`; the label
  text is pinned by the re-homed failure lane); **the `_git`
  wrapper** (new at 3b — injects the transport allowlist flags on
  every TEST-mode git invocation it spawns; sabotage-pinned).""",
    """  lane); **the guarded push helpers** (L745–770 — their sed
  redaction stays and is PARITY-PINNED to `redact`; the label
  text is pinned by the re-homed failure lane; AND at STAGE 4b
  each helper gains the PUSH-TIME TARGET RE-CANONICALIZATION
  that closes the later-materialized-alias class — S8-PG1-iter3
  RT-C2/Arch-M2, see exit-criterion item 2); **the `_git`
  wrapper** (new at 3b — injects the transport allowlist flags on
  every TEST-mode git invocation it spawns; sabotage-pinned).""",
))

# P10: module contract — neutralization-hook delivery path (Arch-m1)
plan_edits.append((
    "P10",
    """  the exact ported equivalent of deleting a refusal block, with
  no source string-patching.""",
    """  the exact ported equivalent of deleting a refusal block, with
  no source string-patching. DELIVERY PATH through the bash
  entrypoint (ADDED at S8-PG1-iter3 — Arch-m1: the hook flag
  must reach the module THROUGH scripts/sandbox_backup.sh for
  the end-to-end lanes): the shim surface translates a
  TEST-mode-only environment variable
  `PC_TEST_NEUTRALIZE=<check>` into the module flag — honored
  ONLY when the script itself is in TEST mode (never PROD;
  refuse otherwise), passed as one extra argv token on the
  delegation — so the E20/E25/E29/E31-class lanes drive the hook
  end-to-end through the real entrypoint.""",
))

# P11: coverage table — the off-by-one cells
plan_edits.append((
    "P11",
    """| 121 preserved: quartet lanes re-shaped in place (E3/E28/r2 → refusal expectations), E11 → the two-lane re-homing stays INSIDE v6 (22 checks, re-shaped), message-token rule keeps L989/L1151/L1187 green unedited | unchanged 121 through the STAGE-6 gate; retirement BY that gate's finding (or later), with the per-lane table as the count map |""",
    """| **122** total: quartet lanes re-shaped in place (E3/E28/r2 → refusal expectations); E11 → the two-lane re-homing, BOTH lanes INSIDE v6 — v6 = 22−1+2 = **23 checks** (lane map: −1 old E11, +1 success lane, +1 hook-rejection failure lane) — CORRECTED at S8-PG1-iter3, RT-M1/Arch-M1/Steward-M1: all three roles derived 122 and the prior "121 preserved / (22, re-shaped)" cell was off by one and underivable; message-token rule keeps L989/L1151/L1187 + the matrix twins green unedited | unchanged **122** through the STAGE-6 gate; retirement BY that gate's finding (or later), with the per-lane table as the count map |""",
))

# P12: coverage table — E34 twin staging (Arch-m3)
plan_edits.append((
    "P12",
    """| 16 + module unit tests + the seam-anomaly lane + the five demo re-homes' pytest twins (count recorded at the 3a commit) |""",
    """| 16 + module unit tests + the seam-anomaly lane + the demo re-homes' pytest twins — FOUR of the five at 3a; v10 E34's twin lands at 3c (its mechanism, merge_union's union-prefers-OURS, is 3c surface — S8-PG1-iter3 Arch-m3; counts recorded at each stage commit) |""",
))

# P13: trailing derivability paragraph
plan_edits.append((
    "P13",
    """(the expected cells are derivable from the ledgered 3a/3b edit
lists — corrected at cap closure, Steward-M1).""",
    """(the expected cells are derivable from the ledgered 3a/3b edit
lists — corrected at cap closure, Steward-M1, and again at
S8-PG1-iter3: the post-3b cell was off by one, RT-M1/Arch-M1/
Steward-M1 — derivation: E11 1→2 inside v6 ⇒ v6 23 ⇒ total 122).""",
))

# P14: STAGE 5 — retirement blast radius completed (Arch-m6)
plan_edits.append((
    "P14",
    """         ported suite (S8-PG1 Arch-M4 — otherwise every later fix
         cycle is checklist-noncompliant against a retired
         artifact).""",
    """         ported suite (S8-PG1 Arch-M4 — otherwise every later fix
         cycle is checklist-noncompliant against a retired
         artifact). Retirement blast radius COMPLETED at
         S8-PG1-iter3 (Arch-m6): the same-commit amendment set
         also re-points every OTHER invocation site of the bash
         entrypoint — execution-plan-template.md FINAL STAGE,
         the process doc's closure choreography step 6, the
         release runbook's event-backup step, and harness/README
         — all name scripts/sandbox_backup.sh and must flip to
         the ported equivalent in the SAME retire commit; the
         SHIM option (open decision 4's default lean) avoids the
         entire radius.""",
))

# P15: port-time notes — stale citation ledgered into 3a (RT-m2)
plan_edits.append((
    "P15",
    """- sandbox_backup.sh L1132 cites "scripts/verify_backup_v7.sh" —
  stale since G1-iter6 (the matrix lives at
  harness/backups/matrices/); fix at STAGE 3a.""",
    """- sandbox_backup.sh L1132 cites "scripts/verify_backup_v7.sh" —
  stale since G1-iter6 (the matrix lives at
  harness/backups/matrices/); LEDGERED into the 3a edit list
  item (5) at S8-PG1-iter3 (RT-m2) — fixed at STAGE 3a.""",
))

apply(PLAN, plan_edits)

# ---------------- EVALUATION E1-E4 ----------------
eval_edits = []

# E1: criterion paragraph — the alias claim (RT-C2/Arch-M2 twin)
eval_edits.append((
    "E1",
    """resolves into/under production refuses; the
later-materialized-alias class is covered at push time by the
retained symlinked-.git + git-dir containment (corrected at cap
closure, S8-PG1 iteration 2: RT-C1/Steward-C2 — the earlier
"realpath-or-refuse for non-existent operands" wording would have
refused five green resilience lanes and contradicted the E11
failure-lane re-homing).""",
    """resolves into/under production refuses; the
later-materialized-alias class is NOT covered at push time — the
retained symlinked-.git + git-dir containment are guard-time
REPO-side checks (CORRECTED at S8-PG1-iter3, RT-C2/Arch-M2: the
prior "covered at push time" claim was falsified by executed E2E
— a symlink planted at a non-existent suffix after judgment
landed the checkpoint in a stand-in production .git, rc 0): it is
the FILESYSTEM face of frozen residual item 3 (recorded by that
gate finding, README amended), closed at the port by the
module-contract push helpers' push-time target
re-canonicalization (a STAGE 4b commitment of the plan). (The
ancestor-canonicalization itself was corrected at cap closure,
S8-PG1 iteration 2: RT-C1/Steward-C2 — the earlier
"realpath-or-refuse for non-existent operands" wording would have
refused five green resilience lanes and contradicted the E11
failure-lane re-homing.)""",
))

# E2: v9 E26 half-lane wording (Arch-m5)
eval_edits.append((
    "E2",
    """  remain LEGAL operands (the bothclean control lanes and v9 E26
  stay rc-0; the criterion never refused names, only their
  resolved targets).""",
    """  remain LEGAL operands (the bothclean control lanes stay rc-0,
  and v9 E26's plain-remote control sub-lane stays rc-0 — its
  scp-`:22:` sub-lane correctly stays a refusal under the type
  inversion, its resolved target being a remote URL — wording
  corrected at S8-PG1-iter3, Arch-m5; the criterion never
  refused names, only their resolved targets).""",
))

# E3: header — amendment provenance
eval_edits.append((
    "E3",
    """# Allowlist inversion — adopt/reject evaluation (S8 pre-gate
deliverable, decision #20b; AMENDED at S8-PG1 iteration 1,
2026-11-19)""",
    """# Allowlist inversion — adopt/reject evaluation (S8 pre-gate
deliverable, decision #20b; AMENDED at S8-PG1 iteration 1,
2026-11-19, and at S8-PG1-iter3 iteration 1, 2026-11-25 — record
`memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`: the
later-materialized-alias coverage claim corrected to the honest
not-covered form + the residual recording + the push-time
re-canonicalization commitment, RT-C2/Arch-M2; the v9 E26
half-lane wording, Arch-m5)""",
))

# E4: residual-list impact — the filesystem-face recording
eval_edits.append((
    "E4",
    """**New residual candidate for the frozen
list, per S8-PG1 RT-M3: mount-namespace aliasing — unprivileged
`unshare -rm mount --bind` works in this environment and realpath
cannot see through it; the port either implements device/inode
identity containment (bind mounts preserve st_dev/st_ino) or the
class joins the frozen list by gate finding.**""",
    """**New residual candidate for the frozen
list, per S8-PG1 RT-M3: mount-namespace aliasing — unprivileged
`unshare -rm mount --bind` works in this environment and realpath
cannot see through it; the port either implements device/inode
identity containment (bind mounts preserve st_dev/st_ino) or the
class joins the frozen list by gate finding.** **Recorded at
S8-PG1-iter3 (RT-C2/Arch-M2, by gate finding): the
later-materialized-alias class — a symlink planted at a
non-existent push-target suffix after judgment — is the
FILESYSTEM face of frozen residual item 3 (the README item is
amended accordingly); the plan's module contract closes it at
the port via the push helpers' push-time target
re-canonicalization (STAGE 4b).**""",
))

apply(EVAL, eval_edits)

# ---------------- README R1 ----------------
readme_edits = []

# R1: frozen residual item 3 — the filesystem face (RT-C2/Arch-M2)
readme_edits.append((
    "R1",
    """3. **Resolution/use TOCTOU** (G1-iter5-i2 Architect minor #2) — the
   guard resolves the target once, pre-action; the pushes re-resolve
   at push time, so a config rewrite (insteadOf/pushurl/remote url)
   in the multi-second window re-opens the lane. Requires a
   concurrent writer on the machine (same boundary as item 4);
   relative operands — the form that made the two bases DIFFER — are
   refused outright since v8.""",
    """3. **Resolution/use TOCTOU** (G1-iter5-i2 Architect minor #2) — the
   guard resolves the target once, pre-action; the pushes re-resolve
   at push time, so a config rewrite (insteadOf/pushurl/remote url)
   in the multi-second window re-opens the lane. Requires a
   concurrent writer on the machine (same boundary as item 4);
   relative operands — the form that made the two bases DIFFER — are
   refused outright since v8. **FILESYSTEM face added by gate
   finding (S8-PG1-iter3, RT-C2/Arch-M2 — executed E2E: a symlink
   planted at a non-existent push-target suffix AFTER judgment
   lands the checkpoint in the aliased production .git with every
   guard green; the guard-time symlinked-.git/containment checks
   inspect the REPO side, not the push target at push time). The
   S8 port closes this face: the module-contract push helpers
   re-canonicalize the target immediately before each push
   (STAGE 4b). Until the port, this is the documented shape of
   the residual.**""",
))

apply(README, readme_edits)
print("ALL REMEDIATION EDITS APPLIED")

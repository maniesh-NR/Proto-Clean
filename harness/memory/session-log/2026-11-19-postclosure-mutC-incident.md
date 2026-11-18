# Session 2026-11-19 — post-closure: the mutC probe incident (seq
# 1'/2'/13 cluster), annotated and disclosed

Follows `2026-11-19-g1-iter5-closure.md` (same working session; a
separate entry because the closure commit had already landed).

## What happened

The closing backup's audit (manifest seq 14) surfaced an unexplained
**seq 13 "override probe"** (2026-11-18T18:23:16Z) — and the branch
graph showed more: a "push-target probe" checkpoint (`5516e36`), a
**divergence-self-heal merge** (`00c2ba9`), then "override probe"
(`2277469`). Root cause: the orchestrator's **mutC mutation probe**
(the relative-refusal revert, run during the closing fix cycle)
patched `PROD_CHECKOUT` to a scratch stand-in in the mutated copy —
per the seq-10 rule — but did NOT patch the TEST LANES that reference
the real production path. With the constant patched:

- the guard test's **push-target lanes** (`PC_BACKUP_PUSH_REMOTE` =
  the real production path, literal spellings) matched nothing and
  were NOT refused — the scratch clone's checkpoints (seq 1' "guard
  clean lane", seq 2' "push-target probe") were pushed INTO the
  production checkout's local `sandbox/backups`; the non-FF push
  triggered the divergence self-heal, which merged the production
  branch in (`-s ours` + manifest union, exactly as designed, on the
  wrong base) and re-pushed successfully;
- the override test's **symlink REPO lane** (`PC_BACKUP_REPO` =
  symlink → the real production checkout) also matched nothing and
  was NOT refused — a full backup ran directly against the production
  checkout (seq 13 "override probe"; its harness refresh snapshotting
  the then-uncommitted closing docs).

The v8 script itself behaved correctly throughout — every involved
lane refuses on the REAL script (16/16 suite + 86 matrix checks);
only the probe's one-sided patch opened them. Damage: content clean
(all scan layers ran; the manifest union followed the documented
triple-key semantics; the production checkout's working tree
untouched — only its local branch ref); audit-trail pollution: three
test entries + a merge commit + the branch's frozen product snapshot
replaced by the newer 517ad3f-era tree (preserved in history). The
fifth accidental-checkpoint incident, third variant (env loss,
half-edited script, one-sided guard-mutation patch).

## Remediation

- All three entries (seq 1' 18:23:15Z, seq 2' 18:23:16Z, seq 13
  18:23:16Z) annotated invalid on the branch (`bbbbd2f`, the
  seq-3/5/7/10 precedent).
- Disclosure amended into the closed G1-iter5 record (a post-closure
  incident section, inserted before the closure line; the mutation
  bullet's containment claim corrected — the detection results stand,
  the containment claim was wrong), the README anomaly log, the
  lessons entry, and process-doc checklist item (f).
- **The corrected rule (supersedes the seq-10 one-sided rule): a
  guard-mutation probe patches BOTH SIDES — the guarded constant AND
  every test lane that references the real protected path — or runs
  only where the production path does not exist.**

## Standing state after this session

G1-iter5 remains closed (NO CONSENSUS at the cap) and escalated to
the owner; the escalation decision (order G1-iter6 on the closing
commit `a1607ce` + this disclosure commit, or another option) is the
owner's call.

# Session 2026-11-19 — The sixth accidental-checkpoint incident
(G1-iter6 fix cycle, fourth variant)

## PROVENANCE DISCLOSURE

The orchestrating session lost its context during the G1-iter6 fix
cycle; this log is RECONSTRUCTED from the anomaly-log entry the
lost session wrote in `harness/backups/README.md` (which carries
the reflog evidence and the corrected rule) and from the reflog
itself, re-verified by the continuation orchestrator: the local
`sandbox/backups` branch equals `origin/sandbox/backups`
(`0a48be5`, single unique SHA across both refs) and the pushed
manifest ends at seq 15 with main_push ok / prev_branch_push ok.
The narrative below restates the README entry; no detail beyond it
is recoverable.

## What happened (from the README anomaly entry)

During the G1-iter6 fix cycle the orchestrator's mutation-probe
battery cloned its probe repos from HEAD while the v9 fix (which
makes the integrity lanes DERIVE `PROD_CHECKOUT` from the script
under test) was still UNCOMMITTED in the working tree. The probe
clone therefore carried the v8 test file with its HAND-COPIED
production paths, and probe L (which patches the script constant
to a stand-in) became a one-sided patch: the guard test's
push-target lanes ran full backups against the production checkout
and pushed two junk clusters onto its LOCAL `sandbox/backups`
branch (a "guard clean lane" checkpoint rode each time: the
prod-lane run based on the clone's local branch, which carried the
clean-lane commit, then the self-heal merged the fetched production
branch and pushed).

The second cluster came from the orchestrator's DEBUG re-run of
the failing probe — a debug re-run of a production-touching probe
is itself production-touching.

## Damage and containment

- **Origin was NEVER touched** — the reflog shows only local ref
  updates; no push to the remote left the machine.
- Content clean: test-shaped scratch homes; all scan layers ran;
  the manifest union followed the documented triple-key semantics;
  the production checkout's working tree untouched — only its
  local branch ref.
- The local branch was reset to `origin/sandbox/backups`
  (`0a48be5`) and verified identical (re-verified by the
  continuation orchestrator: local == origin, manifest seq 15,
  17 entries including the annotated-invalid seq 1'/2').
- Audit-trail pollution only, local-only — removed by reset with
  this disclosure, per the G1-iter6 lesson: annotating would PUSH
  the junk to the remote — the opposite of containment.

## The corrected rule (extends the both-sides rule, lessons +
process doc)

Probe from the tree that CONTAINS the guard fix being exercised —
a probe clone taken from HEAD while the fix sits uncommitted in
the working tree re-creates the one-sided patch structurally, and
the fix that saves you (derived lanes) is exactly the part the
stale clone lacks. Mutation-probe batteries snapshot the WORKING
TREE (clone for history + rsync the tree over it), never bare
HEAD; anchors verify LOUDLY (a missing anchor is an inconclusive
probe, never a silent skip); and never re-run a failing
production-touching probe to "see what happens" without
re-checking its containment first.

Sixth incident of the accidental-checkpoint class, fourth variant
(env loss, half-edited script, one-sided constant patch,
stale-clone probe battery).

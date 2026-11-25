# Allowlist inversion — adopt/reject evaluation (S8 pre-gate
deliverable, decision #20b; AMENDED at S8-PG1 iteration 1,
2026-11-19, and at S8-PG1-iter3 iteration 1, 2026-11-25 — record
`memory/consensus-log/2026-11-25-s8-pre-gate-iter3.md`: the
later-materialized-alias coverage claim corrected to the honest
not-covered form + the residual recording + the push-time
re-canonicalization commitment, RT-C2/Arch-M2; the v9 E26
half-lane wording, Arch-m5)

Status: **ADOPT** (recommended), with the loopback-observability
QUARTET (v6 E11, v5 E3, v9 E28, machine-suite r2) converted at the
port per the amended recommendation below. This is an ADOPT, not a
rejection — no owner decision is triggered by #20b; the S8 pre-gate
judges this document. **Amendment provenance: S8-PG1 iteration 1
(2026-11-19, record `memory/consensus-log/2026-11-19-s8-pre-gate.md`)
— Red Team BLOCK + Devil's Architect BLOCK + Ship Steward
PROCEED-WITH-FINDINGS; every finding below cites its source. The
ADOPT direction was confirmed by all three roles; what changed is
the retirement schedule (now family-by-family), the inventory
(trio→quartet), and the E11 characterization.**

Inventory verified at `5e70fae` (2026-11-19) by repo-wide scan and
RE-CORRECTED at S8-PG1: the consumers of
`scripts/sandbox_backup.sh` TEST mode are exactly the integrity
suite, the six repo-resident matrices, and CI (which runs the
integrity suite on POSIX legs); the remaining reference hits are
docs. No other caller exists.

## The criterion being adopted (decision #20, semantics clarified
at S8-PG1)

Judgment applies to the RESOLVED EFFECTIVE targets of BOTH
directions of every TEST-mode push/fetch operand — never to the raw
typed string alone:

- a URL/path-typed operand is judged as the typed spelling for the
  push view and as the insteadOf-resolved spelling for the fetch
  view (`git ls-remote --get-url` semantics — this resolution is
  what subsumes the insteadOf family);
- a remote NAME is judged as `remote.<n>.url` (fetch view) and
  `remote.<n>.pushurl` if set (push view) — clean remote names
  remain LEGAL operands (the bothclean control lanes stay rc-0,
  and v9 E26's plain-remote control sub-lane stays rc-0 — its
  scp-`:22:` sub-lane correctly stays a refusal under the type
  inversion, its resolved target being a remote URL — wording
  corrected at S8-PG1-iter3, Arch-m5; the criterion never
  refused names, only their resolved targets).

A TEST run's resolved effective targets must be ONLY local absolute
filesystem paths, physically disjoint from the production checkout
(containment, not equality); production is opt-in; nothing exits
the machine in TEST mode. Physical disjointness for a NON-EXISTENT
operand is judged by its deepest EXISTING ancestor (realpath): a
non-existent operand under a scratch ancestor stays LEGAL (the
unreachable-push resilience lanes keep their semantics — see the
inventory note below), while an operand whose existing ancestor
resolves into/under production refuses; the
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
failure-lane re-homing.)

## Consumer inventory (re-verified 2026-11-19, `5e70fae`; quartet
correction from S8-PG1: RT-C2b / Steward-C1 / Arch-M1)

1. **`tests/test_harness_integrity.py`** — 29 grep hits for
   `PC_BACKUP_PUSH_REMOTE` (27 env-dict invocation sites + 2 comment
   lines). Every success-expecting lane EXCEPT ONE targets a
   `tmp_path` bare or `tmp_path` directory — local absolute
   filesystem paths. The non-local spellings (`dead.example.com`,
   the `ghdiv` / `urlpush` / `bothclean` named-remote probes,
   unreachable-remote lanes) are refusal/failure probes: they
   consume no network capability, they prove it absent. The ONE
   success-expecting exception — missed by the original inventory
   because the URL flows through a parameter, not a
   `PC_BACKUP_PUSH_REMOTE` literal — is the machine-suite leak-probe
   lane **r2** inside `test_backup_script_mainpush_redaction_and_
   trace_hygiene`: it binds a local 401 server, pushes to
   `http://user:$fake@127.0.0.1:$PORT/x.git` (env site L1468, URL
   built L1489), asserts rc 0 + "credentials redacted" + no
   "Server auth using Basic" (L1501–1508), and passes today only
   via the `127.*` raw-IP exemption (L538–547; the operative case
   at L539 — anchor corrected at cap closure, Steward-m5).
2. **Matrices v5–v10** — 34 raw `PC_BACKUP_PUSH_REMOTE` hits across
   the six scripts (33 env-setting sites + 1 patch-anchor string
   mention, v9 L259 — decomposition per S8-PG1 Steward-m1). Every
   capability-USING success lane (E25, E27, E31, E34, …) targets a
   mktemp scratch bare (`$S/<lane>/bare.git`, `$d/bare.git`) —
   local absolute filesystem paths. NON-EXISTENT-OPERAND lanes
   (corrected at cap closure, RT-m3 — the original inventory
   misclassified them): E12 run 2 targets `$S/nope.git` (rc 0,
   unreachable-push resilience — the operand PASSES the guard via
   today's literal-only degradation and stays legal under the
   corrected ancestor-canonicalized containment); v5 E4's
   `$d4/nope.git` lanes are SABOTAGE lanes whose operand must PASS
   the guard so the sabotaged self-test fires (exit 5) — also
   non-refusal. Actual refusal lanes: `relhide*`,
   `definitely-not-a-remote`, `dead.example.com`. (E10 and E33,
   listed as success lanes in the original enumeration, are
   refusal-only lanes — E10: partial overrides exit 2 +
   production-checkout exit 6; E33: refusals — corrected per
   S8-PG1 Steward-m2.) The same non-existent-operand class in the
   machine suite (the alarm lane's `nope.git`, the key-scrub run's
   `missing.git`) is likewise legal-and-green under the corrected
   rule — no lane conversions needed beyond the quartet.
3. **The loopback-URL QUARTET** — the inventory's one exception
   class (a quartet, not the trio first written — S8-PG1):
   machine-local (loopback never leaves the machine) but
   URL-typed, not filesystem-path-typed:
   - **v6 E11** (verify_backup_v6.sh ~L135): a FAILING-push
     redaction lane, not a success-surface lane (corrected per
     RT-C2a / Steward-C2): the lane's own server 401s everything;
     both http pushes FAIL; the asserted "credentials redacted"
     labels come from the main-push and branch-push FAILURE paths;
     rc 0 means the run survives failed pushes. The v6 header
     itself says "failing credentialed main push". With the
     verbose/trace family ON it observes redaction on a FAILED
     http push — the surface where curl-level verbose leaks live.
   - **v5 E3** (~L114): rc-0 lane — `https://u:$FAKE@127.0.0.1:1/
     x.git` (dead port): asserts no leak under the `GIT_TRACE2`
     family and that the run survives a failed push.
   - **v9 E28** (~L231): mechanism lane — asserts the loopback
     EXEMPTION itself (the guard passes `127.0.0.1` targets to the
     push layer; any rc but 6).
   - **machine-suite r2** (tests ~L1489): the success-expecting
     leak-probe lane described above — CI runs it on every POSIX
     push.
4. **Production runs** — opt-in only (`PC_BACKUP_ALLOW_PRODUCTION=1`);
   outside TEST mode; not consumers of TEST capability.

## Finding

The decision-#20b claim — "every legitimate TEST lane pushes to a
local scratch bare" — verifies **TRUE for backup capability**: every
capability-USING TEST consumer that performs a meaningful backup push
targets a local absolute filesystem path. The refinement (amended at
S8-PG1): FOUR redaction/exemption observability lanes use loopback
URLs; they consume no backup capability against any remote and exist
to prove hygiene properties of the push layer.

## Decision: ADOPT, with the family-by-family disposition below
(amended at S8-PG1: RT-C1 / Arch-C1 / RT-m4)

The inversion is adopted **total for remote targets**: every
RESOLVED EFFECTIVE target (per the semantics above) of a TEST-mode
operand that is not a local absolute filesystem path, physically
disjoint from the production checkout, refuses exit 6 — no host
spellings, no suffix matching, no enumeration, no URL forms.

**The refusal families do NOT retire as one flat list.** The
original document's flat retirement list over-reached: it would have
retired refusals that are NOT subsumed by the inversion and thereby
reopened two executed-E2E criticals (G1-iter6 RT-C3;
G1-iter6-i2 RT-C1). The corrected disposition:

| Family | Disposition | Why |
|---|---|---|
| insteadOf (fetch side) | **RETIRE at conversion** | Subsumed via resolution: the judged fetch view resolves the rewrite (`ls-remote --get-url`); a rewritten-to-URL view fails the allowlist (E16 pattern) |
| transports (`ext::`/`fd::`/…), percent-encoded hosts, raw-IP (incl. the loopback exemption), trailing-dot, multi-@, scp spellings, relative targets, host suffix matching | **RETIRE at conversion** | Operand-shape families: none of these spellings is a local absolute filesystem path; the type inversion refuses them by construction |
| **pushInsteadOf (config key)** | **SURVIVES the inversion** | NOT subsumed: git applies pushInsteadOf to direct push operands AT PUSH TIME — invisible to both judged views (the guard judges the typed operand as the push view; proven E2E at G1-iter6 RT-C3 and by the S8-PG1 Red Team scratch probe: a clean local scratch path + a visible `url.<target>.pushInsteadOf=<local path>` key lands the push on the rewrite target with the guard green). The config-level refusal stays. |
| **include/includeIf file content** | **SURVIVES the inversion** | NOT subsumed: the delivery vector for a context-divergent pushInsteadOf/pushurl — inactive in the guard's context (repo on main), active at push time (worktree on sandbox/backups); proven E2E at G1-iter6-i2 RT-C1 (rc 0, zero refusals). The file-content scan (repo + global + XDG + system) stays. |
| **symlinked-.git + git-dir containment** | **SURVIVES the inversion** (identity mechanism, not an operand-shape family) | The containment compare is what enforces "physically disjoint" for the git-dir itself — a `.git` symlink can point AT `$PROD/.git` from a disjoint operand path (the E33 shape: a symlink to a NON-production checkout's .git passes production containment and would operate on another checkout's git state). Retirement was never subsumed; the two inconsistent lists in the original document are both superseded by this row. |
| off-domain redirector URLs | **documented residual** (unchanged) | No client-side spelling check can catch them |

**Defense-in-depth (adopted from S8-PG1 RT-C1 option (b); HONESTLY
RE-SCOPED at cap closure — RT-C3/Arch-C2: the earlier claim
"structurally subsumes every push-time rewrite class" was false
twice over)**: a BASH-SIDE `_git` wrapper (added to the module
contract's stays-in-bash list — a child module cannot attach `-c`
flags to parent-spawned processes, and env injection is blocked by
the scrub's own GIT_CONFIG_* drop) prefixes every TEST-mode git
invocation it spawns with the non-file transports denied
(`protocol.http.allow=never`, `protocol.https.allow=never`,
`protocol.git.allow=never`, `protocol.ssh.allow=never`,
`protocol.ext.allow=never`, …; `protocol.file.allow` stays
permitted — the legitimate TEST pushes are local paths), pinned by
a wrapper-sabotage lane proving the flags load-bearing. Scope of
the backstop, stated honestly: it subsumes every NETWORK-transport
rewrite (verified by the S8-PG1 Red Team scratch probe: a
pushInsteadOf-rewritten push aborts with "fatal: transport 'http'
not allowed"). A rewrite to a LOCAL path — the G1-iter6 RT-C3
incident shape and the E25/E31 demo shapes — is NOT subsumed
(file must stay allowed); that residual is guarded SOLELY by the
retained config-level refusals (pushInsteadOf key scan +
include/includeIf content scan), and this is now the recorded
residual, not a structural claim.

## The loopback QUARTET conversion (amended at S8-PG1: RT-C2a /
Steward-C2 / Steward-M1 / Arch-m2 / Arch-M1)

- (i) **E3/E28 and machine-r2's guard-facing aspect** become
  refusal-expectation lanes (a URL operand now refuses up-front;
  the no-leak assertions re-target the refusal surface, which is
  already redaction-covered — E35 + the refusal-redaction lanes).
  v5 E3's resilience aspect ("the run survives a failed push")
  re-homes to the v5-E8 hook-rejection class (verify_backup_v5.sh
  L180–189 — citation corrected at cap closure from the mislabeled
  "v8/E8", RT-M4: v8 numbers E19–E22), which covers failed-push
  resilience (per S8-PG1 Arch-m4 — the per-lane audit at plan
  STAGE 4 records this mapping).
- (ii) **E11's redaction observability is preserved by TWO
  local-filesystem lanes** (re-specified per RT-C2a / Steward-C2 —
  the original "redaction label on the captured success output" was
  unimplementable: `_push_main`/`_push_branch` print nothing on
  success, and E11's own pushes fail):
  - a SUCCESS lane: push to a tmp scratch bare with the
    verbose/trace family ON; assert zero credential material and
    zero trace lines in the captured output (the v7-E17 /
    machine-r3 shape);
  - a FAILURE lane: push to an EXISTING-but-REJECTING local target
    — the v5-E8 hook-rejection shape (a scratch bare whose
    pre-receive hook rejects the ref update; the push executes
    against a real git endpoint and fails) — and assert the
    "credentials redacted" label plus zero credential material on
    the captured failing stderr (the label only ever prints on
    failure). Re-specified at cap closure (RT-C1/Steward-C2): the
    earlier "unreachable LOCAL target" wording was the
    non-existent-operand shape, which the pre-correction exit
    criterion would have refused up-front (no push executes, no
    label prints); the hook shape decouples the lane from
    non-existence semantics entirely and is the stronger failure
    surface (a real ref-update rejection, not a connection
    failure).
- (iii) **The scrub and redaction become pinned unit surfaces +
  PARITY-PINNED live copies**: the ported module's `sanitize_env`
  and `redact` are pure functions with unit tests asserting the
  sanitized env drops the `GIT_TRACE*` / `GIT_CURL_VERBOSE` /
  `GIT_CONFIG_*` / `GIT_DIR` families — correcting the original
  document's false claim (L88–92 of the pre-amendment text) that
  the v6 pattern scrub + v7 zero-trace lane "structurally
  neutralize" that class: v7 E17 and machine-r3 run LOCAL
  transports where curl never executes and would pass with
  GIT_CURL_VERBOSE deleted from the pattern; the only http-transport
  witnesses were E11 and machine-r2, both converting. AND —
  extended at cap closure (RT-M1: unit pins alone pin module
  COPIES, not the live bash artifacts that actually guard the
  bash-spawned pushes) — PATTERN-PARITY machine lanes pin the live
  copies to the module: the bash scrub case-list
  (sandbox_backup.sh L111–117) must equal `sanitize_env`'s
  drop-list, and the bash push helpers' sed redaction rules
  (L754/L767) must equal `redact`'s rules — both extracted from
  the live sources at test time and compared, so a regression in
  EITHER copy (the G1-iter4-i2 executed-leak class) fails the
  suite. The module unit tests catch the class directly, in CI,
  on every leg; the parity lanes keep the live bash artifacts
  honest for as long as they exist.
- (iv) **The loopback exemption retires** together with the raw-IP
  refusal family it was carved from.

**Alternative considered and rejected** (unchanged): retain a named
loopback allowance to keep http-transport observability in TEST
mode. This preserves a URL-shaped hole inside an allowlist guard —
exactly the operand-spelling space six gates spent closing; a total
inversion is strictly safer, and with (ii)+(iii) above it loses no
assertion that cannot be re-homed (the original document's claim of
the same name was false for the curl-verbose class until the scrub
unit-pin was added).

## Residual-list impact (frozen list, backups README; corrected at
S8-PG1)

At the port, the RETIRE families' refusal lanes (insteadOf
fetch-side, transports, percent, raw-IP/loopback, trailing-dot,
multi-@, scp spellings, relative targets, host suffix matching)
convert to allowlist lanes; what closes on the frozen residual list
is the third-party-egress clause of residual item 1 (the spelling
families it enumerated) — wording refined at cap closure
(Steward-m2: the RETIRE families were never residual-list entries
themselves). The SURVIVES rows (pushInsteadOf, include/includeIf
content, symlinked-.git/git-dir containment) remain on the guard —
and the LOCAL-path rewrite residual under the transport backstop
(cap-closure re-scope above) is recorded beside them. Off-domain
redirector URLs remain a documented residual (no client-side
spelling check can catch them) — unchanged. **New residual candidate for the frozen
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
re-canonicalization (STAGE 4b).**

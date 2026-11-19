# Allowlist inversion — adopt/reject evaluation (S8 pre-gate
deliverable, decision #20b; AMENDED at S8-PG1 iteration 1,
2026-11-19)

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
  remain LEGAL operands (the bothclean control lanes and v9 E26
  stay rc-0; the criterion never refused names, only their
  resolved targets).

A TEST run's resolved effective targets must be ONLY local absolute
filesystem paths, physically disjoint from the production checkout
(containment, not equality); production is opt-in; nothing exits
the machine in TEST mode.

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
   via the `127.*` raw-IP exemption (L533–535).
2. **Matrices v5–v10** — 34 raw `PC_BACKUP_PUSH_REMOTE` hits across
   the six scripts (33 env-setting sites + 1 patch-anchor string
   mention, v9 L259 — decomposition per S8-PG1 Steward-m1). Every
   capability-USING success lane (E12, E25, E27, E31, E34, …)
   targets a mktemp scratch bare (`$S/<lane>/bare.git`, `$d/bare.git`)
   — local absolute filesystem paths. `relhide*`,
   `definitely-not-a-remote`, `$d4/nope.git`, `dead.example.com`
   are refusal lanes. (E10 and E33, listed as success lanes in the
   original enumeration, are refusal-only lanes — E10: partial
   overrides exit 2 + production-checkout exit 6; E33: refusals —
   corrected per S8-PG1 Steward-m2.)
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

**Defense-in-depth (adopted from S8-PG1 RT-C1 option (b))**: on top
of the retained config-level refusals, the ported module runs every
TEST-mode git invocation with all non-file transports denied
(`protocol.http.allow=never`, `protocol.https.allow=never`,
`protocol.git.allow=never`, `protocol.ssh.allow=never`,
`protocol.ext.allow=never`, …; `protocol.file.allow` governs the
local pushes) — verified by the S8-PG1 Red Team scratch probe: a
pushInsteadOf-rewritten push aborts with "fatal: transport 'http'
not allowed". This structurally subsumes every push-time rewrite
class even if a config-level refusal regresses.

## The loopback QUARTET conversion (amended at S8-PG1: RT-C2a /
Steward-C2 / Steward-M1 / Arch-m2 / Arch-M1)

- (i) **E3/E28 and machine-r2's guard-facing aspect** become
  refusal-expectation lanes (a URL operand now refuses up-front;
  the no-leak assertions re-target the refusal surface, which is
  already redaction-covered — E35 + the refusal-redaction lanes).
  v5 E3's resilience aspect ("the run survives a failed push")
  re-homes to the v8/E8 hook-rejection class, which covers
  failed-push resilience (per S8-PG1 Arch-m4 — the per-lane audit
  at plan STAGE 4 records this mapping).
- (ii) **E11's redaction observability is preserved by TWO
  local-filesystem lanes** (re-specified per RT-C2a / Steward-C2 —
  the original "redaction label on the captured success output" was
  unimplementable: `_push_main`/`_push_branch` print nothing on
  success, and E11's own pushes fail):
  - a SUCCESS lane: push to a tmp scratch bare with the
    verbose/trace family ON; assert zero credential material and
    zero trace lines in the captured output (the v7-E17 /
    machine-r3 shape);
  - a FAILURE lane: push to an unreachable LOCAL target; assert the
    "credentials redacted" label on the captured failing stderr
    (the label only ever prints on failure — the alarm lane's
    unreachable-local-target shape already yields it).
- (iii) **The scrub becomes a pinned unit surface**: the ported
  module's env-scrub is a pure function with unit tests asserting
  the sanitized env drops the `GIT_TRACE*` / `GIT_CURL_VERBOSE` /
  `GIT_CONFIG_*` / `GIT_DIR` families. This is the STRUCTURAL
  witness for the curl-verbose leak class — correcting the original
  document's false claim (L88–92 of the pre-amendment text) that
  the v6 pattern scrub + v7 zero-trace lane "structurally
  neutralize" that class: v7 E17 and machine-r3 run LOCAL
  transports where curl never executes and would pass with
  GIT_CURL_VERBOSE deleted from the pattern; the only http-transport
  witnesses were E11 and machine-r2, both converting. Post-port the
  unit-pinned pattern is strictly better than the http sink: it
  catches a scrub regression directly, in CI, on every leg.
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

At the port, the RETIRE row of the disposition table above
(insteadOf fetch-side, transports, percent, raw-IP/loopback,
trailing-dot, multi-@, scp spellings, relative targets, host suffix
matching) converts to allowlist lanes and leaves the residual list
by gate finding. The SURVIVES rows (pushInsteadOf, include/includeIf
content, symlinked-.git/git-dir containment) remain on the guard —
they are not residuals of the inversion. Off-domain redirector URLs
remain a documented residual (no client-side spelling check can
catch them) — unchanged. **New residual candidate for the frozen
list, per S8-PG1 RT-M3: mount-namespace aliasing — unprivileged
`unshare -rm mount --bind` works in this environment and realpath
cannot see through it; the port either implements device/inode
identity containment (bind mounts preserve st_dev/st_ino) or the
class joins the frozen list by gate finding.**

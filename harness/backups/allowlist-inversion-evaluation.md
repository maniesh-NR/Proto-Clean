# Allowlist inversion — adopt/reject evaluation (S8 pre-gate
deliverable, decision #20b)

Status: **ADOPT** (recommended), with the loopback-observability trio
(E11/E3/E28) converted at the port per the recommendation below. This
is an ADOPT, not a rejection — no owner decision is triggered by
#20b; the S8 pre-gate judges this document, and a pre-gate
disagreement with the loopback retirement escalates per the gate's
own rules.

Inventory verified at `5e70fae` (2026-11-19) by repo-wide scan: the
consumers of `scripts/sandbox_backup.sh` TEST mode are exactly the
integrity suite, the six repo-resident matrices, and CI (which runs
the integrity suite on POSIX legs); the remaining reference hits are
docs. No other caller exists.

## The criterion being adopted (decision #20)

A TEST run addresses ONLY local absolute filesystem paths, physically
disjoint from the production checkout (containment, not equality);
production is opt-in; nothing exits the machine in TEST mode. The
denylist refusal families (insteadOf/pushInsteadOf, include/includeIf
content, transports, percent/raw-IP/trailing-dot/multi-@/scp
spellings, symlinked-.git, relative targets) retire as their matrix
lanes convert to allowlist lanes.

## Consumer inventory (re-verified 2026-11-19, `5e70fae`)

1. **`tests/test_harness_integrity.py`** — 29 grep hits for
   `PC_BACKUP_PUSH_REMOTE` (27 env-dict invocation sites + 2 comment
   lines). Every success-expecting lane targets a `tmp_path` bare or
   `tmp_path` directory — local absolute filesystem paths. The
   non-local spellings (`dead.example.com`, the `ghdiv` / `urlpush` /
   `bothclean` named-remote probes, unreachable-remote lanes) are
   refusal/failure probes: they consume no network capability, they
   prove it absent.
2. **Matrices v5–v10** — 33 `PC_BACKUP_PUSH_REMOTE` hits across the
   six scripts. Every success-expecting lane (E10, E12, E25, E27,
   E31, E33, E34, …) targets a mktemp scratch bare
   (`$S/<lane>/bare.git`, `$d/bare.git`) — local absolute filesystem
   paths. `relhide*`, `definitely-not-a-remote`, `$d4/nope.git`,
   `dead.example.com` are refusal lanes.
3. **The loopback-URL trio** — the inventory's one exception class.
   Machine-local (loopback never leaves the machine — consistent with
   "nothing exits the machine in TEST mode") but URL-typed, not
   filesystem-path-typed:
   - **v6 E11** (verify_backup_v6.sh ~L135): SUCCESS lane — pushes to
     `http://user:$FAKE@127.0.0.1:$PORT/x.git` with the verbose/trace
     family ON; asserts rc 0, zero credential material in output, and
     the "credentials redacted" label. It observes redaction on a
     SUCCESSFUL push surface over the http transport (the class where
     curl-level verbose leaks live).
   - **v5 E3** (~L114): rc-0 lane — `https://u:$FAKE@127.0.0.1:1/x.git`
     (dead port): asserts no leak under the `GIT_TRACE2` family and
     that the run survives a failed push.
   - **v9 E28** (~L231): mechanism lane — asserts the loopback
     EXEMPTION itself (the guard passes `127.0.0.1` targets to the
     push layer; any rc but 6).
4. **Production runs** — opt-in only (`PC_BACKUP_ALLOW_PRODUCTION=1`);
   outside TEST mode; not consumers of TEST capability.

## Finding

The decision-#20b claim — "every legitimate TEST lane pushes to a
local scratch bare" — verifies **TRUE for backup capability**: every
capability-USING TEST consumer that performs a meaningful backup push
targets a local absolute filesystem path. The refinement: three
redaction/exemption observability lanes use loopback URLs; they
consume no backup capability against any remote and exist to prove
hygiene properties of the push layer.

## Decision: ADOPT, with the loopback trio converted at the port

- The inversion is adopted **total for remote targets**: any TEST-mode
  operand that is not a local absolute filesystem path, physically
  disjoint from the production checkout, refuses exit 6 — no host
  spellings, no suffix matching, no enumeration, no URL forms.
- The loopback trio converts: (i) **E3/E28** become
  refusal-expectation lanes (a URL operand now refuses up-front; the
  no-leak assertions re-target the refusal surface, which is already
  redaction-covered — E35 + the refusal-redaction lanes); (ii) **E11's
  success-surface redaction observability is preserved by a NEW
  local-filesystem success lane** — push to a tmp scratch bare with
  the verbose/trace family on, assert zero credential material and
  the redaction label on the captured success output; (iii) the
  **loopback exemption retires** together with the raw-IP refusal
  family it was carved from.
- The curl-transport-specific leak classes (`GIT_CURL_VERBOSE`,
  `Server auth using Basic`) are separately and structurally
  neutralized by the pattern env scrub (v6) and the zero-trace-lines
  observability lane (v7) — the http-transport sink is not the only
  witness to that class.
- **Alternative considered and rejected**: retain a named loopback
  allowance to keep http-transport observability in TEST mode. This
  preserves a URL-shaped hole inside an allowlist guard — exactly the
  operand-spelling space six gates spent closing; a total inversion
  is strictly safer and loses no assertion that cannot be re-homed.

## Residual-list impact (frozen list, backups README)

At the port, the insteadOf/pushInsteadOf/includeIf/transport/percent/
raw-IP/trailing-dot/multi-@/scp families convert to allowlist lanes
and leave the residual list by gate finding. Off-domain redirector
URLs remain a documented residual (no client-side spelling check can
catch them) — unchanged by this decision.

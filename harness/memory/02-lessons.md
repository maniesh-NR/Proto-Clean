# Lessons / Constraints (read before running anything)

Hard-won gotchas. rediscovering these costs 10+ minutes each.

## Sandbox environment

- The sandbox is recycled between prompts: installed pip packages
  vanish (INCLUDING optional extras — reinstall `aioquic dnslib segno
  zxing-cpp` too or 21 test modules fail to collect). Re-run
  `pip install -q -e . pytest` in `/home/z/my-project/cleanroom`
  before running tests.
- **Never store credentials in sandbox scripts** — anything under
  `/home/z/my-project/scripts/` gets rsynced into the repo by the
  backup workflow. Read tokens from `GITHUB_TOKEN` or the git remote;
  the backup script secret-scans and hard-fails, but don't rely on
  the scanner (G1 near-miss: two poll scripts shipped embedded PATs;
  nothing leaked, but rotation was advised).
- `gh` CLI does not work in the sandbox — use `curl` + the GitHub API.
- The PAT is embedded in the git remote URL (`https://user:token@…`).
  Extract with `CRED=$(git remote get-url origin); CRED="${CRED##*://}";`
  `CRED="${CRED%%@*}"; TOKEN="${CRED##*:}"` — a plain `sed` grabs the
  username too and every API call 401s.
- Blocked commands (tunnels, metadata endpoints, reading other
  processes' env) — don't try to work around; pick another approach.
- `python -c "import yaml; yaml.safe_load(ci.yml)"` reads `on:` as
  boolean `True` — it's a YAML 1.1 quirk, the file is fine.
- **A script whose default action is a production push will eventually
  run by accident** — make the dangerous path opt-in. Two gates, two
  accidental production pushes (manifest seq 3 "t5", seq 5 "E9c"),
  both from agents losing env overrides through broken command chains.
  v5 refuses production mode without `PC_BACKUP_ALLOW_PRODUCTION=1`.
- A substring integrity check is satisfied by its own documentation —
  anchor machine checks to full lines, require exactly one, and
  self-falsify them with synthetic forgeries (the FINAL-OUTCOME
  rule's own prose backed a forged ☑ at `6324a4d` until G1-iter4's
  Architect caught it).

## Test suite

- **CI has no pytest-asyncio**: async tests must use the `_aitest`
  decorator (asyncio.run wrapper) — see `tests/test_perf_stability.py`
  / `tests/test_bond_desktop.py`. Verify locally with
  `pytest -p no:asyncio`.
- Async shutdown paths: `asyncio.CancelledError` is a `BaseException`
  since 3.8 — a broad `except Exception` does NOT catch it. Every
  thread that runs `serve_forever()` must catch it explicitly or the
  thread dies with an "Exception in thread" traceback (this shipped
  user-visible stderr spam before `39a1436`).
- CPython's `Server.close()` does not cancel `serve_forever()` while
  handler connections are active; and `BondSession.last_member_left`
  sleeps 60s — teardown drains must cancel() explicitly, and never
  close a loop that `is_running()` (macOS CI caught this, `bdefec5`).
- Full suite runtime ≈ 80-90 s locally; `python -m pytest tests/ -q
  -p no:asyncio`.
- Baseline (after the G1-iter6 fix cycle): local 728 passed +
  9 skipped; CI 737 per POSIX leg (windows 605 passed + 132
  platform skips). A changed skip count on a leg means a test
  silently changed behavior — check before/after when adding tests.
  (One documented environmental variance: `517ad3f`'s ubuntu leg
  showed 736+1 — the bond-desktop loopback-alias skip, runner
  instance variance, not drift.)

## Harness / adversarial process (gates G1 → G1-iter6)

- Enumeration is how defenses die. v5's unset list enumerated trace
  variables and missed the legacy alias `GIT_CURL_VERBOSE` (raw
  credential leaked through the main push in an executed probe); its
  guard enumerated github hosts and missed every SUBDOMAIN
  (`www.github.com` was verified a live anonymous git endpoint for
  the production repo). Pattern-match the defense (unset
  `GIT_TRACE*`, deny host-suffix `*.github.com`) instead of
  enumerating it (G1-iter4-i2 RT M1/C1).
- A remediation claim is itself a finding surface: "the main push
  gained the same token-shape scrub" was documented at v5 but never
  implemented — caught only by the Steward mapping every claim to its
  diff hunk. Verify each claim against the code that allegedly
  changed, not against the record that says it did (G1-iter4-i2
  Steward major #1).
- "Any single override marks a TEST run" was itself the hole: the
  seq-3/seq-5 accident class is a PARTIAL env loss, so the override
  contract must be all-three-or-none (G1-iter4-i2 RT M2) — an
  interface whose failure mode is "silently narrower than intended"
  must fail closed on partial configuration.
- An integrity check that matches by incidence (substring presence)
  will be satisfied by documentation, cross-stage prose, and forged
  examples; bind machine authority to explicit declarations
  (`Stage:` lines, last-line closure, fence-stripping) — the check's
  own forgery suite must enumerate the attack classes the check's
  history actually produced (G1-iter4-i2 RT C2 / Architect M1).
- A test that runs `git commit` without an inline identity works on
  the dev sandbox and breaks every POSIX CI leg (exit 128) — the
  G1-iter3 hermetic-cycle lesson, re-learned at G1-iter4-i2 by the
  new main-push test. EVERY git commit inside a test carries
  `-c user.name=… -c user.email=…`.
- Never run the test suite against a script that has UNCOMMITTED
  edits: the G1-iter4-i2 opt-in probe ran while the backup script sat
  between editor batches — the only (never-committed) state in which
  the gate did not fire — and completed a production checkpoint
  (manifest seq 7, annotated invalid). Test from HEAD: stash first,
  or point the test at a clean clone. Three incidents, three
  variants: env loss (t5, E9c), half-edited script (seq 7) — the
  common factor is a production-capable path reachable by accident.
- Empty-credential URL spellings parse differently from their
  populated forms: `https://@github.com/…`, `github.com:/…` and scp
  `git@github.com:/…` all survived a normalizer whose @-strip needed
  ≥1 char before the `@` and whose port strips needed content after
  the `:` (G1-iter5 RT C1). Test normalizers with EMPTY segments, not
  just populated variants.
- Bash's plain `pwd` is LOGICAL — it preserves symlinks and a leading
  `//` (G1-iter5 RT C2). Path-identity compares use `pwd -P` plus a
  leading-`//` collapse loop, and must cover EVERY operand naming the
  protected path (the repo AND the push target — the un-compared
  operand was the hole, G1-iter5 Architect M1).
- A raw-string guard never sees config-file rewrites: judge a push
  target the way git resolves it (`remote get-url --push` for remote
  names, `ls-remote --get-url` for URL/path operands), or an
  `url.*.insteadOf` rule makes the guard inspect an operand git will
  never use (G1-iter5 RT M1 — a local-looking target reached a real
  `git-receive-pack` against git@github.com in scratch).
- "Machine-covered" must mean MUTATION-covering, not incidence-true:
  the G1-iter5 Architect reverted the ENTIRE env scrub and CI stayed
  green — the guarded helpers absorbed the scrub's removal and the
  marker asserts were vacuous on that git version. Every guarantee
  claim needs a lane whose REMOVAL (not whose trigger) fails a test
  (G1-iter5 Architect M2 — the zero-trace-lines lane is the pattern).
- Re-run ALL verification matrices after any behavior change, not
  just the newest one: the v5 matrix's E4 lanes probed the production
  checkout as a TEST repo and had been silently stale since v6 added
  the production-checkout refusal — an entire gate passed without
  anyone re-running the old matrix (found at G1-iter5; now a fix-cycle
  checklist item in the process doc).
- A mutation probe of a PATH-GUARD lane is production-touching by
  design — and patching the guarded constant ALONE MAKES IT WORSE
  (two incidents, two variants, one corrected rule): the guard-mutated
  copy lets the lane's production-path reference through (the seq-10
  incident — a logical-pwd revert ran the symlink REPO lanes straight
  into production), and a one-sided constant patch NEUTRALIZES the
  refusal for every OTHER lane that still references the real path
  (the seq-1'/2'/13 cluster — the mutC relative-refusal probe patched
  PROD_CHECKOUT but not the test lanes, so the push-target lanes
  pushed a scratch lineage into the production checkout and the
  self-heal merged it). The rule: a guard-mutation probe patches BOTH
  SIDES — the guarded constant AND every test lane that references
  the real protected path — or runs only where the production path
  does not exist (G1-iter5 + G1-iter5-i2, disclosed in the records +
  README anomaly log).
- Judge an operand WHERE IT WILL BE USED, or refuse the ambiguous
  form: the G1-iter5-i2 relative push-target bypass (found
  independently by two agents, executed E2E) existed because the
  guard resolved the target at the repo's cwd while the push executed
  from a temporary worktree — the same operand, two bases, two
  meanings. When a guard cannot evaluate an operand at every base it
  will be used from, the ambiguous form must be refused, not judged
  at a convenient base (v8 refuses relative push targets outright).
- Degenerate spellings come in FAMILIES, and each normalization fix
  must probe the whole family: empty-credential apex forms
  (G1-iter5), then the empty-AUTHORITY forms `https:///github.com/…`
  and multi-@ ssh userinfo `ssh://user@evil.com@github.com/…`
  (G1-iter5-i2 — the @-strip removed only the first segment while
  OpenSSH parses the LAST @). After fixing one empty/degenerate
  segment, enumerate the OTHERS before the next gate does.
- Verify the tool's actual behavior before freezing a residual
  characterization: the frozen residual list claimed pushInsteadOf
  applies to direct URL operands at push time — git does NOT
  (executed at G1-iter5-i2; the phantom was corrected per the list's
  own gate-finding rule). A residual list is only as good as its
  executed facts.

- **Judge the git dir, not the path spelling** (G1-iter6 RT C1,
  executed E2E): every REPO compare judged the operand's spelling
  while git's DISCOVERY can land elsewhere — GIT_DIR env, a
  subdirectory (discovery walks UP into the parent .git), a linked
  worktree (git-common-dir points at the main checkout). A full test
  run landed a checkpoint + self-heal merge inside a stand-in
  production with all guards green. Fix: scrub the discovery-redirection
  env family AND verify `git rev-parse --git-common-dir` physically
  equals the operand's own `.git`; make the protected-path compares
  CONTAINMENT checks (the checkout AND everything under it).
- **Fetch-side resolution is not push-time resolution** (G1-iter6 RT
  C3): `git ls-remote --get-url` applies `insteadOf` but never
  `pushInsteadOf` — and git 2.47.3 DOES rewrite direct path push
  operands at push time (executed: the typed operand landed the
  checkpoint in the reconfigured bare). Fix: refuse the CLASS (any
  pushInsteadOf key in visible config), don't chase the rewrites.
- **META: one spelling's non-exploitability never certifies a
  family** (G1-iter6, the pushInsteadOf case): the G1-iter5-i2
  "verified non-residual, executed" finding was probed via `file://`
  — the ONE form git does not rewrite. When verifying a
  transport-mechanism claim, enumerate the spellings the mechanism
  has (plain path, file://, ssh, scp, remote-name) or verify the
  mechanism at the git source level; a single-lane probe that passes
  proves only that lane.
- **The transport decodes what the guard compares raw**
  (G1-iter6 RT C4): curl percent-decodes the HOST before connecting
  (`%67ithub.com` → CONNECT github.com:443, observed at a local
  sink) — any spelling-based denylist must refuse encodings it
  cannot canonicalize (v9 refuses any `%` in the authority).
- **Helper transports hide the destination inside the operand**
  (G1-iter6 RT C5): `ext::git-receive-pack <path>` EXECUTES as the
  push — URL normalization cannot see the target at all. Refuse the
  transport prefix class (`::`), not the parsed destination.
- **Greedy parsing artifacts are bypasses** (G1-iter6 RT M1/m2): the
  host cut took everything up to the LAST colon-before-slash, so
  `git@github.com:22:repo` read host `github.com:22` (no suffix
  match) while ssh handed off to github.com. Cut at the FIRST colon
  after the last `@`; collapse trailing dots; refuse raw-IP hosts
  (the suffix denylist is a NAME check).
- **Glyph-check rules need adoption dates on their TEETH too**
  (G1-iter6 RT C6): a backdated record carrying a Stage line + a
  terminal closure machine-backed a ☑; multiple Date: headers
  parsed first-match; multi-id glyph lines verified only the first
  id; lookalike glyphs (✅/✔/✓) were invisible; an id-less ◐ skipped;
  a fenced addendum after the closure line hid a retraction. Every
  rule the checker enforces needs: the date semantics, the
  multi-instance case, the lookalike class, and the RAW-text
  terminal position (fence-stripping is for CONTENT rules, never for
  position rules).
- **Derive guarded constants in the lanes, never hand-copy them**
  (G1-iter6 Architect M1, the seq-10 / seq-1'/2'/13 root cause):
  test lanes that hardcode the production path independently of the
  script's constant are exactly the one-sided-patch accident. The
  integrity lanes now parse PROD_CHECKOUT out of the script under
  test — a mutation probe that patches the constant repoints the
  lanes automatically.
- **An exit criterion measured by an artifact nobody must run is not
  a criterion** (G1-iter6 Architect M2): the verification matrices
  lived only in the sandbox home, referenced by repo docs through
  paths that did not resolve in-repo, and went stale twice (v5 E4;
  v8 E20's patch anchor drifted silently). They are repo-resident
  (`harness/backups/matrices/`) and the checklist re-runs all of
  them; the port's exit criterion is now PROPERTY-based, not
  behavior-preserving (decision #19).
- **Probe from the tree that contains the fix — cloning a probe repo
  from HEAD while the fix is uncommitted re-creates the one-sided
  patch structurally** (G1-iter6, sixth incident, fourth variant,
  executed TWICE): the mutation-probe battery cloned from HEAD, got
  the v8 test file with hand-copied production paths, patched the
  script constant — and the stale lanes pushed two junk clusters
  onto production's local branch. The v9 fix (lanes DERIVE the
  constant) was exactly the part the stale clone lacked. Probe
  batteries snapshot the WORKING TREE over a history clone
  (`git clone` + `rsync --delete` overlay), never bare HEAD; anchors
  verify LOUDLY (a missing anchor is an inconclusive probe, never a
  silent skip); and a debug re-run of a failing production-touching
  probe is itself production-touching — re-check containment before
  re-running (the second cluster came from exactly such a debug
  re-run).
- **A local branch polluted by test runs that never reached the
  remote resets to origin — no annotation theater** (G1-iter6): the
  append-only discipline protects the PUSHED audit trail; junk that
  exists only in a local ref (reflog-verified) is removed by reset
  with the incident disclosed in the anomaly log. Annotating would
  PUSH the junk to the remote — the opposite of containment.

- **A control with no terminal state is an escalation ladder**
  (G1-iter6 Architect M3): five consecutive cap-exhaustions, each
  followed by an owner-ordered fresh gate of the same scope, with
  the findings concentrated in one subsystem while the deliverable
  stayed green. The owner-side rule now DEFAULTS to splitting the
  subsystem out (S8) after two consecutive subsystem-concentrated
  caps (process doc, decision #19).

## CI / GitHub

- `ci.yml` runs on push to `main` only → the `sandbox/backups` branch
  is CI-silent by design (backups don't burn runner minutes).
- `release.yml` triggers on tag push `v*`; `env.VERSION`, the release
  body, download-table filenames and the test count inside it must ALL
  be bumped (see `03-release-runbook.md`).
- Windows CI runners: cross-address loopback connects are blocked
  (strong host model) — bonding tests use the primary-address fallback
  (`_plan_bind_ips` strategy 2).
- CI logs print pytest `-q` output only: to know whether a test ran
  or skipped on a runner, compare per-leg skip counts before/after,
  or download job logs and grep.

## Android

- Release APKs must be signed with the release keystore (Play
  Protect flags debug-signed sideloads); handled in `release.yml`.
- Android tests can't run in the sandbox — the `Android compile check`
  CI job is the verification (gradle assembleDebug).

## Theming

- `ui/md3.py` must stay importable without Qt (headless tests import
  it). QColor/QSS wiring stays in `ui/theme.py`.
- md3.py's module constants (DARK_SCHEME/STATE_COLORS/…) are ALWAYS
  brand-seeded (tests + dev preview only); theme.py rebinds its own
  on seed change. Runtime painters must use the accessors
  (`effective_scheme`, `state_color`, `stylesheet_for`) — never import
  the constants by value (they go stale on reseed).
- Legacy legs run Python 3.8: no `match`/`case`, no 3.9+ stdlib
  (`dict |`, `str.removeprefix`); walrus IS fine on 3.8.
  `from __future__ import annotations` is already everywhere.
- Desktop OS-accent detection covers GNOME 47+ / Windows / macOS;
  inside the Flatpak sandbox gsettings reads the sandbox's dconf, not
  the host's (deferred finding #4 — finish-args or portal needed).
  KDE/XFCE fall back to the brand seed.

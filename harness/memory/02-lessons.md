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
- Baseline (after the G1-iter4-i2 fix cycle): local 727 passed +
  9 skipped; CI 736 per POSIX leg (windows 605 passed + 131
  platform skips). A changed skip count on a leg means a test
  silently changed behavior — check before/after when adding tests.

## Harness / adversarial process (gates G1 → G1-iter4-i2)

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

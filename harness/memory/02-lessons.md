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
- Baseline (post Material You): local 712 passed + 6 skipped; CI
  718 per leg (windows 596 + 122 platform skips). A changed skip
  count on a leg means a test silently changed behavior — check
  before/after when adding tests.

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

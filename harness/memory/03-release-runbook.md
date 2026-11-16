# Release Runbook (version bump + ship)

Applies to a normal patch/minor release. Every file below MUST change
in the same commit, or some platform reports a stale version.

## 1. Version bump (example: 0.6.1 → 0.6.2)

| File | Change |
|---|---|
| `pyproject.toml` | `version = "0.6.2"` |
| `proto_clean/__init__.py` | `__version__ = "0.6.2"` |
| `android/app/build.gradle.kts` | `versionCode` +1 **and** `versionName = "0.6.2"` |
| `packaging/macos/Info.plist` | `CFBundleShortVersionString` |
| `packaging/windows/installer.iss` | `#define AppVersion "0.6.2"` |
| `packaging/flatpak/…metainfo.xml` | **append** a new `<release>` entry (keep old ones) |
| `.github/workflows/release.yml` | `env.VERSION`; release-body section; download-table filenames; test count |

## 2. Verify

```bash
pip install -q -e . pytest aioquic dnslib segno zxing-cpp
python -m pytest tests/ -q -p no:asyncio      # full suite green
```

Before tagging, clear **every deferred-findings row whose "Gate
before" is this tag or names this tag's stage** (S2 ≡ the v0.6.3 tag) —
the ledger (`harness/memory/deferred-findings.md`)
is authoritative; do not rely on any list transcribed here (G1-iter3
Steward major #2: the docs had drifted to three different subsets).
At time of writing that set is #1 (Android dynamicColor QA — toggle
in Settings, force-kill, relaunch, verify persisted + honored), #2
(accessor allow-list test), #3 (accent-probe caching, with legacy-leg
behavior for Qt < 6.5), #4 (Flatpak dconf finish-args or documented
limitation), #7 (raw-hex ban in painter runtime paths).

Also REQUIRED before the tag (S2 headline scope, G1-iter3 Steward
major #3 — neither exists yet):

- **SHA-256 checksums**: add checksum generation to the publish job of
  `release.yml` (over all 13 assets) AND a Checksums section in the
  release body — the workflow currently has neither; verify all 13
  assets are covered.
- **WCAG contrast property test**: seed-corpus test asserting ≥ 4.5:1
  on the fixed CONTENT tone pairs (on_X/X, containers, surfaces —
  decorative pairs like outline-vs-surface are excluded by design)
  across ~200 seeds, both modes; it gates the tag. (An ad-hoc
  execution during G1-iter3 passed 4,000 checks with worst 6.42:1, so
  this is a regression gate, not a redesign.)
- **Release body counts**: update "684 tests passing" / "678 automated
  tests" to the current baseline, and the 13 download-table filenames.

## 3. Commit + tag + push

```bash
git add -A && git commit -m "v0.6.2: <headline>"
git push origin main
git tag v0.6.2 && git push origin v0.6.2      # triggers release.yml
```

## 4. Watch the release workflow

```bash
# (sandbox: curl + GitHub API, see memory/02-lessons.md for token
#  extraction) — poll actions runs for the tag; then check
#  https://github.com/maniesh-NR/Proto-Clean/releases/tag/vX.Y.Z
```

12/12 jobs must succeed (4 lantern-box + linux + windows-modern +
2 windows-legacy + 2 macos + android + publish); 13 assets uploaded
(win installer+zip, macos portable zip x2 arch, linux
deb+portable+flatpak bundle, android apk x2).

## 5. Close out

- Update `harness/memory/00-project-state.md` (version, baseline).
- Append a session-log entry.
- Run `PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh "release vX.Y.Z"`
  (v5+: production is OPT-IN — a bare invocation refuses exit 6).

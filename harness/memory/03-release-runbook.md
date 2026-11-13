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
pip install -q -e . pytest
python -m pytest tests/ -q -p no:asyncio      # full suite green
```

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

11/11 jobs must succeed; 13 assets uploaded (win installer+zip,
macos dmg x2 arch, linux deb+portable+flatpak bundle, android apk x2).

## 5. Close out

- Update `harness/memory/00-project-state.md` (version, baseline).
- Append a session-log entry.
- Run `scripts/sandbox_backup.sh "release vX.Y.Z"`.

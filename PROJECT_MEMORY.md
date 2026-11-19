# Project Memory & State

> **Single source of truth — pstack protocol**: deep-first planning → playbook execution → verification contracts → event-driven backup → zero-noise compaction (this file).
> **Session-start drill**: `python3 update_memory.py` → read §1–§3 here + the head of `harness/memory/00-project-state.md` → `git status -sb` → work the playbook → end every plan with `git add <outputs> && git commit && git push`.
> Deep state lives in `harness/memory/` (00-project-state, 01-decisions, 02-lessons, 03-release-runbook, deferred-findings, session-log/, consensus-log/) and `harness/roadmap.md` — indexed here, never duplicated. When updating this file at a milestone: keep decisions, modified files, and next steps; prune failed iterations and raw tool output.
> `update_memory.py` (repo root) refreshes the auto activity section at the end of this file — run it at session start; a post-commit hook refreshes it after every commit.

## 1. Tech Stack & Architecture Rules

- **Project**: Proto Clean (`proto-clean`) **v0.6.2 (released; 684 tests at tag)** — GPL-3.0-or-later clean-room ProtonVPN client; Linux / Windows 7+ / macOS 10.15+ desktop + Android 8+. 25+ protocol engines, Clash/V2ray/sing-box import, multiprotocol chains, link bonding, split tunneling, NAT-PMP, kill switch, custom DNS, IPv6 leak protection, alternative routing.
- **Repo**: `github.com/maniesh-NR/Proto-Clean`, branch `main`. **Origin remote URL embeds a PAT — never print, log, or copy it.** Sandbox has no `gh` CLI → curl + REST API. After a sandbox recycle: `pip install -q -e . pytest` (full deps incl. PySide6), then `import proto_clean` must succeed.
- **Desktop core** (`proto_clean/`, Python ≥ 3.8): `controller.py`; `vpn/` — tunnel, killswitch, monitor, split_tunnel, portforward, `bond*` (bond + balance modes, self-hostable `proto-clean-bond-server` CLI), `samizdat*` (alternative bonding upstream), xray/ovpnconf/wgconf, helper — plus `vpn/protocols/` engines (sslocal, hysteria2, tuic, masque, naive, cloak, tor, warp, obscura, ikev2, coverdtls, boxproto, chain…); `ui/` PySide6 with PySide2-Qt5 fallback (`qtcompat.py`), MD3 theme (`md3.py` HCT tonal palettes + `theme.py`); `platforms/`; `proton/guest`; `netshield/` (9 uBO-parity blocklists); `servers/` region-grouped tree; `account/`; `helper/proto-clean-helper` (privileged).
- **Material You**: desktop dynamic-color seed — brand / system accent / custom hex; OS accent detection (GNOME 47 `accent-color`, Windows DWM `AccentColor`, macOS `AppleHighlightColor`); full-scheme re-derivation + settings persistence. Desktop defaults to brand green, Android 12+ to wallpaper dynamic color (decision #10). Android UI: Jetpack Compose + Material 3, DataStore-backed settings.
- **Android** (`android/`): vpn/ (ProtoCleanVpnService, TunnelManager, NatPmp, DnsFilterVpnService), bond/, protocols/, proton/ (Ed25519/X25519, GuestApi, ProtonWeb), data/ (CredentialsStore, Settings, Blocklists, ConfigCache).
- **Packaging**: Linux deb + portable + Flatpak (`packaging/flatpak/`) · Windows Inno Setup (`packaging/windows/installer.iss`) · macOS portable zip (`packaging/macos/Info.plist`) · Android release-signed APKs. **CI** `.github/workflows/ci.yml` = 7 legs: ubuntu/macos/windows × Python 3.12 + legacy legs (Python 3.8, PySide2-Qt5, PySide6-6.2) + wheel + Android compile. **Release** `release.yml`: tag-push `v*`, 13 assets.
- **Governance harness** (`harness/`): `process/adversarial-consensus.md` (Red Team / Devil's Architect / Ship Steward; 2-iteration cap; owner escalation) + `execution-plan-template.md`; `backups/` manifest + `verify_backup_v5–v10.sh` matrices (121 checks) + backup guard (insteadOf/includeIf file-content refusal, symlinked-.git refusal + git-dir containment, both-directions `_judge_target`, scp redaction, exactly-once PROD derivation); guarded backups via `scripts/sandbox_backup.sh`.

### Hard rules (each cost an incident — do not relearn)
1. `asyncio.CancelledError` subclasses `BaseException` — a broad `except Exception` will not catch it (fix `39a1436`).
2. CI runners have no pytest-asyncio: async tests use the `_aitertest` decorator; local runs add `-p no:asyncio`.
3. Adapter death mid-send → retry the block on the next member WITHOUT advancing the sequence number (fix `53afc6c`).
4. macOS teardown race: the 60 s `last_member_left` grace sleep must not fight `close()` (fix `bdefec5`).
5. Guard-mutation probes are production-touching unless the guarded constant is patched in EVERY real-path lane (both sides) or run where the production path is absent (incidents #4–#6).
6. Probe batteries from stale clones: reset to origin and verify identical; probe from WORKING-TREE snapshots; zero production contact (sixth-incident rule).
7. Never pre-record gate outcomes; record the iteration verdict before entering a fix cycle; disclose incidents in the branch record.

### Version bump checklist (8 places)
`pyproject.toml` · `proto_clean/__init__.py` · `android/app/build.gradle.kts` (versionCode + versionName) · `packaging/macos/Info.plist` · `packaging/windows/installer.iss` · `packaging/flatpak/app.protoclean.ProtoClean.metainfo.xml` · `.github/workflows/release.yml`

## 2. Active Playbook & Todo List

**Objective:** execute the consensus-gated roadmap (`harness/roadmap.md` is authoritative) under adversarial governance — independent consensus required before every stage transition — with an event-driven sandbox → GitHub backup as the mandatory LAST step of every execution plan.

- [x] v0.6.0–v0.6.2 released line + desktop link bonding (retrospectively assessed at G1, zero findings).
- [x] **S1 deliverable — Material You across all OSes** (desktop + Android dynamic color, seed persistence, OS accent detection): shipped green in the first gate iteration and stayed green through all six cap-exhaustions — every exhaustion was decided by backup/harness-subsystem findings, never the deliverable.
- [◐] **S1 closure gate G1 → iter6-i2: NO CONSENSUS at the 2-iteration cap (2026-11-19), escalated to the project owner.** Closing v10 fix cycle in `7a13645` (both-directions judgment, include-class refusal, symlinked-.git refusal, union-prefers-ours audited, scp redaction, exactly-once PROD derivation; matrices v10 E31–E35; decisions #19/#20; ledger #10→S8 + #11/#12). CI run 44462797163 on `7a13645`: 7/7 legs green, per-leg job-log-verified (`4766ff8`). **Owner disposition PENDING — default per decision #19: S1 closes on its deliverable with the harness findings owned by S8, unless the owner orders another gate. No outcome pre-recorded.**
- [x] **pstack protocol bootstrap** (this change): `PROJECT_MEMORY.md` + `update_memory.py` + post-commit hook + backup push.
- [ ] **Owner disposition of the G1-iter6-i2 escalation** (decisions #19/#20) — gates S1 closure and S8 sequencing.
- [ ] **S8 — harness subsystem hardening + Python port**: port the backup merge/alarm/guard core from bash to a tested Python module; property-based exit criterion (TEST runs address only local scratch paths physically disjoint from production; allowlist inversion MANDATED per decision #20; identity single-sourced); ledger rows #9/#10 ride the port. Own gate before S2's stage gate.
- [ ] **S2 — release v0.6.3** (Material You + bonding fixes; runbook `harness/memory/03-release-runbook.md`; adversarial pre-gate REQUIRED — none has run): SHA-256 asset checksums in the release body, WCAG ≥ 4.5 contrast property test (~200 seeds) gating the tag, deferred findings #1–#4 + #7.
- [ ] **S3** bond-server packaging (BLOCKED by S6) · **S4** Android split-tunneling parity · **S5** accessibility pass · **S6** security/threat-model review (helper privileges, DNS surface, blocklist chain, bond-server exposure, account/auth chain) · **S7** legacy-stack sunset decision (Py 3.8 EOL; due by v0.7) — each with its own gate.

**Backup rule (mandatory):** every execution plan ends with `git add <outputs> && git commit && git push` — unpushed work is considered lost. Guarded backups: `scripts/sandbox_backup.sh` + `harness/backups/` matrices.

## 3. Verification Contracts

- **Full suite**: `python -m pytest -q -p no:asyncio` from repo root → **728 passed, 9 skipped, 0 failed** (4 pyOpenSSL deprecation warnings, ~96 s). Re-verified 2026-11-19 after a full env reinstall. CI equivalents: 737 × 4 POSIX legs, 605 + 132 Windows, wheel + Android green.
- **CI green on `main`**: latest confirmed run 44462797163 on `7a13645` (7/7 legs, job-log-verified). Any change must keep the suite green; new features add tests to the baseline.
- **Backup**: `git push` exit 0; `git status -sb` → `## main...origin/main` with no ahead marker.
- **Memory**: `python3 update_memory.py` from repo root exits 0 and refreshes the auto activity section; post-commit hook installed (`.git/hooks/post-commit`, local-only).
- **Governance**: consensus records live only in `harness/memory/consensus-log/`; outcomes are never pre-recorded anywhere.

## 4. `update_memory.py` — provenance & local adaptations

Owner-uploaded 2026-11-19 (verbatim original preserved in the session upload store). Three disclosed one-line adaptations in the repo copy:
1. `"-p"` → `"--stat"` — full patches of the last 3 commits measured 271,010 bytes, violating the zero-noise rule; the stat digest keeps this file ≈ 10 KB.
2. `MEMORY_FILE` anchored to the script's directory — safe from any CWD and inside hooks.
3. Success message reads "commit summaries (stat)" instead of "commit diffs".

Revert = restore those three lines from the upload. The script replaces everything between the auto section's fixed header (see end of file) and end-of-file on every run; the post-commit hook refresh leaves a one-commit lag by design (the refresh rides with the next commit).

## Recent Progress & Git Activity

```diff
### Commit: 4766ff8 - G1-iter6-i2 CI confirmation on the closing commit 7a13645: run 44462797163, all 7 legs success, per-leg job-log-verified - 737x4 POSIX, 605+132 windows, wheel + Android green, exact expectation met (state doc + gate record hedges replaced per the fix-cycle checklist item (b)) (Z User, 2026-11-19)
 harness/memory/00-project-state.md                                 | 7 ++++---
 .../memory/consensus-log/2026-11-19-S1-material-you-gate-iter6.md  | 7 ++++---
 2 files changed, 8 insertions(+), 6 deletions(-)

### Commit: 7a13645 - G1-iter6-i2 (iteration 2, final): NO CONSENSUS at the 2-iteration cap - Red Team BLOCK on two executed E2E criticals (includeIf-conditional pushInsteadOf: the key is invisible to the guard's context on main and materializes at push time in the sandbox/backups worktree, the full TEST checkpoint landed in the unjudged rewrite target rc 0 zero refusals; the fetch side of a named remote never judged: url=<github-spelled> + pushurl=<local bare> fetched from github in TEST mode, 3x CONNECT github.com:443 at a local sink) + symlinked .git major (both identity-compare sides resolve through it) + 3 minors (union prefers the remote same-triple entry, PROD derivation first-match vs bash last-assignment, scp password echo); Architect PWF (the allowlist hedge -> decision #20 mandates the inversion, evaluation as a named S8 pre-gate deliverable; identity derivation unfinished -> exactly-once assertion + derived E30 + loud anchors; the split left stale ledger #10/S6 docs -> corrected; 5 minors incl. the record-before-fix-cycle rule adopted + residual third-party-egress entry added); Steward PWF (CI confirmed exact on 0c4b8f9 run 44458438836 - 737x4 POSIX, 605+132 windows, wheel+Android green; claim map clean; 2 doc minors fixed) - v10 closing fix cycle: BOTH-DIRECTIONS target judgment via _judge_target (push view + fetch view resolved and judged per operand shape - closing RT-C2 AND the URL-operand insteadOf sibling found by orchestrator analysis during the fix and disclosed in the record), include/includeIf class refusal by FILE CONTENT (repo+global+XDG+system), symlinked-.git refusal + git-dir containment, union-prefers-ours with merge_triple_conflicts audited, scp-syntax redaction on all three refusal surfaces, exactly-once PROD derivation; matrix v10 E31-E35 (includeIf refusal + mechanism demo, fetch divergence + clean control, symlink, union patched-TS demo, redaction) + v9 hardening (loud PROD anchors in E25/E29, E30 derives PROD from the script, E30 skip counted loudly); 16 integrity tests extended in place (fetch-divergence + bothclean control, insteadOf push-view, includeIf + include + clean control, symlink, scp redaction, exactly-once derivation); suite 728+9 exact; matrices v5-v10 = 121 checks 0 failed all re-run; mutation probes from WORKING-TREE snapshots (the sixth-incident rule) 5/5 caught, zero production contact, no incident this cycle; escalated to the project owner - per the owner-side default the decision-#19 split is already recorded (S1 may close on its deliverable, the harness findings owned by S8's own gate); no outcome pre-recorded (Z User, 2026-11-19)
 harness/backups/README.md                          |  51 ++++-
 harness/backups/matrices/verify_backup_v10.sh      | 255 +++++++++++++++++++++
 harness/backups/matrices/verify_backup_v9.sh       |  34 ++-
 harness/memory/00-project-state.md                 |  65 ++++--
 harness/memory/01-decisions.md                     |  27 +++
 harness/memory/02-lessons.md                       |  47 +++-
 .../2026-11-19-S1-material-you-gate-iter6.md       | 212 ++++++++++++++++-
 harness/memory/deferred-findings.md                |   6 +-
 .../2026-11-19-g1-iter6-iteration1-fixcycle.md     |  43 ++++
 harness/process/adversarial-consensus.md           |  19 +-
 harness/roadmap.md                                 |  46 +++-
 scripts/sandbox_backup.sh                          | 188 +++++++++++----
 tests/test_harness_integrity.py                    | 165 ++++++++++++-
 13 files changed, 1054 insertions(+), 104 deletions(-)

### Commit: 0c4b8f9 - G1-iter6 iteration 1: NO CONSENSUS (Red Team BLOCK on six executed E2E criticals - git-dir identity redirects, remote-carried relative targets, pushInsteadOf on direct operands falsifying the G1-iter5-i2 frozen-residual claim, percent-encoded hosts, ext:: transports, six glyph-forgery classes; Architect PWF - identity coupling, exit-criterion shape, gate convergence; Steward PWF - the stale closure-log claim) - v9 fix cycle: git-dir identity verification (git-common-dir physical compare) + discovery-redirection env scrub, every-relative + pushInsteadOf-class + transport + percent + raw-IP/trailing-dot refusals, first-colon/post-@ host cut, containment compares on repo AND push target; glyph teeth (backing adoption dates, single-Date, multi-id, lookalike glyphs, id-less in-progress, post-closure fences); integrity lanes DERIVE PROD_CHECKOUT from the script under test (one-sided-patch class structurally impossible); matrices REPO-RESIDENT v5-v9 = 112 checks, all re-run 0 failed; residual list corrected per findings (items 1/2/6); S8 split + decision #19 (property-based port exit criterion) + owner-side escalation rule in process doc; brand seed single-sourced (PROTO_BRAND_SEED); S6 scope + account/auth chain; sixth accidental-checkpoint incident disclosed (stale-clone probe battery, local-only, reset to origin, verified identical) with the probe-from-the-fixed-tree rule; provenance disclosure for the lost iteration-1 verdict texts (context loss mid-cycle; record reconstructed from fix-cycle annotations); suite 728+9 local exact; iteration 2 (final) re-judges this commit - no outcome pre-recorded (Z User, 2026-11-19)
 harness/backups/README.md                          | 127 +++++--
 harness/backups/matrices/verify_backup_v5.sh       | 194 ++++++++++
 harness/backups/matrices/verify_backup_v6.sh       | 200 +++++++++++
 harness/backups/matrices/verify_backup_v7.sh       | 228 ++++++++++++
 harness/backups/matrices/verify_backup_v8.sh       | 196 ++++++++++
 harness/backups/matrices/verify_backup_v9.sh       | 306 ++++++++++++++++
 harness/memory/00-project-state.md                 |  62 ++--
 harness/memory/01-decisions.md                     |  35 +-
 harness/memory/02-lessons.md                       |  98 ++++-
 .../2026-11-19-S1-material-you-gate-iter6.md       | 222 ++++++++++++
 .../session-log/2026-11-19-g1-iter5-closure.md     |  16 +-
 .../2026-11-19-g1-iter6-iteration1-fixcycle.md     |  60 ++++
 .../2026-11-19-g1-iter6-sixth-incident.md          |  69 ++++
 harness/process/adversarial-consensus.md           |  20 +-
 harness/roadmap.md                                 | 145 +++-----
 proto_clean/settings.py                            |   8 +-
 proto_clean/ui/md3.py                              |   5 +
 proto_clean/ui/resources.py                        |   5 +-
 proto_clean/ui/settings_dialog.py                  |   5 +-
 proto_clean/ui/theme.py                            |   5 +-
 scripts/sandbox_backup.sh                          | 326 +++++++++++++----
 tests/test_harness_integrity.py                    | 398 +++++++++++++++++----
 22 files changed, 2418 insertions(+), 312 deletions(-)
```


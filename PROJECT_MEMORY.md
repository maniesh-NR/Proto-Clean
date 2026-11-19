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
- [◐] **S1 closure gate G1 → iter6-i2: NO CONSENSUS at the 2-iteration cap (2026-11-19), escalated to the project owner.** Closing v10 fix cycle in `7a13645` (both-directions judgment, include-class refusal, symlinked-.git refusal, union-prefers-ours audited, scp redaction, exactly-once PROD derivation; matrices v10 E31–E35; decisions #19/#20; ledger #10→S8 + #11/#12). CI run 44462797163 on `7a13645`: 7/7 legs green, per-leg job-log-verified (`4766ff8`). **Owner disposition RECORDED 2026-11-19 (decision #21): the owner instructed "Continue" — no override; the #19 split is operative. S1-closing gate scheduled 2026-11-20+ (scoped: deliverable closure + split boundary correctness + disposition recording — NOT harness re-judgment; the same-date close-withdrawal tie rule forces the later date). No closing-gate outcome pre-recorded.**
- [x] **pstack protocol bootstrap**: `PROJECT_MEMORY.md` + `update_memory.py` + post-commit hook + backup push (`89b1d70`).
- [x] **Owner disposition of the G1-iter6-i2 escalation** — recorded as decision #21 (2026-11-19): split default operative; S1-closing gate scheduled 2026-11-20+; S8 activated.
- [ ] **NEXT · S8 (ACTIVE) — harness subsystem hardening + Python port**: (1) DONE — pre-gate deliverables landed: `harness/backups/allowlist-inversion-evaluation.md` (decision #20b: ADOPT + re-verified consumer inventory) and `harness/process/s8-execution-plan.md`; (2) **PRE-GATE S8-PG1 iteration 1 RAN 2026-11-19 on `82fb63c`: NO CONSENSUS — RT BLOCK (2C/4M/4m) + Architect BLOCK (3C/6M/4m) + Steward PWF (2C/5M/4m)**; converged: the retirement over-reach (pushInsteadOf + include/includeIf are NOT subsumed by the inversion — retained mechanism refusals or a transport-level `protocol.*.allow=never` structural mechanism), the loopback QUARTET (machine-r2 success lane missed by the inventory), the E11 mischaracterization (failing-push redaction; replacement spec re-specified), the STAGE 3/5 cutover contradiction (fix: bash delegates guard to the module AT STAGE 3, split 3a parity / 3b inversion), no module contract, unpinned containment primitive, Seq-field spec, 3.8 floor + import seam, coverage arithmetic, STAGE-6 cap contingency; record: `harness/memory/consensus-log/2026-11-19-s8-pre-gate.md`; (3) NEXT — remediation cycle amends both deliverable documents per the record's resolution list (own commit after the record), then iteration 2 re-judges; the port itself (merge/alarm/guard core to a tested Python module) starts only on consensus. Own gate before S2's stage gate.
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

Revert = restore those three lines from the upload. The script replaces everything between the auto section's fixed header (see end of file) and end-of-file on every run; the post-commit hook refresh leaves a one-commit lag by design (the refresh rides with the next commit). The hook is fail-soft since 2026-11-19 (post-backup hardening): it no-ops in worktrees where the script is absent — the backup script's temp worktree (`sandbox/backups` branch commit, manifest entry #19) fired the hook and printed a python3 file-not-found before the guard; harmless to the backup, both pushes ok.

## Recent Progress & Git Activity

```diff
### Commit: 82fb63c - S8 pre-gate deliverables: allowlist-inversion ADOPT evaluation (consumer inventory re-verified) + S8 execution plan; post-commit hook hardened fail-soft (Z User, 2026-11-19)
 PROJECT_MEMORY.md                                  |  28 ++----
 harness/backups/allowlist-inversion-evaluation.md  | 105 +++++++++++++++++++++
 harness/memory/00-project-state.md                 |   7 +-
 .../2026-11-19-owner-disposition-s8-activation.md  |  39 +++++++-
 harness/process/s8-execution-plan.md               |  79 ++++++++++++++++
 5 files changed, 236 insertions(+), 22 deletions(-)

### Commit: 5e70fae - G1-iter6-i2 owner disposition recorded (decision #21): split default operative - S1 closing gate scheduled 2026-11-20+, S8 activated (Z User, 2026-11-19)
 PROJECT_MEMORY.md                                  | 38 ++++-----------
 harness/memory/00-project-state.md                 | 38 ++++++++++-----
 harness/memory/01-decisions.md                     | 34 +++++++++++++
 .../2026-11-19-owner-disposition-s8-activation.md  | 57 ++++++++++++++++++++++
 harness/roadmap.md                                 | 17 +++++--
 5 files changed, 137 insertions(+), 47 deletions(-)

### Commit: 89b1d70 - pstack bootstrap: PROJECT_MEMORY.md root state memory + update_memory.py activity sync (Z User, 2026-11-19)
 PROJECT_MEMORY.md | 111 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
 update_memory.py  |  68 +++++++++++++++++++++++++++++++++
 2 files changed, 179 insertions(+)
```


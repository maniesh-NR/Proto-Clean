#!/usr/bin/env bash
# G1-iter4 fix-cycle verification matrix for scripts/sandbox_backup.sh (v5).
#
# Complements tests/test_harness_integrity.py, which already machine-covers:
#   * production opt-in (default refusal exit 6 + conflicting-mode exit 2)
#   * all github-spelling refusals (case/:443///ssh/scp/trailing-dot/
#     credentialed/other-repo + a remote NAME resolving to scp) + clean lane
#   * branch-push alarm under an unreachable remote (run1 rc0, run2 exit 7)
#   * shaped-name exclusion on BOTH surfaces + state.json counts
#   * hermetic fresh-create / append / planted-secret abort
# This matrix covers the rest: divergence-merge scrubbing (poisoned
# remote manifest + out-of-harness remote file), GIT_TRACE2 hygiene,
# canary-sabotage regression, input validation, rsync -c, untracked
# content-secret regression, hook-rejection alarm regression.
#
# All fake tokens are built at runtime (no literals). Everything stays
# under /tmp/pc-v5-verify; production is never contacted.
set -u
# G1-iter6 (Architect major #2): matrices are REPO-RESIDENT (CI-visible) — ROOT derives from this file's location so the matrix runs against ANY checkout (the sandbox-home copies are retired)
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v5-verify
rm -rf "$S"; mkdir -p "$S"
FAKE="ghp_$(printf 'a%.0s' $(seq 1 36))"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

# env for every run: neutralized git config (identity fallback path)
base_env() {
  printf 'GIT_CONFIG_GLOBAL=/dev/null\nGIT_CONFIG_SYSTEM=/dev/null\n'
}

# new_lane <name>: clone + bare + home under $S/<name>; echoes the dir
new_lane() {
  local d="$S/$1"
  git clone -q "$ROOT" "$d/clone"
  git init -q --bare "$d/bare.git"
  git -C "$d/clone" remote set-url origin "$d/bare.git"
  mkdir -p "$d/home/scripts"
  echo "print('ok')" > "$d/home/scripts/ok.py"
  echo "$d"
}

# run_bk <dir> <push-target> <message> [K=V extra env...]
run_bk() {
  local d="$1" tgt="$2" msg="$3"; shift 3
  ( export $(base_env) PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
      PC_BACKUP_PUSH_REMOTE="$tgt" "$@"
    cd "$d/clone" && bash "$SCRIPT" "$msg" )
}

echo "=== E1: divergence — poisoned remote manifest is scrubbed, no brick ==="
d1="$(new_lane e1)"
d="$d1"
run_bk "$d" "$d/bare.git" "e1 run1" >/dev/null 2>&1 || echo "  (run1 note rc=$?)"
# machine A advances locally against a second bare (A ahead of bare1)
git init -q --bare "$d/bare2.git"
run_bk "$d" "$d/bare2.git" "e1 run2 (to bare2)" >/dev/null 2>&1
# machine B pushes a poisoned manifest entry to bare1
git clone -q "$d/bare.git" "$d/cloneB" 2>/dev/null
git -C "$d/cloneB" checkout -q sandbox/backups 2>/dev/null || git -C "$d/cloneB" checkout -q -b sandbox/backups origin/sandbox/backups
python3 - "$d/cloneB/harness/backups/manifest.json" "$FAKE" <<'PY'
import json, sys
path, fake = sys.argv[1], sys.argv[2]
doc = json.load(open(path))
doc["backups"].append({"seq": 99, "timestamp": "2026-11-15T00:00:00Z",
                        "trigger": "event", "message": "poison " + fake,
                        "git_head": "deadbee", "git_branch": "main",
                        "main_push": "ok"})
json.dump(doc, open(path, "w"), indent=2)
PY
git -C "$d/cloneB" add harness/backups/manifest.json
git -C "$d/cloneB" -c user.name=B -c user.email=b@x commit -qm "poison manifest"
git -C "$d/cloneB" push -q origin sandbox/backups 2>/dev/null
# machine A reconciles against bare1
OUT="$(run_bk "$d" "$d/bare.git" "e1 run3 (reconcile)" 2>&1)"; RC=$?
if [ "$RC" = 0 ]; then ok "E1 reconcile run rc 0"; else bad "E1 reconcile rc=$RC: $OUT"; fi
PUSHED="$(git -C "$d/bare.git" show sandbox/backups:harness/backups/manifest.json)"
if printf '%s' "$PUSHED" | grep -q "$FAKE"; then bad "E1 FAKE token in pushed manifest"; else ok "E1 no token in pushed manifest"; fi
if printf '%s' "$PUSHED" | grep -q '\[REDACTED\]'; then ok "E1 scrubbed marker present in message"; else bad "E1 no [REDACTED] marker"; fi
if printf '%s' "$PUSHED" | grep -q 'merge_scrubbed_entries'; then ok "E1 scrub count marker recorded"; else bad "E1 no scrub count marker"; fi
OUT2="$(run_bk "$d" "$d/bare.git" "e1 run4 (no brick)" 2>&1)"; RC2=$?
if [ "$RC2" = 0 ]; then ok "E1 next run appends cleanly (no exit-4 brick)"; else bad "E1 next run rc=$RC2: $OUT2"; fi

echo "=== E2: divergence — remote file OUTSIDE harness/ never enters the tree ==="
d2="$(new_lane e2)"
d="$d2"
run_bk "$d" "$d/bare.git" "e2 run1" >/dev/null 2>&1
git init -q --bare "$d/bare2.git"
run_bk "$d" "$d/bare2.git" "e2 run2 (to bare2)" >/dev/null 2>&1
git clone -q "$d/bare.git" "$d/cloneB" 2>/dev/null
git -C "$d/cloneB" checkout -q -b sandbox/backups origin/sandbox/backups
printf 'token %s\n' "$FAKE" > "$d/cloneB/POISON.txt"
git -C "$d/cloneB" add POISON.txt
git -C "$d/cloneB" -c user.name=B -c user.email=b@x commit -qm "add poison root file"
git -C "$d/cloneB" push -q origin sandbox/backups 2>/dev/null
OUT="$(run_bk "$d" "$d/bare.git" "e2 run3 (reconcile)" 2>&1)"; RC=$?
if [ "$RC" = 0 ]; then ok "E2 reconcile run rc 0"; else bad "E2 reconcile rc=$RC: $OUT"; fi
if git -C "$d/bare.git" show sandbox/backups:POISON.txt >/dev/null 2>&1; then
  bad "E2 remote root file entered the merged tree"
else
  ok "E2 remote-only file outside harness/ absent from merged tree"
fi
if git -C "$d/bare.git" show sandbox/backups:harness/backups/manifest.json | grep -q "$FAKE"; then
  bad "E2 token reachable on the branch"
else
  ok "E2 no token anywhere on the pushed branch"
fi

echo "=== E3: GIT_TRACE2 family — no credential in output ==="
d3="$(new_lane e3)"
d="$d3"
OUT="$(run_bk "$d" "https://u:${FAKE}@127.0.0.1:1/x.git" "e3 trace2" \
        GIT_TRACE2=1 GIT_TRACE2_EVENT=1 GIT_TRACE2_PERF=1 2>&1)"; RC=$?
if printf '%s' "$OUT" | grep -q "$FAKE"; then bad "E3 fake credential leaked under GIT_TRACE2 (rc=$RC)"; else ok "E3 no credential in output under GIT_TRACE2=1"; fi
if printf '%s' "$OUT" | grep -q '://u:'; then bad "E3 userinfo URL fragment leaked"; else ok "E3 no userinfo fragment"; fi
if [ "$RC" = 0 ]; then ok "E3 run itself completed rc 0 (push kept locally)"; else bad "E3 unexpected rc=$RC"; fi

echo "=== E4: canary self-test sabotage regression ==="
# (lane fixed at G1-iter5: the v5-era lanes ran with PC_BACKUP_REPO=$ROOT
#  — the PRODUCTION checkout — which v6's production-checkout refusal
#  correctly refuses exit 6 before the self-test runs; the stale lanes
#  had not been re-run since v6. The sabotage now runs against a
#  scratch clone, as every other lane always has.)
d4="$S/e4"; mkdir -p "$d4"
git clone -q "$ROOT" "$d4/clone"
sed 's/gho_\[A-Za-z0-9\]{30,}/ghx_[A-Za-z0-9]{30,}/' "$SCRIPT" > "$d4/sabotaged1.sh"
( export $(base_env) PC_BACKUP_REPO="$d4/clone" PC_SANDBOX_HOME="$d4" \
    PC_BACKUP_PUSH_REMOTE="$d4/nope.git"
  cd "$d4/clone" && bash "$d4/sabotaged1.sh" "sabotage canary" ) > "$d4/out1" 2>&1
RC=$?
if [ "$RC" = 5 ]; then ok "E4 pattern sabotage (gho_ branch) exits 5"; else bad "E4 pattern sabotage rc=$RC"; fi
sed 's/grep -rEn/grep -rn/' "$SCRIPT" > "$d4/sabotaged2.sh"
( export $(base_env) PC_BACKUP_REPO="$d4/clone" PC_SANDBOX_HOME="$d4" \
    PC_BACKUP_PUSH_REMOTE="$d4/nope.git"
  cd "$d4/clone" && bash "$d4/sabotaged2.sh" "sabotage flags" ) > "$d4/out2" 2>&1
RC=$?
if [ "$RC" = 5 ]; then ok "E4 flag drift (-rEn -> -rn) exits 5"; else bad "E4 flag drift rc=$RC"; fi

echo "=== E5: input validation ==="
d5="$S/e5"; mkdir -p "$d5"
git init -q --bare "$d5/bare.git"
( export $(base_env) PC_BACKUP_REPO="$d5/bare.git" PC_SANDBOX_HOME="$d5" \
    PC_BACKUP_PUSH_REMOTE="$d5/bare.git"
  cd / && bash "$SCRIPT" "bare repo" ) > "$d5/out1" 2>&1
RC=$?
if [ "$RC" = 2 ] && grep -q "working-tree" "$d5/out1"; then ok "E5 bare repo refused exit 2 with message"; else bad "E5 bare repo rc=$RC"; fi
git init -q "$d5/unborn"
( export $(base_env) PC_BACKUP_REPO="$d5/unborn" PC_SANDBOX_HOME="$d5" \
    PC_BACKUP_PUSH_REMOTE="$d5/bare.git"
  cd / && bash "$SCRIPT" "unborn" ) > "$d5/out2" 2>&1
RC=$?
if [ "$RC" = 2 ] && grep -q "no HEAD commit" "$d5/out2"; then ok "E5 unborn HEAD refused exit 2 with message"; else bad "E5 unborn rc=$RC"; fi

echo "=== E6: rsync -c — same-size edit lands in the SAME run ==="
d6="$(new_lane e6)"
d="$d6"
python3 - "$d/clone/harness/roadmap.md" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
assert "\u2610" in s, "roadmap has no queued glyph to flip"
open(p, "w", encoding="utf-8").write(s.replace("\u2610", "\u25cb", 1))
PY
run_bk "$d" "$d/bare.git" "e6 same-size edit" >/dev/null 2>&1
BR="$(git -C "$d/bare.git" show sandbox/backups:harness/roadmap.md)"
if printf '%s' "$BR" | grep -q $'\u25cb'; then ok "E6 same-size edit captured in the same checkpoint (-c)"; else bad "E6 same-size edit skipped"; fi

echo "=== E7: untracked content secret in harness/memory/ still aborts ==="
d7="$(new_lane e7)"
d="$d7"
printf 'note %s\n' "$FAKE" > "$d/clone/harness/memory/untracked-note.md"
TIP_BEFORE="$(git -C "$d/bare.git" rev-parse --verify refs/heads/sandbox/backups 2>/dev/null || echo none)"
OUT="$(run_bk "$d" "$d/bare.git" "e7 untracked secret" 2>&1)"; RC=$?
TIP_AFTER="$(git -C "$d/bare.git" rev-parse --verify refs/heads/sandbox/backups 2>/dev/null || echo none)"
if [ "$RC" = 4 ]; then ok "E7 untracked harness/memory secret aborts exit 4"; else bad "E7 rc=$RC"; fi
if [ "$TIP_BEFORE" = "$TIP_AFTER" ]; then ok "E7 remote untouched"; else bad "E7 remote moved"; fi

echo "=== E8: hook-rejection alarm regression (fetch OK, push rejected) ==="
d8="$(new_lane e8)"
d="$d8"
printf '#!/bin/sh\nexit 1\n' > "$d/bare.git/hooks/pre-receive"
chmod +x "$d/bare.git/hooks/pre-receive"
OUT1="$(run_bk "$d" "$d/bare.git" "e8 hook 1" 2>&1)"; RC1=$?
OUT2="$(run_bk "$d" "$d/bare.git" "e8 hook 2" 2>&1)"; RC2=$?
if [ "$RC1" = 0 ]; then ok "E8 first rejected push recorded (rc 0)"; else bad "E8 run1 rc=$RC1: $OUT1"; fi
if [ "$RC2" = 7 ] && printf '%s' "$OUT2" | grep -q "BRANCH-PUSH-ALARM"; then ok "E8 second consecutive rejection alarms exit 7"; else bad "E8 run2 rc=$RC2"; fi
rm -f "$d/bare.git/hooks/pre-receive"

echo
echo "=== matrix result: $PASS passed, $FAIL failed ==="
rm -rf "$S"
[ "$FAIL" = 0 ]

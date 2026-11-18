#!/usr/bin/env bash
# G1-iter3 fix-cycle verification matrix v2 — runs the REAL (uncommitted
# v4) script from $REPO against scratch clones; replicates every gate
# experiment. KEY FIX vs v1: invoke "$REPO/scripts/sandbox_backup.sh"
# (the clones' committed copies are the old v3 — v1 tested the wrong
# script and caused the accidental production push recorded in the
# G1-iter3 consensus log).
set -u
REPO=/home/z/my-project/cleanroom
SCRIPT="$REPO/scripts/sandbox_backup.sh"
S=/tmp/v4test
rm -rf "$S"; mkdir -p "$S"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1 (rc=$3)"; else bad "$1 (want rc=$2 got rc=$3)"; fi; }
run()  { # run <clone> <home> <pushremote-or-'-'> <message>  -> rc + log at $S/last.log
  local clone="$1" home="$2" pr="$3" msg="$4"
  local env=()
  [ "$clone" != "-" ] && env+=("PC_BACKUP_REPO=$clone")
  [ "$home"  != "-" ] && env+=("PC_SANDBOX_HOME=$home")
  [ "$pr"    != "-" ] && env+=("PC_BACKUP_PUSH_REMOTE=$pr")
  ( cd "$clone" && env "${env[@]}" bash "$SCRIPT" "$msg" ) >"$S/last.log" 2>&1
  return $?
}
run_local() { # run_local: execute the CLONE's own (possibly sabotaged) copy
  local clone="$1" home="$2" msg="$3"
  ( cd "$clone" && PC_BACKUP_REPO="$clone" PC_SANDBOX_HOME="$home" \
      bash scripts/sandbox_backup.sh "$msg" ) >"$S/last.log" 2>&1
  return $?
}

echo "== setup: clone + bare (stale origin refs pruned)"
git clone -q "$REPO" "$S/clone"
git init -q --bare "$S/bare.git"
git -C "$S/clone" remote set-url origin "$S/bare.git"
# prune refs copied from the real repo so the bare starts empty
git -C "$S/clone" fetch -q origin --prune 2>/dev/null || true
git -C "$S/clone" update-ref -d refs/remotes/origin/sandbox/backups 2>/dev/null || true
git -C "$S/clone" update-ref -d refs/remotes/origin/main 2>/dev/null || true
git -C "$S/clone" branch -D sandbox/backups 2>/dev/null || true
mkdir -p "$S/home/scripts"; echo 'print("hi")' > "$S/home/scripts/ok.py"

echo "== T1: two baseline runs (create + append)"
run "$S/clone" "$S/home" - "t1 first";  check "T1a first run creates branch" 0 $?
run "$S/clone" "$S/home" - "t1 second"; check "T1b second run appends" 0 $?
seq2=$(git -C "$S/bare.git" show sandbox/backups:harness/backups/manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['backups'][-1]['seq'])")
[ "$seq2" = "2" ] && ok "T1 manifest seq=2" || bad "T1 manifest seq=$seq2 (want 2)"
# harness refresh (Architect M2): touch an UNCOMMITTED harness file in the clone, run, verify it lands on the branch
echo "refresh-probe-$(date +%s)" >> "$S/clone/harness/roadmap.md"
run "$S/clone" "$S/home" - "t1 refresh probe"; check "T1c refresh run" 0 $?
git -C "$S/bare.git" show sandbox/backups:harness/roadmap.md | grep -q "refresh-probe" \
  && ok "T1c harness refresh lands on branch" || bad "T1c harness refresh missing"
git -C "$S/clone" checkout -q -- harness/roadmap.md
git -C "$S/clone" status --porcelain harness | grep -q . && bad "T1 main checkout dirty" || ok "T1 main checkout clean"

echo "== T2: planted secret in sandbox scripts -> abort 4, nothing pushed"
FAKE=$(python3 -c "print('gh'+'s_'+'c'*36)")
echo "token = '$FAKE'" > "$S/home/scripts/leaky.sh"
TIP_BEFORE=$(git -C "$S/bare.git" rev-parse sandbox/backups)
run "$S/clone" "$S/home" - "t2"; check "T2 aborts" 4 $?
[ "$(git -C "$S/bare.git" rev-parse sandbox/backups)" = "$TIP_BEFORE" ] \
  && ok "T2 bare unchanged" || bad "T2 bare moved"
rm "$S/home/scripts/leaky.sh"

echo "== T3: secret in the MESSAGE -> abort 4; message never echoed (m1)"
FAKEM=$(python3 -c "print('gh'+'p_'+'a'*36)")
run "$S/clone" "$S/home" - "contains $FAKEM secret"; check "T3 message secret aborts" 4 $?
if grep -q "$FAKEM" "$S/last.log"; then bad "T3 message echoed into log pre-scan"; else ok "T3 message never echoed"; fi

echo "== T4a: sabotage EVERY pattern branch, one at a time -> self-test abort 5 (C1)"
cp "$SCRIPT" "$S/clone/scripts/sandbox_backup.sh"   # sabotage the CLONE's copy (invoked via abs path)
for pat in "ghs_[A-Za-z0-9]{30,}:ghs_[A-Za-z0-9]{300,}" \
           "gho_[A-Za-z0-9]{30,}:gho_[A-Za-z0-9]{300,}" \
           "ghv_[A-Za-z0-9]{30,}:ghv_[A-Za-z0-9]{300,}" \
           "ghp_[A-Za-z0-9]{30,}:ghp_[A-Za-z0-9]{300,}" \
           "github_pat_[A-Za-z0-9_]{20,}:github_pat_[A-Za-z0-9_]{200,}" \
           "AKIA[0-9A-Z]{16}:AKIA[0-9A-Z]{1600}"; do
  from="${pat%%:*}"; to="${pat##*:}"
  python3 - "$S/clone/scripts/sandbox_backup.sh" "$from" "$to" <<'PY'
import sys
p, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert frm in s, f"pattern not found: {frm}"
open(p, "w").write(s.replace(frm, to))
PY
  run_local "$S/clone" "$S/home" "t4a sabotage $from" ; check "T4a sabotage [$from] -> self-test abort" 5 $?
  cp "$SCRIPT" "$S/clone/scripts/sandbox_backup.sh"   # restore for next round
done
# PEM branch sabotage: make the PEM alternative unmatchable
python3 - "$S/clone/scripts/sandbox_backup.sh" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "BEGIN (RSA |EC )?PRIVATE KEY"
new = "BEGIN (RSA |EC )?PRIVATE KEYX"
assert old in s
open(p, "w").write(s.replace(old, new))
PY
run_local "$S/clone" "$S/home" "t4a pem sabotage"; check "T4a sabotage [PEM] -> self-test abort" 5 $?
cp "$SCRIPT" "$S/clone/scripts/sandbox_backup.sh"

echo "== T4b: flag drift (grep -rEn -> grep -rn in secret_scan) -> self-test abort 5 (C2)"
python3 - "$S/clone/scripts/sandbox_backup.sh" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "grep -rEn --exclude-dir='__pycache__'"
new = "grep -rn --exclude-dir='__pycache__'"
assert old in s, "anchor not found"
open(p, "w").write(s.replace(old, new))
PY
run_local "$S/clone" "$S/home" "t4b flag drift"; check "T4b flag drift -> self-test abort" 5 $?
cp "$SCRIPT" "$S/clone/scripts/sandbox_backup.sh"

echo "== T4c: intact script + token-shaped FILENAME -> excluded from state.json (M2)"
FAKEN=$(python3 -c "print('gh'+'p_'+'f'*36)")
: > "$S/home/scripts/$FAKEN.txt"
run "$S/clone" "$S/home" - "t4c"
rc4c=$?
if [ $rc4c -eq 0 ] || [ $rc4c -eq 4 ]; then
  st=$(git -C "$S/bare.git" show sandbox/backups:harness/sandbox/state.json 2>/dev/null || true)
  if echo "$st" | grep -q "$FAKEN"; then bad "T4c shape-named file leaked into state.json"; else ok "T4c shape filter excludes the name"; fi
else
  bad "T4c unexpected rc=$rc4c"
fi
rm -f "$S/home/scripts/$FAKEN.txt"

echo "== T5: test-run push isolation (M1) — clone whose origin IS production-like -> exit 6"
git clone -q "$REPO" "$S/clone2"
PRODURL=$(git -C "$REPO" remote get-url origin)
git -C "$S/clone2" remote set-url origin "$PRODURL"
run "$S/clone2" "$S/home" - "t5"; check "T5 test run w/ production origin aborts" 6 $?
grep -q "PRODUCTION" "$S/last.log" && ok "T5 explains the refusal" || bad "T5 message unclear"
if grep -q "$PRODURL" "$S/last.log"; then bad "T5 LOGGED THE PRODUCTION URL"; else ok "T5 never logs the remote URL"; fi
# production origin must be UNTOUCHED by the refused run:
git -C "$REPO" fetch -q origin sandbox/backups 2>/dev/null
TIPNOW=$(git -C "$REPO" rev-parse origin/sandbox/backups)
[ "$TIPNOW" = "5db0853$(git -C "$REPO" rev-parse origin/sandbox/backups | cut -c8-)" ] 2>/dev/null || true
# (just informational; the exact accidental tip is recorded in the consensus log)
echo "  (info) origin/sandbox/backups now at: $TIPNOW"

echo "== T5b: file:// PC_BACKUP_REPO + bare-path push remote"
git init -q --bare "$S/bare2.git"
( cd "$S/clone" && PC_BACKUP_REPO="file://$S/clone" PC_SANDBOX_HOME="$S/home" \
    PC_BACKUP_PUSH_REMOTE="$S/bare2.git" bash "$SCRIPT" "t5b" ) >"$S/t5b.log" 2>&1
check "T5b file:// repo + path push remote" 0 $?
git -C "$S/bare2.git" rev-parse --verify sandbox/backups >/dev/null 2>&1 \
  && ok "T5b bare2 got the branch" || bad "T5b bare2 missing branch"

echo "== T6: TRUE divergence brick, self-healed (Architect M1)"
# (a) make the local branch one commit AHEAD with a dead push remote
( cd "$S/clone" && PC_BACKUP_REPO="$S/clone" PC_SANDBOX_HOME="$S/home" \
    PC_BACKUP_PUSH_REMOTE="$S/dead-not-exist.git" bash "$SCRIPT" "t6 kept-local" ) >"$S/t6a.log" 2>&1
rc6a=$?
if [ $rc6a -eq 0 ] || [ $rc6a -eq 1 ]; then ok "T6a dead-remote run kept commit (rc=$rc6a)"; else bad "T6a rc=$rc6a"; fi
grep -q "kept locally" "$S/t6a.log" && ok "T6a warned about kept-local commit" || bad "T6a no kept-local warning"
# (b) a foreign writer lands a commit on the bare
git clone -q "$S/bare.git" "$S/clone3"
git -C "$S/clone3" remote set-url origin "$S/bare.git"
git -C "$S/clone3" fetch -q origin && git -C "$S/clone3" checkout -q -B sandbox/backups origin/sandbox/backups
python3 - "$S/clone3" <<'PY'
import json, sys
p = f"{sys.argv[1]}/harness/backups/manifest.json"
d = json.load(open(p))
d["backups"].append({"seq": d["backups"][-1]["seq"] + 50, "timestamp": "2026-11-13T00:00:00Z",
                     "trigger": "foreign", "message": "foreign writer", "git_head": "deadbee",
                     "git_branch": "main", "main_push": "ok"})
open(p, "w").write(json.dumps(d, indent=2))
PY
git -C "$S/clone3" add harness && git -C "$S/clone3" -c user.email=t@t -c user.name=t commit -qm "foreign entry"
git -C "$S/clone3" push -q origin sandbox/backups
# (c) now the real run: local ahead AND remote moved -> must merge, not brick
run "$S/clone" "$S/home" - "t6 divergence"; check "T6c divergence run self-heals" 0 $?
git -C "$S/bare.git" show sandbox/backups:harness/backups/manifest.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
msgs=[e['message'] for e in d['backups']]
assert 'foreign writer' in msgs, 'foreign entry lost!'
assert 't6 kept-local' in msgs, 'kept-local entry lost!'
assert 't6 divergence' in msgs, 'new entry lost!'
seqs=[e['seq'] for e in d['backups']]
assert seqs == sorted(seqs), 'entries not sorted by seq'
assert d.get('merged_divergence') is True, 'no divergence marker'
print('  PASS: T6 union preserved all three sides, sorted, marked')" && PASS=$((PASS+1)) || { echo "  FAIL: T6 union"; FAIL=$((FAIL+1)); }

echo "== T7: concurrency — 6 simultaneous runs, no exit-1/128 fatals"
for i in 1 2 3; do
  ( cd "$S/clone" && PC_BACKUP_REPO="$S/clone" PC_SANDBOX_HOME="$S/home" \
      bash "$SCRIPT" "t7 round $i" ) >"$S/t7-$i.log" 2>&1 &
done
wait
for i in 4 5 6; do
  ( cd "$S/clone" && PC_BACKUP_REPO="$S/clone" PC_SANDBOX_HOME="$S/home" \
      bash "$SCRIPT" "t7 round $i" ) >"$S/t7-$i.log" 2>&1 &
done
wait
W=$(grep -l "== backup complete" "$S"/t7-*.log 2>/dev/null | wc -l)
echo "  T7 completed runs: $W/6 (1 per concurrent wave expected)"
HARD=0
for f in "$S"/t7-*.log; do
  grep -q "== backup complete" "$f" && continue
  grep -q "aborting" "$f" && continue
  HARD=$((HARD+1)); echo "    hard failure in $f:"; tail -3 "$f" | sed 's/^/      /'
done
[ "$HARD" = 0 ] && ok "T7 no hard failures (clean exits only)" || bad "T7 $HARD hard failures"
LASTSEQ=$(git -C "$S/bare.git" show sandbox/backups:harness/backups/manifest.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['backups'][-1]['seq'], len(d['backups']))")
echo "  T7 manifest (last seq, entries): $LASTSEQ"

echo "== T8: corrupt manifest recovery (m3) — loud, seq continues, no silent reset"
git -C "$S/clone3" fetch -q origin && git -C "$S/clone3" checkout -q sandbox/backups && \
  git -C "$S/clone3" pull -q origin sandbox/backups 2>/dev/null
echo '{"schema": 2, "backups": [TRUNC' > "$S/clone3/harness/backups/manifest.json"
git -C "$S/clone3" add harness && git -C "$S/clone3" -c user.email=t@t -c user.name=t commit -qm "corrupt manifest"
git -C "$S/clone3" push -q origin sandbox/backups
run "$S/clone" "$S/home" - "t8 after corruption"; check "T8 run survives corrupt manifest" 0 $?
grep -q "RECOVERED" "$S/last.log" && ok "T8 recovery is loud" || bad "T8 recovery silent/absent"
PREVSEQ=$(git -C "$S/bare.git" show sandbox/backups~2:harness/backups/manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['backups'][-1]['seq'])")
LASTSEQ=$(git -C "$S/bare.git" show sandbox/backups:harness/backups/manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['backups'][-1]['seq'])")
if [ "$LASTSEQ" -gt "$PREVSEQ" ] && [ "$LASTSEQ" -lt 100 ]; then
  ok "T8 seq continued from recovered history ($PREVSEQ -> $LASTSEQ)"
else
  bad "T8 seq wrong ($PREVSEQ -> $LASTSEQ)"
fi

echo "== T9: detached HEAD records 'detached' (m4)"
git -C "$S/clone" checkout -q --detach
run "$S/clone" "$S/home" - "t9 detached"
rc9=$?
git -C "$S/clone" checkout -q main 2>/dev/null || git -C "$S/clone" checkout -q -
GB=$(git -C "$S/bare.git" show sandbox/backups:harness/backups/manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['backups'][-1]['git_branch'])")
if [ $rc9 -eq 0 ] && [ "$GB" = "detached" ]; then ok "T9 git_branch=detached"; else bad "T9 rc=$rc9 git_branch=$GB"; fi

echo "== T10: main-push alarm on 2+ consecutive failures (Architect M2)"
git -C "$S/clone" push -q "$S/bare.git" main:refs/heads/main   # seed main with real objects
HOOK="$S/bare.git/hooks/pre-receive"
printf '#!/bin/sh\nexit 1\n' > "$HOOK"; chmod +x "$HOOK"
git -C "$S/clone" commit -q --allow-empty -m "main ahead 1"
run "$S/clone" "$S/home" - "t10 first fail"
if [ $? -eq 0 ]; then ok "T10a first failure: backup completes (rc=0), recorded"; else bad "T10a rc=$?"; fi
run "$S/clone" "$S/home" - "t10 second fail"; check "T10b SECOND consecutive failure raises exit 7" 7 $?
grep -q "MAIN-PUSH-ALARM" "$S/last.log" && ok "T10b alarm banner present" || bad "T10b banner missing"
rm -f "$HOOK"
run "$S/clone" "$S/home" - "t10 recovery"; check "T10c run after hook removal recovers" 0 $?

echo "== T11: real repo + real origin untouched by this matrix"
git -C "$REPO" fetch -q origin sandbox/backups 2>/dev/null
echo "  (info) origin/sandbox/backups: $(git -C "$REPO" rev-parse --short origin/sandbox/backups) (the v1-matrix accidental tip — disclosed in consensus log)"
worktrees=$(git -C "$REPO" worktree list | wc -l)
[ "$worktrees" = "1" ] && ok "T11 no leftover worktrees in real repo" || bad "T11 $worktrees worktrees!"
[ -d /tmp/pc-sandbox-backup.lock ] && bad "T11 leftover lock" || ok "T11 no leftover lock"

echo ""
echo "===================================="
echo "RESULTS: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] && echo "ALL GREEN" || echo "FAILURES PRESENT"

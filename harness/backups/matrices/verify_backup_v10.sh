#!/usr/bin/env bash
# G1-iter6-i2 fix-cycle verification matrix for scripts/sandbox_backup.sh
# (v10).
#
# Complements verify_backup_v5/v6/v7/v8/v9.sh (E1-E30, all still valid
# — re-run them too) and tests/test_harness_integrity.py, which
# machine-covers (mutation-verified) every v9 surface plus the v10
# additions: the BOTH-DIRECTIONS target judgment (the fetch view of
# named remotes + the typed push view of URL operands), the
# include/includeIf config-class refusal, the symlinked-.git refusal,
# the union-prefers-ours merge, the scp-syntax redaction.
# This matrix covers the v10 scenarios END-TO-END in scratch:
#   E31 includeIf-conditional pushInsteadOf — the guard's context sits
#       on main while the push context sits on sandbox/backups, so a
#       branch-conditional key is INVISIBLE at guard time and ACTIVE
#       at push time (v9 sailed past, executed E2E) + the MECHANISM
#       demo (refusal removed -> the checkpoint lands in the unjudged
#       rewrite target, proving the refusal load-bearing)
#   E32 fetch-side divergence — a remote name whose url is
#       github-spelled and whose pushurl is a clean bare (v9 judged
#       only the pushurl; the FETCH view refuses now) + a clean
#       remote-name control
#   E33 symlinked .git — both identity-compare sides resolve through
#       the symlink (the equality held while the operand shared the
#       stand-in's git state)
#   E34 union prefers OURS — a same-triple divergence keeps the LOCAL
#       entry and audits the collision (patched-TS mechanism demo)
#   E35 scp-syntax user:pass@host redaction on the not-a-remote
#       refusal
#
# All fake tokens are built at runtime. Everything stays under
# /tmp/pc-v10-verify; production is never contacted or written (the
# mutated-copy probes patch PROD_CHECKOUT to a stand-in with LOUD
# anchors — the G1-iter6-i2 hardening of the both-sides rule, process
# doc item (f) — and every lane references only scratch paths).
set -u
# G1-iter6 (Architect major #2): matrices are REPO-RESIDENT
# (CI-visible) — ROOT derives from this file's location so the matrix
# runs against ANY checkout (the sandbox-home copies are retired).
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v10-verify
rm -rf "$S"; mkdir -p "$S"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

mk_lane() {
  local d="$S/$1"
  mkdir -p "$d/home/scripts"
  git clone -q "$ROOT" "$d/clone"
  git init -q --bare "$d/bare.git"
  git -C "$d/clone" remote set-url origin "$d/bare.git" 2>/dev/null || true
  echo "print('ok')" > "$d/home/scripts/ok.py"
}

run_bk() {  # $1=lane $2=msg $3=push_remote
  local d="$S/$1"
  env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
    PC_BACKUP_PUSH_REMOTE="$3" \
    bash "$SCRIPT" "$2" >"$d/out" 2>&1
  echo "$?"
}

# -- E31: includeIf-conditional pushInsteadOf --------------------------
mk_lane e31
git init -q --bare "$S/e31/rewrite-target.git"
printf '[url "%s"]\n\tpushInsteadOf = %s\n' \
  "$S/e31/rewrite-target.git" "$S/e31/bare.git" > "$S/e31/clone/.git/evil.inc"
git -C "$S/e31/clone" config "includeif.onbranch:sandbox/backups.path" \
  "$S/e31/clone/.git/evil.inc"
rc=$(run_bk e31 "e31 probe" "$S/e31/bare.git")
if [ "$rc" = 6 ] && grep -q "\[include" "$S/e31/out"; then
  ok "E31 includeIf-gated pushInsteadOf refuses exit 6 (inactive at guard time, caught by file content)"
else
  bad "E31 includeIf rc=$rc out=$(tail -1 "$S/e31/out")"
fi
if git --git-dir="$S/e31/rewrite-target.git" rev-parse --verify \
     sandbox/backups >/dev/null 2>&1; then
  bad "E31 the refusal leaked a checkpoint into the rewrite target"
else
  ok "E31 rewrite target untouched"
fi
# mechanism demo: the include-refusal REMOVED from a mutated copy —
# the guard (on main) never sees the branch-conditional key, the push
# (from the temporary worktree on sandbox/backups) is rewritten, and
# the checkpoint lands in the unjudged rewrite target. PROD patched
# to a stand-in with LOUD anchors (both-sides rule; scratch paths
# only).
python3 - "$SCRIPT" > "$S/patched-e31.sh" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
prod = 'PROD_CHECKOUT="/home/z/my-project/cleanroom"'
assert src.count(prod) == 1, "PROD_CHECKOUT anchor missing or not unique"
src = src.replace(prod, 'PROD_CHECKOUT="/tmp/pc-v10-verify/standin-prod"')
old = '''  for _cf in "$(git rev-parse --git-path config)" \\
             "$HOME/.gitconfig" \\
             "${XDG_CONFIG_HOME:-$HOME/.config}/git/config" \\
             /etc/gitconfig; do
    [ -f "$_cf" ] || continue
    if grep -qiE '^[[:space:]]*\\[include' "$_cf" 2>/dev/null; then
      echo "!! refusing: an [include]/[includeIf] section exists in git config" >&2
      echo "   ($_cf) — include conditions (onbranch:, gitdir:, hasconfig:) are" >&2
      echo "   invisible to the guard's context and materialize at push time," >&2
      echo "   so a TEST run refuses the class outright (see" >&2
      echo "   harness/backups/README.md)." >&2
      exit 6
    fi
  done
'''
assert old in src, "include-refusal anchor not found"
src = src.replace(old, "")
pathlib.Path("/tmp/pc-v10-verify/patched-e31.sh").write_text(src, encoding="utf-8")
PY
if [ -s "$S/patched-e31.sh" ] && bash -n "$S/patched-e31.sh"; then
  mkdir -p "$S/standin-prod"
  env PC_BACKUP_REPO="$S/e31/clone" PC_SANDBOX_HOME="$S/e31/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e31/bare.git" \
    bash "$S/patched-e31.sh" "e31 mechanism demo" >"$S/e31/out-demo" 2>&1 || true
  if git --git-dir="$S/e31/rewrite-target.git" rev-parse --verify \
       sandbox/backups >/dev/null 2>&1; then
    ok "E31 mechanism demo: refusal removed -> the rewrite target received the checkpoint (the refusal is load-bearing)"
  else
    bad "E31 mechanism demo did not reach the rewrite target (out=$(tail -2 "$S/e31/out-demo"))"
  fi
else
  bad "E31 patched copy missing or does not parse (anchor drift)"
fi

# -- E32: fetch-side divergence ----------------------------------------
mk_lane e32
git -C "$S/e32/clone" remote add ghdiv \
  "https://github.com/maniesh-NR/Proto-Clean.git"
git -C "$S/e32/clone" remote set-url --push ghdiv "$S/e32/bare.git"
rc=$(run_bk e32 "e32 probe" "ghdiv")
if [ "$rc" = 6 ] && grep -q "fetch" "$S/e32/out"; then
  ok "E32 github-spelled FETCH url + clean pushurl refuses (the fetch view is judged)"
else
  bad "E32 fetch-divergence rc=$rc out=$(tail -1 "$S/e32/out")"
fi
git -C "$S/e32/clone" remote add bothclean "$S/e32/bare.git"
rc=$(run_bk e32 "e32 clean control" "bothclean")
[ "$rc" = 0 ] && ok "E32 clean remote-name control passes" \
  || bad "E32 clean control rc=$rc: $(tail -2 "$S/e32/out")"

# -- E33: symlinked .git -----------------------------------------------
mk_lane e33
mkdir -p "$S/e33/symrepo"
ln -s "$S/e33/clone/.git" "$S/e33/symrepo/.git"
env PC_BACKUP_REPO="$S/e33/symrepo" PC_SANDBOX_HOME="$S/e33/home" \
  PC_BACKUP_PUSH_REMOTE="$S/e33/bare.git" \
  bash "$SCRIPT" "e33 probe" >"$S/e33/out" 2>&1
rc=$?
if [ "$rc" = 6 ] && grep -q "symlink" "$S/e33/out"; then
  ok "E33 symlinked .git refuses exit 6"
else
  bad "E33 symlink rc=$rc out=$(tail -1 "$S/e33/out")"
fi
if git --git-dir="$S/e33/clone/.git" rev-parse --verify \
     sandbox/backups >/dev/null 2>&1; then
  bad "E33 the probe wrote into the stand-in clone's git state"
else
  ok "E33 stand-in git state untouched"
fi

# -- E34: union prefers OURS (same-triple divergence) ------------------
# Mechanism demo with a patched copy: TS pinned to a fixed value (LOUD
# anchor) so two runs on different remotes produce the SAME
# (seq, timestamp, message) triple with DIFFERENT git_head content;
# the third run (back onto the second remote) diverges, the union
# fires, and OURS — the LOCAL entry — must win, with the collision
# audited. PROD patched to a stand-in (both-sides rule).
python3 - "$SCRIPT" > "$S/patched-e34.sh" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
prod = 'PROD_CHECKOUT="/home/z/my-project/cleanroom"'
assert src.count(prod) == 1, "PROD_CHECKOUT anchor missing or not unique"
src = src.replace(prod, 'PROD_CHECKOUT="/tmp/pc-v10-verify/standin-prod"')
ts = 'TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
assert src.count(ts) == 1, "TS anchor missing or not unique"
src = src.replace(ts, 'TS="2077-01-01T00:00:00Z"')
pathlib.Path("/tmp/pc-v10-verify/patched-e34.sh").write_text(src, encoding="utf-8")
PY
if [ -s "$S/patched-e34.sh" ] && bash -n "$S/patched-e34.sh"; then
  mkdir -p "$S/standin-prod"
  git clone -q "$ROOT" "$S/e34/c1" 2>/dev/null
  git clone -q "$ROOT" "$S/e34/c2" 2>/dev/null
  git init -q --bare "$S/e34/r1.git"
  git init -q --bare "$S/e34/r2.git"
  mkdir -p "$S/e34/home/scripts"
  echo "print('ok')" > "$S/e34/home/scripts/ok.py"
  # run 1 (C1 -> R1): the local branch's first entry, head = C1's HEAD
  env PC_BACKUP_REPO="$S/e34/c1" PC_SANDBOX_HOME="$S/e34/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e34/r1.git" \
    bash "$S/patched-e34.sh" "union demo" >"$S/e34/out1" 2>&1 || true
  # run 2 (C2 -> R2): a SEPARATE lineage — C2's head deliberately
  # differs, so the same triple carries different git_head content
  git -C "$S/e34/c2" -c user.email=t@t -c user.name=t commit \
    --allow-empty -qm "e34 head bump"
  env PC_BACKUP_REPO="$S/e34/c2" PC_SANDBOX_HOME="$S/e34/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e34/r2.git" \
    bash "$S/patched-e34.sh" "union demo" >"$S/e34/out2" 2>&1 || true
  # run 3 (C1 -> R2): C1's branch vs R2's branch diverge -> the
  # self-heal union fires on the same triple
  env PC_BACKUP_REPO="$S/e34/c1" PC_SANDBOX_HOME="$S/e34/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e34/r2.git" \
    bash "$S/patched-e34.sh" "union demo" >"$S/e34/out3" 2>&1 || true
  _c1head="$(git -C "$S/e34/c1" rev-parse --short HEAD)"
  _c2head="$(git -C "$S/e34/c2" rev-parse --short HEAD)"
  _verdict="$(python3 - "$S/e34/r2.git" "$_c1head" "$_c2head" <<'PY'
import json, subprocess, sys
gitdir, c1, c2 = sys.argv[1], sys.argv[2], sys.argv[3]
out = subprocess.run(
    ["git", "--git-dir", gitdir, "show",
     "sandbox/backups:harness/backups/manifest.json"],
    capture_output=True, text=True).stdout
doc = json.loads(out)
# the COLLIDED triple is seq 1 (run 3's own entry is seq 2 on the
# same pinned timestamp/message — filtered out by seq)
rows = [e for e in doc.get("backups", [])
        if str(e.get("seq")) == "1"
        and e.get("timestamp") == "2077-01-01T00:00:00Z"
        and e.get("message") == "union demo"]
heads = [e.get("git_head") for e in doc.get("backups", [])]
if len(rows) == 1 and rows[0].get("git_head") == c1 \
        and c2 not in heads \
        and doc.get("merge_triple_conflicts") == 1:
    print("OK")
else:
    print("BAD rows=%d conflicts=%r heads=%s"
          % (len(rows), doc.get("merge_triple_conflicts"), heads))
PY
)"
  if grep -q "the LOCAL entry kept" "$S/e34/out3" && [ "$_verdict" = "OK" ]; then
    ok "E34 union keeps the LOCAL entry on a same-triple collision (audited)"
  else
    bad "E34 union preference failed (verdict=$_verdict out3=$(tail -3 "$S/e34/out3"))"
  fi
else
  bad "E34 patched copy missing or does not parse (anchor drift)"
fi

# -- E35: scp-syntax password redaction --------------------------------
mk_lane e35
rc=$(run_bk e35 "e35 probe" "user:E35SeCrEt@evil-nowhere.invalid:x.git")
if [ "$rc" = 6 ] && ! grep -q "E35SeCrEt" "$S/e35/out" \
   && grep -q "\[REDACTED\]" "$S/e35/out"; then
  ok "E35 scp-syntax password redacted on the not-a-remote refusal"
else
  bad "E35 redaction rc=$rc out=$(tail -1 "$S/e35/out")"
fi

echo "----------------------------------------"
echo "verify_backup_v10: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

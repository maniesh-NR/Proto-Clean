#!/usr/bin/env bash
# G1-iter5-i2 closing fix-cycle verification matrix for
# scripts/sandbox_backup.sh (v8).
#
# Complements verify_backup_v5/v6/v7.sh (E1-E18, all still valid —
# re-run them too) and tests/test_harness_integrity.py, which
# machine-covers (mutation-verified) every v7 surface plus the v8
# additions: empty-authority spellings, multi-@ ssh userinfo,
# relative-target refusal, fail-closed unresolvable targets, the
# pushurl-divergent remote lane, the Shipped-signature and
# fenced-mention glyph rules.
# This matrix covers the v8 scenarios END-TO-END in scratch:
#   E19 empty-authority + multi-@ spelling refusal matrix
#   E20 relative push-target refusal (incl. the literal RT vector
#       ../../home/z/my-project/cleanroom — refused pre-push) + the
#       cwd-mismatch mechanism demonstration on a STAND-IN (an
#       identity-patched copy proves the relative push resolves at
#       the worktree base — the reason relatives are refused)
#   E21 pushurl divergence: url=local-bare + pushurl=github → refuse
#   E22 fail-closed: an unresolvable remote name refuses (exit 6,
#       never silently skipping the checks)
#
# All fake tokens are built at runtime. Everything stays under
# /tmp/pc-v8-verify; production is never contacted or written (the
# one identity-patched probe patches PROD_CHECKOUT to a stand-in per
# the seq-10 process rule).
set -u
ROOT=/home/z/my-project/cleanroom
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v8-verify
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

# -- E19: empty-authority + multi-@ spellings --------------------------
mk_lane e19
for t in \
  "https:///github.com/maniesh-NR/Proto-Clean.git" \
  "http:///github.com/maniesh-NR/Proto-Clean.git" \
  "https:///gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git" \
  "https:////github.com/maniesh-NR/Proto-Clean.git" \
  "ssh://user@evil.com@github.com/maniesh-NR/Proto-Clean" \
  "ssh://@evil.com@github.com:22/maniesh-NR/Proto-Clean" \
  "user@evil.com@github.com:maniesh-NR/Proto-Clean.git" \
  "user@@github.com:maniesh-NR/Proto-Clean.git"
do
  rc=$(run_bk e19 "e19 probe" "$t")
  if [ "$rc" = 6 ]; then
    ok "E19 refuse: ${t:0:48}"
  else
    bad "E19 refused? rc=$rc target=${t:0:48}"
  fi
done
git -C "$S/e19/clone" remote add doublescp "user@evil.com@github.com:maniesh-NR/Proto-Clean.git"
rc=$(run_bk e19 "e19 probe" "doublescp")
[ "$rc" = 6 ] && ok "E19 refuse: remote name -> double-@ scp" \
  || bad "E19 remote-name double-@ rc=$rc"
rc=$(run_bk e19 "e19 clean" "$S/e19/bare.git")
[ "$rc" = 0 ] && ok "E19 clean local lane passes" \
  || bad "E19 clean lane rc=$rc: $(tail -2 "$S/e19/out")"

# -- E20: relative push-target refusal + mechanism demo ----------------
mk_lane e20
for t in "../bare.git" "./bare.git" "../../home/z/my-project/cleanroom"
do
  rc=$(run_bk e20 "e20 probe" "$t")
  if [ "$rc" = 6 ] && grep -q "RELATIVE" "$S/e20/out"; then
    ok "E20 refuse relative: $t"
  else
    bad "E20 relative rc=$rc target=$t out=$(tail -1 "$S/e20/out")"
  fi
done
# bare-relative spellings (no ./ or ../ prefix) are classified as
# remote NAMES by the remote-plumbing layer and refused there — exit 6
# either way, just a different (earlier) refusal
rc=$(run_bk e20 "e20 probe" "sub/dir/bare.git")
if [ "$rc" = 6 ]; then
  ok "E20 refuse bare-relative (via the not-a-remote layer): sub/dir/bare.git"
else
  bad "E20 bare-relative rc=$rc out=$(tail -1 "$S/e20/out")"
fi
# mechanism demo on a STAND-IN (the seq-10 rule: PROD_CHECKOUT patched
# in the probe copy): with the refusal REMOVED (the v7 state), a
# relative ../../-chain from the worktree base reaches the stand-in —
# proving the base mismatch is real and the refusal is load-bearing
python3 - "$SCRIPT" > "$S/patched.sh" <<'PY'
import sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
# patch the guarded constant to the stand-in (seq-10 rule) ...
src = src.replace('PROD_CHECKOUT="/home/z/my-project/cleanroom"',
                  'PROD_CHECKOUT="/tmp/pc-v8-verify/standin-prod/checkout"')
# ... and REMOVE the relative refusal (restore the v7 behavior)
old = """  case "$_tgt" in
    ./*|../*)
      echo "!! refusing: PC_BACKUP_PUSH_REMOTE is a RELATIVE path — the push" >&2
      echo "   executes from a temporary worktree, so a relative target" >&2
      echo "   resolves somewhere the guard never judged. Use an absolute" >&2
      echo "   scratch path (see harness/backups/README.md)." >&2
      exit 6
      ;;
  esac
"""
assert old in src, "relative-refusal anchor not found"
src = src.replace(old, "")
pathlib.Path("/tmp/pc-v8-verify/patched.sh").write_text(src, encoding="utf-8")
PY
bash -n "$S/patched.sh" || { bad "E20 patched copy does not parse"; exit 1; }
# the stand-in "production checkout": a real working clone whose local
# sandbox/backups the v7-state push would land on
mkdir -p "$S/standin-prod"
git clone -q "$ROOT" "$S/standin-prod/checkout" 2>/dev/null
d="$S/e20"
env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
  PC_BACKUP_PUSH_REMOTE="../../tmp/pc-v8-verify/standin-prod/checkout" \
  bash "$S/patched.sh" "e20 mechanism demo" >"$d/out-demo" 2>&1
rc=$?
# from the REPO cwd the operand dead-ends (no refusal, v7 state); the
# push from the worktree base resolves to the stand-in — the run may
# rc 0 or 7, but the stand-in's local branch must NOT be addressed
# before the push... it WILL be (that is the bug being demonstrated):
# assert the mechanism: the stand-in checkout gained a local
# sandbox/backups branch (the checkpoint landed there)
if git -C "$S/standin-prod/checkout" rev-parse --verify sandbox/backups >/dev/null 2>&1; then
  ok "E20 mechanism demo: v7-state relative push landed on the stand-in (the refusal is load-bearing)"
else
  bad "E20 mechanism demo did not reproduce the base mismatch (rc=$rc): $(tail -2 "$d/out-demo")"
fi
# and the REAL v8 script refuses the same operand outright
rc=$(run_bk e20 "e20 probe" "../../tmp/pc-v8-verify/standin-prod/checkout")
[ "$rc" = 6 ] && ok "E20 the real v8 script refuses the same operand" \
  || bad "E20 real-script relative-to-standin rc=$rc"

# -- E21: pushurl divergence -------------------------------------------
mk_lane e21
git -C "$S/e21/clone" remote add urlpush "$S/e21/bare.git"
git -C "$S/e21/clone" remote set-url --push urlpush \
  "https://github.com/maniesh-NR/Proto-Clean.git"
rc=$(run_bk e21 "e21 probe" "urlpush")
[ "$rc" = 6 ] && ok "E21 pushurl=github behind url=local refused" \
  || bad "E21 pushurl divergence rc=$rc: $(tail -2 "$S/e21/out")"
# the plain remote (no pushurl) still works
git -C "$S/e21/clone" remote add plainremote "$S/e21/bare.git"
rc=$(run_bk e21 "e21 clean via remote name" "plainremote")
[ "$rc" = 0 ] && ok "E21 remote name without pushurl passes" \
  || bad "E21 plain remote rc=$rc: $(tail -2 "$S/e21/out")"

# -- E22: fail-closed on unresolvable targets ---------------------------
mk_lane e22
# a remote NAME that is not configured: the not-a-remote refusal
# (exit 6, redacted echo) fires after repo validation — the fail-closed
# empty-resolution path is belt-and-braces; verify the refusal fires
env PC_BACKUP_REPO="$S/e22/clone" PC_SANDBOX_HOME="$S/e22/home" \
  PC_BACKUP_PUSH_REMOTE="definitely-not-a-remote" \
  bash "$SCRIPT" "e22 probe" >"$S/e22/out" 2>&1
rc=$?
if [ "$rc" = 6 ] && ! grep -qE "ghp_|github_pat_" "$S/e22/out"; then
  ok "E22 unresolvable remote name refused exit 6 (no token echo)"
else
  bad "E22 unresolvable rc=$rc out=$(tail -1 "$S/e22/out")"
fi

echo "----------------------------------------"
echo "verify_backup_v8: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

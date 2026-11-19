#!/usr/bin/env bash
# G1-iter6 fix-cycle verification matrix for scripts/sandbox_backup.sh
# (v9).
#
# Complements verify_backup_v5/v6/v7/v8.sh (E1-E22, all still valid —
# re-run them too) and tests/test_harness_integrity.py, which
# machine-covers (mutation-verified) every v8 surface plus the v9
# additions: percent-encoded hosts, helper transports, the
# pushInsteadOf config refusal, the git-dir identity check + env scrub
# of the discovery-redirection family, the every-relative-target
# refusal, the first-colon/post-@ host cut, raw-IP and trailing-dot
# refusal, the backing-adoption glyph rules.
# This matrix covers the v9 scenarios END-TO-END in scratch:
#   E23 percent-encoded host refusal (curl decodes before connecting)
#   E24 helper-transport (::) refusal — direct AND remote-carried
#   E25 pushInsteadOf: config key refused + the REWRITE MECHANISM demo
#       (with the refusal removed, the typed operand's checkpoint lands
#       in the REWRITTEN bare — the stand-in "github" — proving the
#       refusal is load-bearing)
#   E26 scp double-colon :22: spelling via a remote name (the greedy
#       host cut used to read github.com:22 — no suffix match)
#   E27 git-dir identity: subdirectory + linked-worktree operands
#       refused; GIT_DIR env redirection scrubbed inert
#   E28 raw-IP hosts refused (loopback exempt by design), trailing-dot
#       hosts collapsed into the suffix match
#   E29 remote-carried interior-.. relative URL refused + the
#       worktree-base mechanism demo on a stand-in
#   E30 push-target CONTAINMENT: a target inside the production
#       checkout refuses (v8 compared only equality)
#
# All fake tokens are built at runtime. Everything stays under
# /tmp/pc-v9-verify; production is never contacted or written (the
# mutated-copy probes patch PROD_CHECKOUT to a stand-in AND every lane
# references only scratch paths — the G1-iter6 corrected both-sides
# rule, process doc item (f)).
set -u
# G1-iter6 (Architect major #2): matrices are REPO-RESIDENT
# (CI-visible) — ROOT derives from this file's location so the matrix
# runs against ANY checkout (the sandbox-home copies are retired).
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v9-verify
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

# -- E23: percent-encoded hosts ----------------------------------------
mk_lane e23
for t in \
  "https://%67ithub.com/maniesh-NR/Proto-Clean.git" \
  "https://github%2ecom/maniesh-NR/Proto-Clean.git" \
  "https://gist.%67ithub.com/aa11bb22cc33dd44ee55ff6677aabbcc.git"
do
  rc=$(run_bk e23 "e23 probe" "$t")
  if [ "$rc" = 6 ]; then
    ok "E23 refuse percent-encoded: ${t:0:52}"
  else
    bad "E23 percent rc=$rc target=${t:0:52}"
  fi
done
rc=$(run_bk e23 "e23 clean" "$S/e23/bare.git")
[ "$rc" = 0 ] && ok "E23 clean local lane passes" \
  || bad "E23 clean lane rc=$rc: $(tail -2 "$S/e23/out")"

# -- E24: helper transports --------------------------------------------
mk_lane e24
for t in \
  "ext::git-receive-pack /tmp/nowhere.git" \
  "fd::17,/tmp/nowhere.git" \
  "vendor::whatever" \
  "https://[::1]/x.git"
do
  rc=$(run_bk e24 "e24 probe" "$t")
  if [ "$rc" = 6 ]; then
    ok "E24 refuse transport: ${t:0:44}"
  else
    bad "E24 transport rc=$rc target=${t:0:44}"
  fi
done
git -C "$S/e24/clone" remote add extrans "ext::git-receive-pack /tmp/nowhere.git"
rc=$(run_bk e24 "e24 probe" "extrans")
[ "$rc" = 6 ] && ok "E24 refuse transport via remote name" \
  || bad "E24 remote-carried transport rc=$rc"

# -- E25: pushInsteadOf config refusal + mechanism demo ----------------
mk_lane e25
git init -q --bare "$S/e25/rewrite-target.git"
git -C "$S/e25/clone" config \
  "url.$S/e25/rewrite-target.git.pushInsteadOf" "$S/e25/bare.git"
rc=$(run_bk e25 "e25 probe" "$S/e25/bare.git")
if [ "$rc" = 6 ] && grep -q "pushInsteadOf" "$S/e25/out"; then
  ok "E25 pushInsteadOf key in config refuses exit 6"
else
  bad "E25 pushInsteadOf refusal rc=$rc out=$(tail -1 "$S/e25/out")"
fi
if git --git-dir="$S/e25/rewrite-target.git" rev-parse --verify \
     sandbox/backups >/dev/null 2>&1; then
  bad "E25 refused run still reached the rewrite target"
else
  ok "E25 the rewrite target stayed untouched under refusal"
fi
git -C "$S/e25/clone" config --unset \
  "url.$S/e25/rewrite-target.git.pushInsteadOf"
# mechanism demo: the same config with the REFUSAL REMOVED from a
# mutated copy — the typed operand's checkpoint lands in the REWRITE
# TARGET (the stand-in "github"), proving the rewrite is real and the
# refusal is load-bearing. Lanes reference scratch paths only
# (both-sides rule); PROD_CHECKOUT patched to a stand-in for safety.
python3 - "$SCRIPT" > "$S/patched.sh" <<'PY'
import sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
# G1-iter6-i2 Architect major #2c: LOUD anchors — a silent no-op on a
# spelling change re-creates the E20 anchor-drift class
prod = 'PROD_CHECKOUT="/home/z/my-project/cleanroom"'
assert src.count(prod) == 1, "PROD_CHECKOUT anchor missing or not unique"
src = src.replace(prod, 'PROD_CHECKOUT="/tmp/pc-v9-verify/standin-prod"')
old = """  if git config --get-regexp '^url\\..+\\.pushinsteadof$' >/dev/null 2>&1; then
    echo "!! refusing: a url.*.pushInsteadOf key exists in visible git config —" >&2
    echo "   push-time rewrites are invisible to fetch-side resolution, so a" >&2
    echo "   TEST run refuses outright. Remove the key or use a clean scratch" >&2
    echo "   repo (see harness/backups/README.md)." >&2
    exit 6
  fi
"""
assert old in src, "pushInsteadOf refusal anchor not found"
src = src.replace(old, "")
pathlib.Path("/tmp/pc-v9-verify/patched.sh").write_text(src, encoding="utf-8")
PY
bash -n "$S/patched.sh" || { bad "E25 patched copy does not parse"; exit 1; }
mkdir -p "$S/standin-prod"
git -C "$S/e25/clone" config \
  "url.$S/e25/rewrite-target.git.pushInsteadOf" "$S/e25/bare.git"
env PC_BACKUP_REPO="$S/e25/clone" PC_SANDBOX_HOME="$S/e25/home" \
  PC_BACKUP_PUSH_REMOTE="$S/e25/bare.git" \
  bash "$S/patched.sh" "e25 mechanism demo" >"$S/e25/out-demo" 2>&1
if git --git-dir="$S/e25/rewrite-target.git" rev-parse --verify \
     sandbox/backups >/dev/null 2>&1; then
  ok "E25 mechanism demo: refusal removed -> checkpoint landed in the REWRITE TARGET (the refusal is load-bearing)"
else
  bad "E25 mechanism demo did not reproduce the rewrite (out=$(tail -2 "$S/e25/out-demo"))"
fi
git -C "$S/e25/clone" config --unset \
  "url.$S/e25/rewrite-target.git.pushInsteadOf"

# -- E26: scp :22: via remote name ------------------------------------
mk_lane e26
git -C "$S/e26/clone" remote add scp22 \
  "git@github.com:22:maniesh-NR/Proto-Clean.git"
rc=$(run_bk e26 "e26 probe" "scp22")
if [ "$rc" = 6 ]; then
  ok "E26 refuse scp :22: via remote name"
else
  bad "E26 scp22 rc=$rc out=$(tail -1 "$S/e26/out")"
fi
# the FIRST-COLON host cut must not over-reach: a plain local remote
# through a remote name still passes
git -C "$S/e26/clone" remote add plain "$S/e26/bare.git"
rc=$(run_bk e26 "e26 clean" "plain")
[ "$rc" = 0 ] && ok "E26 plain remote name still passes" \
  || bad "E26 plain remote rc=$rc: $(tail -2 "$S/e26/out")"

# -- E27: git-dir identity --------------------------------------------
mk_lane e27
# a stand-in "other" checkout: its subdirectory and its linked
# worktree share ITS .git — the identity check must refuse both (no
# production dependency; scratch stand-ins)
git clone -q "$ROOT" "$S/e27/other" 2>/dev/null
for operand in "$S/e27/other/harness" "$S/e27/other-wt"; do
  if [ "$operand" = "$S/e27/other-wt" ]; then
    git -C "$S/e27/other" worktree add --quiet --detach "$operand" 2>/dev/null
  fi
  env PC_BACKUP_REPO="$operand" PC_SANDBOX_HOME="$S/e27/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e27/bare.git" \
    bash "$SCRIPT" "e27 probe" >"$S/e27/out" 2>&1
  rc=$?
  if [ "$rc" = 6 ] && grep -q "git dir is not its own" "$S/e27/out"; then
    ok "E27 identity refusal: $operand"
  else
    bad "E27 identity rc=$rc operand=$operand out=$(tail -1 "$S/e27/out")"
  fi
done
# GIT_DIR env redirection is scrubbed: the run behaves as if unset
env PC_BACKUP_REPO="$S/e27/clone" PC_SANDBOX_HOME="$S/e27/home" \
  PC_BACKUP_PUSH_REMOTE="$S/e27/bare.git" \
  GIT_DIR="$S/e27/other/.git" \
  bash "$SCRIPT" "e27 gitdir-scrub" >"$S/e27/out" 2>&1
rc=$?
if [ "$rc" = 0 ] && ! git --git-dir="$S/e27/other/.git" rev-parse \
     --verify sandbox/backups >/dev/null 2>&1; then
  ok "E27 GIT_DIR env scrubbed inert (run clean, stand-in untouched)"
else
  bad "E27 GIT_DIR scrub rc=$rc out=$(tail -2 "$S/e27/out")"
fi

# -- E28: raw-IP + trailing dots --------------------------------------
mk_lane e28
for t in \
  "https://140.82.121.4/maniesh-NR/Proto-Clean.git" \
  "https://192.168.13.37/x.git" \
  "https://gist.github.com../aa11bb22cc33dd44ee55ff6677aabbcc.git" \
  "https://github.com../maniesh-NR/Proto-Clean.git"
do
  rc=$(run_bk e28 "e28 probe" "$t")
  if [ "$rc" = 6 ]; then
    ok "E28 refuse: $t"
  else
    bad "E28 rc=$rc target=$t"
  fi
done
# loopback is exempt by design (the redaction lane's local http sink):
# the guard must PASS it to the push layer (any rc but 6 — the dead
# sink makes the push itself fail)
rc=$(run_bk e28 "e28 loopback" "https://127.0.0.1:9/x.git")
if [ "$rc" != 6 ]; then
  ok "E28 loopback exempt from the raw-IP refusal (rc=$rc at the push layer)"
else
  bad "E28 loopback wrongly refused by the raw-IP rule"
fi

# -- E29: remote-carried interior-.. relative -------------------------
mk_lane e29
git -C "$S/e29/clone" remote add relhide "harness/../../e29-sink.git"
rc=$(run_bk e29 "e29 probe" "relhide")
if [ "$rc" = 6 ] && grep -q "RELATIVE" "$S/e29/out"; then
  ok "E29 refuse remote-carried interior-.. relative URL"
else
  bad "E29 relhide rc=$rc out=$(tail -1 "$S/e29/out")"
fi
# mechanism demo: with the every-relative refusal REMOVED (the v8
# state) and the push executed from a cwd where harness/ exists, the
# remote-carried relative lands on an unjudged sink — stand-in only
# (both-sides rule: PROD patched, lanes reference scratch paths)
python3 - "$SCRIPT" > "$S/patched2.sh" <<'PY'
import sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
# G1-iter6-i2 Architect major #2c: LOUD anchors (same as E25)
prod = 'PROD_CHECKOUT="/home/z/my-project/cleanroom"'
assert src.count(prod) == 1, "PROD_CHECKOUT anchor missing or not unique"
src = src.replace(prod, 'PROD_CHECKOUT="/tmp/pc-v9-verify/standin-prod"')
old = """    *)
      echo "!! refusing: the $_dir target (PC_BACKUP_PUSH_REMOTE) resolves to a RELATIVE target" >&2
      echo "   (however carried — direct operand or a remote's URL) — the push" >&2
      echo "   executes from a temporary worktree, so a relative target resolves" >&2
      echo "   somewhere the guard never judged. Use an absolute scratch path" >&2
      echo "   (see harness/backups/README.md)." >&2
      exit 6
      ;;
"""
assert old in src, "relative-refusal anchor not found"
src = src.replace(old, "    *) : ;;\n")
pathlib.Path("/tmp/pc-v9-verify/patched2.sh").write_text(src, encoding="utf-8")
PY
bash -n "$S/patched2.sh" || { bad "E29 patched copy does not parse"; exit 1; }
# the unjudged sink sits depth-1 under /tmp (the worktree base)
git init -q --bare /tmp/e29-sink.git
mkdir -p "$S/wtbase" && cd "$S/wtbase" && git init -q . \
  && git config user.email t@t && git config user.name t \
  && mkdir harness && echo h > harness/x && git add . && git commit -qm wt \
  && git remote add relhide "harness/../../e29-sink.git"
env PC_BACKUP_REPO="$S/e29/clone" PC_SANDBOX_HOME="$S/e29/home" \
  PC_BACKUP_PUSH_REMOTE="relhide" \
  bash "$S/patched2.sh" "e29 mechanism demo" >"$S/e29/out-demo" 2>&1 || true
# the push from the temp worktree (depth-1 under /tmp) resolves
# harness/../../e29-sink.git -> /tmp/e29-sink.git — wait: the worktree
# is /tmp/pc-backup.XXXXXX (depth-1), so harness/../.. = /tmp; the
# sink receives the branch. Assert it did.
if git --git-dir=/tmp/e29-sink.git rev-parse --verify \
     sandbox/backups >/dev/null 2>&1; then
  ok "E29 mechanism demo: refusal removed -> the unjudged sink received the branch (the refusal is load-bearing)"
else
  bad "E29 mechanism demo did not reach the sink (out=$(tail -2 "$S/e29/out-demo"))"
fi
cd "$ROOT"

# -- E30: push-target containment -------------------------------------
mk_lane e30
# G1-iter6-i2 Architect major #2b: DERIVE the guarded identity from
# the script under test (exactly-one assignment, loud) — a
# hand-copied production path is the one-sided-patch coupling in a
# repo-resident artifact the checklist forces every fix cycle to
# re-run
PROD="$(python3 -c '
import re, pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
m = re.findall(r"(?m)^PROD_CHECKOUT=\"(.+)\"$", src)
assert len(m) == 1, "PROD_CHECKOUT not found or not unique"
print(m[0])
' "$SCRIPT")" || { bad "E30 PROD derivation failed"; }
SKIP=0
if [ -d "$PROD" ]; then
  for t in "$PROD/harness" "$PROD/.git" ; do
    rc=$(run_bk e30 "e30 probe" "$t")
    if [ "$rc" = 6 ]; then
      ok "E30 refuse target inside production: $t"
    else
      bad "E30 containment rc=$rc target=$t"
    fi
  done
else
  SKIP=1
  echo "SKIP: E30 (2 lanes — the production checkout is not present on this machine); counted loudly, not silent"
fi

echo "----------------------------------------"
echo "verify_backup_v9: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]

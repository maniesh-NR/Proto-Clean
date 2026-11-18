#!/usr/bin/env bash
# G1-iter5 fix-cycle verification matrix for scripts/sandbox_backup.sh (v7).
#
# Complements verify_backup_v5.sh (E1-E8) and verify_backup_v6.sh
# (E9-E13), both still valid, and tests/test_harness_integrity.py,
# which machine-covers (all mutation-verified at G1-iter5): the opt-in
# gate, the guard spellings incl. subdomains and empty-credential
# forms, the physical production-path compares (repo + push target),
# insteadOf resolution, partial overrides, the unreachable alarm,
# shaped names, the hermetic cycle, refusal-echo redaction, main-push
# redaction + trace hygiene (incl. the zero-trace-lines observability
# lane), the union key-scrub, and the index re-scan position.
# This matrix covers the v7 scenarios END-TO-END in scratch:
#   E14 empty-credential spelling refusal matrix (empty userinfo /
#       empty port / both / scp-empty-path, direct + remote name)
#   E15 push-TARGET production-path refusal (plain, file://, /.git,
#       symlink, //) + the REPO-operand symlink/`//` lanes — the
#       physical (pwd -P) compares
#   E16 insteadOf resolution: a config-FILE rewrite to github is
#       refused (the guard resolves the operand the way git does);
#       an env-injected GIT_CONFIG_GLOBAL rewrite is INERT (scrubbed)
#   E17 hostile GIT_TRACE=1 clean lane: zero git trace lines in the
#       output (the platform-independent scrub-observability signal)
#   E18 widened-window TOCTOU probe: an INSTRUMENTED COPY (a plant
#       inserted AFTER the worktree scan, before the add — the exact
#       G1-iter5 RT minor #3 window, widened to be deterministic)
#       must be caught by the INDEX re-scan (exit 4, "staged
#       content"); the real script's scan position is separately
#       pinned by tests/test_harness_integrity.py
#
# All fake tokens are built at runtime (no literals). Everything stays
# under /tmp/pc-v7-verify; production is never contacted or written.
set -u
ROOT=/home/z/my-project/cleanroom
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v7-verify
rm -rf "$S"; mkdir -p "$S"
FAKE="ghp_$(printf 'a%.0s' $(seq 1 36))"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

mk_lane() {  # $1 = lane name -> $S/$1/{clone,bare,home}
  local d="$S/$1"
  mkdir -p "$d/home/scripts"
  git clone -q "$ROOT" "$d/clone"
  git init -q --bare "$d/bare.git"
  git -C "$d/clone" remote set-url origin "$d/bare.git" 2>/dev/null || true
  echo "print('ok')" > "$d/home/scripts/ok.py"
}

run_bk() {  # $1=lane $2=msg $3=push_remote; extra env via $d/env.extra
  local d="$S/$1"
  env $(cat "$d/env.extra" 2>/dev/null || true) \
    PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
    PC_BACKUP_PUSH_REMOTE="$3" \
    bash "$SCRIPT" "$2" >"$d/out" 2>&1
  echo "$?"
}

# -- E14: empty-credential spelling refusal matrix ---------------------
mk_lane e14
for t in \
  "https://@github.com/maniesh-NR/Proto-Clean.git" \
  "https://github.com:/maniesh-NR/Proto-Clean.git" \
  "https://@github.com:/maniesh-NR/Proto-Clean.git" \
  "git@github.com:/maniesh-NR/Proto-Clean.git" \
  "https://@gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git" \
  "https://GITHUB.com:/maniesh-NR/Proto-Clean.git" \
  "https://@GitHub.Com:443/maniesh-NR/Proto-Clean.git"
do
  rc=$(run_bk e14 "e14 probe" "$t")
  if [ "$rc" = 6 ] && ! grep -q "$FAKE" "$S/e14/out"; then
    ok "E14 refuse: ${t:0:46}..."
  else
    bad "E14 refused? rc=$rc target=${t:0:46}..."
  fi
done
git -C "$S/e14/clone" remote add prodempty "git@github.com:/maniesh-NR/Proto-Clean.git"
rc=$(run_bk e14 "e14 probe" "prodempty")
[ "$rc" = 6 ] && ok "E14 refuse: remote name -> scp empty path" \
  || bad "E14 remote-name empty-scp rc=$rc"
rc=$(run_bk e14 "e14 clean" "$S/e14/bare.git")
[ "$rc" = 0 ] && ok "E14 clean local lane passes" \
  || bad "E14 clean lane rc=$rc: $(tail -2 "$S/e14/out")"

# -- E15: physical production-path compares ----------------------------
# (needs the production checkout to exist — dev sandbox; this is the
#  matrix the CI machine tests cannot run, which is why it lives here)
mk_lane e15
PROD=/home/z/my-project/cleanroom
ln -sfn "$PROD" "$S/e15/prodlink"
for t in \
  "$PROD" \
  "file://$PROD" \
  "$PROD/" \
  "$PROD/.git" \
  "$S/e15/prodlink" \
  "//$PROD"
do
  rc=$(run_bk e15 "e15 target probe" "$t")
  if [ "$rc" = 6 ] && grep -q "production checkout" "$S/e15/out"; then
    ok "E15 push-target refuse: ${t:0:40}"
  else
    bad "E15 push-target rc=$rc target=${t:0:40} out=$(tail -1 "$S/e15/out")"
  fi
done
# REPO-operand spellings (symlink, symlink+slash, parent-symlink, //)
ln -sfn "$PROD" "$S/e15/repolink"
ln -sfn "$(dirname "$PROD")" "$S/e15/parentlink"
for r in \
  "$S/e15/repolink" \
  "$S/e15/repolink/" \
  "$S/e15/parentlink/$(basename "$PROD")" \
  "//$PROD"
do
  d="$S/e15"
  env PC_BACKUP_REPO="$r" PC_SANDBOX_HOME="$d/home" \
    PC_BACKUP_PUSH_REMOTE="$d/bare.git" \
    bash "$SCRIPT" "e15 repo probe" >"$d/out-repo" 2>&1
  rc=$?
  if [ "$rc" = 6 ] && grep -q "production checkout" "$d/out-repo"; then
    ok "E15 repo-operand refuse: ${r:0:40}"
  else
    bad "E15 repo-operand rc=$rc target=${r:0:40} out=$(tail -1 "$d/out-repo")"
  fi
done
rc=$(run_bk e15 "e15 clean" "$S/e15/bare.git")
[ "$rc" = 0 ] && ok "E15 clean local lane passes" \
  || bad "E15 clean lane rc=$rc: $(tail -2 "$S/e15/out")"

# -- E16: insteadOf resolution + env-config inertness ------------------
mk_lane e16
git -C "$S/e16/clone" config \
  "url.https://github.com/maniesh-NR/Proto-Clean.git.insteadOf" \
  "$S/e16/innocent"
rc=$(run_bk e16 "e16 insteadOf probe" "$S/e16/innocent")
[ "$rc" = 6 ] && ok "E16 config-file insteadOf rewrite refused" \
  || bad "E16 insteadOf rc=$rc: $(tail -2 "$S/e16/out")"
# env-injected config file must be INERT (scrubbed before any git call):
# the push goes to the local bare it was addressed to
printf '[url "git@github.com:/maniesh-NR/Proto-Clean.git"]\n\tinsteadOf = %s\n' \
  "$S/e16/bare.git" > "$S/e16/evil.conf"
d="$S/e16"
env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
  PC_BACKUP_PUSH_REMOTE="$d/bare.git" \
  GIT_CONFIG_GLOBAL="$d/evil.conf" \
  bash "$SCRIPT" "e16 config-inert probe" >"$d/out-inert" 2>&1
rc=$?
if [ "$rc" = 0 ] && ! grep -q "push failed" "$d/out-inert"; then
  ok "E16 env-injected GIT_CONFIG_GLOBAL insteadOf inert"
else
  bad "E16 config-inert rc=$rc out=$(tail -2 "$d/out-inert")"
fi

# -- E17: hostile GIT_TRACE=1 clean lane, zero trace lines -------------
mk_lane e17
d="$S/e17"
env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
  PC_BACKUP_PUSH_REMOTE="$d/bare.git" \
  GIT_TRACE=1 GIT_TRACE2=1 GIT_CURL_VERBOSE=1 \
  bash "$SCRIPT" "e17 trace probe" >"$d/out" 2>&1
rc=$?
if [ "$rc" = 0 ] && ! grep -q "trace:" "$d/out"; then
  ok "E17 hostile GIT_TRACE=1 clean lane: zero trace lines"
else
  bad "E17 trace lane rc=$rc, trace-lines=$(grep -c 'trace:' "$d/out" || true)"
fi

# -- E18: widened-window TOCTOU probe (instrumented COPY) --------------
# The exact G1-iter5 RT minor #3 window — a plant landing AFTER the
# worktree scan, BEFORE the add — widened with an inserted plant so it
# is deterministic. The INDEX re-scan must catch it (exit 4, staged
# content). The real script's scan POSITION is pinned by the machine
# suite (test_backup_script_index_rescan_positions); this probe proves
# the scan's BEHAVIOR when the window is real.
mk_lane e18
cp "$SCRIPT" "$S/e18/instrumented.sh"
python3 - "$S/e18/instrumented.sh" "$FAKE" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); fake = sys.argv[2]
src = p.read_text(encoding="utf-8")
anchor = "  git add -A harness\n"
plant = ("  # INSTRUMENTED (verify_backup_v7 E18): plant AFTER the worktree\n"
         "  # scan, BEFORE the add — the TOCTOU window, made deterministic\n"
         f"  printf 't = \"{fake}\"\\n' > harness/memory/toctou-e18.md\n")
i = src.index(anchor)
src = src[:i] + plant + src[i:]
p.write_text(src, encoding="utf-8")
PY
bash -n "$S/e18/instrumented.sh" || { bad "E18 instrumented copy does not parse"; exit 1; }
d="$S/e18"
env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
  PC_BACKUP_PUSH_REMOTE="$d/bare.git" \
  bash "$S/e18/instrumented.sh" "e18 toctou probe" >"$d/out" 2>&1
rc=$?
if [ "$rc" = 4 ] && grep -q "staged content" "$d/out"; then
  ok "E18 post-scan plant caught by the INDEX re-scan (exit 4)"
else
  bad "E18 rc=$rc out=$(tail -2 "$d/out")"
fi
# negative control: the same plant BEFORE the worktree scan is caught
# by the worktree scan (proves the plant itself is the trigger)
cp "$SCRIPT" "$S/e18/instrumented2.sh"
python3 - "$S/e18/instrumented2.sh" "$FAKE" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); fake = sys.argv[2]
src = p.read_text(encoding="utf-8")
anchor = "if secret_scan harness; then\n"
plant = (f"printf 't = \"{fake}\"\\n' > harness/memory/toctou-e18b.md\n")
i = src.index(anchor)
src = src[:i] + plant + src[i:]
p.write_text(src, encoding="utf-8")
PY
env PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
  PC_BACKUP_PUSH_REMOTE="$d/bare.git" \
  bash "$S/e18/instrumented2.sh" "e18 pre-scan control" >"$d/out2" 2>&1
rc=$?
if [ "$rc" = 4 ]; then
  ok "E18 negative control: pre-scan plant caught by the worktree scan"
else
  bad "E18 control rc=$rc out=$(tail -2 "$d/out2")"
fi

echo "----------------------------------------"
echo "verify_backup_v7: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

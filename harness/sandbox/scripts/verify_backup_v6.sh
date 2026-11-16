#!/usr/bin/env bash
# G1-iter4-i2 fix-cycle verification matrix for scripts/sandbox_backup.sh (v6).
#
# Complements verify_backup_v5.sh (E1-E8, still valid) and
# tests/test_harness_integrity.py, which machine-covers: the opt-in
# gate, the guard spellings incl. subdomains, the unreachable-remote
# alarm, shaped names, the hermetic cycle, partial overrides, the
# production-checkout refusal, refusal-echo redaction, main-push
# redaction + trace hygiene, and the union key-scrub.
# This matrix covers the v6 scenarios END-TO-END in scratch:
#   E9  github-subdomain refusal matrix (gist./www./api./education.,
#       plain + credentialed + remote-name) + the clean local lane
#   E10 partial-override refusals (all 1-of-3 and 2-of-3) + the
#       TEST-run production-checkout refusal (literal + file://)
#   E11 GIT_CURL_VERBOSE + TRACE2 + env config-injection under a
#       failing credentialed main push (local 401 server): no raw
#       credential, no verbose output, redaction labeled
#   E12 key-poison divergence union: heals (key scrubbed, remote
#       entry preserved, next run appends cleanly)
#   E13 the not-a-remote refusal never echoes the raw target
#
# All fake tokens are built at runtime (no literals). Everything stays
# under /tmp/pc-v6-verify; production is never contacted.
set -u
ROOT=/home/z/my-project/cleanroom
SCRIPT="$ROOT/scripts/sandbox_backup.sh"
S=/tmp/pc-v6-verify
rm -rf "$S"; mkdir -p "$S"
FAKE="ghp_$(printf 'a%.0s' $(seq 1 36))"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

base_env() {
  printf 'GIT_CONFIG_GLOBAL=/dev/null\nGIT_CONFIG_SYSTEM=/dev/null\n'
}

mk_lane() {  # $1 = lane name -> $S/$1/{clone,bare,home}
  local d="$S/$1"
  mkdir -p "$d/home/scripts"
  git clone -q "$ROOT" "$d/clone"
  git -C "$d/clone" remote set-url origin "$d/bare.git" 2>/dev/null || true
  git init -q --bare "$d/bare.git"
  echo "print('ok')" > "$d/home/scripts/ok.py"
}

run_bk() {  # $1=lane $2=msg $3=push_remote [$4=push_remote_extra_env]
  local d="$S/$1"
  env $(cat "$d/env.extra" 2>/dev/null || true) \
    PC_BACKUP_REPO="$d/clone" PC_SANDBOX_HOME="$d/home" \
    PC_BACKUP_PUSH_REMOTE="$3" \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    bash "$SCRIPT" "$2" >"$d/out" 2>&1
  echo "$?"
}

# -- E9: subdomain refusal matrix --------------------------------------
mk_lane e9
for t in \
  "https://gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git" \
  "https://www.github.com/maniesh-NR/Proto-Clean.git" \
  "https://api.github.com/repos/maniesh-NR/Proto-Clean" \
  "https://education.github.com/x" \
  "https://$FAKE@gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git" \
  "https://GIST.GitHub.Com./aa11bb22cc33dd44ee55ff6677aabbcc.git"
do
  rc=$(run_bk e9 "e9 probe" "$t")
  if [ "$rc" = 6 ] && ! grep -q "$FAKE" "$S/e9/out"; then
    ok "E9 refuse: ${t:0:44}..."
  else
    bad "E9 refused? rc=$rc target=${t:0:44}..."
  fi
done
git -C "$S/e9/clone" remote add gistscp "git@gist.github.com:aa11bb22cc33dd44ee55ff6677aabbcc.git"
rc=$(run_bk e9 "e9 probe" "gistscp")
[ "$rc" = 6 ] && ok "E9 refuse: remote name -> gist subdomain" \
  || bad "E9 remote-name subdomain rc=$rc"
rc=$(run_bk e9 "e9 clean" "$S/e9/bare.git")
[ "$rc" = 0 ] && ok "E9 clean local lane passes" \
  || bad "E9 clean lane rc=$rc: $(tail -2 "$S/e9/out")"

# -- E10: partial overrides + production-checkout refusal --------------
PARTIALS=(
  "PC_BACKUP_PUSH_REMOTE=$S/e10/bare.git"
  "PC_BACKUP_REPO=$S/e10/clone"
  "PC_SANDBOX_HOME=$S/e10/home"
  "PC_BACKUP_REPO=$S/e10/clone PC_BACKUP_PUSH_REMOTE=$S/e10/bare.git"
  "PC_SANDBOX_HOME=$S/e10/home PC_BACKUP_PUSH_REMOTE=$S/e10/bare.git"
  "PC_BACKUP_REPO=$S/e10/clone PC_SANDBOX_HOME=$S/e10/home"
)
for p in "${PARTIALS[@]}"; do
  rc=$(env $p GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    bash "$SCRIPT" "e10 partial" >/dev/null 2>&1; echo $?)
  if [ "$rc" = 2 ]; then ok "E10 partial refuses exit 2: ${p:0:40}..."
  else bad "E10 partial rc=$rc: $p"; fi
done
mk_lane e10
for spelling in "/home/z/my-project/cleanroom" "file:///home/z/my-project/cleanroom"
do
  rc=$(env PC_BACKUP_REPO="$spelling" PC_SANDBOX_HOME="$S/e10/home" \
    PC_BACKUP_PUSH_REMOTE="$S/e10/bare.git" \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    bash "$SCRIPT" "e10 prodrepo" >/dev/null 2>&1; echo $?)
  if [ "$rc" = 6 ]; then ok "E10 TEST-on-production-checkout refused (${spelling:0:7} spelling)"
  else bad "E10 prod-repo rc=$rc ($spelling)"; fi
done

# -- E11: CURL_VERBOSE + config injection + main-push redaction --------
mk_lane e11
git -C "$S/e11/clone" push -q "$S/e11/bare.git" main
env PC_BACKUP_REPO="$S/e11/clone" PC_SANDBOX_HOME="$S/e11/home" \
  PC_BACKUP_PUSH_REMOTE="$S/e11/bare.git" \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  bash "$SCRIPT" "e11 seed" >/dev/null 2>&1
git -C "$S/e11/clone" commit -q --allow-empty -m ahead
PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)
python3 - "$PORT" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _d(self):
        self.send_response(401); self.end_headers(); self.wfile.write(b"no")
    do_GET = _d; do_POST = _d
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
SRV=$!
sleep 1
rc=$(env PC_BACKUP_REPO="$S/e11/clone" PC_SANDBOX_HOME="$S/e11/home" \
  PC_BACKUP_PUSH_REMOTE="http://user:$FAKE@127.0.0.1:$PORT/x.git" \
  GIT_CURL_VERBOSE=1 GIT_TRACE2=1 GIT_TRACE=1 GIT_TERMINAL_PROMPT=0 \
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.verbose GIT_CONFIG_VALUE_0=true \
  NO_PROXY='*' no_proxy='*' \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  bash "$SCRIPT" "e11 leak probe" >"$S/e11/out" 2>&1; echo $?)
kill $SRV 2>/dev/null || true
if [ "$rc" = 0 ] && ! grep -q "$FAKE" "$S/e11/out" \
   && ! grep -q "Issue another request" "$S/e11/out" \
   && ! grep -q "Server auth using Basic" "$S/e11/out" \
   && grep -q "credentials redacted" "$S/e11/out"; then
  ok "E11 no credential/verbose leak; redaction labeled (rc=$rc)"
else
  bad "E11 leak lane rc=$rc: $(grep -c "$FAKE" "$S/e11/out") token hits"
fi

# -- E12: key-poison divergence union heals ----------------------------
mk_lane e12
rc=$(run_bk e12 "e12 one" "$S/e12/bare.git")
[ "$rc" = 0 ] && ok "E12 run1 healthy" || bad "E12 run1 rc=$rc"
git clone -q --branch sandbox/backups "$S/e12/clone" "$S/e12/clone2"
python3 - "$S/e12/clone2/harness/backups/manifest.json" "$FAKE" <<'PY'
import json, sys
p, fake = sys.argv[1], sys.argv[2]
doc = json.load(open(p))
doc["backups"].append({"seq": 99, "timestamp": "2030-01-01T00:00:00Z",
  "trigger": "event", "message": "poison from remote",
  fake: "innocuous", "git_head": "deadbee", "git_branch": "main",
  "main_push": "ok"})
json.dump(doc, open(p, "w"), indent=2)
PY
git -C "$S/e12/clone2" add -A
git -C "$S/e12/clone2" -c user.name=x -c user.email=x@y.z commit -q -m poison
git -C "$S/e12/clone2" push -q "$S/e12/bare.git" sandbox/backups
rc=$(run_bk e12 "e12 unreachable" "$S/nope.git")
[ "$rc" = 0 ] && ok "E12 run2 unreachable keeps checkpoint" || bad "E12 run2 rc=$rc"
echo "note" > "$S/e12/clone/harness/memory/note-e12.md"
rc=$(run_bk e12 "e12 heal" "$S/e12/bare.git")
PUSHED=$(git -C "$S/e12/bare.git" show refs/heads/sandbox/backups:harness/backups/manifest.json)
if [ "$rc" = 0 ] && ! printf '%s' "$PUSHED" | grep -q "$FAKE" \
   && printf '%s' "$PUSHED" | grep -q '\[REDACTED\]' \
   && printf '%s' "$PUSHED" | grep -q '"seq": 99' \
   && printf '%s' "$PUSHED" | grep -q 'triple'; then
  ok "E12 key-poisoned union healed (key scrubbed, entry kept, note normalized)"
else
  bad "E12 heal rc=$rc (token-in-pushed=$(printf '%s' "$PUSHED" | grep -c "$FAKE"))"
fi
echo "note2" > "$S/e12/clone/harness/memory/note-e12b.md"
rc=$(run_bk e12 "e12 append" "$S/e12/bare.git")
[ "$rc" = 0 ] && ok "E12 next run appends cleanly" || bad "E12 append rc=$rc: $(tail -2 "$S/e12/out")"

# -- E13: refusal never echoes the raw target --------------------------
mk_lane e13
rc=$(env PC_BACKUP_REPO="$S/e13/clone" PC_SANDBOX_HOME="$S/e13/home" \
  PC_BACKUP_PUSH_REMOTE="$FAKE@dead.example.com:x.git" \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  bash "$SCRIPT" "e13 echo probe" >"$S/e13/out" 2>&1; echo $?)
if [ "$rc" = 6 ] && ! grep -q "$FAKE" "$S/e13/out" \
   && grep -q '\[REDACTED\]' "$S/e13/out"; then
  ok "E13 refusal redacts the target"
else
  bad "E13 rc=$rc raw-echo=$(grep -c "$FAKE" "$S/e13/out")"
fi

echo "== v6 matrix: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1

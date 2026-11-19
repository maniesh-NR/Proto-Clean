#!/usr/bin/env bash
# G1-iter6-i2 mutation-probe battery — verifies the v10 machine/matrix
# coverage is LOAD-BEARING: each probe removes one v10 guard from a
# snapshot of the WORKING TREE (clone for history + rsync overlay —
# the sixth-incident rule: never bare HEAD while the fix is
# uncommitted) and asserts the corresponding coverage CATCHES it.
# All probes run inside /tmp snapshots; production is never touched.
set -u
PROD_REPO=/home/z/my-project/cleanroom
BASE=/tmp/pc-g1i6i2-probes
rm -rf "$BASE"; mkdir -p "$BASE"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PROBE-PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "PROBE-FAIL: $1"; }

snapshot() {  # $1 = name -> $BASE/$1 is a working-tree snapshot
  local snap="$BASE/$1"
  git clone -q "$PROD_REPO" "$snap"
  rsync -a --delete --exclude='.git' "$PROD_REPO"/ "$snap"/
}

# probe A: include/includeIf refusal removed -> the includeIf lane
# must FAIL (catch) when run from the snapshot
snapshot pA
python3 - "$BASE/pA/scripts/sandbox_backup.sh" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
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
assert old in src, "include-refusal anchor not found in probe A"
p.write_text(src.replace(old, ""), encoding="utf-8")
PY
if cd "$BASE/pA" && ! python -m pytest tests/test_harness_integrity.py::test_backup_script_guard_refuses_github_spellings -q -p no:asyncio >/dev/null 2>&1; then
  ok "A: include-refusal removal CAUGHT (lane failed)"
else
  bad "A: include-refusal removal NOT caught"
fi

# probe B: fetch-view judgment removed (push view only) -> the
# fetch-divergence lane must FAIL
snapshot pB
python3 - "$BASE/pB/scripts/sandbox_backup.sh" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
old = '''  _judge_target "$_push_tgt" "push"
  _judge_target "$_fetch_tgt" "fetch"
'''
assert old in src, "both-directions call anchor not found in probe B"
p.write_text(src.replace(old, '  _judge_target "$_push_tgt" "push"\n'),
             encoding="utf-8")
PY
if cd "$BASE/pB" && ! python -m pytest tests/test_harness_integrity.py::test_backup_script_guard_refuses_github_spellings -q -p no:asyncio >/dev/null 2>&1; then
  ok "B: fetch-view removal CAUGHT (lane failed)"
else
  bad "B: fetch-view removal NOT caught"
fi

# probe C: symlinked-.git refusal removed -> the symlink lane must FAIL
snapshot pC
python3 - "$BASE/pC/scripts/sandbox_backup.sh" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
old = '''  if [ -L "$REPO/.git" ]; then
    echo "!! refusing: PC_BACKUP_REPO/.git is a symlink — the git dir it names" >&2
    echo "   is not the repo's own (test traffic would operate on another" >&2
    echo "   checkout's git state). Clone a full scratch checkout (see" >&2
    echo "   harness/backups/README.md)." >&2
    exit 6
  fi
'''
assert old in src, "symlink-refusal anchor not found in probe C"
p.write_text(src.replace(old, ""), encoding="utf-8")
PY
if cd "$BASE/pC" && ! python -m pytest tests/test_harness_integrity.py::test_backup_script_guard_refuses_github_spellings -q -p no:asyncio >/dev/null 2>&1; then
  ok "C: symlink-refusal removal CAUGHT (lane failed)"
else
  bad "C: symlink-refusal removal NOT caught"
fi

# probe D: union order reverted to (ours, theirs) -> E34 must FAIL
snapshot pD
python3 - "$BASE/pD/scripts/sandbox_backup.sh" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
old = "    for side in (theirs, ours):"
assert src.count(old) == 1, "union-order anchor not found in probe D"
p.write_text(src.replace(old, "    for side in (ours, theirs):"),
             encoding="utf-8")
PY
if cd "$BASE/pD" && ! bash harness/backups/matrices/verify_backup_v10.sh >/dev/null 2>&1; then
  ok "D: union-order revert CAUGHT (E34 failed)"
else
  bad "D: union-order revert NOT caught"
fi

# probe E: scp redaction removed -> the redaction lane must FAIL
snapshot pE
python3 - "$BASE/pE/scripts/sandbox_backup.sh" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")
old = "; s#^[^/@[:space:]]+:[^/@[:space:]]+@#[REDACTED]@#"
assert src.count(old) == 1, "scp-redaction anchor not found in probe E"
p.write_text(src.replace(old, ""), encoding="utf-8")
PY
if cd "$BASE/pE" && ! python -m pytest tests/test_harness_integrity.py::test_backup_script_guard_refuses_github_spellings -q -p no:asyncio >/dev/null 2>&1; then
  ok "E: scp-redaction removal CAUGHT (lane failed)"
else
  bad "E: scp-redaction removal NOT caught"
fi

echo "----------------------------------------"
echo "probe battery: $PASS caught, $FAIL missed"
[ "$FAIL" = 0 ]

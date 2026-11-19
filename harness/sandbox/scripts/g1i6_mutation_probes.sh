#!/usr/bin/env bash
# G1-iter6 fix-cycle MUTATION PROBES for the v9 surfaces.
# Every guarantee claim gets a probe whose REMOVAL must FAIL a test
# (the lessons rule). All probes run in SCRATCH CLONES under
# /tmp/g1i6-mut; egress is sinkholed globally (dead https_proxy +
# GIT_SSH_COMMAND=/bin/false — neither is in the script's scrub list,
# so they reach the pushes); the guarded constant is patched to a
# stand-in in mutated copies AND the machine lanes DERIVE the constant
# from the script under test (G1-iter6 Architect M1), so the both-
# sides rule holds structurally for every probe.
set -u
ROOT=/home/z/my-project/cleanroom
S=/tmp/g1i6-mut
rm -rf "$S"; mkdir -p "$S"
export https_proxy=http://127.0.0.1:9
export http_proxy=http://127.0.0.1:9
export GIT_SSH_COMMAND=/bin/false
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

# The guard test is slow-ish; run only the affected node when the
# mutation targets one lane family, else the whole function.
GT="tests/test_harness_integrity.py::test_backup_script_guard_refuses_github_spellings"
FT="tests/test_harness_integrity.py::test_final_outcome_check_cannot_be_forged"
DT="tests/test_harness_integrity.py::test_harness_doc_references_resolve"
RT="tests/test_harness_integrity.py::test_backup_script_mainpush_redaction_and_trace_hygiene"

fresh_clone() {  # $1 = name
  # G1-iter6 SIXTH-INCIDENT rule: probe from the tree that CONTAINS
  # the fix — a bare HEAD clone while the fix sits uncommitted in the
  # working tree re-creates the one-sided patch structurally (the
  # stale clone lacks exactly the derived-lane guard). History from
  # HEAD + the WORKING TREE rsynced over it (the tests clone ROOT and
  # need full history; the v9 surfaces come from the overlay).
  rm -rf "$S/$1"
  git clone -q "$ROOT" "$S/$1"
  rsync -a --delete --exclude='.git' "$ROOT/" "$S/$1/"
}

verify_v9_tree() {  # $1 = name — the probe tree MUST carry the v9
  # anchors before any mutation (a missing anchor = inconclusive
  # probe = FAIL, never a silent skip — the battery's first run
  # silently skipped nine probes whose anchors were v9-only and the
  # stale-lane L probe pushed two junk clusters onto production's
  # local branch: the sixth accidental-checkpoint incident)
  grep -q 'GIT_DIR|GIT_WORK_TREE' "$S/$1/scripts/sandbox_backup.sh" \
    && grep -q "ids = re.findall" "$S/$1/tests/test_harness_integrity.py" \
    && grep -q 'STAGE_DECLARATION_ADOPTION' "$S/$1/tests/test_harness_integrity.py" \
    && grep -q 'verify_backup_v9' "$S/$1/harness/backups/matrices/verify_backup_v9.sh"
}

mutate() {  # $1=clone  $2=python-replacement-file
  verify_v9_tree "$1" || { echo "FAIL: $1 tree lacks v9 anchors (stale probe tree — the sixth-incident shape)"; return 1; }
  python3 "$2" "$S/$1/scripts/sandbox_backup.sh" || { echo "FAIL: mutation anchor missing in $1 (inconclusive probe)"; return 1; }
}

run_test() {  # $1=clone  $2=test-node  -> echoes PASS/FAIL of pytest
  (cd "$S/$1" && python -m pytest -q -p no:asyncio "$2" >/dev/null 2>&1 \
     && echo PASS || echo FAIL)
}

# ---------- control: the unmutated clone passes all four ----------
fresh_clone ctrl
verify_v9_tree ctrl || { echo "FAIL: control tree lacks the v9 anchors (probing a stale tree — aborting the battery)"; exit 1; }
for t in "$GT" "$FT" "$DT" "$RT"; do
  r=$(run_test ctrl "$t")
  [ "$r" = PASS ] && ok "control: $(basename "$t") passes unmutated" \
                   || { bad "control failed on $t"; }
done

# ---------- probe A: the discovery-redirection env scrub ----------
cat > "$S/mutA.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = "GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_DIR|GIT_WORK_TREE|GIT_COMMON_DIR|GIT_INDEX_FILE|GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES|GIT_CEILING_DIRECTORIES)"
new = "GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM)"
assert old in t, "anchor A"
p.write_text(t.replace(old, new))
PY
fresh_clone A && mutate A "$S/mutA.py" \
  && { r=$(run_test A "$GT"); [ "$r" = FAIL ] && ok "A: GIT_DIR family unscrubbed -> guard test FAILS (gitdir-scrub lane caught)" || bad "A survived: $r"; }

# ---------- probe B: the git-dir identity check ----------
cat > "$S/mutB.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
m = re.search(r"# -- git-dir IDENTITY check.*?\nfi\n", t, re.S)
assert m, "anchor B"
p.write_text(t.replace(m.group(0), ""))
PY
fresh_clone B && mutate B "$S/mutB.py" \
  && { r=$(run_test B "$GT"); [ "$r" = FAIL ] && ok "B: identity check removed -> guard test FAILS (subdir/worktree lanes caught)" || bad "B survived: $r"; }

# ---------- probe C: the push-target CONTAINMENT compare ----------
cat > "$S/mutC.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = '''      case "$_ptgt" in
        "$PROD_CHECKOUT"|"$PROD_CHECKOUT"/*|"$PROD_CHECKOUT/.git"|"$PROD_CHECKOUT/.git"/*)
          echo "!! refusing: env overrides mark this as a TEST run, but the push" >&2
          echo "   target is the production checkout (or inside it / its .git) —" >&2
          echo "   test traffic never touches it. Point PC_BACKUP_PUSH_REMOTE at a" >&2
          echo "   scratch bare repo (see harness/backups/README.md)." >&2
          exit 6
          ;;
      esac'''
new = '''      case "$_ptgt" in
        "$PROD_CHECKOUT"|"$PROD_CHECKOUT/.git")
          echo "!! refusing: env overrides mark this as a TEST run, but the push" >&2
          echo "   target is the production checkout (or inside it / its .git) —" >&2
          echo "   test traffic never touches it. Point PC_BACKUP_PUSH_REMOTE at a" >&2
          echo "   scratch bare repo (see harness/backups/README.md)." >&2
          exit 6
          ;;
      esac'''
assert old in t, "anchor C"
p.write_text(t.replace(old, new))
PY
fresh_clone C && mutate C "$S/mutC.py" \
  && { r=$(run_test C "$GT"); [ "$r" = FAIL ] && ok "C: target containment reverted to equality -> guard test FAILS (prod-subdir target lane caught)" || bad "C survived: $r"; }

# ---------- probe D: the pushInsteadOf config refusal ----------
cat > "$S/mutD.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
m = re.search(r"  # url\.\*\.pushInsteadOf refusal.*?\n  fi\n", t, re.S)
assert m, "anchor D"
p.write_text(t.replace(m.group(0), ""))
PY
fresh_clone D && mutate D "$S/mutD.py" \
  && { r=$(run_test D "$GT"); [ "$r" = FAIL ] && ok "D: pushInsteadOf refusal removed -> guard test FAILS (rewrite lane caught)" || bad "D survived: $r"; }

# ---------- probe E: the :: transport refusal ----------
cat > "$S/mutE.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
m = re.search(r"  # helper-TRANSPORT refusal.*?\n  esac\n", t, re.S)
assert m, "anchor E"
p.write_text(t.replace(m.group(0), ""))
PY
fresh_clone E && mutate E "$S/mutE.py" \
  && { r=$(run_test E "$GT"); [ "$r" = FAIL ] && ok "E: :: transport refusal removed -> guard test FAILS (ext/fd lanes caught)" || bad "E survived: $r"; }

# ---------- probe F: the percent-encoding refusal ----------
cat > "$S/mutF.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
m = re.search(r"  # PERCENT-ENCODED host refusal.*?\n  esac\n", t, re.S)
assert m, "anchor F"
p.write_text(t.replace(m.group(0), ""))
PY
fresh_clone F && mutate F "$S/mutF.py" \
  && { r=$(run_test F "$GT"); [ "$r" = FAIL ] && ok "F: %-refusal removed -> guard test FAILS (percent lanes caught; egress sinkholed)" || bad "F survived: $r"; }

# ---------- probe G: the every-relative refusal (revert to ./-only) ----------
cat > "$S/mutG.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = '''    *)
      echo "!! refusing: PC_BACKUP_PUSH_REMOTE resolves to a RELATIVE target" >&2
      echo "   (however carried — direct operand or a remote's URL) — the push" >&2
      echo "   executes from a temporary worktree, so a relative target resolves" >&2
      echo "   somewhere the guard never judged. Use an absolute scratch path" >&2
      echo "   (see harness/backups/README.md)." >&2
      exit 6
      ;;
  esac'''
new = '''  esac'''
assert old in t, "anchor G"
p.write_text(t.replace(old, new))
PY
fresh_clone G && mutate G "$S/mutG.py" \
  && { r=$(run_test G "$GT"); [ "$r" = FAIL ] && ok "G: every-relative reverted to prefix-only -> guard test FAILS (remote-carried interior-.. lane caught)" || bad "G survived: $r"; }

# ---------- probe H: the first-colon host cut ----------
cat > "$S/mutH.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = '''    case "$_host" in *@*) _host="${_host##*@}" ;; esac
    _host="${_host%%:*}"
    while [ "${_host:0-1}" = "." ] && [ -n "$_host" ]; do _host="${_host%.}"; done'''
new = '''    case "$_host" in *@*) _host="${_host##*@}" ;; esac'''
assert old in t, "anchor H"
p.write_text(t.replace(old, new))
PY
fresh_clone H && mutate H "$S/mutH.py" \
  && { r=$(run_test H "$GT"); [ "$r" = FAIL ] && ok "H: first-colon cut + dot collapse removed -> guard test FAILS (:22: / trailing-dot lanes caught)" || bad "H survived: $r"; }

# ---------- probe I: the raw-IP refusal ----------
cat > "$S/mutI.py" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); t = p.read_text()
m = re.search(r"    # raw-IP refusal.*?\n    esac\n", t, re.S)
assert m, "anchor I"
p.write_text(t.replace(m.group(0), ""))
PY
fresh_clone I && mutate I "$S/mutI.py" \
  && { r=$(run_test I "$GT"); [ "$r" = FAIL ] && ok "I: raw-IP refusal removed -> guard test FAILS (IP lanes caught; egress sinkholed)" || bad "I survived: $r"; }

# ---------- probes K1-K6: the glyph-rule hardenings ----------
mutate_k() {  # $1=clone $2=pyfile $3=label
  fresh_clone "$1" && python3 "$2" "$S/$1/tests/test_harness_integrity.py" \
    && { r=$(run_test "$1" "$FT"); [ "$r" = FAIL ] && ok "K: $3 -> forgery test FAILS" || bad "K survived: $3 ($r)"; }
}
cat > "$S/mutK1.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """        backs_consensus[name] = (
            d is not None and d >= STAGE_DECLARATION_ADOPTION
            and m is not None"""
new = """        backs_consensus[name] = (
            d is not None
            and m is not None"""
assert old in t, "anchor K1"
p.write_text(t.replace(old, new))
PY
mutate_k K1 "$S/mutK1.py" "backing adoption threshold removed"

cat > "$S/mutK2.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """        if len(re.findall(r"(?m)^Date: ", text)) > 1:
            violations.append(
                f"{name} carries multiple 'Date:' headers — exactly one is "
                f"required (first-match date parsing is forgeable)")
"""
assert old in t, "anchor K2"
p.write_text(t.replace(old, ""))
PY
mutate_k K2 "$S/mutK2.py" "multi-Date detection removed"

cat > "$S/mutK3.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = "            ids = re.findall(r\"\\bS(\\d+)\\b\", line)"
new = "            _m = re.search(r\"\\bS(\\d+)\\b\", line)\n            ids = [_m.group(1)] if _m else []"
assert old in t, "anchor K3"
p.write_text(t.replace(old, new))
PY
mutate_k K3 "$S/mutK3.py" "multi-id check reverted to first-id-only"

cat > "$S/mutK4.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """        if re.search(r"[\u2705\u2714\u2713]", line):
            violations.append(
                f"roadmap line carries a done-claim lookalike glyph "
                f"(\u2705/\u2714/\u2713) — the status legend defines exactly "
                f"\u2610/\u25d0/\u2611: {line.strip()!r}")
"""
assert old in t, "anchor K4"
p.write_text(t.replace(old, ""))
PY
mutate_k K4 "$S/mutK4.py" "lookalike-glyph scan removed"

cat > "$S/mutK5.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """                if (line.lstrip().startswith("- ")
                        and not (section.startswith("shipped")
                                 and "retrospectively assessed" in section)):
                    violations.append(
                        f"roadmap marks work done/active (glyph) with no "
                        f"stage id outside the 'Shipped' section: "
                        f"{line.strip()!r}")"""
new = """                if ("\u2611" in line and line.lstrip().startswith("- ")
                        and not (section.startswith("shipped")
                                 and "retrospectively assessed" in section)):
                    violations.append(
                        f"roadmap marks work done (glyph) with no "
                        f"stage id outside the 'Shipped' section: "
                        f"{line.strip()!r}")"""
assert old in t, "anchor K5"
p.write_text(t.replace(old, new))
PY
mutate_k K5 "$S/mutK5.py" "id-less rule reverted to \u2611-only"

cat > "$S/mutK6.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """                raw_last = _last_line(text)
                if outcome_lines[0] != raw_last:
                    violations.append(
                        f"{name}: non-blank content (a fenced addendum?) "
                        f"follows the FINAL OUTCOME line — post-closure "
                        f"fences are auditable forgeries, not formatting")
"""
assert old in t, "anchor K6"
p.write_text(t.replace(old, ""))
PY
mutate_k K6 "$S/mutK6.py" "post-closure raw-text check removed"

# ---------- probe L: lanes DERIVE the guarded identity (positive) ----------
fresh_clone L
python3 - "$S/L/scripts/sandbox_backup.sh" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = 'PROD_CHECKOUT="/home/z/my-project/cleanroom"'
assert old in t
p.write_text(t.replace(old, 'PROD_CHECKOUT="/tmp/g1i6-mut/standin-prod"'))
PY
mkdir -p "$S/standin-prod" && git clone -q "$ROOT" "$S/standin-prod/checkout" 2>/dev/null
r=$(run_test L "$GT")
[ "$r" = PASS ] && ok "L: constant patched to a stand-in -> guard test still PASSES (lanes derive the constant — the seq-1'/2'/13 one-sided-patch class is structurally closed)" \
  || bad "L: derivation broken: $r"

# ---------- probe M: the loopback exemption ----------
cat > "$S/mutM.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = """    case "$_host" in
      127.*) : ;;
      *[!0-9.]*) : ;;
      *)"""
new = """    case "$_host" in
      *[!0-9.]*) : ;;
      *)"""
assert old in t, "anchor M"
p.write_text(t.replace(old, new))
PY
fresh_clone M && mutate M "$S/mutM.py" \
  && { r=$(run_test M "$RT"); [ "$r" = FAIL ] && ok "M: loopback exemption removed -> redaction test FAILS (127.0.0.1 sink wrongly refused)" || bad "M survived: $r"; }

# ---------- probe N: the doc baseline-agreement lane ----------
fresh_clone N
python3 - "$S/N/harness/memory/00-project-state.md" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = "**Test baseline**: local sandbox **728 passed + 9 skipped**"
assert old in t
p.write_text(t.replace(old, "**Test baseline**: local sandbox **999 passed + 9 skipped**"))
PY
r=$(run_test N "$DT")
[ "$r" = FAIL ] && ok "N: one doc's baseline pair drifted -> doc test FAILS (agreement lane caught it)" \
  || bad "N survived: $r"

echo "----------------------------------------"
echo "mutation probes: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]

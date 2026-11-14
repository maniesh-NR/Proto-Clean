#!/usr/bin/env bash
# Event-driven sandbox backup — run as the LAST step of every
# execution plan / prompt output. Never on a timer.
#
#   scripts/sandbox_backup.sh "message describing this checkpoint"
#
# Design (see harness/backups/README.md + consensus-log 2026-11-13):
#   * the MAIN CHECKOUT IS NEVER WRITTEN: all backup state is built
#     inside a temporary git worktree on the 'sandbox/backups' branch
#     (harness/sandbox/ is .gitignored on main; the worktree adds it
#     with -f, so the ignore rule protects main without blocking the
#     branch — G1-iter2 critical #1)
#   * append-only: one plain commit per backup, NO amend, NO force-push
#     — commit SHAs live in `git log sandbox/backups` keyed by the
#     manifest sequence numbers; a local branch ahead of origin keeps
#     its unpushed commits (never silently discarded)
#   * the secret scan is ERE (G1-iter2 critical #2), SELF-TESTED at
#     every run with runtime-built canaries — one canary per pattern
#     alternation, checked through THE PRODUCTION scan invocation, so
#     neither pattern drift nor flag drift can pass silently
#     (G1-iter3 criticals #1+#2) — and covers the sandbox scripts dir,
#     the checkpoint message, and the exact backup tree
#   * test isolation (G1-iter3 major #1): any env override
#     (PC_BACKUP_REPO / PC_SANDBOX_HOME / PC_BACKUP_PUSH_REMOTE) marks
#     the run as a TEST run, and a test run whose push target resolves
#     to the production origin ABORTS (exit 6) — test traffic can never
#     reach github, not even via a clone's origin
#   * divergence self-heals (G1-iter3 major #1): if the remote branch
#     has commits we lack, the script merges it inside the worktree
#     with a programmatic manifest union — append-only preserved, no
#     force-push, no human in the loop
#   * every run refreshes harness/ memory+process docs from the live
#     checkout onto the branch (branch-owned sandbox/ + manifest are
#     protected), so the branch is self-contained per checkpoint
#     (G1-iter3 major #2); 2+ consecutive main-push failures raise a
#     loud exit-7 alarm after the backup itself is safely pushed
#   * a mkdir lock with atomic steal + PID/age staleness serializes
#     concurrent runs (G1-iter3 minors)
#   * the manifest is written atomically; a corrupt copy is recovered
#     from the branch's git history, never silently reset
set -euo pipefail

REPO="${PC_BACKUP_REPO:-/home/z/my-project/cleanroom}"
REPO="${REPO#file://}"          # accept file:// URLs (G1-iter3 major #1)
SANDBOX_HOME="${PC_SANDBOX_HOME:-/home/z/my-project}"
PUSH_URL="${PC_BACKUP_PUSH_REMOTE:-origin}"
BRANCH="sandbox/backups"
SANDBOX_SCRIPTS="$SANDBOX_HOME/scripts"
LOCK="/tmp/pc-sandbox-backup.lock"

cd "$REPO"
MSG="${1:-checkpoint}"
if [ "$#" -gt 1 ]; then
  echo "usage: scripts/sandbox_backup.sh \"message\"" >&2
  exit 2
fi

# -- git identity self-sufficiency (G1-iter3 fix-cycle extension,
#    2026-11-13): backups are the MANDATORY last step of every
#    execution plan, so the script must be able to commit even where no
#    ambient identity is configured (fresh sandboxes, CI runners — the
#    hermetic CI test caught exactly this: 5/7 legs have no global git
#    identity and died at the first commit). The fallback identity is
#    used ONLY when none is configured anywhere; an existing identity
#    keeps authoring the commits as before.
if [ -z "$(git config user.email 2>/dev/null || true)" ]; then
  export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-Proto Clean Sandbox Backup}"
  export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-backup@sandbox.protoclean.invalid}"
  export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-Proto Clean Sandbox Backup}"
  export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-backup@sandbox.protoclean.invalid}"
  echo "== no git identity configured — using the built-in backup identity for this run's commits"
fi

# -- test-mode isolation (G1-iter3 major #1) -------------------------
# Any env override marks this as a TEST run. A test run must never
# push to the production origin — even when $REPO is a clone of the
# production repo whose 'origin' IS github (the iter-2 accidental-run
# class, propagated). Refuse before anything else happens.
TEST_MODE=0
[ "$REPO" != "/home/z/my-project/cleanroom" ] && TEST_MODE=1
[ "$SANDBOX_HOME" != "/home/z/my-project" ] && TEST_MODE=1
[ -n "${PC_BACKUP_PUSH_REMOTE:-}" ] && TEST_MODE=1
if [ "$TEST_MODE" = 1 ] && [ "$PUSH_URL" = "origin" ]; then
  # resolve origin WITHOUT ever printing it (it may embed a token)
  if git remote get-url origin 2>/dev/null | grep -q 'github\.com[:/]maniesh-NR/Proto-Clean'; then
    echo "!! refusing: env overrides mark this as a TEST run, but the push target 'origin'" >&2
    echo "   is the PRODUCTION github repo. Retarget it first:" >&2
    echo "     git remote set-url origin /path/to/your-test-bare.git" >&2
    echo "   or point PC_BACKUP_PUSH_REMOTE at your test bare repo." >&2
    exit 6
  fi
fi

# -- remote plumbing: every fetch/push goes through $PUSH_URL --------
case "$PUSH_URL" in
  *://*|/*|./*)
    : # a URL or filesystem path — git addresses it directly
    ;;
  *)
    git remote get-url "$PUSH_URL" >/dev/null 2>&1 || {
      echo "!! push target '$PUSH_URL' is not a configured remote (set PC_BACKUP_PUSH_REMOTE to a remote name, path or URL)" >&2
      exit 6
    }
    ;;
esac
if [ "$PUSH_URL" = "origin" ]; then
  RMAIN="refs/remotes/origin/main"
  RBRANCH="refs/remotes/origin/$BRANCH"
  fetch_main()   { git fetch -q origin "+refs/heads/main:$RMAIN" 2>/dev/null || true; }
  fetch_branch() { git fetch -q origin "+refs/heads/$BRANCH:$RBRANCH" 2>/dev/null || true; }
else
  RMAIN="refs/remotes/pcbk/main"
  RBRANCH="refs/remotes/pcbk/$BRANCH"
  fetch_main()   { git fetch -q "$PUSH_URL" "+refs/heads/main:$RMAIN" 2>/dev/null || true; }
  fetch_branch() { git fetch -q "$PUSH_URL" "+refs/heads/$BRANCH:$RBRANCH" 2>/dev/null || true; }
fi

# -- secret patterns (ERE — grep -E / grep -En everywhere) ------------
SECRET_PATTERNS='github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghv_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY'

# EVERY scan surface routes through this ONE invocation (G1-iter3
# critical #2): the self-test exercises the production code path, so
# flag drift here is a caught failure, not a silent one.
secret_scan() {
  grep -rEn --exclude-dir='__pycache__' "$SECRET_PATTERNS" "$@" -l
}

# -- self-test: one canary per alternation, through the PRODUCTION
#    invocation (G1-iter3 criticals #1+#2). Canaries are BUILT at
#    runtime (prefix + repeated chars) so this script never contains a
#    literal credential-shaped string either.
_st="$(mktemp -d /tmp/pc-scan-selftest.XXXXXX)"
_canary_github_pat="github_pat_""$(printf 'A%.0s' $(seq 1 40))"
_canary_ghp="ghp_""$(printf 'a%.0s' $(seq 1 40))"
_canary_gho="gho_""$(printf 'b%.0s' $(seq 1 40))"
_canary_ghs="ghs_""$(printf 'c%.0s' $(seq 1 40))"
_canary_ghv="ghv_""$(printf 'd%.0s' $(seq 1 40))"
_canary_aws="AKIA""IOSFODNN7EXAMPLE"
_canary_rsa="-----BEGIN ""RSA PRIVATE KEY-----"
_canary_ec="-----BEGIN ""EC PRIVATE KEY-----"
_canary_pk="-----BEGIN ""PRIVATE KEY-----"
printf '%s' "$_canary_github_pat" > "$_st/canary_github_pat.txt"
printf '%s' "$_canary_ghp"        > "$_st/canary_ghp.txt"
printf '%s' "$_canary_gho"        > "$_st/canary_gho.txt"
printf '%s' "$_canary_ghs"        > "$_st/canary_ghs.txt"
printf '%s' "$_canary_ghv"        > "$_st/canary_ghv.txt"
printf '%s' "$_canary_aws"        > "$_st/canary_aws.txt"
printf '%s' "$_canary_rsa"        > "$_st/canary_rsa.txt"
printf '%s' "$_canary_ec"         > "$_st/canary_ec.txt"
printf '%s' "$_canary_pk"         > "$_st/canary_pk.txt"
printf 'nothing credential-shaped in here, just a clean file\n' > "$_st/clean.txt"
_selftest_fail() {
  echo "!! secret-scan SELF-TEST failed: $1 — aborting (a silently-blind scanner is worse than none)" >&2
  rm -rf "$_st"; exit 5
}
for c in github_pat ghp gho ghs ghv aws rsa ec pk; do
  if ! secret_scan "$_st" 2>/dev/null | grep -q "/canary_$c.txt$"; then
    _selftest_fail "canary '$c' not caught by the production scan"
  fi
done
if secret_scan "$_st" 2>/dev/null | grep -q "/clean.txt$"; then
  _selftest_fail "the pattern matches clean content (over-broad)"
fi
rm -rf "$_st"

# -- lock: serialize runs; ATOMIC steal of a stale lock (exactly one
#    racer wins — G1-iter3 minor #2 / Architect minor #4); a lock whose
#    pid is dead OR whose dir is older than 5 minutes (pid-recycled) is
#    stale; every contention path exits cleanly with code 3.
if ! mkdir "$LOCK" 2>/dev/null; then
  # decide staleness WITHOUT touching the lock: moving a LIVE lock away
  # opens a window in which a third run can mkdir a fresh lock and
  # overlap the owner (proven by the G1-iter3 concurrency matrix).
  STALE=1
  _pid="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
    STALE=0
    # alive — but a lock older than 5 min may belong to a recycled PID
    if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +5 2>/dev/null)" ]; then
      STALE=1
    fi
  fi
  if [ "$STALE" = 1 ]; then
    if mv "$LOCK" "$LOCK.stale.$$" 2>/dev/null; then
      echo "== removing stale lock (dead pid or older than 5 min)"
      rm -rf "$LOCK.stale.$$"
      if ! mkdir "$LOCK" 2>/dev/null; then
        echo "== another backup just took the lock; aborting" >&2
        exit 3
      fi
    else
      echo "== another backup is running (lock contended); aborting" >&2
      exit 3
    fi
  else
    echo "== another backup is running; aborting (event-driven backups never overlap)" >&2
    exit 3
  fi
fi
echo $$ > "$LOCK/pid"
trap 'rm -rf "$LOCK" 2>/dev/null || true' EXIT

# -- 1. main ahead? push it (product code + memory = part of backup) --
# A FAILED MAIN PUSH DOES NOT ABORT THE BACKUP: warn, record it in the
# manifest entry, continue — but 2+ consecutive failures raise a loud
# alarm after the backup completes (exit 7; G1-iter3 Architect major #2).
MAIN_PUSH="ok"
fetch_main
if git rev-parse --verify "$RMAIN" >/dev/null 2>&1; then
  AHEAD=$(git rev-list --count "$RMAIN..main" 2>/dev/null || echo 0)
  if [ "$AHEAD" -gt 0 ]; then
    echo "== pushing main ($AHEAD commit(s))"
    _mperr="$(mktemp /tmp/pc-mainpush.XXXXXX)"
    if ! git push "$PUSH_URL" main 2>"$_mperr"; then
      MAIN_PUSH="failed"
      echo "!! main push failed (diverged? network?) — stderr:" >&2
      sed 's/^/   /' "$_mperr" >&2
      echo "!! backing up the sandbox snapshot anyway" >&2
    fi
    rm -f "$_mperr"
  fi
fi

# -- 2. secret scan layer 1: the sandbox scripts source dir ------------
# (-rptgoD, not -a: symlinks are SKIPPED, so a link's target path can
#  never enter the tree unscanned — G1-iter3 Red Team minor #8)
if [ -d "$SANDBOX_SCRIPTS" ]; then
  if secret_scan "$SANDBOX_SCRIPTS"; then
    echo "!! SECRET DETECTED in sandbox scripts — backup ABORTED:" >&2
    secret_scan "$SANDBOX_SCRIPTS" >&2
    echo "Remove the credential (read it from env / the git remote) and retry." >&2
    exit 4
  fi
fi

# -- 3. the checkpoint message itself is a channel: scan it BEFORE it
#    is ever echoed (G1-iter3 Red Team minor #1) ----------------------
_msgfile="$(mktemp /tmp/pc-msg.XXXXXX)"
printf '%s' "$MSG" > "$_msgfile"
if secret_scan "$_msgfile"; then
  echo "!! SECRET DETECTED in the checkpoint message — backup ABORTED" >&2
  rm -f "$_msgfile"
  exit 4
fi
rm -f "$_msgfile"
echo "== sandbox backup: $MSG"

# -- 4. temporary worktree on the backup branch -----------------------
git worktree prune >/dev/null 2>&1 || true   # drop stale registrations
TMPWT="$(mktemp -d /tmp/pc-backup.XXXXXX)"
trap 'git -C "$REPO" worktree remove --force "$TMPWT" >/dev/null 2>&1 || true; rm -rf "$LOCK" 2>/dev/null || true' EXIT

fetch_branch
BASE_REF=""
if git rev-parse --verify "$RBRANCH" >/dev/null 2>&1; then
  BASE_REF="$RBRANCH"
  # local ahead of origin (previous push failed)? keep those commits
  if git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
    LOCAL_AHEAD=$(git rev-list --count "$RBRANCH..$BRANCH" 2>/dev/null || echo 0)
    if [ "$LOCAL_AHEAD" -gt 0 ]; then
      echo "== local $BRANCH is $LOCAL_AHEAD commit(s) ahead of origin — keeping them"
      BASE_REF="$BRANCH"
    fi
  fi
elif git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  BASE_REF="$BRANCH"
else
  echo "== creating branch $BRANCH from main"
fi

if [ -n "$BASE_REF" ]; then
  git worktree add --quiet --detach "$TMPWT" "$BASE_REF"
else
  git worktree add --quiet --detach "$TMPWT" main
fi
cd "$TMPWT"
git checkout --quiet --no-track -B "$BRANCH" "${BASE_REF:-main}"

# -- 5. build the backup state INSIDE the worktree only ---------------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MAIN_HEAD="$(git -C "$REPO" rev-parse --short HEAD)"
MAIN_BRANCH="$(git -C "$REPO" branch --show-current)"
[ -n "$MAIN_BRANCH" ] || MAIN_BRANCH="detached"   # G1-iter3 minor #4

mkdir -p harness/sandbox/scripts harness/backups

# 5-0. refresh harness/ memory + process docs from the live checkout
#      so the branch is self-contained as of every checkpoint
#      (G1-iter3 Architect major #2). Branch-owned state is protected:
#      sandbox/ (the snapshot itself) and backups/manifest.json (the
#      append-only audit trail). -rptgoD skips symlinks (see layer 1).
rsync -rptgoD --delete --exclude='/sandbox' --exclude='/backups/manifest.json' \
  "$REPO/harness"/ harness/

# 5a. sandbox scripts snapshot
if [ -d "$SANDBOX_SCRIPTS" ]; then
  rsync -rptgoD --delete --exclude '__pycache__' \
    "$SANDBOX_SCRIPTS"/ harness/sandbox/scripts/
fi

# 5b. sandbox inventory (scripts/download/skills; upload/ is
#     deliberately NOT listed — user uploads may have sensitive FILE
#     NAMES; credential-looking names are filtered by WORD and by SHAPE
#     — G1-iter3 Red Team major #2)
SANDBOX_HOME="$SANDBOX_HOME" TS="$TS" MAIN_HEAD="$MAIN_HEAD" \
MAIN_BRANCH="$MAIN_BRANCH" MAIN_PUSH="$MAIN_PUSH" python3 - <<'PY'
import json, os, re
ts = os.environ["TS"]; head = os.environ["MAIN_HEAD"]
branch = os.environ["MAIN_BRANCH"]; home = os.environ["SANDBOX_HOME"]
BAD_WORDS = ("token", "secret", "credential", "passwd", "password", "key")
BAD_SHAPE = re.compile(r'(?i)(github_pat_|ghp_|gho_|ghs_|ghv_|akia)[a-z0-9_]{8,}')
def inv(path):
    try:
        names = sorted(os.listdir(os.path.join(home, path)))
    except OSError:
        return []
    out = []
    for n in names:
        if any(b in n.lower() for b in BAD_WORDS):
            continue
        if BAD_SHAPE.search(n):
            continue
        out.append(n)
    return out
state = {
    "timestamp": ts,
    "git_head": head,
    "git_branch": branch,
    "main_push": os.environ["MAIN_PUSH"],
    "sandbox": {
        "download": inv("download"),
        "scripts": inv("scripts"),
        "skills": inv("skills"),
    },
}
with open("harness/sandbox/state.json", "w") as f:
    json.dump(state, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# 5c. append to the manifest (branch-owned; main keeps the empty seed).
#     The write is ATOMIC (tmpfile + os.replace); a corrupt working copy
#     is recovered by walking the branch's git history for the last
#     parseable manifest — never a silent reset (G1-iter3 minor #3).
#     Also computes the consecutive-main-push-failure streak for the
#     exit-7 alarm (G1-iter3 Architect major #2: the alarm fires on a
#     STREAK of 2+, not the first failure — one transient is recorded,
#     two in a row means main is not surviving this machine).
TS="$TS" MSG="$MSG" MAIN_HEAD="$MAIN_HEAD" MAIN_BRANCH="$MAIN_BRANCH" \
MAIN_PUSH="$MAIN_PUSH" python3 - <<'PY' >"$TMPWT/.manifest-out"
import json, os, subprocess, sys, tempfile
ts, msg = os.environ["TS"], os.environ["MSG"]
path = "harness/backups/manifest.json"
recovered_from = None
doc = None
parse_failed = False
try:
    with open(path) as f:
        doc = json.load(f)
except (OSError, ValueError):
    doc = None
    parse_failed = True
usable = isinstance(doc, dict) and isinstance(doc.get("backups"), list)
if not usable:
    # working copy unparseable / wrong shape — recover the last usable
    # copy from the branch's own history (walk ancestors, newest first)
    try:
        shas = subprocess.run(
            ["git", "log", "--format=%H", "-n", "15", "--", path],
            capture_output=True, text=True, check=True).stdout.split()
    except Exception:
        shas = []
    for sha in shas:
        try:
            blob = subprocess.run(
                ["git", "show", f"{sha}:harness/backups/manifest.json"],
                capture_output=True, text=True, check=True).stdout
            cand = json.loads(blob)
            if isinstance(cand, dict) and isinstance(cand.get("backups"), list):
                doc, recovered_from = cand, sha[:12]
                break
        except Exception:
            continue
    if doc is not None:
        print(f"!! working manifest.json unparseable — RECOVERED {len(doc['backups'])} "
              f"prior entries from git history ({recovered_from})", file=sys.stderr)
    else:
        print("!! manifest.json unparseable AND no usable copy in the last 15 "
              "commits — starting a fresh audit trail (reset marker recorded)",
              file=sys.stderr)
        doc = {"backups": []}
if not isinstance(doc, dict) or doc.get("schema") != 2:
    # migrate (e.g. the schema-1 seed from main) KEEPING prior entries
    prev = doc.get("backups", []) if isinstance(doc, dict) else []
    doc = {"schema": 2, "note": "Append-only audit trail (branch-owned; "
                                "SHAs live in git log of this branch; "
                                "entries keyed by seq).",
           "backups": prev}
seq = (doc["backups"][-1]["seq"] + 1) if doc["backups"] else 1
entry = {
    "seq": seq, "timestamp": ts, "trigger": "event", "message": msg,
    "git_head": os.environ["MAIN_HEAD"],
    "git_branch": os.environ["MAIN_BRANCH"],
    "main_push": os.environ["MAIN_PUSH"],
}
if recovered_from:
    entry["manifest_recovered_from"] = recovered_from
elif parse_failed and not doc["backups"]:
    entry["manifest_reset"] = True
doc["backups"].append(entry)
d = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(dir=d, prefix=".manifest.", suffix=".tmp")
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
print(f"== manifest entry #{seq}: {msg}")
# main-push-failure streak (including this entry) for the exit-7 alarm
streak = 0
for e in reversed(doc["backups"]):
    if e.get("main_push") == "failed":
        streak += 1
    else:
        break
if streak >= 2:
    print(f"MAIN-PUSH-ALARM: {streak} consecutive backups could not push main")
PY
cat "$TMPWT/.manifest-out"
case "$(cat "$TMPWT/.manifest-out")" in
  *MAIN-PUSH-ALARM*) MAINPUSH_ALARM=1 ;;
  *)                  MAINPUSH_ALARM=0 ;;
esac
rm -f "$TMPWT/.manifest-out"

# 5d. secret scan layer 2: the exact tree that would be pushed
if secret_scan harness/sandbox harness/backups; then
  echo "!! SECRET DETECTED in backup tree — ABORTED (nothing pushed)" >&2
  exit 4
fi

# -- 6. commit (append-only; -f: harness/sandbox/ is gitignored on
#    main by design — the ignore protects main, the branch tracks it) --
if [ -z "$(git status --porcelain harness)" ]; then
  echo "== nothing new to back up on $BRANCH"
else
  git add -A harness
  git add -f harness/sandbox harness/backups
  git commit -q -m "[sandbox-backup] $MSG" \
    -m "Event-driven checkpoint (see harness/backups/README.md). repo HEAD: $MAIN_HEAD ($MAIN_BRANCH). Append-only; no force-push."
  SHA="$(git rev-parse --short HEAD)"

  # 6b. push — and self-heal a DIVERGED remote branch (G1-iter3
  #     Architect major #1): if the remote has commits we lack, merge
  #     it here (programmatic manifest union, ours for state.json) and
  #     push the merge commit. Append-only is preserved; force-push is
  #     never attempted; unresolvable conflicts abort loudly (exit 8).
  #     Push stderr is CAPTURED and printed on failure (a silent push
  #     failure burned a full CI debugging cycle on 2026-11-14: two
  #     rc-0 runs, branch never landed in the remote, error discarded).
  _bperr="$(mktemp /tmp/pc-branchpush.XXXXXX)"
  if ! git push "$PUSH_URL" "$BRANCH" 2>"$_bperr"; then
    echo "== branch push failed — stderr:" >&2
    sed 's/^/   /' "$_bperr" >&2
    rm -f "$_bperr"
    echo "== checking for divergence"
    fetch_branch
    if ! git rev-parse --verify "$RBRANCH" >/dev/null 2>&1; then
      echo "!! branch push failed (remote rejected or unreachable? — see stderr above) — commit kept locally; next run retries" >&2
    elif git merge-base --is-ancestor "$RBRANCH" HEAD 2>/dev/null; then
      echo "!! branch push failed (network?) — commit kept locally; next run retries" >&2
    else
      echo "== remote $BRANCH has commits we lack — merging (append-only preserved)"
      if git merge --no-edit "$RBRANCH"; then
        git push "$PUSH_URL" "$BRANCH"
      else
        git checkout --ours harness/sandbox/state.json 2>/dev/null || true
        if ! MERGE_HEAD_REF="$RBRANCH" python3 - <<'PY'
import json, os, subprocess, sys, tempfile
theirs_ref = os.environ["MERGE_HEAD_REF"]
def show(ref):
    try:
        out = subprocess.run(["git", "show", f"{ref}:harness/backups/manifest.json"],
                             capture_output=True, text=True, check=True).stdout
        d = json.loads(out)
        if isinstance(d, dict) and d.get("schema") == 2 and isinstance(d.get("backups"), list):
            return d
    except Exception:
        pass
    return None
ours, theirs = show("HEAD"), show(theirs_ref)
if ours is None and theirs is None:
    print("!! neither side has a parseable manifest — starting a fresh "
          "audit trail with a reset marker", file=sys.stderr)
    doc = {"schema": 2, "note": "Append-only audit trail.", "backups": [],
           "merged_divergence": True, "merge_reset": True}
elif ours is None:
    doc = dict(theirs); doc["merged_divergence"] = True
    doc["merge_ours_unparseable"] = True
    print("!! our manifest unparseable — kept the remote side's entries "
          "(marker recorded)", file=sys.stderr)
elif theirs is None:
    doc = dict(ours); doc["merged_divergence"] = True
    doc["merge_theirs_unparseable"] = True
    print("!! remote manifest unparseable — kept our entries (marker recorded)",
          file=sys.stderr)
else:
    merged = {}
    for side in (ours, theirs):
        for e in side.get("backups", []):
            merged[(e.get("seq"), e.get("timestamp"), e.get("message", ""))] = e
    doc = {"schema": 2,
           "note": ours.get("note", "Append-only audit trail."),
           "backups": sorted(merged.values(), key=lambda e: (e.get("seq", 0), e.get("timestamp", ""))),
           "merged_divergence": True}
path = "harness/backups/manifest.json"
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".manifest.", suffix=".tmp")
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
print(f"== manifest divergence-merged: {len(doc['backups'])} entries (union)")
PY
        then
          echo "!! divergence merge could not be completed automatically — ABORT (exit 8)" >&2
          exit 8
        fi
        git add harness/backups/manifest.json
        git add -f harness/sandbox/state.json 2>/dev/null || true
        if git diff --name-only --diff-filter=U | grep -q .; then
          echo "!! unresolved conflicts beyond the manifest — ABORT (exit 8); manual recovery required" >&2
          exit 8
        fi
        git commit --no-edit -q
        git push "$PUSH_URL" "$BRANCH"
      fi
    fi
  fi
  rm -f "$_bperr" 2>/dev/null || true
  echo "== backup commit $SHA recorded on $BRANCH (branch tip: $(git rev-parse --short HEAD))"
fi

echo "== backup complete: $TS (repo HEAD $MAIN_HEAD on $MAIN_BRANCH, main push: $MAIN_PUSH)"

# -- 7. main-push alarm (G1-iter3 Architect major #2): the backup is
#    safely pushed, but main has failed to push for 2+ consecutive
#    checkpoints — that means product code + memory are NOT surviving
#    this machine. Loud, non-zero, impossible to miss.
if [ "$MAINPUSH_ALARM" = 1 ]; then
  echo "" >&2
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
  echo "!! MAIN-PUSH-ALARM: product code could NOT be pushed to the remote" >&2
  echo "!! again this checkpoint. The sandbox snapshot is safe, but main" >&2
  echo "!! is not surviving this machine — owner attention required." >&2
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
  exit 7
fi

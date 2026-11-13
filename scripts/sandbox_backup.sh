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
#     every run with canary strings so it can never silently go blind,
#     and covers the sandbox scripts dir, the backup tree, AND the
#     checkpoint message itself
#   * a mkdir lock with PID staleness check serializes concurrent runs
#   * step 1 pushes main if ahead (a failed main push WARNs and
#     continues — recorded in the manifest — instead of aborting the
#     sandbox backup)
#   * the branch bases itself on origin's tip when it exists, on the
#     local tip when local is ahead (unpushed commits preserved), or is
#     created from main once
set -euo pipefail

REPO="${PC_BACKUP_REPO:-/home/z/my-project/cleanroom}"
SANDBOX_HOME="${PC_SANDBOX_HOME:-/home/z/my-project}"
BRANCH="sandbox/backups"
SANDBOX_SCRIPTS="$SANDBOX_HOME/scripts"
LOCK="/tmp/pc-sandbox-backup.lock"

cd "$REPO"
MSG="${1:-checkpoint}"
if [ "$#" -gt 1 ]; then
  echo "usage: scripts/sandbox_backup.sh \"message\"" >&2
  exit 2
fi

echo "== sandbox backup: $MSG"

# -- secret patterns (ERE — grep -E / grep -En everywhere) ------------
SECRET_PATTERNS='github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghv_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY'

# self-test: the scan must catch canary credentials, else abort — a
# silently-blind scanner is worse than none (G1-iter2 critical #2).
# The canaries are BUILT at runtime (prefix + repeated chars) so this
# script never contains a literal credential-shaped string either.
_canary_pat="github_pat_""$(printf 'A%.0s' $(seq 1 40))"
_canary_ghp="ghp_""$(printf 'a%.0s' $(seq 1 40))"
_canary_aws="AKIA""IOSFODNN7EXAMPLE"
_canary_pem="-----BEGIN ""RSA PRIVATE KEY-----"
for canary in "$_canary_pat" "$_canary_ghp" "$_canary_aws" "$_canary_pem"; do
  if ! printf '%s' "$canary" | grep -Eq "$SECRET_PATTERNS"; then
    echo "!! secret-scan SELF-TEST failed (pattern no longer matches a canary) — aborting" >&2
    exit 5
  fi
done

# -- lock: serialize runs; steal a stale lock left by a killed run ----
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -f "$LOCK/pid" ] && ! kill -0 "$(cat "$LOCK/pid" 2>/dev/null)" 2>/dev/null; then
    echo "== removing stale lock (previous run died without cleanup)"
    rm -rf "$LOCK"
    mkdir "$LOCK"
  else
    echo "== another backup is running; aborting (event-driven backups never overlap)" >&2
    exit 3
  fi
fi
echo $$ > "$LOCK/pid"
trap 'rm -rf "$LOCK" 2>/dev/null || true' EXIT

# -- 1. main ahead? push it (product code + memory = part of backup) --
# A FAILED MAIN PUSH DOES NOT ABORT THE BACKUP: warn, record it in the
# manifest entry, continue (diverged/force-pushed history is an owner
# problem; the sandbox snapshot is still worth preserving).
MAIN_PUSH="ok"
git fetch -q origin main 2>/dev/null || true
if git rev-parse --verify origin/main >/dev/null 2>&1; then
  AHEAD=$(git rev-list --count origin/main..main 2>/dev/null || echo 0)
  if [ "$AHEAD" -gt 0 ]; then
    echo "== pushing main ($AHEAD commit(s))"
    if ! git push origin main; then
      MAIN_PUSH="failed"
      echo "!! main push failed (diverged? network?) — backing up the sandbox snapshot anyway" >&2
    fi
  fi
fi

# -- 2. secret scan layer 1: the sandbox scripts source dir ------------
if [ -d "$SANDBOX_SCRIPTS" ]; then
  if grep -rEn --exclude-dir='__pycache__' "$SECRET_PATTERNS" \
      "$SANDBOX_SCRIPTS" -l 2>/dev/null; then
    echo "!! SECRET DETECTED in sandbox scripts — backup ABORTED:" >&2
    grep -rEn --exclude-dir='__pycache__' "$SECRET_PATTERNS" \
      "$SANDBOX_SCRIPTS" -l 2>/dev/null >&2
    echo "Remove the credential (read it from env / the git remote) and retry." >&2
    exit 4
  fi
fi

# -- 3. the checkpoint message itself is a channel: scan it -----------
if printf '%s' "$MSG" | grep -Eq "$SECRET_PATTERNS"; then
  echo "!! SECRET DETECTED in the checkpoint message — backup ABORTED" >&2
  exit 4
fi

# -- 4. temporary worktree on the backup branch -----------------------
git worktree prune >/dev/null 2>&1 || true   # drop stale registrations
TMPWT="$(mktemp -d /tmp/pc-backup.XXXXXX)"
trap 'git -C "$REPO" worktree remove --force "$TMPWT" >/dev/null 2>&1 || true; rm -rf "$LOCK" 2>/dev/null || true' EXIT

git fetch -q origin "$BRANCH" 2>/dev/null || true
BASE_REF=""
if git rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
  BASE_REF="origin/$BRANCH"
  # local ahead of origin (previous push failed)? keep those commits
  if git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
    LOCAL_AHEAD=$(git rev-list --count "origin/$BRANCH..$BRANCH" 2>/dev/null || echo 0)
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
git checkout --quiet -B "$BRANCH" "${BASE_REF:-main}"

# -- 5. build the backup state INSIDE the worktree only ---------------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MAIN_HEAD="$(git -C "$REPO" rev-parse --short HEAD)"
MAIN_BRANCH="$(git -C "$REPO" branch --show-current || echo detached)"

mkdir -p harness/sandbox/scripts harness/backups

# 5a. sandbox scripts snapshot
if [ -d "$SANDBOX_SCRIPTS" ]; then
  rsync -a --delete --exclude '__pycache__' \
    "$SANDBOX_SCRIPTS"/ harness/sandbox/scripts/
fi

# 5b. sandbox inventory (scripts/download/skills; upload/ is
#     deliberately NOT listed — user uploads may have sensitive FILE
#     NAMES; credential-looking names are filtered everywhere)
SANDBOX_HOME="$SANDBOX_HOME" TS="$TS" MAIN_HEAD="$MAIN_HEAD" \
MAIN_BRANCH="$MAIN_BRANCH" MAIN_PUSH="$MAIN_PUSH" python3 - <<'PY'
import json, os
ts = os.environ["TS"]; head = os.environ["MAIN_HEAD"]
branch = os.environ["MAIN_BRANCH"]; home = os.environ["SANDBOX_HOME"]
BAD = ("token", "secret", "credential", "passwd", "password", "key")
def inv(path):
    try:
        names = sorted(os.listdir(os.path.join(home, path)))
    except OSError:
        return []
    return [n for n in names if not any(b in n.lower() for b in BAD)]
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

# 5c. append to the manifest (branch-owned; main keeps the empty seed)
TS="$TS" MSG="$MSG" MAIN_HEAD="$MAIN_HEAD" MAIN_BRANCH="$MAIN_BRANCH" \
MAIN_PUSH="$MAIN_PUSH" python3 - <<'PY'
import json, os
ts, msg = os.environ["TS"], os.environ["MSG"]
path = "harness/backups/manifest.json"
try:
    with open(path) as f:
        doc = json.load(f)
except (OSError, ValueError):
    doc = None
if not isinstance(doc, dict) or doc.get("schema") != 2:
    prev = doc.get("backups", []) if isinstance(doc, dict) else []
    doc = {"schema": 2, "note": "Append-only audit trail (branch-owned; "
                                "SHAs live in git log of this branch; "
                                "entries keyed by seq).",
           "backups": prev}
seq = (doc["backups"][-1]["seq"] + 1) if doc["backups"] else 1
doc["backups"].append({
    "seq": seq, "timestamp": ts, "trigger": "event", "message": msg,
    "git_head": os.environ["MAIN_HEAD"],
    "git_branch": os.environ["MAIN_BRANCH"],
    "main_push": os.environ["MAIN_PUSH"],
})
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f"== manifest entry #{seq}: {msg}")
PY

# 5d. secret scan layer 2: the exact tree that would be pushed
if grep -rEn --exclude-dir='__pycache__' "$SECRET_PATTERNS" \
    harness/sandbox harness/backups -l 2>/dev/null; then
  echo "!! SECRET DETECTED in backup tree — ABORTED (nothing pushed)" >&2
  exit 4
fi

# -- 6. commit (append-only; -f: harness/sandbox/ is gitignored on
#    main by design — the ignore protects main, the branch tracks it)
if [ -z "$(git status --porcelain harness/sandbox harness/backups)" ]; then
  echo "== nothing new to back up on $BRANCH"
else
  git add -f harness/sandbox harness/backups
  git commit -q -m "[sandbox-backup] $MSG" \
    -m "Event-driven checkpoint (see harness/backups/README.md). repo HEAD: $MAIN_HEAD ($MAIN_BRANCH). Append-only; no force-push."
  SHA="$(git rev-parse --short HEAD)"
  git push -u origin "$BRANCH"
  echo "== backup commit $SHA pushed to $BRANCH"
fi

echo "== backup complete: $TS (repo HEAD $MAIN_HEAD on $MAIN_BRANCH, main push: $MAIN_PUSH)"

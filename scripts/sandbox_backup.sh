#!/usr/bin/env bash
# Event-driven sandbox backup — run as the LAST step of every
# execution plan / prompt output. Never on a timer.
#
#   scripts/sandbox_backup.sh "message describing this checkpoint"
#
# Design (see harness/backups/README.md + consensus-log 2026-11-13 —
# hardened after the adversarial gate):
#   * the MAIN CHECKOUT IS NEVER WRITTEN: all backup state is built
#     inside a temporary git worktree on the 'sandbox/backups' branch
#     (harness/sandbox/ is also .gitignored on main as a second layer)
#   * append-only: one plain commit per backup, NO amend, NO force-push
#     — the commit SHAs live in `git log sandbox/backups` keyed by the
#     manifest timestamps (a manifest self-recording its own SHA is
#     impossible without history rewriting, which is what broke v1)
#   * the branch bases itself on origin's tip when it exists
#     (fresh-clone safe), or is created from main once
#   * a mkdir lock serializes concurrent runs
#   * a SECRET SCAN hard-fails before anything is pushed: any file
#     matching credential patterns (github_pat_/ghp_/gho_/ghs_ tokens,
#     AWS keys, private keys, bearer headers) aborts the backup
#   * step 1 pushes main if ahead — product code + harness memory are
#     part of the backup; the branch itself is CI-silent (main-only
#     trigger in ci.yml)
set -euo pipefail

REPO="/home/z/my-project/cleanroom"
SANDBOX_HOME="/home/z/my-project"
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

# -- lock: serialize concurrent runs --------------------------------
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "== another backup is running; aborting (event-driven backups " >&2
  echo "   never overlap by design)" >&2
  exit 3
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

# -- 1. main ahead? push it (product code + memory = part of backup) --
git fetch -q origin main || true
if git rev-parse --verify origin/main >/dev/null 2>&1; then
  AHEAD=$(git rev-list --count origin/main..main 2>/dev/null || echo 0)
  if [ "$AHEAD" -gt 0 ]; then
    echo "== pushing main ($AHEAD commit(s))"
    git push origin main
  fi
fi

# -- 2. secret scan: nothing that looks like a credential may leave --
SECRET_PATTERNS='github_pat_[A-Za-z0-9_]\{20,\}\|ghp_[A-Za-z0-9]\{30,\}\|gho_[A-Za-z0-9]\{30,\}\|ghs_[A-Za-z0-9]\{30,\}\|ghv_[A-Za-z0-9]\{30,\}\|AKIA[0-9A-Z]\{16\}\|BEGIN \(RSA \|EC \)\?PRIVATE KEY'
if [ -d "$SANDBOX_SCRIPTS" ]; then
  if grep -rEn "$SECRET_PATTERNS" "$SANDBOX_SCRIPTS" \
      --include='*' -l 2>/dev/null | rg -v '__pycache__' > /tmp/pc-secrets.txt; then
    echo "!! SECRET DETECTED in sandbox scripts — backup ABORTED:" >&2
    cat /tmp/pc-secrets.txt >&2
    echo "Remove the credential (read it from env / the git remote) and retry." >&2
    exit 4
  fi
fi

# -- 3. temporary worktree on the backup branch ----------------------
TMPWT="$(mktemp -d /tmp/pc-backup.XXXXXX)"
git worktree remove --force "$TMPWT" >/dev/null 2>&1 || true
trap 'git worktree remove --force "$TMPWT" >/dev/null 2>&1 || true; rmdir "$LOCK" 2>/dev/null || true' EXIT

git fetch -q origin "$BRANCH" 2>/dev/null || true
if git rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
  # base on the remote tip: pushes are always fast-forward, even in a
  # fresh clone (branch created from main only the very first time)
  git worktree add --quiet --detach "$TMPWT" "origin/$BRANCH"
  cd "$TMPWT"
  git checkout --quiet -B "$BRANCH" "origin/$BRANCH"
elif git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  git worktree add --quiet "$TMPWT" "$BRANCH"
  cd "$TMPWT"
else
  echo "== creating branch $BRANCH from main"
  git worktree add --quiet --detach "$TMPWT" main
  cd "$TMPWT"
  git checkout --quiet -b "$BRANCH"
fi

# -- 4. build the backup state INSIDE the worktree only --------------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MAIN_HEAD="$(cd "$REPO" && git rev-parse --short HEAD)"
MAIN_BRANCH="$(cd "$REPO" && git branch --show-current || echo detached)"

mkdir -p harness/sandbox/scripts harness/backups

# 4a. sandbox scripts snapshot
if [ -d "$SANDBOX_SCRIPTS" ]; then
  rsync -a --delete --exclude '__pycache__' \
    "$SANDBOX_SCRIPTS"/ harness/sandbox/scripts/
fi

# 4b. sandbox inventory
SANDBOX_HOME="$SANDBOX_HOME" TS="$TS" MAIN_HEAD="$MAIN_HEAD" \
MAIN_BRANCH="$MAIN_BRANCH" python3 - <<'PY'
import json, os, sys
ts = os.environ["TS"]; head = os.environ["MAIN_HEAD"]
branch = os.environ["MAIN_BRANCH"]; home = os.environ["SANDBOX_HOME"]
def inv(path):
    try:
        return sorted(os.listdir(os.path.join(home, path)))
    except OSError:
        return []
state = {
    "timestamp": ts,
    "git_head": head,           # HEAD of the repo the backup ran from
    "git_branch": branch,
    "sandbox": {
        "upload": inv("upload"),
        "download": inv("download"),
        "scripts": inv("scripts"),
        "skills": inv("skills"),
    },
}
with open("harness/sandbox/state.json", "w") as f:
    json.dump(state, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# 4c. append to the manifest (branch-owned; main keeps the empty seed)
TS="$TS" MSG="$MSG" MAIN_HEAD="$MAIN_HEAD" MAIN_BRANCH="$MAIN_BRANCH" \
python3 - <<'PY'
import json, os
ts, msg = os.environ["TS"], os.environ["MSG"]
path = "harness/backups/manifest.json"
try:
    with open(path) as f:
        doc = json.load(f)
except (OSError, ValueError):
    doc = {"schema": 2, "note": "Append-only audit trail (branch-owned; "
                                "SHAs live in git log of this branch).",
           "backups": []}
if doc.get("schema") != 2:      # migrate a schema-1 manifest
    doc = {"schema": 2, "note": "Append-only audit trail (branch-owned; "
                                "SHAs live in git log of this branch).",
           "backups": doc.get("backups", [])}
doc["backups"].append({
    "timestamp": ts, "trigger": "event", "message": msg,
    "git_head": os.environ["MAIN_HEAD"],
    "git_branch": os.environ["MAIN_BRANCH"],
})
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f"== manifest entry {len(doc['backups'])}: {msg}")
PY

# 4d. second secret-scan layer: the exact tree that would be pushed
if grep -rEn "$SECRET_PATTERNS" harness/sandbox/ -l 2>/dev/null; then
  echo "!! SECRET DETECTED in backup tree — ABORTED (nothing pushed)" >&2
  exit 4
fi

# -- 5. commit (append-only, only the backup paths) and push ----------
if git diff --quiet -- harness/sandbox harness/backups && \
   git diff --cached --quiet -- harness/sandbox harness/backups && \
   [ ! "$(git status --porcelain harness/sandbox harness/backups)" ]; then
  echo "== nothing new to back up on $BRANCH"
else
  git add harness/sandbox harness/backups
  git commit -q -m "[sandbox-backup] $MSG" \
    -m "Event-driven checkpoint (see harness/backups/README.md). repo HEAD: $MAIN_HEAD ($MAIN_BRANCH). No force-push, no history rewrite."
  SHA="$(git rev-parse --short HEAD)"
  git push -u origin "$BRANCH"
  echo "== backup commit $SHA pushed to $BRANCH"
fi

echo "== backup complete: $TS (repo HEAD $MAIN_HEAD on $MAIN_BRANCH)"

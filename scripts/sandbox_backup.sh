#!/usr/bin/env bash
# Event-driven sandbox backup — run as the LAST step of every
# execution plan / prompt output. Never on a timer.
#
#   scripts/sandbox_backup.sh "message describing this checkpoint"
#
# Layers (see harness/backups/README.md):
#   1. main branch pushed if ahead (product code + harness memory)
#   2. /home/z/my-project/scripts/  -> harness/sandbox/scripts/
#   3. harness/sandbox/state.json   -> sandbox inventory snapshot
#   4. harness/backups/manifest.json <- append-only entry
#   5. all of the above committed on the 'sandbox/backups' branch via a
#      temporary git worktree (the current checkout is never touched)
#      and pushed. That branch does not trigger CI (main-only trigger).
set -euo pipefail

REPO="/home/z/my-project/cleanroom"
SANDBOX_HOME="/home/z/my-project"
BRANCH="sandbox/backups"
SANDBOX_SCRIPTS="$SANDBOX_HOME/scripts"

cd "$REPO"
MSG="${1:-checkpoint}"
if [ "$#" -gt 1 ]; then
  echo "usage: scripts/sandbox_backup.sh \"message\"" >&2
  exit 2
fi

echo "== sandbox backup: $MSG"

# -- 1. main ahead? push it (product code is part of the backup) ----
if git rev-parse --verify origin/main >/dev/null 2>&1; then
  if [ "$(git rev-list --count origin/main..main 2>/dev/null || echo 0)" -gt 0 ]; then
    echo "== pushing main ($(git rev-list --count origin/main..main) commit(s))"
    git push origin main
  fi
else
  echo "== no origin/main ref yet; skipping main push"
fi

# -- 2. snapshot sandbox scripts into the repo tree -----------------
if [ -d "$SANDBOX_SCRIPTS" ]; then
  mkdir -p harness/sandbox/scripts
  rsync -a --delete --exclude '__pycache__' \
    "$SANDBOX_SCRIPTS"/ harness/sandbox/scripts/
fi

# -- 3. sandbox inventory ------------------------------------------
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MAIN_HEAD="$(git rev-parse --short HEAD)"
BRANCH_HEAD="$(git rev-parse --verify --short "$BRANCH" 2>/dev/null || echo none)"
python3 - "$TS" "$MAIN_HEAD" <<'PY'
import json, os, sys
ts, head = sys.argv[1], sys.argv[2]
home = "/home/z/my-project"
def inv(path):
    try:
        return sorted(os.listdir(os.path.join(home, path)))
    except OSError:
        return []
state = {
    "timestamp": ts,
    "repo_head_on_main": head,
    "sandbox": {
        "upload": inv("upload"),
        "download": inv("download"),
        "scripts": inv("scripts"),
        "skills": inv("skills"),
    },
}
with open(os.path.join(home, "cleanroom", "harness", "sandbox", "state.json"),
          "w") as f:
    json.dump(state, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# -- 4. append manifest entry ---------------------------------------
python3 - "$TS" "$MSG" <<'PY'
import json, sys
ts, msg = sys.argv[1], sys.argv[2]
path = "harness/backups/manifest.json"
with open(path) as f:
    doc = json.load(f)
doc["backups"].append({"timestamp": ts, "trigger": "event",
                       "message": msg})
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f"== manifest now has {len(doc['backups'])} backup(s)")
PY

# -- 5. commit on the backup branch via a temporary worktree ---------
TMPWT="$(mktemp -d /tmp/pc-backup.XXXXXX)"
trap 'git worktree remove --force "$TMPWT" >/dev/null 2>&1 || true' EXIT

if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  echo "== creating branch $BRANCH from main"
  git branch "$BRANCH" main
fi
git worktree add --checkout "$TMPWT" "$BRANCH" >/dev/null 2>&1

# copy the harness/sandbox + manifest updates into the worktree
mkdir -p "$TMPWT/harness/sandbox/scripts" "$TMPWT/harness/backups"
rsync -a --delete --exclude '__pycache__' \
  harness/sandbox/scripts/ "$TMPWT/harness/sandbox/scripts/"
cp harness/sandbox/state.json "$TMPWT/harness/sandbox/state.json"
cp harness/backups/manifest.json "$TMPWT/harness/backups/manifest.json"
cp harness/README.md "$TMPWT/harness/README.md" 2>/dev/null || true
rsync -a harness/memory/ "$TMPWT/harness/memory/" 2>/dev/null || true
rsync -a harness/process/ "$TMPWT/harness/process/" 2>/dev/null || true
rsync -a harness/roadmap.md "$TMPWT/harness/roadmap.md" 2>/dev/null || true

cd "$TMPWT"
if git diff --quiet && git diff --cached --quiet; then
  echo "== nothing new to back up on $BRANCH"
else
  git add -A harness/
  git commit -q -m "[sandbox-backup] $MSG" \
    -m "Event-driven checkpoint (see harness/backups/README.md). main HEAD: $MAIN_HEAD"
  SHA="$(git rev-parse --short HEAD)"
  git push -u origin "$BRANCH"
  echo "== backup commit $SHA pushed to $BRANCH"
fi

# record the SHA in the manifest too (kept on the backup branch)
python3 - "$SHA" <<'PY' 2>/dev/null || true
import json, sys
sha = sys.argv[1]
path = "harness/backups/manifest.json"
with open(path) as f:
    doc = json.load(f)
if doc["backups"]:
    doc["backups"][-1]["commit"] = sha
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
PY
if git diff --quiet 2>/dev/null; then :; else
  git add -A harness/ && git commit -q --amend --no-edit && \
  git push -f -u origin "$BRANCH"
fi

echo "== backup complete: $TS (main=$MAIN_HEAD, branch-prev=$BRANCH_HEAD)"

#!/usr/bin/env bash
# Event-driven sandbox backup — run as the LAST step of every
# execution plan / prompt output. Never on a timer.
#
#   PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh "msg"  # production (OPT-IN)
#   PC_BACKUP_REPO=… PC_SANDBOX_HOME=… PC_BACKUP_PUSH_REMOTE=… \
#     scripts/sandbox_backup.sh "msg"                              # test / CI (never github)
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
# GIT_TRACE* would make git print full push URLs — INCLUDING embedded
# credentials — into captured/pushed stderr (proven by the G1-iter3-i2
# Red Team; G1-iter4 RT major #5 proved the TRACE2 family leaks through
# v4's UNCAPPED re-pushes — every trace family is unset, and EVERY
# push captures + redacts its stderr).
unset GIT_TRACE GIT_TRACE_PACKET GIT_TRACE_EVENT GIT_TRACE_CURL GIT_TRACE_SHALLOW \
      GIT_TRACE2 GIT_TRACE2_EVENT GIT_TRACE2_PERF GIT_TRACE2_BRIEF

REPO="${PC_BACKUP_REPO:-/home/z/my-project/cleanroom}"
REPO="${REPO#file://}"          # accept file:// URLs (G1-iter3 major #1)
SANDBOX_HOME="${PC_SANDBOX_HOME:-/home/z/my-project}"
PUSH_URL="${PC_BACKUP_PUSH_REMOTE:-origin}"
BRANCH="sandbox/backups"
SANDBOX_SCRIPTS="$SANDBOX_HOME/scripts"
LOCK="/tmp/pc-sandbox-backup.lock"

MSG="${1:-checkpoint}"
if [ "$#" -gt 1 ]; then
  echo "usage: PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh \"message\"        # production (opt-in)" >&2
  echo "       PC_BACKUP_REPO=… PC_SANDBOX_HOME=… PC_BACKUP_PUSH_REMOTE=… scripts/sandbox_backup.sh \"message\"  # test/CI" >&2
  exit 2
fi

# -- test-mode detection (any env override marks a TEST run) ----------
TEST_MODE=0
[ "$REPO" != "/home/z/my-project/cleanroom" ] && TEST_MODE=1
[ "$SANDBOX_HOME" != "/home/z/my-project" ] && TEST_MODE=1
[ -n "${PC_BACKUP_PUSH_REMOTE:-}" ] && TEST_MODE=1

# -- production is OPT-IN (G1-iter4 RT major #1) ----------------------
# Two consecutive gates produced two accidental production pushes by
# agents that lost their env overrides (manifest seq 3 "t5" at
# G1-iter3; seq 5 "E9c" at G1-iter4 — the gate's own Red Team, a
# broken && chain). A default-production script WILL eventually run
# by accident: without the explicit flag the script refuses BEFORE
# any action; the flag plus test overrides is a conflicting mode.
ALLOW_PRODUCTION="${PC_BACKUP_ALLOW_PRODUCTION:-0}"
if [ "$TEST_MODE" = 1 ] && [ "$ALLOW_PRODUCTION" = "1" ]; then
  echo "!! conflicting mode: PC_BACKUP_ALLOW_PRODUCTION=1 combined with test overrides" >&2
  echo "   (PC_BACKUP_REPO / PC_SANDBOX_HOME / PC_BACKUP_PUSH_REMOTE) — pick one mode." >&2
  exit 2
fi
if [ "$TEST_MODE" = 0 ] && [ "$ALLOW_PRODUCTION" != "1" ]; then
  echo "!! production backups are OPT-IN — refusing to run production-mode by default." >&2
  echo "   Real run:  PC_BACKUP_ALLOW_PRODUCTION=1 scripts/sandbox_backup.sh \"message\"" >&2
  echo "   Test run:  set PC_BACKUP_REPO / PC_SANDBOX_HOME / PC_BACKUP_PUSH_REMOTE to scratch paths" >&2
  echo "   (see harness/backups/README.md)." >&2
  exit 6
fi

cd "$REPO"

# -- input validation (G1-iter4 RT minor #6 / Architect minor #5): a
#    bare or HEAD-less repo used to die deep inside rsync/git with a
#    raw error (exit 23/128, undocumented) — fail fast with a message
if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null || echo false)" != "true" ]; then
  echo "!! PC_BACKUP_REPO must be a working-tree checkout (bare repos are not supported)" >&2
  exit 2
fi
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  echo "!! the backup repo has no HEAD commit (unborn branch?) — clone a real checkout first" >&2
  exit 2
fi

# -- git identity self-sufficiency (G1-iter3 fix-cycle extension,
#    2026-11-13): backups are the MANDATORY last step of every
#    execution plan, so the script must be able to commit even where no
#    ambient identity is configured (fresh sandboxes, CI runners — the
#    hermetic CI test caught exactly this: 5/7 legs have no global git
#    identity and died at the first commit). Per-field (G1-iter3-i2
#    remediation): only the MISSING fields fall back — a configured
#    name is never silently overridden, and a half-configured identity
#    no longer bricks the run (email-only used to die at exit 128).
_gb_name="$(git config user.name 2>/dev/null || true)"
_gb_email="$(git config user.email 2>/dev/null || true)"
if [ -z "$_gb_name" ] || [ -z "$_gb_email" ]; then
  if [ -z "$_gb_name" ]; then
    export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-Proto Clean Sandbox Backup}"
    export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-Proto Clean Sandbox Backup}"
  fi
  if [ -z "$_gb_email" ]; then
    export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-backup@sandbox.protoclean.invalid}"
    export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-backup@sandbox.protoclean.invalid}"
  fi
  echo "== git identity incomplete (name/email) — built-in backup identity covers the missing field(s)"
fi

# (test-mode detection + the OPT-IN production gate live ABOVE the cd
#  now — the gate must be able to refuse before touching any repo)

# -- remote plumbing: every fetch/push goes through $PUSH_URL --------
case "$PUSH_URL" in
  *://*|/*|./*|../*)
    : # a URL or filesystem path — git addresses it directly
    ;;
  *)
    git remote get-url "$PUSH_URL" >/dev/null 2>&1 || {
      echo "!! push target '$PUSH_URL' is not a configured remote (set PC_BACKUP_PUSH_REMOTE to a remote name, path or URL)" >&2
      exit 6
    }
    ;;
esac
FETCH_OK=0
if [ "$PUSH_URL" = "origin" ]; then
  RMAIN="refs/remotes/origin/main"
  RBRANCH="refs/remotes/origin/$BRANCH"
  fetch_main()   { git fetch -q origin "+refs/heads/main:$RMAIN" 2>/dev/null || true; }
  # fetch ALL heads: a missing branch ref must not read as "fetch
  # failed" — the branch-push alarm depends on telling "remote has
  # nothing" apart from "remote unreachable" (G1-iter3-i2 RT major)
  fetch_branch() { if git fetch -q origin "+refs/heads/*:refs/remotes/origin/*" 2>/dev/null; then FETCH_OK=1; else FETCH_OK=0; fi; }
else
  RMAIN="refs/remotes/pcbk/main"
  RBRANCH="refs/remotes/pcbk/$BRANCH"
  fetch_main()   { git fetch -q "$PUSH_URL" "+refs/heads/main:$RMAIN" 2>/dev/null || true; }
  fetch_branch() { if git fetch -q "$PUSH_URL" "+refs/heads/*:refs/remotes/pcbk/*" 2>/dev/null; then FETCH_OK=1; else FETCH_OK=0; fi; }
fi
_GITDIR="$(git -C "$REPO" rev-parse --absolute-git-dir)"

# -- production-target refusal for TEST runs (G1-iter3-i2 RT major;
#    NORMALIZED at G1-iter4 after the Red Team bypassed v4's
#    case-sensitive spelling grep with :443, //, case, scp and
#    trailing-dot variants — one executed end-to-end on a decoy). Two
#    rules:
#      1. a TEST run never pushes to ANY github host, however
#         spelled (scratch is always local);
#      2. a TEST run never pushes to the production repo, however
#         spelled (canonical comparison after normalization).
#    The resolved URL is NEVER printed (it may embed a token); nor is
#    the normalized form. Off-domain redirectors remain outside any
#    client-side spelling check (documented residual, G1-iter4 RT).
_norm_url() {
  printf '%s\n' "$1" | tr 'A-Z' 'a-z' | sed -E \
    -e 's#^[a-z0-9+.-]+://##' \
    -e 's#^[^/@]+@##' \
    -e 's#:443(/|$)#\1#g' \
    -e 's#:22(/|$)#\1#g' \
    -e 's#^([^/]+):([^/].*)$#\1/\2#' \
    -e 's#//+#/#g' \
    -e 's#^([^/]+)\./#\1/#' \
    -e 's#\.git$##' \
    -e 's#/$##' \
    -e 's#^\./##'
}
if [ "$TEST_MODE" = 1 ]; then
  case "$PUSH_URL" in
    *://*|/*|./*|../*) _tgt="$PUSH_URL" ;;
    *)                 _tgt="$(git remote get-url "$PUSH_URL" 2>/dev/null || true)" ;;
  esac
  if [ -n "${_tgt:-}" ]; then
    _nt="$(_norm_url "$_tgt")"
    case "$_nt" in
      github.com|github.com/*|ssh.github.com|ssh.github.com/*)
        echo "!! refusing: env overrides mark this as a TEST run, but the push" >&2
        echo "   target resolves to a github host — test traffic never reaches" >&2
        echo "   github, whatever the spelling. Point PC_BACKUP_PUSH_REMOTE at a" >&2
        echo "   scratch bare repo (see harness/backups/README.md)." >&2
        exit 6
        ;;
    esac
    if [ "$_nt" = "$(_norm_url 'https://github.com/maniesh-NR/Proto-Clean.git')" ]; then
      echo "!! refusing: env overrides mark this as a TEST run, but the push target" >&2
      echo "   resolves to the PRODUCTION repo (however spelled). Point" >&2
      echo "   PC_BACKUP_PUSH_REMOTE at a scratch bare repo (see harness/backups/README.md)." >&2
      exit 6
    fi
  fi
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
      sed -E 's#(://)[^/@[:space:]]+:[^/@[:space:]]+@#\1#g; s/^/   /' "$_mperr" >&2
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
LOCAL_AHEAD=0
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
  LOCAL_AHEAD=1   # no remote ref visible: treat prior pushes as failed
else
  echo "== creating branch $BRANCH from main"
fi
# G1-iter3-i2 RT major: the previous run's branch-push outcome is
# auditable in the manifest (one-run lag — an entry can't contain its
# own push result, which happens after its commit exists)
PREV_BRANCH_PUSH="ok"
if [ "$LOCAL_AHEAD" -gt 0 ]; then PREV_BRANCH_PUSH="failed"; fi

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
#      append-only audit trail). -rptgoD skips symlinks (see layer 1);
#      -c (checksum) so a same-size edit made in the same second as
#      the worktree checkout is never silently skipped (G1-iter4
#      Architect minor #4 — the mtime quick-check proved skippable).
rsync -c -rptgoD --delete --exclude='/sandbox' --exclude='/backups/manifest.json' \
  "$REPO/harness"/ harness/

# 5a. sandbox scripts snapshot
if [ -d "$SANDBOX_SCRIPTS" ]; then
  rsync -c -rptgoD --delete --exclude '__pycache__' \
    "$SANDBOX_SCRIPTS"/ harness/sandbox/scripts/
fi

# 5a-2. credential-SHAPED filenames never enter the pushed tree from
#       ANY surface (G1-iter3-i2 RT minor for the scripts snapshot;
#       G1-iter4 RT minor #2 widened it to the WHOLE harness/ refresh
#       surface — v4 only excluded the scripts snapshot while the
#       refresh rsyncs ALL of harness/ including untracked files).
#       Names are never printed (G1-iter4 RT minor #3) and never
#       recorded (a shaped name in state.json would itself trip the
#       tree scan) — the COUNT is the audit trail.
_h_shaped=0
while IFS= read -r -d '' _sf; do
  rm -f -- "$_sf" && _h_shaped=$((_h_shaped + 1))
done < <(find harness -type f \
    \( -iname 'github_pat_*' -o -iname 'ghp_*' -o -iname 'gho_*' \
       -o -iname 'ghs_*' -o -iname 'ghv_*' -o -iname 'akia*' \) -print0)

# 5b. sandbox inventory (scripts/download/skills; upload/ is
#     deliberately NOT listed — user uploads may have sensitive FILE
#     NAMES; credential-looking names are filtered by WORD and by SHAPE
#     — G1-iter3 Red Team major #2)
SANDBOX_HOME="$SANDBOX_HOME" TS="$TS" MAIN_HEAD="$MAIN_HEAD" \
MAIN_BRANCH="$MAIN_BRANCH" MAIN_PUSH="$MAIN_PUSH" HARNESS_SHAPED="$_h_shaped" python3 - <<'PY'
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
def shaped_count(path):
    try:
        return sum(1 for n in os.listdir(os.path.join(home, path))
                   if BAD_SHAPE.search(n))
    except OSError:
        return 0
state = {
    "timestamp": ts,
    "git_head": head,
    "git_branch": branch,
    "main_push": os.environ["MAIN_PUSH"],
    "sandbox": {
        "download": inv("download"),
        "scripts": inv("scripts"),
        "skills": inv("skills"),
        "scripts_skipped_shaped_count": shaped_count("scripts"),
        "harness_skipped_shaped_count": int(os.environ.get("HARNESS_SHAPED", "0")),
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
MAIN_PUSH="$MAIN_PUSH" PREV_BRANCH_PUSH="$PREV_BRANCH_PUSH" python3 - <<'PY' >"$TMPWT/.manifest-out"
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
                                "SHAs live in git log of this branch; entries "
                                "keyed by the (seq, timestamp, message) triple "
                                "— seq may repeat after a divergence union).",
           "backups": prev}
seq = (doc["backups"][-1]["seq"] + 1) if doc["backups"] else 1
entry = {
    "seq": seq, "timestamp": ts, "trigger": "event", "message": msg,
    "git_head": os.environ["MAIN_HEAD"],
    "git_branch": os.environ["MAIN_BRANCH"],
    "main_push": os.environ["MAIN_PUSH"],
    "prev_branch_push": os.environ.get("PREV_BRANCH_PUSH", "ok"),
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

# 5d. secret scan layer 2: the ENTIRE pushed delta. The backup commit
#     only ever adds paths under harness/, so scanning all of harness/
#     covers everything this run can introduce — including the harness/
#     refresh, which rsyncs UNCOMMITTED and UNTRACKED files from the
#     live checkout (G1-iter3-i2 RT critical: v4 scanned only
#     sandbox+backups and a planted token in an untracked
#     harness/memory/ file was proven to reach the pushed branch with
#     every check green; the "exact backup tree" claim was false)
if secret_scan harness; then
  echo "!! SECRET DETECTED in backup tree — ABORTED (nothing pushed)" >&2
  exit 4
fi

# -- 6. commit (append-only; -f: harness/sandbox/ is gitignored on
#    main by design — the ignore protects main, the branch tracks it) --
# _alarms: exit-7 alarm machinery, defined HERE (before first use at
# the exit-8 aborts inside 6b) — G1-iter3 Architect major #2 (main
# push streak) + G1-iter3-i2 RT major (persistent branch-push failure
# was masked forever: exit 0 every run, no alarm, no manifest field)
# + G1-iter3-i2 Architect minor (an exit-8 abort used to skip the
# banner entirely). The snapshot being safe LOCALLY is not the bar —
# memory must SURVIVE the machine.
_alarms() {
  local flagged=0 _ahead _cnt
  fetch_branch
  _cnt=0
  if [ -f "$_GITDIR/pc-backup-failcount" ]; then
    _cnt="$(cat "$_GITDIR/pc-backup-failcount" 2>/dev/null || echo 0)"
    case "$_cnt" in ''|*[!0-9]*) _cnt=0 ;; esac
  fi
  if [ "$FETCH_OK" = 1 ]; then
    if git rev-parse --verify "$RBRANCH" >/dev/null 2>&1; then
      _ahead=$(git rev-list --count "$RBRANCH..$BRANCH" 2>/dev/null || echo 0)
      case "$_ahead" in ''|*[!0-9]*) _ahead=0 ;; esac
    elif git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
      _ahead=1   # remote never received the branch at all
    else
      _ahead=0
    fi
    if [ "$_ahead" -gt 0 ]; then _cnt=$((_cnt + 1)); else _cnt=0; fi
  else
    # G1-iter4 RT major #3: v4 froze the counter whenever the fetch
    # failed, so a revoked credential or a persistent partition meant
    # rc-0 runs forever with the audit trail machine-bound (3 runs
    # executed, no banner, counter frozen). If THIS run's branch push
    # failed, the checkpoint did not verifiably survive the machine —
    # count it even unreachable. (A fetch failure on a run that pushed
    # fine, or backed nothing up, leaves the streak untouched — a
    # blip is still never punished.)
    if [ "$BRANCH_PUSH" = "failed" ]; then _cnt=$((_cnt + 1)); fi
  fi
  printf '%s\n' "$_cnt" > "$_GITDIR/.pc-backup-failcount.tmp" \
    && mv "$_GITDIR/.pc-backup-failcount.tmp" "$_GITDIR/pc-backup-failcount"
  if [ "$_cnt" -ge 2 ]; then
    flagged=1
    echo "" >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    echo "!! BRANCH-PUSH-ALARM: the backup branch could NOT be pushed to" >&2
    echo "!! the remote again this checkpoint ($_cnt consecutive). The" >&2
    echo "!! audit trail currently exists ONLY on this machine — owner" >&2
    echo "!! attention required (push stderr above names the cause)." >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
  fi
  if [ "$MAINPUSH_ALARM" = 1 ]; then
    flagged=1
    echo "" >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    echo "!! MAIN-PUSH-ALARM: product code could NOT be pushed to the remote" >&2
    echo "!! again this checkpoint. The sandbox snapshot is safe, but main" >&2
    echo "!! is not surviving this machine — owner attention required." >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
  fi
  return "$flagged"
}

# _push_branch: EVERY branch push goes through here (G1-iter4 RT
# major #5 + RT minor #1 / Architect major #2: v4's post-merge
# re-pushes were UNCAPPED — a set -e rc-1 death that masked pending
# alarm banners and, under GIT_TRACE2, printed the credentialed push
# URL raw). stderr is captured and printed credential-redacted on
# failure; BRANCH_PUSH stays accurate; the caller decides the next
# step. No push anywhere in this script bypasses this helper.
_push_branch() {
  local _pe
  _pe="$(mktemp /tmp/pc-branchpush.XXXXXX)"
  if git push "$PUSH_URL" "$BRANCH" 2>"$_pe"; then
    rm -f "$_pe"
    return 0
  fi
  BRANCH_PUSH="failed"
  echo "!! branch push failed — stderr (credentials redacted):" >&2
  sed -E 's#(://)[^/@[:space:]]+:[^/@[:space:]]+@#\1#g; s/(ghp_|gho_|ghs_|ghv_|github_pat_)[A-Za-z0-9_]+/[REDACTED]/g; s/^/   /' "$_pe" >&2
  rm -f "$_pe"
  return 1
}

BRANCH_PUSH="ok"
if [ -z "$(git status --porcelain harness)" ]; then
  echo "== nothing new to back up on $BRANCH"
else
  git add -A harness
  git add -f harness/sandbox harness/backups
  git commit -q -m "[sandbox-backup] $MSG" \
    -m "Event-driven checkpoint (see harness/backups/README.md). repo HEAD: $MAIN_HEAD ($MAIN_BRANCH). Append-only; no force-push."
  SHA="$(git rev-parse --short HEAD)"

  # 6b. push — and self-heal a DIVERGED remote branch (G1-iter3
  #     Architect major #1; HARDENED at G1-iter4 after the Red Team
  #     proved v4's content merge pushed unscanned remote content — an
  #     injected manifest token rode the union merge RC 0 and then
  #     bricked every future run with an exit-4 loop, and a token in a
  #     remote file OUTSIDE harness/ rode a clean merge): merge with
  #     `-s ours` (remote commits become ANCESTORS — append-only
  #     preserved, no force-push — but the TREE stays exactly ours, so
  #     remote-only files can never enter), take the programmatic
  #     manifest union with EVERY string value scrubbed against the
  #     secret patterns, re-scan, and only then commit + push through
  #     the guarded helper. Nothing is committed or pushed dirty.
  if ! _push_branch; then
    echo "== checking for divergence"
    fetch_branch
    if ! git rev-parse --verify "$RBRANCH" >/dev/null 2>&1; then
      echo "!! branch push failed (remote rejected or unreachable? — see stderr above) — commit kept locally; next run retries" >&2
    elif git merge-base --is-ancestor "$RBRANCH" HEAD 2>/dev/null; then
      echo "!! branch push failed (network?) — commit kept locally; next run retries" >&2
    else
      echo "== remote $BRANCH has commits we lack — merging (append-only preserved; content stays ours)"
      if ! git merge --no-edit -s ours --no-commit "$RBRANCH" 2>/dev/null; then
        git merge --abort 2>/dev/null || true
        echo "!! divergence merge could not be prepared — ABORT (exit 8); manual recovery required" >&2
        _alarms || true
        exit 8
      fi
      if ! MERGE_HEAD_REF="$RBRANCH" SECRET_PATTERNS="$SECRET_PATTERNS" python3 - <<'PY'
import json, os, re, subprocess, sys, tempfile
theirs_ref = os.environ["MERGE_HEAD_REF"]
SECRET = re.compile(os.environ["SECRET_PATTERNS"])
def scrub(x):
    if isinstance(x, str):
        return SECRET.sub("[REDACTED]", x)
    if isinstance(x, list):
        return [scrub(v) for v in x]
    if isinstance(x, dict):
        return {k: scrub(v) for k, v in x.items()}
    return x
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
scrubbed = 0
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
            e = scrub(e)
            merged[(e.get("seq"), e.get("timestamp"), e.get("message", ""))] = e
    # count entries the scrub actually changed (audit marker)
    def _flat(s):
        return json.dumps(s.get("backups", []), sort_keys=True)
    doc = {"schema": 2,
           "note": ours.get("note", "Append-only audit trail."),
           "backups": sorted(merged.values(), key=lambda e: (e.get("seq", 0), e.get("timestamp", ""))),
           "merged_divergence": True}
    raw_ours = _flat(ours); raw_theirs = _flat(theirs)
    for e in doc["backups"]:
        if json.dumps(e, sort_keys=True) not in raw_ours and json.dumps(e, sort_keys=True) not in raw_theirs:
            scrubbed += 1
    if scrubbed:
        doc["merge_scrubbed_entries"] = scrubbed
        print(f"== manifest union scrubbed {scrubbed} entry(ies) carrying "
              f"secret-shaped strings (G1-iter4 RT major #4)", file=sys.stderr)
path = "harness/backups/manifest.json"
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".manifest.", suffix=".tmp")
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
print(f"== manifest divergence-merged: {len(doc['backups'])} entries (union)")
PY
      then
        git merge --abort 2>/dev/null || true
        echo "!! manifest union could not be computed — ABORT (exit 8); manual recovery required" >&2
        _alarms || true
        exit 8
      fi
      git add harness/backups/manifest.json
      # the merged surface is re-scanned BEFORE anything is committed
      # or pushed (G1-iter4 RT major #4: v4 scanned pre-merge only — a
      # poisoned remote manifest rode the union and then bricked
      # every future run; dirty merged content aborts with the branch
      # left unmerged and unpushed)
      if secret_scan harness; then
        git merge --abort 2>/dev/null || true
        echo "!! SECRET DETECTED in merged content — divergence ABORTED (exit 8); nothing committed, nothing pushed" >&2
        _alarms || true
        exit 8
      fi
      git commit --no-edit -q
      if _push_branch; then
        echo "== divergence healed: remote commits preserved as ancestors, sanitized manifest union pushed"
      else
        echo "!! healed-merge push failed — commit kept locally; next run retries" >&2
      fi
    fi
  fi
  echo "== backup commit $SHA recorded on $BRANCH (branch tip: $(git rev-parse --short HEAD))"
fi

echo "== backup complete: $TS (repo HEAD $MAIN_HEAD on $MAIN_BRANCH, main push: $MAIN_PUSH, branch push: $BRANCH_PUSH)"

# -- 7. alarms — see _alarms (defined above step 6; returns 0 = no
#    alarm, 1 = alarm): MAIN-PUSH-ALARM (2+ consecutive manifest
#    entries with main_push: failed) and BRANCH-PUSH-ALARM (2+
#    consecutive checkpoints the branch did not verifiably survive:
#    streak counter at $_GITDIR/pc-backup-failcount — incremented on
#    unpushed-ahead commits, or on a failed push even when the remote
#    is unreachable (G1-iter4 RT major #3); a fetch blip on a run that
#    pushed fine or backed nothing up is never punished).
#    _alarms also runs at every exit-8 abort so no alarm can be
#    masked by an abort.
_alarms || exit 7

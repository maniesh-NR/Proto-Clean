#!/usr/bin/env python3
"""Drive a GitHub Copilot code review on maniesh-NR/Proto-Clean via the REST API.

Subcommands:
  whoami              Print the authenticated login (sanity check).
  create-pr           Create the review PR (base copilot/review-base, head copilot/review-v061).
  request <n>         Request copilot-pull-request-reviewer[bot] as reviewer on PR <n>.
  poll <n> [secs]     Poll until Copilot posts a review; dump review + inline comments.
  state <n>           Print PR state, requested reviewers, latest reviews summary.

The token is parsed from the git remote URL and never printed.
"""
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = "maniesh-NR/Proto-Clean"
BOT = "copilot-pull-request-reviewer"
BOT2 = "copilot-pull-request-reviewer[bot]"
OUT = "/tmp/copilot_review.json"


def tok() -> str:
    url = subprocess.run(
        ["git", "-C", "/home/z/my-project/cleanroom", "config", "--get", "remote.origin.url"],
        capture_output=True, text=True, check=True).stdout.strip()
    m = re.match(r"https://([^@/]+)@", url)
    if not m:
        sys.exit("no token found in remote url")
    # userinfo may be "user:token" — the credential is the last segment
    return m.group(1).split(":")[-1]


def api(method: str, path: str, body=None, token: str | None = None):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token or tok()}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "proto-clean-ci",
        },
        method=method)
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read().decode()
            return r.status, (json.loads(data) if data else {})
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {}
        return e.code, payload


def create_pr() -> None:
    body = (
        "Review vehicle for a Copilot bug hunt: this PR replays the complete "
        "**v0.6.1 changeset** (`f2eae29..dad27dc` — region-grouped server list UI, "
        "guest-mode certificate/load fixes, release-signed Android APKs, new Ed25519 "
        "module) on top of a temporary base branch, so the whole recent diff can be "
        "reviewed in one pass. The base branch is throwaway; fixes will land on "
        "`main` via a separate PR.\n\n"
        "Focus per `.github/copilot-instructions.md`: real correctness bugs in "
        "`proto_clean/proton/guest.py`, `GuestApi.kt`, the two server-list UIs, and "
        "the signing config."
    )
    st, pr = api("POST", "pulls", {
        "title": "Copilot bug review: v0.6.1 changeset (guest cert flow, region UI, signing)",
        "head": "copilot/review-v061",
        "base": "copilot/review-base",
        "body": body,
        "maintainer_can_modify": False,
    })
    if st == 201:
        print(f"PR #{pr['number']}: {pr['html_url']}")
    elif st == 422 and pr.get("errors"):
        print(f"422: {json.dumps(pr['errors'])}")
    else:
        print(f"HTTP {st}: {json.dumps(pr)[:600]}")


def request_review(n: int) -> None:
    for reviewer in (BOT, BOT2):
        st, resp = api("POST", f"pulls/{n}/requested_reviewers", {"reviewers": [reviewer]})
        if st in (201, 200):
            print(f"review requested from {reviewer} (HTTP {st})")
            return
        print(f"{reviewer} -> HTTP {st}: {json.dumps(resp)[:400]}")
    sys.exit(1)


def state(n: int) -> None:
    st, pr = api("GET", f"pulls/{n}")
    st2, revs = api("GET", f"pulls/{n}/reviews")
    print(f"PR state={pr.get('state')} mergeable={pr.get('mergeable')} "
          f"commits={pr.get('commits')} changed_files={pr.get('changed_files')}")
    if isinstance(revs, list):
        for r in revs:
            print(f"  review by {r['user']['login']} ({r['state']}) at {r['submitted_at']}")


def poll(n: int, seconds: int) -> None:
    deadline = time.time() + seconds
    seen_states: dict[int, str] = {}
    while time.time() < deadline:
        st, revs = api("GET", f"pulls/{n}/reviews")
        if st == 200 and isinstance(revs, list):
            for r in revs:
                login = r["user"]["login"]
                if "copilot" in login.lower():
                    print(f"[{time.strftime('%H:%M:%S')}] copilot review: state={r['state']}")
                    st2, comments = api("GET", f"pulls/{n}/comments")
                    data = {"review": r, "comments": comments if isinstance(comments, list) else []}
                    with open(OUT, "w") as f:
                        json.dump(data, f, indent=1)
                    print(f"saved {len(data['comments'])} inline comments -> {OUT}")
                    print("---- REVIEW BODY ----")
                    print(r.get("body") or "(empty)")
                    return
            print(f"[{time.strftime('%H:%M:%S')}] no copilot review yet "
                  f"({len(revs)} reviews so far, states={sorted(set(seen_states.values()))})")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] reviews GET -> HTTP {st}")
        time.sleep(20)
    print("TIMEOUT waiting for copilot review")


def whoami() -> None:
    st, u = api("GET", "", body=None)  # not used; repo-level below
    st, u = api("GET", "../user") if False else (0, {})
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {tok()}", "User-Agent": "proto-clean-ci",
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req) as r:
        u = json.load(r)
    print(f"authenticated as {u.get('login')}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "create-pr":
        create_pr()
    elif cmd == "request":
        request_review(int(sys.argv[2]))
    elif cmd == "poll":
        poll(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 480)
    elif cmd == "state":
        state(int(sys.argv[2]))
    elif cmd == "whoami":
        whoami()
    else:
        sys.exit(__doc__)

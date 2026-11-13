#!/usr/bin/env python3
"""Poll the Proto Clean Release workflow run until it completes.

The token comes from the GITHUB_TOKEN env var or is extracted from the
cleanroom git remote — it is NEVER written into this file (a leaked
credential in harness backups would be pushed to the public repo).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request


def _token_from_remote() -> str:
    """Extract the PAT embedded in the cleanroom remote URL (if any)."""
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd="/home/z/my-project/cleanroom", capture_output=True,
            text=True, timeout=5).stdout.strip()
        # https://user:token@github.com/...
        cred = url.split("://", 1)[-1].split("@", 1)[0]
        if ":" in cred:
            return cred.split(":", 1)[1]
    except Exception:
        pass
    return ""


TOKEN = os.environ.get("GITHUB_TOKEN") or _token_from_remote()
if not TOKEN:
    print("no GitHub token available (set GITHUB_TOKEN or configure the "
          "cleanroom remote with an embedded PAT)", file=sys.stderr)
    raise SystemExit(2)

RUN = "42044075693"
URL = f"https://api.github.com/repos/maniesh-NR/Proto-Clean/actions/runs/{RUN}"
JOBS = f"https://api.github.com/repos/maniesh-NR/Proto-Clean/actions/runs/{RUN}/jobs?per_page=30"


def get(url):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


deadline = time.time() + 540  # leave headroom under the bash timeout
while time.time() < deadline:
    run = get(URL)
    status, concl = run["status"], run["conclusion"]
    if status == "completed":
        print(f"RUN COMPLETED: conclusion={concl}")
        jobs = get(JOBS)["jobs"]
        for j in jobs:
            mark = "OK " if j["conclusion"] == "success" else \
                   "ERR" if j["conclusion"] != "skipped" else "SKIP"
            print(f"  [{mark}] {j['name']} -> {j['conclusion']}")
        sys_exit = 0 if concl == "success" else 1
        raise SystemExit(sys_exit)
    jobs = get(JOBS)["jobs"]
    done = sum(1 for j in jobs if j["status"] == "completed")
    runn = [j["name"] for j in jobs if j["status"] == "in_progress"]
    print(f"[{time.strftime('%H:%M:%S')}] status={status} jobs {done}/{len(jobs)} "
          f"running: {', '.join(runn) or '-'}", flush=True)
    time.sleep(60)
print("STILL RUNNING (poll window elapsed)")

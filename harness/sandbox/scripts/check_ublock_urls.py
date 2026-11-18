#!/usr/bin/env python3
"""One-off sanity check: download every uBlock Origin default list URL and
parse it with the app's real parse_filters, printing blocked/allowed counts."""
import sys
import time

sys.path.insert(0, "/home/z/my-project/cleanroom")

import httpx  # noqa: E402

from proto_clean.netshield.blocklists import parse_filters  # noqa: E402
from proto_clean.settings import default_blocklists  # noqa: E402

def main() -> int:
    total_b = total_a = 0
    failed = []
    for src in default_blocklists():
        t0 = time.time()
        try:
            with httpx.Client(follow_redirects=True, timeout=60.0,
                              headers={"User-Agent": "proto_clean/0.2"}) as c:
                resp = c.get(src.url)
                resp.raise_for_status()
                blocked, allowed = parse_filters(resp.text)
            total_b += len(blocked)
            total_a += len(allowed)
            print(f"OK   {src.name:44s} {len(blocked):>7,} blocked "
                  f"{len(allowed):>5,} allowed  {len(resp.content)/1e6:5.1f} MB  "
                  f"{time.time()-t0:4.1f}s")
        except Exception as e:  # noqa: BLE001
            failed.append(src.name)
            print(f"FAIL {src.name:44s} {e}")
    print(f"\nTOTAL blocked={total_b:,}  allowed={total_a:,}  failed={len(failed)}")
    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())

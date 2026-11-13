# Session 2026-11-07 — desktop link-bonding verification (reconstructed)

Reconstructed 2026-11-13 from git history (53afc6c → bdefec5) during the
harness backfill; details verified against commit messages and CI logs.

## Task
"Test if combining network interfaces works on desktop
(windows, mac, linux)."

## Outcome: YES — works on all three desktop platforms

- Built `tests/test_bond_desktop.py` (12 tests): real multi-adapter E2E
  on Linux (127.0.0.2/127.0.0.3 on lo), failover-retry contract (4 unit
  tests), macOS (`ifconfig -a` dual-NIC + utun replayed through the real
  parser), Windows (`Get-NetIPAddress` JSON + `ipconfig` fallback),
  discovery-replayed adapters driving real bond sessions.
- **Real bug found and fixed** (`53afc6c`): a member dying mid-send
  killed the whole stream — the retry loop broke after the first send
  attempt AND advanced the seq, leaving a permanent reassembly gap.
  Fix: `_send_chunk` retries the same chunk with the same seq on a
  surviving member; seq advances only on confirmed send (both client
  pump and server download pump).
- **Shutdown stderr spam fixed** (`39a1436`): CancelledError escaping
  listener threads printed "Exception in thread" on every disconnect
  (CancelledError is BaseException — `except Exception` missed it).
- **macOS CI close-race fixed** (`bdefec5`): teardown could close a
  still-running loop (Server.close() defers wakeup while handlers are
  active; last_member_left sleeps 60 s). Fail-safe drain + conditional
  close.
- Verification method worth reusing: compared CI pass/skip counts
  before/after the new tests — ubuntu/macos +12 passed 0 skipped,
  windows +12 passed with skip count unchanged (122) → nothing silently
  skipped on any OS.

Baseline after: 696 local (+4 skips) / 700 per CI leg.

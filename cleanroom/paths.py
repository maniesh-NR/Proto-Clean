"""Filesystem layout for Cleanroom.

Platform-aware:
  * Linux   — XDG base directories (~/.config, ~/.cache, ~/.local/state)
  * Windows — %APPDATA%\\cleanroom (config) and %LOCALAPPDATA%\\cleanroom
              (cache/state)
  * macOS   — ~/Library/Application Support/Cleanroom and
              ~/Library/Caches/Cleanroom

The privileged-helper port also differs per OS: on Windows low ports are not
restricted, so the DNS blocker can bind 127.0.0.1:53 directly and the
WireGuard config simply points DNS at the loopback; on Linux/macOS it listens
on :5353 and the privileged helper redirects / relays port 53 to it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = not (IS_WINDOWS or IS_MACOS)

PLATFORM_NAME = "windows" if IS_WINDOWS else "macos" if IS_MACOS else "linux"


def _base(env: str, default: str) -> Path:
    return Path(os.environ.get(env, default)).expanduser()


if IS_WINDOWS:
    _appdata = _base("APPDATA", "~/AppData/Roaming")
    _local = _base("LOCALAPPDATA", "~/AppData/Local")
    CONFIG_DIR = _appdata / "cleanroom"
    CACHE_DIR = _local / "cleanroom" / "cache"
    STATE_DIR = _local / "cleanroom" / "state"
    # elevated helper writes/reads tunnel configs here
    SYSTEM_CONFIG_DIR = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "Cleanroom"
    HELPER_BIN = ""                      # in-process helper (UAC elevation)
elif IS_MACOS:
    CONFIG_DIR = _base("CLEANROOM_CONFIG", "~/Library/Application Support/Cleanroom")
    CACHE_DIR = _base("CLEANROOM_CACHE", "~/Library/Caches/Cleanroom")
    STATE_DIR = CONFIG_DIR / "state"
    SYSTEM_CONFIG_DIR = Path("/etc/wireguard")
    HELPER_BIN = "/usr/local/bin/cleanroom-helper"
else:
    CONFIG_DIR = _base("XDG_CONFIG_HOME", "~/.config") / "cleanroom"
    CACHE_DIR = _base("XDG_CACHE_HOME", "~/.cache") / "cleanroom"
    STATE_DIR = _base("XDG_STATE_HOME", "~/.local/state") / "cleanroom"
    SYSTEM_CONFIG_DIR = Path("/etc/wireguard")
    HELPER_BIN = "/usr/local/bin/cleanroom-helper"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"  # fallback when keyring unavailable
BROWSER_STATE_FILE = CONFIG_DIR / "browser-state.json"      # cookies/localStorage of the Proton session
SERVER_CACHE_FILE = CACHE_DIR / "servers.json"
BLOCKLIST_DIR = CACHE_DIR / "blocklists"
CONFIG_CACHE_DIR = CACHE_DIR / "configs"    # cached WireGuard configs, reused until they fail
DOWNLOADS_DIR = CACHE_DIR / "downloads"                     # raw configs captured from the web UI
LOG_DIR = STATE_DIR / "logs"
LOG_FILE = LOG_DIR / "cleanroom.log"

WG_IFACE = "cleanroom"        # interface/tunnel name (<=15 chars, wg-quick compatible)

# Port of the embedded DNS blocker.
#   * Windows: 53 — any user may bind low ports and the tunnel config's DNS
#     is rewritten to 127.0.0.1, so no firewall redirect is needed at all.
#   * Linux: 5353 — the helper REDIRECTs all port-53 traffic here (uid-exempt).
#   * macOS: 5353 — the helper relays 127.0.0.1:53 -> :5353 as root and the
#     primary network service's DNS is set to 127.0.0.1.
DNS_BLOCKER_PORT = 53 if IS_WINDOWS else 5353


def ensure_dirs() -> None:
    dirs = [CONFIG_DIR, CACHE_DIR, STATE_DIR, BLOCKLIST_DIR, CONFIG_CACHE_DIR,
            DOWNLOADS_DIR, LOG_DIR]
    if IS_WINDOWS:
        dirs.append(SYSTEM_CONFIG_DIR)
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # SYSTEM_CONFIG_DIR may need elevation; created on demand

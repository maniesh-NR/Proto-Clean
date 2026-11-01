"""Exclude-apps split tunneling.

On Linux, excluded apps are placed in the root-level cgroup v2
``proton_clean_split``; packets from that cgroup are fwmark-tagged by an
iptables mangle rule and routed through a separate table that keeps the
original (non-VPN) gateway.

On Windows/macOS per-app policy routing is not available to user space, so
app exclusion is a Linux-only feature there (the settings UI says so); the
portable destination-based exclusions (CIDRs removed from AllowedIPs) are
applied by the tunnel manager on every OS.
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Optional

from ..log import get
from ..platforms import capabilities
from .helper import Helper, HelperError

log = get("split")


def _is_linux() -> bool:
    return capabilities().name == "linux"


class SplitTunnel:
    def __init__(self, helper: Helper) -> None:
        self.helper = helper
        self.active = False

    # ------------------------------------------------------------- lifecycle
    def on(self, phys_iface: str, gateway_ip: str) -> None:
        self.helper.call("split-on", phys_iface, gateway_ip)
        self.active = True

    def off(self) -> None:
        try:
            self.helper.call("split-off")
        except HelperError as e:
            log.debug("split-off: %s", e)
        self.active = False

    # ----------------------------------------------------------------- apps
    def move_pid(self, pid: int) -> None:
        self.helper.call("split-add-pid", str(pid))

    def launch_excluded(self, executable: str, args: Optional[List[str]] = None) -> int:
        """Start an executable inside the split cgroup as the current user."""
        if not _is_linux():
            raise HelperError("per-app split tunneling requires Linux")
        uid = os.getuid()
        gid = os.getgid()
        out = self.helper.call("split-launch", str(uid), str(gid), "--",
                               executable, *(args or []))
        return int(out.get("launched", 0))

    # ------------------------------------------------------------- listing
    @staticmethod
    def excluded_pids() -> List[int]:
        """PIDs currently living in the split cgroup (Linux only)."""
        path = "/sys/fs/cgroup/proton_clean_split/cgroup.procs"
        if not _is_linux():
            return []
        try:
            txt = open(path).read()
            return [int(x) for x in txt.split() if x.strip().isdigit()]
        except OSError:
            return []

    @staticmethod
    def pid_owner(pid: int) -> str:
        if not _is_linux():
            return "?"
        try:
            import pwd
            return pwd.getpwuid(int(
                subprocess.run(["stat", "-c", "%u", f"/proc/{pid}"],
                               capture_output=True, text=True).stdout.strip()
            )).pw_name
        except Exception:  # noqa: BLE001
            return "?"

    @staticmethod
    def pid_cmdline(pid: int) -> str:
        if not _is_linux():
            return ""
        try:
            return open(f"/proc/{pid}/cmdline").read().replace("\0", " ").strip()
        except OSError:
            return ""

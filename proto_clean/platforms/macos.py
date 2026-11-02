"""macOS backend: the same sudo helper script (with Darwin implementations
inside), pf-based kill switch, DNS via a root relay on 127.0.0.1:53 and
AllowedIPs-based CIDR split tunneling (per-app routing is not available to
user space on macOS)."""

from __future__ import annotations

import subprocess
from typing import Optional, Tuple

from ..paths import HELPER_BIN
from .base import Capabilities, PlatformBackend
from .linux import SudoHelperClient


class MacOsBackend(PlatformBackend):
    def __init__(self) -> None:
        self.capabilities = Capabilities(
            "macos", "macOS",
            app_split_tunnel=False,          # no policy routing for user space
            kill_switch_backend="pf",
            dns_backend="root-relay",        # helper relays 127.0.0.1:53 -> :5353
            elevation="sudo",
            dns_loopback_in_config=False,
            openvpn_tunnel=True,            # brew install openvpn (TUN or TAP)
        )

    # --------------------------------------------------------------- api
    def make_helper(self, binary: str = "") -> SudoHelperClient:
        return SudoHelperClient(binary or HELPER_BIN)

    def default_route(self) -> Tuple[Optional[str], Optional[str]]:
        """`route -n get default` -> interface + gateway."""
        try:
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=5
                                 ).stdout
        except (subprocess.SubprocessError, OSError):
            return None, None
        iface, gw = None, None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "interface:":
                iface = parts[1]
            if len(parts) >= 2 and parts[0] == "gateway:":
                gw = parts[1]
        return iface, gw

    def env_check(self) -> list:
        import shutil

        checks = []
        for tool, why in (("wg", "WireGuard tools (brew install wireguard-tools)"),
                          ("wg-quick", "WireGuard tools (tunnel setup)"),
                          ("pfctl", "kill switch (built into macOS)"),
                          ("networksetup", "DNS configuration (built into macOS)"),
                          ("openvpn", "OpenVPN protocol support "
                                       "(optional — 'brew install openvpn')")):
            checks.append((f"{tool} — {why}", bool(shutil.which(tool)),
                           "" if tool != "openvpn" else
                           "only needed when the OpenVPN protocol is selected"))
        return checks

    def open_folder(self, path: str) -> None:
        subprocess.Popen(["open", path])

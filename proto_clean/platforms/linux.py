"""Linux backend: sudo helper script, iptables kill switch, cgroup split
tunneling, DNS port-53 redirect to the in-app blocker on :5353."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional, Tuple

from ..paths import HELPER_BIN
from .base import HelperClient, HelperError, PlatformBackend


class SudoHelperClient(HelperClient):
    """Runs whitelisted verbs through sudo (Linux and macOS)."""

    def __init__(self, binary: str = HELPER_BIN) -> None:
        self.binary = binary
        if not os.path.isfile(binary):
            raise HelperError(
                f"helper not installed at {binary} — run scripts/install.sh "
                "(Linux) or scripts/install_macos.sh (macOS) to install the "
                "privileged helper and its sudoers entry"
            )

    # ------------------------------------------------------------- plumbing
    def _command(self, verb: str, args: Tuple[str, ...]) -> List[str]:
        sudo = shutil.which("sudo")
        if sudo:
            return [sudo, "-n", self.binary, verb, *args]
        return [self.binary, verb, *args]   # running as root already

    def _run_one(self, verb: str, args: Tuple[str, ...],
                 timeout: float) -> dict:
        import json

        cmd = self._command(verb, args)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise HelperError(f"helper {verb}: timed out") from e
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "unknown failure"
            if "a password is required" in err:
                err = ("passwordless sudo not configured — add the sudoers "
                       "entry from scripts/install.sh")
            raise HelperError(f"helper {verb}: {err}", stderr=proc.stderr)
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise HelperError(
                f"helper {verb}: unexpected output {proc.stdout[:200]!r}")

    # --------------------------------------------------------------- api
    def call(self, verb: str, *args: str, timeout: float = 60.0) -> dict:
        return self._run_one(verb, tuple(str(a) for a in args), timeout)

    def call_batch(self, calls, timeout: float = 120.0) -> list:
        out = []
        for call in calls:
            verb, args = call[0], tuple(str(a) for a in call[1:])
            out.append(self._run_one(verb, args, timeout))
        return out

    def available(self) -> bool:
        try:
            self._run_one("status", (), timeout=15.0)
            return True
        except HelperError:
            return False


class LinuxBackend(PlatformBackend):
    capabilities = None  # set below (avoids mutable class attribute sharing)

    def __init__(self) -> None:
        from .base import Capabilities
        self.capabilities = Capabilities(
            "linux", "Linux",
            app_split_tunnel=True,           # cgroup v2 + fwmark policy routing
            kill_switch_backend="iptables",
            dns_backend="iptables-redirect",  # nat REDIRECT 53 -> 5353
            elevation="sudo",
            dns_loopback_in_config=False,
            openvpn_tunnel=True,            # openvpn package (TUN or TAP driver)
        )

    # --------------------------------------------------------------- api
    def make_helper(self, binary: str = "") -> HelperClient:
        return SudoHelperClient(binary or HELPER_BIN)

    def default_route(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            out = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            return None, None
        iface, gw = None, None
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
            if iface:
                break
        return iface, gw

    def env_check(self) -> list:
        checks = []
        for tool, why in (("wg", "WireGuard tools (kernel interface)"),
                          ("wg-quick", "WireGuard tools (tunnel setup)"),
                          ("iptables", "kill switch + DNS redirect"),
                          ("ip", "routing"),
                          ("openvpn", "OpenVPN protocol support "
                                       "(optional — 'sudo apt install openvpn')")):
            checks.append((f"{tool} — {why}", bool(shutil.which(tool)),
                           "" if tool != "openvpn" else
                           "only needed when the OpenVPN protocol is selected"))
        return checks

    def open_folder(self, path: str) -> None:
        for opener in ("xdg-open", "open"):
            if shutil.which(opener):
                subprocess.Popen([opener, path])
                return

"""Windows backend.

There is no sudo on Windows, so the privileged verbs (implemented in
``cleanroom.helper_win``) run either

  * in-process, when the app itself is elevated (recommended — right-click
    "Run as administrator"), or
  * through exactly one UAC prompt per batch, via ShellExecuteW("runas").

Batching matters: a connect needs ~6 verbs and each elevated invocation
would otherwise show its own prompt. ``TunnelManager`` therefore uses
``call_batch``.

Kill switch: per-physical-adapter outbound block rules plus an allow rule
for the WireGuard handshake endpoint (the tunnel adapter is virtual, so it
is never blocked). DNS blocking needs no firewall rule at all: Windows does
not restrict low ports, the embedded blocker binds 127.0.0.1:53 and the
tunnel config's DNS is rewritten to 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from typing import List, Optional, Tuple

from .base import Capabilities, HelperClient, HelperError, PlatformBackend

WG_INSTALL_DIRS = (r"C:\Program Files\WireGuard", r"C:\Program Files (x86)\WireGuard")


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 — not on Windows / old ctypes
        return False


class WindowsHelperClient(HelperClient):
    def __init__(self) -> None:
        self._status_cache: dict = {"wg_up": False, "up": False}
        self._cache_lock_src = None  # single-threaded helper use per tunnel

    # ---------------------------------------------------------------- core
    def _dispatch(self, calls: List[tuple], timeout: float) -> list:
        from .. import helper_win

        try:
            if is_admin():
                results = helper_win.run_calls(calls)
            else:
                results = self._elevated(calls, timeout)
        except HelperError:
            raise
        except RuntimeError as e:      # WinHelperError from the in-process verbs
            raise HelperError(str(e)) from e
        for call, res in zip(calls, results):
            if call[0] == "status" and isinstance(res, dict):
                self._status_cache = res
        return results

    # ------------------------------------------------------------- UAC path
    def _elevated(self, calls: List[tuple], timeout: float) -> list:
        import ctypes

        tmp = tempfile.gettempdir()
        calls_path = os.path.join(tmp, f"cleanroom-calls-{uuid.uuid4().hex}.json")
        out_path = os.path.join(tmp, f"cleanroom-out-{uuid.uuid4().hex}.json")
        with open(calls_path, "w", encoding="utf-8") as fh:
            json.dump([list(c) for c in calls], fh)

        if getattr(sys, "frozen", False):     # PyInstaller build
            exe, prefix = sys.executable, "--cleanroom-helper-win"
        else:
            exe, prefix = sys.executable, "-m cleanroom.helper_win"
        params = f'{prefix} --out "{out_path}" --calls "{calls_path}"'

        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, None, 0)
        except Exception as e:  # noqa: BLE001
            raise HelperError(f"could not request elevation: {e}") from e
        if ret <= 32:
            _unlink(calls_path)
            raise HelperError(
                "elevation declined — accept the UAC prompt or run Cleanroom "
                "as administrator")

        # NB: calls_path must stay on disk until the elevated process has
        # read it — the UAC prompt blocks the child's start, so deleting it
        # here (before consent) would always break the run.
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                if os.path.isfile(out_path):
                    time.sleep(0.15)          # let the writer finish
                    try:
                        with open(out_path, encoding="utf-8") as fh:
                            data = json.load(fh)
                    except (json.JSONDecodeError, OSError) as e:
                        raise HelperError(f"helper result unreadable: {e}") from e
                    finally:
                        _unlink(out_path)
                    if isinstance(data, dict) and not data.get("ok", False):
                        raise HelperError(data.get("error", "helper failed"))
                    return data
                time.sleep(0.25)
            raise HelperError("elevated helper timed out")
        finally:
            _unlink(calls_path)
            _unlink(out_path)

    # ----------------------------------------------------------------- api
    def call(self, verb: str, *args: str, timeout: float = 60.0) -> dict:
        calls = [(verb, *[str(a) for a in args])]
        if verb == "status" and not is_admin():
            # polling must not spam UAC: return the freshest status any
            # elevated verb reported (documented in PLATFORMS.md)
            return dict(self._status_cache)
        try:
            return self._dispatch(calls, timeout)[0]
        except IndexError as e:
            raise HelperError(f"helper {verb}: no result") from e

    def call_batch(self, calls, timeout: float = 180.0) -> list:
        return self._dispatch([tuple(c) for c in calls], timeout)

    def available(self) -> bool:
        return True    # verbs are always reachable (in-process or via UAC)


class WindowsBackend(PlatformBackend):
    def __init__(self) -> None:
        self.capabilities = Capabilities(
            "windows", "Windows",
            app_split_tunnel=False,          # needs a WFP kernel driver
            kill_switch_backend="wfp-netsh",
            dns_backend="config-loopback",   # DNS = 127.0.0.1 in the config
            elevation="uac",
            dns_loopback_in_config=True,
            openvpn_tunnel=False,           # no bundled OpenVPN driver — WG only
        )

    # --------------------------------------------------------------- api
    def make_helper(self, binary: str = "") -> HelperClient:
        return WindowsHelperClient()

    def default_route(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                 "Sort-Object RouteMetric | Select-Object -First 1 "
                 "-Property ifIndex,NextHop,InterfaceAlias | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15).stdout
            data = json.loads(out)
            if isinstance(data, dict):
                return (data.get("InterfaceAlias") or None,
                        data.get("NextHop") or None)
        except (subprocess.SubprocessError, OSError, ValueError):
            pass
        # text fallback: `route print` lists "Default Gateway:" per adapter
        try:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"],
                                 capture_output=True, text=True,
                                 timeout=10).stdout
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return None, parts[2]
        except (subprocess.SubprocessError, OSError):
            pass
        return None, None

    def env_check(self) -> list:
        import shutil

        checks = []
        wg = shutil.which("wg") or self._in_wg_dir("wg.exe")
        wgsvc = shutil.which("wireguard") or self._in_wg_dir("wireguard.exe")
        checks.append(("wg.exe — WireGuard tools "
                       "(https://download.wireguard.com/windows/)", bool(wg), ""))
        checks.append(("wireguard.exe — WireGuard service manager "
                       "(same download)", bool(wgsvc), ""))
        checks.append(("netsh — kill switch (built into Windows)",
                       bool(shutil.which("netsh")), ""))
        checks.append(("PowerShell — firewall rules (built into Windows)",
                       bool(shutil.which("powershell")), ""))
        return checks

    @staticmethod
    def _in_wg_dir(exe: str) -> Optional[str]:
        for d in WG_INSTALL_DIRS:
            p = os.path.join(d, exe)
            if os.path.isfile(p):
                return p
        return None

    def open_folder(self, path: str) -> None:
        subprocess.Popen(["explorer", path])

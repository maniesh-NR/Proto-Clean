"""Xray-core process lifecycle + system-proxy integration.

The manager runs the user-installed ``xray`` binary (Xray-core) with a
generated config (see :mod:`proto_clean.vpn.xrayconf`) and, in "system"
mode, points the OS proxy at the local inbounds:

* Linux   — per-user ``gsettings`` (GNOME / Cinnamon / MATE desktops;
            the proxy keys are shared with Mint's Cinnamon)
* Windows — per-user WinINET registry keys (no elevation needed) +
            a live "settings changed" broadcast
* macOS   — ``networksetup`` through the privileged helper verbs
            ``proxy-on`` / ``proxy-off`` (one network service at a time)

Xray-core is not bundled; ``find_xray_binary`` looks in PATH, common
install dirs and ``PROTO_CLEAN_XRAY_BIN``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from ..log import get
from ..paths import CACHE_DIR, PLATFORM_NAME
from .xrayconf import (DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, XrayProfile,
                       write_xray_config)

log = get("xray")

# Proxy states surfaced to the UI.
PROXY_OFF = "off"
PROXY_STARTING = "starting"
PROXY_ON = "on"
PROXY_ERROR = "error"

_CREATE_NO_WINDOW = 0x08000000 if sys.platform.startswith("win") else 0


class XrayError(RuntimeError):
    """Failed to start / run the Xray proxy."""


def find_xray_binary(explicit: str = "") -> Optional[str]:
    """Locate the Xray-core binary. Returns None when not installed."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("PROTO_CLEAN_XRAY_BIN", "")
    if env:
        candidates.append(env)
    exe = "xray.exe" if sys.platform.startswith("win") else "xray"
    which = shutil.which(exe)
    if which:
        candidates.append(which)
    if sys.platform.startswith("win"):
        local = os.path.dirname(os.path.abspath(sys.executable))
        candidates += [
            os.path.join(local, exe),
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                         "xray", exe),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "xray", exe),
        ]
    else:
        home = os.path.expanduser("~")
        candidates += [
            f"/usr/local/bin/{exe}", f"/usr/bin/{exe}", f"{home}/bin/{exe}",
            f"/opt/xray/{exe}", f"/opt/homebrew/bin/{exe}",
        ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


class XrayManager:
    """Owns the xray process and (optionally) the system proxy state."""

    def __init__(self, binary: str = "") -> None:
        self._binary = binary
        self._proc: Optional[subprocess.Popen] = None
        self._config_path: Optional[str] = None
        self._proxy_applied = False
        self._saved_proxy: Optional[dict] = None
        self.socks_port = DEFAULT_SOCKS_PORT
        self.http_port = DEFAULT_HTTP_PORT
        self.profile: Optional[XrayProfile] = None

    # ------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _dir(self) -> Path:
        d = CACHE_DIR / "xray"
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return d

    def start(self, profile: XrayProfile, socks_port: int = DEFAULT_SOCKS_PORT,
              http_port: int = DEFAULT_HTTP_PORT, timeout: float = 10.0,
              binary: str = "") -> None:
        """Write the config, spawn xray and wait until the SOCKS inbound
        accepts connections."""
        if self.running:
            raise XrayError("the Xray proxy is already running")
        exe = find_xray_binary(binary or self._binary)
        if not exe:
            raise XrayError(
                "the xray binary was not found — install Xray-core "
                "(https://github.com/XTLS/Xray-core) or set "
                "PROTO_CLEAN_XRAY_BIN")
        self.socks_port, self.http_port = int(socks_port), int(http_port)
        self._config_path = str(self._dir() / "config.json")
        write_xray_config(profile, self._config_path,
                          self.socks_port, self.http_port)
        self.profile = profile
        logf = open(self._dir() / "xray.log", "ab", buffering=0)
        popen_kw = dict(
            stdout=logf, stderr=subprocess.STDOUT,
            cwd=str(self._dir()),
        )
        if sys.platform.startswith("win"):
            popen_kw["creationflags"] = _CREATE_NO_WINDOW
        else:
            popen_kw["start_new_session"] = True
        log.info("starting %s -c %s", exe, self._config_path)
        self._proc = subprocess.Popen([exe, "run", "-c", self._config_path],
                                      **popen_kw)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise XrayError("xray exited immediately — " +
                                self._log_tail())
            if self._port_open(self.socks_port):
                log.info("xray up (socks %d, http %d)",
                         self.socks_port, self.http_port)
                return
            time.sleep(0.15)
        self.stop(revert_proxy=False)
        raise XrayError(f"xray did not open port {self.socks_port} "
                        f"within {timeout:.0f}s — " + self._log_tail())

    def stop(self, revert_proxy: bool = True, timeout: float = 3.0) -> None:
        """Terminate xray and restore the previous system proxy."""
        if revert_proxy and self._proxy_applied:
            try:
                self.revert_system_proxy()
            except Exception as e:  # noqa: BLE001
                log.warning("proxy revert failed: %s", e)
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout)
        self._proc = None
        log.info("xray stopped")

    def _log_tail(self, lines: int = 6) -> str:
        try:
            text = (self._dir() / "xray.log").read_text(encoding="utf-8",
                                                        errors="replace")
            tail = text.strip().splitlines()[-lines:]
            return "; ".join(tail) or "no log output"
        except OSError:
            return "no log output"

    @staticmethod
    def _port_open(port: int, host: str = "127.0.0.1") -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            return False

    def status(self) -> dict:
        return {
            "running": self.running,
            "pid": self._proc.pid if self._proc else None,
            "binary": self._binary or find_xray_binary() or "",
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "system_proxy": self._proxy_applied,
            "protocol": self.profile.protocol if self.profile else "",
        }

    # --------------------------------------------------------- system proxy
    def apply_system_proxy(self) -> None:
        """Point the OS at the local inbounds (idempotent)."""
        if self._proxy_applied:
            return
        if PLATFORM_NAME == "windows":
            self._win_apply()
        elif PLATFORM_NAME == "macos":
            self._mac_apply()
        else:
            self._linux_apply()
        self._proxy_applied = True

    def revert_system_proxy(self) -> None:
        """Restore whatever proxy state was there before we touched it."""
        if not self._proxy_applied:
            return
        try:
            if PLATFORM_NAME == "windows":
                self._win_revert()
            elif PLATFORM_NAME == "macos":
                self._mac_revert()
            else:
                self._linux_revert()
        finally:
            self._proxy_applied = False
            self._saved_proxy = None

    # --- Linux: gsettings (GNOME/Cinnamon/MATE) ---------------------------
    def _gs(self, *args: str) -> "subprocess.CompletedProcess":
        return subprocess.run(["gsettings", *args], capture_output=True,
                              text=True, timeout=10)

    def _gs_set(self, schema: str, key: str, value: str) -> None:
        r = self._gs("set", schema, key, value)
        if r.returncode != 0:
            raise XrayError(f"gsettings set {key} failed: "
                            f"{(r.stderr or r.stdout).strip()}")

    def _linux_apply(self) -> None:
        if shutil.which("gsettings") is None:
            raise XrayError(
                "gsettings not found — set the proxy manually to "
                f"127.0.0.1:{self.http_port} (SOCKS {self.socks_port})")
        r = self._gs("get", "org.gnome.system.proxy", "mode")
        self._saved_proxy = {"mode": r.stdout.strip().strip("'") or "none"}
        ignore = ("['localhost', '127.0.0.0/8', '::1', "
                  "'192.168.0.0/16', '10.0.0.0/8']")
        self._gs_set("org.gnome.system.proxy", "ignore-hosts", ignore)
        self._gs_set("org.gnome.system.proxy.socks", "host", "127.0.0.1")
        self._gs_set("org.gnome.system.proxy.socks", "port",
                     str(self.socks_port))
        self._gs_set("org.gnome.system.proxy", "mode", "'manual'")

    def _linux_revert(self) -> None:
        mode = (self._saved_proxy or {}).get("mode", "none")
        self._gs_set("org.gnome.system.proxy", "mode", f"'{mode}'")

    # --- macOS: networksetup via the privileged helper --------------------
    def _mac_services(self) -> list:
        from .helper import Helper
        r = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=10)
        services = []
        for line in (r.stdout or "").splitlines()[1:]:
            name = line.strip()
            if name and not name.startswith("*"):
                services.append(name)
        return services

    def _mac_apply(self) -> None:
        from .helper import Helper, HelperError
        services = self._mac_services()
        if not services:
            raise XrayError("no network services found (networksetup)")
        helper = Helper()
        for service in services:
            try:
                helper.call("proxy-on", service, "127.0.0.1",
                            str(self.socks_port))
            except HelperError as e:
                log.warning("proxy-on %s failed: %s", service, e)
        self._saved_proxy = {"services": services}

    def _mac_revert(self) -> None:
        from .helper import Helper, HelperError
        helper = Helper()
        for service in (self._saved_proxy or {}).get("services", []):
            try:
                helper.call("proxy-off", service)
            except HelperError as e:
                log.warning("proxy-off %s failed: %s", service, e)

    # --- Windows: WinINET registry (per user, no elevation) ---------------
    def _win_reg(self):
        import winreg
        return winreg

    def _win_key(self):
        winreg = self._win_reg()
        return winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_ALL_ACCESS)

    def _win_apply(self) -> None:
        winreg = self._win_reg()
        with self._win_key() as k:
            def get(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None
            self._saved_proxy = {
                "ProxyEnable": get("ProxyEnable"),
                "ProxyServer": get("ProxyServer"),
                "ProxyOverride": get("ProxyOverride"),
            }
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ,
                              f"127.0.0.1:{self.http_port}")
            winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                              "localhost;127.*;10.*;192.168.*;<local>")
        self._win_refresh()

    def _win_revert(self) -> None:
        winreg = self._win_reg()
        saved = self._saved_proxy or {}
        with self._win_key() as k:
            if saved.get("ProxyEnable") is not None:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD,
                                  int(saved["ProxyEnable"]))
            for name in ("ProxyServer", "ProxyOverride"):
                if saved.get(name) is not None:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ,
                                      saved[name])
        self._win_refresh()

    def _win_refresh(self) -> None:
        """Broadcast the WinINET change so running apps pick it up."""
        import ctypes
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(None, 39, None, 0)   # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(None, 37, None, 0)   # INTERNET_OPTION_REFRESH

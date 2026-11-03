"""Network-adapter discovery for link bonding (per-platform, no deps).

Bonding needs the local IPv4 address of every adapter the user wants to
use, so each member socket can be bound to exactly one adapter
(``sock.bind((addr, 0))``) — that is what forces traffic out of the
right NIC. Discovery shells out to the platform's standard tool:

* Linux   — ``ip -j -4 addr show`` (iproute2 JSON; falls back to the
            ``-o`` text form for very old iproute2)
* macOS   — ``ifconfig -a`` (blocks with a status line and ``inet``)
* Windows — ``powershell Get-NetIPAddress | ConvertTo-Json`` (locale
            independent), falling back to parsing ``ipconfig``

Everything degrades gracefully: any adapter we cannot parse is simply
not offered in the UI, and the user can always type an interface *or*
a bare IP into the bonding settings by hand.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Callable, List, Optional

from ..paths import PLATFORM_NAME


class Adapter:
    """One usable IPv4 adapter (value object for the settings UI)."""

    __slots__ = ("name", "ipv4")

    def __init__(self, name: str, ipv4: str) -> None:
        self.name = name
        self.ipv4 = ipv4

    def __repr__(self) -> str:      # pragma: no cover — debugging aid
        return f"Adapter({self.name!r}, {self.ipv4})"

    def __eq__(self, other) -> bool:
        return (isinstance(other, Adapter)
                and self.name == other.name and self.ipv4 == other.ipv4)


# ----------------------------------------------------------------- linux
def _parse_ip_json(text: str) -> List[Adapter]:
    out: List[Adapter] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for iface in data or []:
        name = iface.get("ifname") or ""
        if not name or iface.get("operstate") == "down":
            continue
        for addr in iface.get("addr_info") or []:
            ip = addr.get("local") or ""
            family = addr.get("family")
            if family == "inet" or ":" not in ip and "." in ip:
                if ip and not ip.startswith("127."):
                    out.append(Adapter(name, ip))
                break
    return out


def _parse_ip_text(text: str) -> List[Adapter]:
    """``ip -o -4 addr show`` lines:
    ``2:  wlan0    inet 192.168.1.4/24 brd ... scope global wlan0 ...``"""
    out: List[Adapter] = []
    for line in text.splitlines():
        m = re.match(
            r"\s*\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)",
            line)
        if not m:
            continue
        name, ip = m.group(1), m.group(2)
        if ip.startswith("127."):
            continue
        if "scope global" not in line and "scope host" in line:
            continue
        out.append(Adapter(name.rstrip("@"), ip))
    return out


# ----------------------------------------------------------------- macOS
_IFCONFIG_BLOCK = re.compile(
    r"^(\S+):\s+flags=\d+<([^>]*)>\s+mtu\s+\d+", re.M)


def _parse_ifconfig(text: str) -> List[Adapter]:
    out: List[Adapter] = []
    blocks = _IFCONFIG_BLOCK.split(text)
    # split -> [pre, name, flags, body, name, flags, body, ...]
    for i in range(1, len(blocks) - 2, 3):
        name, flags, body = blocks[i], blocks[i + 1], blocks[i + 2]
        if "up" not in [f.strip().lower() for f in flags.split(",")]:
            continue
        for line in body.splitlines():
            m = re.match(r"\s*inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m and not m.group(1).startswith("127."):
                out.append(Adapter(name, m.group(1)))
                break
    return out


# --------------------------------------------------------------- windows
def _parse_powershell_json(text: str) -> List[Adapter]:
    out: List[Adapter] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if isinstance(data, dict):      # single-address output
        data = [data]
    for row in data or []:
        if not isinstance(row, dict):
            continue
        # Get-NetIPAddress -AddressFamily IPv4 already filtered the
        # family server-side; just skip anything that is not dotted.
        ip = str(row.get("IPAddress", "")).strip()
        name = str(row.get("InterfaceAlias", "")).strip()
        if not name or not ip or ip.startswith("127."):
            continue
        if "." not in ip or ":" in ip:      # IPv4 only
            continue
        adapter = Adapter(name, ip)
        if adapter not in out:
            out.append(adapter)
    return out


_IPCONFIG_BLOCK = re.compile(
    r"^.*adapter\s+(.+?):\s*$", re.M | re.I)


def _parse_ipconfig(text: str) -> List[Adapter]:
    """Classic ``ipconfig`` blocks ('Ethernet adapter Ethernet0:')."""
    out: List[Adapter] = []
    blocks = _IPCONFIG_BLOCK.split(text)
    for i in range(1, len(blocks), 2):
        name, body = blocks[i].strip(), blocks[i + 1]
        for line in body.splitlines():
            m = re.search(
                r"(?:IPv4|IP Address)[^\d]*:?\s*(\d+\.\d+\.\d+\.\d+)",
                line, re.I)
            if m and not m.group(1).startswith("127."):
                out.append(Adapter(name, m.group(1)))
                break
    return out


# ----------------------------------------------------------------- api
def _run(cmd: List[str], timeout: float = 5.0) -> str:
    try:
        kw = {}
        if sys.platform.startswith("win"):
            kw["creationflags"] = 0x08000000      # CREATE_NO_WINDOW
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, **kw)
        return r.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _discover_linux() -> List[Adapter]:
    text = _run(["ip", "-j", "-4", "addr", "show"])
    if text:
        adapters = _parse_ip_json(text)
        if adapters:
            return adapters
    return _parse_ip_text(_run(["ip", "-o", "-4", "addr", "show"]))


def _discover_macos() -> List[Adapter]:
    return _parse_ifconfig(_run(["ifconfig", "-a"]))


def _discover_windows() -> List[Adapter]:
    ps = ("Get-NetIPAddress -AddressFamily IPv4 | "
          "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json "
          "-Compress")
    text = _run(["powershell", "-NoProfile", "-NonInteractive",
                 "-Command", ps], timeout=10)
    if text:
        adapters = _parse_powershell_json(text)
        if adapters:
            return adapters
    return _parse_ipconfig(_run(["ipconfig"]))


_DISCOVER: dict = {
    "linux": _discover_linux,
    "macos": _discover_macos,
    "windows": _discover_windows,
}

# Parsers exposed for tests.
PARSERS = {
    "ip_json": _parse_ip_json,
    "ip_text": _parse_ip_text,
    "ifconfig": _parse_ifconfig,
    "powershell_json": _parse_powershell_json,
    "ipconfig": _parse_ipconfig,
}


def list_adapters(platform: Optional[str] = None) -> List[Adapter]:
    """Every adapter that currently has a usable IPv4 address.

    ``platform`` overrides the detected OS (tests / forced selection).
    Empty list = discovery failed (the UI offers manual entry).
    """
    discover = _DISCOVER.get(platform or PLATFORM_NAME)
    if discover is None:
        return []
    try:
        return discover()
    except Exception:      # noqa: BLE001 — never crash the UI over this
        return []


def resolve_bind_ips(selected: List[str],
                     adapters: Optional[List[Adapter]] = None,
                     platform: Optional[str] = None) -> List[str]:
    """Turn the user's interface selection into bind IPs.

    Each selected entry may be an adapter name ("wlan0"), a "name=ip"
    pair, or a bare IPv4 address. Unknown names are dropped; if the
    whole selection resolves to nothing, an empty list is returned
    (the caller then binds no socket, i.e. uses the default route).
    """
    selected = [str(s or "").strip() for s in selected if str(s or "").strip()]
    if not selected:
        return []
    adapters = adapters if adapters is not None else list_adapters(platform)
    by_name = {a.name: a.ipv4 for a in adapters}
    out: List[str] = []
    for entry in selected:
        if "=" in entry:                       # explicit name=ip
            _, _, ip = entry.partition("=")
            ip = ip.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                out.append(ip)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", entry):   # bare IP
            out.append(entry)
        elif entry in by_name:
            out.append(by_name[entry])
        # unknown adapter name: dropped silently
    # de-duplicate, keep order
    seen = set()
    uniq = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq

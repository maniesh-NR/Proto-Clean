"""OpenVPN (.ovpn) config handling.

Parses the config captured from the Proton downloads page, validates it
(refusing shell-hook directives the same way the WireGuard path refuses
PreUp/PostUp), and applies Proto Clean's local edits:

* IPv6 support ON  — make sure IPv6 is routed through the tunnel
  (``tun-ipv6`` + ``route-ipv6 ::/0`` for TUN; TAP bridges v6 natively,
  so only the route is added);
* IPv6 support OFF — strip any ``route-ipv6`` directives so IPv6 never
  enters an IPv4-only tunnel.

The network driver (TUN or TAP) is not a file edit: it is passed to the
``ovpn-up`` helper verb as ``--dev-type`` so the same config works with
either driver.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Directives that run commands or override our routing tooling — a config
# containing any of these is rejected before it ever reaches openvpn as root.
FORBIDDEN_DIRECTIVES = {
    "up", "down", "script-security", "iproute", "route-up", "down-pre",
    "iproute6", "tls-verify", "tls-export-cert", "client-cert-not-required",
}

_REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)(?:\s+(udp|tcp))?\s*$", re.I)
_PROTO_RE = re.compile(r"^proto\s+(udp|tcp)\s*$", re.I)


class OvpnConfigError(ValueError):
    pass


@dataclass
class OvpnConf:
    lines: List[str] = field(default_factory=list)

    # ---- parsing ----------------------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "OvpnConf":
        lines = [ln.rstrip() for ln in (text or "").splitlines()]
        conf = cls(lines=lines)
        if not conf.remotes:
            raise OvpnConfigError("no usable 'remote' line in the OpenVPN config")
        for bad in conf.directives & FORBIDDEN_DIRECTIVES:
            raise OvpnConfigError(
                f"refusing config: '{bad}' directive is not allowed")
        return conf

    # ---- accessors --------------------------------------------------------
    @property
    def directives(self) -> set:
        """Every directive keyword present in the config."""
        out = set()
        in_block = False
        for raw in self.lines:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("</"):
                in_block = False
                continue
            if line.startswith("<"):
                in_block = True      # <ca>/<cert>/<key>/… block content
                continue
            if in_block:
                continue
            out.add(line.split()[0].lower())
        return out

    @property
    def remotes(self) -> List[Tuple[str, int, Optional[str]]]:
        """(host, port, proto|None) for every 'remote' line."""
        out: List[Tuple[str, int, Optional[str]]] = []
        for raw in self.lines:
            m = _REMOTE_RE.match(raw.strip())
            if m:
                proto = m.group(3).lower() if m.group(3) else None
                out.append((m.group(1), int(m.group(2)), proto))
        return out

    @property
    def proto(self) -> Optional[str]:
        """Transport from 'proto' line, else the first remote's inline one."""
        for raw in self.lines:
            m = _PROTO_RE.match(raw.strip())
            if m:
                return m.group(1).lower()
        for _h, _p, proto in self.remotes:
            if proto:
                return proto
        return None

    @property
    def endpoint(self) -> Tuple[str, int, Optional[str]]:
        """The first remote: (host, port, proto|None)."""
        return self.remotes[0]

    # ---- local modifications ---------------------------------------------
    def with_ipv6(self, driver: str = "tun") -> "OvpnConf":
        """IPv6 support ON: route ::/0 through the tunnel."""
        want_tun_ipv6 = driver != "tap" and not any(
            ln.strip() == "tun-ipv6" for ln in self.lines)
        want_route = not any(ln.strip().startswith("route-ipv6")
                             for ln in self.lines)
        if want_route:
            self.lines.append("route-ipv6 ::/0")
        if want_tun_ipv6:
            self.lines.append("tun-ipv6")
        return self

    def without_ipv6(self) -> "OvpnConf":
        """IPv6 support OFF: remove IPv6 routes (and tun-ipv6) so v6 never
        enters an IPv4-only tunnel."""
        self.lines = [ln for ln in self.lines
                      if not ln.strip().startswith("route-ipv6")
                      and ln.strip() != "tun-ipv6"]
        return self

    def serialize(self) -> str:
        return "\n".join(self.lines) + "\n"


def apply_ovpn_edits(config_text: str, *, ipv6: Optional[bool] = None,
                     driver: str = "tun") -> str:
    """Minimal, comment-preserving edits to a downloaded .ovpn config.

    * ipv6=True  — append ``route-ipv6 ::/0`` (+ ``tun-ipv6`` for TUN) when
      missing, so IPv6 passes through the tunnel;
    * ipv6=False — strip ``route-ipv6``/``tun-ipv6`` so IPv6 stays outside
      an IPv4-only tunnel (blocked when IPv6 leak protection is on).

    Returns the original text unchanged when no edit applies.
    """
    try:
        conf = OvpnConf.parse(config_text)
    except OvpnConfigError:
        # validation errors surface later, at install time
        conf = OvpnConf(lines=config_text.splitlines())
    if ipv6 is True:
        conf.with_ipv6(driver)
    elif ipv6 is False:
        conf.without_ipv6()
    else:
        return config_text
    return conf.serialize()

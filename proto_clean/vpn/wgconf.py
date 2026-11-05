"""WireGuard / wg-quick config handling.

Parses the config captured from the Proton downloads page, validates it,
and applies Proto Clean's local modifications (kept intentionally minimal —
the DNS redirect happens in the firewall, not the file, so the config
stays byte-identical to what Proton generated wherever possible).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_ENDPOINT_RE = re.compile(r"^(?P<host>[^:\s\[]+):(?P<port>\d+)$")


class WgConfigError(ValueError):
    pass


@dataclass
class WgQuickConf:
    interface: Dict[str, List[str]] = field(default_factory=dict)
    peer: Dict[str, List[str]] = field(default_factory=dict)

    # ---- parsing ----------------------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "WgQuickConf":
        conf = cls()
        section: Optional[Dict[str, List[str]]] = None
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line == "[Interface]":
                section = conf.interface
            elif line == "[Peer]":
                if not conf.interface.get("PrivateKey"):
                    raise WgConfigError(f"line {lineno}: [Peer] before PrivateKey")
                section = conf.peer
            elif "=" in line and section is not None:
                key, value = line.split("=", 1)
                section.setdefault(key.strip(), []).append(value.strip())
            else:
                raise WgConfigError(f"line {lineno}: cannot parse {line!r}")
        for required in ("PrivateKey", "Address"):
            if required not in conf.interface:
                raise WgConfigError(f"missing Interface.{required}")
        for required in ("PublicKey", "AllowedIPs", "Endpoint"):
            if required not in conf.peer:
                raise WgConfigError(f"missing Peer.{required}")
        if len(conf.peer.get("Endpoint", [])) != 1:
            raise WgConfigError("exactly one Endpoint expected")
        return conf

    # ---- accessors --------------------------------------------------------
    @property
    def endpoint(self) -> str:
        return self.peer["Endpoint"][0]

    @property
    def endpoint_host_port(self) -> tuple:
        m = _ENDPOINT_RE.match(self.endpoint)
        if not m:
            raise WgConfigError(f"bad Endpoint {self.endpoint!r}")
        return m.group("host"), int(m.group("port"))

    @property
    def dns(self) -> Optional[str]:
        vals = self.interface.get("DNS", [])
        return vals[0] if vals else None

    @property
    def addresses(self) -> List[str]:
        return [a.strip() for a in
                (addr for line in self.interface.get("Address", [])
                 for addr in line.split(",")) if a.strip()]

    @property
    def tunnel_ip(self) -> Optional[str]:
        for item in self.addresses:
            ip = item.split("/")[0]
            if ip.startswith("10."):
                return ip
        return None

    def serialize(self) -> str:
        out: List[str] = ["[Interface]"]
        for key, values in self.interface.items():
            out.append(f"{key} = {', '.join(values)}")
        out.append("")
        out.append("[Peer]")
        for key, values in self.peer.items():
            out.append(f"{key} = {', '.join(values)}")
        return "\n".join(out) + "\n"

    # ---- local modifications ----------------------------------------------
    def apply_split_dns_hints(self) -> None:
        """No-op placeholder kept for symmetry; DNS interception is firewall-based."""
        return

    def without_ipv6(self) -> "WgQuickConf":
        """IPv6 support OFF: drop IPv6 addresses, routes and DNS entries.

        Whatever v6 is no longer covered by AllowedIPs keeps using the
        original default route (or is blocked when IPv6 leak protection is
        on) — it never enters an IPv4-only tunnel. IPv4 tokens and unknown
        tokens (hostnames in DNS lines) are always kept.
        """
        import ipaddress

        def _v4_only(tokens: List[str]) -> List[str]:
            kept: List[str] = []
            for tok in tokens:
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    if ipaddress.ip_network(tok, strict=False).version == 6:
                        continue
                except ValueError:
                    pass               # hostname / unknown token — keep it
                kept.append(tok)
            return kept

        for key in ("Address", "DNS"):
            merged: List[str] = []
            for line in self.interface.get(key, []):
                merged.extend(_v4_only(line.split(",")))
            if merged:
                self.interface[key] = [", ".join(merged)]
            else:
                # every token was IPv6 — with IPv6 support off the line must
                # not survive (a v6-only Address makes the tunnel fail loudly
                # at bring-up instead of leaking IPv6 through it)
                self.interface.pop(key, None)

        kept_all: List[str] = []
        for line in self.peer.get("AllowedIPs", []):
            kept_all.extend(_v4_only(line.split(",")))
        if kept_all:
            self.peer["AllowedIPs"] = [", ".join(kept_all)]
        return self

    def with_dns(self, dns: str) -> "WgQuickConf":
        self.interface["DNS"] = [dns]
        return self

    def without_cidrs(self, cidrs: List[str]) -> "WgQuickConf":
        """Split-tunnel exclusions: remove CIDRs from AllowedIPs (portable).

        Whatever is no longer covered by AllowedIPs keeps using the original
        default route, which is exactly "bypass the VPN" for those
        destinations. Works identically on Linux, Windows and macOS because
        it only edits the config, not the routing tables. Invalid or
        non-containing entries are ignored; if everything would be excluded
        the config is left untouched (a tunnel with no AllowedIPs cannot
        route at all).
        """
        import ipaddress

        clean = [c.strip() for c in cidrs if c and c.strip()]
        if not clean:
            return self
        try:
            excl = [ipaddress.ip_network(c, strict=False) for c in clean]
        except ValueError as e:
            raise WgConfigError(f"invalid excluded CIDR: {e}") from e

        kept_all: List[str] = []
        for line in self.peer.get("AllowedIPs", []):
            kept: List[str] = []
            for tok in line.split(","):
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    kept.append(tok)      # pass unknown tokens through
                    continue
                remaining = [net]
                for e in excl:
                    nxt = []
                    for r in remaining:
                        if e.version == r.version and e.subnet_of(r):
                            try:
                                nxt.extend(r.address_exclude(e))
                            except ValueError:
                                pass        # e covers r entirely (e == r)
                        else:
                            nxt.append(r)
                    remaining = nxt
                kept.extend(str(r) for r in remaining)
            kept_all.extend(kept)
        if kept_all:
            self.peer["AllowedIPs"] = [", ".join(kept_all)]
        return self


def parse_wg_config(text: str) -> List[Dict[str, str]]:
    """Split a wg-quick / AmneziaWG config into flat section dicts.

    Returns ``[interface, peer, peer, ...]`` — one ``{key: value}`` dict
    per section in file order, values comma-joined when a key repeats.
    The first section must be ``[Interface]``; later ``[Peer]`` sections
    follow. This is the lenient shape the protocol importers consume
    (they validate the fields they need themselves); use
    :meth:`WgQuickConf.parse` for the strict single-tunnel validation.

    Raises :class:`WgConfigError` on text that is not a wg-quick file.
    """
    sections: List[Dict[str, str]] = []
    labels: List[str] = []
    current: Optional[Dict[str, str]] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line in ("[Interface]", "[Peer]"):
            current = {}
            sections.append(current)
            labels.append(line[1:-1])
            continue
        if "=" not in line:
            raise WgConfigError(f"line {lineno}: cannot parse {line!r}")
        if current is None:
            raise WgConfigError(
                f"line {lineno}: key before any [Interface]/[Peer] section")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key:
            raise WgConfigError(f"line {lineno}: empty key")
        if key in current:
            current[key] = current[key] + ", " + value
        else:
            current[key] = value
    if not sections:
        raise WgConfigError("no [Interface] section")
    if labels[0] != "Interface":
        raise WgConfigError("the first section must be [Interface]")
    # keep the documented shape: interface first, then the peers in order
    interface = sections[0]
    peers = [s for s, lbl in zip(sections, labels) if lbl == "Peer"]
    return [interface] + peers

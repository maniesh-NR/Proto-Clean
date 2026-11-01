"""Proton logical-server models.

Mirrors the JSON the account web app fetches (captured from the logged-in
Downloads page) so it can be parsed without manual field mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Feature bit flags used by Proton logicals
FEATURE_SECURE_CORE = 1
FEATURE_TOR = 2
FEATURE_P2P = 4
FEATURE_STREAMING = 8

TIER_FREE = 0


@dataclass
class PhysicalServer:
    id: str
    domain: str
    entry_ip: str
    exit_ip: str
    status: int = 1
    x25519_pk: str = ""

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "PhysicalServer":
        return cls(
            id=d.get("ID", ""),
            domain=d.get("Domain", ""),
            entry_ip=d.get("EntryIP", ""),
            exit_ip=d.get("ExitIP", ""),
            status=d.get("Status", 1),
            x25519_pk=d.get("X25519PublicKey", ""),
        )


@dataclass
class LogicalServer:
    id: str
    name: str                 # e.g. "US-FREE#1" / "NL#3"
    entry_country: str
    exit_country: str
    domain: str
    tier: int                 # 0 = free
    features: int             # bitmask, see FEATURE_* constants
    city: str = ""
    region: str = ""
    load: float = 0.0         # 0..100 percent
    score: float = 1e9        # lower = better candidate (Proton's own metric)
    status: int = 1           # 1 = online
    enabled: bool = True
    physical: List[PhysicalServer] = field(default_factory=list)

    # ---- derived helpers -------------------------------------------------
    @property
    def is_free(self) -> bool:
        return self.tier == TIER_FREE

    @property
    def is_online(self) -> bool:
        return self.status == 1 and bool(self.physical) and all(
            p.status == 1 for p in self.physical
        ) if self.physical else self.status == 1

    @property
    def supports_p2p(self) -> bool:
        return bool(self.features & FEATURE_P2P)

    @property
    def supports_tor(self) -> bool:
        return bool(self.features & FEATURE_TOR)

    @property
    def is_secure_core(self) -> bool:
        return bool(self.features & FEATURE_SECURE_CORE)

    @property
    def load_label(self) -> str:
        return f"{int(round(self.load))}%"

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "LogicalServer":
        loc = d.get("Location") or {}
        return cls(
            id=str(d.get("ID", "")),
            name=d.get("Name", ""),
            entry_country=d.get("EntryCountry", ""),
            exit_country=d.get("ExitCountry", ""),
            domain=d.get("Domain", ""),
            tier=int(d.get("Tier", 0)),
            features=int(d.get("Features", 0)),
            city=loc.get("City", "") or "",
            region=loc.get("Region", "") or "",
            load=float(d.get("Load", 0.0)),
            score=float(d.get("Score", 1e9)),
            status=int(d.get("Status", 1)),
            enabled=bool(d.get("Enabled", True)),
            physical=[PhysicalServer.from_json(p) for p in d.get("Servers", [])],
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "ID": self.id, "Name": self.name, "EntryCountry": self.entry_country,
            "ExitCountry": self.exit_country, "Domain": self.domain, "Tier": self.tier,
            "Features": self.features, "City": self.city, "Region": self.region,
            "Load": self.load, "Score": self.score, "Status": self.status,
            "Servers": [vars(p) for p in self.physical],
        }


def parse_logical_servers(payload: Any) -> List[LogicalServer]:
    """Accepts either the API envelope {LogicalServers: [...]} or a bare list."""
    if isinstance(payload, dict):
        items = payload.get("LogicalServers") or payload.get("Servers") or []
    elif isinstance(payload, list):
        items = payload
    else:
        return []
    out: List[LogicalServer] = []
    for item in items:
        try:
            out.append(LogicalServer.from_json(item))
        except Exception:
            continue
    return out

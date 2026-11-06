"""Server ranking / "fastest server" selection.

Proton computes `Score` server-side precisely for "connect to the fastest";
lower is better. We reproduce the ranking locally so the choice also works
if Score is missing from a scrape, and we always prefer *online* servers
whose load is not critical.
"""

from __future__ import annotations

from typing import List, Optional

from .models import LogicalServer

# Load above which a server is considered saturated (Proton's own UI marks
# >90% red).
CRITICAL_LOAD = 90.0


def score_of(s: LogicalServer) -> float:
    """Local estimate of a server's quality (lower = better).

    Uses Proton's Score when available; otherwise falls back to a load-based
    heuristic so the fastest picker still works on partial scrapes.
    """
    if s.score and s.score < 1e8:
        base = s.score
    else:
        base = s.load / 100.0
    if not s.is_online:
        return 1e9
    if s.load >= CRITICAL_LOAD:
        base += 5.0          # strongly deprioritise saturated servers
    return base


def rank_servers(servers: List[LogicalServer], max_tier: int = 0) -> List[LogicalServer]:
    """Servers sorted best-first, filtered to the plan tier (0 = free)."""
    usable = [s for s in servers if s.tier <= max_tier and s.is_online]
    return sorted(usable, key=score_of)


def fastest_server(servers: List[LogicalServer], max_tier: int = 0) -> Optional[LogicalServer]:
    ranked = rank_servers(servers, max_tier)
    return ranked[0] if ranked else None


def region_of(server: LogicalServer) -> str:
    """Region grouping key for the collapsible server list.

    Proton names its logical servers ``<REGION>#<index>`` where the
    region is a country or a country-city code (``US-FREE#3``,
    ``US-NY#1``, ``SE#2``, ``JP-FREE#1``). The header a group of servers
    folds under is that region prefix, with the free-tier ``-FREE``
    marker stripped so all of a country's free servers (``US-FREE#1..N``)
    fold under the country itself (``US``); non-free city servers keep
    their city region (``US-NY``). Falls back to the exit country when
    the name carries no ``#`` separator.
    """
    name = (server.name or "").split("#", 1)[0].strip()
    if name.upper().endswith("-FREE"):
        name = name[:-len("-FREE")].strip()
    if name:
        return name
    return server.exit_country or "?"

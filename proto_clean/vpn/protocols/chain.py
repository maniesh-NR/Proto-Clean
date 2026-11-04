"""Multiprotocol multihop chain engine.

A chain is an ordered list of share URLs (CLIENT -> EXIT): the local SOCKS
of hop N becomes the upstream that hop N+1 dials its own server through.
Two engines can be joined when the previous hop exposes a local SOCKS
(``exposes`` in ``("socks", "mixed")``) and the next engine supports dialing
through one (``supports_upstream``).

Full-tunnel engines (registry family ``"tunnel"`` — WireGuard-style engines
such as IKEv2 or Obscura) take over the whole device network: they may only
be the FIRST hop and nothing may follow them, because a tunnel carries all
traffic by itself.

Local ports are handed out by :func:`.base.free_port` starting from
:data:`CHAIN_BASE_PORT`; allocated ports are tracked so two hops of a chain
never share one (engines only bind at ``start`` time, after the whole chain
has been built).
"""

from __future__ import annotations

import time
from typing import List, Tuple

from ...log import get
from ..samizdatconf import SamizdatProfile
from ..xrayconf import XrayProfile
from . import links
from . import models as M
from .base import (PROXY_FAMILY, TUNNEL_FAMILY, ProtocolEngine, ProtocolError,
                   ProtocolProfile, free_port)

log = get("protocols.chain")

#: first local port tried for chain hops
CHAIN_BASE_PORT = 10800


class ChainError(ProtocolError):
    """Raised when a protocol chain cannot be built or started."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _kind_for(profile: ProtocolProfile) -> str:
    """Registry kind of ``profile`` (older model classes lack ``.kind``)."""
    kind = getattr(profile, "kind", "") or ""
    if kind:
        return kind
    if isinstance(profile, XrayProfile):
        return "trojan" if getattr(profile, "protocol", "") == "trojan" \
            else "vless"
    if isinstance(profile, SamizdatProfile):
        return "samizdat"
    return ""


def _alloc_port(used: set) -> int:
    """Next distinct free local port from :data:`CHAIN_BASE_PORT`.

    ``free_port`` only checks the OS, not our own bookkeeping — hops are
    built before any of them binds, so ``used`` prevents double allocation.
    """
    candidate = CHAIN_BASE_PORT
    for _ in range(4096):
        if candidate not in used:
            port = free_port(candidate)
            if port not in used:
                used.add(port)
                return port
        candidate += 1
    raise ChainError("no free local port available for the chain")


# ---------------------------------------------------------------------------
# chain building
# ---------------------------------------------------------------------------
def build_chain(profiles: List[ProtocolProfile]
                ) -> List[Tuple[ProtocolEngine, ProtocolProfile]]:
    """Validate an ordered profile list (CLIENT -> EXIT) and instantiate
    its engines without starting them.

    Rules:

    * hop 1 is what the client dials into; the last hop is the exit;
    * tunnel-family engines (``registry.family(kind) == "tunnel"``) may only
      be the first hop and nothing may follow them;
    * every later hop is wired with ``upstream_socks = (host, port)`` of the
      previous engine's local SOCKS — only possible when the previous engine
      exposes ``"socks"``/``"mixed"`` and the hop itself has
      ``supports_upstream`` set (otherwise :class:`ChainError` naming the
      pair);
    * every hop gets a distinct local port from :data:`CHAIN_BASE_PORT`
      (``http_port`` stays 0).

    Returns ``[(engine, profile), ...]`` in chain order.
    """
    # late import so tests can monkeypatch the registry factories
    from . import family as registry_family
    from . import make_engine as registry_make_engine

    profiles = list(profiles)
    if not profiles:
        raise ChainError("empty chain — at least one hop is required")

    pairs: List[Tuple[ProtocolEngine, ProtocolProfile]] = []
    used: set = set()
    prev: Tuple[str, str, ProtocolEngine] = ("", "", None)  # kind, family, eng
    for idx, profile in enumerate(profiles):
        hop = idx + 1
        kind = _kind_for(profile)
        if not kind:
            raise ChainError("chain hop %d: profile has no protocol kind" % hop)
        fam = registry_family(kind)
        if fam == TUNNEL_FAMILY and idx > 0:
            raise ChainError(
                "chain hop %d: %s is a full-tunnel engine and may only be "
                "the first hop" % (hop, kind))
        if idx > 0 and prev[1] == TUNNEL_FAMILY:
            raise ChainError(
                "chain hop %d: %s cannot follow %s — a full-tunnel engine "
                "takes all traffic and must be the only hop"
                % (hop, kind, prev[0]))
        try:
            eng = registry_make_engine(kind, profile,
                                       socks_port=_alloc_port(used))
        except ProtocolError as exc:
            raise ChainError("chain hop %d (%s): %s" % (hop, kind, exc)) \
                from None
        eng.http_port = 0
        if idx > 0:
            prev_kind, _prev_fam, prev_eng = prev
            if prev_eng.exposes not in ("socks", "mixed"):
                raise ChainError(
                    "chain hop %d (%s) cannot dial through hop %d (%s): the "
                    "previous engine exposes %r, not a local SOCKS"
                    % (hop, kind, hop - 1, prev_kind, prev_eng.exposes))
            if not eng.supports_upstream:
                raise ChainError(
                    "chain hop %d (%s) cannot dial through hop %d (%s): %s "
                    "has no upstream SOCKS support"
                    % (hop, kind, hop - 1, prev_kind, kind))
            eng.upstream_socks = ("127.0.0.1", prev_eng.socks_port)
        prev = (kind, fam, eng)
        pairs.append((eng, profile))
    return pairs


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class ChainEngine(ProtocolEngine):
    """Runs a multiprotocol chain; exposes the LAST hop's local SOCKS."""

    proxy_kind = "chain"
    family = PROXY_FAMILY
    exposes = "socks"
    binary_name = ""
    supports_upstream = True                  # a chain can front another hop

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self.engines: List[ProtocolEngine] = []

    # -- lifecycle ----------------------------------------------------------
    def start(self, chain_profile: M.ChainProfile, timeout: float = 60.0) -> None:
        if self.running:
            raise ProtocolError("the chain is already running")
        if not isinstance(chain_profile, M.ChainProfile):
            raise ChainError("chain engine needs a ChainProfile")
        hops = list(chain_profile.hops or [])
        if not hops:
            raise ChainError("chain profile has no hops")

        profiles: List[ProtocolProfile] = []
        for i, url in enumerate(hops):
            try:
                _kind, prof = links.parse_link(url)
            except ProtocolError as exc:
                raise ChainError("chain hop %d: bad link %r: %s"
                                 % (i + 1, url[:60], exc)) from None
            profiles.append(prof)

        pairs = build_chain(profiles)
        per_hop = float(timeout) // len(pairs)      # per-engine time budget
        started: List[ProtocolEngine] = []
        try:
            for i, (eng, prof) in enumerate(pairs):  # first hop first
                try:
                    eng.start(prof, timeout=per_hop)
                except Exception as exc:
                    raise ChainError("chain hop %d (%s) failed: %s"
                                     % (i + 1, eng.proxy_kind, exc)) from exc
                started.append(eng)
        except BaseException:
            for eng in reversed(started):            # unwind what came up
                try:
                    eng.stop()
                except Exception:                    # noqa: BLE001 — best effort
                    pass
            self.engines = []
            raise
        self.engines = started
        self.socks_port = started[-1].socks_port     # chain endpoint = exit hop
        self.http_port = 0
        self._started_at = time.time()
        log.info("chain up: %s -> socks://127.0.0.1:%d",
                 " -> ".join(e.proxy_kind for e in started), self.socks_port)

    def stop(self, timeout: float = 5.0) -> None:
        for eng in reversed(self.engines):           # exit hop first
            try:
                eng.stop(timeout)
            except Exception as exc:                 # noqa: BLE001 — best effort
                log.warning("chain hop %s stop failed: %s",
                            eng.proxy_kind, exc)
        super().stop(timeout)
        self._started_at = 0.0

    # -- introspection --------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self.engines) and all(e.running for e in self.engines)

    def status(self) -> dict:
        d = super().status()
        hops = [{"kind": e.proxy_kind, "running": e.running,
                 "socks_port": e.socks_port} for e in self.engines]
        d["hops"] = hops
        d["exit"] = hops[-1]["kind"] if hops else ""
        return d


def engine(profile: M.ChainProfile, socks_port: int = 0) -> ChainEngine:
    """Registry factory for the ``chain`` protocol kind."""
    return ChainEngine(socks_port=socks_port)

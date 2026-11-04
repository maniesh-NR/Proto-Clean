"""Protocol registry: maps profile kinds to engines and parsers.

This is the single place the UI / controller / importer consult; adding a
protocol means adding a model (in :mod:`.models`), a parser (in
:mod:`.links`), an engine module and one entry here.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from ..samizdatconf import SamizdatProfile
from ..samizdat import SamizdatManager
from ..xrayconf import XrayProfile
from ..xray import XrayManager
from . import coverdtls, ikev2, links, masque, sslocal, tor, tuic
from . import hysteria2
from . import models as M
from .base import ProtocolEngine, ProtocolError, ProtocolProfile

#: kind -> (model class, engine factory, engine class)
_REGISTRY: Dict[str, dict] = {}


def _register(kind: str, title: str, model, factory: Callable,
              engine_cls=None, family: str = "proxy") -> None:
    _REGISTRY[kind] = {
        "title": title,
        "model": model,
        "factory": factory,
        "engine_cls": engine_cls,
        "family": family,
    }


def _xray_engine(profile: XrayProfile, socks_port: int = 0) -> XrayManager:
    return XrayManager(socks_port=socks_port)


def _samizdat_engine(profile, socks_port: int = 0) -> SamizdatManager:
    return SamizdatManager(socks_port=socks_port)


_register("shadowsocks", "Shadowsocks", M.ShadowsocksProfile,
          lambda p, socks_port=0: sslocal.engine(p, socks_port),
          sslocal.ShadowsocksEngine)
_register("shadowsocksr", "ShadowsocksR", M.ShadowsocksrProfile,
          None)                       # lantern-box capability probe
_register("vless", "VLESS (Xray)", XrayProfile, _xray_engine, XrayManager)
_register("trojan", "Trojan (Xray)", XrayProfile, _xray_engine, XrayManager)
_register("hysteria2", "Hysteria 2", M.Hysteria2Profile,
          lambda p, socks_port=0: hysteria2.engine(p, socks_port),
          hysteria2.Hysteria2Engine)
_register("tuic", "TUIC v5", M.TuicProfile,
          lambda p, socks_port=0: tuic.engine(p, socks_port), tuic.TuicEngine)
_register("masque", "MASQUE (QUIC)", M.MasqueProfile,
          lambda p, socks_port=0: masque.engine(p, socks_port),
          masque.MasqueEngine)
_register("naive", "NaïveProxy", M.NaiveProfile, None)     # naive binary
_register("coverdtls", "Cover-DTLS", M.CoverDtlsProfile,
          lambda p, socks_port=0: coverdtls.engine(p, socks_port),
          coverdtls.CoverDtlsEngine)
_register("cloak", "OpenVPN over Cloak", M.CloakProfile, None)
_register("amneziawg", "AmneziaWG", M.AwgProfile, None)    # box endpoint /
_register("awg", "AmneziaWG", M.AwgProfile, None)          # awg-quick adapter
_register("ikev2", "IKEv2", M.Ikev2Profile,
          lambda p, socks_port=0: ikev2.engine(p, socks_port),
          ikev2.Ikev2Engine, family="tunnel")
_register("tor", "Tor", M.TorProfile,
          lambda p, socks_port=0: tor.engine(p, socks_port), tor.TorEngine)
_register("obscura", "Obscura relays", M.ObscuraProfile, None)
_register("radiance", "Lantern Radiance", M.RadianceProfile, None)
_register("lampshade", "Lantern Lampshade", M.LampshadeProfile, None)
_register("samizdat", "Lantern Samizdat", SamizdatProfile,
          _samizdat_engine, SamizdatManager)
_register("reflex", "Reflex", M.ReflexProfile, None)
_register("outline", "Outline smart dialer", M.OutlineProfile, None)
_register("algeneva", "ALGeneva", M.AlgenevaProfile, None)
_register("water", "WATER (WASM)", M.WaterProfile, None)
_register("vmess", "VMess (V2ray/V2fly)", M.VmessProfile, None)
_register("warp", "Cloudflare WARP", M.WarpProfile, None)
_register("boxraw", "Sing-box config (raw)", M.BoxRawProfile, None)
_register("clash", "Clash config", M.ClashProfile, None)
_register("chain", "Protocol chain", M.ChainProfile, None)


# ---------------------------------------------------------------------------
# public helpers
# ---------------------------------------------------------------------------
def kinds() -> List[str]:
    """All registered protocol kinds."""
    return sorted(_REGISTRY)


def title(kind: str) -> str:
    entry = _REGISTRY.get(kind)
    return entry["title"] if entry else kind


def family(kind: str) -> str:
    entry = _REGISTRY.get(kind)
    return entry["family"] if entry else "proxy"


def has_engine(kind: str) -> bool:
    """True when a local engine implementation exists for ``kind``."""
    entry = _REGISTRY.get(kind)
    return bool(entry and entry["factory"])


def model_class(kind: str) -> Optional[type]:
    entry = _REGISTRY.get(kind)
    return entry["model"] if entry else None


def make_engine(kind: str, profile: ProtocolProfile,
                socks_port: int = 0) -> ProtocolEngine:
    """Instantiate the engine for ``kind``.

    Raises :class:`ProtocolError` for protocols without a built-in engine
    (they need an external binary — lantern-box, naive, ck-client, tor —
    which the capability-probing adapters provide in later layers).
    """
    entry = _REGISTRY.get(kind)
    if entry is None:
        raise ProtocolError("unknown protocol kind %r" % kind)
    if not entry["factory"]:
        raise ProtocolError(
            "%s has no built-in engine — it runs through the lantern-box / "
            "external-binary adapters (see proto_clean/vpn/protocols/box)"
            % kind)
    return entry["factory"](profile, socks_port=socks_port)


def parse_any_url(url: str) -> Tuple[str, ProtocolProfile]:
    """Parse any share link (thin alias over :func:`links.parse_link`)."""
    return links.parse_link(url)

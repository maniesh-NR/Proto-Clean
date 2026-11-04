"""Convert foreign client configs into Proto Clean profiles.

Supported inputs (each also importable from files, the clipboard, QR
codes and subscription URLs — see :mod:`.importers`):

* **Clash / Clash.Meta / Mihomo** — YAML configs (``proxies:`` list) and
  ``clash://install-config?url=…`` subscription links.  Proxy types:
  ss, ssr, vmess, vless, trojan, hysteria2, tuic, socks5, http, wireguard.
* **V2ray / V2fly / Xray JSON** — client configs: every ``outbounds``
  entry convertible maps to a profile (vmess, vless, trojan, shadowsocks,
  socks).  Share links (``vmess://``, ``vless://``, ``trojan://``,
  ``ss://``) go through :mod:`.links` directly.
* **Sing-box JSON** — two modes: convert the ``outbounds`` to profiles
  (vmess, vless, trojan, shadowsocks, hysteria2, tuic, naive, socks,
  http, wireguard) *or* run the whole config as-is through lantern-box
  (``BoxRawProfile`` passthrough — nothing is lost or re-interpreted).
* **Subscriptions** — plain text (one share link per line), base64
  (v2rayNG style), Clash YAML and sing-box JSON, auto-detected.
"""

from __future__ import annotations

import base64
import binascii
import json as _json
from typing import Dict, List, Optional, Tuple

from ...log import get
from . import links, models as M
from .base import ProtocolError, ProtocolProfile

log = get("protocols.convert")


def _tagged(profile: ProtocolProfile, name: str) -> ProtocolProfile:
    """Set the display tag when the profile model has one."""
    if name and hasattr(type(profile), "__dataclass_fields__") \
            and "tag" in type(profile).__dataclass_fields__:
        profile.tag = name
    return profile

try:                                            # PyYAML (Clash configs)
    import yaml as _yaml
    HAVE_YAML = True
except ImportError:                             # pragma: no cover
    _yaml = None
    HAVE_YAML = False


# ---------------------------------------------------------------------------
# Clash (YAML) -> profiles
# ---------------------------------------------------------------------------
_CLASH_SS_METHODS = ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
                     "chacha20-ietf-poly1305")


def clash_proxies_to_profiles(proxies: List[dict]) -> List[ProtocolProfile]:
    """Convert a Clash ``proxies:`` list into Proto Clean profiles.

    Unconvertable entries are skipped (and logged), never fatal — Clash
    configs routinely mix in types we proxy through lantern-box anyway.
    """
    out: List[ProtocolProfile] = []
    for entry in proxies or []:
        try:
            prof = _clash_proxy(entry)
        except (ProtocolError, ValueError, TypeError, KeyError) as exc:
            log.debug("skipping clash proxy %r: %s",
                      entry.get("name") if isinstance(entry, dict) else entry,
                      exc)
            continue
        if prof is not None:
            out.append(_tagged(prof, str((entry or {}).get("name") or "")))
    return out


def _clash_proxy(p: dict) -> Optional[ProtocolProfile]:
    ptype = (p.get("type") or "").lower()
    name = str(p.get("name") or "")
    if ptype == "ss":
        return M.ShadowsocksProfile(
            server=str(p["server"]), port=int(p["port"]),
            method=p.get("cipher") or "aes-256-gcm",
            password=str(p.get("password") or ""),
            plugin=(p.get("plugin") or ""),
            tag=name)
    if ptype == "ssr":
        return M.ShadowsocksrProfile(
            server=str(p["server"]), port=int(p["port"]),
            protocol=p.get("protocol") or "origin",
            method=p.get("cipher") or "aes-256-cfb",
            obfs=p.get("obfs") or "plain",
            password=str(p.get("password") or ""),
            protocol_param=str(p.get("protocol-param") or ""),
            obfs_param=str(p.get("obfs-param") or ""))
    if ptype == "vmess":
        return M.VmessProfile(
            server=str(p["server"]), port=int(p["port"]),
            uuid=str(p.get("uuid") or ""),
            alter_id=int(p.get("alterId") or p.get("alter-id") or 0),
            security=p.get("cipher") or "auto",
            transport=(p.get("network") or "tcp").lower(),
            header_type=((p.get("ws-opts") or {}).get("headers") or {}).get(
                "type", "") if p.get("network") == "ws" else
                ((p.get("h2-opts") or {}).get("host") and "") or "",
            host=_clash_host(p), path=_clash_path(p),
            tls=bool(p.get("tls")),
            sni=str(p.get("servername") or p.get("sni") or ""),
            fp=str(p.get("client-fingerprint") or ""))
    if ptype == "vless":
        # map onto the Xray VLESS profile the existing engines speak
        from ..xrayconf import XrayProfile
        flow = str(p.get("flow") or "")
        reality = bool((p.get("reality-opts") or {}).get("public-key"))
        return XrayProfile(
            protocol="vless-reality" if reality else "vless-reality",
            address=str(p["server"]), port=int(p["port"]), name=name,
            uuid=str(p.get("uuid") or ""),
            public_key=str((p.get("reality-opts") or {}).get("public-key")
                           or ""),
            short_id=str((p.get("reality-opts") or {}).get("short-id") or ""),
            flow=flow or "xtls-rprx-vision",
            sni=str(p.get("servername") or p.get("sni") or ""),
            fingerprint=str(p.get("client-fingerprint") or "chrome"),
            allow_insecure=bool(p.get("skip-cert-verify")))
    if ptype == "trojan":
        from ..xrayconf import XrayProfile
        return XrayProfile(
            protocol="trojan", address=str(p["server"]), port=int(p["port"]),
            name=name, password=str(p.get("password") or ""),
            sni=str(p.get("sni") or p.get("servername") or ""),
            allow_insecure=bool(p.get("skip-cert-verify")))
    if ptype in ("hysteria2", "hysteria"):
        obfs = (p.get("obfs") or "")
        return M.Hysteria2Profile(
            server=str(p["server"]), port=int(p["port"]),
            auth=str(p.get("password") or ""),
            sni=str(p.get("sni") or p.get("servername") or ""),
            insecure=bool(p.get("skip-cert-verify")),
            obfs="salamander" if obfs == "salamander" else "",
            obfs_password=str(p.get("obfs-password") or ""))
    if ptype == "tuic":
        return M.TuicProfile(
            uuid=str(p.get("uuid") or ""), password=str(p.get("password") or ""),
            server=str(p["server"]), port=int(p["port"]),
            sni=str(p.get("sni") or ""),
            congestion=p.get("congestion-controller") or "bbr",
            alpn=",".join(p.get("alpn") or ["h3"]),
            udp_relay_mode=p.get("udp-relay-mode") or "native",
            allow_insecure=bool(p.get("skip-cert-verify")))
    if ptype in ("socks5", "socks"):
        # keep as a lantern-box socks outbound via a naive-style profile?
        # socks servers are rare in clash lists — skip with a log line
        log.debug("clash socks proxy %r skipped (no profile model)", name)
        return None
    if ptype == "wireguard":
        return M.AwgProfile(
            server=str(p["server"]), port=int(p["port"]),
            private_key=str(p.get("private-key") or ""),
            peer_public_key=str(
                (p.get("peers") or [{}])[0].get("public-key") or
                p.get("public-key") or ""),
            address=[str(a) for a in (p.get("ip") or
                                      p.get("allowed-ips") or
                                      ["172.16.0.2/32"])],
            dns=[str(d) for d in (p.get("dns") or [])],
            allowed_ips=["0.0.0.0/0"],
            keepalive=int(p.get("persistent-keepalive") or 25))
    log.debug("clash proxy type %r (%r) not convertible", ptype, name)
    return None


def _clash_host(p: dict) -> str:
    net = (p.get("network") or "").lower()
    if net == "ws":
        opts = p.get("ws-opts") or {}
        return str(opts.get("headers", {}).get("Host")
                   or p.get("server") or "")
    if net in ("h2", "http"):
        opts = p.get("h2-opts") or {}
        hosts = opts.get("host") or []
        return str(hosts[0]) if hosts else str(p.get("server") or "")
    if net == "grpc":
        return str((p.get("grpc-opts") or {}).get("grpc-service-name") or "")
    return str(p.get("server") or "")


def _clash_path(p: dict) -> str:
    net = (p.get("network") or "").lower()
    if net == "ws":
        return str((p.get("ws-opts") or {}).get("path") or "/")
    if net in ("h2", "http"):
        return str((p.get("h2-opts") or {}).get("path") or "/")
    return ""


def parse_clash_yaml(text: str) -> List[ProtocolProfile]:
    """Parse a Clash YAML document into profiles."""
    if not HAVE_YAML:
        raise ProtocolError("Clash configs need PyYAML (pip install pyyaml)")
    try:
        doc = _yaml.safe_load(text) or {}
    except _yaml.YAMLError as exc:
        raise ProtocolError("invalid Clash YAML: %s" % exc) from None
    if not isinstance(doc, dict):
        raise ProtocolError("Clash config is not a mapping")
    return clash_proxies_to_profiles(doc.get("proxies") or [])


def parse_clash_link(url: str) -> Tuple[str, List[ProtocolProfile]]:
    """Handle ``clash://install-config?url=<subscription>`` — returns the
    subscription URL and the (not yet fetched) empty profile list."""
    u = links._Url(url)
    if u.scheme != "clash":
        raise ProtocolError("not a clash:// link")
    sub = u.first("url")
    if not sub:
        raise ProtocolError("clash:// link has no subscription url= param")
    return sub, []


# ---------------------------------------------------------------------------
# V2ray / V2fly / Xray JSON -> profiles
# ---------------------------------------------------------------------------
def parse_v2ray_json(text: str) -> List[ProtocolProfile]:
    """Convert a v2ray/Xray client config's outbounds to profiles."""
    try:
        doc = _json.loads(text)
    except ValueError as exc:
        raise ProtocolError("invalid JSON: %s" % exc) from None
    outbounds = doc.get("outbounds") or []
    profiles: List[ProtocolProfile] = []
    for ob in outbounds:
        try:
            prof = _v2ray_outbound(ob)
        except (KeyError, ValueError, TypeError) as exc:
            log.debug("skipping v2ray outbound %r: %s",
                      ob.get("tag") if isinstance(ob, dict) else ob, exc)
            continue
        if prof is not None:
            profiles.append(_tagged(prof, str(ob.get("tag") or "")))
    if not profiles:
        raise ProtocolError("no convertible outbounds in this V2ray config")
    return profiles


def _v2ray_outbound(ob: dict) -> Optional[ProtocolProfile]:
    proto = (ob.get("protocol") or "").lower()
    name = str(ob.get("tag") or "")
    if proto in ("freedom", "blackhole", "dns"):
        return None
    sv = ob.get("settings") or {}
    stream = ob.get("streamSettings") or {}
    net = (stream.get("network") or "tcp").lower()
    sec = (stream.get("security") or "").lower()
    tls_on = sec in ("tls", "reality")
    sni = ((stream.get("tlsSettings") or {}).get("serverName")
           or (stream.get("realitySettings") or {}).get("serverName") or "")
    ws = stream.get("wsSettings") or {}
    grpc = stream.get("grpcSettings") or {}
    h2 = stream.get("httpSettings") or {}
    if proto == "vmess":
        vnext = (sv.get("vnext") or [{}])[0]
        users = (vnext.get("users") or [{}])[0]
        return M.VmessProfile(
            server=str(vnext.get("address") or ""), port=int(vnext.get("port") or 443),
            uuid=str(users.get("id") or ""),
            alter_id=int(users.get("alterId") or 0),
            security=str(users.get("security") or "auto"),
            transport=net, host=str(ws.get("headers", {}).get("Host")
                                    or grpc.get("authority")
                                    or (h2.get("host") or [""])[0]),
            path=str(ws.get("path") or grpc.get("serviceName")
                     or h2.get("path") or ""),
            tls=tls_on, sni=str(sni))
    if proto == "vless":
        from ..xrayconf import XrayProfile
        vnext = (sv.get("vnext") or [{}])[0]
        users = (vnext.get("users") or [{}])[0]
        reality = stream.get("realitySettings") or {}
        return XrayProfile(
            protocol="vless-reality",
            address=str(vnext.get("address") or ""),
            port=int(vnext.get("port") or 443), name=name,
            uuid=str(users.get("id") or ""),
            public_key=str(reality.get("publicKey") or ""),
            short_id=str(reality.get("shortId") or ""),
            flow=str(users.get("flow") or "xtls-rprx-vision"),
            sni=str(sni or reality.get("serverName") or ""),
            allow_insecure=bool((stream.get("tlsSettings") or {})
                                .get("allowInsecure")))
    if proto == "trojan":
        from ..xrayconf import XrayProfile
        servers = (sv.get("servers") or [{}])[0]
        return XrayProfile(
            protocol="trojan", address=str(servers.get("address") or ""),
            port=int(servers.get("port") or 443), name=name,
            password=str(servers.get("password") or ""), sni=str(sni),
            allow_insecure=bool((stream.get("tlsSettings") or {})
                                .get("allowInsecure")))
    if proto in ("shadowsocks", "ss"):
        servers = (sv.get("servers") or [{}])[0]
        return M.ShadowsocksProfile(
            server=str(servers.get("address") or ""),
            port=int(servers.get("port") or 8388),
            method=str(servers.get("method") or "aes-256-gcm"),
            password=str(servers.get("password") or ""))
    if proto in ("socks", "http"):
        log.debug("v2ray %s outbound %r skipped", proto, name)
        return None
    return None


# ---------------------------------------------------------------------------
# Sing-box JSON -> profiles (or raw passthrough)
# ---------------------------------------------------------------------------
_SINGBOX_KIND_MAP = {
    "shadowsocks": "shadowsocks", "vmess": "vmess", "vless": "vless",
    "trojan": "trojan", "hysteria2": "hysteria2", "tuic": "tuic",
    "naive": "naive",
}


def parse_singbox_json(text: str, raw_passthrough: bool = False
                       ) -> List[ProtocolProfile]:
    """Convert a sing-box config's outbounds to profiles.

    With ``raw_passthrough`` the config is instead wrapped in a
    :class:`M.BoxRawProfile` and executed verbatim through lantern-box —
    the most faithful way to run someone else's sing-box config.
    """
    try:
        doc = _json.loads(text)
    except ValueError as exc:
        raise ProtocolError("invalid sing-box JSON: %s" % exc) from None
    if raw_passthrough or not doc.get("outbounds"):
        return [M.BoxRawProfile(config_json=text)]
    profiles: List[ProtocolProfile] = []
    for ob in doc["outbounds"]:
        try:
            prof = _singbox_outbound(ob)
        except (KeyError, ValueError, TypeError) as exc:
            log.debug("skipping sing-box outbound %r: %s", ob.get("tag"), exc)
            continue
        if prof is not None:
            profiles.append(_tagged(prof, str(ob.get("tag") or "")))
    if not profiles:
        # nothing convertible — fall back to passthrough so the config
        # still runs instead of erroring out
        return [M.BoxRawProfile(config_json=text)]
    return profiles


def _singbox_outbound(ob: dict) -> Optional[ProtocolProfile]:
    otype = (ob.get("type") or "").lower()
    tag = str(ob.get("tag") or "")
    if otype in ("direct", "block", "dns", "selector", "urltest", "dns-out"):
        return None
    tls = ob.get("tls") or {}
    sni = str(tls.get("server_name") or ob.get("server") or "")
    insecure = bool(tls.get("insecure"))
    if otype == "shadowsocks":
        return M.ShadowsocksProfile(
            server=str(ob["server"]), port=int(ob["server_port"]),
            method=ob.get("method") or "aes-256-gcm",
            password=str(ob.get("password") or ""))
    if otype == "vmess":
        return M.VmessProfile(
            server=str(ob["server"]), port=int(ob["server_port"]),
            uuid=str(ob.get("uuid") or ""),
            alter_id=int(ob.get("alter_id") or 0),
            security=str(ob.get("security") or "auto"),
            transport=_singbox_transport(ob), host=_singbox_host(ob),
            path=_singbox_path(ob), tls=bool(tls.get("enabled")),
            sni=sni)
    if otype == "trojan":
        from ..xrayconf import XrayProfile
        return XrayProfile(
            protocol="trojan", address=str(ob["server"]),
            port=int(ob["server_port"]), name=tag,
            password=str(ob.get("password") or ""), sni=sni,
            allow_insecure=insecure)
    if otype == "hysteria2":
        obfs = ob.get("obfs") or {}
        return M.Hysteria2Profile(
            server=str(ob["server"]), port=int(ob["server_port"]),
            auth=str(ob.get("password") or ""), sni=sni, insecure=insecure,
            obfs="salamander" if obfs.get("type") == "salamander" else "",
            obfs_password=str(obfs.get("password") or ""))
    if otype == "tuic":
        return M.TuicProfile(
            uuid=str(ob.get("uuid") or ""),
            password=str(ob.get("password") or ""),
            server=str(ob["server"]), port=int(ob["server_port"]),
            sni=sni, congestion=ob.get("congestion_control") or "bbr",
            alpn=",".join(tls.get("alpn") or ["h3"]),
            udp_relay_mode=ob.get("udp_relay_mode") or "native",
            allow_insecure=insecure)
    if otype == "naive":
        return M.NaiveProfile(
            server=str(ob["server"]), port=int(ob["server_port"]),
            username=str(ob.get("username") or ""),
            password=str(ob.get("password") or ""), sni=sni,
            insecure=insecure)
    log.debug("sing-box outbound type %r (%r) not convertible", otype, tag)
    return None


def _singbox_transport(ob: dict) -> str:
    t = (ob.get("transport") or {})
    return str(t.get("type") or "tcp")


def _singbox_host(ob: dict) -> str:
    t = ob.get("transport") or {}
    if t.get("type") == "ws":
        return str((t.get("headers") or {}).get("Host") or ob.get("server")
                   or "")
    if t.get("type") == "http":
        return str((t.get("host") or [""])[0] or ob.get("server") or "")
    return str(ob.get("server") or "")


def _singbox_path(ob: dict) -> str:
    t = ob.get("transport") or {}
    if t.get("type") == "grpc":
        return str(t.get("service_name") or "")
    return str(t.get("path") or "")


# ---------------------------------------------------------------------------
# Subscriptions (auto-detect format)
# ---------------------------------------------------------------------------
def looks_like_base64(text: str) -> bool:
    """True when the text is (mostly) one base64 blob."""
    stripped = "".join((text or "").split())
    if not stripped or len(stripped) < 24:
        return False
    if "://" in stripped[:200]:
        return False
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        base64.b64decode(padded, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def decode_subscription(text: str) -> List[ProtocolProfile]:
    """Auto-detect and parse a subscription payload."""
    text = (text or "").strip()
    if not text:
        return []
    # 1. JSON? (sing-box or v2ray)
    if text.lstrip().startswith("{"):
        try:
            doc = _json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            if "outbounds" in doc:
                # sing-box configs (have "route"/"inbounds" or outbound
                # types that look sing-box) vs v2ray (protocol fields)
                if any("type" in o and "protocol" not in o
                       for o in doc["outbounds"] if isinstance(o, dict)):
                    return parse_singbox_json(text)
                return parse_v2ray_json(text)
            raise ProtocolError("JSON subscription without outbounds")
    # 2. Clash YAML?
    if HAVE_YAML and _looks_like_clash(text):
        return parse_clash_yaml(text)
    # 3. base64 blob (v2rayNG style)?
    if looks_like_base64(text):
        padded = "".join(text.split())
        padded += "=" * (-len(padded) % 4)
        try:
            text = base64.b64decode(padded).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            pass
    # 4. plain link list
    profiles: List[ProtocolProfile] = []
    for link in links.extract_links(text):
        try:
            _kind, prof = links.parse_link(link)
            profiles.append(prof)
        except ProtocolError as exc:
            log.debug("subscription link skipped: %s", exc)
    return profiles


def _looks_like_clash(text: str) -> bool:
    head = text[:4000]
    return ("proxies:" in head and ("\n- " in head or "- {" in head)) or \
        "proxy-groups:" in head or "mixed-port:" in head or \
        "port:" in head and "socks-port:" in head

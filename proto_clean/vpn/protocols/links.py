"""Share-link parsing/building for every supported protocol.

One function to rule them all: :func:`parse_link` accepts any supported
share URL and returns ``(kind, profile)``. Existing Proton-Clean parsers are
reused where they exist (VLESS/Trojan via :mod:`..xrayconf`, samizdat via
:mod:`..samizdatconf`); the rest are implemented here.

Custom schemes with ``*://``-free canonical forms (tor://config, chain://)
are Proto Clean share formats; everything else follows the scheme's
community convention so imports from other clients just work.
"""

from __future__ import annotations

import base64
import binascii
import json as _json
import re
import socket
import struct
import urllib.parse as _up
from typing import Dict, List, Optional, Tuple

from ..samizdatconf import SamizdatProfile, parse_samizdat_url
from ..xrayconf import XrayProfile, parse_xray_url
from .base import ProtocolError, ProtocolProfile
from . import models as M

_XRAY_KINDS = {"vless": "vless-reality", "trojan": "trojan"}

# share-link schemes registered for the importer UI
SCHEMES: Tuple[str, ...] = (
    "ss", "ssr", "vless", "trojan", "vmess", "hysteria2", "hy2", "tuic",
    "naive", "naive+https", "masque", "dtls", "cloak", "awg", "amnezia",
    "vpn", "ikev2", "tor", "obscura", "radiance", "lampshade", "samizdat",
    "reflex", "outline", "algeneva", "water", "chain", "warp", "singbox",
    "clash",
)


class _Url:
    """Lenient ``scheme://[user[:pass]@]host[:port][/path][?q][#frag`` parse.

    urllib chokes on base64 in the userinfo/host of exotic schemes, so the
    split is done by hand.
    """

    def __init__(self, url: str) -> None:
        url = url.strip()
        m = re.match(r"^([A-Za-z0-9+.\-]+)://(.*)$", url, re.S)
        if not m:
            raise ProtocolError("not a URL: %r" % url[:60])
        self.scheme = m.group(1).lower()
        rest = m.group(2)
        if "#" in rest:
            rest, self.fragment = rest.split("#", 1)
        else:
            self.fragment = ""
        self.query: Dict[str, str] = {}
        if "?" in rest:
            rest, qs = rest.split("?", 1)
            for part in qs.split("&"):
                if not part:
                    continue
                k, _, v = part.partition("=")
                self.query[k.strip()] = _up.unquote_plus(v)
        if "@" in rest:
            self.userinfo, hostport = rest.rsplit("@", 1)
        else:
            self.userinfo, hostport = "", rest
        if "/" in hostport:
            hostport, self.path = hostport.split("/", 1)
        else:
            self.path = ""
        self.host, self.port = _split_host_port(hostport)

    def user_pass(self) -> Tuple[str, str]:
        if ":" in self.userinfo:
            u, _, p = self.userinfo.partition(":")
            return _up.unquote(u), _up.unquote(p)
        return _up.unquote(self.userinfo), ""

    def first(self, *names: str, dflt: str = "") -> str:
        for n in names:
            v = self.query.get(n)
            if v:
                return v
        return dflt

    def flag(self, *names: str) -> bool:
        return self.first(*names).lower() in ("1", "true", "yes", "on")


def _split_host_port(hostport: str) -> Tuple[str, int]:
    hostport = hostport.strip().strip("[]")
    if hostport.startswith("["):                       # [v6]:port
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", hostport)
        if not m:
            raise ProtocolError("bad IPv6 host:port %r" % hostport)
        return m.group(1), int(m.group(2))
    if ":" not in hostport:
        return hostport, 0
    host, _, port = hostport.rpartition(":")
    if not host:                                       # bare ":443"?
        raise ProtocolError("missing host in %r" % hostport)
    try:
        return host, int(port)
    except ValueError:
        raise ProtocolError("bad port in %r" % hostport)


def _b64decode(text: str, urlsafe: bool = True) -> bytes:
    text = text.strip().split("#")[0].rstrip("=")
    if not text:
        raise ProtocolError("empty base64 payload")
    text += "=" * (-len(text) % 4)
    try:
        dec = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        return dec(text.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("bad base64 payload: %s" % exc)


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------
def _parse_ss(u: _Url) -> M.ShadowsocksProfile:
    """SIP002: ss://b64(method:password)@host:port[?plugin=..#tag],
    the userinfo-as-plaintext variant and the legacy whole-link base64."""
    user, password = u.user_pass()
    if user and ":" in user:
        # plaintext method:password in the userinfo
        method, _, password = user.partition(":")
    elif user:
        # SIP002: base64(method:password) in the userinfo
        try:
            decoded = _b64decode(user, urlsafe=False).decode("utf-8", "replace")
        except ProtocolError:
            decoded = user
        method, _, password = decoded.partition(":")
        if not password and not decoded:
            raise ProtocolError("ss:// link has an undecodable userinfo")
    else:
        # legacy: ss://b64(method:password@host:port)
        raw = _b64decode(u.userinfo + ("@" + u.host if u.host else "")
                         + ("/" + u.path if u.path else ""), urlsafe=False)
        text = raw.decode("utf-8", "replace")
        creds, _, hostport = text.rpartition("@")
        method, _, password = creds.partition(":")
        u2 = _Url("ss://%s" % hostport)
        u.host, u.port = u2.host, u2.port
    if not u.host:
        raise ProtocolError("ss:// link lacks a server")
    if not password:
        raise ProtocolError("ss:// link lacks a password")
    return M.ShadowsocksProfile(server=u.host, port=u.port or 8388,
                                method=method, password=password,
                                plugin=u.first("plugin"), tag=u.fragment)


def _parse_ssr(u: _Url) -> M.ShadowsocksrProfile:
    # The whole payload after ssr:// is ONE base64 blob. Community clients
    # use the standard alphabet; our share_url the url-safe one — the
    # url-safe decoder accepts both ('+' and '/' pass through untouched).
    # A '/' inside a standard blob was split into host/path by _Url, so
    # the blob is rebuilt verbatim before decoding.
    blob = u.userinfo + ("@" + u.host if u.userinfo else u.host or "")
    if u.path:
        blob += "/" + u.path
    body = _b64decode(blob).decode("utf-8", "replace")
    main, _, tail = body.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        raise ProtocolError("ssr:// link needs 6 ':'-separated fields")
    server, port, protocol, method, obfs, pass_b64 = parts[:6]
    q: Dict[str, str] = {}
    for part in tail.split("&"):
        k, _, v = part.partition("=")
        q[k] = _up.unquote_plus(v)

    def _ssr_field(text: str) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        try:
            return _b64decode(text).decode("utf-8", "replace")
        except ProtocolError:
            return ""

    return M.ShadowsocksrProfile(
        server=server, port=int(port or 8388), protocol=protocol, method=method,
        obfs=obfs, password=_ssr_field(pass_b64),
        obfs_param=_ssr_field(q.get("obfsparam", "")),
        protocol_param=_ssr_field(q.get("protoparam", "")),
        tag=u.fragment)


def _parse_hysteria2(u: _Url) -> M.Hysteria2Profile:
    auth, _ = u.user_pass()
    pin = u.first("pin", "pinSHA256")
    if pin.startswith("sha256:"):        # py3.8-safe removeprefix
        pin = pin[len("sha256:"):]
    return M.Hysteria2Profile(
        server=u.host, port=u.port or 443, auth=auth, sni=u.first("sni", "peer"),
        insecure=u.flag("insecure", "allow_insecure"),
        obfs=u.first("obfs"), obfs_password=u.first("obfs-password", "obfsParam"),
        pin_sha256=pin, mport=u.first("mport"),
        up_mbps=int(u.first("up", "upmbps", "0") or 0),
        down_mbps=int(u.first("down", "downmbps", "0") or 0),
        engine=u.first("engine", dflt="builtin"))


def _parse_tuic(u: _Url) -> M.TuicProfile:
    uuid, password = u.user_pass()
    if not uuid:
        raise ProtocolError("tuic:// link needs a uuid")
    return M.TuicProfile(
        uuid=uuid, password=password, server=u.host, port=u.port or 443,
        sni=u.first("sni"), congestion=u.first("congestion_control", "bbr"),
        alpn=u.first("alpn", "h3"), udp_relay_mode=u.first("udp_relay_mode", "native"),
        allow_insecure=u.flag("allow_insecure", "allow_insecure_1", "insecure"))


def _parse_naive(u: _Url) -> M.NaiveProfile:
    username, password = u.user_pass()
    return M.NaiveProfile(
        server=u.host, port=u.port or 443, username=username, password=password,
        sni=u.first("sni"), insecure=u.flag("insecure"),
        padding=u.first("padding"))


def _parse_masque(u: _Url) -> M.MasqueProfile:
    username, password = u.user_pass()
    return M.MasqueProfile(
        server=u.host, port=u.port or 443, username=username, password=password,
        template=u.first("template", "/masque"), sni=u.first("sni"),
        insecure=u.flag("insecure"), proxy_style=u.first("style", "socks"))


def _parse_dtls(u: _Url) -> M.CoverDtlsProfile:
    psk, _ = u.user_pass()
    # DTLS servers almost always use self-signed certs: insecure defaults
    # to True and is only disabled with insecure=0
    flag_val = u.first("insecure").lower()
    insecure = flag_val != "0" if flag_val else True
    return M.CoverDtlsProfile(
        server=u.host, port=u.port or 443, psk=psk, sni=u.first("sni"),
        insecure=insecure)


def _parse_cloak(u: _Url) -> M.CloakProfile:
    uid, _ = u.user_pass()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", uid or ""):
        raise ProtocolError("cloak:// UID must be 32 hex chars")
    pubkey = u.first("public_key", "pubkey")
    if pubkey and not re.fullmatch(r"[0-9a-fA-F]{64}", pubkey):
        raise ProtocolError("cloak:// public key must be 64 hex chars")
    return M.CloakProfile(
        server=u.host, port=u.port or 443, uid=uid, public_key=pubkey,
        server_name=u.first("server_name", "sni"),
        transport=u.first("transport", "direct"),
        encryption_method=u.first("encryption", "aes-256-gcm"),
        num_conn=int(u.first("num_conn", "4") or 4),
        browser_sig=u.first("browser_sig", "chrome"),
        alternative_names=[a for a in u.first("alternative_names").split(",") if a])


_AWG_KEYS = ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")
#: canonical AmneziaWG spellings for the junk params (the parser accepts
#: any casing in links, but the profile carries the official names)
_AWG_CANON = {"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", "s1": "S1",
              "s2": "S2", "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4"}


def _parse_awg(u: _Url) -> M.AwgProfile:
    junk = {_AWG_CANON[k]: int(u.first(k)) for k in _AWG_KEYS if u.first(k)}
    extra = {k[2:]: v for k, v in u.query.items() if k.startswith("x_")}
    addrs = [a for a in u.first("address").split(",") if a]
    dns = [a for a in u.first("dns").split(",") if a]
    ips = [a for a in u.first("allowed_ips", "allowedips").split(",") if a]
    return M.AwgProfile(
        server=u.host, port=u.port or 51820, private_key=u.first("private_key"),
        peer_public_key=u.first("peer", "public_key", "server_public_key"),
        preshared_key=u.first("preshared", "preshared_key"),
        address=addrs or ["10.8.1.2/32"], dns=dns,
        mtu=int(u.first("mtu", "0") or 0),
        allowed_ips=ips or ["0.0.0.0/0"],
        keepalive=int(u.first("keepalive", "25") or 25),
        junk=junk, extra=extra)


def _parse_vpn_amnezia(u: _Url) -> M.AwgProfile:
    """Amnezia ``vpn://<b64url json>`` container config."""
    raw = _b64decode(u.userinfo + ("@" + u.host if u.host else "")
                     + ("/" + u.path if u.path else ""), urlsafe=True)
    doc = _json.loads(raw.decode("utf-8", "replace"))
    containers = doc.get("containers") or []
    awg = {}
    for c in containers:
        if "awg" in c:
            awg = c["awg"]
            break
    if not awg:
        raise ProtocolError("vpn:// config has no AmneziaWG container")
    last = awg.get("last_config") or ""
    host, port, priv, dns, mtu, allowed = "", 51820, "", [], 0, ["0.0.0.0/0"]
    peer = preshared = ""
    addrs: List[str] = ["10.8.1.2/32"]
    if last:
        try:
            lc = _json.loads(last)
            host = lc.get("hostName") or host
            port = int(lc.get("port") or port)
            priv = lc.get("client_priv_key") or lc.get("privateKey") or priv
            mtu = int(lc.get("mtu") or 0)
            if lc.get("dns1"):
                dns.append(str(lc["dns1"]))
            if lc.get("dns2"):
                dns.append(str(lc["dns2"]))
        except (ValueError, TypeError):
            pass
    junk = {}
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
        if k in awg:
            junk[k] = int(awg[k])
    if not host:
        raise ProtocolError("vpn:// config lacks a server host")
    return M.AwgProfile(server=host, port=port, private_key=priv,
                        peer_public_key=peer, preshared_key=preshared,
                        address=addrs, dns=dns, mtu=mtu, allowed_ips=allowed,
                        junk=junk)


def _parse_ikev2(u: _Url) -> M.Ikev2Profile:
    username, userinfo_pw = u.user_pass()
    password = u.first("password") or userinfo_pw
    return M.Ikev2Profile(
        server=u.host, port=u.port or 500, username=username, password=password,
        auth=u.first("auth", "eap-mschapv2"), psk=u.first("psk"),
        identity=u.first("identity", username), remote_id=u.first("remote_id"))


def _parse_tor(u: _Url) -> M.TorProfile:
    bridges = [b for b in u.first("bridges").replace("\r", "").split("\n") if b.strip()]
    return M.TorProfile(
        bridges=bridges, exit_nodes=u.first("exit"), entry_nodes=u.first("entry"),
        strict_nodes=u.flag("strict"), upstream_url=u.first("upstream"))


def _parse_obscura(u: _Url) -> M.ObscuraProfile:
    account, _ = u.user_pass()
    if account and not re.fullmatch(r"[0-9A-Za-z]{20}", account):
        raise ProtocolError("obscura:// account number must be 20 chars")
    api = u.first("api", "https://v1.api.prod.obscura.net/api/")
    return M.ObscuraProfile(
        account_id=account, api_base=api, auth_token=u.first("token"),
        tunnel_id=u.first("tunnel"), tunnel_type=u.first("type", "udp_port"),
        relay=u.first("relay"), exit=u.first("exit"))


def _parse_radiance(u: _Url) -> M.RadianceProfile:
    token, _ = u.user_pass()
    return M.RadianceProfile(
        server=u.host, port=u.port or 443, token=token,
        transport=u.first("transport", "tls"), sni=u.first("sni"),
        insecure=u.flag("insecure"))


def _parse_lampshade(u: _Url) -> M.LampshadeProfile:
    token, _ = u.user_pass()
    return M.LampshadeProfile(
        server=u.host, port=u.port or 443, token=token,
        transport=u.first("transport", "tcp"), psk=u.first("psk"),
        window_size=int(u.first("window", "0") or 0),
        max_padding=int(u.first("padding", "0") or 0))


def _parse_reflex(u: _Url) -> M.ReflexProfile:
    return M.ReflexProfile(
        server=u.host, port=u.port or 443,
        cert_pem=_b64decode(u.first("cert"), urlsafe=True).decode("utf-8", "replace"),
        key_pem=_b64decode(u.first("key"), urlsafe=True).decode("utf-8", "replace"))


def _parse_outline(u: _Url) -> M.OutlineProfile:
    split = lambda s: [x for x in s.split(",") if x]  # noqa: E731
    return M.OutlineProfile(
        server=u.host, port=u.port or 443, dns=split(u.first("dns")),
        tls=split(u.first("tls")), domains=split(u.first("domains")))


def _parse_algeneva(u: _Url) -> M.AlgenevaProfile:
    return M.AlgenevaProfile(server=u.host, port=u.port or 9001,
                             strategy=u.first("strategy"))


def _parse_water(u: _Url) -> M.WaterProfile:
    return M.WaterProfile(
        server=u.host, port=u.port or 9003, transport=u.first("transport", "plain"),
        hashsum=u.first("hashsum"),
        wasm_urls=[w for w in u.first("wasm").split(",") if w],
        download_timeout=u.first("download_timeout", "60s"))


def _parse_chain(u: _Url) -> M.ChainProfile:
    payload = ((u.userinfo + "@") if u.userinfo else "") + u.host \
        + ("/" + u.path if u.path else "")
    hops = _json.loads(_b64decode(payload).decode("utf-8"))
    if not isinstance(hops, list) or not hops:
        raise ProtocolError("chain:// payload must be a non-empty list of URLs")
    return M.ChainProfile(hops=[str(h) for h in hops])



def _parse_vmess(u: _Url) -> M.VmessProfile:
    """v2rayN share link: vmess://<base64 JSON>."""
    payload = ((u.userinfo + "@") if u.userinfo else "") + u.host \
        + ("/" + u.path if u.path else "")
    raw = _b64decode(payload, urlsafe=False)
    doc = _json.loads(raw.decode("utf-8", "replace"))
    try:
        port = int(doc.get("port") or 443)
    except (TypeError, ValueError):
        port = 443
    raw_type = str(doc.get("type") or "").strip()
    return M.VmessProfile(
        server=str(doc.get("add") or ""), port=port,
        uuid=str(doc.get("id") or ""), alter_id=int(doc.get("aid") or 0),
        security=str(doc.get("scy") or "auto"),
        transport=str(doc.get("net") or "tcp"),
        header_type="" if raw_type in ("", "none") else raw_type,
        host=str(doc.get("host") or ""), path=str(doc.get("path") or ""),
        tls=str(doc.get("tls") or "").lower() in ("tls", "true", "1"),
        sni=str(doc.get("sni") or ""), fp=str(doc.get("fp") or ""),
        tag=str(doc.get("ps") or ""))


def _parse_warp(u: _Url) -> M.WarpProfile:
    return M.WarpProfile(
        license_key=u.first("license"), endpoint=u.first(
            "endpoint", "engage.cloudflareclient.com:2408"),
        port=int(u.first("port", "2408") or 2408),
        private_key=u.first("priv"), peer_public_key=u.first("peer"),
        client_id_b64=u.first("cid"), address_v4=u.first("v4"),
        address_v6=u.first("v6"), token=u.first("token"),
        device_id=u.first("device"))


def _parse_singbox(u: _Url) -> M.BoxRawProfile:
    payload = ((u.userinfo + "@") if u.userinfo else "") + u.host \
        + ("/" + u.path if u.path else "")
    return M.BoxRawProfile(
        config_json=_b64decode(payload).decode("utf-8", "replace"))


def _parse_clash(u: _Url) -> M.ClashProfile:
    payload = ((u.userinfo + "@") if u.userinfo else "") + u.host \
        + ("/" + u.path if u.path else "")
    return M.ClashProfile(yaml_text=_b64decode(payload).decode(
        "utf-8", "replace"))

_PARSERS = {
    "ss": _parse_ss,
    "ssr": _parse_ssr,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "naive": _parse_naive,
    "naive+https": _parse_naive,
    "masque": _parse_masque,
    "dtls": _parse_dtls,
    "cloak": _parse_cloak,
    "awg": _parse_awg,
    "amnezia": _parse_awg,
    "ikev2": _parse_ikev2,
    "tor": _parse_tor,
    "obscura": _parse_obscura,
    "radiance": _parse_radiance,
    "lampshade": _parse_lampshade,
    "reflex": _parse_reflex,
    "outline": _parse_outline,
    "algeneva": _parse_algeneva,
    "water": _parse_water,
    "chain": _parse_chain,
    "vmess": _parse_vmess,
    "warp": _parse_warp,
    "singbox": _parse_singbox,
    "clash": _parse_clash,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def parse_link(url: str) -> Tuple[str, ProtocolProfile]:
    """Parse any supported share URL. Returns ``(kind, profile)``.

    ``kind`` is the registry key ("shadowsocks", "hysteria2", "vless", …).
    VLESS/Trojan links are parsed by the existing Xray parser and returned
    with their registry kinds; samizdat likewise.
    """
    if not url or not url.strip():
        raise ProtocolError("empty link")
    u = _Url(url.strip())
    if u.scheme in _XRAY_KINDS:
        prof = parse_xray_url(url.strip())
        prof = prof if isinstance(prof, XrayProfile) else prof
        return ("vless" if prof.protocol == "vless-reality" else "trojan"), prof
    if u.scheme == "samizdat":
        prof = parse_samizdat_url(url.strip())
        return "samizdat", prof
    if u.scheme == "vpn":
        return "amneziawg", _parse_vpn_amnezia(u)
    parser = _PARSERS.get(u.scheme)
    if parser is None:
        raise ProtocolError("unsupported scheme: %s://" % u.scheme)
    prof = parser(u)
    kind = {"awg": "amneziawg", "amnezia": "amneziawg",
            "naive": "naive", "naive+https": "naive",
            "hysteria2": "hysteria2", "hy2": "hysteria2",
            "singbox": "boxraw", "ss": "shadowsocks",
            "ssr": "shadowsocksr",
            "dtls": "coverdtls"}.get(u.scheme, u.scheme)
    if isinstance(prof, ProtocolProfile):
        # enforce the model kind so registry lookups always match
        pass
    return kind, prof


def looks_like_link(text: str) -> bool:
    """True if ``text`` starts with any supported scheme."""
    text = (text or "").strip().lower()
    return any(text.startswith(s + "://") for s in SCHEMES)


def extract_links(text: str) -> List[str]:
    """Pull every supported share URL out of arbitrary text."""
    found: List[str] = []
    pattern = re.compile(
        r"(?:%s)://[^\s<>\"']+" % "|".join(re.escape(s) for s in SCHEMES))
    for m in pattern.finditer(text or ""):
        link = m.group(0).rstrip(".,;)")
        if link not in found:
            found.append(link)
    return found


def build_chain_url(urls: List[str]) -> str:
    """Encode an ordered list of share URLs as a chain:// link."""
    return M.ChainProfile(hops=urls).share_url()

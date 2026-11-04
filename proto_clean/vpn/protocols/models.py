"""Profile models for every supported protocol.

All classes are plain dataclasses so they serialise to/from JSON without
custom glue (see :meth:`ProtocolProfile.from_json`). Each class carries its
``kind`` (registry key), ``title`` (human name), a ``summary()`` for UI
lists and a ``share_url()`` that produces the canonical importable link for
that protocol — the same formats the QR/config-file importers accept.
"""

from __future__ import annotations

import base64
import json as _json
import urllib.parse as _up
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .base import ProtocolProfile


def _b64(data: bytes, urlsafe: bool = True) -> str:
    raw = base64.urlsafe_b64encode(data) if urlsafe else base64.b64encode(data)
    return raw.decode("ascii").rstrip("=")


def _unb64(text: str, urlsafe: bool = True) -> bytes:
    text = text.strip().rstrip("=")
    text += "=" * (-len(text) % 4)
    raw = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    return raw(text.encode("ascii"))


def _qs(params: Dict[str, object]) -> str:
    clean = {k: v for k, v in params.items() if v not in ("", None, [], {})}
    return _up.urlencode({k: str(v) for k, v in clean.items()})


# --------------------------------------------------------------------------
# Shadowsocks (SIP002) — engine: lantern-box or built-in AEAD client
# --------------------------------------------------------------------------
@dataclass
class ShadowsocksProfile(ProtocolProfile):
    kind = "shadowsocks"
    title = "Shadowsocks"
    server: str = ""
    port: int = 8388
    method: str = "aes-256-gcm"
    password: str = ""
    plugin: str = ""          # SIP002 plugin string, e.g. "obfs-local;obfs=http"
    tag: str = ""

    def share_url(self) -> str:
        userinfo = _b64(("%s:%s" % (self.method, self.password)).encode())
        q = ("?plugin=" + _up.quote(self.plugin, safe="")) if self.plugin else ""
        frag = "#" + _up.quote(self.tag) if self.tag else ""
        return "ss://%s@%s:%d%s%s" % (userinfo, self.server, self.port, q, frag)

    def summary(self) -> str:
        return "%s:%d (%s)%s" % (self.server, self.port, self.method,
                                 " +" + self.plugin.split(";")[0] if self.plugin else "")


@dataclass
class ShadowsocksrProfile(ProtocolProfile):
    """Legacy SSR links are parsed for import; engines require lantern-box."""
    kind = "shadowsocksr"
    title = "ShadowsocksR"
    server: str = ""
    port: int = 8388
    protocol: str = "origin"
    method: str = "aes-256-cfb"
    obfs: str = "plain"
    password: str = ""
    protocol_param: str = ""
    obfs_param: str = ""
    tag: str = ""

    def share_url(self) -> str:
        body = "%s:%d:%s:%s:%s:%s/?obfsparam=%s&protoparam=%s" % (
            self.server, self.port, self.protocol, self.method, self.obfs,
            _b64(self.password.encode(), False),
            _b64(self.obfs_param.encode(), False),
            _b64(self.protocol_param.encode(), False))
        return "ssr://" + _b64(body.encode()) + \
            (("#" + _up.quote(self.tag)) if self.tag else "")

    def summary(self) -> str:
        return "%s:%d (%s/%s)" % (self.server, self.port, self.protocol, self.obfs)


# --------------------------------------------------------------------------
# Hysteria 2 — engines: built-in (aioquic) / lantern-box hysteria2|hy2x
# --------------------------------------------------------------------------
@dataclass
class Hysteria2Profile(ProtocolProfile):
    kind = "hysteria2"
    title = "Hysteria 2"
    server: str = ""
    port: int = 443
    auth: str = ""
    sni: str = ""
    insecure: bool = False
    obfs: str = ""                 # "" | "salamander"
    obfs_password: str = ""
    pin_sha256: str = ""           # base64 server cert pin (no "sha256:" prefix)
    mport: str = ""                # port hopping range, e.g. "20000-30000"
    up_mbps: int = 0
    down_mbps: int = 0
    engine: str = "builtin"        # builtin | box | hysteria2x (GFW QUIC junk)

    def share_url(self) -> str:
        q = _qs({"sni": self.sni, "insecure": 1 if self.insecure else "",
                 "obfs": self.obfs, "obfs-password": self.obfs_password,
                 "pin": ("sha256:" + self.pin_sha256) if self.pin_sha256 else "",
                 "mport": self.mport})
        frag = "#" + _up.quote(getattr(self, "tag", "") or "hysteria2")
        return "hysteria2://%s@%s:%d/?%s%s" % (
            _up.quote(self.auth, safe=""), self.server, self.port, q, frag)

    def summary(self) -> str:
        extra = " salamander" if self.obfs else ""
        return "%s:%d%s" % (self.server, self.port, extra)


# --------------------------------------------------------------------------
# TUIC v5 — engines: lantern-box "tuic" or built-in (TLS exporter permitting)
# --------------------------------------------------------------------------
@dataclass
class TuicProfile(ProtocolProfile):
    kind = "tuic"
    title = "TUIC v5"
    uuid: str = ""
    password: str = ""
    token_hex: str = ""             # 64 hex chars; v5 TLS-exporter token
                                    # (required by the built-in engine)
    server: str = ""
    port: int = 443
    sni: str = ""
    congestion: str = "bbr"        # bbr | cubic | new_reno
    alpn: str = "h3"
    udp_relay_mode: str = "native"  # native | quic
    allow_insecure: bool = False

    def share_url(self) -> str:
        q = _qs({"sni": self.sni, "congestion_control": self.congestion,
                 "alpn": self.alpn, "udp_relay_mode": self.udp_relay_mode,
                 "allow_insecure": 1 if self.allow_insecure else ""})
        return "tuic://%s:%s@%s:%d/?%s" % (
            self.uuid, _up.quote(self.password, safe=""),
            self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (%s)" % (self.server, self.port, self.congestion)


# --------------------------------------------------------------------------
# MASQUE over QUIC (RFC 9298 CONNECT-UDP) — built-in aioquic engine
# --------------------------------------------------------------------------
@dataclass
class MasqueProfile(ProtocolProfile):
    kind = "masque"
    title = "MASQUE (QUIC)"
    server: str = ""
    port: int = 443
    username: str = ""
    password: str = ""
    template: str = "/masque"      # CONNECT-UDP URI template
    sni: str = ""
    insecure: bool = False
    proxy_style: str = "socks"     # local front-end: socks | http

    def share_url(self) -> str:
        q = _qs({"template": self.template, "sni": self.sni,
                 "insecure": 1 if self.insecure else "",
                 "style": self.proxy_style})
        userinfo = "%s:%s@" % (_up.quote(self.username, safe=""),
                               _up.quote(self.password, safe="")) \
            if (self.username or self.password) else ""
        return "masque://%s%s:%d/?%s" % (userinfo, self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d %s" % (self.server, self.port, self.template)


# --------------------------------------------------------------------------
# QUIC obfuscation (HTTP/3 masquerade + whitening) — built-in transport layer
# Applied on top of another QUIC protocol profile via `obfuscation` field.
# --------------------------------------------------------------------------
@dataclass
class QuicObfsSettings:
    mode: str = "none"             # none | http3 | whitening
    key: str = ""                  # PSK for whitening mode


# --------------------------------------------------------------------------
# NaïveProxy — engine: official "naive" binary
# --------------------------------------------------------------------------
@dataclass
class NaiveProfile(ProtocolProfile):
    kind = "naive"
    title = "NaïveProxy"
    server: str = ""
    port: int = 443
    username: str = ""
    password: str = ""
    sni: str = ""
    insecure: bool = False
    padding: str = ""              # e.g. "head=xon,chunk=1000"

    def share_url(self) -> str:
        q = _qs({"sni": self.sni, "insecure": 1 if self.insecure else "",
                 "padding": self.padding})
        return "naive+https://%s:%s@%s:%d/?%s" % (
            _up.quote(self.username, safe=""), _up.quote(self.password, safe=""),
            self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (H2 CONNECT)" % (self.server, self.port)


# --------------------------------------------------------------------------
# Cover-DTLS / Pion-DTLS-style covert transport — built-in pyOpenSSL engine
# --------------------------------------------------------------------------
@dataclass
class CoverDtlsProfile(ProtocolProfile):
    kind = "coverdtls"
    title = "Cover-DTLS"
    server: str = ""
    port: int = 443
    psk: str = ""                  # optional whitening PSK for the outer cover
    sni: str = ""
    insecure: bool = True          # DTLS self-signed server certs are the norm

    def share_url(self) -> str:
        q = _qs({"sni": self.sni, "insecure": "" if self.insecure else "0"})
        userinfo = _up.quote(self.psk, safe="") + "@" if self.psk else ""
        return "dtls://%s%s:%d/?%s" % (userinfo, self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (DTLS 1.2 cover)" % (self.server, self.port)


# --------------------------------------------------------------------------
# Cloak (cbeuw/Cloak) + OpenVPN over Cloak composite
# --------------------------------------------------------------------------
@dataclass
class CloakProfile(ProtocolProfile):
    kind = "cloak"
    title = "OpenVPN over Cloak"
    server: str = ""
    port: int = 443
    uid: str = ""                  # 32 hex chars
    public_key: str = ""           # 64 hex chars
    server_name: str = ""          # SNI used for masking
    transport: str = "direct"      # direct | CDN
    encryption_method: str = "aes-256-gcm"
    num_conn: int = 4
    browser_sig: str = "chrome"
    alternative_names: List[str] = field(default_factory=list)
    openvpn_config: str = ""       # raw .ovpn body for the inner tunnel

    def share_url(self) -> str:
        q = _qs({"public_key": self.public_key, "server_name": self.server_name,
                 "transport": self.transport,
                 "encryption": self.encryption_method,
                 "num_conn": self.num_conn, "browser_sig": self.browser_sig,
                 "alternative_names": ",".join(self.alternative_names)})
        return "cloak://%s@%s:%d/?%s" % (self.uid, self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (TLS-masked OpenVPN)" % (self.server, self.port)


# --------------------------------------------------------------------------
# AmneziaWG 1.5 / 2.0 — engines: lantern-box amneziawg endpoint, awg-quick
# --------------------------------------------------------------------------
@dataclass
class AwgProfile(ProtocolProfile):
    kind = "amneziawg"
    title = "AmneziaWG"
    server: str = ""
    port: int = 51820
    private_key: str = ""
    peer_public_key: str = ""
    preshared_key: str = ""
    address: List[str] = field(default_factory=lambda: ["10.8.1.2/32"])
    dns: List[str] = field(default_factory=list)
    mtu: int = 0
    allowed_ips: List[str] = field(default_factory=lambda: ["0.0.0.0/0"])
    keepalive: int = 25
    junk: Dict[str, int] = field(default_factory=dict)   # Jc Jmin Jmax S1 S2 H1-H4
    extra: Dict[str, str] = field(default_factory=dict)  # AWG 2.0 passthrough

    def share_url(self) -> str:
        q = _qs({"private_key": self.private_key,
                 "peer": self.peer_public_key, "preshared": self.preshared_key,
                 "address": ",".join(self.address), "dns": ",".join(self.dns),
                 "mtu": self.mtu, "allowed_ips": ",".join(self.allowed_ips),
                 "keepalive": self.keepalive,
                 **{k.lower(): v for k, v in self.junk.items()},
                 **{"x_" + k: v for k, v in self.extra.items()}})
        return "awg://%s:%d/?%s" % (self.server, self.port, q)

    def summary(self) -> str:
        jc = self.junk.get("Jc") or self.junk.get("jc") or 0
        return "%s:%d (junk x%s)" % (self.server, self.port, jc)


# --------------------------------------------------------------------------
# IKEv2 — per-OS system adapters (strongSwan / rasdial / Apple IKEv2)
# --------------------------------------------------------------------------
@dataclass
class Ikev2Profile(ProtocolProfile):
    kind = "ikev2"
    title = "IKEv2"
    server: str = ""
    port: int = 500
    auth: str = "eap-mschapv2"     # eap-mschapv2 | psk | cert
    username: str = ""
    password: str = ""
    psk: str = ""
    identity: str = ""             # local identity / EAP id
    remote_id: str = ""            # server identity (must match cert)

    def share_url(self) -> str:
        q = _qs({"auth": self.auth, "password": self.password, "psk": self.psk,
                 "identity": self.identity, "remote_id": self.remote_id})
        userinfo = _up.quote(self.username, safe="") + "@" if self.username else ""
        return "ikev2://%s%s:%d/?%s" % (userinfo, self.server, self.port, q)

    def summary(self) -> str:
        return "%s (%s)" % (self.server, self.auth)


# --------------------------------------------------------------------------
# Tor — engine: tor binary; bridges, exits, upstream chaining
# --------------------------------------------------------------------------
@dataclass
class TorProfile(ProtocolProfile):
    kind = "tor"
    title = "Tor"
    bridges: List[str] = field(default_factory=list)   # full bridge lines
    exit_nodes: str = ""           # e.g. "{de},{at}" country codes
    entry_nodes: str = ""
    strict_nodes: bool = False
    upstream_url: str = ""         # share URL of an engine Tor dials through

    def share_url(self) -> str:
        q = _qs({"bridges": "\n".join(self.bridges),
                 "exit": self.exit_nodes, "entry": self.entry_nodes,
                 "strict": 1 if self.strict_nodes else "",
                 "upstream": self.upstream_url})
        return "tor://config?" + q

    def summary(self) -> str:
        n = len(self.bridges)
        return "Tor%s" % (" + %d bridge%s" % (n, "s" if n != 1 else "") if n else
                          " (direct)")


# --------------------------------------------------------------------------
# Obscura relays — WireGuard tunnels with relay/exit multihop
# --------------------------------------------------------------------------
@dataclass
class ObscuraProfile(ProtocolProfile):
    kind = "obscura"
    title = "Obscura relays"
    account_id: str = ""           # 20-char account number
    api_base: str = "https://v1.api.prod.obscura.net/api/"
    auth_token: str = ""
    tunnel_id: str = ""
    tunnel_type: str = "udp_port"  # udp_port | obfuscated
    relay: str = ""                # relay id, e.g. "NYC-001"
    exit: str = ""                 # exit id — relay != exit gives multihop
    wg_conf: str = ""              # cached WireGuard config from the API

    def share_url(self) -> str:
        q = _qs({"token": self.auth_token, "tunnel": self.tunnel_id,
                 "type": self.tunnel_type, "relay": self.relay,
                 "exit": self.exit, "api": self.api_base})
        return "obscura://%s@%s" % (self.account_id, _qs({"x": 0})[2:] or "") + \
            ("?" + q if q else "")

    def summary(self) -> str:
        if self.relay and self.exit and self.relay != self.exit:
            return "%s -> %s (multihop)" % (self.relay, self.exit)
        return self.relay or "Obscura"


# --------------------------------------------------------------------------
# Lantern network: Radiance / Lampshade clients (lantern-box capability probe)
# --------------------------------------------------------------------------
@dataclass
class RadianceProfile(ProtocolProfile):
    kind = "radiance"
    title = "Lantern Radiance"
    server: str = ""
    port: int = 443
    token: str = ""
    transport: str = "tls"         # tls | quic
    sni: str = ""
    insecure: bool = False

    def share_url(self) -> str:
        q = _qs({"transport": self.transport, "sni": self.sni,
                 "insecure": 1 if self.insecure else ""})
        return "radiance://%s@%s:%d/?%s" % (
            _up.quote(self.token, safe=""), self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (%s)" % (self.server, self.port, self.transport)


@dataclass
class LampshadeProfile(ProtocolProfile):
    kind = "lampshade"
    title = "Lantern Lampshade"
    server: str = ""
    port: int = 443
    token: str = ""
    transport: str = "tcp"         # tcp | quic
    psk: str = ""
    window_size: int = 0
    max_padding: int = 0

    def share_url(self) -> str:
        q = _qs({"transport": self.transport, "psk": self.psk,
                 "window": self.window_size, "padding": self.max_padding})
        return "lampshade://%s@%s:%d/?%s" % (
            _up.quote(self.token, safe=""), self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (%s)" % (self.server, self.port, self.transport)


@dataclass
class SamizdatLinkProfile(ProtocolProfile):
    """Thin re-export so the registry can carry the existing samizdat engine."""
    kind = "samizdat"
    title = "Lantern Samizdat"
    url: str = ""                  # full samizdat:// share URL

    def share_url(self) -> str:
        return self.url

    def summary(self) -> str:
        return "samizdat (DPI-resistant HTTP/2)"


# --------------------------------------------------------------------------
# lantern-box extras: Reflex / Outline / ALGeneva / WATER
# --------------------------------------------------------------------------
@dataclass
class ReflexProfile(ProtocolProfile):
    kind = "reflex"
    title = "Reflex (reversed TLS)"
    server: str = ""
    port: int = 443
    cert_pem: str = ""
    key_pem: str = ""

    def share_url(self) -> str:
        q = _qs({"cert": _b64(self.cert_pem.encode()),
                 "key": _b64(self.key_pem.encode())})
        return "reflex://%s:%d/?%s" % (self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (server-first TLS)" % (self.server, self.port)


@dataclass
class OutlineProfile(ProtocolProfile):
    kind = "outline"
    title = "Outline smart dialer"
    server: str = ""
    port: int = 443
    dns: List[str] = field(default_factory=list)     # "system", "https:...", ...
    tls: List[str] = field(default_factory=list)     # "fragmentation", "reordering"
    domains: List[str] = field(default_factory=list)

    def share_url(self) -> str:
        q = _qs({"dns": ",".join(self.dns), "tls": ",".join(self.tls),
                 "domains": ",".join(self.domains)})
        return "outline://%s:%d/?%s" % (self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (DNS/SNI evasion)" % (self.server, self.port)


@dataclass
class AlgenevaProfile(ProtocolProfile):
    kind = "algeneva"
    title = "ALGeneva"
    server: str = ""
    port: int = 9001
    strategy: str = ""

    def share_url(self) -> str:
        q = _qs({"strategy": self.strategy})
        return "algeneva://%s:%d/?%s" % (self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (HTTP DPI evasion)" % (self.server, self.port)


@dataclass
class WaterProfile(ProtocolProfile):
    kind = "water"
    title = "WATER (WASM transport)"
    server: str = ""
    port: int = 9003
    transport: str = "plain"
    hashsum: str = ""
    wasm_urls: List[str] = field(default_factory=list)
    download_timeout: str = "60s"

    def share_url(self) -> str:
        q = _qs({"transport": self.transport, "hashsum": self.hashsum,
                 "wasm": ",".join(self.wasm_urls),
                 "download_timeout": self.download_timeout})
        return "water://%s:%d/?%s" % (self.server, self.port, q)

    def summary(self) -> str:
        return "%s:%d (%s WASM)" % (self.server, self.port, self.transport)


# --------------------------------------------------------------------------
# Chained engines (multiprotocol multihop)
# --------------------------------------------------------------------------
@dataclass
class ChainProfile(ProtocolProfile):
    """An ordered list of share URLs; traffic flows url[0] -> url[N-1]."""
    kind = "chain"
    title = "Protocol chain"
    hops: List[str] = field(default_factory=list)    # share URLs in order

    def share_url(self) -> str:
        return "chain://" + _b64(_json.dumps(self.hops).encode())

    def summary(self) -> str:
        return " chain -> ".join(_up.urlparse(h).scheme.upper() or "conf"
                                 for h in self.hops).upper()


# --------------------------------------------------------------------------
# VMess (V2ray / V2fly) — engine: lantern-box "vmess" outbound
# --------------------------------------------------------------------------
@dataclass
class VmessProfile(ProtocolProfile):
    kind = "vmess"
    title = "VMess"
    server: str = ""
    port: int = 443
    uuid: str = ""
    alter_id: int = 0
    security: str = "auto"          # auto | aes-128-gcm | chacha20-poly1305 | none
    transport: str = "tcp"          # tcp | ws | grpc | http (h2)
    header_type: str = ""           # tcp/http: none | http
    host: str = ""                  # ws host / h2 host / grpc authority
    path: str = ""                  # ws path / h2 path / grpc service
    tls: bool = False
    sni: str = ""
    fp: str = ""                    # uTLS fingerprint
    tag: str = ""

    def share_url(self) -> str:
        doc = {"v": "2", "ps": self.tag or "vmess", "add": self.server,
               "port": str(self.port), "id": self.uuid,
               "aid": str(self.alter_id), "scy": self.security,
               "net": self.transport, "type": self.header_type or "none",
               "host": self.host, "path": self.path,
               "tls": "tls" if self.tls else "",
               "sni": self.sni, "fp": self.fp}
        return "vmess://" + _b64(_json.dumps(doc, separators=(",", ":")).encode())

    def summary(self) -> str:
        extra = "+tls" if self.tls else ""
        return "%s:%d (%s%s)" % (self.server, self.port, self.transport, extra)


# --------------------------------------------------------------------------
# Cloudflare WARP — oblivion/warp-plus style registration + WireGuard
# --------------------------------------------------------------------------
@dataclass
class WarpProfile(ProtocolProfile):
    kind = "warp"
    title = "Cloudflare WARP"
    license_key: str = ""           # optional WARP+ license
    endpoint: str = "engage.cloudflareclient.com:2408"
    port: int = 2408
    # cached registration (so re-connects do not re-register)
    private_key: str = ""           # base64 X25519
    peer_public_key: str = ""       # base64
    client_id_b64: str = ""         # reserved bytes source
    address_v4: str = ""
    address_v6: str = ""
    token: str = ""
    device_id: str = ""

    def share_url(self) -> str:
        q = _qs({"license": self.license_key, "endpoint": self.endpoint,
                 "port": self.port, "priv": self.private_key,
                 "peer": self.peer_public_key, "cid": self.client_id_b64,
                 "v4": self.address_v4, "v6": self.address_v6,
                 "token": self.token, "device": self.device_id})
        return "warp://config?" + q

    def summary(self) -> str:
        cached = " (registered)" if self.peer_public_key else ""
        plus = " WARP+" if self.license_key else ""
        return "WARP%s%s" % (plus, cached)


# --------------------------------------------------------------------------
# Sing-box raw config passthrough — run any sing-box JSON as-is
# --------------------------------------------------------------------------
@dataclass
class BoxRawProfile(ProtocolProfile):
    kind = "boxraw"
    title = "Sing-box config"
    config_json: str = ""           # the full sing-box client config
    source: str = ""                # file name / URL it came from

    def share_url(self) -> str:
        return "singbox://" + _b64(self.config_json.encode())

    def summary(self) -> str:
        try:
            doc = _json.loads(self.config_json)
            kinds = [o.get("type", "?") for o in doc.get("outbounds", [])]
            return "sing-box: " + ", ".join(kinds[:4])
        except (ValueError, TypeError):
            return "sing-box config"


# --------------------------------------------------------------------------
# Clash config — converts to the concrete protocol profiles on import
# --------------------------------------------------------------------------
@dataclass
class ClashProfile(ProtocolProfile):
    """A Clash YAML document; :mod:`.convert` turns each proxy entry into
    the concrete profile (ss/vmess/trojan/hysteria2/tuic/...)."""
    kind = "clash"
    title = "Clash config"
    yaml_text: str = ""
    source: str = ""

    def share_url(self) -> str:
        return "clash://" + _b64(self.yaml_text.encode())

    def summary(self) -> str:
        n = self.yaml_text.count("- name:") + self.yaml_text.count("- {name:")
        return "Clash config (~%d proxies)" % n

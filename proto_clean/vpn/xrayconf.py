"""Xray-core config generation for the v2ray proxy feature.

Two protocols are supported, driven by user-imported share URLs:

* ``vless-reality`` — VLESS over TCP with the REALITY transport. REALITY
  masks the connection as ordinary TLS to a decoy site: the ClientHello
  carries the *steal-oneself* SNI (``serverName``) and a uTLS browser
  fingerprint, so deep-packet-inspectors see a normal HTTPS handshake
  to that site instead of a proxy handshake.
* ``trojan`` — Trojan-Go/Trojan-GFW protocol over TLS (password
  authenticated, also SNI-masked via ``serverName``).

The generated config exposes a local SOCKS5 inbound (default
127.0.0.1:10808, UDP enabled) and an HTTP inbound (127.0.0.1:10809);
the app can then point the system proxy at them.

Run ``xray run -c <file>`` (Xray-core, https://github.com/XTLS/Xray-core)
with the produced JSON. Xray-core is NOT bundled — see README.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

# uTLS fingerprints Xray-core accepts for REALITY / TLS.
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge",
                "randomized")
# VLESS flows understood by current Xray-core ("" = no flow).
FLOWS = ("", "xtls-rprx-vision")
XRAY_PROTOCOLS = ("vless-reality", "trojan")

DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 10809


class XrayConfigError(ValueError):
    """Invalid profile or share URL."""


@dataclass
class XrayProfile:
    """Everything needed to build one outbound proxy."""

    protocol: str = "vless-reality"     # "vless-reality" | "trojan"
    address: str = ""
    port: int = 443
    name: str = ""
    # --- VLESS + REALITY ---
    uuid: str = ""
    public_key: str = ""                # REALITY `pbk` (server x25519 public key)
    short_id: str = ""                  # REALITY `sid`
    flow: str = "xtls-rprx-vision"
    # --- Trojan ---
    password: str = ""
    # --- shared TLS ---
    sni: str = ""                       # masked SNI / serverName
    fingerprint: str = "chrome"         # uTLS client fingerprint
    allow_insecure: bool = False
    spider_x: str = "/"                 # REALITY spider prefix (spiderX)

    def normalized(self) -> "XrayProfile":
        proto = self.protocol if self.protocol in XRAY_PROTOCOLS else "vless-reality"
        fp = self.fingerprint if self.fingerprint in FINGERPRINTS else "chrome"
        if proto == "vless-reality":
            flow = self.flow if self.flow in FLOWS else "xtls-rprx-vision"
        else:
            flow = ""                       # trojan carries no flow
        try:
            port = int(self.port)
        except (TypeError, ValueError):
            port = 443
        port = port if 1 <= port <= 65535 else 443
        return XrayProfile(
            protocol=proto, address=(self.address or "").strip(),
            port=port, name=(self.name or "").strip(),
            uuid=(self.uuid or "").strip().lower(),
            public_key=(self.public_key or "").strip(),
            short_id=(self.short_id or "").strip(),
            flow=flow, password=self.password or "",
            sni=(self.sni or "").strip(), fingerprint=fp,
            allow_insecure=bool(self.allow_insecure),
            spider_x=self.spider_x or "/",
        )


_UUID_LEN = 36  # 8-4-4-4-12


def _check_uuid(uuid: str) -> str:
    u = uuid.strip().lower()
    if len(u) != _UUID_LEN or u.count("-") != 4:
        raise XrayConfigError(
            f"VLESS id must be a UUID (got {u!r})")
    if not all(c in "0123456789abcdef-" for c in u):
        raise XrayConfigError(f"VLESS id is not a valid UUID (got {u!r})")
    return u


def parse_xray_url(url: str) -> XrayProfile:
    """Parse a ``vless://`` (REALITY) or ``trojan://`` share URL.

    Raises :class:`XrayConfigError` for anything else — including VLESS
    URLs without REALITY (only ``security=reality`` is supported).
    """
    raw = (url or "").strip()
    if "://" not in raw:
        raise XrayConfigError("not a share URL (expected vless:// or trojan://)")
    scheme, _, rest = raw.partition("://")
    scheme = scheme.lower()

    parsed = urlparse(raw)
    host = parsed.hostname or ""
    try:
        port = parsed.port or (443 if scheme != "http" else 80)
    except ValueError:
        raise XrayConfigError("invalid port in URL")
    if not host:
        raise XrayConfigError("missing server address")

    q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    name = unquote(parsed.fragment) if parsed.fragment else ""
    sni = q.get("sni") or q.get("peer") or host
    fp = q.get("fp", "chrome")
    insecure = q.get("allowInsecure") in ("1", "true") or \
        q.get("insecure") in ("1", "true")

    if scheme == "vless":
        uuid = unquote(parsed.username or "")
        if q.get("security") != "reality":
            raise XrayConfigError(
                "only VLESS + REALITY is supported (this URL uses "
                f"security={q.get('security') or 'none'})")
        pbk = q.get("pbk", "")
        if not pbk:
            raise XrayConfigError("VLESS REALITY URL is missing pbk (public key)")
        return XrayProfile(
            protocol="vless-reality", address=host, port=port, name=name,
            uuid=_check_uuid(uuid), public_key=pbk, short_id=q.get("sid", ""),
            flow=q.get("flow", "xtls-rprx-vision"),
            sni=sni, fingerprint=fp, allow_insecure=insecure,
            spider_x=unquote(q.get("spx", "/")) or "/",
        ).normalized()
    if scheme == "trojan":
        password = unquote(parsed.username or "") or parsed.password or ""
        if not password:
            raise XrayConfigError("trojan URL is missing the password")
        security = q.get("security", "tls")
        if security not in ("tls", ""):
            raise XrayConfigError(
                f"trojan over security={security!r} is not supported (TLS only)")
        return XrayProfile(
            protocol="trojan", address=host, port=port, name=name,
            password=password, sni=sni, fingerprint=fp,
            allow_insecure=insecure,
        ).normalized()
    raise XrayConfigError(
        f"unsupported scheme {scheme!r} (expected vless:// or trojan://)")


def _inbounds(socks_port: int, http_port: int) -> list:
    return [
        {
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
        {
            "tag": "http-in", "listen": "127.0.0.1", "port": http_port,
            "protocol": "http", "settings": {},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
    ]


def _outbounds(p: XrayProfile) -> list:
    if p.protocol == "vless-reality":
        proxy = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{
                "address": p.address, "port": p.port,
                "users": [{"id": p.uuid, "encryption": "none",
                           "flow": p.flow}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": p.sni,          # SNI masking target
                    "fingerprint": p.fingerprint,  # uTLS browser mimicry
                    "publicKey": p.public_key,
                    "shortId": p.short_id,
                    "spiderX": p.spider_x,
                },
            },
        }
    else:  # trojan
        proxy = {
            "tag": "proxy", "protocol": "trojan",
            "settings": {"servers": [{
                "address": p.address, "port": p.port, "password": p.password,
            }]},
            "streamSettings": {
                "network": "tcp", "security": "tls",
                "tlsSettings": {
                    "serverName": p.sni,          # SNI masking target
                    "fingerprint": p.fingerprint,
                    "allowInsecure": p.allow_insecure,
                },
            },
        }
    return [
        proxy,
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ]


def build_xray_config(profile: XrayProfile,
                      socks_port: int = DEFAULT_SOCKS_PORT,
                      http_port: int = DEFAULT_HTTP_PORT) -> dict:
    """Full Xray-core JSON config for the profile (as a plain dict)."""
    p = profile.normalized()
    if not p.address:
        raise XrayConfigError("server address is empty")
    if p.protocol == "vless-reality":
        _check_uuid(p.uuid)
        if not p.public_key:
            raise XrayConfigError("REALITY needs the server public key (pbk)")
        if not p.sni:
            raise XrayConfigError("REALITY needs the masked SNI (serverName)")
    elif not p.password:
        raise XrayConfigError("trojan needs the password")
    return {
        "log": {"loglevel": "warning"},
        "inbounds": _inbounds(int(socks_port), int(http_port)),
        "outbounds": _outbounds(p),
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"],
                 "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"],
                 "outboundTag": "block"},
            ],
        },
    }


def write_xray_config(profile: XrayProfile, path,
                      socks_port: int = DEFAULT_SOCKS_PORT,
                      http_port: int = DEFAULT_HTTP_PORT) -> str:
    """Write the config to *path* (chmod 600 — it holds credentials)."""
    import tempfile
    path = str(path)
    cfg = build_xray_config(profile, socks_port, http_port)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".xray-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return path


def profile_from_kwargs(**kw) -> XrayProfile:
    """Build a normalized profile from settings-style keyword arguments
    (unknown keys are ignored, mirroring how settings load tolerates
    unknown JSON fields)."""
    known = {f for f in XrayProfile.__dataclass_fields__}  # noqa: C416
    return XrayProfile(**{k: v for k, v in kw.items() if k in known}).normalized()

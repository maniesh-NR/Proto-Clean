"""Samizdat client configuration (the Lantern censorship-resistance stack).

`Samizdat <https://github.com/getlantern/samizdat>`_ is Lantern's protocol
that makes proxy traffic indistinguishable from a browser visiting a real
website over HTTP/2:

* one TLS 1.3 layer with a uTLS browser fingerprint (no TLS-over-TLS),
* HTTP/2 CONNECT tunnels multiplexed on that single connection,
* PSK authentication embedded in the TLS SessionID
  (``shortID(8) || nonce(8) || HMAC-SHA256(PSK, nonce)[:16]`` with
  ``PSK = HKDF-SHA256(serverPubKey, shortID, "SAMIZDAT")``),
* a masquerade *cover domain* (``server_name``) — failed auth makes the
  server transparently forward to the real site, defeating active probes,
* Geneva-style ClientHello TCP fragmentation plus padding/timing jitter.

Lantern ships samizdat as inbound/outbound adapters in
`lantern-box <https://github.com/getlantern/lantern-box>`_, a sing-box
fork. This module generates the *documented client config format* and
drives that binary. Proto Clean is GPL-3.0-or-later, so the official
releases also **bundle lantern-box binaries** built from the Lantern
source (see ``find_box_binary`` in vpn/samizdat.py for the lookup
order — PATH, bundle locations and ``PROTO_CLEAN_BOX_BIN``).

Share URLs use the same parameter names as our VLESS/REALITY importer:
``samizdat://server:443?pbk=<64-hex>&sid=<16-hex>&sni=ok.ru&fp=chrome#label``
(the parameter set is our convention — samizdat itself has no official
share-URL format yet).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

# uTLS fingerprints documented by lantern-box's samizdat outbound.
FINGERPRINTS = ("chrome", "firefox", "safari")
PADDING_PROFILES = ("chrome", "firefox")

# Duration strings sing-box accepts ("300ms", "5s", "2m45s", "1h").
_DURATION_RE = re.compile(r"^\d+(ms|s|m|h)$")

DEFAULT_MIXED_PORT = 10810  # local mixed (SOCKS+HTTP) inbound


class SamizdatConfigError(ValueError):
    """Invalid profile or share URL."""


@dataclass
class SamizdatProfile:
    """Everything needed to reach one samizdat server."""

    protocol: str = "samizdat"            # fixed marker
    address: str = ""
    port: int = 443
    name: str = ""
    # --- credentials (from the server operator) ---
    public_key: str = ""                  # server X25519 public key, 64 hex
    short_id: str = ""                    # pre-shared 8-byte id, 16 hex
    # --- masquerade ---
    server_name: str = ""                 # cover SNI (e.g. ok.ru)
    # --- traffic shaping / DPI evasion (lantern-box defaults) ---
    fingerprint: str = "chrome"
    padding_profile: str = "chrome"
    max_jitter_ms: int = 30
    max_streams_per_conn: int = 100
    data_threshold: int = 14000
    disable_padding: bool = False
    disable_jitter: bool = False
    disable_tcp_fragmentation: bool = False
    disable_record_fragmentation: bool = False
    idle_timeout: str = "5m"
    connect_timeout: str = "15s"

    def normalized(self) -> "SamizdatProfile":
        fp = self.fingerprint if self.fingerprint in FINGERPRINTS else "chrome"
        pp = (self.padding_profile if self.padding_profile in PADDING_PROFILES
              else "chrome")

        def clamp(v, lo, hi, dflt):
            try:
                v = int(v)
            except (TypeError, ValueError):
                return dflt
            return max(lo, min(hi, v))

        port = clamp(self.port, 1, 65535, 443)
        return SamizdatProfile(
            protocol="samizdat",
            address=(self.address or "").strip(),
            port=port,
            name=(self.name or "").strip(),
            public_key=(self.public_key or "").strip().lower(),
            short_id=(self.short_id or "").strip().lower(),
            server_name=(self.server_name or "").strip(),
            fingerprint=fp, padding_profile=pp,
            max_jitter_ms=clamp(self.max_jitter_ms, 0, 1000, 30),
            max_streams_per_conn=clamp(self.max_streams_per_conn, 1, 1000, 100),
            data_threshold=clamp(self.data_threshold, 0, 1_000_000, 14000),
            disable_padding=bool(self.disable_padding),
            disable_jitter=bool(self.disable_jitter),
            disable_tcp_fragmentation=bool(self.disable_tcp_fragmentation),
            disable_record_fragmentation=bool(self.disable_record_fragmentation),
            idle_timeout=self._dur(self.idle_timeout, "5m"),
            connect_timeout=self._dur(self.connect_timeout, "15s"),
        )

    @staticmethod
    def _dur(v: str, dflt: str) -> str:
        v = str(v or "").strip()
        return v if _DURATION_RE.match(v) else dflt


def _check_hex(value: str, hex_len: int, what: str) -> str:
    v = (value or "").strip().lower()
    if len(v) != hex_len or any(c not in "0123456789abcdef" for c in v):
        raise SamizdatConfigError(
            f"{what} must be {hex_len} hex characters (got {value!r})")
    return v


def _bool(qs_value: str) -> bool:
    return qs_value.strip().lower() in ("0", "false", "no", "off")


def parse_samizdat_url(url: str) -> SamizdatProfile:
    """Parse a ``samizdat://`` share URL into a profile."""
    raw = (url or "").strip()
    if "://" not in raw:
        raise SamizdatConfigError(
            "not a share URL (expected samizdat://)")
    scheme, _, _ = raw.partition("://")
    if scheme.lower() != "samizdat":
        raise SamizdatConfigError(
            f"unsupported scheme {scheme!r} (expected samizdat://)")
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if not host:
        raise SamizdatConfigError("missing server address")
    try:
        port = parsed.port or 443
    except ValueError:
        raise SamizdatConfigError("invalid port in URL")
    q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    pbk = q.get("pbk") or q.get("public_key") or q.get("pk") or ""
    sid = q.get("sid") or q.get("short_id") or q.get("id") or ""
    if not pbk:
        raise SamizdatConfigError(
            "samizdat URL is missing pbk (server X25519 public key)")
    if not sid:
        raise SamizdatConfigError(
            "samizdat URL is missing sid (short id)")
    return SamizdatProfile(
        address=host, port=port,
        name=unquote(parsed.fragment) if parsed.fragment else "",
        public_key=_check_hex(pbk, 64, "pbk (public key)"),
        short_id=_check_hex(sid, 16, "sid (short id)"),
        server_name=q.get("sni") or q.get("server_name") or "",
        fingerprint=q.get("fp", "chrome"),
        padding_profile=q.get("profile") or q.get("padding_profile")
        or "chrome",
        max_jitter_ms=q.get("jitterms", 30),
        max_streams_per_conn=q.get("streams", 100),
        data_threshold=q.get("threshold", 14000),
        disable_padding=_bool(q.get("padding", "1")),
        disable_jitter=_bool(q.get("jitter", "1")),
        disable_tcp_fragmentation=_bool(q.get("tcpfrag", "1")),
        disable_record_fragmentation=_bool(q.get("recfrag", "1")),
        idle_timeout=q.get("idle", "5m"),
        connect_timeout=q.get("connect", "15s"),
    ).normalized()


def build_samizdat_config(profile: SamizdatProfile,
                          mixed_port: int = DEFAULT_MIXED_PORT,
                          upstream_socks_port: int = 0) -> dict:
    """The sing-box/lantern-box client config (as a plain dict).

    ``upstream_socks_port`` chains the samizdat outbound through the
    bond engine's local SOCKS (sing-box ``detour``), so the masqueraded
    HTTP/2 stream itself rides every selected adapter.
    """
    p = profile.normalized()
    if not p.address:
        raise SamizdatConfigError("server address is empty")
    _check_hex(p.public_key, 64, "public_key")
    _check_hex(p.short_id, 16, "short_id")
    outbound = {
        "type": "samizdat", "tag": "samizdat-out",
        "server": p.address, "server_port": p.port,
        "public_key": p.public_key, "short_id": p.short_id,
        # masquerade cover site — omit when unset so lantern-box uses
        # its own default behaviour
        "fingerprint": p.fingerprint,
        "padding_profile": p.padding_profile,
        "max_jitter_ms": p.max_jitter_ms,
        "max_streams_per_conn": p.max_streams_per_conn,
        "data_threshold": p.data_threshold,
        "disable_padding": p.disable_padding,
        "disable_jitter": p.disable_jitter,
        "disable_tcp_fragmentation": p.disable_tcp_fragmentation,
        "disable_record_fragmentation": p.disable_record_fragmentation,
        "idle_timeout": p.idle_timeout,
        "connect_timeout": p.connect_timeout,
    }
    if p.server_name:
        outbound["server_name"] = p.server_name
    outbounds = [outbound, {"type": "direct", "tag": "direct"}]
    if upstream_socks_port:
        outbound["detour"] = "bond-out"
        outbounds.append({
            "type": "socks", "tag": "bond-out",
            "server": "127.0.0.1", "server_port": int(upstream_socks_port),
            "version": "5",
        })
    return {
        "log": {"level": "warn"},
        # mixed inbound = SOCKS5 + HTTP CONNECT on one port
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": int(mixed_port)}],
        "outbounds": outbounds,
        "route": {"rules": [{"ip_is_private": True, "outbound": "direct"}]},
    }


def write_samizdat_config(profile: SamizdatProfile, path,
                          mixed_port: int = DEFAULT_MIXED_PORT,
                          upstream_socks_port: int = 0) -> str:
    """Write the config to *path* (chmod 600 — it holds pre-shared keys)."""
    import tempfile
    path = str(path)
    cfg = build_samizdat_config(profile, mixed_port, upstream_socks_port)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".samizdat-", suffix=".json")
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


def profile_from_kwargs(**kw) -> SamizdatProfile:
    """Normalized profile from settings-style kwargs (unknown ignored)."""
    known = set(SamizdatProfile.__dataclass_fields__)
    return SamizdatProfile(**{k: v for k, v in kw.items()
                              if k in known}).normalized()

"""Cloudflare WARP — the oblivion / warp-plus approach.

Registration follows bepass-org/warp-plus (the engine oblivion bundles),
verified against its ``warp/api.go``:

* ``POST https://api.cloudflareclient.com/v0a4005/reg`` with the
  android-flavoured headers (``User-Agent: okhttp/3.12.1``,
  ``CF-Client-Version: a-6.30-3596``) and a JSON body carrying our
  X25519 public key.
* The response carries the WireGuard identity: ``config.client_id``
  (base64 — its first three bytes are the WG *reserved* field),
  ``config.interface.addresses.{v4,v6}``, ``config.peers[0].public_key``
  and the engage endpoint.
* Locally we keep the X25519 private key; nothing else is needed to run
  the tunnel.

Engine: the WARP WireGuard tunnel runs through **lantern-box** as a
``wireguard`` endpoint behind a ``mixed`` inbound, so WARP looks like any
other local SOCKS engine — which is exactly what makes it chainable:

* **WARP before** — chain = [WARP, <protocol>]: the protocol engine dials
  its server through the WARP SOCKS (``upstream_socks``).
* **WARP after** — chain = [<protocol>, WARP]: traffic exits through
  Cloudflare instead of the protocol server's IP.

Both presets are one click in the Protocols UI (see
:class:`ChainProfile` builders in :mod:`.chain`).
"""

from __future__ import annotations

import base64
import hashlib
import json as _json
import os
import secrets
from typing import Dict, Optional, Tuple

import httpx

from ...log import get
from . import models as M
from .base import ProtocolError

log = get("protocols.warp")

API_BASE = "https://api.cloudflareclient.com/v0a4005"
DEFAULT_ENDPOINT_HOST = "engage.cloudflareclient.com"
DEFAULT_PORT = 2408
_PEER_PUBKEY_FALLBACK = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="


def _headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
        "CF-Client-Version": "a-6.30-3596",
    }


def generate_keypair() -> Tuple[str, str]:
    """A WireGuard-compatible X25519 keypair as ``(private, public)``
    base64 strings (clamped like wg does)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import \
        X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (Encoding,
                                                              PublicFormat)
    while True:
        priv_raw = bytearray(os.urandom(32))
        priv_raw[0] &= 248
        priv_raw[31] &= 127
        priv_raw[31] |= 64
        try:
            priv = X25519PrivateKey.from_private_bytes(bytes(priv_raw))
            break
        except Exception:                        # pragma: no cover
            continue
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (base64.b64encode(bytes(priv_raw)).decode(),
            base64.b64encode(pub).decode())


def reserved_from_client_id(client_id_b64: str) -> Tuple[int, int, int]:
    """The WireGuard ``reserved`` bytes are the first three bytes of the
    registration ``client_id`` (warp-plus ``generateWireguardConfig``)."""
    try:
        raw = base64.b64decode(client_id_b64)
    except Exception:
        raise ProtocolError("invalid WARP client_id") from None
    if len(raw) < 3:
        raise ProtocolError("WARP client_id too short")
    return (raw[0], raw[1], raw[2])


def register(profile: M.WarpProfile, timeout: float = 20.0,
             client: Optional[httpx.Client] = None) -> M.WarpProfile:
    """Register a new WARP device (or reuse the cached registration).

    Returns the profile with ``private_key``/``peer_public_key``/
    ``client_id_b64``/addresses filled in. Registration is done once and
    cached; a WARP+ ``license_key`` can be attached afterwards via
    :func:`attach_license`.
    """
    if profile.peer_public_key and profile.private_key:
        return profile                      # already registered
    priv_b64, pub_b64 = generate_keypair()
    body = {
        "install_id": "",
        "fcm_token": "",
        "tos": "2024-01-01T00:00:00.000000000Z",
        "key": pub_b64,
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
        "warp_enabled": True,
    }
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=timeout)
    try:
        resp = client.post(API_BASE + "/reg", headers=_headers(),
                           json=body)
        if resp.status_code >= 400:
            raise ProtocolError(
                "WARP registration failed (HTTP %d): %s"
                % (resp.status_code, resp.text[:160]))
        ident = resp.json()
    finally:
        if own_client:
            client.close()
    cfg = ident.get("config") or {}
    peers = cfg.get("peers") or []
    if not peers:
        raise ProtocolError("WARP registration response has no peers")
    peer = peers[0]
    addresses = (cfg.get("interface") or {}).get("addresses") or {}
    profile.private_key = priv_b64
    profile.peer_public_key = str(peer.get("public_key")
                                  or _PEER_PUBKEY_FALLBACK)
    profile.client_id_b64 = str(cfg.get("client_id") or "")
    profile.address_v4 = str(addresses.get("v4") or "172.16.0.2/32")
    profile.address_v6 = str(addresses.get("v6") or "")
    profile.token = str(ident.get("token") or "")
    profile.device_id = str(ident.get("id") or "")
    if not profile.client_id_b64:
        raise ProtocolError("WARP registration response lacks client_id")
    return profile


def attach_license(profile: M.WarpProfile, license_key: str,
                   timeout: float = 20.0,
                   client: Optional[httpx.Client] = None) -> bool:
    """Attach a WARP+ license to the registered device."""
    if not profile.token or not profile.device_id:
        register(profile, timeout=timeout, client=client)
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=timeout)
    try:
        resp = client.put(
            API_BASE + "/reg/%s/account/reg" % profile.device_id,
            headers=dict(_headers(),
                         Authorization="Bearer " + profile.token),
            json={"license": license_key})
        ok = resp.status_code < 400
        if ok:
            profile.license_key = license_key
        return ok
    finally:
        if own_client:
            client.close()


def build_warp_box_config(profile: M.WarpProfile, socks_port: int,
                          upstream: Tuple[str, int] = ("", 0)) -> dict:
    """sing-box config: mixed inbound + wireguard endpoint (WARP).

    ``upstream`` makes the WARP tunnel itself dial through another
    engine's local SOCKS (the *protocol -> WARP* chain uses this so the
    WireGuard handshake to Cloudflare rides inside the protocol tunnel —
    supported through the legacy wireguard *outbound* with a detour,
    probed at start time; endpoints do not support detour).
    """
    reserved = reserved_from_client_id(profile.client_id_b64) \
        if profile.client_id_b64 else (0, 0, 0)
    host, _, port_s = profile.endpoint.partition(":")
    port = int(port_s or profile.port or DEFAULT_PORT)
    addresses = [profile.address_v4]
    if profile.address_v6:
        addresses.append(profile.address_v6)
    peer = {
        "address": host,
        "port": port,
        "public_key": profile.peer_public_key,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "reserved": list(reserved),
    }
    cfg: dict = {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    if upstream[1]:
        # WARP *after* another engine: wireguard outbound + detour
        cfg["outbounds"].insert(0, {
            "type": "socks", "tag": "upstream",
            "server": upstream[0], "server_port": upstream[1],
            "version": "5",
        })
        cfg["outbounds"].append({
            "type": "wireguard", "tag": "warp-out", "detour": "upstream",
            "address": addresses, "private_key": profile.private_key,
            "peers": [peer],
        })
        cfg["route"] = {"rules": [{"inbound": "mixed-in",
                                   "outbound": "warp-out"}]}
    else:
        # WARP *before* everything: a plain endpoint
        cfg["endpoints"] = [{
            "type": "wireguard", "tag": "warp-ep",
            "address": addresses, "private_key": profile.private_key,
            "peers": [peer],
        }]
        cfg["route"] = {"rules": [{"inbound": ["mixed-in"],
                                   "endpoint": "warp-ep"}],
                        "final": "direct"}
    return cfg


def warp_before_chain_url(protocol_url: str) -> str:
    """chain:// link with WARP as the first hop: client -> WARP -> server."""
    return M.ChainProfile(hops=["warp://config", protocol_url]).share_url()


def warp_after_chain_url(protocol_url: str) -> str:
    """chain:// link with WARP as the exit: client -> server -> WARP."""
    return M.ChainProfile(hops=[protocol_url, "warp://config"]).share_url()


def fingerprint_of(text: str) -> str:
    """Stable fingerprint for caching registrations on disk."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def new_profile(license_key: str = "") -> M.WarpProfile:
    prof = M.WarpProfile(license_key=license_key)
    prof.endpoint = "%s:%d" % (DEFAULT_ENDPOINT_HOST, DEFAULT_PORT)
    return prof

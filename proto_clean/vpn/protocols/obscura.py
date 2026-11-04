"""Obscura VPN relays — WireGuard tunnels with relay/exit multihop.

Obscura (https://github.com/Sovereign-Engineering/obscuravpn-api) exposes a
small JSON API, base ``https://v1.api.prod.obscura.net/api/``:

* ``POST auth`` ``{"account_no": "<20-char account number>"}`` →
  ``{"auth_token": ...}``; every following command carries the token.
* ``POST tunnel`` ``{"type": "udp_port"|"obfuscated", "label": null,
  "wg_pubkey": "<base64 32B>", "relay": "<relay id>", "exit": "<exit id>"}``
  → a OneTunnel document (``id``, ``status``, ``config``, ``relay``,
  ``exit``).  A relay different from the exit selects a multihop path.
* ``GET tunnel`` → ``[OneTunnel]``; the relay summaries shown in the UI are
  derived from these documents.

The engine exchanges a fresh WireGuard keypair for a tunnel, renders a
wg-quick config (via :class:`..wgconf.WgQuickConf`), writes it under
``CONFIG_DIR/obscura/<tunnel_id>.conf`` and brings it up through
:class:`..tunnel.TunnelManager` — the same privileged path the Proton
WireGuard flow uses.  ``"obfuscated"`` tunnels wrap WireGuard in a
QUIC-obfuscated transport that wg-quick cannot speak; the generated config
carries a note saying it needs the official obscura client binary and still
uses the plain WireGuard parameters (the exit's WireGuard layer).

Assumptions where the public API spec is not explicit:

* the auth token travels as ``Authorization: Bearer <token>``;
* ``DELETE tunnel/<id>`` removes a tunnel (``delete_all`` loops over
  ``GET tunnel``);
* ``relay``/``exit`` are optional in the create body (the server picks when
  omitted), and idle tunnels are never auto-removed server-side.
"""

from __future__ import annotations

import base64
import os
import time
from typing import List, Optional, Tuple

import httpx

from ... import __version__ as _PC_VERSION
from ...log import get
from ...paths import CONFIG_DIR
from ..tunnel import TunnelManager
from ..wgconf import WgConfigError, WgQuickConf
from . import models as M
from .base import ProtocolEngine, ProtocolError, TUNNEL_FAMILY, write_private

log = get("protocols.obscura")

#: production API base (overridable per profile)
DEFAULT_API_BASE = "https://v1.api.prod.obscura.net/api/"

_KEEPALIVE = 25


def generate_keypair() -> Tuple[str, str]:
    """Fresh clamped Curve25519 keypair as ``(private_b64, public_b64)``.

    Same recipe as ``wg genkey``: 32 random bytes with the WireGuard
    clamping applied, then the X25519 public key is derived from them.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)

    raw = bytearray(os.urandom(32))
    raw[0] &= 248                                # WireGuard key clamping
    raw[31] &= 127
    raw[31] |= 64
    priv = X25519PrivateKey.from_private_bytes(bytes(raw))
    pub = priv.public_key().public_bytes_raw()
    return (base64.b64encode(bytes(raw)).decode("ascii"),
            base64.b64encode(pub).decode("ascii"))


class ObscuraClient:
    """Minimal httpx client for the Obscura relay API.

    Every request goes through a fresh ``httpx.Client`` bound to the
    profile's ``api_base``; non-2xx responses raise
    :class:`~.base.ProtocolError` carrying the API message (response text
    truncated to 200 chars).  The auth token is fetched once and cached in
    ``profile.auth_token``.
    """

    def __init__(self, profile: M.ObscuraProfile, timeout: float = 20.0) -> None:
        self.profile = profile
        self.timeout = float(timeout)
        #: private key (b64) of the tunnel created most recently by
        #: :meth:`create_tunnel` — the profile's cached ``wg_conf`` embeds it
        self.private_key_b64 = ""
        self._headers = {"User-Agent": "ProtoClean/%s (obscura client)"
                                      % _PC_VERSION}

    # -- plumbing ----------------------------------------------------------
    @staticmethod
    def _api_message(resp: httpx.Response) -> str:
        """API error message: JSON ``message`` field or truncated body text."""
        text = (resp.text or "").strip()
        try:
            data = resp.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            for key in ("message", "error", "detail", "msg"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return text[:200]

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = dict(self._headers)
        if path != "auth":
            token = self.auth_token()
            if token:
                headers["Authorization"] = "Bearer %s" % token
        try:
            with httpx.Client(base_url=self.profile.api_base,
                              timeout=self.timeout) as client:
                resp = client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise ProtocolError("obscura API %s %s failed: %s"
                                % (method, path, exc)) from None
        if not 200 <= resp.status_code < 300:
            raise ProtocolError(
                "obscura API %s %s failed (%d): %s"
                % (method, path, resp.status_code, self._api_message(resp)))
        return resp

    # -- commands ----------------------------------------------------------
    def auth_token(self) -> str:
        """Exchange the account number for an auth token (cached)."""
        if self.profile.auth_token:
            return self.profile.auth_token
        resp = self._request("POST", "auth",
                             json={"account_no": self.profile.account_id})
        try:
            data = resp.json()
        except ValueError:
            data = {}
        token = ""
        if isinstance(data, dict):
            token = str(data.get("auth_token") or "")
        if not token:
            raise ProtocolError(
                "obscura auth response did not include an auth_token")
        self.profile.auth_token = token
        return token

    def create_tunnel(self, relay: Optional[str] = None,
                      exit: Optional[str] = None,          # noqa: A002 — API name
                      tunnel_type: Optional[str] = None) -> dict:
        """Register a fresh WireGuard keypair; returns the OneTunnel dict.

        The generated config is cached in ``profile.wg_conf`` (it embeds the
        fresh private key) and ``profile.tunnel_id`` is updated.
        """
        priv_b64, pub_b64 = generate_keypair()
        body = {
            "type": tunnel_type or self.profile.tunnel_type or "udp_port",
            "label": None,
            "wg_pubkey": pub_b64,
            "relay": relay or self.profile.relay or None,
            "exit": exit or self.profile.exit or None,
        }
        resp = self._request("POST", "tunnel", json=body)
        try:
            tunnel = resp.json()
        except ValueError:
            tunnel = None
        if not isinstance(tunnel, dict) or not tunnel.get("id"):
            raise ProtocolError("obscura tunnel response lacks an id")
        self.private_key_b64 = priv_b64
        self.profile.tunnel_id = str(tunnel["id"])
        self.profile.wg_conf = self.build_wg_config(tunnel, priv_b64)
        return tunnel

    def list_tunnels(self) -> list:
        """All tunnels on the account (``[OneTunnel]``)."""
        resp = self._request("GET", "tunnel")
        try:
            data = resp.json()
        except ValueError:
            data = []
        return data if isinstance(data, list) else []

    def list_relays(self, tunnels: Optional[list] = None) -> List[dict]:
        """Relay summaries (id, country, city, preferred exits) derived from
        tunnel documents — first-seen order, deduplicated by relay id."""
        tunnels = self.list_tunnels() if tunnels is None else tunnels
        out: List[dict] = []
        seen = set()
        for t in tunnels:
            relay = (t or {}).get("relay") or {}
            rid = relay.get("id")
            if not rid or rid in seen:
                continue
            seen.add(rid)
            exits = [e.get("id") for e in (relay.get("preferred_exits") or [])
                     if isinstance(e, dict) and e.get("id")]
            out.append({
                "id": rid,
                "country_code": relay.get("country_code", ""),
                "city_name": relay.get("city_name", ""),
                "preferred_exits": exits,
            })
        return out

    def delete_tunnel(self, tid: str) -> None:
        """Remove one tunnel; forgets ``profile.tunnel_id`` if it matches."""
        self._request("DELETE", "tunnel/%s" % tid)
        if self.profile.tunnel_id == tid:
            self.profile.tunnel_id = ""

    def delete_all(self) -> None:
        """Remove every tunnel on the account."""
        for t in self.list_tunnels():
            tid = (t or {}).get("id")
            if tid:
                self.delete_tunnel(str(tid))

    # -- wg-quick rendering --------------------------------------------------
    def build_wg_config(self, tunnel: dict, private_key_b64: str) -> str:
        """Render a wg-quick config for a OneTunnel document.

        ``[Interface]`` gets the fresh private key, the client IPs (v4 + v6)
        and the API-provided DNS; ``[Peer]`` points at the exit's public key
        with ::/0 AllowedIPs and the relay's v4 endpoint (v6 fallback).
        """
        cfg = (tunnel or {}).get("config") or {}
        tunnel_id = str((tunnel or {}).get("id") or "")
        ttype = str(cfg.get("type") or "udp_port")
        addrs = [a for a in list(cfg.get("client_ips_v4") or [])
                 + list(cfg.get("client_ips_v6") or []) if a]
        if not addrs:
            raise ProtocolError("obscura tunnel %s has no client addresses"
                                % (tunnel_id or "?"))
        dns = [str(d) for d in (cfg.get("dns") or []) if d]
        peer_key = str(cfg.get("exit_pubkey") or "")
        if not peer_key:
            raise ProtocolError("obscura tunnel %s lacks exit_pubkey"
                                % (tunnel_id or "?"))
        endpoint = str(cfg.get("relay_addr_v4")
                       or cfg.get("relay_addr_v6") or "")
        if not endpoint:
            raise ProtocolError("obscura tunnel %s lacks a relay address"
                                % (tunnel_id or "?"))

        conf = WgQuickConf()
        conf.interface["PrivateKey"] = [private_key_b64]
        conf.interface["Address"] = [", ".join(addrs)]
        if dns:
            conf.interface["DNS"] = [", ".join(dns)]
        conf.peer["PublicKey"] = [peer_key]
        conf.peer["AllowedIPs"] = ["0.0.0.0/0, ::/0"]
        conf.peer["Endpoint"] = [endpoint]
        conf.peer["PersistentKeepalive"] = [str(_KEEPALIVE)]

        header: List[str] = []
        if tunnel_id:
            header.append("# Proto Clean: Obscura tunnel %s" % tunnel_id)
        header.append("# tunnel type: %s" % ttype)
        if ttype == "obfuscated":
            header += [
                '# NOTE: the "obfuscated" tunnel type wraps WireGuard in a QUIC-',
                "# obfuscated transport that wg-quick cannot speak — bring this",
                "# config up with the official obscura client binary instead.",
            ]
        text = ("\n".join(header) + "\n" if header else "") + conf.serialize()
        try:
            WgQuickConf.parse(text)              # self-check (comments skipped)
        except WgConfigError as exc:
            raise ProtocolError(
                "generated Obscura WireGuard config is invalid: %s" % exc) \
                from None
        return text


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class ObscuraEngine(ProtocolEngine):
    """Obscura relay tunnel — a WireGuard device tunnel via TunnelManager."""

    proxy_kind = "obscura"
    family = TUNNEL_FAMILY                    # "tunnel"
    exposes = "tunnel"
    binary_name = ""                          # HTTP + wg-quick, no extra binary
    supports_upstream = False                 # a tunnel takes all traffic

    def __init__(self, socks_port: int = 0) -> None:
        super().__init__(socks_port)
        self.client: Optional[ObscuraClient] = None
        self._manager: Optional[TunnelManager] = None
        self._conf_path = ""
        self._tunnel_id = ""
        self._connected = False

    # -- lifecycle ----------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._connected

    def start(self, profile: M.ObscuraProfile, timeout: float = 40.0) -> None:
        if self.running:
            raise ProtocolError("the Obscura tunnel is already up")
        if not isinstance(profile, M.ObscuraProfile):
            raise ProtocolError("obscura engine needs an ObscuraProfile")
        if not (profile.account_id or "").strip():
            raise ProtocolError(
                "obscura: profile needs a 20-char account number "
                "(obscura://<account>)")

        client = ObscuraClient(profile)
        self.client = client
        client.auth_token()                   # ensure the token early
        tunnel, conf_text = self._resolve_tunnel(client, profile)
        tunnel_id = str(tunnel.get("id") or "")
        if not tunnel_id:
            raise ProtocolError("obscura: API returned a tunnel without id")
        self._tunnel_id = tunnel_id
        self._conf_path = os.path.join(str(CONFIG_DIR), "obscura",
                                       "%s.conf" % tunnel_id)
        write_private(self._conf_path, conf_text)

        manager = TunnelManager()
        self._manager = manager
        try:
            manager.up(conf_text)
            if not manager.wait_handshake(timeout=max(5.0, float(timeout) / 2.0)):
                raise ProtocolError(
                    "Obscura tunnel %s is up but the WireGuard handshake never "
                    "completed" % tunnel_id)
        except ProtocolError:
            self._teardown(manager)
            raise
        except Exception as exc:
            self._teardown(manager)
            raise ProtocolError(
                "obscura tunnel %s failed to come up: %s" % (tunnel_id, exc)) \
                from exc
        self._connected = True
        self._started_at = time.time()
        log.info("obscura tunnel %s up (%s)", tunnel_id,
                 profile.summary() or "default path")

    def stop(self, timeout: float = 5.0) -> None:
        manager, self._manager = self._manager, None
        self._connected = False
        if manager is not None:
            try:
                manager.down()
            except Exception as exc:           # best-effort teardown
                log.warning("obscura tunnel teardown error: %s", exc)
        self._proc = None
        super().stop(timeout)
        # NOTE: the server-side tunnel is intentionally kept — Obscura idle
        # tunnels are not auto-removed and a later start can reuse it (or
        # remove it explicitly via ObscuraClient.delete_tunnel/delete_all).

    def status(self) -> dict:
        d = super().status()
        prof = self.client.profile if self.client is not None else None
        d.update({
            "relay": (getattr(prof, "relay", "") or "") if prof else "",
            "exit": (getattr(prof, "exit", "") or "") if prof else "",
            "tunnel_id": self._tunnel_id,
            "tool": "wireguard",
        })
        return d

    # -- internals ----------------------------------------------------------
    def _resolve_tunnel(self, client: ObscuraClient,
                        profile: M.ObscuraProfile) -> Tuple[dict, str]:
        """Reuse the cached tunnel when it still exists, else create one.

        A cached ``tunnel_id`` is verified through ``GET tunnel``; it is only
        reusable when the profile still carries the matching ``wg_conf`` (the
        private key of an imported tunnel id is unrecoverable, so such a
        tunnel is replaced with a fresh one).
        """
        if profile.tunnel_id:
            tunnels = client.list_tunnels()
            for t in tunnels:
                if isinstance(t, dict) and t.get("id") == profile.tunnel_id \
                        and profile.wg_conf:
                    return t, profile.wg_conf
        tunnel = client.create_tunnel()
        return tunnel, (profile.wg_conf or "")

    def _teardown(self, manager: TunnelManager) -> None:
        self._manager = None
        try:
            manager.down()
        except Exception as exc:               # best-effort
            log.warning("obscura tunnel teardown error: %s", exc)


def engine(profile: M.ObscuraProfile, socks_port: int = 0) -> ObscuraEngine:
    """Registry factory for the ``obscura`` protocol kind."""
    return ObscuraEngine(socks_port=socks_port)

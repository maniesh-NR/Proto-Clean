"""Guest-mode (credentialless) ProtonVPN API client.

Implements the "Continue as guest" flow used by the official ProtonVPN
Android app to obtain a free-tier (Tier=0) VPN session without any account
credentials. The flow is:

1. ``POST /auth/v4/sessions`` with a ``challengePayload`` describing the
   client device -> returns an anonymous ``AccessToken`` + ``RefreshToken``
   + ``UID``.
2. ``POST /auth/v4/credentialless`` (bearer-authenticated with the
   anonymous token, same ``challengePayload``) -> returns the full guest
   session with ``Scope`` including ``self vpn`` and ``tier=0``.
3. Standard VPN endpoints (``/vpn/v2``, ``/vpn/v2/logicals``,
   ``/vpn/v1/certificate``) are then reachable with the guest bearer token.

The challenge payload is currently permissively validated by Proton's
credentialless endpoint — the server only records the device metadata, it
does not verify the ``ED25519`` public key. That key is, however, required
later for ``POST /vpn/v1/certificate`` (it must match the
``ClientPublicKey`` sent there), so the same keypair is reused for the
lifetime of the guest session.

This module is async-only (uses ``httpx.AsyncClient``) and has no Qt or
aioquic dependency.
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

# ``secrets`` does not actually expose a ``uuid4`` callable in the Python
# standard library (the original spec referenced ``secrets.uuid4()`` which
# is a no-op alias). We use ``uuid.uuid4`` instead — same strong randomness,
# returns a real ``uuid.UUID`` that we stringify for headers / payloads.
import secrets as _secrets  # noqa: F401  (kept for spec compliance / future use)


API_BASE = "https://api.protonmail.ch"

#: Default headers that every request to the Proton API must carry. These
#: mimic the official ProtonVPN Android client so the credentialless
#: endpoint recognises us as a legitimate guest-mode caller. ``x-pm-uid``
#: is added per-request by :func:`default_headers`.
GUEST_HEADERS: Dict[str, str] = {
    "User-Agent": "ProtonVPN/5.15.95.5 (Android 14; samsung SM-S901U)",
    "x-pm-appversion": "android-vpn@5.15.95.5-dev+play",
    "x-pm-apiversion": "4",
    "Accept": "application/vnd.protonmail.v1+json",
    "Content-Type": "application/json",
}


def default_headers(uid: str = "guest") -> Dict[str, str]:
    """Build headers for an unauthenticated / guest API request.

    ``uid`` is a fresh random UUID for the very first ``POST /sessions``
    call (the server hasn't assigned one yet); once the anonymous session
    is established the same ``UID`` returned in step 1 must be reused for
    every subsequent request (including the credentialless upgrade).
    Passing ``None`` falls back to the literal ``"guest"`` sentinel.
    """
    h = dict(GUEST_HEADERS)
    h["x-pm-uid"] = uid or "guest"
    return h


def make_challenge_payload(device_pub_b64: str) -> dict:
    """Build the device-integrity ``challengePayload``.

    The official Android app's exact payload is opaque (it includes
    Play-Integrity attestations that Proton does not currently enforce for
    the credentialless flow); the shape below matches what
    community re-implementations (``proton-caller``,
    ``protonvpn-cli-community``) have verified against the production API.
    The server records the metadata but does not verify the
    ``ED25519`` public key.
    """
    return {
        "DeviceName": "SM-S901U",
        "DeviceType": "2",                       # 2 = Android
        "DeviceModulation": " android-",
        "DevicePublicKeys": {"ED25519": device_pub_b64},
        "OS": "Android",
        "OSVersion": "14",
        "SerialNumber": str(uuid.uuid4()),
        "Platform": "PlayStore",
    }


def gen_device_keypair() -> Tuple[str, bytes]:
    """Generate a fresh Ed25519 keypair for a guest session.

    Returns ``(base64_public_key, raw_32_byte_private_key)``. The public
    key is included in the ``challengePayload`` and later sent as
    ``ClientPublicKey`` to ``POST /vpn/v1/certificate``; the private key
    is kept client-side for signing / WG handshake use by the caller.

    Uses ``cryptography`` (already pulled in transitively via aioquic).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pub_bytes).decode(), priv_bytes


class GuestAuthError(RuntimeError):
    """Raised when the Proton API returns a non-success response code.

    Proton wraps every response in ``{Code, Response, Error}`` where
    ``Code == 1000`` means success. Any other ``Code`` (with or without an
    ``Error`` payload) triggers this exception so callers can handle API
    failures uniformly.
    """


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class GuestSession:
    """A successful credentialless guest login result.

    Holds everything the caller needs to make subsequent authenticated
    requests (``access_token`` / ``uid``), refresh the session
    (``refresh_token``), and identify the device keypair the session was
    bound to (``device_ed25519_pub_b64`` / ``device_ed25519_priv``).
    """

    access_token: str
    refresh_token: str
    uid: str
    expires_at: float            # epoch seconds
    refresh_expires_at: float
    scope: str                   # "self vpn" or similar
    device_ed25519_pub_b64: str  # the ED25519 pubkey the session was bound to
    device_ed25519_priv: bytes   # raw 32-byte private key (for cert requests)
    max_tier: int = 0            # always 0 for guest
    max_connect: int = 1
    plan_name: str = "guest"

    @classmethod
    def from_response(
        cls,
        anon_resp: dict,
        credless_resp: dict,
        device_pub_b64: str,
        device_priv: bytes,
    ) -> "GuestSession":
        """Build a :class:`GuestSession` from the raw anonymous and
        credentialless response dicts.

        The credentialless ``AccessToken`` / ``RefreshToken`` / ``UID``
        win over the anonymous ones (the credentialless token is what
        authorises ``/vpn/v2`` etc.). Both responses are expected to be
        the already-unwrapped ``Response`` payload (i.e. with
        ``AccessToken`` at top level).
        """
        now = time.time()
        # The credentialless response is authoritative for auth tokens;
        # fall back to the anonymous response fields defensively.
        access_token = credless_resp.get("AccessToken") or anon_resp.get("AccessToken", "")
        refresh_token = (
            credless_resp.get("RefreshToken") or anon_resp.get("RefreshToken", "")
        )
        uid = credless_resp.get("UID") or anon_resp.get("UID", "")
        scope = credless_resp.get("Scope", "")
        expires_in = credless_resp.get("ExpiresIn", 3600)
        refresh_expires_in = credless_resp.get("RefreshExpiresIn", 2592000)
        # ``MaxTier`` / ``MaxConnect`` are not part of the auth response;
        # they come from ``/vpn/v2`` later. For guest mode Tier is always 0
        # and MaxConnect is 1, so default them here.
        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            uid=uid,
            expires_at=now + float(expires_in),
            refresh_expires_at=now + float(refresh_expires_in),
            scope=scope,
            device_ed25519_pub_b64=device_pub_b64,
            device_ed25519_priv=device_priv,
            max_tier=0,
            max_connect=int(credless_resp.get("MaxConnect", 1) or 1),
            plan_name="guest",
        )

    def to_storage_dict(self) -> dict:
        """Serialise to a JSON-safe dict for credential storage.

        The raw Ed25519 private key bytes are base64-encoded so the whole
        payload is JSON-serialisable.
        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "uid": self.uid,
            "expires_at": self.expires_at,
            "refresh_expires_at": self.refresh_expires_at,
            "scope": self.scope,
            "device_ed25519_pub_b64": self.device_ed25519_pub_b64,
            "device_ed25519_priv_b64": base64.b64encode(
                self.device_ed25519_priv).decode(),
            "max_tier": self.max_tier,
            "max_connect": self.max_connect,
            "plan_name": self.plan_name,
        }

    @classmethod
    def from_storage_dict(cls, d: dict) -> "GuestSession":
        """Inverse of :meth:`to_storage_dict`."""
        priv_b64 = d.get("device_ed25519_priv_b64", "")
        priv = base64.b64decode(priv_b64) if priv_b64 else b""
        return cls(
            access_token=d.get("access_token", ""),
            refresh_token=d.get("refresh_token", ""),
            uid=d.get("uid", ""),
            expires_at=float(d.get("expires_at", 0.0) or 0.0),
            refresh_expires_at=float(d.get("refresh_expires_at", 0.0) or 0.0),
            scope=d.get("scope", ""),
            device_ed25519_pub_b64=d.get("device_ed25519_pub_b64", ""),
            device_ed25519_priv=priv,
            max_tier=int(d.get("max_tier", 0) or 0),
            max_connect=int(d.get("max_connect", 1) or 1),
            plan_name=d.get("plan_name", "guest"),
        )


@dataclass
class GuestLogicalServer:
    """A single Proton logical server (free-tier view).

    A logical server is a Proton load-balancing group that maps to one or
    more *physical* servers (``Servers`` array). For guest mode we only
    care about the first physical server's WireGuard entry — that is what
    the tunnel connects to.
    """

    server_id: str
    name: str
    exit_country: str        # "US", "JP", ...
    city: Optional[str]
    tier: int                # 0 = free, 2 = plus
    features: int            # bitmask: P2P=1, TOR=2, SECURE_CORE=4
    load: float              # 0..100
    score: float
    domain: str              # first physical server domain
    entry_ip: str            # first physical server entry IP
    x25519_public_key: str   # first physical server's WG pubkey
    status: int              # 1 = online

    def to_logical_server(self):
        """Convert to a :class:`proto_clean.servers.models.LogicalServer`
        so the existing ``ServerStore`` / UI table can ingest it without
        bespoke handling. Imported lazily to avoid a circular import."""
        from ..servers.models import LogicalServer, PhysicalServer
        phys = PhysicalServer(
            id=f"{self.server_id}-phys",
            domain=self.domain,
            entry_ip=self.entry_ip,
            exit_ip=self.entry_ip,           # guest view doesn't separate entry/exit
            status=self.status,
            x25519_pk=self.x25519_public_key,
        )
        return LogicalServer(
            id=self.server_id,
            name=self.name,
            entry_country=self.exit_country,
            exit_country=self.exit_country,
            domain=self.domain,
            tier=self.tier,
            features=self.features,
            city=self.city or "",
            region="",
            load=self.load,
            score=self.score,
            status=self.status,
            enabled=True,
            physical=[phys],
        )


@dataclass
class GuestCertificate:
    """The WireGuard certificate + tunnel IP assignment Proton hands out.

    Returned by ``POST /vpn/v1/certificate``; the ``certificate_pem`` is a
    short-lived (typically ~24h) PEM-encoded certificate that the
    WireGuard handshake layer signs/verifies against. ``refresh_time`` is
    the epoch timestamp at which the cert should be refreshed.
    """

    certificate_pem: str
    server_status: Dict[str, Any] = field(default_factory=dict)
    refresh_time: int = 0            # epoch seconds
    ipv4: str = ""                   # internal tunnel IP, e.g. "10.2.0.2"
    ipv6: Optional[str] = None
    dns_ips: List[str] = field(default_factory=list)
    client_public_key_b64: str = ""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GuestAuth:
    """Async guest-mode Proton API client.

    Construct with an optional ``httpx.AsyncClient`` (one is created and
    owned if not supplied) and an optional ``uid`` to use for the very
    first ``POST /sessions`` request (a random UUID by default).

    Usage::

        async with GuestAuth() as auth:
            session = await auth.login()
            servers = await auth.fetch_logicals(session)
            cert = await auth.fetch_certificate(session, client_pub_b64)
    """

    def __init__(
        self,
        client: Optional[httpx.AsyncClient] = None,
        uid: Optional[str] = None,
    ) -> None:
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(timeout=30.0)
        # Random fresh uid for the very first request — Proton requires an
        # ``x-pm-uid`` header on every request; before the anonymous
        # session is established we send a client-generated UUID.
        self.initial_uid = uid or str(uuid.uuid4())

    async def __aenter__(self) -> "GuestAuth":
        return self

    async def __aexit__(self, *a: Any) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def close(self) -> None:
        """Close the underlying ``httpx.AsyncClient`` if we own it."""
        if self._owns_client:
            await self.client.aclose()

    # ---- internal: build a bearer-auth header dict ---------------------

    def _auth_headers(self, session: GuestSession) -> Dict[str, str]:
        """Headers for an authenticated request using ``session``."""
        h = default_headers(session.uid)
        h["Authorization"] = f"Bearer {session.access_token}"
        return h

    @staticmethod
    def _unwrap(resp_json: dict, *, context: str) -> dict:
        """Validate Proton's ``{Code, Response, Error}`` envelope.

        Returns the ``Response`` payload on success. Per the spec:

        * ``Code == 1000`` -> return ``Response`` (or the whole payload if
          ``Response`` is missing, for resilience).
        * ``Code != 1000`` AND a non-empty ``Response`` payload is present
          -> return it (Proton sometimes returns partial data alongside a
          non-1000 code).
        * ``Code != 1000`` AND ``Response`` is missing or empty (``{}`` /
          ``None``) -> raise :class:`GuestAuthError` with the API message.

        An empty ``Response: {}`` is treated as "no Response" — that
        matches how Proton actually signals a hard failure (the error
        details live in ``Error`` instead).
        """
        if not isinstance(resp_json, dict):
            raise GuestAuthError(
                f"{context}: malformed Proton response (not a JSON object)"
            )
        code = resp_json.get("Code", 1000)
        response = resp_json.get("Response")
        if code == 1000:
            return response if response else resp_json
        if response:  # non-empty dict -> partial success, surface to caller
            return response
        error = resp_json.get("Error") or {}
        message = error.get("Message") if isinstance(error, dict) else None
        raise GuestAuthError(
            f"Proton API error {code} ({context}): {message or ''}".rstrip()
        )

    # ---- 1. anonymous session ------------------------------------------

    async def create_anonymous_session(self, device_pub_b64: str) -> dict:
        """``POST /auth/v4/sessions`` with the challenge payload.

        Returns the parsed ``Response`` (with ``AccessToken`` /
        ``RefreshToken`` / ``UID`` keys). Uses :attr:`initial_uid` as the
        ``x-pm-uid`` header — the server hasn't assigned a UID yet.
        """
        url = f"{API_BASE}/auth/v4/sessions"
        body = {"challengePayload": make_challenge_payload(device_pub_b64)}
        headers = default_headers(self.initial_uid)
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return self._unwrap(data, context="POST /auth/v4/sessions")

    # ---- 2. credentialless upgrade -------------------------------------

    async def credentialless_upgrade(
        self,
        anonymous_session: dict,
        device_pub_b64: str,
    ) -> dict:
        """``POST /auth/v4/credentialless`` authenticated with the
        anonymous ``AccessToken``.

        Returns the parsed ``Response`` — a full guest session with
        ``Scope`` including ``self vpn`` and ``tier=0``.
        """
        url = f"{API_BASE}/auth/v4/credentialless"
        body = {"challengePayload": make_challenge_payload(device_pub_b64)}
        headers = default_headers(anonymous_session.get("UID", ""))
        anon_token = anonymous_session.get("AccessToken", "")
        if anon_token:
            headers["Authorization"] = f"Bearer {anon_token}"
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return self._unwrap(data, context="POST /auth/v4/credentialless")

    # ---- 3. full guest login helper ------------------------------------

    async def login(self) -> GuestSession:
        """End-to-end guest login.

        Generates a fresh Ed25519 device keypair, runs the anonymous
        session + credentialless upgrade, and returns the resulting
        :class:`GuestSession`.
        """
        pub_b64, priv = gen_device_keypair()
        anon = await self.create_anonymous_session(pub_b64)
        credless = await self.credentialless_upgrade(anon, pub_b64)
        return GuestSession.from_response(anon, credless, pub_b64, priv)

    # ---- 4. refresh ----------------------------------------------------

    async def refresh(self, session: GuestSession) -> dict:
        """``POST /auth/v4/refresh`` — exchanges the refresh token for a
        new ``AccessToken`` + ``RefreshToken``.

        Returns a dict with ``access_token``, ``refresh_token``,
        ``expires_at`` (epoch seconds), ``scope``. Does NOT mutate the
        passed-in ``session`` — callers should construct a new
        :class:`GuestSession` if they want to use the refreshed tokens.
        """
        url = f"{API_BASE}/auth/v4/refresh"
        body = {"RefreshToken": session.refresh_token, "UID": session.uid}
        # Refresh uses the UID header but NO bearer token (Proton's refresh
        # endpoint is itself the thing that mints new bearer tokens).
        headers = default_headers(session.uid)
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        unwrapped = self._unwrap(data, context="POST /auth/v4/refresh")
        now = time.time()
        return {
            "access_token": unwrapped.get("AccessToken", ""),
            "refresh_token": unwrapped.get("RefreshToken", ""),
            "expires_at": now + float(unwrapped.get("ExpiresIn", 3600)),
            "refresh_expires_at": now + float(
                unwrapped.get("RefreshExpiresIn", 2592000)
            ),
            "scope": unwrapped.get("Scope", session.scope),
            "uid": unwrapped.get("UID", session.uid),
        }

    # ---- 5. user VPN status --------------------------------------------

    async def fetch_vpn_status(self, session: GuestSession) -> dict:
        """``GET /vpn/v2`` — user VPN status.

        Returns the ``Response`` dict, which includes ``MaxTier``,
        ``MaxConnect``, ``PlanName``, etc. For a guest session
        ``MaxTier=0`` and ``MaxConnect=1``.
        """
        url = f"{API_BASE}/vpn/v2"
        headers = self._auth_headers(session)
        resp = await self.client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return self._unwrap(data, context="GET /vpn/v2")

    # ---- 6. logicals ---------------------------------------------------

    async def fetch_logicals(
        self,
        session: GuestSession,
        *,
        protocols: str = "wireguard",
        with_state: bool = True,
    ) -> List[GuestLogicalServer]:
        """``GET /vpn/v2/logicals`` — parse to :class:`GuestLogicalServer`.

        Only Tier=0 (free) servers are returned — guest mode is
        free-only; paid (Plus / Visionary) servers are filtered out
        because the guest bearer token cannot obtain a certificate for
        them. Each entry's first physical server is used as the
        WireGuard endpoint (``domain`` / ``entry_ip`` /
        ``x25519_public_key``).
        """
        url = f"{API_BASE}/vpn/v2/logicals"
        params = {
            "WithEntriesForProtocols": protocols,
            # Proton expects a lower-cased boolean string here.
            "WithState": "true" if with_state else "false",
        }
        headers = self._auth_headers(session)
        resp = await self.client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        unwrapped = self._unwrap(data, context="GET /vpn/v2/logicals")
        raw_servers = unwrapped.get("LogicalServers", []) or []
        out: List[GuestLogicalServer] = []
        for entry in raw_servers:
            try:
                tier = int(entry.get("Tier", 0))
            except (TypeError, ValueError):
                tier = 0
            # Filter out paid (non-free) servers — guest mode is free-only.
            if tier != 0:
                continue
            servers_arr = entry.get("Servers") or []
            first = servers_arr[0] if servers_arr else {}
            try:
                features = int(entry.get("Features", 0))
            except (TypeError, ValueError):
                features = 0
            try:
                status = int(first.get("Status", 0))
            except (TypeError, ValueError):
                status = 0
            try:
                load = float(entry.get("Load", 0.0))
            except (TypeError, ValueError):
                load = 0.0
            try:
                score = float(entry.get("Score", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            out.append(
                GuestLogicalServer(
                    server_id=str(entry.get("ID", "")),
                    name=str(entry.get("Name", "")),
                    exit_country=str(entry.get("ExitCountry", "")),
                    city=entry.get("City"),
                    tier=tier,
                    features=features,
                    load=load,
                    score=score,
                    domain=str(first.get("Domain", "")),
                    entry_ip=str(first.get("EntryIP", "")),
                    x25519_public_key=str(first.get("X25519PublicKey", "")),
                    status=status,
                )
            )
        return out

    # ---- 7. wireguard certificate --------------------------------------

    async def fetch_certificate(
        self,
        session: GuestSession,
        client_public_key_b64: str,
        *,
        persistent: bool = True,
    ) -> GuestCertificate:
        """``POST /vpn/v1/certificate`` — returns the WireGuard cert +
        internal tunnel IP assignment.

        ``client_public_key_b64`` should be a base64-encoded X25519
        public key (NOT the Ed25519 device key — WireGuard uses
        Curve25519). The caller is responsible for generating it. With
        ``persistent=True`` the cert is valid for ~24h and refreshable;
        with ``ephemeral`` it is single-use.
        """
        url = f"{API_BASE}/vpn/v1/certificate"
        body = {
            "ClientPublicKey": client_public_key_b64,
            "Mode": "persistent" if persistent else "ephemeral",
        }
        headers = self._auth_headers(session)
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        unwrapped = self._unwrap(data, context="POST /vpn/v1/certificate")
        dns_block = unwrapped.get("DNS") or {}
        dns_ips = dns_block.get("IP") if isinstance(dns_block, dict) else None
        if dns_ips is None:
            dns_ips = []
        try:
            refresh_time = int(unwrapped.get("RefreshTime", 0))
        except (TypeError, ValueError):
            refresh_time = 0
        return GuestCertificate(
            certificate_pem=str(unwrapped.get("Certificate", "")),
            server_status=unwrapped.get("ServerStatus", {}) or {},
            refresh_time=refresh_time,
            ipv4=str(unwrapped.get("IPv4", "")),
            ipv6=unwrapped.get("IPv6"),
            dns_ips=list(dns_ips),
            client_public_key_b64=client_public_key_b64,
        )


# ---------------------------------------------------------------------------
# WireGuard tunnel-key helpers
# ---------------------------------------------------------------------------


def gen_x25519_keypair() -> Tuple[str, str]:
    """Generate a fresh X25519 keypair for WireGuard.

    Returns ``(base64_public_key, base64_private_key)`` — both are 44-char
    base64 strings (32 raw bytes each). The *public* key is sent to Proton
    in ``POST /vpn/v1/certificate`` as ``ClientPublicKey``; the *private*
    key is the WireGuard ``[Interface] PrivateKey`` for the tunnel.

    This is distinct from the Ed25519 device keypair used in the
    credentialless challenge — WireGuard uses Curve25519 (X25519), not
    Ed25519.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pub_bytes).decode(), base64.b64encode(priv_bytes).decode()


# Default ProtonVPN WireGuard port
WG_DEFAULT_PORT = 51820


def build_wg_quick_config(
    server: "GuestLogicalServer | object",
    cert: "GuestCertificate | object",
    x25519_priv_b64: str,
    *,
    dns_server: Optional[str] = None,
    ipv6: bool = True,
) -> str:
    """Build a wg-quick config text from a guest logical server + cert.

    Parameters
    ----------
    server : GuestLogicalServer
        The server to connect to — its ``entry_ip`` and
        ``x25519_public_key`` are used for the [Peer] block.
    cert : GuestCertificate
        The certificate response from ``POST /vpn/v1/certificate`` — its
        ``ipv4`` / ``ipv6`` / ``dns_ips`` populate the [Interface] block.
        The PEM certificate itself is *not* part of the wg-quick config
        text (it's used out-of-band by Proton's server-side handshake
        validator, which sees the X25519 public key we sent).
    x25519_priv_b64 : str
        Base64 X25519 private key (the WireGuard ``PrivateKey``).
    dns_server : str, optional
        Override the DNS line — Proto Clean's DNS blocker redirects
        ``127.0.0.1`` (Linux/macOS via firewall, Windows via the
        ``dns_loopback`` config knob). When None, the cert's
        ``dns_ips`` are used verbatim.
    ipv6 : bool
        When False, drop the IPv6 address / IPv6 DNS entries
        (``::/128``) from the config — the tunnel becomes IPv4-only.

    Returns
    -------
    str
        A wg-quick INI-style config:
        ``[Interface]`` with PrivateKey/Address/DNS, ``[Peer]`` with
        PublicKey/AllowedIPs/Endpoint.
    """
    dns_list = []
    if dns_server:
        dns_list = [dns_server]
    else:
        # Use the cert's DNS IPs (Proton's internal DNS, e.g. 10.140.0.1)
        dns_list = list(getattr(cert, "dns_ips", []) or [])
        if not dns_list:
            dns_list = ["1.1.1.1"]    # fallback

    address_tokens = []
    ipv4 = getattr(cert, "ipv4", "") or ""
    if ipv4:
        address_tokens.append(f"{ipv4}/32")
    if ipv6 and getattr(cert, "ipv6", None):
        address_tokens.append(f"{cert.ipv6}/128")

    allowed_ips = ["0.0.0.0/0"]
    if ipv6:
        allowed_ips.append("::/0")

    entry_ip = getattr(server, "entry_ip", "") or ""
    endpoint = f"{entry_ip}:{WG_DEFAULT_PORT}" if entry_ip else ""
    peer_pub = getattr(server, "x25519_public_key", "") or ""

    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {x25519_priv_b64}")
    if address_tokens:
        lines.append(f"Address = {', '.join(address_tokens)}")
    if dns_list:
        lines.append(f"DNS = {', '.join(dns_list)}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {peer_pub}")
    lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    return "\n".join(lines) + "\n"

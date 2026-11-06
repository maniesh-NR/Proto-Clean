"""Guest-mode (credentialless) ProtonVPN API client.

Implements the "Continue as guest" flow used by the official ProtonVPN
clients to obtain a free-tier (Tier=0) VPN session without any account
credentials. The request/response shapes below were transcribed from the
open-source official clients (ProtonMail/protoncore_android
``AuthenticationApi.kt`` + ``ChallengeFrame.kt``, ProtonVPN/android-app
``ProtonVPNRetrofit.kt`` + ``CertificateRequestBody.kt`` +
``Constants.kt``) — do not "simplify" the payloads, the API is strict
about the envelope.

The flow (same one the morphe-patches project exposes by unlocking the
guest server list):

1. ``POST /auth/v4/sessions`` with the anti-abuse ``Payload``
   (a ``vpn-android-v4-challenge-0`` device frame) -> creates an
   *unauthenticated* session: ``AccessToken``/``RefreshToken``/``UID``.
2. ``POST /auth/v4/credentialless`` with the same ``Payload``, bearer-
   authenticated with the anonymous token -> returns the full guest
   session (``Scopes`` including ``vpn``, ``LocalID``, ``EventID``).
3. Standard VPN endpoints (``/vpn/v2``, ``/vpn/v1/logicals``
   (primary, carries live loads — fallback ``/vpn/v2/logicals``),
   ``/vpn/v1/loads``, ``/vpn/v1/certificate``) are then reachable with
   the guest bearer token. Guest tier is always 0 (free servers only).
4. The WireGuard tunnel uses *fixed* addresses (10.2.0.2/32 client,
   10.2.0.1 gateway/DNS) — they are NOT part of the certificate
   response; the cert PEM authenticates the session with Proton's
   local agent (10.2.0.1:65432) inside the tunnel. The WG private key
   is derived from the session's Ed25519 device keypair (official
   flow), NOT generated separately.

This module is async-only (uses ``httpx.AsyncClient``) and has no Qt or
aioquic dependency.
"""

from __future__ import annotations

import base64
import hashlib
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

#: Anti-abuse challenge frame constants (protoncore-android
#: ``challenge/domain/ChallengeUtils.kt``): the device frame is sent
#: under this exact key in the ``Payload`` object of both
#: ``/auth/v4/sessions`` and ``/auth/v4/credentialless``.
CHALLENGE_VERSION = "2.0.7"
CHALLENGE_FRAME_KEY = "vpn-android-v4-challenge-0"

#: WireGuard tunnel constants (ProtonVPN/android-app ``Constants.kt``).
#: Every Proton WG client uses the same fixed addresses — the gateway
#: doubles as the tunnel DNS resolver and hosts the local agent on
#: :data:`LOCAL_AGENT_PORT`.
VPN_CLIENT_IP = "10.2.0.2"
VPN_CLIENT_IP_V6 = "2a07:b944::2:2"
VPN_GATEWAY_IP = "10.2.0.1"
VPN_GATEWAY_IP_V6 = "2a07:b944::2:1"
LOCAL_AGENT_PORT = 65432

#: Default headers that every request to the Proton API must carry. These
#: mimic the official ProtonVPN Android client so the credentialless
#: endpoint recognises us as a legitimate guest-mode caller (the
#: ``x-pm-appversion`` format is ``{platform}-{app}@{version}+{store}``).
#: ``x-pm-uid`` is added per-request by :func:`default_headers`.
GUEST_HEADERS: Dict[str, str] = {
    "User-Agent": "ProtonVPN/5.15.95.5 (Android 14; samsung SM-S901U)",
    "x-pm-appversion": "android-vpn@5.15.95.5+play",
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


def make_challenge_frame() -> dict:
    """Build the device-integrity challenge frame.

    Shape transcribed from protoncore-android ``ChallengeFrame.Device``
    (``challenge/data/src/main/kotlin/.../frame/ChallengeFrame.kt``):
    the server-side anti-abuse check expects these exact ``@SerialName``
    keys (``v``, ``appLang``, ``timezone``, ``deviceName`` …). The values
    describe a plausible stock Android device; the API records but does
    not attest them for guest sessions.
    """
    return {
        "v": CHALLENGE_VERSION,
        "appLang": "en",
        "timezone": "Europe/Zurich",
        "deviceName": 3605,          # stable numeric model id (Build hash)
        "regionCode": "CH",
        "timezoneOffset": 60,
        "isJailbreak": False,
        "preferredContentSize": "1.0",
        "storageCapacity": 128.0,
        "isDarkmodeOn": False,
        "keyboards": ["com.google.android.inputmethod.latin"],
    }


def make_challenge_payload() -> dict:
    """Build the request body for the auth endpoints.

    Both ``POST /auth/v4/sessions`` (unauthenticated session creation,
    protoncore-android ``RequestSessionRequest``) and
    ``POST /auth/v4/credentialless`` (``LoginLessRequest``) wrap the
    device frame in ``{"Payload": {"vpn-android-v4-challenge-0": …}}``.
    """
    return {"Payload": {CHALLENGE_FRAME_KEY: make_challenge_frame()}}


def gen_device_keypair() -> Tuple[str, bytes]:
    """Generate a fresh Ed25519 keypair identifying this installation.

    Returns ``(base64_public_key, raw_32_byte_seed)``. The *public* half
    (in PKIX PEM form, see :func:`ed25519_pub_pem`) is what the official
    clients send to ``POST /vpn/v1/certificate`` as ``ClientPublicKey``;
    the WireGuard private key is *derived* from the same keypair (see
    :func:`ed25519_to_x25519_priv_b64`) — the server converts the
    Ed25519 point to its Montgomery (X25519) form when binding the
    certificate, which is why the two must come from one keypair.

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


def ed25519_pub_pem(priv_bytes: bytes) -> str:
    """Ed25519 public key as a PKIX (SubjectPublicKeyInfo) PEM string.

    This is the exact ``ClientPublicKey`` form the official clients send
    to ``POST /vpn/v1/certificate`` — ProtonVPN/android-app
    ``CertInfo.publicKeyPem`` (gopenpgp ``publicKeyPKIXPem()``) and the
    Linux client's ``KeyHandler.ed25519_pk_pem``. A raw base64 X25519 key
    is *rejected* there with Code 2001 "unable to read the key, please
    provide valid EC key".
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def ed25519_to_x25519_priv_b64(priv_bytes: bytes) -> str:
    """Derive the WireGuard X25519 private key from an Ed25519 seed.

    Same conversion as PyNaCl's ``crypto_sign_ed25519_sk_to_curve25519``
    and gopenpgp's ``KeyPair.toX25519Base64()``: SHA-512 of the 32-byte
    seed, first 32 bytes, RFC 7748-clamped. The official clients use the
    result verbatim as the WireGuard ``[Interface] PrivateKey`` — it
    matches the Montgomery form of the Ed25519 public point sent in the
    certificate request.
    """
    h = bytearray(hashlib.sha512(priv_bytes).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return base64.b64encode(bytes(h)).decode()


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


def _scopes_to_str(resp: dict) -> str:
    """Normalise ``Scopes`` (official: a JSON array of strings) or the
    legacy ``Scope`` string to a single space-joined string."""
    scopes = resp.get("Scopes")
    if isinstance(scopes, (list, tuple)):
        return " ".join(str(s) for s in scopes if s)
    return str(resp.get("Scope", "") or "")


def _expires_in(resp: dict, *keys: str, default: float = 3600.0) -> float:
    """Best-effort token TTL. The official auth responses do not include
    expiry fields — fall back to the conservative default so the caller
    refreshes early rather than late."""
    for k in keys:
        v = resp.get(k)
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
    return default


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
        scope = _scopes_to_str(credless_resp) or _scopes_to_str(anon_resp)
        expires_in = _expires_in(credless_resp, "ExpiresIn", default=3600.0)
        refresh_expires_in = _expires_in(
            credless_resp, "RefreshExpiresIn", default=2592000.0)
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
    """The WireGuard session certificate Proton hands out.

    Returned by ``POST /vpn/v1/certificate``; the ``certificate_pem`` is
    a short-lived PEM certificate that authenticates the session with
    Proton's local agent (``10.2.0.1:65432``) once the tunnel is up.
    ``refresh_time`` / ``expiration_time`` are epoch seconds. The tunnel
    addresses are the fixed constants from ProtonVPN/android-app
    ``Constants.kt`` (they are *not* in the API response): client
    ``10.2.0.2/32`` (+ ``2a07:b944::2:2/128``), gateway/DNS
    ``10.2.0.1`` (+ ``2a07:b944::2:1``).

    ``wg_private_key_b64`` is the X25519 private key *derived from the
    session's Ed25519 device keypair* (official flow: gopenpgp
    ``KeyPair.toX25519Base64()``) — it pairs with the public key the
    request carried, so it is the WireGuard ``[Interface] PrivateKey``.
    """

    certificate_pem: str
    server_status: Dict[str, Any] = field(default_factory=dict)
    refresh_time: int = 0            # epoch seconds
    expiration_time: int = 0         # epoch seconds
    ipv4: str = VPN_CLIENT_IP        # fixed tunnel IP (constant)
    ipv6: Optional[str] = VPN_CLIENT_IP_V6
    dns_ips: List[str] = field(
        default_factory=lambda: [VPN_GATEWAY_IP, VPN_GATEWAY_IP_V6])
    client_public_key_pem: str = ""   # the PKIX PEM sent in the request
    wg_private_key_b64: str = ""      # X25519 form of the same keypair


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
            cert = await auth.fetch_certificate(session)
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

    async def create_anonymous_session(self, device_pub_b64: str = "") -> dict:
        """``POST /auth/v4/sessions`` with the challenge payload.

        Returns the parsed ``Response`` (with ``AccessToken`` /
        ``RefreshToken`` / ``UID`` keys). Uses :attr:`initial_uid` as the
        ``x-pm-uid`` header — the server hasn't assigned a UID yet.
        ``device_pub_b64`` is accepted for call-site compatibility but
        NOT sent: the official unauth-session body carries device
        metadata only (no keys).
        """
        url = f"{API_BASE}/auth/v4/sessions"
        body = make_challenge_payload()
        headers = default_headers(self.initial_uid)
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return self._unwrap(data, context="POST /auth/v4/sessions")

    # ---- 2. credentialless upgrade -------------------------------------

    async def credentialless_upgrade(
        self,
        anonymous_session: dict,
        device_pub_b64: str = "",
    ) -> dict:
        """``POST /auth/v4/credentialless`` authenticated with the
        anonymous ``AccessToken``.

        Returns the parsed ``Response`` — a full guest session whose
        ``Scopes`` array includes ``vpn`` (tier is always 0).
        """
        url = f"{API_BASE}/auth/v4/credentialless"
        body = make_challenge_payload()
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
        # Body shape per protoncore-android ``RefreshSessionRequest`` —
        # the grant fields are required, not decorative.
        body = {
            "UID": session.uid,
            "RefreshToken": session.refresh_token,
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RedirectURI": "http://protonmail.ch",
        }
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
            "expires_at": now + _expires_in(unwrapped, "ExpiresIn"),
            "refresh_expires_at": now + _expires_in(
                unwrapped, "RefreshExpiresIn", default=2592000.0),
            "scope": _scopes_to_str(unwrapped) or session.scope,
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

    @staticmethod
    def _parse_logical_entry(entry: dict) -> Optional[GuestLogicalServer]:
        """Parse one raw logical-server JSON entry (v1 or v2 shape).

        Returns ``None`` for entries that are not free-tier (guest mode
        is free-only). ``Status`` is read from the logical level first
        (v1: int; v2: int-or-bool per the official model's
        ``VpnIntToBoolSerializer``), then from the first physical server.
        """
        try:
            tier = int(entry.get("Tier", 0))
        except (TypeError, ValueError):
            tier = 0
        # Filter out paid (non-free) servers — guest mode is free-only.
        if tier != 0:
            return None
        servers_arr = entry.get("Servers") or []
        first = servers_arr[0] if servers_arr else {}
        try:
            features = int(entry.get("Features", 0))
        except (TypeError, ValueError):
            features = 0

        def _status(obj: dict) -> int:
            v = obj.get("Status")
            if isinstance(v, bool):
                return 1 if v else 0
            try:
                return 1 if int(v) == 1 else 0
            except (TypeError, ValueError):
                return 0

        status = _status(entry) if "Status" in entry else _status(first)
        try:
            load = float(entry.get("Load", 0.0))
        except (TypeError, ValueError):
            load = 0.0
        try:
            score = float(entry.get("Score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        return GuestLogicalServer(
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

    async def _get_json(self, url: str, session: GuestSession,
                        params: Optional[dict], context: str) -> dict:
        resp = await self.client.get(
            url, params=params, headers=self._auth_headers(session))
        resp.raise_for_status()
        return self._unwrap(resp.json(), context=context)

    async def fetch_loads(self, session: GuestSession) -> Dict[str, float]:
        """``GET /vpn/v1/loads`` — live per-logical loads.

        The endpoint the official clients poll every ~15 minutes (the
        Linux client's ``MixinEndpointV1.LOADS``). Returns
        ``{server_id: load_percent}``.
        """
        data = await self._get_json(f"{API_BASE}/vpn/v1/loads", session,
                                    None, context="GET /vpn/v1/loads")
        out: Dict[str, float] = {}
        for item in data.get("LogicalServers", []) or []:
            sid = str(item.get("ID", ""))
            try:
                out[sid] = float(item.get("Load", 0.0))
            except (TypeError, ValueError):
                continue
        return out

    async def fetch_logicals(
        self,
        session: GuestSession,
        *,
        with_state: bool = True,
    ) -> List[GuestLogicalServer]:
        """Free-tier (Tier=0) logical servers **with live loads**.

        Endpoint strategy (mirrors the official clients):

        * **Primary: ``GET /vpn/v1/logicals?SecureCoreFilter=all&
          WithState=true``** — the exact URL of the official Linux
          client's v1 flow; the v1 response carries real per-logical
          ``Load`` values inline. Each entry's first physical server is
          the WireGuard endpoint (``domain`` / ``entry_ip`` /
          ``x25519_public_key``).
        * **Fallback: ``GET /vpn/v2/logicals`` with
          ``WithEntriesForProtocols=wireguard``** — used when v1 is
          unavailable. The v2 payload reports loads as zero (official
          clients compute them from the binary status blob
          ``/vpn/v2/status/{StatusID}/binary``), so after a v2 fetch the
          live loads are merged in from :meth:`fetch_loads` when that
          endpoint is reachable — without it every load would read 0%.

        Paid (Plus / Visionary) servers are filtered out: guest mode is
        free-only and the guest bearer token cannot obtain a certificate
        for them.
        """
        raw: Optional[List[dict]] = None
        try:
            data = await self._get_json(
                f"{API_BASE}/vpn/v1/logicals", session,
                {"SecureCoreFilter": "all",
                 "WithState": "true" if with_state else "false"},
                context="GET /vpn/v1/logicals")
            raw = data.get("LogicalServers") or []
        except Exception:  # noqa: BLE001 — v1 unavailable, fall back to v2
            raw = None

        from_v2 = False
        if not raw:
            from_v2 = True
            data = await self._get_json(
                f"{API_BASE}/vpn/v2/logicals", session,
                {"WithEntriesForProtocols": "wireguard",
                 "WithState": "true" if with_state else "false"},
                context="GET /vpn/v2/logicals")
            raw = data.get("LogicalServers") or []

        out = [s for s in (self._parse_logical_entry(e) for e in raw)
               if s is not None]

        if from_v2:
            # v2 payloads report zero loads — merge the live values from
            # /vpn/v1/loads when available (best-effort).
            try:
                loads = await self.fetch_loads(session)
                for s in out:
                    if s.server_id in loads:
                        s.load = loads[s.server_id]
            except Exception:  # noqa: BLE001 — loads are best-effort
                pass
        return out

    # ---- 7. wireguard certificate --------------------------------------

    async def fetch_certificate(
        self,
        session: GuestSession,
        *,
        persistent: bool = True,
    ) -> GuestCertificate:
        """``POST /vpn/v1/certificate`` — returns the WireGuard session
        certificate.

        Body and response shapes per ProtonVPN/android-app
        ``CertificateRequestBody`` / ``CertificateResponseBody``:
        ``{ClientPublicKey, ClientPublicKeyMode: "EC", DeviceName,
        Mode: "session", Features: []}`` -> ``{Certificate,
        ExpirationTime, RefreshTime}``. The response carries NO tunnel
        addresses — every Proton WG client uses the fixed
        :data:`VPN_CLIENT_IP` / :data:`VPN_GATEWAY_IP` constants (the
        certificate authenticates the session against the local agent
        inside the tunnel), so the returned dataclass populates
        ``ipv4``/``ipv6``/``dns_ips`` from those constants.

        **Key flow (the official one):** the ``ClientPublicKey`` is the
        session's Ed25519 *device* public key as a PKIX
        (SubjectPublicKeyInfo) PEM — gopenpgp ``publicKeyPKIXPem()`` in
        the Android app, ``KeyHandler.ed25519_pk_pem`` in the Linux
        client. The WireGuard private key is *derived from the same
        keypair* (X25519 form of the seed, see
        :func:`ed25519_to_x25519_priv_b64`) and returned as
        ``GuestCertificate.wg_private_key_b64`` — the server converts the
        Ed25519 point to its Montgomery form when binding the
        certificate, so the two halves always match. Sending a raw
        base64 X25519 key instead is rejected with Code 2001
        "unable to read the key, please provide valid EC key".
        """
        url = f"{API_BASE}/vpn/v1/certificate"
        pub_pem = ed25519_pub_pem(session.device_ed25519_priv)
        body = {
            "ClientPublicKey": pub_pem,
            "ClientPublicKeyMode": "EC",
            "DeviceName": "SM-S901U",
            "Mode": "session",
            "Features": [],
        }
        headers = self._auth_headers(session)
        resp = await self.client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        unwrapped = self._unwrap(data, context="POST /vpn/v1/certificate")
        try:
            refresh_time = int(unwrapped.get("RefreshTime", 0))
        except (TypeError, ValueError):
            refresh_time = 0
        try:
            expiration_time = int(unwrapped.get("ExpirationTime", 0))
        except (TypeError, ValueError):
            expiration_time = 0
        return GuestCertificate(
            certificate_pem=str(unwrapped.get("Certificate", "")),
            server_status=unwrapped.get("ServerStatus", {}) or {},
            refresh_time=refresh_time,
            expiration_time=expiration_time,
            ipv4=VPN_CLIENT_IP,
            ipv6=VPN_CLIENT_IP_V6 if unwrapped.get("IPv6") is not False else None,
            dns_ips=[VPN_GATEWAY_IP, VPN_GATEWAY_IP_V6],
            client_public_key_pem=pub_pem,
            wg_private_key_b64=ed25519_to_x25519_priv_b64(
                session.device_ed25519_priv),
        )


# ---------------------------------------------------------------------------
# WireGuard tunnel-key helpers
# ---------------------------------------------------------------------------


def gen_x25519_keypair() -> Tuple[str, str]:
    """Generate a fresh standalone X25519 keypair.

    Returns ``(base64_public_key, base64_private_key)`` — both are 44-char
    base64 strings (32 raw bytes each).

    NOTE: the guest-mode certificate flow no longer uses this — the
    official clients derive the WireGuard keypair from the session's
    Ed25519 device key (see :func:`ed25519_to_x25519_priv_b64`) so the
    ``ClientPublicKey`` PEM and the WG private key always pair up. This
    helper remains for ad-hoc key generation (e.g. tests and future
    engines).
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
    # Match the official clients: keepalive so the handshake fires even
    # with no user traffic (avoids stuck-in-CONNECTING on some devices).
    lines.append("PersistentKeepalive = 60")
    return "\n".join(lines) + "\n"

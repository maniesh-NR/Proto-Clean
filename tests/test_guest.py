"""Tests for ``proto_clean.proton.guest`` — the guest-mode API client.

All tests run against an in-memory ``httpx.MockTransport`` (no real
network) via the :class:`_FakeApi` helper. Each test programs the routes
it cares about, drives the ``GuestAuth`` async methods inside
``asyncio.run``, and asserts on the recorded requests / parsed results.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid

import httpx
import pytest

from proto_clean.proton.guest import (
    CHALLENGE_FRAME_KEY,
    GUEST_HEADERS,
    GuestAuth,
    GuestAuthError,
    GuestCertificate,
    GuestLogicalServer,
    GuestSession,
    default_headers,
    gen_device_keypair,
    make_challenge_payload,
)


# ---------------------------------------------------------------------------
# Fake API harness
# ---------------------------------------------------------------------------


class _FakeApi:
    """In-memory Proton API with request recording.

    Call :meth:`set` to program a response for a ``(method, path)`` route.
    The recorded request tuples (``method, path, body, headers``) are
    available on :attr:`requests` for assertions.
    """

    def __init__(self) -> None:
        self.requests = []  # list of (method, path, body, headers)
        self.routes = {}    # (method, path) -> Response | callable

    def set(self, method: str, path: str, response) -> None:
        """Program a response for ``(method, path)``.

        ``response`` may be either an ``httpx.Response`` (returned as-is)
        or a callable taking the ``httpx.Request`` and returning a
        ``httpx.Response``.
        """
        self.routes[(method, path)] = response

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = None
        if request.content:
            try:
                body = json.loads(request.content.decode("utf-8"))
            except ValueError:
                body = None
        headers = {k: v for k, v in request.headers.items()}
        self.requests.append((request.method, path, body, headers))
        key = (request.method, path)
        if key in self.routes:
            r = self.routes[key]
            return r(request) if callable(r) else r
        return httpx.Response(
            404, text="unknown route: %s %s" % (request.method, path)
        )

    def client(self, **kw) -> httpx.AsyncClient:
        kw.setdefault("transport", httpx.MockTransport(self.handler))
        return httpx.AsyncClient(**kw)

    def find(self, method: str, path: str):
        """Return the first recorded request matching (method, path)."""
        for m, p, b, h in self.requests:
            if m == method and p == path:
                return b, h
        raise LookupError("no recorded request for %s %s" % (method, path))


def _ok(response: dict) -> httpx.Response:
    """Wrap a payload in Proton's success envelope ``{Code:1000, Response}``."""
    return httpx.Response(200, json={"Code": 1000, "Response": response})


# ---------------------------------------------------------------------------
# 1. headers
# ---------------------------------------------------------------------------


def test_default_headers_include_required_fields():
    h = default_headers("abc")
    assert h["User-Agent"].startswith("ProtonVPN/")
    assert h["x-pm-appversion"] == "android-vpn@5.15.95.5+play"
    assert h["x-pm-apiversion"] == "4"
    assert h["x-pm-uid"] == "abc"
    assert h["Accept"] == "application/vnd.protonmail.v1+json"
    # And the constant mirrors these (minus the per-request uid).
    assert GUEST_HEADERS["x-pm-appversion"] == "android-vpn@5.15.95.5+play"


# ---------------------------------------------------------------------------
# 2. challenge payload shape
# ---------------------------------------------------------------------------


def test_make_challenge_payload_shape():
    # Official shape (protoncore-android RequestSessionRequest /
    # LoginLessRequest + ChallengeFrame.Device): the device frame is
    # wrapped in {"Payload": {"vpn-android-v4-challenge-0": ...}}.
    payload = make_challenge_payload()
    assert set(payload.keys()) == {"Payload"}
    assert set(payload["Payload"].keys()) == {CHALLENGE_FRAME_KEY}
    frame = payload["Payload"][CHALLENGE_FRAME_KEY]
    assert set(frame.keys()) == {
        "v", "appLang", "timezone", "deviceName", "regionCode",
        "timezoneOffset", "isJailbreak", "preferredContentSize",
        "storageCapacity", "isDarkmodeOn", "keyboards",
    }
    # Values match a plausible stock device (the server records but does
    # not attest them for credentialless sessions).
    assert frame["v"] == "2.0.7"
    assert frame["appLang"] == "en"
    assert isinstance(frame["deviceName"], int)
    assert frame["isJailbreak"] is False
    assert frame["storageCapacity"] > 0
    assert isinstance(frame["keyboards"], list)


# ---------------------------------------------------------------------------
# 3. device keypair
# ---------------------------------------------------------------------------


def test_gen_device_keypair_returns_base64_pub_and_32_byte_priv():
    pub_b64, priv_bytes = gen_device_keypair()
    assert isinstance(pub_b64, str)
    assert isinstance(priv_bytes, bytes)
    # Ed25519 raw public key is 32 bytes -> base64 is 44 chars (no padding
    # issues since 32 is a multiple of 3).
    assert len(pub_b64) == 44
    decoded = base64.b64decode(pub_b64)
    assert len(decoded) == 32
    assert len(priv_bytes) == 32
    # Two calls produce independent keypairs.
    pub2, _ = gen_device_keypair()
    assert pub2 != pub_b64


# ---------------------------------------------------------------------------
# 4. GuestSession.from_response
# ---------------------------------------------------------------------------


def test_GuestSession_from_response():
    now = time.time()
    anon = {
        "AccessToken": "anon-tok",
        "RefreshToken": "anon-refresh",
        "UID": "anon-uid",
        "ExpiresIn": 3600,
        "RefreshExpiresIn": 2592000,
        "Scope": "self",
    }
    # Official LoginResponse uses a Scopes ARRAY (no ExpiresIn field).
    credless = {
        "AccessToken": "guest-tok",
        "RefreshToken": "guest-refresh",
        "UID": "guest-uid",
        "UserID": "user-uid",
        "EventID": "event-1",
        "LocalID": 42,
        "Scopes": ["self", "vpn"],
    }
    pub = base64.b64encode(bytes(range(32))).decode()
    priv = bytes(range(32))
    sess = GuestSession.from_response(anon, credless, pub, priv)
    # The credentialless AccessToken wins.
    assert sess.access_token == "guest-tok"
    assert sess.refresh_token == "guest-refresh"
    assert sess.uid == "guest-uid"
    assert sess.scope == "self vpn"
    # expires_at is in the future.
    assert sess.expires_at > now
    assert sess.refresh_expires_at > now
    # Guest mode defaults.
    assert sess.max_tier == 0
    assert sess.max_connect == 1
    assert sess.plan_name == "guest"
    # Device key binding.
    assert sess.device_ed25519_pub_b64 == pub
    assert sess.device_ed25519_priv == priv


# ---------------------------------------------------------------------------
# 5. create_anonymous_session
# ---------------------------------------------------------------------------


def test_create_anonymous_session_posts_correct_body():
    api = _FakeApi()
    api.set(
        "POST", "/auth/v4/sessions",
        _ok({"AccessToken": "anon-tok", "RefreshToken": "anon-refresh",
             "UID": "anon-uid", "ExpiresIn": 3600, "Scope": "self"}),
    )
    auth = GuestAuth(client=api.client(), uid="initial-uid-123")

    async def go():
        return await auth.create_anonymous_session("devpub")

    result = asyncio.run(go())
    assert result["AccessToken"] == "anon-tok"
    body, headers = api.find("POST", "/auth/v4/sessions")
    # Official body: the anti-abuse device frame wrapped in Payload.
    assert "Payload" in body
    assert CHALLENGE_FRAME_KEY in body["Payload"]
    frame = body["Payload"][CHALLENGE_FRAME_KEY]
    assert frame["v"] == "2.0.7"
    # No device keys are sent (the official flow sends metadata only).
    assert "DevicePublicKeys" not in str(body)
    # The initial uid is used as the x-pm-uid header on this first request.
    assert headers["x-pm-uid"] == "initial-uid-123"
    # Required app headers are present.
    assert headers["x-pm-appversion"] == "android-vpn@5.15.95.5+play"
    assert headers["x-pm-apiversion"] == "4"
    # No bearer auth on the very first request.
    assert "authorization" not in headers


# ---------------------------------------------------------------------------
# 6. credentialless_upgrade uses anonymous bearer
# ---------------------------------------------------------------------------


def test_credentialless_upgrade_uses_anonymous_bearer():
    api = _FakeApi()
    api.set(
        "POST", "/auth/v4/credentialless",
        _ok({"AccessToken": "guest-tok", "RefreshToken": "guest-refresh",
             "UID": "guest-uid", "ExpiresIn": 600, "Scope": "self vpn"}),
    )
    auth = GuestAuth(client=api.client())

    anon = {"AccessToken": "anon-tok", "RefreshToken": "anon-refresh",
            "UID": "anon-uid"}

    async def go():
        return await auth.credentialless_upgrade(anon, "devpub")

    result = asyncio.run(go())
    assert result["AccessToken"] == "guest-tok"
    body, headers = api.find("POST", "/auth/v4/credentialless")
    # Path is the credentialless endpoint.
    assert ("POST", "/auth/v4/credentialless") in [(m, p) for m, p, _, _ in api.requests]
    # Authorization uses the anonymous AccessToken as bearer.
    assert headers["authorization"] == "Bearer anon-tok"
    # x-pm-uid is the anonymous UID returned by step 1.
    assert headers["x-pm-uid"] == "anon-uid"
    # Body still carries the challenge payload (same official shape).
    assert "Payload" in body
    assert CHALLENGE_FRAME_KEY in body["Payload"]
    assert body["Payload"][CHALLENGE_FRAME_KEY]["v"] == "2.0.7"


# ---------------------------------------------------------------------------
# 7. login end-to-end
# ---------------------------------------------------------------------------


def test_login_end_to_end():
    api = _FakeApi()
    api.set(
        "POST", "/auth/v4/sessions",
        _ok({"AccessToken": "anon-tok", "RefreshToken": "anon-refresh",
             "UID": "anon-uid", "ExpiresIn": 3600, "Scope": "self"}),
    )
    api.set(
        "POST", "/auth/v4/credentialless",
        _ok({"AccessToken": "guest-tok", "RefreshToken": "guest-refresh",
             "UID": "guest-uid", "ExpiresIn": 600, "Scope": "self vpn"}),
    )
    auth = GuestAuth(client=api.client())

    async def go():
        return await auth.login()

    sess = asyncio.run(go())
    assert isinstance(sess, GuestSession)
    assert sess.access_token == "guest-tok"
    assert sess.refresh_token == "guest-refresh"
    assert sess.uid == "guest-uid"
    assert sess.scope == "self vpn"
    assert sess.max_tier == 0
    # Two POSTs were made in sequence: /sessions then /credentialless.
    paths = [p for m, p, _, _ in api.requests if m == "POST"]
    assert paths == ["/auth/v4/sessions", "/auth/v4/credentialless"]
    # The same device pubkey was used in both challenge payloads.
    _, h1 = api.find("POST", "/auth/v4/sessions")
    _, h2 = api.find("POST", "/auth/v4/credentialless")
    # session is bound to the device key generated in login()
    assert sess.device_ed25519_pub_b64
    assert len(sess.device_ed25519_priv) == 32


# ---------------------------------------------------------------------------
# 8. fetch_logicals filters paid servers
# ---------------------------------------------------------------------------


def _logical_server(server_id, name, country, tier, **kw):
    """Build a single logical-server dict the way the API returns it."""
    physical = kw.get("physical", {
        "Domain": "us-free-01.protonvpn.com",
        "EntryIP": "185.159.158.1",
        "X25519PublicKey": "abcPubKeyBase64==",
        "Status": 1,
    })
    return {
        "ID": server_id,
        "Name": name,
        "ExitCountry": country,
        "City": kw.get("city"),
        "Tier": tier,
        "Features": kw.get("features", 0),
        "Load": kw.get("load", 12.5),
        "Score": kw.get("score", 1.05),
        "Servers": [physical] if kw.get("physical") is not False else [],
    }


def test_fetch_logicals_filters_paid_servers():
    api = _FakeApi()
    logicals = [
        _logical_server("s-free-1", "US-FREE#1", "US", tier=0),
        _logical_server("s-plus-1", "US-PLUS#1", "US", tier=2,
                        physical={
                            "Domain": "us-plus-01.protonvpn.com",
                            "EntryIP": "185.159.159.2",
                            "X25519PublicKey": "plusPub==",
                            "Status": 1,
                        }),
        _logical_server("s-free-2", "JP-FREE#1", "JP", tier=0,
                        city="Tokyo",
                        features=1,   # P2P
                        load=42.0, score=2.0,
                        physical={
                            "Domain": "jp-free-01.protonvpn.com",
                            "EntryIP": "185.159.158.9",
                            "X25519PublicKey": "jpPub==",
                            "Status": 1,
                        }),
    ]
    api.set("GET", "/vpn/v2/logicals",
            _ok({"LogicalServers": logicals}))
    auth = GuestAuth(client=api.client())
    sess = GuestSession(
        access_token="guest-tok", refresh_token="guest-refresh",
        uid="guest-uid", expires_at=time.time() + 3600,
        refresh_expires_at=time.time() + 9999, scope="self vpn",
        device_ed25519_pub_b64="devpub", device_ed25519_priv=bytes(32),
    )

    async def go():
        return await auth.fetch_logicals(sess)

    out = asyncio.run(go())
    # Only Tier=0 servers survive the filter.
    assert len(out) == 2
    assert all(isinstance(s, GuestLogicalServer) for s in out)
    ids = {s.server_id for s in out}
    assert ids == {"s-free-1", "s-free-2"}
    # First physical server is parsed correctly.
    free1 = next(s for s in out if s.server_id == "s-free-1")
    assert free1.entry_ip == "185.159.158.1"
    assert free1.x25519_public_key == "abcPubKeyBase64=="
    assert free1.domain == "us-free-01.protonvpn.com"
    assert free1.exit_country == "US"
    assert free1.city is None
    assert free1.tier == 0
    assert free1.status == 1
    free2 = next(s for s in out if s.server_id == "s-free-2")
    assert free2.city == "Tokyo"
    assert free2.exit_country == "JP"
    assert free2.features == 1
    assert free2.load == 42.0
    assert free2.score == 2.0


# ---------------------------------------------------------------------------
# 9. fetch_certificate parses response
# ---------------------------------------------------------------------------


def test_fetch_certificate_parses_response():
    api = _FakeApi()
    cert_pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
    # Official response shape (CertificateResponseBody): only the PEM
    # and the refresh/expiry timestamps — tunnel addresses are fixed
    # constants, not part of the response.
    api.set("POST", "/vpn/v1/certificate",
            _ok({
                "Certificate": cert_pem,
                "ExpirationTime": 1735786000,
                "RefreshTime": 1735689600,
            }))
    auth = GuestAuth(client=api.client())
    sess = GuestSession(
        access_token="guest-tok", refresh_token="guest-refresh",
        uid="guest-uid", expires_at=time.time() + 3600,
        refresh_expires_at=time.time() + 9999, scope="self vpn",
        device_ed25519_pub_b64="devpub", device_ed25519_priv=bytes(32),
    )

    async def go():
        return await auth.fetch_certificate(sess, "wgpub==")

    cert = asyncio.run(go())
    assert isinstance(cert, GuestCertificate)
    assert cert.certificate_pem == cert_pem
    # Tunnel addresses are the fixed constants from Constants.kt.
    assert cert.ipv4 == "10.2.0.2"
    assert cert.ipv6 == "2a07:b944::2:2"
    assert cert.dns_ips == ["10.2.0.1", "2a07:b944::2:1"]
    assert cert.refresh_time == 1735689600
    assert cert.expiration_time == 1735786000
    assert cert.client_public_key_b64 == "wgpub=="
    # Body matches CertificateRequestBody from the official app.
    body, headers = api.find("POST", "/vpn/v1/certificate")
    assert body["ClientPublicKey"] == "wgpub=="
    assert body["ClientPublicKeyMode"] == "EC"
    assert body["DeviceName"]
    assert body["Mode"] == "session"
    assert body["Features"] == []
    # Bearer auth used.
    assert headers["authorization"] == "Bearer guest-tok"


# ---------------------------------------------------------------------------
# 10. refresh posts correct body
# ---------------------------------------------------------------------------


def test_refresh_posts_correct_body():
    api = _FakeApi()
    api.set("POST", "/auth/v4/refresh",
            _ok({"AccessToken": "new-tok", "RefreshToken": "new-refresh",
                 "UID": "guest-uid", "ExpiresIn": 600, "Scope": "self vpn"}))
    auth = GuestAuth(client=api.client())
    sess = GuestSession(
        access_token="old-tok", refresh_token="old-refresh",
        uid="guest-uid", expires_at=time.time() - 10,
        refresh_expires_at=time.time() + 9999, scope="self vpn",
        device_ed25519_pub_b64="devpub", device_ed25519_priv=bytes(32),
    )

    async def go():
        return await auth.refresh(sess)

    new = asyncio.run(go())
    assert new["access_token"] == "new-tok"
    assert new["refresh_token"] == "new-refresh"
    assert new["expires_at"] > time.time()
    assert new["scope"] == "self vpn"
    body, headers = api.find("POST", "/auth/v4/refresh")
    assert body["RefreshToken"] == "old-refresh"
    assert body["UID"] == "guest-uid"
    # Grant fields per protoncore-android RefreshSessionRequest (required).
    assert body["ResponseType"] == "token"
    assert body["GrantType"] == "refresh_token"
    assert body["RedirectURI"] == "http://protonmail.ch"
    # Refresh uses the UID header but no bearer token.
    assert headers["x-pm-uid"] == "guest-uid"
    assert "authorization" not in headers
    # session is not mutated.
    assert sess.access_token == "old-tok"
    assert sess.refresh_token == "old-refresh"


# ---------------------------------------------------------------------------
# 11. API error code raises GuestAuthError
# ---------------------------------------------------------------------------


def test_api_error_code_raises_GuestAuthError():
    api = _FakeApi()
    api.set(
        "POST", "/auth/v4/sessions",
        httpx.Response(200, json={
            "Code": 8002,
            "Response": {},
            "Error": {"Message": "bad challenge"},
        }),
    )
    auth = GuestAuth(client=api.client())

    async def go():
        await auth.create_anonymous_session("devpub")

    with pytest.raises(GuestAuthError) as exc_info:
        asyncio.run(go())
    assert "bad challenge" in str(exc_info.value)
    assert "8002" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 12. initial_uid is random uuid
# ---------------------------------------------------------------------------


def test_initial_uid_is_random_uuid():
    a = GuestAuth(client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(404))))
    b = GuestAuth(client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(404))))
    assert a.initial_uid != b.initial_uid
    # Each is a valid uuid4 string.
    u = uuid.UUID(a.initial_uid)
    assert u.version == 4
    u2 = uuid.UUID(b.initial_uid)
    assert u2.version == 4
    # An explicit uid is honoured.
    c = GuestAuth(client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(404))), uid="fixed-uid")
    assert c.initial_uid == "fixed-uid"

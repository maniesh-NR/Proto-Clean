"""Integration tests for guest-mode wiring in the Controller.

These tests exercise the controller's guest-mode plumbing (login_guest_async
→ _login_guest_worker → _refresh_guest_servers_worker → _connect_guest_worker)
without touching the real Proton API or requiring a Qt binding. A fake
GuestAuth stub replaces the network layer; an asyncio event loop is
spun up on a background thread exactly like the production code.
"""

from __future__ import annotations

import asyncio
import base64
import os
import threading
import time
import types
from typing import List

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from proto_clean import controller as ctl_mod
from proto_clean import credentials as creds
from proto_clean.controller import Controller, State
from proto_clean.proton import guest as guest_mod
from proto_clean.proton.guest import (
    GuestAuth,
    GuestAuthError,
    GuestCertificate,
    GuestLogicalServer,
    GuestSession,
    build_wg_quick_config,
    gen_x25519_keypair,
)
from proto_clean.servers.models import LogicalServer, PhysicalServer


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _FakeGuestAuth:
    """Stand-in for GuestAuth that returns canned responses synchronously."""

    def __init__(self, *, login_session: GuestSession = None,
                 logicals: List[GuestLogicalServer] = None,
                 cert: GuestCertificate = None,
                 refresh_payload: dict = None,
                 raise_on_login: Exception = None) -> None:
        self._login_session = login_session
        self._logicals = logicals or []
        self._cert = cert
        self._refresh_payload = refresh_payload or {}
        self._raise_on_login = raise_on_login
        self.closed = False
        self.login_calls = 0
        self.logicals_calls = 0
        self.cert_calls = 0
        self.refresh_calls = 0

    async def login(self) -> GuestSession:
        self.login_calls += 1
        if self._raise_on_login:
            raise self._raise_on_login
        return self._login_session

    async def fetch_logicals(self, session, *, with_state=True) -> List[GuestLogicalServer]:
        self.logicals_calls += 1
        return list(self._logicals)

    async def fetch_certificate(self, session, *, persistent=True) -> GuestCertificate:
        self.cert_calls += 1
        return self._cert

    async def refresh(self, session) -> dict:
        self.refresh_calls += 1
        return dict(self._refresh_payload)

    async def close(self) -> None:
        self.closed = True


def _make_session() -> GuestSession:
    return GuestSession(
        access_token="guest-access-token",
        refresh_token="guest-refresh-token",
        uid="guest-uid-123",
        expires_at=time.time() + 3600,
        refresh_expires_at=time.time() + 2592000,
        scope="self vpn",
        device_ed25519_pub_b64="dGVzdC1lZDI1NTE5LXB1Yg==",
        device_ed25519_priv=b"\x01" * 32,
        max_tier=0, max_connect=1, plan_name="guest",
    )


def _make_logical(name="US-FREE#1", country="US",
                  entry_ip="1.2.3.4", wg_pk="serverWgPubKeyBase64==") -> GuestLogicalServer:
    return GuestLogicalServer(
        server_id=f"{name}-id",
        name=name,
        exit_country=country,
        city="New York",
        tier=0,
        features=0,
        load=20.0,
        score=0.5,
        domain=f"{name}.protonvpn.com",
        entry_ip=entry_ip,
        x25519_public_key=wg_pk,
        status=1,
    )


def _make_cert() -> GuestCertificate:
    return GuestCertificate(
        certificate_pem="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        server_status={},
        refresh_time=int(time.time()) + 86400,
        ipv4="10.2.0.5",
        ipv6=None,
        dns_ips=["10.140.0.1"],
        client_public_key_pem="-----BEGIN PUBLIC KEY-----\nFAKEPUB\n-----END PUBLIC KEY-----\n",
        wg_private_key_b64="clientWgPrivKeyBase64==",
    )


# ---------------------------------------------------------------------------
# Fixture — a Controller with __init__ skipped and only the fields we need
# for the guest path set up. GuestAuth is replaced with _FakeGuestAuth and
# a real asyncio loop runs on a daemon thread.
# ---------------------------------------------------------------------------


@pytest.fixture()
def guest_controller(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "CREDENTIALS_FILE", tmp_path / "creds.json")
    # Bypass keyring entirely so tests don't touch the real secret service.
    monkeypatch.setattr(creds, "_keyring", lambda: (None, None))
    # Skip the helper gate.
    monkeypatch.setattr(ctl_mod, "helper_installed", lambda: True)
    # Skip TunnelManager — we don't bring up a real tunnel here.
    monkeypatch.setattr(ctl_mod, "TunnelManager",
                        lambda: types.SimpleNamespace(
                            up=lambda *a, **k: {},
                            down=lambda: True,
                            protocol="wireguard"))

    ctl = Controller.__new__(Controller)
    ctl.settings = ctl_mod.load_settings()
    ctl.settings.netshield.enabled = False
    ctl.settings.port_forward.request_in_config = False
    ctl.settings.autoconnect_fastest = False
    ctl.settings.kill_switch.enabled = False
    ctl.settings.split_tunnel.enabled = False
    ctl.settings.cache_configs = False
    ctl.settings.advanced.ipv6_support = True

    ctl.state = State.LOGGED_OUT
    ctl.state_detail = ""
    ctl.session = types.SimpleNamespace(logged_in=False, user_plan_hint=None,
                                        logout=lambda: None)
    ctl.downloads = types.SimpleNamespace()
    ctl.config_cache = types.SimpleNamespace()
    ctl.store = ctl_mod.ServerStore()
    ctl.store.replace([])
    ctl.dns = None
    ctl.dns_thread_lock = threading.Lock()
    ctl._blocklist_lock = threading.Lock()
    ctl._op_lock = threading.Lock()
    ctl._threads = []
    ctl.on_state = lambda s, d: None
    ctl.on_servers = lambda s: None
    ctl.on_stats = lambda s: None
    ctl.on_port = lambda p: None
    ctl.messages = []
    ctl.on_message = lambda t, l: ctl.messages.append((t, l))
    ctl.on_blocklists = lambda e: None
    ctl.totp_provider = lambda: None
    ctl.tunnel = None
    ctl.monitor = None
    ctl.port_forwarder = None
    ctl.current_server = None
    ctl.connected_via = {}
    ctl.helper_ready = lambda: True
    ctl.guest_session = None
    ctl.guest_auth = None
    ctl._guest_loop = None
    ctl._proxy_listeners = []
    ctl.xray = types.SimpleNamespace()
    ctl._protocol_engine = None
    ctl.samizdat = types.SimpleNamespace()
    ctl.bond = types.SimpleNamespace()
    ctl.proxy_state = "off"
    ctl._proxy_lock = threading.Lock()
    ctl.bond_state = "off"
    ctl._bond_listeners = []
    ctl._bond_lock = threading.Lock()
    ctl.blocklists = types.SimpleNamespace()
    ctl._apply_browser_proxy = lambda: None
    ctl.on_login_event = lambda k, d: None
    ctl._bring_up = lambda config_text, server: {}
    ctl._set_connected = lambda server, sid, via_cache=True, exact=True: None
    ctl._teardown_partial = lambda: None
    ctl._harvest_configs_worker = lambda: None
    ctl.update_blocklists_async = lambda *a, **k: None
    yield ctl
    # Teardown: stop the guest loop if it was started.
    if ctl._guest_loop is not None:
        try:
            ctl._guest_loop.call_soon_threadsafe(ctl._guest_loop.stop)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_is_guest_is_false_by_default(guest_controller):
    assert guest_controller.is_guest() is False


def test_login_guest_async_sets_mode_and_spawns_worker(guest_controller, monkeypatch):
    """login_guest_async records the request and spawns _login_worker."""
    spawned = []
    monkeypatch.setattr(guest_controller, "_spawn",
                        lambda fn, name: spawned.append((fn, name)))
    guest_controller.login_guest_async()
    assert guest_controller._login_request == {"mode": "guest"}
    assert len(spawned) == 1
    fn, name = spawned[0]
    assert name == "proto_clean-guest-login"
    assert fn == guest_controller._login_worker


def test_guest_login_persists_session_and_marks_logged_in(guest_controller, monkeypatch):
    """A successful guest login stores the session, sets guest_session,
    and transitions to LOGGED_IN with the "guest mode" detail."""
    session = _make_session()
    fake_auth = _FakeGuestAuth(login_session=session,
                               logicals=[_make_logical()],
                               cert=_make_cert())
    # Controller imports GuestAuth into its own namespace, so patch there.
    monkeypatch.setattr(ctl_mod, "GuestAuth", lambda: fake_auth)

    state_log = []
    guest_controller.on_state = lambda s, d: state_log.append((s, d))
    guest_controller.on_login_event = lambda k, d: None

    # Run the worker synchronously (it's normally spawned on a thread).
    # _login_worker acquires the op lock itself.
    guest_controller._login_request = {"mode": "guest"}
    guest_controller._login_worker()

    assert guest_controller.is_guest() is True
    assert guest_controller.guest_session.access_token == "guest-access-token"
    # Stored in the credentials file (keyring bypassed in fixture).
    stored = creds.load_guest_session()
    assert stored is not None
    assert stored["access_token"] == "guest-access-token"
    assert stored["uid"] == "guest-uid-123"
    # Logged in with the "guest mode" detail.
    assert guest_controller.state == State.LOGGED_IN
    assert "guest mode" in guest_controller.state_detail


def test_guest_login_failure_emits_error_and_keeps_logged_out(guest_controller, monkeypatch):
    fake_auth = _FakeGuestAuth(
        raise_on_login=GuestAuthError("Proton API error 8002: bad challenge"))
    monkeypatch.setattr(ctl_mod, "GuestAuth", lambda: fake_auth)

    guest_controller._login_request = {"mode": "guest"}
    guest_controller._login_worker()

    assert guest_controller.is_guest() is False
    assert guest_controller.state == State.LOGGED_OUT
    # An error message was emitted to the UI.
    assert any("Guest login failed" in t for t, l in guest_controller.messages)


def test_guest_connect_builds_wg_config_and_brings_up_tunnel(guest_controller, monkeypatch):
    """The guest connect path generates an X25519 keypair, fetches a
    certificate via the API, builds a wg-quick config, and brings up
    the tunnel — bypassing the browser downloads-page flow."""
    session = _make_session()
    logical = _make_logical()
    cert = _make_cert()
    fake_auth = _FakeGuestAuth(login_session=session,
                               logicals=[logical],
                               cert=cert)
    monkeypatch.setattr(guest_mod, "GuestAuth", lambda: fake_auth)

    # Logged-in guest controller with a server already in the store.
    guest_controller.guest_session = session
    guest_controller.guest_auth = fake_auth
    # Spin up the event loop on a thread (production code does this).
    loop = asyncio.new_event_loop()
    guest_controller._guest_loop = loop
    t = threading.Thread(target=lambda: (asyncio.set_event_loop(loop),
                                          loop.run_forever()),
                         daemon=True)
    t.start()

    # Insert the server into the store (production code does this via
    # _refresh_guest_servers_worker).
    guest_controller.store.replace([logical.to_logical_server()])
    server = guest_controller.store.free_servers()[0]

    bring_up_calls = []
    guest_controller._bring_up = lambda config_text, srv: bring_up_calls.append(
        (config_text, srv))
    connected_calls = []
    guest_controller._set_connected = lambda srv, sid, **k: connected_calls.append(
        (srv, sid))

    # Run the guest connect worker synchronously. _connect_worker
    # acquires the op lock itself; bypass it by calling the inner worker.
    guest_controller._connect_guest_worker(server)

    assert len(bring_up_calls) == 1
    config_text, srv = bring_up_calls[0]
    assert srv.name == "US-FREE#1"
    # The wg-quick config has the expected shape.
    assert "[Interface]" in config_text
    assert "[Peer]" in config_text
    # The WG private key is the one DERIVED from the session's Ed25519
    # device key (returned by the certificate call) — not a fresh random
    # X25519 keypair (that mismatch used to make Proton reject the cert
    # request with Code 2001).
    assert "PrivateKey = clientWgPrivKeyBase64==" in config_text
    assert "10.2.0.5/32" in config_text        # IPv4 from cert
    assert "1.2.3.4:51820" in config_text      # entry_ip:port
    assert "serverWgPubKeyBase64==" in config_text   # server WG pubkey
    # The certificate API was called exactly once.
    assert fake_auth.cert_calls == 1
    # The tunnel was brought up and the state machine marked connected.
    assert len(connected_calls) == 1

    # Stop the background event loop.
    loop.call_soon_threadsafe(loop.stop)


def test_guest_login_reuses_stored_session_when_refresh_window_open(guest_controller, monkeypatch):
    """If a guest session is still in its refresh window, the login worker
    reuses it instead of doing a fresh credentialless login."""
    session = _make_session()
    # Persist a still-valid session.
    creds.store_guest_session(session.to_storage_dict())
    # Sanity-check the file actually has the payload.
    stored_before = creds.load_guest_session()
    assert stored_before is not None, "fixture storage didn't persist"

    fake_auth = _FakeGuestAuth(login_session=session)
    created = []
    monkeypatch.setattr(ctl_mod, "GuestAuth",
                        lambda: (created.append(1), fake_auth)[1])

    captured = []
    guest_controller.on_state = lambda s, d: captured.append((s, d))
    guest_controller.on_message = lambda t, l: captured.append(("msg", t, l))
    guest_controller.on_login_event = lambda k, d: captured.append(("ev", k, d))

    guest_controller._login_request = {"mode": "guest"}
    try:
        guest_controller._login_worker()
    except Exception as e:
        pytest.fail(f"_login_worker raised: {e!r}; captured={captured}")

    # login() was NOT called on the fake auth — we reused the stored session.
    assert fake_auth.login_calls == 0, f"expected reuse, login was called: captured={captured}"
    assert guest_controller.is_guest() is True, f"captured={captured}"
    assert guest_controller.guest_session.access_token == "guest-access-token"


def test_guest_logout_clears_session_and_resets_state(guest_controller, monkeypatch):
    session = _make_session()
    guest_controller.guest_session = session
    # Stub _stop_guest_loop so we don't try to stop a non-existent loop.
    guest_controller._stop_guest_loop = lambda: None
    # Stub disconnect_async so it doesn't try to tear down a real tunnel.
    guest_controller.disconnect_async = lambda: None
    creds.store_guest_session(session.to_storage_dict())

    guest_controller.logout()

    assert guest_controller.is_guest() is False
    assert guest_controller.guest_session is None
    assert guest_controller.guest_auth is None
    assert creds.load_guest_session() is None
    assert guest_controller.state == State.LOGGED_OUT


# ---------------------------------------------------------------------------
# build_wg_quick_config / gen_x25519_keypair unit tests
# ---------------------------------------------------------------------------


def test_gen_x25519_keypair_returns_base64_pair():
    pub_b64, priv_b64 = gen_x25519_keypair()
    assert isinstance(pub_b64, str) and isinstance(priv_b64, str)
    # Each is a 44-char base64 of 32 raw bytes.
    assert len(pub_b64) == 44
    assert len(priv_b64) == 44
    pub_bytes = base64.b64decode(pub_b64)
    priv_bytes = base64.b64decode(priv_b64)
    assert len(pub_bytes) == 32
    assert len(priv_bytes) == 32
    # The two are different (priv != pub).
    assert pub_b64 != priv_b64


def test_build_wg_quick_config_full_shape():
    server = _make_logical(entry_ip="203.0.113.5",
                           wg_pk="serverPubKeyABC==")
    cert = _make_cert()  # IPv4=10.2.0.5, DNS=10.140.0.1
    priv_b64 = "clientPrivKeyXYZ=="

    text = build_wg_quick_config(server, cert, priv_b64)
    lines = text.strip().splitlines()
    assert lines[0] == "[Interface]"
    assert "PrivateKey = clientPrivKeyXYZ==" in lines
    assert "Address = 10.2.0.5/32" in lines
    assert "DNS = 10.140.0.1" in lines
    # [Peer] block
    assert "[Peer]" in lines
    assert "PublicKey = serverPubKeyABC==" in lines
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in lines
    assert "Endpoint = 203.0.113.5:51820" in lines


def test_build_wg_quick_config_ipv6_off_drops_v6_tokens():
    server = _make_logical()
    cert = _make_cert()
    cert.ipv6 = "2002:db8::1"        # hypothetically v6
    text = build_wg_quick_config(server, cert, "priv=", ipv6=False)
    assert "::" not in text
    assert "0.0.0.0/0" in text


def test_build_wg_quick_config_dns_override():
    server = _make_logical()
    cert = _make_cert()
    text = build_wg_quick_config(server, cert, "priv=",
                                 dns_server="127.0.0.1")
    assert "DNS = 127.0.0.1" in text
    assert "10.140.0.1" not in text   # cert DNS overridden


def test_guest_logical_to_logical_server_preserves_fields():
    gl = _make_logical(name="NL-FREE#3", country="NL",
                       entry_ip="5.6.7.8", wg_pk="nlPubKey==")
    ls = gl.to_logical_server()
    assert ls.id == "NL-FREE#3-id"
    assert ls.name == "NL-FREE#3"
    assert ls.exit_country == "NL"
    assert ls.tier == 0
    assert ls.is_free is True
    assert len(ls.physical) == 1
    assert ls.physical[0].entry_ip == "5.6.7.8"
    assert ls.physical[0].x25519_pk == "nlPubKey=="


def test_guest_session_roundtrip_through_storage_dict():
    session = _make_session()
    payload = session.to_storage_dict()
    restored = GuestSession.from_storage_dict(payload)
    assert restored.access_token == session.access_token
    assert restored.refresh_token == session.refresh_token
    assert restored.uid == session.uid
    assert restored.device_ed25519_pub_b64 == session.device_ed25519_pub_b64
    assert restored.device_ed25519_priv == session.device_ed25519_priv
    assert restored.max_tier == 0
    assert restored.plan_name == "guest"

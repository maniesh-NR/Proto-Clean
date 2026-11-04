"""Connect-flow tests: cached config reuse + re-download on failure.

Drives Controller._connect_worker with stubbed browser downloads and a fake
TunnelManager, verifying the cache-first behaviour the user asked for:

  * a cached config connects with NO download at all
  * a failing cached config (no handshake) is invalidated and re-downloaded
  * a cache miss downloads once and then caches
"""

from __future__ import annotations

import threading
import time
import types

import pytest

from proto_clean import settings as S
from proto_clean.account.downloads_page import ScrapeResult
from proto_clean.controller import Controller, State
from proto_clean.servers import store as store_mod
from proto_clean.servers.models import LogicalServer
from proto_clean.vpn.config_cache import ConfigCache
from proto_clean.vpn import tunnel as tunnel_mod

CONFIG = """[Interface]
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on
PrivateKey = k
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# US-FREE#1
PublicKey = p
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
"""


def _server(name="US-FREE#1"):
    return LogicalServer(id=name, name=name, entry_country="US",
                         exit_country="US", domain="", tier=0, features=0,
                         load=30.0, score=1.0, status=1, physical=[])


class FakeDownloads:
    def __init__(self):
        self.calls = []

    def scrape_servers(self):
        return [_server()]

    def create_config(self, server, options, config_name="ProtoClean",
                      fastest=False):
        self.calls.append(server.name)
        return ScrapeResult(config_text=CONFIG, server=server)


class FakeTunnelManager:
    """Sequence of handshakes: pops from the class-level list."""
    handshake_results = [True]

    def __init__(self, helper=None):
        self.up_calls = []
        self.helper = types.SimpleNamespace(call=lambda *a, **k: {"wg_up": True})
        self.split = types.SimpleNamespace(active=False)
        self.ks = types.SimpleNamespace(on=lambda *a: None, off=lambda: None)
        self.down_calls = 0

    def up(self, config_text, **kw):
        self.up_calls.append(config_text)
        return {"phys_iface": "eth0", "tunnel_ip": "10.2.0.2"}

    def wait_handshake(self, timeout=0, poll=0):
        return FakeTunnelManager.handshake_results.pop(0)

    def down(self, **kw):
        self.down_calls += 1


@pytest.fixture()
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(store_mod, "SERVER_CACHE_FILE",
                        tmp_path / "servers.json")
    monkeypatch.setattr(tunnel_mod, "_default_route",
                        staticmethod(lambda: ("eth0", "192.168.1.1")))

    ctl = Controller.__new__(Controller)
    ctl.settings = S.load_settings()
    ctl.settings.netshield.enabled = False          # no DNS server in tests
    ctl.settings.port_forward.request_in_config = False
    ctl.settings.autoconnect_fastest = False
    ctl.settings.kill_switch.enabled = False
    ctl.settings.split_tunnel.enabled = False

    ctl.state = State.LOGGED_OUT
    ctl.state_detail = ""
    ctl.session = types.SimpleNamespace(logged_in=True)
    ctl.downloads = FakeDownloads()
    ctl.config_cache = ConfigCache(root=tmp_path / "configs")
    ctl.store = store_mod.ServerStore()
    ctl.store.replace([_server()])
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
    # Guest-mode fields (normally initialised in Controller.__init__).
    # These tests exercise the account-mode path; guest_session=None
    # means is_guest() returns False and the connect worker stays on
    # the browser/downloads flow.
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

    import proto_clean.controller as ctl_mod
    monkeypatch.setattr(ctl_mod, "TunnelManager", FakeTunnelManager)
    return ctl


def _connect_and_wait(ctl, server_id=None, timeout=10.0):
    ctl._connect_worker(server_id)
    # _connect_worker runs synchronously here (called directly)
    return ctl.state


def test_cached_config_connects_without_any_download(controller):
    controller.config_cache.put("US-FREE#1", CONFIG,
                                options=types.SimpleNamespace(
                                    vpn_accelerator=True,
                                    nat_pmp_port_forward=False))
    FakeTunnelManager.handshake_results = [True]
    state = _connect_and_wait(controller, "US-FREE#1")
    assert state is State.CONNECTED
    assert controller.downloads.calls == []          # zero downloads!
    assert any("cached config" in m[0] for m in controller.messages)


def test_failing_cached_config_triggers_one_redownload(controller):
    controller.config_cache.put("US-FREE#1", CONFIG,
                                options=types.SimpleNamespace(
                                    vpn_accelerator=True,
                                    nat_pmp_port_forward=False))
    # cached config: interface up but handshake never completes
    FakeTunnelManager.handshake_results = [False, True]
    state = _connect_and_wait(controller, "US-FREE#1")
    assert state is State.CONNECTED
    # re-downloaded exactly once for this server
    assert controller.downloads.calls == ["US-FREE#1"]
    # the fresh download replaced the cache entry
    got = controller.config_cache.get("US-FREE#1")
    assert got is not None
    # and the user was told what happened
    assert any("failed" in m[0] for m in controller.messages)


def test_cache_miss_downloads_once_then_reuses(controller):
    FakeTunnelManager.handshake_results = [True, True]
    assert _connect_and_wait(controller, "US-FREE#1") is State.CONNECTED
    assert controller.downloads.calls == ["US-FREE#1"]
    assert len(controller.config_cache) == 1

    # second connect: served entirely from the cache
    controller.tunnel.down()
    controller.tunnel = None
    controller.monitor = None
    FakeTunnelManager.handshake_results = [True]
    assert _connect_and_wait(controller, "US-FREE#1") is State.CONNECTED
    assert controller.downloads.calls == ["US-FREE#1"]   # still one download


def test_paid_server_id_is_rejected(controller):
    plus = LogicalServer(id="US#1", name="US#1", entry_country="US",
                         exit_country="US", domain="", tier=1, features=0,
                         load=10.0, score=0.1, status=1, physical=[])
    controller.store.replace([_server(), plus])
    FakeTunnelManager.handshake_results = [True]
    assert _connect_and_wait(controller, "US#1") is State.CONNECTED
    # it silently fell back to the fastest *free* server, never the paid one
    assert controller.downloads.calls == ["US-FREE#1"]
    assert controller.current_server.is_free


def test_disabling_cache_always_downloads(controller):
    controller.settings.cache_configs = False
    FakeTunnelManager.handshake_results = [True]
    assert _connect_and_wait(controller, "US-FREE#1") is State.CONNECTED
    assert controller.downloads.calls == ["US-FREE#1"]
    assert len(controller.config_cache) == 0

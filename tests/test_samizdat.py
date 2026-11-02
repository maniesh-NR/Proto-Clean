"""Tests for the samizdat process manager (drives lantern-box/sing-box)
and the controller's proxy interop (provider dispatch, browser routing)."""

import json
import sys

import pytest

from proto_clean.vpn import samizdat as SZ
from proto_clean.vpn.samizdatconf import SamizdatProfile

from test_xray import _free_port, _write_executable  # noqa: F401  (helpers)

PBK = "a" * 64
SID = "0123456789abcdef"
PROFILE = SamizdatProfile(address="a.example", port=443,
                          public_key=PBK, short_id=SID,
                          server_name="ok.ru")


@pytest.fixture()
def fake_box(tmp_path):
    """Stand-in for the lantern-box/sing-box binary: reads the config,
    binds the mixed inbound port and idles."""
    return _write_executable(tmp_path, "fake-box", """
        import json, socket, sys, time
        cfg = sys.argv[sys.argv.index("-c") + 1]
        with open(cfg) as f:
            port = json.load(f)["inbounds"][0]["listen_port"]
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        while True:
            time.sleep(0.2)
    """)


@pytest.fixture()
def failing_box(tmp_path):
    return _write_executable(tmp_path, "bad-box", "", fail=True)


# ---------------------------------------------------------------- lifecycle
def test_start_stop_roundtrip(fake_box):
    m = SZ.SamizdatManager()
    port = _free_port()
    m.start(PROFILE, socks_port=port, binary=fake_box)
    try:
        assert m.running is True
        assert m.status()["protocol"] == "samizdat"
        # the mixed inbound serves both proxy kinds
        assert m.status()["socks_port"] == port
        assert m.status()["http_port"] == port
    finally:
        m.stop(revert_proxy=False)
    assert m.running is False


def test_written_config_is_singbox_samizdat(fake_box, tmp_path, monkeypatch):
    m = SZ.SamizdatManager()
    port = _free_port()
    from proto_clean.vpn import xray as xray_mod
    monkeypatch.setattr(xray_mod, "CACHE_DIR",
                        tmp_path)  # keep the config inside the test dir
    m.start(PROFILE, socks_port=port, binary=fake_box)
    try:
        cfg = json.loads((tmp_path / "samizdat" / "config.json")
                         .read_text())
        assert cfg["inbounds"][0]["type"] == "mixed"
        assert cfg["inbounds"][0]["listen_port"] == port
        out = cfg["outbounds"][0]
        assert out["type"] == "samizdat"
        assert out["server_name"] == "ok.ru"
    finally:
        m.stop(revert_proxy=False)


def test_missing_binary_help_mentions_lantern_box():
    m = SZ.SamizdatManager()
    with pytest.raises(SZ.XrayError) as ei:
        m.start(PROFILE, binary="/nonexistent/lantern-box-xyz")
    assert "lantern-box" in str(ei.value)
    assert "not found" in str(ei.value)


def test_start_failure_reports_log(failing_box):
    m = SZ.SamizdatManager()
    with pytest.raises(SZ.XrayError) as ei:
        m.start(PROFILE, binary=failing_box)
    assert "failed to start" in str(ei.value)


def test_find_box_binary_explicit(tmp_path):
    exe = tmp_path / "lantern-box"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert SZ.find_box_binary(str(exe)) == str(exe)
    assert SZ.find_box_binary("/nope/box") is None


# ------------------------------------------------------- controller interop
def _fake_running(mgr, port):
    mgr._proc = type("P", (), {"pid": 12345, "poll": lambda self: None})()
    mgr.socks_port = port
    mgr.http_port = port


def test_browser_proxy_modes(tmp_path, monkeypatch):
    import types
    from proto_clean import controller as C
    from proto_clean.controller import Controller, _proxy_server_dict

    ctl = Controller()
    # direct
    assert ctl.browser_proxy() is None
    # custom (Lantern default port)
    monkeypatch.setattr(ctl.settings.advanced, "browser_proxy_mode", "custom")
    assert ctl.browser_proxy() == {"server": "http://127.0.0.1:8787"}
    monkeypatch.setattr(ctl.settings.advanced, "browser_proxy_custom",
                        "socks5://127.0.0.1:1080")
    assert ctl.browser_proxy() == {"server": "socks5://127.0.0.1:1080"}
    # custom without a scheme gets http://
    assert _proxy_server_dict("127.0.0.1:8787") == \
        {"server": "http://127.0.0.1:8787"}
    assert _proxy_server_dict("garbage") is None
    # auto: samizdat preferred over xray when both run
    monkeypatch.setattr(ctl.settings.advanced, "browser_proxy_mode", "auto")
    _fake_running(ctl.xray, 10808)
    assert ctl.browser_proxy() == {"server": "socks5://127.0.0.1:10808"}
    _fake_running(ctl.samizdat, 10810)
    assert ctl.browser_proxy() == {"server": "socks5://127.0.0.1:10810"}


def test_apply_browser_proxy_pushes_to_session_and_blocklists(monkeypatch):
    from proto_clean.controller import Controller
    ctl = Controller()
    monkeypatch.setattr(ctl.settings.advanced, "browser_proxy_mode", "custom")
    monkeypatch.setattr(ctl.settings.advanced, "browser_proxy_custom",
                        "127.0.0.1:8787")
    ctl._apply_browser_proxy()
    assert ctl.session.proxy == {"server": "http://127.0.0.1:8787"}
    assert ctl.blocklists.proxy == "http://127.0.0.1:8787"


def test_provider_dispatch_start(monkeypatch, fake_box):
    """Start with provider=samizdat drives the samizdat manager (with a
    fake binary), applies the system proxy and reports on."""
    from proto_clean.settings import Settings, XraySettings, SamizdatSettings
    from proto_clean import controller as C

    ctl = C.Controller()
    ctl.settings = Settings(
        xray=XraySettings(provider="samizdat"),
        samizdat=SamizdatSettings(address="a.example", port=443,
                                  public_key=PBK, short_id=SID,
                                  server_name="ok.ru",
                                  mixed_port=_free_port()))
    applied = {}
    monkeypatch.setattr(type(ctl.samizdat), "apply_system_proxy",
                        lambda self: applied.update(sysproxy=True))
    monkeypatch.setattr(ctl, "_apply_browser_proxy", lambda: None)

    # mgr.running must be False at dispatch time (the guard above);
    # start() is faked so no real process is needed
    monkeypatch.setattr(type(ctl.samizdat), "start",
                        lambda self, profile, socks_port=None, **kw:
                        applied.update(profile=profile, port=socks_port))
    ctl._proxy_start_worker()
    assert applied["profile"].server_name == "ok.ru"
    assert applied["port"] == ctl.settings.samizdat.mixed_port
    assert applied["sysproxy"] is True
    assert ctl.proxy_state == "on"


def test_browser_launch_passes_proxy():
    """The backend browser must forward the proxy to Playwright."""
    from proto_clean.account.browser import AccountSession

    captured = {}

    class FakeCtx:
        def new_page(self):
            return None

    class FakeBrowser:
        def new_context(self, **kw):
            captured["context_kw"] = kw
            return FakeCtx()

        def close(self):
            pass

    class FakeChromium:
        def launch(self, **kw):
            captured["launch_kw"] = kw
            return FakeBrowser()

    class FakePw:
        chromium = FakeChromium()

    s = AccountSession(state_file="/nonexistent/state.json")
    s.proxy = {"server": "socks5://127.0.0.1:10810"}
    browser, ctx = s._launch(FakePw(), headless=True)
    assert captured["launch_kw"]["proxy"] == {"server":
                                              "socks5://127.0.0.1:10810"}
    assert captured["launch_kw"]["headless"] is True
    # without a proxy the kwarg is absent (Playwright default: direct)
    s.proxy = None
    s._launch(FakePw(), headless=True)
    assert "proxy" not in captured["launch_kw"]


def test_blocklist_download_uses_proxy(monkeypatch, tmp_path):
    """Blocklist fetches ride the proxy when one is configured — the
    Lantern-style fallback when direct downloads are blocked."""
    from proto_clean.netshield import blocklists as B
    from proto_clean.settings import BlocklistSource

    captured = {}

    class FakeResp:
        text = "0.0.0.0 ads.example"

        def raise_for_status(self):
            pass

    class FakeClient:
        def __init__(self, **kw):
            captured.update(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            return FakeResp()

    monkeypatch.setattr(B, "httpx", type("httpx", (), {"Client": FakeClient}))
    mgr = B.BlocklistManager(
        sources=[BlocklistSource(name="x", url="http://example/hosts")],
        cache_dir=tmp_path)
    mgr.proxy = "socks5://127.0.0.1:10810"
    mgr.update_all(timeout=5)
    assert captured["proxy"] == "socks5://127.0.0.1:10810"

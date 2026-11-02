"""Tests for the Xray process manager + system-proxy integration.

The real xray binary is not needed: a tiny fake (a Python script that
reads the generated config, opens the SOCKS port and idles) exercises
the whole lifecycle, including failure paths.
"""

import json
import os
import socket
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from proto_clean.vpn import xray as X
from proto_clean.vpn.xrayconf import XrayConfigError, XrayProfile, parse_xray_url

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PROFILE = XrayProfile(protocol="vless-reality", address="a.example",
                      port=443, uuid=UUID,
                      public_key="xW46H2JWbRzuLdROUeK0mnjGMsVrRgpMwfqNJOkUt0c",
                      short_id="30", sni="www.microsoft.com")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def fake_xray(tmp_path):
    """A stand-in for the xray binary: reads the config passed via -c,
    binds the SOCKS inbound port and idles until killed."""
    script = tmp_path / "fake-xray"
    script.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(f"""
        import json, socket, sys, time
        cfg = sys.argv[sys.argv.index("-c") + 1]
        with open(cfg) as f:
            port = json.load(f)["inbounds"][0]["port"]
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        while True:
            time.sleep(0.2)
    """))
    script.chmod(0o755)
    return str(script)


@pytest.fixture()
def failing_xray(tmp_path):
    script = tmp_path / "bad-xray"
    script.write_text("#!/bin/sh\necho 'failed to start: bad config' >&2\nexit 3\n")
    script.chmod(0o755)
    return str(script)


# ---------------------------------------------------------------- lifecycle
def test_start_stop_roundtrip(fake_xray):
    m = X.XrayManager()
    port = _free_port()
    assert m.running is False
    m.start(PROFILE, socks_port=port, http_port=_free_port(),
            binary=fake_xray)
    try:
        assert m.running is True
        assert X.XrayManager._port_open(port)
        assert m.socks_port == port
        assert m.status()["running"] is True
        assert m.status()["pid"] > 0
    finally:
        m.stop(revert_proxy=False)
    assert m.running is False
    assert not X.XrayManager._port_open(port)


def test_stop_terminates_stubborn_process(fake_xray):
    m = X.XrayManager()
    m.start(PROFILE, socks_port=_free_port(), http_port=_free_port(),
            binary=fake_xray)
    m.stop(revert_proxy=False, timeout=0.1)
    assert m.running is False


def test_start_twice_rejected(fake_xray):
    m = X.XrayManager()
    m.start(PROFILE, socks_port=_free_port(), http_port=_free_port(),
            binary=fake_xray)
    try:
        with pytest.raises(X.XrayError):
            m.start(PROFILE, binary=fake_xray)
    finally:
        m.stop(revert_proxy=False)


def test_start_failure_reports_log(failing_xray):
    m = X.XrayManager()
    with pytest.raises(X.XrayError) as ei:
        m.start(PROFILE, binary=failing_xray)
    assert "failed to start" in str(ei.value)
    assert m.running is False


def test_missing_binary():
    m = X.XrayManager()
    with pytest.raises(X.XrayError) as ei:
        m.start(PROFILE, binary="/nonexistent/xray-xyz")
    assert "not found" in str(ei.value)


def test_bad_profile_raises_config_error(fake_xray):
    m = X.XrayManager()
    with pytest.raises(XrayConfigError):
        m.start(XrayProfile(protocol="vless-reality", address="",
                            uuid=UUID, public_key="k", sni="s"),
                binary=fake_xray)


# ------------------------------------------------------------ system proxy
def test_linux_system_proxy_roundtrip(monkeypatch):
    if sys.platform.startswith("win"):
        pytest.skip("linux path")
    calls = []

    def fake_gs(*args):
        if args and not isinstance(args[0], str):   # bound self
            args = args[1:]
        calls.append(list(args))
        class R:
            returncode = 0
            stdout = "'none'" if args[0] == "get" else ""
            stderr = ""
        return R()

    monkeypatch.setattr(X.shutil, "which", lambda n: "/usr/bin/gsettings")
    monkeypatch.setattr(X.XrayManager, "_gs", fake_gs)
    m = X.XrayManager()
    m.socks_port, m.http_port = 10808, 10809
    m.apply_system_proxy()
    assert m._proxy_applied is True
    set_calls = [c for c in calls if c[0] == "set"]
    assert ["set", "org.gnome.system.proxy.socks", "port", "10808"] in set_calls
    # mode was set to manual last
    assert calls[-1] == ["set", "org.gnome.system.proxy", "mode", "'manual'"]
    m.revert_system_proxy()
    assert m._proxy_applied is False
    assert calls[-1] == ["set", "org.gnome.system.proxy", "mode", "'none'"]


def test_find_xray_binary_explicit(tmp_path):
    exe = tmp_path / "xray"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert X.find_xray_binary(str(exe)) == str(exe)
    assert X.find_xray_binary("/nope/xray") is None

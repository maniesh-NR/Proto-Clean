"""Tests for the Tor engine.

Covers bridge-line parsing, torrc generation (golden strings), the
control-port client against a canned fake control server, and the engine's
torrc wiring — everything except spawning a real tor daemon.
"""

from __future__ import annotations

import os
import shutil
import socketserver
import threading

import pytest

from proto_clean.vpn.protocols import tor as T
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.models import TorProfile


# ------------------------------------------------------------------ parsing
def test_parse_obfs4_bridge():
    b = T.parse_bridge_line("obfs4 1.2.3.4:443 CERT=xxxxxxxxx iat-mode=0")
    assert b == {"transport": "obfs4", "addr": "1.2.3.4", "port": 443,
                 "fingerprint": "",
                 "params": {"CERT": "xxxxxxxxx", "iat-mode": "0"}}


def test_parse_obfs4_bridge_with_fingerprint():
    fp = "0123456789abcdef0123456789abcdef01234567"
    b = T.parse_bridge_line("obfs4 198.51.100.2:9001 %s cert=c iat-mode=2"
                            % fp)
    assert b["transport"] == "obfs4"
    assert b["addr"] == "198.51.100.2" and b["port"] == 9001
    assert b["fingerprint"] == fp
    assert b["params"] == {"cert": "c", "iat-mode": "2"}


def test_parse_snowflake_bridge():
    b = T.parse_bridge_line("snowflake 192.0.2.1:80 B9Tk6fCgR6kNkJbWQpublickey")
    assert b == {"transport": "snowflake", "addr": "192.0.2.1", "port": 80,
                 "fingerprint": "B9Tk6fCgR6kNkJbWQpublickey", "params": {}}


def test_parse_webtunnel_bridge():
    b = T.parse_bridge_line("webtunnel 203.0.113.9:8443 public=abc")
    assert b["transport"] == "webtunnel"
    assert b["addr"] == "203.0.113.9" and b["port"] == 8443
    assert b["params"] == {"public": "abc"}
    assert b["fingerprint"] == ""


def test_parse_plain_bridge():
    fp = "f" * 40
    b = T.parse_bridge_line("1.2.3.4:443 " + fp)
    assert b == {"transport": "", "addr": "1.2.3.4", "port": 443,
                 "fingerprint": fp, "params": {}}


def test_parse_transport_only_bridge():
    b = T.parse_bridge_line("obfs4 1.2.3.4:443")
    assert b["transport"] == "obfs4" and b["fingerprint"] == ""
    assert b["params"] == {}


def test_parse_normalizes_transport_case_and_whitespace():
    b = T.parse_bridge_line("  OBFS4   1.2.3.4:443  CERT=x  ")
    assert b["transport"] == "obfs4"
    assert b["params"] == {"CERT": "x"}


def test_parse_ipv6_bridge():
    b = T.parse_bridge_line("[2001:db8::1]:443 " + "a" * 40)
    assert b["addr"] == "2001:db8::1" and b["port"] == 443


@pytest.mark.parametrize("bad", [
    "", "   ", "# a comment", "obfs4", "obfs4 nohost",
    "obfs4 1.2.3.4:notaport", "obfs4 1.2.3.4:70000", "obfs4 1.2.3.4:0",
    "!!!! 1.2.3.4:443", "1.2.3.4 fpr",                      # missing port
    "1.2.3.4:443 fpr junk-extra", "=x 1.2.3.4:443",
])
def test_parse_garbage_raises(bad):
    with pytest.raises(ProtocolError):
        T.parse_bridge_line(bad)


# ------------------------------------------------------------------ torrc
def test_build_torrc_direct(tmp_path):
    text = T.build_torrc(TorProfile(), 9050, 9051, str(tmp_path / "tor"))
    lines = text.splitlines()
    assert "SocksPort 127.0.0.1:9050" in lines
    assert "ControlPort 127.0.0.1:9051" in lines
    assert "CookieAuthentication 1" in lines
    assert "DataDirectory %s" % (tmp_path / "tor") in lines
    assert "Log notice file %s" % (tmp_path / "tor" / "notice.log") in lines
    assert "ClientOnly 1" in lines
    assert "UseBridges" not in text
    assert "Socks5Proxy" not in text
    assert "ExitNodes" not in text and "StrictNodes" not in text
    assert text.endswith("\n")


def test_build_torrc_bridges_with_transport_map(tmp_path):
    p = TorProfile(bridges=[
        "obfs4 1.2.3.4:443 CERT=abc iat-mode=0",
        "obfs4 5.6.7.8:443 CERT=def iat-mode=1",
        "snowflake 1.2.3.4:80 sfp",
    ])
    text = T.build_torrc(
        p, 9050, 9051, str(tmp_path),
        transport_map={"obfs4": "/usr/bin/obfs4proxy",
                       "snowflake": "/usr/bin/snowflake-client"})
    lines = text.splitlines()
    assert "UseBridges 1" in lines
    assert "Bridge obfs4 1.2.3.4:443 CERT=abc iat-mode=0" in lines
    assert "Bridge obfs4 5.6.7.8:443 CERT=def iat-mode=1" in lines
    assert "Bridge snowflake 1.2.3.4:80 sfp" in lines
    plugins = [l for l in lines if l.startswith("ClientTransportPlugin")]
    assert plugins == ["ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
                       "ClientTransportPlugin snowflake exec "
                       "/usr/bin/snowflake-client"]


def test_build_torrc_skips_kinds_absent_from_map(tmp_path):
    p = TorProfile(bridges=["obfs4 1.2.3.4:443 CERT=abc iat-mode=0"])
    text = T.build_torrc(p, 9050, 9051, str(tmp_path), transport_map={})
    assert "ClientTransportPlugin" not in text
    assert "UseBridges 1" in text
    assert "Bridge obfs4 1.2.3.4:443 CERT=abc iat-mode=0" in text


def test_build_torrc_ignores_blank_and_comment_bridges(tmp_path):
    p = TorProfile(bridges=["", "   ", "# note", "1.2.3.4:443 " + "b" * 40])
    text = T.build_torrc(p, 9050, 9051, str(tmp_path))
    assert "UseBridges 1" in text
    assert [l for l in text.splitlines() if l.startswith("Bridge")] == \
        ["Bridge 1.2.3.4:443 " + "b" * 40]


def test_build_torrc_upstream_socks5proxy(tmp_path):
    p = TorProfile(upstream_url="socks5://127.0.0.1:10808")
    text = T.build_torrc(p, 9050, 9051, str(tmp_path),
                         upstream=("127.0.0.1", 10808))
    assert "Socks5Proxy 127.0.0.1:10808" in text


def test_build_torrc_no_upstream_when_port_zero(tmp_path):
    text = T.build_torrc(TorProfile(), 9050, 9051, str(tmp_path),
                         upstream=("127.0.0.1", 0))
    assert "Socks5Proxy" not in text


def test_build_torrc_exit_entry_strict(tmp_path):
    p = TorProfile(exit_nodes="{de},{at}", entry_nodes="{us}",
                   strict_nodes=True)
    text = T.build_torrc(p, 9050, 9051, str(tmp_path))
    assert "ExitNodes {de},{at}" in text
    assert "EntryNodes {us}" in text
    assert "StrictNodes 1" in text


def test_build_torrc_no_strict_line_when_false(tmp_path):
    p = TorProfile(exit_nodes="{de}", strict_nodes=False)
    text = T.build_torrc(p, 9050, 9051, str(tmp_path))
    assert "ExitNodes {de}" in text
    assert "EntryNodes" not in text
    assert "StrictNodes" not in text


# ------------------------------------------------------------------ upstream
def test_parse_upstream_url():
    assert T._parse_upstream_url("socks5://127.0.0.1:10808") == \
        ("127.0.0.1", 10808)
    assert T._parse_upstream_url("socks5h://10.0.0.1") == ("10.0.0.1", 1080)
    assert T._parse_upstream_url("127.0.0.1:10808") == ("127.0.0.1", 10808)
    assert T._parse_upstream_url("") == ("", 0)
    with pytest.raises(ProtocolError):
        T._parse_upstream_url("vless://uuid@host:443")
    with pytest.raises(ProtocolError):
        T._parse_upstream_url("socks5://host:notaport")
    with pytest.raises(ProtocolError):
        T._parse_upstream_url("just-a-word")


# ------------------------------------------------------------------ engine
def test_engine_class_attributes():
    eng = T.engine(TorProfile(), socks_port=19111)
    assert isinstance(eng, T.TorEngine)
    assert eng.proxy_kind == "tor"
    assert eng.family == "proxy"
    assert eng.exposes == "socks"
    assert eng.binary_name == "tor"
    assert eng.supports_upstream is True
    assert eng.socks_port == 19111


def test_engine_status_fields_offline():
    eng = T.TorEngine(socks_port=19121)
    eng.profile = TorProfile(bridges=["1.2.3.4:443 " + "c" * 40])
    st = eng.status()
    assert st["kind"] == "tor"
    assert st["family"] == "proxy"
    assert st["exposes"] == "socks"
    assert st["running"] is False
    assert st["bridges"] == 1
    assert st["bootstrap"] == 0.0
    assert st["data_dir"] == ""
    assert "control_port" in st


def test_engine_builds_torrc_without_spawning(tmp_path):
    """Instantiate the engine and drive the torrc builder directly — no tor."""
    eng = T.TorEngine(socks_port=19131)
    eng.control_port = 19132
    p = TorProfile(exit_nodes="{de}", strict_nodes=True,
                   upstream_url="socks5://127.0.0.1:10808")
    text = T.build_torrc(p, eng.socks_port, eng.control_port,
                         str(tmp_path / "tor"), {},
                         upstream=("127.0.0.1", 10808))
    assert "SocksPort 127.0.0.1:19131" in text
    assert "ControlPort 127.0.0.1:19132" in text
    assert "Socks5Proxy 127.0.0.1:10808" in text
    assert "ExitNodes {de}" in text
    assert "StrictNodes 1" in text
    assert eng._proc is None and eng.running is False


def test_engine_missing_transport_binary(tmp_path):
    if shutil.which("obfs4proxy"):
        pytest.skip("obfs4proxy is installed")
    eng = T.TorEngine()
    with pytest.raises(ProtocolError) as ei:
        eng._resolve_transports(
            TorProfile(bridges=["obfs4 1.2.3.4:443 CERT=x iat-mode=0"]))
    assert "obfs4" in str(ei.value)


def test_engine_rejects_bad_bridge_line():
    eng = T.TorEngine()
    with pytest.raises(ProtocolError):
        eng._resolve_transports(TorProfile(bridges=["obfs4 not-an-addr"]))


def test_engine_accepts_plain_bridges_without_transports():
    eng = T.TorEngine()
    assert eng._resolve_transports(
        TorProfile(bridges=["1.2.3.4:443 " + "d" * 40])) == {}


def test_find_tor_binary_env_var(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only executable bit handling")
    fake = tmp_path / "tor"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PROTO_CLEAN_TOR_BIN", str(fake))
    assert T.find_tor_binary() == str(fake)
    assert T.find_tor_binary(explicit=str(fake)) == str(fake)


def test_find_transport_binary_via_path(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only executable bit handling")
    fake = tmp_path / "obfs4proxy"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH",
                       str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    assert T.find_transport_binary("obfs4") == str(fake)
    assert T.find_transport_binary("meek_lite") is None   # unknown kind


# ------------------------------------------------------- control-port client
class _FakeControlHandler(socketserver.BaseRequestHandler):
    """Canned Tor control server: one command per line, tor-style replies."""

    def handle(self):
        rec = getattr(self.server, "rec", {})
        rfile = self.request.makefile("rb")
        try:
            while True:
                raw = rfile.readline()
                if not raw:
                    return
                text = raw.decode("utf-8", "replace").strip()
                rec["commands"].append(text)
                if text.startswith("AUTHENTICATE"):
                    rec["auth"].append(text)
                    self.request.sendall(b"250 OK\r\n")
                elif text.startswith("GETINFO status/bootstrap-phase"):
                    self.request.sendall(
                        b"250-status/bootstrap-phase=NOTICE BOOTSTRAP "
                        b"PROGRESS=80 TAG=loading_status SUMMARY=Loading "
                        b"relay descriptors\r\n"
                        b"250-exit-mode=off\r\n"
                        b"250 OK\r\n")
                elif text.startswith("SIGNAL"):
                    rec["signals"].append(text)
                    self.request.sendall(b"250 OK\r\n")
                elif text.startswith("GETINFO"):
                    self.request.sendall(
                        b"552 Unrecognized option\r\n")
                elif text == "QUIT":
                    self.request.sendall(b"250 closing connection\r\n")
                    return
                else:
                    self.request.sendall(b"510 Unrecognized command\r\n")
        except OSError:
            return


class _FakeControlServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture()
def fake_control():
    srv = _FakeControlServer(("127.0.0.1", 0), _FakeControlHandler)
    srv.rec = {"commands": [], "auth": [], "signals": []}
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=2)


def _connect_fake(srv, tmp_path) -> T.TorControl:
    cookie = tmp_path / "control_auth_cookie"
    cookie.write_bytes(bytes(range(32)))
    ctl = T.TorControl(timeout=5.0)
    ctl.connect("127.0.0.1", srv.server_address[1], str(cookie))
    return ctl


def test_control_authenticates_with_cookie_hex(fake_control, tmp_path):
    ctl = _connect_fake(fake_control, tmp_path)
    rec = fake_control.rec
    assert rec["auth"] == ["AUTHENTICATE " + bytes(range(32)).hex()]
    ctl.close()


def test_control_bootstrap_status_and_multi_line_getinfo(fake_control,
                                                         tmp_path):
    ctl = _connect_fake(fake_control, tmp_path)
    try:
        assert ctl.bootstrap_status() == 80.0
        info = ctl.get_info("status/bootstrap-phase")
        assert info["status/bootstrap-phase"].startswith("NOTICE BOOTSTRAP")
        assert "PROGRESS=80" in info["status/bootstrap-phase"]
        assert info["exit-mode"] == "off"      # mid-reply line still captured
    finally:
        ctl.close()


def test_control_signal_newnym(fake_control, tmp_path):
    ctl = _connect_fake(fake_control, tmp_path)
    try:
        ctl.signal("NEWNYM")
        assert fake_control.rec["signals"] == ["SIGNAL NEWNYM"]
    finally:
        ctl.close()


def test_control_getinfo_5xx_raises(fake_control, tmp_path):
    ctl = _connect_fake(fake_control, tmp_path)
    try:
        with pytest.raises(ProtocolError):
            ctl.get_info("net/listeners/socks")
    finally:
        ctl.close()


def test_control_not_connected_raises():
    ctl = T.TorControl(timeout=1.0)
    with pytest.raises(ProtocolError):
        ctl.bootstrap_status()
    with pytest.raises(ProtocolError):
        ctl.signal("NEWNYM")
    ctl.close()


def test_control_missing_cookie_raises(fake_control, tmp_path):
    ctl = T.TorControl(timeout=2.0)
    with pytest.raises(ProtocolError):
        ctl.connect("127.0.0.1", fake_control.server_address[1],
                    str(tmp_path / "does-not-exist"))
    ctl.close()

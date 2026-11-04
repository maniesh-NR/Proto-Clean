"""Tests for the OpenVPN-over-Cloak composite engine (protocols/cloak.py).

No real ck-client/openvpn is involved.  The spawn tests (skipped on
Windows, like the rest of the fake-binary suites) use two stand-ins:

* a fake ``ck-client`` whose ``-h`` prints a Go-style usage advertising
  the REAL Cloak flags (verified against cbeuw/Cloak cmd/ck-client:
  ``-c`` config, ``-s`` remoteHost, ``-p`` remotePort, ``-l`` localPort
  default 1984) and which — when actually started — binds the local
  SOCKS port it is told to use;
* a fake ``openvpn`` that validates the composed config and prints the
  "Initialization Sequence Completed" marker (or misbehaves, for the
  failure paths).
"""

from __future__ import annotations

import json
import os
import socket
import sys
import textwrap

import pytest

from proto_clean.vpn.protocols import cloak as CL
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.base import ProtocolError

POSIX_ONLY = pytest.mark.skipif(sys.platform.startswith("win"),
                                reason="POSIX-only fake executables")

UID = "0123456789abcdef0123456789abcdef"
PUB = "0123456789abcdef" * 4                     # 64 hex chars
PROFILE = M.CloakProfile(
    server="cloak.example.com", port=443, uid=UID, public_key=PUB,
    server_name="www.apple.com", transport="direct",
    encryption_method="aes-256-gcm", num_conn=4, browser_sig="chrome",
    alternative_names=["alt1.example.com", "alt2.example.com"])

BASE_OVPN = """\
client
dev tun
proto udp
remote old.example.com 1194
nobind
persist-key
persist-tun
<ca>
-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIRAK7sC4ZBqk6i2NgeFakhL6AwDQYJKoZIhvcNAQEL
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIICJDCCAY2gAwIBAgIQW5ZaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA ==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----
</key>
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def _write_script(tmp_path, name, body) -> str:
    """A runnable stand-in executable (POSIX-only; spawn tests skip on
    Windows)."""
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n"
                    + textwrap.dedent(body).lstrip("\n"))
    path.chmod(0o755)
    return str(path)


# ----------------------------------------------------------- fake binaries
FAKE_CK_BODY = """
    import socket, sys, time

    args = sys.argv[1:]
    if "-h" in args or "-c" not in args:
        print("Usage of ck-client:")
        print("  -c string")
        print("    \\tconfig: path to the configuration file")
        print("  -l string")
        print("    \\tlocalPort: Cloak listens to proxy clients on this "
              "port (default \\"1984\\")")
        print("  -p string")
        print("    \\tremotePort: proxy port, should be 443")
        print("  -s string")
        print("    \\tremoteHost: IP of your proxy server")
        sys.exit(0)

    with open("ck-argv.txt", "w") as f:
        f.write(repr(args))
    with open(args[args.index("-c") + 1]) as f:
        body = f.read()
    assert '"ProxyMethod": "openvpn"' in body, body
    port = 1984
    for flag in ("-l", "-o"):
        if flag in args:
            port = int(args[args.index(flag) + 1])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    sys.stdout.write("fake ck-client listening on %d\\n" % port)
    sys.stdout.flush()
    while True:
        time.sleep(0.2)
"""

FAKE_OVPN_BODY = """
    import sys, time

    argv = sys.argv[1:]
    cfg = argv[argv.index("--config") + 1] if "--config" in argv else ""
    with open(cfg) as f:
        text = f.read()
    assert "socks-proxy 127.0.0.1" in text, text
    print("OpenVPN 2.5 fake starting; config=%s" % cfg)
    sys.stdout.flush()
    time.sleep(0.2)
    print("Initialization Sequence Completed")
    sys.stdout.flush()
    while True:
        time.sleep(0.2)
"""

FAIL_OVPN_BODY = """
    import sys, time
    print("Options error: --ca fails with 'no such file'")
    sys.stdout.flush()
    time.sleep(0.05)
    sys.exit(1)
"""

SLOW_OVPN_BODY = """
    import sys, time
    print("OpenVPN 2.5 fake resolving...")
    sys.stdout.flush()
    time.sleep(60)
"""


@pytest.fixture()
def fake_binaries(tmp_path, monkeypatch):
    """Fake ck-client + openvpn wired in via env vars, CONFIG_DIR isolated."""
    ck = _write_script(tmp_path, "ck-client", FAKE_CK_BODY)
    ovpn = _write_script(tmp_path, "openvpn", FAKE_OVPN_BODY)
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN", ck)
    monkeypatch.setenv("PROTO_CLEAN_OPENVPN_BIN", ovpn)
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    return tmp_path


# ------------------------------------------------------- build_ckclient_json
def test_build_ckclient_json_all_fields():
    cfg = CL.build_ckclient_json(PROFILE)
    assert cfg == {
        "Transport": "direct",
        "ProxyMethod": "openvpn",
        "EncryptionMethod": "aes-256-gcm",
        "UID": UID,
        "PublicKey": PUB,
        "ServerName": "www.apple.com",
        "NumConn": 4,
        "BrowserSig": "chrome",
        "StreamTimeout": 300,
        "AlternativeNames": ["alt1.example.com", "alt2.example.com"],
    }


def test_build_ckclient_json_empty_transport_becomes_direct():
    p = M.CloakProfile(uid=UID, public_key=PUB, transport="",
                       alternative_names=[])
    cfg = CL.build_ckclient_json(p, proxy_method="shadowsocks")
    assert cfg["Transport"] == "direct"
    assert cfg["ProxyMethod"] == "shadowsocks"
    assert cfg["AlternativeNames"] == []


# ------------------------------------------------------ compose_openvpn_config
def test_compose_rewrites_base_config():
    p = M.CloakProfile(server="cloak.example.com", port=443, uid=UID,
                       public_key=PUB, openvpn_config=BASE_OVPN)
    text = CL.compose_openvpn_config(p, 1984)
    lines = text.splitlines()
    # transport + endpoint + socks-proxy, each exactly once
    assert lines.count("proto tcp") == 1
    assert not any("proto udp" in l for l in lines)
    assert lines.count("remote cloak.example.com 443") == 1
    assert lines.count("socks-proxy 127.0.0.1 1984") == 1
    # old remote stripped
    assert not any("old.example.com" in l for l in lines)
    # ca/cert/key blocks preserved verbatim
    for marker in ("<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>",
                   "-----BEGIN CERTIFICATE-----",
                   "-----END CERTIFICATE-----",
                   "-----BEGIN PRIVATE KEY-----"):
        assert marker in text
    # non-owned directives survive
    for want in ("client", "dev tun", "nobind", "persist-key",
                 "persist-tun"):
        assert want in lines


def test_compose_strips_existing_socks_proxy_and_remote():
    base = BASE_OVPN + "socks-proxy 127.0.0.1 9999\nremote other.host 1080\n"
    p = M.CloakProfile(server="s.example.com", port=443, uid=UID,
                       public_key=PUB, openvpn_config=base)
    lines = CL.compose_openvpn_config(p, 12345).splitlines()
    assert lines.count("socks-proxy 127.0.0.1 12345") == 1
    assert "socks-proxy 127.0.0.1 9999" not in lines
    assert lines.count("remote s.example.com 443") == 1
    assert not any("other.host" in l for l in lines)


def test_compose_synthesizes_skeleton_without_base():
    p = M.CloakProfile(server="cloak.example.com", port=8443, uid=UID,
                       public_key=PUB, openvpn_config="")
    text = CL.compose_openvpn_config(p, 1984)
    lines = text.splitlines()
    for want in ("proto tcp", "client", "dev tun", "nobind", "persist-key",
                 "persist-tun", "remote-cert-tls server",
                 "remote cloak.example.com 8443",
                 "socks-proxy 127.0.0.1 1984"):
        assert want in lines
    assert text.endswith("\n")


# ------------------------------------------------------------------ -h parser
# Real Go flag.Usage() layout (matches cbeuw/Cloak cmd/ck-client flags)
CK_HELP = """Usage of ck-client:
  -V\tignored. (SS plugin mode)
  -a string
    \tadminUID: enter the adminUID to serve the admin api
  -c string
    \tconfig: path to the configuration file or options separated with semicolons (default "ckclient.json")
  -h\tPrint this message
  -i string
    \tlocalHost: Cloak listens to proxy clients on this ip (default "127.0.0.1")
  -l string
    \tlocalPort: Cloak listens to proxy clients on this port (default "1984")
  -p string
    \tremotePort: proxy port, should be 443 (default "443")
  -proxy string
    \tproxy: the proxy method's name
  -s string
    \tremoteHost: IP of your proxy server
  -u\tudp: set this flag if the underlying proxy is using UDP protocol
  -v\tPrint the version number
"""


def test_parse_ck_help_real_flags():
    flags = CL.parse_ck_help(CK_HELP)
    for name in ("V", "a", "c", "h", "i", "l", "p", "proxy", "s", "u", "v"):
        assert name in flags, name
    assert "localPort" in flags["l"] and "1984" in flags["l"]
    assert "remoteHost" in flags["s"]
    assert "remotePort" in flags["p"] and "443" in flags["p"]
    assert "adminUID" in flags["a"]
    assert "config" in flags["c"]
    assert flags["h"] == "Print this message"
    assert flags["u"].startswith("udp")


def test_parse_ck_help_empty_and_junk():
    assert CL.parse_ck_help("") == {}
    assert CL.parse_ck_help("this is not help at all\nreally not\n") == {}
    assert CL.parse_ck_help(None) == {}    # type: ignore[arg-type]


def test_parse_ck_help_two_line_and_continuations():
    text = ("Usage of ck-client:\n"
            "  -c string\n"
            "    \tpath to the config file\n"
            "    \tsecond line of the description\n")
    flags = CL.parse_ck_help(text)
    assert flags == {"c": "path to the config file second line of the "
                          "description"}


# --------------------------------------------------------------- find_binary
def test_find_ck_client_env_var(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only executable bit handling")
    fake = tmp_path / "ck-client"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN", str(fake))
    assert CL.find_ck_client() == str(fake)
    assert CL.find_ck_client(explicit=str(fake)) == str(fake)


def test_find_openvpn_binary_env_var(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only executable bit handling")
    fake = tmp_path / "openvpn"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PROTO_CLEAN_OPENVPN_BIN", str(fake))
    assert CL.find_openvpn_binary() == str(fake)


# ---------------------------------------------------------------- engine bits
def test_engine_class_attributes():
    eng = CL.engine(PROFILE, socks_port=19111)
    assert isinstance(eng, CL.CloakEngine)
    assert eng.proxy_kind == "cloak"
    assert eng.family == "proxy"
    assert eng.exposes == "socks"
    assert eng.binary_name == "ck-client"
    assert eng.supports_upstream is False
    assert eng.socks_port == 19111
    st = eng.status()
    assert st["running"] is False
    assert st["phase"] == ""
    assert st["cloak_socks"] == 19111
    assert st["openvpn"] is False


def test_engine_rejects_empty_server():
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError):
        eng.start(M.CloakProfile(server="", uid=UID, public_key=PUB))


def test_engine_tunnel_ready_without_start_raises():
    eng = CL.CloakEngine()
    with pytest.raises(ProtocolError):
        eng.tunnel_ready(timeout=1.0)


# ------------------------------------------------------------ engine: missing
def test_engine_missing_ck_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    monkeypatch.setattr(CL, "find_ck_client", lambda explicit="": None)
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE)
    assert "cbeuw/Cloak" in str(ei.value)
    assert eng.running is False


@POSIX_ONLY
def test_engine_missing_openvpn_binary(tmp_path, monkeypatch):
    ck = _write_script(tmp_path, "ck-client", FAKE_CK_BODY)
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN", ck)
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    monkeypatch.setattr(CL, "find_openvpn_binary", lambda explicit="": None)
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE, timeout=10)
    assert "openvpn" in str(ei.value).lower()
    # the already-started ck-client was cleaned up again
    assert eng.ck_proc is None and eng.ovpn_proc is None
    assert eng.running is False
    assert not _port_open(eng.socks_port)


# ------------------------------------------------------ engine: full lifecycle
@POSIX_ONLY
def test_engine_start_stop_full(fake_binaries):
    port = _free_port()
    eng = CL.CloakEngine(socks_port=port)
    assert not _port_open(port)
    eng.start(PROFILE, timeout=10)
    try:
        st = eng.status()
        assert st["running"] is True
        assert st["cloak_socks"] == port
        assert st["openvpn"] is True
        assert st["phase"] == "tunnel"
        assert st["kind"] == "cloak"
        # ckclient.json written into CONFIG_DIR/cloak and matches the builder
        with open(eng.ck_config_path) as f:
            data = json.load(f)
        assert data == CL.build_ckclient_json(PROFILE)
        # composed .ovpn routes openvpn through the local cloak SOCKS
        with open(eng.ovpn_config_path) as f:
            ovpn_text = f.read()
        assert "socks-proxy 127.0.0.1 %d" % port in ovpn_text
        assert "remote cloak.example.com 443" in ovpn_text.splitlines()
        # flags from the fake's -h were mapped and honoured on the cmdline
        assert "l" in eng.ck_help_flags and "c" in eng.ck_help_flags
        argv_txt = (fake_binaries / "conf" / "cloak" / "ck-argv.txt") \
            .read_text()
        assert "'-s', 'cloak.example.com'" in argv_txt
        assert "'-p', '443'" in argv_txt
        assert "'-l', '%d'" % port in argv_txt
        assert "ckclient.json" in argv_txt
        # the local SOCKS is really listening
        assert _port_open(port)
    finally:
        eng.stop()

    st = eng.status()
    assert st["running"] is False
    assert st["openvpn"] is False
    assert eng.ck_proc is None and eng.ovpn_proc is None
    assert not _port_open(port)


@POSIX_ONLY
def test_engine_stop_kills_both_processes(fake_binaries):
    eng = CL.CloakEngine(socks_port=_free_port())
    eng.start(PROFILE, timeout=10)
    ck, ovpn = eng.ck_proc, eng.ovpn_proc
    assert ck is not None and ovpn is not None
    assert ck.poll() is None and ovpn.poll() is None
    eng.stop()
    # both processes were terminated, not just the primary one
    for proc in (ck, ovpn):
        assert proc.poll() is not None
    assert eng.running is False
    assert eng.status()["phase"] == ""


@POSIX_ONLY
def test_status_phase_degrades_when_openvpn_dies(fake_binaries):
    eng = CL.CloakEngine(socks_port=_free_port())
    eng.start(PROFILE, timeout=10)
    try:
        assert eng.status()["phase"] == "tunnel"
        eng.tunnel_ready(timeout=5)        # idempotent once established
        ovpn = eng.ovpn_proc
        assert ovpn is not None
        ovpn.terminate()
        ovpn.wait(timeout=5)
        st = eng.status()
        assert st["openvpn"] is False
        assert st["phase"] == "cloak"      # degraded, SOCKS still up
        assert st["running"] is True
    finally:
        eng.stop()


# ----------------------------------------------------------- failure paths
@POSIX_ONLY
def test_openvpn_failure_reports_tail(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN",
                       _write_script(tmp_path, "ck-client", FAKE_CK_BODY))
    monkeypatch.setenv("PROTO_CLEAN_OPENVPN_BIN",
                       _write_script(tmp_path, "openvpn", FAIL_OVPN_BODY))
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE, timeout=10)
    msg = str(ei.value)
    assert "exited" in msg
    assert "Options error" in msg          # stdout tail included
    assert eng.ck_proc is None and eng.ovpn_proc is None
    assert eng.running is False


@POSIX_ONLY
def test_openvpn_timeout_without_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN",
                       _write_script(tmp_path, "ck-client", FAKE_CK_BODY))
    monkeypatch.setenv("PROTO_CLEAN_OPENVPN_BIN",
                       _write_script(tmp_path, "openvpn", SLOW_OVPN_BODY))
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE, timeout=1.5)
    assert "timeout" in str(ei.value)
    assert eng.ck_proc is None and eng.ovpn_proc is None


@POSIX_ONLY
def test_ck_client_dying_reports_tail(tmp_path, monkeypatch):
    body = """
        import sys
        print("FATAL: cannot parse config")
        sys.exit(2)
    """
    monkeypatch.setenv("PROTO_CLEAN_CLOAK_BIN",
                       _write_script(tmp_path, "ck-client", body))
    monkeypatch.setenv("PROTO_CLEAN_OPENVPN_BIN",
                       _write_script(tmp_path, "openvpn", FAKE_OVPN_BODY))
    monkeypatch.setattr(CL, "CONFIG_DIR", tmp_path / "conf")
    eng = CL.CloakEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE, timeout=10)
    msg = str(ei.value)
    assert "ck-client" in msg
    assert "FATAL" in msg
    assert eng.ck_proc is None

"""Tests for the NaïveProxy engine (protocols/naive.py).

Covers the config builder (percent-encoding, sni override, socks listen
scheme), binary discovery via ``PROTO_CLEAN_NAIVE_BIN``, validation
errors and the full engine lifecycle against a fake ``naive`` binary —
a tiny SOCKS5 server that reads the generated config (path from argv)
and forwards every CONNECT to a real loopback echo server.  The test
then drives the engine with :func:`socks5_dial`, exactly like the app
would.  Spawn tests are skipped on Windows (POSIX shebang scripts).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import socketserver
import sys
import textwrap
import threading

import pytest

from proto_clean.vpn.protocols import naive as NV
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.socks_server import socks5_dial

POSIX_ONLY = pytest.mark.skipif(sys.platform.startswith("win"),
                                reason="POSIX-only fake executables")

PROFILE = M.NaiveProfile(server="naive.example.com", port=443,
                         username="a@b", password="p@ss w0rd/123",
                         sni="cdn.example.com")


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
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n"
                    + textwrap.dedent(body).lstrip("\n"))
    path.chmod(0o755)
    return str(path)


# ---------------------------------------------------------- build_naive_config
def test_build_naive_config_golden():
    cfg = NV.build_naive_config(PROFILE, 10880)
    assert cfg == {
        "listen": "socks://127.0.0.1:10880",
        # "a@b" -> a%40b, "p@ss w0rd/123" -> p%40ss%20w0rd%2F123
        "proxy": "https://a%40b:p%40ss%20w0rd%2F123@cdn.example.com:443",
        "log": "",
    }


def test_build_naive_config_sni_fallback_and_defaults():
    p = M.NaiveProfile(server="plain.example.com", port=8443,
                       username="u", password="p")
    cfg = NV.build_naive_config(p, 10881)
    assert cfg["proxy"] == "https://u:p@plain.example.com:8443"
    assert cfg["listen"] == "socks://127.0.0.1:10881"


def test_build_naive_config_dns_param_reserved():
    """The official binary exposes no DNS override — the golden shape
    stays listen/proxy/log even when callers pass ``dns``."""
    cfg = NV.build_naive_config(PROFILE, 10880, dns="1.1.1.1")
    assert set(cfg) == {"listen", "proxy", "log"}


# ------------------------------------------------------------ binary discovery
def test_find_naive_binary_env_var(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only executable bit handling")
    fake = tmp_path / "naive"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PROTO_CLEAN_NAIVE_BIN", str(fake))
    assert NV.find_naive_binary() == str(fake)
    assert NV.find_naive_binary(explicit=str(fake)) == str(fake)


def test_find_naive_binary_missing(monkeypatch):
    monkeypatch.delenv("PROTO_CLEAN_NAIVE_BIN", raising=False)
    assert NV.find_naive_binary("/nonexistent/naive-xyz") is None


# ---------------------------------------------------------------- engine bits
def test_engine_class_attributes():
    eng = NV.engine(PROFILE, socks_port=19111)
    assert isinstance(eng, NV.NaiveEngine)
    assert eng.proxy_kind == "naive"
    assert eng.family == "proxy"
    assert eng.exposes == "socks"
    assert eng.binary_name == "naive"
    assert eng.supports_upstream is False
    assert eng.socks_port == 19111
    st = eng.status()
    assert st["kind"] == "naive"
    assert st["running"] is False
    assert st["server"] == ""
    assert st["sni"] == ""


def test_engine_status_reports_server_offline():
    eng = NV.NaiveEngine(socks_port=19121)
    eng.profile = PROFILE
    eng.config_path = "/tmp/naive.json"
    st = eng.status()
    assert st["running"] is False
    assert st["server"] == "naive.example.com:443"
    assert st["sni"] == "cdn.example.com"
    assert st["config"] == "/tmp/naive.json"


def test_engine_rejects_bad_profiles(tmp_path, monkeypatch):
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    eng = NV.NaiveEngine()
    with pytest.raises(ProtocolError):
        eng.start(M.NaiveProfile(server="", port=443,
                                 username="u", password="p"))
    with pytest.raises(ProtocolError):
        eng.start(M.NaiveProfile(server="s.example", port=70000,
                                 username="u", password="p"))


def test_engine_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    monkeypatch.setattr(NV, "find_naive_binary", lambda explicit="": None)
    eng = NV.NaiveEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE)
    assert "klzgrad/naiveproxy" in str(ei.value)
    assert eng.running is False


def test_engine_stop_without_start_is_noop():
    eng = NV.NaiveEngine()
    eng.stop()                                 # must not raise
    assert eng.running is False


# ----------------------------------------------------------- fake naive binary
# A tiny TCP proxy with the ports baked in: reads the config json (naive
# takes the config path as its only argument), answers the SOCKS5
# handshake and pipes every CONNECT through to the echo server.
FAKE_NAIVE_BODY = """
    import json, socket, sys, threading

    LISTEN_PORT = __LISTEN_PORT__
    ECHO_PORT = __ECHO_PORT__

    def recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("unexpected EOF")
            buf += chunk
        return buf

    def pipe(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(client):
        upstream = None
        try:
            greeting = recv_exact(client, 3)          # VER NMETHODS METHODS
            if greeting[0] != 5:
                return
            client.sendall(b"\\x05\\x00")              # no auth
            head = recv_exact(client, 4)              # VER CMD RSV ATYP
            atyp = head[3]
            if atyp == 1:                             # IPv4
                recv_exact(client, 6)
            elif atyp == 3:                           # domain
                ln = recv_exact(client, 1)[0]
                recv_exact(client, 1 + ln + 2)
            elif atyp == 4:                           # IPv6
                recv_exact(client, 18)
            else:
                return
            client.sendall(b"\\x05\\x00\\x00\\x01" + b"\\x00" * 6)
            upstream = socket.create_connection(("127.0.0.1", ECHO_PORT),
                                                timeout=5)
            up = threading.Thread(target=pipe, args=(client, upstream),
                                  daemon=True)
            down = threading.Thread(target=pipe, args=(upstream, client),
                                    daemon=True)
            up.start()
            down.start()
            up.join()
            down.join()
        except OSError:
            pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

    with open(sys.argv[1]) as f:                      # naive: config = argv[1]
        cfg = json.load(f)
    assert cfg["listen"] == "socks://127.0.0.1:%d" % LISTEN_PORT, cfg
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(16)
    sys.stdout.write("fake naive listening on %d\\n" % LISTEN_PORT)
    sys.stdout.flush()
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
"""


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


class _EchoServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture()
def echo_server():
    srv = _EchoServer(("127.0.0.1", 0), _EchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=2)


# ------------------------------------------------------------ engine: lifecycle
@POSIX_ONLY
def test_engine_start_socks5_roundtrip(tmp_path, monkeypatch, echo_server):
    port = _free_port()
    fake = _write_script(tmp_path, "naive",
                         FAKE_NAIVE_BODY
                         .replace("__LISTEN_PORT__", str(port))
                         .replace("__ECHO_PORT__", str(echo_server)))
    monkeypatch.setenv("PROTO_CLEAN_NAIVE_BIN", fake)
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    eng = NV.engine(PROFILE, socks_port=port)
    eng.start(PROFILE, timeout=15)
    try:
        st = eng.status()
        assert st["running"] is True
        assert st["socks_port"] == port
        assert st["server"] == "naive.example.com:443"
        assert st["sni"] == "cdn.example.com"
        # the generated config matches the builder and lives in CONFIG_DIR
        assert os.path.samefile(eng.config_path,
                                tmp_path / "conf" / "naive" / "naive.json")
        with open(eng.config_path) as f:
            data = json.load(f)
        assert data == NV.build_naive_config(PROFILE, port)
        # a REAL socks5 CONNECT through the fake naive to the echo server
        payload = b"ping-through-naive"

        async def flow():
            rd, wr = await socks5_dial("127.0.0.1", port,
                                       "127.0.0.1", echo_server)
            wr.write(payload)
            await wr.drain()
            echo = await asyncio.wait_for(rd.readexactly(len(payload)), 5)
            wr.close()
            return echo

        assert asyncio.run(flow()) == payload
    finally:
        eng.stop()

    assert eng.running is False
    assert eng.status()["running"] is False
    assert not _port_open(port)


@POSIX_ONLY
def test_engine_uses_free_port_when_none_requested(tmp_path, monkeypatch,
                                                   echo_server):
    port = _free_port()
    fake = _write_script(tmp_path, "naive",
                         FAKE_NAIVE_BODY
                         .replace("__LISTEN_PORT__", str(port))
                         .replace("__ECHO_PORT__", str(echo_server)))
    monkeypatch.setenv("PROTO_CLEAN_NAIVE_BIN", fake)
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    eng = NV.NaiveEngine(socks_port=port)      # explicit port is kept
    eng.start(PROFILE, timeout=15)
    try:
        assert eng.socks_port == port
        assert _port_open(port)
        with open(eng.config_path) as f:
            cfg = json.load(f)
        assert cfg["listen"].endswith(":%d" % port)
    finally:
        eng.stop()


@POSIX_ONLY
def test_engine_start_failure_reports_tail(tmp_path, monkeypatch):
    body = """
        import sys
        print("FATAL: listen tcp 127.0.0.1:10880: bind: address in use")
        sys.exit(1)
    """
    monkeypatch.setenv("PROTO_CLEAN_NAIVE_BIN",
                       _write_script(tmp_path, "bad-naive", body))
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    eng = NV.NaiveEngine(socks_port=_free_port())
    with pytest.raises(ProtocolError) as ei:
        eng.start(PROFILE, timeout=15)
    msg = str(ei.value)
    assert "FATAL" in msg                      # stdout tail included
    assert "exited" in msg
    assert eng.running is False
    assert eng._proc is None


@POSIX_ONLY
def test_engine_start_twice_rejected(tmp_path, monkeypatch, echo_server):
    port = _free_port()
    fake = _write_script(tmp_path, "naive",
                         FAKE_NAIVE_BODY
                         .replace("__LISTEN_PORT__", str(port))
                         .replace("__ECHO_PORT__", str(echo_server)))
    monkeypatch.setenv("PROTO_CLEAN_NAIVE_BIN", fake)
    monkeypatch.setattr(NV, "CONFIG_DIR", tmp_path / "conf")
    eng = NV.NaiveEngine(socks_port=port)
    eng.start(PROFILE, timeout=15)
    try:
        with pytest.raises(ProtocolError):
            eng.start(PROFILE, timeout=15)
    finally:
        eng.stop()

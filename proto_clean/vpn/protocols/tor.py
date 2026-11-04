"""Tor engine: drives the real ``tor`` binary (SOCKS5 + control port).

Proto Clean never bundles tor; :func:`find_tor_binary` looks in PATH,
common install dirs, the Tor Browser directory (Windows) and
``PROTO_CLEAN_TOR_BIN``.  The engine writes a private ``torrc`` into the
cache dir, spawns ``tor -f torrc``, waits for the SOCKS inbound to accept
connections and then attaches to the control port with cookie
authentication to follow bootstrap progress and to serve "new identity"
(SIGNAL NEWNYM).

Bridges are supported through pluggable transports (obfs4 / snowflake /
webtunnel); the transport client binaries are located with
:func:`find_transport_binary`.  Chaining works through
``TorProfile.upstream_url`` — the ``socks5://host:port`` of another
engine's local SOCKS inbound becomes ``Socks5Proxy`` in the torrc, so Tor
dials its guards through it (Tor-over-Xray).
"""

from __future__ import annotations

import binascii
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse as _up
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...log import get
from ...paths import CACHE_DIR
from . import models as M
from .base import (PROXY_FAMILY, ProtocolEngine, ProtocolError, find_binary,
                   free_port, wait_port, write_private)

log = get("tor")

# The Tor Browser bundle ships tor.exe here (Windows).
_WIN_TOR_BROWSER_DIR = r"C:\Program Files\Tor Browser\Browser"
_WIN_PT_DIR = os.path.join(_WIN_TOR_BROWSER_DIR, "TorBrowser", "Tor",
                           "PluggableTransports")
_TOR_EXTRA_DIRS: Tuple[str, ...] = \
    (_WIN_TOR_BROWSER_DIR,) if sys.platform.startswith("win") else ()
_PT_EXTRA_DIRS: Tuple[str, ...] = \
    (_WIN_PT_DIR,) if sys.platform.startswith("win") else ()

_TOR_BINARY_HELP = ("the tor binary was not found — install Tor "
                    "(https://www.torproject.org) or Tor Browser, or set "
                    "PROTO_CLEAN_TOR_BIN")

#: candidate binary names per pluggable-transport kind
_TRANSPORT_BINARIES: Dict[str, Tuple[str, ...]] = {
    "obfs4": ("obfs4proxy",),
    "snowflake": ("snowflake-client", "snowflake-proxy"),
    "webtunnel": ("webtunnel-client", "webtunnel"),
}

#: human hints for the "missing plugin" error
_TRANSPORT_HINTS: Dict[str, str] = {
    "obfs4": "obfs4proxy",
    "snowflake": "snowflake-client",
    "webtunnel": "webtunnel-client",
}


# ---------------------------------------------------------------------------
# binary discovery
# ---------------------------------------------------------------------------
def find_tor_binary(explicit: str = "") -> Optional[str]:
    """Locate the ``tor`` binary. Returns None when not installed."""
    if explicit:
        explicit = explicit.strip()
        if explicit and os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
    return find_binary(("tor", "tor.exe"), env_var="PROTO_CLEAN_TOR_BIN",
                       extra_dirs=_TOR_EXTRA_DIRS)


def find_transport_binary(kind: str) -> Optional[str]:
    """Locate a pluggable-transport client (obfs4proxy, snowflake-client, …).

    Returns the path, or None when the kind is unknown / not installed.
    """
    names = _TRANSPORT_BINARIES.get((kind or "").strip().lower(), ())
    if not names:
        return None
    return find_binary(names, extra_dirs=_PT_EXTRA_DIRS)


# ---------------------------------------------------------------------------
# bridge lines
# ---------------------------------------------------------------------------
def _split_host_port(token: str, text: str) -> Tuple[str, str]:
    if token.startswith("["):                       # [2001:db8::1]:443
        host, sep, tail = token.partition("]")
        if not sep or not tail.startswith(":"):
            raise ProtocolError("bad bridge line %r — expected [IPv6]:port"
                                % text)
        return host[1:], tail[1:]
    host, sep, port = token.partition(":")
    if not sep or not host:
        raise ProtocolError("bad bridge line %r — expected addr:port" % text)
    return host, port


def parse_bridge_line(line: str) -> Dict[str, object]:
    """Parse a Tor bridge line into its parts.

    Accepts ``obfs4 1.2.3.4:443 CERT=xxx iat-mode=0``,
    ``snowflake 1.2.3.4:80 <fingerprint-or-key>``,
    ``webtunnel 1.2.3.4:443 public=…`` and vanilla ``1.2.3.4:443 <fp>``.
    Raises :class:`ProtocolError` on garbage.
    """
    text = (line or "").strip()
    if not text:
        raise ProtocolError("empty bridge line")
    if text.startswith("#"):
        raise ProtocolError("comment is not a bridge line: %r" % text)
    tokens = text.split()
    transport = ""
    rest = tokens
    if ":" not in tokens[0]:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", tokens[0]):
            raise ProtocolError("bad bridge line %r — unknown transport %r"
                                % (text, tokens[0]))
        transport = tokens[0].lower()
        rest = tokens[1:]
    if not rest:
        raise ProtocolError("bad bridge line %r — missing address" % text)
    host, port_s = _split_host_port(rest[0], text)
    try:
        port = int(port_s)
    except ValueError:
        raise ProtocolError("bad bridge line %r — port %r is not a number"
                            % (text, port_s)) from None
    if not 0 < port < 65536:
        raise ProtocolError("bad bridge line %r — port %d out of range"
                            % (text, port))
    fingerprint = ""
    params: Dict[str, str] = {}
    for tok in rest[1:]:
        if "=" in tok:
            key, val = tok.split("=", 1)
            if not key:
                raise ProtocolError("bad bridge line %r — empty parameter"
                                    % text)
            params[key] = val
        elif not fingerprint:
            fingerprint = tok
        else:
            raise ProtocolError("bad bridge line %r — unexpected token %r"
                                % (text, tok))
    return {"transport": transport, "addr": host, "port": port,
            "fingerprint": fingerprint, "params": params}


# ---------------------------------------------------------------------------
# torrc generation
# ---------------------------------------------------------------------------
def build_torrc(profile: M.TorProfile, socks_port: int, control_port: int,
                data_dir: str, transport_map: Optional[Dict[str, str]] = None,
                upstream: Tuple[str, int] = ("127.0.0.1", 0)) -> str:
    """Render the torrc for ``profile``.

    ``transport_map`` maps pluggable-transport kind -> client binary path;
    only kinds present in the map get a ``ClientTransportPlugin`` line (the
    ENGINE validates that every bridge kind is covered and raises
    :class:`ProtocolError` for missing binaries before calling this).
    ``upstream`` is the local SOCKS the Tor daemon dials through.
    """
    tmap = transport_map or {}
    lines: List[str] = [
        "SocksPort 127.0.0.1:%d" % int(socks_port),
        "ControlPort 127.0.0.1:%d" % int(control_port),
    ]
    if upstream and upstream[1]:
        host = upstream[0] or "127.0.0.1"
        lines.append("Socks5Proxy %s:%d" % (host, int(upstream[1])))
    lines += [
        "CookieAuthentication 1",
        "DataDirectory %s" % data_dir,
        "Log notice file %s" % os.path.join(data_dir, "notice.log"),
        "ClientOnly 1",
    ]
    bridges = [(b or "").strip() for b in (profile.bridges or [])]
    bridges = [b for b in bridges if b and not b.startswith("#")]
    if bridges:
        lines.append("UseBridges 1")
        kinds: List[str] = []
        for raw in bridges:                      # distinct kinds, in order
            try:
                kind = parse_bridge_line(raw)["transport"]
            except ProtocolError:
                continue                         # the engine already validated
            kind = str(kind)
            if kind and kind not in kinds:
                kinds.append(kind)
        for kind in kinds:
            path = tmap.get(kind)
            if path:
                lines.append("ClientTransportPlugin %s exec %s" % (kind, path))
        for raw in bridges:
            lines.append("Bridge %s" % raw)
    if (profile.exit_nodes or "").strip():
        lines.append("ExitNodes %s" % profile.exit_nodes.strip())
    if (profile.entry_nodes or "").strip():
        lines.append("EntryNodes %s" % profile.entry_nodes.strip())
    if profile.strict_nodes:
        lines.append("StrictNodes 1")
    return "\n".join(lines) + "\n"


def _parse_upstream_url(url: str) -> Tuple[str, int]:
    """Extract (host, port) of the upstream SOCKS from ``upstream_url``."""
    text = (url or "").strip()
    if not text:
        return ("", 0)
    parsed = _up.urlparse(text)
    if parsed.scheme in ("socks5", "socks5h", "socks4", "socks4a", "socks"):
        host = parsed.hostname or "127.0.0.1"
        try:
            port = parsed.port
        except ValueError:
            raise ProtocolError("bad upstream port in %r" % text) from None
        return (host, int(port or 1080))
    if "://" in text:
        raise ProtocolError(
            "unsupported upstream %r — the upstream engine's local SOCKS "
            "must look like socks5://127.0.0.1:<port>" % text)
    host, sep, port_s = text.partition(":")
    if not sep:
        raise ProtocolError(
            "unsupported upstream %r — expected socks5://host:port" % text)
    try:
        port = int(port_s)
    except ValueError:
        raise ProtocolError("bad upstream port %r" % port_s) from None
    if not 0 < port < 65536:
        raise ProtocolError("bad upstream port %d" % port)
    return (host or "127.0.0.1", port)


# ---------------------------------------------------------------------------
# control-port client (minimal, no stem)
# ---------------------------------------------------------------------------
class TorControl:
    """A tiny Tor control-port client speaking the plain socket protocol.

    Only what the engine needs: cookie authentication, SIGNAL (NEWNYM),
    GETINFO and bootstrap progress. Every socket op has a timeout;
    :class:`ProtocolError` is raised for 4xx/5xx replies and IO trouble.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._buf = b""

    # -- transport ----------------------------------------------------------
    def _read_line(self) -> str:
        while b"\n" not in self._buf:
            if self._sock is None:
                raise ProtocolError("not connected to the Tor control port")
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                raise ProtocolError("timeout reading from the Tor control "
                                    "port") from None
            except OSError as e:
                raise ProtocolError("Tor control connection error: %s" % e) \
                    from None
            if not chunk:
                raise ProtocolError("Tor control connection closed")
            self._buf += chunk
        raw, self._buf = self._buf.split(b"\n", 1)
        return raw.rstrip(b"\r").decode("utf-8", "replace")

    def _read_reply(self) -> Tuple[int, List[Tuple[str, str]]]:
        """Read one reply; returns (code, [(sep, text), …]).

        Data blocks (``250+key=`` … ``.``) are flattened into a single
        ``("-" , "key=<block>")`` item.
        """
        items: List[Tuple[str, str]] = []
        while True:
            line = self._read_line()
            if len(line) < 4 or not line[:3].isdigit():
                raise ProtocolError("malformed Tor control reply: %r" % line)
            code = int(line[:3])
            sep, text = line[3], line[4:]
            if sep == " ":
                items.append((" ", text))
                return code, items
            if sep == "-":
                items.append(("-", text))
                continue
            if sep == "+":
                block: List[str] = []
                while True:
                    data = self._read_line()
                    if data == ".":
                        break
                    block.append(data)
                items.append(("-", text + "\n".join(block)))
                continue
            raise ProtocolError("malformed Tor control reply: %r" % line)

    def _send_line(self, line: str) -> None:
        if self._sock is None:
            raise ProtocolError("not connected to the Tor control port")
        try:
            self._sock.sendall((line + "\r\n").encode("utf-8"))
        except OSError as e:
            raise ProtocolError("Tor control send failed: %s" % e) from None

    def _command(self, line: str) -> Tuple[int, List[Tuple[str, str]]]:
        self._send_line(line)
        return self._read_reply()

    # -- protocol -----------------------------------------------------------
    def connect(self, host: str, port: int, cookie_path: str) -> None:
        """Connect and authenticate with the control-port cookie file."""
        try:
            with open(cookie_path, "rb") as f:
                cookie = f.read()
        except OSError as e:
            raise ProtocolError("cannot read the Tor control cookie %s: %s"
                                % (cookie_path, e)) from None
        if not cookie:
            raise ProtocolError("empty Tor control cookie at %s" % cookie_path)
        try:
            sock = socket.create_connection((host, int(port)),
                                            timeout=self.timeout)
        except OSError as e:
            raise ProtocolError("cannot reach the Tor control port "
                                "%s:%d: %s" % (host, port, e)) from None
        sock.settimeout(self.timeout)
        self._sock = sock
        self._buf = b""
        try:
            code, items = self._command(
                "AUTHENTICATE " + binascii.hexlify(cookie).decode("ascii"))
        except ProtocolError:
            self.close()
            raise
        if code != 250:
            self.close()
            raise ProtocolError("Tor authentication failed (%d): %s"
                                % (code, items[-1][1] if items else ""))

    def signal(self, signal_name: str) -> None:
        code, items = self._command("SIGNAL " + signal_name)
        if code not in (250, 251):
            raise ProtocolError("SIGNAL %s failed (%d): %s"
                                % (signal_name, code,
                                   items[-1][1] if items else ""))

    def get_info(self, *keys: str) -> Dict[str, str]:
        code, items = self._command("GETINFO " + " ".join(keys))
        if code != 250:
            raise ProtocolError("GETINFO %s failed (%d): %s"
                                % (" ".join(keys), code,
                                   items[-1][1] if items else ""))
        info: Dict[str, str] = {}
        current: Optional[str] = None
        for sep, text in items:
            if sep == " ":
                break
            if sep != "-":
                continue
            if "=" in text:
                key, val = text.split("=", 1)
                current = key
                info[key] = (info[key] + "\n" + val) if key in info else val
            elif current is not None:
                # multi-line style: value continues on the next 250- line
                info[current] += ("\n" if info[current] else "") + text
        return info

    def bootstrap_status(self) -> float:
        """Bootstrap progress as a 0-100 percentage (0.0 when unknown)."""
        info = self.get_info("status/bootstrap-phase")
        raw = info.get("status/bootstrap-phase", "")
        m = re.search(r"PROGRESS=(\d+)", raw)
        return float(m.group(1)) if m else 0.0

    def close(self) -> None:
        sock, self._sock = self._sock, None
        self._buf = b""
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class TorEngine(ProtocolEngine):
    """Runs the ``tor`` daemon and exposes its SOCKS5 inbound locally."""

    proxy_kind = "tor"
    family = PROXY_FAMILY                  # "proxy"
    exposes = "socks"
    binary_name = "tor"
    supports_upstream = True               # Tor dials its guards via Socks5Proxy

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self.control_port = 0
        self.data_dir = ""
        self.torrc_path = ""
        self.bootstrap = 0.0               # best-effort bootstrap percentage
        self.profile: Optional[M.TorProfile] = None
        self._control: Optional[TorControl] = None

    # -- helpers ------------------------------------------------------------
    def _dir(self) -> Path:
        d = CACHE_DIR / self.proxy_kind
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)             # cookie auth demands a private dir
        except OSError:
            pass
        return d

    def _notice_tail(self, lines: int = 8) -> str:
        """Last lines of the tor notice log (for failure messages)."""
        if not self.data_dir:
            return ""
        try:
            text = (Path(self.data_dir) / "notice.log").read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            return ""
        keep = [l.strip() for l in text.strip().splitlines() if l.strip()]
        return "; ".join(keep[-lines:])

    def _resolve_transports(self, profile: M.TorProfile) -> Dict[str, str]:
        """Validate bridge lines and locate the pluggable-transport clients."""
        kinds: List[str] = []
        for raw in profile.bridges or []:
            line = (raw or "").strip()
            if not line or line.startswith("#"):
                continue
            try:
                kind = str(parse_bridge_line(line)["transport"])
            except ProtocolError as e:
                raise ProtocolError("bad bridge line %r: %s" % (line, e)) \
                    from None
            if kind and kind not in kinds:
                kinds.append(kind)
        if not kinds:
            return {}
        mapping: Dict[str, str] = {}
        missing: List[str] = []
        for kind in kinds:
            path = find_transport_binary(kind)
            if path:
                mapping[kind] = path
            else:
                missing.append(kind)
        if missing:
            hints = ", ".join("%s (install %s)"
                              % (k, _TRANSPORT_HINTS.get(k, k))
                              for k in missing)
            raise ProtocolError(
                "missing Tor pluggable transport binaries: %s — install them "
                "(e.g. from the Tor Browser bundle) or put them on PATH"
                % hints)
        return mapping

    def _poll_bootstrap(self, attempts: int = 5, delay: float = 0.3) -> None:
        """Best-effort bootstrap read — never fails the engine."""
        ctrl = self._control
        if ctrl is None:
            return
        best = self.bootstrap
        for _ in range(attempts):
            try:
                best = max(best, ctrl.bootstrap_status())
            except ProtocolError as e:
                log.warning("bootstrap poll failed: %s", e)
                break
            if best >= 90.0:
                break
            time.sleep(delay)
        self.bootstrap = best

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.TorProfile, timeout: float = 60.0) -> None:
        if self.running:
            raise ProtocolError("the Tor proxy is already running")
        exe = find_tor_binary()
        if not exe:
            raise ProtocolError(_TOR_BINARY_HELP)
        self.profile = profile
        self.bootstrap = 0.0
        self.socks_port = free_port(self.socks_port or 9050)
        self.control_port = free_port(self.control_port or 9051)
        data_dir = self._dir()
        self.data_dir = str(data_dir)
        transport_map = self._resolve_transports(profile)
        if (profile.upstream_url or "").strip():
            self.upstream_socks = _parse_upstream_url(profile.upstream_url)
        else:
            self.upstream_socks = ("", 0)
        self.torrc_path = str(data_dir / "torrc")
        write_private(self.torrc_path,
                      build_torrc(profile, self.socks_port, self.control_port,
                                  self.data_dir, transport_map,
                                  upstream=self.upstream_socks))
        try:
            self.spawn([exe, "-f", self.torrc_path], cwd=self.data_dir)
            wait_port(self.socks_port, timeout=timeout,
                      stop=lambda: not self.running)
        except ProtocolError as e:
            self.stop()
            msg = str(e)
            tail = self._notice_tail()
            if tail:
                msg += " — " + tail
            raise ProtocolError(msg) from None
        cookie_path = str(data_dir / "control_auth_cookie")
        ctrl = TorControl(timeout=5.0)
        try:
            ctrl.connect("127.0.0.1", self.control_port, cookie_path)
        except ProtocolError as e:
            log.warning("tor control port %d unavailable: %s",
                        self.control_port, e)
        else:
            self._control = ctrl
            self._poll_bootstrap()
        log.info("tor up (socks %d, control %d, bootstrap %.0f%%, %d bridge(s))",
                 self.socks_port, self.control_port, self.bootstrap,
                 len(self.profile.bridges or []))

    def new_identity(self) -> None:
        """Ask tor for a fresh circuit (SIGNAL NEWNYM)."""
        ctrl = self._control
        if ctrl is None:
            raise ProtocolError("the Tor control connection is not available")
        ctrl.signal("NEWNYM")

    def status(self) -> dict:
        d = super().status()
        d.update({
            "bootstrap": self.bootstrap,
            "bridges": len(self.profile.bridges or []) if self.profile else 0,
            "control_port": self.control_port,
            "data_dir": self.data_dir,
        })
        return d

    def stop(self, timeout: float = 5.0) -> None:
        ctrl, self._control = self._control, None
        if ctrl is not None:
            try:
                ctrl.close()
            except Exception:              # noqa: BLE001 — best effort
                pass
        proc = self._proc
        if proc is not None and proc.poll() is None:
            if sys.platform.startswith("win"):
                # /T kills tor *and* its pluggable-transport children
                subprocess.run(["taskkill", "/F", "/T", "/PID",
                                str(proc.pid)],
                               capture_output=True, check=False)
                try:
                    proc.wait(timeout)
                except subprocess.TimeoutExpired:
                    pass
            else:
                proc.terminate()
                try:
                    proc.wait(timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout)
        self._proc = None
        super().stop(timeout)
        self.bootstrap = 0.0
        log.info("tor stopped")


def engine(profile: M.TorProfile, socks_port: int = 0) -> TorEngine:
    """Registry factory for the ``tor`` protocol kind."""
    return TorEngine(socks_port=socks_port)

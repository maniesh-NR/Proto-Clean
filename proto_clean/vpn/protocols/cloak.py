"""OpenVPN-over-Cloak composite engine (cbeuw/Cloak ``ck-client`` + openvpn).

Cloak is not a proxy by itself: ``ck-client`` exposes a local SOCKS5
inbound (port 1984 by default) and masquerades everything that flows
into it as TLS web traffic towards ``remoteHost:remotePort``, where the
ck-server hands the stream to the underlying proxy program — OpenVPN in
this engine's case.  The composite therefore runs TWO processes:

1. ``ck-client`` with a generated ``ckclient.json``
   (:func:`build_ckclient_json`, matching Cloak's documented field set:
   Transport / ProxyMethod / EncryptionMethod / UID / PublicKey /
   ServerName / NumConn / BrowserSig / StreamTimeout /
   AlternativeNames);
2. ``openvpn`` with a composed config (:func:`compose_openvpn_config`)
   whose ``remote`` points at the Cloak server entry and whose
   ``socks-proxy 127.0.0.1 <port>`` routes the tunnel through the local
   ck-client SOCKS (Cloak's SOCKS only carries TCP, so ``proto tcp`` is
   enforced; existing ``remote``/``proto``/``socks-proxy`` lines of the
   provider's base config are replaced, everything else — ca/cert/key
   blocks — is kept verbatim).

ck-client CLI flags — verified against cbeuw/Cloak ``cmd/ck-client``:

    -i  localHost   (default "127.0.0.1")   local SOCKS bind IP
    -l  localPort   (default "1984")        local SOCKS listen port
    -s  remoteHost  (no default!)           IP/host of the proxy server
    -p  remotePort  (default "443")         proxy server port
    -u  udp                                 underlying proxy uses UDP
    -c  config      (default "ckclient.json")
    -proxy <name>                           ProxyMethod override
    -a  adminUID    -v / -h                 -verbosity <level>

The config JSON carries NO server address, so standalone ck-client
*requires* ``-s <server>`` (``client.ParseConfig`` rejects an empty
RemoteHost); the local SOCKS port override is ``-l`` (not ``-o``).
Because flags vary between Cloak versions and forks, ``start`` runs
``ck-client -h`` once (output captured, failure ignored),
:func:`parse_ck_help` maps whatever usage text was printed, and the
engine passes ``-s``/``-p`` (from the profile) and ``-l`` (for a
non-default local port) only when the captured help advertises them —
an unparseable help text degrades to the plain ``-c <config>``
invocation, which is the only form every build understands.

Failure hints point at https://github.com/cbeuw/Cloak/releases (and
``PROTO_CLEAN_CLOAK_BIN``); the OpenVPN half needs the ``openvpn``
binary (``PROTO_CLEAN_OPENVPN_BIN``).  The tunnel is up when openvpn's
output shows "Initialization Sequence Completed" — the pump thread
buffering openvpn's stdout feeds :meth:`CloakEngine.tunnel_ready`.
"""

from __future__ import annotations

import json as _json
import os
import re
import subprocess
import sys
import threading
import time
from typing import Dict, Optional

from ...log import get
from ...paths import CONFIG_DIR
from . import models as M
from .base import (PROXY_FAMILY, ProtocolEngine, ProtocolError, find_binary,
                   free_port, wait_port, write_private)

log = get("protocols.cloak")

#: ck-client's documented default local SOCKS port
CK_DEFAULT_SOCKS = 1984
#: openvpn stdout marker for an established tunnel
CK_TUNNEL_MARKER = "Initialization Sequence Completed"

_CK_BINARY_HELP = ("the ck-client binary was not found — download Cloak from "
                   "https://github.com/cbeuw/Cloak/releases or set "
                   "PROTO_CLEAN_CLOAK_BIN")
_OVPN_BINARY_HELP = ("OpenVPN-over-Cloak needs both binaries — ck-client was "
                     "found but openvpn was not; install OpenVPN "
                     "(https://openvpn.net) or set PROTO_CLEAN_OPENVPN_BIN")

#: .ovpn directives the composite owns (stripped from the base config and
#: re-emitted from the profile); "remote-cert-tls" is NOT in this list and
#: survives verbatim.
_OWNED_DIRECTIVES = ("remote", "proto", "socks-proxy")


# ---------------------------------------------------------------------------
# config builders
# ---------------------------------------------------------------------------
def build_ckclient_json(profile: M.CloakProfile,
                        proxy_method: str = "openvpn") -> dict:
    """Render ``profile`` as a ckclient.json body (Cloak's documented
    client field set; the server address is NOT part of the file —
    standalone ck-client takes it from ``-s``/``-p``)."""
    return {
        "Transport": profile.transport or "direct",
        "ProxyMethod": proxy_method,
        "EncryptionMethod": profile.encryption_method,
        "UID": profile.uid,
        "PublicKey": profile.public_key,
        "ServerName": profile.server_name,
        "NumConn": profile.num_conn,
        "BrowserSig": profile.browser_sig,
        "StreamTimeout": 300,
        "AlternativeNames": list(profile.alternative_names or []),
    }


def compose_openvpn_config(profile: M.CloakProfile,
                           cloak_socks_port: int) -> str:
    """OpenVPN client config that tunnels THROUGH the local Cloak SOCKS.

    ``profile.openvpn_config`` is the base when non-empty, otherwise a
    minimal client skeleton is synthesised (client / dev tun / nobind /
    persist-key / persist-tun / remote-cert-tls server).  From the base
    every ``remote``, ``proto`` and ``socks-proxy`` line is stripped
    (Cloak's SOCKS requires TCP) and three directives are re-emitted:

    * ``proto tcp``;
    * ``remote <cloak-server> <port>`` — the ck-server masquerade entry,
      i.e. the destination the SOCKS CONNECT asks for;
    * ``socks-proxy 127.0.0.1 <cloak_socks_port>``.

    Everything else (ca/cert/key blocks, ciphers, …) is kept verbatim.
    """
    base = (profile.openvpn_config or "").strip()
    if base:
        lines = base.splitlines()
    else:
        lines = ["client", "dev tun", "nobind", "persist-key", "persist-tun",
                 "remote-cert-tls server"]
    kept = []
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", ";")) and \
                stripped.split()[0].lower() in _OWNED_DIRECTIVES:
            continue
        kept.append(line)
    out = ["proto tcp"]
    out.extend(kept)
    out.append("remote %s %d" % (profile.server, int(profile.port)))
    out.append("socks-proxy 127.0.0.1 %d" % int(cloak_socks_port))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# ck-client CLI discovery
# ---------------------------------------------------------------------------
_FLAG_RE = re.compile(r"^-([A-Za-z0-9][A-Za-z0-9_.+-]*)(?:\s+(.*))?$")
_TYPE_TOKENS = frozenset(("string", "int", "int64", "uint", "uint64", "float",
                          "duration", "bool", "value"))


def parse_ck_help(text: str) -> Dict[str, str]:
    """Map the flags advertised by ``ck-client -h`` to their descriptions.

    Understands the Go ``flag`` package usage layout (which ck-client
    prints via ``flag.Usage()``)::

        Usage of ck-client:
          -c string
                config: path to the configuration file (default "ckclient.json")
          -u    udp: set this flag if the underlying proxy is using UDP

    Returns ``{flag_name_without_dashes: description}`` (empty description
    for bare boolean flags); anything unparseable yields ``{}`` — the
    engine then falls back to the minimal ``-c <config>`` invocation.
    """
    flags: Dict[str, str] = {}
    current: Optional[str] = None
    for raw in (text or "").splitlines():
        stripped = raw.rstrip().strip()
        if not stripped:
            continue
        if stripped.startswith("-"):
            m = _FLAG_RE.match(stripped)
            if m is not None:
                name, rest = m.group(1), (m.group(2) or "").strip()
                if rest in _TYPE_TOKENS:      # Go's two-line form
                    flags[name] = ""
                    current = name
                elif rest:                    # one-line form: "-u\tusage..."
                    flags[name] = rest
                    current = None
                else:
                    flags[name] = ""
                    current = name
                continue
        if current is not None:               # continuation of the usage text
            flags[current] = (flags[current] + " " + stripped).strip()
    return flags


def _capture_ck_help(exe: str, timeout: float = 10.0) -> str:
    """Run ``ck-client -h`` once and return its output ("" on any failure).

    Go's flag package prints usage to stderr and exits 2, so stdout and
    stderr are merged and the exit code is ignored.
    """
    try:
        r = subprocess.run([exe, "-h"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return (r.stdout or b"").decode("utf-8", "replace")
    except Exception:                          # noqa: BLE001 — best effort
        return ""


# ---------------------------------------------------------------------------
# binary discovery
# ---------------------------------------------------------------------------
def find_ck_client(explicit: str = "") -> Optional[str]:
    """Locate the ``ck-client`` binary (PATH, common dirs,
    ``PROTO_CLEAN_CLOAK_BIN``). Returns None when not installed."""
    return find_binary(("ck-client", "ck-client.exe"),
                       env_var="PROTO_CLEAN_CLOAK_BIN")


def find_openvpn_binary(explicit: str = "") -> Optional[str]:
    """Locate the ``openvpn`` binary (PATH, common dirs,
    ``PROTO_CLEAN_OPENVPN_BIN``). Returns None when not installed."""
    return find_binary(("openvpn", "openvpn.exe"),
                       env_var="PROTO_CLEAN_OPENVPN_BIN")


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class CloakEngine(ProtocolEngine):
    """OpenVPN tunnelled through a local ``ck-client`` SOCKS inbound.

    ``self.socks_port`` IS the ck-client SOCKS port (1984 when free) —
    that is what the engine exposes and what the composed OpenVPN config
    dials through.  ``start`` brings up ck-client (phase "cloak"), then
    openvpn and waits for the tunnel marker (phase "tunnel").
    """

    proxy_kind = "cloak"
    family = PROXY_FAMILY                  # "proxy"
    exposes = "socks"
    binary_name = "ck-client"
    supports_upstream = False              # Cloak dials directly; no chaining

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self.profile: Optional[M.CloakProfile] = None
        self.ck_proc: Optional[subprocess.Popen] = None
        self.ovpn_proc: Optional[subprocess.Popen] = None
        self.ck_config_path = ""
        self.ovpn_config_path = ""
        self.ck_help_text = ""             # raw `ck-client -h` output
        self.ck_help_flags: Dict[str, str] = {}
        self.phase = ""                    # "" | "cloak" | "tunnel"
        self._out_buf = ""                 # openvpn stdout buffer
        self._buf_lock = threading.Lock()
        self._log_thread: Optional[threading.Thread] = None

    # -- helpers ------------------------------------------------------------
    def _dir(self) -> str:
        d = os.path.join(str(CONFIG_DIR), self.proxy_kind)
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return d

    @staticmethod
    def _proc_tail(proc: Optional[subprocess.Popen], chars: int = 800) -> str:
        """Last stdout bytes of an EXITED process (for error messages)."""
        if proc is None or proc.poll() is None or proc.stdout is None:
            return ""
        try:
            return (proc.stdout.read() or b"").decode("utf-8", "replace") \
                .strip()[-chars:]
        except Exception:                      # noqa: BLE001 — best effort
            return ""

    def _buffer_tail(self, chars: int = 800) -> str:
        with self._buf_lock:
            return self._out_buf.strip()[-chars:]

    def _watch_output(self) -> None:
        """Pump openvpn's stdout into ``self._out_buf`` (daemon thread)."""
        proc = self.ovpn_proc
        if proc is None or proc.stdout is None:
            return

        def pump() -> None:
            try:
                for raw in iter(proc.stdout.readline, b""):
                    text = raw.decode("utf-8", "replace")
                    with self._buf_lock:
                        # bounded: a verbose openvpn on a long session
                        # used to grow this buffer without limit
                        self._out_buf = (self._out_buf + text)[-16384:]
                    log.debug("openvpn: %s", text.rstrip())
            except Exception:              # noqa: BLE001 — best effort
                pass

        t = threading.Thread(target=pump, daemon=True,
                             name="proto-clean-openvpn-log")
        t.start()
        self._log_thread = t

    def _spawn_openvpn(self, exe: str, cwd: str) -> subprocess.Popen:
        kwargs: dict = {}
        if sys.platform.startswith("win"):
            kwargs["creationflags"] = getattr(subprocess,
                                              "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            [exe, "--config", self.ovpn_config_path, "--auth-nocache"],
            cwd=cwd or None, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, **kwargs)
        return proc

    @staticmethod
    def _kill(proc: Optional[subprocess.Popen], timeout: float) -> None:
        if proc is None or proc.poll() is not None:
            return
        try:
            if sys.platform.startswith("win"):
                # /T kills openvpn/ck-client *and* any children
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
        except Exception:                  # noqa: BLE001 — best effort
            pass

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.CloakProfile, timeout: float = 30.0) -> None:
        if self.running or self.ck_proc is not None or \
                self.ovpn_proc is not None:
            raise ProtocolError("the cloak engine is already running")
        if not isinstance(profile, M.CloakProfile):
            raise ProtocolError("cloak engine needs a CloakProfile")
        if not (profile.server or "").strip():
            raise ProtocolError("cloak: empty server address")
        ck = find_ck_client()
        if not ck:
            raise ProtocolError(_CK_BINARY_HELP)
        self.profile = profile
        self.phase = ""
        self._out_buf = ""

        # discover the CLI surface of THIS ck-client build once
        self.ck_help_text = _capture_ck_help(ck)
        self.ck_help_flags = parse_ck_help(self.ck_help_text)
        log.info("ck-client flags discovered via -h: %s",
                 ", ".join("-" + f for f in sorted(self.ck_help_flags))
                 or "none (falling back to plain -c invocation)")

        self.socks_port = free_port(self.socks_port or CK_DEFAULT_SOCKS)
        d = self._dir()
        self.ck_config_path = os.path.join(d, "ckclient.json")
        write_private(self.ck_config_path,
                      _json.dumps(build_ckclient_json(profile), indent=2,
                                  sort_keys=True) + "\n")
        argv = [ck, "-c", self.ck_config_path]
        flags = self.ck_help_flags
        if "s" in flags and (profile.server or "").strip():
            argv += ["-s", profile.server]
        if "p" in flags:
            argv += ["-p", str(profile.port)]
        port_flag = "l" if "l" in flags else ("o" if "o" in flags else "")
        if port_flag and self.socks_port != CK_DEFAULT_SOCKS:
            argv += ["-" + port_flag, str(self.socks_port)]
        try:
            self.spawn(argv, cwd=d)        # base: sets self._proc
            self.ck_proc = self._proc
            wait_port(self.socks_port, timeout=timeout,
                      stop=lambda: self.ck_proc is None or
                      self.ck_proc.poll() is not None)
        except ProtocolError as e:
            tail = self.output_tail(800) or self._proc_tail(self.ck_proc)
            self.stop()
            msg = "ck-client: %s" % e
            if tail:
                msg += " — " + tail
            raise ProtocolError(msg) from None
        self.phase = "cloak"
        log.info("cloak up (socks 127.0.0.1:%d)", self.socks_port)

        ovpn = find_openvpn_binary()
        if not ovpn:
            self.stop()
            raise ProtocolError(_OVPN_BINARY_HELP)
        self.ovpn_config_path = os.path.join(d, "proto-clean.ovpn")
        write_private(self.ovpn_config_path,
                      compose_openvpn_config(profile, self.socks_port))
        try:
            self.ovpn_proc = self._spawn_openvpn(ovpn, d)
            self._watch_output()
            self.tunnel_ready(timeout=timeout)
        except ProtocolError:
            self.stop()
            raise
        log.info("cloak tunnel established (openvpn pid %d)",
                 self.ovpn_proc.pid)

    def tunnel_ready(self, timeout: float = 30.0) -> None:
        """Block until openvpn prints its "Initialization Sequence
        Completed" marker; raise :class:`ProtocolError` (with the output
        tail) when it exits or the marker never shows up."""
        proc = self.ovpn_proc
        if proc is None:
            raise ProtocolError("openvpn is not running")
        deadline = time.time() + float(timeout)
        while True:
            if proc.poll() is not None:
                tail = self._proc_tail(proc)
                if not tail:
                    # the pump thread may have drained the pipe already —
                    # let it finish and take the buffered output instead
                    t = self._log_thread
                    if t is not None and t.is_alive():
                        t.join(timeout=1.0)
                    tail = self._proc_tail(proc) or self._buffer_tail()
                raise ProtocolError("openvpn exited with code %s%s"
                                    % (proc.returncode,
                                       (":\n" + tail) if tail else ""))
            with self._buf_lock:
                if CK_TUNNEL_MARKER in self._out_buf:
                    self.phase = "tunnel"
                    return
            if time.time() >= deadline:
                tail = self._buffer_tail()
                raise ProtocolError(
                    "timeout waiting for the OpenVPN tunnel to come up%s"
                    % ((" — " + tail) if tail else ""))
            time.sleep(0.1)

    def status(self) -> dict:
        st = super().status()
        ovpn_running = self.ovpn_proc is not None and \
            self.ovpn_proc.poll() is None
        st["cloak_socks"] = self.socks_port
        st["openvpn"] = ovpn_running
        phase = self.phase
        if phase == "tunnel" and not ovpn_running:
            phase = "cloak"                # degraded: SOCKS alive, tunnel down
        st["phase"] = phase
        return st

    def stop(self, timeout: float = 5.0) -> None:
        procs = (self.ovpn_proc, self.ck_proc)   # tunnel first, then cloak
        self.ovpn_proc = None
        self.ck_proc = None
        self._proc = None
        self.phase = ""
        self._started_at = 0.0
        for proc in procs:
            self._kill(proc, timeout)
        self._log_thread = None
        super().stop(timeout)
        log.info("cloak stopped")


def engine(profile: M.CloakProfile, socks_port: int = 0) -> CloakEngine:
    """Registry factory for the ``cloak`` protocol kind."""
    return CloakEngine(socks_port=socks_port)

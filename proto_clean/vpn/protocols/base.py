"""Multi-protocol engine layer for Proto Clean.

Every protocol supported by the app plugs into two building blocks:

* :class:`ProtocolProfile` — a serialisable description of a server
  (credentials, transport options) with a canonical share URL so profiles
  can be round-tripped through links, QR codes and config files.
* :class:`ProtocolEngine` — something that can be started and stopped and
  exposes a local SOCKS5/HTTP proxy (proxy-style engines: Xray, lantern-box,
  Shadowsocks, Hysteria2, TUIC, MASQUE, NaïveProxy, Cover-DTLS, Tor, …) or a
  system tunnel (WireGuard-family: AmneziaWG, Obscura, IKEv2, OpenVPN).

The registry in :mod:`proto_clean.vpn.protocols.__init__` maps profile
``kind`` strings to engine factories so the UI, the importer and the
controller never need to know the individual protocols.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from ...log import get

log = get("protocols")

#: bytes of child-process output kept for error messages (bounded so a
#: chatty child cannot grow memory without limit)
_SPAWN_TAIL = 8192

#: Families: "proxy" engines expose a local proxy, "tunnel" engines take
#: over the device's network. Tunnel engines may only be the FIRST hop of a
#: chain, proxy engines may sit anywhere.
TUNNEL_FAMILY = "tunnel"
PROXY_FAMILY = "proxy"


class ProtocolError(ValueError):
    """Raised for malformed profiles/links or missing binaries."""


class ProtocolProfile:
    """Base class for all protocol profiles."""

    kind = ""                      # registry key, e.g. "shadowsocks"
    title = ""                     # human name, e.g. "Shadowsocks"

    def to_json(self) -> dict:
        d = dict(self.__dict__)
        d["kind"] = self.kind
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ProtocolProfile":
        fields = getattr(cls, "__dataclass_fields__", None)
        if fields:
            kw = {k: v for k, v in d.items() if k in fields}
        else:
            kw = dict(d)
        kw.pop("kind", None)
        return cls(**kw)  # type: ignore[arg-type]

    def share_url(self) -> str:
        """Canonical share link for this profile (importable again)."""
        raise NotImplementedError

    def summary(self) -> str:
        """One-line description for the UI list."""
        return self.title


class ProtocolEngine:
    """A started/stoppable protocol engine.

    Engines are created with the local port(s) they should bind; ``start``
    blocks until the local endpoint is ready (or raises :class:`ProtocolError`);
    ``stop`` tears the engine down. ``status`` returns a small dict used by
    the UI and the controller.
    """

    #: registry key ("shadowsocks", "hysteria2", ...) — set by subclasses
    proxy_kind = ""
    #: "proxy" (local SOCKS/HTTP) or "tunnel" (network-level)
    family = PROXY_FAMILY
    #: what the engine exposes locally: "socks" | "mixed" | "tunnel"
    exposes = "socks"
    #: whether the engine can dial its server through an upstream SOCKS5
    supports_upstream = False
    #: name of the external binary this engine needs ("" = built into Python)
    binary_name = ""

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        self.socks_port = int(socks_port or 0)
        self.http_port = int(http_port or 0)
        self.upstream_socks: Tuple[str, int] = ("", 0)
        self._proc: Optional[subprocess.Popen] = None
        self._started_at = 0.0
        self._log_tail: str = ""        # last child output (drained)
        self._log_lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------
    def start(self, profile: ProtocolProfile, timeout: float = 15.0) -> None:
        raise NotImplementedError

    def stop(self, timeout: float = 5.0) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if sys.platform.startswith("win"):
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, timeout=timeout)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=timeout)
        except Exception:
            pass

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def status(self) -> dict:
        return {
            "kind": self.proxy_kind,
            "family": self.family,
            "running": self.running,
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "exposes": self.exposes,
            "binary": self.binary_name or "builtin",
            "uptime": round(time.time() - self._started_at, 1) if self._started_at else 0,
        }

    # -- helpers for subclasses -------------------------------------------
    def spawn(self, argv: List[str], cwd: str = "") -> subprocess.Popen:
        """Start the external process for this engine.

        The child's stdout/stderr is PIPEd and constantly drained by a
        daemon thread into a bounded tail buffer: without the drain, a
        child that logs more than the OS pipe buffer (~64 KiB) blocks on
        write and the "connection" freezes forever — the classic silent
        deadlock of piped subprocesses.  The tail feeds :meth:`check_process`
        error messages."""
        kwargs: dict = {}
        if sys.platform.startswith("win"):
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = subprocess.Popen(
            argv, cwd=cwd or None, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, **kwargs)
        self._drain_output(self._proc)
        self._started_at = time.time()
        return self._proc

    def _drain_output(self, proc: subprocess.Popen) -> None:
        """Keep the child's pipe empty; retain the last few KB for errors."""
        out = proc.stdout
        if out is None:
            return
        lock = getattr(self, "_log_lock", None)

        def pump() -> None:
            tail = getattr(self, "_log_tail", "")
            try:
                # read1 = at most one raw read: returns whatever arrived,
                # never blocks for a full buffer or a newline
                while True:
                    chunk = out.read1(65536)
                    if not chunk:
                        break
                    tail = (tail + chunk.decode("utf-8", "replace"))[-_SPAWN_TAIL:]
                    try:
                        if lock is not None:
                            with lock:
                                self._log_tail = tail
                        else:
                            self._log_tail = tail
                    except AttributeError:      # engine overrode __init__
                        pass
            except (OSError, ValueError):     # closed / bad fd at shutdown
                pass

        threading.Thread(target=pump, daemon=True,
                         name="proto-clean-engine-log").start()

    def output_tail(self, chars: int = 2000) -> str:
        """The last ``chars`` of drained child output (for error messages)."""
        tail = getattr(self, "_log_tail", "") or ""
        return tail.strip()[-chars:]

    def check_process(self) -> None:
        """Raise :class:`ProtocolError` if the external process died."""
        proc = self._proc
        if proc is not None and proc.poll() is not None:
            tail = self.output_tail()
            if not tail:
                try:
                    if proc.stdout is not None:
                        # drained pipes EOF early; a leftover slice may
                        # still sit in the buffer
                        tail = (proc.stdout.read() or b"").decode(
                            "utf-8", "replace").strip()[-2000:]
                except Exception:
                    pass
            raise ProtocolError(
                "%s exited with code %s%s" % (self.proxy_kind, proc.returncode,
                                              (":\n" + tail) if tail else ""))


def find_binary(names: Tuple[str, ...], env_var: str = "",
                extra_dirs: Tuple[str, ...] = ()) -> Optional[str]:
    """Generalised binary discovery (same rules as the samizdat finder)."""
    candidates: List[str] = []
    env = os.environ.get(env_var, "") if env_var else ""
    if env:
        candidates.append(env)
    for name in names:
        which = shutil.which(name)
        if which:
            candidates.append(which)
    app_dir = os.path.dirname(os.path.abspath(sys.executable))
    meipass = getattr(sys, "_MEIPASS", "")
    exe_sfx = ".exe" if sys.platform.startswith("win") else ""
    for name in names:
        fname = name + exe_sfx
        local_dirs = [app_dir]
        if meipass:
            local_dirs.append(meipass)
        if not sys.platform.startswith("win"):
            local_dirs += ["/opt/proto-clean", "/app/bin",
                           "/usr/local/bin", "/usr/bin",
                           os.path.expanduser("~/bin"), "/opt/homebrew/bin"]
        for d in local_dirs:
            candidates.append(os.path.join(d, fname))
    for d in extra_dirs:
        for name in names:
            candidates.append(os.path.join(d, name + exe_sfx))
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def free_port(preferred: int = 0, host: str = "127.0.0.1") -> int:
    """Return a free localhost port — ``preferred`` if it is free."""
    if preferred and _port_free(preferred, host):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def wait_port(port: int, timeout: float = 10.0, host: str = "127.0.0.1",
              stop: Optional[Callable[[], bool]] = None) -> None:
    """Block until a TCP port ACCEPTS connections.

    Probed by connecting: a successful ``connect`` proves the engine has
    called ``listen()`` — a bind-only check reports "ready" up to the
    listen backlog and can race, and a bound-but-not-listening socket
    used to fail the first client connect.  Also returns as soon as the
    port is up instead of on the next 100 ms poll tick."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            try:
                if s.connect_ex((host, port)) == 0:
                    return
            except OSError:
                pass
        if stop is not None and stop():
            raise ProtocolError("engine exited while waiting for port %d" % port)
        time.sleep(0.05)
    raise ProtocolError("timeout waiting for local port %d" % port)


def write_private(path: str, data: str) -> str:
    """Atomically write ``data`` to ``path`` with owner-only permissions."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pc-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path

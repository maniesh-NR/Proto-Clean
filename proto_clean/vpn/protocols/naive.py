"""NaïveProxy engine: drives the official ``naive`` binary.

``naive`` (https://github.com/klzgrad/naiveproxy — Chrome's network stack
compiled as a Caddy plugin) speaks HTTP/2 CONNECT with a genuine Chrome
TLS fingerprint towards the server and exposes a local listener
configured through a single JSON file passed as the only CLI argument:

    {"listen": "socks://127.0.0.1:10880",
     "proxy":  "https://user:pass@server.example.com:443",
     "log":    ""}

``listen`` accepts ``socks://`` (used here — it plugs into the rest of
Proto Clean) or ``http://``.  The user/password embedded in the
``proxy`` URL must be percent-encoded with :func:`urllib.parse.quote`
and ``safe=""`` — providers routinely hand out credentials containing
``@``, ``/`` or spaces which would otherwise corrupt the URL.  The
hostname is the profile's ``sni`` when set (the TLS-frontend name the
server certificate must carry), falling back to ``server``.

The engine writes the config into ``CONFIG_DIR/naive/`` with owner-only
permissions (:func:`write_private`), spawns ``[naive <config>]``, waits
for the local port to accept connections and surfaces the server
endpoint through :meth:`NaiveEngine.status`.  Chaining is unsupported
(``supports_upstream = False``): naive dials the server directly.

Note: :func:`build_naive_config` accepts a ``dns`` parameter for API
compatibility, but the official binary exposes no DNS override — only
``listen``/``proxy``/``log`` are ever emitted.
"""

from __future__ import annotations

import json as _json
import os
import subprocess
import sys
import urllib.parse as _up
from typing import Optional

from ...log import get
from ...paths import CONFIG_DIR
from . import models as M
from .base import (PROXY_FAMILY, ProtocolEngine, ProtocolError, find_binary,
                   free_port, wait_port, write_private)

log = get("protocols.naive")

#: naive's conventional local SOCKS port when none is requested
DEFAULT_NAIVE_SOCKS = 10880

_NAIVE_BINARY_HELP = ("the naive binary was not found — download NaïveProxy "
                      "from https://github.com/klzgrad/naiveproxy/releases "
                      "(proxy strings — server, port, username, password — "
                      "come from your provider) or set PROTO_CLEAN_NAIVE_BIN")


# ---------------------------------------------------------------------------
# config builder
# ---------------------------------------------------------------------------
def build_naive_config(profile: M.NaiveProfile, listen_port: int,
                       dns: str = "local") -> dict:
    """Render ``profile`` as naive's JSON config.

    Percent-encoding note: ``quote(..., safe="")`` is mandatory — user
    ``"a@b"`` becomes ``a%40b`` in the ``proxy`` URL.  ``dns`` is
    accepted for forward-compatibility but not emitted (the official
    binary has no DNS override key).
    """
    user = _up.quote(profile.username or "", safe="")
    password = _up.quote(profile.password or "", safe="")
    host = (profile.sni or profile.server or "").strip()
    return {
        "listen": "socks://127.0.0.1:%d" % int(listen_port),
        "proxy": "https://%s:%s@%s:%d" % (user, password, host,
                                          int(profile.port)),
        "log": "",
    }


# ---------------------------------------------------------------------------
# binary discovery
# ---------------------------------------------------------------------------
def find_naive_binary(explicit: str = "") -> Optional[str]:
    """Locate the ``naive`` binary (PATH, common dirs,
    ``PROTO_CLEAN_NAIVE_BIN``). Returns None when not installed."""
    return find_binary(("naive", "naive.exe"),
                       env_var="PROTO_CLEAN_NAIVE_BIN")


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class NaiveEngine(ProtocolEngine):
    """Runs the official ``naive`` binary and exposes its local SOCKS."""

    proxy_kind = "naive"
    family = PROXY_FAMILY                  # "proxy"
    exposes = "socks"
    binary_name = "naive"
    supports_upstream = False

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self.profile: Optional[M.NaiveProfile] = None
        self.config_path = ""

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
        """Last stdout bytes of an EXITED process (for error messages).

        The shared spawn drain keeps only a bounded tail — leftover bytes
        still sitting in the pipe buffer when the process died are read
        here directly."""
        if proc is None or proc.poll() is None or proc.stdout is None:
            return ""
        try:
            return (proc.stdout.read() or b"").decode("utf-8", "replace") \
                .strip()[-chars:]
        except Exception:                      # noqa: BLE001 — best effort
            return ""

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.NaiveProfile, timeout: float = 15.0) -> None:
        if self.running:
            raise ProtocolError("the naive engine is already running")
        if not isinstance(profile, M.NaiveProfile):
            raise ProtocolError("naive engine needs a NaiveProfile")
        server = (profile.server or "").strip()
        if not server:
            raise ProtocolError("naive: empty server address")
        try:
            port = int(profile.port)
        except (TypeError, ValueError):
            raise ProtocolError("naive: bad server port %r"
                                % (profile.port,)) from None
        if not 1 <= port <= 65535:
            raise ProtocolError("naive: bad server port %d" % port)
        if not (profile.username or profile.password):
            log.warning("naive: profile has no credentials — the server "
                        "will most likely refuse CONNECTs")
        exe = find_naive_binary()
        if not exe:
            raise ProtocolError(_NAIVE_BINARY_HELP)
        self.profile = profile
        self.socks_port = free_port(self.socks_port or DEFAULT_NAIVE_SOCKS)
        d = self._dir()
        self.config_path = os.path.join(d, "naive.json")
        write_private(self.config_path,
                      _json.dumps(build_naive_config(profile, self.socks_port),
                                  indent=2, sort_keys=True) + "\n")
        try:
            self.spawn([exe, self.config_path], cwd=d)
            wait_port(self.socks_port, timeout=timeout,
                      stop=lambda: not self.running)
            self.check_process()           # died right after opening the port
        except ProtocolError as e:
            tail = self.output_tail(800) or self._proc_tail(self._proc)
            self.stop()
            msg = "naive: %s" % e
            if tail:
                msg += " — " + tail
            raise ProtocolError(msg) from None
        log.info("naive up (socks 127.0.0.1:%d -> %s:%d)",
                 self.socks_port, server, port)

    def status(self) -> dict:
        st = super().status()
        prof = self.profile
        st["server"] = "%s:%d" % (prof.server, prof.port) if prof else ""
        st["sni"] = prof.sni if prof else ""
        st["config"] = self.config_path
        return st

    def stop(self, timeout: float = 5.0) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            try:
                if sys.platform.startswith("win"):
                    # /T kills naive *and* any children it spawned
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
            except Exception:              # noqa: BLE001 — best effort
                pass
        self.profile = None
        self._started_at = 0.0
        super().stop(timeout)
        log.info("naive stopped")


def engine(profile: M.NaiveProfile, socks_port: int = 0) -> NaiveEngine:
    """Registry factory for the ``naive`` protocol kind."""
    return NaiveEngine(socks_port=socks_port)

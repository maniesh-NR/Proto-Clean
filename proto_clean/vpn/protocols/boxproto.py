"""lantern-box engine — one sing-box fork binary for every other protocol.

`lantern-box <https://github.com/getlantern/lantern-box>`_ is Lantern's
GPL-3.0 fork of sing-box.  On top of upstream sing-box it adds the
samizdat, reflex, water, outline, algeneva, amneziawg and hysteria2x
adapters; the sing-box built-ins (shadowsocks incl. 2022, hysteria2,
tuic, naive, trojan, vless, shadowsocksr-capable builds, wireguard)
come along for free.  One binary therefore covers every remaining proxy
protocol the built-in Python engines cannot speak.

The lifecycle, log handling and system-proxy integration are inherited
from :class:`proto_clean.vpn.xray.XrayManager` — exactly like
:class:`proto_clean.vpn.samizdat.SamizdatManager`, which differs only in
binary discovery, config format and inbound layout:

* one ``mixed`` inbound (SOCKS5 + HTTP CONNECT on a single port),
* one outbound (or, for AmneziaWG, one sing-box ``endpoints`` entry plus
  a route rule that points the inbound at it),
* an optional ``socks`` upstream outbound + ``detour`` for chaining the
  box engine behind another engine (the bond builder sets
  ``upstream_socks`` / ``upstream_socks_port``).

:func:`probe_support` asks the binary itself which outbound types it
validates (``box check -c`` with a minimal per-kind config) and caches
the answer per binary path, so the UI can grey out kinds the installed
build does not support.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from ...log import get
from ..samizdat import find_box_binary
from ..samizdatconf import DEFAULT_MIXED_PORT
from ..xray import XrayError, XrayManager
from ..xrayconf import XrayProfile
from . import models as M
from .base import ProtocolError, write_private

log = get("protocols.box")

__all__ = ["SUPPORTED_KINDS", "REGISTER_KINDS", "REGISTERED_KINDS",
           "BoxEngine", "build_box_config", "probe_support", "engine"]

#: registry kinds this engine can run.  "hysteria2" with
#: ``profile.engine == "hysteria2x"`` builds the GFW-junk variant.
SUPPORTED_KINDS: Tuple[str, ...] = (
    "shadowsocks", "shadowsocksr", "hysteria2", "tuic", "naive", "trojan",
    "reflex", "water", "outline", "algeneva", "amneziawg", "vmess",
    "warp", "boxraw",
)

#: registry keys wired to this engine at import ("awg" is an alias of
#: "amneziawg"; kinds that already ship a built-in engine — shadowsocks,
#: hysteria2, tuic, trojan — keep their factories and are NOT replaced).
REGISTER_KINDS: Tuple[str, ...] = SUPPORTED_KINDS + ("awg",)

_KIND_ALIASES = {"awg": "amneziawg"}

# stable tags inside the generated config
MAIN_TAG = "box-out"
MIXED_TAG = "mixed-in"
UPSTREAM_TAG = "upstream"
AWG_ENDPOINT_TAG = "awg-ep"

# AmneziaWG junk-parameter short names (profile.junk keys, case
# insensitive) -> sing-box amneziawg endpoint field names
JUNK_FIELDS: Dict[str, str] = {
    "jc": "junk_packet_count",
    "jmin": "junk_packet_min_size",
    "jmax": "junk_packet_max_size",
    "s1": "init_packet_junk_size",
    "s2": "response_packet_junk_size",
    "h1": "init_packet_magic_header",
    "h2": "response_packet_magic_header",
    "h3": "underload_packet_magic_header",
    "h4": "transport_packet_magic_header",
}


# ---------------------------------------------------------------------------
# per-kind outbound builders (pure functions over the profile)
# ---------------------------------------------------------------------------
def _tls_block(server_name: str, insecure: bool) -> dict:
    return {"enabled": True, "server_name": server_name,
            "insecure": bool(insecure)}


def _ss_outbound(p: M.ShadowsocksProfile) -> dict:
    out = {"type": "shadowsocks", "server": p.server,
           "server_port": int(p.port), "method": p.method,
           "password": p.password}
    # SIP002 plugin string "name;opts" -> plugin + plugin_opts
    plugin = (p.plugin or "").strip()
    if plugin:
        name, _, opts = plugin.partition(";")
        out["plugin"] = name.strip()
        opts = opts.strip()
        if opts:
            out["plugin_opts"] = opts
    return out


def _ssr_outbound(p: M.ShadowsocksrProfile) -> dict:
    return {"type": "shadowsocksr", "server": p.server,
            "server_port": int(p.port), "method": p.method,
            "password": p.password, "protocol": p.protocol,
            "protocol_param": p.protocol_param, "obfs": p.obfs,
            "obfs_param": p.obfs_param}


def _hysteria2_outbound(p: M.Hysteria2Profile) -> dict:
    # lantern-box's hysteria2x = hysteria2 with GFW pre-initial junk
    kind = "hysteria2x" if getattr(p, "engine", "") == "hysteria2x" \
        else "hysteria2"
    out = {"type": kind, "server": p.server, "server_port": int(p.port),
           "password": p.auth,
           "tls": _tls_block(p.sni or p.server, p.insecure)}
    if kind == "hysteria2x":
        out["pre_initial_junk"] = True
    if p.obfs:
        out["obfs"] = {"type": "salamander", "password": p.obfs_password}
    return out


def _tuic_outbound(p: M.TuicProfile) -> dict:
    return {"type": "tuic", "server": p.server, "server_port": int(p.port),
            "uuid": p.uuid, "password": p.password,
            "congestion_control": p.congestion,
            "udp_relay_mode": p.udp_relay_mode,
            "tls": {"enabled": True, "server_name": p.sni or p.server,
                    "alpn": [p.alpn or "h3"],
                    "insecure": bool(p.allow_insecure)}}


def _naive_outbound(p: M.NaiveProfile) -> dict:
    return {"type": "naive", "server": p.server, "server_port": int(p.port),
            "username": p.username, "password": p.password,
            "tls": _tls_block(p.sni or p.server, p.insecure)}


def _trojan_outbound(p: XrayProfile) -> dict:
    # the registry kind "trojan" carries an XrayProfile
    return {"type": "trojan", "server": p.address, "server_port": int(p.port),
            "password": p.password,
            "tls": _tls_block(p.sni or p.address, p.allow_insecure)}


def _reflex_outbound(p: M.ReflexProfile) -> dict:
    return {"type": "reflex", "server": p.server, "server_port": int(p.port),
            "cert_pem": p.cert_pem, "key_pem": p.key_pem}


def _water_outbound(p: M.WaterProfile) -> dict:
    return {"type": "water", "server": p.server, "server_port": int(p.port),
            "transport": p.transport, "hashsum": p.hashsum,
            "wasm_available_at": list(p.wasm_urls),
            "download_timeout": p.download_timeout, "config": {}}


def _outline_dns(entry: str) -> Optional[dict]:
    """One ``profile.dns`` entry -> a sing-box DNS-server descriptor.

    ``system`` -> {"system": {}}; ``https:name`` -> {"https": {"name": …}};
    ``tls:name:address`` -> {"tls": {"name", "address"}}; ``udp:address`` /
    ``tcp:address`` -> {"udp"/"tcp": {"address": …}}; a bare address falls
    back to UDP.  Unparseable entries are dropped (returns None).
    """
    e = (entry or "").strip()
    if not e:
        return None
    if e == "system" or e.startswith("system:"):
        return {"system": {}}
    scheme, _, rest = e.partition(":")
    scheme = scheme.lower()
    if scheme == "https":
        return {"https": {"name": rest}} if rest else None
    if scheme == "tls":
        name, _, address = rest.partition(":")
        if not name:
            return None
        d: Dict[str, str] = {"name": name}
        if address:
            d["address"] = address
        return {"tls": d}
    if scheme == "udp":
        return {"udp": {"address": rest}} if rest else None
    if scheme == "tcp":
        return {"tcp": {"address": rest}} if rest else None
    return {"udp": {"address": e}}


def _outline_outbound(p: M.OutlineProfile) -> dict:
    dns = [d for d in (_outline_dns(e) for e in (p.dns or [])) if d]
    return {"type": "outline", "server": p.server, "server_port": int(p.port),
            "dns": dns, "tls": list(p.tls or []), "domains": list(p.domains
                                                                 or []),
            "test_timeout": "10s"}


def _algeneva_outbound(p: M.AlgenevaProfile) -> dict:
    return {"type": "algeneva", "server": p.server,
            "server_port": int(p.port), "strategy": p.strategy}


def _amneziawg_endpoint(p: M.AwgProfile) -> dict:
    """The sing-box ENDPOINTS entry (NOT an outbound) for AmneziaWG."""
    junk = {str(k).lower(): v for k, v in (getattr(p, "junk", None)
                                           or {}).items()}
    peer = {"public_key": p.peer_public_key,
            "endpoint": "%s:%d" % (p.server, int(p.port)),
            "allowed_ips": list(p.allowed_ips or [])}
    if getattr(p, "preshared_key", ""):
        peer["pre_shared_key"] = p.preshared_key
    endpoint = {"type": "amneziawg", "tag": AWG_ENDPOINT_TAG,
                "address": list(p.address or []), "private_key": p.private_key,
                "peers": [peer]}
    for short, field in JUNK_FIELDS.items():
        if short in junk:
            endpoint[field] = junk[short]
    return endpoint



def _vmess_outbound(profile) -> dict:
    """V2ray / V2fly VMess with ws / grpc / h2 transports and uTLS."""
    p = profile
    out = {"type": "vmess", "server": p.server,
           "server_port": int(p.port), "uuid": p.uuid,
           "security": p.security or "auto"}
    if p.alter_id:
        out["alter_id"] = int(p.alter_id)
    transport = (p.transport or "tcp").lower()
    if transport in ("ws", "websocket"):
        ws = {"type": "ws", "path": p.path or "/"}
        if p.host:
            ws["headers"] = {"Host": p.host}
        out["transport"] = ws
    elif transport == "grpc":
        out["transport"] = {"type": "grpc", "service_name": p.path or ""}
    elif transport in ("h2", "http", "http2"):
        out["transport"] = {"type": "http", "path": p.path or "/",
                            "host": [p.host] if p.host else []}
    elif transport == "tcp" and (p.header_type or "none") == "http":
        out["transport"] = {"type": "http",
                            "host": [p.host] if p.host else []}
    if p.tls:
        tls = {"enabled": True,
               "server_name": p.sni or p.host or p.server}
        if p.fp:
            tls["utls"] = {"enabled": True, "fingerprint": p.fp}
        out["tls"] = tls
    return out


def _boxraw_outbound(profile) -> dict:
    """Not an outbound builder: boxraw returns the whole user config."""
    raise NotImplementedError  # handled specially in build_box_config


_OUTBOUND_BUILDERS = {
    "shadowsocks": _ss_outbound,
    "shadowsocksr": _ssr_outbound,
    "hysteria2": _hysteria2_outbound,
    "tuic": _tuic_outbound,
    "naive": _naive_outbound,
    "trojan": _trojan_outbound,
    "reflex": _reflex_outbound,
    "water": _water_outbound,
    "outline": _outline_outbound,
    "algeneva": _algeneva_outbound,
    "vmess": _vmess_outbound,
}


# ---------------------------------------------------------------------------
# config building
# ---------------------------------------------------------------------------
def build_box_config(kind: str, profile, socks_port: int,
                     upstream: Tuple[str, int] = ("", 0)) -> dict:
    """The sing-box/lantern-box client config (as a plain dict).

    ``kind`` is a registry kind from :data:`SUPPORTED_KINDS`; ``upstream``
    is ``(host, port)`` of an upstream SOCKS5 to chain through (sing-box
    ``detour``).  AmneziaWG builds an ``endpoints`` entry plus a route
    rule instead of an outbound and can never be chained.
    """
    kind = _KIND_ALIASES.get(kind, kind)
    if kind not in SUPPORTED_KINDS:
        raise ProtocolError("box engine: unsupported protocol kind %r" % kind)
    if kind == "warp":
        from .warp import build_warp_box_config
        return build_warp_box_config(profile, socks_port, upstream)
    if kind == "boxraw":
        import json as _json
        try:
            doc = _json.loads(profile.config_json or "{}")
        except ValueError as exc:
            raise ProtocolError("invalid sing-box config: %s" % exc) \
                from None
        if not doc.get("inbounds"):
            doc["inbounds"] = [{"type": "mixed", "tag": MIXED_TAG,
                                "listen": "127.0.0.1",
                                "listen_port": int(socks_port)}]
        return doc
    up_host, up_port = upstream or ("", 0)
    chained = bool(int(up_port or 0))
    if kind == "amneziawg" and chained:
        raise ProtocolError(
            "AmneziaWG cannot be chained behind another engine")
    config = {
        "log": {"level": "warn"},
        # mixed inbound = SOCKS5 + HTTP CONNECT on one port
        "inbounds": [{"type": "mixed", "tag": MIXED_TAG,
                      "listen": "127.0.0.1", "listen_port": int(socks_port)}],
    }
    if kind == "amneziawg":
        # endpoints are referenced by tag from route rules (sing-box 1.11+);
        # a binary that rejects the layout fails the probe_support check
        config["outbounds"] = [{"type": "direct", "tag": "direct"}]
        config["endpoints"] = [_amneziawg_endpoint(profile)]
        config["route"] = {"rules": [{"inbound": MIXED_TAG,
                                      "endpoint": AWG_ENDPOINT_TAG}],
                           "final": "direct"}
        return config
    outbound = _OUTBOUND_BUILDERS[kind](profile)
    outbound["tag"] = MAIN_TAG
    outbounds = [outbound]
    if chained:
        outbound["detour"] = UPSTREAM_TAG
        outbounds.append({"type": "socks", "tag": UPSTREAM_TAG,
                          "server": up_host or "127.0.0.1",
                          "server_port": int(up_port), "version": "5"})
    outbounds.append({"type": "direct", "tag": "direct"})
    config["outbounds"] = outbounds
    return config


# ---------------------------------------------------------------------------
# capability probe
# ---------------------------------------------------------------------------
_PROBE_CACHE: Dict[str, Dict[str, bool]] = {}   # binary path -> kind -> bool
_CHECK_TIMEOUT = 20.0

# a structurally valid 32-byte key (base64) so a real binary's validator
# accepts the probe configs
_PROBE_KEY = base64.b64encode(b"\x01" * 32).decode("ascii")


def _probe_profile(kind: str):
    """A minimal-but-valid profile per kind for the ``check`` probe."""
    if kind == "shadowsocks":
        return M.ShadowsocksProfile(server="127.0.0.1", port=8388,
                                    method="aes-256-gcm", password="probe")
    if kind == "shadowsocksr":
        return M.ShadowsocksrProfile(server="127.0.0.1", port=8388,
                                     method="aes-256-cfb", password="probe",
                                     protocol="origin", obfs="plain")
    if kind == "hysteria2":
        return M.Hysteria2Profile(server="127.0.0.1", port=443, auth="probe",
                                  sni="probe.example", engine="box")
    if kind == "tuic":
        return M.TuicProfile(uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                             password="probe", server="127.0.0.1", port=443,
                             sni="probe.example")
    if kind == "naive":
        return M.NaiveProfile(server="127.0.0.1", port=443, username="probe",
                              password="probe", sni="probe.example")
    if kind == "trojan":
        return XrayProfile(protocol="trojan", address="127.0.0.1", port=443,
                           password="probe", sni="probe.example")
    if kind == "reflex":
        return M.ReflexProfile(server="127.0.0.1", port=443,
                               cert_pem="probe", key_pem="probe")
    if kind == "water":
        return M.WaterProfile(server="127.0.0.1", port=9003,
                              transport="plain",
                              wasm_urls=["https://probe.example/mod.wasm"])
    if kind == "outline":
        return M.OutlineProfile(server="127.0.0.1", port=443, dns=["system"])
    if kind == "algeneva":
        return M.AlgenevaProfile(server="127.0.0.1", port=9001,
                                 strategy="tcp:5:split2")
    if kind == "amneziawg":
        return M.AwgProfile(server="127.0.0.1", port=51820,
                            private_key=_PROBE_KEY,
                            peer_public_key=_PROBE_KEY,
                            address=["10.8.1.2/32"],
                            allowed_ips=["0.0.0.0/0"],
                            junk={"Jc": 4, "Jmin": 40, "Jmax": 70})
    if kind == "vmess":
        return M.VmessProfile(server="127.0.0.1", port=443,
                              uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                              transport="ws", path="/probe")
    if kind == "warp":
        return M.WarpProfile(private_key=_PROBE_KEY,
                             peer_public_key=_PROBE_KEY,
                             client_id_b64="cHJvYmU=",    # "probe"
                             address_v4="172.16.0.2/32",
                             endpoint="engage.cloudflareclient.com:2408")
    if kind == "boxraw":
        return M.BoxRawProfile(config_json=json.dumps(
            {"inbounds": [{"type": "mixed", "tag": "mixed-in",
                           "listen": "127.0.0.1", "listen_port":
                               DEFAULT_MIXED_PORT}],
             "outbounds": [{"type": "direct", "tag": "direct"}]}))
    raise ProtocolError("box engine: unsupported protocol kind %r" % kind)


def _run_check(binary: str, config: dict) -> bool:
    """``binary check -c <config>`` — True when the binary accepts it."""
    fd, path = tempfile.mkstemp(prefix=".box-probe-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        kwargs: dict = {}
        if sys.platform.startswith("win"):
            kwargs["creationflags"] = 0x08000000     # CREATE_NO_WINDOW
        proc = subprocess.run([binary, "check", "-c", path],
                              capture_output=True, timeout=_CHECK_TIMEOUT,
                              **kwargs)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def probe_support(binary: str,
                  kinds: Tuple[str, ...] = SUPPORTED_KINDS) -> Dict[str, bool]:
    """Ask ``binary`` which box kinds it can validate.

    Runs ``binary check -c`` with a minimal config per kind; returncode 0
    means supported.  Results are cached per binary path.  A missing or
    non-executable binary yields all-False (with a logged warning) and
    never raises.
    """
    kinds = tuple(kinds)
    results: Dict[str, bool] = {k: False for k in kinds}
    if not binary:
        log.warning("box capability probe: no binary given")
        return results
    path = os.path.abspath(binary)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        log.warning("box capability probe: binary %r not found or not "
                    "executable", binary)
        return results
    cached = _PROBE_CACHE.setdefault(path, {})
    for kind in kinds:
        if kind in cached:
            results[kind] = bool(cached[kind])
            continue
        try:
            cfg = build_box_config(kind, _probe_profile(kind),
                                   DEFAULT_MIXED_PORT)
            ok = _run_check(path, cfg)
        except Exception as exc:                       # probe never raises
            log.debug("box probe for %s failed: %s", kind, exc)
            ok = False
        cached[kind] = ok
        results[kind] = ok
        log.info("box capability probe %s via %s: %s", kind, path,
                 "supported" if ok else "unsupported")
    return results


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------
class BoxEngine(XrayManager):
    """lantern-box process manager (same lifecycle as Xray/samizdat).

    One *mixed* inbound (SOCKS5 + HTTP on :attr:`socks_port`); the
    outbound is selected by :attr:`box_kind` (set by :func:`engine`).
    Chaining: set ``upstream_socks`` (engine-style) or
    ``upstream_socks_port`` (controller-style) to dial the box server
    through an upstream SOCKS5 — every kind except AmneziaWG.
    """

    proxy_kind = "box"                      # config/log dir + file names
    box_kind = ""                           # registry kind (per instance)
    family = "proxy"
    exposes = "mixed"
    supports_upstream = True                # detour; amneziawg raises earlier

    def __init__(self, socks_port: int = 0, binary: str = "") -> None:
        super().__init__(binary=binary)
        if socks_port:
            self.socks_port = int(socks_port)
        # ProtocolEngine-style upstream attribute (the controller uses the
        # XrayManager-style upstream_socks_port; support both)
        self.upstream_socks: Tuple[str, int] = ("", 0)

    # ------------------------------------------------------------- hooks
    def _find_binary(self, explicit: str = "") -> Optional[str]:
        return find_box_binary(explicit or self._binary)

    def _binary_help(self) -> str:
        return ("the lantern-box binary was not found — the official builds "
                "bundle it next to the app; otherwise install lantern-box "
                "(https://github.com/getlantern/lantern-box, the sing-box "
                "fork providing shadowsocksr/naive/reflex/outline/algeneva/"
                "water/amneziawg) or set PROTO_CLEAN_BOX_BIN")

    def _upstream(self) -> Tuple[str, int]:
        up = getattr(self, "upstream_socks", ("", 0)) or ("", 0)
        if up[1]:
            return (up[0] or "127.0.0.1", int(up[1]))
        port = int(getattr(self, "upstream_socks_port", 0) or 0)
        return ("127.0.0.1", port) if port else ("", 0)

    def _write_config(self, profile, path: str) -> None:
        cfg = build_box_config(self.box_kind, profile, self.socks_port,
                               self._upstream())
        write_private(path, json.dumps(cfg, indent=2))

    # --------------------------------------------------------- lifecycle
    def start(self, profile, socks_port: int = DEFAULT_MIXED_PORT,
              http_port: int = 0, timeout: float = 10.0,
              binary: str = "") -> None:
        """Resolve the binary, probe its capabilities, then run the
        inherited start (spawn, wait for the mixed port, system proxy)."""
        kind = _KIND_ALIASES.get(self.box_kind, self.box_kind)
        if not kind:
            raise ProtocolError("box engine needs a protocol kind (box_kind)")
        if kind not in SUPPORTED_KINDS:
            raise ProtocolError("box engine: unsupported protocol kind %r"
                                % kind)
        if kind == "amneziawg" and self._upstream()[1]:
            raise ProtocolError(
                "AmneziaWG cannot be chained behind another engine")
        exe = self._find_binary(binary)
        if not exe:
            raise XrayError(self._binary_help())
        if not probe_support(exe, kinds=(kind,)).get(kind, False):
            raise ProtocolError(
                "the box binary (%s) cannot run %s — install a current "
                "lantern-box (https://github.com/getlantern/lantern-box) "
                "or point PROTO_CLEAN_BOX_BIN at it" % (exe, kind))
        super().start(profile, socks_port=socks_port,
                      http_port=socks_port, timeout=timeout, binary=exe)

    def status(self) -> dict:
        # own dict (the base status expects an XrayProfile.protocol field;
        # box profiles carry .kind and one mixed inbound serves both ports)
        prof = getattr(self, "profile", None)
        st = {
            "running": self.running,
            "pid": self._proc.pid if self._proc else None,
            "binary": self._binary or find_box_binary() or "",
            "socks_port": self.socks_port,
            "http_port": self.socks_port,
            "system_proxy": self._proxy_applied,
            "protocol": getattr(prof, "kind", "") or self.box_kind,
            "box_kind": self.box_kind,
        }
        return st


def engine(kind: str, profile, socks_port: int = 0) -> BoxEngine:
    """Convenience factory used by the protocol registry."""
    kind = _KIND_ALIASES.get(kind, kind)
    if kind not in SUPPORTED_KINDS:
        raise ProtocolError("box engine: unsupported protocol kind %r" % kind)
    if kind == "warp":
        from .warp import build_warp_box_config
        return build_warp_box_config(profile, socks_port, upstream)
    if kind == "boxraw":
        import json as _json
        try:
            doc = _json.loads(profile.config_json or "{}")
        except ValueError as exc:
            raise ProtocolError("invalid sing-box config: %s" % exc) \
                from None
        if not doc.get("inbounds"):
            doc["inbounds"] = [{"type": "mixed", "tag": MIXED_TAG,
                                "listen": "127.0.0.1",
                                "listen_port": int(socks_port)}]
        return doc
    eng = BoxEngine(socks_port=socks_port)
    eng.box_kind = kind
    return eng


# ---------------------------------------------------------------------------
# registry self-registration
# ---------------------------------------------------------------------------
_FALLBACK_MODELS = {
    "shadowsocks": M.ShadowsocksProfile,
    "shadowsocksr": M.ShadowsocksrProfile,
    "hysteria2": M.Hysteria2Profile,
    "tuic": M.TuicProfile,
    "naive": M.NaiveProfile,
    "trojan": XrayProfile,
    "reflex": M.ReflexProfile,
    "water": M.WaterProfile,
    "outline": M.OutlineProfile,
    "algeneva": M.AlgenevaProfile,
    "amneziawg": M.AwgProfile,
    "awg": M.AwgProfile,
}


def _make_factory(kind: str):
    def factory(profile, socks_port: int = 0) -> BoxEngine:
        return engine(kind, profile, socks_port)
    return factory


def _register_box_kinds() -> List[str]:
    """Wire the previously factory-less registry kinds to this engine.

    Only kinds registered without a factory (the lantern-box capability
    probes) are replaced — the built-in engines for shadowsocks,
    hysteria2, tuic and trojan keep their factories.
    """
    registered: List[str] = []
    try:
        from proto_clean.vpn import protocols as _registry
    except Exception as exc:                       # pragma: no cover
        log.warning("box engine registration skipped: %s", exc)
        return registered
    for kind in REGISTER_KINDS:
        entry = _registry._REGISTRY.get(kind)
        if entry is None or entry.get("factory"):
            continue          # unknown kind, or it already has an engine
        model = entry.get("model") or _FALLBACK_MODELS.get(kind)
        _registry._register(kind, entry.get("title") or kind, model,
                            _make_factory(kind), BoxEngine,
                            family=entry.get("family") or "proxy")
        registered.append(kind)
        log.debug("registry: kind %r now runs through lantern-box", kind)
    return registered


#: kinds that got wired to BoxEngine when this module was imported
REGISTERED_KINDS: Tuple[str, ...] = tuple(_register_box_kinds())

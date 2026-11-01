"""Local cache of downloaded configs (WireGuard AND OpenVPN).

The user requirement: configs are downloaded once and cached on the local
machine; the config for a specific server is only downloaded again when the
*saved* config fails (tunnel will not come up, or the handshake never
completes — e.g. the certificate was revoked server-side).

Layout (under ~/.cache/proton-clean/configs/):

    <server-slug>.<fingerprint>.conf    the cached WireGuard config text
    <server-slug>.<fingerprint>.ovpn    the cached OpenVPN config text
    index.json                          per-server metadata:
                                          entries -> fingerprint -> {file,
                                            created, verified_at, failures,
                                            source, options}

The *fingerprint* encodes the options that were baked into the file
when it was generated on the Downloads page (protocol + transport +
VPN Accelerator + NAT-PMP), e.g. ``wg-acc1-nat1`` or ``ovpn-tcp-acc1-nat0``:
lookups prefer an exact match but fall back to any cached config for the
server *of the same protocol* — an .ovpn file must never be handed to
wg-quick, and vice versa. Options are comments in the file and never block
the connection; failure-based invalidation is the real correctness
mechanism.

Proton embeds the options as comments in the generated file, e.g.::

    [Interface]
    # NAT-PMP (Port Forwarding) = off
    # VPN Accelerator = on
    ...
    [Peer]
    # CA-FREE#1
    PublicKey = ...
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..log import get
from ..paths import CONFIG_CACHE_DIR

log = get("configcache")

INDEX_FILE = "index.json"

_SERVER_COMMENT = re.compile(r"^\s*#\s*([A-Z]{2}(?:-[A-Z]{2})?-[A-Z0-9]+#\d+)\s*$",
                             re.M)
_NATPMP_COMMENT = re.compile(
    r"#\s*NAT-PMP[^=]*=\s*(on|yes|true|off|no|false)", re.I)
_ACCEL_COMMENT = re.compile(
    r"#\s*VPN Accelerator[^=]*=\s*(on|yes|true|off|no|false)", re.I)
_OVPN_PROTO_RE = re.compile(r"(?m)^proto\s+(udp|tcp)\s*$", re.I)


def looks_like_openvpn(text: str) -> bool:
    lines = [ln.strip() for ln in (text or "").splitlines()]
    return any(ln.startswith("remote ") for ln in lines)


def looks_like_wireguard(text: str) -> bool:
    return "[Interface]" in text and "PrivateKey" in text


def slugify(name: str) -> str:
    out = []
    for ch in name.strip().lower():
        if ch.isalnum():
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-") or "server"


def parse_config_meta(text: str) -> Dict[str, Any]:
    """Extract protocol/server/option flags from a generated Proton config."""
    meta: Dict[str, Any] = {"server": None, "nat_pmp": False,
                            "vpn_accelerator": True,
                            "protocol": "wireguard", "openvpn_transport": "udp"}
    if looks_like_openvpn(text):
        meta["protocol"] = "openvpn"
        m = _OVPN_PROTO_RE.search(text)
        if m and m.group(1).lower() == "tcp":
            meta["openvpn_transport"] = "tcp"
    m = _SERVER_COMMENT.search(text)
    if m:
        meta["server"] = m.group(1)
    m = _NATPMP_COMMENT.search(text)
    if m:
        meta["nat_pmp"] = m.group(1).lower() in ("on", "yes", "true")
    m = _ACCEL_COMMENT.search(text)
    if m:
        meta["vpn_accelerator"] = m.group(1).lower() in ("on", "yes", "true")
    return meta


def fingerprint_of(options) -> str:
    """Stable key for the option set that affects a generated config.

    Includes the protocol (and, for OpenVPN, the TCP/UDP transport) so a
    WireGuard lookup can never match an OpenVPN cache entry.
    """
    proto = str(getattr(options, "protocol", "") or "wireguard")
    if proto not in ("wireguard", "openvpn"):
        proto = "wireguard"
    if proto == "openvpn":
        transport = str(getattr(options, "openvpn_transport", "udp") or "udp")
        if transport not in ("udp", "tcp"):
            transport = "udp"
        base = f"ovpn-{transport}"
    else:
        base = "wg"
    accel = bool(getattr(options, "vpn_accelerator", True))
    nat = bool(getattr(options, "nat_pmp_port_forward", False))
    return f"{base}-acc{int(accel)}-nat{int(nat)}"


def _entry_protocol(entry_options: Dict[str, Any]) -> str:
    """Protocol an index entry was stored under (legacy entries = wireguard)."""
    proto = (entry_options or {}).get("protocol", "")
    return proto if proto in ("wireguard", "openvpn") else "wireguard"


@dataclass
class CachedConfig:
    text: str
    server: str
    fingerprint: str
    exact: bool              # True when options match the request exactly
    created: float = 0.0
    verified_at: float = 0.0
    failures: int = 0
    source: str = "downloaded"   # downloaded | harvested
    protocol: str = "wireguard"   # wireguard | openvpn


@dataclass
class _Entry:
    file: str
    options: Dict[str, Any] = field(default_factory=dict)
    created: float = 0.0
    verified_at: float = 0.0
    failures: int = 0
    source: str = "downloaded"

    def to_json(self) -> dict:
        return vars(self)

    @classmethod
    def from_json(cls, d: dict) -> "_Entry":
        e = cls(file=str(d.get("file", "")))
        e.options = d.get("options", {}) or {}
        e.created = float(d.get("created", 0) or 0)
        e.verified_at = float(d.get("verified_at", 0) or 0)
        e.failures = int(d.get("failures", 0) or 0)
        e.source = d.get("source", "downloaded")
        return e


class ConfigCache:
    def __init__(self, root: Path = CONFIG_CACHE_DIR) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock_src = None  # guarded by the GIL for our usage patterns
        self._index = self._load_index()

    # ------------------------------------------------------------------ index
    def _index_path(self) -> Path:
        return self.root / INDEX_FILE

    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        p = self._index_path()
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_index(self) -> None:
        tmp = self._index_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(self._index, indent=1), encoding="utf-8")
        tmp.replace(self._index_path())

    # ------------------------------------------------------------------- api
    def get(self, server_name: str, options=None) -> Optional[CachedConfig]:
        """Cached config for the server; exact fingerprint preferred.

        Falls back to a config generated with different options — but only
        *of the requested protocol* (an OpenVPN lookup never returns a
        WireGuard file and vice versa; legacy entries without a recorded
        protocol are WireGuard by definition). Re-downloading is exactly
        what the user wants to avoid.
        Returns None when nothing is cached for the server.
        """
        rec = self._index.get(slugify(server_name))
        if not rec or not rec.get("entries"):
            return None
        want = fingerprint_of(options) if options is not None else None
        want_proto = (str(getattr(options, "protocol", "wireguard") or "wireguard")
                      if options is not None else None)
        entries = {k: _Entry.from_json(v) for k, v in rec["entries"].items()}
        entry = None
        exact = False
        if want and want in entries:
            entry, exact = entries[want], True
        else:
            candidates = [e for k, e in entries.items()
                          if want_proto is None
                          or _entry_protocol(e.options) == want_proto]
            if not candidates:
                return None           # nothing of this protocol cached
            # most recently created entry for this server
            entry = max(candidates, key=lambda e: e.created)
        path = self.root / entry.file
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            log.warning("cached config missing on disk: %s", path)
            return None
        if "[Interface]" not in text and not looks_like_openvpn(text):
            return None
        return CachedConfig(
            text=text, server=rec.get("server", server_name),
            fingerprint=next(k for k, v in entries.items() if v is entry),
            exact=exact, created=entry.created, verified_at=entry.verified_at,
            failures=entry.failures, source=entry.source,
            protocol=_entry_protocol(entry.options),
        )

    def put(self, server_name: str, text: str, options=None,
            source: str = "downloaded") -> str:
        """Store a config; returns the fingerprint it was filed under.

        When `options` is None the options are parsed from the config text
        (harvested configs embed them as comments — and the protocol is
        detected from the text itself).
        """
        slug = slugify(server_name)
        if options is None:
            meta = parse_config_meta(text)
            options = _ParsedOptions(protocol=meta["protocol"],
                                     openvpn_transport=meta["openvpn_transport"],
                                     vpn_accelerator=meta["vpn_accelerator"],
                                     nat_pmp_port_forward=meta["nat_pmp"])
        fp = fingerprint_of(options)
        proto = str(getattr(options, "protocol", "wireguard") or "wireguard")
        ext = "ovpn" if proto == "openvpn" else "conf"
        fname = f"{slug}.{fp}.{ext}"
        (self.root / fname).write_text(text, encoding="utf-8")
        rec = self._index.setdefault(slug, {"server": server_name, "entries": {}})
        rec["server"] = server_name
        rec["entries"][fp] = _Entry(
            file=fname,
            options={"protocol": proto,
                     "openvpn_transport": str(getattr(options, "openvpn_transport", "udp") or "udp"),
                     "vpn_accelerator": bool(getattr(options, "vpn_accelerator", True)),
                     "nat_pmp": bool(getattr(options, "nat_pmp_port_forward",
                                             getattr(options, "nat_pmp", False)))},
            created=time.time(), source=source,
        ).to_json()
        self._save_index()
        log.info("cached %s config for %s (%s, %s)", proto, server_name, fp,
                 source)
        return fp

    def invalidate(self, server_name: str) -> None:
        """Drop every cached variant for a server (config failed)."""
        slug = slugify(server_name)
        rec = self._index.pop(slug, None)
        if rec:
            for entry in rec.get("entries", {}).values():
                try:
                    (self.root / entry.get("file", "")).unlink(missing_ok=True)
                except OSError:
                    pass
            self._save_index()
            log.info("invalidated cached config for %s", server_name)

    def mark_verified(self, server_name: str, fingerprint: Optional[str] = None,
                      options=None) -> None:
        self._mutate_entry(server_name, fingerprint, options,
                           lambda e: setattr(e, "verified_at", time.time()))

    def note_failure(self, server_name: str, fingerprint: Optional[str] = None,
                     options=None) -> None:
        self._mutate_entry(server_name, fingerprint, options,
                           lambda e: setattr(e, "failures", e.failures + 1))

    def _mutate_entry(self, server_name: str, fingerprint: Optional[str],
                      options, fn) -> None:
        slug = slugify(server_name)
        rec = self._index.get(slug)
        if not rec:
            return
        fp = fingerprint or (fingerprint_of(options) if options is not None else None)
        entries = rec.get("entries", {})
        if fp and fp in entries:
            target = [fp]
        else:
            target = list(entries.keys())
        for key in target:
            e = _Entry.from_json(entries[key])
            fn(e)
            entries[key] = e.to_json()
        self._save_index()

    def entries(self) -> List[dict]:
        """Flat listing for UI / diagnostics."""
        out = []
        for slug, rec in self._index.items():
            for fp, e in rec.get("entries", {}).items():
                e = _Entry.from_json(e)
                out.append({
                    "server": rec.get("server", slug),
                    "fingerprint": fp,
                    "file": e.file,
                    "created": e.created,
                    "verified_at": e.verified_at,
                    "failures": e.failures,
                    "source": e.source,
                    "protocol": _entry_protocol(e.options),
                })
        return out

    def __len__(self) -> int:
        return sum(len(r.get("entries", {})) for r in self._index.values())

    def purge(self) -> None:
        """Remove every cached config."""
        for p in self.root.iterdir():
            if p.is_file() and p.name != INDEX_FILE:
                try:
                    p.unlink()
                except OSError:
                    pass
        self._index = {}
        self._save_index()


@dataclass
class _ParsedOptions:
    """Options recovered from a config file's comments."""
    protocol: str = "wireguard"
    openvpn_transport: str = "udp"
    vpn_accelerator: bool = True
    nat_pmp_port_forward: bool = False
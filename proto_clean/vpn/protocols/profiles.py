"""Profile storage — the saved servers list behind the Protocols UI.

Profiles live in ``CONFIG_DIR/profiles.json`` as a list of entries::

    {"id": "<hex>", "name": "...", "kind": "hysteria2", "url": "...",
     "data": {profile fields}, "created": 1699999999, "pinned": false}

Every entry keeps the canonical share URL so profiles round-trip through
links/QR even across model changes; ``data`` is the expanded profile for
fast loading.  A single file keeps backup/sync trivial.
"""

from __future__ import annotations

import json as _json
import os
import time
import uuid
from typing import Iterable, List, Optional

from ...log import get
from ...paths import CONFIG_DIR, ensure_dirs
from . import links
from .base import ProtocolError, ProtocolProfile

log = get("protocols.profiles")


def canonical_url(profile) -> str:
    """Best-effort share URL for any profile object.

    ProtocolProfile models implement ``share_url``; foreign profiles
    (the Xray VLESS/Trojan dataclass, samizdat) are re-encoded into
    their canonical link forms so stored entries round-trip.
    """
    if hasattr(profile, "share_url"):
        try:
            return profile.share_url()
        except Exception as exc:                      # pragma: no cover
            log.debug("share_url failed for %s: %s",
                      type(profile).__name__, exc)
    from urllib.parse import quote as _q
    # XrayProfile (vless-reality / trojan)
    proto = getattr(profile, "protocol", "")
    if proto in ("vless-reality", "trojan"):
        if proto == "vless-reality":
            return ("vless://%s@%s:%d?encryption=none&security=reality"
                    "&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp&flow=%s#%s"
                    % (getattr(profile, "uuid", ""),
                       getattr(profile, "address", ""),
                       int(getattr(profile, "port", 443)),
                       _q(getattr(profile, "sni", "")),
                       getattr(profile, "fingerprint", "chrome"),
                       getattr(profile, "public_key", ""),
                       getattr(profile, "short_id", ""),
                       getattr(profile, "flow", "xtls-rprx-vision"),
                       _q(getattr(profile, "name", "") or "vless")))
        return "trojan://%s@%s:%d?security=tls&sni=%s&type=tcp#%s" % (
            _q(getattr(profile, "password", "")),
            getattr(profile, "address", ""),
            int(getattr(profile, "port", 443)),
            _q(getattr(profile, "sni", "")),
            _q(getattr(profile, "name", "") or "trojan"))
    raise ProtocolError("cannot build a share URL for %s"
                        % type(profile).__name__)

#: entries whose profile kind must stay in sync with the registry
MAX_ENTRIES = 500


class ProfileEntry:
    __slots__ = ("id", "name", "kind", "url", "data", "created", "pinned")

    def __init__(self, id: str, name: str, kind: str, url: str,
                 data: Optional[dict] = None, created: float = 0.0,
                 pinned: bool = False) -> None:
        self.id = id
        self.name = name
        self.kind = kind
        self.url = url
        self.data = data or {}
        self.created = created or time.time()
        self.pinned = pinned

    # -- (de)serialisation -------------------------------------------------
    def to_json(self) -> dict:
        return {"id": self.id, "name": self.name, "kind": self.kind,
                "url": self.url, "data": self.data,
                "created": int(self.created), "pinned": self.pinned}

    @classmethod
    def from_json(cls, d: dict) -> "ProfileEntry":
        return cls(str(d.get("id") or uuid.uuid4().hex),
                   str(d.get("name") or ""), str(d.get("kind") or ""),
                   str(d.get("url") or ""), dict(d.get("data") or {}),
                   float(d.get("created") or 0.0),
                   bool(d.get("pinned")))

    def profile(self) -> Optional[ProtocolProfile]:
        """Rebuild the profile object from the stored URL (canonical)."""
        if not self.url:
            return None
        try:
            _kind, prof = links.parse_link(self.url)
            return prof
        except ProtocolError as exc:
            log.debug("stored profile %s no longer parses: %s",
                      self.name, exc)
            return None

    def rename(self, name: str) -> None:
        self.name = (name or "").strip()[:80]


class ProfileStore:
    """CRUD over ``profiles.json`` with in-place saves."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or str(CONFIG_DIR / "profiles.json")
        self._entries: List[ProfileEntry] = []
        self._loaded = False

    # -- loading -------------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = _json.load(f)
            if isinstance(raw, list):
                self._entries = [ProfileEntry.from_json(e) for e in raw
                                 if isinstance(e, dict)]
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.warning("profiles file unreadable (%s); starting empty",
                        exc)
            self._entries = []

    def _save(self) -> None:
        ensure_dirs()
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump([e.to_json() for e in self._entries], f,
                       indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- CRUD ------------------------------------------------------------------
    def add(self, kind: str, profile: ProtocolProfile,
            name: str = "", url: str = "") -> ProfileEntry:
        """Add a profile; ``url`` defaults to its canonical share URL."""
        if len(self._entries) >= MAX_ENTRIES:
            raise ProtocolError("profile store is full (%d)" % MAX_ENTRIES)
        if not url:
            url = canonical_url(profile)
        fallback = "%s %s" % (profile.title if hasattr(profile, "title")
                              else type(profile).__name__,
                              getattr(profile, "address",
                                      getattr(profile, "server", "")))
        entry = ProfileEntry(
            id=uuid.uuid4().hex,
            name=(name or getattr(profile, "tag", "")
                  or (profile.summary() if hasattr(profile, "summary")
                      else fallback)).strip()[:80] or fallback,
            kind=kind or getattr(profile, "kind", ""),
            url=url,
            data=profile.to_json() if hasattr(profile, "to_json") else {},
            created=time.time())
        self._ensure_loaded()
        # dedupe by URL — importing twice must not duplicate
        for existing in self._entries:
            if existing.url == entry.url:
                existing.data = entry.data
                existing.kind = entry.kind
                self._save()
                return existing
        self._entries.append(entry)
        self._save()
        return entry

    def remove(self, entry_id: str) -> bool:
        self._ensure_loaded()
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.id != entry_id]
        if len(self._entries) != before:
            self._save()
            return True
        return False

    def get(self, entry_id: str) -> Optional[ProfileEntry]:
        self._ensure_loaded()
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None

    def rename(self, entry_id: str, name: str) -> bool:
        entry = self.get(entry_id)
        if entry is None:
            return False
        entry.rename(name)
        self._save()
        return True

    def set_pinned(self, entry_id: str, pinned: bool) -> bool:
        entry = self.get(entry_id)
        if entry is None:
            return False
        entry.pinned = pinned
        self._save()
        return True

    def all(self) -> List[ProfileEntry]:
        self._ensure_loaded()
        return list(self._entries)

    def count(self) -> int:
        self._ensure_loaded()
        return len(self._entries)

    def clear(self) -> None:
        self._ensure_loaded()
        self._entries = []
        self._save()

    # -- bulk import -------------------------------------------------------------
    def add_many(self, profiles: Iterable) -> List[ProfileEntry]:
        """Add ``(kind, profile)`` pairs or bare profiles."""
        added: List[ProfileEntry] = []
        for item in profiles:
            if isinstance(item, tuple) and len(item) == 2:
                kind, profile = item
            else:
                kind, profile = getattr(item, "kind", ""), item
            try:
                added.append(self.add(kind, profile))
            except ProtocolError as exc:
                log.debug("profile not added: %s", exc)
        return added

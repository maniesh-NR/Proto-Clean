"""Local NetShield: blocklist management (add / remove / update), merging
and domain filtering.

Each configured source is downloaded to its own cache file
(~/.cache/proton-clean/blocklists/<slug>.txt) plus a metadata sidecar
(<slug>.json with domain count + timestamp). Enabled lists are merged into
merged.json which feeds the live DomainFilter used by the DNS blocker.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import httpx

from ..log import get
from ..paths import BLOCKLIST_DIR, ensure_dirs
from ..settings import BlocklistSource, default_blocklists

log = get("blocklists")

DEFAULT_SOURCES = default_blocklists  # backward-compatible name

USER_AGENT = "proton_clean/0.2"

# Never block these even if a list contains them.
WHITELIST = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "0.0.0.0", "127.0.0.1", "::1",
}


class DomainFilter:
    """Suffix-matching domain filter (a listed domain also blocks subdomains)."""

    def __init__(self, domains: Iterable[str]) -> None:
        self.exact: Set[str] = {
            d.strip().lower().rstrip(".") for d in domains if d and d.strip()
        } - WHITELIST

    def __len__(self) -> int:
        return len(self.exact)

    def blocked(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        if not name or name in WHITELIST:
            return False
        labels = name.split(".")
        # exact entry, or any parent domain is listed
        for i in range(len(labels)):
            if ".".join(labels[i:]) in self.exact:
                return True
        return False


@dataclass
class UpdateResult:
    ok: bool = True
    total_domains: int = 0
    per_source: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    updated: List[str] = field(default_factory=list)   # names refreshed OK


@dataclass
class BlocklistEntry:
    """A source plus its local cache status (for the management UI)."""
    name: str
    url: str
    enabled: bool = True
    domains: int = 0          # domains in the local cache (0 = never updated)
    updated_at: Optional[str] = None   # human timestamp of last update
    error: str = ""           # last download error, if any


def parse_hosts(text: str) -> Set[str]:
    """Parse hosts-format (and plain domain-per-line) content."""
    out: Set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:                       # plain "domain.tld"
            cand = parts[0].lower().strip(".")
            if _valid_domain(cand):
                out.add(cand)
        else:                                     # "0.0.0.0 domain [domain ...]"
            for cand in parts[1:]:
                cand = cand.lower().strip(".")
                if _valid_domain(cand):
                    out.add(cand)
    out -= WHITELIST
    return out


def _valid_domain(name: str) -> bool:
    if not name or len(name) > 253 or "." not in name:
        return False
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-._" for c in name):
        return False
    return not name.startswith(".") and not name.endswith(".")


def slug_for(url: str) -> str:
    """Stable cache filename for a blocklist URL."""
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]


class BlocklistManager:
    MERGED_FILE = "merged.json"

    def __init__(self, sources: Optional[List] = None,
                 cache_dir: Path = BLOCKLIST_DIR) -> None:
        # sources may be List[BlocklistSource] (new) or List[str] (legacy)
        self.sources: List[BlocklistSource] = [
            s if isinstance(s, BlocklistSource) else BlocklistSource.from_json(s)
            for s in (sources or default_blocklists())
        ]
        self.cache_dir = cache_dir
        self.filter = DomainFilter([])
        self._errors: Dict[str, str] = {}

    # ------------------------------------------------------------- sources
    def set_sources(self, sources: List[BlocklistSource]) -> None:
        self.sources = list(sources)

    def entries(self) -> List[BlocklistEntry]:
        """Sources joined with their cache metadata, for the UI."""
        out: List[BlocklistEntry] = []
        for src in self.sources:
            meta = self._read_meta(src.url)
            out.append(BlocklistEntry(
                name=src.name, url=src.url, enabled=src.enabled,
                domains=meta.get("domains", 0),
                updated_at=meta.get("updated_at_text"),
                error=self._errors.get(src.url, ""),
            ))
        return out

    def by_name(self, name: str) -> Optional[BlocklistSource]:
        for s in self.sources:
            if s.name == name:
                return s
        return None

    # ------------------------------------------------------------ updating
    def _download(self, url: str, timeout: float) -> Set[str]:
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": USER_AGENT}) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return parse_hosts(resp.text)

    def update_one(self, name: str, timeout: float = 60.0) -> UpdateResult:
        src = self.by_name(name)
        if not src:
            return UpdateResult(ok=False, error=f"no blocklist named {name!r}")
        try:
            domains = self._download(src.url, timeout)
        except Exception as e:  # noqa: BLE001
            self._errors[src.url] = str(e)
            log.warning("blocklist %s failed: %s", name, e)
            result = UpdateResult(ok=False, error=f"{name}: {e}")
            self.rebuild()
            return result
        self._errors.pop(src.url, None)
        self._store_cache(src.url, domains)
        log.info("blocklist %s: %d domains", name, len(domains))
        merged = self.rebuild()
        return UpdateResult(ok=True, total_domains=merged, updated=[name])

    def update_all(self, timeout: float = 60.0) -> UpdateResult:
        """Download every configured list (enabled and disabled alike)."""
        ensure_dirs()
        per_source: Dict[str, str] = {}
        updated: List[str] = []
        ok_any = False
        for src in self.sources:
            try:
                domains = self._download(src.url, timeout)
                self._errors.pop(src.url, None)
                self._store_cache(src.url, domains)
                per_source[src.name] = f"{len(domains):,} domains"
                updated.append(src.name)
                ok_any = True
                log.info("blocklist %s: %d domains", src.name, len(domains))
            except Exception as e:  # noqa: BLE001
                self._errors[src.url] = str(e)
                per_source[src.name] = f"failed: {e}"
                log.warning("blocklist %s failed: %s", src.name, e)
        if not ok_any and not self._any_cache():
            return UpdateResult(ok=False, error="all blocklist sources failed",
                                per_source=per_source)
        total = self.rebuild()
        return UpdateResult(ok=ok_any, total_domains=total,
                            per_source=per_source, updated=updated)

    # Backward-compatible name.
    def update(self, timeout: float = 60.0) -> UpdateResult:
        return self.update_all(timeout)

    # -------------------------------------------------------------- rebuild
    def rebuild(self) -> int:
        """Merge the cached files of all *enabled* lists into the filter."""
        ensure_dirs()
        merged: Set[str] = set()
        used: List[str] = []
        for src in self.sources:
            if not src.enabled:
                continue
            domains = self._read_cache_domains(src.url)
            if domains:
                merged |= domains
                used.append(src.name)
        self.filter = DomainFilter(merged)
        payload = {
            "updated_at": time.time(),
            "sources": used,
            "domains": sorted(self.filter.exact),
        }
        path = self.cache_dir / self.MERGED_FILE
        path.write_text(json.dumps(payload), encoding="utf-8")
        log.info("merged %d blocklists -> %d domains", len(used), len(self.filter))
        return len(self.filter)

    def remove_cached(self, url: str) -> None:
        """Drop the cache files of a removed list and rebuild."""
        for suffix in (".txt", ".json"):
            p = self.cache_dir / f"{slug_for(url)}{suffix}"
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        self._errors.pop(url, None)
        self.rebuild()

    def purge(self) -> None:
        """Remove every cached list + the merged file."""
        for p in self.cache_dir.glob("*"):
            if p.is_file():
                try:
                    p.unlink()
                except OSError:
                    pass
        self.filter = DomainFilter([])

    # --------------------------------------------------------------- cache
    def _store_cache(self, url: str, domains: Set[str]) -> None:
        slug = slug_for(url)
        (self.cache_dir / f"{slug}.txt").write_text(
            "\n".join(sorted(domains)), encoding="utf-8")
        meta = {
            "url": url,
            "domains": len(domains),
            "updated_at": time.time(),
            "updated_at_text": time.strftime("%Y-%m-%d %H:%M"),
        }
        (self.cache_dir / f"{slug}.json").write_text(
            json.dumps(meta), encoding="utf-8")

    def _read_meta(self, url: str) -> dict:
        p = self.cache_dir / f"{slug_for(url)}.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _read_cache_domains(self, url: str) -> Set[str]:
        p = self.cache_dir / f"{slug_for(url)}.txt"
        if not p.exists():
            return set()
        try:
            return {d for d in p.read_text(encoding="utf-8").split() if d}
        except OSError:
            return set()

    def _any_cache(self) -> bool:
        return any(self._read_cache_domains(s.url) for s in self.sources)

    # --------------------------------------------------------------- loading
    def load_cached(self) -> int:
        path = self.cache_dir / self.MERGED_FILE
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.filter = DomainFilter(data.get("domains", []))
            return len(self.filter)
        except (json.JSONDecodeError, OSError):
            return 0

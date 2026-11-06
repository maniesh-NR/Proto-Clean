"""Local NetShield: blocklist management (add / remove / update), merging
and domain filtering.

Each configured source is downloaded to its own cache file
(~/.cache/proto-clean/blocklists/<slug>.txt) plus a metadata sidecar
(<slug>.json with domain count + timestamp). Enabled lists are merged into
merged.json which feeds the live DomainFilter used by the DNS blocker.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import httpx

from ..log import get
from ..paths import BLOCKLIST_DIR, ensure_dirs
from ..settings import BlocklistSource, default_blocklists

log = get("blocklists")

DEFAULT_SOURCES = default_blocklists  # backward-compatible name

USER_AGENT = "proto_clean/0.2"

# Never block these even if a list contains them.
WHITELIST = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "0.0.0.0", "127.0.0.1", "::1",
}

# Cosmetic-filter marker inside Adblock/uBlock lists (##, #@#, #$#, #?#, ...).
# Such rules hide page elements — they never mean the DNS-level domain is
# bad, so the whole line must be ignored, not reduced to a bare domain.
_COSMETIC_RE = re.compile(r"#[@$%?^]*#")

# $options that still express a domain-level verdict usable at DNS level.
# "all" = every request type, "document"/"doc" = page loads, "important" =
# precedence flag. Anything else (script, image, xhr, 3p/1p, domain=,
# popup, redirect=, removeparam, replace=, ...) depends on browser context
# a DNS filter does not have and the rule is skipped.
_DNS_SAFE_OPTIONS = {"all", "document", "doc", "important"}


def _dns_safe_options(line: str) -> bool:
    """True when a rule's ``$options`` (if any) are all DNS-applicable."""
    if "$" not in line:
        return True
    options = line.split("$", 1)[1].split(None, 1)[0]   # options end at first space
    return all(o.strip() in _DNS_SAFE_OPTIONS for o in options.split(","))


def parse_filters(text: str) -> Tuple[Set[str], Set[str]]:
    """Parse a blocklist, returning ``(blocked, allowed)`` domains.

    Accepts hosts-format (``0.0.0.0 domain``), plain domain-per-line and
    Adblock/uBlock network-filter syntax — the formats of every default
    list (which are the same ones uBlock Origin enables out of the box):

    - ``||domain^`` / ``||domain``  → blocked (DNS-applicable network rule)
    - ``@@||domain^``               → exception (never blocked)
    - rules whose ``$options`` are all ``all`` / ``document`` / ``doc`` /
      ``important`` stay applied; any other option, wildcards, URL
      patterns, cosmetic (``##``) and scriptlet rules are skipped: they
      depend on browser context a DNS filter does not have.

    URL-specific rules (``||host/path…``) are also skipped: DNS knows the
    host only, and collapsing e.g. ``||github.com/some/malware.zip^`` to
    the bare domain would block the whole shared host.
    """
    blocked: Set[str] = set()
    allowed: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "[")):    # ABP/uBO comments
            continue
        if not line.startswith("#") and (_COSMETIC_RE.search(line)
                                         or "$$" in line):
            continue                                   # cosmetic / HTML rule
        line = line.split("#", 1)[0].strip()           # hosts-format comment
        if not line or not _dns_safe_options(line):    # context-dependent $options
            continue
        exception = line.startswith("@@")
        if exception:
            line = line[2:].strip()
            if not line:                                # bare "@@" (allow-all)
                continue
        if line.startswith("||"):
            host = line[2:].split("^", 1)[0]
            if "/" in host:                              # URL-specific rule
                continue
            host = host.strip(".").lower()
            if _valid_domain(host):
                (allowed if exception else blocked).add(host)
            continue
        if exception:
            continue                                    # non-domain exception
        parts = line.split()
        if len(parts) == 1:                             # plain "domain.tld"
            cand = parts[0].lower().strip(".")
            if _valid_domain(cand):
                blocked.add(cand)
        else:                                           # "0.0.0.0 d1 [d2 …]"
            for cand in parts[1:]:
                cand = cand.lower().strip(".")
                if _valid_domain(cand):
                    blocked.add(cand)
    blocked -= WHITELIST
    allowed -= WHITELIST
    return blocked, allowed


class DomainFilter:
    """Suffix-matching domain filter (a listed domain also blocks subdomains).

    ``exceptions`` (from ``@@||domain^`` rules) never block — when both a
    block and an exception match, the more specific (longer) name wins.
    """

    def __init__(self, domains: Iterable[str],
                 exceptions: Iterable[str] = ()) -> None:
        self.exact: Set[str] = {
            d.strip().lower().rstrip(".") for d in domains if d and d.strip()
        } - WHITELIST
        self.allowed: Set[str] = {
            d.strip().lower().rstrip(".") for d in exceptions if d and d.strip()
        } - WHITELIST

    @property
    def exceptions(self) -> Set[str]:
        return set(self.allowed)

    def __len__(self) -> int:
        return len(self.exact)

    def blocked(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        if not name or name in WHITELIST:
            return False
        labels = name.split(".")
        # walk from the most specific suffix outward; the first list that
        # matches an entry decides (so @@ exceptions can punch holes)
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in self.allowed:
                return False
            if suffix in self.exact:
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
    return parse_filters(text)[0]


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
        # Optional upstream proxy URL for blocklist downloads (e.g. the
        # running Xray/samizdat inbound or Lantern on 127.0.0.1:8787) —
        # the Lantern-style fallback path when direct fetches are blocked.
        self.proxy: Optional[str] = None

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
    def _download(self, url: str, timeout: float) -> Tuple[Set[str], Set[str]]:
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": USER_AGENT},
                          proxy=self.proxy) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return parse_filters(resp.text)

    def update_one(self, name: str, timeout: float = 60.0) -> UpdateResult:
        src = self.by_name(name)
        if not src:
            return UpdateResult(ok=False, error=f"no blocklist named {name!r}")
        try:
            domains, exceptions = self._download(src.url, timeout)
        except Exception as e:  # noqa: BLE001
            self._errors[src.url] = str(e)
            log.warning("blocklist %s failed: %s", name, e)
            result = UpdateResult(ok=False, error=f"{name}: {e}")
            self.rebuild()
            return result
        self._errors.pop(src.url, None)
        self._store_cache(src.url, domains, exceptions)
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
                domains, exceptions = self._download(src.url, timeout)
                self._errors.pop(src.url, None)
                self._store_cache(src.url, domains, exceptions)
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
        merged_exceptions: Set[str] = set()
        used: List[str] = []
        for src in self.sources:
            if not src.enabled:
                continue
            domains = self._read_cache_domains(src.url)
            exceptions = self._read_cache_exceptions(src.url)
            if domains or exceptions:
                merged |= domains
                merged_exceptions |= exceptions
                used.append(src.name)
        self.filter = DomainFilter(merged, merged_exceptions)
        payload = {
            "updated_at": time.time(),
            "sources": used,
            "domains": sorted(self.filter.exact),
            "exceptions": sorted(self.filter.allowed),
        }
        path = self.cache_dir / self.MERGED_FILE
        path.write_text(json.dumps(payload), encoding="utf-8")
        log.info("merged %d blocklists -> %d domains", len(used), len(self.filter))
        return len(self.filter)

    def remove_cached(self, url: str) -> None:
        """Drop the cache files of a removed list and rebuild."""
        for suffix in (".txt", ".json", ".allow.txt"):
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
    def _store_cache(self, url: str, domains: Set[str],
                     exceptions: Set[str] = frozenset()) -> None:
        slug = slug_for(url)
        (self.cache_dir / f"{slug}.txt").write_text(
            "\n".join(sorted(domains)), encoding="utf-8")
        (self.cache_dir / f"{slug}.allow.txt").write_text(
            "\n".join(sorted(exceptions)), encoding="utf-8")
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

    def _read_cache_exceptions(self, url: str) -> Set[str]:
        p = self.cache_dir / f"{slug_for(url)}.allow.txt"
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
            self.filter = DomainFilter(data.get("domains", []),
                                       data.get("exceptions", []))
            return len(self.filter)
        except (json.JSONDecodeError, OSError):
            return 0

import pytest

from proto_clean.netshield.blocklists import (BlocklistManager, DomainFilter,
                                                parse_filters, parse_hosts,
                                                slug_for)
from proto_clean.settings import BlocklistSource, default_blocklists


def _lists():
    return [
        BlocklistSource(name="List A", url="https://a.example/hosts"),
        BlocklistSource(name="List B", url="https://b.example/hosts"),
    ]


HOSTS_SAMPLE = """# Title: test list
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.org analytics.example.org
badtoken!!line.example
somebare.domain
"""


def test_parse_hosts_variants():
    domains = parse_hosts(HOSTS_SAMPLE)
    assert "ads.example.com" in domains
    assert "tracker.example.org" in domains
    assert "analytics.example.org" in domains
    assert "somebare.domain" in domains
    assert "localhost" not in domains          # whitelisted out
    assert "badtoken!!line.example" not in domains


ADBLOCK_SAMPLE = r"""!
[Adblock Plus 2.0]
! Title: uBlock filters – test sample
||ads.example.com^
||tracker.example.net^$script,third-party   (options: not DNS-level)
||malware.example^$document                 (document: DNS-applicable)
||everything.example^$all                   (all: DNS-applicable)
||github.example/some/malware.zip^$document (URL-specific: not DNS-level)
||plain.example.org
@@||ok.ads.example.com^
@@||allowme.example^$document               (document exception: applied)
@@||denyall.example^$popup                  (option not DNS-level: skipped)
example.com##.banner                        (cosmetic: never a DNS block)
example.org#@#.promo                        (cosmetic unhide)
example.com$$script[data-ad]                (HTML filtering)
/regex\.pattern/
||wild*.example.com^
! @@||commented.example^
0.0.0.0 hosts.example.com
"""


def test_parse_filters_adblock_syntax():
    blocked, allowed = parse_filters(ADBLOCK_SAMPLE)
    assert "ads.example.com" in blocked
    assert "plain.example.org" in blocked
    assert "hosts.example.com" in blocked          # hosts lines still work
    assert "malware.example" in blocked            # $document keeps DNS meaning
    assert "everything.example" in blocked         # $all keeps DNS meaning
    # URL-specific rules never collapse to a bare domain (shared hosts!)
    assert "github.example" not in blocked
    # $option rules are context-dependent -> not DNS-blockable
    assert "tracker.example.net" not in blocked
    # exceptions parse; option-carrying exceptions without DNS meaning don't
    assert allowed == {"ok.ads.example.com", "allowme.example"}
    # cosmetic / scriptlet / HTML / regex lines never become bare domains
    assert "example.com" not in blocked
    assert "example.org" not in blocked
    assert "wild*.example.com" not in blocked
    assert "commented.example" not in allowed
    assert "denyall.example" not in allowed


def test_domain_filter_exceptions_most_specific_wins():
    f = DomainFilter(["ads.example.com", "doubleclick.net"],
                     ["ok.ads.example.com"])
    assert f.blocked("ads.example.com")
    assert f.blocked("other.ads.example.com")
    assert not f.blocked("ok.ads.example.com")
    assert not f.blocked("sub.ok.ads.example.com")   # exception covers children
    assert f.blocked("doubleclick.net")
    assert not f.blocked("doubleclick.org")
    # a blocked child under an allowed parent still blocks (longer name wins)
    g = DomainFilter(["ads.example.com"], ["example.com"])
    assert g.blocked("ads.example.com")
    assert not g.blocked("shop.example.com")


def test_exceptions_survive_cache_roundtrip(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    monkeypatch.setattr(
        BlocklistManager, "_download",
        lambda self, url, timeout: ({"ads.example.com", "tracker.example"},
                                    {"ok.ads.example.com"}))
    m.update_all()
    assert m.filter.blocked("ads.example.com")
    assert not m.filter.blocked("ok.ads.example.com")
    # fresh manager loading merged.json keeps the exceptions
    m2 = BlocklistManager(_lists(), cache_dir=tmp_path)
    assert m2.load_cached() == 2
    assert m2.filter.exceptions == {"ok.ads.example.com"}
    assert not m2.filter.blocked("ok.ads.example.com")


def test_suffix_matching_blocks_subdomains():
    f = DomainFilter(["doubleclick.net"])
    assert f.blocked("doubleclick.net")
    assert f.blocked("ad.doubleclick.net")
    assert f.blocked("AD.DoubleClick.Net.")    # case + trailing dot
    assert not f.blocked("notdoubleclick.net")


def test_whitelist_never_blocked():
    f = DomainFilter(["localhost"])
    assert not f.blocked("localhost")
    assert len(f) == 0


def test_empty_and_weird():
    f = DomainFilter([])
    assert not f.blocked("anything.example")
    assert not f.blocked("")
    assert not f.blocked("...")


# --------------------------------------------------------------- manager

def test_update_all_merges_and_caches(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)

    def fake_download(self, url, timeout):
        if "a.example" in url:
            return {"ads.a.example", "track.a.example"}, set()
        if "b.example" in url:
            return {"ads.b.example"}, set()
        raise RuntimeError("boom")

    monkeypatch.setattr(BlocklistManager, "_download", fake_download)
    result = m.update_all()
    assert result.ok is True
    assert result.total_domains == 3
    assert set(result.updated) == {"List A", "List B"}
    # per-list cache files exist
    a_slug = slug_for("https://a.example/hosts")
    assert (tmp_path / f"{a_slug}.txt").exists()
    assert (tmp_path / f"{a_slug}.json").exists()
    # merged filter loaded from disk on a fresh manager
    m2 = BlocklistManager(_lists(), cache_dir=tmp_path)
    assert m2.load_cached() == 3
    assert m2.filter.blocked("ads.a.example")
    assert m2.filter.blocked("ads.b.example")


def test_update_all_survives_total_failure_with_cache(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    monkeypatch.setattr(BlocklistManager, "_download",
                        lambda self, url, timeout: ({"x.example"}, set()))
    m.update_all()
    monkeypatch.setattr(BlocklistManager, "_download",
                        lambda self, url, timeout: (_ for _ in ()).throw(
                            RuntimeError("network down")))
    result = m.update_all()
    # download failed but the cache keeps the old domains alive
    assert result.ok is False
    assert m.filter.blocked("x.example")


def test_update_one_unknown_name(tmp_path):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    result = m.update_one("nope")
    assert result.ok is False


def test_disabled_lists_excluded_from_merge(tmp_path, monkeypatch):
    lists = _lists()
    lists[1].enabled = False
    m = BlocklistManager(lists, cache_dir=tmp_path)
    monkeypatch.setattr(BlocklistManager, "_download",
                        lambda self, url, timeout: ({"ads.example"}, set()))
    m.update_all()
    # disabling B must drop its domains from the merged filter
    m.rebuild()
    assert m.filter.blocked("ads.example")     # from A only, but same domain
    # now check via a list only B would provide
    lists[0].enabled = False
    lists[1].enabled = True
    m.set_sources(lists)
    m.rebuild()
    assert len(m.filter) > 0                    # B enabled -> merged again
    lists[1].enabled = False
    m.set_sources(lists)
    m.rebuild()
    assert len(m.filter) == 0                   # nothing enabled


def test_entries_reflect_cache_metadata(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    monkeypatch.setattr(
        BlocklistManager, "_download",
        lambda self, url, timeout: ({"a.example", "b.example"}, set())
        if "a.example" in url else (_ for _ in ()).throw(RuntimeError("nope")))
    m.update_all()
    entries = {e.name: e for e in m.entries()}
    assert entries["List A"].domains == 2
    assert entries["List A"].updated_at
    assert "nope" in entries["List B"].error


def test_remove_cached_drops_files_and_rebuilds(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    monkeypatch.setattr(BlocklistManager, "_download",
                        lambda self, url, timeout: ({"ads.example"}, set()))
    m.update_all()
    a_url = "https://a.example/hosts"
    m.remove_cached(a_url)
    assert not (tmp_path / f"{slug_for(a_url)}.txt").exists()
    # B's domains still merged
    assert m.filter.blocked("ads.example")


def test_legacy_string_sources_accepted(tmp_path):
    m = BlocklistManager(["https://legacy.example/hosts"], cache_dir=tmp_path)
    assert m.sources[0].url == "https://legacy.example/hosts"
    assert m.sources[0].name
    assert m.sources[0].enabled is True


def test_default_blocklists_match_ublock_origin():
    """Defaults must be exactly uBlock Origin's out-of-the-box filter lists."""
    expected = [
        ("uBlock filters – Ads",
         "https://ublockorigin.github.io/uAssets/filters/filters.txt"),
        ("uBlock filters – Badware risks",
         "https://ublockorigin.github.io/uAssets/filters/badware.txt"),
        ("uBlock filters – Privacy",
         "https://ublockorigin.github.io/uAssets/filters/privacy.txt"),
        ("uBlock filters – Unbreak",
         "https://ublockorigin.github.io/uAssets/filters/unbreak.txt"),
        ("uBlock filters – Quick fixes",
         "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt"),
        ("EasyList",
         "https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt"),
        ("EasyPrivacy",
         "https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt"),
        ("Online Malicious URL Blocklist",
         "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-vivaldi-online.txt"),
        ("Peter Lowe's Ad and tracking server list",
         "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
    ]
    assert [(b.name, b.url) for b in default_blocklists()] == expected

    # every default is re-addable from the presets after removal
    from proto_clean.settings import BLOCKLIST_PRESETS
    assert {u for _, u in expected} <= {u for _, u in BLOCKLIST_PRESETS}

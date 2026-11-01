import pytest

from cleanroom.netshield.blocklists import (BlocklistManager, DomainFilter,
                                                parse_hosts, slug_for)
from cleanroom.settings import BlocklistSource


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
            return {"ads.a.example", "track.a.example"}
        if "b.example" in url:
            return {"ads.b.example"}
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
                        lambda self, url, timeout: {"x.example"})
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
                        lambda self, url, timeout: {"ads.example"})
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
        lambda self, url, timeout: {"a.example", "b.example"}
        if "a.example" in url else (_ for _ in ()).throw(RuntimeError("nope")))
    m.update_all()
    entries = {e.name: e for e in m.entries()}
    assert entries["List A"].domains == 2
    assert entries["List A"].updated_at
    assert "nope" in entries["List B"].error


def test_remove_cached_drops_files_and_rebuilds(tmp_path, monkeypatch):
    m = BlocklistManager(_lists(), cache_dir=tmp_path)
    monkeypatch.setattr(BlocklistManager, "_download",
                        lambda self, url, timeout: {"ads.example"})
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

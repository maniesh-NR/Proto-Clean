import pytest

from proto_clean.servers.models import LogicalServer, parse_logical_servers
from proto_clean.servers.selection import (
    fastest_server,
    rank_servers,
    region_of,
    score_of,
)

SAMPLE = {
    "ID": "abc-1",
    "Name": "US-FREE#1",
    "EntryCountry": "US",
    "ExitCountry": "US",
    "Domain": "us-free-01.protonvpn.net",
    "Tier": 0,
    "Features": 4,
    "Load": 31.4,
    "Score": 1.23,
    "Status": 1,
    "Location": {"City": "New York City", "Region": "East"},
    "Servers": [
        {"ID": "s1", "Domain": "a.protonvpn.net", "EntryIP": "1.2.3.4",
         "ExitIP": "1.2.3.4", "Status": 1, "X25519PublicKey": "pk"}
    ],
}


def _mk(name, tier=0, load=10.0, score=1.0, status=1, features=0,
        exit_country="US"):
    return LogicalServer(
        id=name, name=name, entry_country=exit_country,
        exit_country=exit_country,
        domain=f"{name}.protonvpn.net", tier=tier, features=features,
        load=load, score=score, status=status, physical=[])


def test_parse_api_envelope():
    out = parse_logical_servers({"LogicalServers": [SAMPLE]})
    assert len(out) == 1
    s = out[0]
    assert s.name == "US-FREE#1"
    assert s.is_free
    assert s.supports_p2p            # Features = 4
    assert s.city == "New York City"
    assert len(s.physical) == 1
    assert s.load == 31.4


def test_parse_bare_list_and_garbage():
    assert parse_logical_servers([]) == []
    assert parse_logical_servers("junk") == []
    assert parse_logical_servers({"nope": 1}) == []


def test_fastest_prefers_lowest_score():
    servers = [_mk("A", score=2.0), _mk("B", score=0.5), _mk("C", score=1.0)]
    assert fastest_server(servers).name == "B"


def test_offline_servers_ranked_last():
    servers = [_mk("DOWN", score=0.1, status=0), _mk("UP", score=9.0)]
    assert fastest_server(servers).name == "UP"


def test_critical_load_penalised():
    servers = [_mk("HOT", score=0.1, load=95), _mk("COOL", score=0.2, load=40)]
    assert fastest_server(servers).name == "COOL"


def test_tier_filter():
    servers = [_mk("FREE", tier=0, score=5), _mk("PLUS", tier=2, score=0.1)]
    assert fastest_server(servers, max_tier=0).name == "FREE"
    assert fastest_server(servers, max_tier=2).name == "PLUS"


def test_ranking_stable_order():
    servers = [_mk("C", score=3), _mk("A", score=1), _mk("B", score=2)]
    assert [s.name for s in rank_servers(servers)] == ["A", "B", "C"]


def test_score_of_falls_back_to_load():
    s = _mk("X", score=1e9, load=25)
    assert score_of(s) == 0.25


# ------------------------------------------------- paid servers are excluded

def test_rank_free_only_never_returns_paid():
    servers = [
        _mk("US-FREE#1", tier=0, score=5),
        _mk("US#1", tier=1, score=0.1),           # Plus
        _mk("CH-SE#1", tier=2, score=0.2),        # Secure Core
    ]
    ranked = rank_servers(servers, max_tier=0)
    assert [s.name for s in ranked] == ["US-FREE#1"]
    assert fastest_server(servers, max_tier=0).name == "US-FREE#1"


def test_store_free_servers_filters_paid(tmp_path, monkeypatch):
    from proto_clean.servers import store as store_mod

    monkeypatch.setattr(store_mod, "SERVER_CACHE_FILE",
                        tmp_path / "servers.json")
    st = store_mod.ServerStore()
    st.replace([
        _mk("US-FREE#1", tier=0, score=5),
        _mk("NL#3", tier=1, score=0.1),
        _mk("IS-UK#1", tier=2, score=0.2),
        _mk("JP-FREE#2", tier=0, score=3),
    ])
    free = st.free_servers()
    assert {s.name for s in free} == {"US-FREE#1", "JP-FREE#2"}
    assert all(s.is_free for s in free)
    # and it survives a reload from disk
    st2 = store_mod.ServerStore()
    assert {s.name for s in st2.free_servers()} == {"US-FREE#1", "JP-FREE#2"}


# ---------------------------------------------------------------------------
# region_of — the collapsible server-list grouping key
# ---------------------------------------------------------------------------

def test_region_of_free_servers_group_under_country():
    # Free-tier names ("US-FREE#1..N") fold under the country itself.
    assert region_of(_mk("US-FREE#1", exit_country="US")) == "US"
    assert region_of(_mk("US-FREE#12", exit_country="US")) == "US"
    assert region_of(_mk("JP-FREE#3", exit_country="JP")) == "JP"


def test_region_of_city_servers_keep_city_region():
    # Non-free city servers keep their country-city region code.
    assert region_of(_mk("US-NY#1", exit_country="US")) == "US-NY"
    assert region_of(_mk("SE-STA#4", exit_country="SE")) == "SE-STA"


def test_region_of_plain_country_names_and_fallbacks():
    assert region_of(_mk("SE#2", exit_country="SE")) == "SE"
    # No "#" in the name -> whole name is the region.
    assert region_of(_mk("NL", exit_country="NL")) == "NL"
    # Empty name -> fall back to the exit country.
    assert region_of(_mk("", exit_country="DE")) == "DE"


def test_region_of_matches_the_android_implementation():
    """The Kotlin `LogicalServer.regionOf` mirrors this logic — keep the
    two in sync (same seeds in /android .../Models.kt)."""
    for name, country, expected in (
        ("US-FREE#1", "US", "US"),
        ("US-NY#1", "US", "US-NY"),
        ("SE#2", "SE", "SE"),
        ("jp-free#7", "JP", "jp"),
        ("", "DE", "DE"),
    ):
        assert region_of(_mk(name, exit_country=country)) == expected, name

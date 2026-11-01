"""Parsing tests for the Downloads-page scrapers, using cell text sampled
from the real logged-in page dump."""

from cleanroom.account import downloads_page as dp
from cleanroom.account.downloads_page import (
    FREE_CATEGORY_SELECTORS, LOGICALS_ALT_FETCH_URLS, OVPN,
    OVPN_FREE_CATEGORY_SELECTORS, OVPN_TCP_SELECTORS, OVPN_UDP_SELECTORS,
    OVPN_CONFIG_NAME_SELECTORS, OPENVPN_LINK_SELECTORS, WG,
    WIREGUARD_LINK_SELECTORS, ConfigOptions, _config_matches,
    _free_category_selectors_for, _link_selectors_for, _name_selectors_for,
    _section_for, looks_like_openvpn, looks_like_wireguard, parse_server_row,
)


WG_TEXT = "[Interface]\nPrivateKey = k\nAddress = 10.2.0.2/32\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
OVPN_TEXT = "client\nproto tcp\nremote 1.2.3.4 443 tcp\n<ca>\nxyz\n</ca>\n"


def test_real_page_row_with_newlines_and_ipv6():
    # exact inner_text() of the CA-FREE#1 row in the real dump
    row = "CA-FREE#1\t\n64%\nIPv6\n\tCreate"
    assert parse_server_row(row) == ("CA-FREE#1", 64.0)


def test_row_rendered_with_tabs_only():
    row = "CA-FREE#1\t64%\tCreate"
    assert parse_server_row(row) == ("CA-FREE#1", 64.0)


def test_row_without_ipv6_badge():
    row = "CA-FREE#2\t\n37%\n\tCreate"
    assert parse_server_row(row) == ("CA-FREE#2", 37.0)


def test_plain_space_separated_row():
    assert parse_server_row("US-FREE#50 12% Create") == ("US-FREE#50", 12.0)


def test_name_prefix_trap():
    # CA-FREE#1 must be found in its own row; CA-FREE#10 is a different row
    assert parse_server_row("CA-FREE#10\t\n62%\nIPv6\n\tCreate") \
        == ("CA-FREE#10", 62.0)
    assert parse_server_row("CA-FREE#1\t\n64%\n\tCreate")[0] == "CA-FREE#1"


def test_missing_load_defaults_to_zero():
    assert parse_server_row("JP-FREE#1 Create") == ("JP-FREE#1", 0.0)


def test_non_server_rows_rejected():
    for junk in ("Name Status Action", "Canada", "", "Create", "64% IPv6",
                 "US#1 20% Create"):          # paid names lack the -FREE part
        assert parse_server_row(junk) is None, junk


# --------------------------------------------- protocol detection & selectors


def test_config_format_detection():
    assert looks_like_wireguard(WG_TEXT)
    assert not looks_like_wireguard(OVPN_TEXT)
    assert looks_like_openvpn(OVPN_TEXT)
    assert not looks_like_openvpn(WG_TEXT)
    # a bare "client" with a marker but no remote is NOT accepted
    assert not looks_like_openvpn("client\nproto udp\n")


def test_config_matches_by_protocol():
    assert _config_matches("wireguard", WG_TEXT)
    assert not _config_matches("wireguard", OVPN_TEXT)
    assert _config_matches("openvpn", OVPN_TEXT)
    assert not _config_matches("openvpn", WG_TEXT)


def test_per_protocol_selector_sets():
    assert _section_for("wireguard") == WG
    assert _section_for("openvpn") == OVPN
    assert _link_selectors_for("wireguard") == WIREGUARD_LINK_SELECTORS
    assert _link_selectors_for("openvpn") == OPENVPN_LINK_SELECTORS
    assert _link_selectors_for("openvpn")[0].startswith(OVPN)
    # every OpenVPN selector is scoped to the OpenVPN section
    for sel in (OVPN_CONFIG_NAME_SELECTORS + OVPN_UDP_SELECTORS
                + OVPN_TCP_SELECTORS + OVPN_FREE_CATEGORY_SELECTORS):
        assert sel.startswith(OVPN), sel
    # WireGuard free-category is still scoped to the WG section
    assert _free_category_selectors_for("wireguard") == FREE_CATEGORY_SELECTORS
    assert _name_selectors_for("wireguard") == dp.CONFIG_NAME_SELECTORS


def test_config_options_defaults():
    o = ConfigOptions()
    assert o.protocol == "wireguard"
    assert o.openvpn_transport == "udp"
    assert o.vpn_accelerator is True          # WG toggles default ON
    assert o.nat_pmp_port_forward is True
    assert o.alternative_routing is True


def test_alternative_routing_mirror_urls():
    # mirror API hosts, used only when alternative routing is enabled
    assert LOGICALS_ALT_FETCH_URLS == [
        "https://api.protonvpn.com/vpn/logicals",
        "https://vpn-api.proton.me/vpn/logicals",
    ]
    assert all("api.protonvpn.com" not in u or ".com" in u
               for u in dp.LOGICALS_FETCH_URLS)   # direct list unchanged

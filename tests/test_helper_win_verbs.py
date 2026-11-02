"""Windows helper verb-whitelist tests (pure validation — runs anywhere)."""

import pytest

from proto_clean.helper_win import WinHelperError, validate_call, execute


def _args(verb, *args):
    return validate_call(verb, tuple(str(a) for a in args))


def test_ks_on_accepts_optional_transport():
    _args("ks-on", "Ethernet", "1.2.3.4", "51820", "0")           # legacy 4-arg
    _args("ks-on", "Ethernet", "1.2.3.4", "51820", "0", "udp")    # 5-arg udp
    _args("ks-on", "Ethernet", "1.2.3.4", "51820", "1", "tcp")    # OpenVPN/TCP
    with pytest.raises(WinHelperError):                # bad transport
        _args("ks-on", "Ethernet", "1.2.3.4", "51820", "0", "sctp")
    with pytest.raises(WinHelperError):                # bad ip
        _args("ks-on", "Ethernet", "not-an-ip", "51820", "0", "tcp")
    with pytest.raises(WinHelperError):                # bad allow_lan flag
        _args("ks-on", "Ethernet", "1.2.3.4", "51820", "2", "tcp")


def test_v6_verbs_in_whitelist():
    _args("v6-on")
    _args("v6-off")
    with pytest.raises(WinHelperError):
        _args("v6-on", "extra-arg")


def test_ovpn_verbs_validate_but_refuse_to_execute():
    _args("ovpn-up", "tun")
    _args("ovpn-up", "tap")
    _args("ovpn-install-config", "C:/somewhere/proto_clean.ovpn")
    _args("ovpn-down")
    with pytest.raises(WinHelperError):
        _args("ovpn-up", "vEthernet")
    # execution must fail with a clear "not supported" message
    for verb, args in (("ovpn-up", ("tun",)), ("ovpn-down", ()),
                       ("ovpn-install-config", ("whatever",))):
        with pytest.raises(WinHelperError, match="not supported"):
            execute(verb, args)

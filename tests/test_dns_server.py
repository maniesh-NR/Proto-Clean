"""Live test of the embedded DNS blocker.

Starts DnsBlocker on a free port with a small filter, queries it with a
dnslib client: blocked names must be NXDOMAIN, real names must resolve
via the upstream (plain UDP in the test environment). Skips when no
network is available.
"""

import socket
import time

import pytest
from dnslib import DNSRecord, QTYPE

from proto_clean.netshield.blocklists import DomainFilter
from proto_clean.netshield.dns_server import DnsBlocker, DnsUpstream

BLOCKED = {"doubleclick.net", "ads.example.com"}


def _udp_query(port: int, name: str, qtype="A", timeout=6.0):
    q = DNSRecord.question(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q.pack(), ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    return DNSRecord.parse(data)


def _have_network() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(DNSRecord.question("example.com").pack(),
                     ("1.1.1.1", 53))
            s.recvfrom(1024)
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def blocker():
    if not _have_network():
        pytest.skip("no network for DNS upstream test")
    server = DnsBlocker(
        DomainFilter(BLOCKED),
        upstream=DnsUpstream(udp_resolver="1.1.1.1", use_doh=False),
        port=15353,
        nxdomain_for_blocked=True,
    )
    server.start()
    time.sleep(0.3)
    yield server
    server.stop()


def test_blocked_name_gets_nxdomain(blocker):
    a = _udp_query(blocker.port, "ad.doubleclick.net")
    assert a.header.rcode == 3            # NXDOMAIN
    assert not a.rr                       # no answer records
    assert blocker.blocked_hits >= 1


def test_allowed_name_resolves(blocker):
    a = _udp_query(blocker.port, "example.com")
    assert a.header.rcode == 0
    assert len(a.rr) >= 1
    assert QTYPE[a.rr[0].rtype] == "A"


def test_response_id_matches_request(blocker):
    q = DNSRecord.question("example.com")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(6)
        s.sendto(q.pack(), ("127.0.0.1", blocker.port))
        data, _ = s.recvfrom(4096)
    assert DNSRecord.parse(data).header.id == q.header.id


def test_blocked_zero_ip_mode():
    server = DnsBlocker(
        DomainFilter(BLOCKED),
        upstream=DnsUpstream(udp_resolver="1.1.1.1", use_doh=False),
        port=15354,
        nxdomain_for_blocked=False,
    )
    server.start()
    time.sleep(0.2)
    try:
        a = _udp_query(server.port, "ads.example.com")
        assert a.header.rcode == 0
        assert str(a.rr[0].rdata) == "0.0.0.0"
    finally:
        server.stop()


# ------------------------------------------------- regression tests (review)

def test_doh_tls_is_verified_against_the_hostname(monkeypatch):
    """DoH connects to a literal IP; the TLS handshake must still verify
    the certificate against the real hostname (SNI), or every query would
    fail verification and silently fall back to plain UDP."""
    from proto_clean.netshield import dns_server as dns_mod

    captured = {}

    class FakeSock:
        def close(self):
            pass

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            captured["sni"] = server_hostname
            return FakeSock()

    monkeypatch.setattr(dns_mod.socket, "create_connection",
                        lambda *a, **k: FakeSock())
    conn = dns_mod._IPHTTPSConnection("1.2.3.4", "doh.protonvpn.ch", 443,
                                      context=FakeCtx())
    conn.connect()
    assert captured["sni"] == "doh.protonvpn.ch"

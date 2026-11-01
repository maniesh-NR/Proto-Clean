import socket
import struct

import pytest

from cleanroom.vpn.portforward import (
    NatPmpClient, NatPmpError, build_map_request, parse_map_response,
)


def test_request_layout():
    # 12-byte MAP-UDP request, big-endian
    req = build_map_request(internal_port=51827, external_port=0, lifetime=7200)
    assert len(req) == 12
    ver, op, reserved, internal, external, lifetime = struct.unpack(">BBHHHI", req)
    assert (ver, op, reserved) == (0, 1, 0)
    assert internal == 51827
    assert external == 0
    assert lifetime == 7200


def test_parse_success_response():
    # ver, op|0x80, result=0, epoch, internal, external, lifetime
    body = struct.pack(">BBHIHHI", 0, 0x81, 0, 12345, 51827, 40000, 60)
    result, internal, external, lifetime = parse_map_response(body)
    assert result == 0
    assert internal == 51827
    assert external == 40000
    assert lifetime == 60


def test_parse_refused_response():
    body = struct.pack(">BBHIHHI", 0, 0x81, 2, 0, 0, 0, 0)  # 2 = not authorized
    with pytest.raises(NatPmpError) as exc:
        parse_map_response(body)
    assert "paid" in str(exc.value)


def test_short_response_rejected():
    with pytest.raises(NatPmpError):
        parse_map_response(b"\x00\x81\x00")


def test_client_to_unreachable_gateway():
    # 10.255.255.254 should not answer → timeout error, no crash
    client = NatPmpClient(gateway="10.255.255.254", timeout=0.3)
    with pytest.raises(socket.timeout):
        client.map(12345)

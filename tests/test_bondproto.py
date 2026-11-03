"""Tests for the PCB wire protocol (proto_clean.vpn.bondproto)."""

from __future__ import annotations

import pytest

from proto_clean.vpn.bondproto import (
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, FRAME_DATA, FRAME_FIN,
    FRAME_HANDSHAKE, FRAME_MEMBER_DOWN, FRAME_PING, FRAME_PONG,
    FrameReader, Reassembler, WeightedScheduler, auth_digest,
    chunk_data, handshake_matches_token, new_session_id, pack_address,
    pack_frame, pack_handshake, unpack_address, unpack_handshake,
    BondProtocolError, MAX_CHUNK, NULL_AUTH,
)


# ---------------------------------------------------------------- framing
class TestFraming:
    def test_roundtrip_all_types(self):
        for ftype, seq, payload in [
            (FRAME_DATA, 0, b"hello"),
            (FRAME_DATA, 0xFFFFFFF0, b"x" * 300),
            (FRAME_FIN, 0, b""),
            (FRAME_PING, 7, b"\x01" * 8),
            (FRAME_PONG, 7, b"\x01" * 8),
            (FRAME_MEMBER_DOWN, 3, b""),
            (FRAME_HANDSHAKE, 0, b"\x00" * 56),
        ]:
            blob = pack_frame(ftype, seq, payload)
            reader = FrameReader()
            frames = reader.feed(blob)
            assert frames == [(ftype, seq, payload)]

    def test_split_delivery(self):
        """Frames arriving in tiny TCP segments still parse."""
        blob = pack_frame(FRAME_DATA, 5, b"chunk-of-data" * 4)
        reader = FrameReader()
        out = []
        for i in range(len(blob)):
            out += reader.feed(blob[i:i + 1])
        assert out == [(FRAME_DATA, 5, b"chunk-of-data" * 4)]

    def test_multiple_frames_one_feed(self):
        reader = FrameReader()
        blob = (pack_frame(FRAME_DATA, 0, b"a")
                + pack_frame(FRAME_DATA, 1, b"b")
                + pack_frame(FRAME_FIN, 0))
        assert reader.feed(blob) == [
            (FRAME_DATA, 0, b"a"), (FRAME_DATA, 1, b"b"), (FRAME_FIN, 0, b"")]

    def test_empty_payload_frame(self):
        reader = FrameReader()
        assert reader.feed(pack_frame(FRAME_FIN, 0)) == [(FRAME_FIN, 0, b"")]

    def test_bad_magic_rejected(self):
        reader = FrameReader()
        with pytest.raises(BondProtocolError):
            reader.feed(b"XXX" + b"\x00" * 20)

    def test_bad_version_rejected(self):
        blob = bytearray(pack_frame(FRAME_DATA, 0, b"hi"))
        blob[3] = 9     # version byte
        reader = FrameReader()
        with pytest.raises(BondProtocolError):
            reader.feed(bytes(blob))

    def test_oversized_payload_rejected(self):
        with pytest.raises(BondProtocolError):
            pack_frame(FRAME_DATA, 0, b"x" * (MAX_CHUNK * 5))

    def test_seq_out_of_range(self):
        with pytest.raises(BondProtocolError):
            pack_frame(FRAME_DATA, -1, b"")


# --------------------------------------------------------------- addresses
class TestAddresses:
    def test_ipv4(self):
        blob = pack_address("192.168.1.10", 443)
        assert blob[0] == ATYP_IPV4
        host, port, off = unpack_address(blob)
        assert (host, port) == ("192.168.1.10", 443)
        assert off == len(blob)

    def test_ipv6(self):
        import ipaddress
        blob = pack_address("2001:db8::1", 10820)
        assert blob[0] == ATYP_IPV6
        host, port, _ = unpack_address(blob)
        assert ipaddress.ip_address(host) == ipaddress.ip_address("2001:db8::1")
        assert port == 10820

    def test_domain(self):
        blob = pack_address("example.com", 80)
        assert blob[0] == ATYP_DOMAIN
        host, port, _ = unpack_address(blob)
        assert (host, port) == ("example.com", 80)

    def test_embedded_offset(self):
        prefix = b"\xaa\xbb"
        blob = prefix + pack_address("10.0.0.1", 9999)
        host, port, off = unpack_address(blob, len(prefix))
        assert (host, port) == ("10.0.0.1", 9999)

    def test_invalid(self):
        with pytest.raises(BondProtocolError):
            pack_address("", 80)
        with pytest.raises(BondProtocolError):
            pack_address("example.com", 0)
        with pytest.raises(BondProtocolError):
            pack_address("example.com", 70000)
        with pytest.raises(BondProtocolError):
            unpack_address(bytes([0x07]))    # unknown atyp


# --------------------------------------------------------------- handshake
class TestHandshake:
    def test_roundtrip(self):
        sid = new_session_id()
        payload = pack_handshake("secret-token", sid, 1, 3,
                                 "vpn.example.org", 443)
        assert len(sid) == 16
        hs = unpack_handshake(payload)
        assert hs["member_index"] == 1 and hs["member_count"] == 3
        assert (hs["host"], hs["port"]) == ("vpn.example.org", 443)
        assert hs["session_id"] == sid
        assert hs["auth"] == auth_digest("secret-token", sid)

    def test_no_token_gives_null_auth(self):
        sid = new_session_id()
        hs = unpack_handshake(pack_handshake("", sid, 0, 1, "h.io", 1))
        assert hs["auth"] == NULL_AUTH
        assert handshake_matches_token(hs["auth"], "", sid)

    def test_token_match_and_mismatch(self):
        sid = new_session_id()
        good = auth_digest("tok", sid)
        assert handshake_matches_token(good, "tok", sid)
        assert not handshake_matches_token(good, "other", sid)
        assert not handshake_matches_token(b"\x00" * 32, "tok", sid)

    def test_bad_member_layout(self):
        sid = new_session_id()
        with pytest.raises(BondProtocolError):
            pack_handshake("", sid, 3, 2, "h.io", 80)   # index >= count
        with pytest.raises(BondProtocolError):
            pack_handshake("", sid, 0, 0, "h.io", 80)   # count == 0

    def test_truncated_handshake(self):
        with pytest.raises(BondProtocolError):
            unpack_handshake(b"\x00" * 30)


# --------------------------------------------------------------- reassembly
class TestReassembler:
    def test_in_order(self):
        r = Reassembler()
        assert r.feed(0, b"a") == [b"a"]
        assert r.feed(1, b"b") == [b"b"]
        assert r.next_seq == 2

    def test_out_of_order_buffered_then_flushed(self):
        r = Reassembler()
        assert r.feed(1, b"b") == []       # waiting for 0
        assert r.feed(2, b"c") == []
        assert r.pending == 2
        assert r.feed(0, b"a") == [b"a", b"b", b"c"]
        assert r.pending == 0

    def test_duplicate_ignored(self):
        r = Reassembler()
        r.feed(0, b"a")
        assert r.feed(0, b"a") == []       # stale duplicate
        assert r.next_seq == 1

    def test_window_overflow(self):
        r = Reassembler(max_buffer=10)
        with pytest.raises(BondProtocolError):
            r.feed(5, b"x" * 20)           # gap too big to buffer

    def test_interleaved_chunks_from_two_members(self):
        """The core case: chunks 0,2,4 from Wi-Fi and 1,3,5 from LTE."""
        r = Reassembler()
        got: list = []
        for seq in (0, 2, 4, 1, 3, 5):
            got += r.feed(seq, bytes([seq]))
        assert got == [b"\x00", b"\x01", b"\x02", b"\x03", b"\x04", b"\x05"]


# ---------------------------------------------------------------- scheduler
class TestScheduler:
    def test_equal_weights_round_robin(self):
        s = WeightedScheduler([1, 1])
        assert s.plan(6) == [0, 1, 0, 1, 0, 1]

    def test_weighted_two_to_one(self):
        s = WeightedScheduler([2, 1])
        plan = s.plan(6)
        assert plan.count(0) == 4 and plan.count(1) == 2
        # smooth: member 0's two shares spread out, not clustered
        assert plan[:2].count(0) == 1

    def test_dead_member_skipped_and_share_redistributed(self):
        s = WeightedScheduler([1, 1, 1])
        s.mark_dead(1)
        assert s.live_indices() == [0, 2]
        assert all(i in (0, 2) for i in s.plan(10))
        assert not s.all_dead()

    def test_revive(self):
        s = WeightedScheduler([1, 1])
        s.mark_dead(0)
        s.revive(0)
        assert s.live_indices() == [0, 1]

    def test_all_dead_raises(self):
        s = WeightedScheduler([1])
        s.mark_dead(0)
        assert s.all_dead()
        with pytest.raises(BondProtocolError):
            s.next()

    def test_invalid_weights(self):
        with pytest.raises(ValueError):
            WeightedScheduler([])
        # weights clamp to at least 1
        s = WeightedScheduler([0, -5])
        assert s.weights == [1, 1]


# ------------------------------------------------------------------ chunker
class TestChunker:
    def test_split(self):
        parts = chunk_data(b"x" * (MAX_CHUNK * 2 + 5))
        assert len(parts) == 3
        assert len(parts[0]) == len(parts[1]) == MAX_CHUNK
        assert len(parts[2]) == 5

    def test_empty(self):
        assert chunk_data(b"") == []

    def test_small(self):
        assert chunk_data(b"abc") == [b"abc"]

"""The Proto Clean Bond (PCB) wire protocol — v1.

PCB lets one TCP stream ride **several network adapters at once**: the
client splits the stream into sequenced chunks, sends them over one TCP
"member" connection per adapter (each socket bound to that adapter's
local address), and a bond server reassembles the chunks in order and
forwards them to the destination. Responses are split the same way in
reverse, so a single download can use the combined bandwidth of Wi-Fi +
Ethernet + tethering — the Speedify / MPTCP idea in userspace (see
https://github.com/net-merge/net-merge for the related per-connection
distribution approach; PCB adds true *stream* bonding).

Frame layout (12-byte header, all integers big-endian)::

    +---------+-----+------+------+------------+-----------+---------+
    | "PCB"   | ver | type | flags| seq: u32   | len: u16  | payload |
    +---------+-----+------+------+------------+-----------+---------+

* ``ver``    — protocol version (1).
* ``type``   — HANDSHAKE / DATA / FIN / PING / PONG / MEMBER_DOWN.
* ``flags``  — reserved (0).
* ``seq``    — chunk sequence number within the session *and direction*
  (DATA frames only; 0 for the others). Both directions number from 0,
  so client->server chunk 3 and server->client chunk 3 are different
  frames — each side reassembles what it receives.
* ``len``    — payload length (0..65535). DATA payloads are capped at
  MAX_CHUNK (16 KiB) by the chunker.

HANDSHAKE payload (sent first on every member connection)::

    +----------------+-----------------+--------------+--------------+
    | auth: 32 bytes | session: 16 B   | member u16   | members u16  |
    +----------------+-----------------+--------------+--------------+
    | atyp: u8       | address         | port: u16    |
    +----------------+-----------------+--------------+

* ``auth``       — SHA256(token || session_id); all-zero when no token
  is configured (the server then runs in no-auth mode).
* ``session_id`` — random 16 bytes, identical on every member of the
  session; the server groups members by it.
* ``member`` / ``members`` — this connection's index (0..n-1) and the
  total member count announced by the client.
* ``atyp``       — 0x01 IPv4 (4 bytes), 0x03 domain (1-byte length +
  bytes), 0x04 IPv6 (16 bytes), then the big-endian destination port.

Everything else is symmetric: DATA carries stream bytes, FIN half-closes
the sender's direction, PING/PONG (8-byte nonce) are keepalives, and
MEMBER_DOWN (empty) tells the peer that one of *its* member links died
so it can reschedule — a session survives as long as one member lives,
and sequenced chunks make re-ordering across members a non-event.
"""

from __future__ import annotations

import hashlib
import struct
import secrets
from typing import List, Optional, Tuple

MAGIC = b"PCB"
VERSION = 1

# Frame types.
FRAME_HANDSHAKE = 0x01
FRAME_DATA = 0x02
FRAME_FIN = 0x03
FRAME_PING = 0x04
FRAME_PONG = 0x05
FRAME_MEMBER_DOWN = 0x06

HEADER = struct.Struct(">3sBBBII")   # magic, ver, type, flags, seq, len
HEADER_SIZE = HEADER.size            # 14 bytes
MAX_PAYLOAD = 0xFFFF                 # u16 length field
MAX_CHUNK = 16 * 1024                # DATA chunk size produced by chunker

# Address types (SOCKS5-style).
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# An auth digest of all zeros means "no token configured".
NULL_AUTH = b"\x00" * 32


class BondProtocolError(ValueError):
    """Malformed frame / handshake."""


# --------------------------------------------------------------- framing
def pack_frame(ftype: int, seq: int, payload: bytes = b"",
               flags: int = 0, version: int = VERSION) -> bytes:
    """Serialize one PCB frame."""
    if len(payload) > MAX_PAYLOAD:
        raise BondProtocolError(
            f"payload too large for one frame ({len(payload)} > {MAX_PAYLOAD})")
    if not 0 <= seq <= 0xFFFFFFFF:
        raise BondProtocolError(f"sequence number out of range: {seq}")
    return HEADER.pack(MAGIC, version, ftype, flags, seq, len(payload)) \
        + payload


class FrameReader:
    """Incremental frame parser: feed() raw socket bytes, get frames.

    Buffers partial frames internally; raises BondProtocolError on a
    bad magic/version (the connection is beyond salvage at that point).
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> List[Tuple[int, int, bytes]]:
        """Consume *data*; return complete (type, seq, payload) tuples."""
        self._buf += data
        out: List[Tuple[int, int, bytes]] = []
        while True:
            if len(self._buf) < HEADER_SIZE:
                return out
            magic, ver, ftype, flags, seq, ln = \
                HEADER.unpack_from(bytes(self._buf[:HEADER_SIZE]))
            if magic != MAGIC:
                raise BondProtocolError("bad frame magic (not a PCB peer?)")
            if ver != VERSION:
                raise BondProtocolError(f"unsupported PCB version {ver}")
            if len(self._buf) < HEADER_SIZE + ln:
                return out
            payload = bytes(self._buf[HEADER_SIZE:HEADER_SIZE + ln])
            del self._buf[:HEADER_SIZE + ln]
            out.append((ftype, seq, payload))
            if ftype not in (FRAME_HANDSHAKE, FRAME_DATA, FRAME_FIN,
                             FRAME_PING, FRAME_PONG, FRAME_MEMBER_DOWN):
                raise BondProtocolError(f"unknown frame type {ftype}")


# ------------------------------------------------------------ addresses
def pack_address(host: str, port: int) -> bytes:
    """SOCKS5-style address blob (atyp + addr + port)."""
    host = str(host or "")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise BondProtocolError(f"invalid port {port!r}")
    if not 1 <= port <= 65535:
        raise BondProtocolError(f"port out of range: {port}")
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and ip.version == 4:
        return bytes([ATYP_IPV4]) + ip.packed + struct.pack(">H", port)
    if ip is not None and ip.version == 6:
        return bytes([ATYP_IPV6]) + ip.packed + struct.pack(">H", port)
    raw = host.encode("idna") if host else b""
    if not raw or len(raw) > 255:
        raise BondProtocolError(f"invalid destination host {host!r}")
    return bytes([ATYP_DOMAIN, len(raw)]) + raw + struct.pack(">H", port)


def unpack_address(buf: bytes, offset: int = 0) -> Tuple[str, int, int]:
    """Parse an address blob; return (host, port, next_offset)."""
    if offset >= len(buf):
        raise BondProtocolError("address blob truncated (atyp)")
    atyp = buf[offset]
    offset += 1
    if atyp == ATYP_IPV4:
        if offset + 4 + 2 > len(buf):
            raise BondProtocolError("IPv4 address truncated")
        host = ".".join(str(b) for b in buf[offset:offset + 4])
        offset += 4
    elif atyp == ATYP_IPV6:
        if offset + 16 + 2 > len(buf):
            raise BondProtocolError("IPv6 address truncated")
        host = ":".join(
            buf[offset + i:offset + i + 2].hex() for i in range(0, 16, 2))
        offset += 16
    elif atyp == ATYP_DOMAIN:
        if offset >= len(buf):
            raise BondProtocolError("domain length byte truncated")
        ln = buf[offset]
        offset += 1
        if offset + ln + 2 > len(buf):
            raise BondProtocolError("domain address truncated")
        host = buf[offset:offset + ln].decode("utf-8", errors="replace")
        # try the strict idna codec first so punycode survives; raw utf-8
        # is the safe fallback for odd-but-harmless bytes
        try:
            host = buf[offset:offset + ln].decode("idna")
        except UnicodeError:
            pass
        offset += ln
    else:
        raise BondProtocolError(f"unknown address type {atyp}")
    if offset + 2 > len(buf):
        raise BondProtocolError("port truncated")
    port = struct.unpack_from(">H", buf, offset)[0]
    return host, port, offset + 2


# ------------------------------------------------------------ handshake
def auth_digest(token: str, session_id: bytes) -> bytes:
    """SHA256(token || session_id) — 32 bytes; zeros for an empty token."""
    token = str(token or "")
    if not token:
        return NULL_AUTH
    return hashlib.sha256(token.encode("utf-8") + session_id).digest()


def pack_handshake(token: str, session_id: bytes, member_index: int,
                   member_count: int, dest_host: str, dest_port: int) -> bytes:
    """HANDSHAKE payload (auth + session + member layout + destination)."""
    if len(session_id) != 16:
        raise BondProtocolError("session_id must be 16 bytes")
    if not 0 <= member_index < member_count <= 0xFFFF:
        raise BondProtocolError(
            f"member index/count invalid: {member_index}/{member_count}")
    return (auth_digest(token, session_id)
            + session_id
            + struct.pack(">HH", member_index, member_count)
            + pack_address(dest_host, dest_port))


def unpack_handshake(payload: bytes) -> dict:
    """Parse a HANDSHAKE payload into a dict."""
    if len(payload) < 32 + 16 + 4:
        raise BondProtocolError("handshake payload truncated")
    auth = payload[:32]
    session_id = payload[32:48]
    member_index, member_count = struct.unpack_from(">HH", payload, 48)
    host, port, _ = unpack_address(payload, 52)
    return {
        "auth": auth,
        "session_id": session_id,
        "member_index": member_index,
        "member_count": member_count,
        "host": host,
        "port": port,
    }


def handshake_matches_token(payload_auth: bytes, token: str,
                            session_id: bytes) -> bool:
    """Constant-time-ish comparison of a handshake auth digest."""
    if not token:
        return True     # server runs without a token: accept everyone
    import hmac
    return hmac.compare_digest(payload_auth,
                               auth_digest(token, session_id))


# ------------------------------------------------------------ reassembly
class Reassembler:
    """In-order chunk reassembly for one direction of one session.

    Feed chunks with :meth:`feed`; it returns the contiguous run of
    payloads that became deliverable, in order. Reordered arrivals (the
    normal case when chunks ride different adapters) are buffered.
    """

    __slots__ = ("_next", "_pending", "_buffered", "max_buffer")

    def __init__(self, max_buffer: int = 8 * 1024 * 1024) -> None:
        self._next = 0
        self._pending = {}          # seq -> payload
        self._buffered = 0
        self.max_buffer = max_buffer

    def feed(self, seq: int, payload: bytes) -> List[bytes]:
        """Buffer one chunk; return whatever became deliverable."""
        if seq < self._next:
            # duplicate / stale retransmit — already delivered
            return []
        if seq > self._next and self._buffered + len(payload) > self.max_buffer:
            raise BondProtocolError(
                f"reassembly window exceeded at seq {seq} "
                f"(peer stalled or link loss)")
        if seq not in self._pending:
            self._pending[seq] = payload
            self._buffered += len(payload)
        out: List[bytes] = []
        while self._next in self._pending:
            chunk = self._pending.pop(self._next)
            self._buffered -= len(chunk)
            out.append(chunk)
            self._next += 1
        return out

    @property
    def next_seq(self) -> int:
        return self._next

    @property
    def pending(self) -> int:
        """Number of not-yet-deliverable chunks buffered."""
        return len(self._pending)

    @property
    def awaiting(self) -> int:
        """The sequence number we are still waiting for."""
        return self._next


# -------------------------------------------------------------- scheduler
class WeightedScheduler:
    """Smooth weighted round-robin over live members (nginx-style).

    ``weights[i]`` is member *i*'s relative weight (>= 1). Members marked
    dead are skipped entirely — their share is taken over by the rest,
    which is what keeps a session alive when an adapter drops (the
    net-merge behaviour: "links without internet receive no traffic
    until they are restored"). :meth:`revive` brings a member back.
    """

    __slots__ = ("weights", "dead", "_current")

    def __init__(self, weights: List[int]) -> None:
        if not weights:
            raise ValueError("scheduler needs at least one member")
        self.weights = [max(1, int(w)) for w in weights]
        self.dead = [False] * len(self.weights)
        self._current = [0] * len(self.weights)

    def mark_dead(self, index: int) -> None:
        if 0 <= index < len(self.dead):
            if not self.dead[index]:
                self.dead[index] = True
                self._current[index] = 0

    def revive(self, index: int) -> None:
        if 0 <= index < len(self.dead):
            self.dead[index] = False

    def live_indices(self) -> List[int]:
        return [i for i, d in enumerate(self.dead) if not d]

    def all_dead(self) -> bool:
        return all(self.dead)

    def next(self) -> int:
        """Pick the next live member for one chunk (weighted RR)."""
        live = self.live_indices()
        if not live:
            raise BondProtocolError("all member links are down")
        total = sum(self.weights[i] for i in live)
        best = live[0]
        for i in live:
            self._current[i] += self.weights[i]
            if self._current[i] > self._current[best]:
                best = i
        self._current[best] -= total
        return best

    def plan(self, chunks: int) -> List[int]:
        """Member index for each of *chunks* consecutive chunks."""
        return [self.next() for _ in range(chunks)]


def chunk_data(data: bytes, max_chunk: int = MAX_CHUNK) -> List[bytes]:
    """Split a write into wire-sized chunks."""
    if max_chunk < 1:
        max_chunk = MAX_CHUNK
    return [data[i:i + max_chunk]
            for i in range(0, len(data), max_chunk)] or []


def new_session_id() -> bytes:
    """A fresh random 16-byte session id."""
    return secrets.token_bytes(16)

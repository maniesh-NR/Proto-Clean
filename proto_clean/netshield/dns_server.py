"""Embedded DNS server with blocklist filtering (the local NetShield).

Listens on 127.0.0.1:5353 and [::1]:5353 (the privileged helper REDIRECTs
all port-53 traffic here while the tunnel is up). Blocked names get
NXDOMAIN or 0.0.0.0; everything else is forwarded upstream:

  * by default via DNS-over-HTTPS to Proton's DoH resolver (encrypted,
    goes through the tunnel, and cannot loop back through the redirect
    rule because DoH uses port 443), or
  * plain UDP to a chosen resolver (default 10.2.0.1, Proton's in-tunnel
    resolver) — safe because the helper's redirect rule excludes our uid.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple

from dnslib import DNSRecord

from ..log import get
from .blocklists import DomainFilter

log = get("dns")

LISTEN_PORT = 5353
BLOCK_TTL = 60
CACHE_TTL_CAP = 300
BLOCKED_IP = "0.0.0.0"


class DnsUpstream:
    """DoH (POST application/dns-message) with plain-UDP bootstrap/fallback.

    ``udp_resolvers`` is the ordered list of plain resolvers tried after
    (or instead of) DoH: Proton's in-tunnel resolver by default, or the
    user's custom DNS servers (Advanced settings) when configured.
    """

    def __init__(self, doh_url: str = "https://doh.protonvpn.ch/dns-query",
                 udp_resolver: str = "10.2.0.1", use_doh: bool = True,
                 udp_resolvers: Optional[list] = None) -> None:
        self.doh_url = doh_url
        self.udp_resolvers = [r for r in (udp_resolvers or [udp_resolver])
                              if r] or [udp_resolver]
        self.use_doh = use_doh
        self._doh_addr: Optional[Tuple[str, int]] = None
        self._doh_lock = threading.Lock()
        self._doh_ip = ""

    # ----------------------------------------------------------- resolution
    def resolve(self, wire: bytes, timeout: float = 5.0) -> Optional[bytes]:
        if self.use_doh:
            try:
                return self._doh_query(wire, timeout)
            except Exception as e:  # noqa: BLE001
                log.debug("DoH failed (%s), falling back to UDP", e)
        return self._udp_query(wire, timeout)

    # ------------------------------------------------------------------ DoH
    def _doh_query(self, wire: bytes, timeout: float) -> bytes:
        ip = self._doh_ip or self._bootstrap_doh_ip()
        parsed = urllib.parse.urlparse(self.doh_url)
        ctx = ssl.create_default_context()
        conn = _IPHTTPSConnection(ip, parsed.hostname or ip,
                                  parsed.port or 443,
                                  timeout=timeout, context=ctx)
        try:
            conn.request(
                "POST", parsed.path or "/dns-query", body=wire,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "Host": parsed.hostname,
                },
            )
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"DoH HTTP {resp.status}")
            return data
        finally:
            conn.close()

    def _bootstrap_doh_ip(self) -> str:
        """Resolve the DoH hostname via plain UDP (through the tunnel)."""
        with self._doh_lock:
            if self._doh_ip:
                return self._doh_ip
            parsed = urllib.parse.urlparse(self.doh_url)
            host = parsed.hostname or ""
            probe = DNSRecord.question(host, "A").pack()
            answer = self._udp_query(probe, timeout=5.0)
            if answer:
                rec = DNSRecord.parse(answer)
                for rr in rec.rr:
                    if str(rr.rdata) and rr.rtype == 1:
                        self._doh_ip = str(rr.rdata)
                        return self._doh_ip
            raise RuntimeError(f"could not bootstrap DoH host {host}")

    # ----------------------------------------------------------------- UDP
    def _udp_query(self, wire: bytes, timeout: float) -> Optional[bytes]:
        """Ask every configured resolver in order (custom DNS support)."""
        for resolver in self.udp_resolvers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(wire, (resolver, 53))
                    data, _ = s.recvfrom(4096)
                    return data
            except OSError as e:
                log.debug("UDP upstream %s failed: %s", resolver, e)
        return None


class _IPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a literal IP while verifying the cert against the real
    hostname (connecting with HTTPSConnection(ip, ...) would check the
    certificate against the IP and fail hostname verification)."""

    def __init__(self, ip: str, hostname: str, port: int,
                 **kw) -> None:
        super().__init__(ip, port, **kw)
        self._hostname = hostname

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self._hostname)


def _make_reply(request: DNSRecord, rcode: int = 0) -> DNSRecord:
    """dnslib's reply() has no rcode kwarg in 0.9.x — build it manually."""
    from dnslib import DNSHeader

    return DNSRecord(
        DNSHeader(id=request.header.id, bitmap=request.header.bitmap,
                  qr=1, ra=1, aa=0, rcode=rcode),
        q=request.q,
    )


class DnsBlocker:
    """Threaded DNS server: UDP + TCP on loopback, filtering via DomainFilter."""

    def __init__(self, block_filter: Optional[DomainFilter] = None,
                 upstream: Optional[DnsUpstream] = None,
                 port: int = LISTEN_PORT,
                 nxdomain_for_blocked: bool = True) -> None:
        self.filter = block_filter or DomainFilter([])
        self.upstream = upstream or DnsUpstream()
        self.port = port
        self.nxdomain_for_blocked = nxdomain_for_blocked
        self._cache: dict = {}
        self._cache_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="proto_clean-dns")
        self._stop = threading.Event()
        self._threads: list = []
        self._socks: list = []
        self.queries = 0
        self.blocked_hits = 0

    # ----------------------------------------------------------- lifecycle
    def start(self) -> None:
        self._stop.clear()
        for family, addr in ((socket.AF_INET, ("127.0.0.1", self.port)),
                             (socket.AF_INET6, ("::1", self.port))):
            try:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.bind(addr)
                sock.settimeout(1.0)
                self._socks.append(sock)
                t = threading.Thread(target=self._serve_udp, args=(sock,),
                                     daemon=True, name="proto_clean-dns-udp")
                t.start()
                self._threads.append(t)
                t_tcp = threading.Thread(target=self._serve_tcp, args=(sock.family,),
                                         daemon=True, name="proto_clean-dns-tcp")
                t_tcp.start()
                self._threads.append(t_tcp)
            except OSError as e:
                log.warning("could not bind %s: %s (continuing without)", addr, e)
        log.info("DNS blocker listening on 127.0.0.1:%d (::1:%d), %d blocked domains",
                 self.port, self.port, len(self.filter))

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._socks.clear()
        self._threads.clear()

    @property
    def running(self) -> bool:
        return bool(self._threads) and not self._stop.is_set()

    # ------------------------------------------------------------- hot reload
    def reload_filter(self, block_filter: DomainFilter) -> None:
        """Swap the blocklist filter while the server keeps running.

        The filter object reference is replaced atomically; in-flight queries
        finish against the old filter, new queries see the new one. The answer
        cache is cleared so stale verdicts do not linger.
        """
        self.filter = block_filter
        with self._cache_lock:
            self._cache.clear()
        log.info("DNS filter reloaded: %d blocked domains", len(block_filter))

    # -------------------------------------------------------------- servers
    def _serve_udp(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                wire, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_udp, sock, wire, addr)

    def _serve_tcp(self, family: int) -> None:
        srv = socket.socket(family, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.port) if family == socket.AF_INET
                     else ("::1", self.port))
            srv.listen(8)
            srv.settimeout(1.0)
            self._socks.append(srv)
        except OSError as e:
            log.debug("TCP DNS listener unavailable: %s", e)
            return
        while not self._stop.is_set():
            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_tcp, conn)

    def _handle_udp(self, sock: socket.socket, wire: bytes, addr) -> None:
        reply = self._answer(wire)
        if reply:
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            header = conn.recv(2)
            if len(header) < 2:
                return
            (length,) = struct.unpack(">H", header)
            wire = b""
            while len(wire) < length:
                chunk = conn.recv(length - len(wire))
                if not chunk:
                    return
                wire += chunk
            reply = self._answer(wire)
            if reply:
                conn.sendall(struct.pack(">H", len(reply)) + reply)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # --------------------------------------------------------------- answer
    def _answer(self, wire: bytes) -> Optional[bytes]:
        try:
            request = DNSRecord.parse(wire)
        except Exception:
            return None
        self.queries += 1
        qname = str(request.q.qname)

        # ---- blocked?
        if self.filter.blocked(qname):
            self.blocked_hits += 1
            return self._blocked_reply(request, wire)

        # ---- cache
        key = (qname.lower().rstrip("."), request.q.qtype)
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and hit[1] > time.time():
                return _patch_id(hit[0], wire)

        # ---- upstream
        answer = self.upstream.resolve(wire)
        if answer is None:
            # SERVFAIL keeps callers retrying instead of falling back to plaintext
            return _patch_id(_make_reply(request, rcode=2).pack(), wire)
        with self._cache_lock:
            self._cache[key] = (answer, time.time() + CACHE_TTL_CAP)
            if len(self._cache) > 5000:
                now = time.time()
                self._cache = {k: v for k, v in self._cache.items() if v[1] > now}
        return _patch_id(answer, wire)

    def _blocked_reply(self, request: DNSRecord, wire: bytes) -> bytes:
        if not self.nxdomain_for_blocked and request.q.qtype == 1:  # A → 0.0.0.0
            reply = request.reply()
            reply.add_answer(RR_A_BLOCKED(str(request.q.qname).rstrip(".")))
            return _patch_id(reply.pack(), wire)
        return _patch_id(_make_reply(request, rcode=3).pack(), wire)


def RR_A_BLOCKED(name: str):  # noqa: N802 - mirrors dnslib naming
    from dnslib import A, RR

    return RR(name, rtype=1, ttl=BLOCK_TTL, rdata=A(BLOCKED_IP))


def _patch_id(response: bytes, request_wire: bytes) -> bytes:
    """Copy the request's transaction ID into the response."""
    if len(response) < 2 or len(request_wire) < 2:
        return response
    return request_wire[:2] + response[2:]

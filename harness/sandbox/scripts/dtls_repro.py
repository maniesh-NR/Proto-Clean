"""Repro with datagram tracing: Cover-DTLS PSK handshake."""
import os, sys, time, socket, threading
sys.path.insert(0, "/home/z/my-project/cleanroom")
from OpenSSL import crypto
from proto_clean.vpn.protocols import coverdtls as C

def make_cert_key():
    key = crypto.PKey(); key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509(); cert.get_subject().CN = "t"; cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0); cert.gmtime_adj_notAfter(3600)
    cert.set_issuer(cert.get_subject()); cert.set_pubkey(key); cert.sign(key, "sha256")
    return cert, key

PSK = "hunter2-covered"

# trace client sends
orig_client_send = C._ClientLink._send_raw
def trace_client_send(self, datagram):
    print("C-> %3d %s" % (len(datagram), datagram[:12].hex()))
    return orig_client_send(self, datagram)
C._ClientLink._send_raw = trace_client_send

# trace server recv
orig_route = C.CoverDtlsServer._route
def trace_route(self, data, addr):
    print("S<  %3d %s salt_expected=%s" % (len(data), data[:12].hex(), bool(self.psk)))
    return orig_route(self, data, addr)
C.CoverDtlsServer._route = trace_route

# trace server sends
orig_peer_send = C._ServerPeer._send_raw
def trace_peer_send(self, datagram):
    print("S-> %3d %s" % (len(datagram), datagram[:12].hex()))
    return orig_peer_send(self, datagram)
C._ServerPeer._send_raw = trace_peer_send

# trace client recv
orig_reader = C._ClientLink._reader_loop
def trace_reader(self):
    orig_sock_recv = self._sock.recv
    def recv(n):
        d = orig_sock_recv(n)
        print("C<  %3d %s" % (len(d), d[:12].hex()))
        return d
    self._sock.recv = recv
    return orig_reader(self)
C._ClientLink._reader_loop = trace_reader

cert, key = make_cert_key()
srv = C.CoverDtlsServer("127.0.0.1", 0, cert, key, psk=PSK)
srv.start()
print("server on", srv.address)

cli = C._ClientLink(("127.0.0.1", srv.address[1]), psk=b"hunter2-covered",
                    sni="", insecure=True)
try:
    cli.handshake(timeout=6)
    print("HANDSHAKE OK")
except Exception as e:
    print("HANDSHAKE FAIL:", type(e).__name__, e)
finally:
    cli.close(); srv.stop()

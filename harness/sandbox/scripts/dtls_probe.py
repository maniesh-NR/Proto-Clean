"""Feasibility probe: pyOpenSSL DTLS 1.2 over a UDP loopback (MemoryBIO)."""
import socket
import threading

from OpenSSL import SSL, crypto

DONE = object()


def make_cert_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "cover-dtls-test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert, key


def pump(conn, sock, peer):
    """Push any pending ciphertext from MemoryBIO to the UDP peer."""
    while True:
        try:
            out = conn.bio_read(65535)
        except SSL.WantReadError:
            return
        if peer:
            sock.sendto(out, peer)


def main():
    cert, key = make_cert_key()
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_port = srv_sock.getsockname()[1]

    sctx = SSL.Context(SSL.DTLS_METHOD)
    sctx.use_certificate(cert)
    sctx.use_privatekey(key)
    server = SSL.Connection(sctx)
    server.set_ciphertext_mtu(1200)
    server.set_accept_state()

    state = {"peer": None, "echo": None}

    def run_server():
        # handshake
        for _ in range(60):
            srv_sock.settimeout(0.25)
            try:
                data, addr = srv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            state["peer"] = state["peer"] or addr
            server.bio_write(data)
            try:
                server.do_handshake()
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            pump(server, srv_sock, state["peer"])
            try:
                if server.get_state_string() == b"SSLOK":
                    break
            except Exception:
                pass
        # echo loop
        for _ in range(40):
            srv_sock.settimeout(0.25)
            try:
                data, addr = srv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            server.bio_write(data)
            pump(server, srv_sock, state["peer"])
            try:
                msg = server.recv(65535)
                if msg:
                    server.send(b"echo:" + msg)
                    pump(server, srv_sock, state["peer"])
                    state["echo"] = msg
                    return
            except SSL.WantReadError:
                pass

    cctx = SSL.Context(SSL.DTLS_METHOD)
    cctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
    client = SSL.Connection(cctx)
    client.set_ciphertext_mtu(1200)
    client.set_connect_state()
    cli_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli_sock.bind(("127.0.0.1", 0))
    cli_sock.connect(("127.0.0.1", srv_port))
    cpeer = cli_sock.getsockname()

    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    ok = False
    for _ in range(60):
        try:
            client.do_handshake()
        except (SSL.WantReadError, SSL.WantWriteError):
            pass
        try:
            out = client.bio_read(65535)
            if out:
                cli_sock.sendto(out, ("127.0.0.1", srv_port))
        except SSL.WantReadError:
            pass
        cli_sock.settimeout(0.25)
        try:
            data, _ = cli_sock.recvfrom(65535)
            if data:
                client.bio_write(data)
        except socket.timeout:
            pass
        try:
            if client.get_state_string() == b"SSLOK":
                ok = True
                break
        except Exception:
            pass
    print("handshake ok:", ok)

    client.send(b"ping-cover-dtls")
    try:
        out = client.bio_read(65535)
        if out:
            cli_sock.sendto(out, ("127.0.0.1", srv_port))
    except SSL.WantReadError:
        pass

    t.join(timeout=15)
    echo = None
    for _ in range(40):
        cli_sock.settimeout(0.25)
        try:
            data, _ = cli_sock.recvfrom(65535)
            if data:
                client.bio_write(data)
        except socket.timeout:
            continue
        pump(client, cli_sock, ("127.0.0.1", srv_port))
        try:
            msg = client.recv(65535)
            if msg:
                echo = msg
                break
        except SSL.WantReadError:
            pass
    print("echo:", echo)


if __name__ == "__main__":
    main()

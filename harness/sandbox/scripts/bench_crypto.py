"""Benchmark: SS AEAD stream decrypt (old O(n^2) bytes-concat pattern vs
new bytearray) and cover whitening keystream cache."""
import sys, time
sys.path.insert(0, "/home/z/my-project/cleanroom")
from proto_clean.vpn.protocols import sscrypto
from proto_clean.vpn.protocols.coverdtls import whitening_keystream, cover

# --- SessionCipher throughput: 2000 chunks of 4KB fed in 2KB slices (the
# pattern a real stream produces: kernel-sized reads, partial chunks)
ctx = sscrypto.CipherCtx.from_password("aes-256-gcm", "bench-pass")
enc = ctx.new_session(b"A" * 32)
dec = ctx.new_session(b"A" * 32)
payload = bytes(range(256)) * 16            # 4096 B
wire = enc.encrypt(payload * 2000)          # ~8 MB of chunks

t0 = time.perf_counter()
out = b""
for i in range(0, len(wire), 2048):
    out += dec.decrypt(wire[i:i + 2048])
dt = time.perf_counter() - t0
assert len(out) == len(payload) * 2000, (len(out), len(payload) * 2000)
print(f"SS AES-256-GCM stream decrypt: {len(wire)/dt/1e6:7.1f} MB/s "
      f"(buffer stays small: {dec.pending} B pending)")

# chacha path too
ctx2 = sscrypto.CipherCtx.from_password("chacha20-ietf-poly1305", "bench-pass")
enc2 = ctx2.new_session(b"B" * 32)
dec2 = ctx2.new_session(b"B" * 32)
wire2 = enc2.encrypt(payload * 1000)
t0 = time.perf_counter()
out2 = b""
for i in range(0, len(wire2), 2048):
    out2 += dec2.decrypt(wire2[i:i + 2048])
dt = time.perf_counter() - t0
print(f"SS ChaCha20-Poly1305 decrypt : {len(wire2)/dt/1e6:7.1f} MB/s (key schedule cached)")

# --- cover keystream: 5000 datagrams of 1350B with the same salt
salt = b"12345678"
t0 = time.perf_counter()
for _ in range(5000):
    cover(b"psk-bench", salt, b"x" * 1350)
dt = time.perf_counter() - t0
print(f"cover whitening per-datagram : {5000*1350/dt/1e6:7.1f} MB/s (cached keystream)")

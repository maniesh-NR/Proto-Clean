"""Benchmark: old per-byte XOR vs new big-int XOR + keystream caching."""
import sys, time, os
sys.path.insert(0, "/home/z/my-project/cleanroom")

from proto_clean.vpn.protocols.hysteria2 import Salamander

def old_xor(data: bytes, ks: bytes) -> bytes:
    return bytes(a ^ ks[i % 32] for i, a in enumerate(data))

def bench(fn, arg, n=200):
    t0 = time.perf_counter()
    for _ in range(n):
        fn(arg)
    dt = time.perf_counter() - t0
    return (len(arg) * n) / dt / 1e6  # MB/s

s = Salamander("benchmark-key")
payload = os.urandom(1350)
ks = s._stream(b"benchmark-key", b"12345678")

old = bench(lambda d: old_xor(d, ks), payload)
new_wrap = bench(s.wrap, payload)          # full wrap incl. blake2b + urandom
new_raw = bench(lambda d: s._xor(d, ks), payload)

print(f"payload=1350B  old per-byte XOR : {old:8.1f} MB/s")
print(f"payload=1350B  new big-int XOR   : {new_raw:8.1f} MB/s  ({new_raw/old:.0f}x)")
print(f"payload=1350B  full Salamander.wrap: {new_wrap:6.1f} MB/s  ({new_wrap/old:.0f}x vs old raw)")

# correctness cross-check
for n in (0, 1, 7, 31, 32, 33, 64, 1350, 65535):
    d = os.urandom(n)
    k = os.urandom(32)
    assert s._xor(d, k) == old_xor(d, k), n
print("correctness: big-int XOR == per-byte XOR for all lengths ✓")

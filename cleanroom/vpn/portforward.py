"""NAT-PMP client (RFC 6886) for Proton's port forwarding.

Talks to the VPN-side gateway (10.2.0.1) on UDP/5351 once the tunnel is
up, requests a UDP mapping for an internal port and keeps the lease
alive. Proton grants short leases (~60s), so the keeper refreshes at
~75% of the granted lifetime (45s for a 60s lease, matching Proton's
own manual-setup docs).
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Callable, Optional, Tuple

from ..log import get

log = get("natpmp")

GATEWAY = "10.2.0.1"
PORT = 5351
REQ_LIFETIME = 7200          # what we ask for; server may grant less
RESULT_OK = 0

# (version=0, opcode) request codes
OP_MAP_UDP = 1


class NatPmpError(RuntimeError):
    RESULT_TEXT = {
        1: "unsupported protocol version",
        2: "not authorized / refused (port forwarding is a paid-plan feature)",
        3: "network failure",
        4: "out of resources",
        5: "unsupported opcode",
    }

    def __init__(self, result: int) -> None:
        super().__init__(self.RESULT_TEXT.get(result, f"NAT-PMP result code {result}"))
        self.result = result


def build_map_request(internal_port: int, external_port: int = 0,
                      lifetime: int = REQ_LIFETIME) -> bytes:
    """12-byte MAP UDP request: ver, op, reserved, int, ext, lifetime."""
    return struct.pack(
        ">BBHHHI", 0, OP_MAP_UDP, 0,
        internal_port & 0xFFFF, external_port & 0xFFFF, lifetime,
    )


def parse_map_response(data: bytes) -> Tuple[int, int, int, int]:
    """Returns (result, internal_port, external_port, lifetime)."""
    if len(data) < 16:
        raise NatPmpError(-1)
    ver, op, result, _epoch = struct.unpack(">BBHI", data[:8])
    if ver != 0 or op != (0x80 | OP_MAP_UDP):
        raise NatPmpError(-1)
    internal, external, lifetime = struct.unpack(">HHI", data[8:16])
    if result != RESULT_OK:
        raise NatPmpError(result)
    return result, internal, external, lifetime


class NatPmpClient:
    def __init__(self, gateway: str = GATEWAY, timeout: float = 3.0) -> None:
        self.gateway = gateway
        self.timeout = timeout

    def map(self, internal_port: int, external_port: int = 0,
            lifetime: int = REQ_LIFETIME) -> Tuple[int, int, int]:
        """One-shot mapping request → (internal, external, lifetime)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(build_map_request(internal_port, external_port, lifetime),
                     (self.gateway, PORT))
            data, _addr = s.recvfrom(64)
        _r, internal, external, life = parse_map_response(data)
        return internal, external, life


class PortForwarder:
    """Keeps a NAT-PMP mapping alive in a background thread."""

    def __init__(self, internal_port: int = 0, gateway: str = GATEWAY,
                 on_update: Optional[Callable[[Optional[int]], None]] = None,
                 on_error: Optional[Callable[[str], None]] = None) -> None:
        self.client = NatPmpClient(gateway)
        self.internal_port = internal_port
        self.external_port: Optional[int] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.on_update = on_update or (lambda port: None)
        self.on_error = on_error or (lambda msg: log.warning("port-forward: %s", msg))

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="cleanroom-natpmp")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None
        self.external_port = None

    # ------------------------------------------------------------- internal
    def _run(self) -> None:
        # First request also probes availability (free plans get result 2).
        first = True
        while not self._stop.is_set():
            try:
                internal, external, lifetime = self.client.map(
                    self.internal_port or 0)
                if self._stop.is_set():
                    break          # stopped while the request was in flight
                self.internal_port = internal
                self.external_port = external
                self.on_update(external)
                log.info("NAT-PMP mapping: internal %d -> external %d (%ds lease)",
                         internal, external, lifetime)
                wait = max(15.0, lifetime * 0.75)
                first = False
            except NatPmpError as e:
                if first:
                    self.on_error(str(e))
                    return
                log.debug("natpmp refresh failed: %s", e)
                wait = 15.0
            except OSError as e:
                log.debug("natpmp network error: %s", e)
                if first:
                    self.on_error(f"could not reach NAT-PMP gateway: {e}")
                    return
                wait = 15.0
            self._stop.wait(wait)

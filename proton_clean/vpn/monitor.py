"""Polls tunnel stats (handshake age, transfer, uptime) from the helper."""

from __future__ import annotations

import time
from typing import Callable, Optional

from ..log import get
from .helper import Helper, HelperError

log = get("monitor")

POLL_INTERVAL = 5.0


class TunnelStats:
    def __init__(self) -> None:
        self.up: bool = False
        self.handshake_age: float = float("inf")
        self.rx: int = 0
        self.tx: int = 0
        self.connected_since: float = 0.0
        self.endpoint: str = ""
        self.tunnel_ip: str = ""

    def as_dict(self) -> dict:
        return {
            "up": self.up,
            "handshake_age": None if self.handshake_age == float("inf")
            else round(self.handshake_age, 1),
            "rx": self.rx, "tx": self.tx,
            "connected_since": self.connected_since,
            "endpoint": self.endpoint,
            "tunnel_ip": self.tunnel_ip,
        }


class TunnelMonitor:
    def __init__(self, helper: Helper,
                 on_stats: Optional[Callable[[TunnelStats], None]] = None) -> None:
        self.helper = helper
        self.on_stats = on_stats or (lambda s: None)
        self._stop = False
        self._thread: Optional[object] = None
        self.stats = TunnelStats()

    def start(self) -> None:
        import threading

        self._stop = False
        self.stats.connected_since = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="proton_clean-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        self._thread = None

    def _run(self) -> None:
        while not self._stop:
            try:
                st = self.helper.call("status")
            except (HelperError, TimeoutError) as e:
                log.debug("status poll failed: %s", e)
                st = {"wg_up": False}
            s = self.stats
            if st.get("wg_up"):
                s.up = True
                hs = st.get("latest_handshake", 0)
                s.handshake_age = time.time() - hs if hs else float("inf")
                s.rx = st.get("rx", 0)
                s.tx = st.get("tx", 0)
                s.endpoint = st.get("endpoint", "")
                s.tunnel_ip = st.get("tunnel_ip", "")
            else:
                s.up = False
            self.on_stats(s)
            time.sleep(POLL_INTERVAL)

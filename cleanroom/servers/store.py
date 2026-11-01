"""Cache of logical servers + loads (refreshed by scraping the logged-in
Downloads page)."""

from __future__ import annotations

import json
import time
from typing import List, Optional

from ..log import get
from ..paths import SERVER_CACHE_FILE, ensure_dirs
from .models import LogicalServer, parse_logical_servers

log = get("servers")


class ServerStore:
    def __init__(self) -> None:
        self._servers: List[LogicalServer] = []
        self._updated_at: float = 0.0
        self.load_from_disk()

    # ------------------------------------------------------------------ disk
    def load_from_disk(self) -> None:
        if SERVER_CACHE_FILE.exists():
            try:
                data = json.loads(SERVER_CACHE_FILE.read_text(encoding="utf-8"))
                self._servers = parse_logical_servers(data.get("servers", []))
                self._updated_at = float(data.get("updated_at", 0))
            except (json.JSONDecodeError, OSError, ValueError):
                log.warning("server cache unreadable, ignoring")

    def save_to_disk(self) -> None:
        ensure_dirs()
        SERVER_CACHE_FILE.write_text(
            json.dumps(
                {
                    "updated_at": self._updated_at,
                    "servers": [s.to_json() for s in self._servers],
                }
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------- api
    @property
    def servers(self) -> List[LogicalServer]:
        return list(self._servers)

    @property
    def updated_at(self) -> float:
        return self._updated_at

    def free_servers(self) -> List[LogicalServer]:
        return [s for s in self._servers if s.tier == 0]

    def by_id(self, server_id: str) -> Optional[LogicalServer]:
        for s in self._servers:
            if s.id == server_id:
                return s
        return None

    def by_name(self, name: str) -> Optional[LogicalServer]:
        for s in self._servers:
            if s.name == name:
                return s
        return None

    def replace(self, servers: List[LogicalServer]) -> None:
        self._servers = servers
        self._updated_at = time.time()
        self.save_to_disk()
        log.info("server list refreshed: %d logicals (%d free)",
                 len(servers), len(self.free_servers()))

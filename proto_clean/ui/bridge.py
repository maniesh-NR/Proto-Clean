"""Qt bridge: marshals Controller callbacks (worker threads) into Qt
signals (UI thread) and implements the blocking TOTP prompt."""

from __future__ import annotations

import threading

from proto_clean.qtcompat import QObject, Signal

from ..controller import Controller, State


class ControllerBridge(QObject):
    state_changed = Signal(str, str)        # state, detail
    servers_changed = Signal(list)          # list[LogicalServer]
    stats_changed = Signal(dict)            # TunnelStats.as_dict()
    port_changed = Signal(object)           # int | None
    message = Signal(str, str)              # text, level
    totp_requested = Signal()               # UI: show 2FA dialog
    blocklists_changed = Signal(list)       # list[BlocklistEntry]
    login_event = Signal(str, str)          # kind, detail (captcha, …)

    def __init__(self, controller: Controller, parent=None) -> None:
        super().__init__(parent)
        self.controller = controller

        # pending TOTP dialog machinery
        self._totp_event = threading.Event()
        self._totp_code: str | None = None

        controller.on_state = self._on_state
        controller.on_servers = self._on_servers
        controller.on_stats = self._on_stats
        controller.on_port = self._on_port
        controller.on_message = self._on_message
        controller.on_blocklists = self._on_blocklists
        controller.on_login_event = self._on_login_event
        controller.totp_provider = self._totp_provider

    # -------------------------------------------------- controller → signals
    def _on_state(self, state: State, detail: str) -> None:
        self.state_changed.emit(state.value, detail)

    def _on_servers(self, servers) -> None:
        self.servers_changed.emit(list(servers))

    def _on_stats(self, stats: dict) -> None:
        self.stats_changed.emit(stats)

    def _on_port(self, port) -> None:
        self.port_changed.emit(port)

    def _on_message(self, text: str, level: str) -> None:
        self.message.emit(text, level)

    def _on_blocklists(self, entries) -> None:
        self.blocklists_changed.emit(list(entries))

    def _on_login_event(self, kind: str, detail: str) -> None:
        self.login_event.emit(kind, detail)

    # -------------------------------------------------- UI → controller
    def _totp_provider(self):
        """Called on the login worker thread: ask the UI and block for input."""
        self._totp_code = None
        self._totp_event.clear()
        self.totp_requested.emit()
        self._totp_event.wait(timeout=180)
        return self._totp_code

    def provide_totp(self, code: str | None) -> None:
        self._totp_code = code
        self._totp_event.set()

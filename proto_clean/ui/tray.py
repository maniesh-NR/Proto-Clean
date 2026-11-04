"""System tray icon with quick actions."""

from __future__ import annotations

from proto_clean.qtcompat import QAction
from proto_clean.qtcompat import QMenu, QSystemTrayIcon

from ..controller import Controller, State
from . import resources


class Tray(QSystemTrayIcon):
    def __init__(self, window, controller: Controller) -> None:
        super().__init__(resources.app_icon(), window)
        self.window = window
        self.controller = controller
        self.setToolTip("ProtoClean")

        menu = QMenu()
        self.show_action = QAction("Show Proto Clean", self)
        self.show_action.triggered.connect(window.showNormal)
        self.toggle_action = QAction("Connect (fastest)", self)
        self.toggle_action.triggered.connect(self._toggle)
        self.proxy_action = QAction("Proxy (Xray / samizdat)", self)
        self.proxy_action.setCheckable(True)
        self.proxy_action.setToolTip("Toggle the proxy engine (Xray VLESS "
                                     "REALITY / Trojan, or samizdat)")
        self.proxy_action.toggled.connect(self._toggle_proxy)
        self.bond_action = QAction("Link bonding (multi-adapter)", self)
        self.bond_action.setCheckable(True)
        self.bond_action.setToolTip("Combine two or more network adapters "
                                    "into one fat pipe (needs a bond "
                                    "server)")
        self.bond_action.toggled.connect(self._toggle_bond)
        # -- multi-protocol quick access ----------------------------------
        self.protocols_menu = QMenu("Protocols", self)
        self.protocols_open = QAction("Manage protocols…", self)
        self.protocols_open.triggered.connect(self._open_protocols)
        self.protocols_stop = QAction("Stop protocol engine", self)
        self.protocols_stop.triggered.connect(
            self.controller.stop_protocol_async)
        self.quit_action = QAction("Quit", self)
        self.quit_action.triggered.connect(self._quit)
        menu.addAction(self.show_action)
        menu.addAction(self.toggle_action)
        menu.addAction(self.proxy_action)
        menu.addAction(self.bond_action)
        self.protocols_menu.addAction(self.protocols_open)
        self.protocols_menu.addSeparator()
        self.protocols_menu.addAction(self.protocols_stop)
        self._reload_protocol_profiles()
        menu.addMenu(self.protocols_menu)
        menu.addSeparator()
        menu.addAction(self.quit_action)
        self.setContextMenu(menu)
        self.activated.connect(
            lambda reason: window.showNormal()
            if reason == QSystemTrayIcon.DoubleClick else None)

        window.bridge.state_changed.connect(self._on_state)
        self._on_state(controller.state.value, controller.state_detail)
        self.controller.add_proxy_listener(self._on_proxy)
        self._on_proxy(controller.proxy_state, "")
        self.controller.add_bond_listener(self._on_bond)
        self._on_bond(controller.bond_state, "")

    def _on_state(self, state: str, detail: str) -> None:
        if state in (State.CONNECTED.value,):
            self.toggle_action.setText("Disconnect")
            self.setIcon(resources.shield_icon("#22c55e"))
            self.setToolTip(f"Proto Clean — protected ({detail})")
        else:
            self.toggle_action.setText("Connect (fastest)")
            self.setIcon(resources.shield_icon("#2f6d3f"))
            self.setToolTip(f"Proto Clean — {state.replace('_', ' ')}")

    def _reload_protocol_profiles(self) -> None:
        """(Re)build the pinned-profile entries in the Protocols menu."""
        from ..vpn.protocols.profiles import ProfileStore
        menu = self.protocols_menu
        # remove previous profile actions (keep open/stop/separator)
        for action in list(menu.actions()):
            if action not in (self.protocols_open, self.protocols_stop) \
                    and not action.isSeparator():
                menu.removeAction(action)
        try:
            entries = [e for e in ProfileStore().all() if e.pinned][:8]
        except Exception:                       # noqa: BLE001 — tray must live
            entries = []
        for entry in entries:
            action = QAction("%s (%s)" % (entry.name, entry.kind), self)
            action.triggered.connect(
                lambda _checked=False, eid=entry.id:
                    self.controller.start_profile_async(eid))
            menu.addAction(action)

    def _open_protocols(self) -> None:
        from .protocols_dialog import ProtocolsDialog
        dialog = ProtocolsDialog(self.controller, self.window)
        dialog.show()
        self._reload_protocol_profiles()

    def _toggle(self) -> None:
        if self.controller.state in (State.CONNECTED, State.CONNECTING):
            self.controller.disconnect_async()
        else:
            self.controller.connect_async(None)

    def _on_proxy(self, state: str, detail: str) -> None:
        on = state == "on"
        self.proxy_action.blockSignals(True)
        self.proxy_action.setChecked(on)
        self.proxy_action.blockSignals(False)
        self.proxy_action.setText("Proxy: on" if on else "Proxy")

    def _toggle_proxy(self, on: bool) -> None:
        if on:
            self.controller.start_proxy_async()
        else:
            self.controller.stop_proxy_async()

    def _on_bond(self, state: str, detail: str) -> None:
        on = state == "on"
        self.bond_action.blockSignals(True)
        self.bond_action.setChecked(on)
        self.bond_action.blockSignals(False)
        self.bond_action.setText("Bonding: on" if on else "Link bonding")

    def _toggle_bond(self, on: bool) -> None:
        if on:
            self.controller.start_bond_async()
        else:
            self.controller.stop_bond_async()

    def _quit(self) -> None:
        self.controller.shutdown()
        self.window.tray = None          # allow the window to really close
        self.window.close()
        from proto_clean.qtcompat import QApplication

        QApplication.quit()

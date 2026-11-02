"""System tray icon with quick actions."""

from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

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
        self.quit_action = QAction("Quit", self)
        self.quit_action.triggered.connect(self._quit)
        menu.addAction(self.show_action)
        menu.addAction(self.toggle_action)
        menu.addSeparator()
        menu.addAction(self.quit_action)
        self.setContextMenu(menu)
        self.activated.connect(
            lambda reason: window.showNormal()
            if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)

        window.bridge.state_changed.connect(self._on_state)
        self._on_state(controller.state.value, controller.state_detail)

    def _on_state(self, state: str, detail: str) -> None:
        if state in (State.CONNECTED.value,):
            self.toggle_action.setText("Disconnect")
            self.setIcon(resources.shield_icon("#22c55e"))
            self.setToolTip(f"Proto Clean — protected ({detail})")
        else:
            self.toggle_action.setText("Connect (fastest)")
            self.setIcon(resources.shield_icon("#2f6d3f"))
            self.setToolTip(f"Proto Clean — {state.replace('_', ' ')}")

    def _toggle(self) -> None:
        if self.controller.state in (State.CONNECTED, State.CONNECTING):
            self.controller.disconnect_async()
        else:
            self.controller.connect_async(None)

    def _quit(self) -> None:
        self.controller.shutdown()
        self.window.tray = None          # allow the window to really close
        self.window.close()
        from PySide6.QtWidgets import QApplication

        QApplication.quit()

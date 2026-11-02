"""Main Proto Clean window."""

from __future__ import annotations

import time
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMenu, QMainWindow, QPushButton,
    QStatusBar, QSystemTrayIcon, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ..controller import Controller, State
from .. import credentials as creds
from ..servers.models import LogicalServer
from ..servers.selection import rank_servers
from ..settings import load_settings, save_settings, update
from . import resources
from .blocklists_dialog import AddBlocklistDialog, BlocklistsDialog
from .bridge import ControllerBridge
from .login_dialog import LoginDialog
from .settings_dialog import SettingsDialog
from .theme import (
    STATE_COLORS, THEMES, THEME_LABELS, apply_theme, effective_theme,
)


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n} B"


class MainWindow(QMainWindow):
    def __init__(self, controller: Controller) -> None:
        super().__init__()
        self.controller = controller
        self.bridge = ControllerBridge(controller, self)
        self.selected_server: Optional[LogicalServer] = None
        self._connect_started_at = 0.0
        self._stats: dict = {}

        self.setWindowTitle("Proto Clean — ProtonVPN, cleanly")
        self.setWindowIcon(resources.app_icon())
        self.resize(880, 640)

        # Self-apply the persisted theme so the window is styled regardless
        # of how the QApplication was created (tests, tools, embedding).
        if not QApplication.instance().property("proto_clean_theme_applied"):
            apply_theme(QApplication.instance(), load_settings().theme)
            QApplication.instance().setProperty("proto_clean_theme_applied", True)

        self._build_ui()
        self._wire_signals()

        # kick off: auto-login with stored credentials, or ask for them
        QTimer.singleShot(300, self._startup_login)

    def _subtitle_text(self) -> str:
        """Header subtitle: reflects the selected download protocol."""
        proto = load_settings().protocol.normalized().protocol
        return ("clean-room ProtonVPN client · OpenVPN (TCP/UDP, TUN/TAP)"
                if proto == "openvpn"
                else "clean-room ProtonVPN client · WireGuard")

    def _refresh_subtitle(self) -> None:
        self.subtitle.setText(self._subtitle_text())

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 14, 18, 8)
        root.setSpacing(12)

        # ---- header row
        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title = QLabel("ProtoClean")
        title.setObjectName("Title")
        self.subtitle = QLabel(self._subtitle_text())
        self.subtitle.setObjectName("Subtitle")
        title_col.addWidget(title)
        title_col.addWidget(self.subtitle)
        header.addLayout(title_col)
        header.addStretch(1)

        self.status_dot = QLabel()
        self.status_label = QLabel("Starting…")
        self.status_label.setStyleSheet("font-weight:600;")
        status_col = QVBoxLayout()
        status_col.setAlignment(Qt.AlignRight)
        status_row = QHBoxLayout()
        status_row.setAlignment(Qt.AlignRight)
        status_row.addWidget(self.status_dot)
        status_row.addWidget(self.status_label)
        self.plan_label = QLabel("")
        self.plan_label.setObjectName("Stats")
        status_col.addLayout(status_row)
        status_col.addWidget(self.plan_label)
        header.addLayout(status_col)
        root.addLayout(header)

        # ---- login relay banner (CAPTCHA / waiting for the user)
        self.login_banner = QLabel()
        self.login_banner.setObjectName("LoginBanner")
        self.login_banner.setWordWrap(True)
        self.login_banner.hide()
        root.addWidget(self.login_banner)

        # ---- stats line
        self.stats_label = QLabel("not connected")
        self.stats_label.setObjectName("Stats")
        root.addWidget(self.stats_label)

        # ---- control row: fastest toggle + connect button
        controls = QHBoxLayout()
        self.fastest_toggle = QCheckBox("Fastest server")
        self.fastest_toggle.setToolTip(
            "Auto-connect to the fastest available free server "
            "(Proton's own live server score) — free servers only")
        bolt = QLabel()
        bolt.setPixmap(resources.bolt_icon(size=18))
        controls.addWidget(bolt)
        controls.addWidget(self.fastest_toggle)
        self.fastest_toggle.setChecked(load_settings().autoconnect_fastest)
        self.fastest_toggle.stateChanged.connect(self._on_fastest_toggled)
        controls.addStretch(1)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("Connect")
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        self.connect_btn.setMinimumWidth(170)
        controls.addWidget(self.connect_btn)
        root.addLayout(controls)

        # ---- server list
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search country / server / city…")
        self.search.textChanged.connect(self._refresh_table)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.controller.refresh_servers_async)
        search_row = QHBoxLayout()
        search_row.addWidget(self.search, 1)
        search_row.addWidget(self.refresh_btn)
        root.addLayout(search_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Country", "Server", "City", "Load", "Features"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setShowGrid(False)
        self.table.cellClicked.connect(self._on_row_clicked)
        self.table.doubleClicked.connect(lambda _: self._on_connect_clicked())
        root.addWidget(self.table, 1)

        # ---- bottom bar
        bottom = QHBoxLayout()
        self.login_btn = QPushButton("Log in…")
        self.login_btn.setToolTip(
            "Save your Proton credentials for automatic login, "
            "or log in by hand in a browser window")
        self.login_btn.clicked.connect(lambda: self._open_login_dialog())
        self.theme_btn = QPushButton("Theme ▾")
        self.theme_btn.setToolTip(
            "Dark mode, light mode, or follow the system theme "
            "(switches automatically with the desktop)")
        self.theme_menu = QMenu(self)
        self.theme_btn.setMenu(self.theme_menu)
        self.theme_menu.aboutToShow.connect(self._rebuild_theme_menu)
        self.settings_btn = QPushButton("Settings")
        self.settings_btn.clicked.connect(self._open_settings)
        self.blocklists_btn = QPushButton("Blocklists ▾")
        self.blocklists_btn.setToolTip(
            "Manage the locally maintained blocklists used for ad blocking")
        self.blocklists_menu = QMenu(self)
        self.blocklists_btn.setMenu(self.blocklists_menu)
        self.blocklists_menu.aboutToShow.connect(self._rebuild_blocklists_menu)
        self.adblock_label = QLabel()
        self.port_label = QLabel()
        bottom.addWidget(self.settings_btn)
        bottom.addWidget(self.login_btn)
        bottom.addWidget(self.theme_btn)
        bottom.addWidget(self.blocklists_btn)
        bottom.addStretch(1)
        bottom.addWidget(self.adblock_label)
        bottom.addWidget(self.port_label)
        root.addLayout(bottom)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.statusBar().showMessage("Ready")

    # ------------------------------------------------------------- signals
    def _wire_signals(self) -> None:
        self.bridge.state_changed.connect(self._on_state)
        self.bridge.servers_changed.connect(self._on_servers)
        self.bridge.stats_changed.connect(self._on_stats)
        self.bridge.port_changed.connect(self._on_port)
        self.bridge.message.connect(self._on_message)
        self.bridge.totp_requested.connect(self._on_totp_requested)
        self.bridge.blocklists_changed.connect(self._on_blocklists)
        self.bridge.login_event.connect(self._on_login_event)
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start()
        self._refresh_table([])
        self._blocklist_entries = []
        self._blocklists_dialog: BlocklistsDialog | None = None
        self._login_dialog: LoginDialog | None = None

    # ------------------------------------------------------------- handlers
    def _on_state(self, state: str, detail: str) -> None:
        color, label = STATE_COLORS.get(state, ("#9aa3b2", state))
        self.status_dot.setPixmap(resources.status_dot(color, 14))
        self.status_label.setText(f"{label}" + (f" — {detail}" if detail else ""))
        self._update_connect_button()
        self._update_login_button()
        if state == "connected":
            self._connect_started_at = time.time()
        if state in ("logged_in", "logged_out"):
            self._connect_started_at = 0.0
        if state == "logged_in":
            self._hide_login_banner()
        plan = self.controller.session.user_plan_hint
        self.plan_label.setText(
            f"plan: {plan or 'free'}" + (" (detected)" if plan else ""))

    def _on_servers(self, servers) -> None:
        self._servers = servers
        self._refresh_table()
        self.statusBar().showMessage(
            f"{len(servers)} free servers · updated {time.strftime('%H:%M')}")

    def _on_stats(self, stats: dict) -> None:
        self._stats = stats
        self._tick()

    def _on_port(self, port) -> None:
        if port:
            self.port_label.setText(f"forwarded port: {port}")
        else:
            self.port_label.setText("")

    def _on_message(self, text: str, level: str) -> None:
        prefix = {"info": "", "warn": "⚠ ", "error": "✖ "}.get(level, "")
        self.statusBar().showMessage(f"{prefix}{text}", 8000)

    def _on_totp_requested(self) -> None:
        code, ok = QInputDialog.getText(
            self, "Two-factor authentication",
            "Proton is asking for your 2FA code.\n"
            "Tip: store your TOTP secret in Settings for automatic login.",
            QLineEdit.EchoMode.Normal)
        self.bridge.provide_totp(code.strip().replace(" ", "") if ok else None)

    def _on_fastest_toggled(self, checked: bool) -> None:
        update(autoconnect_fastest=bool(checked))
        self.controller.reload_settings()
        if checked:
            self.selected_server = None
            self.table.clearSelection()

    # ------------------------------------------------------------- login
    def _startup_login(self) -> None:
        """Auto-login when credentials are stored; otherwise ask for them."""
        username, _password = creds.load_credentials()
        if username:
            self.controller.login_async()
        else:
            self._open_login_dialog(first_run=True)

    def _open_login_dialog(self, first_run: bool = False,
                           prefill: str = "") -> None:
        if getattr(self, "_login_dialog", None) is not None \
                and self._login_dialog.isVisible():
            self._login_dialog.raise_()
            return
        stored_user, _ = creds.load_credentials()
        self._login_dialog = LoginDialog(
            self.controller, self, prefill_username=prefill or stored_user or "")
        self._login_dialog.show()

    def _on_login_event(self, kind: str, detail: str) -> None:
        """Relay login progress: CAPTCHA prompts, waiting states, failures."""
        if kind == "captcha":
            self._show_login_banner(
                "⚠ Proton requires human verification (CAPTCHA).\n"
                "A browser window has been opened — please complete the "
                "verification there; login continues automatically once "
                "you're done.", level="warn")
            self._relay_desktop_notification(
                "Human verification required",
                "Complete the CAPTCHA in the browser window to continue "
                "logging in.", warning=True)
        elif kind == "interactive_open":
            self._show_login_banner(
                f"⏳ Waiting for you in the browser window — {detail}",
                level="warn")
        elif kind == "totp_needed":
            self._show_login_banner(
                "Two-factor code required — enter the code in the dialog "
                "that just opened (or store your 2FA secret to answer "
                "automatically).", level="info")
        elif kind == "interactive_done":
            self._show_login_banner(
                "✓ Verification completed — logging in…", level="info")
        elif kind == "interactive_timeout":
            self._hide_login_banner()
        elif kind == "bad_credentials":
            self._hide_login_banner()
            self._open_login_dialog(
                prefill=creds.load_credentials()[0] or "")
        elif kind == "credentials_needed":
            self._open_login_dialog()

    def _show_login_banner(self, text: str, level: str = "warn") -> None:
        self.login_banner.setText(text)
        self.login_banner.setProperty("level", level)
        self.login_banner.style().unpolish(self.login_banner)
        self.login_banner.style().polish(self.login_banner)
        self.login_banner.show()
        QApplication.alert(self)          # flash the taskbar entry

    def _hide_login_banner(self) -> None:
        self.login_banner.hide()

    def _relay_desktop_notification(self, title: str, body: str,
                                    warning: bool = False) -> None:
        """Desktop notification via the tray icon (when available)."""
        tray = getattr(self, "tray", None)
        if tray is not None and tray.isVisible():
            icon = (QSystemTrayIcon.MessageIcon.Warning if warning
                    else QSystemTrayIcon.MessageIcon.Information)
            try:
                tray.showMessage(title, body, icon, 10000)
            except Exception:  # noqa: BLE001
                pass

    def _update_login_button(self) -> None:
        logged_in = self.controller.state in (State.LOGGED_IN, State.CONNECTING,
                                              State.CONNECTED,
                                              State.DISCONNECTING)
        self.login_btn.setText("Switch account…" if logged_in else "Log in…")

    # ------------------------------------------------------------ blocklists
    def _on_blocklists(self, entries) -> None:
        """Controller reported blocklist changes → refresh menu + dialog."""
        self._blocklist_entries = list(entries)
        if self._blocklists_dialog is not None:
            self._blocklists_dialog.refresh(self._blocklist_entries)
        self._update_netshield_label()

    def _rebuild_blocklists_menu(self) -> None:
        """(Re)build the Blocklists ▾ menu right before it opens."""
        m = self.blocklists_menu
        m.clear()
        entries = self.controller.blocklist_entries()
        self._blocklist_entries = entries

        update_all = m.addAction("Update all now")
        update_all.triggered.connect(lambda: self.controller.update_blocklists_async())
        m.addSeparator()

        if not entries:
            empty = m.addAction("(no blocklists configured)")
            empty.setEnabled(False)
        for e in entries:
            label = ("✓ " if e.enabled else "✗ ") + e.name
            label += f"  ·  {e.domains:,} domains" if e.domains else "  ·  not downloaded"
            top = m.addAction(label)
            top.setCheckable(True)
            top.setChecked(e.enabled)
            name = e.name
            top.toggled.connect(
                lambda checked, n=name: self.controller.set_blocklist_enabled_async(n, checked))
            sub = m.addMenu(f"{e.name} — actions")
            act_update = sub.addAction("Update now")
            act_update.triggered.connect(
                lambda _=False, n=name: self.controller.update_blocklists_async(n))
            act_remove = sub.addAction("Remove…")
            act_remove.triggered.connect(lambda _=False, n=name: self._remove_blocklist(n))

        m.addSeparator()
        act_add = m.addAction("Add blocklist…")
        act_add.triggered.connect(self._add_blocklist)
        act_rm = m.addAction("Remove blocklist…")
        act_rm.triggered.connect(
            lambda: self._choose_and_remove_blocklist())
        act_manage = m.addAction("Manage blocklists…")
        act_manage.triggered.connect(self._open_blocklists_dialog)

    def _add_blocklist(self) -> None:
        dlg = AddBlocklistDialog(
            self, taken_names={e.name for e in self._blocklist_entries},
            taken_urls={e.url for e in self._blocklist_entries})
        if dlg.exec():
            name, url = dlg.values()
            self.controller.add_blocklist_async(name, url)

    # ---------------------------------------------------------------- theme
    def _rebuild_theme_menu(self) -> None:
        """(Re)build the Theme ▾ menu right before it opens."""
        from PySide6.QtGui import QActionGroup

        m = self.theme_menu
        m.clear()
        current = load_settings().theme
        group = QActionGroup(m)
        group.setExclusive(True)
        for mode in THEMES:
            suffix = {
                "system": " — switches with the desktop",
                "light": " — bright look, same violet accent",
                "dark": " — the original Proto Clean look",
            }[mode]
            act = m.addAction(THEME_LABELS[mode] + suffix)
            act.setCheckable(True)
            act.setChecked(mode == current)
            group.addAction(act)
            act.triggered.connect(
                lambda _=False, md=mode: self._change_theme(md))
        m.addSeparator()
        eff = effective_theme()
        info = m.addAction(f"now painting: {eff}")
        info.setEnabled(False)

    def _change_theme(self, mode: str) -> None:
        """Persist the theme choice and restyle the running application."""
        update(theme=mode)
        eff = apply_theme(QApplication.instance(), mode)
        self._refresh_table()      # repaint load bars with matching colors
        self.statusBar().showMessage(
            f"Theme: {THEME_LABELS.get(mode, mode)} (now painting: {eff})",
            6000)

    def _remove_blocklist(self, name: str) -> None:
        from PySide6.QtWidgets import QMessageBox

        if QMessageBox.question(
                self, "Remove blocklist",
                f"Remove {name!r} and its local cache?") is QMessageBox.Yes:
            self.controller.remove_blocklist_async(name)

    def _choose_and_remove_blocklist(self) -> None:
        entries = self.controller.blocklist_entries()
        if not entries:
            self.statusBar().showMessage("no blocklists configured", 4000)
            return
        names = [e.name for e in entries]
        name, ok = QInputDialog.getItem(
            self, "Remove blocklist", "Blocklist to remove:", names, 0, False)
        if ok and name:
            self._remove_blocklist(name)

    def _open_blocklists_dialog(self) -> None:
        if self._blocklists_dialog is None:
            self._blocklists_dialog = BlocklistsDialog(self.controller, self)
        self._blocklists_dialog.refresh(self.controller.blocklist_entries())
        self._blocklists_dialog.show()
        self._blocklists_dialog.raise_()
        self._blocklists_dialog.activateWindow()

    def _on_row_clicked(self, row: int, _col: int) -> None:
        server = self._server_at_row(row)
        if server:
            self.selected_server = server
            self.fastest_toggle.blockSignals(True)
            self.fastest_toggle.setChecked(False)
            self.fastest_toggle.blockSignals(False)
            update(autoconnect_fastest=False)
            self.controller.reload_settings()
            self.statusBar().showMessage(f"selected {server.name}", 4000)

    def _on_connect_clicked(self) -> None:
        state = self.controller.state
        if state in (State.CONNECTED, State.CONNECTING):
            self.controller.disconnect_async()
        else:
            server_id = self.selected_server.id if self.selected_server else None
            self.controller.connect_async(server_id)

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self.controller, self)
        dlg.exec()
        self.controller.reload_settings()
        self._update_netshield_label()
        self._refresh_subtitle()
        # the Appearance tab may have switched the theme — re-apply + repaint
        apply_theme(QApplication.instance(), load_settings().theme)
        self._refresh_table()

    # --------------------------------------------------------------- table
    def _visible_servers(self) -> list:
        """Free servers only (paid excluded), filtered by the search box."""
        servers = getattr(self, "_servers", [])
        ranked = rank_servers(servers, max_tier=0)
        needle = self.search.text().strip().lower()
        if needle:
            ranked = [s for s in ranked if needle in (
                f"{s.exit_country} {s.name} {s.city}".lower())]
        return ranked

    def _refresh_table(self, *_ignored) -> None:
        ranked = self._visible_servers()
        self.table.setRowCount(0)
        for server in ranked:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._set_item(row, 0, server.exit_country)
            self._set_item(row, 1, server.name)
            self._set_item(row, 2, server.city or "—")
            load_widget = QLabel()
            load_widget.setPixmap(resources.load_bar_pixmap(server.load))
            load_widget.setToolTip(f"{server.load:.0f}% load")
            self.table.setCellWidget(row, 3, load_widget)
            feats = ["Free"]
            if server.supports_p2p:
                feats.append("P2P")
            if server.is_secure_core:
                feats.append("SecureCore")
            if server.supports_tor:
                feats.append("Tor")
            self._set_item(row, 4, " · ".join(feats) or "—")
            self.table.setRowHeight(row, 30)

    def _set_item(self, row: int, col: int, text: str) -> None:
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        self.table.setItem(row, col, item)

    def _server_at_row(self, row: int) -> Optional[LogicalServer]:
        ranked = self._visible_servers()
        return ranked[row] if 0 <= row < len(ranked) else None

    # ---------------------------------------------------------------- misc
    def _update_connect_button(self) -> None:
        state = self.controller.state
        if state in (State.CONNECTED,):
            self.connect_btn.setText("Disconnect")
            self.connect_btn.setObjectName("Disconnect")
        else:
            self.connect_btn.setText("Connect")
            self.connect_btn.setObjectName("Connect")
        self.connect_btn.setEnabled(state not in
                                     (State.CONNECTING, State.DISCONNECTING))
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)
        self._update_netshield_label()

    def _update_netshield_label(self) -> None:
        s = load_settings()
        count = s.netshield.domain_count
        self.adblock_label.setText(
            f"ad blocking: {'ON' if s.netshield.enabled else 'OFF'}"
            + (f" ({count:,} domains)" if count else ""))

    def _tick(self) -> None:
        stats = self._stats
        if not stats:
            return
        if stats.get("up"):
            dur = time.time() - (self._connect_started_at or time.time())
            parts = [f"up {int(dur)//3600:02d}:{(int(dur)//60)%60:02d}:{int(dur)%60:02d}"]
            if stats.get("handshake_age") is not None:
                parts.append(f"handshake {int(stats['handshake_age'])}s ago")
            parts.append(f"↓ {human_bytes(stats.get('rx', 0))}")
            parts.append(f"↑ {human_bytes(stats.get('tx', 0))}")
            if stats.get("endpoint"):
                parts.append(f"endpoint {stats['endpoint']}")
            self.stats_label.setText("   ".join(parts))
        else:
            self.stats_label.setText("tunnel down")

    def closeEvent(self, event) -> None:
        # Keep the app alive in the tray; only truly exit via tray → Quit.
        if getattr(self, "tray", None) and self.tray.isVisible():
            self.hide()
            event.ignore()
        else:
            event.accept()

"""Protocols dialog — the multi-protocol control centre.

Lists every imported profile (any of the 25+ protocols), imports from
the clipboard / QR on screen / QR image / config files / subscription
URLs, starts and stops engines, shares profiles as QR codes and composes
chains — including the one-click "WARP before/after" presets.
"""

from __future__ import annotations

from typing import List, Optional

from ..qtcompat import QtWidgets, QtCore, QtGui
from ..controller import Controller
from ..vpn.protocols import profiles as profiles_mod
from ..vpn.protocols.importers import (HAVE_SEGNO, HAVE_ZXING,
                                       ImportSummary)

IMPORT_SOURCES = ("Clipboard", "QR on screen", "QR image…", "File…",
                  "Subscription…")

_columns = ("Name", "Protocol", "Server", "")


class ProtocolsDialog(QtWidgets.QDialog):
    """Modal-free manager for imported protocol profiles."""

    def __init__(self, controller: Controller,
                 parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.controller = controller
        self.store = controller.protocol_store()
        self.import_center = controller.import_center()
        self.setWindowTitle("Proto Clean — Protocols")
        self.resize(720, 480)
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)

        hint = QtWidgets.QLabel(
            "Import configs from the clipboard, QR codes, files or a "
            "subscription URL. Supported: Shadowsocks (incl. 2022), "
            "VMess, VLESS + REALITY, Trojan, Hysteria 2, TUIC v5, "
            "MASQUE over QUIC, NaïveProxy, ShadowsocksR, OpenVPN over "
            "Cloak, AmneziaWG 1.5/2.0, WireGuard, IKEv2, Tor + bridges, "
            "Obscura relays, Lantern samizdat/radiance/lampshade, Reflex, "
            "WATER, Outline, ALGeneva, Cloudflare WARP, Clash, V2ray/"
            "V2fly, sing-box configs and multiprotocol chains.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QtWidgets.QHBoxLayout()
        self.import_combo = QtWidgets.QComboBox()
        self.import_combo.addItems(IMPORT_SOURCES)
        row.addWidget(self.import_combo, 1)
        import_btn = QtWidgets.QPushButton("Import")
        import_btn.clicked.connect(self._on_import)
        row.addWidget(import_btn)
        layout.addLayout(row)

        self.table = QtWidgets.QTableWidget(0, len(_columns))
        self.table.setHorizontalHeaderLabels(_columns)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table, 1)

        btns = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.start_btn.clicked.connect(self._on_start)
        btns.addWidget(self.start_btn)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.clicked.connect(self._on_stop)
        btns.addWidget(self.stop_btn)
        self.qr_btn = QtWidgets.QPushButton("Show QR")
        self.qr_btn.clicked.connect(self._on_share_qr)
        btns.addWidget(self.qr_btn)
        self.chain_btn = QtWidgets.QPushButton("Chain…")
        self.chain_btn.clicked.connect(self._on_chain)
        btns.addWidget(self.chain_btn)
        del_btn = QtWidgets.QPushButton("Delete")
        del_btn.clicked.connect(self._on_delete)
        btns.addWidget(del_btn)
        btns.addStretch(1)
        self.close_btn = QtWidgets.QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        btns.addWidget(self.close_btn)
        layout.addLayout(btns)

        self.status = QtWidgets.QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

    # ------------------------------------------------------------- helpers
    def _reload(self) -> None:
        entries = self.store.all()
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            prof = entry.profile()
            server = ""
            if prof is not None:
                server = getattr(prof, "server", "") or \
                    getattr(prof, "address", "")
            values = (entry.name, entry.kind, server)
            for col, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setData(QtCore.Qt.ItemDataRole.UserRole, entry.id)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()

    def _selected_entry(self) -> Optional[profiles_mod.ProfileEntry]:
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if item is None:
            return None
        return self.store.get(str(item.data(
            QtCore.Qt.ItemDataRole.UserRole) or ""))

    def _report(self, summary: ImportSummary) -> None:
        parts = []
        if summary.added:
            parts.append("imported %d profile%s" % (
                len(summary.added), "s" if len(summary.added) != 1 else ""))
        if summary.errors:
            parts.append("errors: " + "; ".join(summary.errors[:3]))
        self.status.setText(" — ".join(parts) if parts else
                            "nothing imported")
        self._reload()

    # -------------------------------------------------------------- actions
    def _on_import(self) -> None:
        source = self.import_combo.currentText()
        try:
            if source == "Clipboard":
                clipboard = QtWidgets.QApplication.clipboard()
                summary = self.import_center.import_clipboard(
                    clipboard.text() or "")
            elif source == "QR on screen":
                if not HAVE_ZXING:
                    QtWidgets.QMessageBox.warning(
                        self, "Protocols", "QR decoding needs the "
                        "zxing-cpp package.")
                    return
                summary = self.import_center.import_qr_screen()
            elif source == "QR image…":
                if not HAVE_ZXING:
                    QtWidgets.QMessageBox.warning(
                        self, "Protocols", "QR decoding needs the "
                        "zxing-cpp package.")
                    return
                path, _filter = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Pick a QR image", "",
                    "Images (*.png *.jpg *.jpeg *.bmp);;All files (*)")
                if not path:
                    return
                summary = self.import_center.import_qr_image(path)
            elif source == "File…":
                path, _filter = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Pick a config file", "",
                    "Configs (*.txt *.yaml *.yml *.json *.conf *.ovpn);;"
                    "All files (*)")
                if not path:
                    return
                summary = self.import_center.import_file(path)
            elif source == "Subscription…":
                url, ok = QtWidgets.QInputDialog.getText(
                    self, "Subscription", "Subscription URL:")
                if not ok or not url.strip():
                    return
                self.status.setText("fetching subscription…")
                QtWidgets.QApplication.processEvents()
                summary = self.import_center.import_subscription(
                    url.strip())
            else:                                       # pragma: no cover
                return
            self._report(summary)
        except Exception as exc:  # noqa: BLE001 — surface to the user
            self.status.setText("import failed: %s" % exc)

    def _on_start(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self.status.setText("select a profile first")
            return
        self.controller.start_profile_async(entry.id)
        self.status.setText("starting %s…" % entry.name)

    def _on_stop(self) -> None:
        self.controller.stop_protocol_async()
        self.status.setText("stopping…")

    def _on_share_qr(self) -> None:
        entry = self._selected_entry()
        if entry is None or not entry.url:
            self.status.setText("select a profile first")
            return
        if not HAVE_SEGNO:
            QtWidgets.QMessageBox.warning(
                self, "Protocols", "QR generation needs the segno "
                "package.")
            return
        try:
            import tempfile
            import os
            from ..vpn.protocols.importers import make_qr
            fd, path = tempfile.mkstemp(suffix=".png",
                                        prefix="proto-clean-qr-")
            os.close(fd)
            make_qr(entry.url, path, scale=10)
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("Share — %s" % entry.name)
            lay = QtWidgets.QVBoxLayout(dialog)
            scene = QtWidgets.QGraphicsScene(dialog)
            pixmap = QtGui.QPixmap(path)
            scene.addPixmap(pixmap)
            view = QtWidgets.QGraphicsView(scene)
            view.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)
            lay.addWidget(view)
            link = QtWidgets.QLineEdit(entry.url)
            link.setReadOnly(True)
            lay.addWidget(link)
            dialog.resize(min(560, pixmap.width() + 40),
                          min(640, pixmap.height() + 80))
            dialog.exec()
            os.unlink(path)
        except Exception as exc:  # noqa: BLE001
            self.status.setText("QR failed: %s" % exc)

    def _on_delete(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        confirm = QtWidgets.QMessageBox.question(
            self, "Protocols", "Delete %r?" % entry.name)
        if confirm == QtWidgets.QMessageBox.StandardButton.Yes:
            self.store.remove(entry.id)
            self._reload()

    def _on_chain(self) -> None:
        entry = self._selected_entry()
        if entry is None or not entry.url:
            self.status.setText("select a profile first")
            return
        from ..vpn.protocols import warp as warp_mod
        menu = QtWidgets.QMenu(self)
        plain = menu.addAction("Just this profile")
        warp_before = menu.addAction("Chain: WARP → profile")
        warp_after = menu.addAction("Chain: profile → WARP")
        custom = menu.addAction("Custom chain…")
        picked = menu.exec(QtGui.QCursor.pos())
        if picked is plain:
            return
        if picked in (warp_before, warp_after):
            url = (warp_mod.warp_before_chain_url(entry.url) if
                   picked is warp_before else
                   warp_mod.warp_after_chain_url(entry.url))
            from ..vpn.protocols import links
            kind, prof = links.parse_link(url)
            self.store.add(kind, prof, name=("%s (WARP)" % entry.name))
            self._reload()
            self.status.setText("chain profile added — select it and Start")
            return
        if picked is custom:
            hops, ok = QtWidgets.QInputDialog.getMultiLineText(
                self, "Custom chain",
                "One share URL per line, client → exit order:",
                entry.url + "\n")
            if not ok:
                return
            from ..vpn.protocols import links as L
            urls = [ln.strip() for ln in hops.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
            if len(urls) < 2:
                self.status.setText("a chain needs at least two hops")
                return
            kind, prof = L.parse_link(L.build_chain_url(urls))
            self.store.add(kind, prof, name="chain (%d hops)" % len(urls))
            self._reload()
            self.status.setText("chain profile added — select it and Start")

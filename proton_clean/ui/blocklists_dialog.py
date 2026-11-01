"""Blocklist manager dialog: add / remove / update the locally maintained
blocklists that power the NetShield-style ad blocking."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from ..settings import BLOCKLIST_PRESETS


class AddBlocklistDialog(QDialog):
    """Pick a known list or enter a custom hosts/domains URL."""

    def __init__(self, parent=None, taken_names=(), taken_urls=()) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add blocklist")
        self.setMinimumWidth(520)
        self.taken_names = set(taken_names)
        self.taken_urls = set(taken_urls)

        form = QFormLayout(self)
        self.preset = QComboBox()
        self.preset.addItem("Custom…", "")
        for name, url in BLOCKLIST_PRESETS:
            self.preset.addItem(name, url)
        self.preset.currentIndexChanged.connect(self._preset_changed)

        self.name = QLineEdit()
        self.name.setPlaceholderText("display name (optional)")
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://… hosts or domain-per-line list")

        form.addRow("Preset", self.preset)
        form.addRow("Name", self.name)
        form.addRow("URL", self.url)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _preset_changed(self, index: int) -> None:
        url = self.preset.currentData()
        if url:
            self.url.setText(url)
            if not self.name.text().strip():
                self.name.setText(self.preset.currentText())

    def _validate(self) -> None:
        url = self.url.text().strip()
        name = self.name.text().strip() or self.preset.currentText()
        if not url.startswith(("http://", "https://")):
            QMessageBox.warning(self, "Add blocklist",
                                "The URL must start with http:// or https://")
            return
        if url in self.taken_urls:
            QMessageBox.warning(self, "Add blocklist",
                                "That URL is already configured.")
            return
        self.name.setText(name if name != "Custom…" else "")
        self.accept()

    def values(self) -> tuple:
        return self.name.text().strip(), self.url.text().strip()


class BlocklistsDialog(QDialog):
    """Table of blocklists with add / remove / update / enable controls."""

    def __init__(self, controller, parent=None) -> None:
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Manage blocklists")
        self.resize(760, 420)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "These lists are downloaded, merged and kept locally; enabled "
            "lists feed the DNS blocker while the VPN is up."))

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Enabled", "Name", "Domains", "Updated", "Status"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        self.add_btn = QPushButton("Add…")
        self.add_btn.clicked.connect(self._add)
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.clicked.connect(self._remove)
        self.update_btn = QPushButton("Update selected")
        self.update_btn.clicked.connect(self._update_selected)
        self.update_all_btn = QPushButton("Update all")
        self.update_all_btn.clicked.connect(self._update_all)
        for b in (self.add_btn, self.remove_btn, self.update_btn,
                  self.update_all_btn):
            buttons.addWidget(b)
        buttons.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close)
        close.rejected.connect(self.reject)
        close.clicked.connect(lambda _: self.reject())
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self._entries = []
        self.refresh(controller.blocklist_entries())

    # ------------------------------------------------------------------ data
    def refresh(self, entries) -> None:
        """Called by the main window whenever the controller reports changes."""
        self._entries = list(entries)
        self.table.setRowCount(0)
        for e in self._entries:
            row = self.table.rowCount()
            self.table.insertRow(row)

            cb = QCheckBox()
            cb.setChecked(e.enabled)
            cb.toggled.connect(
                lambda checked, name=e.name:
                    self.controller.set_blocklist_enabled_async(name, checked))
            self.table.setCellWidget(row, 0, cb)

            for col, text in (
                (1, e.name),
                (2, f"{e.domains:,}" if e.domains else "—"),
                (3, e.updated_at or "never"),
                (4, ("error: " + e.error) if e.error else "ok"),
            ):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if col == 4 and e.error:
                    item.setForeground(Qt.red)
                self.table.setItem(row, col, item)
            self.table.setRowHeight(row, 30)

    def _current(self):
        row = self.table.currentRow()
        return self._entries[row] if 0 <= row < len(self._entries) else None

    # ---------------------------------------------------------------- actions
    def _add(self) -> None:
        dlg = AddBlocklistDialog(
            self, taken_names={e.name for e in self._entries},
            taken_urls={e.url for e in self._entries})
        if dlg.exec():
            name, url = dlg.values()
            self.controller.add_blocklist_async(name, url)

    def _remove(self) -> None:
        e = self._current()
        if not e:
            return
        if QMessageBox.question(
                self, "Remove blocklist",
                f"Remove {e.name!r} and its local cache?") is QMessageBox.Yes:
            self.controller.remove_blocklist_async(e.name)

    def _update_selected(self) -> None:
        e = self._current()
        if e:
            self.controller.update_blocklists_async(e.name)

    def _update_all(self) -> None:
        self.controller.update_blocklists_async()

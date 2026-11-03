"""Settings dialog — account, protocol (WireGuard/OpenVPN), advanced
connection options, kill switch, ad-blocking, split tunneling and port
forwarding.

The Protocol tab mirrors Proton's protocol page: pick the config type to
download, and the per-protocol options (NAT-PMP + VPN Accelerator for
WireGuard, TCP/UDP transport for OpenVPN). The Advanced tab mirrors
Proton's advanced settings: alternative routing, LAN access, custom DNS,
NAT type, the OpenVPN network driver (TAP/TUN) and both IPv6 toggles.
"""

from __future__ import annotations

import ipaddress
import os
import re

from proto_clean.qtcompat import Qt
from proto_clean.qtcompat import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPushButton, QRadioButton, QSpinBox, QTabWidget,
    QVBoxLayout, QWidget, QMessageBox,
)

from .. import credentials as creds
from ..controller import Controller
from ..paths import BLOCKLIST_DIR, LOG_DIR
from ..settings import THEMES, load_settings, save_settings, update
from ..vpn.split_tunnel import SplitTunnel

# The driver descriptions requested verbatim for the Advanced tab.
TAP_DESCRIPTION = ("TAP: Bridges network traffic. Slower than TUN, but "
                   "needed for some legacy or special network setups.")
TUN_DESCRIPTION = ("TUN: Routes traffic between different networks. "
                   "TUN can be faster and more stable than TAP.")


class SettingsDialog(QDialog):
    def __init__(self, controller: Controller, parent=None) -> None:
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Proto Clean settings")
        self.resize(660, 580)

        tabs = QTabWidget()
        tabs.addTab(self._account_tab(), "Account")
        tabs.addTab(self._appearance_tab(), "Appearance")
        tabs.addTab(self._protocol_tab(), "Protocol")
        tabs.addTab(self._advanced_tab(), "Advanced")
        tabs.addTab(self._killswitch_tab(), "Kill switch")
        tabs.addTab(self._adblock_tab(), "Ad blocking")
        tabs.addTab(self._split_tab(), "Split tunneling")
        tabs.addTab(self._portfwd_tab(), "Port forwarding")
        tabs.addTab(self._xray_tab(), "Proxy")
        tabs.addTab(self._bond_tab(), "Link bonding")

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.clicked.connect(lambda _: self.accept())

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    # -------------------------------------------------- Proxy (Xray/samizdat)
    def _xray_tab(self) -> QWidget:
        """Proxy engines: Xray (VLESS + REALITY SNI masking / Trojan) and
        samizdat (Lantern's DPI-resistant HTTP/2 masquerade), plus the
        browser-routing option that carries Proton logins/config downloads
        and blocklist updates through the running proxy (or an external
        Lantern on 127.0.0.1:8787)."""
        w = QWidget()
        outer = QVBoxLayout(w)
        s = self.controller.settings.xray.normalized()
        sam = self.controller.settings.samizdat.normalized()
        adv = self.controller.settings.advanced

        # ---- engine selector ----
        self.proxy_provider = QComboBox()
        self.proxy_provider.addItem("Xray — VLESS + REALITY (SNI masking) / Trojan", "xray")
        self.proxy_provider.addItem("Samizdat (Lantern) — HTTP/2 masquerade", "samizdat")
        self.proxy_provider.setCurrentIndex(0 if s.provider == "xray" else 1)
        self.proxy_provider.currentIndexChanged.connect(self._proxy_persist)
        prov_row = QHBoxLayout()
        prov_row.addWidget(QLabel("Engine"))
        prov_row.addWidget(self.proxy_provider, 1)
        outer.addLayout(prov_row)

        # ---- Xray group ----
        xg = QGroupBox("Xray profile (vless:// / trojan://)")
        form = QFormLayout(xg)
        self.xray_proto = QComboBox()
        self.xray_proto.addItem("VLESS + REALITY (SNI masking)", "vless-reality")
        self.xray_proto.addItem("Trojan (TLS)", "trojan")
        self.xray_proto.setCurrentIndex(0 if s.protocol == "vless-reality" else 1)
        self.xray_name = QLineEdit(s.name)
        self.xray_name.setPlaceholderText("optional label")
        self.xray_address = QLineEdit(s.address)
        self.xray_port = QSpinBox()
        self.xray_port.setRange(1, 65535)
        self.xray_port.setValue(s.port)
        self.xray_sni = QLineEdit(s.sni)
        self.xray_sni.setPlaceholderText("the site the connection pretends to "
                                         "be (REALITY serverName / TLS SNI)")
        self.xray_fp = QComboBox()
        for fp in ("chrome", "firefox", "safari", "ios", "android",
                   "edge", "randomized"):
            self.xray_fp.addItem(fp, fp)
        self.xray_fp.setCurrentIndex(max(0, self.xray_fp.findData(s.fingerprint)))
        self.xray_uuid = QLineEdit(s.uuid)
        self.xray_uuid.setPlaceholderText("VLESS user id (UUID) — REALITY only")
        self.xray_pbk = QLineEdit(s.public_key)
        self.xray_pbk.setPlaceholderText("REALITY public key (pbk)")
        self.xray_sid = QLineEdit(s.short_id)
        self.xray_sid.setPlaceholderText("REALITY short id (sid)")
        self.xray_flow = QComboBox()
        self.xray_flow.addItem("xtls-rprx-vision", "xtls-rprx-vision")
        self.xray_flow.addItem("(none)", "")
        self.xray_flow.setCurrentIndex(0 if s.flow else 1)
        self.xray_password = QLineEdit(s.password)
        self.xray_password.setEchoMode(QLineEdit.Password)
        self.xray_password.setPlaceholderText("trojan password")
        self.xray_insecure = QCheckBox("allow insecure TLS (trojan only)")
        self.xray_insecure.setChecked(s.allow_insecure)
        self.xray_mode = QComboBox()
        self.xray_mode.addItem("Set the system proxy automatically", "system")
        self.xray_mode.addItem("Manual (inbounds only — I configure apps myself)",
                               "manual")
        self.xray_mode.setCurrentIndex(0 if s.mode == "system" else 1)
        self.xray_socks = QSpinBox()
        self.xray_socks.setRange(1024, 65535)
        self.xray_socks.setValue(s.socks_port)
        self.xray_http = QSpinBox()
        self.xray_http.setRange(1024, 65535)
        self.xray_http.setValue(s.http_port)

        form.addRow("Protocol", self.xray_proto)
        form.addRow("Label", self.xray_name)
        form.addRow("Server", self.xray_address)
        form.addRow("Port", self.xray_port)
        form.addRow("Masked SNI", self.xray_sni)
        form.addRow("uTLS fingerprint", self.xray_fp)
        form.addRow("VLESS id (UUID)", self.xray_uuid)
        form.addRow("REALITY public key", self.xray_pbk)
        form.addRow("REALITY short id", self.xray_sid)
        form.addRow("VLESS flow", self.xray_flow)
        form.addRow("Trojan password", self.xray_password)
        form.addRow("", self.xray_insecure)
        form.addRow("Mode", self.xray_mode)
        form.addRow("SOCKS port", self.xray_socks)
        form.addRow("HTTP port", self.xray_http)
        outer.addWidget(xg)

        # ---- Samizdat group ----
        sg = QGroupBox("Samizdat profile (Lantern) — samizdat://")
        sform = QFormLayout(sg)
        self.sam_address = QLineEdit(sam.address)
        self.sam_port = QSpinBox()
        self.sam_port.setRange(1, 65535)
        self.sam_port.setValue(sam.port)
        self.sam_name = QLineEdit(sam.name)
        self.sam_pbk = QLineEdit(sam.public_key)
        self.sam_pbk.setPlaceholderText("server X25519 public key (pbk, 64 hex)")
        self.sam_sid = QLineEdit(sam.short_id)
        self.sam_sid.setPlaceholderText("short id (sid, 16 hex)")
        self.sam_sni = QLineEdit(sam.server_name)
        self.sam_sni.setPlaceholderText("cover site the connection pretends to "
                                        "visit (e.g. ok.ru)")
        self.sam_fp = QComboBox()
        for fp in ("chrome", "firefox", "safari"):
            self.sam_fp.addItem(fp, fp)
        self.sam_fp.setCurrentIndex(max(0, self.sam_fp.findData(sam.fingerprint)))
        self.sam_profile = QComboBox()
        for pp in ("chrome", "firefox"):
            self.sam_profile.addItem(pp, pp)
        self.sam_profile.setCurrentIndex(max(0, self.sam_profile.findData(sam.padding_profile)))
        self.sam_mode = QComboBox()
        self.sam_mode.addItem("Set the system proxy automatically", "system")
        self.sam_mode.addItem("Manual (mixed inbound only)", "manual")
        self.sam_mode.setCurrentIndex(0 if sam.mode == "system" else 1)
        self.sam_mixed = QSpinBox()
        self.sam_mixed.setRange(1024, 65535)
        self.sam_mixed.setValue(sam.mixed_port)
        sam_import = QPushButton("Import samizdat:// URL…")
        sam_import.clicked.connect(self._samizdat_import_url)
        sform.addRow("Server", self.sam_address)
        sform.addRow("Port", self.sam_port)
        sform.addRow("Label", self.sam_name)
        sform.addRow("Public key (pbk)", self.sam_pbk)
        sform.addRow("Short id (sid)", self.sam_sid)
        sform.addRow("Cover SNI", self.sam_sni)
        sform.addRow("uTLS fingerprint", self.sam_fp)
        sform.addRow("Padding profile", self.sam_profile)
        sform.addRow("Mode", self.sam_mode)
        sform.addRow("Mixed port (SOCKS+HTTP)", self.sam_mixed)
        sform.addRow("", sam_import)
        outer.addWidget(sg)

        # ---- browser routing (the Lantern interop) ----
        bg = QGroupBox("Reaching Proton & blocklists (works even if protonvpn.com is blocked)")
        bform = QFormLayout(bg)
        self.route_mode = QComboBox()
        self.route_mode.addItem("Direct connection", "direct")
        self.route_mode.addItem("Through the running proxy (Xray / samizdat)", "auto")
        self.route_mode.addItem("Custom proxy (e.g. Lantern on 127.0.0.1:8787)", "custom")
        self.route_mode.setCurrentIndex(
            ("direct", "auto", "custom").index(adv.browser_proxy_mode)
            if adv.browser_proxy_mode in ("direct", "auto", "custom") else 0)
        self.route_mode.currentIndexChanged.connect(self._route_persist)
        self.route_custom = QLineEdit(adv.browser_proxy_custom)
        self.route_custom.setPlaceholderText("http://127.0.0.1:8787 — e.g. "
                                             "lantern-headless-client / Lantern")
        self.route_custom.textChanged.connect(self._route_persist)
        bform.addRow("Route", self.route_mode)
        bform.addRow("Custom proxy", self.route_custom)
        outer.addWidget(bg)

        # ---- buttons + status ----
        import_btn = QPushButton("Import vless:// trojan:// URL…")
        import_btn.setToolTip("Paste a vless:// (REALITY) or trojan:// link")
        import_btn.clicked.connect(self._xray_import_url)
        start_btn = QPushButton("Start proxy")
        start_btn.clicked.connect(self.controller.start_proxy_async)
        stop_btn = QPushButton("Stop proxy")
        stop_btn.clicked.connect(self.controller.stop_proxy_async)
        btns = QHBoxLayout()
        btns.addWidget(import_btn)
        btns.addWidget(start_btn)
        btns.addWidget(stop_btn)
        outer.addLayout(btns)

        self.xray_status = QLabel(self._xray_status_text())
        self.xray_status.setWordWrap(True)
        outer.addWidget(self.xray_status)

        # ride-the-bond toggles (chain each engine through the bond's
        # local SOCKS when bonding is running)
        self.xray_ride = QCheckBox("Ride the bond: dial through link "
                                   "bonding while it is running")
        self.xray_ride.setChecked(
            getattr(s, "ride_bond", True) and True)
        self.xray_ride.toggled.connect(self._xray_persist)
        self.sam_ride = QCheckBox("Samizdat: ride the bond as well")
        self.sam_ride.setChecked(getattr(sam, "ride_bond", True) and True)
        self.sam_ride.toggled.connect(self._samizdat_persist)
        outer.addWidget(self.xray_ride)
        outer.addWidget(self.sam_ride)

        outer.addWidget(QLabel(
            "Official builds bundle the engine binaries: Xray-core for "
            "vless/trojan and lantern-box (Lantern's GPL-3 sing-box fork) "
            "for samizdat — see the README. Profiles are stored locally "
            "with your credentials and never uploaded."))

        # persist on every edit
        for wdg, sig in ((self.xray_proto, "currentIndexChanged"),
                         (self.xray_fp, "currentIndexChanged"),
                         (self.xray_flow, "currentIndexChanged"),
                         (self.xray_mode, "currentIndexChanged"),
                         (self.xray_port, "valueChanged"),
                         (self.xray_socks, "valueChanged"),
                         (self.xray_http, "valueChanged"),
                         (self.xray_name, "textChanged"),
                         (self.xray_address, "textChanged"),
                         (self.xray_sni, "textChanged"),
                         (self.xray_uuid, "textChanged"),
                         (self.xray_pbk, "textChanged"),
                         (self.xray_sid, "textChanged"),
                         (self.xray_password, "textChanged"),
                         (self.xray_insecure, "toggled")):
            getattr(wdg, sig).connect(self._xray_persist)
        for wdg, sig in ((self.sam_fp, "currentIndexChanged"),
                         (self.sam_profile, "currentIndexChanged"),
                         (self.sam_mode, "currentIndexChanged"),
                         (self.sam_port, "valueChanged"),
                         (self.sam_mixed, "valueChanged"),
                         (self.sam_address, "textChanged"),
                         (self.sam_name, "textChanged"),
                         (self.sam_pbk, "textChanged"),
                         (self.sam_sid, "textChanged"),
                         (self.sam_sni, "textChanged")):
            getattr(wdg, sig).connect(self._samizdat_persist)
        self.controller.add_proxy_listener(self._xray_on_proxy_state)
        return w

    def _proxy_persist(self, *_) -> None:
        self.controller.save_xray_settings(self._xray_collect())

    def _xray_collect(self):
        from ..settings import XraySettings
        return XraySettings(
            provider=self.proxy_provider.currentData(),
            protocol=self.xray_proto.currentData(),
            address=self.xray_address.text(),
            port=self.xray_port.value(),
            name=self.xray_name.text(),
            uuid=self.xray_uuid.text(),
            public_key=self.xray_pbk.text(),
            short_id=self.xray_sid.text(),
            flow=self.xray_flow.currentData(),
            password=self.xray_password.text(),
            sni=self.xray_sni.text(),
            fingerprint=self.xray_fp.currentData(),
            allow_insecure=self.xray_insecure.isChecked(),
            mode=self.xray_mode.currentData(),
            socks_port=self.xray_socks.value(),
            http_port=self.xray_http.value(),
            ride_bond=self.xray_ride.isChecked(),
        ).normalized()

    def _xray_persist(self, *_) -> None:
        self.controller.save_xray_settings(self._xray_collect())

    def _samizdat_collect(self):
        from ..settings import SamizdatSettings
        return SamizdatSettings(
            address=self.sam_address.text(),
            port=self.sam_port.value(),
            name=self.sam_name.text(),
            public_key=self.sam_pbk.text(),
            short_id=self.sam_sid.text(),
            server_name=self.sam_sni.text(),
            fingerprint=self.sam_fp.currentData(),
            padding_profile=self.sam_profile.currentData(),
            mode=self.sam_mode.currentData(),
            mixed_port=self.sam_mixed.value(),
            ride_bond=self.sam_ride.isChecked(),
        ).normalized()

    def _samizdat_persist(self, *_) -> None:
        self.controller.save_samizdat_settings(self._samizdat_collect())

    def _route_persist(self, *_) -> None:
        from ..settings import update
        update(**{
            "advanced.browser_proxy_mode": self.route_mode.currentData(),
            "advanced.browser_proxy_custom": self.route_custom.text(),
        })
        self.controller.settings = load_settings()

    def _xray_import_url(self) -> None:
        from ..vpn.xrayconf import XrayConfigError, parse_xray_url
        from proto_clean.qtcompat import QInputDialog
        url, ok = QInputDialog.getMultiLineText(
            self, "Import Xray share URL",
            "Paste a vless:// (REALITY) or trojan:// link:")
        if not ok or not url.strip():
            return
        try:
            p = parse_xray_url(url)
        except XrayConfigError as e:
            QMessageBox.warning(self, "Proto Clean", f"Could not import:\n{e}")
            return
        self.proxy_provider.setCurrentIndex(0)   # engine: xray
        self.xray_proto.setCurrentIndex(0 if p.protocol == "vless-reality" else 1)
        self.xray_name.setText(p.name)
        self.xray_address.setText(p.address)
        self.xray_port.setValue(p.port)
        self.xray_sni.setText(p.sni)
        self.xray_fp.setCurrentIndex(max(0, self.xray_fp.findData(p.fingerprint)))
        self.xray_uuid.setText(p.uuid)
        self.xray_pbk.setText(p.public_key)
        self.xray_sid.setText(p.short_id)
        self.xray_flow.setCurrentIndex(0 if p.flow else 1)
        self.xray_password.setText(p.password)
        self._xray_persist()
        QMessageBox.information(
            self, "Proto Clean",
            f"Imported {p.protocol} profile \"{p.name or p.address}\" "
            f"(SNI {p.sni}).")

    def _samizdat_import_url(self) -> None:
        from ..vpn.samizdatconf import SamizdatConfigError, parse_samizdat_url
        from proto_clean.qtcompat import QInputDialog
        url, ok = QInputDialog.getMultiLineText(
            self, "Import samizdat share URL",
            "Paste a samizdat:// link (pbk, sid, sni):")
        if not ok or not url.strip():
            return
        try:
            p = parse_samizdat_url(url)
        except SamizdatConfigError as e:
            QMessageBox.warning(self, "Proto Clean", f"Could not import:\n{e}")
            return
        self.proxy_provider.setCurrentIndex(1)   # engine: samizdat
        self.sam_address.setText(p.address)
        self.sam_port.setValue(p.port)
        self.sam_name.setText(p.name)
        self.sam_pbk.setText(p.public_key)
        self.sam_sid.setText(p.short_id)
        self.sam_sni.setText(p.server_name)
        self.sam_fp.setCurrentIndex(max(0, self.sam_fp.findData(p.fingerprint)))
        self.sam_profile.setCurrentIndex(
            max(0, self.sam_profile.findData(p.padding_profile)))
        self._samizdat_persist()
        QMessageBox.information(
            self, "Proto Clean",
            f"Imported samizdat profile \"{p.name or p.address}\" "
            f"(cover {p.server_name or 'default'}).")

    def _xray_on_proxy_state(self, state: str, detail: str) -> None:
        if not hasattr(self, "xray_status"):
            return
        self.xray_status.setText(self._xray_status_text(detail))

    def _xray_status_text(self, detail: str = "") -> str:
        st = self.controller.proxy_state if hasattr(self.controller,
                                                    "proxy_state") else "off"
        words = {"off": "Proxy off", "starting": "Starting…",
                 "on": "Proxy on", "error": "Proxy error"}
        text = words.get(st, st)
        if detail:
            text += f" — {detail}"
        if st != "on":
            from ..vpn.samizdat import find_box_binary
            from ..vpn.xray import find_xray_binary
            if not find_xray_binary():
                text += "\n(xray binary not found — see README to install Xray-core)"
            if not find_box_binary():
                text += ("\n(lantern-box binary not found — needed for "
                         "samizdat; see README)")
        return text

    # ------------------------------------------------------------- account
    # ------------------------------------------------------ Link bonding
    def _bond_tab(self) -> QWidget:
        """Multi-adapter link bonding (Speedify-style stream bonding /
        net-merge-style per-connection balancing)."""
        w = QWidget()
        outer = QVBoxLayout(w)
        b = self.controller.settings.bond.normalized()

        intro = QLabel(
            "Use two or more network adapters at once. Traffic to the "
            "same server is split across the selected adapters and "
            "rejoined at your bond server, so one connection gets the "
            "combined bandwidth of Wi-Fi + Ethernet + tethering. Run "
            "<code>python3 -m proto_clean.bondserver</code> on any "
            "reachable host (VPS) first.")
        intro.setWordWrap(True)
        outer.addWidget(intro)

        form = QFormLayout()
        self.bond_mode = QComboBox()
        self.bond_mode.addItem("Stream bonding — every connection uses "
                               "all adapters (max bandwidth)", "bond")
        self.bond_mode.addItem("Per-connection balancing — spread "
                               "connections across adapters (net-merge "
                               "style)", "balance")
        self.bond_mode.setCurrentIndex(
            0 if b.mode == "bond" else 1)
        self.bond_server = QLineEdit(b.server)
        self.bond_server.setPlaceholderText("bond server host")
        self.bond_port = QSpinBox()
        self.bond_port.setRange(1, 65535)
        self.bond_port.setValue(b.port)
        self.bond_token = QLineEdit(b.token)
        self.bond_token.setEchoMode(QLineEdit.Password)
        self.bond_token.setPlaceholderText(
            "shared secret (optional; must match the server --token)")
        self.bond_socks = QSpinBox()
        self.bond_socks.setRange(1024, 65535)
        self.bond_socks.setValue(b.socks_port)
        self.bond_proxy_mode = QComboBox()
        self.bond_proxy_mode.addItem(
            "Manual (apps point at the SOCKS port themselves)", "manual")
        self.bond_proxy_mode.addItem(
            "Set the system SOCKS proxy automatically (Linux desktops)",
            "system")
        self.bond_proxy_mode.setCurrentIndex(
            1 if b.mode_proxy == "system" else 0)
        form.addRow("Mode", self.bond_mode)
        form.addRow("Bond server", self.bond_server)
        form.addRow("Server port", self.bond_port)
        form.addRow("Token", self.bond_token)
        form.addRow("Local SOCKS port", self.bond_socks)
        form.addRow("System proxy", self.bond_proxy_mode)
        outer.addLayout(form)

        # adapter selection: detected adapters (checkboxes) + manual extras
        from ..vpn.bondnet import list_adapters
        self.bond_if_list = QListWidget()
        self._bond_fill_adapters()
        refresh_btn = QPushButton("Refresh adapters")
        refresh_btn.clicked.connect(self._bond_refresh_adapters)
        self.bond_if_manual = QLineEdit(", ".join(
            i for i in b.interfaces if "=" not in i and
            not any(a.name == i for a in list_adapters())))
        self.bond_if_manual.setPlaceholderText(
            "extra adapters / IPs, comma separated "
            "(e.g. usb0, 172.20.10.2)")
        outer.addWidget(QLabel("Adapters to bond (detected):"))
        outer.addWidget(self.bond_if_list)
        outer.addWidget(refresh_btn)
        outer.addWidget(QLabel("Manual entries (adapter names or IPs):"))
        outer.addWidget(self.bond_if_manual)

        btns = QHBoxLayout()
        start_btn = QPushButton("Start bonding")
        start_btn.clicked.connect(self.controller.start_bond_async)
        stop_btn = QPushButton("Stop bonding")
        stop_btn.clicked.connect(self.controller.stop_bond_async)
        btns.addWidget(start_btn)
        btns.addWidget(stop_btn)
        btns.addWidget(refresh_btn)
        outer.addLayout(btns)

        self.bond_status = QLabel(self._bond_status_text())
        self.bond_status.setWordWrap(True)
        outer.addWidget(self.bond_status)
        outer.addWidget(QLabel(
            "Chain it up: leave \u201cRide the bond\u201d on in the Proxy "
            "tab and Xray / samizdat dial through bonding automatically; "
            "the browser-routing \u201cauto\u201d mode uses it too."))

        for wdg, sig in ((self.bond_mode, "currentIndexChanged"),
                         (self.bond_proxy_mode, "currentIndexChanged"),
                         (self.bond_port, "valueChanged"),
                         (self.bond_socks, "valueChanged"),
                         (self.bond_server, "textChanged"),
                         (self.bond_token, "textChanged"),
                         (self.bond_if_manual, "textChanged")):
            getattr(wdg, sig).connect(self._bond_persist)
        self.bond_if_list.itemChanged.connect(self._bond_persist)
        self.controller.add_bond_listener(self._bond_on_state)
        return w

    def _bond_fill_adapters(self, checked: "list" = None) -> None:
        """(Re)populate the adapter checklist from the OS."""
        from ..vpn.bondnet import list_adapters
        selected = set(checked if checked is not None else
                       self.controller.settings.bond.interfaces)
        self.bond_if_list.blockSignals(True)
        self.bond_if_list.clear()
        for adapter in list_adapters():
            item = QListWidgetItem(f"{adapter.name}  ({adapter.ipv4})")
            item.setData(Qt.UserRole, adapter.name)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if adapter.name in selected
                               else Qt.Unchecked)
            self.bond_if_list.addItem(item)
        self.bond_if_list.blockSignals(False)

    def _bond_refresh_adapters(self) -> None:
        self._bond_fill_adapters(
            checked=self._bond_selected_from_list())

    def _bond_selected_from_list(self) -> list:
        out = []
        for i in range(self.bond_if_list.count()):
            item = self.bond_if_list.item(i)
            if item.checkState() == Qt.Checked:
                out.append(str(item.data(Qt.UserRole)))
        return out

    def _bond_collect(self):
        from ..settings import BondSettings
        manual = [t.strip() for t in
                  self.bond_if_manual.text().split(",") if t.strip()]
        return BondSettings(
            server=self.bond_server.text(),
            port=self.bond_port.value(),
            token=self.bond_token.text(),
            mode=self.bond_mode.currentData(),
            interfaces=self._bond_selected_from_list() + manual,
            socks_port=self.bond_socks.value(),
            mode_proxy=self.bond_proxy_mode.currentData(),
        ).normalized()

    def _bond_persist(self, *_) -> None:
        self.controller.save_bond_settings(self._bond_collect())

    def _bond_on_state(self, state: str, detail: str = "") -> None:
        self.bond_status.setText(self._bond_status_text(detail))
        if hasattr(self, "bond_status"):
            st = self.controller.bond_status()
            if st.get("members"):
                lines = [self.bond_status.text()]
                for ip, m in sorted(st["members"].items()):
                    lines.append(
                        f"\u2022 {ip}: {'up' if m['alive'] else 'down'} — "
                        f"\u2191 {m['up'] / 1024:.1f} KiB, "
                        f"\u2193 {m['down'] / 1024:.1f} KiB")
                self.bond_status.setText("\n".join(lines))

    def _bond_status_text(self, detail: str = "") -> str:
        st = getattr(self.controller, "bond_state", "off")
        words = {"off": "Link bonding off", "starting": "Starting\u2026",
                 "on": "Link bonding on", "error": "Bonding error"}
        text = words.get(st, st)
        if detail:
            text += f" \u2014 {detail}"
        if st == "on":
            s = self.controller.bond_status()
            text += (f" ({s.get('mode', '')}, {s.get('sessions', 0)} "
                     f"session(s), server {s.get('server', '')})")
        return text

    def _account_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("Proton account name (or email)")
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.totp_edit = QLineEdit()
        self.totp_edit.setPlaceholderText("optional — TOTP secret or otpauth:// URI")

        u, p = creds.load_credentials()
        if u:
            self.user_edit.setText(u)
        self.totp_edit.setText(creds.load_totp_secret() or "")

        save_btn = QPushButton("Save credentials & log in")
        save_btn.clicked.connect(self._save_credentials)
        dialog_btn = QPushButton("Login dialog…")
        dialog_btn.setToolTip("Open the login dialog (remember me, "
                              "browser login, CAPTCHA hints)")
        dialog_btn.clicked.connect(self._open_login_dialog)
        interactive_btn = QPushButton("Interactive login…")
        interactive_btn.setToolTip(
            "Open a visible browser window to log in by hand "
            "(CAPTCHA-friendly)")
        interactive_btn.clicked.connect(self._interactive_login)
        logout_btn = QPushButton("Log out & forget")
        logout_btn.clicked.connect(self._logout)

        row = QHBoxLayout()
        row.addWidget(dialog_btn)
        row.addWidget(interactive_btn)
        row.addWidget(logout_btn)
        form.addRow("Username", self.user_edit)
        form.addRow("Password", self.pass_edit)
        form.addRow("2FA secret", self.totp_edit)
        form.addRow(save_btn)
        form.addRow("", row)
        form.addRow("", QLabel(
            "Credentials are stored in your system keyring when available, "
            "otherwise in a chmod-600 file. The 2FA secret lets Proto Clean "
            "answer two-factor prompts automatically."))
        return w

    def _open_login_dialog(self) -> None:
        from .login_dialog import LoginDialog

        dlg = LoginDialog(self.controller, self,
                          prefill_username=self.user_edit.text().strip())
        self.accept()
        dlg.show()

    def _save_credentials(self) -> None:
        u = self.user_edit.text().strip()
        p = self.pass_edit.text()
        if not u or not p:
            QMessageBox.warning(self, "ProtoClean",
                                "Both username and password are required.")
            return
        creds.store_credentials(u, p)
        creds.store_totp_secret(self.totp_edit.text().strip())
        # fresh credentials: log in as this account right away (no cached
        # session probe — it might belong to a different account)
        self.controller.login_once_async(u, p, remember=True)
        self.accept()

    def _interactive_login(self) -> None:
        u = self.user_edit.text().strip()
        p = self.pass_edit.text()
        if u and p:
            creds.store_credentials(u, p)
            creds.store_totp_secret(self.totp_edit.text().strip())
            self.controller.login_interactive_async(u, p)
        else:
            self.controller.login_interactive_async()
        self.accept()

    def _logout(self) -> None:
        self.controller.logout()
        self.user_edit.clear()
        self.pass_edit.clear()
        self.totp_edit.clear()
        self.accept()

    # ---------------------------------------------------------- appearance
    def _appearance_tab(self) -> QWidget:
        """Theme: dark, light or follow the system color scheme."""
        s = load_settings()
        w = QWidget()
        outer = QVBoxLayout(w)

        box = QGroupBox("Theme")
        box_layout = QVBoxLayout(box)
        self.radio_system = QRadioButton(
            "System theme\n"
            "Follow the desktop color scheme and switch automatically "
            "when the system changes between light and dark")
        self.radio_light = QRadioButton(
            "Light mode\n"
            "Bright look with the same violet accent")
        self.radio_dark = QRadioButton(
            "Dark mode\n"
            "The original Proto Clean look")
        getattr(self, f"radio_{s.theme if s.theme in THEMES else 'dark'}"
                      ).setChecked(True)
        for r in (self.radio_system, self.radio_light, self.radio_dark):
            box_layout.addWidget(r)
        outer.addWidget(box)

        hint = QLabel(
            "The theme applies immediately and is remembered for the next "
            "launch. The same options live in the Theme ▾ menu of the main "
            "window.")
        hint.setWordWrap(True)
        outer.addWidget(hint)
        outer.addStretch(1)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_appearance)
        outer.addWidget(apply_btn)
        return w

    def _apply_appearance(self) -> None:
        mode = ("system" if self.radio_system.isChecked()
                else "light" if self.radio_light.isChecked() else "dark")
        update(theme=mode)
        from proto_clean.qtcompat import QApplication

        from .theme import apply_theme

        apply_theme(QApplication.instance(), mode)
        self.controller.reload_settings()
        self.accept()

    # ------------------------------------------------------------ protocol
    def _protocol_tab(self) -> QWidget:
        """Which config to download: WireGuard or OpenVPN (+ options)."""
        from ..platforms import capabilities

        s = load_settings()
        p = s.protocol.normalized()
        w = QWidget()
        outer = QVBoxLayout(w)

        caps = capabilities()
        note = QLabel(caps.protocol_note())
        note.setWordWrap(True)
        outer.addWidget(note)

        # ---- protocol selection
        proto_box = QGroupBox("Config to download from the Proton Downloads page")
        proto_row = QHBoxLayout(proto_box)
        self.radio_wireguard = QRadioButton(
            "WireGuard\nModern protocol — best speed and security")
        self.radio_openvpn = QRadioButton(
            "OpenVPN\nWidely compatible; choose TCP or UDP below")
        self.radio_wireguard.setChecked(p.protocol == "wireguard")
        self.radio_openvpn.setChecked(p.protocol == "openvpn")
        proto_row.addStretch(1)
        proto_row.addWidget(self.radio_wireguard)
        proto_row.addSpacing(32)
        proto_row.addWidget(self.radio_openvpn)
        proto_row.addStretch(1)
        outer.addWidget(proto_box)

        # ---- WireGuard options (NAT-PMP + VPN Accelerator, on by default)
        self.wg_box = QGroupBox("WireGuard options (set on the download page)")
        wg_layout = QVBoxLayout(self.wg_box)
        self.wg_natpmp = QCheckBox(
            "NAT-PMP (Port Forwarding)\n"
            "Ask for a forwarded port in the generated config — paid plans; "
            "the external port is shown while connected.")
        self.wg_natpmp.setChecked(s.port_forward.request_in_config)
        self.wg_accel = QCheckBox(
            "VPN Accelerator\n"
            "Proton's performance suite (new TCP/TLS stack for the VPN "
            "endpoints) — enabled on the download page.")
        self.wg_accel.setChecked(s.vpn_options.vpn_accelerator)
        wg_layout.addWidget(self.wg_natpmp)
        wg_layout.addWidget(self.wg_accel)
        outer.addWidget(self.wg_box)

        # ---- OpenVPN options (transport; driver lives in Advanced)
        self.ovpn_box = QGroupBox("OpenVPN options")
        ovpn_layout = QVBoxLayout(self.ovpn_box)
        transport_label = QLabel("<b>Transport</b> (baked into the config):")
        ovpn_layout.addWidget(transport_label)
        t_row = QHBoxLayout()
        self.radio_udp = QRadioButton(
            "UDP\nFaster — the usual choice for streaming and downloads")
        self.radio_tcp = QRadioButton(
            "TCP\nMore reliable on restrictive networks; works through "
            "some firewalls that block UDP")
        self.radio_udp.setChecked(p.openvpn_transport != "tcp")
        self.radio_tcp.setChecked(p.openvpn_transport == "tcp")
        t_row.addStretch(1)
        t_row.addWidget(self.radio_udp)
        t_row.addSpacing(32)
        t_row.addWidget(self.radio_tcp)
        t_row.addStretch(1)
        ovpn_layout.addLayout(t_row)
        ovpn_layout.addWidget(QLabel(
            "The network driver (TUN or TAP) is chosen in Advanced settings."))
        outer.addWidget(self.ovpn_box)

        outer.addStretch(1)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_protocol)
        outer.addWidget(apply_btn)

        self.radio_wireguard.toggled.connect(self._sync_protocol_panes)
        self._sync_protocol_panes()
        return w

    def _sync_protocol_panes(self) -> None:
        wg = self.radio_wireguard.isChecked()
        self.wg_box.setVisible(wg)
        self.ovpn_box.setVisible(not wg)

    def _apply_protocol(self) -> None:
        update(**{
            "protocol.protocol": ("openvpn" if self.radio_openvpn.isChecked()
                                  else "wireguard"),
            "protocol.openvpn_transport": ("tcp" if self.radio_tcp.isChecked()
                                           else "udp"),
            "port_forward.request_in_config": self.wg_natpmp.isChecked(),
            "vpn_options.vpn_accelerator": self.wg_accel.isChecked(),
        })
        self.controller.reload_settings()
        self.accept()

    # ------------------------------------------------------------ advanced
    def _advanced_tab(self) -> QWidget:
        """Advanced connection options (mirrors Proton's Advanced page)."""
        s = load_settings()
        w = QWidget()
        outer = QVBoxLayout(w)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignTop)
        outer.addLayout(form)

        # 1. Alternative routing
        self.adv_alt_routing = QCheckBox(
            "Try Proton's mirror API hosts when the direct ones are blocked")
        self.adv_alt_routing.setChecked(s.advanced.alternative_routing)
        form.addRow("Alternative routing", self.adv_alt_routing)

        # 2. Allow LAN connections
        self.adv_allow_lan = QCheckBox(
            "Keep printers, speakers and other local devices reachable while "
            "the kill switch is on")
        self.adv_allow_lan.setChecked(s.kill_switch.allow_lan)
        form.addRow("Allow LAN connections", self.adv_allow_lan)

        # 3. Custom DNS servers
        self.adv_custom_dns = QCheckBox("Use your own DNS servers")
        self.adv_custom_dns.setChecked(s.advanced.custom_dns_enabled)
        self.custom_dns_edit = QLineEdit(", ".join(s.advanced.custom_dns_servers))
        self.custom_dns_edit.setPlaceholderText("e.g. 1.1.1.1, 9.9.9.9")
        dns_row = QHBoxLayout()
        dns_row.addWidget(self.adv_custom_dns, 1)
        dns_row.addWidget(self.custom_dns_edit, 2)
        form.addRow("Custom DNS servers", dns_row)

        # 4. NAT type
        self.adv_moderate_nat = QCheckBox(
            "Moderate NAT (off = Strict NAT) — paid plans; friendlier for "
            "online gaming / P2P")
        self.adv_moderate_nat.setChecked(s.vpn_options.moderate_nat)
        form.addRow("NAT type", self.adv_moderate_nat)

        # 5. OpenVPN network driver (TAP / TUN) with the requested texts
        driver_box = QGroupBox("OpenVPN network driver")
        driver_box.setToolTip("Only used when the OpenVPN protocol is selected")
        d_layout = QVBoxLayout(driver_box)
        self.radio_tap = QRadioButton(TAP_DESCRIPTION)
        self.radio_tun = QRadioButton(TUN_DESCRIPTION)
        self.radio_tun.setChecked(s.protocol.openvpn_driver != "tap")
        self.radio_tap.setChecked(s.protocol.openvpn_driver == "tap")
        d_layout.addWidget(self.radio_tap)
        d_layout.addWidget(self.radio_tun)
        form.addRow("", driver_box)

        # 6. IPv6 support
        self.adv_ipv6 = QCheckBox(
            "Allow IPv6 traffic to pass through the tunnel — improves "
            "compatibility with IPv6 websites and services")
        self.adv_ipv6.setChecked(s.advanced.ipv6_support)
        form.addRow("IPv6 support", self.adv_ipv6)

        # 7. IPv6 leak protection
        self.adv_ipv6_leak = QCheckBox(
            "Block IPv6 traffic that would bypass the VPN tunnel")
        self.adv_ipv6_leak.setChecked(s.advanced.ipv6_leak_protection)
        form.addRow("IPv6 leak protection", self.adv_ipv6_leak)

        hint = QLabel(
            "Changes apply from the next connection. IPv6 support routes ::/0 "
            "through the tunnel; with leak protection on, any IPv6 outside "
            "the tunnel is blocked (ip6tables PROTO_CLEAN_V6 / pf anchor).")
        hint.setWordWrap(True)
        outer.addWidget(hint)
        outer.addStretch(1)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_advanced)
        outer.addWidget(apply_btn)
        return w

    def _apply_advanced(self) -> None:
        servers = [t.strip() for t in re.split("[,\\s]+",
                                               self.custom_dns_edit.text() or "")
                   if t.strip()]
        if self.adv_custom_dns.isChecked() and not servers:
            QMessageBox.warning(
                self, "ProtoClean",
                "Custom DNS is enabled but no servers are given — add at "
                "least one IP address (e.g. 1.1.1.1) or disable the option.")
            return
        try:
            for srv in servers:
                ipaddress.ip_address(srv)
        except ValueError as e:
            QMessageBox.warning(self, "ProtoClean",
                                f"Not a valid DNS server address: {e}")
            return
        update(**{
            "advanced.alternative_routing": self.adv_alt_routing.isChecked(),
            "kill_switch.allow_lan": self.adv_allow_lan.isChecked(),
            "advanced.custom_dns_enabled": self.adv_custom_dns.isChecked(),
            "advanced.custom_dns_servers": servers,
            "vpn_options.moderate_nat": self.adv_moderate_nat.isChecked(),
            "protocol.openvpn_driver": ("tap" if self.radio_tap.isChecked()
                                        else "tun"),
            "advanced.ipv6_support": self.adv_ipv6.isChecked(),
            "advanced.ipv6_leak_protection": self.adv_ipv6_leak.isChecked(),
        })
        self.controller.reload_settings()
        self.accept()

    # ---------------------------------------------------------- kill switch
    def _killswitch_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        s = load_settings()
        self.ks_enable = QCheckBox(
            "Enable kill switch — block all traffic outside the tunnel\n"
            "(armed before the tunnel starts, so there is no leak window)")
        self.ks_enable.setChecked(s.kill_switch.enabled)
        form.addRow(self.ks_enable)
        note = QLabel(
            "The LAN exception and IPv6 leak protection live in Advanced "
            "settings; the firewall rules themselves are installed by the "
            "privileged helper (iptables on Linux, pf on macOS, Windows "
            "Firewall on Windows).")
        note.setWordWrap(True)
        form.addRow(note)
        open_logs = QPushButton("Open log folder")
        from ..platforms import get_platform
        open_logs.clicked.connect(
            lambda: get_platform().open_folder(str(LOG_DIR)))
        form.addRow(open_logs)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_killswitch)
        form.addRow(apply_btn)
        return w

    def _apply_killswitch(self) -> None:
        update(**{"kill_switch.enabled": self.ks_enable.isChecked()})
        self.controller.reload_settings()
        self.accept()

    # ------------------------------------------------------------- adblock
    def _adblock_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        s = load_settings()
        self.adblock_enable = QCheckBox("Enable local ad & malware blocking "
                                        "(NetShield alternative)")
        self.adblock_enable.setChecked(s.netshield.enabled)
        self.block_nxdomain = QCheckBox("Answer blocked domains with NXDOMAIN "
                                        "(else 0.0.0.0)")
        self.block_nxdomain.setChecked(s.netshield.block_nxdomain)

        manage_btn = QPushButton("Manage blocklists…")
        manage_btn.setToolTip(
            "Add, remove and update the blocklists used for ad blocking")
        manage_btn.clicked.connect(self._manage_blocklists)
        update_btn = QPushButton("Update all blocklists now")
        update_btn.clicked.connect(self._update_blocklists)
        n_lists = len(s.netshield.blocklists)
        n_enabled = len(s.netshield.enabled_lists())
        self.adblock_status = QLabel(
            f"{n_lists} blocklist(s), {n_enabled} enabled · "
            f"last update: {s.netshield.last_update or 'never'} · "
            f"{s.netshield.domain_count:,} domains")
        self.adblock_status.setWordWrap(True)

        form.addRow(self.adblock_enable)
        form.addRow(self.block_nxdomain)
        row = QHBoxLayout()
        row.addWidget(manage_btn)
        row.addWidget(update_btn)
        form.addRow("Blocklists", row)
        form.addRow(self.adblock_status)
        self._adblock_apply_btn = QPushButton("Apply")
        self._adblock_apply_btn.clicked.connect(self._apply_adblock)
        form.addRow(self._adblock_apply_btn)
        return w

    def _manage_blocklists(self) -> None:
        from .blocklists_dialog import BlocklistsDialog

        self._apply_adblock(keep_open=True)
        dlg = BlocklistsDialog(self.controller, self)
        dlg.exec()
        self._refresh_adblock_status()

    def _refresh_adblock_status(self) -> None:
        s = load_settings()
        self.adblock_status.setText(
            f"{len(s.netshield.blocklists)} blocklist(s), "
            f"{len(s.netshield.enabled_lists())} enabled · "
            f"last update: {s.netshield.last_update or 'never'} · "
            f"{s.netshield.domain_count:,} domains")

    def _apply_adblock(self, keep_open: bool = False) -> None:
        update(**{
            "netshield.enabled": self.adblock_enable.isChecked(),
            "netshield.block_nxdomain": self.block_nxdomain.isChecked(),
        })
        self.controller.reload_settings()
        if not keep_open:
            self.accept()

    def _update_blocklists(self) -> None:
        self._apply_adblock()
        self.controller.update_blocklists_async()
        self.accept()

    # --------------------------------------------------------------- split
    def _split_tab(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        from ..platforms import capabilities
        caps = capabilities()
        s = load_settings()
        self.split_enable = QCheckBox("Enable split tunneling (exclude mode)")
        self.split_enable.setChecked(s.split_tunnel.enabled)
        outer.addWidget(self.split_enable)

        outer.addWidget(QLabel(
            "<b>Excluded IP ranges</b> (works on every platform): traffic to "
            "these destinations keeps using the original connection — the "
            "ranges are removed from the tunnel's AllowedIPs."))
        self.cidr_edit = QLineEdit(", ".join(s.split_tunnel.excluded_cidrs))
        self.cidr_edit.setPlaceholderText(
            "e.g. 192.168.1.0/24, 10.0.0.0/8, 2001:db8::/32")
        outer.addWidget(self.cidr_edit)

        outer.addWidget(QLabel(f"<b>Excluded apps</b> — {caps.split_tunnel_note()}"))
        self.app_list = QListWidget()
        for app in s.split_tunnel.excluded_apps:
            self.app_list.addItem(app)
        if not caps.app_split_tunnel:
            self.app_list.setEnabled(False)
        outer.addWidget(self.app_list)
        row = QHBoxLayout()
        add_btn = QPushButton("Add executable…")
        add_btn.clicked.connect(self._add_app)
        launch_btn = QPushButton("Launch excluded…")
        launch_btn.clicked.connect(self._launch_app)
        pid_btn = QPushButton("Move running PID…")
        pid_btn.clicked.connect(self._move_pid)
        rm_btn = QPushButton("Remove")
        rm_btn.clicked.connect(lambda: [
            self.app_list.takeItem(self.app_list.currentRow())
            for _ in [0] if self.app_list.currentRow() >= 0])
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_split)
        for b in (add_btn, launch_btn, pid_btn, rm_btn):
            row.addWidget(b)
            if not caps.app_split_tunnel:
                b.setEnabled(False)
        row.addStretch(1)
        row.addWidget(apply_btn)
        outer.addLayout(row)
        return w

    def _pick_executable(self) -> str:
        import sys
        start = "/usr/bin" if sys.platform != "win32" else ""
        path, _ = QFileDialog.getOpenFileName(self, "Choose an executable", start)
        return path

    def _add_app(self) -> None:
        path = self._pick_executable()
        if path:
            self.app_list.addItem(path)

    def _launch_app(self) -> None:
        path = self._pick_executable()
        if not path:
            return
        if not self.controller.launch_excluded(path):
            return
        if [i for i in range(self.app_list.count())
                if self.app_list.item(i).text() == path] == []:
            self.app_list.addItem(path)
            self._apply_split()

    def _move_pid(self) -> None:
        pid, ok = QInputDialog_getInt(self, "Move process", "PID to exclude:")
        if ok:
            self.controller.move_pid_to_split(int(pid))

    def _apply_split(self) -> None:
        apps = [self.app_list.item(i).text()
                for i in range(self.app_list.count())]
        cidrs = [c.strip() for c in re.split("[,\\s]+", self.cidr_edit.text() or "")
                 if c.strip()]
        try:
            for c in cidrs:
                ipaddress.ip_network(c, strict=False)
        except ValueError as e:
            QMessageBox.warning(self, "ProtoClean",
                                f"Not a valid IP range: {e}")
            return
        update(**{
            "split_tunnel.enabled": self.split_enable.isChecked(),
            "split_tunnel.excluded_apps": apps,
            "split_tunnel.excluded_cidrs": cidrs,
        })
        self.controller.reload_settings()
        self.accept()

    # ------------------------------------------------------------- portfwd
    def _portfwd_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        s = load_settings()
        self.pf_request = QCheckBox(
            "Request NAT-PMP port forwarding when generating the config\n"
            "(the toggle shown in the Protocol tab — repeated here for "
            "convenience; paid plans only)")
        self.pf_request.setChecked(s.port_forward.request_in_config)
        self.pf_internal = QSpinBox()
        self.pf_internal.setRange(0, 65535)
        self.pf_internal.setValue(s.port_forward.internal_port)
        self.pf_internal.setToolTip(
            "Local (internal) port that receives the forwarded traffic. "
            "0 = map a generic port.")
        form.addRow(self.pf_request)
        form.addRow("Internal service port", self.pf_internal)
        pf_note = QLabel(
            "While connected, Proto Clean keeps the NAT-PMP lease alive "
            "(gateway 10.2.0.1, ~60s lease, refreshed at 45s) and shows the "
            "external port in the main window. Works over both WireGuard and "
            "OpenVPN tunnels.")
        pf_note.setWordWrap(True)
        form.addRow(pf_note)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_portfwd)
        form.addRow(apply_btn)
        return w

    def _apply_portfwd(self) -> None:
        update(**{
            "port_forward.request_in_config": self.pf_request.isChecked(),
            "port_forward.internal_port": self.pf_internal.value(),
        })
        self.controller.reload_settings()
        self.accept()


def QInputDialog_getInt(parent, title, label, value=0):  # noqa: N802
    from proto_clean.qtcompat import QInputDialog

    return QInputDialog.getInt(parent, title, label, value)

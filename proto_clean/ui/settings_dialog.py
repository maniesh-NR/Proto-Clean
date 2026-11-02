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
    QPushButton, QRadioButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
    QMessageBox,
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
        tabs.addTab(self._xray_tab(), "Xray proxy")

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.clicked.connect(lambda _: self.accept())

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    # ------------------------------------------------------------ Xray
    def _xray_tab(self) -> QWidget:
        """Xray-core proxy profile: VLESS + REALITY (SNI masking) or Trojan.

        Fields can be filled from a vless:// / trojan:// share URL. The
        proxy runs xray locally (SOCKS + HTTP inbounds) and optionally
        switches the system proxy.
        """
        w = QWidget()
        form = QFormLayout(w)
        s = self.controller.settings.xray.normalized()

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

        import_btn = QPushButton("Import share URL…")
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

        self.xray_status = QLabel(self._xray_status_text())
        self.xray_status.setWordWrap(True)

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
        form.addRow("", btns)
        form.addRow("", self.xray_status)
        form.addRow("", QLabel(
            "Requires the Xray-core binary (xray) on PATH or "
            "PROTO_CLEAN_XRAY_BIN — see README. The config is stored "
            "locally with your credentials and never uploaded."))

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
        self.controller.add_proxy_listener(self._xray_on_proxy_state)
        return w

    def _xray_collect(self):
        from ..settings import XraySettings
        return XraySettings(
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
        ).normalized()

    def _xray_persist(self, *_) -> None:
        self.controller.save_xray_settings(self._xray_collect())

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
            from ..vpn.xray import find_xray_binary
            if not find_xray_binary():
                text += "\n(xray binary not found — see README to install Xray-core)"
        return text

    # ------------------------------------------------------------- account
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

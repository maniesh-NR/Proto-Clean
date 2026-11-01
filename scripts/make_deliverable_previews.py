"""Generate the deliverable preview images for the new settings UI.

Produces (into download/):
  proton_clean-settings-protocol-wireguard.png  Protocol tab, WireGuard selected
  proton_clean-settings-protocol-openvpn.png    Protocol tab, OpenVPN selected
  proton_clean-settings-advanced.png            Advanced tab (defaults)
  proton_clean-settings-appearance.png          Appearance tab (theme options)
  proton_clean-settings-preview.png             Advanced tab (legacy name kept)

QT_QPA_PLATFORM=offscreen python scripts/make_deliverable_previews.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QTabWidget  # noqa: E402

from proton_clean.controller import Controller  # noqa: E402
from proton_clean.settings import update, load_settings  # noqa: E402
from proton_clean.ui.settings_dialog import SettingsDialog  # noqa: E402
from proton_clean.ui.theme import apply_theme  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "..", "download")

app = QApplication([])
apply_theme(app, "dark")
controller = Controller()

def snapshot(protocol: str, tab: str, out_name: str) -> None:
    update(**{"protocol.protocol": protocol})
    controller.reload_settings()
    dlg = SettingsDialog(controller)
    dlg.resize(700, 620)
    dlg.show()
    tabs = dlg.findChild(QTabWidget)
    for i in range(tabs.count()):
        if tabs.tabText(i) == tab:
            tabs.setCurrentIndex(i)
            break
    app.processEvents()
    path = os.path.join(OUT, out_name)
    dlg.grab().save(path)
    print("saved", path)
    dlg.deleteLater()
    app.processEvents()

# clean defaults first (the sandbox settings.json carried test values)
update(**{
    "protocol.protocol": "wireguard",
    "protocol.openvpn_transport": "udp",
    "protocol.openvpn_driver": "tun",
    "advanced.custom_dns_enabled": False,
    "advanced.custom_dns_servers": [],
    "advanced.ipv6_support": False,
    "advanced.ipv6_leak_protection": True,
    "advanced.alternative_routing": True,
    "kill_switch.allow_lan": False,
    "vpn_options.moderate_nat": False,
})
assert load_settings().protocol.protocol == "wireguard"

snapshot("wireguard", "Protocol", "proton_clean-settings-protocol-wireguard.png")
snapshot("openvpn", "Protocol", "proton_clean-settings-protocol-openvpn.png")
snapshot("wireguard", "Advanced", "proton_clean-settings-advanced.png")
snapshot("wireguard", "Appearance", "proton_clean-settings-appearance.png")

import shutil  # noqa: E402
shutil.copy(os.path.join(OUT, "proton_clean-settings-advanced.png"),
            os.path.join(OUT, "proton_clean-settings-preview.png"))
print("legacy preview refreshed")

controller.shutdown()
print("OK")

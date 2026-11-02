"""Render every Settings dialog tab offscreen with seeded data — smoke test
plus preview images for the deliverables.

QT_QPA_PLATFORM=offscreen python scripts/ui_screenshot_settings.py [out-prefix]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QTabWidget, QRadioButton  # noqa: E402

from proto_clean.controller import Controller  # noqa: E402
from proto_clean.settings import update  # noqa: E402
from proto_clean.ui.settings_dialog import SettingsDialog  # noqa: E402
from proto_clean.ui.theme import apply_theme  # noqa: E402

# seed a few interesting values so both protocols' panes are populated
update(**{
    "split_tunnel.enabled": True,
    "split_tunnel.excluded_cidrs": ["192.168.1.0/24", "10.8.0.0/16"],
    "split_tunnel.excluded_apps": ["/usr/bin/deluge"],
    "advanced.custom_dns_enabled": True,
    "advanced.custom_dns_servers": ["1.1.1.1", "9.9.9.9"],
    "protocol.protocol": "openvpn",        # so the OpenVPN pane renders
    "protocol.openvpn_transport": "tcp",
})

app = QApplication([])
apply_theme(app, "dark")
controller = Controller()
dlg = SettingsDialog(controller)
dlg.resize(700, 600)
dlg.show()

tabs = dlg.findChild(QTabWidget)
out_prefix = (sys.argv[1] if len(sys.argv) > 1
              else "/tmp/protoclean-settings")

# render both the WireGuard and the OpenVPN variant of the Protocol tab
for protocol, transport in (("wireguard", "udp"), ("openvpn", "tcp")):
    update(**{"protocol.protocol": protocol,
              "protocol.openvpn_transport": transport})
    controller.reload_settings()
    dlg2 = SettingsDialog(controller)
    dlg2.resize(700, 600)
    dlg2.show()
    t2 = dlg2.findChild(QTabWidget)
    for i in range(t2.count()):
        name = t2.tabText(i).lower().replace(" ", "-")
        if name in ("protocol", "advanced"):
            t2.setCurrentIndex(i)
            app.processEvents()
            path = f"{out_prefix}-{protocol}-{name}.png"
            dlg2.grab().save(path)
            print("saved", path)
    dlg2.deleteLater()

# every tab must render without exceptions
assert tabs is not None, "settings dialog has no tabs"
expected = ["Account", "Appearance", "Protocol", "Advanced", "Kill switch",
            "Ad blocking", "Split tunneling", "Port forwarding"]
names = [tabs.tabText(i) for i in range(tabs.count())]
assert names == expected, f"unexpected tab order: {names}"
for i in range(tabs.count()):
    tabs.setCurrentIndex(i)
    app.processEvents()
print("all tabs rendered:", names)

# the driver descriptions requested verbatim must be present
from proto_clean.ui.settings_dialog import TAP_DESCRIPTION, TUN_DESCRIPTION  # noqa: E402
wg_dlg = SettingsDialog(controller)
assert TAP_DESCRIPTION.startswith("TAP: Bridges network traffic.")
assert TUN_DESCRIPTION.startswith("TUN: Routes traffic between")
print("driver descriptions verified")
controller.shutdown()
print("OK")

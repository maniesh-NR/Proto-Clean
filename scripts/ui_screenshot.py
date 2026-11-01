"""Render the main window offscreen with fake data and save screenshots:

QT_QPA_PLATFORM=offscreen python scripts/ui_screenshot.py [out.png] [mode] [theme]

mode: "all" (main + menus + dialogs), "login" (banner + dialog) or omitted.
theme: dark | light | system (default from settings).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from proton_clean.controller import Controller  # noqa: E402
from proton_clean.netshield.blocklists import BlocklistEntry  # noqa: E402
from proton_clean.servers.models import LogicalServer  # noqa: E402
from proton_clean.ui.main_window import MainWindow  # noqa: E402


def _mk(name, cc, city, load, score, tier=0, features=0):
    return LogicalServer(id=name, name=name, entry_country=cc, exit_country=cc,
                         domain=f"{name}.protonvpn.net", tier=tier,
                         features=features, city=city, load=load, score=score)


FAKE = [
    _mk("NL-FREE#1", "NL", "Amsterdam", 22.5, 0.83),
    _mk("US-FREE#2", "US", "New York City", 48.0, 1.12),
    _mk("JP-FREE#3", "JP", "Tokyo", 91.0, 2.40),
    _mk("US-FREE#1", "US", "Seattle", 35.7, 1.05),
    _mk("CH-FREE#9", "CH", "Zurich", 63.0, 1.44),
    # paid servers — these must NOT appear in the table anymore
    _mk("NL#12", "NL", "Assen", 12.0, 0.60, tier=2, features=4),
    _mk("SE#8", "SE", "Stockholm", 55.0, 1.30, tier=1, features=4),
    _mk("CH#5", "CH", "Zurich", 63.0, 1.44, tier=2, features=1),
]

FAKE_BLOCKLISTS = [
    BlocklistEntry(name="StevenBlack unified (ads + malware)",
                   url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                   enabled=True, domains=76736, updated_at="2025-11-01 09:12"),
    BlocklistEntry(name="HaGeZi Pro",
                   url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
                   enabled=True, domains=112458, updated_at="2025-11-01 09:12"),
    BlocklistEntry(name="Peter Lowe's ad servers",
                   url="https://pgl.yoyo.org/adservers/serverlist.php",
                   enabled=False, domains=3871, updated_at="2025-10-28 22:40"),
]

app = QApplication([])
from proton_clean.ui.theme import apply_theme  # noqa: E402

theme = sys.argv[3] if len(sys.argv) > 3 else "dark"
# persist the rendered theme so menus/dialogs show a matching checkmark
from proton_clean.settings import update as _update  # noqa: E402

_update(theme=theme)
apply_theme(app, theme)
# the script owns the theme — stop MainWindow from re-applying settings
app.setProperty("proton_clean_theme_applied", True)
controller = Controller()
controller.blocklist_entries = lambda: list(FAKE_BLOCKLISTS)
window = MainWindow(controller)
window.resize(900, 660)
window.show()
window._servers = FAKE
window._refresh_table()
window._on_state("logged_in", "logged in")
window._on_stats({"up": True, "rx": 148_234_112, "tx": 12_302_112,
                  "handshake_age": 4.0, "endpoint": "185.107.56.130:51820"})
window._on_servers(FAKE)
window._on_blocklists(FAKE_BLOCKLISTS)
window._on_port(51827)
out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/protonclean-ui.png"
window.grab().save(out)
print("saved", out)


def _save_with_popup(window, popup, out_path) -> None:
    """Window grab with the popup menu pasted in (offscreen popups are
    separate top-level windows, so window.grab() alone misses them).
    The canvas is extended so a menu hanging over the window's bottom
    edge stays fully visible."""
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtCore import QPoint

    base = window.grab().toImage()
    popup_img = popup.grab().toImage()
    delta = popup.mapToGlobal(QPoint(0, 0)) - window.mapToGlobal(QPoint(0, 0))
    w = max(base.width(), delta.x() + popup_img.width())
    h = max(base.height(), delta.y() + popup_img.height())
    canvas = QImage(w, h, QImage.Format_ARGB32)
    canvas.fill(0)
    p = QPainter(canvas)
    p.drawImage(0, 0, base)
    p.drawImage(delta, popup_img)
    p.end()
    canvas.save(out_path)
    print("saved", out_path)


if len(sys.argv) > 2 and sys.argv[2] == "all":
    prefix = out.rsplit(".", 1)[0]

    # ---- theme menu, open under its button
    tmenu = window.theme_menu
    window._rebuild_theme_menu()
    tbtn = window.theme_btn
    pos = tbtn.mapTo(window, tbtn.rect().bottomLeft())
    tmenu.move(window.mapToGlobal(pos))
    tmenu.show()
    tmenu.activateWindow()
    app.processEvents()
    _save_with_popup(window, tmenu, f"{prefix}-theme-menu.png")
    tmenu.hide()

    # ---- blocklists menu, open under its button
    menu = window.blocklists_menu
    window._rebuild_blocklists_menu()
    btn = window.blocklists_btn
    pos = btn.mapTo(window, btn.rect().bottomLeft())
    menu.move(window.mapToGlobal(pos))
    menu.show()
    menu.activateWindow()
    app.processEvents()
    _save_with_popup(window, menu, f"{prefix}-menu.png")
    menu.hide()

    # ---- manage dialog
    from proton_clean.ui.blocklists_dialog import BlocklistsDialog  # noqa: E402

    dlg = BlocklistsDialog(controller, window)
    dlg.refresh(FAKE_BLOCKLISTS)
    dlg.show()
    app.processEvents()
    dlg_out = f"{prefix}-dialog.png"
    dlg.grab().save(dlg_out)
    print("saved", dlg_out)

if len(sys.argv) > 2 and sys.argv[2] in ("all", "login"):
    # ---- login experience: CAPTCHA banner + login dialog
    from proton_clean.ui.login_dialog import LoginDialog  # noqa: E402

    window._on_login_event(
        "captcha", "human verification required — browser window opened")
    app.processEvents()
    login_out = out.rsplit(".", 1)[0] + "-login-banner.png"
    window.grab().save(login_out)
    print("saved", login_out)

    window._hide_login_banner()
    dlg = LoginDialog(controller, window, prefill_username="ischos")
    dlg.show()
    app.processEvents()
    dlg_out = out.rsplit(".", 1)[0] + "-login-dialog.png"
    dlg.grab().save(dlg_out)
    print("saved", dlg_out)

controller.shutdown()

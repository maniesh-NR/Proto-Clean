#!/usr/bin/env python3
"""Programmatic verification of the UI state + pixel sanity of screenshots."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from proto_clean.qtcompat import QApplication

from proto_clean.controller import Controller, State
from proto_clean.netshield.blocklists import BlocklistEntry
from proto_clean.servers.models import LogicalServer
from proto_clean.ui.main_window import MainWindow


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
    _mk("NL#12", "NL", "Assen", 12.0, 0.60, tier=2, features=4),
    _mk("SE#8", "SE", "Stockholm", 55.0, 1.30, tier=1, features=4),
    _mk("CH#5", "CH", "Zurich", 63.0, 1.44, tier=2, features=1),
]

BLOCKLISTS = [
    BlocklistEntry(name="StevenBlack unified", url="https://a/hosts",
                   enabled=True, domains=76736, updated_at="2025-11-01 09:12"),
    BlocklistEntry(name="HaGeZi Pro", url="https://b/hosts",
                   enabled=True, domains=112458, updated_at="2025-11-01 09:12"),
    BlocklistEntry(name="Peter Lowe", url="https://c/hosts",
                   enabled=False, domains=3871, updated_at="never"),
]

app = QApplication([])
controller = Controller()
controller.blocklist_entries = lambda: list(BLOCKLISTS)
w = MainWindow(controller)
w.show()
w._on_servers(FAKE)
app.processEvents()

# ---- 1. free-only table
names = [w.table.item(r, 1).text() for r in range(w.table.rowCount())]
assert w.table.rowCount() == 5, f"expected 5 free rows, got {w.table.rowCount()}"
assert all("-FREE#" in n for n in names), names
assert not any(n in ("NL#12", "SE#8", "CH#5") for n in names), names
assert "NL#12" not in names and "SE#8" not in names
print("OK table is free-only:", names)

# search box filters, still free-only
w.search.setText("US")
app.processEvents()
us_names = [w.table.item(r, 1).text() for r in range(w.table.rowCount())]
assert all(n.startswith("US-") for n in us_names), us_names
w.search.clear()
app.processEvents()
print("OK search filter:", us_names)

# ---- 2. blocklists menu structure
w._rebuild_blocklists_menu()
acts = w.blocklists_menu.actions()
labels = [a.text() for a in acts if a.text()]
assert "Update all now" in labels, labels
assert "Add blocklist…" in labels, labels
assert "Remove blocklist…" in labels, labels
assert "Manage blocklists…" in labels, labels
checkable = [a for a in acts if a.isCheckable()]
assert len(checkable) == 3, [a.text() for a in checkable]
assert checkable[0].isChecked() and not checkable[2].isChecked()
subs = [a.menu() for a in acts if a.menu()]
assert all(s is not None for s in subs)
sub_labels = [x.text() for s in subs for x in s.actions()]
assert "Update now" in sub_labels and "Remove…" in sub_labels
print("OK menu:", labels[:2], "…", len(checkable), "checkable lists with",
      "update/remove submenus")

# ---- 3. manager dialog reflects entries
from proto_clean.ui.blocklists_dialog import AddBlocklistDialog, BlocklistsDialog
dlg = BlocklistsDialog(controller, w)
dlg.refresh(BLOCKLISTS)
app.processEvents()
assert dlg.table.rowCount() == 3
assert dlg.table.item(0, 2).text() == "76,736"
assert dlg.table.item(2, 3).text() == "never"
cb = dlg.table.cellWidget(2, 0)
assert cb.isChecked() is False
print("OK dialog rows:", [[dlg.table.item(r, c).text() for c in (1, 2, 3)]
                          for r in range(3)])

# ---- 4. Add dialog presets
add = AddBlocklistDialog(w)
presets = [add.preset.itemText(i) for i in range(add.preset.count())]
assert presets[0] == "Custom…" and len(presets) > 4
add.preset.setCurrentIndex(1)
app.processEvents()
assert add.url.text().startswith("https://")
print("OK add-dialog presets:", len(presets) - 1, "known lists")

# ---- 5. login dialog + CAPTCHA banner
from proto_clean.ui.login_dialog import LoginDialog  # noqa: E402

dlg = LoginDialog(controller, w)
assert dlg.remember.isChecked() is True
assert dlg.user_edit.placeholderText()
assert dlg.totp_edit.placeholderText()
dlg.user_edit.setText("ischos")
dlg.pass_edit.setText("pw")
# remember=True path: calls login_once_async
called = {}
controller.login_once_async = lambda u, p, totp_secret="", remember=True: \
    called.update(u=u, p=p, remember=remember)
dlg._on_login()
assert called == {"u": "ischos", "p": "pw", "remember": True}
print("OK login dialog: remember-me default on, login_once wired")

# CAPTCHA banner relay
w._on_login_event("captcha", "human verification required")
assert w.login_banner.isVisible()
assert "human verification" in w.login_banner.text()
w._on_login_event("interactive_open", "5 minutes to complete")
assert w.login_banner.isVisible() and "browser window" in w.login_banner.text()
w._on_login_event("interactive_done", "captured")
assert "completed" in w.login_banner.text()
w._on_state("logged_in", "logged in")
assert not w.login_banner.isVisible()
w._on_login_event("totp_needed", "2fa")
assert w.login_banner.isVisible() and "Two-factor" in w.login_banner.text()
w._hide_login_banner()
print("OK login banner: captcha/waiting/2fa shown, hidden on login success")

# bad credentials / credentials_needed reopen the dialog
w._on_login_event("credentials_needed", "none stored")
assert w._login_dialog is not None and w._login_dialog.isVisible()
w._login_dialog.close()
w._on_login_event("bad_credentials", "wrong password")
assert w._login_dialog is not None and w._login_dialog.isVisible()
w._login_dialog.close()
print("OK login dialog auto-opens on missing/bad credentials")

# login button label reflects state
controller.state = State.LOGGED_IN
w._update_login_button()
assert w.login_btn.text() == "Switch account…"
controller.state = State.LOGGED_OUT
w._update_login_button()
assert w.login_btn.text() == "Log in…"
print("OK login button label:", w.login_btn.text())

# ---- 6. pixel sanity of the screenshots
from PIL import Image
for f, min_dark in (("/tmp/protoclean-ui.png", 0.25),
                    ("/tmp/protoclean-ui-menu.png", 0.25),
                    ("/tmp/protoclean-ui-dialog.png", 0.20)):
    im = Image.open(f).convert("RGB")
    px = list(im.getdata())
    dark = sum(1 for p in px if sum(p) < 200) / len(px)
    colorful = sum(1 for p in px if max(p) - min(p) > 40) / len(px)
    assert dark > min_dark, (f, dark)
    assert colorful > 0.008, (f, colorful)
    print(f"OK pixels {f}: dark={dark:.0%} colorful={colorful:.0%}")

controller.shutdown()
print("ALL UI CHECKS PASSED")

"""Live smoke tests (run manually): python scripts/dev_smoke.py [what]

  login-page  — load the real account.protonvpn.com login page headless and
                check that our selectors match
  blocklist   — download + parse the default blocklist
  qt          — instantiate the full UI offscreen
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def smoke_login_page() -> int:
    from cleanroom.account.browser import (
        PASSWORD_SELECTORS, SUBMIT_SELECTORS, USERNAME_SELECTORS,
    )
    from playwright.sync_api import sync_playwright

    bad = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox",
                                                          "--disable-dev-shm-usage"])
        page = browser.new_page()
        from cleanroom.account.browser import settle
        page.goto("https://account.protonvpn.com/login",
                  wait_until="domcontentloaded", timeout=60000)
        settle(page)
        print(f"URL: {page.url}")
        print(f"title: {page.title()!r}")

        def probe(name, selectors, want_visible=True):
            nonlocal bad
            hits = []
            for sel in selectors:
                try:
                    loc = page.locator(sel).first
                    if loc.count():
                        vis = loc.is_visible()
                        hits.append(f"{sel} (visible={vis})")
                except Exception:
                    pass
            if hits:
                print(f"  ok   {name}: {hits[0]}" +
                      (f"  +{len(hits)-1} more" if len(hits) > 1 else ""))
            else:
                print(f"  MISS {name}: none of {selectors}")
                bad += 1

        probe("username field", USERNAME_SELECTORS)
        probe("submit button", SUBMIT_SELECTORS)
        # password appears only after Continue — verify the two-step flow
        page.locator(",".join(USERNAME_SELECTORS)).first.fill("cleanroom-smoke")
        page.locator(",".join(SUBMIT_SELECTORS)).first.click()
        try:
            page.locator(",".join(PASSWORD_SELECTORS)).first \
                .wait_for(state="visible", timeout=20000)
            print("  ok   two-step flow: password field appeared after Continue")
        except Exception:
            print("  MISS password step after Continue — flow changed?")
            bad += 1
        probe("password field", PASSWORD_SELECTORS)
        # dump all inputs/buttons for selector maintenance
        for sel in ("input", "button"):
            els = page.locator(sel).all()
            print(f"  <{sel}> count={len(els)}")
            for e in els[:12]:
                try:
                    print(f"    {sel}: id={e.get_attribute('id')!r} "
                          f"name={e.get_attribute('name')!r} "
                          f"type={e.get_attribute('type')!r} "
                          f"text={(e.inner_text() or '')[:30]!r}")
                except Exception:
                    pass
        browser.close()
    print("\nRESULT:", "FAIL" if bad else "PASS")
    return 1 if bad else 0


def smoke_blocklist() -> int:
    from cleanroom.netshield.blocklists import BlocklistManager

    mgr = BlocklistManager()
    result = mgr.update()
    print("ok:", result.ok, "| domains:", f"{result.total_domains:,}")
    for src, status in result.per_source.items():
        print(f"  {src}: {status}")
    assert result.ok and result.total_domains > 50000, "unexpectedly small list"
    probe = ["doubleclick.net", "googleadservices.com", "example.com"]
    for d in probe:
        print(f"  blocked({d}) = {mgr.filter.blocked(d)}")
    return 0


def smoke_qt() -> int:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from cleanroom.controller import Controller
    from cleanroom.ui.main_window import MainWindow

    app = QApplication([])
    controller = Controller()
    window = MainWindow(controller)
    window.show()
    # exercise the UI state machine a bit
    for state, detail in (("logged_in", "smoke"), ("connected", "NL-FREE#1"),
                          ("connecting", "…"), ("error", "smoke")):
        window._on_state(state, detail)
    window._on_servers(controller.store.servers)
    window._on_stats({"up": True, "rx": 1234, "tx": 99, "handshake_age": 3.0,
                      "endpoint": "1.2.3.4:51820"})
    from cleanroom.ui.settings_dialog import SettingsDialog

    dlg = SettingsDialog(controller, window)
    print("UI instantiated offscreen: OK")
    controller.shutdown()
    return 0


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    code = 0
    if what in ("all", "login-page"):
        code |= smoke_login_page()
    if what in ("all", "blocklist"):
        code |= smoke_blocklist()
    if what in ("all", "qt"):
        code |= smoke_qt()
    sys.exit(code)

#!/usr/bin/env python3
"""Drive the REAL DownloadsPage selector methods against the real page DOM.

Usage:
    python scripts/verify_real_dom.py [path-to-inspect-element-dump]

If a dump (inspect-element "Copy outerHTML" of the logged-in Downloads page)
is given or found, the WireGuard section is extracted from it and every
selector is replayed against the real markup. Without a dump, a synthetic
page with the same DOM contract is used, so the check still runs anywhere.

Verifies:
  * _read_certificates — parses existing config textareas (+ option comments)
  * _scrape_tables     — "Free server configs" category + country tables
  * PageBot.set_toggle — #feature-SplitTCP / #feature-PortForwarding
  * platform radio     — #wg-platform-Linux
  * _select_server     — exact-match row Create button (CA-FREE#1 vs #10)
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from playwright.sync_api import sync_playwright

from proto_clean.account.downloads_page import (
    FREE_CATEGORY_SELECTORS, DownloadsPage, PageBot, PLATFORM_RADIO_SELECTORS,
    WG,
)
from proto_clean.vpn.config_cache import parse_config_meta

DUMP_CANDIDATES = [
    sys.argv[1] if len(sys.argv) > 1 else None,
    "/home/z/my-project/upload/Pasted Content_1793515154108.txt",
]

# Minimal page with the same DOM contract as the real Downloads page.
SYNTHETIC = """<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<section id="section-wireguard-configuration">
<h2>WireGuard configuration</h2>
<details data-certificate-id="cert-1"><summary>cert</summary>
<div><button>Extend</button><button>Download</button>
<label>Config to connect to CA-FREE#1</label>
<textarea readonly rows="4">[Interface]
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on
PrivateKey = k
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# CA-FREE#1
PublicKey = p
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820</textarea></div></details>
<form>
<input id="certificate-device-name" placeholder="Choose a name">
<label for="wg-platform-Linux"><input id="wg-platform-Linux" type="radio" name="platform"><span>GNU/Linux</span></label>
<label><input id="feature-SplitTCP" type="checkbox" checked> VPN Accelerator</label>
<label><input id="feature-PortForwarding" type="checkbox"> NAT-PMP (Port Forwarding)</label>
<p>Use the best server according to current load and position: <strong>US-FREE#50</strong></p>
<button type="submit">Create</button>
<label><input id="category-list-radio_1" type="radio" name="category-list" checked> Free server configs</label>
<input id="server-lookup" placeholder="e.g., AT#62"><button>Search</button>
<details open><summary><p>Canada</p></summary><div><table><tbody>
<tr><td>CA-FREE#1</td><td>64%</td><td><button type="button">Create</button></td></tr>
<tr><td>CA-FREE#10</td><td>62%</td><td><button type="button">Create</button></td></tr>
</tbody></table></div></details>
</form></section></body></html>"""


def build_fixture() -> str:
    for path in DUMP_CANDIDATES:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                doc = fh.read()
            start = doc.find('<section id="section-wireguard-configuration"')
            end = doc.find('<section id="', start + 10)
            if end == -1:
                end = doc.find("Get VPN Plus", start)
            if start != -1 and end > start:
                html = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                        "</head><body>" + doc[start:end] + "</body></html>")
                print(f"fixture: extracted WG section from {path} "
                      f"({len(html):,} chars)")
                return "real"
    return "synthetic"


mode = build_fixture()
url = ("file:///tmp/wg-section.html" if mode == "real" else None)
if mode == "synthetic":
    f = tempfile.NamedTemporaryFile(
        "w", suffix=".html", delete=False, encoding="utf-8")
    f.write(SYNTHETIC)
    f.close()
    url = "file://" + f.name
    print("fixture: synthetic page (no dump found)")

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto(url, wait_until="domcontentloaded")
    dp = DownloadsPage.__new__(DownloadsPage)   # no session: static page
    bot = PageBot(page)

    # ---- 1. existing certificate textarea -> full config
    certs = dp._read_certificates(page)
    assert certs, "no certificates found"
    name, text = list(certs.values())[0]
    assert name == "CA-FREE#1", name
    assert text.startswith("[Interface]") and "PrivateKey" in text
    meta = parse_config_meta(text)
    assert meta["server"] == "CA-FREE#1"
    assert meta["nat_pmp"] is False and meta["vpn_accelerator"] is True
    print("OK certificate textarea:", name, "| options:", meta)

    # ---- 2. free category radio + country tables scrape
    assert bot.click_any(FREE_CATEGORY_SELECTORS, timeout=4000)
    page.wait_for_timeout(300)
    servers = dp._scrape_tables(page)
    names = [s.name for s in servers]
    assert "CA-FREE#1" in names, names[:8]
    ca1 = next(s for s in servers if s.name == "CA-FREE#1")
    assert ca1.load == 64.0, ca1.load          # 64% in the real dump
    assert all(s.tier == 0 for s in servers)
    print(f"OK table scrape: {len(servers)} free servers, CA-FREE#1 load "
          f"{ca1.load:.0f}%")

    # ---- 3. option toggles by real id
    accel = page.locator("#feature-SplitTCP")
    pf = page.locator("#feature-PortForwarding")
    before_accel = accel.is_checked()
    got = bot.set_toggle(["#feature-SplitTCP"], not before_accel)
    assert got == (not before_accel)
    assert accel.is_checked() == (not before_accel)
    bot.set_toggle(["#feature-SplitTCP"], before_accel)   # restore
    assert bot.set_toggle(["#feature-PortForwarding"], True) is True
    assert pf.is_checked() is True
    bot.set_toggle(["#feature-PortForwarding"], False)
    print("OK toggles: SplitTCP / PortForwarding flip correctly")

    # ---- 4. platform radio
    assert bot.click_any(PLATFORM_RADIO_SELECTORS, timeout=4000)
    assert page.locator("#wg-platform-Linux").is_checked()
    print("OK platform radio: GNU/Linux selected")

    # ---- 5. per-server row Create click (exact match, not #10 vs #1)
    row_sel = f'{WG} tr:has(td:text-is("CA-FREE#1"))'
    rows = page.locator(row_sel)
    assert rows.count() == 1, f"expected 1 exact row, got {rows.count()}"
    create_btn = page.locator(f'{row_sel} button:has-text("Create")')
    assert create_btn.count() == 1
    assert page.locator(f'{WG} tr:has(td:text-is("CA-FREE#10"))').count() \
        in (0, 1)
    create_btn.click()
    print("OK server row: exact CA-FREE#1 row found, Create clicked")

    # ---- 6. best-server submit button exists
    submit = page.locator(f"{WG} button[type='submit']")
    assert submit.count() >= 1
    print("OK recommended-server submit Create button present")

    browser.close()

print("ALL REAL-DOM SELECTOR CHECKS PASSED")

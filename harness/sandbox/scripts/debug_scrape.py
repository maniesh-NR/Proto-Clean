#!/usr/bin/env python3
"""Debug why _scrape_tables returns empty on the extracted real DOM."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from playwright.sync_api import sync_playwright

URL = "file:///tmp/wg-section.html"

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto(URL, wait_until="domcontentloaded")

    WG = "#section-wireguard-configuration"
    print("section count:", page.locator(WG).count())
    print("tbody tr count:", page.locator(f"{WG} tbody tr").count())
    print("tr count:", page.locator(f"{WG} tr").count())
    print("details count:", page.locator(f"{WG} details").count())
    print("table count:", page.locator(f"{WG} table").count())

    # how many details are open?
    n_open = page.evaluate(
        "Array.from(document.querySelectorAll('"
        + WG.replace("#", "#")
        + " details')).filter(d => d.open).length")
    print("details open:", n_open)

    # sample first rows text
    rows = page.locator(f"{WG} tbody tr")
    for i in range(min(3, rows.count())):
        print(f"row {i} inner_text:", repr(rows.nth(i).inner_text())[:120])

    # try opening all details
    page.evaluate(
        "Array.from(document.querySelectorAll('" + WG + " details'))"
        ".forEach(d => d.open = true)")
    print("after force-open, row0:", repr(rows.nth(0).inner_text())[:120])
    print("total rows now visible:",
          sum(1 for i in range(rows.count()) if rows.nth(i).inner_text()))

    browser.close()

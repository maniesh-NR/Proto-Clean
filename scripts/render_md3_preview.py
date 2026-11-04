"""Render an HTML preview of the Proto Clean Material Design 3 UI.

Since the sandbox lacks libEGL.so.1 (PySide6.QtGui can't import), we
can't render the actual Qt UI offscreen. Instead we generate an HTML
page that paints the same widgets using the MD3 color roles from
proto_clean/ui/md3.py and the same widget object names — QSS selectors
translate almost 1:1 to CSS. Playwright (already a project dep) renders
the HTML to a PNG so we can visually verify the MD3 look.

Output: /home/z/my-project/download/md3_preview.png + .html
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from proto_clean.ui.md3 import (
    DARK_SCHEME,
    LIGHT_SCHEME,
    MaterialScheme,
    md3_qss,
)


def _scheme_css(scheme: MaterialScheme) -> str:
    """Emit CSS custom properties for every MD3 color role."""
    roles = [
        "primary", "on_primary", "primary_container", "on_primary_container",
        "secondary", "on_secondary", "secondary_container", "on_secondary_container",
        "tertiary", "on_tertiary", "tertiary_container", "on_tertiary_container",
        "error", "on_error", "error_container", "on_error_container",
        "background", "on_background",
        "surface", "on_surface",
        "surface_variant", "on_surface_variant",
        "surface_dim", "surface_bright",
        "surface_container_lowest", "surface_container_low",
        "surface_container", "surface_container_high",
        "surface_container_highest",
        "outline", "outline_variant",
        "inverse_surface", "inverse_on_surface", "inverse_primary",
        "scrim", "shadow",
    ]
    lines = []
    for r in roles:
        v = getattr(scheme, r, None)
        if v:
            lines.append(f"  --md3-{r.replace('_', '-')}: {v};")
    return "\n".join(lines)


def _qss_to_css(qss: str) -> str:
    """Translate QSS to CSS: drop Qt-only selectors and adapt properties
    that differ. The result is approximation good enough for preview."""
    css = qss
    # QSS-only pseudo-states that CSS doesn't understand → drop or alias.
    css = css.replace("QPushButton:hover", ".btn:hover") \
             .replace("QPushButton:pressed", ".btn:active") \
             .replace("QPushButton:disabled", ".btn:disabled") \
             .replace("QLineEdit:focus, QComboBox:focus, QSpinBox:focus",
                      ".input:focus") \
             .replace("QPushButton#Connect", ".btn-connect") \
             .replace("QPushButton#Disconnect", ".btn-disconnect") \
             .replace("QPushButton#GuestButton", ".btn-guest") \
             .replace("QPushButton", ".btn") \
             .replace("QLineEdit, QComboBox, QSpinBox", ".input") \
             .replace("QLabel#Title", ".title") \
             .replace("QLabel#Subtitle, QLabel#Stats", ".subtitle") \
             .replace('QLabel#LoginBanner[level="info"]', ".banner.info") \
             .replace("QLabel#LoginBanner", ".banner") \
             .replace("QLabel#LoginNote", ".note") \
             .replace("QLabel#Plan", ".plan-chip") \
             .replace("QFrame#M3Divider", ".divider") \
             .replace("QWidget", "body") \
             .replace("QMainWindow, QDialog", ".window") \
             .replace("QTableWidget", ".table") \
             .replace("QHeaderView::section", ".table th") \
             .replace("QTableWidget::item", ".table td") \
             .replace("QTableWidget::item:selected", ".table tr.selected td") \
             .replace("QTabWidget::pane", ".tabs-pane") \
             .replace("QTabBar::tab", ".tab") \
             .replace("QTabBar::tab:selected", ".tab.selected") \
             .replace("QCheckBox::indicator, QRadioButton::indicator",
                      ".check") \
             .replace("QCheckBox::indicator:checked, QRadioButton::indicator:checked",
                      ".check.checked") \
             .replace("QStatusBar", ".statusbar") \
             .replace("QToolTip", ".tooltip") \
             .replace("QScrollBar:vertical", ".scrollbar") \
             .replace("QScrollBar::handle:vertical", ".scrollbar-thumb") \
             .replace("QScrollBar::add-line, QScrollBar::sub-line",
                      ".scrollbar-btn") \
             .replace("QComboBox QAbstractItemView", ".combo-popup") \
             .replace("QMenu", ".menu") \
             .replace("QMenu::item", ".menu-item") \
             .replace("QMenu::item:selected", ".menu-item.selected")
    return css


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Proto Clean — Material Design 3 Preview</title>
<style>
{css_vars}
* {{
  box-sizing: border-box;
  font-family: 'Inter', 'Segoe UI', 'Noto Sans', sans-serif;
}}
{css_rules}

/* HTML preview scaffolding — mock widgets that exercise every
   object name the QSS covers so the screenshot is representative. */
.preview-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  padding: 24px;
  background: var(--md3-background);
  color: var(--md3-on-background);
  font-size: 13px;
}}
.window {{
  padding: 18px 14px 8px;
  border-radius: 12px;
  background: var(--md3-surface-container-low);
  display: flex; flex-direction: column; gap: 12px;
  min-height: 540px;
}}
.header-row {{ display: flex; justify-content: space-between; align-items: flex-start; }}
.header-col {{ display: flex; flex-direction: column; gap: 2px; }}
.status-col {{ display: flex; flex-direction: column; align-items: flex-end; gap: 4px; }}
.status-row {{ display: flex; align-items: center; gap: 6px; }}
.dot {{ width: 10px; height: 10px; border-radius: 50%; background: #22c55e; }}
.controls {{ display: flex; align-items: center; gap: 12px; }}
.search-row {{ display: flex; gap: 8px; }}
.table {{ width: 100%; border-collapse: collapse; }}
.table th {{ text-align: left; }}
.table tr {{ height: 30px; }}
.bottom-bar {{ display: flex; align-items: center; gap: 8px; padding-top: 8px; }}
.bottom-bar .stretch {{ flex: 1; }}
.banner {{ display: block; margin-bottom: 8px; }}
.login-dialog {{
  padding: 24px; border-radius: 16px;
  background: var(--md3-surface-container-low);
  display: flex; flex-direction: column; gap: 12px;
  min-height: 540px;
}}
.form-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }}
.form-row label {{ width: 80px; color: var(--md3-on-surface-variant); font-size: 12px; }}
.form-row .input {{ flex: 1; }}
.guest-row {{ display: flex; align-items: center; gap: 12px; }}
.guest-row .blurb {{ flex: 1; font-size: 12px; color: var(--md3-on-surface-variant); }}
.btn-row {{ display: flex; gap: 8px; margin-top: 12px; }}
.btn-row .stretch {{ flex: 1; }}
.divider {{ margin: 16px 0; }}
.section-label {{
  font-size: 11px; color: var(--md3-on-surface-variant);
  text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px;
}}
.check {{ display: inline-block; vertical-align: middle; margin-right: 6px; }}
.tabs-row {{ display: flex; gap: 4px; margin-bottom: 8px; }}
.scrollbar-demo {{
  height: 60px; overflow-y: scroll; background: var(--md3-surface-container);
  border-radius: 12px; padding: 8px; color: var(--md3-on-surface-variant);
  font-size: 12px;
}}
.scrollbar-demo::-webkit-scrollbar {{ width: 8px; }}
.scrollbar-demo::-webkit-scrollbar-thumb {{ background: var(--md3-outline-variant); border-radius: 4px; }}
</style>
</head>
<body>
<div class="preview-grid">

<!-- =================== DARK MODE — MAIN WINDOW =================== -->
<div class="window">
  <div class="header-row">
    <div class="header-col">
      <div class="title">ProtoClean</div>
      <div class="subtitle">clean-room ProtonVPN client · WireGuard</div>
    </div>
    <div class="status-col">
      <div class="status-row">
        <span class="dot"></span>
        <span style="font-weight: 600;">Protected — US-FREE#1</span>
      </div>
      <div class="plan-chip">guest mode · free servers</div>
    </div>
  </div>

  <div class="banner">
    Guest login successful — free-tier servers only. Continue as guest uses
    Proton's credentialless API; no account, no CAPTCHA.
  </div>

  <div class="subtitle">not connected · up 00:14:32 · handshake 8s ago · ↓ 1.2 GB · ↑ 86 MB</div>

  <div class="controls">
    <span style="color: var(--md3-primary);">⚡</span>
    <label style="display: flex; align-items: center; color: var(--md3-on-surface-variant); font-size: 12px;">
      <span class="check checked"></span>
      Fastest server
    </label>
    <span style="flex: 1;"></span>
    <button class="btn-disconnect">Disconnect</button>
  </div>

  <div class="search-row">
    <input class="input" placeholder="Search country / server / city…" style="flex: 1;">
    <button class="btn">Refresh</button>
  </div>

  <table class="table">
    <thead>
      <tr><th>Country</th><th>Server</th><th>City</th><th>Load</th><th>Features</th></tr>
    </thead>
    <tbody>
      <tr class="selected"><td>US</td><td>US-FREE#1</td><td>New York</td><td><div style="width:60px;height:6px;background:var(--md3-outline-variant);border-radius:3px;"><div style="width:24%;height:100%;background:#22c55e;border-radius:3px;"></div></div></td><td>Free</td></tr>
      <tr><td>NL</td><td>NL-FREE#3</td><td>Amsterdam</td><td><div style="width:60px;height:6px;background:var(--md3-outline-variant);border-radius:3px;"><div style="width:48%;height:100%;background:#f59e0b;border-radius:3px;"></div></div></td><td>Free · P2P</td></tr>
      <tr><td>JP</td><td>JP-FREE#1</td><td>Tokyo</td><td><div style="width:60px;height:6px;background:var(--md3-outline-variant);border-radius:3px;"><div style="width:67%;height:100%;background:#f59e0b;border-radius:3px;"></div></div></td><td>Free</td></tr>
      <tr><td>PL</td><td>PL-FREE#2</td><td>Warsaw</td><td><div style="width:60px;height:6px;background:var(--md3-outline-variant);border-radius:3px;"><div style="width:81%;height:100%;background:#ef4444;border-radius:3px;"></div></div></td><td>Free</td></tr>
      <tr><td>RO</td><td>RO-FREE#1</td><td>Bucharest</td><td><div style="width:60px;height:6px;background:var(--md3-outline-variant);border-radius:3px;"><div style="width:33%;height:100%;background:#22c55e;border-radius:3px;"></div></div></td><td>Free · Tor</td></tr>
    </tbody>
  </table>

  <div class="bottom-bar">
    <button class="btn">Settings</button>
    <button class="btn">Switch account…</button>
    <button class="btn">Theme ▾</button>
    <button class="btn">Blocklists ▾</button>
    <span class="stretch"></span>
    <span class="subtitle">ad blocking: ON (187,432 domains)</span>
    <span class="subtitle">forwarded port: 45931</span>
  </div>

  <div class="statusbar">Ready</div>

  <div class="tabs-row">
    <button class="tab selected">Servers</button>
    <button class="tab">Protocols</button>
    <button class="tab">Bonding</button>
  </div>

  <div class="scrollbar-demo">
    Scrollable region — QScrollBar MD3 styling preview.<br>
    Surface container background, outline-variant thumb.
  </div>
</div>

<!-- =================== DARK MODE — LOGIN DIALOG =================== -->
<div class="login-dialog">
  <div class="title">Log in to Proton VPN</div>
  <div class="note">
    Save your Proton credentials so Proto Clean can log in automatically
    (at launch and whenever the session expires). Credentials are kept
    in your system keyring — or a chmod-600 file when no keyring is
    available.
  </div>

  <div class="form-row">
    <label>Username</label>
    <input class="input" placeholder="Proton account name (or email)">
  </div>
  <div class="form-row">
    <label>Password</label>
    <input class="input" type="password" placeholder="Proton password">
  </div>
  <div class="form-row">
    <label>2FA secret</label>
    <input class="input" placeholder="optional — TOTP secret (otpauth://… or raw base32)">
  </div>
  <div class="form-row" style="margin-left: 80px;">
    <label style="display: flex; align-items: center; width: auto;">
      <span class="check checked"></span>
      Remember me — save credentials for automatic login
    </label>
  </div>

  <div class="note">
    If Proton asks for human verification (CAPTCHA), a browser window
    will open automatically — complete it there and login continues
    by itself.
  </div>

  <div class="divider"></div>

  <div class="guest-row">
    <div class="blurb">
      No account? Continue as guest — uses Proton's credentialless
      API to obtain a free-tier (Tier=0) session. Free servers only
      (NL, JP, PL, RO, US); one connection at a time.
    </div>
    <button class="btn-guest">Continue as guest</button>
  </div>

  <div class="btn-row">
    <button class="btn">Log in in browser…</button>
    <span class="stretch"></span>
    <button class="btn">Cancel</button>
    <button class="btn-connect">Log in</button>
  </div>
</div>

</div>
</body>
</html>
"""


def render(scheme: MaterialScheme, label: str, out_png: Path) -> None:
    css_vars = f":root {{\n{_scheme_css(scheme)}\n}}"
    qss = md3_qss(scheme)
    css_rules = _qss_to_css(qss)
    html = HTML_TEMPLATE.format(css_vars=css_vars, css_rules=css_rules)
    out_html = out_png.with_suffix(".html")
    out_html.write_text(html, encoding="utf-8")
    # Render with Playwright (project dep — bundled Chromium).
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            ctx = browser.new_context(
                viewport={"width": 1280, "height": 1400},
                device_scale_factor=2,
            )
            page = ctx.new_page()
            page.goto(f"file://{out_html}")
            page.wait_for_load_state("networkidle")
            page.screenshot(path=str(out_png), full_page=True)
        finally:
            browser.close()
    print(f"rendered {label}: {out_png} ({out_png.stat().st_size} bytes)")


def main() -> None:
    out_dir = Path("/home/z/my-project/download")
    out_dir.mkdir(parents=True, exist_ok=True)
    render(DARK_SCHEME, "MD3 dark scheme",
           out_dir / "md3_preview_dark.png")
    render(LIGHT_SCHEME, "MD3 light scheme",
           out_dir / "md3_preview_light.png")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Extract the WireGuard section from the real uploads page dump and build a
minimal static HTML page that Playwright can load, to verify our selectors."""
import re

SRC = "/home/z/my-project/upload/Pasted Content_1793515154108.txt"
OUT = "/tmp/wg-section.html"

with open(SRC, "r", encoding="utf-8") as fh:
    doc = fh.read()

start = doc.find('<section id="section-wireguard-configuration"')
end = doc.find('<section id="', start + 10)
if end == -1:
    end = doc.find('Get VPN Plus to access all servers', start)
wg = doc[start:end]
print(f"extracted {len(wg)} chars of WG section")

# wrap in a minimal page skeleton with the same ids/classes used by selectors
html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Downloads</title></head>
<body>
<div class="app-root">
{wg}
</div>
</body></html>"""
with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(html)

# sanity: the pieces our selectors rely on are present
for probe in ('id="certificate-device-name"', 'id="wg-platform-Linux"',
              'id="feature-PortForwarding"', 'id="feature-SplitTCP"',
              'name="category-list"', 'Free server configs',
              'data-certificate-id', '<textarea', 'CA-FREE#1', 'US-FREE#50',
              'id="server-lookup"', 'button-solid-norm'):
    assert probe in wg, f"missing: {probe}"
print("all selector anchors present in extracted section")

#!/usr/bin/env python3
"""Extract category radios, best-server radio, row markup, search input."""
import re
import html as htmllib

SRC = "/home/z/my-project/upload/Pasted Content_1793515154108.txt"
with open(SRC, "r", encoding="utf-8") as fh:
    doc = fh.read()

def strip(h):
    t = re.sub(r"<[^>]+>", " ", h)
    return re.sub(r"\s+", " ", htmllib.unescape(t)).strip()

print("=" * 70)
print("ALL radio inputs (WG + OpenVPN sections)")
for m in re.finditer(r'<input[^>]*type="radio"[^>]*>', doc):
    print("  ", m.group(0)[:260])

print("=" * 70)
print("Best-server area raw (around 'Use the best server')")
i = doc.find("Use the best server")
print(doc[i - 700: i + 700].replace("><", ">\n<")[:2200])

print("=" * 70)
print("One full server table row raw")
i = doc.find("CA-FREE#2")
print(doc[i - 600: i + 900].replace("><", ">\n<")[:2600])

print("=" * 70)
print("Lock icons / upgrade markers on rows")
for pat in ("lock", "Lock", "upgrade", "Upgrade this", "badge-plus", "PLUS"):
    print(f"  '{pat}':", len(re.findall(re.escape(pat), doc)))

print("=" * 70)
print("Search input raw")
i = doc.find("Search for additional servers")
seg = doc[i: i + 4000]
m = re.search(r"<input[^>]*>", seg)
print(m.group(0) if m else "no input found in segment")
print(strip(seg)[:400])

print("=" * 70)
print("countries (details summaries) in server tables")
for m in re.finditer(r'<details[^>]*open[^>]*>.*?<summary.*?<img[^>]*alt="([^"]+)"[^>]*>.*?<p class="mx-1">([^<]*)</p>', doc):
    print("  open details:", m.group(1), "/", m.group(2))
allc = re.findall(r'<img width="20"[^>]*alt="([^"]+)"[^>]*>', doc)
print("  country imgs (first 20):", allc[:20])
print("  total country imgs:", len(allc))

print("=" * 70)
print("th/Status headers + load percent cells sample")
loads = re.findall(r'>(\d{1,3}%)<', doc)
print("  load cells found:", len(loads), loads[:15])

print("=" * 70)
print("'IPv6' badges:", doc.count("IPv6"), " 'P2P' badges:", doc.count("P2P"))
print("AT-PMP context:")
i = doc.find("AT-PMP")
print(strip(doc[i - 300: i + 300])[:300])

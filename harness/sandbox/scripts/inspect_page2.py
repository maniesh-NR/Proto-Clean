#!/usr/bin/env python3
"""Deep-dive into server selection + certificate areas of the downloads page."""
import re
import html as htmllib

SRC = "/home/z/my-project/upload/Pasted Content_1793515154108.txt"
with open(SRC, "r", encoding="utf-8") as fh:
    doc = fh.read()

def strip(h):
    t = re.sub(r"<[^>]+>", " ", h)
    return re.sub(r"\s+", " ", htmllib.unescape(t)).strip()

print("=" * 70)
print("'4. Select a server to connect to' area")
i = doc.find("4. Select a server to connect to")
chunk = doc[i: i + 6000]
print(strip(chunk)[:2000])
print()
print("---- RAW first server entry markup ----")
# find first CA-FREE#1 radio/entry
j = chunk.find("CA-FREE#1")
print(chunk[max(0, j - 1200): j + 400].replace("><", ">\n<")[:3000])

print("=" * 70)
print("'Moderate NAT' mentions:", doc.count("Moderate NAT"))
k = doc.find("Moderate NAT")
if k != -1:
    print(strip(doc[k - 800: k + 800])[:600])

print("=" * 70)
print("VPN Accelerator mentions:", doc.count("VPN Accelerator"))
k = doc.find("VPN Accelerator")
print(strip(doc[k - 900: k + 900])[:700] if k != -1 else "none")

print("=" * 70)
print("NAT-PMP mentions:", doc.count("NAT-PMP"))

print("=" * 70)
print("'Get VPN Plus' area")
i = doc.find("Get VPN Plus to access all servers")
print(strip(doc[i: i + 2500])[:900])

print("=" * 70)
print("Count of 'FREE#' occurrences:", len(re.findall(r'FREE#', doc)))
print("Count of 'PLUS' occurrences:", len(re.findall(r'PLUS', doc)))
print("Count of 'PMP' server entries:", len(re.findall(r'-PMP', doc)))

print("=" * 70)
print("'Create' button raw markup")
for m in re.finditer(r'<button[^>]*>[^<]*Create[^<]*</button>', doc):
    print(m.group(0)[:400])
    print()

print("=" * 70)
print("'Search' area raw markup (WG section)")
i = doc.find("Search for additional servers")
print(strip(doc[i: i + 1200])[:500])

print("=" * 70)
print("certificate details: textarea + expires")
i = doc.find("expires")
print(strip(doc[i - 400: i + 300])[:400])

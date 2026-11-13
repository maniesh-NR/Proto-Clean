#!/usr/bin/env python3
"""Extract relevant structures from the real downloads page HTML."""
import re
import html as htmllib

SRC = "/home/z/my-project/upload/Pasted Content_1793515154108.txt"
with open(SRC, "r", encoding="utf-8") as fh:
    doc = fh.read()

print("=" * 70)
print("SECTION HEADINGS")
for m in re.finditer(r'<h3[^>]*>(.*?)</h3>', doc):
    print("  h3:", re.sub(r"<[^>]+>", "", m.group(1))[:120])
for m in re.finditer(r'<h2[^>]*>.*?<span[^>]*>(.*?)</span>', doc):
    print("  h2:", m.group(1)[:120])

print("=" * 70)
print("FEATURE TOGGLES (input ids / labels)")
for m in re.finditer(r'<input[^>]*id="(feature-[^"]+|wg-feature-[^"]+)"[^>]*>', doc):
    print("  input:", m.group(0)[:200])

print("=" * 70)
print("WG PLATFORM RADIOS")
for m in re.finditer(r'<input[^>]*id="wg-platform-([^"]+)"[^>]*>', doc):
    print("  platform:", m.group(1))

print("=" * 70)
print("TEXTAREAS (config previews)")
for m in re.finditer(r'<textarea[^>]*>(.*?)</textarea>', doc, re.S):
    content = htmllib.unescape(m.group(1))
    print("  textarea len:", len(content))
    print("  head:", content[:200].replace("\n", " | "))
    print("  ...")

print("=" * 70)
print("CERTIFICATE DETAILS BLOCKS")
for m in re.finditer(r'<details[^>]*data-certificate-id="([^"]+)"', doc):
    print("  certificate:", m.group(1)[:60])

print("=" * 70)
print("SELECT DROPDOWNS")
for m in re.finditer(r'<select[^>]*>', doc):
    print("  ", m.group(0)[:220])

print("=" * 70)
print("BUTTONS")
seen = set()
for m in re.finditer(r'<button[^>]*>(?:<span[^>]*>)?\s*([A-Za-z][^<]{0,60})', doc):
    label = m.group(1).strip()
    if label and label not in seen:
        seen.add(label)
        print("  button:", label[:80])

print("=" * 70)
print("SERVER NAMES mentioned (FREE / # patterns)")
names = set(re.findall(r'[A-Z]{2}(?:-[A-Z]+)?-(?:FREE|PLUS|PM|VIP)[^<\s"]{0,12}', doc))
for n in sorted(names)[:60]:
    print("  server:", n)

print("=" * 70)
print("SERVER SELECT AREA — find 'Select server' / country selector")
idx = doc.find("Select server")
if idx == -1:
    for probe in ("server", "Server"):
        idx = doc.find(probe)
        break
print("  found 'Select server' at:", idx)
if idx != -1:
    chunk = doc[idx - 300: idx + 3000]
    text = re.sub(r"<[^>]+>", " ", chunk)
    print("  text:", re.sub(r"\s+", " ", htmllib.unescape(text))[:1200])

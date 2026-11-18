"""Crop the generated logo tile, round corners, emit the full asset set."""
from PIL import Image, ImageDraw

SRC = "/tmp/logo/raw1.png"
OUT = "/home/z/my-project/cleanroom"

img = Image.open(SRC).convert("RGBA")

# --- 1. Locate the tile: the tile is bright teal (green channel > 100), the
# gradient background is dark blue (green channel < 70) everywhere. ---
px = img.load()
w, h = img.size
step = 4
row_hits = [sum(1 for x in range(0, w, step) if px[x, y][1] > 100) for y in range(0, h, step)]
col_hits = [sum(1 for y in range(0, h, step) if px[x, y][1] > 100) for x in range(0, w, step)]
def span(hits, st):
    idx = [i for i, c in enumerate(hits) if c > len(hits) * 0.10]
    return (idx[0] * st, idx[-1] * st) if idx else (0, h)
top, bottom = span(row_hits, step)
left, right = span(col_hits, step)
print("tile bounds:", left, top, right, bottom)

# small inset to drop anti-aliased edge fringe, then square-ify
inset = 3
tile = img.crop((left + inset, top + inset, right - inset, bottom - inset))
tw, th = tile.size
side = min(tw, th)
tile = tile.crop(((tw - side) // 2, (th - side) // 2,
                  (tw - side) // 2 + side, (th - side) // 2 + side))

# --- 2. Rounded-corner mask (squircle-ish radius ~22%) on transparent canvas ---
big = 1024
tile = tile.resize((big, big), Image.LANCZOS)
mask = Image.new("L", (big, big), 0)
d = ImageDraw.Draw(mask)
r = int(big * 0.225)
d.rounded_rectangle([0, 0, big - 1, big - 1], radius=r, fill=255)
tile.putalpha(mask)

# --- 3. Emit the asset set ---
import os
os.makedirs(f"{OUT}/packaging/windows", exist_ok=True)

p512 = tile.resize((512, 512), Image.LANCZOS)
p512.save(f"{OUT}/docs/logo.png")
p512.save(f"{OUT}/packaging/linux/cleanroom.png")

# Windows .ico with embedded multi-resolution frames
tile.resize((256, 256), Image.LANCZOS).save(
    f"{OUT}/packaging/windows/cleanroom.ico",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

for f in ("docs/logo.png", "packaging/linux/cleanroom.png", "packaging/windows/cleanroom.ico"):
    p = f"{OUT}/{f}"
    print(f, os.path.getsize(p), "bytes")
print("DONE")

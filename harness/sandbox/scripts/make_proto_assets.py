#!/usr/bin/env python3
"""Proto Clean brand asset pipeline.

Two background styles in the uploads:
  * logo sheet + wordmark: 24px checkerboard (23px squares + 1px divider)
  * full emblem logo:      noisy near-white background

Produces:
  packaging/linux/proto-clean.png        512x512 app icon
  packaging/windows/proto-clean.ico      16..256 multi-resolution
  docs/logo.png                          full logo (emblem + wordmark)
  docs/brand/*.png                       all cleaned logo variants
  android .../drawable-nodpi/ic_launcher_foreground.png  432x432 adaptive fg
  /tmp/proto_debug/proto_icon_b64.txt    base64 PNG for resources.py
  /tmp/proto_debug/*                     previews for visual checking
"""
from __future__ import annotations

import base64
from collections import deque
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image

UP = Path("/home/z/my-project/upload")
REPO = Path("/home/z/my-project/cleanroom")
DEBUG = Path("/tmp/proto_debug")
DEBUG.mkdir(parents=True, exist_ok=True)

SHEET = UP / "pasted_image_1793587453919.png"
FULL = UP / "pasted_image_1793587520446.png"
WORD = UP / "proto clean vpn.png"


# ------------------------------------------------------------- checkerboard
def checker_params(im: Image.Image):
    rgb = im.convert("RGB")
    w, h = rgb.size
    px = rgb.load()
    strips = [[px[x, 1] for x in range(w)],
              [px[x, h - 2] for x in range(w)],
              [px[1, y] for y in range(h)],
              [px[w - 2, y] for y in range(h)]]
    sizes, evens, odds, dividers = [], [], [], []
    for strip in strips:
        runs, cur, n = [], strip[0], 1
        for c in strip[1:]:
            if max(abs(a - b) for a, b in zip(c, cur)) <= 8:
                n += 1
            else:
                runs.append((cur, n))
                cur, n = c, 1
        runs.append((cur, n))
        parity = 0
        for c, ln in runs:
            if 5 <= ln <= 40:
                (evens if parity == 0 else odds).append(c)
                sizes.append(ln)
                parity ^= 1
            elif ln <= 4:
                dividers.append(c)

    def med(channels):
        return tuple(sorted(channels)[len(channels) // 2][i] for i in range(3))

    s = sorted(sizes)[len(sizes) // 2]
    c0, c1 = med(evens), med(odds)
    div = med(dividers) if dividers else c0
    return s + 1, c0, c1, div


import numpy as np
from collections import deque

from PIL import Image


def _box(mask, r, h, w):
    """Count of True in a (2r+1)-wide window around each pixel (False-padded)."""
    mp = np.zeros((h + 2 * r, w + 2 * r), dtype=np.int32)
    mp[r:r + h, r:r + w] = mask
    p = np.zeros((h + 2 * r + 1, w + 2 * r + 1), dtype=np.int32)
    p[1:, 1:] = mp.cumsum(0).cumsum(1)
    k = 2 * r + 1
    return p[k:, k:] - p[:-k, k:] - p[k:, :-k] + p[:-k, :-k]


def _flood_border(seed, gate, h, w):
    """4-connected flood from border seeds, expanding through gate pixels."""
    keep = np.zeros((h, w), dtype=bool)
    q = deque()
    for x in range(w):
        for y in (0, h - 1):
            if seed[y, x] and not keep[y, x]:
                keep[y, x] = True
                q.append((x, y))
    for y in range(h):
        for x in (0, w - 1):
            if seed[y, x] and not keep[y, x]:
                keep[y, x] = True
                q.append((x, y))
    while q:
        x, y = q.popleft()
        for nx, ny in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
            if 0 <= nx < w and 0 <= ny < h and gate[ny, nx] and not keep[ny, nx]:
                keep[ny, nx] = True
                q.append((nx, ny))
    return keep


def _erode_dust(arr, trans, rounds=8, lo=195, sat=60):
    """Light, low-saturation noise adjacent to transparency becomes
    transparent (repeated so dust chains are eaten progressively)."""
    t = trans.copy()
    light = (arr.min(axis=2) >= lo) & ((arr.max(axis=2) - arr.min(axis=2)) <= sat)
    h, w = t.shape
    for _ in range(rounds):
        tp = np.zeros((h + 2, w + 2), dtype=bool)
        tp[1:-1, 1:-1] = t
        tp[0, :] = tp[-1, :] = True      # outside the image = transparent
        tp[:, 0] = tp[:, -1] = True
        nb = np.zeros((h, w), dtype=np.int8)
        nb += tp[:-2, 1:-1]
        nb += tp[2:, 1:-1]
        nb += tp[1:-1, :-2]
        nb += tp[1:-1, 2:]
        grow = light & (nb >= 2) & (~t)
        if not grow.any():
            break
        t |= grow
    return t


def _to_rgba(arr, trans):
    rgba = np.dstack([arr.astype(np.uint8),
                      np.where(trans, 0, 255).astype(np.uint8)])
    return Image.fromarray(rgba)


def strip_checker(im: Image.Image) -> Image.Image:
    """Remove the checkerboard background.

    A pixel is background only if it is near one of the two checker colors
    AND its ~(2*pitch)-wide neighbourhood contains BOTH colors — true
    checkers alternate, uniform design fills do not.  Only regions
    connected to the image border are removed, then light dust adjacent
    to the new transparency is eroded away.
    """
    pitch, c0, c1, div = checker_params(im)
    print(f"  checker: pitch={pitch} {c0} / {c1} divider~{div}")
    arr = np.asarray(im.convert("RGB"), dtype=np.int16)
    h, w = arr.shape[:2]
    near0 = np.abs(arr - np.array(c0, dtype=np.int16)).sum(axis=2) <= 75
    near1 = np.abs(arr - np.array(c1, dtype=np.int16)).sum(axis=2) <= 75
    neard = np.abs(arr - np.array(div, dtype=np.int16)).sum(axis=2) <= 60
    near_any = near0 | near1 | neard
    r = pitch
    b0 = _box(near0, r, h, w)
    b1 = _box(near1, r, h, w)
    window = (2 * r + 1) ** 2
    gate = near_any & (b0 >= window // 12) & (b1 >= window // 12)
    trans = _flood_border(near_any, gate, h, w)
    trans = trans | gate          # enclosed checkered counters too
    trans = _erode_dust(arr, trans, rounds=60)
    return _to_rgba(arr, trans)


# ------------------------------------------------------- white bg knock-out
def knockout_white(im: Image.Image, lo: int = 222, sat: int = 26) -> Image.Image:
    """Flood-fill the noisy near-white border background to transparent,
    then erode remaining light dust next to the transparency."""
    arr = np.asarray(im.convert("RGB"), dtype=np.int16)
    h, w = arr.shape[:2]
    is_bg = (arr.min(axis=2) >= lo) & ((arr.max(axis=2) - arr.min(axis=2)) <= sat)
    trans = _flood_border(is_bg, is_bg, h, w)
    trans = _erode_dust(arr, trans, rounds=60)
    return _to_rgba(arr, trans)


# ------------------------------------------------------------------ helpers
def tight(im: Image.Image, pad: int = 0) -> Image.Image:
    bbox = im.getbbox()
    if not bbox:
        return im
    x0, y0, x1, y1 = bbox
    return im.crop((max(0, x0 - pad), max(0, y0 - pad),
                    min(im.width, x1 + pad), min(im.height, y1 + pad)))


def segments(im: Image.Image, axis: str, min_gap: int = 6, thresh: int = 12):
    w, h = im.size
    n = w if axis == "x" else h
    hist = [0] * n
    px = im.load()
    if axis == "x":
        for x in range(w):
            hist[x] = sum(1 for y in range(0, h, 2) if px[x, y][3] > thresh) * 2
    else:
        for y in range(h):
            hist[y] = sum(1 for x in range(0, w, 2) if px[x, y][3] > thresh) * 2
    spans, start, gap = [], None, 0
    for i, v in enumerate(hist):
        if v > 0:
            if start is None:
                start = i
            gap = 0
        elif start is not None:
            gap += 1
            if gap >= min_gap:
                spans.append((start, i - gap))
                start, gap = None, 0
    if start is not None:
        spans.append((start, n - 1))
    return [s for s in spans if s[1] - s[0] > 8]


def sheet_variants(sheet: Image.Image) -> list:
    """Split the sheet into its logo variants via connected components,
    grouped into x-clusters (a variant = mark + its wordmark blobs)."""
    w, h = sheet.size
    px = sheet.load()
    step = 2
    sw, sh = w // step, h // step
    solid = [[px[x * step, y * step][3] > 40 for x in range(sw)] for y in range(sh)]
    seen = [[False] * sw for _ in range(sh)]
    comps = []
    for yy in range(sh):
        for xx in range(sw):
            if solid[yy][xx] and not seen[yy][xx]:
                stack = [(xx, yy)]
                seen[yy][xx] = True
                x0 = x1 = xx
                y0 = y1 = yy
                n = 0
                while stack:
                    cx, cy = stack.pop()
                    n += 1
                    if cx < x0: x0 = cx
                    if cx > x1: x1 = cx
                    if cy < y0: y0 = cy
                    if cy > y1: y1 = cy
                    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                        nx, ny = cx + dx, cy + dy
                        if 0 <= nx < sw and 0 <= ny < sh and solid[ny][nx] \
                                and not seen[ny][nx]:
                            seen[ny][nx] = True
                            stack.append((nx, ny))
                if n >= 150:      # real content blobs only (at half-res)
                    comps.append([x0 * step, (x1 + 1) * step,
                                  y0 * step, (y1 + 1) * step])
    comps.sort(key=lambda b: b[0])
    groups: list[list] = []
    for b in comps:
        if groups and b[0] - groups[-1][1] <= 80:
            g = groups[-1]
            g[0] = min(g[0], b[0]); g[1] = max(g[1], b[1])
            g[2] = min(g[2], b[2]); g[3] = max(g[3], b[3])
        else:
            groups.append([b[0], b[1], b[2], b[3]])
    variants = []
    for g in groups:
        if g[1] - g[0] < 60:      # stray specks
            continue
        variants.append(tight(sheet.crop((g[0], g[2], g[1], g[3]))))
        print(f"  variant: {variants[-1].size}")
    return variants


def crop_span(im, span, axis):
    x0, y0, x1, y1 = 0, 0, im.width, im.height
    if axis == "x":
        x0, x1 = span
    else:
        y0, y1 = span
    return im.crop((x0, y0, x1 + 1, y1 + 1))


def palette_report(mark: Image.Image, label: str):
    px = mark.load()
    greens, grays = [], []
    for y in range(0, mark.height, 2):
        for x in range(0, mark.width, 2):
            r, g, b, a = px[x, y]
            if a > 100:
                if g > r + 25 and g > b + 25:
                    greens.append((r, g, b))
                elif abs(r - g) < 15 and abs(g - b) < 15 and 90 < g < 200:
                    grays.append((r, g, b))
    for name, arr in (("green", greens), ("gray", grays)):
        if arr:
            arr.sort(key=lambda c: sum(c))
            print(f"  {label} {name}: n={len(arr)} median={arr[len(arr)//2]} "
                  f"p10={arr[len(arr)//10]} p90={arr[len(arr)*9//10]}")


def on_bg(im: Image.Image, color: str, scale: int = 256) -> Image.Image:
    tile = Image.new("RGB", (scale, scale), color)
    fg = tight(im)
    fg = fg.resize((scale - 16, scale - 16), Image.LANCZOS)
    tile.paste(fg, (8, 8), fg)
    return tile


def square_icon(mark: Image.Image, size: int, fill_frac: float = 0.86) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    m = tight(mark)
    target = int(size * fill_frac)
    m = m.resize((target, target), Image.LANCZOS)
    canvas.paste(m, ((size - target) // 2, (size - target) // 2), m)
    return canvas


def _png_bytes(im: Image.Image) -> bytes:
    buf = BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue()


# --------------------------------------------------------------------- main
def main() -> None:
    print("== sheet ==")
    sheet = tight(strip_checker(Image.open(SHEET)), pad=2)
    variants = sheet_variants(sheet)
    print("== full ==")
    full = tight(knockout_white(Image.open(FULL)), pad=2)
    rows = segments(full, "y", min_gap=8)
    for r in rows:
        print(f"  row block: y={r[0]}..{r[1]} h={r[1]-r[0]+1}")
    emblem = tight(crop_span(full, rows[0], "y"))
    print(f"  emblem: {emblem.size}")
    print("== wordmark ==")
    word = tight(strip_checker(Image.open(WORD)), pad=2)
    print(f"  wordmark: {word.size}")

    palette_report(emblem, "emblem")

    on_bg(emblem, "#ffffff").save(DEBUG / "emblem-on-white.png")
    on_bg(emblem, "#16181d").save(DEBUG / "emblem-on-dark.png")
    on_bg(full, "#ffffff", scale=320).save(DEBUG / "full-on-white.png")
    if variants:
        sheet_dbg = Image.new("RGB", (300 * len(variants) + 20, 340), "#ffffff")
        xoff = 10
        for v in variants:
            t = v.copy()
            t.thumbnail((280, 320), Image.LANCZOS)
            sheet_dbg.paste(t, (xoff, 10), t)
            xoff += 300
        sheet_dbg.save(DEBUG / "sheet-variants.png")

    (REPO / "docs/brand").mkdir(parents=True, exist_ok=True)
    icon512 = square_icon(emblem, 512)
    icon512.save(REPO / "packaging/linux/proto-clean.png")
    icon512.save(REPO / "docs/brand/proto-clean-icon-512.png")
    icon512.save(DEBUG / "icon-512.png")
    ico_src = square_icon(emblem, 256, fill_frac=0.95)
    ico_src.save(REPO / "packaging/windows/proto-clean.ico",
                 sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                        (64, 64), (128, 128), (256, 256)])
    full.save(REPO / "docs/logo.png")
    full.save(REPO / "docs/brand/proto-clean-full.png")
    word.save(REPO / "docs/brand/proto-clean-wordmark.png")
    for i, v in enumerate(variants):
        v.save(REPO / f"docs/brand/proto-clean-sheet-{i + 1}.png")

    fg = Image.new("RGBA", (432, 432), (0, 0, 0, 0))
    m = tight(emblem)
    m.thumbnail((246, 246), Image.LANCZOS)
    fg.paste(m, ((432 - m.width) // 2, (432 - m.height) // 2), m)
    fg.save(REPO / "android/app/src/main/res/drawable-nodpi/ic_launcher_foreground.png")
    fg.save(DEBUG / "android-fg.png")

    b64 = base64.b64encode(_png_bytes(square_icon(emblem, 256, fill_frac=0.95))).decode()
    (DEBUG / "proto_icon_b64.txt").write_text(b64)
    print(f"  base64 png: {len(b64)} chars")


if __name__ == "__main__":
    main()

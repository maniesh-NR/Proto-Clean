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


def _erode_dust(arr, trans, rounds=6, lo=195, sat=30):
    """Light, low-saturation noise adjacent to transparency becomes
    transparent (repeated so dust chains are eaten progressively)."""
    t = trans.copy()
    light = (arr.min(axis=2) >= lo) & ((arr.max(axis=2) - arr.min(axis=2)) <= sat)
    for _ in range(rounds):
        nb = np.zeros(t.shape, dtype=np.int8)
        nb[1:, :] += t[:-1, :]
        nb[:-1, :] += t[1:, :]
        nb[:, 1:] += t[:, :-1]
        nb[:, :-1] += t[:, 1:]
        grow = light & (nb >= 2) & (~t)
        if not grow.any():
            break
        t |= grow
    return t


def _to_rgba(arr, trans):
    rgba = np.dstack([arr.astype(np.uint8),
                      np.where(trans, 0, 255).astype(np.uint8)])
    return Image.fromarray(rgba, "RGBA")


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
    near0 = np.abs(arr - np.array(c0, dtype=np.int16)).sum(axis=2) <= 48
    near1 = np.abs(arr - np.array(c1, dtype=np.int16)).sum(axis=2) <= 48
    neard = np.abs(arr - np.array(div, dtype=np.int16)).sum(axis=2) <= 40
    near_any = near0 | near1 | neard
    r = pitch
    b0 = _box(near0, r, h, w)
    b1 = _box(near1, r, h, w)
    window = (2 * r + 1) ** 2
    gate = near_any & (b0 >= window // 12) & (b1 >= window // 12)
    trans = _flood_border(near_any, gate, h, w)
    trans = _erode_dust(arr, trans, rounds=3)
    return _to_rgba(arr, trans)


# ------------------------------------------------------- white bg knock-out
def knockout_white(im: Image.Image, lo: int = 222, sat: int = 26) -> Image.Image:
    """Flood-fill the noisy near-white border background to transparent,
    then erode remaining light dust next to the transparency."""
    arr = np.asarray(im.convert("RGB"), dtype=np.int16)
    h, w = arr.shape[:2]
    is_bg = (arr.min(axis=2) >= lo) & ((arr.max(axis=2) - arr.min(axis=2)) <= sat)
    trans = _flood_border(is_bg, is_bg, h, w)
    trans = _erode_dust(arr, trans, rounds=6)
    return _to_rgba(arr, trans)

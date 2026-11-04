"""Material Design 3 color + QSS system for the Proto Clean desktop UI.

This module is the source of MD3 styling for the Qt UI. It provides:

* an HCT (Hue / Chroma / Tone) color space approximation built on CIELAB,
  with sRGB gamut clamping at the chroma boundary;
* a :class:`TonalPalette` (same hue/chroma, varying perceptual lightness);
* the full :class:`MaterialScheme` dataclass — every Material 3 color role
  (primary, secondary, tertiary, error, surfaces, outlines, inverses, …);
* :func:`scheme_from_seed` deriving a scheme from a single seed color;
* :func:`md3_qss` generating a Qt stylesheet that paints every Proto Clean
  widget in the Material 3 visual language;
* :func:`md3_palette_qss` returning a Qt ``QPalette`` role → hex mapping
  (the actual ``QColor`` construction stays in ``proto_clean.ui.theme``);
* :func:`state_colors` for the connection-state dot palette, plus a
  backward-compatible module-level :data:`STATE_COLORS` constant;
* ready-to-use :data:`DARK_SCHEME`, :data:`LIGHT_SCHEME`, :data:`DARK_QSS`
  and :data:`LIGHT_QSS` defaults (theme.py re-exports the QSS strings).

The module is **Qt-free at import time** — every public API works on hex
strings, plain dicts and the dataclasses defined below. This lets it run
in headless test environments where no Qt binding is importable.

HCT notes
---------
HCT is Google's perceptual color space (Material Color Utilities). Hue is
the standard hue angle (0..360°), Chroma is the CIELAB chroma
(``sqrt(a² + b²)``) and Tone is CIELAB L* (0..100). We approximate the
HCT → sRGB path as ``HCT → CIELAB → XYZ(D65) → linear sRGB → sRGB`` with
gamma encoding; chroma is uniformly scaled down (binary search) when the
requested Lab color would fall outside the sRGB gamut.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Tuple

__all__ = [
    "hct_to_rgb",
    "rgb_to_hct",
    "TonalPalette",
    "MaterialScheme",
    "scheme_from_seed",
    "md3_scheme_for",
    "md3_qss",
    "md3_palette_qss",
    "state_colors",
    "STATE_COLORS",
    "SHAPE_EXTRA_SMALL",
    "SHAPE_SMALL",
    "SHAPE_MEDIUM",
    "SHAPE_LARGE",
    "SHAPE_EXTRA_LARGE",
    "DARK_SCHEME",
    "LIGHT_SCHEME",
    "DARK_QSS",
    "LIGHT_QSS",
]

# ---------------------------------------------------------------------------
# MD3 shape system (corner radii in pixels)
# ---------------------------------------------------------------------------
SHAPE_EXTRA_SMALL: int = 4
SHAPE_SMALL: int = 8
SHAPE_MEDIUM: int = 12
SHAPE_LARGE: int = 16
SHAPE_EXTRA_LARGE: int = 28

# ---------------------------------------------------------------------------
# HCT color space — CIELAB backbone, D65 white point, sRGB gamut clamping.
# XYZ is kept on the 0..1 scale (Yn = 1.0) so the standard sRGB matrices
# apply without extra scaling.
# ---------------------------------------------------------------------------
_XN: float = 0.95047   # D65 reference white X (Yn = 1.0 scale)
_YN: float = 1.00000
_ZN: float = 1.08883

# CIELAB constants (per CIE 15:2004)
_EPS: float = 216.0 / 24389.0    # ≈ 0.008856
_KAPPA: float = 24389.0 / 27.0   # ≈ 903.3

# XYZ(D65) → linear sRGB (Bruce Lindbloom, precise sRGB / D65 matrix).
# These are the exact inverses of the sRGB → XYZ matrix below.
_M_XYZ2LIN = (
    (3.2404542, -1.5371385, -0.4985314),
    (-0.9692660, 1.8760108, 0.0415560),
    (0.0556434, -0.2040259, 1.0572252),
)
# linear sRGB → XYZ(D65)
_M_LIN2XYZ = (
    (0.4124564, 0.3575761, 0.1804375),
    (0.2126729, 0.7151522, 0.0721750),
    (0.0193339, 0.1191920, 0.9503041),
)


def _srgb_to_lin(c: float) -> float:
    """Inverse sRGB companding: sRGB component in [0,1] → linear in [0,1]."""
    if c <= 0.04045:
        return c / 12.92
    return ((c + 0.055) / 1.055) ** 2.4


def _lin_to_srgb(c: float) -> float:
    """Forward sRGB companding: linear in [0,1] → sRGB component in [0,1]."""
    if c <= 0.0031308:
        return 12.92 * c
    return 1.055 * (c ** (1.0 / 2.4)) - 0.055


def _f_lab(t: float) -> float:
    """CIELAB forward ``f`` function (used in XYZ → Lab)."""
    if t > _EPS:
        return t ** (1.0 / 3.0)
    return (_KAPPA * t + 16.0) / 116.0


def _f_inv_lab(t: float) -> float:
    """CIELAB inverse ``f`` function (used in Lab → XYZ)."""
    t3 = t ** 3
    if t3 > _EPS:
        return t3
    return (116.0 * t - 16.0) / _KAPPA


def _lab_to_lin_rgb(L: float, a: float, b: float) -> Tuple[float, float, float]:
    """Convert CIELAB L*a*b* to linear sRGB (0..1), no gamut clamp."""
    fy = (L + 16.0) / 116.0
    fx = fy + a / 500.0
    fz = fy - b / 200.0
    X = _XN * _f_inv_lab(fx)
    Y = _YN * _f_inv_lab(fy)
    Z = _ZN * _f_inv_lab(fz)
    r = _M_XYZ2LIN[0][0] * X + _M_XYZ2LIN[0][1] * Y + _M_XYZ2LIN[0][2] * Z
    g = _M_XYZ2LIN[1][0] * X + _M_XYZ2LIN[1][1] * Y + _M_XYZ2LIN[1][2] * Z
    bl = _M_XYZ2LIN[2][0] * X + _M_XYZ2LIN[2][1] * Y + _M_XYZ2LIN[2][2] * Z
    return (r, g, bl)


def _lab_in_gamut(L: float, a: float, b: float, tol: float = 1e-4) -> bool:
    """Return True iff Lab color maps to an in-gamut sRGB triple."""
    r, g, bl = _lab_to_lin_rgb(L, a, b)
    return (-tol <= r <= 1.0 + tol
            and -tol <= g <= 1.0 + tol
            and -tol <= bl <= 1.0 + tol)


def _clamp_chroma(L: float, hue_deg: float, chroma: float) -> float:
    """Largest chroma ``<= chroma`` whose Lab color is in sRGB gamut.

    Uniformly scales ``a`` and ``b`` down (binary search) until the
    resulting Lab color maps to an in-gamut sRGB triple.
    """
    if chroma <= 0.0:
        return 0.0
    h = math.radians(hue_deg)
    a = chroma * math.cos(h)
    b = chroma * math.sin(h)
    if _lab_in_gamut(L, a, b):
        return chroma
    lo, hi = 0.0, chroma
    for _ in range(32):                 # 32 iters → ~1e-9 relative precision
        mid = (lo + hi) * 0.5
        a = mid * math.cos(h)
        b = mid * math.sin(h)
        if _lab_in_gamut(L, a, b):
            lo = mid
        else:
            hi = mid
    return lo


def hct_to_rgb(hue_deg: float, chroma: float, tone: float) -> Tuple[int, int, int]:
    """Convert HCT to sRGB (0-255 integers).

    Parameters
    ----------
    hue_deg:
        Hue angle in degrees (0..360). Values outside the range are
        reduced modulo 360.
    chroma:
        CIELAB chroma (perpendicular distance from the achromatic axis).
        Values ``<= 0`` yield an achromatic result. Out-of-gamut chromas
        are uniformly scaled down until the color fits in sRGB.
    tone:
        CIELAB L* (perceptual lightness 0..100). Clamped to that range.

    Returns
    -------
    tuple[int, int, int]
        ``(r, g, b)`` channels in 0..255.
    """
    hue_deg = hue_deg % 360.0
    L = max(0.0, min(100.0, float(tone)))
    c = max(0.0, float(chroma))
    c = _clamp_chroma(L, hue_deg, c)
    h = math.radians(hue_deg)
    a = c * math.cos(h)
    b = c * math.sin(h)
    r, g, bl = _lab_to_lin_rgb(L, a, b)
    r = _lin_to_srgb(max(0.0, min(1.0, r)))
    g = _lin_to_srgb(max(0.0, min(1.0, g)))
    bl = _lin_to_srgb(max(0.0, min(1.0, bl)))
    return (
        int(round(r * 255.0)),
        int(round(g * 255.0)),
        int(round(bl * 255.0)),
    )


def rgb_to_hct(r: int, g: int, b: int) -> Tuple[float, float, float]:
    """Convert sRGB (0-255) to HCT (hue_deg, chroma, tone).

    Inverse of :func:`hct_to_rgb` up to floating-point rounding. Hue is
    returned in degrees (0..360), chroma in CIELAB units and tone as L*.
    """
    rl = _srgb_to_lin(max(0.0, min(1.0, r / 255.0)))
    gl = _srgb_to_lin(max(0.0, min(1.0, g / 255.0)))
    bl = _srgb_to_lin(max(0.0, min(1.0, b / 255.0)))
    X = _M_LIN2XYZ[0][0] * rl + _M_LIN2XYZ[0][1] * gl + _M_LIN2XYZ[0][2] * bl
    Y = _M_LIN2XYZ[1][0] * rl + _M_LIN2XYZ[1][1] * gl + _M_LIN2XYZ[1][2] * bl
    Z = _M_LIN2XYZ[2][0] * rl + _M_LIN2XYZ[2][1] * gl + _M_LIN2XYZ[2][2] * bl
    fx = _f_lab(X / _XN)
    fy = _f_lab(Y / _YN)
    fz = _f_lab(Z / _ZN)
    L = 116.0 * fy - 16.0
    a = 500.0 * (fx - fy)
    bb = 200.0 * (fy - fz)
    hue = math.degrees(math.atan2(bb, a))
    if hue < 0.0:
        hue += 360.0
    chroma = math.sqrt(a * a + bb * bb)
    return (hue, chroma, L)


# ---------------------------------------------------------------------------
# Hex helpers
# ---------------------------------------------------------------------------
def _rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
    """``(r, g, b)`` → ``#rrggbb`` lowercase hex string."""
    r, g, b = rgb
    return "#{:02x}{:02x}{:02x}".format(
        max(0, min(255, int(r))),
        max(0, min(255, int(g))),
        max(0, min(255, int(b))),
    )


def _hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    """``#rrggbb`` (or ``#rgb``) → ``(r, g, b)`` integers."""
    s = hex_str.lstrip("#").strip()
    if len(s) == 3:
        s = "".join(ch * 2 for ch in s)
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


# ---------------------------------------------------------------------------
# Tonal palette
# ---------------------------------------------------------------------------
class TonalPalette:
    """A Material Design 3 tonal palette.

    A tonal palette fixes a hue and chroma and varies the tone
    (perceptual lightness L*) — the M3 color system's backbone for
    generating role colors (primary, neutral, surface tones, …).

    Pre-computed tones ``0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99,
    100`` are exposed as ``palette.tone_X`` attributes and as the
    ``palette.tones`` dict (int tone → hex string). Arbitrary tones are
    available via ``palette(tone)``.
    """

    _PRECOMPUTED: Tuple[int, ...] = (0, 10, 20, 30, 40, 50, 60, 70,
                                     80, 90, 95, 99, 100)

    def __init__(self, hue: float, chroma: float) -> None:
        """Build a palette for ``hue`` (degrees) and ``chroma`` (CIELAB)."""
        self.hue: float = float(hue)
        self.chroma: float = float(chroma)
        self.tones: Dict[int, str] = {}
        for t in self._PRECOMPUTED:
            value = self._compute(t)
            self.tones[t] = value
            setattr(self, "tone_{:d}".format(t), value)

    def _compute(self, tone: float) -> str:
        """Compute the hex string for an arbitrary tone."""
        return _rgb_to_hex(hct_to_rgb(self.hue, self.chroma, tone))

    def __call__(self, tone: float) -> str:
        """Return the sRGB hex string for ``tone`` (perceptual L*, 0..100)."""
        return self._compute(tone)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "TonalPalette(hue={!r}, chroma={!r})".format(self.hue, self.chroma)


# ---------------------------------------------------------------------------
# MaterialScheme dataclass + builder
# ---------------------------------------------------------------------------
@dataclass
class MaterialScheme:
    """A complete Material Design 3 color scheme as hex strings.

    Every field is a ``#RRGGBB`` hex string. The field set mirrors the
    Material 3 color roles: primary/secondary/tertiary/error pairs, the
    surface tonal set (surface, surface_dim/bright, surface_container_*),
    surface_variant, outline, inverse roles, scrim and shadow.
    """

    is_dark: bool
    primary: str
    on_primary: str
    primary_container: str
    on_primary_container: str
    secondary: str
    on_secondary: str
    secondary_container: str
    on_secondary_container: str
    tertiary: str
    on_tertiary: str
    tertiary_container: str
    on_tertiary_container: str
    error: str
    on_error: str
    error_container: str
    on_error_container: str
    background: str
    on_background: str
    surface: str
    on_surface: str
    surface_variant: str
    on_surface_variant: str
    surface_dim: str
    surface_bright: str
    surface_container_lowest: str
    surface_container_low: str
    surface_container: str
    surface_container_high: str
    surface_container_highest: str
    outline: str
    outline_variant: str
    inverse_surface: str
    inverse_on_surface: str
    inverse_primary: str
    scrim: str
    shadow: str


def scheme_from_seed(seed_rgb_hex: str, is_dark: bool) -> MaterialScheme:
    """Build a Material Design 3 :class:`MaterialScheme` from a seed color.

    The seed's hue is preserved across palettes; chromas follow the M3
    spec — primary ``min(seed_chroma, 48)``, secondary 16, tertiary 24
    (hue + 60°), error 84 at hue 25, neutral 4 and neutral-variant 8.
    Role → tone assignment follows the M3 light/dark tables.
    """
    sr, sg, sb = _hex_to_rgb(seed_rgb_hex)
    seed_hue, seed_chroma, _seed_tone = rgb_to_hct(sr, sg, sb)

    primary_pal = TonalPalette(seed_hue, min(seed_chroma, 48.0))
    secondary_pal = TonalPalette(seed_hue, 16.0)
    tertiary_pal = TonalPalette((seed_hue + 60.0) % 360.0, 24.0)
    error_pal = TonalPalette(25.0, 84.0)
    neutral_pal = TonalPalette(seed_hue, 4.0)
    neutral_variant_pal = TonalPalette(seed_hue, 8.0)

    if is_dark:
        return MaterialScheme(
            is_dark=True,
            primary=primary_pal(80),
            on_primary=primary_pal(20),
            primary_container=primary_pal(30),
            on_primary_container=primary_pal(90),
            secondary=secondary_pal(80),
            on_secondary=secondary_pal(20),
            secondary_container=secondary_pal(30),
            on_secondary_container=secondary_pal(90),
            tertiary=tertiary_pal(80),
            on_tertiary=tertiary_pal(20),
            tertiary_container=tertiary_pal(30),
            on_tertiary_container=tertiary_pal(90),
            error=error_pal(80),
            on_error=error_pal(20),
            error_container=error_pal(30),
            on_error_container=error_pal(90),
            background=neutral_pal(10),
            on_background=neutral_pal(90),
            surface=neutral_pal(10),
            on_surface=neutral_pal(90),
            surface_variant=neutral_variant_pal(30),
            on_surface_variant=neutral_variant_pal(80),
            surface_dim=neutral_pal(6),
            surface_bright=neutral_pal(24),
            surface_container_lowest=neutral_pal(4),
            surface_container_low=neutral_pal(10),
            surface_container=neutral_pal(12),
            surface_container_high=neutral_pal(17),
            surface_container_highest=neutral_pal(22),
            outline=neutral_variant_pal(60),
            outline_variant=neutral_variant_pal(30),
            inverse_surface=neutral_pal(90),
            inverse_on_surface=neutral_pal(20),
            inverse_primary=primary_pal(40),
            scrim=neutral_pal(0),
            shadow=neutral_pal(0),
        )
    return MaterialScheme(
        is_dark=False,
        primary=primary_pal(40),
        on_primary=primary_pal(100),
        primary_container=primary_pal(90),
        on_primary_container=primary_pal(10),
        secondary=secondary_pal(40),
        on_secondary=secondary_pal(100),
        secondary_container=secondary_pal(90),
        on_secondary_container=secondary_pal(10),
        tertiary=tertiary_pal(40),
        on_tertiary=tertiary_pal(100),
        tertiary_container=tertiary_pal(90),
        on_tertiary_container=tertiary_pal(10),
        error=error_pal(40),
        on_error=error_pal(100),
        error_container=error_pal(90),
        on_error_container=error_pal(10),
        background=neutral_pal(98),
        on_background=neutral_pal(10),
        surface=neutral_pal(98),
        on_surface=neutral_pal(10),
        surface_variant=neutral_variant_pal(90),
        on_surface_variant=neutral_variant_pal(30),
        surface_dim=neutral_pal(87),
        surface_bright=neutral_pal(98),
        surface_container_lowest=neutral_pal(100),
        surface_container_low=neutral_pal(96),
        surface_container=neutral_pal(94),
        surface_container_high=neutral_pal(92),
        surface_container_highest=neutral_pal(90),
        outline=neutral_variant_pal(50),
        outline_variant=neutral_variant_pal(80),
        inverse_surface=neutral_pal(20),
        inverse_on_surface=neutral_pal(95),
        inverse_primary=primary_pal(80),
        scrim=neutral_pal(0),
        shadow=neutral_pal(0),
    )


# ---------------------------------------------------------------------------
# Theme convenience
# ---------------------------------------------------------------------------
_PROTO_SEED: str = "#2f6d3f"   # proto-clean green


def md3_scheme_for(theme: str) -> Tuple[MaterialScheme, str]:
    """Return ``(scheme, accent_object_name)`` for a requested theme.

    ``theme == "dark"`` → dark scheme. ``theme == "light"`` → light
    scheme. ``theme == "system"`` defers resolution to the caller (we
    return a dark scheme as a safe default — :mod:`proto_clean.ui.theme`
    re-resolves at apply time via the desktop color-scheme hint).

    The accent object name is always ``"Connect"`` (Proto Clean's main
    connect button), matching the existing QSS API surface.
    """
    if theme == "light":
        return (scheme_from_seed(_PROTO_SEED, False), "Connect")
    # "dark" and "system" (caller resolves system) → dark default
    return (scheme_from_seed(_PROTO_SEED, True), "Connect")


# ---------------------------------------------------------------------------
# QSS generator
# ---------------------------------------------------------------------------
def _rgba(rgb: Tuple[int, int, int], alpha: float) -> str:
    """Format a Qt ``rgba(r, g, b, a)`` literal."""
    return "rgba({}, {}, {}, {})".format(rgb[0], rgb[1], rgb[2], alpha)


def md3_qss(scheme: MaterialScheme, *,
            accent_object_name: str = "Connect",
            danger_object_name: str = "Disconnect") -> str:
    """Generate a Material Design 3 Qt stylesheet for ``scheme``.

    Covers every Proto Clean widget selector: ``QWidget``, ``QMainWindow``
    / ``QDialog``, ``QLabel#Title`` / ``#Subtitle`` / ``#Stats`` /
    ``#LoginBanner`` (with ``[level="info"]`` variant) / ``#LoginNote``,
    ``QPushButton`` (MD3 text button + ``#Connect``/``#Disconnect``
    filled buttons), ``QLineEdit`` / ``QComboBox`` / ``QSpinBox`` (filled
    text field), ``QTableWidget`` + ``QHeaderView::section``, ``QTabBar``
    (pill tabs), ``QCheckBox`` / ``QRadioButton`` indicators, status bar,
    tooltips, scroll bars, and menus.
    """
    primary_rgb = _hex_to_rgb(scheme.primary)
    on_surface_rgb = _hex_to_rgb(scheme.on_surface)

    # MD3 elevation tint: dark mode windows sit on surface_container_low,
    # light mode on the flat background.
    window_bg = (scheme.surface_container_low
                 if scheme.is_dark else scheme.background)

    parts = []
    add = parts.append

    add("/* Material Design 3 QSS — generated by proto_clean.ui.md3 */")
    add("")

    # --- global -----------------------------------------------------------
    add("QWidget {")
    add("    background-color: {};".format(scheme.background))
    add("    color: {};".format(scheme.on_background))
    add("    font-family: 'Inter', 'Segoe UI', 'Noto Sans', sans-serif;")
    add("    font-size: 13px;")
    add("}")
    add("")
    add("QMainWindow, QDialog {")
    add("    background-color: {};".format(window_bg))
    add("}")
    add("")

    # --- labels -----------------------------------------------------------
    add("QLabel#Title {")                                    # headline-small
    add("    font-size: 22px;")
    add("    font-weight: 600;")
    add("    color: {};".format(scheme.on_surface))
    add("}")
    add("")
    add("QLabel#Subtitle, QLabel#Stats {")                   # 12px variant
    add("    font-size: 12px;")
    add("    color: {};".format(scheme.on_surface_variant))
    add("}")
    add("")

    # --- login banner -----------------------------------------------------
    add("QLabel#LoginBanner {")
    add("    background-color: {};".format(scheme.surface_container_high))
    add("    color: {};".format(scheme.on_surface_variant))
    add("    border-radius: {};".format(SHAPE_MEDIUM))
    add("    border-left: 4px solid {};".format(scheme.outline_variant))
    add("    padding: 12px 16px;")
    add("}")
    add("")
    add('QLabel#LoginBanner[level="info"] {')
    add("    background-color: {};".format(scheme.tertiary_container))
    add("    border-left: 4px solid {};".format(scheme.tertiary))
    add("}")
    add("")
    add("QLabel#LoginNote {")
    add("    font-size: 12px;")
    add("    color: {};".format(scheme.on_surface_variant))
    add("}")
    add("")

    # --- buttons ----------------------------------------------------------
    add("QPushButton {")                                    # MD3 text button
    add("    background-color: transparent;")
    add("    color: {};".format(scheme.on_surface))
    add("    border: none;")
    add("    padding: 8px 12px;")
    add("    border-radius: {};".format(SHAPE_SMALL))
    add("}")
    add("")
    add("QPushButton:hover {")
    add("    background-color: {};".format(_rgba(primary_rgb, 0.08)))
    add("}")
    add("")
    add("QPushButton:pressed {")
    add("    background-color: {};".format(_rgba(primary_rgb, 0.12)))
    add("}")
    add("")
    add("QPushButton:disabled {")
    add("    color: {};".format(scheme.outline_variant))
    add("    background-color: transparent;")
    add("}")
    add("")

    # MD3 filled button — high emphasis (pill / full radius)
    add("QPushButton#{} {{".format(accent_object_name))
    add("    background-color: {};".format(scheme.primary))
    add("    color: {};".format(scheme.on_primary))
    add("    border: none;")
    add("    border-radius: 20px;")
    add("    padding: 10px 24px;")
    add("    font-weight: 600;")
    add("    font-size: 14px;")
    add("}")
    add("")
    add("QPushButton#{}:hover {{".format(accent_object_name))
    add("    background-color: {};".format(scheme.primary_container))
    add("}")
    add("")
    add("QPushButton#{}:disabled {{".format(accent_object_name))
    add("    background-color: {};".format(_rgba(on_surface_rgb, 0.12)))
    add("    color: {};".format(_rgba(on_surface_rgb, 0.38)))
    add("}")
    add("")

    # MD3 filled danger button (same shape as filled)
    add("QPushButton#{} {{".format(danger_object_name))
    add("    background-color: {};".format(scheme.error))
    add("    color: {};".format(scheme.on_error))
    add("    border: none;")
    add("    border-radius: 20px;")
    add("    padding: 10px 24px;")
    add("    font-weight: 600;")
    add("    font-size: 14px;")
    add("}")
    add("")
    add("QPushButton#{}:hover {{".format(danger_object_name))
    add("    background-color: {};".format(scheme.error_container))
    add("}")
    add("")
    add("QPushButton#{}:disabled {{".format(danger_object_name))
    add("    background-color: {};".format(_rgba(on_surface_rgb, 0.12)))
    add("    color: {};".format(_rgba(on_surface_rgb, 0.38)))
    add("}")
    add("")

    # MD3 filled-tonal button — medium emphasis (used for "Continue as
    # guest": lower emphasis than the primary "Log in" CTA but higher
    # than a plain text button). Same pill shape as the filled button.
    add("QPushButton#GuestButton {")
    add("    background-color: {};".format(scheme.secondary_container))
    add("    color: {};".format(scheme.on_secondary_container))
    add("    border: none;")
    add("    border-radius: 20px;")
    add("    padding: 10px 24px;")
    add("    font-weight: 500;")
    add("    font-size: 14px;")
    add("}")
    add("")
    add("QPushButton#GuestButton:hover {")
    add("    background-color: {};".format(scheme.tertiary_container))
    add("}")
    add("")
    add("QPushButton#GuestButton:disabled {")
    add("    background-color: {};".format(_rgba(on_surface_rgb, 0.12)))
    add("    color: {};".format(_rgba(on_surface_rgb, 0.38)))
    add("}")
    add("")

    # MD3 divider — thin outline-variant rule. Used to separate the
    # account-login block from the guest-mode block in the login dialog.
    add("QFrame#M3Divider {")
    add("    background-color: transparent;")
    add("    border: none;")
    add("    border-top: 1px solid {};".format(scheme.outline_variant))
    add("    max-height: 1px;")
    add("    min-height: 1px;")
    add("}")
    add("")

    # Plan / guest-mode indicator label (small chip-style text in the
    # main window's header — "plan: free" / "guest mode — free servers").
    add("QLabel#Plan {")
    add("    font-size: 12px;")
    add("    color: {};".format(scheme.on_surface_variant))
    add("    background-color: {};".format(scheme.secondary_container))
    add("    color: {};".format(scheme.on_secondary_container))
    add("    border: none;")
    add("    border-radius: 8px;")
    add("    padding: 4px 10px;")
    add("}")
    add("")

    # --- inputs (MD3 filled text field) -----------------------------------
    add("QLineEdit, QComboBox, QSpinBox {")
    add("    background-color: {};".format(scheme.surface_container_highest))
    add("    border: none;")
    add("    border-bottom: 1px solid {};".format(scheme.outline))
    add("    border-radius: {}px {}px 0 0;".format(SHAPE_EXTRA_SMALL,
                                                   SHAPE_EXTRA_SMALL))
    add("    padding: 8px 12px;")
    add("    selection-background-color: {};".format(scheme.primary))
    add("    selection-color: {};".format(scheme.on_primary))
    add("}")
    add("")
    add("QLineEdit:focus, QComboBox:focus, QSpinBox:focus {")
    add("    border-bottom: 2px solid {};".format(scheme.primary))
    add("    padding-bottom: 7px;")
    add("}")
    add("")
    add("QComboBox QAbstractItemView {")
    add("    background-color: {};".format(scheme.surface_container_high))
    add("    selection-background-color: {};".format(scheme.primary))
    add("    selection-color: {};".format(scheme.on_primary))
    add("}")
    add("")

    # --- tables -----------------------------------------------------------
    add("QTableWidget {")
    add("    background-color: {};".format(scheme.surface_container_low))
    add("    alternate-background-color: {};".format(scheme.surface_container))
    add("    border: none;")
    add("    border-radius: {};".format(SHAPE_MEDIUM))
    add("}")
    add("")
    add("QHeaderView::section {")
    add("    background-color: {};".format(scheme.surface_container_high))
    add("    color: {};".format(scheme.on_surface_variant))
    add("    border: none;")
    add("    border-bottom: 1px solid {};".format(scheme.outline_variant))
    add("    padding: 10px 12px;")
    add("    font-weight: 600;")
    add("}")
    add("")
    add("QTableWidget::item {")
    add("    padding: 8px;")
    add("}")
    add("")
    add("QTableWidget::item:selected {")
    add("    background-color: {};".format(_rgba(primary_rgb, 0.12)))
    add("    color: {};".format(scheme.on_surface))
    add("}")
    add("")

    # --- tabs (MD3 pill tabs) ---------------------------------------------
    add("QTabWidget::pane {")
    add("    border: none;")
    add("    border-radius: {};".format(SHAPE_MEDIUM))
    add("}")
    add("")
    add("QTabBar::tab {")
    add("    background: transparent;")
    add("    color: {};".format(scheme.on_surface_variant))
    add("    padding: 8px 16px;")
    add("    margin: 4px 2px;")
    add("    border-radius: 16px;")
    add("    border: none;")
    add("}")
    add("")
    add("QTabBar::tab:selected {")
    add("    background-color: {};".format(scheme.secondary_container))
    add("    color: {};".format(scheme.on_secondary_container))
    add("}")
    add("")

    # --- checkboxes / radios ----------------------------------------------
    add("QCheckBox::indicator, QRadioButton::indicator {")
    add("    width: 18px;")
    add("    height: 18px;")
    add("    border-radius: {};".format(SHAPE_EXTRA_SMALL))
    add("    border: 2px solid {};".format(scheme.outline))
    add("    background: transparent;")
    add("}")
    add("")
    add("QCheckBox::indicator:checked, QRadioButton::indicator:checked {")
    add("    background: {};".format(scheme.primary))
    add("    border-color: {};".format(scheme.primary))
    add("}")
    add("")

    # --- status bar / tooltips --------------------------------------------
    add("QStatusBar {")
    add("    color: {};".format(scheme.on_surface_variant))
    add("    background: transparent;")
    add("}")
    add("")
    add("QToolTip {")
    add("    background-color: {};".format(scheme.surface_container_high))
    add("    color: {};".format(scheme.on_surface))
    add("    border: none;")
    add("    border-radius: {};".format(SHAPE_EXTRA_SMALL))
    add("    padding: 6px 8px;")
    add("}")
    add("")

    # --- scroll bars (MD3 thin pill handles) ------------------------------
    add("QScrollBar:vertical {")
    add("    background: transparent;")
    add("    width: 8px;")
    add("    margin: 0;")
    add("}")
    add("")
    add("QScrollBar::handle:vertical {")
    add("    background: {};".format(scheme.outline_variant))
    add("    border-radius: {};".format(SHAPE_EXTRA_SMALL))
    add("    min-height: 32px;")
    add("}")
    add("")
    add("QScrollBar::handle:vertical:hover {")
    add("    background: {};".format(scheme.outline))
    add("}")
    add("")
    add("QScrollBar::add-line, QScrollBar::sub-line {")
    add("    height: 0;")
    add("    width: 0;")
    add("}")
    add("")

    # --- menus ------------------------------------------------------------
    add("QMenu {")
    add("    background-color: {};".format(scheme.surface_container))
    add("    color: {};".format(scheme.on_surface))
    add("    border-radius: {};".format(SHAPE_SMALL))
    add("    padding: 4px;")
    add("}")
    add("")
    add("QMenu::item {")
    add("    padding: 8px 16px;")
    add("    border-radius: {};".format(SHAPE_EXTRA_SMALL))
    add("}")
    add("")
    add("QMenu::item:selected {")
    add("    background-color: {};".format(_rgba(primary_rgb, 0.08)))
    add("}")
    add("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# QPalette role mapping (consumed by proto_clean.ui.theme._apply_palette)
# ---------------------------------------------------------------------------
def md3_palette_qss(scheme: MaterialScheme) -> Dict[str, str]:
    """Map Qt ``QPalette`` role names to hex strings for ``scheme``.

    Returns a plain dict so :mod:`proto_clean.ui.theme` (the only consumer
    that actually needs a real ``QColor``) can construct the palette
    without dragging Qt into this module. The ``"Disabled"`` entry is
    the disabled-text color (applied to WindowText / Text / ButtonText
    in the ``QPalette.Disabled`` group by the caller).
    """
    return {
        "Window": scheme.surface_container_low,
        "WindowText": scheme.on_surface,
        "Base": scheme.surface_container,
        "Text": scheme.on_surface,
        "Button": scheme.surface_container_high,
        "ButtonText": scheme.on_surface,
        "Highlight": scheme.primary,
        "HighlightedText": scheme.on_primary,
        "ToolTipBase": scheme.surface_container_high,
        "ToolTipText": scheme.on_surface,
        "PlaceholderText": scheme.on_surface_variant,
        "Link": scheme.primary,
        "AlternateBase": scheme.surface_container_highest,
        "Disabled": scheme.outline_variant,
    }


# ---------------------------------------------------------------------------
# State colors (connection-state dot + label)
# ---------------------------------------------------------------------------
def state_colors(scheme: MaterialScheme) -> Dict[str, Tuple[str, str]]:
    """Build the Proto Clean connection-state palette for ``scheme``.

    Returns a ``state → (color_hex, label)`` mapping. Most dots are fixed
    semantic colors (blue=ready, amber=transitioning, green=protected);
    ``logged_out`` uses the scheme's outline and ``error`` uses the
    scheme's error role, so dark/light themes get matching tones.
    """
    return {
        "logged_out": (scheme.outline, "Not logged in"),
        "logged_in": ("#3b82f6", "Ready"),
        "connecting": ("#f59e0b", "Connecting…"),
        "connected": ("#22c55e", "Protected"),
        "disconnecting": ("#f59e0b", "Disconnecting…"),
        "error": (scheme.error, "Error"),
    }


# ---------------------------------------------------------------------------
# Default schemes + QSS
# ---------------------------------------------------------------------------
DARK_SCHEME, _DARK_ACCENT = md3_scheme_for("dark")
LIGHT_SCHEME, _LIGHT_ACCENT = md3_scheme_for("light")

DARK_QSS: str = md3_qss(DARK_SCHEME)
LIGHT_QSS: str = md3_qss(LIGHT_SCHEME)

# Backward-compat module-level STATE_COLORS (computed from the dark scheme).
# The orchestrator re-exports a matching constant from proto_clean.ui.theme.
STATE_COLORS: Dict[str, Tuple[str, str]] = state_colors(DARK_SCHEME)

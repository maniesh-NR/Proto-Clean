"""Tests for the Material Design 3 color + QSS system (proto_clean.ui.md3).

Covers the HCT color space round-trip, the tonal palette, the scheme
builder, the QSS generator and the state-color helper. The MD3 module is
Qt-free at import time, so the tests run with no Qt binding available.
"""

from __future__ import annotations

import re

import pytest

from proto_clean.ui import md3
from proto_clean.ui.md3 import (
    DARK_QSS,
    DARK_SCHEME,
    LIGHT_QSS,
    LIGHT_SCHEME,
    MaterialScheme,
    TonalPalette,
    hct_to_rgb,
    md3_palette_qss,
    md3_qss,
    md3_scheme_for,
    rgb_to_hct,
    scheme_from_seed,
    state_colors,
)


# ----------------------------------------------------------------- helpers
def _tone_of(hex_str: str) -> float:
    """Perceptual lightness L* of a ``#rrggbb`` hex string."""
    s = hex_str.lstrip("#")
    r, g, b = int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)
    return rgb_to_hct(r, g, b)[2]


# ----------------------------------------------------------------- HCT core
def test_hct_mid_gray():
    """HCT(0, 0, 50) is a near-mid gray (achromatic, L*≈50)."""
    r, g, b = hct_to_rgb(0, 0, 50)
    assert 110 <= r <= 150
    assert 110 <= g <= 150
    assert 110 <= b <= 150
    # channels agree within 5 (no residual chroma)
    assert max(r, g, b) - min(r, g, b) <= 5


def test_hct_white():
    """HCT(0, 0, 100) is pure white."""
    assert hct_to_rgb(0, 0, 100) == (255, 255, 255)


def test_hct_black():
    """HCT(0, 0, 0) is pure black."""
    assert hct_to_rgb(0, 0, 0) == (0, 0, 0)


def test_hct_round_trip_green():
    """rgb_to_hct inverts hct_to_rgb approximately for a saturated green."""
    hue, chroma, tone = 140.0, 48.0, 40.0
    rgb = hct_to_rgb(hue, chroma, tone)
    h2, c2, t2 = rgb_to_hct(*rgb)
    assert abs(h2 - hue) <= 5.0
    assert abs(c2 - chroma) <= 5.0
    assert abs(t2 - tone) <= 2.0


def test_hct_round_trip_gray_axis():
    """Achromatic HCT round-trips with zero chroma and zero hue (any angle)."""
    # gray has chroma 0 and arbitrary hue; just check chroma ~ 0 and tone round-trips
    for tone in (10, 25, 50, 75, 90):
        r, g, b = hct_to_rgb(42.0, 0.0, tone)
        _h, c, t = rgb_to_hct(r, g, b)
        assert c <= 1.0
        assert abs(t - tone) <= 1.5


# ----------------------------------------------------------------- palette
def test_tonal_palette_call_returns_hex():
    """TonalPalette is callable and returns a 7-char hex string."""
    palette = TonalPalette(140.0, 48.0)
    hex_str = palette(40)
    assert isinstance(hex_str, str)
    assert hex_str.startswith("#")
    assert len(hex_str) == 7


def test_tonal_palette_precomputed_tones_monotonic_in_lightness():
    """Tonal palette tones 40 and 80 differ and 80 is lighter (higher L*)."""
    palette = TonalPalette(140.0, 48.0)
    t40 = _tone_of(palette.tone_40)
    t80 = _tone_of(palette.tone_80)
    assert t80 > t40
    # full monotonic check over the precomputed tones
    tones = [palette.tones[t] for t in sorted(palette.tones)]
    Ls = [_tone_of(h) for h in tones]
    for prev, cur in zip(Ls, Ls[1:]):
        assert cur >= prev - 0.5     # allow a tiny numerical jitter


def test_tonal_palette_attributes_and_dict_match():
    """``palette.tone_X`` matches ``palette.tones[X]`` for every precomputed tone."""
    palette = TonalPalette(250.0, 30.0)
    for t in palette.tones:
        assert getattr(palette, "tone_{}".format(t)) == palette.tones[t]


# ----------------------------------------------------------------- scheme
@pytest.mark.parametrize("is_dark", [True, False])
def test_scheme_primary_vs_on_primary_contrast(is_dark: bool):
    """Dark: primary lighter than on_primary; light: primary darker than on_primary."""
    scheme = scheme_from_seed("#2f6d3f", is_dark=is_dark)
    L_primary = _tone_of(scheme.primary)
    L_on_primary = _tone_of(scheme.on_primary)
    if is_dark:
        assert L_primary > L_on_primary
    else:
        assert L_primary < L_on_primary


def test_scheme_dark_and_light_primaries_differ():
    """Dark primary (tone 80) and light primary (tone 40) are not equal hex."""
    dark = scheme_from_seed("#2f6d3f", is_dark=True)
    light = scheme_from_seed("#2f6d3f", is_dark=False)
    assert dark.primary != light.primary


def test_scheme_has_all_roles():
    """MaterialScheme exposes every M3 role as a non-empty hex string."""
    scheme = DARK_SCHEME
    expected = {
        "is_dark",
        "primary", "on_primary", "primary_container", "on_primary_container",
        "secondary", "on_secondary", "secondary_container",
        "on_secondary_container",
        "tertiary", "on_tertiary", "tertiary_container",
        "on_tertiary_container",
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
    }
    fields = set(scheme.__dataclass_fields__.keys())
    assert fields == expected
    for name in fields:
        if name == "is_dark":
            assert getattr(scheme, name) is True
            continue
        v = getattr(scheme, name)
        assert isinstance(v, str) and v.startswith("#") and len(v) == 7, name


def test_scheme_dark_surfaces_darker_than_light():
    """Every dark surface_container_* has lower L* than its light counterpart.

    Also verifies the on-paper M3 ordering within each scheme:
    lowest < low < container < high < highest in L* (dark) — and the
    reverse for light, since light "lowest" is the LIGHTEST (highest L*).
    """
    dark = DARK_SCHEME
    light = LIGHT_SCHEME
    names = [
        "surface_container_lowest",
        "surface_container_low",
        "surface_container",
        "surface_container_high",
        "surface_container_highest",
    ]
    for name in names:
        d_L = _tone_of(getattr(dark, name))
        l_L = _tone_of(getattr(light, name))
        assert d_L < l_L, (name, d_L, l_L)
    # Within dark: lowest is darkest, highest is lightest (ascending L*).
    d_Ls = [_tone_of(getattr(dark, n)) for n in names]
    assert d_Ls == sorted(d_Ls)
    # Within light: lowest is lightest, highest is darkest (descending L*).
    l_Ls = [_tone_of(getattr(light, n)) for n in names]
    assert l_Ls == sorted(l_Ls, reverse=True)


# ----------------------------------------------------------------- QSS
def test_md3_qss_contains_all_required_selectors():
    """The MD3 QSS covers every selector the rest of the codebase expects."""
    scheme = DARK_SCHEME
    qss = md3_qss(scheme)
    assert isinstance(qss, str) and qss
    required = [
        "QWidget",
        "QLabel#Title",
        "QLabel#LoginBanner",
        "QPushButton#Connect",
        "QPushButton#Disconnect",
        "QLineEdit",
        "QTableWidget",
        "QHeaderView::section",
        "QTabBar::tab",
        "QCheckBox::indicator",
        "QScrollBar:vertical",
        "QMenu",
        "QPushButton:disabled",
    ]
    for token in required:
        assert token in qss, token


def test_dark_qss_and_light_qss_differ_and_nonempty():
    """DARK_QSS != LIGHT_QSS and both are non-empty."""
    assert DARK_QSS
    assert LIGHT_QSS
    assert DARK_QSS != LIGHT_QSS


def test_md3_qss_no_sharp_corners():
    """Every border-radius value is either >= 4 px or 0 (MD3 filled text field)."""
    pattern = re.compile(r"border-radius:\s*([^;]+);")
    for qss in (DARK_QSS, LIGHT_QSS):
        for match in pattern.finditer(qss):
            value = match.group(1)
            nums = [int(x) for x in re.findall(r"(\d+)", value)]
            for n in nums:
                # 0 is allowed: MD3 filled text field has sharp bottom corners.
                # Everything else must be >= 4 (the M3 extra-small shape step).
                assert n == 0 or n >= 4, (n, value)


def test_md3_qss_uses_scheme_primary_for_connect_button():
    """The accent filled button is painted with the scheme primary."""
    scheme = DARK_SCHEME
    qss = md3_qss(scheme)
    # Find the QPushButton#Connect block and confirm primary is in there.
    block = re.search(r"QPushButton#Connect\s*\{[^}]*\}", qss)
    assert block is not None
    assert scheme.primary in block.group(0)
    assert scheme.on_primary in block.group(0)


def test_md3_qss_accent_object_name_is_overridable():
    """A custom accent object name flows into the QSS."""
    scheme = DARK_SCHEME
    qss = md3_qss(scheme, accent_object_name="GoButton",
                  danger_object_name="StopButton")
    assert "QPushButton#GoButton" in qss
    assert "QPushButton#StopButton" in qss
    assert "QPushButton#Connect" not in qss


# ----------------------------------------------------------------- palette role map
def test_md3_palette_qss_has_all_roles():
    """md3_palette_qss returns hex strings for every expected QPalette role."""
    roles = md3_palette_qss(DARK_SCHEME)
    expected = {
        "Window", "WindowText", "Base", "Text", "Button", "ButtonText",
        "Highlight", "HighlightedText", "ToolTipBase", "ToolTipText",
        "PlaceholderText", "Link", "AlternateBase", "Disabled",
    }
    assert set(roles.keys()) == expected
    for k, v in roles.items():
        assert isinstance(v, str) and v.startswith("#") and len(v) == 7, k


# ----------------------------------------------------------------- state colors
def test_state_colors_error_matches_scheme():
    """state_colors(scheme)['error'][0] is scheme.error (per-scheme refresh)."""
    sc = state_colors(DARK_SCHEME)
    assert sc["error"][0] == DARK_SCHEME.error
    assert sc["error"][1] == "Error"


def test_state_colors_keeps_fixed_dots():
    """Semantic-state dots stay fixed across schemes (blue/amber/green)."""
    sc = state_colors(LIGHT_SCHEME)
    assert sc["logged_in"][0] == "#3b82f6"
    assert sc["connecting"][0] == "#f59e0b"
    assert sc["connected"][0] == "#22c55e"
    assert sc["disconnecting"][0] == "#f59e0b"
    assert sc["logged_out"][0] == LIGHT_SCHEME.outline


def test_module_level_state_colors_constant():
    """Module-level STATE_COLORS (dark-scheme-derived) is non-empty and well-formed."""
    assert isinstance(md3.STATE_COLORS, dict)
    expected_keys = {
        "logged_out", "logged_in", "connecting", "connected",
        "disconnecting", "error",
    }
    assert set(md3.STATE_COLORS.keys()) == expected_keys
    assert md3.STATE_COLORS["error"][0] == DARK_SCHEME.error


# ----------------------------------------------------------------- convenience
def test_md3_scheme_for_returns_scheme_and_accent():
    """md3_scheme_for yields (MaterialScheme, 'Connect') for dark/light/system."""
    for theme in ("dark", "light", "system"):
        scheme, accent = md3_scheme_for(theme)
        assert isinstance(scheme, MaterialScheme)
        assert accent == "Connect"
    assert md3_scheme_for("dark")[0].is_dark is True
    assert md3_scheme_for("light")[0].is_dark is False
    # 'system' falls back to dark (caller re-resolves)
    assert md3_scheme_for("system")[0].is_dark is True


def test_module_default_constants_match_builder():
    """DARK_SCHEME / LIGHT_SCHEME match scheme_from_seed for the proto seed."""
    assert DARK_SCHEME.primary == scheme_from_seed("#2f6d3f", True).primary
    assert LIGHT_SCHEME.primary == scheme_from_seed("#2f6d3f", False).primary
    assert DARK_QSS == md3_qss(DARK_SCHEME)
    assert LIGHT_QSS == md3_qss(LIGHT_SCHEME)


def test_shape_constants_exposed():
    """MD3 shape corner-radius constants are exposed with the spec values."""
    assert md3.SHAPE_EXTRA_SMALL == 4
    assert md3.SHAPE_SMALL == 8
    assert md3.SHAPE_MEDIUM == 12
    assert md3.SHAPE_LARGE == 16
    assert md3.SHAPE_EXTRA_LARGE == 28

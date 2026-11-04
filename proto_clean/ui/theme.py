"""Themes for Proto Clean — Material Design 3 (Qt stylesheets).

The desktop UI is themed with a real Material Design 3 system:
HCT tonal palettes, MD3 color roles and MD3 widget styles (filled
buttons, filled text fields, pill tabs, surface containers, etc.).
The seed color is the Proto Clean brand green ``#2f6d3f`` so the
project's identity is preserved while every other color is derived
from a Material tonal palette.

apply_theme(app, mode) styles the whole application:

* "dark"   — Material 3 dark scheme (surface = tone 10);
* "light"  — Material 3 light scheme (surface = tone 98);
* "system" — follows the desktop color scheme and live-switches when the
  desktop switches (Qt colorSchemeChanged, Qt >= 6.5; falls back to the
  GNOME color-scheme gsettings key, then to the palette lightness).

The module tracks the effective mode so runtime painters (icons, load
bars) can pick theme-matching colors via is_dark(). The MD3-derived
``DARK_SCHEME`` / ``LIGHT_SCHEME`` objects expose all Material 3 color
roles for runtime painters (e.g. ``DARK_SCHEME.primary_container``,
``LIGHT_SCHEME.surface_container_high``).
"""

from __future__ import annotations

# Qt is imported lazily inside the functions that actually need it
# (apply_theme, system_prefers_dark) so this module can be imported
# headlessly to read DARK_QSS / LIGHT_QSS / STATE_COLORS — which is
# what the test suite does.
from .md3 import (
    DARK_QSS,
    LIGHT_QSS,
    DARK_SCHEME,
    LIGHT_SCHEME,
    MaterialScheme,
    md3_palette_qss,
    md3_qss,
    md3_scheme_for,
    scheme_from_seed,
    state_colors as _state_colors_for,
)

# Backward-compat alias (old imports / scripts use `QSS`).
QSS = DARK_QSS

THEMES = ("system", "light", "dark")

THEME_LABELS = {
    "system": "System theme",
    "light": "Light mode",
    "dark": "Dark mode",
}

# module state: what was requested / what is actually painted
_requested: str = "dark"
_effective: str = "dark"
_scheme_connected = False


def system_prefers_dark() -> bool:
    """Best-effort desktop color-scheme detection."""
    from proto_clean.qtcompat import QGuiApplication, Qt

    app = QGuiApplication.instance()
    if app is not None:
        try:                                   # Qt >= 6.5: real platform hint
            scheme = app.styleHints().colorScheme()
            dark = getattr(Qt.ColorScheme, "Dark", None)
            light = getattr(Qt.ColorScheme, "Light", None)
            if dark is not None and scheme == dark:
                return True
            if light is not None and scheme == light:
                return False
        except Exception:                      # noqa: BLE001 — older Qt
            pass
    try:                                       # GNOME fallback (gsettings key)
        import subprocess

        out = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.interface",
             "color-scheme"],
            capture_output=True, text=True, timeout=3)
        val = (out.stdout or "").strip().strip("'\"")
        if out.returncode == 0 and val:
            return "dark" in val.lower()
    except Exception:                          # noqa: BLE001 — no gsettings
        pass
    if app is not None:                        # last resort: palette lightness
        try:
            return app.palette().window().color().lightness() < 128
        except Exception:                      # noqa: BLE001
            pass
    return True                                # default: dark


def resolve_theme(mode: str) -> str:
    """Map a requested mode ("system"/"light"/"dark") to dark or light."""
    if mode not in THEMES:
        mode = "dark"
    if mode == "system":
        return "dark" if system_prefers_dark() else "light"
    return mode


def effective_theme() -> str:
    """The mode actually painted right now: "dark" or "light"."""
    return _effective


def is_dark() -> bool:
    """True when the currently applied look is dark (for runtime painters)."""
    return _effective == "dark"


def effective_scheme() -> MaterialScheme:
    """The MaterialScheme object currently in effect (for runtime painters
    that want full MD3 color roles, not just dark/light)."""
    return DARK_SCHEME if _effective == "dark" else LIGHT_SCHEME


def stylesheet_for(mode: str) -> str:
    return DARK_QSS if resolve_theme(mode) == "dark" else LIGHT_QSS


def apply_theme(app, mode: str = "dark") -> str:
    """Apply the requested theme to the whole application.

    Returns the effective mode ("dark" or "light"). In "system" mode the
    application keeps following the desktop color scheme live.
    """
    global _requested, _effective
    _requested = mode if mode in THEMES else "dark"
    _effective = resolve_theme(_requested)
    app.setStyleSheet(DARK_QSS if _effective == "dark" else LIGHT_QSS)
    _apply_palette(app, _effective)
    _update_scheme_listener(app)
    return _effective


def _apply_palette(app, effective: str) -> None:
    """Keep the base palette in sync so native bits (menus, popups, edits)
    that the stylesheet does not cover still match the Material 3 scheme."""
    from proto_clean.qtcompat import QColor, QPalette

    scheme = DARK_SCHEME if effective == "dark" else LIGHT_SCHEME
    roles_map = md3_palette_qss(scheme)

    p = QPalette()
    # The md3_palette_qss map uses Qt role names as string keys
    # (Window, WindowText, Base, Text, Button, ButtonText, Highlight,
    #  HighlightedText, ToolTipBase, ToolTipText, PlaceholderText,
    #  AlternateBase, Link). Material 3 roles map to:
    #   Window        → surface_container_low
    #   WindowText    → on_surface
    #   Base          → surface_container_highest (edit/list backgrounds)
    #   AlternateBase → surface_container
    #   Text          → on_surface
    #   Button        → surface_container_high
    #   ButtonText    → on_surface
    #   Highlight     → primary
    #   HighlightedText → on_primary
    #   ToolTipBase   → surface_container_highest
    #   ToolTipText   → on_surface
    #   PlaceholderText → on_surface_variant
    #   AlternateBase → surface_container
    #   Link          → primary
    material_palette = {
        "Window": scheme.surface_container_low,
        "WindowText": scheme.on_surface,
        "Base": scheme.surface_container_highest,
        "AlternateBase": scheme.surface_container,
        "Text": scheme.on_surface,
        "Button": scheme.surface_container_high,
        "ButtonText": scheme.on_surface,
        "Highlight": scheme.primary,
        "HighlightedText": scheme.on_primary,
        "ToolTipBase": scheme.surface_container_highest,
        "ToolTipText": scheme.on_surface,
        "PlaceholderText": scheme.on_surface_variant,
        "Link": scheme.primary,
    }
    disabled = scheme.outline_variant

    # Resolve Qt role names → QPalette role enum values
    role_name_to_enum = {
        "Window": getattr(QPalette, "Window", None),
        "WindowText": getattr(QPalette, "WindowText", None),
        "Base": getattr(QPalette, "Base", None),
        "AlternateBase": getattr(QPalette, "AlternateBase", None),
        "Text": getattr(QPalette, "Text", None),
        "Button": getattr(QPalette, "Button", None),
        "ButtonText": getattr(QPalette, "ButtonText", None),
        "Highlight": getattr(QPalette, "Highlight", None),
        "HighlightedText": getattr(QPalette, "HighlightedText", None),
        "ToolTipBase": getattr(QPalette, "ToolTipBase", None),
        "ToolTipText": getattr(QPalette, "ToolTipText", None),
        "PlaceholderText": getattr(QPalette, "PlaceholderText", None),
        "Link": getattr(QPalette, "Link", None),
    }
    for name, color_hex in material_palette.items():
        role = role_name_to_enum.get(name)
        if role is not None and color_hex:
            p.setColor(role, QColor(color_hex))
    # Disabled state
    for name in ("WindowText", "Text", "ButtonText"):
        role = role_name_to_enum.get(name)
        if role is not None:
            p.setColor(QPalette.Disabled, role, QColor(disabled))
    app.setPalette(p)


def _update_scheme_listener(app) -> None:
    """Connect/disconnect the live "system theme changed" hook."""
    global _scheme_connected
    hints = app.styleHints()
    signal = getattr(hints, "colorSchemeChanged", None)
    want = _requested == "system" and signal is not None
    if want and not _scheme_connected:
        signal.connect(_on_scheme_changed)
        _scheme_connected = True
    elif not want and _scheme_connected:
        try:
            signal.disconnect(_on_scheme_changed)
        except (RuntimeError, TypeError):
            pass
        _scheme_connected = False


def _on_scheme_changed(_scheme=None) -> None:
    """The desktop switched light/dark — re-resolve in system mode."""
    from proto_clean.qtcompat import QApplication

    app = QApplication.instance()
    if app is not None and _requested == "system":
        apply_theme(app, "system")


# State → (dot color, text color, label) — derived from the active MD3
# scheme so the dots stay readable on both light and dark surfaces.
# Kept as a module-level constant for backward compat with callers that
# do ``from proto_clean.ui.theme import STATE_COLORS``; the lookup is
# always the dark-scheme values (mid-tones readable on both themes).
STATE_COLORS = _state_colors_for(DARK_SCHEME)

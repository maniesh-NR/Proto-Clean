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
bars) can pick theme-matching colors via is_dark(). For full MD3 color
roles at runtime use :func:`effective_scheme` — it always reflects the
active Material You seed (e.g. ``effective_scheme().primary_container``).
Do NOT import ``DARK_SCHEME`` / ``LIGHT_SCHEME`` / ``STATE_COLORS`` by
value in runtime painters: those constants are rebound when the seed
changes, so a name captured at import time goes stale. Accessor forms:
:func:`effective_scheme`, :func:`state_color`, :func:`stylesheet_for`.
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

# Material You: the brand seed mirrors md3._PROTO_SEED / settings' default.
_BRAND_SEED = "#2f6d3f"

# module state: what was requested / what is actually painted
_requested: str = "dark"
_effective: str = "dark"
_scheme_connected = False

# Material You dynamic color state: where the scheme seed comes from
# ("brand" | "system" | "custom"), the custom seed hex, and the seed the
# current module-level schemes were generated from. `set_accent` configures
# the source, `apply_theme` (re)generates DARK_SCHEME / LIGHT_SCHEME /
# DARK_QSS / LIGHT_QSS / STATE_COLORS from the resolved seed.
_accent_source: str = "brand"
_accent_custom: str = _BRAND_SEED
_active_seed: str = _BRAND_SEED


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


# ------------------------------------------------------ Material You seed
def system_accent_color():
    r"""Best-effort OS accent color as a ``#rrggbb`` seed (None if unknown).

    Desktop analogue of Android's wallpaper-derived dynamic color:

    * **Windows 10/11** — ``HKCU\Software\Microsoft\Windows\DWM``
      ``AccentColor`` (0xAABBGGRR dword), falling back to
      ``ColorizationColor``.
    * **macOS** — ``AppleHighlightColor`` ("0.78 0.88 0.98" floats),
      falling back to the ``AppleAccentColor`` index (red…graphite).
    * **Linux/GNOME 47+** — ``gsettings get org.gnome.desktop.interface
      accent-color`` (blue/teal/green/yellow/orange/red/pink/purple/slate).

    Every probe is time-boxed and failure-proofed: a headless test host
    or an unusual desktop simply yields None and callers fall back to
    the brand seed.
    """
    import sys

    try:
        if sys.platform == "win32":
            return _windows_accent_color()
        if sys.platform == "darwin":
            return _macos_accent_color()
        return _linux_accent_color()
    except Exception:                                    # noqa: BLE001
        return None


def _run_cmd(argv, timeout=2.0):
    """Run a read-only probe command; '' on any failure."""
    import subprocess

    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             timeout=timeout)
        return out.stdout or "" if out.returncode == 0 else ""
    except Exception:                                    # noqa: BLE001
        return ""


def _windows_accent_color():
    for value in ("AccentColor", "ColorizationColor"):
        out = _run_cmd(
            ["reg", "query", r"HKCU\Software\Microsoft\Windows\DWM",
             "/v", value])
        for token in out.split():
            if token.startswith("0x") and len(token) >= 8:
                n = int(token, 16)              # 0xAABBGGRR
                return "#{:02x}{:02x}{:02x}".format(
                    (n >> 0) & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF)
    return None


# AppleAccentColor index -> system accent (seed approximation)
_MACOS_ACCENTS = {
    "-1": "#8e8e93",   # graphite
    "0": "#ff453a",    # red
    "1": "#ff9f0a",    # orange
    "2": "#ffd60a",    # yellow
    "3": "#32d74b",    # green
    "4": "#0a84ff",    # blue
    "5": "#bf5af2",    # purple
    "6": "#ff375f",    # pink
}


def _macos_accent_color():
    out = _run_cmd(["defaults", "read", "-g", "AppleHighlightColor"])
    if out:
        parts = out.replace(",", " ").split()
        try:
            rgb = [float(p) for p in parts[:3]]
            if len(rgb) == 3 and all(0.0 <= v <= 1.0 for v in rgb):
                return "#{:02x}{:02x}{:02x}".format(
                    *(int(round(v * 255)) for v in rgb))
        except ValueError:
            pass
    out = _run_cmd(["defaults", "read", "-g", "AppleAccentColor"])
    if out:
        return _MACOS_ACCENTS.get(out.strip())
    return None


# GNOME 47 accent-color names -> seed approximation (libadwaita accents)
_LINUX_ACCENTS = {
    "blue": "#3584e4", "teal": "#2190a4", "green": "#3a944a",
    "yellow": "#c88800", "orange": "#ed5b00", "red": "#e62d42",
    "pink": "#d56199", "purple": "#9141ac", "slate": "#6f8396",
}


def _linux_accent_color():
    out = _run_cmd(["gsettings", "get",
                    "org.gnome.desktop.interface", "accent-color"])
    if out:
        return _LINUX_ACCENTS.get(out.strip().strip("'\""))
    return None


def _resolve_seed(source: str = None) -> str:
    """The seed for the configured accent source ("system" probes the OS)."""
    src = source or _accent_source
    if src == "custom":
        return _accent_custom
    if src == "system":
        return system_accent_color() or _BRAND_SEED
    return _BRAND_SEED


def set_accent(source: str, custom_hex: str = None) -> str:
    """Configure the Material You seed source (no app required).

    Returns the *resolved* seed: brand green, the OS accent color, or the
    normalized custom hex. The resolved seed is applied on the next
    ``apply_theme`` call (or immediately if a theme is already applied —
    callers that want a live restyle call ``apply_saved_theme`` after this).
    """
    global _accent_source, _accent_custom
    from ..settings import ACCENT_SOURCES, normalize_hex_color

    _accent_source = source if source in ACCENT_SOURCES else "brand"
    if custom_hex is not None:
        _accent_custom = normalize_hex_color(custom_hex)
    return _resolve_seed()


def effective_seed() -> str:
    """The Material You seed the current schemes were generated from."""
    return _active_seed


def accent_source() -> str:
    """The configured accent source: "brand", "system" or "custom"."""
    return _accent_source


def _regenerate(seed: str) -> None:
    """Rebuild every module-level scheme constant from ``seed``."""
    global _active_seed, DARK_SCHEME, LIGHT_SCHEME
    global DARK_QSS, LIGHT_QSS, STATE_COLORS, QSS
    _active_seed = seed
    DARK_SCHEME = scheme_from_seed(seed, True)
    LIGHT_SCHEME = scheme_from_seed(seed, False)
    DARK_QSS = md3_qss(DARK_SCHEME)
    LIGHT_QSS = md3_qss(LIGHT_SCHEME)
    STATE_COLORS = _state_colors_for(DARK_SCHEME)
    QSS = DARK_QSS          # keep the backward-compat alias in sync


def apply_saved_theme(app) -> str:
    """Configure the Material You accent + apply the persisted theme.

    Single entry point for "style the app like the settings say" — used at
    startup, after the settings dialog, and on theme-menu switches.
    """
    from ..settings import load_settings

    s = load_settings()
    set_accent(s.accent_source, s.accent_color)
    return apply_theme(app, s.theme)


def state_color(state: str):
    """(dot color, label) for a connection state.

    Accessor form of the ``STATE_COLORS`` constant so callers always see
    the colors of the *active* Material You seed, even after a live
    restyle (constants imported by value at import time go stale).
    """
    return STATE_COLORS.get(state, ("#9aa3b2", state))


def apply_theme(app, mode: str = "dark", *, seed: str = None) -> str:
    """Apply the requested theme to the whole application.

    Returns the effective mode ("dark" or "light"). In "system" mode the
    application keeps following the desktop color scheme live.

    ``seed`` (optional) forces the Material You seed for this application
    (e.g. a live preview); by default the seed configured via
    :func:`set_accent` / the settings is (re)resolved — "system" probes
    the OS accent color each time, so an accent change is picked up on
    the next apply.
    """
    global _requested, _effective
    from ..settings import normalize_hex_color

    _requested = mode if mode in THEMES else "dark"
    _effective = resolve_theme(_requested)
    resolved = normalize_hex_color(seed) if seed else _resolve_seed()
    if resolved != _active_seed:
        _regenerate(resolved)
    app.setStyleSheet(DARK_QSS if _effective == "dark" else LIGHT_QSS)
    _apply_palette(app, _effective)
    _update_scheme_listener(app)
    return _effective


def _apply_palette(app, effective: str) -> None:
    """Keep the base palette in sync so native bits (menus, popups, edits)
    that the stylesheet does not cover still match the Material 3 scheme."""
    from proto_clean.qtcompat import QColor, QPalette

    scheme = DARK_SCHEME if effective == "dark" else LIGHT_SCHEME

    p = QPalette()
    # Material 3 roles map to Qt roles so native bits (menus, popups,
    # edits, tooltips) that the stylesheet does not cover still match:
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

"""Themes for Cleanroom (Qt stylesheets): dark, light, follow-system.

apply_theme(app, mode) styles the whole application:

* "dark"   — the original Cleanroom look;
* "light"  — a clean light variant with the same teal accent;
* "system" — follows the desktop color scheme and live-switches when the
  desktop switches (Qt colorSchemeChanged, Qt >= 6.5; falls back to the
  GNOME color-scheme gsettings key, then to the palette lightness).

The module tracks the effective mode so runtime painters (icons, load
bars) can pick theme-matching colors via is_dark().
"""

from __future__ import annotations

from PySide6.QtCore import Qt

DARK_QSS = """
* { font-family: 'Inter', 'Segoe UI', 'Noto Sans', sans-serif; }
QWidget { background-color: #16181d; color: #e6e9ef; font-size: 13px; }
QMainWindow, QDialog { background-color: #16181d; }

QLabel#Title { font-size: 20px; font-weight: 700; color: #ffffff; }
QLabel#Subtitle { color: #9aa3b2; font-size: 12px; }
QLabel#Stats { color: #9aa3b2; font-size: 12px; }

/* login relay banner (CAPTCHA / waiting-for-user) */
QLabel#LoginBanner {
    background-color: #3a2b12;
    border: 1px solid #b45309;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 10px 14px;
    color: #fcd34d;
    font-weight: 600;
}
QLabel#LoginBanner[level="info"] {
    background-color: #12262b;
    border: 1px solid #0e7490;
    border-left: 4px solid #22d3ee;
    color: #67e8f9;
}
QLabel#LoginNote { color: #9aa3b2; font-size: 12px; }

QPushButton {
    background-color: #23262e;
    border: 1px solid #2f333d;
    border-radius: 8px;
    padding: 8px 16px;
    color: #e6e9ef;
}
QPushButton:hover { background-color: #2a2e37; }
QPushButton:disabled { color: #5c6370; background-color: #1b1d23; }

QPushButton#Connect {
    background-color: #0f766e;   /* cleanroom teal */
    border: none;
    font-size: 15px;
    font-weight: 700;
    padding: 12px 28px;
    border-radius: 10px;
    color: white;
}
QPushButton#Connect:hover { background-color: #0d9488; }
QPushButton#Connect:disabled { background-color: #3a3f4b; color: #9aa3b2; }
QPushButton#Disconnect { background-color: #b91c1c; border: none; }
QPushButton#Disconnect:hover { background-color: #dc2626; }

QLineEdit, QComboBox, QSpinBox {
    background-color: #1e2128;
    border: 1px solid #2f333d;
    border-radius: 8px;
    padding: 7px 10px;
    selection-background-color: #0f766e;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #14b8a6; }

QComboBox QAbstractItemView {
    background-color: #1e2128;
    border: 1px solid #2f333d;
    selection-background-color: #0f766e;
}

QTableWidget {
    background-color: #1b1d23;
    alternate-background-color: #1e2128;
    gridline-color: #262a33;
    border: 1px solid #262a33;
    border-radius: 8px;
}
QHeaderView::section {
    background-color: #20242c;
    color: #9aa3b2;
    border: none;
    border-bottom: 1px solid #2f333d;
    padding: 8px;
    font-weight: 600;
}
QTableWidget::item { padding: 6px; }
QTableWidget::item:selected { background-color: #134e4a; }

QTabWidget::pane { border: 1px solid #262a33; border-radius: 8px; }
QTabBar::tab {
    background: #1e2128; color: #9aa3b2;
    padding: 8px 18px; margin-right: 3px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}
QTabBar::tab:selected { background: #23262e; color: #ffffff; }

QCheckBox::indicator, QRadioButton::indicator {
    width: 17px; height: 17px;
    border: 1px solid #3a3f4b; border-radius: 5px;
    background: #1e2128;
}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background: #14b8a6; border-color: #14b8a6;
}

QStatusBar { color: #9aa3b2; }
QToolTip { background-color: #23262e; color: #e6e9ef; border: 1px solid #3a3f4b; }

QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: #2f333d; border-radius: 5px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
"""

LIGHT_QSS = """
* { font-family: 'Inter', 'Segoe UI', 'Noto Sans', sans-serif; }
QWidget { background-color: #f4f5f7; color: #20242c; font-size: 13px; }
QMainWindow, QDialog { background-color: #f4f5f7; }

QLabel#Title { font-size: 20px; font-weight: 700; color: #14161c; }
QLabel#Subtitle { color: #5d6675; font-size: 12px; }
QLabel#Stats { color: #5d6675; font-size: 12px; }

/* login relay banner (CAPTCHA / waiting-for-user) */
QLabel#LoginBanner {
    background-color: #fef3c7;
    border: 1px solid #d97706;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 10px 14px;
    color: #92400e;
    font-weight: 600;
}
QLabel#LoginBanner[level="info"] {
    background-color: #e0f2fe;
    border: 1px solid #0284c7;
    border-left: 4px solid #0ea5e9;
    color: #075985;
}
QLabel#LoginNote { color: #5d6675; font-size: 12px; }

QPushButton {
    background-color: #ffffff;
    border: 1px solid #c9ced8;
    border-radius: 8px;
    padding: 8px 16px;
    color: #20242c;
}
QPushButton:hover { background-color: #eceff3; }
QPushButton:disabled { color: #9aa3b2; background-color: #eef0f3; }

QPushButton#Connect {
    background-color: #0d9488;   /* cleanroom teal */
    border: none;
    font-size: 15px;
    font-weight: 700;
    padding: 12px 28px;
    border-radius: 10px;
    color: white;
}
QPushButton#Connect:hover { background-color: #0f766e; }
QPushButton#Connect:disabled { background-color: #b3c9c6; color: #f4f5f7; }
QPushButton#Disconnect { background-color: #dc2626; border: none; }
QPushButton#Disconnect:hover { background-color: #b91c1c; }

QLineEdit, QComboBox, QSpinBox {
    background-color: #ffffff;
    border: 1px solid #c9ced8;
    border-radius: 8px;
    padding: 7px 10px;
    selection-background-color: #0d9488;
    selection-color: #ffffff;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #14b8a6; }

QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #c9ced8;
    selection-background-color: #0d9488;
    selection-color: #ffffff;
}

QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f2f4f7;
    gridline-color: #e3e6eb;
    border: 1px solid #d8dce3;
    border-radius: 8px;
}
QHeaderView::section {
    background-color: #eceff3;
    color: #5d6675;
    border: none;
    border-bottom: 1px solid #c9ced8;
    padding: 8px;
    font-weight: 600;
}
QTableWidget::item { padding: 6px; }
QTableWidget::item:selected { background-color: #ccfbf1; color: #20242c; }

QTabWidget::pane { border: 1px solid #d8dce3; border-radius: 8px; }
QTabBar::tab {
    background: #eef0f3; color: #5d6675;
    padding: 8px 18px; margin-right: 3px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}
QTabBar::tab:selected { background: #ffffff; color: #14161c; }

QCheckBox::indicator, QRadioButton::indicator {
    width: 17px; height: 17px;
    border: 1px solid #9aa3b2; border-radius: 5px;
    background: #ffffff;
}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background: #14b8a6; border-color: #14b8a6;
}

QStatusBar { color: #5d6675; }
QToolTip { background-color: #ffffff; color: #20242c; border: 1px solid #c3c8d2; }

QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: #c3c8d2; border-radius: 5px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
"""

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
    from PySide6.QtGui import QGuiApplication

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
    that the stylesheet does not cover still match the theme."""
    from PySide6.QtGui import QColor, QPalette

    p = QPalette()
    if effective == "dark":
        roles = {
            QPalette.ColorRole.Window: "#16181d",
            QPalette.ColorRole.WindowText: "#e6e9ef",
            QPalette.ColorRole.Base: "#1b1d23",
            QPalette.ColorRole.AlternateBase: "#1e2128",
            QPalette.ColorRole.Text: "#e6e9ef",
            QPalette.ColorRole.Button: "#23262e",
            QPalette.ColorRole.ButtonText: "#e6e9ef",
            QPalette.ColorRole.Highlight: "#0f766e",
            QPalette.ColorRole.HighlightedText: "#ffffff",
            QPalette.ColorRole.ToolTipBase: "#23262e",
            QPalette.ColorRole.ToolTipText: "#e6e9ef",
            QPalette.ColorRole.PlaceholderText: "#6b7280",
            QPalette.ColorRole.Link: "#5eead4",
        }
        disabled = "#5c6370"
    else:
        roles = {
            QPalette.ColorRole.Window: "#f4f5f7",
            QPalette.ColorRole.WindowText: "#20242c",
            QPalette.ColorRole.Base: "#ffffff",
            QPalette.ColorRole.AlternateBase: "#f2f4f7",
            QPalette.ColorRole.Text: "#20242c",
            QPalette.ColorRole.Button: "#ffffff",
            QPalette.ColorRole.ButtonText: "#20242c",
            QPalette.ColorRole.Highlight: "#0d9488",
            QPalette.ColorRole.HighlightedText: "#ffffff",
            QPalette.ColorRole.ToolTipBase: "#ffffff",
            QPalette.ColorRole.ToolTipText: "#20242c",
            QPalette.ColorRole.PlaceholderText: "#8a92a3",
            QPalette.ColorRole.Link: "#0d9488",
        }
        disabled = "#9aa3b2"
    for role, color in roles.items():
        p.setColor(role, QColor(color))
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                 QPalette.ColorRole.ButtonText):
        p.setColor(QPalette.ColorGroup.Disabled, role, QColor(disabled))
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
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is not None and _requested == "system":
        apply_theme(app, "system")


# state → (dot color, text color, label) — mid-tones readable on both themes
STATE_COLORS = {
    "logged_out": ("#9aa3b2", "Not logged in"),
    "logged_in": ("#3b82f6", "Ready"),
    "connecting": ("#f59e0b", "Connecting…"),
    "connected": ("#22c55e", "Protected"),
    "disconnecting": ("#f59e0b", "Disconnecting…"),
    "error": ("#ef4444", "Error"),
}

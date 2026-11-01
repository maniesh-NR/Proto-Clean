"""Tests for the theme system: settings persistence, legacy migration,
theme resolution and live application."""

import json
import os

import pytest

from cleanroom import settings as S

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# ----------------------------------------------------------------- settings
def test_theme_default_is_dark(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    s = S.load_settings()
    assert s.theme == "dark"
    assert s.theme in S.THEMES


def test_theme_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(theme="light")
    assert S.load_settings().theme == "light"
    S.update(theme="system")
    assert S.load_settings().theme == "system"
    S.update(theme="dark")
    assert S.load_settings().theme == "dark"


def test_legacy_prefer_dark_theme_migrates(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    # pre-theme settings file: prefer_dark_theme=False meant light mode
    (tmp_path / "settings.json").write_text(json.dumps(
        {"username": "x", "prefer_dark_theme": False}))
    s = S.load_settings()
    assert s.theme == "light"
    # and the migrated file keeps preferring dark explicitly
    (tmp_path / "settings.json").write_text(json.dumps(
        {"username": "x", "prefer_dark_theme": True}))
    assert S.load_settings().theme == "dark"


def test_unknown_theme_value_falls_back_to_dark(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(json.dumps({"theme": "sepia"}))
    assert S.load_settings().theme == "dark"


def test_save_keeps_legacy_flag_in_sync(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(theme="light")
    raw = json.loads((tmp_path / "settings.json").read_text())
    assert raw["theme"] == "light"
    assert raw["prefer_dark_theme"] is False
    S.update(theme="system")
    raw = json.loads((tmp_path / "settings.json").read_text())
    assert raw["theme"] == "system"
    assert raw["prefer_dark_theme"] is True


# ----------------------------------------------------------------- resolver
def test_resolve_explicit_modes():
    from cleanroom.ui.theme import resolve_theme

    assert resolve_theme("light") == "light"
    assert resolve_theme("dark") == "dark"
    assert resolve_theme("carrier-pigeon") == "dark"   # unknown → dark


def test_resolve_system_uses_desktop_scheme(monkeypatch):
    from cleanroom.ui import theme as T

    monkeypatch.setattr(T, "system_prefers_dark", lambda: True)
    assert T.resolve_theme("system") == "dark"
    monkeypatch.setattr(T, "system_prefers_dark", lambda: False)
    assert T.resolve_theme("system") == "light"


def test_stylesheets_differ_and_alias_holds():
    from cleanroom.ui.theme import DARK_QSS, LIGHT_QSS, QSS, stylesheet_for

    assert QSS is DARK_QSS                 # backward-compat alias
    assert DARK_QSS != LIGHT_QSS
    assert stylesheet_for("dark") is DARK_QSS
    assert stylesheet_for("light") is LIGHT_QSS
    # both themes cover the core widgets and object names
    for qss in (DARK_QSS, LIGHT_QSS):
        for token in ("QLabel#Title", "QLabel#LoginBanner", "QPushButton#Connect",
                      "QTableWidget", "QTabBar::tab", "QHeaderView::section"):
            assert token in qss


def test_state_colors_shared_between_themes():
    from cleanroom.ui.theme import STATE_COLORS

    assert STATE_COLORS["connected"][0] == "#22c55e"
    assert STATE_COLORS["connected"][1] == "Protected"


# ------------------------------------------------------------------ runtime
@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_apply_theme_switches_stylesheet(qapp):
    from cleanroom.ui import theme as T

    eff = T.apply_theme(qapp, "light")
    assert eff == "light"
    assert T.is_dark() is False
    assert qapp.styleSheet() == T.LIGHT_QSS

    eff = T.apply_theme(qapp, "dark")
    assert eff == "dark"
    assert T.is_dark() is True
    assert qapp.styleSheet() == T.DARK_QSS

    # garbage falls back to dark, never leaves the app unstyled
    assert T.apply_theme(qapp, "neon") == "dark"
    assert qapp.styleSheet() == T.DARK_QSS
    T.apply_theme(qapp, "dark")


def test_apply_theme_system_resolves(qapp, monkeypatch):
    from cleanroom.ui import theme as T

    monkeypatch.setattr(T, "system_prefers_dark", lambda: False)
    assert T.apply_theme(qapp, "system") == "light"
    assert qapp.styleSheet() == T.LIGHT_QSS
    monkeypatch.setattr(T, "system_prefers_dark", lambda: True)
    assert T.apply_theme(qapp, "system") == "dark"
    assert qapp.styleSheet() == T.DARK_QSS
    T.apply_theme(qapp, "dark")


def test_apply_theme_sets_matching_palette(qapp):
    from cleanroom.ui import theme as T

    T.apply_theme(qapp, "dark")
    assert qapp.palette().window().color().name() == "#16181d"
    T.apply_theme(qapp, "light")
    assert qapp.palette().window().color().name() == "#f4f5f7"
    T.apply_theme(qapp, "dark")


def test_load_bar_uses_theme_track(qapp):
    from cleanroom.ui import resources
    from cleanroom.ui import theme as T

    # x=80 sits beyond the 50% fill, so the pixel shows the track color
    T.apply_theme(qapp, "dark")
    pm = resources.load_bar_pixmap(50.0)
    assert pm.toImage().pixelColor(80, 5).name() == "#262a33"
    T.apply_theme(qapp, "light")
    pm = resources.load_bar_pixmap(50.0)
    assert pm.toImage().pixelColor(80, 5).name() == "#dfe3ea"
    T.apply_theme(qapp, "dark")

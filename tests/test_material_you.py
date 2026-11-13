"""Material You (dynamic color) tests: settings persistence, hex
normalization, seed resolution (brand / system / custom), OS accent
detection, scheme regeneration, and the settings-dialog wiring.

The theme module's scheme constants (DARK_SCHEME, DARK_QSS, STATE_COLORS,
…) are module-level for backward compatibility, but they are REBOUND when
the seed changes — so every test that reseeds must restore the brand seed
afterwards (the ``restore_brand`` fixture) or test-ordering breaks the
existing hardcoded-color tests in test_theme.py / test_md3.py.
"""

import json
import os

import pytest

from proto_clean import settings as S

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

BRAND = "#2f6d3f"


@pytest.fixture(autouse=True)
def restore_brand():
    """Restore the brand seed + accent state after EVERY test in this
    module (autouse — the reseedable module state must never leak into
    other test files' hardcoded-color assertions, regardless of which
    tests opt in)."""
    from proto_clean.ui import theme as T
    yield T
    T._accent_source = "brand"
    T._accent_custom = BRAND
    T._regenerate(BRAND)


# ------------------------------------------------------------ hex normalize
def test_normalize_hex_accepts_forms():
    from proto_clean.settings import normalize_hex_color

    assert normalize_hex_color("#2f6d3f") == "#2f6d3f"
    assert normalize_hex_color("2F6D3F") == "#2f6d3f"
    assert normalize_hex_color("  #b3261e ") == "#b3261e"
    assert normalize_hex_color("#f80") == "#ff8800"      # 3-digit expand
    assert normalize_hex_color("f80") == "#ff8800"


def test_normalize_hex_rejects_garbage():
    from proto_clean.settings import normalize_hex_color

    for bad in ("", "#12345", "#1234567", "#gggggg", "rgb(1,2,3)",
                None, 42, "#2f6d3g"):
        assert normalize_hex_color(bad) == BRAND


# ----------------------------------------------------------------- settings
def test_accent_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    s = S.load_settings()
    assert s.accent_source == "brand"
    assert s.accent_color == BRAND


def test_accent_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(accent_source="custom", accent_color="#b3261e")
    s = S.load_settings()
    assert s.accent_source == "custom"
    assert s.accent_color == "#b3261e"
    S.update(accent_source="system")
    assert S.load_settings().accent_source == "system"


def test_accent_invalid_values_fall_back(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(json.dumps(
        {"accent_source": "neon", "accent_color": "zzz"}))
    s = S.load_settings()
    assert s.accent_source == "brand"
    assert s.accent_color == BRAND


def test_legacy_settings_without_accent_keys(tmp_path, monkeypatch):
    """Pre-Material-You settings files load with the brand defaults."""
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(json.dumps(
        {"username": "x", "theme": "light"}))
    s = S.load_settings()
    assert s.accent_source == "brand"
    assert s.accent_color == BRAND
    assert s.theme == "light"


def test_update_normalizes_hex_before_save(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(accent_source="custom", accent_color="B3261E")
    raw = json.loads((tmp_path / "settings.json").read_text())
    assert raw["accent_color"] == "#b3261e"


# ------------------------------------------------------------ seed resolution
def test_set_accent_sources(restore_brand):
    from proto_clean.ui import theme as T

    assert T.set_accent("custom", "#0a84ff") == "#0a84ff"
    assert T.accent_source() == "custom"
    assert T.set_accent("brand") == BRAND
    assert T.accent_source() == "brand"
    # unknown source -> brand
    assert T.set_accent("neon") == BRAND
    assert T.accent_source() == "brand"
    # custom without a stored hex -> last custom seed kept/normalized
    T.set_accent("custom", "nope")            # normalized to brand
    assert T._resolve_seed() == BRAND


def test_set_accent_system_probes_os(restore_brand, monkeypatch):
    from proto_clean.ui import theme as T

    monkeypatch.setattr(T, "system_accent_color", lambda: "#3584e4")
    assert T.set_accent("system") == "#3584e4"
    # probe failure -> brand fallback
    monkeypatch.setattr(T, "system_accent_color", lambda: None)
    assert T.set_accent("system") == BRAND


def test_regenerate_changes_schemes_and_qss(restore_brand):
    from proto_clean.ui import theme as T

    brand_primary = T.DARK_SCHEME.primary
    brand_qss = T.DARK_QSS
    T.set_accent("custom", "#b3261e")
    T._regenerate("#b3261e")
    assert T.effective_seed() == "#b3261e"
    assert T.DARK_SCHEME.primary != brand_primary
    assert T.DARK_QSS != brand_qss
    # the alias stays in sync with the rebound constant
    assert T.QSS is T.DARK_QSS
    # both light and dark derive from the same seed
    from proto_clean.ui.md3 import scheme_from_seed
    assert T.DARK_SCHEME == scheme_from_seed("#b3261e", True)
    assert T.LIGHT_SCHEME == scheme_from_seed("#b3261e", False)


def test_state_color_accessor_follows_seed(restore_brand):
    from proto_clean.ui import theme as T

    brand = T.state_color("connected")
    T._regenerate("#b3261e")
    # label text is seed-independent, the color is derived
    assert T.state_color("connected")[1] == brand[1]
    assert isinstance(T.state_color("connected")[0], str)
    assert T.state_color("unknown-state")[0] == "#9aa3b2"


# ---------------------------------------------------------- OS accent probes
def test_linux_gnome_accent(monkeypatch):
    from proto_clean.ui import theme as T

    monkeypatch.setattr(T, "_run_cmd",
                        lambda argv, timeout=2.0: "'blue'\n")
    assert T._linux_accent_color() == "#3584e4"
    monkeypatch.setattr(T, "_run_cmd", lambda argv, timeout=2.0: "'teal'\n")
    assert T._linux_accent_color() == "#2190a4"
    # unknown name / empty output
    monkeypatch.setattr(T, "_run_cmd", lambda argv, timeout=2.0: "'neon'\n")
    assert T._linux_accent_color() is None
    monkeypatch.setattr(T, "_run_cmd", lambda argv, timeout=2.0: "")
    assert T._linux_accent_color() is None


def test_macos_highlight_color(monkeypatch):
    from proto_clean.ui import theme as T

    monkeypatch.setattr(
        T, "_run_cmd",
        lambda argv, timeout=2.0: "0.780392 0.882353 0.980392 \n")
    assert T._macos_accent_color() == "#c7e1fa"
    # AppleAccentColor index fallback
    monkeypatch.setattr(
        T, "_run_cmd",
        lambda argv, timeout=2.0: "4" if "Accent" in argv[-1] else "")
    assert T._macos_accent_color() == "#0a84ff"


def test_windows_dwm_accent(monkeypatch):
    from proto_clean.ui import theme as T

    reg_out = ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM\n"
               "    AccentColor    REG_DWORD    0xffd2691e\n")
    monkeypatch.setattr(T, "_run_cmd", lambda argv, timeout=2.0: reg_out)
    # 0xffd2691e = ABGR -> R=1e G=69 B=d2
    assert T._windows_accent_color() == "#1e69d2"
    monkeypatch.setattr(T, "_run_cmd", lambda argv, timeout=2.0: "")
    assert T._windows_accent_color() is None


def test_run_cmd_swallow_errors():
    from proto_clean.ui import theme as T

    assert T._run_cmd(["/definitely/not/a/program"]) == ""


# ------------------------------------------------------------- apply + saved
def test_apply_saved_theme_reads_settings(restore_brand, monkeypatch,
                                          tmp_path):
    from proto_clean.qtcompat import qt_available

    if not qt_available():
        pytest.skip("no Qt binding available in this environment")
    from proto_clean.qtcompat import QApplication
    from proto_clean.ui import theme as T

    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(accent_source="custom", accent_color="#0a84ff", theme="dark")
    app = QApplication.instance() or QApplication([])
    eff = T.apply_saved_theme(app)
    assert eff == "dark"
    assert T.effective_seed() == "#0a84ff"
    # the QSS really was regenerated from the blue seed
    from proto_clean.ui.md3 import scheme_from_seed
    assert T.DARK_SCHEME == scheme_from_seed("#0a84ff", True)
    assert app.styleSheet() == T.DARK_QSS
    S.update(accent_source="brand")
    T.apply_saved_theme(app)
    assert T.effective_seed() == BRAND


def test_apply_theme_explicit_seed_overrides(restore_brand, monkeypatch,
                                             tmp_path):
    from proto_clean.qtcompat import qt_available

    if not qt_available():
        pytest.skip("no Qt binding available in this environment")
    from proto_clean.qtcompat import QApplication
    from proto_clean.ui import theme as T

    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    S.update(accent_source="brand")
    app = QApplication.instance() or QApplication([])
    T.apply_theme(app, "light", seed="#b3261e")
    assert T.effective_seed() == "#b3261e"
    assert app.styleSheet() == T.LIGHT_QSS
    # invalid explicit seed -> normalized back to brand
    T.apply_theme(app, "dark", seed="garbage")
    assert T.effective_seed() == BRAND


def test_stylesheet_for_tracks_active_seed(restore_brand):
    from proto_clean.ui import theme as T

    T._regenerate("#0a84ff")
    assert T.stylesheet_for("dark") is T.DARK_QSS
    assert T.stylesheet_for("light") is T.LIGHT_QSS


# ------------------------------------------------- live restyle (G1-iter3)
def test_live_restyle_repaints_painted_surfaces(restore_brand):
    """A live theme/accent change must repaint the status dot, the tray
    icon AND the table — not just the QSS (G1-iter3, Architect major
    #3: the dot and tray only repainted on VPN state transitions, so a
    mid-session accent change left them painted with the previous seed).
    """
    from proto_clean.qtcompat import qt_available

    if not qt_available():
        pytest.skip("no Qt binding available in this environment")
    from proto_clean.qtcompat import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841 (QPixmap needs it)

    import types
    from proto_clean.ui import resources
    from proto_clean.ui.main_window import MainWindow
    from proto_clean.ui.theme import state_color

    calls = []
    fake = types.SimpleNamespace(
        controller=types.SimpleNamespace(
            state=types.SimpleNamespace(value="connected"),
            state_detail="via WireGuard"),
        status_dot=types.SimpleNamespace(
            setPixmap=lambda pix: calls.append(("dot", pix))),
        tray=types.SimpleNamespace(
            _on_state=lambda s, d: calls.append(("tray", s, d))),
        _refresh_table=lambda: calls.append(("table",)),
    )

    MainWindow._restyle(fake)

    kinds = [c[0] for c in calls]
    assert kinds == ["dot", "tray", "table"], kinds
    # the dot is repainted from the CURRENT state color (seed-aware)
    expected = resources.status_dot(state_color("connected")[0], 14)
    got = [c[1] for c in calls if c[0] == "dot"][0]
    assert got.toImage() == expected.toImage()
    # the tray is poked with the current state + detail
    assert ("tray", "connected", "via WireGuard") in calls


def test_live_restyle_without_tray(restore_brand):
    """_restyle must not crash when the tray has not been created yet."""
    from proto_clean.qtcompat import qt_available

    if not qt_available():
        pytest.skip("no Qt binding available in this environment")
    from proto_clean.qtcompat import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841

    import types
    from proto_clean.ui.main_window import MainWindow

    calls = []
    fake = types.SimpleNamespace(
        controller=types.SimpleNamespace(
            state=types.SimpleNamespace(value="logged_out"),
            state_detail=""),
        status_dot=types.SimpleNamespace(
            setPixmap=lambda pix: calls.append(("dot", pix))),
        _refresh_table=lambda: calls.append(("table",)),
    )  # NOTE: no `tray` attribute — pre-tray window state

    MainWindow._restyle(fake)
    assert [c[0] for c in calls] == ["dot", "table"]


def test_change_theme_routes_through_restyle(restore_brand, monkeypatch,
                                             tmp_path):
    """The Theme-menu path must call _restyle (dot + tray + table), not
    just _refresh_table (G1-iter3 wiring contract)."""
    from proto_clean.qtcompat import qt_available

    if not qt_available():
        pytest.skip("no Qt binding available in this environment")
    from proto_clean.qtcompat import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841

    import types
    import proto_clean.ui.main_window as MW
    from proto_clean.ui.main_window import MainWindow

    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(MW, "update", lambda **kw: None)
    monkeypatch.setattr(MW, "apply_saved_theme", lambda app: "dark")

    calls = []
    fake = types.SimpleNamespace(
        _restyle=lambda: calls.append("restyle"),
        statusBar=lambda: types.SimpleNamespace(
            showMessage=lambda *a, **k: calls.append("status")))

    MainWindow._change_theme(fake, "dark")

    assert "restyle" in calls, "_change_theme must repaint painted surfaces"
    assert "status" in calls

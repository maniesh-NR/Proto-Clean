"""Qt binding compatibility layer.

Proto Clean runs on PySide6 (Qt 6) everywhere except the legacy
Windows 7 / 32-bit builds, which ship Qt 5 through PySide2 — the last
Qt line that published 32-bit Windows wheels and supports Windows 7.

All UI code imports Qt names from this module instead of a specific
binding; the first installed binding wins. When neither binding is
importable (e.g. headless CI without GL libs), ``QT_BINDING`` is None
and ``qt_available()`` returns False — UI tests that only touch QSS
strings still run, while tests that actually need a QApplication skip
themselves via ``pytestmark`` or an explicit ``skipif``.
"""

from __future__ import annotations

QT_BINDING: str | None = None
QT_VERSION_MAJOR: int = 0


def qt_available() -> bool:
    """True when a real Qt binding could be imported."""
    return QT_BINDING is not None


try:  # primary: Qt 6
    from PySide6.QtCore import *  # noqa: F401,F403
    from PySide6.QtGui import *  # noqa: F401,F403
    from PySide6.QtWidgets import *  # noqa: F401,F403

    QT_BINDING = "PySide6"
    QT_VERSION_MAJOR = 6
except ImportError:  # pragma: no cover - exercised only on legacy Qt5
    try:  # legacy builds: Qt 5
        from PySide2.QtCore import *  # noqa: F401,F403
        from PySide2.QtGui import *  # noqa: F401,F403
        from PySide2.QtWidgets import *  # noqa: F401,F403

        QT_BINDING = "PySide2"
        QT_VERSION_MAJOR = 5
    except ImportError:  # headless: provide a minimal stub so static
        # analysis and QSS-only tests can import ``proto_clean.ui.theme``
        # without a real Qt. The stub classes are *only* placeholders —
        # any actual UI work goes through ``qt_available()`` gating.

        class _Stub:  # pragma: no cover - test-only fallback
            """Sentinel base for stub enum-like / namespace objects."""

            def __init__(self, *_a, **_kw) -> None:
                pass

            def __getattr__(self, _name: str) -> "_Stub":
                return self

            def __call__(self, *_a, **_kw) -> "_Stub":
                return self

            def __bool__(self) -> bool:  # behave falsy so ``if Qt.AlignRight:``
                return False

        # Common names imported across the UI package — each is a
        # falsy sentinel. ``class X(_Stub)`` makes them type-ish too.
        Qt = _Stub()
        QTimer = _Stub()
        QApplication = _Stub()
        QMainWindow = _Stub()
        QDialog = _Stub()
        QLabel = _Stub()
        QPushButton = _Stub()
        QLineEdit = _Stub()
        QCheckBox = _Stub()
        QComboBox = _Stub()
        QVBoxLayout = _Stub()
        QHBoxLayout = _Stub()
        QFormLayout = _Stub()
        QGridLayout = _Stub()
        QWidget = _Stub()
        QTableWidget = _Stub()
        QTableWidgetItem = _Stub()
        QHeaderView = _Stub()
        QAbstractItemView = _Stub()
        QSystemTrayIcon = _Stub()
        QMenu = _Stub()
        QStatusBar = _Stub()
        QInputDialog = _Stub()
        QMessageBox = _Stub()
        QPalette = _Stub()
        QColor = _Stub()
        QBrush = _Stub()
        QPen = _Stub()
        QPixmap = _Stub()
        QIcon = _Stub()
        QPainter = _Stub()
        QPainterPath = _Stub()
        QRectF = _Stub()
        QPoint = _Stub()
        QGuiApplication = _Stub()
        QActionGroup = _Stub()
        QDialogButtonBox = _Stub()
        QSpinBox = _Stub()
        QTabWidget = _Stub()
        QTabBar = _Stub()
        QFrame = _Stub()
        QToolButton = _Stub()
        QScrollBar = _Stub()
        QShortcut = _Stub()
        QKeySequence = _Stub()
        QSizePolicy = _Stub()
        QButtonGroup = _Stub()
        QRadioButton = _Stub()
        QSlider = _Stub()
        QProgressBar = _Stub()
        QListWidget = _Stub()
        QListWidgetItem = _Stub()
        QSplitter = _Stub()
        QTextEdit = _Stub()
        QPlainTextEdit = _Stub()
        QCheckBox = _Stub()
        QFileDialog = _Stub()
        QFontComboBox = _Stub()
        QFont = _Stub()
        QFontMetrics = _Stub()
        QAction = _Stub()

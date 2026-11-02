"""Qt binding compatibility layer.

Proto Clean runs on PySide6 (Qt 6) everywhere except the legacy
Windows 7 / 32-bit builds, which ship Qt 5 through PySide2 — the last
Qt line that published 32-bit Windows wheels and supports Windows 7.

All UI code imports Qt names from this module instead of a specific
binding; the first installed binding wins.
"""

from __future__ import annotations

try:  # primary: Qt 6
    from PySide6.QtCore import *  # noqa: F401,F403
    from PySide6.QtGui import *  # noqa: F401,F403
    from PySide6.QtWidgets import *  # noqa: F401,F403

    QT_BINDING = "PySide6"
    QT_VERSION_MAJOR = 6
except ImportError:  # legacy builds: Qt 5
    from PySide2.QtCore import *  # noqa: F401,F403
    from PySide2.QtGui import *  # noqa: F401,F403
    from PySide2.QtWidgets import *  # noqa: F401,F403

    QT_BINDING = "PySide2"
    QT_VERSION_MAJOR = 5

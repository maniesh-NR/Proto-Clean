"""Icons drawn at runtime with QPainter — no binary assets needed."""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPixmap, QPen

from .theme import is_dark


def _pixmap(size: int = 64) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    return pm


def shield_icon(color: str = "#7c3aed", size: int = 64) -> QIcon:
    pm = _pixmap(size)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    path = QPainterPath()
    s = size
    path.moveTo(s * 0.5, s * 0.06)
    path.lineTo(s * 0.88, s * 0.20)
    path.lineTo(s * 0.88, s * 0.48)
    path.quadTo(s * 0.88, s * 0.78, s * 0.5, s * 0.95)
    path.quadTo(s * 0.12, s * 0.78, s * 0.12, s * 0.48)
    path.lineTo(s * 0.12, s * 0.20)
    path.closeSubpath()
    p.fillPath(path, QColor(color))
    # check mark
    pen = QPen(QColor("#ffffff"), size * 0.07)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.drawLine(int(s * 0.32), int(s * 0.5), int(s * 0.45), int(s * 0.63))
    p.drawLine(int(s * 0.45), int(s * 0.63), int(s * 0.70), int(s * 0.36))
    p.end()
    return QIcon(pm)


def status_dot(color: str, size: int = 14) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QBrush(QColor(color)))
    p.setPen(Qt.NoPen)
    p.drawEllipse(QRectF(1, 1, size - 2, size - 2))
    p.end()
    return pm


def load_bar_pixmap(percent: float, width: int = 90, height: int = 10) -> QPixmap:
    pm = QPixmap(width, height)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#262a33" if is_dark() else "#dfe3ea"))
    p.drawRoundedRect(0, 0, width, height, 5, 5)
    frac = max(0.0, min(1.0, percent / 100.0))
    if percent < 50:
        color = "#22c55e"
    elif percent < 75:
        color = "#f59e0b"
    else:
        color = "#ef4444"
    p.setBrush(QBrush(QColor(color)))
    p.drawRoundedRect(0, 0, max(3, int(width * frac)), height, 5, 5)
    p.end()
    return pm


def app_icon(size: int = 64) -> QIcon:
    return shield_icon("#5b21b6", size)


def bolt_icon(color: str = "#f59e0b", size: int = 64) -> QPixmap:
    pm = _pixmap(size)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    pts = [QPoint(int(size * .55), int(size * .08)), QPoint(int(size * .25), int(size * .55)),
           QPoint(int(size * .47), int(size * .55)), QPoint(int(size * .40), int(size * .92)),
           QPoint(int(size * .75), int(size * .42)), QPoint(int(size * .52), int(size * .42))]
    path = QPainterPath()
    path.moveTo(pts[0])
    for pt in pts[1:]:
        path.lineTo(pt)
    path.closeSubpath()
    p.fillPath(path, QColor(color))
    p.end()
    return pm

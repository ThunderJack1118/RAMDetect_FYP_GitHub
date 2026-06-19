"""Animated Light/Dark theme switch for RAMDetect Settings.

UI-only widget. It stores no RAMDetect forensic, ML, database, report, or
path logic. The Settings page connects ``theme_changed`` to the central theme
loader.
"""
from __future__ import annotations

from PyQt5.QtCore import Qt, QRectF, pyqtSignal, pyqtProperty, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QFont, QPainter, QPen
from PyQt5.QtWidgets import QWidget, QSizePolicy

try:
    from ui.theme import THEME_DARK, THEME_LIGHT, current_theme
except Exception:  # pragma: no cover - package import fallback
    from ramdetect.ui.theme import THEME_DARK, THEME_LIGHT, current_theme


class ThemeSwitch(QWidget):
    """A compact animated segmented switch for RAMDetect appearance mode."""

    theme_changed = pyqtSignal(str)

    def __init__(self, theme: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("ThemeSwitch")
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(250, 52)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self._theme = THEME_LIGHT if str(theme or current_theme()).lower() == THEME_LIGHT else THEME_DARK
        self._progress = 1.0 if self._theme == THEME_LIGHT else 0.0
        self._anim = QPropertyAnimation(self, b"progress", self)
        self._anim.setDuration(220)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self.setToolTip("Switch RAMDetect between dark and light interface themes.")

    def getProgress(self) -> float:
        return float(self._progress)

    def setProgress(self, value: float) -> None:
        self._progress = max(0.0, min(1.0, float(value)))
        self.update()

    progress = pyqtProperty(float, getProgress, setProgress)

    def theme(self) -> str:
        return self._theme

    def set_theme(self, theme: str, animated: bool = True, emit: bool = False) -> None:
        target = THEME_LIGHT if str(theme or "").lower() == THEME_LIGHT else THEME_DARK
        changed = target != self._theme
        self._theme = target
        end = 1.0 if target == THEME_LIGHT else 0.0
        if animated:
            self._anim.stop()
            self._anim.setStartValue(self._progress)
            self._anim.setEndValue(end)
            self._anim.start()
        else:
            self.setProgress(end)
        if emit and changed:
            self.theme_changed.emit(target)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            new_theme = THEME_LIGHT if event.pos().x() >= self.width() / 2 else THEME_DARK
            if new_theme == self._theme:
                new_theme = THEME_DARK if self._theme == THEME_LIGHT else THEME_LIGHT
            self.set_theme(new_theme, animated=True, emit=True)
            event.accept()
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            new_theme = THEME_DARK if self._theme == THEME_LIGHT else THEME_LIGHT
            self.set_theme(new_theme, animated=True, emit=True)
            event.accept()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event):
        del event
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)

        w, h = self.width(), self.height()
        outer = QRectF(0.8, 0.8, w - 1.6, h - 1.6)
        is_light = self._progress >= 0.5

        if is_light:
            track_bg = QColor("#eaf1ff")
            border = QColor("#b9cdf8")
            inactive_text = QColor("#5d76a9")
        else:
            track_bg = QColor("#111827")
            border = QColor("#334155")
            inactive_text = QColor("#94a3b8")

        p.setPen(QPen(border, 1.2))
        p.setBrush(track_bg)
        p.drawRoundedRect(outer, 18, 18)

        pad = 5
        half = (w - pad * 2) / 2
        knob_x = pad + self._progress * half
        knob = QRectF(knob_x, pad, half, h - pad * 2)
        if is_light:
            knob_bg = QColor("#1a56db")
            knob_border = QColor("#174bbf")
        else:
            knob_bg = QColor("#06b6d4")
            knob_border = QColor("#0891b2")
        p.setPen(QPen(knob_border, 1.0))
        p.setBrush(knob_bg)
        p.drawRoundedRect(knob, 14, 14)

        font = QFont("Segoe UI", 10, QFont.Bold)
        p.setFont(font)

        left_rect = QRectF(pad, 0, half, h)
        right_rect = QRectF(pad + half, 0, half, h)

        dark_active = self._progress < 0.5
        light_active = not dark_active
        p.setPen(QColor("#ffffff") if dark_active else inactive_text)
        p.drawText(left_rect, Qt.AlignCenter, "🌙  Dark")
        p.setPen(QColor("#ffffff") if light_active else inactive_text)
        p.drawText(right_rect, Qt.AlignCenter, "☀  Light")

        p.end()

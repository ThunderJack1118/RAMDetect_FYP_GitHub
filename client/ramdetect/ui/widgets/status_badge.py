"""
StatusBadge
───────────
Pill-shaped status indicator widget.

Supported states
  clean       — green ✓ CLEAN
  suspicious  — red   ⚠ SUSPICIOUS
  pending     — amber ◷ PENDING
  running     — cyan  ⟳ RUNNING
  error       — red   ✗ ERROR
  unknown     — grey  ? UNKNOWN

Usage
  badge = StatusBadge("suspicious")
  badge.set_status("clean")     # live update
"""

from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt5.QtGui     import QFont


class StatusBadge(QWidget):
    """Compact pill badge.  Pass verdict string; call set_status() to update live."""

    STYLES: dict[str, dict] = {
        "clean": {
            "bg":     "rgba(52,211,153,0.16)",
            "border": "rgba(52,211,153,0.40)",
            "color":  "#34d399",
            "icon":   "✓",
            "text":   "CLEAN",
        },
        "suspicious": {
            "bg":     "rgba(248,113,113,0.16)",
            "border": "rgba(248,113,113,0.40)",
            "color":  "#f87171",
            "icon":   "⚠",
            "text":   "SUSPICIOUS",
        },
        "pending": {
            "bg":     "rgba(250,204,21,0.16)",
            "border": "rgba(250,204,21,0.40)",
            "color":  "#facc15",
            "icon":   "◷",
            "text":   "PENDING",
        },
        "running": {
            "bg":     "rgba(6,182,212,0.14)",
            "border": "rgba(6,182,212,0.40)",
            "color":  "#06b6d4",
            "icon":   "⟳",
            "text":   "RUNNING",
        },
        "error": {
            "bg":     "rgba(248,113,113,0.16)",
            "border": "rgba(248,113,113,0.40)",
            "color":  "#f87171",
            "icon":   "✗",
            "text":   "ERROR",
        },
        "complete": {
            "bg":     "rgba(52,211,153,0.16)",
            "border": "rgba(52,211,153,0.40)",
            "color":  "#34d399",
            "icon":   "✓",
            "text":   "COMPLETE",
        },
        "unknown": {
            "bg":     "rgba(100,116,139,0.16)",
            "border": "rgba(100,116,139,0.40)",
            "color":  "#94a3b8",
            "icon":   "?",
            "text":   "UNKNOWN",
        },
    }

    def __init__(self, status: str = "unknown", parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)

        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(5)

        self._icon_lbl = QLabel()
        self._icon_lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))

        self._text_lbl = QLabel()
        self._text_lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))

        row.addWidget(self._icon_lbl)
        row.addWidget(self._text_lbl)

        self.set_status(status)

    def set_status(self, status: str):
        """Update badge to a new status string."""
        key   = status.lower().strip() if status else "unknown"
        style = self.STYLES.get(key, self.STYLES["unknown"])

        col = style["color"]
        self._icon_lbl.setText(style["icon"])
        self._icon_lbl.setStyleSheet(f"color: {col}; background: transparent;")

        self._text_lbl.setText(style["text"])
        self._text_lbl.setStyleSheet(f"color: {col}; background: transparent;")

        self.setStyleSheet(
            f"StatusBadge {{"
            f"  background: {style['bg']};"
            f"  border: 1px solid {style['border']};"
            f"  border-radius: 14px;"
            f"}}"
        )
        self.update()

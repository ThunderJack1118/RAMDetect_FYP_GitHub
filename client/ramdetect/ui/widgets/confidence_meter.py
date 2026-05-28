"""
ConfidenceMeter
───────────────
Horizontal gradient progress bar with optional value label.

Gradient colours track the verdict:
  clean       — teal → green        (#34d399 → #059669)
  suspicious  — orange-red → red    (#fb923c → #dc2626)
  neutral/AE  — cyan → indigo       (#06b6d4 → #4f46e5)

Usage
  meter = ConfidenceMeter(value=94.2, status="suspicious")
  meter = ConfidenceMeter(value=12.0, status="clean", height=10)
  meter.set_value(87.5, "suspicious")   # live update
  meter = ConfidenceMeter(value=73.0, show_label=False, height=4)
"""

from PyQt5.QtWidgets import QWidget, QHBoxLayout, QProgressBar, QLabel
from PyQt5.QtCore    import Qt
from PyQt5.QtGui     import QFont


_GRADIENTS: dict[str, str] = {
    "suspicious": (
        "qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 #fb923c, stop:0.5 #ef4444, stop:1 #dc2626)"
    ),
    "clean": (
        "qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 #34d399, stop:0.5 #10b981, stop:1 #059669)"
    ),
    "neutral": (
        "qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 #06b6d4, stop:0.5 #3b82f6, stop:1 #4f46e5)"
    ),
}

_LABEL_COLORS: dict[str, str] = {
    "suspicious": "#f87171",
    "clean":      "#34d399",
    "neutral":    "#06b6d4",
}


def _resolve_status(status: str) -> str:
    s = status.lower().strip()
    if s in ("suspicious", "error"):       return "suspicious"
    if s in ("clean", "complete", "ok"):   return "clean"
    return "neutral"


class ConfidenceMeter(QWidget):
    """
    Horizontal gradient bar.

    Parameters
    ──────────
    value       0–100 float
    status      'clean' | 'suspicious' | 'neutral' (and aliases above)
    show_label  whether to append the "XX.X%" text label (default True)
    height      bar height in px (default 8)
    label_width fixed width of the label column (default 52)
    """

    def __init__(self,
                 value:       float = 0.0,
                 status:      str   = "neutral",
                 show_label:  bool  = True,
                 height:      int   = 8,
                 label_width: int   = 52,
                 parent=None):
        super().__init__(parent)
        self._height      = height
        self._label_width = label_width

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        # ── Progress bar ──────────────────────────────────────────────────────
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(height)
        row.addWidget(self.bar, stretch=1)

        # ── Optional label ────────────────────────────────────────────────────
        if show_label:
            self._lbl = QLabel()
            self._lbl.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            self._lbl.setFixedWidth(label_width)
            self._lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            row.addWidget(self._lbl)
        else:
            self._lbl = None

        self.set_value(value, status)

    # ── Public API ────────────────────────────────────────────────────────────

    def set_value(self, value: float, status: str = None):
        """Update bar value and optionally the status/colour."""
        self._value = max(0.0, min(100.0, float(value)))
        if status is not None:
            self._status = _resolve_status(status)
        self.bar.setValue(int(self._value))
        self._apply_style()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _apply_style(self):
        grad  = _GRADIENTS.get(self._status, _GRADIENTS["neutral"])
        r     = self._height // 2

        self.bar.setStyleSheet(f"""
            QProgressBar {{
                background: rgba(51,65,85,0.4);
                border: none;
                border-radius: {r}px;
            }}
            QProgressBar::chunk {{
                background: {grad};
                border-radius: {r}px;
            }}
        """)

        if self._lbl is not None:
            col = _LABEL_COLORS.get(self._status, "#94a3b8")
            self._lbl.setText(f"{self._value:.1f}%")
            self._lbl.setStyleSheet(f"color: {col}; background: transparent;")

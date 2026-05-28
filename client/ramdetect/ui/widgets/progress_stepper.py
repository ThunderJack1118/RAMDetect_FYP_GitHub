"""
ProgressStepper
───────────────
Four-step horizontal progress indicator used across the analysis pipeline.

Steps
  1  Acquisition   — dump loaded or live capture running
  2  Configuration — module selection
  3  Analysis      — extraction + ML inference
  4  Results       — final verdict + reporting

Visual states
  complete   — green ✓ circle, solid green connector
  active     — cyan pulsing circle with step number, partial cyan connector
  inactive   — dark circle with step number, dim connector

Usage
  ProgressStepper(current_step=1)   # Acquisition active
  ProgressStepper(current_step=3)   # Analysis active, 1+2 complete
"""

from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout,
                              QLabel, QFrame)
from PyQt5.QtCore    import Qt
from PyQt5.QtGui     import QFont


# ─────────────────────────────────────────────────────────────────────────────
# Step circle
# ─────────────────────────────────────────────────────────────────────────────

_CIRCLE_STYLES = {
    "complete": (
        "background: #34d399; color: #ffffff; border-radius: 17px;"
        "border: 2px solid #10b981;"
    ),
    "active": (
        "background: #06b6d4; color: #ffffff; border-radius: 17px;"
        "border: 2px solid #22d3ee;"
    ),
    "inactive": (
        "background: #1e293b; color: #475569; border-radius: 17px;"
        "border: 2px solid #334155;"
    ),
}

_LABEL_COLORS = {
    "complete": "#34d399",
    "active":   "#06b6d4",
    "inactive": "#475569",
}

_CONNECTOR_COLORS = {
    "done":    "#34d399",   # between two completed steps
    "partial": "#06b6d4",   # between completed and active
    "todo":    "#1e293b",   # before inactive steps
}


def _step_state(step_num: int, current: int) -> str:
    if step_num < current:  return "complete"
    if step_num == current: return "active"
    return "inactive"


def _connector_color(left_step: int, current: int) -> str:
    """Colour of the connector sitting after step `left_step`."""
    if left_step < current - 1: return _CONNECTOR_COLORS["done"]
    if left_step == current - 1: return _CONNECTOR_COLORS["partial"]
    return _CONNECTOR_COLORS["todo"]


# ─────────────────────────────────────────────────────────────────────────────
# ProgressStepper
# ─────────────────────────────────────────────────────────────────────────────

class ProgressStepper(QWidget):
    STEPS = [
        ("1", "Acquisition"),
        ("2", "Configuration"),
        ("3", "Analysis"),
        ("4", "Results"),
    ]

    def __init__(self, current_step: int = 1, parent=None):
        """
        current_step: 1–4 (step that is currently active).
        Steps < current_step are shown as complete.
        Steps > current_step are shown as inactive.
        """
        super().__init__(parent)
        self.setFixedHeight(68)
        self.setStyleSheet(
            "ProgressStepper {"
            "  background: rgba(15,23,42,0.60);"
            "  border-bottom: 1px solid rgba(51,65,85,0.30);"
            "}"
        )

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setAlignment(Qt.AlignCenter)

        inner = QHBoxLayout()
        inner.setSpacing(0)
        inner.setAlignment(Qt.AlignCenter)
        inner.setContentsMargins(0, 0, 0, 0)

        for i, (num, label_text) in enumerate(self.STEPS, start=1):
            state      = _step_state(i, current_step)
            icon_text  = "✓" if state == "complete" else num
            txt_color  = _LABEL_COLORS[state]
            is_bold    = state != "inactive"

            # ── Circle ────────────────────────────────────────────────────────
            circle = QLabel(icon_text)
            circle.setAlignment(Qt.AlignCenter)
            circle.setFixedSize(34, 34)
            circle.setFont(QFont("Segoe UI", 13, QFont.Bold))
            circle.setStyleSheet(_CIRCLE_STYLES[state])

            # ── Label ─────────────────────────────────────────────────────────
            step_lbl = QLabel(label_text)
            step_lbl.setFont(QFont(
                "Segoe UI", 10,
                QFont.DemiBold if is_bold else QFont.Normal
            ))
            step_lbl.setStyleSheet(
                f"color: {txt_color}; background: transparent;"
            )
            step_lbl.setAlignment(Qt.AlignCenter)

            # ── Step column ───────────────────────────────────────────────────
            step_col = QVBoxLayout()
            step_col.setSpacing(5)
            step_col.setAlignment(Qt.AlignCenter)
            step_col.addWidget(circle,   alignment=Qt.AlignCenter)
            step_col.addWidget(step_lbl, alignment=Qt.AlignCenter)

            step_w = QWidget()
            step_w.setStyleSheet("background: transparent;")
            step_w.setLayout(step_col)
            step_w.setMinimumWidth(90)
            inner.addWidget(step_w)

            # ── Connector line (not after last step) ──────────────────────────
            if i < len(self.STEPS):
                conn_col = _connector_color(i, current_step)

                # Outer track (dim)
                track = QFrame()
                track.setFixedHeight(3)
                track.setFixedWidth(60)
                track.setStyleSheet(
                    f"background: #1e293b; border-radius: 2px;"
                )

                # Inner fill (shows progress)
                fill_pct = (
                    1.0 if i < current_step - 1
                    else (0.5 if i == current_step - 1
                          else 0.0)
                )
                if fill_pct > 0:
                    fill_w = max(4, int(60 * fill_pct))
                    fill = QFrame(track)
                    fill.setGeometry(0, 0, fill_w, 3)
                    fill.setStyleSheet(
                        f"background: {conn_col}; border-radius: 2px;"
                    )

                inner.addWidget(track, alignment=Qt.AlignVCenter)

        outer.addLayout(inner)

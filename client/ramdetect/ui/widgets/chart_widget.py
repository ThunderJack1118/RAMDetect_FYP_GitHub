"""
ChartWidget
───────────
Thin PyQt5 wrapper around a Matplotlib FigureCanvas.

Sets consistent dark-theme defaults (transparent axes, slate grid, white text)
so every chart in the app looks the same without per-call style boilerplate.

Bundled chart builders (call any of them to populate the widget):
  plot_bar_h(labels, values, title, color)      — horizontal bar chart
  plot_donut(labels, values, colors, title)     — donut / pie chart
  plot_line(x, y_series, labels, title, colors) — multi-series line chart
  plot_heatmap(data, row_labels, col_labels)    — confusion-matrix style

All builders call self.draw() automatically.

Usage
  chart = ChartWidget(figsize=(6, 4))
  chart.plot_bar_h(
      labels=["Hidden Proc", "Code Inject", "Unsigned DLL"],
      values=[0.18, 0.15, 0.12],
      title="Feature Importance",
  )
  layout.addWidget(chart)
  chart.clear()           # blank the axes
"""

import numpy as np
from typing import List, Optional, Sequence

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QSizePolicy, QToolTip
from PyQt5.QtCore    import Qt, QPoint
from ui.style_helpers import set_role, set_tone
from ui.theme import current_theme

try:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure                  import Figure
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False
    FigureCanvas = QWidget       # fallback — no crash on import


# ─────────────────────────────────────────────────────────────────────────────
# Theme-aware Matplotlib defaults
# ─────────────────────────────────────────────────────────────────────────────

_BG          = "#0f172a"
_AX_BG       = "none"
_GRID        = "#1e293b"
_TEXT        = "#94a3b8"
_TITLE_TEXT  = "#cbd5e1"
_FONT        = "DejaVu Sans"

_PALETTE_MAIN   = ["#06b6d4", "#34d399", "#f87171", "#facc15", "#a78bfa", "#fb923c"]
_PALETTE_STATUS = {"clean": "#34d399", "suspicious": "#f87171", "neutral": "#06b6d4"}


def _refresh_chart_palette(theme: str | None = None):
    """Refresh chart colours from the active RAMDetect UI theme."""
    global _BG, _GRID, _TEXT, _TITLE_TEXT, _PALETTE_MAIN, _PALETTE_STATUS
    light = (theme or current_theme() or "dark").lower() == "light"
    if light:
        _BG = "#f8fbff"
        _GRID = "#d9e6ff"
        _TEXT = "#5873a8"
        _TITLE_TEXT = "#1e3a6e"
        _PALETTE_MAIN = ["#1a56db", "#10b981", "#dc2626", "#d97706", "#7c3aed", "#f97316"]
        _PALETTE_STATUS = {"clean": "#10b981", "suspicious": "#dc2626", "neutral": "#1a56db"}
    else:
        _BG = "#0f172a"
        _GRID = "#1e293b"
        _TEXT = "#94a3b8"
        _TITLE_TEXT = "#cbd5e1"
        _PALETTE_MAIN = ["#06b6d4", "#34d399", "#f87171", "#facc15", "#a78bfa", "#fb923c"]
        _PALETTE_STATUS = {"clean": "#34d399", "suspicious": "#f87171", "neutral": "#06b6d4"}


def _tooltip_qss() -> str:
    if (current_theme() or "dark").lower() == "light":
        return (
            "QToolTip{"
            "background-color:#ffffff;"
            "color:#1e3a6e;"
            "border:1px solid #9fb7e5;"
            "border-radius:8px;"
            "padding:8px 10px;"
            "}"
        )
    return (
        "QToolTip{"
        "background-color:#1e293b;"
        "color:#e2e8f0;"
        "border:1px solid rgba(6,182,212,191);"
        "border-radius:8px;"
        "padding:8px 10px;"
        "}"
    )


def _style_ax(ax, title: str = "", xlabel: str = "", ylabel: str = ""):
    """Apply the active RAMDetect theme to a matplotlib Axes object."""
    _refresh_chart_palette()
    ax.set_facecolor(_AX_BG)
    ax.tick_params(colors=_TEXT, labelsize=9)
    ax.xaxis.label.set_color(_TEXT)
    ax.yaxis.label.set_color(_TEXT)
    for spine in ax.spines.values():
        spine.set_color(_GRID)
    if title:
        ax.set_title(title, color=_TITLE_TEXT, fontsize=11, fontweight="bold", pad=10)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=9)


# ─────────────────────────────────────────────────────────────────────────────
# ChartWidget
# ─────────────────────────────────────────────────────────────────────────────

class ChartWidget(QWidget):
    """Dark-themed Matplotlib canvas embedded in a QWidget."""

    def __init__(self,
                 figsize: tuple = (6, 4),
                 dpi:     int   = 96,
                 parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        _refresh_chart_palette()
        self.setStyleSheet(_tooltip_qss())

        # Optional Matplotlib hover/highlight support.
        self._hover_cid = None
        self._hover_annotation = None
        self._hover_patches = []
        self._hover_last_index = None

        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)

        if _HAS_MPL:
            self._fig    = Figure(figsize=figsize, dpi=dpi, facecolor="none")
            self._fig.patch.set_alpha(0.0)
            self._canvas = FigureCanvas(self._fig)
            set_role(self._canvas, "transparent")
            self._canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self._canvas.setMouseTracking(True)
            self._canvas.setStyleSheet(_tooltip_qss())
            vb.addWidget(self._canvas)
        else:
            from PyQt5.QtWidgets import QLabel
            lbl = QLabel("matplotlib not installed")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color: #64748b; font-size: 12px;")
            vb.addWidget(lbl)
            self._fig    = None
            self._canvas = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _reset(self) -> Optional[object]:
        """Clear the figure and return a fresh Axes, or None if no MPL."""
        if not _HAS_MPL or self._fig is None:
            return None

        if self._canvas is not None and self._hover_cid is not None:
            try:
                self._canvas.mpl_disconnect(self._hover_cid)
            except Exception:
                pass
        self._hover_cid = None
        self._hover_annotation = None
        self._hover_patches = []
        self._hover_last_index = None

        _refresh_chart_palette()
        self.setStyleSheet(_tooltip_qss())
        if self._canvas is not None:
            self._canvas.setStyleSheet(_tooltip_qss())
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        self._fig.patch.set_alpha(0.0)
        ax.set_facecolor("none")
        return ax

    def draw(self):
        if self._canvas:
            self._canvas.draw_idle()

    def clear(self):
        ax = self._reset()
        if ax:
            _style_ax(ax)
            self.draw()

    # ── Chart builders ────────────────────────────────────────────────────────

    def plot_bar_h(self,
                   labels: List[str],
                   values: List[float],
                   title:  str   = "",
                   color:  str   = "#06b6d4",
                   xlabel: str   = "Importance",
                   tooltips: Optional[List[str]] = None,
                   hover: bool = False,
                   left_margin: Optional[float] = None):
        """Horizontal bar chart — feature importance style.

        Optional hover mode highlights the hovered bar and displays a native
        Qt tooltip. Existing callers remain compatible because hover arguments
        are optional.
        """
        ax = self._reset()
        if ax is None:
            return

        import matplotlib.ticker as _ticker

        n       = len(labels)
        y       = np.arange(n)
        max_val = max(values) if values else 1

        bars = ax.barh(y, values, color=color, alpha=0.88, height=0.55)
        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=8.5)
        ax.invert_yaxis()
        ax.set_xlim(0, max_val * 1.25 if max_val else 1)
        ax.set_ylim(n - 0.5, -0.5)
        ax.xaxis.grid(True, color=_GRID, linewidth=0.5, alpha=0.5, linestyle="--")
        ax.set_axisbelow(True)
        ax.xaxis.set_major_formatter(_ticker.FuncFormatter(lambda x, _: f"{x:.2f}"))
        _style_ax(ax, title=title, xlabel=xlabel)
        # Prevent the x-axis label (e.g. "Importance") and final tick from
        # being clipped inside compact dashboard cards.
        ax.xaxis.labelpad = 4

        # Leave enough label space, but keep the bar region wide and centred.
        # Optional left_margin lets narrow/dashboard views use more bar width.
        max_chars = max((len(l) for l in labels), default=8)
        if left_margin is not None:
            left_frac = max(0.16, min(float(left_margin), 0.48))
        else:
            left_frac = min(0.36, 0.10 + max_chars * 0.009)
        self._fig.subplots_adjust(left=left_frac, right=0.955, top=0.955, bottom=0.305)

        if hover and self._canvas is not None:
            # Use a native Qt tooltip instead of an in-chart annotation.
            # This prevents tooltip boxes from covering the bars or being
            # clipped by the matplotlib axes.
            self._hover_patches = list(bars)
            self._hover_last_index = None

            def _html_tip(label: str, val: float, tip: str) -> str:
                safe_tip = str(tip or "").replace("\n", "<br>")
                if safe_tip:
                    safe_tip = safe_tip.replace("Importance:", "<b>Importance:</b>", 1)
                    safe_tip = safe_tip.replace("Meaning:", "<b>Meaning:</b>", 1)
                    if not safe_tip.startswith("<b>"):
                        safe_tip = f"<b>{label}</b><br>{safe_tip}"
                else:
                    safe_tip = f"<b>{label}</b><br><b>Importance:</b> {val:.4f}"
                return (
                    f"<div style='white-space:normal; width:330px; color:{_TITLE_TEXT}; background:transparent;'>"
                    f"{safe_tip}</div>"
                )

            def _reset_bars():
                for patch in bars:
                    patch.set_alpha(0.88)
                    patch.set_linewidth(0.0)
                    patch.set_edgecolor(color)

            def _canvas_pos(event):
                try:
                    return event.guiEvent.pos() + QPoint(18, 18)
                except Exception:
                    # Matplotlib event.y uses bottom-origin; Qt uses top-origin.
                    return QPoint(int(event.x) + 18,
                                  int(self._canvas.height() - event.y) + 18)

            def _on_motion(event):
                if event.inaxes != ax:
                    if self._hover_last_index is not None:
                        self._hover_last_index = None
                        _reset_bars()
                        QToolTip.hideText()
                        self.draw()
                    return

                hit_idx = None
                for i, patch in enumerate(bars):
                    hit, _ = patch.contains(event)
                    if hit:
                        hit_idx = i
                        break

                if hit_idx is None:
                    if self._hover_last_index is not None:
                        self._hover_last_index = None
                        _reset_bars()
                        QToolTip.hideText()
                        self.draw()
                    return

                val = values[hit_idx] if hit_idx < len(values) else 0.0
                label = labels[hit_idx] if hit_idx < len(labels) else "Feature"
                tip = tooltips[hit_idx] if tooltips and hit_idx < len(tooltips) else ""

                QToolTip.showText(
                    self._canvas.mapToGlobal(_canvas_pos(event)),
                    _html_tip(label, val, tip),
                    self._canvas,
                )

                if self._hover_last_index == hit_idx:
                    return

                for i, patch in enumerate(bars):
                    if i == hit_idx:
                        patch.set_alpha(1.0)
                        patch.set_linewidth(1.2)
                        patch.set_edgecolor("#1a56db" if (current_theme() or "dark").lower() == "light" else "#67e8f9")
                    else:
                        patch.set_alpha(0.32)
                        patch.set_linewidth(0.0)
                        patch.set_edgecolor(color)

                self._hover_last_index = hit_idx
                self.draw()

            self._hover_cid = self._canvas.mpl_connect("motion_notify_event", _on_motion)

        self.draw()

    def plot_donut(self,
                   labels:      List[str],
                   values:      List[float],
                   colors:      Optional[List[str]] = None,
                   title:       str  = "",
                   show_legend: bool = True,
                   show_pct:    bool = False):
        """Donut (pie) chart.
        show_legend: False when caller provides its own Qt legend.
        show_pct:    True to show percentage labels inside wedges.
        """
        ax = self._reset()
        if ax is None:
            return

        if colors is None:
            colors = _PALETTE_MAIN[:len(labels)]

        autopct = "%1.1f%%" if show_pct else None
        result = ax.pie(
            values,
            labels=None,
            colors=colors,
            autopct=autopct,
            startangle=90,
            pctdistance=0.75,
            wedgeprops={"linewidth": 0, "edgecolor": "none", "width": 0.52},
        )
        wedges = result[0]
        if show_pct and len(result) >= 3:
            for at in result[2]:
                at.set_color(_BG)
                at.set_fontsize(9)
                at.set_fontweight("bold")

        if show_legend:
            ax.legend(
                wedges, labels,
                loc="lower center",
                bbox_to_anchor=(0.5, -0.12),
                ncol=len(labels),
                fontsize=9,
                labelcolor=_TEXT,
                frameon=False,
            )
        _style_ax(ax, title=title)
        ax.set_aspect("equal")
        # Use explicit padding instead of tight_layout so the donut remains
        # centred without reintroducing a dark rectangular axes patch.
        self._fig.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.02)
        self.draw()

    def plot_line(self,
                  x:         Sequence,
                  y_series:  List[Sequence],
                  labels:    Optional[List[str]] = None,
                  title:     str  = "",
                  colors:    Optional[List[str]] = None,
                  xlabel:    str  = "",
                  ylabel:    str  = "",
                  integer_y: bool = False):
        """Multi-series line chart.
        integer_y: True forces integer Y-axis ticks (for count data).
        """
        ax = self._reset()
        if ax is None:
            return

        if colors is None:
            colors = _PALETTE_MAIN
        if labels is None:
            labels = [f"Series {i+1}" for i in range(len(y_series))]

        for i, (y, lbl) in enumerate(zip(y_series, labels)):
            col = colors[i % len(colors)]
            ax.plot(x, y, color=col, linewidth=2, label=lbl, marker="o",
                    markersize=3, markerfacecolor=col)
            ax.fill_between(x, y, alpha=0.08, color=col)

        ax.xaxis.grid(True, color=_GRID, linewidth=0.5, alpha=0.5)
        ax.yaxis.grid(True, color=_GRID, linewidth=0.5, alpha=0.5)
        ax.set_axisbelow(True)

        if integer_y:
            import matplotlib.ticker as _ticker
            ax.yaxis.set_major_locator(_ticker.MaxNLocator(integer=True))
        if len(y_series) > 1:
            ax.legend(fontsize=9, labelcolor=_TEXT, frameon=False,
                      loc="upper left")
        _style_ax(ax, title=title, xlabel=xlabel, ylabel=ylabel)
        ax.xaxis.labelpad = 6
        ax.yaxis.labelpad = 6
        self._fig.subplots_adjust(left=0.12, right=0.98, top=0.96, bottom=0.19)
        self.draw()

    def plot_heatmap(self,
                     data:       List[List[float]],
                     row_labels: List[str],
                     col_labels: List[str],
                     title:      str = "",
                     cmap:       str = "YlOrRd"):
        """Confusion-matrix / heatmap."""
        ax = self._reset()
        if ax is None:
            return

        arr = np.array(data, dtype=float)
        im  = ax.imshow(arr, cmap=cmap, aspect="auto")

        ax.set_xticks(np.arange(len(col_labels)))
        ax.set_yticks(np.arange(len(row_labels)))
        ax.set_xticklabels(col_labels, fontsize=9, rotation=30, ha="right")
        ax.set_yticklabels(row_labels, fontsize=9)

        # Annotate cells
        for i in range(arr.shape[0]):
            for j in range(arr.shape[1]):
                val  = arr[i, j]
                tcol = "black" if val > arr.max() * 0.6 else _TEXT
                ax.text(j, i, f"{val:.0f}", ha="center", va="center",
                        color=tcol, fontsize=9, fontweight="bold")

        self._fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        _style_ax(ax, title=title)
        self._fig.tight_layout(pad=1.2)
        self.draw()

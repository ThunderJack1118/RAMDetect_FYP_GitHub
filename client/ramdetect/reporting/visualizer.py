"""
ramdetect/reporting/visualizer.py
───────────────────────────────────
Matplotlib chart helpers used by PDFReporter (and optionally by the GUI's
ML Insights page).

All public methods return an ``io.BytesIO`` PNG buffer so the caller can embed
the image wherever it likes (ReportLab, Qt label, etc.).

Design theme: Corporate white — light/transparent background so charts
render cleanly on white PDF pages, with a professional colour palette.

Usage:
    from ramdetect.reporting.visualizer import ChartBuilder

    buf = ChartBuilder.confidence_bar(rf=94.2, ae=87.5, final=91.7, is_suspicious=True)
    buf = ChartBuilder.feature_importance(feature_importance_list)
    buf = ChartBuilder.anomaly_pie(clean_pct=85.0, suspicious_pct=15.0)
    buf = ChartBuilder.artifact_summary(processes, threads, dlls, handles)
"""

from __future__ import annotations

import io
from typing import Any, Dict, List, Optional


# Force a non-GUI Matplotlib backend for report generation threads.
# Report generation runs inside a QThread, and pyplot may otherwise try to
# start a Qt/Tk GUI backend, causing warnings or failures.
try:
    import matplotlib
    matplotlib.use("Agg", force=True)
except Exception:
    pass

# ── Corporate palette (light-bg friendly) ─────────────────────────────────────
_BG_TRANS = "white"       # chart background → white to blend with PDF page
_AX_BG    = "#F8FAFC"     # axes background (very light grey)
_NAVY     = "#1E3A5F"     # dark navy — primary accent (matches PDF header)
_CYAN     = "#0EA5E9"     # sky blue — secondary accent
_GREEN    = "#16A34A"     # clean / safe green
_RED      = "#DC2626"     # suspicious / danger red
_AMBER    = "#D97706"     # warning amber
_MUTED    = "#64748B"     # slate-500 for labels
_GRID     = "#E2E8F0"     # very light grid lines
_TEXT     = "#1E293B"     # near-black text

_DPI = 140


def _fig_init(w: float, h: float):
    """Create a figure with the corporate white theme applied."""
    import matplotlib.pyplot as plt
    import matplotlib as mpl
    mpl.rcParams.update({
        "font.family":      "DejaVu Sans",
        "axes.spines.top":  False,
        "axes.spines.right":False,
    })
    fig, ax_or_axes = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(_BG_TRANS)
    return fig, ax_or_axes


def _buf_from_fig(fig) -> io.BytesIO:
    """Save *fig* to a BytesIO PNG buffer, close the figure, and return it."""
    import matplotlib.pyplot as plt
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=_DPI,
                facecolor=_BG_TRANS, edgecolor="none", bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return buf


def _style_ax(ax):
    """Apply consistent axis styling."""
    ax.set_facecolor(_AX_BG)
    ax.spines["left"].set_color(_GRID)
    ax.spines["bottom"].set_color(_GRID)
    ax.tick_params(colors=_MUTED, labelsize=8)
    ax.xaxis.label.set_color(_MUTED)
    ax.yaxis.label.set_color(_MUTED)


# ── Chart builders ────────────────────────────────────────────────────────────

class ChartBuilder:
    """
    Static factory methods — each returns an ``io.BytesIO`` PNG buffer.
    Returns ``None`` if matplotlib is not installed or data is invalid.
    """

    # ── Chart 1: ML Confidence grouped bar ───────────────────────────────────
    @staticmethod
    def confidence_bar(
        rf: float,
        ae: float,
        final: float,
        is_suspicious: bool = False,
    ) -> Optional[io.BytesIO]:
        """
        Horizontal bar chart: Random Forest, Autoencoder, Hybrid scores.
        Final bar is red for suspicious, green for clean.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches

            labels = ["Random Forest", "Autoencoder", "Hybrid (Final)"]
            scores = [rf, ae, final]
            colors = [_CYAN, _CYAN, _RED if is_suspicious else _GREEN]

            fig, ax = _fig_init(6.5, 2.0)
            _style_ax(ax)

            bars = ax.barh(labels, scores, color=colors, height=0.45,
                           edgecolor="white", linewidth=0.8, zorder=3)
            ax.set_xlim(0, 110)
            ax.set_xlabel("Score (%)", fontsize=8, color=_MUTED)
            ax.set_yticks(range(len(labels)))
            ax.set_yticklabels(labels, color=_TEXT, fontsize=9, fontweight="bold")
            ax.xaxis.set_tick_params(labelsize=8)
            ax.grid(axis="x", color=_GRID, linewidth=0.8, zorder=1)

            for bar, score in zip(bars, scores):
                ax.text(
                    score + 1.5,
                    bar.get_y() + bar.get_height() / 2,
                    f"{score:.1f}%",
                    va="center", ha="left",
                    color=_TEXT, fontsize=9, fontweight="bold",
                )

            ax.set_title("ML Confidence Breakdown", color=_NAVY,
                         fontsize=10, fontweight="bold", pad=8, loc="left")
            fig.tight_layout(pad=0.6)
            return _buf_from_fig(fig)

        except Exception:
            return None

    # ── Chart 2: Feature importance horizontal bar ────────────────────────────
    @staticmethod
    def feature_importance(
        feature_importance: List[Dict[str, Any]],
        top_n: int = 10,
    ) -> Optional[io.BytesIO]:
        """
        Horizontal bar chart for the top-N most important features.
        Bars use a navy→cyan gradient via individual colours by rank.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.cm as cm
            import numpy as np

            top = feature_importance[:top_n]
            if not top:
                return None

            fi_names = [str(f.get("feature", f.get("name", "?")))[:35] for f in top]
            fi_vals  = [float(f.get("importance", f.get("value", 0))) * 100 for f in top]

            # Colour gradient: darkest for highest importance
            norm_vals = np.array(fi_vals)
            if norm_vals.max() > 0:
                norm_vals = norm_vals / norm_vals.max()
            bar_colors = [
                plt.cm.Blues(0.4 + 0.5 * v) for v in norm_vals
            ]

            height = max(3.5, len(fi_names) * 0.52)
            fig, ax = _fig_init(6.5, height)
            _style_ax(ax)

            y_pos = list(range(len(fi_names) - 1, -1, -1))
            bars  = ax.barh(y_pos, fi_vals, color=bar_colors, height=0.55,
                            edgecolor="white", linewidth=0.6, zorder=3)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(fi_names, color=_TEXT, fontsize=8)
            ax.set_xlabel("Importance (%)", fontsize=8, color=_MUTED)
            ax.grid(axis="x", color=_GRID, linewidth=0.8, zorder=1)

            for bar, val in zip(bars, fi_vals):
                ax.text(
                    val + 0.3,
                    bar.get_y() + bar.get_height() / 2,
                    f"{val:.1f}%",
                    va="center", ha="left", color=_TEXT, fontsize=7.5,
                )

            ax.set_title("Top Feature Importance", color=_NAVY,
                         fontsize=10, fontweight="bold", pad=8, loc="left")
            fig.tight_layout(pad=0.6)
            return _buf_from_fig(fig)

        except Exception:
            return None

    # ── Chart 3: Anomaly distribution donut ──────────────────────────────────
    @staticmethod
    def anomaly_pie(
        clean_pct: float,
        suspicious_pct: float,
    ) -> Optional[io.BytesIO]:
        """
        Donut chart: clean vs suspicious artifact percentages.
        Centre label shows the dominant category.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches

            if clean_pct + suspicious_pct <= 0:
                return None

            fig, ax = plt.subplots(figsize=(5.5, 4.2))
            fig.patch.set_facecolor(_BG_TRANS)
            ax.set_facecolor(_BG_TRANS)

            wedge_props = dict(width=0.50, edgecolor="white", linewidth=3)
            ax.pie(
                [clean_pct, suspicious_pct],
                colors=[_GREEN, _RED],
                startangle=90,
                wedgeprops=wedge_props,
                counterclock=False,
            )

            # Centre donut label
            dominant = "CLEAN" if clean_pct >= suspicious_pct else "SUSP."
            dom_col  = _GREEN  if clean_pct >= suspicious_pct else _RED
            dom_pct  = max(clean_pct, suspicious_pct)
            ax.text(0,  0.10, f"{dom_pct:.0f}%", ha="center", va="center",
                    fontsize=20, fontweight="bold", color=dom_col)
            ax.text(0, -0.22, dominant, ha="center", va="center",
                    fontsize=11, fontweight="bold", color=_MUTED)

            # Legend
            legend_items = [
                mpatches.Patch(color=_GREEN, label=f"Clean  {clean_pct:.1f}%"),
                mpatches.Patch(color=_RED,   label=f"Suspicious  {suspicious_pct:.1f}%"),
            ]
            ax.legend(handles=legend_items, loc="lower center",
                      bbox_to_anchor=(0.5, -0.08), ncol=2,
                      fontsize=10, frameon=False, labelcolor=_TEXT)

            ax.set_title("Anomaly Distribution", color=_NAVY,
                         fontsize=12, fontweight="bold", pad=10)
            fig.tight_layout(pad=0.6)
            return _buf_from_fig(fig)

        except Exception:
            return None

    # ── Chart 4: Artifact summary — two-panel split ───────────────────────────
    @staticmethod
    def artifact_summary(
        processes: list,
        threads:   list,
        dlls:      list,
        handles:   list,
    ) -> Optional[io.BytesIO]:
        """
        Two-panel chart:
          Left  — Processes & Threads (small counts, linear scale)
          Right — DLLs & Handles (larger counts, log scale)
        Avoids the massive scale distortion when handles >> processes.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.ticker as ticker
            import numpy as np

            def _is_susp(item: dict) -> bool:
                return str(item.get("status", "")).lower() in ("suspicious", "malicious")

            n_susp_p = sum(1 for p in processes if _is_susp(p))
            n_susp_t = sum(1 for t in threads   if _is_susp(t))
            n_susp_d = sum(1 for d in dlls      if _is_susp(d))
            n_susp_h = sum(1 for h in handles   if _is_susp(h))

            # Split into two groups so different scales don't crush small bars
            group_a_labels  = ["Processes", "Threads"]
            group_a_totals  = [len(processes), len(threads)]
            group_a_suspics = [n_susp_p, n_susp_t]

            group_b_labels  = ["DLLs", "Handles"]
            group_b_totals  = [len(dlls), len(handles)]
            group_b_suspics = [n_susp_d, n_susp_h]

            fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(6.5, 4.0))
            fig.patch.set_facecolor(_BG_TRANS)

            width = 0.38

            for ax_, labels_, totals_, suspics_, use_log in [
                (ax_a, group_a_labels, group_a_totals, group_a_suspics, False),
                (ax_b, group_b_labels, group_b_totals, group_b_suspics, True),
            ]:
                _style_ax(ax_)
                x_ = np.arange(len(labels_))

                b1_ = ax_.bar(x_ - width/2, totals_,  width, label="Total",
                              color=_CYAN, edgecolor="white", linewidth=0.8, zorder=3)
                b2_ = ax_.bar(x_ + width/2, suspics_, width, label="Suspicious",
                              color=_RED,  edgecolor="white", linewidth=0.8, zorder=3)

                ax_.set_xticks(x_)
                ax_.set_xticklabels(labels_, color=_TEXT, fontsize=8.5, fontweight="bold")
                ax_.grid(axis="y", color=_GRID, linewidth=0.8, zorder=1)

                if use_log and max(totals_ + suspics_) > 0:
                    ax_.set_yscale("log")
                    ax_.yaxis.set_major_formatter(ticker.FuncFormatter(
                        lambda val, _: f"{int(val):,}" if val >= 1 else ""
                    ))
                    ax_.set_ylabel("Count (log scale)", fontsize=7.5, color=_MUTED)
                else:
                    ax_.set_ylabel("Count", fontsize=7.5, color=_MUTED)

                # Value labels above bars
                for bar_ in list(b1_) + list(b2_):
                    h_ = bar_.get_height()
                    if h_ > 0:
                        ax_.text(
                            bar_.get_x() + bar_.get_width() / 2,
                            h_ * 1.05 if use_log else h_ + max(totals_) * 0.01,
                            f"{int(h_):,}",
                            ha="center", va="bottom", fontsize=7, color=_TEXT,
                        )

            ax_a.legend(fontsize=7.5, frameon=False, labelcolor=_TEXT, loc="upper right")
            ax_a.set_title("Processes & Threads", color=_NAVY,
                           fontsize=9, fontweight="bold", pad=6, loc="left")
            ax_b.set_title("DLLs & Handles", color=_NAVY,
                           fontsize=9, fontweight="bold", pad=6, loc="left")

            fig.suptitle("Artifact Overview", color=_NAVY,
                         fontsize=10, fontweight="bold", x=0.02, ha="left", y=1.01)
            fig.tight_layout(pad=0.8)
            return _buf_from_fig(fig)

        except Exception:
            return None

    # ── Chart 5: Severity breakdown bar ──────────────────────────────────────
    @staticmethod
    def severity_breakdown(findings: list) -> Optional[io.BytesIO]:
        """
        Horizontal stacked/grouped bar showing HIGH / MEDIUM / LOW finding counts.
        New chart added for the corporate design.
        """
        try:
            import matplotlib.pyplot as plt
            import numpy as np

            if not findings:
                return None

            high   = sum(1 for f in findings if str(f.get("severity","")).upper() in ("HIGH","CRITICAL"))
            medium = sum(1 for f in findings if str(f.get("severity","")).upper() == "MEDIUM")
            low    = sum(1 for f in findings if str(f.get("severity","")).upper() in ("LOW","INFO"))

            if high + medium + low == 0:
                return None

            labels = ["HIGH", "MEDIUM", "LOW"]
            counts = [high, medium, low]
            colors = [_RED, _AMBER, _CYAN]

            fig, ax = _fig_init(5.0, 1.6)
            _style_ax(ax)

            bars = ax.barh(labels, counts, color=colors, height=0.45,
                           edgecolor="white", linewidth=0.8, zorder=3)
            ax.set_xlabel("Finding count", fontsize=8, color=_MUTED)
            ax.set_yticks(range(len(labels)))
            ax.set_yticklabels(labels, color=_TEXT, fontsize=9, fontweight="bold")
            ax.grid(axis="x", color=_GRID, linewidth=0.8, zorder=1)

            for bar, count in zip(bars, counts):
                if count > 0:
                    ax.text(count + 0.1, bar.get_y() + bar.get_height() / 2,
                            str(count), va="center", fontsize=9,
                            fontweight="bold", color=_TEXT)

            ax.set_title("Findings by Severity", color=_NAVY,
                         fontsize=10, fontweight="bold", pad=8, loc="left")
            fig.tight_layout(pad=0.6)
            return _buf_from_fig(fig)

        except Exception:
            return None
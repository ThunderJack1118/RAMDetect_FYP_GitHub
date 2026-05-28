"""
ui/pages/ml_insights.py  —  ML Insights (v8.2 - RAMDetect ML-only Fusion)

Design target:
  • Preserve the older RAMDetect ML Insights layout:
      top-left feature importance, top-right distribution,
      bottom-left score/timeline stack, bottom-right metrics.
  • Update wording to latest RAMDetect architecture:
      post-incident RAM forensics, ML-only decision, RF threshold 0.5,
      Autoencoder MSE as a fused RF input, and 54 + 1 = 55 inputs.
"""
from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QProgressBar, QSizePolicy,
    QPushButton, QDialog, QStackedWidget,
)
from PyQt5.QtCore import Qt

from ui.pages.base_page   import BasePage
from ui.bridge.session    import AppState
from ui.bridge.ml_bridge  import MLBridge          # ← get_model_metadata() lives here
from ui.widgets.chart_widget import ChartWidget

_BG     = '#0f172a'
_BORDER = '#334155'
_CYAN   = '#06b6d4'
_GREEN  = '#34d399'
_RED    = '#f87171'
_YELLOW = '#facc15'
_PURPLE = '#a855f7'
_PINK   = '#ec4899'
_TEXT   = '#e2e8f0'
_MUTED  = '#94a3b8'

# Last-resort defaults — only used if BOTH JSON files are missing
_MOCK = dict(
    accuracy=96.3, precision=94.8, recall=92.1,
    f1=93.4, fpr=3.2, proc_time='3.4s',
    samples=59668, features=55,
    version='v2.4.0-MLOnly-Fusion', trained='Not yet trained',
)

_DATASET_NAME = "CIC-MalMem-2022"
_RF_THRESHOLD = 0.5
_FUSED_INPUT_TEXT = "54 base features + AE MSE = 55 fused RF inputs"
_ML_SUPPORT_TEXT = "ML Decision Feature Support: 28/55"
_SEMANTIC_EXPORT_TEXT = "CIC Semantic Export Coverage: 36/55 (65.45%)"
_CSV_SCHEMA_TEXT = "CIC CSV Schema Compatibility: 100.00%"


# ── Pure helpers ──────────────────────────────────────────────────────────────

def _pct(v: float) -> float:
    """Normalise 0-1 fraction or 0-100 value → 0-100 float."""
    return v * 100.0 if v <= 1.0 else float(v)

def _pct_str(v) -> str:
    """Format a metric value (0-1 or 0-100) as '99.9%'."""
    return f"{_pct(float(v)):.1f}%"

def _fpr_str(v) -> str:
    """Format a false-positive-rate value (0-1 or 0-100) as '0.14%'."""
    pct = float(v) * 100 if float(v) <= 1.0 else float(v)
    return f"{pct:.2f}%"

def _safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default

def _score_pct_from_ml(ml: dict) -> float:
    """Return RAMDetect's final fused ML score as a 0-100 percentage."""
    for key in ("hybrid_score", "fusion_score", "rf_score", "confidence", "score"):
        if key in ml and ml.get(key) is not None:
            return _pct(_safe_float(ml.get(key)))
    return 0.0

def _find_numeric_key(obj, key_names, depth: int = 0):
    """Recursively find a numeric value by key name in nested result dictionaries."""
    if depth > 4:
        return None

    wanted = {k.lower() for k in key_names}

    if isinstance(obj, dict):
        # Exact keys first.
        for k, v in obj.items():
            if str(k).lower() in wanted and v is not None:
                try:
                    return float(v)
                except Exception:
                    pass

        # Then nested structures.
        for v in obj.values():
            found = _find_numeric_key(v, key_names, depth + 1)
            if found is not None:
                return found

    elif isinstance(obj, (list, tuple)):
        for v in obj:
            found = _find_numeric_key(v, key_names, depth + 1)
            if found is not None:
                return found

    return None

def _ae_mse_value(ml: dict):
    """Return Autoencoder reconstruction MSE/fusion value if available.

    Different RAMDetect result versions stored this under different field names.
    Direct MSE fields are preferred. Legacy AE score fields are only used as a
    fallback so the UI does not show N/A when an AE value exists.
    """
    mse_keys = (
        "ae_mse", "autoencoder_mse", "autoencoder_reconstruction_mse",
        "reconstruction_mse", "reconstruction_error", "ae_reconstruction_error",
        "mse", "mse_value", "ae_mse_input", "autoencoder_mse_input",
    )
    found = _find_numeric_key(ml, mse_keys)
    if found is not None:
        return found

    legacy_score_keys = (
        "ae_score", "autoencoder_score", "autoencoder_anomaly_score",
        "ae_anomaly_score", "anomaly_score",
    )
    return _find_numeric_key(ml, legacy_score_keys)

def _ae_mse_display(ml: dict) -> tuple[str, int]:
    """Display the actual AE reconstruction_error from session ml_result.

    Returns (display_text, bar_value). The bar is only a compact visual cue,
    because reconstruction_error is not a percentage.
    """
    direct_keys = (
        "reconstruction_error", "ae_mse", "autoencoder_mse",
        "reconstruction_mse", "ae_reconstruction_error",
    )
    for key in direct_keys:
        if isinstance(ml, dict) and ml.get(key) is not None:
            try:
                value = float(ml.get(key))
                return f"{value:.6f}", int(min(max(value * 100.0, 0), 100))
            except Exception:
                pass

    # Search nested result dictionaries if future bridges move the field.
    value = _ae_mse_value(ml)
    if value is not None:
        try:
            value = float(value)
            return f"{value:.6f}", int(min(max(value * 100.0, 0), 100))
        except Exception:
            pass

    return "Not recorded", 0

def _verdict_label(score_pct: float) -> str:
    return "SUSPICIOUS" if score_pct >= (_RF_THRESHOLD * 100.0) else "CLEAN"

def _clean_name(raw: str) -> str:
    if '.' in raw:
        raw = raw.rsplit('.', 1)[-1]
    return raw.replace('_', ' ').strip().title()

def _feature_display_name(raw: str) -> str:
    """Short visual label for RF feature bars."""
    name = _clean_name(raw)
    replacements = {
        "Shared Process Services": "Shared Proc Services",
        "Avg Handles Per Proc": "Avg Handles / Proc",
        "Avg Dlls Per Proc": "Avg DLLs / Proc",
        "Parent Child Anomaly": "Parent-Child Anom.",
        "High Entropy Pe": "High-Entropy PE",
        "Rwx Sections": "RWX Sections",
    }
    return replacements.get(name, name)

def _feature_meaning(raw: str) -> str:
    """Beginner-friendly meaning for common CIC/RAMDetect feature names."""
    name = _clean_name(raw).lower()
    if "shared process services" in name:
        return "Service-hosted/shared process activity; useful when reviewing abnormal service process behaviour."
    if "nservices" in name or name == "services":
        return "Count of service-related objects/features observed in memory."
    if "kernel driver" in name:
        return "Kernel driver/module feature; abnormal driver activity may support deeper compromise analysis."
    if "avg handles" in name or "avg handlers" in name:
        return "Average open handles per process. Unusual values may indicate abnormal resource access."
    if "avg dll" in name:
        return "Average loaded DLL modules per process; useful when reviewing DLL loading or injection patterns."
    if "nmutant" in name or "mutex" in name:
        return "Mutant/mutex object count. Malware often uses mutexes for single-instance or coordination control."
    if "nevent" in name:
        return "Event object count. Events are Windows synchronization objects used by processes and threads."
    if "nsection" in name:
        return "Section object count. Sections relate to mapped files/memory and can support injection analysis."
    if "nsemaphore" in name:
        return "Semaphore object count. Semaphores are synchronization objects used by running software."
    if "hidden" in name:
        return "Hidden process indicator. Higher importance means this feature influenced the ML decision more."
    if "code injection" in name or "inject" in name:
        return "Code injection indicator. Relates to signs of code being placed into another process."
    if "unsigned" in name:
        return "Unsigned module indicator. Unsigned code can be suspicious depending on context."
    if "entropy" in name:
        return "Entropy feature. High entropy can indicate packed, encrypted, or compressed code/data."
    if "orphan" in name:
        return "Orphan relationship feature. It may indicate missing or unusual parent-child process linkage."
    if "persistence" in name:
        return "Persistence-related feature. Helps identify behaviour that may survive restart or relaunch."
    if "rwx" in name:
        return "Readable-writable-executable memory section feature, often reviewed during injection triage."
    if "path" in name:
        return "Path-based feature. Unusual executable or module locations can support suspicious classification."
    return "Memory-forensics feature used by the Random Forest. Higher importance means stronger influence in this model."

def _feature_tooltip(raw: str, importance: float) -> str:
    display = _clean_name(raw)
    return f"{display}\nImportance: {importance:.4f}\nMeaning: {_feature_meaning(raw)}"

def _L(text, size=12, color=_TEXT, bold=False) -> QLabel:
    w = QLabel(str(text))
    w.setTextFormat(Qt.PlainText)
    w.setStyleSheet(
        f"color:{color};font-size:{size}px;"
        f"font-weight:{'700' if bold else '400'};"
        "background-color:transparent;border:none;"
        "border-radius:0px;padding:0px;margin:0px;")
    return w

def _card(min_h=0, fixed_h=0) -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.NoFrame)
    f.setFrameShadow(QFrame.Plain)
    f.setStyleSheet(
        "QFrame{"
        "background-color:rgba(30,41,59,0.40);"
        f"border:1px solid {_BORDER};"
        "border-radius:12px;}")
    if fixed_h:
        f.setFixedHeight(fixed_h)
    elif min_h:
        f.setMinimumHeight(min_h)
    return f

def _hline() -> QFrame:
    sep = QFrame()
    sep.setFrameShape(QFrame.HLine)
    sep.setFixedHeight(1)
    sep.setStyleSheet("background-color:#334155;border:none;border-radius:0px;")
    return sep


def _vline() -> QFrame:
    sep = QFrame()
    sep.setFrameShape(QFrame.VLine)
    sep.setFixedWidth(1)
    sep.setStyleSheet("background-color:rgba(51,65,85,0.85);border:none;border-radius:0px;")
    return sep


def _title_row(icon, icon_color, text) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setSpacing(7)
    row.setContentsMargins(0, 0, 0, 0)
    ico = QLabel(icon)
    ico.setStyleSheet(
        f"color:{icon_color};font-size:14px;"
        "background-color:transparent;border:none;")
    row.addWidget(ico)
    row.addWidget(_L(text, 12, _TEXT, bold=True))
    row.addStretch()
    return row


class MLInsightsPage(BasePage):
    PAGE_TITLE = "ML Insights"

    def __init__(self, main_window):
        super().__init__(main_window, show_results=True)
        self._build_body()

    def _build_body(self):
        outer = QVBoxLayout(self.body)
        # Keep the old 2×2 ML Insights layout, but avoid vertical compression
        # on 900p screens by using compact margins and balanced row heights.
        outer.setContentsMargins(24, 10, 24, 12)
        outer.setSpacing(0)

        self._grid = QGridLayout()
        self._grid.setSpacing(12)
        self._grid.setColumnStretch(0, 1)
        self._grid.setColumnStretch(1, 1)
        self._grid.setRowStretch(0, 0)
        self._grid.setRowStretch(1, 0)
        # True 2×2 layout:
        #   row 0: ML fusion breakdown       | Artifact status distribution
        #   row 1: Insight View              | ML performance metrics
        # Keeping both rows fixed/compact prevents one panel from dragging
        # the other panel downward on 900p screens.
        self._grid.setRowMinimumHeight(0, 250)
        self._grid.setRowMinimumHeight(1, 300)
        outer.addLayout(self._grid)

    def _populate_grid(self):
        while self._grid.count():
            item = self._grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        sess = AppState.current
        if sess is None or not sess.ml_result:
            card = _card()
            v = QVBoxLayout(card)
            v.setAlignment(Qt.AlignCenter)
            v.addWidget(_L("No ML insight data available.", 14, _MUTED))
            self._grid.addWidget(card, 0, 0, 2, 2)
            return

        # Ensure ML Insights uses the full saved session when available.
        # History-only fallback sessions may not carry raw AE MSE or full feature data.
        try:
            needs_full = (
                sess.session_id
                and AppState.full_session_exists(sess.session_id)
                and (
                    "reconstruction_error" not in sess.ml_result
                    or not sess.ml_result.get("feature_importance")
                )
            )
            if needs_full:
                full_sess = AppState.load_full(sess.session_id)
                if full_sess is not None and full_sess.ml_result:
                    AppState._current = full_sess
                    sess = full_sess
        except Exception:
            pass

        ml = sess.ml_result
        self._grid.addWidget(self._sub_confidence(ml),                  0, 0)
        self._grid.addWidget(self._panel_anomaly_dist(ml),              0, 1)
        self._grid.addWidget(self._sub_switchable_chart(ml, sess),      1, 0)
        self._grid.addWidget(self._panel_perf_metrics(),                1, 1)

    # ── Left Panel: ML Fusion + Switchable Chart ─────────────────────────────

    def _panel_left_ml_review(self, ml: dict, sess) -> QWidget:
        """Left column with ML fusion breakdown and a switchable insight chart."""
        wrap = QWidget()
        wrap.setStyleSheet("background-color:transparent;border:none;")
        v = QVBoxLayout(wrap)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)

        v.addWidget(self._sub_confidence(ml), 0)
        v.addWidget(self._sub_switchable_chart(ml, sess), 1)
        return wrap

    def _sub_switchable_chart(self, ml: dict, sess) -> QFrame:
        """Tabbed/switch mode card for timeline and feature importance."""
        card = _card(fixed_h=300)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        root = QVBoxLayout(card)
        # Same title-top rhythm as the other panels.
        root.setContentsMargins(14, 10, 14, 10)
        root.setSpacing(6)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(8)

        title = _L("Insight View", 12, _TEXT, bold=True)
        title.setToolTip("Switch between post-incident finding timeline and fused RF feature importance.")
        header.addWidget(title)
        header.addStretch()

        btn_timeline = QPushButton("Timeline")
        btn_timeline.setToolTip(
            "Timeline: shows how findings accumulate after post-incident RAM dump analysis. "
            "This is for explanation only and is not live detection."
        )
        btn_features = QPushButton("RF Features")
        btn_features.setToolTip(
            "RF Features: shows the top fused Random Forest input features and their beginner-friendly meanings."
        )
        tab_buttons = [btn_timeline, btn_features]

        base_btn_qss = (
            "QPushButton{background:rgba(30,41,59,0.65);"
            "border:1px solid rgba(148,163,184,0.20);"
            "border-radius:8px;color:#94a3b8;"
            "padding:5px 12px;font-size:12px;font-weight:700;}"
            "QPushButton:hover{background:rgba(6,182,212,0.12);color:#e2e8f0;}"
        )
        active_btn_qss = (
            "QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #06b6d4,stop:1 #2563eb);"
            "border:1px solid rgba(6,182,212,0.75);"
            "border-radius:8px;color:white;"
            "padding:5px 12px;font-size:12px;font-weight:800;}"
        )

        for b in tab_buttons:
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedHeight(28)
            b.setStyleSheet(base_btn_qss)

        header.addWidget(btn_timeline)
        header.addWidget(btn_features)
        root.addLayout(header)

        stack = QStackedWidget()
        stack.setStyleSheet("QStackedWidget{background:transparent;border:none;}")
        stack.addWidget(self._tab_timeline_content(sess))
        stack.addWidget(self._tab_feature_importance_content(ml))
        root.addWidget(stack, 1)

        def activate(index: int):
            stack.setCurrentIndex(index)
            for i, btn in enumerate(tab_buttons):
                btn.setStyleSheet(active_btn_qss if i == index else base_btn_qss)

        btn_timeline.clicked.connect(lambda: activate(0))
        btn_features.clicked.connect(lambda: activate(1))
        activate(0)

        return card

    def _tab_timeline_content(self, sess) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:transparent;border:none;")
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)

        buckets  = ['0-30s','30-60s','60-90s','90-120s','120-150s','150-180s']
        findings = getattr(sess, 'findings', None) if sess else None
        if findings:
            total = len(findings)
            ramp  = [max(0, min(total,
                         round(total * (i + 1) / len(buckets))))
                     for i in range(len(buckets))]
            for i in range(1, len(ramp)):
                ramp[i] = max(ramp[i], ramp[i - 1])
        else:
            ramp = [0] * len(buckets)

        chart = ChartWidget(figsize=(5.3, 1.66))
        chart.setMinimumHeight(140)
        chart.setMaximumHeight(156)
        chart.plot_line(
            x=buckets, y_series=[ramp],
            labels=["Findings"],
            title="", colors=[_CYAN],
            xlabel="", ylabel="Count",
            integer_y=True,
        )
        # Prevent the vertical "Count" label from being clipped on the left.
        # This trims the plot area slightly and reserves label padding.
        try:
            chart._fig.subplots_adjust(left=0.155, right=0.975, bottom=0.255, top=0.940)
            if hasattr(chart, "_canvas"):
                chart._canvas.draw_idle()
        except Exception:
            pass
        v.addWidget(chart, 1)
        return page

    def _tab_feature_importance_content(self, ml: dict) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:transparent;border:none;")
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)

        fi = ml.get('feature_importance', [])
        if fi:
            raw_names = [str(d.get('feature', 'Feature')) for d in fi]
            names = [_feature_display_name(n) for n in raw_names]
            vals  = [float(d.get('importance', 0.0)) for d in fi]
            tips = [_feature_tooltip(raw, val) for raw, val in zip(raw_names, vals)]
        else:
            names = ["Feature data not available"]
            vals = [0.0]
            tips = ["No feature-importance data was found in this session."]

        chart = ChartWidget(figsize=(6.5, 1.86))
        chart.setMinimumHeight(158)
        chart.setMaximumHeight(174)
        chart.plot_bar_h(
            labels=names,
            values=vals,
            title="",
            color=_CYAN,
            xlabel="Importance",
            tooltips=tips,
            hover=True,
            left_margin=0.30,
        )
        v.addWidget(chart, 1)
        return page


    # ── Panel 1: Feature Importance ───────────────────────────────────────────

    def _panel_feature_importance(self, ml: dict) -> QFrame:
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(5)
        v.addLayout(_title_row("↗", _CYAN, "Fused RF Feature Importance (Top 10)"))
        sub = _L(_FUSED_INPUT_TEXT, 9, _MUTED)
        sub.setToolTip("Random Forest input = CIC-MalMem base feature vector plus Autoencoder reconstruction MSE.")
        v.addWidget(sub)

        fi    = ml.get('feature_importance', [])
        names = [_clean_name(d['feature']) for d in fi]
        vals  = [float(d['importance'])    for d in fi]

        chart = ChartWidget(figsize=(5.0, 2.25))
        chart.setMinimumHeight(145)
        chart.plot_bar_h(
            labels=names, values=vals,
            title="", color=_CYAN, xlabel="Importance")
        v.addWidget(chart, 1)
        return card

    # ── Panel 2: Anomaly Distribution ─────────────────────────────────────────

    def _panel_anomaly_dist(self, ml: dict) -> QFrame:
        card = _card(fixed_h=250)
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(5)
        v.addLayout(_title_row("◕", _CYAN, "Artifact Status Distribution"))
        sub = _L("Forensic artifact summary only — not a verdict override.", 9, _MUTED)
        sub.setToolTip("RAMDetect final decision remains ML-only. This chart summarises artifact labels for explanation.")
        v.addWidget(sub)

        dist      = ml.get('anomaly_distribution',
                           {'clean': 85.0, 'suspicious': 15.0})
        clean_pct = float(dist.get('clean', 85.0))
        susp_pct  = float(dist.get('suspicious', 15.0))

        row = QHBoxLayout()
        row.setSpacing(16)
        row.setAlignment(Qt.AlignVCenter)

        chart = ChartWidget(figsize=(3.1, 2.35))
        chart.setMinimumWidth(132)
        chart.plot_donut(
            labels=['Clean', 'Suspicious'],
            values=[clean_pct, susp_pct],
            colors=[_GREEN, _RED],
            title="", show_legend=False, show_pct=False,
        )
        row.addWidget(chart, 6)

        legend = QVBoxLayout()
        legend.setAlignment(Qt.AlignVCenter)
        legend.setSpacing(14)
        for color, name, pct in [(_GREEN, 'Clean',      clean_pct),
                                 (_RED,   'Suspicious', susp_pct)]:
            item = QHBoxLayout()
            item.setSpacing(8)
            dot = QLabel("●")
            dot.setStyleSheet(
                f"color:{color};font-size:12px;"
                "background-color:transparent;border:none;")
            dot.setFixedWidth(14)
            item.addWidget(dot)
            item.addWidget(_L(f"{name}  ({pct:.1f}%)", 12, _TEXT))
            item.addStretch()
            legend.addLayout(item)
        row.addLayout(legend, 4)
        v.addLayout(row, 1)
        return card

    # ── Panel 3: Confidence + Timeline ────────────────────────────────────────

    def _panel_conf_and_timeline(self, ml: dict, sess) -> QWidget:
        # Backward-compatible wrapper retained for older navigation calls.
        return self._panel_left_ml_review(ml, sess)

    def _sub_confidence(self, ml: dict) -> QFrame:
        card = _card(fixed_h=250)
        v = QVBoxLayout(card)
        # Match the top title baseline used by the other cards.
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(10)
        v.addLayout(_title_row("🧠", _PURPLE, "ML-Only Feature Fusion Breakdown"))

        final = _score_pct_from_ml(ml)
        verdict = _verdict_label(final)
        ae_value_text, _ = _ae_mse_display(ml)

        def add_bar_row(name: str, value: str, score: float, c1: str, c2: str,
                        is_final: bool, tip: str):
            grp = QVBoxLayout()
            grp.setSpacing(3)
            grp.setContentsMargins(0, 0, 0, 0)

            lrow = QHBoxLayout()
            lrow.setContentsMargins(0, 0, 0, 0)
            lrow.setSpacing(0)

            nl = QLabel(name)
            nl.setToolTip(tip)
            nl.setStyleSheet(
                f"color:{_CYAN if is_final else '#cbd5e1'};font-size:12px;"
                f"font-weight:{'700' if is_final else '400'};"
                "background-color:transparent;border:none;padding:0;margin:0;")
            lrow.addWidget(nl)
            lrow.addStretch()

            sl = QLabel(value)
            sl.setToolTip(tip)
            sl.setStyleSheet(
                f"color:{_CYAN if is_final else _MUTED};font-size:13px;font-weight:800;"
                "background-color:transparent;border:none;padding:0;margin:0;")
            lrow.addWidget(sl)
            grp.addLayout(lrow)

            bar = QProgressBar()
            bar.setMaximum(100)
            bar.setValue(int(min(max(score, 0), 100)))
            bar.setTextVisible(False)
            bar.setFixedHeight(10)
            bar.setStyleSheet(
                "QProgressBar{background-color:#334155;border-radius:3px;border:none;}"
                f"QProgressBar::chunk{{"
                f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                f"stop:0 {c1},stop:1 {c2});"
                f"border-radius:3px;}}"
            )
            grp.addWidget(bar)
            v.addLayout(grp)

        add_bar_row(
            "Fused Random Forest Score",
            f"{final:.1f}%",
            final,
            _PURPLE,
            _PINK,
            False,
            "Final Random Forest score after feature fusion."
        )

        # AE MSE is a raw reconstruction-error value, not a percentage. Showing
        # it as text avoids the old misleading percentage-style progress bar.
        mse_row = QHBoxLayout()
        mse_row.setContentsMargins(0, 0, 0, 0)
        mse_row.setSpacing(6)

        mse_lbl = QLabel("Autoencoder MSE Fusion Input")
        mse_lbl.setToolTip(
            "Read from session ml_result['reconstruction_error']. "
            "This is fused into RF and is not a separate verdict threshold."
        )
        mse_lbl.setStyleSheet(
            "color:#cbd5e1;font-size:12px;font-weight:500;"
            "background:transparent;border:none;padding:0;margin:0;"
        )
        mse_row.addWidget(mse_lbl)
        mse_row.addStretch()

        mse_val = QLabel(ae_value_text)
        mse_val.setToolTip("Raw Autoencoder reconstruction MSE used as the fusion feature.")
        mse_val.setStyleSheet(
            f"color:{_TEXT};font-size:13px;font-weight:800;"
            "background:rgba(148,163,184,0.10);border:1px solid rgba(148,163,184,0.18);"
            "border-radius:6px;padding:3px 10px;margin:0;"
        )
        mse_row.addWidget(mse_val)
        v.addLayout(mse_row)

        add_bar_row(
            f"Final ML Verdict: {verdict}",
            f"{final:.1f}%",
            final,
            (_RED if verdict == "SUSPICIOUS" else _CYAN),
            ("#ef4444" if verdict == "SUSPICIOUS" else "#2563eb"),
            True,
            "ML-only verdict. Threshold fixed at 0.5. No rule-based overrides."
        )

        foot = QLabel("ML-only RF fusion · threshold 0.5 · no veto / dampener / override rules.")
        foot.setWordWrap(False)
        foot.setMaximumHeight(15)
        foot.setToolTip(
            f"{_FUSED_INPUT_TEXT}\n{_ML_SUPPORT_TEXT}\n"
            f"{_SEMANTIC_EXPORT_TEXT}\n{_CSV_SCHEMA_TEXT}"
        )
        foot.setStyleSheet(
            f"color:{_MUTED};font-size:11px;background:transparent;border:none;"
        )
        v.addWidget(foot)

        return card

    def _sub_timeline(self, sess) -> QFrame:
        card = _card(fixed_h=188)
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 8, 14, 8)
        v.setSpacing(4)
        v.addLayout(_title_row("📊", _CYAN, "Post-Incident Finding Timeline"))
        sub = _L("Post-analysis finding accumulation.", 8, _MUTED)
        sub.setToolTip("RAMDetect is a post-incident RAM forensics system.")
        v.addWidget(sub)

        buckets  = ['0-30s','30-60s','60-90s','90-120s','120-150s','150-180s']
        findings = getattr(sess, 'findings', None) if sess else None
        if findings:
            total = len(findings)
            ramp  = [max(0, min(total,
                         round(total * (i + 1) / len(buckets))))
                     for i in range(len(buckets))]
            for i in range(1, len(ramp)):
                ramp[i] = max(ramp[i], ramp[i - 1])
        else:
            ramp = [0] * len(buckets)

        chart = ChartWidget(figsize=(4.6, 1.45))
        chart.setMinimumHeight(104)
        chart.setMaximumHeight(118)
        chart.plot_line(
            x=buckets, y_series=[ramp],
            labels=["Anomalies"],
            title="", colors=[_CYAN],
            xlabel="", ylabel="Count",
            integer_y=True,
        )
        # Prevent the vertical "Count" label from being clipped on the left.
        # This trims the plot area slightly and reserves label padding.
        try:
            chart._fig.subplots_adjust(left=0.155, right=0.975, bottom=0.255, top=0.940)
            if hasattr(chart, "_canvas"):
                chart._canvas.draw_idle()
        except Exception:
            pass
        v.addWidget(chart, 1)
        return card

    def _show_feature_info_dialog(self):
        """Small themed popup explaining current RAMDetect ML feature design."""
        dlg = QDialog(self)
        dlg.setModal(True)
        dlg.setWindowTitle("RAMDetect ML Feature Information")
        dlg.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        dlg.setAttribute(Qt.WA_TranslucentBackground, True)
        dlg.setFixedSize(700, 440)

        outer = QVBoxLayout(dlg)
        outer.setContentsMargins(10, 10, 10, 10)

        card = QFrame()
        card.setObjectName("mlFeatureInfoCard")
        card.setStyleSheet(
            "QFrame#mlFeatureInfoCard {"
            " background: #0f172a;"
            " border: 1px solid rgba(6,182,212,0.40);"
            " border-radius: 14px;"
            "}"
            "QLabel { background: transparent; border: none; }"
        )
        outer.addWidget(card)

        root = QVBoxLayout(card)
        root.setContentsMargins(26, 20, 26, 22)
        root.setSpacing(10)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 6, 0)
        title = QLabel("RAMDetect ML / Feature Information")
        title.setStyleSheet("color:#ffffff;font-size:16px;font-weight:700;background:transparent;border:none;")
        header.addWidget(title, 1)

        close_btn = QPushButton("×")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setFixedSize(34, 34)
        close_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#cbd5e1;border:none;"
            "border-radius:17px;font-size:21px;font-weight:700;}"
            "QPushButton:hover{background:rgba(239,68,68,0.18);color:white;}"
        )
        close_btn.clicked.connect(dlg.accept)
        header.addWidget(close_btn)
        root.addLayout(header)

        desc = QLabel(
            "Architecture reference for documentation only; it does not change runtime verdict logic."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{_MUTED};font-size:11px;background:transparent;border:none;")
        root.addWidget(desc)

        items = [
            ("Application Mode", "Post-incident RAM forensics using DumpIt."),
            ("Decision Logic", "ML-only RF; no veto, clean dampener, or override rules."),
            ("Threshold", "RF decision threshold fixed at 0.5."),
            ("Fusion Schema", _FUSED_INPUT_TEXT),
            ("ML Decision Feature Support", "28/55"),
            ("CIC Semantic Export Coverage", "36/55 (65.45%)"),
            ("CIC CSV Schema Compatibility", "100.00%"),
            ("Autoencoder Role", "AE MSE is a fused RF input, not a separate verdict."),
            ("Dataset", _DATASET_NAME),
        ]

        body = QGridLayout()
        body.setHorizontalSpacing(16)
        body.setVerticalSpacing(7)
        body.setContentsMargins(0, 2, 0, 0)

        for row, (k, val) in enumerate(items):
            k_lbl = QLabel(k)
            k_lbl.setStyleSheet(f"color:{_CYAN};font-size:11px;font-weight:700;background:transparent;border:none;")
            k_lbl.setMinimumWidth(205)
            body.addWidget(k_lbl, row, 0, Qt.AlignTop)

            v_lbl = QLabel(val)
            v_lbl.setWordWrap(True)
            v_lbl.setStyleSheet(f"color:{_TEXT};font-size:11px;font-weight:500;background:transparent;border:none;")
            body.addWidget(v_lbl, row, 1)

        body.setColumnStretch(0, 0)
        body.setColumnStretch(1, 1)
        root.addLayout(body, 1)

        ok = QPushButton("Close")
        ok.setCursor(Qt.PointingHandCursor)
        ok.setFixedHeight(34)
        ok.setStyleSheet(
            "QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #06b6d4,stop:1 #2563eb);color:white;border:none;"
            "border-radius:9px;font-size:12px;font-weight:700;}"
            "QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #22d3ee,stop:1 #3b82f6);}"
        )
        ok.clicked.connect(dlg.accept)
        root.addWidget(ok)

        try:
            parent_geo = self.window().frameGeometry()
            dlg.move(parent_geo.center() - dlg.rect().center())
        except Exception:
            pass

        dlg.exec_()

    # ── Panel 4: Performance Metrics ──────────────────────────────────────────

    def _panel_perf_metrics(self) -> QFrame:
        card = _card(fixed_h=300)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        v = QVBoxLayout(card)
        # Same title-top rhythm as the other panels.
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(6)
        v.addLayout(_title_row("🏆", _YELLOW, "ML Model Performance Metrics"))

        meta = MLBridge.get_model_metadata()

        metrics = [
            ('Accuracy',            _pct_str(meta.get('accuracy',  _MOCK['accuracy']  / 100)), 'excellent'),
            ('Precision',           _pct_str(meta.get('precision', _MOCK['precision'] / 100)), 'excellent'),
            ('Recall',              _pct_str(meta.get('recall',    _MOCK['recall']    / 100)), 'good'),
            ('F1-Score',            _pct_str(meta.get('f1',        _MOCK['f1']        / 100)), 'excellent'),
            ('False Positive Rate', _fpr_str(meta.get('fpr',       _MOCK['fpr']       / 100)), 'good'),
            ('Processing Time',     meta.get('training_time', _MOCK['proc_time']),             'excellent'),
        ]

        STATUS = {
            'excellent': (_GREEN,  'rgba(52,211,153,0.18)'),
            'good':      (_CYAN,   'rgba(6,182,212,0.18)'),
            'fair':      (_YELLOW, 'rgba(250,204,21,0.18)'),
        }

        # One real table container. The previous version stacked rounded mini-cards
        # inside a grid, so borders overlapped and the 2×3 matrix looked misaligned.
        matrix = QFrame()
        matrix.setObjectName("metricMatrix")
        matrix.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        matrix.setFixedHeight(150)
        matrix.setStyleSheet(
            "QFrame#metricMatrix{"
            "background-color:rgba(51,65,85,0.18);"
            "border:1px solid rgba(148,163,184,0.20);"
            "border-radius:10px;"
            "}"
            "QLabel{background:transparent;border:none;}"
        )

        mgrid = QGridLayout(matrix)
        mgrid.setContentsMargins(0, 0, 0, 0)
        mgrid.setHorizontalSpacing(0)
        mgrid.setVerticalSpacing(0)
        mgrid.setColumnStretch(0, 1)
        mgrid.setColumnStretch(1, 1)
        for r in range(3):
            mgrid.setRowMinimumHeight(r, 48)
            mgrid.setRowStretch(r, 0)

        def metric_cell(label: str, value: str, status: str, ri: int, ci: int) -> QFrame:
            vc, bg = STATUS.get(status, (_TEXT, 'transparent'))

            cell = QFrame()
            cell.setObjectName("metricCell")
            cell.setFrameShape(QFrame.NoFrame)
            cell.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

            # Draw only the required separator sides. This keeps a clean single-box
            # matrix with no doubled borders, rounded-card collisions, or row offsets.
            border_right = "border-right:1px solid rgba(148,163,184,0.16);" if ci == 0 else ""
            border_bottom = "border-bottom:1px solid rgba(148,163,184,0.16);" if ri < 2 else ""
            cell.setStyleSheet(
                "QFrame#metricCell{"
                "background:transparent;"
                "border:none;"
                f"{border_right}{border_bottom}"
                "border-radius:0px;"
                "}"
                "QLabel{background:transparent;border:none;}"
            )

            cl = QVBoxLayout(cell)
            cl.setContentsMargins(14, 5, 14, 5)
            cl.setSpacing(2)

            nm = QLabel(label)
            nm.setStyleSheet(
                f"color:{_MUTED};font-size:9px;font-weight:500;"
                "background:transparent;border:none;padding:0;margin:0;"
            )
            cl.addWidget(nm)

            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(8)

            vl = QLabel(value)
            vl.setStyleSheet(
                f"color:{vc};font-size:15px;font-weight:800;"
                "background:transparent;border:none;padding:0;margin:0;"
            )
            row.addWidget(vl)
            row.addStretch()

            bdg = QLabel(status.upper())
            bdg.setAlignment(Qt.AlignCenter)
            bdg.setMinimumWidth(66)
            bdg.setStyleSheet(
                f"color:{vc};background-color:{bg};"
                "border-radius:4px;border:none;"
                "padding:2px 7px;font-size:7px;font-weight:800;"
            )
            row.addWidget(bdg, 0, Qt.AlignVCenter)
            cl.addLayout(row)
            return cell

        for idx, (label, value, status) in enumerate(metrics):
            ri, ci = divmod(idx, 2)
            mgrid.addWidget(metric_cell(label, value, status, ri, ci), ri, ci)

        v.addWidget(matrix)

        samples  = meta.get('total_samples', _MOCK['samples'])
        trained  = meta.get('trained',       _MOCK['trained'])
        version  = meta.get('version',       _MOCK['version'])

        footer = QWidget()
        footer.setObjectName("metricFooter")
        footer.setFixedHeight(74)
        footer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        footer.setStyleSheet(
            "QWidget#metricFooter{background:transparent;border:none;}"
            "QLabel{background:transparent;border:none;}"
        )

        fg = QGridLayout(footer)
        fg.setHorizontalSpacing(20)
        fg.setVerticalSpacing(3)
        fg.setContentsMargins(0, 0, 0, 0)
        fg.setColumnStretch(0, 1)
        fg.setColumnStretch(1, 1)

        footer_items = [
            ('Training Dataset', f"{samples:,} samples"),
            ('Model Version',    str(version)),
            ('Last Trained',     trained),
        ]

        for idx, (k, val) in enumerate(footer_items):
            ri, ci = divmod(idx, 2)
            col = QVBoxLayout()
            col.setSpacing(2)
            kl = QLabel(k)
            kl.setStyleSheet(
                f"color:{_MUTED};font-size:8px;font-weight:400;"
                "background-color:transparent;border:none;padding:0;")
            col.addWidget(kl)

            vl2 = QLabel(str(val))
            vl2.setToolTip(str(val))
            vl2.setWordWrap(True)
            vl2.setStyleSheet(
                f"color:{_TEXT};font-size:9px;font-weight:600;"
                "background-color:transparent;border:none;padding:0;")
            col.addWidget(vl2)
            fg.addLayout(col, ri, ci)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)
        info_lbl = QLabel("ML / Feature Architecture")
        info_lbl.setStyleSheet(
            f"color:{_MUTED};font-size:9px;font-weight:400;"
            "background-color:transparent;border:none;padding:0;")
        info_col.addWidget(info_lbl)

        info_btn = QPushButton("View Details")
        info_btn.setCursor(Qt.PointingHandCursor)
        info_btn.setFixedHeight(26)
        info_btn.setToolTip("Show RAMDetect ML architecture and feature support details.")
        info_btn.setStyleSheet(
            "QPushButton{background:rgba(6,182,212,0.10);"
            "border:1px solid rgba(6,182,212,0.35);border-radius:7px;"
            "color:#67e8f9;padding:0 10px;font-size:10px;font-weight:700;}"
            "QPushButton:hover{background:rgba(6,182,212,0.18);color:#ffffff;}"
            "QPushButton:pressed{background:rgba(8,145,178,0.24);}"
        )
        info_btn.clicked.connect(self._show_feature_info_dialog)
        info_col.addWidget(info_btn)
        fg.addLayout(info_col, 1, 1)

        v.addSpacing(4)
        v.addWidget(footer, 0, Qt.AlignTop)
        return card

    def _on_show(self):
        self._populate_grid()
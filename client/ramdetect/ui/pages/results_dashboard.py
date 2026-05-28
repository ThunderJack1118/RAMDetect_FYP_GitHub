"""
Results Dashboard — Page 5
───────────────────────────
Compact redesign: all cards fit within the viewport without scrolling.

Layout
  HeaderBar  (fixed height)
  ProgressStepper  (fixed height)
  Body  (two equal columns, flex stretch)
    Left   → Verdict card · ML Breakdown · Analysis Statistics
    Right  → Key Findings (scrollable) · Nav row · Quick Actions · Export tiles

Data source: AppState.current  (populated by AnalysisWorker or
restored from history via DashboardPage._view_details + SessionStore).

showEvent rebuilds body on every visit.
"""

import os
import platform
import subprocess

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QPushButton, QScrollArea, QGridLayout,
    QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui  import QFont

from ui.widgets.header_bar       import HeaderBar
from ui.widgets.progress_stepper import ProgressStepper
from ui.widgets.status_badge     import StatusBadge
from ui.widgets.confidence_meter import ConfidenceMeter
from ui.bridge.session           import AppState
from ui.bridge.config_bridge     import Config
from ui.bridge.ml_bridge         import MLBridge
from ui.bridge.report_bridge     import ReportBridge


# ─────────────────────────────────────────────────────────────────────────────
# Severity palette
# ─────────────────────────────────────────────────────────────────────────────
_SEV = {
    "high":   ("#ef4444", "rgba(239,68,68,0.10)"),
    "medium": ("#facc15", "rgba(250,204,21,0.10)"),
    "low":    ("#3b82f6", "rgba(59,130,246,0.10)"),
}


# Designed extractor-level feature indicators shown on Analysis Configuration.
# Runtime raw_features may contain more keys because of aggregation, semantic
# compatibility fields, and diagnostic/provenance metadata; therefore the
# Results Dashboard should display the designed extractor total, not
# len(session.raw_features).
_EXTRACTOR_FEATURE_COUNTS = {
    "process": 25,
    "thread": 15,
    "dll": 20,
    "handle": 12,
    "pe_section": 18,
    "code_injection": 10,
}
_DEFAULT_EXTRACTOR_MODULES = tuple(_EXTRACTOR_FEATURE_COUNTS.keys())


# ─────────────────────────────────────────────────────────────────────────────
# Tiny widget helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(radius: int = 10) -> QFrame:
    f = QFrame()
    f.setStyleSheet(
        f"QFrame {{"
        f"  background: rgba(30,41,59,0.45);"
        f"  border: 1px solid rgba(51,65,85,0.5);"
        f"  border-radius: {radius}px; }}"
    )
    return f


def _bordered_card(border_col: str, radius: int = 10) -> QFrame:
    f = QFrame()
    f.setStyleSheet(
        f"QFrame {{"
        f"  background: rgba(30,41,59,0.45);"
        f"  border: 2px solid {border_col};"
        f"  border-radius: {radius}px; }}"
    )
    return f


def _lbl(text: str, size: int = 11, bold: bool = False,
         color: str = "#94a3b8", wrap: bool = False,
         align=None) -> QLabel:
    l = QLabel(text)
    weight = "700" if bold else "400"
    l.setStyleSheet(
        f"color:{color};background:transparent;border:none;"
        f"font-size:{size}px;font-weight:{weight};"
    )
    if wrap:
        l.setWordWrap(True)
    if align is not None:
        l.setAlignment(align)
    return l


def _hdiv() -> QFrame:
    d = QFrame()
    d.setFixedHeight(1)
    d.setStyleSheet("background:rgba(51,65,85,0.5);border:none;")
    return d


def _icon_circle(char: str, size: int, bg: str, fg: str,
                 font_pt: int = 18) -> QLabel:
    lbl = QLabel(char)
    lbl.setFixedSize(size, size)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setStyleSheet(
        f"background:{bg};border-radius:{size//2}px;color:{fg};border:none;"
        f"font-size:{font_pt}px;padding-bottom:2px;"
    )
    return lbl


def _nav_btn(text: str, page: str, mw) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("iconBtn")
    b.setFont(QFont("Segoe UI", 11))
    b.setFixedHeight(36)
    b.clicked.connect(lambda: mw.navigate_to(page))
    return b


def _action_btn(text: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName("iconBtn")
    b.setFont(QFont("Segoe UI", 11))
    b.setFixedHeight(36)
    return b


# ─────────────────────────────────────────────────────────────────────────────
# Results Dashboard Page
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# Floating centered toast notification
# ─────────────────────────────────────────────────────────────────────────────

class _ExportToast(QWidget):
    """
    Frameless top-level window that floats centred over the parent window
    and auto-dismisses after 3.5 s.
    """

    def __init__(self, parent: QWidget, message: str, success: bool = True):
        super().__init__(
            parent,
            Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint,
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_DeleteOnClose)

        border = "#34d399" if success else "#f87171"
        bg     = "rgba(17,51,34,0.97)" if success else "rgba(60,17,17,0.97)"
        icon   = "✓" if success else "✗"

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QFrame()
        box.setStyleSheet(
            f"QFrame {{"
            f"  background: {bg};"
            f"  border: 2px solid {border};"
            f"  border-radius: 12px;"
            f"}}"
        )
        bv = QHBoxLayout(box)
        bv.setContentsMargins(22, 16, 22, 16)
        bv.setSpacing(14)

        ico = QLabel(icon)
        ico.setStyleSheet(
            f"color:{border}; font-size:22px; font-weight:bold;"
            " background:transparent; border:none;"
        )
        bv.addWidget(ico)

        txt = QLabel(message)
        txt.setStyleSheet(
            f"color:{border}; font-size:12px;"
            " background:transparent; border:none;"
        )
        txt.setWordWrap(True)
        txt.setMaximumWidth(440)
        bv.addWidget(txt, 1)

        outer.addWidget(box)
        self.adjustSize()

    def show_centered(self, parent: QWidget):
        """Centre over the top-level window and auto-dismiss after 3.5 s."""
        win = parent.window() if parent else None
        if win:
            geo = win.geometry()
            x   = geo.x() + (geo.width()  - self.sizeHint().width())  // 2
            y   = geo.y() + (geo.height() - self.sizeHint().height()) // 2
            self.move(x, y)
        self.show()
        self.raise_()
        QTimer.singleShot(3500, self.close)


class ResultsDashboardPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.mw = main_window
        self.setStyleSheet("background:transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        hdr = HeaderBar(show_action=False, show_dashboard=True)
        hdr.dashboard_clicked.connect(lambda: self.mw.navigate_to("dashboard"))
        hdr.settings_clicked.connect(lambda: self.mw.navigate_to("settings"))
        root.addWidget(hdr)

        # 4-step progress stepper
        root.addWidget(ProgressStepper(current_step=4))

        # ── Context bar (filename / date / size / arch) ───────────────────────
        self._ctx_bar = QFrame()
        self._ctx_bar.setFixedHeight(44)
        self._ctx_bar.setStyleSheet(
            "QFrame {"
            "  background: rgba(30,41,59,0.75);"
            "  border: 1px solid rgba(6,182,212,0.3);"
            "  border-radius: 12px;"
            "  margin: 6px 28px 6px 28px;"
            "}"
        )
        ctx_row = QHBoxLayout(self._ctx_bar)
        ctx_row.setContentsMargins(16, 0, 16, 0)
        ctx_row.setSpacing(8)

        # Left stretch to centre the content horizontally
        ctx_row.addStretch()

        ctx_icon = QLabel("📁")
        ctx_icon.setStyleSheet(
            "color:#06b6d4;background:transparent;border:none;font-size:13px;"
        )
        ctx_icon.setFixedWidth(24)

        self._ctx_filename = QLabel("—")
        self._ctx_filename.setStyleSheet(
            "color:#e2e8f0;background:transparent;border:none;"
            "font-size:12px;font-weight:600;"
        )

        self._ctx_meta = QLabel("")
        self._ctx_meta.setStyleSheet(
            "color:#94a3b8;background:transparent;border:none;font-size:11px;"
        )

        ctx_row.addWidget(ctx_icon, alignment=Qt.AlignVCenter)
        ctx_row.addWidget(self._ctx_filename, alignment=Qt.AlignVCenter)
        ctx_row.addWidget(self._ctx_meta, alignment=Qt.AlignVCenter)

        # Right stretch to keep content centred
        ctx_row.addStretch()
        root.addWidget(self._ctx_bar)

        # Body (rebuilt on showEvent)
        self._body = QWidget()
        self._body.setStyleSheet("background:transparent;")
        self._body_layout = QHBoxLayout(self._body)
        self._body_layout.setContentsMargins(28, 10, 28, 10)
        self._body_layout.setSpacing(16)
        root.addWidget(self._body, stretch=1)

        # Export status bar (survives body rebuild)
        self._export_lbl = QLabel("")
        self._export_lbl.setFont(QFont("Segoe UI", 10))
        self._export_lbl.setAlignment(Qt.AlignCenter)
        self._export_lbl.setFixedHeight(20)
        self._export_lbl.setStyleSheet(
            "color:#34d399;background:transparent;border:none;"
        )
        root.addWidget(self._export_lbl)

    # ─────────────────────────────────────────────────────────────────────────
    # Rebuild
    # ─────────────────────────────────────────────────────────────────────────

    def _rebuild(self):
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                _clear_layout(item.layout())

        sess = AppState.current
        ml   = sess.ml_result

        # ── Update context bar ────────────────────────────────────────────────
        fname = sess.dump_filename or "unknown dump"
        if len(fname) > 60:
            fname = fname[:57] + "…"
        self._ctx_filename.setText(fname)

        ts   = sess.created_at.strftime("%Y-%m-%d  %H:%M") if sess.created_at else "—"
        size = sess.dump_size_str
        arch = f"  ·  {sess.architecture}" if sess.architecture else ""
        self._ctx_meta.setText(f"    ·    {ts}    ·    {size}{arch}")

        verdict  = ml.get("verdict", "unknown")
        is_susp  = verdict == "suspicious"
        v_col    = "#f87171" if is_susp else "#34d399"
        b_col    = "#ef4444" if is_susp else "#10b981"
        icon_bg  = "rgba(239,68,68,0.18)"  if is_susp else "rgba(52,211,153,0.18)"
        icon_ch  = "⚠"                     if is_susp else "✓"
        conf        = float(ml.get("confidence", 0))
        rf          = float(ml.get("rf_score",    conf))
        ae          = float(ml.get("ae_score",    conf))
        findings = sess.findings or []

        self._body_layout.addLayout(
            self._left_col(sess, verdict, is_susp, v_col, b_col,
                           icon_bg, icon_ch, conf, rf, ae),
            stretch=1,
        )
        self._body_layout.addLayout(
            self._right_col(findings),
            stretch=1,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Left column
    # ─────────────────────────────────────────────────────────────────────────

    def _left_col(self, sess, verdict, is_susp, v_col, b_col,
                  icon_bg, icon_ch, conf, rf, ae):
        col = QVBoxLayout()
        col.setSpacing(12)

        # 1. Verdict card
        vc = _bordered_card(b_col)
        vc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        vc_vb = QVBoxLayout(vc)
        vc_vb.setContentsMargins(16, 14, 16, 14)
        vc_vb.setSpacing(0)
        vc_vb.setAlignment(Qt.AlignCenter)

        ic_outer = QLabel(icon_ch)
        ic_outer.setFixedSize(34, 34)
        ic_outer.setAlignment(Qt.AlignCenter)
        ic_outer.setStyleSheet(
            f"background:{icon_bg};"
            f"border-radius:17px;"
            f"color:{v_col};"
            f"border:none;"
            f"font-size:14px;"
            f"padding-bottom:2px;"
        )
        vc_vb.addWidget(ic_outer, alignment=Qt.AlignCenter)
        vc_vb.addSpacing(8)

        v_lbl = QLabel(verdict.upper())
        v_lbl.setAlignment(Qt.AlignCenter)
        v_lbl.setStyleSheet(
            f"color:{v_col};background:transparent;border:none;"
            f"font-size:18px;font-weight:700;"
        )
        vc_vb.addWidget(v_lbl)

        desc = ("Potential malicious activity detected in memory dump"
                if is_susp else "No significant threats detected in memory dump")
        desc_lbl = QLabel(desc)
        desc_lbl.setWordWrap(True)
        desc_lbl.setAlignment(Qt.AlignCenter)
        desc_lbl.setStyleSheet(
            "color:#94a3b8;background:transparent;border:none;font-size:10px;"
        )
        vc_vb.addWidget(desc_lbl)

        conf_row = QHBoxLayout()
        conf_row.setAlignment(Qt.AlignCenter)
        conf_row.setSpacing(5)
        # FIX: Explicitly label this as Confidence!
        conf_lbl = QLabel("Hybrid Score:")
        conf_lbl.setStyleSheet(
            "color:#94a3b8;background:transparent;border:none;font-size:11px;"
        )
        conf_row.addWidget(conf_lbl)
        _disp_conf = conf * 100.0 if conf <= 1.0 else conf
        c_val = QLabel(f"{_disp_conf:.2f}%")
        c_val.setStyleSheet(
            f"color:{v_col};background:transparent;border:none;"
            f"font-size:14px;font-weight:700;"
        )
        conf_row.addWidget(c_val)
        vc_vb.addLayout(conf_row)

        col.addWidget(vc)

        # 2. ML Breakdown
        ml_card = _card()
        ml_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        ml_vb = QVBoxLayout(ml_card)
        ml_vb.setContentsMargins(14, 10, 14, 10)
        ml_vb.setSpacing(6)

        mh = QHBoxLayout()
        mh.addWidget(_lbl("🧠  Feature Fusion Analysis  (AE → RF)", 11, True, "#ffffff"))
        mh.addStretch()
        avail = MLBridge.models_available()
        real  = (avail.get("import_ok") and avail.get("random_forest")
                 and avail.get("autoencoder") and avail.get("feature_mapper"))
        mh.addWidget(_lbl("Real models" if real else "Mock mode", 9,
                          color="#34d399" if real else "#94a3b8"))
        ml_vb.addLayout(mh)

        # Show AE Error explicitly
        rec_err = sess.ml_result.get("reconstruction_error", 0.0)
        err_row = QHBoxLayout()
        err_lbl = QLabel("1. Autoencoder MSE:")
        err_lbl.setStyleSheet("color:#94a3b8;background:transparent;border:none;font-size:11px;")
        err_val = QLabel(f"{rec_err:.6f}")
        err_val.setStyleSheet("color:#ffffff;background:transparent;border:none;font-size:11px;font-weight:600;")
        err_row.addWidget(err_lbl)
        err_row.addStretch()
        err_row.addWidget(err_val)
        ml_vb.addLayout(err_row)

        # FIX: Show the raw RF Suspicion Score explicitly!
        disp_rf = rf * 100.0 if rf <= 1.0 else rf
        rf_row = QHBoxLayout()
        rf_lbl = QLabel("2. RF Suspicion Score:")
        rf_lbl.setStyleSheet("color:#94a3b8;background:transparent;border:none;font-size:11px;")
        rf_val = QLabel(f"{disp_rf:.2f}%")
        rf_val.setStyleSheet("color:#ffffff;background:transparent;border:none;font-size:11px;font-weight:600;")
        rf_row.addWidget(rf_lbl)
        rf_row.addStretch()
        rf_row.addWidget(rf_val)
        ml_vb.addLayout(rf_row)

        ml_vb.addWidget(_hdiv())

        disp_conf = conf * 100.0 if conf <= 1.0 else conf
        fr = QHBoxLayout()
        # FIX: Rename to Final Confidence
        final_lbl = QLabel("Final Hybrid Score:")
        final_lbl.setStyleSheet("color:#ffffff;background:transparent;border:none;font-size:11px;font-weight:700;")
        fv = QLabel(f"{disp_conf:.2f}%")
        fv.setStyleSheet(f"color:{v_col};background:transparent;border:none;font-size:12px;font-weight:700;")
        fr.addWidget(final_lbl)
        fr.addStretch()
        fr.addWidget(fv)
        ml_vb.addLayout(fr)

        formula_lbl = QLabel("Logic: RF-AE uses 54 canonical CIC-MalMem features + Autoencoder MSE (55 fused RF inputs). Decision threshold: RF Suspicion >= 50.0% = SUSPICIOUS; below 50.0% = CLEAN.")
        formula_lbl.setStyleSheet("color:#64748b;background:transparent;border:none;font-size:9px;")
        formula_lbl.setWordWrap(True)
        ml_vb.addWidget(formula_lbl)
        col.addWidget(ml_card)

        # 3. Analysis Statistics
        sc = _card()
        sc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sv = QVBoxLayout(sc)
        sv.setContentsMargins(14, 10, 14, 10)
        sv.setSpacing(8)

        sv.addLayout(_hrow(_lbl("📈  Analysis Statistics", 11, True, "#ffffff")))

        flat      = _flat_procs(sess.processes)
        n_procs   = len(flat)
        n_threads = len(sess.threads)
        n_dlls    = len(sess.dlls)
        n_handles = len(sess.handles)

        raw_feature_count = len(sess.raw_features) if sess.raw_features else (
                            len(sess.feature_vector) if sess.feature_vector else 0)
        selected_modules = getattr(sess, "selected_modules", None) or Config.get(
            "analysis.default_modules", list(_DEFAULT_EXTRACTOR_MODULES)
        )
        designed_extractor_features = sum(
            _EXTRACTOR_FEATURE_COUNTS.get(str(module_key), 0)
            for module_key in selected_modules
        ) or sum(_EXTRACTOR_FEATURE_COUNTS.values())

        # FIX: parsers store "SUSPICIOUS" (uppercase); use case-insensitive compare.
        # Also count session.injections — InjectionDetector populates this separately
        # from pe_sections and is not double-counted here.
        def _is_susp(item: dict) -> bool:
            return str(item.get("status", "")).lower() == "suspicious"

        n_anom = (
            sum(1 for p in flat             if _is_susp(p)) +
            sum(1 for t in sess.threads     if _is_susp(t)) +
            sum(1 for d in sess.dlls        if _is_susp(d)) +
            sum(1 for h in sess.handles     if _is_susp(h)) +
            sum(1 for s in sess.pe_sections if _is_susp(s)) +
            len([i for i in (getattr(sess, "injections", None) or []) if i])
        )
        n_low_conf = sum(1 for p in flat if bool(p.get("low_confidence_candidate")))
        hist_mode = n_procs == 0 and bool(sess.dump_filename)

        # Keep the statistics area as a clean 2-column × 3-row layout.
        # Low-confidence process count is preserved as tooltip context on the
        # Anomalies card, not displayed as a separate seventh card.
        feature_tooltip = (
            f"Designed extractor features: {designed_extractor_features:,}\n"
            f"Runtime raw feature keys extracted: {raw_feature_count:,}\n"
            "Final RF-AE ML input: 55 fused features "
            "(54 CIC-MalMem canonical features + Autoencoder MSE)."
        )

        stats_data = [
            ("Processes", "—" if hist_mode else f"{n_procs:,}",   "#ffffff", ""),
            ("Threads",   "—" if hist_mode else f"{n_threads:,}", "#ffffff", ""),
            ("DLLs",      "—" if hist_mode else f"{n_dlls:,}",    "#ffffff", ""),
            ("Handles",   "—" if hist_mode else f"{n_handles:,}", "#ffffff", ""),
            ("Anomalies", "—" if hist_mode else f"{n_anom:,}",
             "#f87171" if n_anom > 0 else "#ffffff", ""),
            ("Extractor Features",
             "—" if hist_mode else f"{designed_extractor_features:,}",
             "#06b6d4",
             feature_tooltip),
        ]

        grid = QGridLayout()
        grid.setSpacing(4)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        for i, (k, v, vc, tooltip) in enumerate(stats_data):
            cell = QFrame()
            cell.setStyleSheet(
                "QFrame{background:rgba(51,65,85,0.22);border-radius:6px;border:none;}"
            )
            cell.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            cv = QVBoxLayout(cell)
            cv.setContentsMargins(6, 4, 6, 4)
            cv.setSpacing(1)

            if tooltip and not hist_mode:
                cell.setToolTip(tooltip)

            if k == "Anomalies" and n_low_conf > 0 and not hist_mode:
                cell.setToolTip(
                    f"{n_low_conf:,} low-confidence/stale process candidate(s) "
                    "were preserved for advanced review. They are not shown as "
                    "a separate statistics card and should be corroborated before "
                    "treating them as confirmed malicious."
                )

            lk = QLabel(k)
            lk.setStyleSheet("color:#94a3b8;background:transparent;border:none;font-size:8px;")
            cv.addWidget(lk)

            vl = QLabel(v)
            vl.setStyleSheet(f"color:{vc};background:transparent;border:none;font-size:10px;font-weight:700;")
            cv.addWidget(vl)

            grid.addWidget(cell, i // 2, i % 2)

        sv.addLayout(grid)

        if hist_mode:
            sv.addWidget(
                _lbl("⚠  Artifact detail unavailable — session was not saved after analysis.",
                     9, color="#64748b", wrap=True)
            )

        col.addWidget(sc)
        col.addStretch()
        return col

    # ─────────────────────────────────────────────────────────────────────────
    # Right column
    # ─────────────────────────────────────────────────────────────────────────

    def _right_col(self, findings: list):
        col = QVBoxLayout()
        col.setSpacing(8)
        col.setContentsMargins(0, 0, 0, 0)

        fc = _card()
        fc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        fc_vb = QVBoxLayout(fc)
        fc_vb.setContentsMargins(0, 0, 0, 0)
        fc_vb.setSpacing(0)

        fhdr = QFrame()
        fhdr.setFixedHeight(46)
        fhdr.setStyleSheet(
            "QFrame{background:transparent;border:none;"
            "border-bottom:1px solid rgba(51,65,85,0.4);border-radius:0px;}"
        )
        fh = QHBoxLayout(fhdr)
        fh.setContentsMargins(16, 0, 16, 0)
        fh.addWidget(_lbl("⚠  Key Findings & Alerts", 12, True, "#ffffff"))
        fh.addStretch()

        fc_vb.addWidget(fhdr)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        scroll.setMinimumHeight(0)
        scroll.setStyleSheet("QScrollArea{background:transparent;border:none;}")
        sw = QWidget()
        sw.setStyleSheet("background:transparent;")
        sw.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sw_vb = QVBoxLayout(sw)
        sw_vb.setContentsMargins(12, 10, 12, 10)
        sw_vb.setSpacing(8)

        if findings:
            for f in _sort_findings_by_severity(findings):
                sw_vb.addWidget(_finding_widget(f))
        else:
            sw_vb.addStretch()
            sw_vb.addWidget(
                _lbl("✓  No anomalies detected", 13, True, "#34d399",
                     align=Qt.AlignCenter)
            )
            sw_vb.addWidget(
                _lbl("Memory dump appears clean.", 11, color="#64748b",
                     align=Qt.AlignCenter)
            )
            sw_vb.addStretch()

        scroll.setWidget(sw)
        fc_vb.addWidget(scroll, stretch=1)

        nav = QFrame()
        nav.setStyleSheet(
            "QFrame{background:transparent;border:none;"
            "border-top:1px solid rgba(51,65,85,0.4);border-radius:0px;}"
        )
        nav_row = QHBoxLayout(nav)
        nav_row.setContentsMargins(12, 6, 12, 6)
        nav_row.setSpacing(8)
        nav_row.addWidget(_nav_btn("🔍 Process Explorer", "process_explorer", self.mw))
        nav_row.addWidget(_nav_btn("👁 Detailed Artifacts", "artifacts_viewer", self.mw))
        fc_vb.addWidget(nav)

        col.addWidget(fc, stretch=2)

        qa = _card()
        qa.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        qa.setFixedHeight(170)
        qa_vb = QVBoxLayout(qa)
        qa_vb.setContentsMargins(14, 8, 14, 8)
        qa_vb.setSpacing(5)
        qa_vb.addWidget(_lbl("📄  Quick Actions", 12, True, "#ffffff"))

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        ml_btn = QPushButton("🧠  View ML Insights")
        ml_btn.setObjectName("iconBtn")
        ml_btn.setFont(QFont("Segoe UI", 11))
        ml_btn.setFixedHeight(38)
        ml_btn.clicked.connect(lambda: self.mw.navigate_to("ml_insights"))
        btn_row.addWidget(ml_btn)

        rep_btn = QPushButton("📋  Generate Reports")
        rep_btn.setObjectName("iconBtn")
        rep_btn.setFont(QFont("Segoe UI", 11))
        rep_btn.setFixedHeight(38)
        rep_btn.clicked.connect(lambda: self.mw.navigate_to("reports"))
        btn_row.addWidget(rep_btn)

        qa_vb.addLayout(btn_row)

        qa_vb.addWidget(_hdiv())
        qa_vb.addWidget(_lbl("Export Formats", 9, color="#64748b"))

        fmt_row = QHBoxLayout()
        fmt_row.setSpacing(8)
        for fmt_name, icon_ch in [("JSON", "{}"), ("CSV", "⊞"), ("PDF", "📋")]:
            fb = QFrame()
            fb.setStyleSheet(
                "QFrame{background:rgba(51,65,85,0.30);"
                "border:1px solid rgba(51,65,85,0.5);border-radius:8px;}"
                "QFrame:hover{background:rgba(6,182,212,0.08);"
                "border:1px solid rgba(6,182,212,0.35);}"
            )
            fb.setCursor(Qt.PointingHandCursor)
            fb_vb = QVBoxLayout(fb)
            fb_vb.setContentsMargins(8, 8, 8, 8)
            fb_vb.setAlignment(Qt.AlignCenter)
            fb_vb.setSpacing(2)
            ic = QLabel(icon_ch)
            ic.setFont(QFont("Segoe UI", 14))
            ic.setAlignment(Qt.AlignCenter)
            ic.setStyleSheet("background:transparent;color:#06b6d4;border:none;")
            fb_vb.addWidget(ic)
            fl = QLabel(fmt_name)
            fl.setFont(QFont("Segoe UI", 11, QFont.Bold))
            fl.setAlignment(Qt.AlignCenter)
            fl.setStyleSheet("background:transparent;color:#ffffff;border:none;")
            fb_vb.addWidget(fl)
            fb.mousePressEvent = lambda e, f=fmt_name.lower(): self._quick_export(f)
            fmt_row.addWidget(fb)
            
        qa_vb.addLayout(fmt_row)
        col.addWidget(qa, stretch=0)
        return col

    # ─────────────────────────────────────────────────────────────────────────
    # Quick export
    # ─────────────────────────────────────────────────────────────────────────

    def _quick_export(self, fmt: str):
        self._export_lbl.setStyleSheet("color:#06b6d4;background:transparent;border:none;")
        self._export_lbl.setText(f"Generating {fmt.upper()}…")

        try:
            result = ReportBridge.generate(AppState.current, fmt)

            if result["success"]:
                self._export_lbl.setText("")

                msg = f"{result['filename']}  ({result['size_str']})"
                toast = _ExportToast(self, msg, success=True)
                toast.show_centered(self)

                self._audit_quick_export(fmt, result)

                try:
                    file_path = result["path"]
                    if os.path.isfile(file_path):
                        if platform.system() == "Windows":
                            os.startfile(file_path)
                        elif platform.system() == "Darwin":
                            subprocess.Popen(["open", file_path])
                        else:
                            subprocess.Popen(["xdg-open", file_path])
                except Exception:
                    pass

            else:
                self._export_lbl.setStyleSheet(
                    "color:#f87171;background:transparent;border:none;"
                )
                self._export_lbl.setText(f"✗  {result['error']}")
                toast = _ExportToast(self, result["error"], success=False)
                toast.show_centered(self)

        except Exception as exc:
            self._export_lbl.setStyleSheet(
                "color:#f87171;background:transparent;border:none;"
            )
            self._export_lbl.setText(f"✗  {exc}")
            toast = _ExportToast(self, str(exc), success=False)
            toast.show_centered(self)


    def _audit_quick_export(self, fmt: str, result: dict) -> None:
        """Register Results Dashboard quick-export actions in Activity Monitor.

        This keeps the Quick Actions export tiles consistent with ReportsPage
        generation and Activity Monitor workbook export. It does not affect ML,
        parser output, FeatureMapper, AE fusion, or the RF threshold.
        """
        try:
            path = str(result.get("path") or "")
            if not path:
                return

            session = AppState.current
            verdict = None
            try:
                verdict = str((session.ml_result or {}).get("verdict") or "").upper() or None
            except Exception:
                verdict = None

            fmt_l = str(fmt or "").lower()
            from ramdetect.case_management.activity_logger import ActivityLogger
            al = ActivityLogger.instance()

            if fmt_l == "pdf" and hasattr(al, "log_pdf_exported"):
                al.log_pdf_exported(path, verdict=verdict)
            elif fmt_l == "json" and hasattr(al, "log_json_exported"):
                al.log_json_exported(path, verdict=verdict)
            elif fmt_l == "csv" and hasattr(al, "log_csv_exported"):
                al.log_csv_exported(path, export_mode="results_dashboard_quick_export", verdict=verdict)
            else:
                action = f"{fmt_l.upper()}_EXPORTED" if fmt_l else "REPORT_GENERATED"
                al.log(
                    action,
                    file_path=path,
                    file_name=os.path.basename(path),
                    report_path=path,
                    verdict=verdict,
                    details={
                        "source": "results_dashboard_quick_export",
                        "format": fmt_l,
                        "dump": getattr(session, "dump_filename", "") or "",
                    },
                )
        except Exception:
            # Audit logging must never interrupt report export or file opening.
            pass

    def showEvent(self, event):
        super().showEvent(event)
        self._rebuild()


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def _flat_procs(procs: list) -> list:
    flat = []
    for p in procs:
        flat.append(p)
        flat.extend(_flat_procs(p.get("children", [])))
    return flat


def _clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()


def _hrow(*widgets) -> QHBoxLayout:
    row = QHBoxLayout()
    for w in widgets:
        row.addWidget(w)
    return row


def _sort_findings_by_severity(findings: list) -> list:
    """Return findings in examiner-friendly severity order: HIGH → MEDIUM → LOW → INFO.

    Stable ordering is preserved within the same severity level. Missing or unknown
    severities are placed after LOW/INFO rather than appearing above higher-risk items.
    """
    order = {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 3, "informational": 3}

    def key(item):
        if not isinstance(item, dict):
            return 9
        return order.get(str(item.get("severity", "low")).strip().lower(), 8)

    return sorted(findings or [], key=key)


def _finding_widget(f: dict) -> QFrame:
    from PyQt5.QtWidgets import QSizePolicy as QSP
    sev = f.get("severity", "low")
    bc, bg = _SEV.get(sev, ("#94a3b8", "transparent"))
    _PILL_BG = {
        "high":   "rgba(239,68,68,0.30)",
        "medium": "rgba(250,204,21,0.28)",
        "low":    "rgba(59,130,246,0.28)",
    }
    pill_bg = _PILL_BG.get(sev, "rgba(148,163,184,0.2)")

    item = QFrame()
    item.setStyleSheet(
        f"QFrame{{background:{bg};border-left:4px solid {bc};"
        f"border-radius:6px;}}"
    )
    item.setSizePolicy(QSP.Expanding, QSP.Fixed)

    outer = QVBoxLayout(item)
    outer.setContentsMargins(8, 5, 10, 5)
    outer.setSpacing(3)

    top = QHBoxLayout()
    top.setSpacing(5)
    top.setContentsMargins(0, 0, 0, 0)

    ic = QLabel("⚠")
    ic.setFixedSize(18, 18)
    ic.setAlignment(Qt.AlignCenter)
    ic.setStyleSheet(
        f"background:rgba(0,0,0,0.22);border-radius:9px;"
        f"color:{bc};border:none;font-size:8px;"
    )
    top.addWidget(ic)

    pill = QLabel(sev.upper())
    pill.setSizePolicy(QSP.Fixed, QSP.Fixed)
    pill.setFixedHeight(15)
    pill.setStyleSheet(
        f"background:{pill_bg};color:{bc};border:none;"
        f"border-radius:7px;padding:0px 6px;"
        f"font-size:8px;font-weight:700;"
    )
    top.addWidget(pill)

    cat = QLabel(f.get("category", ""))
    cat.setStyleSheet(
        "color:#94a3b8;background:transparent;border:none;font-size:9px;"
    )
    top.addWidget(cat)
    top.addStretch()
    outer.addLayout(top)

    desc = QLabel(f.get("description", ""))
    desc.setWordWrap(True)
    desc.setStyleSheet(
        "color:#cbd5e1;background:transparent;border:none;font-size:10px;"
    )
    outer.addWidget(desc)

    return item
"""
Analysis Configuration — Page 3
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QPushButton, QGridLayout, QSizePolicy, QSpacerItem,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont

from ui.widgets.header_bar      import HeaderBar
from ui.widgets.progress_stepper import ProgressStepper
from ui.bridge.session           import AppState
from ui.bridge.config_bridge     import Config
from ui.bridge.ml_bridge         import MLBridge
from ui.style_helpers import set_role, set_tone, set_state, set_variant, refresh_style


# ─────────────────────────────────────────────────────────────────────────────
# Module definitions
# ─────────────────────────────────────────────────────────────────────────────
MODULES = [
    {
        "key":      "process",
        "icon":     "⚙",
        "title":    "Process Analysis",
        "features": 25,
        "desc":     "25 features - Hidden processes, orphans, parent-child anomalies",
    },
    {
        "key":      "thread",
        "icon":     "⏱",
        "title":    "Thread Analysis",
        "features": 15,
        "desc":     "15 features - Orphan threads, unusual start addresses, remote injections",
    },
    {
        "key":      "dll",
        "icon":     "🔗",
        "title":    "DLL Analysis",
        "features": 20,
        "desc":     "20 features - Unsigned DLLs, entropy analysis, suspicious paths",
    },
    {
        "key":      "handle",
        "icon":     "🛡",
        "title":    "Handle Analysis",
        "features": 12,
        "desc":     "12 features - Suspicious file/registry handles",
    },
    {
        "key":      "pe_section",
        "icon":     "📄",
        "title":    "PE Section Analysis",
        "features": 18,
        "desc":     "18 features - RWX permissions, entropy, size mismatches",
    },
    {
        "key":      "code_injection",
        "icon":     "💉",
        "title":    "Code Injection Detection",
        "features": 10,
        "desc":     "10 features - Reflective DLL, hollowing, APC injection",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Helper — plain QLabel, guaranteed border-free
# ─────────────────────────────────────────────────────────────────────────────

def _lbl(text: str, size: int = 11, bold: bool = False,
         color: str = "#ffffff") -> QLabel:
    w = QLabel(text)
    w.setFont(QFont("Segoe UI", size, QFont.Bold if bold else QFont.Normal))
    set_tone(w, color)
    return w


# ─────────────────────────────────────────────────────────────────────────────
# Module card
#
# Grid layout (3 columns):
#
#  col 0 (40 px fixed) | col 1 (stretch)                | col 2 (26 px fixed)
#  ────────────────────┼────────────────────────────────┼────────────────────
#  row 0  [icon_box]   | Title text (bold, white)        | [✓]  ← spans rows
#  row 1  (empty)      | desc text  (small, slate)       |      ← 0 and 1
#
# ─────────────────────────────────────────────────────────────────────────────

class _ModuleCard(QFrame):
    def __init__(self, meta: dict, parent=None):
        super().__init__(parent)
        self.key      = meta["key"]
        self.features = meta["features"]
        self.setFrameShape(QFrame.NoFrame)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setCursor(Qt.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setObjectName("moduleCard")
        self._selected = True

        # ── Grid layout
        #
        #  col 0 (40px) | col 1 (stretch)        | col 2 (26px)
        #  ─────────────┼───────────────────────┼─────────────
        #  row 0  icon  │  Title (bold)          │  [✓]  ← row 0 only, top-right
        #  row 1  ─     │  desc  (small, slate)  │  ─
        #
        # icon height (40px) ≈ title row height, so icon+title share row 0.
        # desc sits in row 1 under title, no icon beside it → clean alignment.
        # ─────────────────────────────────────────────────────────────────────
        gl = QGridLayout(self)
        gl.setContentsMargins(18, 14, 18, 14)
        gl.setHorizontalSpacing(12)
        gl.setVerticalSpacing(2)          # tight gap between title and desc
        gl.setColumnStretch(1, 1)
        # Row 0 height fixed to icon size so title aligns with icon centre
        gl.setRowMinimumHeight(0, 40)
        gl.setRowStretch(0, 0)
        gl.setRowStretch(1, 0)

        # ── Col 0, row 0: icon box ────────────────────────────────────────────
        self._icon_box = QWidget()
        self._icon_box.setObjectName("moduleIconBox")
        self._icon_box.setAttribute(Qt.WA_StyledBackground, True)
        self._icon_box.setFixedSize(40, 40)
        self._icon_box.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        ib_lay = QHBoxLayout(self._icon_box)
        ib_lay.setContentsMargins(0, 0, 0, 0)
        self._icon_lbl = QLabel(meta["icon"])
        self._icon_lbl.setFont(QFont("Segoe UI Emoji", 16))
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        ib_lay.addWidget(self._icon_lbl)
        gl.addWidget(self._icon_box, 0, 0, Qt.AlignLeft | Qt.AlignVCenter)

        # ── Col 1, row 0: title — vertically centred inside the 40 px row ────
        self._title_lbl = QLabel(meta["title"])
        self._title_lbl.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        self._title_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        gl.addWidget(self._title_lbl, 0, 1, Qt.AlignLeft | Qt.AlignVCenter)

        # ── Col 1, row 1: desc — single line, never wraps, never scrolls ─────
        self._desc_lbl = QLabel(meta["desc"])
        self._desc_lbl.setFont(QFont("Segoe UI", 10))
        self._desc_lbl.setWordWrap(False)
        self._desc_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        gl.addWidget(self._desc_lbl, 1, 1, Qt.AlignLeft | Qt.AlignTop)

        # ── Col 2, row 0 only: checkmark, anchored top-right ─────────────────
        self._check_lbl = QLabel("✓")
        self._check_lbl.setObjectName("moduleCheck")
        self._check_lbl.setFixedSize(26, 26)
        self._check_lbl.setAlignment(Qt.AlignCenter)
        self._check_lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        gl.addWidget(self._check_lbl, 0, 2, Qt.AlignTop | Qt.AlignRight)

        self._apply()

    # ── Visual state — every child widget styled individually (no cascade) ────
    def _apply(self):
        state = "selected" if self._selected else "idle"
        set_state(self, state)
        set_state(self._icon_box, state)
        set_state(self._check_lbl, state)
        set_tone(self._icon_lbl, "#06b6d4" if self._selected else "#475569")
        set_tone(self._title_lbl, "#ffffff" if self._selected else "#94a3b8")
        set_tone(self._desc_lbl, "#64748b" if self._selected else "#475569")
        self._check_lbl.setVisible(self._selected)

    def toggle(self):
        self._selected = not self._selected
        self._apply()
        return self._selected

    def set_selected(self, v: bool):
        self._selected = v
        self._apply()

    def is_selected(self) -> bool:
        return self._selected

    def mousePressEvent(self, e):
        self.toggle()
        super().mousePressEvent(e)
        p = self.parent()
        while p and not hasattr(p, "_refresh_summary"):
            p = p.parent()
        if p:
            p._refresh_summary()


# ─────────────────────────────────────────────────────────────────────────────
# Analysis Config Page
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisConfigPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.setObjectName("AnalysisConfigPage")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.mw = main_window
        set_role(self, "transparent")
        self._module_cards: list[_ModuleCard] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        hdr = HeaderBar(show_action=False, show_dashboard=True)
        hdr.dashboard_clicked.connect(lambda: self.mw.navigate_to("dashboard"))
        hdr.settings_clicked.connect(lambda: self.mw.navigate_to("settings"))
        root.addWidget(hdr)

        root.addWidget(ProgressStepper(current_step=2))

        body = QVBoxLayout()
        body.setContentsMargins(40, 20, 40, 20)
        body.setSpacing(14)

        # Model warning banner (hidden until models missing)
        self._model_warn = self._build_model_warning()
        body.addWidget(self._model_warn)

        # Main modules card
        body.addWidget(self._build_modules_card(), stretch=1)

        # Bottom summary + action bar
        body.addWidget(self._build_summary_bar())

        root.addLayout(body, stretch=1)

    # ─────────────────────────────────────────────────────────────────────────
    # Model warning banner
    # ─────────────────────────────────────────────────────────────────────────

    def _build_model_warning(self) -> QWidget:
        # QWidget (not QFrame) — stylesheet is scoped, nothing cascades down
        warn = QWidget()
        warn.setObjectName("warnBanner")
        warn.setAttribute(Qt.WA_StyledBackground, True)
        row = QHBoxLayout(warn)
        row.setContentsMargins(16, 10, 16, 10)
        row.setSpacing(10)
        row.addWidget(_lbl("⚠", 14, color="#facc15"))
        self._warn_text = _lbl(
            "Model files not found — analysis will run in mock mode. "
            "Place random_forest.pkl, autoencoder.pkl, feature_mapper.pkl in models/.",
            11, color="#fde68a"
        )
        self._warn_text.setWordWrap(True)
        row.addWidget(self._warn_text, stretch=1)
        warn.hide()
        return warn

    # ─────────────────────────────────────────────────────────────────────────
    # Modules card  (header row + 2-col grid)
    # ─────────────────────────────────────────────────────────────────────────

    def _build_modules_card(self) -> QWidget:
        # QWidget with objectName — border stays on this widget only
        card = QWidget()
        card.setObjectName("modulesCard")
        card.setAttribute(Qt.WA_StyledBackground, True)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        vb = QVBoxLayout(card)
        vb.setContentsMargins(24, 20, 24, 20)
        vb.setSpacing(16)

        # ── Header row: icon · title · stretch · Select All · Clear All ───────
        hdr_row = QHBoxLayout()
        hdr_row.setSpacing(8)
        hdr_row.addWidget(_lbl("⊞", 14, color="#06b6d4"))
        hdr_row.addWidget(_lbl("Feature Extraction Modules", 14, bold=True))
        hdr_row.addStretch()

        sel_all = QPushButton("Select All")
        sel_all.setFont(QFont("Segoe UI", 11))
        sel_all.setObjectName("linkBtn")
        sel_all.clicked.connect(self._select_all)
        hdr_row.addWidget(sel_all)

        clr_all = QPushButton("Clear All")
        clr_all.setFont(QFont("Segoe UI", 11))
        clr_all.setObjectName("linkBtn")
        set_tone(clr_all, "#64748b")
        clr_all.clicked.connect(self._clear_all)
        hdr_row.addWidget(clr_all)

        vb.addLayout(hdr_row)

        # ── 2-column grid of module cards ─────────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(12)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        for i, meta in enumerate(MODULES):
            mc = _ModuleCard(meta)
            self._module_cards.append(mc)
            grid.addWidget(mc, i // 2, i % 2)

        for r in range(3):
            grid.setRowStretch(r, 1)

        vb.addLayout(grid, stretch=1)
        return card

    # ─────────────────────────────────────────────────────────────────────────
    # Summary bar  (bottom strip: counts + ML model + Start button)
    # ─────────────────────────────────────────────────────────────────────────

    def _build_summary_bar(self) -> QWidget:
        """Bottom action panel.

        Redesigned from a thin compressed strip into a taller summary/action panel.
        The values are separated into compact cards so the ML model text and Start
        button no longer fight for horizontal space.
        """
        bar = QWidget()
        bar.setObjectName("summaryBar")
        bar.setAttribute(Qt.WA_StyledBackground, True)
        bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        bar.setFixedHeight(104)

        row = QHBoxLayout(bar)
        row.setContentsMargins(18, 12, 18, 12)
        row.setSpacing(12)

        def metric_card(title_text: str, value_widget: QLabel,
                        min_width: int = 135) -> QFrame:
            card = QFrame()
            card.setObjectName("summaryMetricCard")
            card.setFrameShape(QFrame.NoFrame)
            card.setAttribute(Qt.WA_StyledBackground, True)
            card.setFixedHeight(76)
            card.setMinimumWidth(min_width)
            card.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            vb = QVBoxLayout(card)
            vb.setContentsMargins(14, 9, 14, 9)
            vb.setSpacing(2)
            vb.addWidget(_lbl(title_text, 9, color="#94a3b8"))
            vb.addWidget(value_widget)
            return card

        # Modules Selected
        self._count_val = _lbl("6 / 6", 18, bold=True, color="#06b6d4")
        row.addWidget(metric_card("Modules Selected", self._count_val, 140))

        # Extractor feature count. This is intentionally labelled as extractor
        # features so it is not confused with the 55 fused RF input features.
        self._feat_val = _lbl("100", 18, bold=True, color="#06b6d4")
        row.addWidget(metric_card("Extractor Features", self._feat_val, 140))

        # ML pipeline card
        model_card = QFrame()
        model_card.setObjectName("summaryModelCard")
        model_card.setFrameShape(QFrame.NoFrame)
        model_card.setAttribute(Qt.WA_StyledBackground, True)
        model_card.setFixedHeight(76)
        model_card.setMinimumWidth(360)
        model_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        mv = QVBoxLayout(model_card)
        mv.setContentsMargins(14, 8, 14, 8)
        mv.setSpacing(3)
        mv.addWidget(_lbl("ML Pipeline", 9, color="#94a3b8"))

        ml_val = QHBoxLayout()
        ml_val.setSpacing(6)
        ml_val.setContentsMargins(0, 0, 0, 0)
        ml_val.addWidget(_lbl("🧠", 12))

        self._model_lbl = _lbl("Hybrid (RF + Autoencoder)", 11, bold=True, color="#a78bfa")
        self._model_lbl.setMinimumHeight(24)
        self._model_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._model_lbl.setToolTip(
            "Hybrid (RF + Autoencoder)\n"
            "Random Forest uses the fused feature vector, including Autoencoder MSE."
        )
        ml_val.addWidget(self._model_lbl, stretch=1)
        mv.addLayout(ml_val)

        pipeline_note = _lbl(
            "54 base features + AE MSE = 55 fused RF input · RF threshold 0.5",
            8,
            color="#64748b",
        )
        pipeline_note.setWordWrap(False)
        pipeline_note.setMinimumHeight(18)
        pipeline_note.setToolTip(
            "54 base features + AE MSE = 55 fused RF input\n"
            "RF decision threshold remains fixed at 0.5"
        )
        mv.addWidget(pipeline_note)
        row.addWidget(model_card, stretch=1)

        # Zero-selection warning
        self._zero_warn = _lbl("⚠  Select at least one module", 10, color="#f87171")
        self._zero_warn.setFixedWidth(220)
        self._zero_warn.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._zero_warn.setStyleSheet("background: transparent; border: none;")
        self._zero_warn.hide()
        row.addWidget(self._zero_warn, alignment=Qt.AlignVCenter)

        # Start Analysis button
        self.start_btn = QPushButton("▶  Start Analysis  ›")
        self.start_btn.setObjectName("primaryBtn")
        self.start_btn.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        self.start_btn.setFixedSize(230, 58)
        set_variant(self.start_btn, "primary")
        self.start_btn.clicked.connect(self._start_analysis)
        row.addWidget(self.start_btn)

        return bar

    # ─────────────────────────────────────────────────────────────────────────
    # State refresh
    # ─────────────────────────────────────────────────────────────────────────

    def _refresh_model_warning(self):
        avail = MLBridge.models_available()
        all_present = (avail["random_forest"] and
                       avail["autoencoder"]   and
                       avail["feature_mapper"])
        if not all_present:
            missing = [k for k in ("random_forest", "autoencoder", "feature_mapper")
                       if not avail[k]]
            self._warn_text.setText(
                f"Model file(s) not found: {', '.join(missing)}.pkl  — "
                "analysis will run in mock mode."
            )
            self._model_warn.show()
            self._model_lbl.setText("Hybrid  (mock mode)")
            set_tone(self._model_lbl, "#94a3b8")
        else:
            self._model_warn.hide()
            self._model_lbl.setText("Hybrid (RF + Autoencoder)")
            set_tone(self._model_lbl, "#a78bfa")

    def _refresh_module_selection(self):
        sess = AppState.current
        if sess.selected_modules:
            selected_keys = set(sess.selected_modules)
        else:
            selected_keys = set(Config.get("analysis.default_modules", [
                "process", "thread", "dll", "handle", "pe_section", "code_injection"
            ]))
        for card in self._module_cards:
            card.set_selected(card.key in selected_keys)
        self._refresh_summary()

    def _refresh_summary(self):
        n          = sum(1 for c in self._module_cards if c.is_selected())
        feat_total = sum(c.features for c in self._module_cards if c.is_selected())
        self._count_val.setText(f"{n} / 6")
        self._feat_val.setText(str(feat_total))
        enabled = n > 0
        self.start_btn.setEnabled(enabled)
        self._zero_warn.setVisible(not enabled)
        color = "#06b6d4" if enabled else "#f87171"
        set_tone(self._count_val, color)

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────

    def _select_all(self):
        for c in self._module_cards:
            c.set_selected(True)
        self._refresh_summary()

    def _clear_all(self):
        for c in self._module_cards:
            c.set_selected(False)
        self._refresh_summary()

    def _start_analysis(self):
        selected = [c.key for c in self._module_cards if c.is_selected()]
        AppState.current.selected_modules = selected
        Config.set("analysis.default_modules", selected)
        self.mw.navigate_to("realtime_analysis")

    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_model_warning()
        self._refresh_module_selection()


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helper — vertical divider (QWidget, zero border cascade)
# ─────────────────────────────────────────────────────────────────────────────

def _vdiv() -> QWidget:
    d = QWidget()
    d.setFixedSize(1, 38)
    set_role(d, "vdiv")
    return d

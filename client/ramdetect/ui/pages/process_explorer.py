"""
Process Explorer — Page 6
──────────────────────────
Rebuilt to match the React wireframe:

Layout
  HeaderBar (with ← Results + Dashboard + Settings)
  Body (horizontal, 32px padding)
    Left  (flex=1) — card: sticky header + search bar + process table
    Right (w=360)  — Process Details card + Anomalies/Clean card

Tree
  QTreeWidget: Process Name | PID | PPID | Threads | Handles | Status
  Children indented via level-based QTreeWidgetItem nesting
  Status column: coloured pill text (⚠ SUSPICIOUS / ✓ CLEAN)
  HIDDEN tag shown inline with process name

Detail panel
  Process Details card:
    Name, PID/PPID 2-col grid, Threads/Handles 2-col grid,
    Path (monospace box), Status badge
  Anomalies card (fills remaining height):
    Left-border rows with bold TYPE + description text
  Clean card: centred checkmark when status = clean

showEvent → repopulates tree from AppState.current on every visit
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QSizePolicy,
)
from PyQt5.QtCore import Qt

from ui.widgets.header_bar       import HeaderBar
from ui.widgets.process_tree_widget import ProcessTreeWidget
from ui.bridge.session import AppState

try:
    from ramdetect.utils.process_confidence import confidence_label as _j10_conf_label, confidence_tooltip as _j10_conf_tooltip
except Exception:
    def _j10_conf_label(proc):
        return str(proc.get("process_confidence_label") or proc.get("process_confidence") or "Not assessed") if isinstance(proc, dict) else "Not assessed"
    def _j10_conf_tooltip(proc):
        return "Process confidence was not assessed for this session."


# ─────────────────────────────────────────────────────────────────────────────
# Palette
# ─────────────────────────────────────────────────────────────────────────────

_SUSP_COL  = "#f87171"
_SUSP_BG   = "rgba(248,113,113,0.15)"
_SUSP_BRD  = "rgba(248,113,113,0.35)"
_CLEAN_COL = "#34d399"
_CLEAN_BG  = "rgba(52,211,153,0.15)"
_CLEAN_BRD = "rgba(52,211,153,0.35)"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(border: str = "rgba(51,65,85,0.5)") -> QFrame:
    f = QFrame()
    f.setStyleSheet(
        f"QFrame{{background:rgba(30,41,59,0.45);"
        f"border:1px solid {border};border-radius:12px;}}"
    )
    return f


def _lbl(text: str, size: int = 12, bold: bool = False,
         color: str = "#94a3b8", wrap: bool = False,
         align=None) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(
        f"color:{color};background:transparent;border:none;"
        f"font-size:{size}px;font-weight:{'700' if bold else '400'};"
    )
    if wrap:
        l.setWordWrap(True)
    if align is not None:
        l.setAlignment(align)
    return l


def _hdiv() -> QFrame:
    d = QFrame()
    d.setFixedHeight(1)
    d.setStyleSheet("background:rgba(51,65,85,0.4);border:none;")
    return d


def _status_pill(status: str) -> QLabel:
    """Solid filled curved-rectangle badge — matches image 1 style."""
    is_susp = status == "suspicious"
    if is_susp:
        col = "#ffffff"
        bg  = "rgba(239,68,68,0.85)"
        brd = "rgba(239,68,68,1.0)"
        txt = "⚠  SUSPICIOUS"
    else:
        col = "#ffffff"
        bg  = "rgba(16,185,129,0.90)"
        brd = "rgba(16,185,129,1.0)"
        txt = "✓  CLEAN"
    lbl = QLabel(txt)
    lbl.setStyleSheet(
        f"color:{col};background:{bg};border:1.5px solid {brd};"
        f"border-radius:8px;padding:5px 16px;"          # curved rect, not pill
        f"font-size:12px;font-weight:700;"
    )
    lbl.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    return lbl


# ─────────────────────────────────────────────────────────────────────────────
# Process Explorer Page
# ─────────────────────────────────────────────────────────────────────────────

class ProcessExplorerPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.mw         = main_window
        self._susp_only = False
        self._processes = []
        self.setStyleSheet("background:transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        hdr = HeaderBar(show_action=False, show_dashboard=True, show_results=True)
        hdr.dashboard_clicked.connect(lambda: self.mw.navigate_to("dashboard"))
        hdr.settings_clicked.connect(lambda: self.mw.navigate_to("settings"))
        hdr.results_clicked.connect(lambda: self.mw.navigate_to("results"))
        root.addWidget(hdr)

        # Body
        body = QHBoxLayout()
        body.setContentsMargins(30, 20, 30, 20)
        body.setSpacing(20)

        # Left (stretch=3): ProcessTreeWidget in a card
        # The card provides the border + background; the widget handles
        # its own internal layout (header bar + tree).
        # We apply top-rounded corners on the header bar and bottom-rounded
        # corners on the tree via the widget's own QSS, so the card edge
        # is always covered by a rounded child — no jagged line visible.
        tree_card = QFrame()
        tree_card.setStyleSheet(
            "QFrame{"
            "  background:rgba(30,41,59,0.45);"
            "  border:1px solid rgba(51,65,85,0.5);"
            "  border-radius:12px;"
            "}"
        )
        tc_vb = QVBoxLayout(tree_card)
        tc_vb.setContentsMargins(0, 0, 0, 0)
        tc_vb.setSpacing(0)
        self._proc_tree = ProcessTreeWidget()
        self._proc_tree.process_selected.connect(self._on_process_selected)
        tc_vb.addWidget(self._proc_tree)
        body.addWidget(tree_card, stretch=4)

        # Right (stretch=2): persistent details panel
        # Plain transparent container — inner cards carry their own borders
        self._details_panel = QFrame()
        self._details_panel.setStyleSheet("QFrame{background:transparent;border:none;}")
        self._details_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._details_layout = QVBoxLayout(self._details_panel)
        self._details_layout.setContentsMargins(0, 0, 0, 0)
        self._details_layout.setSpacing(10)
        self._show_no_selection()
        body.addWidget(self._details_panel, stretch=2)

        root.addLayout(body, stretch=1)

    # ─────────────────────────────────────────────────────────────────────────
    # Left — Process tree card
    # ─────────────────────────────────────────────────────────────────────────

    def _reload(self):
        raw = AppState.current.processes or []
        # normalize() converts image_name→name, SUSPICIOUS→suspicious,
        # and builds the nested children tree from the flat extraction list
        normalised = ProcessTreeWidget.normalize(raw)

        # ── Build per-PID thread counts from AppState.current.threads ─────────
        # Thread dicts may use 'pid', 'PID', or 'UniqueProcessId' as the key.
        thread_counts: dict = {}
        for t in (AppState.current.threads or []):
            raw_pid = (t.get("pid") or t.get("PID")
                       or t.get("UniqueProcessId"))
            if raw_pid is not None:
                try:
                    thread_counts[int(raw_pid)] = (
                        thread_counts.get(int(raw_pid), 0) + 1
                    )
                except (ValueError, TypeError):
                    pass

        # ── Build per-PID handle counts from AppState.current.handles ─────────
        # Handle dicts may use 'pid', 'PID', or 'UniqueProcessId'.
        handle_counts: dict = {}
        for h in (AppState.current.handles or []):
            raw_pid = (h.get("pid") or h.get("PID")
                       or h.get("UniqueProcessId"))
            if raw_pid is not None:
                try:
                    handle_counts[int(raw_pid)] = (
                        handle_counts.get(int(raw_pid), 0) + 1
                    )
                except (ValueError, TypeError):
                    pass

        # ── Inject counts into every node (recursive for nested children) ─────
        def _inject(nodes: list):
            for p in nodes:
                try:
                    pid_int = int(p.get("pid", -1))
                except (ValueError, TypeError):
                    pid_int = -1

                if pid_int >= 0:
                    # Only overwrite when the session actually has data,
                    # so mock / manually-set values are preserved when
                    # the artifact lists happen to be empty.
                    if thread_counts:
                        p["threads"] = thread_counts.get(
                            pid_int, p.get("threads", 0)
                        )
                    if handle_counts:
                        p["handles"] = handle_counts.get(
                            pid_int, p.get("handles", 0)
                        )

                _inject(p.get("children", []))

        _inject(normalised)
        self._proc_tree.load(normalised)

    def _on_process_selected(self, proc: dict):
        """Called by ProcessTreeWidget.process_selected signal."""
        self._update_details(proc)

    # ─────────────────────────────────────────────────────────────────────────
    # Detail panel builders  (match Python wireframe exactly)
    # ─────────────────────────────────────────────────────────────────────────

    def _clear_details(self):
        while self._details_layout.count():
            item = self._details_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _show_no_selection(self):
        self._clear_details()
        placeholder = QFrame()
        placeholder.setStyleSheet("QFrame{background:transparent;border:none;}")
        pl = QVBoxLayout(placeholder)
        pl.setAlignment(Qt.AlignCenter)
        pl.setSpacing(10)
        eye = QLabel("👁")
        eye.setAlignment(Qt.AlignCenter)
        eye.setStyleSheet("font-size:44px;background:transparent;border:none;color:#334155;")
        pl.addWidget(eye)
        pl.addWidget(_lbl("Select a process to view details", 12, color="#475569",
                          align=Qt.AlignCenter))
        self._details_layout.addWidget(placeholder, stretch=1)

    def _update_details(self, proc: dict):
        self._clear_details()
        is_susp = proc.get("status") == "suspicious"

        # No QScrollArea here: the right panel should stay visually fixed and
        # match the page height instead of showing its own scrollbar.  The two
        # detail cards are laid out directly; the lower status/anomaly card uses
        # stretch=1 to fill the remaining vertical space.
        self._details_layout.addWidget(self._build_info_card(proc), stretch=0)

        if is_susp:
            self._details_layout.addWidget(self._build_anomalies_card(proc), stretch=1)
        else:
            self._details_layout.addWidget(self._build_clean_card(), stretch=1)

    def _build_info_card(self, proc: dict) -> QFrame:
        """Process Details card — label above value, matching wireframe."""
        is_susp = proc.get("status") == "suspicious"
        card = _card()
        iv = QVBoxLayout(card)
        iv.setContentsMargins(18, 14, 18, 14)
        iv.setSpacing(10)

        # Title
        iv.addWidget(_lbl("👁  Process Details", 13, True, "#06b6d4"))
        iv.addWidget(_hdiv())

        # Each field: small grey label above white value (wireframe style)
        def _field(label: str, value: str, mono: bool = False):
            fw = QFrame()
            fw.setStyleSheet("QFrame{background:transparent;border:none;}")
            fl = QVBoxLayout(fw)
            fl.setContentsMargins(0, 0, 0, 0)
            fl.setSpacing(2)
            fl.addWidget(_lbl(label, 8, color="#94a3b8"))
            val = QLabel(value)
            val.setWordWrap(True)
            val.setStyleSheet(
                "color:#e2e8f0;background:transparent;border:none;"
                + ("font-family:'Courier New';font-size:11px;"
                   if mono else "font-size:11px;")
            )
            fl.addWidget(val)
            return fw

        iv.addWidget(_field("Process Name", proc.get("name", "?")))

        # PID / PPID side by side
        pid_row = QHBoxLayout()
        pid_row.setSpacing(16)
        pid_row.addWidget(_field("PID",  str(proc.get("pid",  "")), mono=True))
        pid_row.addWidget(_field("PPID", str(proc.get("ppid", "")), mono=True))
        pid_row.addStretch()
        iv.addLayout(pid_row)

        # Threads / Handles side by side
        th_row = QHBoxLayout()
        th_row.setSpacing(16)
        th_row.addWidget(_field("Threads", str(proc.get("threads", 0))))
        th_row.addWidget(_field("Handles", str(proc.get("handles", 0))))
        th_row.addStretch()
        iv.addLayout(th_row)

        iv.addWidget(_field("Executable Path", proc.get("path", "—"), mono=True))

        # Status badge
        iv.addWidget(_lbl("Status", 8, color="#94a3b8"))
        badge = _status_pill(proc.get("status", "clean"))
        iv.addWidget(badge, alignment=Qt.AlignLeft)

        # Phase J10: process confidence is diagnostic/display-only. It helps
        # examiners separate strong process artifacts from stale EPROCESS
        # candidates without changing ML verdicts or parser output.
        conf_label = _j10_conf_label(proc)
        conf_value = QLabel(conf_label)
        conf_value.setWordWrap(True)
        conf_color = "#fbbf24" if "Low-confidence" in conf_label else ("#93c5fd" if "Medium" in conf_label else "#34d399")
        conf_value.setStyleSheet(
            f"color:{conf_color};background:rgba(51,65,85,0.20);"
            "border:1px solid rgba(51,65,85,0.45);border-radius:6px;"
            "padding:5px 8px;font-size:11px;font-weight:700;"
        )
        conf_value.setToolTip(_j10_conf_tooltip(proc))
        iv.addWidget(_lbl("Process Confidence", 8, color="#94a3b8"))
        iv.addWidget(conf_value)

        return card

    def _build_anomalies_card(self, proc: dict) -> QFrame:
        """Anomalies card matching wireframe — border-left rows with type+desc."""
        _DESCS = {
            "Hidden Process":        "Process not visible in standard process list",
            "Orphan Process":        "No valid parent process (PPID: 0)",
            "Suspicious Path":       "Located in unusual directory",
            "Code Injection":        "Reflective DLL injection detected",
            "Path Anomaly":          "System process running from unusual location",
            "Invalid/Swapped Dtb":   "Page directory base is invalid or swapped",
            "Missing Path (Possible Hollowing)": "Executable path missing — possible process hollowing",
        }

        card = QFrame()
        card.setStyleSheet(
            "QFrame{background:rgba(30,41,59,0.45);"
            "border:1px solid rgba(248,113,113,0.4);border-radius:12px;}"
        )
        cv = QVBoxLayout(card)
        cv.setContentsMargins(18, 14, 18, 14)
        cv.setSpacing(9)

        cv.addWidget(_lbl("⚠  Detected Anomalies", 13, True, "#f87171"))
        cv.addWidget(_hdiv())

        anomalies = proc.get("anomalies", [])
        if not anomalies:
            anomalies = [{"type": "Suspicious Indicators",
                          "detail": "Flagged by ML analysis."}]

        for an in anomalies:
            # Anomaly can be a dict {type, detail} or a plain string
            if isinstance(an, dict):
                atype  = an.get("type", "Unknown").title()
                detail = an.get("detail", "")
            else:
                atype  = str(an).title()
                detail = ""

            if not detail:
                detail = _DESCS.get(atype, "Anomalous behaviour detected.")

            af = QFrame()
            af.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            af.setStyleSheet(
                "QFrame{background:rgba(248,113,113,0.08);"
                "border-left:4px solid #ef4444;border-radius:6px;}"
            )
            afv = QVBoxLayout(af)
            afv.setContentsMargins(10, 6, 10, 6)
            afv.setSpacing(2)
            t = QLabel(atype.upper())
            t.setStyleSheet(
                "color:#f87171;background:transparent;border:none;"
                "font-size:11px;font-weight:700;"
            )
            d = QLabel(detail)
            d.setWordWrap(True)
            d.setStyleSheet(
                "color:#cbd5e1;background:transparent;border:none;font-size:11px;"
            )
            afv.addWidget(t)
            afv.addWidget(d)
            cv.addWidget(af)

        cv.addStretch()
        return card

    def _build_clean_card(self) -> QFrame:
        """Clean status card — matches image 1: title + divider + circular icon + text."""
        card = QFrame()
        card.setStyleSheet(
            "QFrame{background:rgba(30,41,59,0.45);"
            "border:1px solid rgba(52,211,153,0.4);border-radius:12px;}"
        )
        cv = QVBoxLayout(card)
        cv.setContentsMargins(18, 14, 18, 14)
        cv.setSpacing(0)

        # Title row
        cv.addWidget(_lbl("✓  Status", 13, True, "#34d399"))
        cv.addSpacing(10)
        cv.addWidget(_hdiv())
        cv.addStretch()

        # Circular checkmark icon (matches image 1's green circle)
        icon_wrap = QHBoxLayout()
        icon_wrap.setAlignment(Qt.AlignCenter)
        ck = QLabel("✓")
        ck.setFixedSize(64, 64)
        ck.setAlignment(Qt.AlignCenter)
        ck.setStyleSheet(
            "color:#34d399;"
            "background:rgba(52,211,153,0.15);"
            "border:2px solid rgba(52,211,153,0.5);"
            "border-radius:32px;"           # perfect circle
            "font-size:32px;"
            "font-weight:700;"
        )
        icon_wrap.addWidget(ck)
        cv.addLayout(icon_wrap)

        cv.addSpacing(9)
        cv.addWidget(_lbl("No anomalies detected", 13, bold=True,
                          color="#cbd5e1", align=Qt.AlignCenter))
        cv.addSpacing(4)
        cv.addWidget(_lbl("This process appears legitimate", 11,
                          color="#94a3b8", align=Qt.AlignCenter))
        cv.addStretch()
        return card

    # ─────────────────────────────────────────────────────────────────────────
    # showEvent
    # ─────────────────────────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        self._reload()
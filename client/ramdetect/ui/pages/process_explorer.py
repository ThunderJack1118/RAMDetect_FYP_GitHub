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
from PyQt5.QtCore import Qt, QEvent, QPoint, QTimer
from PyQt5.QtGui import QFont, QPainter, QPen, QBrush, QColor

from ui.widgets.header_bar       import HeaderBar
from ui.widgets.process_tree_widget import ProcessTreeWidget
from ui.bridge.session import AppState
from ui.style_helpers import set_role, set_tone
from ui.theme import current_theme

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
_SUSP_BG   = "rgba(248,113,113,38)"
_SUSP_BRD  = "rgba(248,113,113,89)"
_CLEAN_COL = "#34d399"
_CLEAN_BG  = "rgba(52,211,153,38)"
_CLEAN_BRD = "rgba(52,211,153,89)"


def _is_light() -> bool:
    return (current_theme() or "dark").lower() == "light"


def _pc() -> dict:
    if _is_light():
        return {
            "card": "#ffffff",
            "inner": "#f8fbff",
            "border": "#d9e6ff",
            "border2": "#c8d8f5",
            "text": "#1e3a6e",
            "text2": "#385f9f",
            "muted": "#6b82b4",
            "muted2": "#7b8fb8",
            "cyan": "#1a56db",
            "green": "#10b981",
            "red": "#dc2626",
            "green_bg": "#ecfdf5",
            "green_brd": "#86efac",
            "red_bg": "#fff1f2",
            "red_brd": "#fecaca",
            "soft": "#eef4ff",
            "hover": "#eef4ff",
        }
    return {
        "card": "rgba(30,41,59,115)",
        "inner": "rgba(15,23,42,140)",
        "border": "rgba(51,65,85,128)",
        "border2": "rgba(51,65,85,153)",
        "text": "#e2e8f0",
        "text2": "#cbd5e1",
        "muted": "#94a3b8",
        "muted2": "#64748b",
        "cyan": "#06b6d4",
        "green": "#34d399",
        "red": "#f87171",
        "green_bg": "rgba(52,211,153,38)",
        "green_brd": "rgba(52,211,153,89)",
        "red_bg": "rgba(248,113,113,38)",
        "red_brd": "rgba(248,113,113,89)",
        "soft": "rgba(148,163,184,26)",
        "hover": "rgba(51,65,85,71)",
    }


def _map_color(color: str) -> str:
    if not _is_light():
        return color
    return {
        "#ffffff": "#1e3a6e",
        "#f8fafc": "#1e3a6e",
        "#e2e8f0": "#1e3a6e",
        "#cbd5e1": "#385f9f",
        "#94a3b8": "#6b82b4",
        "#64748b": "#7b8fb8",
        "#475569": "#9aa8c3",
        "#334155": "#5873a8",
        "#06b6d4": "#1a56db",
        "#67e8f9": "#1a56db",
        "#34d399": "#10b981",
        "#22c55e": "#10b981",
        "#f87171": "#dc2626",
        "#ef4444": "#dc2626",
        "#fbbf24": "#d97706",
        "#93c5fd": "#1a56db",
    }.get(str(color).lower(), color)


class _ProcessHoverTipBox(QFrame):
    """Painted tooltip box with no QSS, matching Artifact Viewer tooltip style."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        if _is_light():
            bg, br = QColor("#ffffff"), QColor("#c8d8f5")
        else:
            bg, br = QColor("#1e293b"), QColor("#334155")
        painter.setBrush(QBrush(bg))
        painter.setPen(QPen(br, 1))
        painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 9, 9)


class _ProcessHoverTip(QWidget):
    """Compact RAMDetect-owned tooltip for Process Explorer widgets.

    Native QToolTip can inherit page/button styles on some Windows/PyQt builds,
    causing oversized coloured boxes and clipped bold text. This widget mirrors
    the Artifact Viewer tooltip design and leaves table/tree item data unchanged.
    """

    def __init__(self, parent=None):
        super().__init__(None, Qt.ToolTip | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._box = _ProcessHoverTipBox()
        outer.addWidget(self._box)

        lay = QVBoxLayout(self._box)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(0)

        self._label = QLabel("")
        self._label.setWordWrap(True)
        self._label.setFont(QFont("Segoe UI", 10))
        self._label.setTextFormat(Qt.PlainText)
        self._label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        lay.addWidget(self._label)
        self._apply_style()

    def _apply_style(self):
        fg = "#1e3a6e" if _is_light() else "#e2e8f0"
        self._box.update()
        self._label.setStyleSheet(
            f"color:{fg};background:transparent;border:none;font-size:10px;font-weight:400;"
        )

    def show_for(self, anchor, text: str):
        if anchor is None:
            return
        self._apply_style()
        text = " ".join(str(text or "").split())
        if not text:
            return
        self._label.setFixedWidth(460 if len(text) > 70 else 340)
        self._label.setText(text)
        self.adjustSize()

        pos = anchor.mapToGlobal(QPoint(0, anchor.height() + 7))
        x, y = pos.x(), pos.y()
        try:
            screen = anchor.screen().availableGeometry()
            x = min(max(screen.left() + 8, x), screen.right() - self.width() - 8)
            if y + self.height() > screen.bottom() - 8:
                y = anchor.mapToGlobal(QPoint(0, -self.height() - 7)).y()
        except Exception:
            pass
        self.move(x, y)
        self.show()
        self.raise_()

    def hide_tip(self):
        self.hide()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(border: str | None = None) -> QFrame:
    c = _pc()
    f = QFrame()
    f.setStyleSheet(
        f"QFrame{{background:{c['card']};"
        f"border:1px solid {border or c['border']};border-radius:12px;}}"
    )
    return f


def _lbl(text: str, size: int = 12, bold: bool = False,
         color: str = "#94a3b8", wrap: bool = False,
         align=None) -> QLabel:
    l = QLabel(text)
    color = _map_color(color)
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
    d.setStyleSheet(f"background:{_pc()['border']};border:none;")
    return d


def _status_pill(status: str) -> QLabel:
    """Theme-aware curved status badge."""
    is_susp = status == "suspicious"
    c = _pc()
    if is_susp:
        col, bg, brd, txt = c["red"], c["red_bg"], c["red_brd"], "⚠  SUSPICIOUS"
    else:
        col, bg, brd, txt = c["green"], c["green_bg"], c["green_brd"], "✓  CLEAN"
    lbl = QLabel(txt)
    lbl.setStyleSheet(
        f"color:{col};background:{bg};border:1.5px solid {brd};"
        "border-radius:8px;padding:5px 16px;font-size:12px;font-weight:800;"
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
        self._hover_tip = None
        set_role(self, "transparent")

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
        body.setContentsMargins(40, 20, 40, 20)
        body.setSpacing(20)

        # Left (stretch=3): ProcessTreeWidget in a card
        # The card provides the border + background; the widget handles
        # its own internal layout (header bar + tree).
        # We apply top-rounded corners on the header bar and bottom-rounded
        # corners on the tree via the widget's own QSS, so the card edge
        # is always covered by a rounded child — no jagged line visible.
        tree_card = QFrame()
        self._tree_card = tree_card
        tree_card.setStyleSheet(
            f"QFrame{{background:{_pc()['card']};border:1px solid {_pc()['border']};border-radius:12px;}}"
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

        # Convert existing native widget tooltips into the same compact
        # RAMDetect-owned tooltip design used by Artifact Viewer.
        QTimer.singleShot(0, self._proxy_native_tooltips)

    # ─────────────────────────────────────────────────────────────────────────
    # Compact tooltip proxy  (same behaviour as Artifact Viewer toolbar tips)
    # ─────────────────────────────────────────────────────────────────────────

    def eventFilter(self, obj, event):
        tip_text = ""
        try:
            tip_text = obj.property("ramdetectProcessTip") or ""
        except Exception:
            tip_text = ""
        if tip_text:
            if event.type() == QEvent.Enter:
                self._show_process_hover_tip(obj, tip_text)
            elif event.type() in (QEvent.Leave, QEvent.MouseButtonPress, QEvent.Hide):
                self._hide_process_hover_tip()
        return super().eventFilter(obj, event)

    def _register_hover_tip(self, widget, text: str):
        """Attach compact tooltip to a widget and suppress native QToolTip."""
        if widget is None:
            return
        text = str(text or "").strip()
        if not text:
            return
        try:
            widget.setToolTip("")
            widget.setProperty("ramdetectProcessTip", text)
            widget.installEventFilter(self)
        except Exception:
            pass

    def _proxy_native_tooltips(self):
        """Replace existing child-widget native tooltips with compact tips.

        This covers HeaderBar buttons, ProcessTreeWidget controls, search boxes,
        and any detail labels that already expose widget-level tooltip text.
        It does not touch backend data or tree item contents.
        """
        try:
            for widget in self.findChildren(QWidget):
                if widget is self or widget is getattr(self, "_hover_tip", None):
                    continue
                if isinstance(widget, _ProcessHoverTip) or isinstance(widget, _ProcessHoverTipBox):
                    continue
                if widget.property("ramdetectProcessTip"):
                    continue
                tip = str(widget.toolTip() or "").strip()
                if tip:
                    self._register_hover_tip(widget, tip)
        except Exception:
            pass

    def _show_process_hover_tip(self, widget, text: str):
        if self._hover_tip is None:
            self._hover_tip = _ProcessHoverTip(self)
        self._hover_tip.show_for(widget, text)

    def _hide_process_hover_tip(self):
        if self._hover_tip is not None:
            self._hover_tip.hide_tip()

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
        eye.setStyleSheet(f"font-size:44px;background:transparent;border:none;color:{_pc()['muted2']};")
        pl.addWidget(eye)
        pl.addWidget(_lbl("Select a process to view details", 12, color=_pc()["muted2"],
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
        QTimer.singleShot(0, self._proxy_native_tooltips)

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
                f"color:{_pc()['text']};background:transparent;border:none;"
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
        conf_color = _map_color("#fbbf24" if "Low-confidence" in conf_label else ("#93c5fd" if "Medium" in conf_label else "#34d399"))
        conf_value.setStyleSheet(
            f"color:{conf_color};background:{_pc()['soft']};"
            f"border:1px solid {_pc()['border']};border-radius:6px;"
            "padding:5px 8px;font-size:11px;font-weight:700;"
        )
        self._register_hover_tip(conf_value, _j10_conf_tooltip(proc))
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
            f"QFrame{{background:{_pc()['card']};border:1px solid {_pc()['red_brd']};border-radius:12px;}}"
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
                f"QFrame{{background:{_pc()['red_bg']};border-left:4px solid {_pc()['red']};border-radius:6px;}}"
            )
            afv = QVBoxLayout(af)
            afv.setContentsMargins(10, 6, 10, 6)
            afv.setSpacing(2)
            t = QLabel(atype.upper())
            t.setStyleSheet(
                f"color:{_pc()['red']};background:transparent;border:none;"
                "font-size:11px;font-weight:700;"
            )
            d = QLabel(detail)
            d.setWordWrap(True)
            d.setStyleSheet(
                f"color:{_pc()['text2']};background:transparent;border:none;font-size:11px;"
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
            f"QFrame{{background:{_pc()['card']};border:1px solid {_pc()['green_brd']};border-radius:12px;}}"
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
            f"color:{_pc()['green']};background:{_pc()['green_bg']};"
            f"border:2px solid {_pc()['green_brd']};border-radius:32px;"
            "font-size:32px;font-weight:700;"
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

    def apply_theme(self, theme: str | None = None) -> None:
        if hasattr(self, '_tree_card'):
            self._tree_card.setStyleSheet(
                f"QFrame{{background:{_pc()['card']};border:1px solid {_pc()['border']};border-radius:12px;}}"
            )
        if hasattr(self, '_proc_tree') and hasattr(self._proc_tree, 'apply_theme'):
            self._proc_tree.apply_theme(theme or current_theme())
        # Details cards use inline colours; rebuild them safely on theme switch.
        self._show_no_selection()
        QTimer.singleShot(0, self._proxy_native_tooltips)

    # ─────────────────────────────────────────────────────────────────────────
    # showEvent
    # ─────────────────────────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        self._reload()
        QTimer.singleShot(0, self._proxy_native_tooltips)

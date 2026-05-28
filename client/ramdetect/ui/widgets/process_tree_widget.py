"""
ProcessTreeWidget
─────────────────
Rebuilt to match the React wireframe exactly.

Layout (mirroring React JSX)
  ┌─ card outer ──────────────────────────────────────────────────────┐
  │  ┌─ header px-6 py-4 border-b ──────────────────────────────────┐ │
  │  │  [Process Tree]                              [⚠ Suspicious]  │ │
  │  │  [🔍 Search processes…                                      ] │ │
  │  └──────────────────────────────────────────────────────────────┘ │
  │  ┌─ column header (sticky, bg-slate-700/30) ────────────────────┐ │
  │  │  Process Name   PID   PPID   Threads   Handles   Status      │ │
  │  └──────────────────────────────────────────────────────────────┘ │
  │  ┌─ scrollable rows ────────────────────────────────────────────┐ │
  │  │  ▼ System        4      0      156      8234     ✓ CLEAN     │ │
  │  │     TiWorker.exe 32     4        0         0     ⚠ SUSP…    │ │
  │  └──────────────────────────────────────────────────────────────┘ │
  └───────────────────────────────────────────────────────────────────┘

Indentation
  React: paddingLeft = level * 24px on the name-cell content div.
  Here : setIndentation(24) with setRootIsDecorated(False).
         Qt applies depth*indentation to col-0 content only.
         All other columns use uniform 24px left padding.

Alignment
  Header bar   : contentsMargins left = 24 px
  Col headers  : padding-left     24 px
  Row items    : padding-left     24 px
  → every layer aligns to the same 24 px grid.

Scrollbar
  margin-top = column-header height (36 px) so the track only covers
  the row area.  background transparent so no coloured strip shows.

Public API (unchanged from previous version)
  load(processes)           populate from nested dict list
  set_filter(text)          programmatic search
  set_suspicious_only(on)   toggle filter
  clear()
  process_selected signal   emits the selected process dict
  normalize(raw)  @static   flatten extraction output to nested tree
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QFrame, QLabel, QPushButton, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QHeaderView,
    QSizePolicy, QStyledItemDelegate, QStyle, QApplication,
)
from PyQt5.QtCore import Qt, pyqtSignal, QRect
from PyQt5.QtGui  import QFont, QColor, QPainter, QPalette


# ── constants ──────────────────────────────────────────────────────────────────
_PAD_LEFT   = 24          # uniform left padding matching React px-6
_HDR_HEIGHT = 36          # column-header row height
_INDENT     = 22          # per-level indentation; compact enough for long names
_ROW_H      = 44          # fixed row height
_BRANCH_W   = 24          # fixed chevron/leaf indicator area in column 0


class _FixedPaddingDelegate(QStyledItemDelegate):
    """
    Custom delegate that draws each cell with a fixed left offset regardless
    of hover / selected / normal state — QSS padding changes between states
    are the root cause of the content-shift bug, so we bypass QSS padding
    entirely and paint text at a hardcoded x position.

    Col 0 gets _PAD_LEFT + depth*_INDENT so the tree hierarchy shows correctly.
    All other cols get a small uniform left offset (8px).
    """

    def __init__(self, tree: QTreeWidget, parent=None):
        super().__init__(parent)
        self._tree = tree

    def sizeHint(self, option, index):
        sh = super().sizeHint(option, index)
        return sh.__class__(sh.width(), _ROW_H)

    def paint(self, painter: QPainter, option, index):
        # ── 1. draw background (hover / selected / normal) ──────────────
        painter.save()
        is_selected = bool(option.state & QStyle.State_Selected)
        is_hovered  = bool(option.state & QStyle.State_MouseOver)

        if is_selected:
            painter.fillRect(option.rect, QColor(6, 182, 212, 38))
        elif is_hovered:
            painter.fillRect(option.rect, QColor(255, 255, 255, 28))

        col = index.column()
        item = self._tree.itemFromIndex(index)

        # ── 2. compute fixed left offset ─────────────────────────────────
        if col == 0:
            depth = 0
            p = item.parent() if item else None
            while p:
                depth += 1
                p = p.parent()
            x_off = _PAD_LEFT + depth * _INDENT
        else:
            x_off = _PAD_LEFT

        # ── 3. font + colour ─────────────────────────────────────────────
        color = index.data(Qt.ForegroundRole)
        font  = index.data(Qt.FontRole)
        if font:
            painter.setFont(font)
        painter.setPen(color.color() if color else QColor("#e2e8f0"))

        if col == 0:
            # Draw a clean custom branch indicator instead of embedding ▼/▶ in text.
            has_children = bool(item and item.childCount() > 0)
            is_expanded = bool(item and item.isExpanded())

            arrow_rect = QRect(
                option.rect.x() + x_off,
                option.rect.y(),
                _BRANCH_W,
                option.rect.height(),
            )

            if has_children:
                arrow = "▾" if is_expanded else "▸"
                painter.setPen(QColor("#cbd5e1"))
                arrow_font = QFont("Segoe UI", 12, QFont.Bold)
                painter.setFont(arrow_font)
                painter.drawText(arrow_rect, Qt.AlignVCenter | Qt.AlignLeft, arrow)
                if font:
                    painter.setFont(font)
                painter.setPen(color.color() if color else QColor("#e2e8f0"))
            else:
                # Keep leaf rows aligned with branch rows.
                painter.setPen(QColor("#475569"))
                leaf_font = QFont("Segoe UI", 8)
                painter.setFont(leaf_font)
                painter.drawText(arrow_rect, Qt.AlignVCenter | Qt.AlignLeft, "•")
                if font:
                    painter.setFont(font)
                painter.setPen(color.color() if color else QColor("#e2e8f0"))

            raw_text = (
                item.data(0, Qt.UserRole + 2)
                if item else index.data(Qt.DisplayRole)
            ) or ""
            text_rect = QRect(
                option.rect.x() + x_off + _BRANCH_W,
                option.rect.y(),
                option.rect.width() - x_off - _BRANCH_W - 8,
                option.rect.height(),
            )
            elided = painter.fontMetrics().elidedText(
                str(raw_text), Qt.ElideMiddle, max(20, text_rect.width())
            )
            painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, elided)

        else:
            text = index.data(Qt.DisplayRole) or ""
            # Keep Status text away from the overlay scrollbar.
            right_pad = 28 if col == 5 else 6
            text_rect = QRect(
                option.rect.x() + (8 if col == 5 else x_off),
                option.rect.y(),
                option.rect.width() - (8 if col == 5 else x_off) - right_pad,
                option.rect.height(),
            )
            elided = painter.fontMetrics().elidedText(
                str(text), Qt.ElideRight, max(20, text_rect.width())
            )
            painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, elided)

        painter.restore()


class ProcessTreeWidget(QWidget):
    """Full process-tree panel: title bar + search + column headers + rows."""

    process_selected = pyqtSignal(dict)

    # ── init ───────────────────────────────────────────────────────────────────

    def __init__(self, parent=None):
        super().__init__(parent)
        self._processes   = []
        self._susp_only   = False
        self._search_text = ""
        self.setStyleSheet("background: transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        root.addWidget(self._build_tree(), 1)

    # ── header : title row + search row ──────────────────────────────────────
    # Mirrors React:
    #   <div className="px-6 py-4 border-b">
    #     <div className="flex justify-between mb-3">
    #       <h2>Process Tree</h2>   <button>⚠ Suspicious</button>
    #     </div>
    #     <div relative><Search /><input placeholder="Search processes…"></div>
    #   </div>

    def _build_header(self) -> QFrame:
        bar = QFrame()
        bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        bar.setStyleSheet(
            "QFrame{"
            "  background: rgba(15,23,42,0.40);"
            "  border-bottom: 1px solid rgba(51,65,85,0.50);"
            "  border-top-left-radius:  12px;"
            "  border-top-right-radius: 12px;"
            "  border-bottom-left-radius:  0px;"
            "  border-bottom-right-radius: 0px;"
            "}"
        )
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(_PAD_LEFT, 16, _PAD_LEFT, 16)
        outer.setSpacing(12)

        # row 1 : "Process Tree"  +  ⚠ Suspicious toggle
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(8)

        title = QLabel("Process Tree")
        title.setStyleSheet(
            "color:#ffffff; background:transparent; border:none;"
            "font-size:15px; font-weight:700;"
        )
        row1.addWidget(title)
        row1.addStretch()

        self._expand_btn = QPushButton("Expand All")
        self._expand_btn.setFixedHeight(32)
        self._expand_btn.setCursor(Qt.PointingHandCursor)
        self._expand_btn.setStyleSheet(
            "QPushButton{"
            "  background: transparent;"
            "  border: 1px solid rgba(6,182,212,0.28);"
            "  border-radius: 8px;"
            "  color: #06b6d4;"
            "  padding: 0px 10px;"
            "  font-size: 11px; font-weight: 600;"
            "}"
            "QPushButton:hover{ background: rgba(6,182,212,0.10); color:#67e8f9; }"
        )
        self._expand_btn.clicked.connect(self._expand_all)
        row1.addWidget(self._expand_btn)

        self._collapse_btn = QPushButton("Collapse All")
        self._collapse_btn.setFixedHeight(32)
        self._collapse_btn.setCursor(Qt.PointingHandCursor)
        self._collapse_btn.setStyleSheet(
            "QPushButton{"
            "  background: transparent;"
            "  border: 1px solid rgba(51,65,85,0.70);"
            "  border-radius: 8px;"
            "  color: #94a3b8;"
            "  padding: 0px 10px;"
            "  font-size: 11px; font-weight: 600;"
            "}"
            "QPushButton:hover{ background: rgba(51,65,85,0.40); color:#ffffff; }"
        )
        self._collapse_btn.clicked.connect(self._collapse_all)
        row1.addWidget(self._collapse_btn)

        self._susp_btn = QPushButton("⚠  Suspicious")
        self._susp_btn.setFixedHeight(32)
        self._susp_btn.setCheckable(True)
        self._susp_btn.setStyleSheet(
            "QPushButton{"
            "  background: rgba(51,65,85,0.40);"
            "  border: 1px solid rgba(51,65,85,0.60);"
            "  border-radius: 8px;"
            "  color: #94a3b8;"
            "  padding: 0px 14px;"
            "  font-size: 12px; font-weight: 500;"
            "}"
            "QPushButton:checked{"
            "  background: rgba(248,113,113,0.18);"
            "  color: #f87171;"
            "  border-color: rgba(248,113,113,0.45);"
            "}"
            "QPushButton:hover{ background: rgba(71,85,105,0.55); color:#ffffff; }"
        )
        self._susp_btn.clicked.connect(self._on_toggle_susp)
        row1.addWidget(self._susp_btn)
        outer.addLayout(row1)

        # row 2 : search input (full width)
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search processes…")
        self._search.setFixedHeight(36)
        self._search.setStyleSheet(
            "QLineEdit{"
            "  background: rgba(15,23,42,0.55);"
            "  border: 1px solid rgba(51,65,85,0.60);"
            "  border-radius: 8px;"
            "  padding: 0px 12px;"
            "  color: #ffffff;"
            "  font-size: 13px;"
            "}"
            "QLineEdit:focus{ border-color: #06b6d4; }"
        )
        self._search.textChanged.connect(self._on_search)
        outer.addWidget(self._search)

        return bar

    # ── tree : column headers + scrollable rows ───────────────────────────────

    def _build_tree(self) -> QFrame:
        """
        Returns a QFrame that contains:
          • the QTreeWidget (built-in scrollbar OFF)
          • an overlay QScrollBar that starts below the column-header row

        The overlay scrollbar is synced to the tree's scrollModel and
        repositioned in resizeEvent so it never overlaps the header band.
        """
        from PyQt5.QtWidgets import QScrollBar
        from PyQt5.QtCore    import Qt as _Qt

        # ── container ─────────────────────────────────────────────────────
        container = QFrame()
        container.setStyleSheet("QFrame { background: transparent; border: none; }")
        # No layout manager — children are positioned manually in resizeEvent.

        # ── tree widget ────────────────────────────────────────────────────
        self._tree = QTreeWidget(container)
        self._tree.setColumnCount(6)
        self._tree.setHeaderLabels(
            ["Process Name", "PID", "PPID", "Threads", "Handles", "Status"]
        )
        self._tree.setRootIsDecorated(False)
        self._tree.setIndentation(0)   # delegate handles depth × _INDENT
        self._tree.setAnimated(False)
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(False)
        self._tree.setEditTriggers(QTreeWidget.NoEditTriggers)
        self._tree.setSelectionMode(QTreeWidget.SingleSelection)
        # Disable the built-in scrollbar — we provide our own overlay
        self._tree.setVerticalScrollBarPolicy(_Qt.ScrollBarAlwaysOff)
        self._tree.setHorizontalScrollBarPolicy(_Qt.ScrollBarAlwaysOff)
        self._tree.header().setFixedHeight(_HDR_HEIGHT)
        # Shift the entire row viewport 24px right so root items (Qt depth=0)
        # land at widget-x=24, aligning with the "Process Tree" title and
        # "Process Name" header.  Children (depth=1) land at widget-x=48, etc.
        # The header is drawn outside the viewport so its padding controls it
        # independently.
        self._tree.setViewportMargins(0, 0, 0, 0)
        self._tree.setStyleSheet(
            "QTreeWidget {"
            "  background: transparent; border: none;"
            "  color: #ffffff; font-size: 13px; outline: none;"
            "}"
            # No padding rules at all — delegate handles all positioning
            "QTreeWidget::item          { padding: 0px; }"
            "QTreeWidget::item:hover    { padding: 0px; }"
            "QTreeWidget::item:selected { padding: 0px; }"
            "QTreeWidget::branch { image: none; width: 0px; border: none; }"
        )
        self._tree.setItemDelegate(_FixedPaddingDelegate(self._tree))
        self._tree.viewport().setStyleSheet("QWidget { background: transparent; }")

        # ── column header ──────────────────────────────────────────────────
        self._tree.header().setStyleSheet(
            "QHeaderView { background: rgba(51,65,85,0.30); border: none; border-radius: 0px; }"
            "QHeaderView::section {"
            "  background: rgba(51,65,85,0.30); color: #cbd5e1;"
            "  padding: 0px 8px 0px 24px;"
            "  border: none;"
            "  border-bottom: 1px solid rgba(51,65,85,0.60);"
            "  border-radius: 0px; margin: 0px;"
            "  font-weight: 600; font-size: 12px;"
            "}"
            "QHeaderView::section:last { border-radius: 0px; }"
        )
        self._tree.header().setContentsMargins(0, 0, 0, 0)

        # corner widget fills the top-right patch between last header section
        # and where the overlay scrollbar begins
        from PyQt5.QtWidgets import QWidget as _QW
        corner = _QW(self._tree)
        corner.setFixedHeight(_HDR_HEIGHT)
        corner.setStyleSheet(
            "background: rgba(51,65,85,0.30);"
            "border-bottom: 1px solid rgba(51,65,85,0.60);"
            "border-radius: 0px;"
        )
        self._tree.setCornerWidget(corner)

        # ── column widths ──────────────────────────────────────────────────
        hdr = self._tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        # Keep numeric/status columns compact so long process names have room.
        for i, w in [(1, 64), (2, 64), (3, 82), (4, 86), (5, 190)]:
            self._tree.setColumnWidth(i, w)
            hdr.setSectionResizeMode(i, QHeaderView.Fixed)

        # ── overlay scrollbar ──────────────────────────────────────────────
        # Child of the container so it floats on top of the tree.
        # Positioned in resizeEvent: x = right edge, y = _HDR_HEIGHT.
        self._overlay_sb = QScrollBar(_Qt.Vertical, container)
        self._overlay_sb.setFixedWidth(6)
        self._overlay_sb.setStyleSheet(
            "QScrollBar:vertical {"
            "  background: transparent; width: 6px;"
            "  border-radius: 3px; margin: 0px;"
            "}"
            "QScrollBar::handle:vertical {"
            "  background: rgba(71,85,105,0.80);"
            "  border-radius: 3px; min-height: 30px;"
            "}"
            "QScrollBar::handle:vertical:hover { background: #06b6d4; }"
            "QScrollBar::add-line:vertical,"
            "QScrollBar::sub-line:vertical { height: 0; }"
            "QScrollBar::add-page:vertical,"
            "QScrollBar::sub-page:vertical { background: transparent; }"
        )

        # Header filler for the reserved scrollbar gutter so the column-header
        # band visually reaches the right edge above the row scrollbar.
        self._header_gutter = QFrame(container)
        self._header_gutter.setStyleSheet(
            "QFrame {"
            "  background: rgba(51,65,85,0.30);"
            "  border: none;"
            "  border-bottom: 1px solid rgba(51,65,85,0.60);"
            "  border-radius: 0px;"
            "}"
        )

        # Sync overlay scrollbar ↔ tree's internal scroll model
        tree_sb = self._tree.verticalScrollBar()
        def _sync_range(mn, mx):
            self._overlay_sb.setRange(mn, mx)
        def _sync_val(v):
            self._overlay_sb.setValue(v)
        def _sync_page(v):
            self._overlay_sb.setPageStep(v)
        tree_sb.rangeChanged.connect(_sync_range)
        tree_sb.valueChanged.connect(_sync_val)
        tree_sb.actionTriggered.connect(lambda _: _sync_page(tree_sb.pageStep()))
        self._overlay_sb.valueChanged.connect(tree_sb.setValue)
        # initial sync
        self._overlay_sb.setRange(tree_sb.minimum(), tree_sb.maximum())
        self._overlay_sb.setValue(tree_sb.value())
        self._overlay_sb.setPageStep(tree_sb.pageStep())
        self._overlay_sb.setSingleStep(tree_sb.singleStep())

        # ── signals ───────────────────────────────────────────────────────
        self._tree.itemSelectionChanged.connect(self._on_selection)
        self._tree.itemClicked.connect(self._on_item_clicked)
        self._tree.itemExpanded.connect(self._on_expanded)
        self._tree.itemCollapsed.connect(self._on_collapsed)

        # Install event filter on the container so we can respond to its resize
        container.installEventFilter(self)

        # Store container ref for resizeEvent
        self._tree_container = container
        return container

    def eventFilter(self, obj, event):
        from PyQt5.QtCore import QEvent
        if obj is self._tree_container and event.type() == QEvent.Resize:
            self._reposition_scrollbar()
        return super().eventFilter(obj, event)

    def _reposition_scrollbar(self):
        """Keep the header band full-width and float the scrollbar over row area only."""
        if not hasattr(self, "_tree_container"):
            return
        c    = self._tree_container
        cw   = c.width()
        ch   = c.height()
        sb_w = 6

        # Tree/header fill the whole container width so the column header band
        # reaches the right edge cleanly. Status text is padded by the delegate.
        self._tree.setGeometry(0, 0, cw, ch)

        # The old header-gutter filler is no longer needed; keeping it hidden
        # prevents the odd darker header block near the scrollbar.
        if hasattr(self, "_header_gutter"):
            self._header_gutter.hide()

        # Overlay scrollbar: right edge, y starts below column header only.
        self._overlay_sb.setGeometry(
            max(0, cw - sb_w - 4),
            _HDR_HEIGHT,
            sb_w,
            max(0, ch - _HDR_HEIGHT),
        )
        self._overlay_sb.raise_()

    # ── Public API ─────────────────────────────────────────────────────────────

    def load(self, processes: list):
        self._processes = processes or []
        self._repopulate()

    def set_filter(self, text: str):
        self._search.setText(text)

    def set_suspicious_only(self, enabled: bool):
        self._susp_only = enabled
        self._susp_btn.setChecked(enabled)
        self._repopulate()

    def clear(self):
        self._tree.clear()
        self._processes = []

    # ── Normalisation ─────────────────────────────────────────────────────────

    @staticmethod
    def normalize(raw: list) -> list:
        """Convert flat extraction output into the nested dict tree."""
        if not raw:
            return []
        normalised = []
        for p in raw:
            np = dict(p)
            np["name"] = (
                p.get("image_name") or p.get("name") or
                p.get("ImageFileName") or "?"
            )
            raw_s = str(
                p.get("status", "") or
                ("SUSPICIOUS" if p.get("is_suspicious") else "") or
                ("SUSPICIOUS" if p.get("anomalies")     else "CLEAN")
            ).upper()
            np["status"] = "suspicious" if raw_s == "SUSPICIOUS" else "clean"
            np["hidden"] = bool(
                p.get("hidden") or p.get("is_hidden") or
                any("hidden" in str(a).lower() for a in p.get("anomalies", []))
            )
            raw_anoms = p.get("anomalies", [])
            if raw_anoms and isinstance(raw_anoms[0], str):
                np["anomalies"] = [
                    {
                        "type":   a.split(":")[0].strip(),
                        "detail": a.split(":", 1)[1].strip() if ":" in a else a,
                    }
                    for a in raw_anoms
                ]
            np.setdefault("children", [])
            normalised.append(np)

        pid_map = {p["pid"]: p for p in normalised}
        roots   = []
        for p in normalised:
            ppid = p.get("ppid", 0)
            if ppid and ppid in pid_map and ppid != p["pid"]:
                pid_map[ppid]["children"].append(p)
            else:
                roots.append(p)

        roots.sort(key=lambda x: x["pid"])
        def _sort(nodes):
            for n in nodes:
                n["children"].sort(key=lambda x: x["pid"])
                _sort(n["children"])
        _sort(roots)
        return roots

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _resolve_name(proc: dict) -> str:
        return (
            proc.get("image_name") or proc.get("name") or
            proc.get("ImageFileName") or "?"
        )

    @staticmethod
    def _resolve_status(proc: dict) -> str:
        raw = str(
            proc.get("status", "") or
            ("SUSPICIOUS" if proc.get("is_suspicious") else "") or
            ("SUSPICIOUS" if proc.get("anomalies")     else "CLEAN")
        ).upper()
        return "suspicious" if raw == "SUSPICIOUS" else "clean"

    @staticmethod
    def _col0_text(proc: dict, expanded: bool = True, level: int = 0) -> str:
        """Return display name only.

        Expand/collapse indicators are painted by _FixedPaddingDelegate, so the
        process name can use middle ellipsis cleanly without embedded arrow text.
        """
        name = ProcessTreeWidget._resolve_name(proc)
        if proc.get("hidden") or proc.get("is_hidden"):
            name += "   [HIDDEN]"
        return name

    def _repopulate(self):
        self._tree.clear()
        text = self._search_text.lower()

        def _matches(p: dict) -> bool:
            name    = self._resolve_name(p).lower()
            name_ok = text in name or text in str(p.get("pid", ""))
            susp_ok = (not self._susp_only) or self._resolve_status(p) == "suspicious"
            if name_ok and susp_ok:
                return True
            return any(_matches(c) for c in p.get("children", []))

        def _add(procs: list, parent, level: int = 0):
            for proc in procs:
                if not _matches(proc):
                    continue
                is_susp  = self._resolve_status(proc) == "suspicious"
                has_kids = bool(proc.get("children"))

                item = QTreeWidgetItem(parent)
                item.setData(0, Qt.UserRole, proc)
                item.setData(0, Qt.UserRole + 1, level)   # store level for expand/collapse

                full_name = self._col0_text(proc, expanded=True, level=level)
                item.setText(0, full_name)
                item.setData(0, Qt.UserRole + 2, full_name)
                item.setToolTip(0, full_name)
                item.setText(1, str(proc.get("pid",     "")))
                item.setText(2, str(proc.get("ppid",    "")))
                item.setText(3, str(proc.get("threads",  0)))
                item.setText(4, str(proc.get("handles",  0)))
                item.setText(5, "⚠  SUSPICIOUS" if is_susp else "✓  CLEAN")
                for _col in range(1, 6):
                    item.setToolTip(_col, item.text(_col))

                item.setFont(0, QFont("Segoe UI", 12,
                                      QFont.Bold if is_susp else QFont.Normal))
                item.setForeground(0, QColor("#f87171" if is_susp else "#e2e8f0"))

                for col in [1, 2]:
                    item.setFont(col, QFont("Courier New", 11))
                    item.setForeground(col, QColor("#94a3b8"))
                for col in [3, 4]:
                    item.setFont(col, QFont("Segoe UI", 11))
                    item.setForeground(col, QColor("#94a3b8"))

                item.setFont(5, QFont("Segoe UI", 11, QFont.Bold))
                item.setForeground(5, QColor("#f87171" if is_susp else "#34d399"))

                _add(proc.get("children", []), item, level + 1)
                if has_kids:
                    item.setExpanded(True)

        _add(self._processes, self._tree.invisibleRootItem())

    # ── Slots ──────────────────────────────────────────────────────────────────

    def _on_expanded(self, item):
        # Chevron is delegate-painted based on item.isExpanded().
        self._tree.viewport().update()

    def _on_collapsed(self, item):
        # Chevron is delegate-painted based on item.isExpanded().
        self._tree.viewport().update()

    def _on_item_clicked(self, item, column: int):
        """Single-click branch rows to expand/minimize them.

        The branch indicator is custom-painted, so this makes the parent row
        itself behave like a clear expand/collapse control.
        """
        if column == 0 and item and item.childCount() > 0:
            item.setExpanded(not item.isExpanded())

    def _expand_all(self):
        self._tree.expandAll()
        self._tree.viewport().update()

    def _collapse_all(self):
        self._tree.collapseAll()
        self._tree.viewport().update()

    def _on_search(self, text: str):
        self._search_text = text.strip()
        self._repopulate()

    def _on_toggle_susp(self, checked: bool):
        self._susp_only = checked
        self._repopulate()

    def _on_selection(self):
        items = self._tree.selectedItems()
        if not items:
            return
        proc = items[0].data(0, Qt.UserRole)
        if proc:
            self.process_selected.emit(proc)

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _flatten(procs: list) -> list:
        out = []
        for p in procs:
            out.append(p)
            out.extend(ProcessTreeWidget._flatten(p.get("children", [])))
        return out
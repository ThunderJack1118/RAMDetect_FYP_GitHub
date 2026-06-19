"""
Acquisition — Page 2
─────────────────────
Wired to the real bridge layer:

  File mode  → AcquisitionBridge.validate_file(path)
               shows full validation card (size, arch, SHA-256, est. time)
               populates AppState.current immediately — no worker needed

  Live mode  → AcquisitionBridge.start_live_dump(...)  (LiveDumpWorker thread)
               progress/status callbacks marshalled back to main thread
               via a queue.Queue polled by a QTimer (thread-safe, no QObject needed)

  Session    → AppState.current populated:
               dump_path, dump_filename, dump_size_bytes, mode, acquired_at
               sha256, md5, dump_format, architecture  (FIX #4: proper fields)

  Config     → DumpIt path + output dir pre-filled from Config
               changes written back to Config on Acquire

  Cancel     → worker.cancel() + reset UI back to idle
  Error      → red error state card in monitor panel
  Re-run     → if AppState.current already has a dump_path (set by Dashboard
               "↺" button), pre-fills file picker and validates on show
"""

import os
import queue
import threading
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QPushButton, QLineEdit, QFileDialog,
    QSizePolicy, QProgressBar, QStackedWidget, QComboBox, QDialog,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui  import QFont

from ui.pages.base_page               import BasePage
from ui.widgets.progress_stepper      import ProgressStepper
from ui.bridge.session                import AppState
from ui.bridge.config_bridge          import Config
from ui.bridge.acquisition_bridge     import AcquisitionBridge
from ui.style_helpers import refresh_style, set_role, set_tone, set_variant, set_state

# Try to get total physical RAM for size estimate during acquisition
try:
    import psutil as _psutil
    _TOTAL_RAM_BYTES = _psutil.virtual_memory().total
    _TOTAL_RAM_STR   = f"{_TOTAL_RAM_BYTES / (1024 ** 3):.1f} GB"
except Exception:
    _TOTAL_RAM_BYTES = 0
    _TOTAL_RAM_STR   = "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Path helper
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_path(path: str) -> str:
    """Backslashes → forward slashes, strip trailing slash."""
    return path.replace("\\", "/").rstrip("/")

def _short_middle(value: str, max_chars: int = 72) -> str:
    """Middle-ellipsis for long paths while keeping the filename visible."""
    value = str(value or "—")
    if value == "—" or len(value) <= max_chars:
        return value
    keep = max_chars - 3
    left = max(12, keep // 2)
    right = max(12, keep - left)
    return f"{value[:left]}...{value[-right:]}"


def _compact_dump_path(value: str, max_chars: int = 72) -> str:
    """Compact one-line path for the acquisition monitor.

    The full path stays in the tooltip. The visible text intentionally keeps only
    the front key directory context and the final .dmp filename so the Path card
    does not wrap, overlap SHA-256, or disturb the right-panel spacing.
    """
    value = _normalize_path(str(value or "—"))
    if value == "—":
        return value

    parts = [p for p in value.split("/") if p]
    filename = parts[-1] if parts else value
    filename = _short_middle(filename, 42)

    if len(value) <= max_chars:
        return value

    # Example: C:/Users/annsi/Downloads/.../DESKTOP-...dmp
    lead = "/".join(parts[:4]) if len(parts) >= 4 else "/".join(parts[:-1])
    display = f"{lead}/.../{filename}" if lead else f".../{filename}"
    if len(display) <= max_chars:
        return display
    return _short_middle(display, max_chars)


def _short_hash(value: str, left: int = 16, right: int = 16) -> str:
    """Shorten long hashes for panel display; full hash remains in tooltip."""
    value = str(value or "—")
    if value == "—" or len(value) <= left + right + 3:
        return value
    return f"{value[:left]}...{value[-right:]}"





def _project_root() -> Path:
    """Return the active RAMDetect runtime root.

    In a packaged/installed build, the correct writable root is the folder
    containing RAMDetect.exe, for example C:/RAMDetect Admin or
    C:/RAMDetect Analyst. This prevents one installed workstation folder from
    reusing stale paths copied from another installation.
    """
    try:
        import sys as _sys
        if getattr(_sys, "frozen", False):
            return Path(_sys.executable).resolve().parent
    except Exception:
        pass

    here = Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass
    return Path.cwd().resolve()


def _canonical_dumps_dir(create: bool = True) -> Path:
    """RAMDetect-managed dump storage folder for this installed copy.

    This intentionally ignores stale absolute paths from config.yaml copied from
    another workstation, such as C:/Users/.../GITHUB/RAMDetect/dumps.
    """
    target = _project_root() / "dumps"
    if create:
        target.mkdir(parents=True, exist_ok=True)
    return target


def _canonical_dumps_dir_str() -> str:
    return _normalize_path(str(_canonical_dumps_dir()))


def _is_inside_canonical_dumps(path: str) -> bool:
    try:
        Path(path).resolve().relative_to(_canonical_dumps_dir().resolve())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Background worker — move a loaded dump into a session subfolder
# ─────────────────────────────────────────────────────────────────────────────

class _FileOrganizeWorker(threading.Thread):
    """
    Moves a user-supplied dump into a new session subfolder via
    AcquisitionBridge.organize_loaded_file().  Runs in a daemon thread;
    results are pushed onto cb_queue so _drain_queue handles them
    identically to live-mode results.

    Queue messages:
        ("progress", pct: int, msg: str)
        ("finished", info: dict)
        ("error",    msg: str)
    """
    def __init__(self, src_path: str, output_base_dir: str,
                 validated_info: dict, cb_queue: "queue.Queue",
                 selected_profile: dict | None = None):
        super().__init__(daemon=True)
        self.src_path        = src_path
        self.output_base_dir = output_base_dir
        self.validated_info  = validated_info
        self.selected_profile = selected_profile
        self.cb_queue        = cb_queue

    def run(self):
        q = self.cb_queue
        try:
            q.put(("progress", 10, "Creating session folder…"))
            result = AcquisitionBridge.organize_loaded_file(
                self.src_path, self.output_base_dir,
                selected_profile=self.selected_profile,
            )
            if not result["success"]:
                q.put(("error", result["message"]))
                return
            q.put(("progress", 75, "Dump organised. Resolving kernel metadata…"))
            vi = self.validated_info
            arch = vi.get("architecture", "—")
            build_number = None
            if isinstance(self.selected_profile, dict) and self.selected_profile.get("build_number"):
                build_number = int(self.selected_profile.get("build_number"))
                arch = f"x64 {self.selected_profile.get('label', f'Windows build {build_number}')}"

            dtb_result = {}
            try:
                dtb_result = AcquisitionBridge.detect_dtb(
                    result["dump_path"],
                    build_number=build_number or vi.get("build_number"),
                    scan_mb=0,
                    write_json=True,
                ) or {}
            except Exception as exc:
                dtb_result = {"success": False, "message": f"Kernel metadata warning: {exc}"}

            if dtb_result.get("build"):
                build_number = int(dtb_result.get("build"))
                arch = f"Windows build {build_number}"

            q.put(("progress", 92, "Verifying move and metadata…"))
            q.put(("finished", {
                "valid":         True,
                "path":          result["dump_path"],
                "filename":      vi.get("filename", ""),
                "session_dir":   result["session_dir"],
                "json_path":     dtb_result.get("json_path") or result.get("json_path"),
                "size_bytes":    vi.get("size_bytes", 0),
                "size_str":      vi.get("size_str", "—"),
                "format":        "Crash Dump" if str(result.get("dump_path", "")).lower().endswith(".dmp") else vi.get("format", "—"),
                "architecture":  arch,
                "build_number":  build_number or vi.get("build_number"),
                "dtb_hex":       dtb_result.get("dtb_hex"),
                "dtb_source":    dtb_result.get("dtb_source"),
                "metadata_source": dtb_result.get("metadata_source") or dtb_result.get("source"),
                "dtb_confidence": dtb_result.get("confidence"),
                "os_hint":       vi.get("os_hint", "Windows"),
                "est_load_time": vi.get("est_load_time", "—"),
                "sha256":        vi.get("sha256", "—"),
                "md5":           vi.get("md5",    "—"),
                "error":         "",
            }))
        except Exception as exc:
            q.put(("error", f"Failed to organise dump: {exc}"))




def _project_root() -> Path:
    """Return the active RAMDetect runtime root.

    In a packaged/installed build, the correct writable root is the folder
    containing RAMDetect.exe, for example C:/RAMDetect Admin or
    C:/RAMDetect Analyst. This prevents one installed workstation folder from
    reusing stale paths copied from another installation.
    """
    try:
        import sys as _sys
        if getattr(_sys, "frozen", False):
            return Path(_sys.executable).resolve().parent
    except Exception:
        pass

    here = Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass
    return Path.cwd().resolve()


def _canonical_dumps_dir(create: bool = True) -> Path:
    """RAMDetect-managed dump storage folder for this installed copy.

    This intentionally ignores stale absolute paths from config.yaml copied from
    another workstation, such as C:/Users/.../GITHUB/RAMDetect/dumps.
    """
    target = _project_root() / "dumps"
    if create:
        target.mkdir(parents=True, exist_ok=True)
    return target


def _canonical_dumps_dir_str() -> str:
    return _normalize_path(str(_canonical_dumps_dir()))


def _is_inside_canonical_dumps(path: str) -> bool:
    try:
        Path(path).resolve().relative_to(_canonical_dumps_dir().resolve())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Background worker — convert .raw/.mem/.vmem/.bin/.lime → .dmp
# ─────────────────────────────────────────────────────────────────────────────

class _ConvertWorker(threading.Thread):
    """
    Converts a non-.dmp memory dump to .dmp via AcquisitionBridge.convert_to_dmp(),
    then immediately generates a JSON sidecar via AcquisitionBridge.generate_json_metadata().

    Results are pushed onto cb_queue:
        ("convert_ok",  output_path: str)
        ("convert_err", message:     str)
    """
    def __init__(self, src_path: str, cb_queue: "queue.Queue",
                 selected_profile: dict | None = None):
        super().__init__(daemon=True)
        self.src_path = src_path
        self.selected_profile = selected_profile
        self.cb_queue = cb_queue

    def run(self):
        try:
            # Step 1 — convert to .dmp
            result = AcquisitionBridge.convert_to_dmp(self.src_path, copy=True)
            if not (result["success"] and result.get("output_path")):
                self.cb_queue.put(("convert_err", result.get("message", "Conversion failed.")))
                return

            dmp_path = result["output_path"]

            # Do NOT generate a JSON sidecar beside the source/original folder.
            # The converted file is only an intermediate selection. The final
            # JSON sidecar is created later after organize_loaded_file() moves
            # the dump into <current RAMDetect>/dumps/<session>/.
            self.cb_queue.put(("convert_ok", dmp_path))

        except Exception as exc:
            self.cb_queue.put(("convert_err", f"Conversion error: {exc}"))




def _project_root() -> Path:
    """Return the active RAMDetect runtime root.

    In a packaged/installed build, the correct writable root is the folder
    containing RAMDetect.exe, for example C:/RAMDetect Admin or
    C:/RAMDetect Analyst. This prevents one installed workstation folder from
    reusing stale paths copied from another installation.
    """
    try:
        import sys as _sys
        if getattr(_sys, "frozen", False):
            return Path(_sys.executable).resolve().parent
    except Exception:
        pass

    here = Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass
    return Path.cwd().resolve()


def _canonical_dumps_dir(create: bool = True) -> Path:
    """RAMDetect-managed dump storage folder for this installed copy.

    This intentionally ignores stale absolute paths from config.yaml copied from
    another workstation, such as C:/Users/.../GITHUB/RAMDetect/dumps.
    """
    target = _project_root() / "dumps"
    if create:
        target.mkdir(parents=True, exist_ok=True)
    return target


def _canonical_dumps_dir_str() -> str:
    return _normalize_path(str(_canonical_dumps_dir()))


def _is_inside_canonical_dumps(path: str) -> bool:
    try:
        Path(path).resolve().relative_to(_canonical_dumps_dir().resolve())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Background worker — detect DTB/CR3 and write it into JSON sidecar
# ─────────────────────────────────────────────────────────────────────────────

class _DTBDetectWorker(threading.Thread):
    """
    Runs AcquisitionBridge.detect_dtb() in the background so the UI does not
    freeze while resolving kernel metadata and DTB/CR3.

    Queue messages:
        ("dtb_ok",  result: dict)
        ("dtb_err", message: str)
    """
    def __init__(self, dump_path: str, cb_queue: "queue.Queue",
                 build_number: int | None = None, scan_mb: int = 4096):
        super().__init__(daemon=True)
        self.dump_path = dump_path
        self.build_number = build_number
        self.scan_mb = scan_mb
        self.cb_queue = cb_queue

    def run(self):
        try:
            result = AcquisitionBridge.detect_dtb(
                self.dump_path,
                build_number=self.build_number,
                scan_mb=self.scan_mb,
                write_json=True,
            )
            if result.get("success"):
                self.cb_queue.put(("dtb_ok", result))
            else:
                self.cb_queue.put(("dtb_err", result.get("message", "DTB detection failed.")))
        except Exception as exc:
            self.cb_queue.put(("dtb_err", f"DTB detection error: {exc}"))


# ─────────────────────────────────────────────────────────────────────────────
# Tiny helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(radius: int = 12) -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.NoFrame)
    f.setAttribute(Qt.WA_StyledBackground, True)
    set_role(f, "card")
    return f


def _lbl(text, size=12, bold=False, color="#94a3b8", mono=False) -> QLabel:
    l = QLabel(text)
    family = "Courier New" if mono else "Segoe UI"
    l.setFont(QFont(family, size, QFont.Bold if bold else QFont.Normal))
    set_tone(l, color)
    if mono:
        l.setProperty("role", "mono")
    return l


def _field_label(text) -> QLabel:
    return _lbl(text, 11, color="#94a3b8")


def _input(placeholder="", text="") -> QLineEdit:
    e = QLineEdit()
    e.setPlaceholderText(placeholder)
    e.setText(text)
    e.setFixedHeight(40)
    return e


# ─────────────────────────────────────────────────────────────────────────────
# Mode selector card  (Live System / Load File)
# ─────────────────────────────────────────────────────────────────────────────

class _ModeCard(QFrame):
    def __init__(self, icon: str, title: str, desc: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(90)
        self.setFrameShape(QFrame.NoFrame)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setCursor(Qt.PointingHandCursor)
        self._selected = False

        row = QHBoxLayout(self)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(14)

        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setFont(QFont("Segoe UI", 20))
        self.icon_lbl.setFixedSize(44, 44)
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        row.addWidget(self.icon_lbl)

        col = QVBoxLayout()
        col.setSpacing(2)
        tl = QLabel(title)
        tl.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        set_tone(tl, "#ffffff")
        dl = QLabel(desc)
        # Slightly smaller subtitle prevents the Load File text from being
        # clipped on high-DPI screens while preserving the existing card size.
        dl.setFont(QFont("Segoe UI", 9))
        dl.setTextFormat(Qt.PlainText)
        dl.setWordWrap(False)
        dl.setToolTip(desc)
        dl.setMinimumWidth(0)
        dl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        set_tone(dl, "#94a3b8")
        col.addWidget(tl)
        col.addWidget(dl)
        row.addLayout(col, stretch=1)

        self._apply(False)

    def _apply(self, sel: bool):
        self.setObjectName("ModeCard")
        self.icon_lbl.setObjectName("ModeIcon")
        set_state(self, "selected" if sel else "idle")
        set_state(self.icon_lbl, "selected" if sel else "idle")

    def set_selected(self, v: bool):
        self._selected = v
        self._apply(v)


# ─────────────────────────────────────────────────────────────────────────────
# Validation result card  (shown after file is selected)
# ─────────────────────────────────────────────────────────────────────────────

class _ValidationCard(QFrame):
    """Shows the AcquisitionBridge.validate_file() result in a detailed card."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hide()
        self._vb = QVBoxLayout(self)
        self._vb.setContentsMargins(14, 12, 14, 12)
        self._vb.setSpacing(6)

    def clear_content(self):
        """Recursively clear all widgets and sub-layouts to prevent ghost widgets."""
        def _clear(layout):
            if layout is None:
                return
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
                else:
                    sub_layout = item.layout()
                    if sub_layout:
                        _clear(sub_layout)
                        sub_layout.deleteLater()
        _clear(self._vb)

    def show_result(self, info: dict):
        # Clear previous content safely using recursive clear
        self.clear_content()

        valid = info.get("valid", False)
        if valid:
            border = "rgba(52,211,153,0.35)"
            bg     = "rgba(52,211,153,0.07)"
            icon   = "✓"
            icon_c = "#34d399"
            head_c = "#34d399"
            head   = info.get("filename", "")
        else:
            border = "rgba(248,113,113,0.35)"
            bg     = "rgba(248,113,113,0.07)"
            icon   = "✗"
            icon_c = "#f87171"
            head_c = "#f87171"
            head   = info.get("error", "Validation failed")

        self.setObjectName("ValidationCard")
        set_state(self, "valid" if valid else "invalid")

        # Header row
        hdr_row = QHBoxLayout()
        hdr_row.setSpacing(8)
        ic = QLabel(icon)
        ic.setFont(QFont("Segoe UI", 13, QFont.Bold))
        set_tone(ic, icon_c)
        hdr_row.addWidget(ic)
        hl = QLabel(head)
        hl.setFont(QFont("Courier New", 12, QFont.Bold))
        set_tone(hl, head_c)
        hl.setWordWrap(True)
        hdr_row.addWidget(hl, stretch=1)
        self._vb.addLayout(hdr_row)

        if valid:
            # Detail rows
            rows = [
                ("Format",    info.get("format", "—")),
                ("Size",      info.get("size_str", "—")),
                ("Architecture", info.get("architecture", "—")),
                ("Est. Load", info.get("est_load_time", "—")),
                ("SHA-256",   (info.get("sha256", "—")[:16] + "...") if info.get("sha256") else "—"),
            ]
            grid = QHBoxLayout()
            left_col  = QVBoxLayout()
            right_col = QVBoxLayout()
            for i, (k, v) in enumerate(rows):
                row_w = QHBoxLayout()
                row_w.addWidget(_lbl(k + ":", 10, color="#64748b"))
                row_w.addStretch()
                row_w.addWidget(_lbl(v, 10, bold=True, color="#cbd5e1", mono=(k=="SHA-256")))
                target = left_col if i < 3 else right_col
                target.addLayout(row_w)
            grid.addLayout(left_col, stretch=1)
            grid.addSpacing(16)
            grid.addLayout(right_col, stretch=1)
            self._vb.addLayout(grid)

        self.show()



# ─────────────────────────────────────────────────────────────────────────────
# OS Profile Dialog — modal selector for dumps without build metadata
# ─────────────────────────────────────────────────────────────────────────────

class _OSProfileDialog(QDialog):
    """Modal dialog used when a .vmem/.raw/.mem dump has no reliable build metadata."""

    def __init__(self, profiles: list[dict], current_profile: dict | None = None, parent=None):
        super().__init__(parent)
        self.selected_profile: dict | None = None
        self.setWindowTitle("Select Windows OS Profile")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.setStyleSheet(
            "QDialog { background: #0f172a; }"
            "QLabel { background: transparent; border: none; }"
            "QComboBox { background: rgba(15,23,42,0.95); color: #e2e8f0;"
            "  border: 1px solid #475569; border-radius: 8px; padding: 8px 10px; }"
            "QPushButton { border-radius: 8px; padding: 9px 14px; font-weight: 600; }"
        )

        vb = QVBoxLayout(self)
        vb.setContentsMargins(22, 20, 22, 18)
        vb.setSpacing(12)

        title = QLabel("OS profile required before analysis")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        set_tone(title, "#ffffff")
        vb.addWidget(title)

        hint = QLabel(
            "This dump does not contain reliable Windows build metadata. "
            "Select the correct profile so RAMDetect can save it into the JSON sidecar "
            "and load the correct kernel parsing offsets."
        )
        hint.setFont(QFont("Segoe UI", 10))
        hint.setWordWrap(True)
        set_tone(hint, "#94a3b8")
        vb.addWidget(hint)

        warn = QLabel("Choose the profile that matches the victim VM/host build, for example Windows 10 22H2 build 19045.")
        warn.setFont(QFont("Segoe UI", 9))
        warn.setWordWrap(True)
        warn.setStyleSheet(
            "color: #facc15; background: rgba(250,204,21,0.07);"
            "border: 1px solid rgba(250,204,21,0.30); border-radius: 8px; padding: 9px 10px;"
        )
        vb.addWidget(warn)

        label = QLabel("Windows profile")
        label.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(label, "#cbd5e1")
        vb.addWidget(label)

        self.combo = QComboBox()
        self.combo.setFixedHeight(40)
        self.combo.addItem("Select OS profile / Windows build…", None)
        selected_index = 0
        for i, prof in enumerate(profiles, start=1):
            if not isinstance(prof, dict) or not prof.get("build_number"):
                continue
            self.combo.addItem(prof.get("label", f"Windows build {prof.get('build_number')}"), prof)
            if current_profile and int(current_profile.get("build_number", -1)) == int(prof.get("build_number", -2)):
                selected_index = i
        self.combo.setCurrentIndex(selected_index)
        vb.addWidget(self.combo)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(
            "QPushButton { background: rgba(51,65,85,0.70); color: #cbd5e1; border: 1px solid #475569; }"
            "QPushButton:hover { background: #475569; color: #ffffff; }"
        )
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        apply_btn = QPushButton("Apply Profile")
        apply_btn.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #06b6d4, stop:1 #2563eb);"
            " color: #ffffff; border: none; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0891b2, stop:1 #1d4ed8); }"
        )
        apply_btn.clicked.connect(self._accept_profile)
        btn_row.addWidget(apply_btn)
        vb.addLayout(btn_row)

    def _accept_profile(self):
        data = self.combo.currentData()
        if isinstance(data, dict) and data.get("build_number"):
            self.selected_profile = data
            self.accept()


class _DTBPopupDialog(QDialog):
    """Small popup for DTB/CR3 status and launching kernel metadata detection."""

    def __init__(self, page, parent=None):
        super().__init__(parent)
        self.page = page
        self.setWindowTitle("DTB / CR3 Detection")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.setStyleSheet(
            "QDialog { background: #0f172a; }"
            "QLabel { background: transparent; border: none; }"
            "QPushButton { border-radius: 8px; padding: 9px 14px; font-weight: 600; }"
        )

        vb = QVBoxLayout(self)
        vb.setContentsMargins(22, 20, 22, 18)
        vb.setSpacing(12)

        title = QLabel("DTB / CR3 Metadata")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        set_tone(title, "#ffffff")
        vb.addWidget(title)

        self.info = QLabel()
        self.info.setFont(QFont("Segoe UI", 10))
        self.info.setWordWrap(True)
        set_tone(self.info, "#cbd5e1")
        vb.addWidget(self.info)

        self.status_card = QFrame()
        self.status_card.setStyleSheet(
            "QFrame { background: rgba(30,41,59,0.65); border: 1px solid rgba(71,85,105,0.7); border-radius: 10px; }"
            "QLabel { border: none; background: transparent; }"
        )
        card_v = QVBoxLayout(self.status_card)
        card_v.setContentsMargins(14, 12, 14, 12)
        card_v.setSpacing(6)
        self.status_lbl = QLabel()
        self.status_lbl.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        self.status_lbl.setWordWrap(True)
        self.status_sub = QLabel()
        self.status_sub.setFont(QFont("Segoe UI", 9))
        set_tone(self.status_sub, "#94a3b8")
        self.status_sub.setWordWrap(True)
        card_v.addWidget(self.status_lbl)
        card_v.addWidget(self.status_sub)
        vb.addWidget(self.status_card)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(
            "QPushButton { background: rgba(51,65,85,0.70); color: #cbd5e1; border: 1px solid #475569; }"
            "QPushButton:hover { background: #475569; color: #ffffff; }"
        )
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(close_btn)

        self.run_btn = QPushButton("Detect DTB")
        self.run_btn.setStyleSheet(
            "QPushButton { background: rgba(14,165,233,0.18); border: 1px solid rgba(14,165,233,0.50); color: #38bdf8; }"
            "QPushButton:hover { background: rgba(14,165,233,0.28); color: #ffffff; }"
        )
        self.run_btn.clicked.connect(self._run_detection)
        btn_row.addWidget(self.run_btn)
        vb.addLayout(btn_row)

        self.refresh()

    def refresh(self):
        info = getattr(self.page, "_last_file_info", None) or {}
        path = info.get("path") or getattr(self.page, "_dtb_detect_path", None) or "—"
        build = self.page._current_build_number()
        dtb_hex = info.get("dtb_hex") or getattr(AppState.current, "dtb_hex", None)

        filename = os.path.basename(path) if path and path != "—" else "—"
        self.info.setText(
            f"File: {filename}\n"
            f"Build: {build if build else 'Not selected'}"
        )

        if dtb_hex:
            self.status_lbl.setText(f"DTB detected: {dtb_hex}")
            set_tone(self.status_lbl, "#34d399")
            self.status_sub.setText(
                "The JSON sidecar already contains DTB / CR3 metadata. You may re-detect if needed."
            )
            self.run_btn.setText("Re-detect DTB")
        elif build:
            self.status_lbl.setText("DTB / CR3 not found in JSON metadata")
            set_tone(self.status_lbl, "#facc15")
            self.status_sub.setText(
                "Run kernel metadata detection to resolve OS build and DTB/CR3, then write the result into the JSON sidecar."
            )
            self.run_btn.setText("Detect DTB")
        else:
            self.status_lbl.setText("DTB / CR3 not found in JSON metadata")
            set_tone(self.status_lbl, "#facc15")
            self.status_sub.setText(
                "OS build can be resolved automatically. Run kernel metadata detection to update the sidecar JSON."
            )
            self.run_btn.setText("Detect DTB")

    def _run_detection(self):
        self.accept()
        self.page._do_detect_dtb()


class _ConvertPromptDialog(QDialog):
    """RAMDetect-themed prompt for converting raw-style dumps to .dmp."""

    def __init__(self, selected_format: str, parent=None):
        super().__init__(parent)
        self.convert_requested = False

        fmt = str(selected_format or "unknown").strip()
        if fmt and not fmt.startswith(".") and fmt != "unknown":
            fmt = f".{fmt}"

        self.setModal(True)
        self.setWindowTitle("Convert memory dump - RAMDetect")
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFixedSize(600, 350)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        root = QFrame()
        root.setObjectName("convertPromptRoot")
        root.setStyleSheet(
            "QFrame#convertPromptRoot {"
            "  background: #0f172a;"
            "  border: 1px solid rgba(6,182,212,0.78);"
            "  border-radius: 18px;"
            "}"
            "QLabel { background: transparent; border: none; }"
        )
        outer.addWidget(root)

        vb = QVBoxLayout(root)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        header = QFrame()
        header.setObjectName("convertPromptHeader")
        header.setFixedHeight(44)
        header.setStyleSheet(
            "QFrame#convertPromptHeader {"
            "  background: rgba(15,23,42,0.98);"
            "  border: none;"
            "  border-top-left-radius: 18px;"
            "  border-top-right-radius: 18px;"
            "  border-bottom: 1px solid rgba(71,85,105,0.45);"
            "}"
        )
        hr = QHBoxLayout(header)
        hr.setContentsMargins(18, 0, 14, 0)
        hr.setSpacing(10)

        mark = QLabel("•")
        mark.setFont(QFont("Segoe UI", 16, QFont.Bold))
        set_tone(mark, "#06b6d4")
        hr.addWidget(mark)

        title = QLabel("Convert memory dump - RAMDetect")
        title.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(title, "#cbd5e1")
        hr.addWidget(title)
        hr.addStretch()

        close_btn = QPushButton("×")
        close_btn.setFixedSize(30, 30)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setFont(QFont("Segoe UI", 15, QFont.Bold))
        close_btn.setStyleSheet(
            "QPushButton { background: transparent; border: none; border-radius: 10px; color: #e2e8f0; }"
            "QPushButton:hover { background: rgba(248,113,113,0.16); color: #fecaca; }"
            "QPushButton:pressed { background: rgba(127,29,29,0.45); }"
        )
        close_btn.clicked.connect(self.reject)
        hr.addWidget(close_btn)
        vb.addWidget(header)

        body = QFrame()
        body.setObjectName("convertPromptBody")
        body.setStyleSheet("QFrame#convertPromptBody { background: #0f172a; border: none; }")
        br = QHBoxLayout(body)
        br.setContentsMargins(28, 20, 28, 12)
        br.setSpacing(18)

        icon = QLabel("?")
        icon.setFixedSize(58, 58)
        icon.setAlignment(Qt.AlignCenter)
        icon.setFont(QFont("Segoe UI", 23, QFont.Bold))
        icon.setStyleSheet(
            "QLabel { color: #67e8f9; background: rgba(6,182,212,0.14);"
            " border: 2px solid rgba(6,182,212,0.55); border-radius: 29px; }"
        )
        br.addWidget(icon, alignment=Qt.AlignTop)

        text_col = QVBoxLayout()
        text_col.setSpacing(8)

        heading = QLabel("Convert memory dump")
        heading.setFont(QFont("Segoe UI", 18, QFont.Bold))
        set_tone(heading, "#ffffff")
        text_col.addWidget(heading)

        desc = QLabel("RAMDetect needs a .dmp file for analysis.")
        desc.setFont(QFont("Segoe UI", 10))
        set_tone(desc, "#cbd5e1")
        desc.setWordWrap(True)
        text_col.addWidget(desc)

        fmt_lbl = QLabel(f"Selected format: <b>{fmt}</b>")
        fmt_lbl.setFont(QFont("Segoe UI", 10))
        set_tone(fmt_lbl, "#e2e8f0")
        text_col.addWidget(fmt_lbl)

        question = QLabel(
            "Convert this dump to .dmp and save the converted copy inside "
            "the configured session folder?"
        )
        question.setFont(QFont("Segoe UI", 10))
        set_tone(question, "#e2e8f0")
        question.setWordWrap(True)
        text_col.addWidget(question)

        note = QLabel(
            "Original raw-style dump will be preserved; RAMDetect analyses the organised .dmp copy."
        )
        note.setFont(QFont("Segoe UI", 9))
        note.setWordWrap(True)
        note.setStyleSheet(
            "QLabel { color: #facc15; background: rgba(250,204,21,0.07);"
            " border: 1px solid rgba(250,204,21,0.42); border-radius: 9px; padding: 9px 11px; }"
        )
        text_col.addWidget(note)
        br.addLayout(text_col, stretch=1)
        vb.addWidget(body, stretch=1)

        footer = QFrame()
        footer.setObjectName("convertPromptFooter")
        footer.setFixedHeight(68)
        footer.setStyleSheet(
            "QFrame#convertPromptFooter { background: rgba(15,23,42,0.98); border: none;"
            " border-top: 1px solid rgba(71,85,105,0.38);"
            " border-bottom-left-radius: 18px; border-bottom-right-radius: 18px; }"
        )
        fr = QHBoxLayout(footer)
        fr.setContentsMargins(28, 10, 28, 14)
        fr.setSpacing(12)
        fr.addStretch()

        no_btn = QPushButton("No")
        no_btn.setFixedSize(120, 40)
        no_btn.setCursor(Qt.PointingHandCursor)
        no_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        no_btn.setStyleSheet(
            "QPushButton { background: rgba(51,65,85,0.90); border: 1px solid rgba(100,116,139,0.80);"
            " border-radius: 12px; color: #e2e8f0; }"
            "QPushButton:hover { background: rgba(71,85,105,0.95); color: #ffffff; }"
            "QPushButton:pressed { background: rgba(30,41,59,1.0); }"
        )
        no_btn.clicked.connect(self.reject)
        fr.addWidget(no_btn)

        yes_btn = QPushButton("Yes, Convert")
        yes_btn.setFixedSize(170, 40)
        yes_btn.setCursor(Qt.PointingHandCursor)
        yes_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        yes_btn.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #06b6d4, stop:1 #2563eb);"
            " border: none; border-radius: 12px; color: #ffffff; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0891b2, stop:1 #1d4ed8); }"
            "QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0e7490, stop:1 #1e40af); }"
        )
        yes_btn.clicked.connect(self._accept_convert)
        fr.addWidget(yes_btn)
        vb.addWidget(footer)

    def _accept_convert(self):
        self.convert_requested = True
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Acquisition Page
# ─────────────────────────────────────────────────────────────────────────────

class AcquisitionPage(BasePage):
    """Page 2 — RAM Acquisition / File Load."""

    PAGE_TITLE = "RAM Acquisition"

    def __init__(self, main_window, parent=None):
        # BasePage sets up the HeaderBar + self.body; pass show_dashboard=True
        super().__init__(main_window, show_dashboard=True)
        self.setObjectName("AcquisitionPage")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.mw          = main_window
        self._mode       = "file"          # default to file (safer)
        self._validated  = False           # True once file passes validation
        self._worker     = None            # active LiveDumpWorker
        self._pending_convert_path = None  # set when a non-.dmp file is loaded
        self._dtb_detect_path = None       # .dmp path that needs DTB detection
        self._last_file_info = None
        self._profile_required = False
        self._selected_profile_cache = None
        self._profile_dialog_shown_for_path = None
        self._metadata_detect_started_for_path = None

        # Tracks which session is currently represented by the right-side
        # monitor success/error panel. This prevents Dashboard re-run from
        # showing stale completed UI from the previous dump after navigation,
        # while still preserving the completed panel on simple minimise/restore.
        self._monitor_session_id = None
        self._monitor_dump_path = ""

        self._cb_queue: queue.Queue = queue.Queue()
        self._poll_timer = QTimer()
        self._poll_timer.timeout.connect(self._drain_queue)
        self._poll_timer.start(50)         # 50 ms — imperceptible latency

        # Elapsed-time tracking for live acquisition
        self._elapsed_secs  = 0
        self._elapsed_timer = QTimer()
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._elapsed_timer.setInterval(1000)  # 1 second

        # File-size polling for live percentage updates (every 1 s)
        self._output_dir_live = ""   # set just before worker starts
        self._acq_start_time  = 0.0  # epoch seconds — only count files created after this
        self._size_timer = QTimer()
        self._size_timer.timeout.connect(self._poll_dump_size)
        self._size_timer.setInterval(1000)

        # ── Insert ProgressStepper between header (index 0) and body (index 1)
        self._root.insertWidget(1, ProgressStepper(current_step=1))

        # ── Build content inside BasePage's self.body ─────────────────────────
        content = QHBoxLayout(self.body)
        content.setContentsMargins(40, 28, 40, 28)
        content.setSpacing(24)
        # Give the left workflow panel a little more room so the
        # selected-file card and OS-profile selector do not feel cramped.
        content.addLayout(self._build_left(),  stretch=12)
        content.addWidget(self._build_right(), stretch=10)

    # ─────────────────────────────────────────────────────────────────────────
    # Left panel  — mode + config + action button
    # ─────────────────────────────────────────────────────────────────────────

    def _build_left(self) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(16)

        # ── Mode selector ─────────────────────────────────────────────────────
        col.addWidget(_lbl("Acquisition Mode", 13, bold=True, color="#ffffff"))

        mode_row = QHBoxLayout()
        mode_row.setSpacing(12)
        self.live_card = _ModeCard("💾", "Live System",  "Acquire RAM using DumpIt")
        self.file_card = _ModeCard("📄", "Load File",    "Open .dmp / .mem / .raw file")
        self.file_card.set_selected(True)   # default = file mode
        self.live_card.mousePressEvent = lambda e: self._select_mode("live")
        self.file_card.mousePressEvent = lambda e: self._select_mode("file")
        mode_row.addWidget(self.live_card)
        mode_row.addWidget(self.file_card)
        col.addLayout(mode_row)

        # ── Config stacked widget ─────────────────────────────────────────────
        self.config_stack = QStackedWidget()
        self.config_stack.addWidget(self._build_live_panel())   # index 0
        self.config_stack.addWidget(self._build_file_panel())   # index 1
        self.config_stack.setCurrentIndex(1)                    # file by default
        col.addWidget(self.config_stack)

        col.addStretch()

        # ── Action button ─────────────────────────────────────────────────────
        self.action_btn = QPushButton("▶  Load & Analyze")
        self.action_btn.setObjectName("primaryBtn")
        self.action_btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        self.action_btn.setFixedHeight(50)
        self.action_btn.clicked.connect(self._start_acquisition)
        self._set_action_btn_enabled(False)   # starts disabled
        col.addWidget(self.action_btn)

        return col

    # ─────────────────────────────────────────────────────────────────────────
    # Button enable/disable  — CSS :disabled gradient is unreliable in PyQt5;
    # set inline stylesheet directly so the ghost-gradient always renders.
    # ─────────────────────────────────────────────────────────────────────────

    _BTN_ENABLED_STYLE = (
        "QPushButton {"
        "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "    stop:0 #06b6d4, stop:1 #2563eb);"
        "  color: #ffffff; border: none; border-radius: 8px;"
        "  font-weight: 600; font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "    stop:0 #0891b2, stop:1 #1d4ed8);"
        "}"
    )
    _BTN_DISABLED_STYLE = (
        "QPushButton {"
        "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "    stop:0 rgba(6,182,212,0.38), stop:1 rgba(37,99,235,0.38));"
        "  color: rgba(255,255,255,0.32); border: none; border-radius: 8px;"
        "  font-weight: 600; font-size: 13px;"
        "}"
    )

    def _set_action_btn_enabled(self, enabled: bool):
        """Set the action state and let the active theme QSS draw the button.

        Older versions used an inline dark gradient here. That blocked the light
        theme from painting a proper disabled button, so the visual styling is
        now kept in styles_dark.qss / styles_light.qss only.
        """
        self.action_btn.setEnabled(enabled)
        self.action_btn.setStyleSheet("")
        set_variant(self.action_btn, "primary")
        refresh_style(self.action_btn)

    def _set_profile_required_action(self):
        """Use the main action button to reopen the OS-profile popup.

        Keeping the OS-profile selector out of the page layout avoids the
        selected-file card and warning banner overlapping on smaller windows.
        """
        self.action_btn.setText("⚠  Select OS Profile")
        self._set_action_btn_enabled(True)

    def _set_file_action_ready(self, enabled: bool = True):
        """Restore the normal file-analysis action button."""
        self.action_btn.setText("📄  Load File for Analysis")
        self._set_action_btn_enabled(enabled)

    # ── Live acquisition config ───────────────────────────────────────────────

    def _build_live_panel(self) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(14)

        # FIX: Force all items to anchor to the top to prevent layout shifting
        vb.setAlignment(Qt.AlignTop)

        # DumpIt path row
        vb.addWidget(_field_label("DumpIt Executable Path"))
        dumpit_row = QHBoxLayout()
        dumpit_row.setSpacing(8)
        self.dumpit_input = _input("DumpIt.exe", _normalize_path(Config.dumpit_path))
        dumpit_row.addWidget(self.dumpit_input, stretch=1)
        browse_dumpit = QPushButton("📂")
        browse_dumpit.setObjectName("iconBtn")
        set_variant(browse_dumpit, "folderBrowse")
        browse_dumpit.setFixedSize(46, 40)
        browse_dumpit.setFont(QFont("Segoe UI Emoji", 13))
        browse_dumpit.setToolTip("Browse for DumpIt.exe")
        browse_dumpit.clicked.connect(self._browse_dumpit)
        dumpit_row.addWidget(browse_dumpit)
        vb.addLayout(dumpit_row)

        # Output dir row
        vb.addWidget(_field_label("Output Directory"))
        outdir_row = QHBoxLayout()
        outdir_row.setSpacing(8)
        self.outdir_input = _input("dumps/", _canonical_dumps_dir_str())
        outdir_row.addWidget(self.outdir_input, stretch=1)
        browse_out = QPushButton("📂")
        browse_out.setObjectName("iconBtn")
        set_variant(browse_out, "folderBrowse")
        browse_out.setFixedSize(46, 40)
        browse_out.setFont(QFont("Segoe UI Emoji", 13))
        browse_out.setToolTip("Browse for output directory")
        browse_out.clicked.connect(self._browse_output_dir)
        outdir_row.addWidget(browse_out)
        vb.addLayout(outdir_row)

        return w

    # ── File load config ──────────────────────────────────────────────────────

    def _build_file_panel(self) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(12)
        vb.setAlignment(Qt.AlignTop)

        # ── Output directory ──────────────────────────────────────────────────
        vb.addWidget(_field_label("Organise Into Directory"))
        file_outdir_row = QHBoxLayout()
        file_outdir_row.setSpacing(8)
        self.file_outdir_input = _input(
            "Select destination folder…",
            _canonical_dumps_dir_str(),
        )
        file_outdir_row.addWidget(self.file_outdir_input, stretch=1)
        browse_file_out = QPushButton("📂")
        browse_file_out.setObjectName("iconBtn")
        set_variant(browse_file_out, "folderBrowse")
        browse_file_out.setFixedSize(46, 40)
        browse_file_out.setFont(QFont("Segoe UI Emoji", 13))
        browse_file_out.setToolTip("Browse for destination directory")
        browse_file_out.clicked.connect(self._browse_file_output_dir)
        file_outdir_row.addWidget(browse_file_out)
        vb.addLayout(file_outdir_row)

        # ── File selector stack ───────────────────────────────────────────────
        # index 0 — drop zone (idle, no file selected)
        # index 1 — unified selected card (header + divider + detail grid)
        # index 2 — error bar (invalid file)
        self._file_stack = QStackedWidget()
        self._file_stack.setObjectName("AcqFileStack")
        self._file_stack.setMinimumHeight(176)
        self._file_stack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        # ── Page 0: drop zone ─────────────────────────────────────────────────
        self.drop_zone = QFrame()
        self.drop_zone.setObjectName("DropZone")
        self.drop_zone.setAttribute(Qt.WA_StyledBackground, True)
        self.drop_zone.setMinimumHeight(120)
        self.drop_zone.setCursor(Qt.PointingHandCursor)
        self.drop_zone.setAcceptDrops(True)
        set_role(self.drop_zone, "dropZone")
        dz_vb = QVBoxLayout(self.drop_zone)
        dz_vb.setAlignment(Qt.AlignCenter)
        dz_vb.setSpacing(5)
        dz_vb.setContentsMargins(16, 12, 16, 12)

        self._dz_icon = QLabel("📄")
        self._dz_icon.setFont(QFont("Segoe UI", 24))
        self._dz_icon.setAlignment(Qt.AlignCenter)
        set_tone(self._dz_icon, "#64748b")

        self._dz_text = QLabel("Drop file here  or  click to browse")
        self._dz_text.setFont(QFont("Segoe UI", 12))
        self._dz_text.setAlignment(Qt.AlignCenter)
        set_tone(self._dz_text, "#94a3b8")

        dz_fmt = QLabel(".dmp  ·  .mem  ·  .raw")
        dz_fmt.setFont(QFont("Segoe UI", 10))
        dz_fmt.setAlignment(Qt.AlignCenter)
        set_tone(dz_fmt, "#64748b")

        dz_vb.addWidget(self._dz_icon)
        dz_vb.addWidget(self._dz_text)
        dz_vb.addWidget(dz_fmt)
        self.drop_zone.mousePressEvent = lambda e: self._browse_file()
        self.drop_zone.dragEnterEvent  = self._drag_enter
        self.drop_zone.dropEvent       = self._drop_event

        # ── Page 1: unified selected-file card ───────────────────────────────
        self._sel_card = QFrame()
        self._sel_card.setFrameShape(QFrame.NoFrame)
        self._sel_card.setAttribute(Qt.WA_StyledBackground, True)
        self._sel_card.setMinimumHeight(168)
        self._sel_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self._sel_card.setObjectName("selCard")
        sel_vb = QVBoxLayout(self._sel_card)
        sel_vb.setContentsMargins(16, 14, 16, 14)
        sel_vb.setSpacing(6)

        # — top row —
        top_row = QHBoxLayout()
        top_row.setSpacing(12)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setAlignment(Qt.AlignVCenter)

        sel_tick = QLabel("✅")
        sel_tick.setFont(QFont("Segoe UI", 22))
        sel_tick.setFixedSize(36, 36)
        sel_tick.setAlignment(Qt.AlignCenter)
        set_role(sel_tick, "transparent")
        top_row.addWidget(sel_tick, alignment=Qt.AlignVCenter)

        name_widget = QWidget()
        set_role(name_widget, "transparent")
        name_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        name_col = QVBoxLayout(name_widget)
        name_col.setSpacing(2)
        name_col.setContentsMargins(0, 0, 0, 0)
        self._sel_filename = QLabel("—")
        self._sel_filename.setObjectName("SelectedDumpName")
        # Slightly larger selected dump name while keeping the row aligned with
        # the tick, DTB Ready, and Change buttons in both themes.
        self._sel_filename.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(self._sel_filename, "#34d399")
        self._sel_filename.setWordWrap(False)
        self._sel_filename.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        # Do not cap the title too tightly; on 125%/150% DPI the text was
        # vertically clipped while the DTB Ready and Change buttons stayed fine.
        self._sel_filename.setMinimumHeight(26)
        self._sel_filename.setMaximumHeight(36)
        self._sel_filename.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._sel_filename.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._sel_sizemeta = QLabel("—")
        self._sel_sizemeta.setFont(QFont("Segoe UI", 9))
        set_tone(self._sel_sizemeta, "#64748b")
        self._sel_sizemeta.setWordWrap(False)
        self._sel_sizemeta.setMaximumHeight(22)
        name_col.addWidget(self._sel_filename)
        name_col.addWidget(self._sel_sizemeta)
        top_row.addWidget(name_widget, stretch=1, alignment=Qt.AlignVCenter)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.setAlignment(Qt.AlignVCenter)

        self._dtb_popup_btn = QPushButton("DTB")
        self._dtb_popup_btn.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        self._dtb_popup_btn.setFixedHeight(40)
        self._dtb_popup_btn.setFixedWidth(112)
        self._dtb_popup_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        set_variant(self._dtb_popup_btn, "info")
        self._dtb_popup_btn.clicked.connect(self._open_dtb_dialog)
        self._dtb_popup_btn.hide()
        btn_row.addWidget(self._dtb_popup_btn)

        # Wider, DPI-safe button. The previous 90px width clipped the text
        # on high-DPI displays and made "Change" appear off-centre.
        self._change_btn = QPushButton("Change")
        self._change_btn.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        self._change_btn.setFixedHeight(40)
        self._change_btn.setFixedWidth(102)
        self._change_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        set_variant(self._change_btn, "secondary")
        self._change_btn.clicked.connect(self._reset_file_state)
        btn_row.addWidget(self._change_btn)

        top_row.addLayout(btn_row)

        sel_vb.addLayout(top_row)

        # — separator —
        sep = QFrame()
        sep.setObjectName("selSep")
        sep.setFixedHeight(1)
        set_role(sep, "successSeparator")
        sel_vb.addSpacing(10)
        sel_vb.addWidget(sep)
        sel_vb.addSpacing(10)

        # — detail grid (2 columns × 3 rows) —
        def _det_row(key: str, mono: bool = False):
            """Returns value QLabel; appends a key:value row to det_left/det_right."""
            k = QLabel(key + ":")
            k.setFont(QFont("Segoe UI", 10))
            set_tone(k, "#64748b")
            v = QLabel("—")
            v.setFont(QFont("Courier New" if mono else "Segoe UI", 10, QFont.DemiBold))
            set_tone(v, "#cbd5e1")
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            v.setWordWrap(True)
            return k, v

        det_grid = QHBoxLayout()
        det_grid.setSpacing(14)
        det_grid.setContentsMargins(0, 0, 0, 0)

        det_left  = QVBoxLayout(); det_left.setSpacing(4)
        det_right = QVBoxLayout(); det_right.setSpacing(4)

        def _add_row(col, key, mono=False):
            row = QHBoxLayout()
            row.setSpacing(8)
            k, v = _det_row(key, mono)
            row.addWidget(k)
            row.addStretch()
            row.addWidget(v)
            col.addLayout(row)
            return v

        self._det_format = _add_row(det_left,  "Format")
        self._det_size   = _add_row(det_left,  "Size")
        self._det_arch   = _add_row(det_left,  "Architecture")
        self._det_load   = _add_row(det_right, "Est. Load")
        self._det_sha    = _add_row(det_right, "SHA-256", mono=True)
        self._det_md5    = _add_row(det_right, "MD5",    mono=True)

        det_grid.addLayout(det_left,  stretch=1)
        det_grid.addLayout(det_right, stretch=1)
        sel_vb.addLayout(det_grid)

        # ── Convert banner (shown only for non-.dmp files) ────────────────────
        self._conv_banner = QFrame()
        self._conv_banner.setFrameShape(QFrame.NoFrame)
        self._conv_banner.setAttribute(Qt.WA_StyledBackground, True)
        self._conv_banner.setMinimumHeight(72)
        self._conv_banner.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self._conv_banner.hide()
        self._conv_banner.setObjectName("convBanner")
        conv_hl = QHBoxLayout(self._conv_banner)
        conv_hl.setContentsMargins(14, 10, 10, 10)
        conv_hl.setSpacing(10)

        conv_icon = QLabel("⚠")
        conv_icon.setFont(QFont("Segoe UI", 14))
        set_tone(conv_icon, "#facc15")
        conv_hl.addWidget(conv_icon)

        conv_text_col = QVBoxLayout()
        conv_text_col.setSpacing(2)
        self._conv_label = QLabel("This file is not in .dmp format")
        self._conv_label.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(self._conv_label, "#facc15")
        self._conv_label.setWordWrap(True)
        self._conv_sub = QLabel("Convert to .dmp before analysis")
        self._conv_sub.setFont(QFont("Segoe UI", 9))
        set_tone(self._conv_sub, "#94a3b8")
        self._conv_sub.setWordWrap(True)
        conv_text_col.addWidget(self._conv_label)
        conv_text_col.addWidget(self._conv_sub)
        conv_hl.addLayout(conv_text_col, stretch=1)

        self._conv_btn = QPushButton("Convert to .dmp")
        self._conv_btn.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        self._conv_btn.setFixedHeight(34)
        self._conv_btn.setMinimumWidth(140)
        set_variant(self._conv_btn, "warning")
        self._conv_btn.clicked.connect(self._do_convert)
        conv_hl.addWidget(self._conv_btn, alignment=Qt.AlignVCenter)

        sel_vb.addSpacing(6)
        sel_vb.addWidget(self._conv_banner)

        # ── DTB detection banner (shown when build exists but dtb_hex is missing) ──
        self._dtb_banner = QFrame()
        self._dtb_banner.setFrameShape(QFrame.NoFrame)
        self._dtb_banner.setAttribute(Qt.WA_StyledBackground, True)
        self._dtb_banner.setMinimumHeight(74)
        self._dtb_banner.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self._dtb_banner.hide()
        self._dtb_banner.setObjectName("dtbBanner")
        dtb_hl = QHBoxLayout(self._dtb_banner)
        dtb_hl.setContentsMargins(14, 10, 10, 10)
        dtb_hl.setSpacing(10)

        dtb_icon = QLabel("🔑")
        dtb_icon.setFont(QFont("Segoe UI", 14))
        set_tone(dtb_icon, "#06b6d4")
        dtb_hl.addWidget(dtb_icon)

        dtb_text_col = QVBoxLayout()
        dtb_text_col.setSpacing(2)
        self._dtb_label = QLabel("DTB/CR3 not found in metadata")
        self._dtb_label.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(self._dtb_label, "#06b6d4")
        self._dtb_label.setWordWrap(True)
        self._dtb_sub = QLabel("Run kernel metadata detection before analysis for raw/VMEM-style dumps.")
        self._dtb_sub.setFont(QFont("Segoe UI", 9))
        set_tone(self._dtb_sub, "#94a3b8")
        self._dtb_sub.setWordWrap(True)
        dtb_text_col.addWidget(self._dtb_label)
        dtb_text_col.addWidget(self._dtb_sub)
        dtb_hl.addLayout(dtb_text_col, stretch=1)

        self._dtb_btn = QPushButton("Detect DTB")
        self._dtb_btn.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        self._dtb_btn.setFixedHeight(34)
        self._dtb_btn.setMinimumWidth(120)
        set_variant(self._dtb_btn, "info")
        self._dtb_btn.clicked.connect(self._do_detect_dtb)
        dtb_hl.addWidget(self._dtb_btn, alignment=Qt.AlignVCenter)

        sel_vb.addSpacing(6)
        sel_vb.addWidget(self._dtb_banner)

        # ── Page 2: error bar ─────────────────────────────────────────────────
        self._err_bar = QFrame()
        self._err_bar.setMinimumHeight(80)
        set_role(self._err_bar, "dangerCard")
        err_hl = QHBoxLayout(self._err_bar)
        err_hl.setContentsMargins(18, 0, 14, 0)
        err_hl.setSpacing(14)

        err_icon = QLabel("❌")
        err_icon.setFont(QFont("Segoe UI", 22))
        err_icon.setAlignment(Qt.AlignCenter)
        set_role(err_icon, "transparent")
        err_hl.addWidget(err_icon)

        err_text_col = QVBoxLayout()
        err_text_col.setSpacing(3)
        err_text_col.setAlignment(Qt.AlignVCenter)
        self._err_reason = QLabel("Invalid file")
        self._err_reason.setFont(QFont("Segoe UI", 11, QFont.DemiBold))
        set_tone(self._err_reason, "#f87171")
        self._err_reason.setWordWrap(True)
        err_hint = QLabel("Try a different file or check the format.")
        err_hint.setFont(QFont("Segoe UI", 10))
        set_tone(err_hint, "#64748b")
        err_text_col.addWidget(self._err_reason)
        err_text_col.addWidget(err_hint)
        err_hl.addLayout(err_text_col, stretch=1)

        retry_btn = QPushButton("↺ Retry")
        retry_btn.setObjectName("AcqRetryButton")
        retry_btn.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        retry_btn.setFixedSize(86, 30)
        set_variant(retry_btn, "secondary")
        retry_btn.clicked.connect(self._reset_file_state)
        err_hl.addWidget(retry_btn, alignment=Qt.AlignVCenter)

        # Assemble stack
        self._file_stack.addWidget(self.drop_zone)   # 0 — idle
        self._file_stack.addWidget(self._sel_card)   # 1 — valid
        self._file_stack.addWidget(self._err_bar)    # 2 — error
        self._file_stack.setCurrentIndex(0)
        vb.addWidget(self._file_stack)

        # ── OS profile notice stub ────────────────────────────────────────────
        # Kept for backward compatibility, but hidden by design.
        # The OS profile selection now happens through a modal popup and the
        # main action button, preventing overlap with the selected-file card.
        self._profile_panel = QFrame()
        self._profile_panel.setFixedHeight(0)
        self._profile_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._profile_panel.hide()
        self._profile_panel.setStyleSheet(
            "QFrame { background: rgba(250,204,21,0.07);"
            "  border: 1px solid rgba(250,204,21,0.35); border-radius: 8px; }"
            "QLabel { border: none; background: transparent; }"
        )
        prof_row = QHBoxLayout(self._profile_panel)
        prof_row.setContentsMargins(14, 8, 12, 8)
        prof_row.setSpacing(12)

        prof_icon = QLabel("⚠")
        prof_icon.setFont(QFont("Segoe UI", 15, QFont.Bold))
        prof_icon.setAlignment(Qt.AlignCenter)
        set_tone(prof_icon, "#facc15")
        prof_row.addWidget(prof_icon)

        prof_text_col = QVBoxLayout()
        prof_text_col.setSpacing(2)
        self._profile_label = QLabel("OS profile required before analysis")
        self._profile_label.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        set_tone(self._profile_label, "#facc15")
        self._profile_label.setWordWrap(True)

        self._profile_hint = QLabel("Select the Windows build so RAMDetect can save a sidecar JSON and load correct parsing offsets.")
        self._profile_hint.setFont(QFont("Segoe UI", 9))
        self._profile_hint.setWordWrap(True)
        set_tone(self._profile_hint, "#94a3b8")

        prof_text_col.addWidget(self._profile_label)
        prof_text_col.addWidget(self._profile_hint)
        prof_row.addLayout(prof_text_col, stretch=1)

        self._profile_btn = QPushButton("Select OS Profile")
        self._profile_btn.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        self._profile_btn.setFixedHeight(34)
        self._profile_btn.setMinimumWidth(150)
        set_variant(self._profile_btn, "warning")
        self._profile_btn.clicked.connect(self._open_profile_dialog)
        prof_row.addWidget(self._profile_btn, alignment=Qt.AlignVCenter)
        vb.addWidget(self._profile_panel)

        # Keep val_card as hidden stub so existing code references don't crash
        self.val_card = _ValidationCard()

        return w

    # ─────────────────────────────────────────────────────────────────────────
    # Right panel  — progress monitor
    # ─────────────────────────────────────────────────────────────────────────

    def _build_right(self) -> QFrame:
        card = _card(12)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        vb = QVBoxLayout(card)
        vb.setContentsMargins(22, 18, 22, 10)
        vb.setSpacing(12)

        # Header
        hdr_row = QHBoxLayout()
        self._monitor_title = _lbl("Progress Monitor", 14, bold=True, color="#ffffff")
        hdr_row.addWidget(self._monitor_title)
        hdr_row.addStretch()
        self._duration_badge = QLabel("")
        self._duration_badge.setObjectName("DurationBadge")
        self._duration_badge.setAttribute(Qt.WA_StyledBackground, True)
        self._duration_badge.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self._duration_badge.hide()
        hdr_row.addWidget(self._duration_badge)
        vb.addLayout(hdr_row)

        # ── Idle state ────────────────────────────────────────────────────────
        idle = QWidget()
        set_role(idle, "transparent")
        idle_outer = QVBoxLayout(idle)
        idle_outer.setAlignment(Qt.AlignCenter)
        idle_outer.setContentsMargins(0, 0, 0, 0)

        idle_inner = QVBoxLayout()
        idle_inner.setAlignment(Qt.AlignCenter)
        idle_inner.setSpacing(10)

        idle_icon = _lbl("📡", 40, color="#2d3f55")
        idle_icon.setAlignment(Qt.AlignCenter)
        idle_title = _lbl("Ready to acquire", 14, bold=True, color="#475569")
        idle_title.setAlignment(Qt.AlignCenter)
        idle_sub = _lbl("Select a file or configure DumpIt, then press Acquire.", 11, color="#64748b")
        idle_sub.setAlignment(Qt.AlignCenter)
        idle_sub.setWordWrap(True)

        idle_inner.addWidget(idle_icon)
        idle_inner.addWidget(idle_title)
        idle_inner.addWidget(idle_sub)
        idle_outer.addLayout(idle_inner)

        # ── Active state (live dump in progress) ──────────────────────────────
        active = QWidget()
        set_role(active, "transparent")
        act_vb = QVBoxLayout(active)
        act_vb.setAlignment(Qt.AlignTop)
        act_vb.setContentsMargins(0, 0, 0, 0)
        act_vb.setSpacing(12)

        self.pct_label = QLabel("0%")
        self.pct_label.setFont(QFont("Segoe UI", 44, QFont.Bold))
        self.pct_label.setAlignment(Qt.AlignCenter)
        set_tone(self.pct_label, "#06b6d4")
        act_vb.addWidget(self.pct_label)

        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setFixedHeight(12)
        self.prog_bar.setTextVisible(False)
        act_vb.addWidget(self.prog_bar)

        act_vb.addSpacing(4)

        def _act_info_row(key: str) -> QLabel:
            """Creates a card row (label: value) and returns the value QLabel."""
            row = QFrame()
            row.setObjectName("AcqInfoRow")
            row.setFrameShape(QFrame.NoFrame)
            row.setAttribute(Qt.WA_StyledBackground, True)
            row.setMinimumHeight(44)
            row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(14, 9, 14, 9)
            k_lbl = QLabel(key)
            k_lbl.setFont(QFont("Segoe UI", 10))
            set_tone(k_lbl, "#64748b")
            v_lbl = QLabel("—")
            v_lbl.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
            v_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            set_tone(v_lbl, "#06b6d4")
            rl.addWidget(k_lbl)
            rl.addStretch()
            rl.addWidget(v_lbl)
            act_vb.addWidget(row)
            return v_lbl

        self.status_lbl   = _act_info_row("Status")
        self.act_size_lbl = _act_info_row("Estimated Size")
        self.act_time_lbl = _act_info_row("Elapsed Time")

        # ── Success state ─────────────────────────────────────────────────────
        succ = QWidget()
        set_role(succ, "transparent")
        succ_vb = QVBoxLayout(succ)
        succ_vb.setContentsMargins(0, 0, 0, 0)
        succ_vb.setSpacing(6)

        # Banner
        banner = QFrame()
        banner.setObjectName("AcqSuccessBanner")
        banner.setFrameShape(QFrame.NoFrame)
        banner.setAttribute(Qt.WA_StyledBackground, True)
        ban_row = QHBoxLayout(banner)
        ban_row.setContentsMargins(12, 8, 12, 8)
        ban_row.setSpacing(9)
        ban_row.setAlignment(Qt.AlignVCenter)
        ban_icon = QLabel("✅")
        ban_icon.setFont(QFont("Segoe UI", 14))
        ban_icon.setAlignment(Qt.AlignCenter)
        set_role(ban_icon, "transparent")
        ban_col = QVBoxLayout()
        ban_col.setSpacing(2)
        ban_title = QLabel("Acquisition Complete")
        ban_title.setFont(QFont("Segoe UI", 9, QFont.Bold))
        set_tone(ban_title, "#34d399")
        ban_sub = QLabel("Memory dump saved successfully")
        ban_sub.setFont(QFont("Segoe UI", 8))
        set_tone(ban_sub, "#94a3b8")
        ban_col.addWidget(ban_title)
        ban_col.addWidget(ban_sub)
        ban_row.addWidget(ban_icon)
        ban_row.addLayout(ban_col, stretch=1)
        succ_vb.addWidget(banner)

        def _info_card(label_text: str, compact: bool = False):
            """Returns (card_frame, value_label).

            Success monitor values can be long paths/hashes, so values are
            single-line, selectable, and tooltip-backed instead of wrapping
            into clipped rows.
            """
            card = QFrame()
            card.setObjectName("AcqResultCard")
            card.setFrameShape(QFrame.NoFrame)
            card.setAttribute(Qt.WA_StyledBackground, True)
            card.setFixedHeight(44 if compact else 48)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            cv = QVBoxLayout(card)
            cv.setContentsMargins(12, 5, 12, 5)
            cv.setSpacing(1)

            lbl_key = QLabel(label_text)
            lbl_key.setFont(QFont("Segoe UI", 8))
            set_tone(lbl_key, "#64748b")

            lbl_val = QLabel("—")
            lbl_val.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
            set_tone(lbl_val, "#e2e8f0")
            lbl_val.setWordWrap(False)
            lbl_val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lbl_val.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

            cv.addWidget(lbl_key)
            cv.addWidget(lbl_val)
            return card, lbl_val

        fn_card,  self._succ_filename = _info_card("Filename", compact=True)
        succ_vb.addWidget(fn_card)

        grid2 = QHBoxLayout()
        grid2.setSpacing(8)
        sz_card,  self._succ_size     = _info_card("Size", compact=True)
        dur_card, self._succ_duration = _info_card("Duration", compact=True)
        grid2.addWidget(sz_card)
        grid2.addWidget(dur_card)
        succ_vb.addLayout(grid2)

        ts_card,   self._succ_time = _info_card("Timestamp", compact=True)
        path_card, self._succ_path = _info_card("Path", compact=True)
        # Show a compact, single-line path in the right monitor panel. The full
        # path stays in the tooltip to avoid uneven card height and overlap with
        # the SHA-256/MD5 cards.
        path_card.setFixedHeight(46)
        self._succ_path.setObjectName("AcqPathValue")
        self._succ_path.setFont(QFont("Segoe UI", 8, QFont.DemiBold))
        self._succ_path.setWordWrap(False)
        self._succ_path.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._succ_path.setMinimumHeight(14)
        self._succ_path.setMaximumHeight(18)
        self._succ_path.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        set_tone(self._succ_path, "#64748b")

        sha_card,  self._succ_sha  = _info_card("SHA-256", compact=True)
        self._succ_sha.setFont(QFont("Consolas", 8))
        set_tone(self._succ_sha, "#94a3b8")

        md5_card,  self._succ_md5  = _info_card("MD5", compact=True)
        self._succ_md5.setFont(QFont("Consolas", 8))
        set_tone(self._succ_md5, "#94a3b8")

        succ_vb.addWidget(ts_card)
        succ_vb.addWidget(path_card)
        succ_vb.addWidget(sha_card)
        succ_vb.addWidget(md5_card)

        # Continue button — hardcode gradient so it is NEVER transparent
        _PROCEED_STYLE = (
            "QPushButton {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #06b6d4, stop:1 #2563eb);"
            "  color: #ffffff; border: none; border-radius: 8px;"
            "  font-weight: 700; font-size: 13px;"
            "}"
            "QPushButton:hover {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #0891b2, stop:1 #1d4ed8);"
            "}"
            "QPushButton:pressed {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #0e7490, stop:1 #1e40af);"
            "}"
        )
        self.continue_btn_inner = QPushButton("Proceed to Analysis  →")
        self.continue_btn_inner.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        self.continue_btn_inner.setFixedHeight(40)
        self.continue_btn_inner.setEnabled(True)
        self.continue_btn_inner.setStyleSheet(_PROCEED_STYLE)
        self.continue_btn_inner.clicked.connect(self._go_to_analysis)
        succ_vb.addWidget(self.continue_btn_inner)

        self._meta_rows: list = []   # kept for API compatibility

        # ── Error state ───────────────────────────────────────────────────────
        err = QWidget()
        set_role(err, "transparent")
        err_vb = QVBoxLayout(err)
        err_vb.setAlignment(Qt.AlignCenter)
        err_vb.setSpacing(10)
        icon_lbl = _lbl("❌", 40, color="#f87171")
        icon_lbl.setAlignment(Qt.AlignCenter)
        err_vb.addWidget(icon_lbl)
        title_lbl = _lbl("Acquisition Failed", 16, bold=True, color="#f87171")
        title_lbl.setAlignment(Qt.AlignCenter)
        err_vb.addWidget(title_lbl)
        self._err_lbl = _lbl("", 11, color="#f87171")
        self._err_lbl.setWordWrap(True)
        self._err_lbl.setAlignment(Qt.AlignCenter)
        err_vb.addWidget(self._err_lbl)
        retry_btn = QPushButton("↺  Try Again")
        retry_btn.setObjectName("iconBtn")
        retry_btn.setFont(QFont("Segoe UI", 12))
        retry_btn.setFixedSize(130, 38)
        retry_btn.clicked.connect(self._reset_monitor)
        err_vb.addWidget(retry_btn, alignment=Qt.AlignCenter)

        # Stack:  0=idle  1=active  2=success  3=error
        self.monitor_stack = QStackedWidget()
        self.monitor_stack.addWidget(idle)
        self.monitor_stack.addWidget(active)
        self.monitor_stack.addWidget(succ)
        self.monitor_stack.addWidget(err)
        vb.addWidget(self.monitor_stack, stretch=1)

        # continue_btn is embedded in the success state; alias for compat.
        self.continue_btn = self.continue_btn_inner

        return card

    def _is_acquisition_busy(self) -> bool:
        """Return True when an acquisition-related worker/timer is active.

        _on_show() uses this guard to avoid resetting the Acquisition page
        while live acquisition, file organisation, conversion, or metadata
        resolution is in progress. This method is intentionally defensive
        because some widgets/timers may not exist during early page setup.
        """
        try:
            # Active worker, for example live DumpIt worker.
            if getattr(self, "_worker", None) is not None:
                return True

            # Live acquisition timers.
            elapsed_timer = getattr(self, "_elapsed_timer", None)
            if elapsed_timer is not None and elapsed_timer.isActive():
                return True

            size_timer = getattr(self, "_size_timer", None)
            if size_timer is not None and size_timer.isActive():
                return True

            # Active/progress monitor page means file organisation/conversion
            # is currently showing progress.
            monitor_stack = getattr(self, "monitor_stack", None)
            if monitor_stack is not None and monitor_stack.currentIndex() == 1:
                return True

            # DTB resolver is running when the DTB popup button exists but is disabled.
            dtb_btn = getattr(self, "_dtb_popup_btn", None)
            if dtb_btn is not None and dtb_btn.isVisible() and not dtb_btn.isEnabled():
                return True

        except Exception:
            # Never allow this guard to crash the UI.
            return False

        return False

    # ─────────────────────────────────────────────────────────────────────────
    # Mode switching
    # ─────────────────────────────────────────────────────────────────────────

    def _select_mode(self, mode: str):
        # Cancel any running live acquisition
        if self._worker:
            self._worker.cancel()
            self._worker = None

        self._mode = mode
        self.live_card.set_selected(mode == "live")
        self.file_card.set_selected(mode == "file")
        self.config_stack.setCurrentIndex(0 if mode == "live" else 1)

        if mode == "live":
            self.action_btn.setText("💾  Acquire Live Memory Dump")
            self._set_action_btn_enabled(True)
        else:
            self.action_btn.setText("📄  Load File for Analysis")
            self._set_action_btn_enabled(False)   # must re-select a file

        # Always wipe file-selection state so stale validation never carries over
        self._reset_file_state()
        self._reset_monitor()

    # ─────────────────────────────────────────────────────────────────────────
    # File state reset
    # ─────────────────────────────────────────────────────────────────────────

    def _reset_file_state(self):
        """Return the file selector to idle (drop zone)."""
        self._validated = False
        self._last_file_info = None
        self._profile_required = False
        self._selected_profile_cache = None
        if hasattr(self, "_profile_panel"):
            self._profile_panel.hide()
        if hasattr(self, "_dtb_popup_btn"):
            self._dtb_popup_btn.hide()
        if hasattr(self, "_profile_label"):
            self._profile_label.setText("OS profile required before analysis")
        if hasattr(self, "_profile_hint"):
            self._profile_hint.setText("Select the Windows build so RAMDetect can save a sidecar JSON and load correct parsing offsets.")
        if hasattr(self, "_profile_btn"):
            self._profile_btn.setText("Select OS Profile")
        if self._mode == "file" and hasattr(self, "action_btn"):
            self.action_btn.setText("📄  Load File for Analysis")
        if hasattr(self, "_file_stack"):
            self._file_stack.setFixedHeight(176)
        if hasattr(self, "_sel_card"):
            self._sel_card.setMinimumHeight(168)
        self._file_stack.setCurrentIndex(0)
        set_role(self.drop_zone, "dropZone")
        self._dz_icon.setText("📄")
        set_tone(self._dz_icon, "#64748b")
        self._dz_text.setText("Drop file here  or  click to browse")
        set_tone(self._dz_text, "#94a3b8")

        self.action_btn.show()

        # FIX: Live mode does not need file validation, so keep button enabled.
        # File mode still requires selecting and validating a dump file first.
        if self._mode == "live":
            self._set_action_btn_enabled(True)
        else:
            self._set_action_btn_enabled(False)

    # ─────────────────────────────────────────────────────────────────────────
    # File browsing + drag-drop
    # ─────────────────────────────────────────────────────────────────────────

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Memory Dump", "",
            "Memory Dumps (*.dmp *.raw *.bin *.mem *.vmem *.lime);;All Files (*)"
        )
        if path:
            self._load_file(path)

    def _drag_enter(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.drop_zone.setStyleSheet(
                "QFrame { background: rgba(6,182,212,0.06);"
                "  border: 2px dashed #06b6d4; border-radius: 12px; }"
                "QLabel { border: none; background: transparent; }"
            )

    def _drop_event(self, event):
        set_role(self.drop_zone, "dropZone")
        urls = event.mimeData().urls()
        if urls:
            self._load_file(urls[0].toLocalFile())

    def _get_profile_choices(self) -> list[dict]:
        """Return supported OS profiles from bridge, with a safe fallback list."""
        try:
            profiles = AcquisitionBridge.get_os_profiles()
            profiles = [p for p in profiles if isinstance(p, dict) and p.get("build_number")]
            if profiles:
                return profiles
        except Exception:
            pass
        return [
            {"label": "Windows 10 20H1/2004 — build 19041", "build_number": 19041, "version": "10.0.19041", "os": "Microsoft Windows 10"},
            {"label": "Windows 10 21H2 — build 19044", "build_number": 19044, "version": "10.0.19044", "os": "Microsoft Windows 10"},
            {"label": "Windows 10 22H2 — build 19045", "build_number": 19045, "version": "10.0.19045", "os": "Microsoft Windows 10"},
            {"label": "Windows 11 21H2 — build 22000", "build_number": 22000, "version": "10.0.22000", "os": "Microsoft Windows 11"},
            {"label": "Windows 11 22H2/23H2 — build 22621/22631", "build_number": 22621, "version": "10.0.22621", "os": "Microsoft Windows 11"},
            {"label": "Windows 11 24H2 — build 26100", "build_number": 26100, "version": "10.0.26100", "os": "Microsoft Windows 11"},
            {"label": "Windows 11 Insider/Canary — build 26200", "build_number": 26200, "version": "10.0.26200", "os": "Microsoft Windows 11"},
        ]

    def _selected_profile(self) -> dict | None:
        """Return the selected manual OS profile, or None if not selected."""
        data = self._selected_profile_cache
        return data if isinstance(data, dict) and data.get("build_number") else None

    def _current_build_number(self) -> int | None:
        """Best-effort build number from selected profile, validation info, or session."""
        prof = self._selected_profile()
        if prof and prof.get("build_number"):
            return int(prof.get("build_number"))
        if self._last_file_info and self._last_file_info.get("build_number"):
            return int(self._last_file_info.get("build_number"))
        sess = AppState.current
        if getattr(sess, "build_number", None):
            return int(sess.build_number)
        return None

    def _set_dtb_button_state(self, state: str, text: str | None = None, tooltip: str | None = None):
        """Set the small DTB button beside Change.

        States:
            missing  -> red button, DTB is absent and action is needed
            ready    -> default/slate button, DTB already exists
            scanning -> cyan button, scanner is currently running
            hidden   -> hide button
        """
        if not hasattr(self, "_dtb_popup_btn"):
            return

        if state == "hidden":
            self._dtb_popup_btn.hide()
            return

        self._dtb_popup_btn.show()
        if text is not None:
            self._dtb_popup_btn.setText(text)
        if tooltip is not None:
            self._dtb_popup_btn.setToolTip(tooltip)

        if state == "missing":
            self._dtb_popup_btn.setEnabled(True)
            self._dtb_popup_btn.setStyleSheet(
                "QPushButton { background: rgba(248,113,113,0.16);"
                "  border: 1px solid rgba(248,113,113,0.60); border-radius: 8px; color: #f87171;"
                "  padding: 0px 14px; text-align: center; font-weight: 700; }"
                "QPushButton:hover { background: rgba(248,113,113,0.28); color: #ffffff; }"
            )
        elif state == "scanning":
            # Grey disabled state while the DTB scanner is running.
            self._dtb_popup_btn.setEnabled(False)
            self._dtb_popup_btn.setStyleSheet(
                "QPushButton { background: rgba(51,65,85,0.45);"
                "  border: 1px solid rgba(100,116,139,0.55); border-radius: 8px; color: #94a3b8;"
                "  padding: 0px 14px; text-align: center; font-weight: 700; }"
            )
        else:
            # Blue ready state when DTB already exists.
            self._dtb_popup_btn.setEnabled(True)
            self._dtb_popup_btn.setStyleSheet(
                "QPushButton { background: rgba(14,165,233,0.16);"
                "  border: 1px solid rgba(14,165,233,0.55); border-radius: 8px; color: #38bdf8;"
                "  padding: 0px 14px; text-align: center; font-weight: 700; }"
                "QPushButton:hover { background: rgba(14,165,233,0.28); color: #ffffff; }"
            )

    def _refresh_dtb_banner(self):
        """Control DTB popup-button state instead of showing an inline banner."""
        if hasattr(self, "_dtb_banner"):
            self._dtb_banner.hide()

        self._dtb_detect_path = None

        if not self._last_file_info or getattr(self, "_pending_convert_path", None):
            self._set_dtb_button_state("hidden")
            return

        info = self._last_file_info
        path = info.get("path")
        dtb_hex = info.get("dtb_hex")
        build = self._current_build_number()

        if not path:
            self._set_dtb_button_state("hidden")
            return

        self._dtb_detect_path = path

        if dtb_hex:
            self._set_dtb_button_state(
                "ready",
                text="DTB Ready",
                tooltip=f"DTB already detected: {dtb_hex}. Click to view details or re-detect.",
            )
        elif build:
            self._set_dtb_button_state(
                "missing",
                text="Detect DTB",
                tooltip="DTB / CR3 is missing. Click to open the kernel metadata detection popup.",
            )
        else:
            self._set_dtb_button_state(
                "missing",
                text="DTB",
                tooltip="Open the DTB popup to resolve OS profile and kernel DTB/CR3.",
            )

    def _open_profile_dialog(self):
        """Open the modal OS profile dialog and apply the chosen build."""
        dlg = _OSProfileDialog(
            profiles=self._get_profile_choices(),
            current_profile=self._selected_profile(),
            parent=self,
        )
        if dlg.exec_() == QDialog.Accepted and dlg.selected_profile:
            self._apply_selected_profile(dlg.selected_profile)

    def _apply_selected_profile(self, profile: dict | None):
        """Enable conversion/analysis once a required profile is selected."""
        self._selected_profile_cache = profile

        if profile:
            build = profile.get("build_number")
            label = profile.get("label", f"Windows build {build}")
            if hasattr(self, "_det_arch"):
                self._det_arch.setText(f"x64 {label}")

            # Persist the selected profile into the current sidecar JSON
            # immediately. This is the important handoff: Real-Time Analysis
            # later reads build_number from the JSON, not from this UI label.
            try:
                current_path = None
                if getattr(self, "_pending_convert_path", None):
                    current_path = self._pending_convert_path
                elif getattr(self, "_last_file_info", None):
                    current_path = self._last_file_info.get("path")
                elif AppState.current and getattr(AppState.current, "dump_path", None):
                    current_path = AppState.current.dump_path

                if (
                    current_path
                    and hasattr(AcquisitionBridge, "update_json_profile")
                    and _is_inside_canonical_dumps(current_path)
                ):
                    result = AcquisitionBridge.update_json_profile(
                        current_path,
                        selected_profile=profile,
                    )
                    if result.get("success"):
                        if getattr(self, "_last_file_info", None) is not None:
                            self._last_file_info["json_path"] = result.get("json_path")
                            self._last_file_info["build_number"] = result.get("build")
                        sess = AppState.current
                        sess.build_number = result.get("build")
                        sess.architecture = f"x64 {label}"
                elif current_path:
                    # The selected dump is still outside RAMDetect's managed
                    # dumps/<session> folder. Do not create a sidecar JSON next
                    # to the user's original dump. The selected profile is cached
                    # and will be written after the file is organized into ./dumps.
                    if getattr(self, "_last_file_info", None) is not None:
                        self._last_file_info["build_number"] = build
                    sess = AppState.current
                    sess.build_number = build
                    sess.architecture = f"x64 {label}"
            except Exception as exc:
                print(f"[AcquisitionPage] profile sidecar update warning: {exc}")

            # Do not show an inline profile banner; it caused visual overlap with
            # the selected-file card on smaller layouts. The profile is shown in
            # the Architecture row and in the conversion banner where relevant.
            if hasattr(self, "_profile_panel"):
                self._profile_panel.hide()
            if hasattr(self, "_profile_label"):
                self._profile_label.setText("OS profile selected")
            if hasattr(self, "_profile_hint"):
                self._profile_hint.setText(f"{label} will be saved into the JSON sidecar.")
            if hasattr(self, "_profile_btn"):
                self._profile_btn.setText("Change Profile")
            if getattr(self, "_pending_convert_path", None):
                self._conv_btn.setEnabled(True)
                self._conv_sub.setText("Selected profile will be saved into the JSON sidecar")
                self._validated = False
                self.action_btn.setText("📄  Convert file first")
                self._set_action_btn_enabled(False)
            elif self._last_file_info and self._last_file_info.get("valid"):
                self._validated = True
                self._set_file_action_ready(True)
            self._refresh_dtb_banner()
        else:
            if getattr(self, "_profile_required", False):
                if hasattr(self, "_profile_panel"):
                    self._profile_panel.hide()
                if getattr(self, "_pending_convert_path", None):
                    self._conv_btn.setEnabled(False)
                    self._conv_sub.setText("Select the correct Windows build before converting")
                self._validated = False
                self._set_profile_required_action()

    def _on_profile_changed(self):
        """Compatibility hook retained for older signal wiring."""
        self._apply_selected_profile(self._selected_profile())

    def _load_file(self, path: str):
        """Validate file and populate the unified selected-file card.
        Auto-detects non-.dmp extensions and shows a conversion banner."""
        self._dz_text.setText("Validating…")
        self._dz_icon.setText("⏳")

        info = AcquisitionBridge.validate_file(path)

        if info["valid"]:
            self._last_file_info = info
            self._profile_required = bool(info.get("profile_required", False))
            # Populate the unified card labels
            _display_filename = _short_middle(info["filename"], 44)
            self._sel_filename.setText(_display_filename)
            self._sel_filename.setToolTip(info["filename"])
            self._sel_sizemeta.setText(
                f"{info.get('size_str','—')}  ·  {info.get('format','—')}"
            )
            sha = info.get("sha256", "—")
            md5 = info.get("md5",    "—")
            self._det_format.setText(info.get("format",       "—"))
            self._det_size.setText(  info.get("size_str",     "—"))
            self._det_arch.setText(  info.get("architecture", "—"))
            self._det_load.setText(  info.get("est_load_time","—"))
            self._det_sha.setText(   (sha[:18] + "…") if sha and sha != "—" else "—")
            self._det_md5.setText(   (md5[:18] + "…") if md5 and md5 != "—" else "—")

            # Switch to the unified card (index 1)
            self._file_stack.setCurrentIndex(1)

            # ── Detect extension — show convert banner for non-.dmp files ─────
            import os as _os
            ext = _os.path.splitext(path)[1].lower()
            _NON_DMP = {".raw", ".mem", ".vmem", ".bin", ".lime"}

            # Phase 6A: raw-style dumps no longer require a manual profile at
            # selection time. Convert first; the converted .dmp will then run
            # automatic kernel metadata resolution.
            if ext in _NON_DMP:
                self._profile_required = False

            metadata_missing = bool(info.get("profile_required", False)) or not bool(info.get("dtb_hex"))

            # Phase 6A: do not force manual OS profile selection. If build/DTB is
            # missing, automatically run the kernel metadata resolver in the
            # background. The UI remains neutral and file loading stays lightweight.
            self._profile_required = False
            self._profile_panel.hide()

            # Only auto-resolve metadata for .dmp files. Raw/vmem/bin/lime files
            # should be converted first, then the converted .dmp will be loaded
            # again and metadata resolution will run for that .dmp.
            if metadata_missing and ext not in _NON_DMP:
                if self._metadata_detect_started_for_path != path:
                    self._metadata_detect_started_for_path = path
                    QTimer.singleShot(180, self._do_detect_dtb)

            if ext in _NON_DMP:
                # Do not show the large inline conversion banner; on smaller
                # screens it squeezes the selected-file card. Ask with a popup
                # and then organise+convert directly into dumps/<session>/.
                self._file_stack.setFixedHeight(176)
                self._sel_card.setMinimumHeight(168)
                self._conv_banner.hide()
                self._validated = False
                self._pending_convert_path = path
                self.action_btn.setText("📄  Convert required")
                self._set_action_btn_enabled(False)
                QTimer.singleShot(220, self._ask_convert_non_dmp)
            else:
                self._file_stack.setFixedHeight(176)
                self._sel_card.setMinimumHeight(168)
                self._conv_banner.hide()
                self._pending_convert_path = None
                self._validated = True
                self._set_file_action_ready(True)

            self._refresh_dtb_banner()

            # FIX #4: populate proper ScanSession fields — no more ad-hoc attrs
            sess = AppState.current
            sess.dump_path       = info["path"]
            sess.dump_filename   = info["filename"]
            sess.dump_size_bytes = info["size_bytes"]
            sess.mode            = "file"
            sess.sha256          = info.get("sha256", "")
            sess.md5             = info.get("md5",    "")
            sess.dump_format     = info.get("format", "")
            sess.architecture    = info.get("architecture", "")
            if info.get("build_number"):
                sess.build_number = int(info.get("build_number"))

        else:
            self._err_reason.setText(info.get("error", "Validation failed"))
            self._file_stack.setCurrentIndex(2)
            self._validated = False
            self._set_action_btn_enabled(False)

    # ─────────────────────────────────────────────────────────────────────────
    # Auto-convert non-.dmp → .dmp
    # ─────────────────────────────────────────────────────────────────────────

    def _open_dtb_dialog(self):
        """Show a small popup for DTB / CR3 status and detection."""
        if not self._last_file_info:
            return
        dlg = _DTBPopupDialog(self, parent=self)
        dlg.exec_()

    def _ask_convert_non_dmp(self):
        """Ask before converting a non-DMP file, then organise+convert in one step."""
        path = getattr(self, "_pending_convert_path", None)
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        dlg = _ConvertPromptDialog(ext or "unknown", parent=self)
        if dlg.exec_() == QDialog.Accepted and dlg.convert_requested:
            self._validated = True
            self.action_btn.setText("Converting and organising…")
            self._set_action_btn_enabled(False)
            QTimer.singleShot(0, self._start_acquisition)
        else:
            self._validated = False
            self.action_btn.setText("📄  Convert required")
            self._set_action_btn_enabled(False)

    def _do_detect_dtb(self):
        """Run kernel metadata resolver through AcquisitionBridge.detect_dtb()."""
        path = getattr(self, "_dtb_detect_path", None)
        if not path and self._last_file_info:
            path = self._last_file_info.get("path")
        if not path:
            return

        # Build is optional in Phase 6A. The metadata resolver can detect the
        # OS build/profile automatically from sidecar/header/windows.info and
        # then fall back to native scanning only when needed.
        build = self._current_build_number()

        self._dtb_detect_path = path
        self._dtb_label.setText("Resolving kernel metadata…")
        self._dtb_sub.setText(
            "Resolving OS build, profile, and DTB/CR3. Native fallback may be used if metadata resolution fails."
        )
        self._dtb_btn.setText("Resolving…")
        self._dtb_btn.setEnabled(False)
        self._set_dtb_button_state(
            "scanning",
            text="Resolving…",
            tooltip="Kernel metadata resolver is running. Please wait.",
        )

        _DTBDetectWorker(
            dump_path=path,
            cb_queue=self._cb_queue,
            build_number=build,
            scan_mb=0,
        ).start()

    def _do_convert(self):
        """Compatibility button handler: organise+convert, never convert beside source."""
        path = getattr(self, "_pending_convert_path", None)
        if not path:
            return
        self._validated = True
        self._set_action_btn_enabled(False)
        self.action_btn.setText("Converting and organising…")
        QTimer.singleShot(0, self._start_acquisition)

    # ─────────────────────────────────────────────────────────────────────────
    # Config browsing
    # ─────────────────────────────────────────────────────────────────────────

    def _browse_dumpit(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Locate DumpIt", "", "Executables (*.exe);;All Files (*)"
        )
        if path:
            self.dumpit_input.setText(_normalize_path(path))

    def _browse_output_dir(self):
        # RAMDetect now always stores live acquisition output under the current
        # installed project's ./dumps directory. This prevents copied clients on
        # other workstations from writing to a stale path from the original PC.
        self.outdir_input.setText(_canonical_dumps_dir_str())

    def _browse_file_output_dir(self):
        # Same rule for imported dumps: always organize into this copy's ./dumps.
        self.file_outdir_input.setText(_canonical_dumps_dir_str())

    # ─────────────────────────────────────────────────────────────────────────
    # Acquisition logic
    # ─────────────────────────────────────────────────────────────────────────

    def _start_acquisition(self):
        sess = AppState.current
        sess.acquired_at = datetime.now()

        if self._mode == "file":
            if not self._validated:
                return
            output_dir = _canonical_dumps_dir_str()
            self.file_outdir_input.setText(output_dir)
            Config.set("acquisition.output_dir", output_dir)
            self._monitor_title.setText("Moving Dump")
            self._duration_badge.setText("0s")
            self._duration_badge.show()
            self.monitor_stack.setCurrentIndex(1)
            self.pct_label.setText("0%")
            self.prog_bar.setValue(0)
            self.status_lbl.setText("Moving dump into session folder…")
            self.act_size_lbl.setText(f"0.0 GB / {sess.dump_size_str}" if sess.dump_size_str else "—")
            self.act_time_lbl.setText("0 seconds")
            self._set_action_btn_enabled(False)
            self.continue_btn.hide()
            self._elapsed_secs = 0
            self._elapsed_timer.start()
            while not self._cb_queue.empty():
                try: self._cb_queue.get_nowait()
                except: pass

            # FIX #4: build validated_info from proper session fields
            validated_info = {
                "filename":      sess.dump_filename,
                "size_bytes":    sess.dump_size_bytes,
                "size_str":      sess.dump_size_str,
                "format":        sess.dump_format    or "DMP",
                "architecture":  sess.architecture   or "—",
                "os_hint":       "Windows",
                "est_load_time": "—",
                "sha256":        sess.sha256          or "—",
                "md5":           sess.md5             or "—",
            }
            _FileOrganizeWorker(
                src_path        = sess.dump_path,
                output_base_dir = output_dir,
                validated_info  = validated_info,
                cb_queue        = self._cb_queue,
                selected_profile = self._selected_profile(),
            ).start()
            return

        # ── Live mode ─────────────────────────────────────────────────────────
        # Persist config changes
        dumpit_path = self.dumpit_input.text().strip() or Config.dumpit_path
        output_dir  = _canonical_dumps_dir_str()
        self.outdir_input.setText(output_dir)
        Config.set("acquisition.dumpit_path", dumpit_path)
        Config.set("acquisition.output_dir",  output_dir)

        sess.mode = "live"

        # Switch UI to active
        self._monitor_title.setText("Acquisition Progress")
        self._duration_badge.setText("0s")
        self._duration_badge.show()
        self.monitor_stack.setCurrentIndex(1)
        self.pct_label.setText("0%")
        self.prog_bar.setValue(0)
        self.status_lbl.setText("Starting DumpIt…")
        self.act_size_lbl.setText(
            f"— / {_TOTAL_RAM_STR}" if _TOTAL_RAM_STR != "Unknown" else "Estimating…"
        )
        self.act_time_lbl.setText("0 seconds")
        self._set_action_btn_enabled(False)
        self.continue_btn.hide()

        # Start elapsed + size-polling timers
        self._elapsed_secs = 0
        self._output_dir_live = output_dir
        self._acq_start_time  = __import__("time").time()
        self._elapsed_timer.start()
        self._size_timer.start()

        # Clear queue
        while not self._cb_queue.empty():
            try: self._cb_queue.get_nowait()
            except: pass

        # Launch worker — callbacks push onto queue (thread-safe).
        try:
            self._worker = AcquisitionBridge.start_live_dump(
                dumpit_path = dumpit_path,
                output_dir  = output_dir,
                progress_cb = lambda pct, msg: self._cb_queue.put(("progress", pct, msg)),
                finished_cb = lambda info:     self._cb_queue.put(("finished", info)),
                error_cb    = lambda msg:      self._cb_queue.put(("error", msg)),
            )
        except Exception as _exc:
            self._worker = None
            self._set_action_btn_enabled(True)
            self._show_error(f"Failed to start acquisition: {_exc}")

    # ─────────────────────────────────────────────────────────────────────────
    # Elapsed time ticker
    # ─────────────────────────────────────────────────────────────────────────

    def _tick_elapsed(self):
        """Called every second while live acquisition is running."""
        self._elapsed_secs += 1
        self.act_time_lbl.setText(f"{self._elapsed_secs} second{'s' if self._elapsed_secs != 1 else ''}")
        s = self._elapsed_secs
        self._duration_badge.setText(f"{s}s" if s < 60 else f"{s // 60}m {s % 60:02d}s")

    def _poll_dump_size(self):
        """
        FIX #3: Use os.walk (recursive) instead of os.scandir (flat) so the
        growing .dmp inside its session subfolder is found during live acquisition.

        Previous implementation scanned only the top-level output_dir; because
        LiveDumpWorker places the dump inside  memdump_YYYYMMDD_HHMMSS/  the
        flat scan never found the file and the size bar always showed 0%.

        Every second: find the largest .dmp / .raw file created AFTER this
        acquisition started, and derive a live percentage from it.
        Ignores pre-existing dumps so we never jump instantly to 99%.
        """
        if not self._output_dir_live or _TOTAL_RAM_BYTES <= 0:
            return
        try:
            best_size = 0
            for root, _dirs, files in os.walk(self._output_dir_live):
                for fname in files:
                    if not fname.lower().endswith((".dmp", ".raw")):
                        continue
                    try:
                        fpath = os.path.join(root, fname)
                        st    = os.stat(fpath)
                        # Skip files that existed before acquisition started
                        if st.st_mtime < self._acq_start_time:
                            continue
                        if st.st_size > best_size:
                            best_size = st.st_size
                    except OSError:
                        pass
            if best_size > 0:
                pct = min(int(best_size * 100 / _TOTAL_RAM_BYTES), 99)
                self.pct_label.setText(f"{pct}%")
                self.prog_bar.setValue(pct)
                written_str = f"{best_size / (1024 ** 3):.1f} GB"
                self.act_size_lbl.setText(f"{written_str} / {_TOTAL_RAM_STR}")
        except Exception:
            pass  # never crash the UI from a background poll

    # ─────────────────────────────────────────────────────────────────────────
    # Queue drain  — runs on main thread every 50 ms
    # ─────────────────────────────────────────────────────────────────────────

    def _drain_queue(self):
        """Pull all pending callbacks from the worker thread and apply to UI."""
        try:
            while True:
                item = self._cb_queue.get_nowait()
                kind = item[0]

                if kind == "progress":
                    _, pct, msg = item
                    self.pct_label.setText(f"{pct}%")
                    self.prog_bar.setValue(pct)
                    self.status_lbl.setText(msg)

                    # Update the size estimate using the correct denominator.
                    # Live mode writes RAM-sized output, so host physical RAM is useful.
                    # File mode only organises/converts the selected dump, so using
                    # _TOTAL_RAM_BYTES causes wrong values such as 11.4 GB / 15.2 GB
                    # for a 4.0 GB old dump rerun.
                    if pct > 0:
                        if self._mode == "file":
                            total_bytes = int(getattr(AppState.current, "dump_size_bytes", 0) or 0)
                            if total_bytes > 0:
                                written = total_bytes * pct / 100
                                written_str = f"{written / (1024**3):.1f} GB"
                                total_str = (
                                    getattr(AppState.current, "dump_size_str", "") 
                                    or f"{total_bytes / (1024**3):.1f} GB"
                                )
                                self.act_size_lbl.setText(f"{written_str} / {total_str}")
                            else:
                                self.act_size_lbl.setText(
                                    getattr(AppState.current, "dump_size_str", "—") or "—"
                                )
                        elif _TOTAL_RAM_BYTES > 0:
                            written = _TOTAL_RAM_BYTES * pct / 100
                            written_str = f"{written / (1024**3):.1f} GB"
                            self.act_size_lbl.setText(f"{written_str} / {_TOTAL_RAM_STR}")

                elif kind == "finished":
                    _, info = item
                    self._worker = None
                    self._elapsed_timer.stop()
                    self._size_timer.stop()
                    self._set_action_btn_enabled(True)
                    sess = AppState.current
                    sess.dump_path       = info["path"]
                    sess.dump_filename   = info["filename"]
                    sess.dump_size_bytes = info["size_bytes"]
                    sess.mode            = self._mode
                    # FIX #4: assign to proper dataclass fields
                    sess.sha256          = info.get("sha256", "")
                    sess.md5             = info.get("md5",    "")
                    sess.dump_format     = info.get("format", "")
                    sess.architecture    = info.get("architecture", "")
                    if info.get("build_number"):
                        sess.build_number = int(info.get("build_number"))
                    if info.get("session_dir"):
                        sess.session_dir = info["session_dir"]
                    if info.get("dtb_hex"):
                        sess.dtb_hex = info.get("dtb_hex")
                    if info.get("dtb_source"):
                        sess.dtb_source = info.get("dtb_source")
                    if info.get("metadata_source"):
                        sess.metadata_source = info.get("metadata_source")
                    if info.get("dtb_confidence") is not None:
                        try:
                            sess.dtb_confidence = int(info.get("dtb_confidence"))
                        except Exception:
                            pass
                    if self._last_file_info is not None:
                        self._last_file_info.update({
                            "path": info.get("path", self._last_file_info.get("path")),
                            "dtb_hex": info.get("dtb_hex") or self._last_file_info.get("dtb_hex"),
                            "build_number": info.get("build_number") or self._last_file_info.get("build_number"),
                            "json_path": info.get("json_path") or self._last_file_info.get("json_path"),
                        })
                    self._show_success(info)

                elif kind == "error":
                    _, msg = item
                    self._worker = None
                    self._elapsed_timer.stop()
                    self._size_timer.stop()
                    self._set_action_btn_enabled(True)
                    self._show_error(msg)

                elif kind == "convert_ok":
                    # Conversion succeeded — reload the card with the new .dmp path
                    _, dmp_path = item
                    self._conv_banner.hide()
                    self._pending_convert_path = None
                    self._load_file(dmp_path)

                elif kind == "convert_err":
                    # Conversion failed — show error in the banner
                    _, msg = item
                    self._conv_label.setText("Conversion failed")
                    self._conv_sub.setText(msg)
                    self._conv_btn.setText("Retry")
                    self._conv_btn.setEnabled(True)

                elif kind == "dtb_ok":
                    _, result = item
                    dtb_hex = result.get("dtb_hex") or result.get("dtb") or "—"
                    conf = result.get("confidence", 0)
                    metadata_source = result.get("metadata_source") or result.get("source") or result.get("dtb_source")
                    dtb_source = result.get("dtb_source") or result.get("source")

                    self._dtb_label.setText(f"DTB detected: {dtb_hex}")
                    self._dtb_sub.setText(
                        f"Confidence {conf}%. Sidecar JSON updated for Real-Time Analysis."
                    )
                    self._dtb_btn.setText("Re-detect")
                    self._dtb_btn.setEnabled(True)

                    if self._last_file_info is not None:
                        self._last_file_info["dtb_hex"] = dtb_hex
                        self._last_file_info["json_path"] = result.get("json_path") or self._last_file_info.get("json_path")
                        if result.get("build"):
                            self._last_file_info["build_number"] = int(result.get("build"))

                    sess = AppState.current
                    sess.dtb_hex = dtb_hex
                    if result.get("build"):
                        sess.build_number = int(result.get("build"))
                    if metadata_source:
                        sess.metadata_source = metadata_source
                    if dtb_source:
                        sess.dtb_source = dtb_source
                    if result.get("confidence") is not None:
                        try:
                            sess.dtb_confidence = int(result.get("confidence"))
                        except Exception:
                            pass
                    self._refresh_dtb_banner()

                elif kind == "dtb_err":
                    _, msg = item
                    self._dtb_label.setText("DTB detection failed")
                    self._dtb_sub.setText(msg)
                    self._dtb_btn.setText("Retry")
                    self._dtb_btn.setEnabled(True)
                    self._refresh_dtb_banner()

        except queue.Empty:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Monitor state helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _show_success(self, info_or_path):
        """
        Accept either the full info dict (from live acquisition)
        or a plain path string (from file mode via _start_acquisition).
        """
        sess = AppState.current
        ts   = sess.acquired_at.strftime("%Y-%m-%d  %H:%M:%S") if sess.acquired_at else "—"

        # FIX #4: resolve sha256 / md5 from proper session fields
        if isinstance(info_or_path, dict):
            path   = info_or_path.get("path", "")
            sha256 = info_or_path.get("sha256") or sess.sha256 or "—"
            md5    = info_or_path.get("md5")    or sess.md5    or "—"
        else:
            path   = info_or_path
            sha256 = sess.sha256 or "—"
            md5    = sess.md5    or "—"

        full_filename = sess.dump_filename or "—"
        full_path = _normalize_path(path) if path else "—"

        self._succ_filename.setText(_short_middle(full_filename, 64))
        self._succ_filename.setToolTip(full_filename)

        # Display a compact path that keeps the front directory context and the
        # final .dmp filename. The exact managed path remains available by
        # hovering over the row.
        self._succ_path.setText(_compact_dump_path(full_path, 66))
        self._succ_path.setToolTip(full_path)

        self._succ_size.setText(sess.dump_size_str or "—")
        s = self._elapsed_secs
        if s <= 0:
            dur_text = "—"
        elif s < 60:
            dur_text = f"{s}s"
        else:
            dur_text = f"{s // 60}m {s % 60:02d}s"
        self._succ_duration.setText(dur_text)
        self._succ_time.setText(ts)

        self._succ_sha.setText(_short_hash(sha256, 16, 16))
        self._succ_sha.setToolTip(sha256)

        self._succ_md5.setText(_short_hash(md5, 12, 12))
        self._succ_md5.setToolTip(md5)

        # Reset header title now that acquisition is done
        self._monitor_title.setText("Progress Monitor")

        # Re-enforce gradient every time — prevents Qt style cascade from wiping it
        self.continue_btn_inner.setEnabled(True)
        self.continue_btn_inner.setStyleSheet(
            "QPushButton {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #06b6d4, stop:1 #2563eb);"
            "  color: #ffffff; border: none; border-radius: 8px;"
            "  font-weight: 700; font-size: 13px;"
            "}"
            "QPushButton:hover {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #0891b2, stop:1 #1d4ed8);"
            "}"
        )
        # Remember exactly which session/path this completed monitor belongs to.
        # If Dashboard later creates a fresh AppState.current for an old dump
        # re-run, _on_show can detect that it is a different session and refresh
        # the Acquisition UI instead of leaving this old success panel visible.
        self._monitor_session_id = getattr(sess, "session_id", None)
        self._monitor_dump_path = sess.dump_path or path or ""

        self.monitor_stack.setCurrentIndex(2)
        self.continue_btn.show()
        # Hide action button once file has been successfully loaded/acquired;
        # it reappears only when the user changes the file (via _reset_file_state).
        self.action_btn.hide()

    def _show_error(self, msg: str):
        sess = AppState.current
        self._monitor_session_id = getattr(sess, "session_id", None)
        self._monitor_dump_path = getattr(sess, "dump_path", "") or ""
        self._err_lbl.setText(msg)
        self.monitor_stack.setCurrentIndex(3)
        self.continue_btn.hide()

    def _reset_monitor(self):
        """Return right panel to idle state."""
        self._monitor_session_id = None
        self._monitor_dump_path = ""
        self._monitor_title.setText("Progress Monitor")
        self._duration_badge.hide()
        self.monitor_stack.setCurrentIndex(0)

    # ─────────────────────────────────────────────────────────────────────────
    # Continue to analysis
    # ─────────────────────────────────────────────────────────────────────────

    def _go_to_analysis(self):
        self.mw.navigate_to("analysis_config")

    # ─────────────────────────────────────────────────────────────────────────
    # showEvent — pre-fill if re-run from Dashboard
    # ─────────────────────────────────────────────────────────────────────────

    def _on_show(self):
        """Called by BasePage.showEvent each time this page becomes visible.

        Important rerun rule:
        - minimise/restore should preserve the current completed success panel;
        - Dashboard rerun creates a new ScanSession with a selected dump_path,
          so Acquisition must refresh the UI for that new session instead of
          showing the previous completed dump card.
        """
        self.dumpit_input.setText(_normalize_path(Config.dumpit_path))
        canonical_out = _canonical_dumps_dir_str()
        self.outdir_input.setText(canonical_out)
        self.file_outdir_input.setText(canonical_out)
        Config.set("acquisition.output_dir", canonical_out)

        # Do not reset while live acquisition, file organisation, conversion,
        # or DTB resolution is running.
        if self._is_acquisition_busy():
            return

        sess = AppState.current

        def _abs_norm(path: str) -> str:
            try:
                return os.path.normcase(os.path.abspath(path or ""))
            except Exception:
                return str(path or "")

        current_path = getattr(sess, "dump_path", "") or ""
        current_path_key = _abs_norm(current_path)
        monitor_path_key = _abs_norm(getattr(self, "_monitor_dump_path", ""))
        monitor_session_id = getattr(self, "_monitor_session_id", None)

        # Preserve completed success/error monitor only when it belongs to the
        # exact same AppState session and dump path. This keeps minimise/restore
        # stable, but prevents the CobaltStrike success card from being shown
        # when the Dashboard rerun button selects another old dump.
        if self.monitor_stack.currentIndex() in (2, 3):
            same_completed_session = (
                monitor_session_id == getattr(sess, "session_id", None)
                and bool(current_path_key)
                and monitor_path_key == current_path_key
            )
            if same_completed_session:
                self.continue_btn_inner.setEnabled(True)
                self.continue_btn_inner.setStyleSheet(
                    "QPushButton {"
                    "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                    "    stop:0 #06b6d4, stop:1 #2563eb);"
                    "  color: #ffffff; border: none; border-radius: 8px;"
                    "  font-weight: 700; font-size: 13px;"
                    "}"
                    "QPushButton:hover {"
                    "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                    "    stop:0 #0891b2, stop:1 #1d4ed8);"
                    "}"
                )
                return

        # Dashboard rerun / restored file session: load the selected dump into
        # the left file card and reset the right monitor away from any stale
        # completed panel.
        if current_path and os.path.exists(current_path):
            self.action_btn.show()
            self._reset_monitor()
            self._select_mode("file")
            self._load_file(current_path)
            return

        # Fresh New Scan: reset into live-acquisition mode.
        self.action_btn.show()
        self._reset_monitor()
        self._select_mode("live")

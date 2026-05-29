"""
ui/bridge/report_bridge.py
───────────────────────────
Wraps  ramdetect/reporting/  for PDF, JSON, and CSV generation.

Real interface (wire when ready):
    from ramdetect.reporting import ReportGenerator
    gen = ReportGenerator(session_data)
    gen.generate_pdf(output_path, options)
    gen.generate_json(output_path)
    gen.generate_csv(output_path)

Fallback delegates to:
    ramdetect.reporting.pdf_reporter   → PDFReporter
    ramdetect.reporting.json_reporter  → JSONReporter
    ramdetect.reporting.csv_reporter   → CSVReporter

generate() always returns:
{
    'success':   bool,
    'path':      str,   # absolute path to generated file
    'filename':  str,   # basename
    'size_str':  str,   # human-readable size
    'error':     str,   # non-empty on failure
}
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List

from ui.bridge.config_bridge import Config


def _runtime_root():
    """Return active RAMDetect runtime root for report exports.

    In packaged mode, __file__ points into _internal, but reports must be saved
    beside RAMDetect.exe:
      C:/RAMDetect Admin/reports
      C:/RAMDetect Analyst/reports
    """
    from pathlib import Path as _Path
    import sys as _sys

    try:
        if getattr(_sys, "frozen", False):
            return _Path(_sys.executable).resolve().parent
    except Exception:
        pass

    here = _Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass

    return _Path.cwd().resolve()


def _reports_dir() -> str:
    path = _runtime_root() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


# ── ReportLab availability flag ───────────────────────────────────────────────
try:
    import reportlab
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False

# ── Real reporting module ─────────────────────────────────────────────────────
_REAL_REPORTING = False
try:
    # ┌─ WIRE YOUR REAL MODULE HERE ────────────────────────────────────────────
    # from ramdetect.reporting import ReportGenerator
    # _REAL_REPORTING = True
    # └─────────────────────────────────────────────────────────────────────────
    pass
except ImportError:
    pass

# ── Fallback reporter modules ─────────────────────────────────────────────────
from ramdetect.reporting.pdf_reporter  import PDFReporter
from ramdetect.reporting.json_reporter import JSONReporter
from ramdetect.reporting.csv_reporter  import CSVReporter


# ── Shared helpers (kept here for list_reports / delete_report) ───────────────

def _bytes_str(path: str) -> str:
    try:
        n = os.path.getsize(path)
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} GB"
    except Exception:
        return "—"


def _dump_folder(dump_filename: str | None) -> str:
    """
    Derive a safe folder name from a dump filename.

    Examples
    --------
    ``"Windows_10_x64-malware.raw"``  →  ``"Windows_10_x64-malware"``
    ``"system_capture.dmp"``          →  ``"system_capture"``
    ``None / ""``                     →  ``"unknown_dump"``
    """
    import re
    stem = os.path.splitext(dump_filename or "")[0].strip()
    if not stem:
        return "unknown_dump"
    # Replace characters that are illegal or awkward in directory names
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", stem)
    return stem or "unknown_dump"


# ── Bridge ────────────────────────────────────────────────────────────────────

class ReportBridge:
    """Static helper — no instance needed."""

    @staticmethod
    def generate(
        session,               # ScanSession
        fmt: str,              # "pdf" | "json" | "csv"
        options: Dict = None,  # PDF content options
        output_dir: str = None,
    ) -> Dict[str, Any]:
        """Generate a report and return a result dict."""
        os.makedirs(_reports_dir(), exist_ok=True)

        # ── Per-dump subfolder ─────────────────────────────────────────────────
        # Organises exports as:  reports/<dump_name>/<dump_name>_<ts>.<ext>
        # e.g.  reports/Windows_10_x64-malware/Windows_10_x64-malware_20241217_143022.pdf
        base_dir = output_dir or _reports_dir()
        dump_sub = _dump_folder(session.dump_filename)
        out_dir  = os.path.join(base_dir, dump_sub)
        os.makedirs(out_dir, exist_ok=True)

        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem  = os.path.splitext(session.dump_filename)[0] if session.dump_filename else "report"
        fname = f"{stem}_{ts}.{fmt.lower()}"
        path  = os.path.join(out_dir, fname)

        if _REAL_REPORTING:
            return ReportBridge._real_generate(session, fmt, options, path)

        dispatch = {
            "pdf":  lambda: PDFReporter.generate(session, options or {}, path, fname),
            "json": lambda: JSONReporter.generate(session, path, fname),
            # Phase K4A: pass options so CSVReporter can honour the selected
            # CSV mode (ML decision feature export vs CIC semantic compatibility).
            "csv":  lambda: CSVReporter.generate(session, path, fname, options or {}),
        }
        fn = dispatch.get(fmt.lower())
        if fn is None:
            return {
                "success": False, "path": path, "filename": fname,
                "size_str": "—", "error": f"Unknown format: {fmt}",
            }
        result = fn()
        if isinstance(result, dict):
            result.setdefault("format", fmt.lower())
        return result

    @staticmethod
    def _real_generate(session, fmt, options, path) -> Dict:
        # ┌─ WIRE YOUR REAL MODULE HERE ────────────────────────────────────────
        # gen = ReportGenerator(session)
        # if fmt == "pdf":
        #     gen.generate_pdf(path, options or {})
        # elif fmt == "json":
        #     gen.generate_json(path)
        # elif fmt == "csv":
        #     gen.generate_csv(path)
        # fname = os.path.basename(path)
        # return {'success': True, 'path': path, 'filename': fname,
        #         'size_str': _bytes_str(path), 'error': ''}
        # └────────────────────────────────────────────────────────────────────
        fname = os.path.basename(path)
        return JSONReporter.generate(session, path, fname)

    # ── Delete report ─────────────────────────────────────────────────────────
    @staticmethod
    def delete_report(path: str) -> bool:
        """
        Delete a single report file and remove its parent subfolder
        if it becomes empty afterwards.  Returns True on success.
        """
        try:
            if os.path.isfile(path):
                os.remove(path)

            # Prune empty per-dump subfolder (but never the root reports/ dir)
            parent = os.path.dirname(path)
            reports_root = os.path.normpath(_reports_dir())
            if (
                os.path.normpath(parent) != reports_root
                and os.path.isdir(parent)
                and not os.listdir(parent)
            ):
                os.rmdir(parent)

            return True
        except Exception as exc:
            print(f"[ReportBridge] Failed to delete {path}: {exc}")
            return False

    # ── Saved reports list ────────────────────────────────────────────────────
    @staticmethod
    def list_reports() -> List[Dict]:
        """
        Recursively scan _reports_dir() (including per-dump subfolders)
        and return a list of report dicts for the saved-reports table.

        Directory layout expected (but not required):
            reports/
              <dump_name>/          ← per-dump subfolder
                <dump_name>_<ts>.pdf
                <dump_name>_<ts>.json
              <dump_name2>/
                ...
        """
        reports = []
        d = _reports_dir()
        if not os.path.isdir(d):
            return reports

        # Collect (mtime, fp) tuples from the entire tree
        found: List[tuple] = []
        for root, _dirs, files in os.walk(d):
            for fn in files:
                fp  = os.path.join(root, fn)
                ext = os.path.splitext(fn)[1].lstrip(".").upper()
                if ext not in ("PDF", "JSON", "CSV"):
                    continue
                found.append((os.path.getmtime(fp), fp, fn, ext))

        # Sort newest-first
        found.sort(key=lambda x: x[0], reverse=True)

        for mtime_ts, fp, fn, ext in found:
            mtime   = datetime.fromtimestamp(mtime_ts)
            verdict = "unknown"

            if ext == "JSON":
                try:
                    with open(fp, "r", encoding="utf-8") as fh:
                        _d = json.load(fh)
                    verdict = _d.get("verdict", {}).get("label", "unknown")
                except Exception:
                    pass

            # Show the subfolder name alongside the file stem so the library
            # table makes it obvious which dump the report belongs to.
            subfolder = os.path.basename(os.path.dirname(fp))
            base_dir  = os.path.normpath(d)
            parent    = os.path.normpath(os.path.dirname(fp))
            stem      = os.path.splitext(fn)[0]
            display   = (
                f"{subfolder}/{stem}"
                if parent != base_dir          # file is inside a subfolder
                else stem
            )

            reports.append({
                "name":    display,
                "date":    mtime,
                "format":  ext,
                "size":    _bytes_str(fp),
                "verdict": verdict,
                "status":  verdict,
                "path":    fp,
            })

        return reports[:50]  # cap at 50
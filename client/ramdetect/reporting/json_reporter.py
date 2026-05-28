"""
ramdetect/reporting/json_reporter.py
──────────────────────────────────────
Generates a structured JSON export from a ScanSession.

Output shape:
    {
        "metadata":  { generated_at, tool, dump_file, dump_size, session_id },
        "verdict":   { label, confidence, rf_score, ae_score, reconstruction_error },
        "findings":  [ … ],
        "artifacts": { processes, threads, dlls, handles, pe_sections },
        "features":  { names, vector },
    }

Usage:
    from ramdetect.reporting.json_reporter import JSONReporter
    result = JSONReporter.generate(session, path, fname)
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict
from .report_only_artifacts import (
    collect_report_only_ransomware_artifacts,
    summarize_report_only_artifacts,
)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _bytes_str(path: str) -> str:
    """Return a human-readable file size for *path*."""
    try:
        n = os.path.getsize(path)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} GB"
    except Exception:
        return "—"


def _norm_conf(raw) -> float:
    """
    Normalise a confidence value to the 0-100 range.
    ML models may store it as 0-1 (e.g. 0.917) or already 0-100 (91.7).
    """
    try:
        v = float(raw)
        return v * 100.0 if v <= 1.0 else v
    except (TypeError, ValueError):
        return 0.0


# ── Reporter ──────────────────────────────────────────────────────────────────

class JSONReporter:
    """Generates a structured JSON export from a ScanSession."""

    @staticmethod
    def generate(session, path: str, fname: str) -> Dict[str, Any]:
        """
        Serialise the session to a pretty-printed JSON file at *path*.

        Parameters
        ----------
        session : ScanSession
            The completed scan session object.
        path : str
            Absolute output file path (already contains the filename).
        fname : str
            Basename of the output file (used in the return dict).

        Returns
        -------
        dict
            ``{'success': bool, 'path': str, 'filename': str,
               'size_str': str, 'error': str}``
        """
        try:
            ml = session.ml_result or {}
            report_only_ransomware_artifacts = collect_report_only_ransomware_artifacts(session)
            report_only_summary = summarize_report_only_artifacts(report_only_ransomware_artifacts)

            payload = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "tool":         "RAMDetect",
                    "dump_file":    session.dump_filename or "",
                    "dump_size":    session.dump_size_str,
                    "session_id":   session.session_id,
                },
                "verdict": {
                    "label":                ml.get("verdict", "unknown"),
                    "confidence":           _norm_conf(ml.get("confidence", 0)),
                    "rf_score":             _norm_conf(ml.get("rf_score", 0)),
                    "ae_score":             _norm_conf(ml.get("ae_score", 0)),
                    "reconstruction_error": ml.get("reconstruction_error", 0),
                },
                "findings":  session.findings  or [],
                "report_only_artifacts": {
                    "verdict_effect": "none",
                    "ml_mapping": "disabled_report_only",
                    "summary": report_only_summary,
                    "ransomware_process_artifacts": report_only_ransomware_artifacts,
                },
                "artifacts": {
                    "processes":   session.processes   or [],
                    "threads":     session.threads     or [],
                    "dlls":        session.dlls        or [],
                    "handles":     session.handles     or [],
                    "pe_sections": session.pe_sections or [],
                    "mapped_files": getattr(session, "mapped_files", []) or [],
                },
                "features": {
                    "names":  session.feature_names  or [],
                    "vector": session.feature_vector or [],
                },
            }

            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)

            return {
                "success":  True,
                "path":     path,
                "filename": fname,
                "size_str": _bytes_str(path),
                "error":    "",
            }

        except Exception as exc:
            return {
                "success":  False,
                "path":     path,
                "filename": fname,
                "size_str": "—",
                "error":    str(exc),
            }
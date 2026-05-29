"""
ui/bridge/session.py
────────────────────
ScanSession  — one dataclass instance per scan, passed page-to-page
AppState     — singleton that holds the active session + history

Every page reads/writes via AppState.current  instead of passing data
through constructor arguments, so pages stay decoupled.

History is persisted to  ui/data/scan_history.json  so the Dashboard
shows real past scans across restarts.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# ScanSession
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanSession:
    """
    Carries all data produced by one full acquisition → analysis → ML cycle.

    Pages populate it stage-by-stage:
      AcquisitionPage      → sets dump_path, dump_size, dump_filename, mode
      RealtimeAnalysisPage → sets processes, threads, dlls, handles,
                             pe_sections, feature_vector, raw_features
      ResultsDashboard     → reads ml_result, findings
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    session_id:     str       = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at:     datetime  = field(default_factory=datetime.now)

    # ── Acquisition ───────────────────────────────────────────────────────────
    dump_path:      str       = ""       # full path to .dmp / .raw file
    dump_filename:  str       = ""       # basename only
    dump_size_bytes: int      = 0        # raw bytes
    mode:           str       = "file"   # "live" | "file"
    acquired_at:    Optional[datetime] = None

    # ── Dump metadata (FIX #4: proper fields, no more ad-hoc attributes) ──────
    sha256:       str = ""   # SHA-256 hex digest (first 4 MB)
    md5:          str = ""   # MD5 hex digest (first 4 MB)
    dump_format:  str = ""   # e.g. "DMP", "RAW"
    architecture: str = ""   # e.g. "x64 Windows (build 19045)"

    # ── Memory profile (loaded from sidecar JSON / kernel metadata resolver) ──
    dtb:            int       = 0        # Kernel CR3 / Directory Table Base
    build_number:   Optional[int] = None # Windows build number (e.g. 19045)
    metadata_source: str      = ""       # sidecar / crash_dump_header / external_kernel_metadata_resolver
    dtb_source:      str      = ""       # e.g. volatility_windows_info, native scanner source
    dtb_confidence:  Optional[int] = None

    # ── Analysis config ───────────────────────────────────────────────────────
    selected_modules: List[str] = field(default_factory=lambda: [
        "process", "thread", "dll", "handle", "pe_section", "code_injection"
    ])

    # ── Parsed artifacts (populated by AnalysisBridge) ────────────────────────
    processes:    List[Dict] = field(default_factory=list)
    threads:      List[Dict] = field(default_factory=list)
    dlls:         List[Dict] = field(default_factory=list)
    handles:      List[Dict] = field(default_factory=list)
    pe_sections:  List[Dict] = field(default_factory=list)
    injections:   List[Dict] = field(default_factory=list)

    # Phase H3D diagnostic service-registry evidence. These records are
    # parser evidence only; they are not mapped to svcscan.* ML features until
    # Type/Start/ImagePath/ServiceDll/state parsing is implemented and validated.
    service_registry_records: List[Dict] = field(default_factory=list)
    service_registry_summary: Dict[str, Any] = field(default_factory=dict)

    # Phase J10 diagnostic process confidence summary. This is display/report
    # metadata only and is not used by the RF-AE classifier.
    process_confidence_summary: Dict[str, Any] = field(default_factory=dict)

    # ── Features (populated by AnalysisBridge) ────────────────────────────────
    raw_features:    Dict[str, Any] = field(default_factory=dict)
    # feature_vector is the canonical 52-dim ndarray — stored as list for JSON
    feature_vector:  List[float]    = field(default_factory=list)
    feature_names:   List[str]      = field(default_factory=list)

    # PHASE_I2B_FEATURE_PERSISTENCE_FIELDS
    # Diagnostic traceability fields persisted for future audits.
    # These fields are read-only for reporting/debugging and are not used
    # to override ML decisions.
    feature_provenance: List[Dict[str, Any]] = field(default_factory=list)
    feature_coverage: Dict[str, Any] = field(default_factory=dict)
    canonical_feature_matrix: List[Dict[str, Any]] = field(default_factory=list)

    # ── ML results (populated by MLBridge) ────────────────────────────────────
    ml_result: Dict[str, Any] = field(default_factory=dict)
    # Normalised result dict shape:
    # {
    #   'verdict':              'clean' | 'suspicious',
    #   'confidence':           float   (0–100) deprecated alias of hybrid_score,
    #   'hybrid_score':         float   (0–100) final RF-AE suspicious score,
    #   'rf_score':             float   (0–100),
    #   'ae_score':             float   (0–100),
    #   'reconstruction_error': float,
    #   'ae_threshold':         float   (default 0.004),
    #   'label':                int     (0 = clean, 1 = suspicious),
    #   'feature_importance':   [{'feature': str, 'importance': float}, ...],
    #   'anomaly_distribution': {'clean': float, 'suspicious': float},
    # }

    # ── Findings (derived from ml_result by MLBridge) ─────────────────────────
    findings: List[Dict] = field(default_factory=list)
    # Each finding: {'severity': 'high'|'medium'|'low',
    #                'category': str, 'description': str}

    # ── Report-only analyst artifacts ────────────────────────────────────────
    # These are not ML features and must not affect verdict decisions.
    report_only_ransomware_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    report_only_artifact_summary: Dict[str, Any] = field(default_factory=dict)

    # ── Status ────────────────────────────────────────────────────────────────
    status: str = "pending"
    # "pending" | "acquiring" | "analysing" | "classifying" | "complete" | "error"
    error_message: str = ""

    # ── Computed helpers ──────────────────────────────────────────────────────
    @property
    def dump_size_str(self) -> str:
        b = self.dump_size_bytes
        if b == 0:
            return "—"
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    @property
    def verdict(self) -> str:
        return self.ml_result.get("verdict", "unknown")

    @staticmethod
    def _score_to_percent(value: Any) -> float:
        """Normalize a stored model score to a 0–100 percentage."""
        try:
            v = float(value)
        except (TypeError, ValueError):
            return 0.0
        if 0.0 <= v <= 1.0:
            v *= 100.0
        return max(0.0, min(100.0, v))

    @property
    def hybrid_score(self) -> float:
        """Final RF-AE suspicious-class Hybrid Score used by the GUI."""
        return self._score_to_percent(
            self.ml_result.get(
                "hybrid_score",
                self.ml_result.get("suspicion_score", self.ml_result.get("confidence", 0.0)),
            )
        )

    @property
    def confidence(self) -> float:
        """Backward-compatible alias for hybrid_score."""
        return self.hybrid_score

    @property
    def is_suspicious(self) -> bool:
        return self.verdict == "suspicious"

    # ── Serialisation for history persistence ─────────────────────────────────
    def to_history_dict(self) -> Dict:
        """Minimal dict written to scan_history.json."""
        return {
            "id":           self.session_id,
            "filename":     self.dump_filename,
            "datetime":     self.created_at.isoformat(),
            "size":         self.dump_size_str,
            "size_bytes":   self.dump_size_bytes,
            "status":       self.verdict,
            "confidence":   self.hybrid_score,   # backward-compatible alias
            "hybrid_score": self.hybrid_score,
            "mode":         self.mode,
            "dump_path":    self.dump_path,
            # FIX #4: include new fields so history rows can show them
            "sha256":       self.sha256,
            "md5":          self.md5,
            "dump_format":  self.dump_format,
            "architecture": self.architecture,
        }

    @classmethod
    def from_history_dict(cls, d: Dict) -> "ScanSession":
        s = cls()
        s.session_id       = d.get("id", s.session_id)
        s.dump_filename    = d.get("filename", "")
        s.dump_path        = d.get("dump_path", "")
        s.dump_size_bytes  = d.get("size_bytes", 0)
        s.mode             = d.get("mode", "file")
        s.status           = "complete"
        raw_dt             = d.get("datetime", "")
        try:
            s.created_at   = datetime.fromisoformat(raw_dt)
        except Exception:
            s.created_at   = datetime.now()
        hybrid_score       = cls._score_to_percent(d.get("hybrid_score", d.get("confidence", 0.0)))
        s.ml_result        = {
            "verdict":             d.get("status", "unknown"),
            "confidence":          hybrid_score,  # backward-compatible alias
            "hybrid_score":        hybrid_score,
            "suspicion_score":     hybrid_score,
            "display_score":       hybrid_score,
            "display_score_label": "hybrid_score",
        }
        # FIX #4: restore new fields
        s.sha256       = d.get("sha256",       "")
        s.md5          = d.get("md5",          "")
        s.dump_format  = d.get("dump_format",  "")
        s.architecture = d.get("architecture", "")
        return s


# ─────────────────────────────────────────────────────────────────────────────
# App-local persistence paths
# ─────────────────────────────────────────────────────────────────────────────

def _runtime_root() -> Path:
    """Return the active RAMDetect runtime root for local UI data.

    Installed Analyst and Admin clients must keep scan history/session snapshots
    isolated under their own folders, for example:
      C:/RAMDetect Analyst/ui/data/
      C:/RAMDetect Admin/ui/data/
    """
    try:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
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


_UI_DATA_DIR = _runtime_root() / "ui" / "data"
_HISTORY_FILE = str(_UI_DATA_DIR / "scan_history.json")
_SESSIONS_DIR = str(_UI_DATA_DIR / "sessions")



class _AppState:
    """
    Singleton accessed via  AppState  (module-level instance at bottom).

    Usage:
        from ui.bridge.session import AppState

        AppState.new_session()              # called by AcquisitionPage
        AppState.current.dump_path = ...    # set fields directly
        AppState.save_current()             # called after analysis completes
        history = AppState.load_history()   # called by DashboardPage
    """

    def __init__(self):
        self._current: Optional[ScanSession] = None
        os.makedirs(os.path.dirname(_HISTORY_FILE), exist_ok=True)
        os.makedirs(_SESSIONS_DIR, exist_ok=True)

    # ── Active session ────────────────────────────────────────────────────────
    @property
    def current(self) -> ScanSession:
        if self._current is None:
            self._current = ScanSession()
        return self._current

    def new_session(self) -> ScanSession:
        """Create a fresh session. Call at the start of every new scan."""
        self._current = ScanSession()
        return self._current

    # ── History persistence ───────────────────────────────────────────────────
    def save_current(self):
        """Append current completed session to scan_history.json."""
        if self._current is None or self._current.status not in ("complete", "error"):
            return
        history = self._raw_history()

        # ── Deduplication ─────────────────────────────────────────────────────
        # Remove stale entries for the same scan so only the latest result is
        # kept.  Three checks in priority order:
        #   1. Same session_id             → exact duplicate (e.g. double-save)
        #   2. Same dump_path (non-empty)  → same file on disk, re-analysed
        #   3. Same filename               → FIX #1: was gated behind "no path",
        #      now always checked so files re-organised into new timestamped
        #      subfolders (different dump_path each run) are still deduplicated.
        current_path  = self._current.dump_path
        current_fname = self._current.dump_filename

        def _is_stale(h: dict) -> bool:
            if h.get("id") == self._current.session_id:
                return True                                    # exact same session
            if current_path and h.get("dump_path") == current_path:
                return True                                    # same file path
            # FIX #1: always check by filename — path changes every re-organise
            # because organize_loaded_file creates a new timestamped subfolder.
            if current_fname and h.get("filename") == current_fname:
                return True
            return False

        history = [h for h in history if not _is_stale(h)]
        history.insert(0, self._current.to_history_dict())
        history = history[:100]          # keep last 100 scans
        try:
            with open(_HISTORY_FILE, "w") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"[AppState] Failed to save history: {e}")
        # Also persist full artifacts so View Details can restore them
        self.save_full()

    def load_history(self) -> List[Dict]:
        """
        Return list of history dicts for the Dashboard table.
        Falls back to empty list if file doesn't exist.
        Deduplicates on read (by dump_path → filename fallback) so stale
        duplicates that slipped in before the save_current fix never appear.
        """
        raw = self._raw_history()
        result = []
        seen_paths: set  = set()   # non-empty dump_paths already emitted
        seen_names: set  = set()   # filenames already emitted (path-agnostic)

        for d in raw:
            try:
                path  = d.get("dump_path", "") or ""
                fname = d.get("filename", "") or ""

                # Skip if we've already included a newer entry for this file.
                # FIX #1 (read-side): always deduplicate by filename, not just
                # when path is absent — mirrors the save_current() logic so any
                # duplicates that slipped into the JSON before the fix are also
                # filtered out on read.
                if path and path in seen_paths:
                    continue
                if fname and fname in seen_names:
                    continue

                if path:
                    seen_paths.add(path)
                if fname:
                    seen_names.add(fname)

                result.append({
                    "id":         d.get("id", ""),
                    "filename":   fname or "unknown.dmp",
                    "datetime":   datetime.fromisoformat(d["datetime"]),
                    "size":       d.get("size", "—"),
                    "status":     d.get("status", "unknown"),
                    "confidence": float(d.get("hybrid_score", d.get("confidence", 0.0))),  # backward-compatible alias
                    "hybrid_score": float(d.get("hybrid_score", d.get("confidence", 0.0))),
                    "mode":       d.get("mode", "file"),
                    "dump_path":  path,
                    # FIX #4: expose new fields to the Dashboard
                    "sha256":       d.get("sha256",       ""),
                    "md5":          d.get("md5",          ""),
                    "dump_format":  d.get("dump_format",  ""),
                    "architecture": d.get("architecture", ""),
                })
            except Exception:
                continue
        return result

    def get_stats(self) -> Dict:
        history = self.load_history()
        clean   = sum(1 for h in history if h["status"] == "clean")
        susp    = sum(1 for h in history if h["status"] == "suspicious")
        last_dt = history[0]["datetime"] if history else None
        last_str = last_dt.strftime("%H:%M  %d/%m") if last_dt else "—"
        return {
            "total":      len(history),
            "clean":      clean,
            "suspicious": susp,
            "last_scan":  last_str,
        }

    # ── Full session persistence ─────────────────────────────────────────────
    def save_full(self) -> bool:
        """
        Write a complete session snapshot (artifacts + ML results) to disk.
        Called automatically by save_current(); can also be called manually.
        Returns True on success.
        """
        sess = self._current
        if sess is None:
            return False
        path = os.path.join(_SESSIONS_DIR, f"{sess.session_id}.json")
        try:
            payload = {
                "session_id":    sess.session_id,
                "dump_filename": sess.dump_filename,
                "dump_path":     sess.dump_path,
                "dump_size_bytes": sess.dump_size_bytes,
                "mode":          sess.mode,
                "created_at":    sess.created_at.isoformat() if sess.created_at else None,
                # FIX #4: persist new metadata fields
                "sha256":        sess.sha256,
                "md5":           sess.md5,
                "dump_format":   sess.dump_format,
                "architecture":  sess.architecture,
                "ml_result":     sess.ml_result,
                "hybrid_score":  sess.hybrid_score,
                "findings":      sess.findings,
                "report_only_ransomware_artifacts": getattr(sess, "report_only_ransomware_artifacts", []),
                "report_only_artifact_summary": getattr(sess, "report_only_artifact_summary", {}),
                "processes":     sess.processes,
                "threads":       sess.threads,
                "dlls":          sess.dlls,
                "handles":       sess.handles,
                "pe_sections":   sess.pe_sections,
                "injections":    sess.injections,
                "selected_modules": getattr(sess, "selected_modules", []),
                # PHASE_I2B_SAVE_FEATURE_TRACE
                "raw_features":  getattr(sess, "raw_features", {}),
                "feature_provenance": getattr(sess, "feature_provenance", []),
                "feature_coverage": getattr(sess, "feature_coverage", {}),
                "canonical_feature_matrix": getattr(sess, "canonical_feature_matrix", []),
                "service_registry_records": getattr(sess, "service_registry_records", []),
                "service_registry_summary": getattr(sess, "service_registry_summary", {}),
                "process_confidence_summary": getattr(sess, "process_confidence_summary", {}),
                "feature_names": sess.feature_names,
                "feature_vector": sess.feature_vector,
                "dtb":           sess.dtb,
                "build_number":  sess.build_number,
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            self._purge_old_sessions()
            return True
        except Exception as exc:
            print(f"[AppState] save_full failed: {exc}")
            return False

    def load_full(self, session_id: str) -> Optional["ScanSession"]:
        """
        Load a previously saved full session by ID.
        Returns a populated ScanSession or None if no file found.
        """
        if not session_id:
            return None
        path = os.path.join(_SESSIONS_DIR, f"{session_id}.json")
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                d = json.load(fh)

            # FIX #9: use ScanSession() so all default_factory fields are
            # initialised before we start overriding individual fields.
            # The old __new__ approach skipped __init__ entirely, leaving any
            # newly added dataclass field uninitialised.
            sess = ScanSession()
            sess.session_id      = d.get("session_id", sess.session_id)
            sess.dump_filename   = d.get("dump_filename", "")
            sess.dump_path       = d.get("dump_path", "")
            sess.dump_size_bytes = d.get("dump_size_bytes", 0)
            sess.mode            = d.get("mode", "file")
            sess.status          = "complete"
            sess.error_message   = ""
            sess.selected_modules = d.get("selected_modules", [
                "process", "thread", "dll", "handle", "pe_section", "code_injection"
            ])
            sess.dtb             = d.get("dtb", 0)
            sess.build_number    = d.get("build_number", None)
            sess.acquired_at     = None
            raw_ts = d.get("created_at")
            try:
                sess.created_at  = datetime.fromisoformat(raw_ts) if raw_ts else datetime.now()
            except (TypeError, ValueError):
                sess.created_at  = datetime.now()

            # FIX #4: restore new metadata fields
            sess.sha256       = d.get("sha256",       "")
            sess.md5          = d.get("md5",          "")
            sess.dump_format  = d.get("dump_format",  "")
            sess.architecture = d.get("architecture", "")

            # ML & findings
            sess.ml_result       = d.get("ml_result", {})
            # Ensure older full-session files still expose the current GUI name.
            _hybrid_score = sess._score_to_percent(
                sess.ml_result.get(
                    "hybrid_score",
                    d.get("hybrid_score", sess.ml_result.get("suspicion_score", sess.ml_result.get("confidence", 0.0))),
                )
            )
            sess.ml_result.setdefault("hybrid_score", _hybrid_score)
            sess.ml_result.setdefault("suspicion_score", _hybrid_score)
            sess.ml_result.setdefault("display_score", _hybrid_score)
            sess.ml_result.setdefault("display_score_label", "hybrid_score")
            sess.ml_result["confidence"] = _hybrid_score  # backward-compatible alias
            sess.findings        = d.get("findings", [])
            sess.report_only_ransomware_artifacts = d.get("report_only_ransomware_artifacts", [])
            sess.report_only_artifact_summary = d.get("report_only_artifact_summary", {})

            # Artifacts
            sess.processes       = d.get("processes", [])
            sess.threads         = d.get("threads", [])
            sess.dlls            = d.get("dlls", [])
            sess.handles         = d.get("handles", [])
            sess.pe_sections     = d.get("pe_sections", [])
            sess.injections      = d.get("injections", [])
            sess.service_registry_records = d.get("service_registry_records", [])
            sess.service_registry_summary = d.get("service_registry_summary", {})
            sess.process_confidence_summary = d.get("process_confidence_summary", {})
            sess.raw_features    = d.get("raw_features", {})
            # PHASE_I2B_LOAD_FEATURE_TRACE
            sess.feature_provenance = d.get("feature_provenance", [])
            sess.feature_coverage = d.get("feature_coverage", {})
            sess.canonical_feature_matrix = d.get("canonical_feature_matrix", [])
            sess.feature_names   = d.get("feature_names", [])
            sess.feature_vector  = d.get("feature_vector", [])

            return sess
        except Exception as exc:
            print(f"[AppState] load_full failed ({path}): {exc}")
            return None

    def full_session_exists(self, session_id: str) -> bool:
        """Return True if a full session snapshot file exists for this ID."""
        if not session_id:
            return False
        return os.path.isfile(os.path.join(_SESSIONS_DIR, f"{session_id}.json"))

    def _purge_old_sessions(self, keep: int = 50):
        """Delete the oldest full session files, keeping the most recent `keep`."""
        try:
            files = sorted(
                [f for f in os.listdir(_SESSIONS_DIR) if f.endswith(".json")],
                key=lambda f: os.path.getmtime(os.path.join(_SESSIONS_DIR, f)),
            )
            while len(files) > keep:
                os.remove(os.path.join(_SESSIONS_DIR, files.pop(0)))
        except Exception:
            pass

    def _raw_history(self) -> List[Dict]:
        try:
            with open(_HISTORY_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []


# Module-level singleton — import this everywhere
AppState = _AppState()
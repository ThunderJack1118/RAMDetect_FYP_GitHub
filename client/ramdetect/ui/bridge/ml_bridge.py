"""
ui/bridge/ml_bridge.py
───────────────────────
Wraps the trained models behind one normalised interface.

ARCHITECTURE CHANGE: Feature Fusion (Dai et al. 2024)
─────────────────────────────────────────────────────────────────────
The HybridClassifier now fuses the Autoencoder's MSE into the feature 
vector and uses the Random Forest to make a single, final classification.

MLBridge.predict() always returns:
{
    'verdict':              'clean' | 'suspicious',
    'confidence':           float   (0–100 %)   deprecated alias of hybrid_score,
    'rf_score':             float   (0–100 %)   Fused RF probability,
    'ae_score':             float   (0–100 %)   AE normalised error (display only),
    'hybrid_score':         float   (0–100 %)   final suspicion score,
    'reconstruction_error': float,
    'label':                int,    (0 = clean, 1 = suspicious)
    'feature_importance':   list[{'feature': str, 'importance': float}],
    'anomaly_distribution': {'clean': float, 'suspicious': float},
    'explanation':          str
}

MLBridge.get_model_metadata() reads live from:
    models/training_report.json    — written by model_trainer.py
    models/evaluation_report.json  — written by model_evaluator.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

from ui.bridge.config_bridge import Config

# ── Report file paths (relative to project root) ──────────────────────────────
_TRAINING_REPORT   = os.path.join("models", "training_report.json")
_EVALUATION_REPORT = os.path.join("models", "evaluation_report.json")

# ── Import real ML backend ────────────────────────────────────────────────────
_IMPORT_ERROR:  Optional[str] = None
_REAL_ML        = False
_rf_model       = None
_ae_model       = None
_hybrid_model   = None
_feature_mapper = None

try:
    from ramdetect.ml.random_forest_model import RandomForestModel
    from ramdetect.ml.autoencoder_model   import AutoencoderModel
    from ramdetect.ml.hybrid_classifier   import HybridClassifier
    from ramdetect.ml.feature_mapper      import FeatureMapper
    _REAL_ML = True
except ImportError as _e:
    _IMPORT_ERROR = (
        f"ML backend unavailable: {_e}. "
        "Ensure ramdetect is installed and models are trained."
    )

# ── Hard-coded fallback metrics (used only if JSON files are missing) ──────────
REAL_MODEL_METRICS = {
    "random_forest": {
        "accuracy": 0.9998, "f1": 0.9998, "auc": 1.0000,
        "fpr": 0.0005, "fnr": 0.0000,
    },
    "autoencoder": {
        "accuracy": 0.9765, "f1": 0.9764, "auc": 0.9879,
        "fpr": 0.0471, "fnr": 0.0000,
    },
    "hybrid": {
        "accuracy": 0.9993, "f1": 0.9993, "auc": 1.0000,
        "fpr": 0.0014, "fnr": 0.0000,
    },
    "dataset": {
        "total": 58596, "train": 41016, "val": 8790,
        "test": 8790, "features": 55,
    },
    "training_time": {"rf": "2.0s", "ae": "9.8s", "total": "13.4s"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Model loader  (lazy, cached)
# ─────────────────────────────────────────────────────────────────────────────

_LOAD_ERROR: Optional[str] = None   # set on first failed load attempt

def _load_models() -> bool:
    """
    Load all model artefacts from disk (once, then cached).
    Raises RuntimeError with a clear message on any failure.
    """
    global _rf_model, _ae_model, _hybrid_model, _feature_mapper, _LOAD_ERROR

    if _hybrid_model is not None:
        return True

    if _LOAD_ERROR:
        raise RuntimeError(_LOAD_ERROR)

    try:
        _rf_model = RandomForestModel.load(Config.rf_model_path)
        _ae_model = AutoencoderModel.load(Config.ae_model_path)
        _hybrid_model = HybridClassifier(
            rf_path=Config.rf_model_path,
            ae_path=Config.ae_model_path,
        )
        _hybrid_model.load()
        _feature_mapper = FeatureMapper.load(Config.feature_mapper_path)
        return True

    except FileNotFoundError as e:
        _LOAD_ERROR = (
            f"Model file not found: {e}\n"
            "Run the training pipeline first or check paths in Settings."
        )
        raise RuntimeError(_LOAD_ERROR)

    except Exception as e:
        _LOAD_ERROR = f"Failed to load ML models: {e}"
        raise RuntimeError(_LOAD_ERROR)

# ─────────────────────────────────────────────────────────────────────────────
# MLBridge
# ─────────────────────────────────────────────────────────────────────────────

class MLBridge:

    @staticmethod
    def predict(
        feature_vector: List[float],
        feature_names:  Optional[List[str]] = None,
        raw_vol_data:   Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the RF-AE classifier on the live RAMDetect feature vector.

        The final architecture uses 54 CIC-MalMem canonical features plus
        Autoencoder MSE as the 55th fused Random Forest input. The optional
        raw_vol_data parameter is retained only as raw-feature context for
        compatibility; it must not trigger any post-classification rule.
        """
        if _IMPORT_ERROR:
            raise RuntimeError(_IMPORT_ERROR)

        _load_models()
        return MLBridge._real_predict(feature_vector, feature_names, raw_vol_data)

    @staticmethod
    def _real_predict(
        fv:           List[float],
        names:        Optional[List[str]],
        raw_vol_data: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        
        # 'fv' is already the mapped live feature array from Phase 1.
        X = np.array(fv, dtype=np.float32).reshape(1, -1)

        # Stage 1: Hybrid ML prediction (Dai et al. Feature Fusion)
        # raw_vol_data is kept only as raw-feature context for compatibility.
        # It must not alter the final RF-AE decision outside the trained model path.
        result = _hybrid_model.predict(X[0], features_dict=raw_vol_data)
        
        label        = result["label"]
        verdict      = str(result["verdict"]).lower()  # UI uses lowercase values
        rf_s         = result.get("rf_score", 0.0)
        ae_s         = result.get("ae_score", 0.0)
        hybrid_score = result.get("suspicion_score", result.get("hybrid_score", 0.0))
        rec_err      = result.get("ae_error", result.get("reconstruction_error", 0.0))
        explanation  = result.get("explanation", "")

        def _to_pct(value: Any) -> float:
            """Normalize model scores to a 0-100 display percentage."""
            try:
                v = float(value)
            except (TypeError, ValueError):
                return 0.0
            return v * 100.0 if 0.0 <= v <= 1.0 else v

        # The RF/hybrid score is RAMDetect's final ML suspicion score.
        # We intentionally display/report this score directly for both CLEAN and
        # SUSPICIOUS verdicts to avoid confusing "CLEAN confidence" with
        # "suspicion probability". A CLEAN verdict with hybrid_score=23% means
        # the dump is below the 50% suspicious threshold.
        suspicion_pct = max(0.0, min(100.0, _to_pct(hybrid_score)))
        rf_pct        = max(0.0, min(100.0, _to_pct(rf_s)))
        ae_pct        = max(0.0, min(100.0, _to_pct(ae_s)))

        # Backward-compatible alias: older UI/export code reads "confidence".
        # Under the current RAMDetect wording, this value is the hybrid score,
        # not verdict confidence.
        display_hybrid_score = suspicion_pct

        # Feature importances from Random Forest (54 canonical features + AE MSE = 55 fused features)
        fi_arr   = _rf_model.feature_importances_
        fi_names = (
            _feature_mapper.canonical_features + ["ae_reconstruction_error"]
            if _feature_mapper
            else [f"feat_{i}" for i in range(len(fi_arr))]
        )
        fi_pairs = sorted(zip(fi_names, fi_arr), key=lambda x: -x[1])[:10]
        fi_list  = [{"feature": n, "importance": float(v)} for n, v in fi_pairs]

        output = {
            "verdict":              verdict,
            # "confidence" is kept only for compatibility with older pages.
            # It now equals the displayed hybrid/suspicion score.
            "confidence":           float(round(display_hybrid_score, 4)),
            "display_score":        float(round(display_hybrid_score, 4)),
            "display_score_label":  "hybrid_score",
            "rf_score":             float(round(rf_pct, 4)),
            "ae_score":             float(round(ae_pct, 4)),
            "hybrid_score":         float(round(display_hybrid_score, 4)),
            "suspicion_score":      float(round(display_hybrid_score, 4)),
            "reconstruction_error": float(rec_err),
            "label":                int(label),
            "feature_importance":   fi_list,
            "explanation":          explanation,
            "anomaly_distribution": {
                "clean":      float(round(100.0 - suspicion_pct, 4)),
                "suspicious": float(round(suspicion_pct, 4)),
            },
            "decision_mode":        "ml_only",
            "extra_features":       {},
        }

        return output

    # ── Findings derivation ───────────────────────────────────────────────────
    @staticmethod
    def derive_findings(session) -> List[Dict]:
        """
        Derive human-readable findings from session artifacts.
        These display in the UI's Key Findings panel but DO NOT change the ML verdict.
        """
        findings = []


        # FIX: Always analyze artifacts regardless of verdict.
        # When ML says CLEAN but the parser flagged indicators, surface them at
        # "medium" severity so the analyst sees the evidence without implying
        # a confirmed threat.  High-noise heuristics (path checks, unsigned DLLs)
        # are still gated behind is_confirmed to avoid FP flooding on clean dumps.
        is_confirmed = session.ml_result.get("verdict", "unknown").lower() == "suspicious"

        # --- Build a PID Map to resolve '?' process names ---
        def _build_pid_map(procs):
            m = {}
            for p in procs:
                pid = p.get("pid")
                if pid is not None:
                    try:
                        m[int(str(pid))] = p.get("image_name", p.get("name", "?"))
                    except ValueError:
                        pass
                m.update(_build_pid_map(p.get("children", [])))
            return m

        pid_map = _build_pid_map(session.processes)

        _LEGIT_PREFIXES = (
            "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
            "c:\\programdata\\", "c:\\users\\",
        )
        _SUSPICIOUS_DIRS = (
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
            "\\appdata\\roaming\\", "\\downloads\\", "\\public\\",
            "\\desktop\\", "\\recycle", "%temp%", "%appdata%",
        )

        def _is_suspicious_path(path: str) -> bool:
            if not path:
                return False
            p = path.lower().replace("/", "\\")
            return any(s in p for s in _SUSPICIOUS_DIRS)

        _KERNEL_PSEUDO_NAMES = {
            'system', 'registry', 'secure system', 'memory compression',
            'memcompression', 'idle',
        }

        def _is_outside_system(path: str) -> bool:
            if not path:
                return False
            p = path.lower().replace("/", "\\")
            if p.strip() in _KERNEL_PSEUDO_NAMES:
                return False
            if p.startswith("\\windows\\") or p.startswith("\\program files"):
                return False
            return not any(p.startswith(prefix) for prefix in _LEGIT_PREFIXES)

        seen_pids: set = set()

        _FINDINGS_FORENSIC_TOOLS = {
            'dumpit.exe', 'ftkimager.exe', 'winpmem.exe',
            'winpmem_mini_x64.exe', 'winpmem_mini_x86.exe',
            'winpmem_x64.exe', 'winpmem_x86.exe',
            'rammap.exe', 'procdump.exe', 'livekd.exe',
            'volatility.exe', 'volatility3.exe',
            'memorize.exe', 'belkasoft ram capturer.exe',
            'magnet ram capture.exe', 'magnetramcapture.exe',
            'rekal.exe', 'rekall.exe',
            'ramdetect.exe', 'ramdetect_gui.exe',
        }

        def _add_proc_finding(p, reason: str, severity: str = "high"):
            pid = p.get("pid", "?")
            if pid in seen_pids:
                return
            seen_pids.add(pid)
            name = p.get("image_name", p.get("name", "?"))
            path = p.get("path", "")
            desc = f"Suspicious process: {name} (PID {pid}) — {reason}"
            if path:
                desc += f"\n   Path: {path}"
            findings.append({"severity": severity, "category": "Process", "description": desc})

        # ── Always: parser-flagged suspicious processes ──────────────────────
        # FIX: case-insensitive status compare (parsers store "SUSPICIOUS" uppercase).
        # When verdict is CLEAN, downgrade to "medium" — parser flagged but ML
        # didn't confirm; worth investigating but not a definitive verdict.
        proc_sev = "high" if is_confirmed else "medium"
        for p in session.processes:
            if str(p.get("status", "")).lower() == "suspicious":
                path = p.get("path", "")
                reasons = []
                if _is_suspicious_path(path):
                    reasons.append("executable in suspicious directory")
                if _is_outside_system(path) and path:
                    reasons.append("executable outside Windows system paths")
                anomaly = p.get("anomaly", "")
                if anomaly:
                    reasons.append(anomaly.lower())
                _add_proc_finding(
                    p,
                    ", ".join(reasons) if reasons else "flagged by parser",
                    severity=proc_sev,
                )

        # ── Always: RWX / injection indicators ──────────────────────────────
        # These are hard forensic evidence regardless of the ML verdict.
        rwx = [
            s for s in session.pe_sections
            if "W" in s.get("perms", "") and "X" in s.get("perms", "")
        ]
        if rwx:
            proc_name = rwx[0].get("process", "?")
            if proc_name == "?":
                pid_raw = rwx[0].get("pid")
                if pid_raw is not None:
                    try:
                        proc_name = pid_map.get(int(str(pid_raw)), "?")
                    except ValueError:
                        pass
            findings.append({
                "severity":    "high",
                "category":    "Code Injection",
                "description": (
                    f"RWX memory region in {proc_name} at {rwx[0].get('va', '?')}"
                    + (f" — {len(rwx)} region(s) total" if len(rwx) > 1 else "")
                ),
            })

        # ── Always: pe_sections marked as injection by InjectionDetector ────
        pe_injections = [
            s for s in session.pe_sections
            if "injection" in str(s.get("anomaly", "")).lower()
            or "injection" in str(s.get("status_reason", "")).lower()
        ]
        if pe_injections and not rwx:   # avoid duplicate if already covered by RWX above
            proc_name = pe_injections[0].get("process", "?")
            findings.append({
                "severity":    "high",
                "category":    "Code Injection",
                "description": (
                    f"Code injection detected in {proc_name}"
                    + (f" — {len(pe_injections)} region(s)" if len(pe_injections) > 1 else "")
                ),
            })

        # ── Always: session.injections (InjectionDetector direct output) ────
        direct_injections = getattr(session, "injections", None) or []
        if direct_injections:
            targets = list({inj.get("process", inj.get("proc_name", "?"))
                            for inj in direct_injections})
            findings.append({
                "severity":    "high",
                "category":    "Code Injection",
                "description": (
                    f"{len(direct_injections)} injection(s) detected by InjectionDetector"
                    + (f" in: {', '.join(targets[:3])}" if targets else "")
                ),
            })

        # ── Gated: noisy heuristics — only surface when ML confirmed SUSPICIOUS ──
        if is_confirmed:
            # Path-heuristic pass (high FP rate on clean systems)
            for p in session.processes:
                path = p.get("path", "")
                if p.get("pid") in seen_pids:
                    continue
                _proc_base = path.lower().replace("/", "\\").rsplit("\\", 1)[-1] if path else ""
                if _proc_base in _FINDINGS_FORENSIC_TOOLS:
                    continue
                if _is_suspicious_path(path):
                    _add_proc_finding(p, "executable in suspicious directory", "high")
                elif _is_outside_system(path) and path and not path.lower().startswith("c:\\"):
                    _add_proc_finding(p, "executable on non-system drive", "medium")

            # Unsigned DLLs (too common on normal systems without ML confirmation)
            unsigned = [d for d in session.dlls if not d.get("signed", True)]
            if unsigned:
                high_ent = [d for d in unsigned if d.get("entropy", 0) > 7.0]
                findings.append({
                    "severity":    "high" if high_ent else "medium",
                    "category":    "DLL",
                    "description": (
                        f"{len(unsigned)} unsigned DLL(s) detected"
                        + (f", {len(high_ent)} with high entropy (>7.0)" if high_ent else "")
                    ),
                })

            # ML explanation (only meaningful when verdict is SUSPICIOUS)
            explanation = session.ml_result.get("explanation", "")
            if explanation:
                findings.append({
                    "severity":    "medium",
                    "category":    "ML Anomaly",
                    "description": explanation,
                })

        # ── Unconfirmed note — shown when ML says CLEAN but artifacts were flagged ──
        elif findings:
            findings.append({
                "severity":    "low",
                "category":    "ML Note",
                "description": (
                    "ML classified this dump as CLEAN "
                    f"(hybrid score {float(session.ml_result.get('hybrid_score', session.ml_result.get('confidence', 0))):.1f}%). "
                    "The indicators above were flagged by the memory parser but not confirmed "
                    "by the RF-AE model. Review the report-only artifact tables and "
                    "parser debug exports for additional analyst context."
                ),
            })

        _SEV = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: _SEV.get(f.get("severity", "low"), 2))

        return findings

    # ── Feature importances ───────────────────────────────────────────────────
    @staticmethod
    def get_feature_importances() -> List[Dict]:
        """Return top-10 feature importance pairs for the ML Insights chart."""
        if _IMPORT_ERROR:
            raise RuntimeError(_IMPORT_ERROR)

        _load_models()

        fi_arr   = _rf_model.feature_importances_
        fi_names = (
            _feature_mapper.canonical_features + ["ae_reconstruction_error"]
            if _feature_mapper
            else [f"feat_{i}" for i in range(len(fi_arr))]
        )
        pairs = sorted(zip(fi_names, fi_arr), key=lambda x: -x[1])[:10]
        return [{"feature": n, "importance": float(v)} for n, v in pairs]

    @staticmethod
    def get_loaded_models() -> Dict[str, Any]:
        """
        Return cached model objects and active model paths for diagnostic-only
        feature debugging. This method must not run prediction or change verdict
        logic; it only ensures the same runtime models are loaded and exposes
        references for export_feature_debug().
        """
        if _IMPORT_ERROR:
            raise RuntimeError(_IMPORT_ERROR)

        _load_models()

        return {
            "rf_model": _rf_model,
            "random_forest_model": _rf_model,
            "ae_model": _ae_model,
            "autoencoder_model": _ae_model,
            "hybrid_model": _hybrid_model,
            "feature_mapper": _feature_mapper,
            "rf_model_path": Config.rf_model_path,
            "ae_model_path": Config.ae_model_path,
            "feature_mapper_path": Config.feature_mapper_path,
        }

    @staticmethod
    def get_model_metrics() -> Dict:
        return REAL_MODEL_METRICS

    @staticmethod
    def get_model_metadata() -> Dict[str, Any]:
        """Read models/training_report.json + models/evaluation_report.json."""
        meta: Dict[str, Any] = {
            "trained":       "Not yet trained",
            "version":       "v2.4.0-RF-AE-Fusion",
            "features":      55,
            "total_samples": 0,
            "n_train":       0,
            "n_val":         0,
            "n_test":        0,
            "training_time": "—",
            "rf_train_time": "—",
            "ae_train_time": "—",
            "accuracy":      REAL_MODEL_METRICS["hybrid"]["accuracy"],
            "precision":     REAL_MODEL_METRICS["hybrid"].get("precision", 0.9993),
            "recall":        REAL_MODEL_METRICS["hybrid"].get("recall",    0.9993),
            "f1":            REAL_MODEL_METRICS["hybrid"]["f1"],
            "fpr":           REAL_MODEL_METRICS["hybrid"]["fpr"],
            "rf_accuracy":   REAL_MODEL_METRICS["random_forest"]["accuracy"],
            "ae_accuracy":   REAL_MODEL_METRICS["autoencoder"]["accuracy"],
        }

        try:
            with open(_TRAINING_REPORT, "r", encoding="utf-8") as fh:
                tr = json.load(fh)
            finished_raw = tr.get("finished_at", "")
            if finished_raw:
                try:
                    dt = datetime.fromisoformat(finished_raw)
                    meta["trained"] = dt.strftime("%b %d, %Y  %H:%M")
                except (ValueError, TypeError):
                    pass
            meta["features"]       = int(tr.get("n_features_base",    52))
            meta["total_samples"]  = int(tr.get("n_total",             0))
            meta["n_train"]        = int(tr.get("n_train",             0))
            meta["n_val"]          = int(tr.get("n_val",               0))
            meta["n_test"]         = int(tr.get("n_test",              0))
            meta["training_time"]  = f"{float(tr.get('total_seconds',  0)):.1f}s"
            meta["rf_train_time"]  = f"{float(tr.get('rf_train_seconds', 0)):.1f}s"
            meta["ae_train_time"]  = f"{float(tr.get('ae_train_seconds', 0)):.1f}s"
        except Exception:
            pass 

        try:
            with open(_EVALUATION_REPORT, "r", encoding="utf-8") as fh:
                er = json.load(fh)
            hybrid = er.get("hybrid", {})
            rf     = er.get("random_forest", {})
            ae     = er.get("autoencoder",   {})

            meta["accuracy"]    = float(hybrid.get("accuracy",             meta["accuracy"]))
            meta["precision"]   = float(hybrid.get("precision",            meta["precision"]))
            meta["recall"]      = float(hybrid.get("recall",               meta["recall"]))
            meta["f1"]          = float(hybrid.get("f1",                   meta["f1"]))
            meta["fpr"]         = float(hybrid.get("false_positive_rate",  meta["fpr"]))
            meta["rf_accuracy"] = float(rf.get("accuracy",                 meta["rf_accuracy"]))
            meta["ae_accuracy"] = float(ae.get("accuracy",                 meta["ae_accuracy"]))
        except Exception:
            pass 

        return meta

    @staticmethod
    def models_available() -> Dict[str, bool]:
        """Return which model files exist on disk — safe to call at any time."""
        return {
            "random_forest":  os.path.exists(Config.rf_model_path),
            "autoencoder":    os.path.exists(Config.ae_model_path),
            "feature_mapper": os.path.exists(Config.feature_mapper_path),
            "import_ok":      _IMPORT_ERROR is None,
            "import_error":   _IMPORT_ERROR or "",
        }
"""
ramdetect/reporting/csv_reporter.py
─────────────────────────────────────
CSV exports for RAMDetect ScanSession.

Phase K4A adds two explicit CSV modes so users do not confuse ML decision
features with CIC-MalMem2022 semantic compatibility/export features.

Modes
-----
1. ml_decision_features
   - Default/recommended for normal users.
   - Exports the feature_names/feature_vector currently used by the RF-AE
     decision path, plus verdict metadata.

2. cic_semantic_compatibility
   - Research/FYP compatibility export.
   - Exports a wide CIC-MalMem2022-shaped row and writes compatibility sidecars.
   - Includes semantic/export-supported fields such as K3B svcscan.* evidence.
   - Does not change FeatureMapper, RF threshold, verdict, or ML pipeline.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Any, Dict, List

try:
    from ramdetect.reporting.cic_canonical_exporter import (
        build_cic_compatible_export,
        load_cic_columns,
    )
except Exception:  # keep ML CSV export working even if optional CIC helper is unavailable
    build_cic_compatible_export = None
    load_cic_columns = None

try:
    from .report_only_artifacts import (
        collect_report_only_ransomware_artifacts,
        summarize_report_only_artifacts,
    )
except Exception:  # report-only artifacts are optional and must never break CSV export
    def collect_report_only_ransomware_artifacts(session):  # type: ignore
        return []
    def summarize_report_only_artifacts(artifacts):  # type: ignore
        return {"count": 0, "max_confidence": 0}


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
    ML models may store it as 0-1 or already 0-100.
    """
    try:
        v = float(raw)
        return v * 100.0 if v <= 1.0 else v
    except (TypeError, ValueError):
        return 0.0


def _safe_mode(options: Dict[str, Any] | None) -> str:
    opts = options or {}
    mode = str(
        opts.get("csv_export_mode")
        or opts.get("csv_mode")
        or opts.get("mode")
        or "ml_decision_features"
    ).strip().lower()
    aliases = {
        "ml": "ml_decision_features",
        "ml_supported": "ml_decision_features",
        "ml_supported_features": "ml_decision_features",
        "decision": "ml_decision_features",
        "decision_features": "ml_decision_features",
        "cic": "cic_semantic_compatibility",
        "semantic": "cic_semantic_compatibility",
        "cic_semantic": "cic_semantic_compatibility",
        "cic_compatibility": "cic_semantic_compatibility",
        "cicmalmem2022": "cic_semantic_compatibility",
    }
    return aliases.get(mode, mode)


def _mode_label(mode: str) -> str:
    if mode == "cic_semantic_compatibility":
        return "CIC-MalMem2022 Semantic Compatibility Export"
    return "ML Decision Feature Export"


def _write_rows(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["category", "key", "value"],
            quoting=csv.QUOTE_MINIMAL,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


# ── Reporter ──────────────────────────────────────────────────────────────────

class CSVReporter:
    """Generates CSV exports from a ScanSession."""

    @staticmethod
    def generate(session, path: str, fname: str, options: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """
        Generate a CSV file.

        ``options['csv_export_mode']`` controls the output:
        - ``ml_decision_features``: flat ML feature vector export.
        - ``cic_semantic_compatibility``: wide CIC-MalMem2022-shaped export.
        """
        mode = _safe_mode(options)
        try:
            if mode == "cic_semantic_compatibility":
                return CSVReporter._generate_cic_semantic(session, path, fname, options or {})
            # Default: safest user-facing ML decision feature export.
            return CSVReporter._generate_ml_decision(session, path, fname, options or {})
        except Exception as exc:
            return {
                "success":  False,
                "path":     path,
                "filename": fname,
                "size_str": "—",
                "error":    str(exc),
                "export_mode": mode,
                "export_mode_label": _mode_label(mode),
            }

    @staticmethod
    def _generate_ml_decision(session, path: str, fname: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Write flat ML decision-path feature export."""
        ml = session.ml_result or {}
        rows: List[Dict[str, Any]] = []

        # Explicit export-mode metadata to avoid confusion with CIC semantic export.
        rows.append({"category": "export", "key": "mode", "value": "ml_decision_features"})
        rows.append({"category": "export", "key": "mode_label", "value": _mode_label("ml_decision_features")})
        rows.append({"category": "export", "key": "verdict_effect", "value": "none_export_only"})
        rows.append({"category": "export", "key": "ml_pipeline_effect", "value": "none_export_only"})

        fc = getattr(session, "feature_coverage", {}) or {}
        if isinstance(fc, dict):
            if fc.get("covered") is not None:
                rows.append({"category": "feature_support", "key": "covered", "value": fc.get("covered")})
            if fc.get("total_canonical") is not None:
                rows.append({"category": "feature_support", "key": "total_canonical", "value": fc.get("total_canonical")})
            if fc.get("coverage_pct") is not None:
                rows.append({"category": "feature_support", "key": "coverage_pct", "value": fc.get("coverage_pct")})

        # Feature vector used by the current ML decision path.
        for name, val in zip(session.feature_names or [], session.feature_vector or []):
            rows.append({"category": "ml_feature", "key": name, "value": val})

        # Verdict scalars.
        for k, v in ml.items():
            if k in ("feature_importance", "anomaly_distribution"):
                continue
            if k in ("confidence", "rf_score", "ae_score"):
                v = _norm_conf(v)
            if isinstance(v, (str, int, float)):
                rows.append({"category": "verdict", "key": k, "value": v})

        # Small artifact metadata only; do not mix report-only ransomware artifacts into
        # this file because the purpose is ML decision-path clarity.
        mapped_files = getattr(session, "mapped_files", []) or []
        rows.append({"category": "artifact", "key": "mapped_file_count", "value": len(mapped_files)})

        _write_rows(path, rows)

        return {
            "success": True,
            "path": path,
            "filename": fname,
            "size_str": _bytes_str(path),
            "error": "",
            "export_mode": "ml_decision_features",
            "export_mode_label": _mode_label("ml_decision_features"),
            "sidecars": {},
        }

    @staticmethod
    def _generate_cic_semantic(session, path: str, fname: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Write wide CIC-MalMem2022 semantic compatibility export."""
        if build_cic_compatible_export is None or load_cic_columns is None:
            raise RuntimeError("CIC compatibility exporter is unavailable")

        dataset_csv = options.get("dataset_csv") or options.get("cic_dataset") or None
        columns = load_cic_columns(dataset_csv)
        wide, matrix, summary = build_cic_compatible_export(session, dataset_csv=dataset_csv)

        # Primary selected CSV is the wide CIC-MalMem2022-style row.
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            writer.writerow(wide)

        stem = os.path.splitext(path)[0]
        matrix_path = f"{stem}_compatibility_matrix.csv"
        summary_path = f"{stem}_summary.json"

        matrix_fields = [
            "session_id", "dump_filename", "cic_feature", "feature_group", "value",
            "status", "defaulted", "ramdetect_source", "compatibility_note",
        ]
        with open(matrix_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=matrix_fields, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            writer.writerows(matrix)

        summary = dict(summary or {})
        summary.update({
            "export_mode": "cic_semantic_compatibility",
            "export_mode_label": _mode_label("cic_semantic_compatibility"),
            "primary_csv": path,
            "compatibility_matrix_csv": matrix_path,
            "verdict_effect": "none",
            "ml_pipeline_effect": "none_export_only",
            "important_note": (
                "This CSV is for CIC-MalMem2022 semantic compatibility/export analysis. "
                "It is not the RF-AE ML decision feature vector. Columns marked default_zero_unmapped "
                "in the compatibility matrix are schema placeholders only."
            ),
        })
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, default=str)

        return {
            "success": True,
            "path": path,
            "filename": fname,
            "size_str": _bytes_str(path),
            "error": "",
            "export_mode": "cic_semantic_compatibility",
            "export_mode_label": _mode_label("cic_semantic_compatibility"),
            "sidecars": {
                "compatibility_matrix_csv": matrix_path,
                "summary_json": summary_path,
                "summary": summary,
            },
        }

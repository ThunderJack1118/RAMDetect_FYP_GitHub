"""
ramdetect/utils/feature_provenance.py
-------------------------------------
Phase I2B diagnostic traceability helper.

Builds a provenance matrix for the live RAMDetect -> CIC canonical feature
mapping. This module is diagnostic-only: it does not change raw feature values,
model inputs, thresholds, or verdict logic.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, Tuple


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
        if math.isnan(out) or math.isinf(out):
            return default
        return out
    except Exception:
        return default


def _family(name: str) -> str:
    return str(name).split(".", 1)[0] if "." in str(name) else "native"


def _recommendation_for(canonical: str, present: bool) -> str:
    """Static safety label from Phase I0/I2A policy."""
    safe = {
        "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.avg_handlers",
        "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
        "handles.nhandles", "handles.avg_handles_per_proc", "handles.nport",
        "handles.nfile", "handles.nevent", "handles.ndesktop", "handles.nkey",
        "handles.nthread", "handles.ndirectory", "handles.nsemaphore",
        "handles.ntimer", "handles.nsection", "handles.nmutant",
    }
    partial = {
        "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
        "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
        "malfind.ninjections", "malfind.commitCharge", "malfind.uniqueInjections",
    }
    diagnostic = {
        "psxview.not_in_pslist", "psxview.not_in_pslist_false_avg",
        "psxview.not_in_ethread_pool", "psxview.not_in_ethread_pool_false_avg",
    }
    if canonical in safe and present:
        return "SAFE"
    if canonical in partial and present:
        return "PARTIAL"
    if canonical in diagnostic and present:
        return "DIAGNOSTIC_ONLY"
    return "DEFAULTED" if not present else "REVIEW_REQUIRED"


def _value_type(canonical: str) -> str:
    if (canonical.endswith("_avg") or canonical.endswith("avg_threads") or
        canonical.endswith("avg_handlers") or canonical.endswith("avg_handles_per_proc") or
        canonical.endswith("avg_dlls_per_proc") or canonical.endswith("false_avg")):
        return "average_or_ratio"
    return "count"


def _evidence_level(canonical: str, present: bool) -> str:
    fam = _family(canonical)
    if not present:
        return "default_used"
    if fam in {"pslist", "dlllist", "handles"}:
        return "direct_saved_artifact_count"
    if fam in {"ldrmodules", "malfind"}:
        return "parser_confirmed_partial"
    if fam == "psxview":
        return "diagnostic_partial_cross_view"
    return "requires_parser_completion"


def build_feature_provenance(
    raw_features: Mapping[str, Any],
    mapper: Any,
    coverage_report: Mapping[str, Any] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Return (provenance_rows, canonical_matrix_rows).

    The function mirrors FeatureMapper source-key selection at a metadata level.
    It does not transform, scale, or alter values.
    """
    try:
        from ramdetect.ml.feature_mapper import CANONICAL_FEATURES, FEATURE_DEFAULTS, RAMDETECT_TO_CIC
    except Exception:
        CANONICAL_FEATURES = []
        FEATURE_DEFAULTS = {}
        RAMDETECT_TO_CIC = {}

    canonical = list(getattr(mapper, "canonical_features", None) or CANONICAL_FEATURES)
    defaults = dict(FEATURE_DEFAULTS)

    reverse: Dict[str, List[str]] = {}
    for raw_key, cic_key in dict(RAMDETECT_TO_CIC).items():
        reverse.setdefault(str(cic_key), []).append(str(raw_key))

    rows: List[Dict[str, Any]] = []
    matrix: List[Dict[str, Any]] = []

    for idx, feature in enumerate(canonical):
        candidate_keys = []
        candidate_keys.extend(reverse.get(feature, []))
        candidate_keys.append(feature)

        source_key = ""
        raw_value = None
        for key in candidate_keys:
            if key in raw_features:
                source_key = key
                raw_value = raw_features.get(key)
                break

        present = bool(source_key)
        used_default = not present
        live_value = _safe_float(raw_value, _safe_float(defaults.get(feature, 0.0), 0.0)) if present else _safe_float(defaults.get(feature, 0.0), 0.0)
        recommendation = _recommendation_for(feature, present)
        row = {
            "index": idx,
            "canonical_feature": feature,
            "family": _family(feature),
            "source_raw_key": source_key,
            "candidate_raw_keys": candidate_keys,
            "raw_value": raw_value if present else "",
            "live_value_or_default": live_value,
            "used_default": used_default,
            "default_value": defaults.get(feature, 0.0),
            "value_type": _value_type(feature),
            "evidence_level": _evidence_level(feature, present),
            "ml_safety_recommendation": recommendation,
            "diagnostic_only": True,
            "note": "provenance only; does not affect ML input",
        }
        rows.append(row)
        matrix.append({
            "canonical_feature": feature,
            "family": row["family"],
            "source_raw_key": source_key,
            "used_default": used_default,
            "evidence_level": row["evidence_level"],
            "ml_safety_recommendation": recommendation,
        })
    return rows, matrix

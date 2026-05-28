"""
ramdetect/utils/feature_debug.py
--------------------------------
Diagnostic-only export for RAMDetect live feature-vector debugging.

This module is intentionally read-only:
- it does not change session.ml_result
- it does not change model scores, thresholds, or verdicts
- it does not call Volatility or any external analyzer
- failures are intended to be caught by the caller and logged as warnings

Export location:
    output/feature_debug/<session_id>/
"""

from __future__ import annotations

import csv
import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import numpy as np

from ramdetect.ml.feature_mapper import (
    CANONICAL_FEATURES,
    COUNT_FEATURE_NAMES,
    FEATURE_DEFAULTS,
    RAMDETECT_TO_CIC,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Small safe helpers
# ---------------------------------------------------------------------------

def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to finite float; return default on failure."""
    try:
        out = float(value)
        if math.isnan(out) or math.isinf(out):
            return default
        return out
    except Exception:
        return default


def _jsonable(value: Any) -> Any:
    """Convert numpy/scalar/path objects into JSON-safe values recursively."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, np.generic):
        return _jsonable(value.item())
    if isinstance(value, np.ndarray):
        return [_jsonable(v) for v in value.tolist()]
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(_jsonable(payload), fh, indent=2, ensure_ascii=False)


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: List[str]) -> None:
    # PHASE_I2F_CSV_SAFE_CELL_FEATURE_DEBUG
    # Diagnostic export only. Converts nested/dirty memory-derived values into
    # safe printable cells so CSV export cannot fail on NUL/control characters
    # or quoting edge cases. Does not affect ML input or verdict logic.
    def _safe_cell(value: Any) -> str:
        try:
            value = _jsonable(value)
            if isinstance(value, (dict, list, tuple, set)):
                s = json.dumps(value, ensure_ascii=False, default=str)
            else:
                s = "" if value is None else str(value)
        except Exception:
            s = ""
        return s.replace("\x00", "")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
            escapechar="\\",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _safe_cell(row.get(k, "")) for k in fieldnames})


def _as_fraction(score: Any) -> float:
    """Normalize a score that may be 0-1 or 0-100 into 0-1."""
    value = _safe_float(score, 0.0)
    return value / 100.0 if value > 1.0 else value


def _score_percent(score: Any) -> float:
    """Normalize a score that may be 0-1 or 0-100 into 0-100."""
    value = _safe_float(score, 0.0)
    return value if value > 1.0 else value * 100.0


# ---------------------------------------------------------------------------
# FeatureMapper mirror logic
# ---------------------------------------------------------------------------

def _mapper_count_indices(mapper: Any, canonical: List[str]) -> List[int]:
    indices = getattr(mapper, "_count_col_indices", None)
    if indices is not None:
        try:
            return [int(i) for i in indices if 0 <= int(i) < len(canonical)]
        except Exception:
            pass
    return [i for i, name in enumerate(canonical) if name in COUNT_FEATURE_NAMES]


def _compress_counts(x_raw: np.ndarray, count_indices: List[int]) -> np.ndarray:
    """Same operation as FeatureMapper v2: log1p on count columns before scaling."""
    x = x_raw.copy().astype(np.float32)
    for idx in count_indices:
        if 0 <= idx < x.shape[1]:
            x[:, idx] = np.log1p(np.maximum(x[:, idx], 0.0))
    return x


def _build_canonical_views(
    raw_features: Mapping[str, Any],
    mapper: Any,
    existing_scaled_vector: Optional[List[float]] = None,
) -> Tuple[List[Dict[str, Any]], np.ndarray, np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Rebuild the exact canonical raw/compressed/scaled feature views using the
    same mapping/default behavior as FeatureMapper.transform_live().
    """
    canonical: List[str] = list(getattr(mapper, "canonical_features", None) or CANONICAL_FEATURES)
    defaults: Dict[str, float] = dict(FEATURE_DEFAULTS)
    count_indices = _mapper_count_indices(mapper, canonical)
    count_index_set = set(count_indices)

    # Mirror FeatureMapper.transform_live():
    #   1) RAMDetect extractor keys are translated through RAMDETECT_TO_CIC.
    #   2) Expanded/native Phase-8 features may already appear in raw_features
    #      using the exact canonical feature name, so consume direct canonical
    #      keys as well.  This fixes the old debug-only mismatch where the live
    #      mapper reported 62/88 coverage but this exporter rebuilt only 28/88.
    #
    # Mapping precedence:
    #   - RAMDETECT_TO_CIC aliases are applied first.
    #   - Direct canonical raw keys then fill only features that were not
    #     already set by an explicit alias. This avoids overriding legacy CIC
    #     aliases such as total_processes -> pslist.nproc.
    cic_values: Dict[str, float] = {}
    source_keys: Dict[str, str] = {}
    source_raw_values: Dict[str, Any] = {}
    mapped_raw_keys: Dict[str, str] = {}

    for raw_key, raw_value in raw_features.items():
        canonical_key = RAMDETECT_TO_CIC.get(raw_key)
        if canonical_key and canonical_key in canonical:
            cic_values[canonical_key] = _safe_float(raw_value, 0.0)
            source_keys[canonical_key] = str(raw_key)
            source_raw_values[canonical_key] = raw_value
            mapped_raw_keys[str(raw_key)] = canonical_key

    for raw_key, raw_value in raw_features.items():
        if raw_key in canonical and raw_key not in cic_values:
            cic_values[str(raw_key)] = _safe_float(raw_value, 0.0)
            source_keys[str(raw_key)] = str(raw_key)
            source_raw_values[str(raw_key)] = raw_value
            mapped_raw_keys[str(raw_key)] = str(raw_key)

    x_raw = np.array(
        [[cic_values.get(name, defaults.get(name, 0.0)) for name in canonical]],
        dtype=np.float32,
    )
    x_compressed = _compress_counts(x_raw, count_indices)

    scaler = getattr(mapper, "scaler", None)
    if scaler is not None:
        x_scaled = scaler.transform(x_compressed).astype(np.float32)
    elif existing_scaled_vector and len(existing_scaled_vector) == len(canonical):
        x_scaled = np.array([existing_scaled_vector], dtype=np.float32)
    else:
        x_scaled = np.zeros_like(x_raw, dtype=np.float32)

    rows: List[Dict[str, Any]] = []
    for idx, name in enumerate(canonical):
        used_default = name not in cic_values
        direct_raw_present = name in raw_features
        source_raw_key = source_keys.get(name, "")
        if used_default:
            note = "default_used"
        elif source_raw_key == name:
            note = "mapped_from_direct_canonical_raw_key"
        else:
            note = "mapped_from_live_raw_key"

        row = {
            "index": idx,
            "canonical_feature": name,
            "live_value": float(x_raw[0, idx]),
            "raw_unscaled_value": float(x_raw[0, idx]),
            "transformed_value": float(x_compressed[0, idx]),
            "scaled_value": float(x_scaled[0, idx]),
            "is_count_feature": idx in count_index_set,
            "source_raw_key": source_raw_key,
            "raw_value": source_raw_values.get(name, ""),
            "used_default": bool(used_default),
            "default_value": defaults.get(name, 0.0) if used_default else "",
            "raw_contains_same_canonical_key": bool(direct_raw_present),
            "same_canonical_raw_value": raw_features.get(name, "") if direct_raw_present else "",
            "note": note,
        }
        # If this still happens after the direct-canonical pass, it means the
        # feature is present in raw_features but absent from the loaded mapper's
        # canonical feature list.
        if used_default and direct_raw_present:
            row["note"] = "raw_contains_canonical_key_but_mapper_uses_default"
        rows.append(row)

    coverage = {
        "total_canonical": len(canonical),
        "covered": len(cic_values),
        "missing": len(canonical) - len(cic_values),
        "coverage_pct": round(len(cic_values) / max(len(canonical), 1) * 100.0, 4),
        "mapped_raw_keys": mapped_raw_keys,
        "missing_features": [name for name in canonical if name not in cic_values],
        "count_features": [canonical[i] for i in count_indices if i < len(canonical)],
    }

    return rows, x_raw, x_compressed, x_scaled, coverage


# ---------------------------------------------------------------------------
# Model introspection
# ---------------------------------------------------------------------------

def _rf_importances(rf_model: Any) -> np.ndarray:
    values = getattr(rf_model, "feature_importances_", None)
    if values is None and getattr(rf_model, "model", None) is not None:
        values = getattr(rf_model.model, "feature_importances_", None)
    if values is None:
        return np.array([], dtype=np.float32)
    return np.asarray(values, dtype=np.float32).ravel()


def _rf_threshold(rf_model: Any) -> float:
    try:
        return float(rf_model.get_decision_threshold())
    except Exception:
        return _safe_float(getattr(rf_model, "threshold", 0.5), 0.5)


def _model_path(value: Any) -> str:
    return str(value) if value is not None else ""



# ---------------------------------------------------------------------------
# Native54 Phase-2A diagnostics (read-only)
# ---------------------------------------------------------------------------

def _flatten_artifact_list(value: Any) -> List[Dict[str, Any]]:
    """Return a flat list of dict artifacts from list/dict/None inputs."""
    if value is None:
        return []
    if isinstance(value, dict):
        out: List[Dict[str, Any]] = []
        for item in value.values():
            if isinstance(item, list):
                out.extend(x for x in item if isinstance(x, dict))
            elif isinstance(item, dict):
                out.append(item)
        return out
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return []


def _session_parsed_data(session: Any) -> Dict[str, Any]:
    """Build a parsed_data-like dict from the ScanSession object."""
    pe_sections = _flatten_artifact_list(getattr(session, "pe_sections", []) or [])
    mapped_files = _flatten_artifact_list(getattr(session, "mapped_files", []) or [])
    return {
        "processes": _flatten_artifact_list(getattr(session, "processes", []) or []),
        "threads": _flatten_artifact_list(getattr(session, "threads", []) or []),
        "dlls": _flatten_artifact_list(getattr(session, "dlls", []) or []),
        "handles": _flatten_artifact_list(getattr(session, "handles", []) or []),
        "pe_sections": pe_sections,
        "memory_regions": pe_sections,
        "vads": pe_sections,
        "mapped_files": mapped_files,
        "injections": _flatten_artifact_list(getattr(session, "injections", []) or []),
        "service_registry_records": _flatten_artifact_list(getattr(session, "service_registry_records", []) or []),
        "service_registry_summary": getattr(session, "service_registry_summary", {}) or {},
    }


def _artifact_name(row: Mapping[str, Any], *keys: str) -> str:
    import os
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-", "None", "none", "N/A", "n/a"):
            text = str(value).replace("/", "\\").strip()
            base = os.path.basename(text)
            return (base or text).lower().strip()
    return ""


def _artifact_path(row: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-", "None", "none", "N/A", "n/a"):
            return str(value).replace("/", "\\").lower().strip()
    return ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return int(value)
        text = str(value).strip()
        if not text or text in {"-", "?", "None", "none", "N/A", "n/a"}:
            return default
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except Exception:
        return default


def _phase2_modules_diagnostics(parsed_data: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Diagnostic-only module summary. This does NOT claim to be a safe live
    replacement for Volatility windows.modules; it helps evaluate whether a
    native modules.nmodules candidate exists.
    """
    import os
    dlls = _flatten_artifact_list(parsed_data.get("dlls"))
    module_stats: Dict[str, Dict[str, Any]] = {}

    for dll in dlls:
        path = _artifact_path(dll, "path", "full_path", "mapped_file_name", "file", "filename")
        name = _artifact_name(dll, "name", "dll_name", "module_name", "path", "full_path", "mapped_file_name")
        if not name:
            continue
        ext = os.path.splitext(name)[1].lower()
        is_kernel_like = bool(ext == ".sys" or "\\drivers\\" in path or "\\system32\\drivers" in path)
        pid = _safe_int(dll.get("pid") or dll.get("PID"), 0)
        rec = module_stats.setdefault(name, {
            "module_name": name,
            "extension": ext,
            "is_kernel_like": is_kernel_like,
            "row_count": 0,
            "pids": set(),
            "example_path": path,
        })
        rec["row_count"] += 1
        rec["is_kernel_like"] = bool(rec["is_kernel_like"] or is_kernel_like)
        if pid:
            rec["pids"].add(pid)
        if not rec.get("example_path") and path:
            rec["example_path"] = path

    rows: List[Dict[str, Any]] = []
    for rec in module_stats.values():
        rows.append({
            "module_name": rec["module_name"],
            "extension": rec["extension"],
            "is_kernel_like": bool(rec["is_kernel_like"]),
            "row_count": int(rec["row_count"]),
            "pid_count": len(rec["pids"]),
            "example_path": rec.get("example_path", ""),
            "diagnostic_only": True,
        })
    rows.sort(key=lambda r: (not bool(r["is_kernel_like"]), -int(r["row_count"]), str(r["module_name"])))

    kernel_like = [r for r in rows if r["is_kernel_like"]]
    summary = {
        "dll_rows_total": len(dlls),
        "unique_module_names_all": len(rows),
        "unique_kernel_like_module_names": len(kernel_like),
        "candidate_modules_nmodules_value": len(kernel_like),
        "candidate_basis": "unique .sys / driver-path module names from DLL rows",
        "caution": (
            "Diagnostic only. CIC modules.nmodules represents kernel module enumeration; "
            "DLL rows are not an exact substitute until validated against clean and malicious dumps."
        ),
    }
    return summary, rows


def _phase2_service_rows(service_features: Mapping[str, Any], canonical_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    current_by_feature = {r.get("canonical_feature"): r for r in canonical_rows}
    aliases = {
        "svcscan.nservices": ["svcscan.nservices", "total_services", "service_artifacts_total"],
        "svcscan.kernel_drivers": ["svcscan.kernel_drivers", "kernel_driver_services", "service_kernel_drivers"],
        "svcscan.fs_drivers": ["svcscan.fs_drivers", "filesystem_driver_services", "service_fs_drivers"],
        "svcscan.process_services": ["svcscan.process_services", "process_services", "service_process_hosts"],
        "svcscan.shared_process_services": ["svcscan.shared_process_services", "shared_process_services", "service_shared_hosts"],
        "svcscan.interactive_process_services": ["svcscan.interactive_process_services", "interactive_process_services", "service_interactive_processes"],
        "svcscan.nactive": ["svcscan.nactive", "active_services", "total_services"],
    }
    rows: List[Dict[str, Any]] = []
    for canonical, keys in aliases.items():
        diag_value = ""
        source_key = ""
        for key in keys:
            if key in service_features:
                diag_value = service_features.get(key)
                source_key = key
                break
        current = current_by_feature.get(canonical, {})
        rows.append({
            "canonical_feature": canonical,
            "diagnostic_raw_value": diag_value,
            "diagnostic_source_key": source_key,
            "featuremapper_default_value": FEATURE_DEFAULTS.get(canonical, 0.0),
            "current_live_value_used_by_model": current.get("live_value", ""),
            "current_scaled_value_used_by_model": current.get("scaled_value", ""),
            "current_used_default": current.get("used_default", ""),
            "would_increase_coverage_if_mapped": bool(current.get("used_default", False) and diag_value != ""),
            "diagnostic_only": True,
            "note": "not injected into raw_features or ML vector",
        })
    return rows


def _export_phase2a_native_diagnostics(
    session: Any,
    out_dir: Path,
    canonical_rows: List[Dict[str, Any]],
    log: logging.Logger,
) -> None:
    """
    Export Native54 Phase-2A svcscan/modules diagnostics only.
    This must never mutate session.raw_features, session.feature_vector,
    session.ml_result, thresholds, or verdicts.
    """
    parsed_data = _session_parsed_data(session)

    service_features: Dict[str, Any] = {}
    service_error = ""
    try:
        from ramdetect.features.service_artifact_features import ServiceArtifactFeatureBuilder
        service_features = ServiceArtifactFeatureBuilder(logger=log).build(parsed_data) or {}
    except Exception as exc:
        service_error = str(exc)
        service_features = {}

    service_rows = _phase2_service_rows(service_features, canonical_rows)
    modules_summary, module_rows = _phase2_modules_diagnostics(parsed_data)

    session_id = str(getattr(session, "session_id", "unknown_session") or "unknown_session")
    payload = {
        "session_id": session_id,
        "description": "Native54 Phase-2A diagnostic-only svcscan/modules candidates.",
        "diagnostic_only": True,
        "not_injected_into_ml": True,
        "no_threshold_or_verdict_change": True,
        "service_builder": {
            "available": service_error == "",
            "error": service_error,
            "raw_features": service_features,
            "canonical_candidates": service_rows,
        },
        "modules_diagnostic": modules_summary,
        "artifact_counts": {
            "processes": len(parsed_data.get("processes", [])),
            "dlls": len(parsed_data.get("dlls", [])),
            "handles": len(parsed_data.get("handles", [])),
            "threads": len(parsed_data.get("threads", [])),
            "injections": len(parsed_data.get("injections", [])),
        },
    }
    _write_json(out_dir / "native_phase2_diagnostics.json", payload)
    _write_csv(
        out_dir / "native_phase2_services.csv",
        service_rows,
        [
            "canonical_feature", "diagnostic_raw_value", "diagnostic_source_key",
            "featuremapper_default_value", "current_live_value_used_by_model",
            "current_scaled_value_used_by_model", "current_used_default",
            "would_increase_coverage_if_mapped", "diagnostic_only", "note",
        ],
    )
    _write_csv(
        out_dir / "native_phase2_modules.csv",
        module_rows,
        [
            "module_name", "extension", "is_kernel_like", "row_count",
            "pid_count", "example_path", "diagnostic_only",
        ],
    )


# ---------------------------------------------------------------------------
# Native54 Phase-3A PSXView diagnostics (read-only)
# ---------------------------------------------------------------------------

_PSXVIEW_CANONICAL_FEATURES = [
    "psxview.not_in_pslist",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg",
    "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
]

_PSXVIEW_THREAD_MISMATCH_SAFE_NAMES = {
    # Kernel / pseudo-processes
    "system", "registry", "secure system", "memcompression", "memcompression.exe",
    # Session / protected / PPL processes where ETHREAD walking can legitimately
    # be incomplete from a raw dump even when EPROCESS.ActiveThreads is non-zero.
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "fontdrvhost.exe", "dwm.exe", "audiodg.exe",
    "securityhealthservice.exe", "securityhealth.exe", "securityhealthserv",
    "msmpeng.exe", "nissrv.exe", "mssense.exe",
    # Common COM/UWP/service hosts with DTB/PEB restrictions in live dumps.
    "svchost.exe", "dllhost.exe", "runtimebroker.exe", "sihost.exe",
    "taskhostw.exe", "ctfmon.exe", "spoolsv.exe", "wmiprvse.exe",
    "searchindexer.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
    "searchfilterho.exe", "searchprotocol.exe", "searchhost.exe",
    "startmenuexper.exe", "startmenuexperiencehost.exe", "backgroundtran.exe",
    "backgroundtransferhost.exe", "dataexchangeho.exe", "dataexchangehost.exe",
    "shellhost.exe", "gamebar.exe", "gamebarft.exe", "widgets.exe",
    "crossdeviceres.exe", "crossdeviceservice.exe", "msedgewebview2.exe",
    "smartscreen.exe", "smartscreen.ex.exe", "usoclient.exe", "olk.exe",
    # Acquisition / forensic utilities.
    "dumpit.exe", "ftkimager.exe", "winpmem.exe", "rammap.exe",
}


def _process_display_name(proc: Mapping[str, Any]) -> str:
    return str(
        proc.get("image_name")
        or proc.get("name")
        or proc.get("process_name")
        or proc.get("Process Name")
        or ""
    ).strip()


def _process_pid(proc: Mapping[str, Any]) -> int:
    return _safe_int(proc.get("pid", proc.get("PID", proc.get("UniqueProcessId", 0))), 0)


def _process_ppid(proc: Mapping[str, Any]) -> int:
    return _safe_int(proc.get("ppid", proc.get("PPID", proc.get("parent_pid", 0))), 0)


def _process_path(proc: Mapping[str, Any]) -> str:
    return str(
        proc.get("path")
        or proc.get("exe_path")
        or proc.get("image_path")
        or proc.get("full_path")
        or proc.get("Path")
        or ""
    ).strip()


def _process_anomaly_text(proc: Mapping[str, Any]) -> str:
    anomalies = proc.get("anomalies", proc.get("anomaly", ""))
    if isinstance(anomalies, (list, tuple, set)):
        return "; ".join(str(a) for a in anomalies if a not in (None, ""))
    return str(anomalies or "")


def _truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (1, 1.0):
        return True
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "hidden", "suspicious"}


def _phase3_current_rows(canonical_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(r.get("canonical_feature")): r for r in canonical_rows}


def _phase3_candidate_row(
    canonical_feature: str,
    diagnostic_raw_value: Any,
    diagnostic_source: str,
    confidence: str,
    reason: str,
    current_by_feature: Mapping[str, Mapping[str, Any]],
    mappable_after_validation: bool,
) -> Dict[str, Any]:
    current = current_by_feature.get(canonical_feature, {})
    has_value = diagnostic_raw_value not in (None, "")
    return {
        "canonical_feature": canonical_feature,
        "diagnostic_raw_value": diagnostic_raw_value if has_value else "",
        "diagnostic_source_key": diagnostic_source,
        "featuremapper_default_value": FEATURE_DEFAULTS.get(canonical_feature, 0.0),
        "current_live_value_used_by_model": current.get("live_value", ""),
        "current_scaled_value_used_by_model": current.get("scaled_value", ""),
        "current_used_default": current.get("used_default", ""),
        "would_increase_coverage_if_mapped": bool(current.get("used_default", False) and has_value),
        "diagnostic_confidence": confidence,
        "mappable_after_validation": bool(mappable_after_validation),
        "diagnostic_only": True,
        "note": reason,
    }


def _phase3_psxview_diagnostics(
    parsed_data: Mapping[str, Any],
    canonical_rows: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Build native PSXView-style diagnostics from artifacts already present in the
    ScanSession. This is intentionally conservative and does not claim parity
    with Volatility's psxview plugin.

    Evidence available now:
      * EPROCESS pool scan output from RAMDetect's native scanner.
      * Optional ActiveProcessLinks DKOM stamps added by EProcessScanner
        (found_by_pool, found_by_links, dkom_detected, hidden).
      * Native ETHREAD rows recovered by ThreadParser.

    Evidence not available yet:
      * PspCidTable walk.
      * CSRSS handle table walk.
      * Session process list walk.
      * Desktop thread list walk.

    Therefore, only pslist-vs-pool and a low-confidence ETHREAD consistency
    signal are exported as candidates. Unsupported views remain blank.
    """
    processes = _flatten_artifact_list(parsed_data.get("processes"))
    threads = _flatten_artifact_list(parsed_data.get("threads"))
    current_by_feature = _phase3_current_rows(canonical_rows)

    thread_counts: Dict[int, int] = {}
    for th in threads:
        pid = _safe_int(th.get("pid", th.get("PID", 0)), 0)
        if pid:
            thread_counts[pid] = thread_counts.get(pid, 0) + 1

    rows: List[Dict[str, Any]] = []
    hidden_from_links = 0
    active_thread_mismatch = 0
    active_thread_mismatch_low_conf = 0
    eligible_for_thread_check = 0
    linked_flag_present = False

    for proc in processes:
        pid = _process_pid(proc)
        ppid = _process_ppid(proc)
        name = _process_display_name(proc)
        name_l = name.lower().strip()
        path = _process_path(proc)
        active_threads = _safe_int(proc.get("active_threads", proc.get("ActiveThreads", 0)), 0)
        enumerated_threads = thread_counts.get(pid, 0)

        found_by_pool = True if "found_by_pool" not in proc else _truthy_flag(proc.get("found_by_pool"))
        if "found_by_links" in proc:
            linked_flag_present = True
            found_by_links = _truthy_flag(proc.get("found_by_links"))
        else:
            found_by_links = ""

        dkom_detected = _truthy_flag(proc.get("dkom_detected", False)) or _truthy_flag(proc.get("hidden", False))
        not_in_pslist_candidate = bool(found_by_pool and (dkom_detected or found_by_links is False))
        if not_in_pslist_candidate:
            hidden_from_links += 1

        # ETHREAD consistency check is intentionally low-confidence: a process
        # with EPROCESS.ActiveThreads > 0 but no recovered ETHREAD rows may be a
        # real cross-view issue, or it may simply be a DTB/offset/read failure.
        thread_check_safe = name_l in _PSXVIEW_THREAD_MISMATCH_SAFE_NAMES or pid in (0, 4)
        ethread_mismatch_candidate = bool(
            active_threads > 0
            and enumerated_threads == 0
            and not thread_check_safe
        )
        if active_threads > 0 and not thread_check_safe:
            eligible_for_thread_check += 1
        if ethread_mismatch_candidate:
            active_thread_mismatch += 1
            active_thread_mismatch_low_conf += 1

        if not_in_pslist_candidate:
            pslist_note = "pool process not present in ActiveProcessLinks walk"
        elif found_by_links == "":
            pslist_note = "ActiveProcessLinks diagnostic flag unavailable"
        else:
            pslist_note = "visible in pool/list view or no DKOM flag"

        if ethread_mismatch_candidate:
            ethread_note = "EPROCESS.ActiveThreads > 0 but ThreadParser recovered 0 rows; low-confidence diagnostic"
        elif thread_check_safe:
            ethread_note = "excluded from ETHREAD mismatch candidate by safe-process guard"
        else:
            ethread_note = "no ETHREAD mismatch candidate"

        rows.append({
            "pid": pid,
            "ppid": ppid,
            "image_name": name,
            "path": path,
            "found_by_pool": found_by_pool,
            "found_by_links": found_by_links,
            "dkom_detected": dkom_detected,
            "hidden": _truthy_flag(proc.get("hidden", False)),
            "active_threads_eprocess": active_threads,
            "enumerated_threads": enumerated_threads,
            "not_in_pslist_candidate": not_in_pslist_candidate,
            "ethread_mismatch_candidate": ethread_mismatch_candidate,
            "thread_check_safe_name": thread_check_safe,
            "anomalies": _process_anomaly_text(proc),
            "pslist_note": pslist_note,
            "ethread_note": ethread_note,
            "diagnostic_only": True,
        })

    n_processes = len(processes)
    pslist_ratio = hidden_from_links / max(n_processes, 1)
    ethread_ratio = active_thread_mismatch / max(eligible_for_thread_check, 1)

    canonical_candidates = [
        _phase3_candidate_row(
            "psxview.not_in_pslist",
            float(hidden_from_links),
            "found_by_pool_and_not_found_by_links",
            "medium" if linked_flag_present else "unavailable",
            "Native DKOM cross-reference from EPROCESS pool scan vs ActiveProcessLinks; diagnostic-only.",
            current_by_feature,
            mappable_after_validation=bool(linked_flag_present),
        ),
        _phase3_candidate_row(
            "psxview.not_in_pslist_false_avg",
            float(pslist_ratio),
            "not_in_pslist_count / total_processes",
            "medium" if linked_flag_present else "unavailable",
            "Ratio derived from native DKOM cross-reference; diagnostic-only.",
            current_by_feature,
            mappable_after_validation=bool(linked_flag_present),
        ),
        _phase3_candidate_row(
            "psxview.not_in_ethread_pool",
            float(active_thread_mismatch),
            "active_threads_gt0_but_no_recovered_ethread_rows",
            "low",
            "Low-confidence ETHREAD consistency check; not safe for ML mapping until validated across more clean dumps.",
            current_by_feature,
            mappable_after_validation=False,
        ),
        _phase3_candidate_row(
            "psxview.not_in_ethread_pool_false_avg",
            float(ethread_ratio),
            "ethread_mismatch_count / eligible_processes",
            "low",
            "Low-confidence ETHREAD ratio; diagnostic-only.",
            current_by_feature,
            mappable_after_validation=False,
        ),
    ]

    unsupported = {
        "psxview.not_in_eprocess_pool": "requires ActiveProcessLinks/list-only process source not present in current session export",
        "psxview.not_in_pspcid_list": "requires native PspCidTable walk; not implemented",
        "psxview.not_in_csrss_handles": "requires native CSRSS handle-table cross-view; not implemented",
        "psxview.not_in_session": "requires native session process list walk; not implemented",
        "psxview.not_in_deskthrd": "requires native desktop thread list walk; not implemented",
        "psxview.not_in_eprocess_pool_false_avg": "requires ActiveProcessLinks/list-only process source not present in current session export",
        "psxview.not_in_pspcid_list_false_avg": "requires native PspCidTable walk; not implemented",
        "psxview.not_in_csrss_handles_false_avg": "requires native CSRSS handle-table cross-view; not implemented",
        "psxview.not_in_session_false_avg": "requires native session process list walk; not implemented",
        "psxview.not_in_deskthrd_false_avg": "requires native desktop thread list walk; not implemented",
    }
    for feature, reason in unsupported.items():
        canonical_candidates.append(
            _phase3_candidate_row(
                feature,
                "",
                "",
                "unavailable",
                reason,
                current_by_feature,
                mappable_after_validation=False,
            )
        )

    rows.sort(key=lambda r: (
        not bool(r.get("not_in_pslist_candidate")),
        not bool(r.get("ethread_mismatch_candidate")),
        int(r.get("pid") or 0),
    ))

    summary = {
        "processes_total": n_processes,
        "threads_total": len(threads),
        "unique_thread_pids": len(thread_counts),
        "linked_list_flags_available": linked_flag_present,
        "not_in_pslist_candidate_count": hidden_from_links,
        "not_in_pslist_candidate_ratio": pslist_ratio,
        "ethread_mismatch_candidate_count": active_thread_mismatch,
        "ethread_mismatch_low_confidence_count": active_thread_mismatch_low_conf,
        "ethread_mismatch_eligible_processes": eligible_for_thread_check,
        "ethread_mismatch_candidate_ratio": ethread_ratio,
        "unsupported_views": unsupported,
        "caution": (
            "Diagnostic only. These values are not Volatility psxview parity. "
            "Only pool-vs-ActiveProcessLinks and low-confidence ETHREAD consistency "
            "signals are available from the current session artifacts. Do not map "
            "these into ML until clean/malicious what-if replay proves safety."
        ),
    }
    return summary, canonical_candidates, rows


def _export_phase3a_psxview_diagnostics(
    session: Any,
    out_dir: Path,
    canonical_rows: List[Dict[str, Any]],
    log: logging.Logger,
) -> None:
    """
    Export Native54 Phase-3A PSXView diagnostics only.
    This must never mutate session.raw_features, session.feature_vector,
    session.ml_result, thresholds, or verdicts.
    """
    parsed_data = _session_parsed_data(session)
    session_id = str(getattr(session, "session_id", "unknown_session") or "unknown_session")
    summary, canonical_candidates, process_rows = _phase3_psxview_diagnostics(parsed_data, canonical_rows)

    payload = {
        "session_id": session_id,
        "description": "Native54 Phase-3A diagnostic-only PSXView-style candidates.",
        "diagnostic_only": True,
        "not_injected_into_ml": True,
        "no_threshold_or_verdict_change": True,
        "psxview_diagnostic": summary,
        "canonical_candidates": canonical_candidates,
    }
    _write_json(out_dir / "native_phase3_psxview_diagnostics.json", payload)
    _write_csv(
        out_dir / "native_phase3_psxview_candidates.csv",
        canonical_candidates,
        [
            "canonical_feature", "diagnostic_raw_value", "diagnostic_source_key",
            "featuremapper_default_value", "current_live_value_used_by_model",
            "current_scaled_value_used_by_model", "current_used_default",
            "would_increase_coverage_if_mapped", "diagnostic_confidence",
            "mappable_after_validation", "diagnostic_only", "note",
        ],
    )
    _write_csv(
        out_dir / "native_phase3_psxview_processes.csv",
        process_rows,
        [
            "pid", "ppid", "image_name", "path", "found_by_pool", "found_by_links",
            "dkom_detected", "hidden", "active_threads_eprocess", "enumerated_threads",
            "not_in_pslist_candidate", "ethread_mismatch_candidate", "thread_check_safe_name",
            "anomalies", "pslist_note", "ethread_note", "diagnostic_only",
        ],
    )

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_feature_debug(
    session: Any,
    ml_models: Optional[Mapping[str, Any]] = None,
    output_root: str | Path = "output/feature_debug",
    logger_: Optional[logging.Logger] = None,
) -> Path:
    """
    Export diagnostic feature-vector files for a completed scan.

    Parameters
    ----------
    session:
        ScanSession-like object with raw_features, feature_vector, ml_result,
        feature_names and session_id fields.
    ml_models:
        Optional dict from MLBridge.get_loaded_models(). Expected keys:
        rf_model, ae_model, hybrid_model, feature_mapper, rf_model_path,
        ae_model_path, feature_mapper_path.
    output_root:
        Base output directory. Defaults to output/feature_debug.

    Returns
    -------
    Path to output/feature_debug/<session_id>/.
    """
    log = logger_ or logger
    ml_models = dict(ml_models or {})

    raw_features: Dict[str, Any] = dict(getattr(session, "raw_features", {}) or {})
    ml_result: Dict[str, Any] = dict(getattr(session, "ml_result", {}) or {})
    existing_scaled = list(getattr(session, "feature_vector", []) or [])

    mapper = ml_models.get("feature_mapper")
    if mapper is None:
        raise RuntimeError("Feature debug requires a loaded FeatureMapper object")

    session_id = str(getattr(session, "session_id", "unknown_session") or "unknown_session")
    out_dir = Path(output_root) / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    canonical_rows, x_raw, x_compressed, x_scaled, coverage = _build_canonical_views(
        raw_features=raw_features,
        mapper=mapper,
        existing_scaled_vector=existing_scaled,
    )

    # Native54 Phase-2A diagnostics are exported from parsed session artifacts
    # only. They are not written back into raw_features or the ML vector.
    try:
        _export_phase2a_native_diagnostics(session, out_dir, canonical_rows, log)
    except Exception as _phase2_diag_ex:
        log.warning("Native Phase-2A diagnostics export skipped: %s", _phase2_diag_ex)

    # Native54 Phase-3A PSXView diagnostics are also read-only and are exported
    # after canonical rows exist so the audit can show current defaults/coverage.
    try:
        _export_phase3a_psxview_diagnostics(session, out_dir, canonical_rows, log)
    except Exception as _phase3_diag_ex:
        log.warning("Native Phase-3A PSXView diagnostics export skipped: %s", _phase3_diag_ex)

    # Compare reconstructed scaled vector with the vector actually stored on the session.
    vector_diff = None
    if existing_scaled and len(existing_scaled) == x_scaled.shape[1]:
        stored = np.asarray(existing_scaled, dtype=np.float32).reshape(1, -1)
        diff = np.abs(stored - x_scaled)
        vector_diff = {
            "max_abs_diff": float(np.max(diff)),
            "mean_abs_diff": float(np.mean(diff)),
            "same_length": True,
        }
    else:
        vector_diff = {
            "max_abs_diff": None,
            "mean_abs_diff": None,
            "same_length": False,
            "stored_vector_length": len(existing_scaled),
            "rebuilt_vector_length": int(x_scaled.shape[1]),
        }

    # 1. raw_features.json
    _write_json(out_dir / "raw_features.json", {
        "session_id": session_id,
        "feature_count": len(raw_features),
        "description": "Full RAMDetect raw feature dictionary before FeatureMapper.transform_live().",
        "raw_features": raw_features,
    })

    # 2. canonical feature debug views. Keep canonical_54_features.json for compatibility.
    canonical_by_name = {row["canonical_feature"]: row for row in canonical_rows}
    canonical_payload = {
        "session_id": session_id,
        "description": (
            "Canonical feature view rebuilt with the same mapping/default/log1p/scaler "
            "behavior as FeatureMapper.transform_live(). raw_unscaled_value is before "
            "log1p; transformed_value is after log1p for count features; scaled_value is "
            "the model-input value."
        ),
        "metadata": {
            "n_features": len(canonical_rows),
            "feature_mapper_class": mapper.__class__.__name__,
            "feature_mapper_version": getattr(mapper, "_VERSION", "unknown"),
            "coverage": coverage,
            "stored_vs_rebuilt_scaled_vector": vector_diff,
        },
        "features": canonical_rows,
        "by_feature": canonical_by_name,
    }
    _write_json(out_dir / "canonical_54_features.json", canonical_payload)
    _write_json(out_dir / "canonical_features.json", canonical_payload)

    # 3. canonical feature CSV. Keep canonical_54_features.csv for compatibility.
    canonical_csv_fields = [
        "index", "canonical_feature", "live_value", "raw_unscaled_value",
        "transformed_value", "scaled_value", "is_count_feature",
        "source_raw_key", "raw_value", "used_default", "default_value",
        "raw_contains_same_canonical_key", "same_canonical_raw_value", "note",
    ]
    _write_csv(out_dir / "canonical_54_features.csv", canonical_rows, canonical_csv_fields)
    _write_csv(out_dir / "canonical_features.csv", canonical_rows, canonical_csv_fields)

    # 4. fused RF-AE feature vector. Keep fused_55_features.json for compatibility.
    ae_mse = _safe_float(
        ml_result.get("reconstruction_error", ml_result.get("ae_error", ml_result.get("autoencoder_mse", 0.0))),
        0.0,
    )
    fused_feature_names = [row["canonical_feature"] for row in canonical_rows] + ["ae_reconstruction_error"]
    fused_values = [row["scaled_value"] for row in canonical_rows] + [ae_mse]
    fused_payload = {
        "session_id": session_id,
        "description": "Exact RF-AE fusion vector: scaled base features plus raw AE reconstruction MSE.",
        "n_features": len(fused_values),
        "features": [
            {"index": i, "feature": name, "value": float(value)}
            for i, (name, value) in enumerate(zip(fused_feature_names, fused_values))
        ],
        "by_feature": {name: float(value) for name, value in zip(fused_feature_names, fused_values)},
    }
    _write_json(out_dir / "fused_55_features.json", fused_payload)
    _write_json(out_dir / "fused_features.json", fused_payload)

    # 5. model_scores.json
    rf_model = ml_models.get("rf_model")
    ae_model = ml_models.get("ae_model")
    threshold = _rf_threshold(rf_model) if rf_model is not None else 0.5
    model_scores = {
        "session_id": session_id,
        "verdict": ml_result.get("verdict", ""),
        "label": ml_result.get("label", ""),
        "decision_mode": ml_result.get("decision_mode", "ml_only"),
        "threshold_fraction": threshold,
        "threshold_percent": threshold * 100.0,
        "rf_score_percent": _score_percent(ml_result.get("rf_score", ml_result.get("rf_suspicion_score", 0.0))),
        "rf_score_fraction": _as_fraction(ml_result.get("rf_score", ml_result.get("rf_suspicion_score", 0.0))),
        "ae_score_percent": _score_percent(ml_result.get("ae_score", 0.0)),
        "ae_score_fraction": _as_fraction(ml_result.get("ae_score", 0.0)),
        "ae_mse": ae_mse,
        "autoencoder_threshold": _safe_float(getattr(ae_model, "threshold", 0.0), 0.0) if ae_model is not None else None,
        "hybrid_score_percent": _score_percent(ml_result.get("hybrid_score", ml_result.get("suspicion_score", ml_result.get("confidence", 0.0)))),
        "hybrid_score_fraction": _as_fraction(ml_result.get("hybrid_score", ml_result.get("suspicion_score", ml_result.get("confidence", 0.0)))),
        "confidence_percent_alias": _score_percent(ml_result.get("confidence", 0.0)),
        "feature_coverage": coverage,
        "feature_vector_lengths": {
            "raw_features": len(raw_features),
            "canonical_54": len(canonical_rows),
            "session_feature_vector": len(existing_scaled),
            "fused_55": len(fused_values),
        },
        "model_paths": {
            "rf_model_path": _model_path(ml_models.get("rf_model_path")),
            "ae_model_path": _model_path(ml_models.get("ae_model_path")),
            "feature_mapper_path": _model_path(ml_models.get("feature_mapper_path")),
        },
        "explanation": ml_result.get("explanation", ""),
    }
    _write_json(out_dir / "model_scores.json", model_scores)

    # 6. top_rf_feature_importances_for_this_run.csv — export all importances.
    importances = _rf_importances(rf_model)
    importance_rows: List[Dict[str, Any]] = []
    if importances.size:
        if importances.size == len(fused_feature_names):
            importance_feature_names = fused_feature_names
            live_lookup = {name: value for name, value in zip(fused_feature_names, fused_values)}
        else:
            rf_feature_names = list(getattr(rf_model, "feature_names", []) or []) if rf_model is not None else []
            if len(rf_feature_names) == importances.size:
                importance_feature_names = rf_feature_names
            else:
                importance_feature_names = [f"feature_{i}" for i in range(importances.size)]
            live_lookup = {name: "" for name in importance_feature_names}
            # Best-effort fill for matching canonical/fused names.
            for name, value in zip(fused_feature_names, fused_values):
                live_lookup[name] = value

        ranked_indices = np.argsort(-importances)
        for rank, idx in enumerate(ranked_indices, start=1):
            name = str(importance_feature_names[int(idx)])
            importance_rows.append({
                "rank": rank,
                "feature": name,
                "importance": float(importances[int(idx)]),
                "live_value": live_lookup.get(name, ""),
            })
    _write_csv(
        out_dir / "top_rf_feature_importances_for_this_run.csv",
        importance_rows,
        ["rank", "feature", "importance", "live_value"],
    )

    # 7. feature_mapping_audit.csv
    audit_fields = [
        "canonical_feature", "live_value", "source_raw_key", "raw_value",
        "used_default", "default_value", "transformed_value", "scaled_value",
        "is_count_feature", "raw_contains_same_canonical_key", "same_canonical_raw_value", "note",
    ]
    _write_csv(out_dir / "feature_mapping_audit.csv", canonical_rows, audit_fields)

    log.info("Feature debug exported to: %s", out_dir)
    return out_dir

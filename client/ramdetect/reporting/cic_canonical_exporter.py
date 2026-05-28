"""
ramdetect/reporting/cic_canonical_exporter.py
──────────────────────────────────────────────
CIC-MalMem2022 canonical compatibility export for RAMDetect sessions.

Purpose
-------
Creates a wide CSV row whose columns mirror the CIC-MalMem2022 dataset schema:
    Category, <canonical CIC memory features...>, Class

It also creates a feature-level compatibility matrix that explains whether each
CIC column was populated from RAMDetect native output, mapped by FeatureMapper,
or defaulted because RAMDetect currently does not extract that canonical field.

Important safety rule
---------------------
This module is export/reporting only. It does not change RF threshold,
FeatureMapper, model files, verdict logic, session artifacts, or malfind mapping.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple


# Header inspected from Obfuscated-MalMem2022.csv / CIC-MalMem2022 style table.
DEFAULT_CIC_COLUMNS: List[str] = [
    "Category",
    "pslist.nproc",
    "pslist.nppid",
    "pslist.avg_threads",
    "pslist.nprocs64bit",
    "pslist.avg_handlers",
    "dlllist.ndlls",
    "dlllist.avg_dlls_per_proc",
    "handles.nhandles",
    "handles.avg_handles_per_proc",
    "handles.nport",
    "handles.nfile",
    "handles.nevent",
    "handles.ndesktop",
    "handles.nkey",
    "handles.nthread",
    "handles.ndirectory",
    "handles.nsemaphore",
    "handles.ntimer",
    "handles.nsection",
    "handles.nmutant",
    "ldrmodules.not_in_load",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.protection",
    "malfind.uniqueInjections",
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
    "modules.nmodules",
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
    "Class",
]

NON_FEATURE_COLUMNS = {"Category", "Class"}

# Known fields that are not currently produced by the RAMDetect CIC54 RF-AE mapping.
# They can still appear in the export table as 0/default so the CSV shape matches
# CIC-MalMem2022, but they should not be treated as extracted evidence unless the
# compatibility matrix says status=mapped.
KNOWN_UNMAPPED_GROUPS = {
    "psxview": "requires native psxview-equivalent parser completion",
    "modules": "requires native modules parser mapping",
    "svcscan": "requires full service state/type/start parser mapping",
    "callbacks": "requires kernel callback parser",
}


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return float(int(value))
        return float(value)
    except Exception:
        return default


def _safe_label(session: Any) -> str:
    ml = _get(session, "ml_result", {}) or {}
    verdict = str(ml.get("verdict", _get(session, "verdict", ""))).strip().lower()
    if verdict in ("clean", "benign"):
        return "Benign"
    if verdict in ("suspicious", "malicious", "malware"):
        return "Malware"
    return "Unknown"


def _safe_category(session: Any) -> str:
    fn = _get(session, "dump_filename", "") or "RAMDetect_Dump"
    stem = os.path.splitext(os.path.basename(str(fn)))[0]
    return stem or "RAMDetect_Dump"


def load_cic_columns(dataset_csv: str | None = None) -> List[str]:
    """Return CIC columns from a dataset header if available; otherwise default."""
    candidates = []
    if dataset_csv:
        candidates.append(dataset_csv)
    candidates += [
        os.path.join("datasets", "Obfuscated-MalMem2022.csv"),
        os.path.join("dataset", "Obfuscated-MalMem2022.csv"),
        "Obfuscated-MalMem2022.csv",
    ]
    for p in candidates:
        try:
            if p and os.path.isfile(p):
                with open(p, "r", encoding="utf-8-sig", newline="") as fh:
                    reader = csv.reader(fh)
                    header = next(reader)
                    if header and "Category" in header and "Class" in header:
                        return [str(c).strip() for c in header]
        except Exception:
            continue
    return list(DEFAULT_CIC_COLUMNS)


def cic_feature_columns(columns: Iterable[str]) -> List[str]:
    return [c for c in columns if c not in NON_FEATURE_COLUMNS]


def _feature_group(name: str) -> str:
    return name.split(".", 1)[0] if "." in name else name


def _extract_from_feature_coverage(session: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Invert session.feature_coverage['mapped_features'].
    That mapping is normally raw_feature_name -> canonical_cic_name.
    """
    raw = _get(session, "raw_features", {}) or {}
    fc = _get(session, "feature_coverage", {}) or {}
    values: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    mapped = {}
    if isinstance(fc, dict):
        mapped = fc.get("mapped_features", {}) or {}
        if isinstance(mapped, str):
            try:
                mapped = json.loads(mapped)
            except Exception:
                mapped = {}
    if isinstance(mapped, dict) and isinstance(raw, dict):
        for raw_name, canonical in mapped.items():
            if canonical in NON_FEATURE_COLUMNS:
                continue
            if raw_name in raw:
                values[str(canonical)] = raw.get(raw_name)
                sources[str(canonical)] = str(raw_name)
    return values, sources


def _extract_from_provenance(session: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Read flexible provenance/matrix shapes produced by RAMDetect debug exports."""
    values: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    rows = []
    for attr in ("feature_provenance", "canonical_feature_matrix"):
        val = _get(session, attr, []) or []
        if isinstance(val, list):
            rows.extend(val)
    name_keys = [
        "canonical_feature", "canonical_name", "cic_feature", "cic_name",
        "feature", "feature_name", "name", "output_feature", "target_feature",
    ]
    val_keys = ["value", "mapped_value", "canonical_value", "final_value", "model_value"]
    source_keys = ["raw_feature", "source_feature", "source", "raw_name", "input_feature"]
    for r in rows:
        if not isinstance(r, dict):
            continue
        cname = None
        for k in name_keys:
            if r.get(k):
                cname = str(r.get(k))
                break
        if not cname or cname in NON_FEATURE_COLUMNS:
            continue
        v = None
        for k in val_keys:
            if k in r:
                v = r.get(k)
                break
        values[cname] = v
        for k in source_keys:
            if r.get(k):
                sources[cname] = str(r.get(k))
                break
    return values, sources


def _extract_from_feature_vector(session: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    names = _get(session, "feature_names", []) or []
    vec = _get(session, "feature_vector", []) or []
    values: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    if isinstance(names, list) and isinstance(vec, list):
        for n, v in zip(names, vec):
            if n and str(n) not in NON_FEATURE_COLUMNS:
                values[str(n)] = v
                sources[str(n)] = "feature_vector"
    return values, sources


def _extract_k3b_svcscan_semantic(session: Any) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, Any]]:
    """Derive svcscan.* values from RAMDetect-native service evidence for export.

    This is used only by the compatibility/reporting exporter. It overrides
    FeatureMapper default svcscan values in the exported CIC row so K2B can
    distinguish RAMDetect-derived service evidence from benign default fillers.
    """
    try:
        from ramdetect.features.svcscan_semantic_features import build_svcscan_semantic_features
        values, sources, summary = build_svcscan_semantic_features(session)
        if not values:
            return {}, {}, summary or {}
        return values, sources, summary
    except Exception as exc:
        return {}, {}, {"ready": False, "error": str(exc)}


def _extract_k3g_malfind_protection_semantic(session: Any) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, Any]]:
    """Derive malfind.protection from RAMDetect-native injection/VAD protection evidence.

    Export-only. This does not modify the ML vector or verdict path.
    """
    try:
        from ramdetect.features.malfind_protection_semantic_features import build_malfind_protection_semantic_feature
        values, sources, summary = build_malfind_protection_semantic_feature(session)
        if not values:
            return {}, {}, summary or {}
        return values, sources, summary
    except Exception as exc:
        return {}, {}, {"ready": False, "error": str(exc)}


def _known_reason(feature: str) -> str:
    group = _feature_group(feature)
    if group in KNOWN_UNMAPPED_GROUPS:
        return KNOWN_UNMAPPED_GROUPS[group]
    if feature == "pslist.nprocs64bit":
        return "not currently produced by RAMDetect process feature mapper"
    if feature == "malfind.protection":
        return "CIC-MalMem field present in dataset; K3G malfind protection semantic source not available for this export"
    return "not mapped by current RAMDetect feature coverage"


def build_cic_compatible_export(
    session: Any,
    dataset_csv: str | None = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """Return (wide_row, compatibility_matrix_rows, summary)."""
    columns = load_cic_columns(dataset_csv)
    features = cic_feature_columns(columns)

    values: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    k3b_svcscan_summary: Dict[str, Any] = {}
    k3g_malfind_protection_summary: Dict[str, Any] = {}
    for extractor in (_extract_from_feature_coverage, _extract_from_provenance, _extract_from_feature_vector):
        v, s = extractor(session)
        # Earlier sources are preferred; later sources fill gaps.
        for k, val in v.items():
            if k not in values:
                values[k] = val
        for k, src in s.items():
            if k not in sources:
                sources[k] = src

    # PHASE_K3B_SVCSCAN_SEMANTIC_EXPORT
    # FeatureMapper may already carry benign/default svcscan values inside the
    # saved feature vector. For CIC compatibility export, prefer RAMDetect-native
    # K3B service evidence so the matrix records actual semantic source evidence
    # rather than treating service fields as opaque defaults. This is export-only.
    k3b_v, k3b_s, k3b_svcscan_summary = _extract_k3b_svcscan_semantic(session)
    for k, val in k3b_v.items():
        values[k] = val
    for k, src in k3b_s.items():
        sources[k] = src

    # PHASE_K3G_MALFIND_PROTECTION_SEMANTIC_EXPORT
    # Prefer explicit RAMDetect injection/VAD protection evidence for the
    # CIC malfind.protection field. This is export-only and does not change
    # FeatureMapper, model input, threshold, or verdict logic.
    k3g_v, k3g_s, k3g_malfind_protection_summary = _extract_k3g_malfind_protection_semantic(session)
    for k, val in k3g_v.items():
        values[k] = val
    for k, src in k3g_s.items():
        sources[k] = src

    wide: Dict[str, Any] = {"Category": _safe_category(session)}
    matrix: List[Dict[str, Any]] = []
    mapped_count = 0
    defaulted_count = 0

    for feature in features:
        if feature in values:
            numeric = _as_float(values[feature])
            wide[feature] = numeric
            mapped_count += 1
            status = "mapped"
            src = sources.get(feature, "RAMDetect")
            if str(src).startswith("k3b_svcscan_semantic"):
                reason = "K3B RAMDetect-native service semantic evidence mapped to CIC svcscan field for compatibility export"
            elif str(src).startswith("k3g_malfind_protection_semantic"):
                reason = "K3G RAMDetect-native injection/VAD protection evidence mapped to CIC malfind.protection for compatibility export"
            else:
                reason = "RAMDetect output mapped to CIC-MalMem feature"
            defaulted = False
        else:
            wide[feature] = 0.0
            defaulted_count += 1
            status = "default_zero_unmapped"
            reason = _known_reason(feature)
            src = "not_available"
            defaulted = True
        matrix.append({
            "session_id": _get(session, "session_id", ""),
            "dump_filename": _get(session, "dump_filename", ""),
            "cic_feature": feature,
            "feature_group": _feature_group(feature),
            "value": wide[feature],
            "status": status,
            "defaulted": defaulted,
            "ramdetect_source": src,
            "compatibility_note": reason,
        })

    wide["Class"] = _safe_label(session)

    mapper_total = None
    fc = _get(session, "feature_coverage", {}) or {}
    if isinstance(fc, dict):
        mapper_total = fc.get("total_canonical")

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "session_id": _get(session, "session_id", ""),
        "dump_filename": _get(session, "dump_filename", ""),
        "dataset_columns_total": len(columns),
        "dataset_feature_columns": len(features),
        "ramdetect_mapped_to_dataset_features": mapped_count,
        "defaulted_unmapped_dataset_features": defaulted_count,
        "dataset_feature_compatibility_pct": round((mapped_count / len(features) * 100.0), 2) if features else 0.0,
        "ramdetect_feature_mapper_total_canonical": mapper_total,
        "label_exported_from_ml_verdict": wide["Class"],
        "verdict_effect": "none",
        "ml_pipeline_effect": "none_export_only",
        "k3b_svcscan_semantic_ready": bool(k3b_svcscan_summary.get("ready")),
        "k3b_svcscan_semantic_quality": k3b_svcscan_summary.get("quality", "unavailable"),
        "k3b_svcscan_semantic_summary": k3b_svcscan_summary,
        "k3g_malfind_protection_semantic_ready": bool(k3g_malfind_protection_summary.get("ready")),
        "k3g_malfind_protection_semantic_quality": k3g_malfind_protection_summary.get("quality", "unavailable"),
        "k3g_malfind_protection_semantic_summary": k3g_malfind_protection_summary,
        "note": (
            "CSV shape is CIC-MalMem2022-compatible. Accuracy depends on mapped feature coverage; "
            "default_zero_unmapped columns are present for dataset shape compatibility only. "
            "K3B svcscan fields and K3G malfind.protection, when present, are derived RAMDetect-native semantic evidence for export traceability."
        ),
    }
    return wide, matrix, summary


def write_cic_compatible_files(
    session: Any,
    out_dir: str,
    base_name: str | None = None,
    dataset_csv: str | None = None,
) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    stem = base_name or os.path.splitext(os.path.basename(_get(session, "dump_filename", "ramdetect_dump")))[0]
    if not stem:
        stem = "ramdetect_dump"

    columns = load_cic_columns(dataset_csv)
    wide, matrix, summary = build_cic_compatible_export(session, dataset_csv=dataset_csv)

    wide_path = os.path.join(out_dir, f"{stem}_cicmalmem2022_row.csv")
    matrix_path = os.path.join(out_dir, f"{stem}_cicmalmem2022_compatibility.csv")
    summary_path = os.path.join(out_dir, f"{stem}_cicmalmem2022_summary.json")

    with open(wide_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        w.writerow(wide)

    matrix_fields = [
        "session_id", "dump_filename", "cic_feature", "feature_group", "value",
        "status", "defaulted", "ramdetect_source", "compatibility_note",
    ]
    with open(matrix_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=matrix_fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(matrix)

    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)

    return {
        "success": True,
        "wide_csv": wide_path,
        "compatibility_csv": matrix_path,
        "summary_json": summary_path,
        "summary": summary,
    }


def write_sidecars_for_report_csv(session: Any, flat_csv_path: str, dataset_csv: str | None = None) -> Dict[str, Any]:
    """Generate CIC compatibility sidecars next to a normal RAMDetect CSV report."""
    out_dir = os.path.dirname(os.path.abspath(flat_csv_path))
    stem = os.path.splitext(os.path.basename(flat_csv_path))[0]
    return write_cic_compatible_files(session, out_dir, base_name=stem, dataset_csv=dataset_csv)

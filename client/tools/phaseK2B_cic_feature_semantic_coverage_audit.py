#!/usr/bin/env python3
"""
Phase K2B — CIC-MalMem2022 Semantic Feature Coverage Audit
===========================================================
Diagnostic-only audit for RAMDetect K2 CIC-MalMem2022 exports.

Why this exists
---------------
K2 proves that RAMDetect can export a wide CSV with the same *shape* as the
CIC-MalMem2022 dataset. K2B separates that schema compatibility from semantic
feature extraction quality, so the FYP report does not over-claim that every
CIC column is fully extracted just because it appears in the CSV.

Inputs
------
--k2-dir: folder containing phaseK2_cicmalmem2022_compatibility_matrix.csv
          and optionally phaseK2_cicmalmem2022_rows.csv / summary.json
--out: output folder

Outputs
-------
phaseK2B_semantic_session_summary.csv
phaseK2B_semantic_feature_status.csv
phaseK2B_semantic_coverage_summary.json
phaseK2B_semantic_coverage_report.md

Rules preserved
---------------
No RF threshold change, no FeatureMapper change, no dataset change,
no session JSON modification, no verdict logic change, no veto rules.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

VALIDATED_EXTRACTED = {
    # pslist validated from RAMDetect process/thread/handle summaries
    "pslist.nproc",
    "pslist.nppid",
    "pslist.avg_threads",
    "pslist.avg_handlers",
    # dlllist
    "dlllist.ndlls",
    "dlllist.avg_dlls_per_proc",
    # handles
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
    # ldrmodules
    "ldrmodules.not_in_load",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",
    # malfind count features from RAMDetect injection evidence / I2G promotion
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.uniqueInjections",
}

EXPLICIT_UNSUPPORTED = {
    # `malfind.protection` can be promoted to validated_extracted only when
    # K2 matrix explicitly shows a K3G RAMDetect-native protection source.
}

NOT_YET_VALIDATED_PREFIXES = {
    "psxview.": "PSXView-style cross-view fields are not yet fully validated as Volatility-equivalent native RAMDetect features.",
    "svcscan.": "Service scanner fields require validated service Type/Start/ImagePath/ServiceDll/state reconstruction before being treated as extracted ML evidence.",
    "callbacks.": "Kernel callback enumeration is not currently implemented as a validated native RAMDetect canonical feature.",
}

NOT_YET_VALIDATED_EXACT = {
    "pslist.nprocs64bit": "64-bit process count is present for dataset shape, but should be treated as derived/placeholder unless architecture-specific per-process validation is implemented.",
    "modules.nmodules": "Kernel module count is present for dataset shape, but native modules-equivalent extraction is not yet validated.",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def classify_feature(feature: str, k2_status: str, defaulted: str, source: str) -> tuple[str, str]:
    feature = feature.strip()
    k2_status_l = (k2_status or "").strip().lower()
    defaulted_l = str(defaulted).strip().lower()

    if feature in EXPLICIT_UNSUPPORTED or k2_status_l == "default_zero_unmapped" or defaulted_l == "true":
        return "unsupported_or_defaulted", EXPLICIT_UNSUPPORTED.get(feature, "K2 marked this field as default-zero/unmapped for schema compatibility only.")

    if feature in VALIDATED_EXTRACTED:
        return "validated_extracted", "RAMDetect currently has a concrete parser/feature source for this CIC-MalMem feature."

    # PHASE_K3B_SVCSCAN_SEMANTIC_VALIDATION
    # Treat svcscan.* as validated only when K2 matrix explicitly shows the
    # RAMDetect-native K3B service semantic source. Feature-vector/default
    # svcscan values remain not-yet-validated placeholders.
    source_l = str(source or "").strip().lower()
    if feature.startswith("svcscan.") and source_l.startswith("k3b_svcscan_semantic"):
        return (
            "validated_extracted",
            "K3B RAMDetect-native service semantic evidence source is present for this svcscan field; exported for CIC compatibility traceability.",
        )

    # PHASE_K3G_MALFIND_PROTECTION_SEMANTIC_VALIDATION
    # Treat malfind.protection as validated only when the K2 matrix explicitly
    # shows K3G RAMDetect-native injection/VAD protection evidence. If it is
    # defaulted/unmapped, it remains unsupported.
    if feature == "malfind.protection" and source_l.startswith("k3g_malfind_protection_semantic"):
        return (
            "validated_extracted",
            "K3G RAMDetect-native injection/VAD protection evidence source is present for malfind.protection; exported for CIC compatibility traceability.",
        )

    if feature in NOT_YET_VALIDATED_EXACT:
        return "not_yet_validated_or_placeholder", NOT_YET_VALIDATED_EXACT[feature]

    for prefix, reason in NOT_YET_VALIDATED_PREFIXES.items():
        if feature.startswith(prefix):
            return "not_yet_validated_or_placeholder", reason

    return "review_needed", "Feature was not in the K2B classification dictionary; review source/provenance manually."


def safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k2-dir", required=True, help="K2 output directory")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()

    k2 = Path(args.k2_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    matrix_path = k2 / "phaseK2_cicmalmem2022_compatibility_matrix.csv"
    if not matrix_path.is_file():
        raise SystemExit(f"Missing K2 matrix: {matrix_path}")

    rows = read_csv(matrix_path)
    if not rows:
        raise SystemExit("K2 matrix is empty")

    # Identify all-zero features across the current sessions.
    values_by_feature: Dict[str, List[float]] = defaultdict(list)
    for r in rows:
        values_by_feature[r.get("cic_feature", "")].append(safe_float(r.get("value", 0)))
    all_zero = {f: all(v == 0.0 for v in vals) for f, vals in values_by_feature.items()}

    feature_rows: List[Dict[str, Any]] = []
    session_counts: Dict[str, Dict[str, Any]] = defaultdict(lambda: defaultdict(int))
    session_meta: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        sid = r.get("session_id", "")
        feat = r.get("cic_feature", "")
        dump = r.get("dump_filename", "")
        k2_status = r.get("status", "")
        semantic_status, reason = classify_feature(
            feat,
            k2_status,
            r.get("defaulted", ""),
            r.get("ramdetect_source", ""),
        )
        zero_note = "all_zero_in_current_sessions" if all_zero.get(feat, False) else "varies_or_nonzero"

        session_meta[sid] = {"session_id": sid, "dump_filename": dump}
        session_counts[sid]["dataset_features"] += 1
        session_counts[sid][f"semantic_{semantic_status}"] += 1
        if (k2_status or "").lower() == "mapped":
            session_counts[sid]["k2_schema_mapped"] += 1
        if (k2_status or "").lower() == "default_zero_unmapped":
            session_counts[sid]["k2_defaulted"] += 1

        feature_rows.append({
            "session_id": sid,
            "dump_filename": dump,
            "cic_feature": feat,
            "feature_group": r.get("feature_group", ""),
            "value": r.get("value", ""),
            "k2_schema_status": k2_status,
            "k2_defaulted": r.get("defaulted", ""),
            "ramdetect_source": r.get("ramdetect_source", ""),
            "semantic_status": semantic_status,
            "semantic_note": reason,
            "current_session_value_profile": zero_note,
        })

    session_summary: List[Dict[str, Any]] = []
    for sid in sorted(session_counts.keys()):
        c = session_counts[sid]
        total = int(c.get("dataset_features", 0))
        validated = int(c.get("semantic_validated_extracted", 0))
        not_validated = int(c.get("semantic_not_yet_validated_or_placeholder", 0))
        unsupported = int(c.get("semantic_unsupported_or_defaulted", 0))
        review = int(c.get("semantic_review_needed", 0))
        schema_mapped = int(c.get("k2_schema_mapped", 0))
        session_summary.append({
            "session_id": sid,
            "dump_filename": session_meta.get(sid, {}).get("dump_filename", ""),
            "dataset_features": total,
            "k2_schema_mapped": schema_mapped,
            "k2_schema_compatibility_pct": round((schema_mapped / total * 100.0), 2) if total else 0.0,
            "semantic_validated_extracted": validated,
            "semantic_validated_pct": round((validated / total * 100.0), 2) if total else 0.0,
            "not_yet_validated_or_placeholder": not_validated,
            "unsupported_or_defaulted": unsupported,
            "review_needed": review,
            "interpretation": "Schema-compatible wide CSV; semantic coverage should be reported separately from K2 schema mapping.",
        })

    write_csv(
        out / "phaseK2B_semantic_feature_status.csv",
        feature_rows,
        [
            "session_id", "dump_filename", "cic_feature", "feature_group", "value",
            "k2_schema_status", "k2_defaulted", "ramdetect_source", "semantic_status",
            "semantic_note", "current_session_value_profile",
        ],
    )
    write_csv(
        out / "phaseK2B_semantic_session_summary.csv",
        session_summary,
        [
            "session_id", "dump_filename", "dataset_features", "k2_schema_mapped",
            "k2_schema_compatibility_pct", "semantic_validated_extracted",
            "semantic_validated_pct", "not_yet_validated_or_placeholder",
            "unsupported_or_defaulted", "review_needed", "interpretation",
        ],
    )

    # Aggregate unique feature statuses.
    unique_feature_status: Dict[str, Dict[str, Any]] = {}
    for fr in feature_rows:
        feat = fr["cic_feature"]
        if feat not in unique_feature_status:
            unique_feature_status[feat] = {
                "cic_feature": feat,
                "feature_group": fr["feature_group"],
                "semantic_status": fr["semantic_status"],
                "semantic_note": fr["semantic_note"],
                "current_session_value_profile": fr["current_session_value_profile"],
            }
    unique_status_counts = defaultdict(int)
    for row in unique_feature_status.values():
        unique_status_counts[row["semantic_status"]] += 1

    payload = {
        "phase": "K2B_CIC_MALMEM2022_SEMANTIC_FEATURE_COVERAGE_AUDIT",
        "diagnostic_only": True,
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
        },
        "input_matrix": str(matrix_path),
        "session_count": len(session_summary),
        "dataset_feature_count": len(unique_feature_status),
        "unique_feature_status_counts": dict(unique_status_counts),
        "session_summary": session_summary,
        "important_note": "K2 schema compatibility and K2B semantic extraction coverage are different metrics. Use both in the FYP report.",
    }
    with (out / "phaseK2B_semantic_coverage_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    validated_n = unique_status_counts.get("validated_extracted", 0)
    total_n = len(unique_feature_status)
    schema_pct = session_summary[0]["k2_schema_compatibility_pct"] if session_summary else 0.0
    sem_pct = round(validated_n / total_n * 100.0, 2) if total_n else 0.0

    md = []
    md.append("# Phase K2B — CIC-MalMem2022 Semantic Feature Coverage Audit\n")
    md.append("## Scope\n")
    md.append("This audit is diagnostic/reporting only. It does not change the RF threshold, FeatureMapper, dataset, session JSON, verdict logic, or any ML decision rule.\n")
    md.append("## Key distinction\n")
    md.append(f"- K2 schema compatibility: **{schema_pct:.2f}%**. This means the exported CSV has the CIC-MalMem2022 column shape.\n")
    md.append(f"- K2B validated semantic extraction coverage: **{validated_n}/{total_n} ({sem_pct:.2f}%)**. This counts only CIC fields with concrete validated RAMDetect parser/feature sources.\n")
    md.append("- Phase K3B marks `svcscan.*` as validated only when the K2 matrix source is `k3b_svcscan_semantic:*`; default FeatureMapper service values are still treated as placeholders.\n")
    md.append("- Phase K3G marks `malfind.protection` as validated only when the K2 matrix source is `k3g_malfind_protection_semantic:*`; default-zero protection values without this source remain unsupported/placeholders.\n")
    md.append("\n## Feature status summary\n")
    md.append("| Semantic status | Unique CIC features | Meaning |\n|---|---:|---|\n")
    meanings = {
        "validated_extracted": "Concrete RAMDetect parser/feature source exists.",
        "not_yet_validated_or_placeholder": "Column is present but native extraction is not yet fully validated as CIC-equivalent evidence.",
        "unsupported_or_defaulted": "Column is default-zero/unmapped for schema compatibility only.",
        "review_needed": "Manual review needed.",
    }
    for key in ["validated_extracted", "not_yet_validated_or_placeholder", "unsupported_or_defaulted", "review_needed"]:
        md.append(f"| `{key}` | {unique_status_counts.get(key, 0)} | {meanings[key]} |\n")
    md.append("\n## Session summary\n")
    md.append("| Session | Dump | K2 schema mapped | K2 schema % | K2B validated | K2B validated % | Placeholder/not validated | Unsupported/defaulted |\n")
    md.append("|---|---|---:|---:|---:|---:|---:|---:|\n")
    for s in session_summary:
        md.append(
            f"| {s['session_id']} | {s['dump_filename']} | {s['k2_schema_mapped']}/{s['dataset_features']} | "
            f"{s['k2_schema_compatibility_pct']:.2f}% | {s['semantic_validated_extracted']}/{s['dataset_features']} | "
            f"{s['semantic_validated_pct']:.2f}% | {s['not_yet_validated_or_placeholder']} | {s['unsupported_or_defaulted']} |\n"
        )
    md.append("\n## Recommendation\n")
    md.append("Use K2 for CSV shape compatibility and K2B for honest extraction fidelity. In the FYP report, state that RAMDetect can export a CIC-MalMem2022-compatible row, but only validated fields should be treated as extracted evidence. Placeholder fields are included only to preserve dataset schema alignment.\n")
    (out / "phaseK2B_semantic_coverage_report.md").write_text("".join(md), encoding="utf-8")

    print("Phase K2B semantic coverage audit complete.")
    print(f"Output: {out}")
    print(f"K2 schema compatibility: {schema_pct:.2f}%")
    print(f"K2B validated semantic extraction coverage: {validated_n}/{total_n} ({sem_pct:.2f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

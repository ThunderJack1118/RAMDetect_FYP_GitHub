#!/usr/bin/env python3
"""
Phase K3A — CIC-MalMem2022 Semantic Coverage Target Audit
=========================================================

Purpose
-------
Diagnostic/readiness audit for improving RAMDetect's validated semantic
coverage after K2/K2B. This tool does NOT modify RAMDetect, the dataset,
FeatureMapper, session JSON, RF threshold, or verdict logic.

It reads:
  1) Phase K2B semantic coverage outputs
  2) Saved RAMDetect session JSON snapshots

It then determines which currently-not-validated CIC-MalMem2022 features are
the best implementation targets for K3B/K3C.

Outputs
-------
  - phaseK3A_feature_target_readiness.csv
  - phaseK3A_session_signal_audit.csv
  - phaseK3A_recommended_implementation_plan.csv
  - phaseK3A_semantic_coverage_target_summary.json
  - phaseK3A_semantic_coverage_target_report.md

Usage
-----
python tools/phaseK3A_semantic_coverage_target_audit.py ^
  --k2b-dir models\\experiments\\EXP_K2B_CIC_SEMANTIC_COVERAGE_AUDIT ^
  --out models\\experiments\\EXP_K3A_SEMANTIC_COVERAGE_TARGET_AUDIT

Optional:
  --session-id <id> can be repeated to force the session list.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


# ----------------------------- generic helpers ----------------------------- #

def _read_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    # Handle normal CSVs, UTF-8 BOMs, and occasional NUL bytes safely.
    raw = path.read_bytes().replace(b"\x00", b"")
    text = raw.decode("utf-8-sig", errors="replace")
    import io
    return list(csv.DictReader(io.StringIO(text)))


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: List[str] = []
    for r in rows:
        for k in r.keys():
            if k not in fields:
                fields.append(k)
    if not fields:
        fields = ["empty"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=fields,
            quoting=csv.QUOTE_MINIMAL,
            escapechar="\\",
            extrasaction="ignore",
        )
        w.writeheader()
        for r in rows:
            w.writerow({k: _safe_cell(r.get(k, "")) for k in fields})


def _safe_cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list, tuple)):
        try:
            return json.dumps(v, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(v)
    s = str(v)
    s = s.replace("\x00", "")
    return s


def _norm_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s or "").strip().lower()).strip("_")


def _first_existing(*paths: Path) -> Path | None:
    for p in paths:
        if p and p.is_file():
            return p
    return None


def _project_root() -> Path:
    return Path.cwd()


def _session_path(session_id: str, root: Path) -> Path:
    return root / "ramdetect" / "ui" / "data" / "sessions" / f"{session_id}.json"


def _load_session(session_id: str, root: Path) -> Dict[str, Any]:
    return _read_json(_session_path(session_id, root), default={}) or {}


def _get_any(d: Dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for k in keys:
        if k in d and d.get(k) not in (None, "", []):
            return d.get(k)
    return default


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


# ------------------------- CIC feature group helpers ------------------------ #

K3_TARGET_GROUPS = {
    "pslist.nprocs64bit": {
        "group": "pslist_architecture",
        "target": "pslist.nprocs64bit",
        "why": "Single missing/weak pslist field; can be supported if process architecture/WoW64 evidence exists.",
        "priority": 3,
    },
    "modules.nmodules": {
        "group": "modules",
        "target": "modules.nmodules",
        "why": "Kernel module count is a compact CIC feature; likely easier than full psxview/callback reconstruction.",
        "priority": 2,
    },
    "svcscan.nservices": {
        "group": "svcscan",
        "target": "svcscan.*",
        "why": "Service registry work already exists in RAMDetect; validating and mapping svcscan fields can improve multiple CIC features.",
        "priority": 1,
    },
    "psxview.not_in_pslist": {
        "group": "psxview",
        "target": "psxview.*",
        "why": "Cross-view process hiding indicators require robust multi-source process views; complex but valuable.",
        "priority": 4,
    },
    "callbacks.ncallbacks": {
        "group": "callbacks",
        "target": "callbacks.*",
        "why": "Kernel callback extraction is advanced; usually lower priority for FYP unless parser support already exists.",
        "priority": 5,
    },
    "malfind.protection": {
        "group": "malfind_protection",
        "target": "malfind.protection",
        "why": "Only defaulted/unmapped CIC feature in K2; requires reliable VAD protection extraction.",
        "priority": 6,
    },
}

PSXVIEW_PREFIXES = (
    "psxview.not_in_pslist",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
)
SVC_PREFIXES = (
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
)
CALLBACK_PREFIXES = (
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
)


def _group_for_feature(feature: str) -> str:
    f = str(feature or "")
    if f == "pslist.nprocs64bit":
        return "pslist_architecture"
    if f == "modules.nmodules":
        return "modules"
    if f.startswith("svcscan."):
        return "svcscan"
    if f.startswith("psxview."):
        return "psxview"
    if f.startswith("callbacks."):
        return "callbacks"
    if f == "malfind.protection":
        return "malfind_protection"
    return "other"


def _priority_for_group(group: str) -> int:
    return {
        "svcscan": 1,
        "modules": 2,
        "pslist_architecture": 3,
        "psxview": 4,
        "callbacks": 5,
        "malfind_protection": 6,
    }.get(group, 99)


# ------------------------- session signal detection ------------------------- #

def _feature_keys(sess: Dict[str, Any]) -> set[str]:
    keys = set()
    rf = _as_dict(sess.get("raw_features"))
    for k in rf.keys():
        keys.add(str(k))
        keys.add(_norm_key(k))
    for item in _as_list(sess.get("feature_provenance")):
        if isinstance(item, dict):
            for k in ("cic_feature", "feature", "canonical", "name", "source", "ramdetect_source"):
                if item.get(k):
                    keys.add(str(item.get(k)))
                    keys.add(_norm_key(item.get(k)))
    return keys


def _count_truthy_records(records: List[Any], required_any: List[str] | None = None) -> int:
    n = 0
    for r in records:
        if not isinstance(r, dict):
            continue
        if required_any:
            if any(r.get(k) not in (None, "", 0, "0", [], {}) for k in required_any):
                n += 1
        else:
            if r:
                n += 1
    return n


def _audit_session_signals(session_id: str, sess: Dict[str, Any]) -> Dict[str, Any]:
    processes = _as_list(sess.get("processes"))
    threads = _as_list(sess.get("threads"))
    dlls = _as_list(sess.get("dlls"))
    handles = _as_list(sess.get("handles"))
    pe_sections = _as_list(sess.get("pe_sections"))
    injections = _as_list(sess.get("injections"))
    raw = _as_dict(sess.get("raw_features"))
    service_records = _as_list(sess.get("service_registry_records"))
    service_summary = _as_dict(sess.get("service_registry_summary"))
    fkeys = _feature_keys(sess)

    # svcscan readiness signals
    svc_record_count = len(service_records)
    svc_summary_keys = len([k for k, v in service_summary.items() if v not in (None, "", [], {})])
    svc_has_type_start = _count_truthy_records(service_records, ["type", "service_type", "Type", "start", "Start"])
    svc_has_path = _count_truthy_records(service_records, ["image_path", "ImagePath", "service_dll", "ServiceDll", "path"])

    # modules readiness signals
    module_like_raw_keys = [
        k for k in raw.keys()
        if any(tok in str(k).lower() for tok in ["modules.nmodules", "nmodules", "kernel_module", "loaded_kernel_module"])
    ]
    module_like_artifacts = []
    for key in ("modules", "kernel_modules", "drivers", "loaded_modules"):
        if isinstance(sess.get(key), list):
            module_like_artifacts.extend(sess.get(key) or [])
    modules_ready_count = len(module_like_artifacts)

    # pslist.nprocs64bit readiness
    arch_fields = ("is_64bit", "is64bit", "wow64", "is_wow64", "architecture", "arch", "machine_type")
    procs_with_arch = 0
    procs64 = 0
    for p in processes:
        if not isinstance(p, dict):
            continue
        if any(k in p for k in arch_fields):
            procs_with_arch += 1
            arch_val = " ".join(str(p.get(k, "")) for k in arch_fields).lower()
            # x64 and not wow64 suggests 64-bit. This is only readiness evidence.
            if ("x64" in arch_val or "64" in arch_val or p.get("is_64bit") is True or p.get("is64bit") is True) and "wow64=true" not in arch_val:
                procs64 += 1

    # psxview readiness
    psx_keys = [k for k in fkeys if "psxview" in str(k).lower()]
    dkom_keys = [k for k in fkeys if any(tok in str(k).lower() for tok in ["dkom", "cross_view", "linked_list", "eprocess_pool", "pspcid", "csrss"])]
    process_view_markers = 0
    for p in processes:
        if not isinstance(p, dict):
            continue
        text = json.dumps(p, default=str).lower()
        if any(tok in text for tok in ["pslist", "eprocess_pool", "pspcid", "csrss", "session", "deskthrd", "linked_list", "dkom"]):
            process_view_markers += 1

    # callback readiness
    callback_keys = [k for k in fkeys if "callback" in str(k).lower()]
    callback_records = []
    for key in ("callbacks", "kernel_callbacks", "callback_records"):
        if isinstance(sess.get(key), list):
            callback_records.extend(sess.get(key) or [])

    # malfind.protection readiness
    protection_count = 0
    protection_sources = []
    for rows, source_name in [(injections, "injections"), (pe_sections, "pe_sections")]:
        for r in rows:
            if not isinstance(r, dict):
                continue
            if any(r.get(k) not in (None, "", [], {}) for k in ("protection", "vad_protection", "protect", "page_protection", "permissions")):
                protection_count += 1
                protection_sources.append(source_name)

    return {
        "session_id": session_id,
        "dump_filename": sess.get("dump_filename", ""),
        "processes": len(processes),
        "threads": len(threads),
        "dlls": len(dlls),
        "handles": len(handles),
        "pe_sections": len(pe_sections),
        "injections": len(injections),
        "raw_feature_count": len(raw),
        "feature_provenance_count": len(_as_list(sess.get("feature_provenance"))),
        "svc_records": svc_record_count,
        "svc_summary_keys": svc_summary_keys,
        "svc_records_with_type_or_start": svc_has_type_start,
        "svc_records_with_path": svc_has_path,
        "module_like_raw_keys": ";".join(map(str, module_like_raw_keys[:10])),
        "module_like_artifact_count": modules_ready_count,
        "processes_with_arch_field": procs_with_arch,
        "estimated_64bit_processes_from_existing_fields": procs64,
        "psxview_raw_or_provenance_keys": len(psx_keys),
        "dkom_or_crossview_keys": len(dkom_keys),
        "process_view_markers": process_view_markers,
        "callback_raw_or_provenance_keys": len(callback_keys),
        "callback_record_count": len(callback_records),
        "malfind_protection_rows": protection_count,
        "malfind_protection_sources": ";".join(sorted(set(protection_sources))),
    }


def _readiness_for_group(group: str, session_rows: List[Dict[str, Any]]) -> Tuple[str, str, Dict[str, Any]]:
    n = len(session_rows) or 1

    def count_if(key: str, pred=lambda v: _num(v) > 0) -> int:
        return sum(1 for r in session_rows if pred(r.get(key)))

    stats = {
        "session_count": len(session_rows),
        "svc_sessions_with_records": count_if("svc_records"),
        "svc_sessions_with_path": count_if("svc_records_with_path"),
        "svc_sessions_with_type_or_start": count_if("svc_records_with_type_or_start"),
        "module_sessions_with_artifacts": count_if("module_like_artifact_count"),
        "module_sessions_with_raw_keys": count_if("module_like_raw_keys", lambda v: bool(v)),
        "arch_sessions_with_process_arch": count_if("processes_with_arch_field"),
        "psx_sessions_with_keys": count_if("psxview_raw_or_provenance_keys"),
        "psx_sessions_with_dkom_or_crossview": count_if("dkom_or_crossview_keys"),
        "callback_sessions_with_records": count_if("callback_record_count"),
        "callback_sessions_with_keys": count_if("callback_raw_or_provenance_keys"),
        "malfind_sessions_with_protection": count_if("malfind_protection_rows"),
    }

    if group == "svcscan":
        if stats["svc_sessions_with_records"] == n and (stats["svc_sessions_with_path"] > 0 or stats["svc_sessions_with_type_or_start"] > 0):
            return "implementation_candidate_now", "Persisted service-registry evidence exists; next step is validate Type/Start/ImagePath/ServiceDll semantics before mapping svcscan.*.", stats
        if stats["svc_sessions_with_records"] > 0:
            return "partial_source_present", "Service records exist but semantic fields are incomplete; improve parser before mapping svcscan.*.", stats
        return "parser_support_missing", "No persisted service evidence found in saved sessions.", stats

    if group == "modules":
        if stats["module_sessions_with_artifacts"] > 0 or stats["module_sessions_with_raw_keys"] > 0:
            return "implementation_candidate_now", "Module-like source evidence appears available; validate kernel-module semantics before mapping modules.nmodules.", stats
        return "parser_support_missing", "No kernel-module source evidence found; DLL rows are not equivalent to modules.nmodules.", stats

    if group == "pslist_architecture":
        if stats["arch_sessions_with_process_arch"] > 0:
            return "implementation_candidate_now", "Process architecture fields exist in at least one session; validate before mapping pslist.nprocs64bit.", stats
        return "needs_parser_extension", "No process architecture/WoW64 fields found in saved sessions.", stats

    if group == "psxview":
        if stats["psx_sessions_with_keys"] > 0 or stats["psx_sessions_with_dkom_or_crossview"] > 0:
            return "partial_source_present", "Some cross-view/DKOM signals exist, but psxview requires stable multi-view semantics.", stats
        return "complex_future_work", "No stable psxview-equivalent multi-view evidence found.", stats

    if group == "callbacks":
        if stats["callback_sessions_with_records"] > 0 or stats["callback_sessions_with_keys"] > 0:
            return "partial_source_present", "Callback-like evidence exists; validate callback table parsing before mapping callbacks.*.", stats
        return "complex_future_work", "No kernel-callback source evidence found.", stats

    if group == "malfind_protection":
        if stats["malfind_sessions_with_protection"] > 0:
            return "implementation_candidate_now", "Protection/permission fields exist in injections or PE/VAD rows; validate mapping to malfind.protection.", stats
        return "needs_vad_protection_support", "No reliable VAD protection field found in saved injections/PE sections.", stats

    return "unknown", "No recommendation available.", stats


# ------------------------------ main workflow ------------------------------- #

def _load_k2b(k2b_dir: Path) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    summary = _read_json(k2b_dir / "phaseK2B_semantic_coverage_summary.json", default={}) or {}
    feature_status = _read_csv(k2b_dir / "phaseK2B_semantic_feature_status.csv")
    return summary, feature_status


def _session_ids_from_k2b(summary: Dict[str, Any]) -> List[str]:
    ids = []
    for row in summary.get("session_summary", []) or []:
        sid = str(row.get("session_id", "")).strip()
        if sid:
            ids.append(sid)
    return ids


def run(args: argparse.Namespace) -> int:
    root = _project_root()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    k2b_dir = Path(args.k2b_dir)
    k2b_summary, k2b_feature_rows = _load_k2b(k2b_dir)

    session_ids = args.session_id or _session_ids_from_k2b(k2b_summary)
    if not session_ids:
        raise SystemExit("No session IDs supplied and none found in K2B summary.")

    # Load session JSONs
    session_audits: List[Dict[str, Any]] = []
    load_errors: List[Dict[str, Any]] = []
    for sid in session_ids:
        sess = _load_session(sid, root)
        if not sess:
            load_errors.append({
                "session_id": sid,
                "error": f"missing_or_unreadable_session_json: {_session_path(sid, root)}"
            })
            continue
        session_audits.append(_audit_session_signals(sid, sess))

    # Target features from K2B feature status
    target_feature_rows: List[Dict[str, Any]] = []
    feature_status_by_group: Dict[str, Counter] = defaultdict(Counter)
    all_unvalidated_features: List[str] = []

    for r in k2b_feature_rows:
        feat = r.get("cic_feature") or r.get("feature") or r.get("dataset_feature") or ""
        status = r.get("semantic_status") or r.get("status") or ""
        if not feat:
            continue
        group = _group_for_feature(feat)
        feature_status_by_group[group][status] += 1
        if status != "validated_extracted":
            all_unvalidated_features.append(feat)

    groups = sorted(
        {g for g in feature_status_by_group.keys() if g != "other"},
        key=_priority_for_group,
    )

    # Ensure expected groups are included even if column names vary.
    for g in ["svcscan", "modules", "pslist_architecture", "psxview", "callbacks", "malfind_protection"]:
        if g not in groups:
            groups.append(g)

    plan_rows: List[Dict[str, Any]] = []
    for group in groups:
        readiness, note, stats = _readiness_for_group(group, session_audits)
        if group == "svcscan":
            target = "svcscan.nservices, svcscan.kernel_drivers, svcscan.fs_drivers, svcscan.process_services, svcscan.shared_process_services, svcscan.interactive_process_services, svcscan.nactive"
            implementation_action = "K3B: validate service_registry_records semantics and map svcscan.* only when Type/Start/ImagePath/ServiceDll/state are reliable."
        elif group == "modules":
            target = "modules.nmodules"
            implementation_action = "K3C: add/validate kernel module enumerator; do not use user-mode DLL count as modules.nmodules."
        elif group == "pslist_architecture":
            target = "pslist.nprocs64bit"
            implementation_action = "K3D: add process architecture/WoW64 extraction and count true 64-bit user processes."
        elif group == "psxview":
            target = "psxview.*"
            implementation_action = "K3E: implement cross-view process comparison from pslist, eprocess pool, ethread pool, pspcid/session/deskthrd equivalents."
        elif group == "callbacks":
            target = "callbacks.*"
            implementation_action = "K3F: optional future work; kernel callback extraction is advanced and may be outside FYP core scope."
        elif group == "malfind_protection":
            target = "malfind.protection"
            implementation_action = "K3G: validate VAD protection/permission parsing before mapping malfind.protection."
        else:
            target = group
            implementation_action = "Review manually."

        statuses = dict(feature_status_by_group.get(group, {}))
        plan_rows.append({
            "priority": _priority_for_group(group),
            "target_group": group,
            "target_features": target,
            "k2b_feature_status_counts": json.dumps(statuses, sort_keys=True),
            "readiness": readiness,
            "readiness_note": note,
            "recommended_action": implementation_action,
            **{f"stat_{k}": v for k, v in stats.items()},
        })

    # Feature target readiness rows: one row per unvalidated CIC feature
    for feat in sorted(set(all_unvalidated_features)):
        group = _group_for_feature(feat)
        readiness, note, stats = _readiness_for_group(group, session_audits)
        target_feature_rows.append({
            "cic_feature": feat,
            "target_group": group,
            "priority": _priority_for_group(group),
            "current_k2b_status": next(
                (r.get("semantic_status") or r.get("status") or ""
                 for r in k2b_feature_rows
                 if (r.get("cic_feature") or r.get("feature") or r.get("dataset_feature") or "") == feat),
                "",
            ),
            "readiness": readiness,
            "recommendation": note,
        })

    _write_csv(out / "phaseK3A_session_signal_audit.csv", session_audits)
    _write_csv(out / "phaseK3A_feature_target_readiness.csv", target_feature_rows)
    _write_csv(out / "phaseK3A_recommended_implementation_plan.csv", plan_rows)
    if load_errors:
        _write_csv(out / "phaseK3A_load_errors.csv", load_errors)

    k2_schema_pct = None
    semantic_pct = None
    try:
        first = (k2b_summary.get("session_summary") or [{}])[0]
        k2_schema_pct = first.get("k2_schema_compatibility_pct")
        semantic_pct = first.get("semantic_validated_pct")
    except Exception:
        pass

    summary = {
        "phase": "K3A_SEMANTIC_COVERAGE_TARGET_AUDIT",
        "diagnostic_only": True,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "input_k2b_dir": str(k2b_dir),
        "session_count_requested": len(session_ids),
        "session_count_loaded": len(session_audits),
        "load_errors": load_errors,
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
        },
        "baseline_metrics_from_k2b": {
            "k2_schema_compatibility_pct": k2_schema_pct,
            "k2b_semantic_validated_pct": semantic_pct,
            "dataset_feature_count": k2b_summary.get("dataset_feature_count"),
            "unique_feature_status_counts": k2b_summary.get("unique_feature_status_counts"),
        },
        "recommended_plan": plan_rows,
        "next_phase": "K3B should implement the highest-readiness target only, then rerun K2 and K2B to prove coverage improvement.",
    }
    with (out / "phaseK3A_semantic_coverage_target_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)

    # Markdown report
    report_lines: List[str] = []
    report_lines.append("# Phase K3A — CIC-MalMem2022 Semantic Coverage Target Audit")
    report_lines.append("")
    report_lines.append("## Scope")
    report_lines.append("This audit is diagnostic/readiness-only. It does not change the RF threshold, FeatureMapper, dataset, session JSON, verdict logic, or any ML decision rule.")
    report_lines.append("")
    report_lines.append("## Current baseline")
    report_lines.append(f"- K2 schema compatibility: **{k2_schema_pct if k2_schema_pct is not None else 'unknown'}%**")
    report_lines.append(f"- K2B validated semantic extraction coverage: **{semantic_pct if semantic_pct is not None else 'unknown'}%**")
    report_lines.append(f"- Loaded sessions: **{len(session_audits)}/{len(session_ids)}**")
    report_lines.append("")
    report_lines.append("## Recommended implementation order")
    report_lines.append("")
    report_lines.append("| Priority | Target group | Readiness | Recommended action |")
    report_lines.append("|---:|---|---|---|")
    for row in sorted(plan_rows, key=lambda r: (r.get("priority", 99), str(r.get("target_group")))):
        report_lines.append(
            f"| {row.get('priority')} | `{row.get('target_group')}` | `{row.get('readiness')}` | {row.get('recommended_action')} |"
        )
    report_lines.append("")
    report_lines.append("## Interpretation")
    report_lines.append("")
    report_lines.append(
        "K3 should improve one semantic feature group at a time. After each implementation, rerun K2 and K2B. "
        "A feature should only move from placeholder/not-validated to validated_extracted when there is a concrete RAMDetect parser or feature source that is semantically equivalent to the CIC-MalMem2022 feature."
    )
    report_lines.append("")
    report_lines.append("## Rule preservation")
    report_lines.append("")
    report_lines.append("- RF threshold: unchanged")
    report_lines.append("- ML-only logic: unchanged")
    report_lines.append("- FeatureMapper: unchanged")
    report_lines.append("- Dataset: unchanged")
    report_lines.append("- Session JSON: not modified")
    report_lines.append("- Veto rules: not added")
    (out / "phaseK3A_semantic_coverage_target_report.md").write_text("\n".join(report_lines), encoding="utf-8")

    print("Phase K3A semantic coverage target audit complete.")
    print(f"Output: {out}")
    print(f"Loaded sessions: {len(session_audits)}/{len(session_ids)}")
    print("Next action: review phaseK3A_recommended_implementation_plan.csv, then implement K3B highest-readiness target.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k2b-dir", required=True, help="Phase K2B output directory.")
    ap.add_argument("--out", required=True, help="Output directory.")
    ap.add_argument("--session-id", action="append", default=[], help="Optional session id. Repeatable.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

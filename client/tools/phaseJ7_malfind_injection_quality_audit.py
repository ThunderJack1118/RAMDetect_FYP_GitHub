#!/usr/bin/env python3
"""
Phase J7 — Malfind / Injection Quality Audit (Diagnostic Only)
==============================================================

Purpose
-------
Audits why near-threshold and missed malicious sessions remain CLEAN by
comparing parser-confirmed injection artifacts against CIC malfind.* fields.

Safety
------
This tool is diagnostic-only. It does not modify session JSON, FeatureMapper,
model files, training data, threshold, or runtime verdict logic. It does not add
veto rules, clean dampeners, score floors, or deterministic overrides.

Expected input
--------------
--j4-dir models/experiments/EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5

Expected outputs
----------------
phaseJ7_malfind_session_audit.csv
phaseJ7_injection_rows.csv
phaseJ7_summary.json
phaseJ7_report.md
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

MISS_IDS_DEFAULT = {"9c896133", "0daa326a", "c99f293c", "8756a863", "695e1d61"}
DETECTED_IDS_DEFAULT = {"f99d9ce1", "bfb5d086", "e17db648", "b755d63c", "59da07e7", "095de269", "14ce2ed3"}
CLEAN_IDS_DEFAULT = {"3054143d", "bde36e7f", "febb14ec"}

MALFIND_KEYS = [
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.protection",
    "malfind.uniqueInjections",
]
CONTEXT_KEYS = [
    "pslist.nproc",
    "dlllist.ndlls",
    "handles.nhandles",
    "handles.nevent",
    "handles.nfile",
    "handles.nsection",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_init_avg",
]


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return float(int(v))
        if isinstance(v, (int, float)):
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return default
            return float(v)
        s = str(v).strip()
        if not s or s.lower() in {"none", "n/a", "na", "-", "?", "unknown"}:
            return default
        # Strip percent signs if score strings appear as 44.9%.
        if s.endswith("%"):
            return float(s[:-1]) / 100.0
        if s.lower().startswith("0x"):
            return float(int(s, 16))
        return float(s)
    except Exception:
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip()
        if not s or s.lower() in {"none", "n/a", "na", "-", "?", "unknown"}:
            return default
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return default


def _text(v: Any) -> str:
    if isinstance(v, (list, tuple, set)):
        return " ".join(str(x) for x in v)
    if isinstance(v, dict):
        return " ".join(f"{k}={v2}" for k, v2 in v.items())
    return str(v or "")


def _basename(path_or_name: Any) -> str:
    s = str(path_or_name or "").strip().replace("/", "\\")
    return s.rsplit("\\", 1)[-1].lower()


def _find_value(obj: Any, keys: Iterable[str]) -> Any:
    keys_l = {k.lower() for k in keys}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys_l:
                return v
        for v in obj.values():
            r = _find_value(v, keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find_value(v, keys)
            if r is not None:
                return r
    return None


def _get_artifact_list(session: Dict[str, Any], names: Iterable[str]) -> List[Dict[str, Any]]:
    names_l = {n.lower() for n in names}
    # Prefer explicit top-level or artifacts-level lists.
    for source in (session, session.get("artifacts", {}) if isinstance(session.get("artifacts"), dict) else {}):
        if isinstance(source, dict):
            for k, v in source.items():
                if str(k).lower() in names_l:
                    if isinstance(v, list):
                        return [x for x in v if isinstance(x, dict)]
                    if isinstance(v, dict):
                        flat = []
                        for vv in v.values():
                            if isinstance(vv, list):
                                flat.extend(x for x in vv if isinstance(x, dict))
                        return flat
    # Fallback recursive search for the first matching list.
    def rec(obj: Any) -> Optional[List[Dict[str, Any]]]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in names_l and isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
            for v in obj.values():
                r = rec(v)
                if r is not None:
                    return r
        elif isinstance(obj, list):
            for v in obj:
                r = rec(v)
                if r is not None:
                    return r
        return None
    return rec(session) or []


def _load_csv_dicts(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _score_from_j4(row: Dict[str, Any]) -> float:
    for k in ("score_raw", "score", "rf_score", "hybrid_score", "suspicion_score"):
        if k in row:
            return _safe_float(row.get(k), 0.0)
    return 0.0


def _classify_group(sid: str, j4_group: str = "") -> str:
    if j4_group:
        return j4_group
    if sid in CLEAN_IDS_DEFAULT:
        return "clean"
    if sid in DETECTED_IDS_DEFAULT:
        return "detected_malicious"
    if sid in MISS_IDS_DEFAULT:
        return "missed_malicious"
    return "unknown"


def _row_key(row: Dict[str, Any]) -> str:
    return str(row.get("session_id") or row.get("Session ID") or row.get("id") or "")


def _extract_dump_name(session: Dict[str, Any], fallback: str = "UNKNOWN") -> str:
    v = _find_value(session, ["dump_filename", "dump_file", "dump_name", "filename", "file_name"])
    if v:
        return os.path.basename(str(v))
    return fallback


def _field(row: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    key_l = {k.lower() for k in keys}
    for k, v in row.items():
        if str(k).lower() in key_l:
            return v
    return default


def _row_text(row: Dict[str, Any]) -> str:
    return " ".join(_text(v) for v in row.values()).lower()


def _extract_pages_or_size(row: Dict[str, Any]) -> Tuple[float, str]:
    for k in ("commit_charge", "commitCharge", "malfind.commitCharge", "commit", "pages", "page_count", "PageCount"):
        if any(str(x).lower() == k.lower() for x in row.keys()):
            val = _safe_float(_field(row, k), 0.0)
            if val > 0:
                return val, k
    for k in ("size", "region_size", "RegionSize", "virtual_size", "Virtual Size", "raw_size", "Raw Size"):
        if any(str(x).lower() == k.lower() for x in row.keys()):
            size = _safe_float(_field(row, k), 0.0)
            if size > 0:
                return max(1.0, size / 4096.0), k
    text = _row_text(row)
    m = re.search(r"(?:size|region_size|commit|commit_charge)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", text)
    if m:
        size = _safe_float(m.group(1), 0.0)
        if size > 0:
            return max(1.0, size / 4096.0), "text_size"
    return 0.0, "missing"


def _audit_injection_row(session_id: str, group: str, dump_name: str, idx: int, row: Dict[str, Any]) -> Dict[str, Any]:
    pid = _field(row, "pid", "PID", "target_pid", "ProcessId", default="")
    proc = _field(row, "process", "process_name", "proc_name", "Process", "ImageFileName", "name", default="")
    addr = _field(row, "address", "Address", "start_address", "StartAddress", "virtual_address", "VirtualAddress", "base", "Base", default="")
    size = _field(row, "size", "region_size", "RegionSize", "virtual_size", "Virtual Size", "raw_size", "Raw Size", default="")
    prot = _field(row, "protection", "Protection", "protect", "vad_protection", "permissions", "permission", default="")
    entropy = _field(row, "entropy", "Entropy", default="")
    anomaly = _field(row, "anomaly", "Anomaly", "anomalies", "status", "reason", "description", "Details", default="")
    pages, pages_source = _extract_pages_or_size(row)
    text = _row_text(row)
    has_explicit = any(term in text for term in [
        "injection", "inject", "shellcode", "hollow", "malfind", "private+x", "private executable",
        "unbacked", "remote thread", "start address outside module", "pe in private", "mz/pe"
    ])
    missing_addr = str(addr).strip().lower() in {"", "none", "n/a", "na", "-", "?", "0", "0x0"}
    missing_size = str(size).strip().lower() in {"", "none", "n/a", "na", "-", "?", "0", "0x0"}
    missing_prot = str(prot).strip().lower() in {"", "none", "n/a", "na", "-", "?", "0", "0x0"}
    return {
        "session_id": session_id,
        "group": group,
        "dump_name": dump_name,
        "row_index": idx,
        "pid": pid,
        "process": proc,
        "address": addr,
        "size": size,
        "protection": prot,
        "entropy": entropy,
        "pages_estimate": pages,
        "pages_source": pages_source,
        "explicit_injection_text": int(has_explicit),
        "missing_address": int(missing_addr),
        "missing_size": int(missing_size),
        "missing_protection": int(missing_prot),
        "anomaly_summary": _text(anomaly)[:300],
        "raw_keys": ";".join(sorted(str(k) for k in row.keys()))[:500],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--j4-dir", required=True, help="EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5 directory")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()

    j4_dir = Path(args.j4_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rules_preserved = {
        "threshold_changed": False,
        "threshold_fraction": 0.5,
        "model_retrained": False,
        "feature_mapper_modified": False,
        "session_json_modified": False,
        "runtime_verdict_logic_modified": False,
        "veto_rules_added": False,
        "clean_dampeners_added": False,
    }

    j4_summary_rows = _load_csv_dicts(j4_dir / "phaseJ4_session_score_summary.csv")
    j4_by_sid = {_row_key(r): r for r in j4_summary_rows if _row_key(r)}

    k2_rows_path = j4_dir / "K2_EXPORT" / "phaseK2_cicmalmem2022_rows.csv"
    k2_rows = _load_csv_dicts(k2_rows_path)
    # K2 row session ID might not be a CSV column depending on exporter, so use Category matching only as fallback.
    # Better: use sorted session JSON list and K2 row order if no session column exists.
    session_paths = sorted((j4_dir / "sessions").glob("*.json"))
    session_ids = [p.stem for p in session_paths]

    k2_by_sid: Dict[str, Dict[str, str]] = {}
    if k2_rows:
        if "session_id" in k2_rows[0]:
            k2_by_sid = {str(r.get("session_id")): r for r in k2_rows}
        elif len(k2_rows) == len(session_ids):
            # phaseK2 exporter writes rows in supplied order; session JSONs are sorted here, so this may not be exact.
            # If exact mapping is unavailable, later we still include session JSON injection audit.
            pass

    # Prefer matrix values if row mapping by session ID is missing.
    # phaseK2 rows usually preserve session order based on command order; J4 command order is fixed below.
    known_order = [
        "3054143d", "bde36e7f", "febb14ec",
        "f99d9ce1", "bfb5d086", "e17db648", "b755d63c", "59da07e7", "095de269", "14ce2ed3",
        "9c896133", "0daa326a", "c99f293c", "8756a863", "695e1d61",
    ]
    if k2_rows and not k2_by_sid and len(k2_rows) == len(known_order):
        k2_by_sid = {sid: row for sid, row in zip(known_order, k2_rows)}

    session_audit: List[Dict[str, Any]] = []
    inj_audit: List[Dict[str, Any]] = []

    clean_malfind_nonzero = []
    missed_near_threshold = []
    missed_low = []

    for sid in known_order:
        sp = j4_dir / "sessions" / f"{sid}.json"
        session = _load_json(sp) if sp.exists() else {}
        j4 = j4_by_sid.get(sid, {})
        group = _classify_group(sid, str(j4.get("group", "")))
        dump_name = str(j4.get("dump_name") or _extract_dump_name(session))
        score = _score_from_j4(j4)
        ae_mse = _safe_float(j4.get("ae_mse"), 0.0)
        k2 = k2_by_sid.get(sid, {})
        injections = _get_artifact_list(session, ["injections", "injection", "code_injection", "code_injections"])
        threads = _get_artifact_list(session, ["threads", "thread"])
        pe_sections = _get_artifact_list(session, ["pe_sections", "memory_regions", "vads", "vad", "sections"])

        mal_vals = {k: _safe_float(k2.get(k), 0.0) for k in MALFIND_KEYS}
        ctx_vals = {k: _safe_float(k2.get(k), 0.0) for k in CONTEXT_KEYS}

        explicit_inj_rows = 0
        missing_addr = 0
        missing_size = 0
        missing_prot = 0
        pages_total = 0.0
        for i, row in enumerate(injections):
            ir = _audit_injection_row(sid, group, dump_name, i, row)
            inj_audit.append(ir)
            explicit_inj_rows += int(ir["explicit_injection_text"])
            missing_addr += int(ir["missing_address"])
            missing_size += int(ir["missing_size"])
            missing_prot += int(ir["missing_protection"])
            pages_total += _safe_float(ir["pages_estimate"], 0.0)

        # Count explicit injection-like thread/PE rows for context only.
        explicit_thread_rows = 0
        for row in threads:
            text = _row_text(row)
            if any(term in text for term in ["injection", "inject", "unbacked", "private executable", "remote thread", "malfind"]):
                explicit_thread_rows += 1
        explicit_pe_rows = 0
        for row in pe_sections:
            text = _row_text(row)
            if any(term in text for term in ["injection", "inject", "shellcode", "malfind", "private+x", "pe in private"]):
                explicit_pe_rows += 1

        interpretation = ""
        recommendation = ""
        if group == "clean" and any(v > 0 for v in mal_vals.values()):
            clean_malfind_nonzero.append(sid)
            interpretation = "Clean baseline has non-zero malfind value; investigate false-positive risk."
            recommendation = "Do not expand malfind until clean source is resolved."
        elif group == "missed_malicious" and score >= 0.40 and score < 0.50:
            missed_near_threshold.append(sid)
            interpretation = "Near-threshold missed malware with parser-confirmed malfind signal."
            recommendation = "Review injection row quality, protection/size completeness, and malfind.protection semantic availability; no threshold change."
        elif group == "missed_malicious":
            missed_low.append(sid)
            interpretation = "Low-score missed malware; likely dataset/feature-representation limitation if no stronger parser-confirmed injection exists."
            recommendation = "Keep report-only artifacts; do not force verdict. Focus on future model/feature research, not rule overrides."
        elif group == "detected_malicious":
            interpretation = "Detected malicious baseline. Use as reference scale for malfind and aggregate features."
            recommendation = "No action unless comparing feature magnitude calibration."
        elif group == "clean":
            interpretation = "Clean baseline. Used as safety boundary."
            recommendation = "Any new runtime feature must keep this below 0.5."

        session_audit.append({
            "session_id": sid,
            "group": group,
            "dump_name": dump_name,
            "baseline_score": score,
            "ae_mse": ae_mse,
            "verdict_at_0_5": "SUSPICIOUS" if score >= 0.5 else "CLEAN",
            "session_json_found": int(bool(session)),
            "injection_rows": len(injections),
            "explicit_injection_rows": explicit_inj_rows,
            "injection_rows_missing_address": missing_addr,
            "injection_rows_missing_size": missing_size,
            "injection_rows_missing_protection": missing_prot,
            "injection_pages_total_estimate": pages_total,
            "explicit_thread_injection_rows": explicit_thread_rows,
            "explicit_pe_injection_rows": explicit_pe_rows,
            **mal_vals,
            **ctx_vals,
            "interpretation": interpretation,
            "recommendation": recommendation,
        })

    def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        keys = []
        for r in rows:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    write_csv(out / "phaseJ7_malfind_session_audit.csv", session_audit)
    write_csv(out / "phaseJ7_injection_rows.csv", inj_audit)

    # Simple generated conclusion.
    near = [r for r in session_audit if r["group"] == "missed_malicious" and 0.40 <= _safe_float(r["baseline_score"]) < 0.50]
    low = [r for r in session_audit if r["group"] == "missed_malicious" and _safe_float(r["baseline_score"]) < 0.40]
    clean_nonzero = [r for r in session_audit if r["group"] == "clean" and any(_safe_float(r.get(k)) > 0 for k in MALFIND_KEYS)]

    summary = {
        "phase": "J7_MALFIND_INJECTION_QUALITY_AUDIT",
        "diagnostic_only": True,
        "rules_preserved": rules_preserved,
        "input_j4_dir": str(j4_dir),
        "sessions_analyzed": len(session_audit),
        "injection_rows_total": len(inj_audit),
        "clean_baselines_with_nonzero_malfind": [r["session_id"] for r in clean_nonzero],
        "near_threshold_missed_malware": [r["session_id"] for r in near],
        "low_score_missed_malware": [r["session_id"] for r in low],
        "decision": {
            "threshold_change": "not_allowed",
            "veto_rules": "not_allowed",
            "svcscan_runtime": "rejected_by_J5",
            "recommended_next_focus": "malfind/injection semantic completeness for near-threshold cases only; report-only for low-score misses",
        },
    }
    (out / "phaseJ7_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    lines = []
    lines.append("# Phase J7 — Malfind / Injection Quality Audit")
    lines.append("")
    lines.append("Diagnostic only. No runtime verdict logic, FeatureMapper, saved model, threshold, session JSON, or training data was modified.")
    lines.append("Fixed RF threshold preserved for interpretation: `0.5`.")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Sessions analyzed: `{len(session_audit)}`")
    lines.append(f"- Injection artifact rows found: `{len(inj_audit)}`")
    lines.append(f"- Clean baselines with non-zero malfind: `{len(clean_nonzero)}`")
    lines.append(f"- Near-threshold missed malware: `{', '.join(r['session_id'] for r in near) or 'none'}`")
    lines.append(f"- Low-score missed malware: `{', '.join(r['session_id'] for r in low) or 'none'}`")
    lines.append("")
    lines.append("## Missed malware interpretation")
    lines.append("| Session | Score | malfind.ninjections | commitCharge | uniqueInjections | Injection rows | Recommendation |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")
    for r in session_audit:
        if r["group"] == "missed_malicious":
            lines.append(
                f"| {r['session_id']} | {float(r['baseline_score']):.4f} | "
                f"{float(r.get('malfind.ninjections', 0)):.0f} | {float(r.get('malfind.commitCharge', 0)):.0f} | "
                f"{float(r.get('malfind.uniqueInjections', 0)):.0f} | {int(r.get('injection_rows', 0))} | {r['recommendation']} |"
            )
    lines.append("")
    lines.append("## Decision")
    lines.append("- Do not change threshold.")
    lines.append("- Do not add veto rules, score floors, or clean dampeners.")
    lines.append("- Keep svcscan runtime support rejected based on J5 clean flips.")
    lines.append("- If any enhancement proceeds, prioritize parser-confirmed malfind/injection semantic completeness for near-threshold cases only.")
    lines.append("- Low-score ransomware misses should be documented as dataset/feature-representation limitations unless stronger parser-confirmed evidence is discovered.")
    (out / "phaseJ7_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Phase J7 malfind/injection quality audit complete.")
    print(f"Output: {out}")
    print(f"Sessions analyzed: {len(session_audit)}")
    print(f"Injection rows: {len(inj_audit)}")
    print("Near-threshold missed:", ", ".join(r["session_id"] for r in near) or "none")
    print("Low-score missed:", ", ".join(r["session_id"] for r in low) or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

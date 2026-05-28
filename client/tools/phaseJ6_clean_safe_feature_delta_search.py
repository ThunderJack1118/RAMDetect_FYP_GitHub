#!/usr/bin/env python3
"""
Phase J6 — Clean-Safe Feature Delta Search for RAMDetect
=========================================================

Diagnostic-only tool. It reads Phase J4/J5 outputs and searches for feature
families that may improve missed-malware detection without breaking clean
baselines.

Safety rules preserved:
- Does not modify session JSON.
- Does not modify FeatureMapper.
- Does not modify model files.
- Does not retrain models.
- Does not change RF threshold.
- Does not add veto rules, clean dampeners, score floors, or deterministic overrides.

Inputs expected:
- J4 directory containing:
  K2_EXPORT/phaseK2_cicmalmem2022_rows.csv
  phaseJ4_session_score_summary.csv
- Optional J5 summary JSON:
  phaseJ5_svcscan_modules_whatif_summary.json

Outputs:
- phaseJ6_feature_group_stats.csv
- phaseJ6_feature_delta_candidates.csv
- phaseJ6_case_gap_report.csv
- phaseJ6_summary.json
- phaseJ6_report.md
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Dict, Iterable, List, Tuple

NON_FEATURE_COLUMNS = {"Category", "Class"}
DEFAULT_GROUPS = {
    "clean": ["3054143d", "bde36e7f", "febb14ec"],
    "detected_malicious": ["f99d9ce1", "bfb5d086", "e17db648", "b755d63c", "59da07e7", "095de269", "14ce2ed3"],
    "missed_malicious": ["9c896133", "0daa326a", "c99f293c", "8756a863", "695e1d61"],
}
RISKY_RUNTIME_FAMILIES = {"svcscan", "modules", "callbacks", "psxview"}

# Keep this aligned with RAMDetect's official rule. J6 does not alter it.
THRESHOLD = 0.5


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        if isinstance(v, str):
            s = v.strip()
            if not s or s.lower() in {"none", "n/a", "na", "-", "?"}:
                return default
            return float(s)
        return float(v)
    except Exception:
        return default


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: List[str] = []
        for r in rows:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        fieldnames = keys
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _feature_group(name: str) -> str:
    return name.split(".", 1)[0] if "." in name else name


def _session_id_from_row(row: Dict[str, str]) -> str:
    # Phase K2 wide row may carry Category but not session ID. The output order
    # follows requested session order. J6 therefore assigns IDs by order if absent.
    for key in ("session_id", "Session ID", "session", "id"):
        if row.get(key):
            return row[key]
    return ""


def _load_k2_rows(j4_dir: Path, groups: Dict[str, List[str]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    k2_path = j4_dir / "K2_EXPORT" / "phaseK2_cicmalmem2022_rows.csv"
    if not k2_path.exists():
        raise FileNotFoundError(f"Missing K2 rows CSV: {k2_path}")
    rows = _read_csv(k2_path)
    ordered_ids = groups["clean"] + groups["detected_malicious"] + groups["missed_malicious"]
    enriched: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows):
        sid = _session_id_from_row(row) or (ordered_ids[idx] if idx < len(ordered_ids) else f"row_{idx}")
        group = next((g for g, ids in groups.items() if sid in ids), "unknown")
        r = dict(row)
        r["session_id"] = sid
        r["group"] = group
        enriched.append(r)
    feature_cols = [c for c in rows[0].keys() if c not in NON_FEATURE_COLUMNS and c not in {"session_id", "group"}]
    return enriched, feature_cols


def _load_scores(j4_dir: Path, groups: Dict[str, List[str]], j5_summary: Path | None) -> Dict[str, Dict[str, Any]]:
    scores: Dict[str, Dict[str, Any]] = {}
    j4_summary = j4_dir / "phaseJ4_session_score_summary.csv"
    if j4_summary.exists():
        for row in _read_csv(j4_summary):
            sid = row.get("session_id", "")
            scores[sid] = dict(row)

    if j5_summary and j5_summary.exists():
        data = json.loads(j5_summary.read_text(encoding="utf-8", errors="replace"))
        for entry in data.get("sessions", []):
            sid = entry.get("session_id")
            if not sid:
                continue
            scores.setdefault(sid, {})
            scores[sid]["baseline_recomputed_score"] = entry.get("scenarios", {}).get("baseline_recomputed", {}).get("score_fraction")
            scores[sid]["logged_score_fraction"] = entry.get("logged_score_fraction")
            scores[sid]["ae_mse"] = entry.get("ae_mse")
            scores[sid]["svcscan_only_score"] = entry.get("scenarios", {}).get("svcscan_only", {}).get("score_fraction")
            scores[sid]["modules_only_score"] = entry.get("scenarios", {}).get("modules_only", {}).get("score_fraction")
            scores[sid]["svcscan_modules_score"] = entry.get("scenarios", {}).get("svcscan_modules", {}).get("score_fraction")
    return scores


def _j5_family_decisions(j5_summary: Path | None) -> Dict[str, Dict[str, Any]]:
    decisions = {
        "svcscan": {"j5_decision": "not_tested", "clean_flips": None, "note": "No J5 summary supplied."},
        "modules": {"j5_decision": "not_tested", "clean_flips": None, "note": "No J5 summary supplied."},
    }
    if not j5_summary or not j5_summary.exists():
        return decisions
    data = json.loads(j5_summary.read_text(encoding="utf-8", errors="replace"))
    clean_entries = [e for e in data.get("sessions", []) if e.get("group") == "clean"]
    svc_flips = sum(1 for e in clean_entries if e.get("scenarios", {}).get("svcscan_only", {}).get("verdict_at_0_5") == "SUSPICIOUS")
    mod_flips = sum(1 for e in clean_entries if e.get("scenarios", {}).get("modules_only", {}).get("verdict_at_0_5") == "SUSPICIOUS")
    svc_missed_gain = []
    mod_missed_gain = []
    for e in data.get("sessions", []):
        if e.get("group") != "missed_malicious":
            continue
        base = _safe_float(e.get("scenarios", {}).get("baseline_recomputed", {}).get("score_fraction"))
        svc = _safe_float(e.get("scenarios", {}).get("svcscan_only", {}).get("score_fraction"))
        mod = _safe_float(e.get("scenarios", {}).get("modules_only", {}).get("score_fraction"))
        svc_missed_gain.append(svc - base)
        mod_missed_gain.append(mod - base)

    decisions["svcscan"] = {
        "j5_decision": "reject_runtime" if svc_flips > 0 else "candidate_runtime",
        "clean_flips": svc_flips,
        "avg_missed_gain": round(mean(svc_missed_gain), 6) if svc_missed_gain else 0.0,
        "note": "Rejected because svcscan what-if flips clean baselines." if svc_flips > 0 else "No clean flips in supplied J5 summary.",
    }
    decisions["modules"] = {
        "j5_decision": "low_priority_safe" if mod_flips == 0 else "reject_runtime",
        "clean_flips": mod_flips,
        "avg_missed_gain": round(mean(mod_missed_gain), 6) if mod_missed_gain else 0.0,
        "note": "Safe but low impact in J5." if mod_flips == 0 else "Rejected because modules what-if flips clean baselines.",
    }
    return decisions


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "std": 0.0}
    return {
        "min": min(values),
        "max": max(values),
        "mean": mean(values),
        "std": pstdev(values) if len(values) > 1 else 0.0,
    }


def _group_feature_stats(rows: List[Dict[str, Any]], features: List[str], j5_decisions: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    groups = ["clean", "detected_malicious", "missed_malicious"]
    for feature in features:
        group_vals: Dict[str, List[float]] = {g: [] for g in groups}
        for row in rows:
            g = row.get("group", "unknown")
            if g in group_vals:
                group_vals[g].append(_safe_float(row.get(feature), 0.0))
        clean = _stats(group_vals["clean"])
        det = _stats(group_vals["detected_malicious"])
        miss = _stats(group_vals["missed_malicious"])
        fam = _feature_group(feature)
        family_decision = j5_decisions.get(fam, {})

        # Simple evidence gap indicators. Higher missed_over_clean suggests the
        # feature is present in missed malware more than clean. Higher detected_over_clean
        # suggests the model already detects it in known malicious cases.
        clean_ref = max(clean["mean"], 1e-9)
        missed_over_clean = miss["mean"] / clean_ref if clean["mean"] != 0 else (math.inf if miss["mean"] > 0 else 0.0)
        detected_over_clean = det["mean"] / clean_ref if clean["mean"] != 0 else (math.inf if det["mean"] > 0 else 0.0)
        clean_max = clean["max"]
        miss_mean = miss["mean"]
        det_mean = det["mean"]

        if fam in RISKY_RUNTIME_FAMILIES:
            recommendation = "KEEP_EXPORT_OR_DIAGNOSTIC_ONLY"
            reason = f"{fam} is broad/unsupported for runtime; J5={family_decision.get('j5_decision', 'not_tested')}"
        elif miss_mean > clean_max and det_mean >= clean["mean"]:
            recommendation = "CLEAN_SAFE_CANDIDATE_REVIEW"
            reason = "Missed-malware mean exceeds clean maximum; review semantic source and model compatibility."
        elif miss_mean > clean["mean"] and det_mean > clean["mean"]:
            recommendation = "WEAK_CANDIDATE_REVIEW"
            reason = "Feature is higher in malicious groups than clean on average, but not clearly separated."
        else:
            recommendation = "NOT_PRIORITY"
            reason = "No clean-safe separation signal from current J4 rows."

        out.append({
            "feature": feature,
            "family": fam,
            "clean_min": clean["min"],
            "clean_mean": clean["mean"],
            "clean_max": clean["max"],
            "clean_std": clean["std"],
            "detected_mean": det["mean"],
            "detected_max": det["max"],
            "missed_mean": miss["mean"],
            "missed_max": miss["max"],
            "missed_over_clean_mean": missed_over_clean,
            "detected_over_clean_mean": detected_over_clean,
            "j5_family_decision": family_decision.get("j5_decision", "n/a"),
            "j5_clean_flips": family_decision.get("clean_flips", ""),
            "recommendation": recommendation,
            "reason": reason,
        })
    return out


def _case_gap_report(rows: List[Dict[str, Any]], features: List[str], scores: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    clean_rows = [r for r in rows if r.get("group") == "clean"]
    clean_max: Dict[str, float] = {f: max((_safe_float(r.get(f), 0.0) for r in clean_rows), default=0.0) for f in features}
    reports: List[Dict[str, Any]] = []
    for row in rows:
        if row.get("group") != "missed_malicious":
            continue
        sid = row.get("session_id", "")
        elevated = []
        absent_or_clean_like = []
        for f in features:
            fam = _feature_group(f)
            if fam in RISKY_RUNTIME_FAMILIES:
                continue
            val = _safe_float(row.get(f), 0.0)
            if val > clean_max.get(f, 0.0):
                elevated.append((f, val, clean_max.get(f, 0.0)))
            elif val <= clean_max.get(f, 0.0):
                absent_or_clean_like.append((f, val, clean_max.get(f, 0.0)))
        elevated = sorted(elevated, key=lambda x: (x[1] - x[2]), reverse=True)[:10]
        s = scores.get(sid, {})
        reports.append({
            "session_id": sid,
            "dump_name": s.get("dump_name") or s.get("dump_file") or row.get("Category", ""),
            "baseline_score": s.get("baseline_recomputed_score") or s.get("logged_score_fraction") or s.get("score_raw", ""),
            "ae_mse": s.get("ae_mse", ""),
            "top_non_risky_elevated_features": "; ".join(f"{f}={v:g} (clean_max={cm:g})" for f, v, cm in elevated),
            "count_non_risky_elevated_features": len(elevated),
            "interpretation": "Near-threshold: prioritize parser-confirmed malfind/injection feature quality." if _safe_float(s.get("baseline_recomputed_score") or s.get("logged_score_fraction")) >= 0.40 else "Low-score miss: likely dataset/feature-representation limitation unless strong report-only artifacts exist.",
        })
    return reports


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase J6 clean-safe feature delta search")
    ap.add_argument("--j4-dir", required=True, help="Path to EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5")
    ap.add_argument("--j5-summary", default="", help="Optional path to phaseJ5_svcscan_modules_whatif_summary.json")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()

    j4_dir = Path(args.j4_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    j5_summary = Path(args.j5_summary) if args.j5_summary else None
    if j5_summary and not j5_summary.exists():
        print(f"[WARN] J5 summary does not exist: {j5_summary}")
        j5_summary = None

    groups = DEFAULT_GROUPS
    rows, features = _load_k2_rows(j4_dir, groups)
    scores = _load_scores(j4_dir, groups, j5_summary)
    j5_decisions = _j5_family_decisions(j5_summary)

    feature_stats = _group_feature_stats(rows, features, j5_decisions)
    candidates = [r for r in feature_stats if r["recommendation"] in {"CLEAN_SAFE_CANDIDATE_REVIEW", "WEAK_CANDIDATE_REVIEW"}]
    candidates = sorted(candidates, key=lambda r: (r["recommendation"] != "CLEAN_SAFE_CANDIDATE_REVIEW", -float(r["missed_over_clean_mean"] if r["missed_over_clean_mean"] != math.inf else 1e9)))
    case_report = _case_gap_report(rows, features, scores)

    _write_csv(out / "phaseJ6_feature_group_stats.csv", feature_stats)
    _write_csv(out / "phaseJ6_feature_delta_candidates.csv", candidates)
    _write_csv(out / "phaseJ6_case_gap_report.csv", case_report)

    summary = {
        "phase": "J6_CLEAN_SAFE_FEATURE_DELTA_SEARCH",
        "diagnostic_only": True,
        "rules_preserved": {
            "threshold_changed": False,
            "threshold_fraction": THRESHOLD,
            "model_retrained": False,
            "feature_mapper_modified": False,
            "session_json_modified": False,
            "runtime_verdict_logic_modified": False,
            "veto_rules_added": False,
            "clean_dampeners_added": False,
        },
        "input_j4_dir": str(j4_dir),
        "input_j5_summary": str(j5_summary) if j5_summary else None,
        "features_analyzed": len(features),
        "candidate_count": len(candidates),
        "j5_family_decisions": j5_decisions,
        "top_candidates": candidates[:15],
        "main_decision": "svcscan remains export/diagnostic-only if J5 clean_flips > 0; modules remains low-priority if avg_missed_gain is 0.",
    }
    (out / "phaseJ6_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    md: List[str] = []
    md.append("# Phase J6 — Clean-Safe Feature Delta Search\n")
    md.append("Diagnostic only. No runtime verdict logic, FeatureMapper, saved model, threshold, session JSON, or training data was modified.\n")
    md.append(f"Fixed RF threshold preserved for interpretation: `{THRESHOLD}`.\n")
    md.append("## J5 family decision\n")
    for fam, dec in j5_decisions.items():
        md.append(f"- `{fam}`: `{dec.get('j5_decision')}`; clean flips = `{dec.get('clean_flips')}`; avg missed gain = `{dec.get('avg_missed_gain', 'n/a')}`. {dec.get('note', '')}\n")
    md.append("\n## Top clean-safe/weak candidates\n")
    if candidates:
        md.append("| Feature | Family | Recommendation | Clean max | Missed mean | Detected mean | Reason |\n")
        md.append("|---|---|---|---:|---:|---:|---|\n")
        for r in candidates[:20]:
            md.append(f"| {r['feature']} | {r['family']} | {r['recommendation']} | {float(r['clean_max']):.4g} | {float(r['missed_mean']):.4g} | {float(r['detected_mean']):.4g} | {r['reason']} |\n")
    else:
        md.append("No clean-safe runtime candidates were found from the K2 wide rows.\n")
    md.append("\n## Missed-malware case interpretation\n")
    md.append("| Session | Score | Interpretation | Top non-risky elevated features |\n")
    md.append("|---|---:|---|---|\n")
    for r in case_report:
        md.append(f"| {r['session_id']} | {r['baseline_score']} | {r['interpretation']} | {r['top_non_risky_elevated_features']} |\n")
    md.append("\n## Final rule\n")
    md.append("Do not promote a feature family to runtime ML support unless it improves missed malicious samples without flipping clean baselines and its semantic extraction source is defensible.\n")
    (out / "phaseJ6_report.md").write_text("".join(md), encoding="utf-8")

    print("Phase J6 clean-safe feature delta search complete.")
    print("Output:", out)
    print("Features analyzed:", len(features))
    print("Candidate rows:", len(candidates))
    print("J5 decisions:", json.dumps(j5_decisions, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

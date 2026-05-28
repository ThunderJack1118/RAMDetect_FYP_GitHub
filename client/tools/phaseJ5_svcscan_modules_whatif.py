"""
Phase J5 — svcscan/modules ML-support what-if audit (diagnostic only).

Purpose
-------
Offline experiment to test whether semantically available svcscan/modules
candidate features would change RF-AE suspicion scores if they were injected
into the live CIC54 mapping path.

Safety rules preserved
----------------------
- Does NOT modify session JSON.
- Does NOT modify FeatureMapper, RF, AE, threshold, or saved models.
- Does NOT retrain models.
- Does NOT add veto rules, clean dampeners, score floors, or overrides.
- Uses fixed RF threshold 0.5 only for diagnostic label comparison.
- Diagnostic only: outputs CSV/JSON/MD under --out.

Inputs
------
--j4-dir should point to EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5.
The tool reads:
  feature_debug/<sid>/raw_features.json
  feature_debug/<sid>/model_scores.json
  feature_debug/<sid>/native_phase2_diagnostics.json
  phaseJ4_session_score_summary.csv

Example
-------
python tools/phaseJ5_svcscan_modules_whatif.py ^
  --j4-dir models/experiments/EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5 ^
  --models-dir models ^
  --out models/experiments/EXP_J5_SVCSCAN_MODULES_WHATIF_POST_L5
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ramdetect.ml.feature_mapper import FeatureMapper  # noqa: E402
from ramdetect.ml.random_forest_model import RandomForestModel, DEFAULT_THRESHOLD  # noqa: E402


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _safe_float(v: Any, default: Optional[float] = None) -> Optional[float]:
    if v is None or v == "":
        return default
    try:
        x = float(v)
    except Exception:
        return default
    if math.isnan(x) or math.isinf(x):
        return default
    return x


def _read_summary_rows(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def _load_raw_features(debug_dir: Path) -> Dict[str, float]:
    payload = _load_json(debug_dir / "raw_features.json", {}) or {}
    raw = payload.get("raw_features", payload)
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, float] = {}
    for k, v in raw.items():
        x = _safe_float(v, None)
        if x is not None:
            out[str(k)] = float(x)
    return out


def _load_model_scores(debug_dir: Path) -> Dict[str, Any]:
    return _load_json(debug_dir / "model_scores.json", {}) or {}


def _load_phase2(debug_dir: Path) -> Dict[str, Any]:
    return _load_json(debug_dir / "native_phase2_diagnostics.json", {}) or {}


def _svcscan_candidates(phase2: Dict[str, Any]) -> Dict[str, float]:
    """Return canonical svcscan.* candidates from K3/native_phase2 diagnostics."""
    out: Dict[str, float] = {}
    svc = phase2.get("service_builder") or {}

    # Preferred: canonical_candidates table records exactly which CIC canonical
    # feature each diagnostic source proposes.
    for row in svc.get("canonical_candidates") or []:
        feat = str(row.get("canonical_feature") or "")
        if not feat.startswith("svcscan."):
            continue
        val = _safe_float(row.get("diagnostic_raw_value"), None)
        if val is not None:
            out[feat] = float(val)

    # Fallback: raw_features may already include canonical svcscan names.
    raw = svc.get("raw_features") or {}
    for k, v in raw.items():
        if str(k).startswith("svcscan."):
            val = _safe_float(v, None)
            if val is not None:
                out[str(k)] = float(val)

    return out


def _modules_candidates(phase2: Dict[str, Any]) -> Dict[str, float]:
    """Return modules.nmodules candidate from diagnostics, if present."""
    out: Dict[str, float] = {}
    md = phase2.get("modules_diagnostic") or {}
    val = _safe_float(md.get("candidate_modules_nmodules_value"), None)
    if val is not None:
        out["modules.nmodules"] = float(val)
    return out


def _predict_score(
    mapper: FeatureMapper,
    rf: RandomForestModel,
    features: Dict[str, float],
    ae_mse: float,
) -> Tuple[float, str, int, int]:
    """Transform with current FeatureMapper, append AE MSE if RF expects 55, return score."""
    x54 = mapper.transform_live(features)
    expected = getattr(rf.model, "n_features_in_", x54.shape[1] + 1)
    if expected == x54.shape[1] + 1:
        x = np.concatenate([x54, np.array([[float(ae_mse)]], dtype=np.float32)], axis=1)
    elif expected == x54.shape[1]:
        x = x54
    else:
        raise RuntimeError(
            f"RF model expects {expected} features, but mapper produced {x54.shape[1]} "
            f"or fused {x54.shape[1] + 1}."
        )
    result = rf.predict(x)
    return float(result["suspicion_score"]), str(result["verdict"]), int(x54.shape[1]), int(expected)


def _coverage_count(mapper: FeatureMapper, features: Dict[str, float]) -> Tuple[int, int, float]:
    rep = mapper.get_coverage_report(features)
    return int(rep["covered"]), int(rep["total_canonical"]), float(rep["coverage_pct"])


def _write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--j4-dir", required=True, help="EXP_J4_ACCURACY_ENHANCEMENT_AUDIT_POST_L5 directory")
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    j4 = Path(args.j4_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    mapper = FeatureMapper.load(Path(args.models_dir) / "feature_mapper.pkl")
    rf = RandomForestModel.load(Path(args.models_dir) / "random_forest.pkl")

    summary_rows = _read_summary_rows(j4 / "phaseJ4_session_score_summary.csv")
    if not summary_rows:
        raise SystemExit(f"Missing or empty J4 summary: {j4 / 'phaseJ4_session_score_summary.csv'}")

    rows: List[Dict[str, Any]] = []
    detail: Dict[str, Any] = {
        "phase": "J5_SVCSCAN_MODULES_WHATIF",
        "diagnostic_only": True,
        "rules_preserved": {
            "threshold_changed": False,
            "threshold_fraction": DEFAULT_THRESHOLD,
            "model_retrained": False,
            "feature_mapper_modified": False,
            "session_json_modified": False,
            "runtime_verdict_logic_modified": False,
            "veto_rules_added": False,
            "clean_dampeners_added": False,
        },
        "sessions": [],
    }

    for s in summary_rows:
        sid = s.get("session_id", "")
        group = s.get("group", "")
        debug_dir = j4 / "feature_debug" / sid
        raw = _load_raw_features(debug_dir)
        scores = _load_model_scores(debug_dir)
        phase2 = _load_phase2(debug_dir)

        ae_mse = _safe_float(scores.get("ae_mse"), 0.0) or 0.0
        logged_score = _safe_float(scores.get("rf_score_fraction"), None)
        if logged_score is None:
            # phaseJ4 summary stores percentage-like score_raw.
            sr = _safe_float(s.get("score_raw"), None)
            logged_score = sr / 100.0 if sr is not None and sr > 1.0 else sr

        svc = _svcscan_candidates(phase2)
        mods = _modules_candidates(phase2)

        scenarios = {
            "baseline_recomputed": dict(raw),
            "svcscan_only": {**raw, **svc},
            "modules_only": {**raw, **mods},
            "svcscan_modules": {**raw, **svc, **mods},
        }

        session_payload = {
            "session_id": sid,
            "group": group,
            "logged_score_fraction": logged_score,
            "ae_mse": ae_mse,
            "svcscan_candidates": svc,
            "modules_candidates": mods,
            "scenarios": {},
        }

        baseline_score = None
        baseline_verdict = ""
        for scenario, feats in scenarios.items():
            try:
                score, verdict, n_mapper, n_rf = _predict_score(mapper, rf, feats, ae_mse)
                cov_n, cov_total, cov_pct = _coverage_count(mapper, feats)
                if scenario == "baseline_recomputed":
                    baseline_score = score
                    baseline_verdict = verdict
                delta = None if baseline_score is None else score - baseline_score
                rows.append({
                    "session_id": sid,
                    "group": group,
                    "scenario": scenario,
                    "logged_score_fraction": logged_score,
                    "recomputed_score_fraction": score,
                    "delta_vs_recomputed_baseline": delta,
                    "whatif_verdict_at_0_5": verdict,
                    "baseline_recomputed_verdict": baseline_verdict,
                    "coverage": f"{cov_n}/{cov_total}",
                    "coverage_pct": cov_pct,
                    "ae_mse_reused": ae_mse,
                    "svcscan_feature_count_injected": len(svc) if scenario in {"svcscan_only", "svcscan_modules"} else 0,
                    "modules_feature_count_injected": len(mods) if scenario in {"modules_only", "svcscan_modules"} else 0,
                    "rf_expected_features": n_rf,
                    "diagnostic_only": True,
                })
                session_payload["scenarios"][scenario] = {
                    "score_fraction": score,
                    "verdict_at_0_5": verdict,
                    "delta_vs_baseline": delta,
                    "coverage": f"{cov_n}/{cov_total}",
                    "coverage_pct": cov_pct,
                }
            except Exception as exc:
                rows.append({
                    "session_id": sid,
                    "group": group,
                    "scenario": scenario,
                    "error": str(exc),
                    "diagnostic_only": True,
                })
                session_payload["scenarios"][scenario] = {"error": str(exc)}

        detail["sessions"].append(session_payload)

    fields = [
        "session_id", "group", "scenario", "logged_score_fraction",
        "recomputed_score_fraction", "delta_vs_recomputed_baseline",
        "whatif_verdict_at_0_5", "baseline_recomputed_verdict",
        "coverage", "coverage_pct", "ae_mse_reused",
        "svcscan_feature_count_injected", "modules_feature_count_injected",
        "rf_expected_features", "diagnostic_only", "error",
    ]
    _write_csv(out / "phaseJ5_svcscan_modules_whatif_scores.csv", rows, fields)

    with (out / "phaseJ5_svcscan_modules_whatif_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(detail, fh, indent=2, default=str)

    # Compact markdown report.
    md: List[str] = []
    md.append("# Phase J5 — svcscan/modules ML-Support What-If")
    md.append("")
    md.append("Diagnostic only. No runtime verdict logic, FeatureMapper, saved model, threshold, or session JSON was modified.")
    md.append("")
    md.append(f"Fixed RF threshold used for diagnostic verdict labels: `{DEFAULT_THRESHOLD}`.")
    md.append("")
    md.append("## Scenario meaning")
    md.append("")
    md.append("- `baseline_recomputed`: current raw features recomputed through current mapper/model.")
    md.append("- `svcscan_only`: adds semantically available `svcscan.*` diagnostic candidates.")
    md.append("- `modules_only`: adds diagnostic `modules.nmodules` candidate.")
    md.append("- `svcscan_modules`: adds both groups together.")
    md.append("")
    md.append("## Key rows")
    md.append("")
    md.append("| Session | Group | Scenario | Score | Δ baseline | Verdict | Coverage |")
    md.append("|---|---|---|---:|---:|---|---|")
    for r in rows:
        if r.get("scenario") != "svcscan_modules":
            continue
        score = r.get("recomputed_score_fraction")
        delta = r.get("delta_vs_recomputed_baseline")
        md.append(
            f"| {r.get('session_id','')} | {r.get('group','')} | {r.get('scenario','')} | "
            f"{float(score):.4f} | {float(delta):+.4f} | {r.get('whatif_verdict_at_0_5','')} | {r.get('coverage','')} |"
        )
    md.append("")
    md.append("## Interpretation rule")
    md.append("")
    md.append("A candidate feature family should only proceed to runtime support if it improves missed malicious samples without flipping clean baselines to SUSPICIOUS and if its semantic extraction is defensible.")
    (out / "phaseJ5_svcscan_modules_whatif_report.md").write_text("\n".join(md), encoding="utf-8")

    print("Phase J5 svcscan/modules what-if complete.")
    print("Output:", out)
    print("Scores CSV:", out / "phaseJ5_svcscan_modules_whatif_scores.csv")
    print("Report:", out / "phaseJ5_svcscan_modules_whatif_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

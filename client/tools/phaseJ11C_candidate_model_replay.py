#!/usr/bin/env python3
"""
Phase J11C — Candidate RF-AE Model Replay
=========================================

Diagnostic-only replay tool for RAMDetect J11.

Purpose
-------
Compare the current production RF-AE score stored in existing feature_debug
outputs against candidate RF-AE model folders, without changing production
models, FeatureMapper, threshold, session JSON, or verdict logic.

Inputs
------
--j4-dir:
    A J4/J11 validation audit folder containing feature_debug/<session_id>/
    with canonical_54_features.json and model_scores.json.

--candidate-dir:
    One or more model folders containing:
      feature_mapper.pkl
      autoencoder.pkl
      autoencoder.keras
      random_forest.pkl

Output
------
CSV/JSON/Markdown reports under --out.

Master rule preserved
---------------------
Final replay decision uses RF probability only, threshold fixed at 0.5.
No parser override, no veto, no clean dampener, no score floor.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import pickle
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np

FIXED_RF_THRESHOLD = 0.5

# Post-L5/J4 validation grouping used in RAMDetect evaluation.
# Unknown/new session IDs are still replayed and labelled "unknown".
SESSION_GROUPS = {
    "3054143d": ("clean", "VMTJ clean"),
    "bde36e7f": ("clean", "G4DINFH clean"),
    "febb14ec": ("clean", "NTDKQQG clean"),

    "f99d9ce1": ("detected_malicious", "CobaltStrike beacon"),
    "bfb5d086": ("detected_malicious", "CobaltStrike Injection 2"),
    "e17db648": ("detected_malicious", "attack2 process injection"),
    "b755d63c": ("detected_malicious", "DLLHijacking"),
    "59da07e7": ("detected_malicious", "RedTail"),
    "095de269": ("detected_malicious", "GandCrab"),
    "14ce2ed3": ("detected_malicious", "GoldenEye"),

    "9c896133": ("missed_malicious", "DeriaLock"),
    "0daa326a": ("missed_malicious", "Locky.AZ"),
    "c99f293c": ("missed_malicious", "InfinityCrypt"),
    "8756a863": ("missed_malicious", "Spora"),
    "695e1d61": ("missed_malicious", "WannaCry"),
}

COUNT_FEATURE_DEFAULT_NAMES = {
    # Used only as fallback if mapper pickle lacks count_col_indices.
    "pslist.nproc", "pslist.nppid", "pslist.nprocs64bit",
    "dlllist.ndlls",
    "handles.nhandles", "handles.nport", "handles.nfile", "handles.nevent",
    "handles.ndesktop", "handles.nkey", "handles.nthread", "handles.ndirectory",
    "handles.nsemaphore", "handles.ntimer", "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "malfind.ninjections", "malfind.commitCharge", "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool", "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list", "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.process_services", "svcscan.shared_process_services",
    "svcscan.interactive_process_services", "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
}


def _load_pickle(path: Path) -> Any:
    with path.open("rb") as f:
        return pickle.load(f)


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        v = float(value)
        if math.isnan(v) or math.isinf(v):
            return default
        return v
    except Exception:
        return default


def _load_canonical_raw_features(feature_debug_dir: Path) -> Tuple[str, Dict[str, float], Dict[str, float]]:
    """Return (session_id, raw canonical dict, original scaled dict)."""
    path = feature_debug_dir / "canonical_54_features.json"
    if not path.exists():
        # Older exports sometimes use canonical_features.json.
        path = feature_debug_dir / "canonical_features.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing canonical features JSON in {feature_debug_dir}")

    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    sid = str(data.get("session_id") or feature_debug_dir.name)

    raw: Dict[str, float] = {}
    scaled: Dict[str, float] = {}
    features = data.get("features", [])
    if isinstance(features, list):
        for row in features:
            if not isinstance(row, dict):
                continue
            name = row.get("canonical_feature") or row.get("feature")
            if not name:
                continue
            raw[name] = _coerce_float(
                row.get("raw_unscaled_value", row.get("live_value", row.get("raw_value", 0.0)))
            )
            scaled[name] = _coerce_float(row.get("scaled_value", row.get("value", 0.0)))

    if not raw and isinstance(data.get("by_feature"), dict):
        for name, row in data["by_feature"].items():
            if isinstance(row, dict):
                raw[name] = _coerce_float(row.get("raw_unscaled_value", row.get("live_value", 0.0)))
                scaled[name] = _coerce_float(row.get("scaled_value", row.get("value", 0.0)))
            else:
                raw[name] = _coerce_float(row)

    if not raw:
        raise RuntimeError(f"No canonical feature rows parsed from {path}")
    return sid, raw, scaled


def _load_original_score(feature_debug_dir: Path) -> Dict[str, Any]:
    path = feature_debug_dir / "model_scores.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return {
        "original_verdict": str(data.get("verdict", "")).upper(),
        "original_score_pct": _coerce_float(data.get("rf_score_percent", data.get("hybrid_score_percent", "")), 0.0),
        "original_score_fraction": _coerce_float(data.get("rf_score_fraction", data.get("hybrid_score_fraction", "")), 0.0),
        "original_ae_mse": _coerce_float(data.get("ae_mse", data.get("reconstruction_error", "")), 0.0),
    }


def _transform_with_mapper(mapper_data: Dict[str, Any], raw_features: Dict[str, float]) -> Tuple[np.ndarray, List[str]]:
    canonical = list(mapper_data.get("canonical_features") or [])
    if not canonical:
        raise RuntimeError("feature_mapper.pkl does not contain canonical_features")
    scaler = mapper_data.get("scaler")
    if scaler is None:
        raise RuntimeError("feature_mapper.pkl does not contain scaler")

    count_indices = mapper_data.get("count_col_indices")
    if count_indices is None:
        count_indices = [i for i, name in enumerate(canonical) if name in COUNT_FEATURE_DEFAULT_NAMES]
    count_indices = [int(i) for i in count_indices]

    x_raw = np.array([_coerce_float(raw_features.get(name, 0.0)) for name in canonical], dtype=np.float32).reshape(1, -1)
    x_log = x_raw.copy()
    for ci in count_indices:
        if 0 <= ci < x_log.shape[1]:
            x_log[:, ci] = np.log1p(np.maximum(x_log[:, ci], 0.0))
    x_scaled = scaler.transform(x_log).astype(np.float32)
    return x_scaled, canonical


def _load_candidate_models(candidate_dir: Path) -> Dict[str, Any]:
    required = ["feature_mapper.pkl", "autoencoder.pkl", "autoencoder.keras", "random_forest.pkl"]
    missing = [name for name in required if not (candidate_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Candidate {candidate_dir} missing files: {missing}")

    mapper_data = _load_pickle(candidate_dir / "feature_mapper.pkl")
    ae_meta = _load_pickle(candidate_dir / "autoencoder.pkl")
    rf_data = _load_pickle(candidate_dir / "random_forest.pkl")

    if not isinstance(rf_data, dict) or "model" not in rf_data:
        raise RuntimeError(f"Unsupported random_forest.pkl format in {candidate_dir}")

    # TensorFlow is imported lazily because loading several AE models can take a few seconds.
    import tensorflow as tf
    ae_model = tf.keras.models.load_model(candidate_dir / "autoencoder.keras")

    return {
        "name": candidate_dir.name,
        "dir": str(candidate_dir),
        "mapper_data": mapper_data,
        "ae_meta": ae_meta,
        "ae_model": ae_model,
        "rf_model": rf_data["model"],
        "rf_params": rf_data.get("params", {}),
        "rf_saved_threshold": rf_data.get("threshold", None),
    }


def _predict_candidate(candidate: Dict[str, Any], raw_features: Dict[str, float]) -> Dict[str, Any]:
    x54, canonical = _transform_with_mapper(candidate["mapper_data"], raw_features)
    recon = candidate["ae_model"].predict(x54, verbose=0)
    ae_mse = float(np.mean(np.square(x54 - recon), axis=1)[0])
    x55 = np.concatenate([x54, np.array([[ae_mse]], dtype=np.float32)], axis=1)
    proba = candidate["rf_model"].predict_proba(x55)[0]
    score = float(proba[1])
    verdict = "SUSPICIOUS" if score >= FIXED_RF_THRESHOLD else "CLEAN"
    return {
        "candidate_score_fraction": score,
        "candidate_score_pct": score * 100.0,
        "candidate_verdict": verdict,
        "candidate_ae_mse": ae_mse,
        "n_features_base": int(x54.shape[1]),
        "n_features_fused": int(x55.shape[1]),
    }


def _iter_feature_debug_dirs(j4_dir: Path) -> Iterable[Path]:
    root = j4_dir / "feature_debug"
    if not root.exists():
        raise FileNotFoundError(f"Missing feature_debug directory: {root}")
    for child in sorted(root.iterdir()):
        if child.is_dir() and ((child / "canonical_54_features.json").exists() or (child / "canonical_features.json").exists()):
            yield child


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase J11C candidate RF-AE model replay")
    ap.add_argument("--j4-dir", required=True, help="J4 audit folder containing feature_debug/<session_id>")
    ap.add_argument("--candidate-dir", action="append", required=True, help="Candidate model folder. Repeat for multiple candidates.")
    ap.add_argument("--out", required=True, help="Output folder")
    args = ap.parse_args()

    j4_dir = Path(args.j4_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    candidates = [_load_candidate_models(Path(p)) for p in args.candidate_dir]

    rows: List[Dict[str, Any]] = []
    for fd in _iter_feature_debug_dirs(j4_dir):
        sid, raw_features, _scaled = _load_canonical_raw_features(fd)
        group, sample_name = SESSION_GROUPS.get(sid, ("unknown", sid))
        original = _load_original_score(fd)
        for cand in candidates:
            pred = _predict_candidate(cand, raw_features)
            score_delta = pred["candidate_score_pct"] - original.get("original_score_pct", 0.0)
            changed = "YES" if original.get("original_verdict") and original.get("original_verdict") != pred["candidate_verdict"] else "NO"
            rows.append({
                "session_id": sid,
                "group": group,
                "sample_name": sample_name,
                "candidate": cand["name"],
                "original_verdict": original.get("original_verdict", ""),
                "original_score_pct": round(original.get("original_score_pct", 0.0), 4),
                "original_ae_mse": round(original.get("original_ae_mse", 0.0), 8),
                "candidate_verdict": pred["candidate_verdict"],
                "candidate_score_pct": round(pred["candidate_score_pct"], 4),
                "candidate_ae_mse": round(pred["candidate_ae_mse"], 8),
                "score_delta_pct": round(score_delta, 4),
                "verdict_changed": changed,
                "n_features_base": pred["n_features_base"],
                "n_features_fused": pred["n_features_fused"],
                "fixed_threshold": FIXED_RF_THRESHOLD,
            })

    csv_path = out / "phaseJ11C_candidate_model_replay_scores.csv"
    if not rows:
        raise RuntimeError("No replay rows generated")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Summary per candidate.
    summary: Dict[str, Any] = {
        "phase": "J11C_candidate_model_replay",
        "master_rule": {
            "decision_mode": "ml_only",
            "rf_threshold": FIXED_RF_THRESHOLD,
            "no_veto_rules": True,
            "no_clean_dampeners": True,
            "no_parser_override": True,
            "no_model_promotion": True,
        },
        "candidate_summaries": {},
    }

    for cand in sorted(set(r["candidate"] for r in rows)):
        cr = [r for r in rows if r["candidate"] == cand]
        clean = [r for r in cr if r["group"] == "clean"]
        detected = [r for r in cr if r["group"] == "detected_malicious"]
        missed = [r for r in cr if r["group"] == "missed_malicious"]
        clean_flips = [r for r in clean if r["candidate_verdict"] == "SUSPICIOUS"]
        detected_kept = [r for r in detected if r["candidate_verdict"] == "SUSPICIOUS"]
        missed_caught = [r for r in missed if r["candidate_verdict"] == "SUSPICIOUS"]
        near_threshold = [r for r in missed if 45.0 <= float(r["candidate_score_pct"]) < 50.0]
        summary["candidate_summaries"][cand] = {
            "clean_total": len(clean),
            "clean_false_positive_flips": len(clean_flips),
            "clean_false_positive_sessions": [r["session_id"] for r in clean_flips],
            "detected_malicious_total": len(detected),
            "detected_malicious_kept_suspicious": len(detected_kept),
            "missed_malicious_total": len(missed),
            "missed_malicious_newly_suspicious": len(missed_caught),
            "missed_malicious_newly_suspicious_sessions": [r["session_id"] for r in missed_caught],
            "missed_malicious_near_threshold_sessions": [r["session_id"] for r in near_threshold],
            "average_clean_score_pct": round(sum(float(r["candidate_score_pct"]) for r in clean) / max(len(clean), 1), 4),
            "average_missed_score_pct": round(sum(float(r["candidate_score_pct"]) for r in missed) / max(len(missed), 1), 4),
            "decision_hint": "candidate_requires_review",
        }

    json_path = out / "phaseJ11C_candidate_model_replay_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Markdown report.
    md = []
    md.append("# Phase J11C Candidate RF-AE Model Replay")
    md.append("")
    md.append("Diagnostic-only replay. No production model files, FeatureMapper, thresholds, session JSON, or verdict logic were changed.")
    md.append("")
    md.append("## Master rule")
    md.append("")
    md.append("Final replay decision uses ML-only Random Forest probability with fixed threshold 0.5. Parser findings are not used as overrides.")
    md.append("")
    md.append("## Candidate summary")
    md.append("")
    md.append("| Candidate | Clean FP flips | Detected kept suspicious | Missed newly suspicious | Avg clean score | Avg missed score |")
    md.append("|---|---:|---:|---:|---:|---:|")
    for cand, s in summary["candidate_summaries"].items():
        md.append(
            f"| {cand} | {s['clean_false_positive_flips']}/{s['clean_total']} | "
            f"{s['detected_malicious_kept_suspicious']}/{s['detected_malicious_total']} | "
            f"{s['missed_malicious_newly_suspicious']}/{s['missed_malicious_total']} | "
            f"{s['average_clean_score_pct']:.2f}% | {s['average_missed_score_pct']:.2f}% |"
        )
    md.append("")
    md.append("## Decision guide")
    md.append("")
    md.append("Reject a candidate if it flips any clean baseline to SUSPICIOUS. Prefer candidates that keep clean baselines CLEAN, preserve previously detected malicious samples, and improve missed-malware scores without threshold changes.")
    (out / "phaseJ11C_candidate_model_replay_report.md").write_text("\n".join(md), encoding="utf-8")

    print("Phase J11C candidate replay complete.")
    print("Output:", out)
    print("Rows:", len(rows))
    for cand, s in summary["candidate_summaries"].items():
        print(
            f"  {cand}: clean_flips={s['clean_false_positive_flips']}/{s['clean_total']} | "
            f"detected_kept={s['detected_malicious_kept_suspicious']}/{s['detected_malicious_total']} | "
            f"missed_new={s['missed_malicious_newly_suspicious']}/{s['missed_malicious_total']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

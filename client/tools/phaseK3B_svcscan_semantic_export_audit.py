#!/usr/bin/env python3
"""
Phase K3B — svcscan Semantic Export Audit
=========================================
Diagnostic-only audit for RAMDetect-native svcscan.* semantic derivation.

This tool reads saved RAMDetect session JSON files and shows the svcscan.*
values that K3B will use in CIC-MalMem2022 compatibility exports. It does not
modify session JSON, ML models, FeatureMapper, thresholds, or verdict logic.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ramdetect.features.svcscan_semantic_features import (  # noqa: E402
    SVC_FEATURES,
    build_svcscan_semantic_features,
)


def _load_session_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return SimpleNamespace(**json.load(fh))


def _resolve_session(session_id: str, sessions_dir: Path) -> Path:
    p = sessions_dir / f"{session_id}.json"
    if not p.is_file():
        raise FileNotFoundError(f"Session JSON not found for {session_id}: {p}")
    return p


def _write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session-id", action="append", default=[], help="RAMDetect saved session ID")
    ap.add_argument("--session-json", action="append", default=[], help="Direct path to saved session JSON")
    ap.add_argument("--sessions-dir", default="ramdetect/ui/data/sessions")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sessions_dir = Path(args.sessions_dir)

    session_paths: List[Path] = []
    for sid in args.session_id:
        session_paths.append(_resolve_session(sid, sessions_dir))
    for sj in args.session_json:
        session_paths.append(Path(sj))
    if not session_paths:
        raise SystemExit("Provide at least one --session-id or --session-json")

    summary_rows: List[Dict[str, Any]] = []
    feature_rows: List[Dict[str, Any]] = []
    summaries: List[Dict[str, Any]] = []

    for sp in session_paths:
        sess = _load_session_json(sp)
        features, sources, summary = build_svcscan_semantic_features(sess)
        sid = getattr(sess, "session_id", sp.stem)
        dump = getattr(sess, "dump_filename", "")
        summaries.append({"session_id": sid, "dump_filename": dump, "summary": summary})
        summary_rows.append({
            "session_id": sid,
            "dump_filename": dump,
            "ready": summary.get("ready", False),
            "quality": summary.get("quality", ""),
            "process_count": summary.get("process_count", 0),
            "dll_count": summary.get("dll_count", 0),
            "handle_count": summary.get("handle_count", 0),
            "service_registry_record_count": summary.get("service_registry_record_count", 0),
            "registry_service_name_count": summary.get("registry_service_name_count", 0),
            "service_handle_pid_count": summary.get("service_handle_pid_count", 0),
            "svchost_instances": summary.get("svchost_instances", 0),
            "own_process_service_pids": summary.get("own_process_service_pids", 0),
            "shared_process_service_pids": summary.get("shared_process_service_pids", 0),
            "interactive_service_pids": summary.get("interactive_service_pids", 0),
            "kernel_driver_names": summary.get("kernel_driver_names", 0),
            "fs_driver_names": summary.get("fs_driver_names", 0),
        })
        for feat in SVC_FEATURES:
            feature_rows.append({
                "session_id": sid,
                "dump_filename": dump,
                "cic_feature": feat,
                "value": features.get(feat, 0.0),
                "ramdetect_source": sources.get(feat, "not_available"),
                "semantic_status_after_k3b": "validated_extracted" if feat in features else "not_available",
            })

    _write_csv(out / "phaseK3B_svcscan_session_summary.csv", summary_rows, [
        "session_id", "dump_filename", "ready", "quality", "process_count", "dll_count",
        "handle_count", "service_registry_record_count", "registry_service_name_count",
        "service_handle_pid_count", "svchost_instances", "own_process_service_pids",
        "shared_process_service_pids", "interactive_service_pids", "kernel_driver_names",
        "fs_driver_names",
    ])
    _write_csv(out / "phaseK3B_svcscan_feature_values.csv", feature_rows, [
        "session_id", "dump_filename", "cic_feature", "value", "ramdetect_source",
        "semantic_status_after_k3b",
    ])

    payload = {
        "phase": "K3B_SVCSCAN_SEMANTIC_EXPORT_AUDIT",
        "diagnostic_only": True,
        "session_count": len(session_paths),
        "expected_semantic_coverage_gain": "+7 CIC svcscan features when K2/K2B are rerun with the K3B exporter patch",
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
            "verdict_override_added": False,
        },
        "sessions": summaries,
    }
    (out / "phaseK3B_svcscan_semantic_summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Phase K3B — svcscan Semantic Export Audit",
        "",
        "This audit is diagnostic/export-only. It does not change RF threshold, FeatureMapper, dataset, session JSON, or verdict logic.",
        "",
        "## Expected coverage impact",
        "",
        "After applying the K3B exporter and rerunning K2/K2B, `svcscan.*` rows with `ramdetect_source=k3b_svcscan_semantic:*` are counted as validated extracted semantic evidence.",
        "This should increase semantic coverage from 28/55 to approximately 35/55, assuming all seven svcscan fields are produced.",
        "",
        "| Session | Dump | Quality | Registry records | svchost | nservices | nactive |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        feats = next((s.get("summary", {}).get("features", {}) for s in summaries if s["session_id"] == row["session_id"]), {})
        lines.append(
            f"| {row['session_id']} | {row['dump_filename']} | {row['quality']} | "
            f"{row['service_registry_record_count']} | {row['svchost_instances']} | "
            f"{feats.get('svcscan.nservices', 0)} | {feats.get('svcscan.nactive', 0)} |"
        )
    (out / "phaseK3B_svcscan_semantic_report.md").write_text("\n".join(lines), encoding="utf-8")

    print("Phase K3B svcscan semantic export audit complete.")
    print("Output:", out)
    for row in summary_rows:
        print(f"  {row['session_id']}: quality={row['quality']} registry_records={row['service_registry_record_count']} svchost={row['svchost_instances']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

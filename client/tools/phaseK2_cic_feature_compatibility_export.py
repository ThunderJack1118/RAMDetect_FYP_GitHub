"""
Phase K2 — CIC-MalMem2022 feature compatibility export.

Creates:
  - phaseK2_cicmalmem2022_rows.csv
      Wide CSV rows shaped like Obfuscated-MalMem2022/CIC-MalMem2022:
      Category, <canonical features>, Class
  - phaseK2_cicmalmem2022_compatibility_matrix.csv
      Per-feature mapped/defaulted evidence for compatibility review.
  - phaseK2_cicmalmem2022_summary.json / .md

This is export-only and does not affect RAMDetect verdicts.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ramdetect.reporting.cic_canonical_exporter import (  # noqa: E402
    build_cic_compatible_export,
    load_cic_columns,
)


def _load_session_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    return SimpleNamespace(**d)


def _resolve_session(session_id: str, sessions_dir: Path) -> Path:
    p = sessions_dir / f"{session_id}.json"
    if not p.is_file():
        raise FileNotFoundError(f"Session JSON not found for {session_id}: {p}")
    return p


def _write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session-id", action="append", default=[], help="RAMDetect saved session ID")
    ap.add_argument("--session-json", action="append", default=[], help="Direct path to a saved session JSON")
    ap.add_argument("--sessions-dir", default="ramdetect/ui/data/sessions")
    ap.add_argument("--dataset", default="datasets/Obfuscated-MalMem2022.csv")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sessions_dir = Path(args.sessions_dir)
    dataset = args.dataset if os.path.isfile(args.dataset) else None
    columns = load_cic_columns(dataset)

    session_paths: List[Path] = []
    for sid in args.session_id:
        session_paths.append(_resolve_session(sid, sessions_dir))
    for sj in args.session_json:
        session_paths.append(Path(sj))
    if not session_paths:
        raise SystemExit("Provide at least one --session-id or --session-json")

    wide_rows: List[Dict[str, Any]] = []
    matrix_rows: List[Dict[str, Any]] = []
    summaries: List[Dict[str, Any]] = []

    for sp in session_paths:
        sess = _load_session_json(sp)
        wide, matrix, summary = build_cic_compatible_export(sess, dataset_csv=dataset)
        wide_rows.append(wide)
        matrix_rows.extend(matrix)
        summaries.append(summary)

    rows_path = out / "phaseK2_cicmalmem2022_rows.csv"
    matrix_path = out / "phaseK2_cicmalmem2022_compatibility_matrix.csv"
    summary_json = out / "phaseK2_cicmalmem2022_summary.json"
    summary_md = out / "phaseK2_cicmalmem2022_summary.md"

    _write_csv(rows_path, wide_rows, columns)
    _write_csv(matrix_path, matrix_rows, [
        "session_id", "dump_filename", "cic_feature", "feature_group", "value",
        "status", "defaulted", "ramdetect_source", "compatibility_note",
    ])

    payload = {
        "phase": "K2_CIC_MALMEM2022_FEATURE_COMPATIBILITY_EXPORT",
        "diagnostic_export_only": True,
        "dataset_header_source": dataset or "DEFAULT_CIC_COLUMNS",
        "sessions": summaries,
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
        },
    }
    with open(summary_json, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    lines = [
        "# Phase K2 — CIC-MalMem2022 Feature Compatibility Export",
        "",
        "This export is diagnostic/reporting only. It does not change the RF threshold, FeatureMapper, dataset, session JSON, or verdict logic.",
        "",
        f"Dataset header source: `{payload['dataset_header_source']}`",
        "",
        "| Session | Dump | Dataset features | Mapped | Defaulted | Compatibility | Exported Class |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for s in summaries:
        lines.append(
            f"| {s.get('session_id','')} | {s.get('dump_filename','')} | "
            f"{s.get('dataset_feature_columns',0)} | {s.get('ramdetect_mapped_to_dataset_features',0)} | "
            f"{s.get('defaulted_unmapped_dataset_features',0)} | {s.get('dataset_feature_compatibility_pct',0)}% | "
            f"{s.get('label_exported_from_ml_verdict','Unknown')} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "The wide CSV has the same column shape as CIC-MalMem2022. Columns marked `default_zero_unmapped` in the compatibility matrix are included for schema compatibility only and should not be treated as extracted evidence.",
        "",
        "For the current RAMDetect RF-AE design, the important distinction is: CIC-MalMem2022 has 55 numeric dataset features, while RAMDetect currently maps a CIC54 base vector and appends Autoencoder MSE as the 55th fused RF input.",
    ]
    summary_md.write_text("\n".join(lines), encoding="utf-8")

    print("Phase K2 CIC-MalMem2022 compatibility export complete.")
    print("Output:", out)
    for s in summaries:
        print(
            f"  {s.get('session_id')}: mapped={s.get('ramdetect_mapped_to_dataset_features')}/"
            f"{s.get('dataset_feature_columns')} "
            f"({s.get('dataset_feature_compatibility_pct')}%)"
        )
    print("Rows CSV:", rows_path)
    print("Matrix CSV:", matrix_path)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

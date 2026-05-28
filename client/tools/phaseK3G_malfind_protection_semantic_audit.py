#!/usr/bin/env python3
"""
Phase K3G — malfind.protection semantic export audit
====================================================
Diagnostic-only audit for RAMDetect-native `malfind.protection` semantic
coverage. This validates whether the CIC compatibility exporter can populate
`malfind.protection` from RAMDetect injection/VAD protection evidence.

No RF threshold, FeatureMapper, dataset, session JSON, verdict logic, or ML
input is changed.
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

from ramdetect.features.malfind_protection_semantic_features import (  # noqa: E402
    build_malfind_protection_semantic_feature,
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


def _ml_verdict(sess: Any) -> str:
    ml = getattr(sess, "ml_result", {}) or {}
    if isinstance(ml, dict):
        return str(ml.get("verdict", "unknown"))
    return "unknown"


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

    rows: List[Dict[str, Any]] = []
    sample_rows: List[Dict[str, Any]] = []
    errors: List[str] = []

    for sp in session_paths:
        try:
            sess = _load_session_json(sp)
            values, sources, summary = build_malfind_protection_semantic_feature(sess)
            sid = getattr(sess, "session_id", sp.stem)
            dump = getattr(sess, "dump_filename", "")
            row = {
                "session_id": sid,
                "dump_filename": dump,
                "verdict": _ml_verdict(sess),
                "injections": len(getattr(sess, "injections", []) or []),
                "pe_sections": len(getattr(sess, "pe_sections", []) or []),
                "ready": summary.get("ready", False),
                "quality": summary.get("quality", ""),
                "malfind_protection_value": values.get("malfind.protection", 0.0),
                "source": sources.get("malfind.protection", ""),
                "artifact_rows_considered": summary.get("artifact_rows_considered", 0),
                "explicit_protection_rows": summary.get("explicit_protection_rows", 0),
                "executable_protection_rows": summary.get("executable_protection_rows", 0),
                "writable_executable_protection_rows": summary.get("writable_executable_protection_rows", 0),
                "verdict_effect": "none",
                "ml_pipeline_effect": "none_export_only",
            }
            rows.append(row)
            for sample in summary.get("sample_protection_rows", []) or []:
                if isinstance(sample, dict):
                    sample_rows.append({"session_id": sid, "dump_filename": dump, **sample})
        except Exception as exc:
            errors.append(f"{sp}: {exc}")

    _write_csv(out / "phaseK3G_malfind_protection_session_audit.csv", rows, [
        "session_id", "dump_filename", "verdict", "injections", "pe_sections",
        "ready", "quality", "malfind_protection_value", "source",
        "artifact_rows_considered", "explicit_protection_rows", "executable_protection_rows",
        "writable_executable_protection_rows", "verdict_effect", "ml_pipeline_effect",
    ])
    _write_csv(out / "phaseK3G_malfind_protection_sample_rows.csv", sample_rows, [
        "session_id", "dump_filename", "pid", "tid", "type", "source",
        "protection", "executable", "writable",
    ])

    ready_count = sum(1 for r in rows if str(r.get("ready", "")).lower() == "true" or r.get("ready") is True)
    explicit_count = sum(1 for r in rows if int(r.get("explicit_protection_rows", 0) or 0) > 0)
    nonzero_count = sum(1 for r in rows if float(r.get("malfind_protection_value", 0) or 0) > 0)

    payload = {
        "phase": "K3G_MALFIND_PROTECTION_SEMANTIC_AUDIT",
        "diagnostic_only": True,
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
        },
        "session_count": len(rows),
        "ready_sessions": ready_count,
        "sessions_with_explicit_protection": explicit_count,
        "sessions_with_nonzero_malfind_protection": nonzero_count,
        "expected_k2b_coverage_after_exporter_patch": "36/55 = 65.45% if K2 matrix source is k3g_malfind_protection_semantic:*",
        "errors": errors,
        "rows": rows,
    }
    (out / "phaseK3G_malfind_protection_summary.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    md = []
    md.append("# Phase K3G — malfind.protection Semantic Export Audit\n\n")
    md.append("## Scope\n")
    md.append("This audit is diagnostic/reporting only. It validates RAMDetect-native protection evidence for the CIC-MalMem2022 `malfind.protection` export field. It does not change the RF threshold, FeatureMapper, dataset, session JSON, ML input, or verdict logic.\n\n")
    md.append("## Summary\n")
    md.append(f"- Sessions audited: **{len(rows)}**\n")
    md.append(f"- Ready sessions: **{ready_count}**\n")
    md.append(f"- Sessions with explicit protection rows: **{explicit_count}**\n")
    md.append(f"- Sessions with non-zero `malfind.protection`: **{nonzero_count}**\n")
    md.append("- Expected K2B coverage after rerun: **36/55 (65.45%)** if the K2 matrix source is `k3g_malfind_protection_semantic:*`.\n\n")
    md.append("## Session audit\n")
    md.append("| Session | Dump | Verdict | Injections | Quality | Value | Explicit protection rows |\n")
    md.append("|---|---|---|---:|---|---:|---:|\n")
    for r in rows:
        md.append(f"| {r['session_id']} | {r['dump_filename']} | {r['verdict']} | {r['injections']} | {r['quality']} | {r['malfind_protection_value']} | {r['explicit_protection_rows']} |\n")
    md.append("\n## Recommendation\n")
    md.append("Proceed to rerun K2 and K2B. Treat `malfind.protection` as semantic/export coverage only. It should not be mapped into the RF-AE decision path unless the model is retrained and explicitly designed to consume this field.\n")
    (out / "phaseK3G_malfind_protection_report.md").write_text("".join(md), encoding="utf-8")

    print("Phase K3G malfind.protection semantic audit complete.")
    print("Output:", out)
    print(f"Ready sessions: {ready_count}/{len(rows)}")
    print("Expected K2B semantic coverage after rerun: 36/55 (65.45%)")
    if errors:
        print("Errors:")
        for e in errors:
            print("  -", e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

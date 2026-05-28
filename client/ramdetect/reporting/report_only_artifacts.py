"""
ramdetect/reporting/report_only_artifacts.py
────────────────────────────────────────────
Report-only forensic artifact helpers.

These helpers identify ransomware-style process artifacts for analyst reporting
only. They must not change the ML verdict, RF threshold, FeatureMapper, dataset,
malfind mapping, or session classification result.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Tuple


RANSOMWARE_TOKENS = (
    "infinitycrypt",
    "locky",
    "wannacry",
    "wcry",
    "ryuk",
    "cerber",
    "teslacrypt",
    "cryptolocker",
    "cryptowall",
    "ransom",
)

USER_WRITABLE_TOKENS = (
    "\\users\\",
    "/users/",
    "\\downloads\\",
    "/downloads/",
    "\\desktop\\",
    "/desktop/",
    "\\appdata\\",
    "/appdata/",
    "\\temp\\",
    "/temp/",
)

SYSTEM_PATH_TOKENS = (
    "\\windows\\",
    "/windows/",
    "\\program files\\",
    "/program files/",
    "\\program files (x86)\\",
    "/program files (x86)/",
)


def _pick(d: Dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = d.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _pid_key(value: Any) -> str:
    try:
        # Handles sometimes store PIDs as floats from CSV/JSON conversions.
        return str(int(float(value)))
    except Exception:
        return str(value or "").strip()


def _clean_text(value: Any, maxlen: int | None = None) -> str:
    if value is None:
        return ""
    s = str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = " ".join(s.split())
    if maxlen and len(s) > maxlen:
        return s[: maxlen - 1].rstrip() + "…"
    return s


def _flatten_processes(processes: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for proc in processes or []:
        if not isinstance(proc, dict):
            continue
        out.append(proc)
        children = proc.get("children") or []
        if isinstance(children, list):
            out.extend(_flatten_processes(children))
    return out


def _handle_counts_by_pid(handles: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    counts: Dict[str, Dict[str, int]] = {}
    for h in handles or []:
        if not isinstance(h, dict):
            continue
        pid = _pid_key(_pick(h, "pid", "PID", "process_id", "UniqueProcessId", default=""))
        if not pid:
            continue
        typ = _pick(h, "type", "Type", "object_type", "ObjectType", default="").lower()
        name = _pick(h, "name", "Name", "object_name", "ObjectName", default="").lower()
        row = counts.setdefault(pid, {"file": 0, "key": 0})
        if "file" in typ:
            row["file"] += 1
        if "key" in typ or "registry" in typ or "\\registry\\" in name:
            row["key"] += 1
    return counts


def _path_is_user_writable(path: str) -> bool:
    low = path.lower().replace("/", "\\")
    if not low:
        return False
    return ("\\users\\" in low and any(t in low for t in ("\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\"))) or low.startswith("c:\\temp\\")


def _path_is_non_system(path: str) -> bool:
    low = path.lower().replace("/", "\\")
    if not low:
        return True
    return not any(token in low for token in SYSTEM_PATH_TOKENS)


def _has_ransomware_token(name: str, path: str) -> bool:
    hay = f"{name} {path}".lower()
    return any(token in hay for token in RANSOMWARE_TOKENS)


def _derive_process_path(proc: Dict[str, Any]) -> str:
    # Common names across RAMDetect parser outputs and diagnostics.
    path = _pick(
        proc,
        "path", "image_path", "full_path", "file_path", "process_path", "ImagePath",
        "FileName", "filename", "command_line", "CommandLine", default="",
    )
    if path:
        return path
    # Some rows only carry the executable name.
    return _pick(proc, "image_name", "name", "process_name", "ImageFileName", default="")


def _load_j3_v2_fallback(session) -> List[Dict[str, Any]]:
    """Best-effort fallback for sessions generated before this helper existed."""
    try:
        dump = str(getattr(session, "dump_filename", "") or "").lower()
        if not dump:
            return []
        case = ""
        if "locky" in dump:
            case = "Locky"
        elif "infinitycrypt" in dump:
            case = "InfinityCrypt"
        else:
            return []

        # Search from current working directory first; this matches the project root.
        candidates = [
            os.path.join(os.getcwd(), "models", "experiments", "EXP_J3_REPORT_ONLY_RANSOMWARE_ARTIFACTS_V2", "phaseJ3_report_only_ransomware_artifacts.json"),
            os.path.join(os.getcwd(), "models", "experiments", "EXP_J3_REPORT_ONLY_RANSOMWARE_ARTIFACTS", "phaseJ3_report_only_ransomware_artifacts.json"),
        ]
        for path in candidates:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            rows = payload.get("artifacts", []) or []
            result = []
            for row in rows:
                if str(row.get("case", "")) != case:
                    continue
                item = dict(row)
                item.setdefault("ml_mapping", "disabled_report_only")
                item.setdefault("verdict_effect", "none")
                item.setdefault("report_only_alert", "ransomware_process_artifact")
                result.append(item)
            return result
    except Exception:
        return []
    return []


def collect_report_only_ransomware_artifacts(session) -> List[Dict[str, Any]]:
    """
    Return report-only ransomware process artifacts.

    This function is intentionally conservative:
    - Requires a ransomware-like process/path token.
    - Requires a user-writable location, such as Downloads/AppData/Desktop/Temp.
    - Requires non-system location context.
    - Requires both file and registry-handle activity.

    The returned artifacts are for PDF/JSON/CSV reporting only. They must not be
    mapped into CIC54 features or used as verdict overrides.
    """
    existing = getattr(session, "report_only_ransomware_artifacts", None)
    if isinstance(existing, list) and existing:
        return existing

    processes = _flatten_processes(getattr(session, "processes", []) or [])
    handles = getattr(session, "handles", []) or []
    handle_counts = _handle_counts_by_pid(handles)
    ml = getattr(session, "ml_result", {}) or {}
    rf_score = ml.get("rf_score", ml.get("confidence", 0))
    verdict = ml.get("verdict", "unknown")

    artifacts: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()

    for proc in processes:
        pid = _pid_key(_pick(proc, "pid", "PID", "UniqueProcessId", "process_id", default=""))
        name = _pick(proc, "image_name", "name", "process_name", "ImageFileName", default="")
        path = _derive_process_path(proc)
        if not (pid or name or path):
            continue

        if not _has_ransomware_token(name, path):
            continue
        if not _path_is_user_writable(path):
            continue
        if not _path_is_non_system(path):
            continue

        hc = handle_counts.get(pid, {"file": 0, "key": 0})
        # Prefer explicit per-process counts if the parser/audit already stored them.
        try:
            file_handles = float(proc.get("file_handles", proc.get("nfile", hc.get("file", 0))) or 0)
        except Exception:
            file_handles = float(hc.get("file", 0))
        try:
            key_handles = float(proc.get("key_handles", proc.get("nkey", hc.get("key", 0))) or 0)
        except Exception:
            key_handles = float(hc.get("key", 0))

        # J3/J1 used medium file-handle activity and high registry-key handle activity.
        if file_handles < 20 or key_handles < 25:
            continue

        ident = (pid, path.lower())
        if ident in seen:
            continue
        seen.add(ident)

        reasons = (
            "ransomware/process-name token; user-writable path; non-system or unresolved path; "
            f"file + registry handle activity (file={int(file_handles)}, key={int(key_handles)}); "
            "strict report-only policy"
        )
        artifacts.append({
            "pid": pid,
            "process_name": _clean_text(name) or os.path.basename(path),
            "path": _clean_text(path),
            "j1_score": proc.get("risk_score_diagnostic", proc.get("risk_score", 9)),
            "report_confidence": 95,
            "report_only_alert": "ransomware_process_artifact",
            "reasons": reasons,
            "flags": "high_registry_key_handle_count;medium_file_handle_count;non_system_path_or_unresolved_path;ransomware_path_token;user_temp_or_appdata_path",
            "file_handles": file_handles,
            "key_handles": key_handles,
            "ml_mapping": "disabled_report_only",
            "verdict_effect": "none",
            "rf_score": rf_score,
            "verdict": verdict,
        })

    if not artifacts:
        artifacts = _load_j3_v2_fallback(session)

    # Save on the session object for downstream reporters in the same export call.
    try:
        session.report_only_ransomware_artifacts = artifacts
    except Exception:
        pass
    return artifacts


def summarize_report_only_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not artifacts:
        return {
            "count": 0,
            "max_confidence": 0,
            "processes": [],
            "verdict_effect": "none",
            "ml_mapping": "disabled_report_only",
        }
    processes = []
    for a in artifacts:
        name = _clean_text(a.get("process_name") or os.path.basename(str(a.get("path", ""))))
        if name and name not in processes:
            processes.append(name)
    max_conf = max(float(a.get("report_confidence", 0) or 0) for a in artifacts)
    return {
        "count": len(artifacts),
        "max_confidence": max_conf,
        "processes": processes,
        "verdict_effect": "none",
        "ml_mapping": "disabled_report_only",
    }

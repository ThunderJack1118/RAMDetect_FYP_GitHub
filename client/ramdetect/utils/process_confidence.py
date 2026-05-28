"""
ramdetect.utils.process_confidence
----------------------------------
Phase J10 diagnostic-only process confidence annotation.

This module labels weak/stale EPROCESS candidates for analyst display and
reporting. It does not remove processes, does not modify ML features, does not
change the RF threshold, and does not override the final verdict.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


_PLACEHOLDER_VALUES = {"", "-", "—", "?", "n/a", "na", "none", "null", "unknown"}


_SUSPICIOUS_TEXT_TOKENS = (
    "contentwindow",
    "rgetarrayindex",
    "ch-ua-platform",
    "orm-urlencoded",
    "collapsebutton",
    "storageprivate",
    "commandpalette",
    "secure-3psid",
    "shockwave-flash",
)


_SYSTEM_NAMES = {
    "system",
    "registry",
    "memcompression",
    "idle",
}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, str):
            s = value.strip()
            if not s or s.lower() in _PLACEHOLDER_VALUES:
                return default
            return int(s, 16) if s.lower().startswith("0x") else int(float(s))
        return int(value)
    except Exception:
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"true", "1", "yes", "y"}:
        return True
    if s in {"false", "0", "no", "n"}:
        return False
    return default


def _first(obj: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in obj and obj.get(key) not in (None, ""):
            return obj.get(key)
    return default


def _name(proc: Dict[str, Any]) -> str:
    return str(_first(proc, "image_name", "name", "process_name", "ImageFileName", default="") or "")


def _path(proc: Dict[str, Any]) -> str:
    return str(_first(proc, "path", "exe_path", "image_path", "full_path", "command_line", default="") or "")


def _anomalies(proc: Dict[str, Any]) -> List[str]:
    raw = proc.get("anomalies") or []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if raw in (None, ""):
        return []
    return [str(raw)]


def _valid_path(path: str) -> bool:
    p = str(path or "").strip()
    if not p or p.lower() in _PLACEHOLDER_VALUES:
        return False
    # Accept common Windows paths and kernel-style \SystemRoot paths.
    return bool(re.match(r"^[A-Za-z]:\\", p) or p.lower().startswith("\\systemroot\\"))


def _create_time_present(proc: Dict[str, Any]) -> bool:
    v = _first(proc, "create_time", "CreateTime", "created", default="")
    s = str(v or "").strip().lower()
    if s in _PLACEHOLDER_VALUES:
        return False
    if "1601" in s or "1970" in s or s.startswith("0"):
        return False
    return True


def _peb_valid(proc: Dict[str, Any]) -> bool:
    if "peb_is_valid" in proc:
        return _as_bool(proc.get("peb_is_valid"), False)
    peb = _as_int(_first(proc, "peb", "Peb", "PEB", default=0), 0)
    return peb not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) and peb > 0x10000


def _name_is_malformed(name: str) -> bool:
    raw = str(name or "")
    stripped = raw.strip()
    if not stripped:
        return True
    low = stripped.lower()
    if any(tok in low for tok in _SUSPICIOUS_TEXT_TOKENS):
        return True
    if raw != stripped:
        return True
    if any(ord(ch) < 32 for ch in raw):
        return True
    if len(stripped) > 64:
        return True
    # Normal system names may not end in .exe.
    if low in _SYSTEM_NAMES:
        return False
    # Most carved Windows process names should be short basename-style names.
    if "\\" in stripped or "/" in stripped:
        return True
    # Embedded spaces are often carved string fragments; allow none for basename.
    if " " in stripped:
        return True
    return False


def _confidence_category(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _build_pid_counts(rows: Iterable[Dict[str, Any]]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        pid = _as_int(_first(row, "pid", "PID", "process_id", "UniqueProcessId", default=0), 0)
        if pid > 0:
            out[pid] = out.get(pid, 0) + 1
    return out


def classify_process(proc: Dict[str, Any], *, thread_count: int = 0, dll_count: int = 0, handle_count: int = 0) -> Dict[str, Any]:
    """Return confidence metadata for a process dict without mutating it."""
    name = _name(proc)
    path = _path(proc)
    anoms = _anomalies(proc)
    anom_text = " | ".join(anoms).lower()

    pid = _as_int(_first(proc, "pid", "PID", "UniqueProcessId", "process_id", default=0), 0)
    ppid = _as_int(_first(proc, "ppid", "PPID", "InheritedFromUniqueProcessId", default=0), 0)
    active_threads = _as_int(_first(proc, "active_threads", "ActiveThreads", "threads", "thread_count", default=0), 0)
    ethread_threads = _as_int(proc.get("ethread_thread_count"), 0)
    resolved_threads = max(active_threads, ethread_threads, int(thread_count or 0))
    resolved_dlls = int(dll_count or 0)
    resolved_handles = max(_as_int(proc.get("handle_owner_count"), 0), int(handle_count or 0))

    path_ok = _valid_path(path)
    create_ok = _create_time_present(proc)
    peb_ok = _peb_valid(proc)
    found_pool = _as_bool(proc.get("found_by_pool"), False) or _as_bool(proc.get("in_eprocess_pool"), False)
    found_links_raw = proc.get("found_by_links", proc.get("in_pslist", None))
    found_links = _as_bool(found_links_raw, False)
    malformed_name = _name_is_malformed(name)
    core_system_process = name.strip().lower().replace(".exe", "") in _SYSTEM_NAMES or pid in (0, 4)

    score = 0
    reasons: List[str] = []

    if core_system_process:
        score += 55
        reasons.append("known core/system process baseline")

    if found_pool:
        score += 10; reasons.append("EPROCESS pool evidence present")
    else:
        reasons.append("EPROCESS pool evidence missing/unknown")

    if found_links:
        score += 10; reasons.append("linked-list/pslist evidence present")
    else:
        reasons.append("linked-list/pslist evidence missing/unknown")

    if resolved_threads > 0:
        score += 30; reasons.append(f"thread evidence present ({resolved_threads})")
    elif core_system_process:
        reasons.append("zero recovered threads but acceptable for core/system baseline row")
    else:
        score -= 20; reasons.append("zero recovered threads")

    if resolved_dlls > 0:
        score += 20; reasons.append(f"DLL/LDR evidence present ({resolved_dlls})")
    elif core_system_process:
        reasons.append("no DLL/LDR rows recovered but acceptable for core/system process")
    else:
        score -= 10; reasons.append("no DLL/LDR rows recovered")

    if resolved_handles > 0:
        score += 15; reasons.append(f"handle-owner evidence present ({resolved_handles})")
    elif core_system_process:
        reasons.append("no handle-owner rows recovered but acceptable for core/system process")
    else:
        score -= 8; reasons.append("no handle-owner rows recovered")

    if path_ok:
        score += 15; reasons.append("resolved executable path present")
    elif core_system_process:
        reasons.append("resolved executable path missing but acceptable for core/system process")
    else:
        score -= 12; reasons.append("resolved executable path missing")

    if create_ok:
        score += 8; reasons.append("create time present")
    elif core_system_process:
        reasons.append("create time missing/zero but acceptable for core/system process")
    else:
        score -= 10; reasons.append("create time missing/zero")

    if peb_ok:
        score += 8; reasons.append("PEB value appears usable")
    elif core_system_process:
        reasons.append("PEB value missing/invalid but acceptable for core/system process")
    else:
        score -= 15; reasons.append("PEB value missing/invalid")

    if malformed_name:
        score -= 18; reasons.append("process name appears malformed or string-fragment-like")

    if ppid < 0 or ppid > 65535:
        score -= 12; reasons.append("parent PID is outside normal range")

    if "orphan" in anom_text and not path_ok and resolved_threads == 0:
        score -= 12; reasons.append("orphan + missing path + zero threads pattern")

    if "zero createtime" in anom_text or "possible ghost" in anom_text:
        score -= 16; reasons.append("ghost/stale CreateTime indicator")

    if "possible hollowing" in anom_text and resolved_threads == 0 and not path_ok:
        score -= 10; reasons.append("weak hollowing indicator only; no supporting live evidence")

    # Active thread ownership is strong evidence that the candidate is not a
    # purely stale pool string. Keep such rows at least medium-confidence unless
    # the name itself is malformed/string-fragment-like.
    if resolved_threads >= 3 and not malformed_name:
        score = max(score, 45)

    score = max(0, min(100, int(score)))
    category = _confidence_category(score)

    low_conf = bool(
        category == "low"
        or (resolved_threads == 0 and not path_ok and resolved_dlls == 0 and (resolved_handles == 0 or malformed_name or not peb_ok))
    )

    if core_system_process:
        low_conf = False

    if low_conf and malformed_name:
        low_cat = "malformed_or_string_fragment"
    elif low_conf and ("ghost" in anom_text or not create_ok):
        low_cat = "stale_or_ghost_candidate"
    elif low_conf:
        low_cat = "weak_eprocess_candidate"
    else:
        low_cat = "none"

    label = {
        "high": "High-confidence process",
        "medium": "Medium-confidence process",
        "low": "Low-confidence / stale candidate",
    }[category]

    if low_conf:
        note = (
            "This process candidate was recovered from EPROCESS-like memory evidence, "
            "but supporting evidence is weak. It is preserved for forensic review and "
            "should be treated as a low-confidence/stale candidate unless corroborated "
            "by threads, DLLs, handles, path, or external logs."
        )
    elif category == "medium":
        note = (
            "This process has partial supporting evidence. Review alongside threads, "
            "DLLs, handles, parent process context, and disk/EDR evidence."
        )
    else:
        note = "This process has multiple supporting parser evidence sources."

    return {
        "process_confidence": category,
        "process_confidence_score": score,
        "process_confidence_label": label,
        "process_confidence_reason": "; ".join(reasons),
        "low_confidence_candidate": low_conf,
        "low_confidence_category": low_cat,
        "j10_display_note": note,
        "j10_thread_count_resolved": resolved_threads,
        "j10_dll_count_resolved": resolved_dlls,
        "j10_handle_count_resolved": resolved_handles,
    }


def annotate_session_processes(session: Any, *, export: bool = True) -> Dict[str, Any]:
    """Annotate session.processes in place and optionally export a J10 audit."""
    processes = list(getattr(session, "processes", []) or [])
    threads = list(getattr(session, "threads", []) or [])
    dlls = list(getattr(session, "dlls", []) or [])
    handles = list(getattr(session, "handles", []) or [])

    thread_counts = _build_pid_counts(threads)
    dll_counts = _build_pid_counts(dlls)
    handle_counts = _build_pid_counts(handles)

    rows: List[Dict[str, Any]] = []
    counts = {"high": 0, "medium": 0, "low": 0}

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = _as_int(_first(proc, "pid", "PID", "UniqueProcessId", "process_id", default=0), 0)
        meta = classify_process(
            proc,
            thread_count=thread_counts.get(pid, 0),
            dll_count=dll_counts.get(pid, 0),
            handle_count=handle_counts.get(pid, 0),
        )
        proc.update(meta)
        counts[meta["process_confidence"]] = counts.get(meta["process_confidence"], 0) + 1
        rows.append({
            "pid": pid,
            "ppid": _as_int(_first(proc, "ppid", "PPID", default=0), 0),
            "process_name": _name(proc),
            "status": str(proc.get("status", "")),
            "confidence": meta["process_confidence"],
            "confidence_score": meta["process_confidence_score"],
            "low_confidence_candidate": meta["low_confidence_candidate"],
            "low_confidence_category": meta["low_confidence_category"],
            "threads": meta["j10_thread_count_resolved"],
            "dlls": meta["j10_dll_count_resolved"],
            "handles": meta["j10_handle_count_resolved"],
            "path_present": _valid_path(_path(proc)),
            "reasons": meta["process_confidence_reason"],
        })

    summary = {
        "process_count": len(processes),
        "confidence_counts": counts,
        "low_confidence_count": counts.get("low", 0),
        "rules_preserved": {
            "diagnostic_only": True,
            "ml_threshold_changed": False,
            "feature_mapper_changed": False,
            "rf_model_changed": False,
            "verdict_logic_changed": False,
            "processes_removed": False,
        },
    }

    try:
        setattr(session, "process_confidence_summary", summary)
    except Exception:
        pass

    if export:
        try:
            sid = (
                getattr(session, "session_id", None)
                or getattr(session, "id", None)
                or getattr(session, "scan_id", None)
                or "unknown_session"
            )
            out_dir = Path("output") / "feature_debug" / str(sid)
            out_dir.mkdir(parents=True, exist_ok=True)
            csv_path = out_dir / "process_confidence_audit.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                fieldnames = list(rows[0].keys()) if rows else ["pid", "process_name", "confidence"]
                w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
                w.writeheader()
                w.writerows(rows)
            (out_dir / "process_confidence_audit.summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            summary["audit_csv"] = str(csv_path)
        except Exception as ex:
            summary["export_error"] = str(ex)

    return summary


def apply_confidence_to_findings(session: Any) -> List[Dict[str, Any]]:
    """Downgrade low-confidence process findings for display/reporting only."""
    findings = list(getattr(session, "findings", []) or [])
    procs = list(getattr(session, "processes", []) or [])
    by_pid: Dict[int, Dict[str, Any]] = {}
    for p in procs:
        if isinstance(p, dict):
            pid = _as_int(_first(p, "pid", "PID", "UniqueProcessId", "process_id", default=0), 0)
            if pid:
                by_pid[pid] = p

    out: List[Dict[str, Any]] = []
    pid_re = re.compile(r"PID\s+(\d+)", re.IGNORECASE)
    for f in findings:
        if not isinstance(f, dict):
            out.append(f)
            continue
        item = dict(f)
        cat = str(item.get("category", "")).lower()
        desc = str(item.get("description", ""))
        if cat == "process":
            m = pid_re.search(desc)
            pid = _as_int(m.group(1), 0) if m else 0
            proc = by_pid.get(pid)
            if proc and proc.get("low_confidence_candidate"):
                item["severity"] = "low"
                if "Low-confidence" not in desc:
                    item["description"] = (
                        desc + "\n   J10 note: Low-confidence/stale process candidate; preserved for advanced review. "
                        "Corroborate with threads, DLLs, handles, disk path, and endpoint logs before treating as confirmed malicious."
                    )
                item["j10_low_confidence_finding"] = True
        out.append(item)
    try:
        session.findings = out
    except Exception:
        pass
    return out


def confidence_label(proc: Dict[str, Any]) -> str:
    if not isinstance(proc, dict):
        return "Unknown"
    return str(proc.get("process_confidence_label") or proc.get("process_confidence") or "Not assessed")


def confidence_tooltip(proc: Dict[str, Any]) -> str:
    if not isinstance(proc, dict):
        return "Process confidence was not assessed."
    return (
        f"{proc.get('process_confidence_label', 'Process confidence')}\n\n"
        f"Score: {proc.get('process_confidence_score', 'N/A')}/100\n"
        f"Reason: {proc.get('process_confidence_reason', 'N/A')}\n\n"
        f"{proc.get('j10_display_note', '')}"
    ).strip()

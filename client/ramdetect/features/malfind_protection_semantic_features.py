"""
ramdetect/features/malfind_protection_semantic_features.py
----------------------------------------------------------
Phase K3G: RAMDetect-native semantic derivation for the CIC-MalMem2022
`malfind.protection` compatibility/export field.

Important: this module is export/traceability only. It does not alter the
RF-AE model input, FeatureMapper, threshold, dataset, verdict logic, or session
artifacts. It only gives the CIC compatibility exporter a documented source for
`malfind.protection` when RAMDetect has parser evidence describing memory
protection/permission for malfind-equivalent injection artifacts.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple


_PROT_KEYS = (
    "protection", "vad_protection", "matched_vad_protection", "page_protection",
    "memory_protection", "protect", "prot", "permissions", "permission",
    "vad_permissions", "flags",
)

# Matches strings produced by RAMDetect detector details, for example:
#   "(size=0x1000, prot=PAGE_EXECUTE_READWRITE)"
#   "(size=0x1000, protection=EXECUTE_READ)"
_PROT_RE = re.compile(r"\b(?:prot|protection|permissions?)\s*[:=]\s*([^\)\],;]+)", re.I)

_EXEC_TOKENS = ("EXECUTE", "PAGE_EXECUTE", "_X", " RX", "RWX", "WX", "WCX")
_WRITE_TOKENS = ("WRITE", "WRITECOPY", "READWRITE", "RW", "RWX", "WX", "WCX")


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return default
            return int(s, 16) if s.lower().startswith("0x") else int(float(s))
        return int(value)
    except Exception:
        return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(x) for x in value)
    return str(value)


def _extract_protection_text(row: Dict[str, Any]) -> str:
    """Return explicit protection/permission text from an artifact row if present."""
    parts: List[str] = []
    for k in _PROT_KEYS:
        v = row.get(k)
        if v not in (None, ""):
            parts.append(_text(v))

    # Fallback: parse human-readable detector details/status strings.
    for k in ("details", "status_reason", "description", "reason", "anomalies"):
        txt = _text(row.get(k))
        if not txt:
            continue
        m = _PROT_RE.search(txt)
        if m:
            parts.append(m.group(1).strip())

    # Keep compact, deterministic representation.
    cleaned = []
    for p in parts:
        p = p.replace("'", "").replace('"', "").strip()
        if p and p not in cleaned:
            cleaned.append(p)
    return "; ".join(cleaned)


def _is_executable(protection: Any) -> bool:
    if isinstance(protection, int):
        return bool(protection & (0x10 | 0x20 | 0x40 | 0x80))
    s = f" {_text(protection).upper()} "
    return ("EXECUTE" in s) or (" RWX" in s) or (" RX" in s) or (" WX" in s) or (" WCX" in s)


def _is_writable(protection: Any) -> bool:
    if isinstance(protection, int):
        return bool(protection & (0x04 | 0x40 | 0x80))
    s = f" {_text(protection).upper()} "
    return any(tok in s for tok in _WRITE_TOKENS)


def _is_injection_like(row: Dict[str, Any]) -> bool:
    """Only use rows that represent malfind-equivalent RAMDetect evidence."""
    text = " ".join(
        _text(row.get(k)) for k in (
            "source", "type", "details", "status_reason", "anomaly", "anomalies",
            "report_only_alert",
        )
    ).lower()
    if row.get("is_suspicious") is True:
        return True
    return any(tok in text for tok in (
        "malfind", "injection", "private executable", "private rwx",
        "write-execute", "mz header", "pe in anonymous", "kernel start",
        "thread start in private",
    ))


def _iter_candidate_rows(session: Any) -> Iterable[Dict[str, Any]]:
    # `session.injections` is the primary source because it feeds malfind count
    # features. PE/VAD rows are secondary because some detector paths tag them
    # with anomaly/status_reason but may not duplicate every field into injection rows.
    for attr in ("injections", "pe_sections"):
        rows = _get(session, attr, []) or []
        if isinstance(rows, list):
            for r in rows:
                if isinstance(r, dict):
                    yield r


def _cic_protection_score(protection_text: str) -> int:
    """Return a CIC-compatible numeric protection score for one artifact.

    CIC-MalMem2022 stores `malfind.protection` as a numeric aggregate rather
    than a raw protection string. In the public dataset, the value commonly
    scales with the number of malfind rows. RAMDetect uses a conservative
    compatibility encoding: each confirmed executable protection observation
    contributes 6. Non-executable or missing protection contributes 0. This
    keeps the field numeric and traceable without pretending to be a direct
    Volatility string clone.
    """
    if not protection_text:
        return 0
    return 6 if _is_executable(protection_text) else 0


def build_malfind_protection_semantic_feature(session: Any) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, Any]]:
    """Build `malfind.protection` for CIC compatibility export.

    Returns:
        values: {"malfind.protection": numeric_score}
        sources: {"malfind.protection": "k3g_malfind_protection_semantic:<quality>"}
        summary: diagnostic metadata
    """
    artifact_rows = []
    explicit_protection_rows = []
    executable_rows = []
    writable_executable_rows = []

    seen = set()
    for row in _iter_candidate_rows(session):
        if not _is_injection_like(row):
            continue
        # Deduplicate roughly by pid/type/details/start to avoid double-counting
        # if the same artifact appears in both injections and PE section rows.
        key = (
            str(row.get("pid", "")),
            str(row.get("tid", "")),
            str(row.get("type", row.get("section", ""))),
            str(row.get("start", row.get("base_address", row.get("address", "")))),
            str(row.get("details", row.get("status_reason", "")))[:120],
        )
        if key in seen:
            continue
        seen.add(key)

        prot = _extract_protection_text(row)
        artifact_rows.append({"row": row, "protection": prot})
        if prot:
            explicit_protection_rows.append({"row": row, "protection": prot})
            if _is_executable(prot):
                executable_rows.append({"row": row, "protection": prot})
                if _is_writable(prot):
                    writable_executable_rows.append({"row": row, "protection": prot})

    score = sum(_cic_protection_score(r["protection"]) for r in explicit_protection_rows)

    # A zero score can still be valid when no reliable protection observation is
    # present. The matrix source remains K3G so K2B can distinguish it from an
    # unsupported/defaulted placeholder.
    ready = True
    quality = "validated_explicit_protection" if explicit_protection_rows else "validated_no_explicit_protection_observed"

    sample = []
    for item in explicit_protection_rows[:10]:
        r = item["row"]
        sample.append({
            "pid": r.get("pid"),
            "tid": r.get("tid"),
            "type": r.get("type", r.get("section", "")),
            "source": r.get("source", ""),
            "protection": item["protection"],
            "executable": _is_executable(item["protection"]),
            "writable": _is_writable(item["protection"]),
        })

    summary = {
        "ready": ready,
        "quality": quality,
        "artifact_rows_considered": len(artifact_rows),
        "explicit_protection_rows": len(explicit_protection_rows),
        "executable_protection_rows": len(executable_rows),
        "writable_executable_protection_rows": len(writable_executable_rows),
        "malfind_protection_score": score,
        "encoding": "6 * explicit executable malfind-equivalent protection observations; 0 when no explicit protection is observed",
        "sample_protection_rows": sample,
        "verdict_effect": "none",
        "ml_pipeline_effect": "none_export_only",
    }
    return (
        {"malfind.protection": float(score)},
        {"malfind.protection": f"k3g_malfind_protection_semantic:{quality}"},
        summary,
    )

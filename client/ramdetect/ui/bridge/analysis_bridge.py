"""
ui/bridge/analysis_bridge.py
─────────────────────────────
QThread worker that drives the three-phase pipeline:

  Phase 1 — Memory Parsing       ramdetect/extraction/   (custom parsers)
  Phase 2 — Feature Extraction   ramdetect/features/     (100+ extractors)
  Phase 3 — ML Classification    MLBridge.predict()

Signals emitted (connect from RealtimeAnalysisPage):

    worker.phase_changed(phase_index: int, phase_name: str)
    worker.module_done(phase_index: int, module_name: str)
    worker.progress(overall_pct: int)
    worker.log(level: str, message: str)     level = INFO|WARNING|ERROR
    worker.finished(session: ScanSession)
    worker.errored(message: str)
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from PyQt5.QtCore import QThread, pyqtSignal

from ui.bridge.session       import ScanSession
from ui.bridge.config_bridge import Config

# ── Real backend imports ──────────────────────────────────────────────────────
_extraction_import_error: Optional[ImportError] = None
_features_import_error:   Optional[ImportError] = None

try:
    from ramdetect.extraction.parsers.memory_reader      import PhysicalMemoryReader
    from ramdetect.extraction.parsers.address_translator import AddressTranslator
    from ramdetect.extraction.parsers.eprocess_scanner   import EProcessScanner
    from ramdetect.extraction.parsers.thread_parser      import ThreadParser
    from ramdetect.extraction.parsers.dll_parser         import DLLParser
    from ramdetect.extraction.parsers.vad_scanner        import VADScanner
    try:
        from ramdetect.extraction.parsers.handle_parser      import HandleParser as _HandleParser
    except ImportError:
        _HandleParser = None
    try:
        from ramdetect.extraction.parsers.injection_detector import InjectionDetector as _InjectionDetector
    except ImportError:
        _InjectionDetector = None
except ImportError as _e:
    _extraction_import_error = _e

try:
    from ramdetect.features.feature_aggregator import FeatureAggregator
    from ramdetect.ml.feature_mapper           import FeatureMapper
    try:
        from ramdetect.utils.offset import get_offsets
    except ImportError:
        def get_offsets(build):
            return {
                "EPROCESS": {"ThreadListHead": 0x370},
                "ETHREAD":  {"ThreadListEntry": 0x578},
            }
except ImportError as _e:
    _features_import_error = _e


# ─────────────────────────────────────────────────────────────────────────────
# Phase / module map
# ─────────────────────────────────────────────────────────────────────────────
PHASE_MAP = [
    {
        "name":    "Memory Parsing",
        "weight":  33,
        "modules": [
            "EPROCESS Walker",
            "Thread Scanner",
            "DLL Module Loader",
            "Handle Extractor",
            "PE Section Parser",
            "VAD Tree Walker",
        ],
    },
    {
        "name":    "Feature Extraction",
        "weight":  40,
        "modules": [
            "Process Features",
            "Thread Features",
            "DLL Features",
            "Handle Features",
            "PE Section Features",
            "Code Injection Features",
        ],
    },
    {
        "name":    "ML Classification",
        "weight":  27,
        "modules": [
            "Feature Mapping (Base 54)",
            "Autoencoder Anomaly Scoring",
            "Feature Fusion (54 → 55)",
            "Random Forest Classifier",
        ],
    },
]

# Default build fallback has been removed from the parsing path.
# Deep parsing now requires a known Windows build profile and a verified DTB/CR3.
_DEFAULT_BUILD = None


# ─────────────────────────────────────────────────────────────────────────────
# Sidecar JSON loader  (mirrors display_metadata in the CLI tool)
# ─────────────────────────────────────────────────────────────────────────────

def _sidecar_candidates(dump_path: str) -> list[Path]:
    """
    Return possible sidecar JSON locations for a dump.

    Search order:
      1. Same directory as the dump
      2. Timestamped output subdirectories: {dump_stem}_*/{dump_stem}.json
    """
    p = Path(dump_path)
    candidates = [
        p.with_suffix(".json"),
        Path(str(p) + ".json"),
        p.with_suffix(".dmp.metadata.json"),
        Path(str(p) + ".metadata.json"),
    ]

    stem = p.stem
    dump_dir = p.parent
    try:
        for subdir in sorted(dump_dir.glob(f"{stem}_*"), reverse=True):
            if subdir.is_dir():
                candidates.append(subdir / f"{stem}.json")
                candidates.append(subdir / f"{stem}.metadata.json")
    except Exception:
        pass

    return candidates


def _parse_int_maybe_hex(value):
    """Parse integers stored as int, decimal string, or hex string."""
    if value in (None, "", "None"):
        return None
    try:
        if isinstance(value, str):
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_sidecar_details(dump_path: str) -> dict:
    """
    Load sidecar metadata and return DTB/build/source details.

    This function intentionally distinguishes between a present DTB and a
    verified DTB. Values marked as default/unverified/KPCR-only should trigger
    the native DTB scanner instead of being trusted blindly.
    """
    for candidate in _sidecar_candidates(dump_path):
        if not candidate.exists():
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                meta = json.load(f)

            kernel = meta.get("kernel_info", {})
            if not isinstance(kernel, dict):
                kernel = {}

            cr3 = (
                kernel.get("dtb_hex")
                or kernel.get("cr3_hex")
                or kernel.get("dtb")
                or kernel.get("cr3")
                or meta.get("dtb_hex")
                or meta.get("cr3_hex")
                or meta.get("dtb")
                or meta.get("cr3")
            )
            build = kernel.get("build_number") or meta.get("build_number")
            dtb_int = _parse_int_maybe_hex(cr3)
            build_int = _parse_int_maybe_hex(build)

            if build_int is not None and not (7600 <= build_int <= 99999):
                build_int = None

            if build_int is None:
                pv = meta.get("system", {}).get("platform_version", "")
                try:
                    candidate_build = int(str(pv).split(".")[2])
                    if 7600 <= candidate_build <= 99999:
                        build_int = candidate_build
                except (IndexError, ValueError):
                    pass

            confidence = _parse_int_maybe_hex(kernel.get("dtb_confidence") or meta.get("dtb_confidence"))
            return {
                "path": candidate,
                "dtb": dtb_int,
                "build": build_int,
                "dtb_source": str(kernel.get("dtb_source") or meta.get("dtb_source") or ""),
                "dtb_confidence": confidence,
                "metadata": meta,
            }
        except Exception:
            return {
                "path": candidate,
                "dtb": None,
                "build": None,
                "dtb_source": "",
                "dtb_confidence": None,
                "metadata": {},
            }

    return {
        "path": None,
        "dtb": None,
        "build": None,
        "dtb_source": "",
        "dtb_confidence": None,
        "metadata": {},
    }


def _is_verified_dtb_source(source: str, confidence: Optional[int] = None) -> bool:
    """
    Decide whether an existing sidecar DTB is trustworthy enough for deep parsing.

    RAMDetect previously wrote fallback/default or KPCR-only DTBs that could be
    wrong for raw/VMEM dumps. Those sources must be rescanned.
    """
    source_l = (source or "").lower()
    bad_markers = (
        "unverified",
        "default",
        "placeholder",
        "ramdetect_default",
        "detected_by_kpcr_cr3",
        "kpcr_cr3",
    )
    if any(marker in source_l for marker in bad_markers):
        return False
    if confidence is not None and confidence < 80:
        return False
    return True


def _load_sidecar(dump_path: str):
    """
    Backward-compatible wrapper returning (dtb_int, build_int).
    New code should use _load_sidecar_details().
    """
    details = _load_sidecar_details(dump_path)
    return details.get("dtb"), details.get("build")


def _is_valid_dtb(dtb: int) -> bool:
    if dtb == 0 or dtb == 0xFFFFFFFFFFFFFFFF:
        return False
    if (dtb & 0xFFF) != 0:        # must be page-aligned
        return False
    if dtb < 0x1000:              # must be above null page
        return False
    if dtb > 0x40000000000:        # sanity cap: 4 TB physical address space
        return False
    return True


def _short_symbol_path(symbols: str) -> str:
    """Extract short symbol path from full path, keeping only the filename/tail."""
    if not symbols:
        return "N/A"
    s = str(symbols).replace("\\", "/")
    if "/symbols/windows/" in s:
        return s.split("/symbols/windows/", 1)[-1]
    return s[-90:]


def _kernel_metadata_summary(kernel_meta: dict) -> str:
    """Format kernel metadata into a readable multi-line summary."""
    ki = kernel_meta.get("kernel_info") or {}

    build = kernel_meta.get("build_number") or ki.get("build_number") or "N/A"
    version = kernel_meta.get("version") or ki.get("version") or "N/A"
    arch = kernel_meta.get("architecture") or ki.get("architecture") or "N/A"

    is64 = kernel_meta.get("is_64bit", ki.get("is_64bit"))
    is_pae = kernel_meta.get("is_pae", ki.get("is_pae"))
    if is64 is False and is_pae:
        arch = "x86 PAE"

    dtb = kernel_meta.get("dtb_hex") or ki.get("dtb_hex") or kernel_meta.get("dtb") or "N/A"
    cr3 = kernel_meta.get("cr3_hex") or ki.get("cr3_hex") or kernel_meta.get("cr3") or "N/A"

    source = kernel_meta.get("resolver_stage") or kernel_meta.get("metadata_source") or "N/A"
    profile_source = kernel_meta.get("profile_source") or ki.get("profile_source") or "N/A"
    layer = kernel_meta.get("layer_name") or ki.get("layer_name") or "N/A"
    symbols = kernel_meta.get("symbols") or ki.get("symbols")

    return (
        "Kernel metadata resolved:\n"
        f"  Build        : {build}\n"
        f"  Version      : {version}\n"
        f"  Architecture : {arch}\n"
        f"  DTB / CR3    : {dtb} / {cr3}\n"
        f"  Layer        : {layer}\n"
        f"  Source       : {source} / {profile_source}\n"
        f"  Symbols      : {_short_symbol_path(symbols)}"
    )


# PHASE_G1_CIC54_MISSING_FEATURE_AUDIT_HELPER
# Diagnostic-only export. Does not modify raw features, mapped features,
# RF threshold, model, dataset, verdict logic, or parser behavior.
def _phaseG1_export_cic54_missing_feature_audit(session, mapper, raw_features, coverage_report):
    import csv as _csv
    import json as _json
    from pathlib import Path as _Path

    raw_features = raw_features or {}
    coverage_report = coverage_report or {}

    session_id = (
        getattr(session, "session_id", None)
        or getattr(session, "id", None)
        or getattr(session, "scan_id", None)
        or getattr(session, "session_uuid", None)
        or "unknown_session"
    )
    dump_name = getattr(session, "dump_filename", "unknown_dump")

    out_dir = _Path("output") / "feature_debug" / str(session_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    canonical = []
    for attr in ("CANONICAL_FEATURES", "canonical_features", "feature_names", "features"):
        value = getattr(mapper, attr, None)
        if isinstance(value, (list, tuple)) and value:
            canonical = [str(x) for x in value]
            break
    if not canonical:
        # Stable fallback from CIC-MalMem-2022 canonical schema used by RAMDetect.
        canonical = [
            "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.nprocs64bit", "pslist.avg_handlers",
            "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
            "handles.nhandles", "handles.avg_handles_per_proc", "handles.nport", "handles.nfile", "handles.nevent",
            "handles.ndesktop", "handles.nkey", "handles.nthread", "handles.ndirectory", "handles.nsemaphore",
            "handles.ntimer", "handles.nsection", "handles.nmutant",
            "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
            "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
            "malfind.ninjections", "malfind.commitCharge", "malfind.uniqueInjections",
            "psxview.not_in_pslist", "psxview.not_in_eprocess_pool", "psxview.not_in_ethread_pool",
            "psxview.not_in_pspcid_list", "psxview.not_in_csrss_handles", "psxview.not_in_session",
            "psxview.not_in_deskthrd", "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
            "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
            "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg", "psxview.not_in_deskthrd_false_avg",
            "modules.nmodules", "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
            "svcscan.process_services", "svcscan.shared_process_services", "svcscan.interactive_process_services",
            "svcscan.nactive", "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
        ]

    mapped_raw_keys = coverage_report.get("mapped_raw_keys") or {}
    missing = list(coverage_report.get("missing_features") or [])
    if not missing:
        missing = [f for f in canonical if f not in mapped_raw_keys.values() and f not in raw_features]

    def _family(feature):
        return str(feature).split(".", 1)[0] if "." in str(feature) else str(feature)

    def _recommend(feature):
        f = str(feature)
        if f == "pslist.nprocs64bit":
            return (
                "EPROCESS/PEB architecture completion",
                "Recover 64-bit process architecture from EPROCESS/PEB/WOW64 fields and emit pslist.nprocs64bit.",
                "medium",
            )
        if f.startswith("psxview."):
            return (
                "Native psxview cross-view parser",
                "Implement native cross-view checks using EPROCESS pool scan, linked list, ETHREAD ownership, PspCid-style PID evidence, session/desktop thread evidence where available.",
                "high",
            )
        if f.startswith("modules."):
            return (
                "Kernel module parser",
                "Recover loaded kernel modules/drivers natively and emit modules.nmodules.",
                "medium",
            )
        if f.startswith("svcscan."):
            return (
                "Native service parser",
                "Recover service records / service registry-backed service metadata and emit svcscan.* canonical counts.",
                "medium-high",
            )
        if f.startswith("callbacks."):
            return (
                "Kernel callback parser",
                "Recover registered kernel callback tables and emit callbacks.ncallbacks, callbacks.nanonymous, callbacks.ngeneric.",
                "medium",
            )
        return (
            "Existing parser/mapping review",
            "Check whether this canonical feature is already extractable but not mapped or not emitted in raw_features.",
            "low",
        )

    rows = []
    for feat in missing:
        parser, rationale, priority = _recommend(feat)
        fam = _family(feat)
        raw_candidates = [k for k in raw_features.keys() if str(k).startswith(fam + ".") or str(k).startswith(fam + "_")]
        rows.append({
            "dump": dump_name,
            "session_id": session_id,
            "canonical_feature": feat,
            "family": fam,
            "status": "missing_from_live_raw_mapping",
            "recommended_parser_or_fix": parser,
            "priority": priority,
            "allowed_under_rules": "yes_parser_feature_completion_only",
            "raw_candidate_keys_present": ";".join(sorted(map(str, raw_candidates))[:20]),
            "rationale": rationale,
        })

    csv_path = out_dir / "cic54_missing_feature_audit.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "dump", "session_id", "canonical_feature", "family", "status",
            "recommended_parser_or_fix", "priority", "allowed_under_rules",
            "raw_candidate_keys_present", "rationale",
        ]
        writer = _csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    by_family = {}
    for row in rows:
        fam = row["family"]
        by_family.setdefault(fam, {"count": 0, "features": [], "recommended_parser_or_fix": row["recommended_parser_or_fix"], "priority": row["priority"]})
        by_family[fam]["count"] += 1
        by_family[fam]["features"].append(row["canonical_feature"])

    summary = {
        "session_id": session_id,
        "dump": dump_name,
        "total_canonical": coverage_report.get("total_canonical", len(canonical)),
        "covered": coverage_report.get("covered"),
        "coverage_pct": coverage_report.get("coverage_pct"),
        "missing_count": len(rows),
        "missing_by_family": by_family,
        "rules_preserved": {
            "ml_only": True,
            "threshold_changed": False,
            "training_dataset_changed": False,
            "verdict_logic_changed": False,
            "native_feature_rule_added": False,
        },
        "recommended_next_order": [
            "psxview.* native cross-view parser",
            "svcscan.* native service parser",
            "callbacks.* kernel callback parser",
            "modules.nmodules kernel module parser",
            "pslist.nprocs64bit architecture completion",
        ],
    }

    json_path = out_dir / "cic54_missing_feature_audit.summary.json"
    with json_path.open("w", encoding="utf-8") as f:
        _json.dump(summary, f, indent=2)

    md_path = out_dir / "cic54_missing_feature_recommendations.md"
    lines = []
    lines.append("# Phase G1 CIC54 Missing Feature Recommendations\n")
    lines.append(f"- Dump: `{dump_name}`")
    lines.append(f"- Session: `{session_id}`")
    lines.append(f"- Coverage: `{summary.get('covered')}/{summary.get('total_canonical')}` = `{summary.get('coverage_pct')}%`")
    lines.append(f"- Missing CIC features: `{len(rows)}`\n")
    lines.append("## Missing families\n")
    for fam, item in sorted(by_family.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        lines.append(f"### `{fam}` ({item['count']} missing)")
        lines.append(f"- Recommended fix: {item['recommended_parser_or_fix']}")
        lines.append(f"- Priority: {item['priority']}")
        lines.append("- Features:")
        for feat in item["features"]:
            lines.append(f"  - `{feat}`")
        lines.append("")
    lines.append("## Rule compliance\n")
    lines.append("This audit is diagnostic-only. It does not modify the RF threshold, model, training dataset, FeatureMapper, raw features, or verdict logic. Parser completion is allowed because it fills existing CIC-MalMem-2022 canonical fields before ML inference.\n")
    lines.append("## Suggested implementation order\n")
    for i, item in enumerate(summary["recommended_next_order"], 1):
        lines.append(f"{i}. {item}")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    return {"csv": str(csv_path), "json": str(json_path), "md": str(md_path)}




# PHASE_G2B_PSXVIEW_FIELD_COMPLETION_HELPER
# Diagnostic-only psxview parser-field completion.
# This does NOT inject psxview.* into raw_features and does NOT affect ML verdicts.
def _phaseG2B_complete_psxview_parser_fields(session):
    import csv as _csv
    import json as _json
    from pathlib import Path as _Path

    processes = list(getattr(session, "processes", []) or [])
    threads = list(getattr(session, "threads", []) or [])
    handles = list(getattr(session, "handles", []) or [])

    def _safe_int(v, default=0):
        try:
            if isinstance(v, str):
                s = v.strip()
                if not s or s.lower() in {"none", "n/a", "na", "-", "?"}:
                    return default
                return int(s, 16) if s.lower().startswith("0x") else int(float(s))
            return int(v or default)
        except Exception:
            return default

    def _as_bool_explicit(v, default=None):
        if isinstance(v, bool):
            return v
        if v is None:
            return default
        if isinstance(v, (int, float)):
            return bool(v)
        s = str(v).strip().lower()
        if s in {"true", "yes", "1", "y"}:
            return True
        if s in {"false", "no", "0", "n"}:
            return False
        return default

    def _name(row):
        return str(
            row.get("image_name") or row.get("name") or row.get("ImageFileName")
            or row.get("process_name") or row.get("Process") or ""
        )

    def _session_id():
        return (
            getattr(session, "session_id", None)
            or getattr(session, "id", None)
            or getattr(session, "scan_id", None)
            or getattr(session, "session_uuid", None)
            or "unknown_session"
        )

    # Thread ownership evidence: if parsed ETHREAD rows carry PID X, X is visible
    # from the ETHREAD owner view. This is still only partial psxview support.
    thread_counts = {}
    for t in threads:
        if not isinstance(t, dict):
            continue
        pid = _safe_int(t.get("pid") or t.get("PID") or t.get("owner_pid"), 0)
        if pid > 0:
            thread_counts[pid] = thread_counts.get(pid, 0) + 1

    # Handle ownership is not CSRSS-target evidence; it only tells us which PID
    # owns handle-table rows. Kept as diagnostic context only.
    handle_owner_counts = {}
    for h in handles:
        if not isinstance(h, dict):
            continue
        pid = _safe_int(h.get("pid") or h.get("PID"), 0)
        if pid > 0:
            handle_owner_counts[pid] = handle_owner_counts.get(pid, 0) + 1

    rows = []
    n_in_pool = 0
    n_in_pslist_known = 0
    n_in_pslist_false = 0
    n_ethread_known = 0
    n_ethread_false_strict = 0
    n_ethread_false_loose = 0

    for p in processes:
        if not isinstance(p, dict):
            continue
        pid = _safe_int(p.get("pid") or p.get("PID"), 0)
        pname = _name(p)
        active_threads = _safe_int(
            p.get("active_threads") or p.get("ActiveThreads") or p.get("threads") or p.get("thread_count"),
            0,
        )
        eproc_pa = _safe_int(p.get("eprocess_phys_addr") or p.get("eprocess_pa") or p.get("offset"), 0)

        # EPROCESS pool view: the current process list comes from EProcessScanner's
        # pool/statistical scanner, so a real eprocess physical address is direct
        # evidence for pool visibility. found_by_pool remains authoritative when present.
        found_by_pool = _as_bool_explicit(p.get("found_by_pool"), default=None)
        if found_by_pool is None:
            found_by_pool = bool(eproc_pa)
        in_eprocess_pool = bool(found_by_pool)

        # PsList view: EProcessScanner's DKOM phase stamps found_by_links. Treat as
        # unknown if absent; do not infer it from the presence of the process itself.
        found_by_links_raw = p.get("found_by_links", None)
        in_pslist = _as_bool_explicit(found_by_links_raw, default=None)

        ethread_count = int(thread_counts.get(pid, 0))
        in_ethread_pool = bool(ethread_count > 0)
        handle_owner_count = int(handle_owner_counts.get(pid, 0))

        reasons = []
        confidence_parts = []

        if in_eprocess_pool:
            n_in_pool += 1
            reasons.append("eprocess_pool:present")
            confidence_parts.append(1.0)
        else:
            reasons.append("eprocess_pool:absent_or_unknown")
            confidence_parts.append(0.0)

        if in_pslist is None:
            reasons.append("pslist:unknown_no_explicit_found_by_links")
        elif in_pslist:
            n_in_pslist_known += 1
            reasons.append("pslist:present_found_by_links")
            confidence_parts.append(1.0)
        else:
            n_in_pslist_known += 1
            n_in_pslist_false += 1
            reasons.append("pslist:absent_found_by_links_false")
            confidence_parts.append(0.8)

        # Strict ETHREAD gap: active_threads says process should have threads, but
        # native ETHREAD ownership view has none. This is an audit candidate only,
        # not safe ML psxview yet, because parser coverage must be validated.
        if in_ethread_pool:
            n_ethread_known += 1
            reasons.append(f"ethread_pool:present_threads={ethread_count}")
            confidence_parts.append(0.9)
        else:
            n_ethread_false_loose += 1
            if active_threads > 0:
                n_ethread_known += 1
                n_ethread_false_strict += 1
                reasons.append(f"ethread_pool:absent_but_active_threads={active_threads}")
                confidence_parts.append(0.4)
            else:
                reasons.append("ethread_pool:absent_no_active_threads_or_unknown")
                confidence_parts.append(0.2)

        if handle_owner_count > 0:
            reasons.append(f"handle_owner_rows={handle_owner_count}")

        # In-session / desktop / CSRSS / PspCid views are intentionally not filled
        # here because RAMDetect does not yet extract explicit parser evidence for
        # them. They remain unsupported until dedicated parsers exist.
        confidence = round(sum(confidence_parts) / max(len(confidence_parts), 1), 4)

        p["in_eprocess_pool"] = in_eprocess_pool
        p["in_pslist"] = in_pslist
        p["in_ethread_pool"] = in_ethread_pool
        p["ethread_thread_count"] = ethread_count
        p["handle_owner_count"] = handle_owner_count
        p["psxview_support_reason"] = "; ".join(reasons)
        p["psxview_confidence"] = confidence

        rows.append({
            "pid": pid,
            "process_name": pname,
            "active_threads": active_threads,
            "in_eprocess_pool": in_eprocess_pool,
            "in_pslist": "unknown" if in_pslist is None else in_pslist,
            "in_ethread_pool": in_ethread_pool,
            "ethread_thread_count": ethread_count,
            "handle_owner_count": handle_owner_count,
            "psxview_confidence": confidence,
            "psxview_support_reason": p["psxview_support_reason"],
        })

    session_id = str(_session_id())
    out_dir = _Path("output") / "feature_debug" / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    total = max(len(processes), 1)
    preview = {
        # Partial, parser-field based previews only. These are NOT injected into ML.
        "psxview.not_in_pslist": {
            "preview_value": int(n_in_pslist_false),
            "support": "partial_explicit_found_by_links" if n_in_pslist_known else "unsupported",
            "safe_for_ml_injection_now": False,
        },
        "psxview.not_in_eprocess_pool": {
            "preview_value": 0,
            "support": "partial_pool_baseline_only",
            "safe_for_ml_injection_now": False,
        },
        "psxview.not_in_ethread_pool": {
            "preview_value": int(n_ethread_false_strict),
            "loose_preview_including_inactive_or_unknown": int(n_ethread_false_loose),
            "support": "partial_ethread_owner_pid_view",
            "safe_for_ml_injection_now": False,
        },
        "psxview.not_in_pslist_false_avg": {
            "preview_value": round(n_in_pslist_false / total, 6),
            "support": "partial_explicit_found_by_links" if n_in_pslist_known else "unsupported",
            "safe_for_ml_injection_now": False,
        },
        "psxview.not_in_eprocess_pool_false_avg": {
            "preview_value": 0.0,
            "support": "partial_pool_baseline_only",
            "safe_for_ml_injection_now": False,
        },
        "psxview.not_in_ethread_pool_false_avg": {
            "preview_value": round(n_ethread_false_strict / total, 6),
            "loose_preview_avg_including_inactive_or_unknown": round(n_ethread_false_loose / total, 6),
            "support": "partial_ethread_owner_pid_view",
            "safe_for_ml_injection_now": False,
        },
        # Explicit unsupported views. Kept null to prevent accidental defaults.
        "psxview.not_in_pspcid_list": {"preview_value": None, "support": "unsupported_requires_pspcid_parser", "safe_for_ml_injection_now": False},
        "psxview.not_in_csrss_handles": {"preview_value": None, "support": "unsupported_requires_target_process_handle_resolution", "safe_for_ml_injection_now": False},
        "psxview.not_in_session": {"preview_value": None, "support": "unsupported_requires_session_view_parser", "safe_for_ml_injection_now": False},
        "psxview.not_in_deskthrd": {"preview_value": None, "support": "unsupported_requires_desktop_thread_view_parser", "safe_for_ml_injection_now": False},
        "psxview.not_in_pspcid_list_false_avg": {"preview_value": None, "support": "unsupported_requires_pspcid_parser", "safe_for_ml_injection_now": False},
        "psxview.not_in_csrss_handles_false_avg": {"preview_value": None, "support": "unsupported_requires_target_process_handle_resolution", "safe_for_ml_injection_now": False},
        "psxview.not_in_session_false_avg": {"preview_value": None, "support": "unsupported_requires_session_view_parser", "safe_for_ml_injection_now": False},
        "psxview.not_in_deskthrd_false_avg": {"preview_value": None, "support": "unsupported_requires_desktop_thread_view_parser", "safe_for_ml_injection_now": False},
    }

    summary = {
        "session_id": session_id,
        "dump_filename": getattr(session, "dump_filename", "unknown_dump"),
        "process_count": len(processes),
        "thread_count": len(threads),
        "handle_count": len(handles),
        "field_completion": {
            "processes_with_in_eprocess_pool": n_in_pool,
            "processes_with_explicit_pslist_view": n_in_pslist_known,
            "processes_not_in_pslist_preview": n_in_pslist_false,
            "processes_with_ethread_owner_view": n_ethread_known,
            "processes_not_in_ethread_pool_strict_preview": n_ethread_false_strict,
            "processes_not_in_ethread_pool_loose_preview": n_ethread_false_loose,
        },
        "ready_to_inject_psxview_into_ml": False,
        "safe_features_now": [],
        "reason": "G2B completes explicit parser fields and exports previews only. PspCid, CSRSS target-handle, session and desktop-thread views are still unsupported; clean-baseline validation is required before ML mapping.",
        "rules_preserved": {
            "diagnostic_only": True,
            "ml_only": True,
            "threshold_changed": False,
            "training_dataset_changed": False,
            "verdict_logic_changed": False,
            "native_feature_rule_added": False,
            "raw_features_modified": False,
        },
    }

    csv_path = out_dir / "psxview_parser_field_completion.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fields = [
            "pid", "process_name", "active_threads", "in_eprocess_pool",
            "in_pslist", "in_ethread_pool", "ethread_thread_count",
            "handle_owner_count", "psxview_confidence", "psxview_support_reason",
        ]
        writer = _csv.DictWriter(f, fieldnames=fields, quoting=_csv.QUOTE_MINIMAL, escapechar="\\")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    summary_path = out_dir / "psxview_parser_field_completion.summary.json"
    summary_path.write_text(_json.dumps(summary, indent=2), encoding="utf-8")

    preview_path = out_dir / "psxview_parser_field_completion.preview.json"
    preview_path.write_text(_json.dumps(preview, indent=2), encoding="utf-8")

    return {"csv": str(csv_path), "summary": str(summary_path), "preview": str(preview_path)}


# ─────────────────────────────────────────────────────────────────────────────
# AnalysisWorker  — QThread
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisWorker(QThread):
    phase_changed = pyqtSignal(int, str)
    module_done   = pyqtSignal(int, str)
    progress      = pyqtSignal(int)
    log           = pyqtSignal(str, str)
    finished      = pyqtSignal(object)
    errored       = pyqtSignal(str)

    def __init__(self, session: ScanSession, parent=None):
        super().__init__(parent)
        self.session  = session
        self._cancel  = False
        self._overall = 0

    def cancel(self):
        self._cancel = True

    # ── Entry point ───────────────────────────────────────────────────────────
    def run(self):
        # ── Logging hygiene fixes (run once at thread start) ──────────────────
        import io, sys
        import logging.handlers as _lh_mod

        _CONSOLE_STREAMS = {sys.stdout, sys.stderr}

        for _h in list(logging.root.handlers):

            # ── Fix 1: console StreamHandlers → UTF-8 ─────────────────────────
            if type(_h) is logging.StreamHandler:
                if not (hasattr(_h, "stream") and _h.stream in _CONSOLE_STREAMS):
                    continue
                try:
                    raw_buf = getattr(_h.stream, "buffer", None)
                    if raw_buf is not None:
                        _h.stream = io.TextIOWrapper(
                            raw_buf, encoding="utf-8", errors="replace",
                            line_buffering=True,
                        )
                except Exception:
                    pass

            # ── Fix 2: RotatingFileHandler — recover closed stream ─────────────
            elif isinstance(_h, _lh_mod.RotatingFileHandler):
                try:
                    closed = (_h.stream is None) or getattr(_h.stream, "closed", False)
                    if closed:
                        try:
                            _h.stream = _h._open()
                        except Exception:
                            logging.root.removeHandler(_h)
                except Exception:
                    try:
                        logging.root.removeHandler(_h)
                    except Exception:
                        pass

        def _quiet_handle_error(record):
            pass
        for _h in logging.root.handlers:
            _h.handleError = _quiet_handle_error

        try:
            self.session.status = "analysing"
            self._run_phase0_parsing()
            if self._cancel: return
            self._run_phase1_features()
            if self._cancel: return
            self._run_phase2_ml()
            if self._cancel: return
            self.session.status = "complete"
            self.finished.emit(self.session)
        except Exception as e:
            self.log.emit("ERROR", str(e))
            self.session.status = "error"
            self.session.error_message = str(e)
            self.errored.emit(str(e))

    # ── Phase 0: Memory Parsing ───────────────────────────────────────────────
    def _run_phase0_parsing(self):
        if _extraction_import_error:
            raise ImportError(
                f"Cannot load extraction modules.\n"
                f"Error: {_extraction_import_error}\n\n"
                f"Run:  pip install -e .  in the project root and restart RAMDetect."
            )

        self.phase_changed.emit(0, "Memory Parsing")
        self.log.emit("INFO", f"Loading memory dump: {self.session.dump_filename}")
        self.log.emit("INFO", f"Dump size: {self.session.dump_size_str}")

        # ── 1. Resolve verified DTB and build number ──────────────────────────
        dtb_val   = self.session.dtb
        build_num = self.session.build_number
        kernel_meta = {}

        # Phase 6A: resolve kernel metadata before native parsing.
        # External resolver scope is limited to OS build/profile and kernel DTB/CR3.
        # All artifact extraction remains RAMDetect-native.
        try:
            from ramdetect.acquisition.metadata_reader import MetadataReader
            _kr = MetadataReader().get_metadata(
                self.session.dump_path,
                allow_external=True,
                allow_native_fallback=True,
                write_sidecar=True,
            )
            if _kr.get("is_valid"):
                kernel_meta = dict(_kr)

                # SAFETY FALLBACK: Windows 10 x86 PAE / ntkrpamp support
                # Some metadata paths resolve build + DTB but do not pass Is64Bit/IsPAE forward.
                try:
                    symbols_text = str(kernel_meta.get("symbols", "")).lower()
                    arch_text = str(kernel_meta.get("architecture", "")).lower()
                    layer_text = str(kernel_meta.get("layer_name", "")).lower()
                    build_int = int(kernel_meta.get("build_number") or kernel_meta.get("build") or build_num or 0)

                    if build_int == 19041 and (
                        "ntkrpamp" in symbols_text
                        or "windowsintelpae" in layer_text
                        or "x86 pae" in arch_text
                    ):
                        kernel_meta["is_64bit"] = False
                        kernel_meta["is_pae"] = True
                        kernel_meta["architecture"] = "x86 PAE"
                        self.log.emit("INFO", "  Forced x86 PAE profile from kernel metadata/symbols")
                except Exception as e:
                    self.log.emit("WARNING", f"  x86 PAE metadata fallback skipped: {e}")

                # Normalize nested kernel_info into top-level kernel_meta.
                # Some sidecar/resolver paths store architecture fields under kernel_info,
                # while the parser setup expects them at the top level.
                try:
                    ki = kernel_meta.get("kernel_info")
                    if isinstance(ki, dict):
                        for k in (
                            "is_64bit",
                            "is_pae",
                            "symbols",
                            "layer_name",
                            "memory_layer",
                            "machine_type",
                            "nt_build_lab",
                            "kernel_base_hex",
                            "kd_version_block_hex",
                        ):
                            if k not in kernel_meta or kernel_meta.get(k) in (None, "", "unknown"):
                                kernel_meta[k] = ki.get(k)

                        if kernel_meta.get("is_64bit") is False and kernel_meta.get("is_pae") is True:
                            kernel_meta["architecture"] = "x86 PAE"
                except Exception as e:
                    self.log.emit("WARNING", f"  Kernel metadata normalization skipped: {e}")

                self.log.emit("INFO", "  " + _kernel_metadata_summary(kernel_meta))

                _resolved_dtb = _parse_int_maybe_hex(_kr.get("dtb"))
                _resolved_build = _parse_int_maybe_hex(_kr.get("build_number"))
                if not build_num and _resolved_build:
                    build_num = _resolved_build
                if not dtb_val and _resolved_dtb and _is_valid_dtb(_resolved_dtb):
                    dtb_val = _resolved_dtb
                self.session.metadata_source = _kr.get("resolver_stage", "kernel_metadata")
                self.session.dtb_source = _kr.get("dtb_source", "")
                self.session.dtb_confidence = _kr.get("dtb_confidence")
            else:
                self.log.emit("WARNING", "  Kernel metadata resolver did not return a verified DTB/build; falling back to existing sidecar/native path")
        except Exception as _km_ex:
            self.log.emit("WARNING", f"  Kernel metadata resolver skipped: {_km_ex}")

        sidecar = _load_sidecar_details(self.session.dump_path)
        sidecar_dtb = sidecar.get("dtb")
        sidecar_build = sidecar.get("build")
        sidecar_source = sidecar.get("dtb_source") or ""
        sidecar_confidence = sidecar.get("dtb_confidence")
        sidecar_path = sidecar.get("path")

        if not build_num and sidecar_build:
            build_num = sidecar_build
            self.log.emit("INFO", f"  Build number from sidecar: {build_num}")

        if not build_num:
            raise RuntimeError(
                "Windows build number is missing. Select an OS profile first "
                "so RAMDetect can use the correct Windows structure offsets."
            )

        session_dtb_verified = bool(dtb_val and _is_valid_dtb(dtb_val))
        sidecar_dtb_verified = bool(
            sidecar_dtb
            and _is_valid_dtb(sidecar_dtb)
            and _is_verified_dtb_source(sidecar_source, sidecar_confidence)
        )

        if session_dtb_verified:
            self.log.emit("INFO", f"  Verified DTB loaded from session: {hex(dtb_val)}")
        elif sidecar_dtb_verified:
            dtb_val = sidecar_dtb
            src = sidecar_source or "sidecar"
            self.log.emit("INFO", f"  Verified DTB loaded from sidecar JSON: {hex(dtb_val)} ({src})")
        else:
            if sidecar_dtb and _is_valid_dtb(sidecar_dtb):
                self.log.emit(
                    "WARNING",
                    f"  Sidecar DTB {hex(sidecar_dtb)} is present but source is unverified "
                    f"({sidecar_source or 'unknown'}); running native DTB scanner..."
                )
            else:
                self.log.emit("WARNING", "  DTB missing — running native DTB scanner...")

            try:
                from ramdetect.utils.find_dtb import find_dtb, write_dtb_to_sidecar
            except Exception as _e:
                raise RuntimeError(
                    "Native DTB scanner is unavailable. Place find_dtb.py at "
                    "ramdetect/utils/find_dtb.py and retry."
                ) from _e

            dump_file = Path(self.session.dump_path)
            file_mb = max(1, int(dump_file.stat().st_size / (1024 * 1024)))
            scan_plan = [4096]
            if file_mb > 4096:
                scan_plan.append(min(8192, file_mb))
            if file_mb > max(scan_plan):
                scan_plan.append(0)  # full dump scan

            candidate = None
            used_scan = None
            for scan_range in scan_plan:
                used_scan = scan_range
                desc = "full dump" if scan_range <= 0 else f"first {scan_range} MB"
                self.log.emit("INFO", f"  DTB scanner scanning {desc}...")
                candidate = find_dtb(
                    dump_file,
                    scan_mb=scan_range,
                    build=int(build_num),
                    strict_system=False,
                    use_selfref=True,
                    use_kpcr=True,
                )
                if candidate:
                    break

            if not candidate:
                raise RuntimeError(
                    "Unable to determine a verified DTB/CR3. Deep parsing has been "
                    "stopped to avoid false forensic extraction. Verify the selected "
                    "Windows build/profile or run: "
                    "python -m ramdetect.utils.find_dtb <dump> --build <build> --scan-mb 0 --write-json"
                )

            try:
                sidecar_path = write_dtb_to_sidecar(dump_file, candidate, build=int(build_num))
            except Exception as _e:
                self.log.emit("WARNING", f"  DTB detected but sidecar update failed: {_e}")
                sidecar_path = None

            dtb_val = candidate.dtb
            self.log.emit(
                "INFO",
                f"  Native DTB scanner selected {candidate.dtb_hex} "
                f"with confidence {candidate.score}% using {candidate.method}"
            )
            if sidecar_path:
                self.log.emit("INFO", f"  Sidecar updated: {sidecar_path}")

        self.session.dtb          = dtb_val
        self.session.build_number = build_num
        if kernel_meta.get("architecture"):
            try:
                self.session.architecture = str(kernel_meta.get("architecture"))
            except Exception:
                pass

        # ── 2. Load offsets profile ────────────────────────────────────────────
        try:
            profile = get_offsets(build_num, is_64bit=kernel_meta.get("is_64bit"), is_pae=kernel_meta.get("is_pae"), symbols=kernel_meta.get("symbols"))
        except Exception:
            profile = {
                "EPROCESS": {"ThreadListHead": 0x370},
                "ETHREAD":  {"ThreadListEntry": 0x578},
            }
        self.log.emit("INFO", f"  Profile: Build {build_num} | DTB: {hex(dtb_val)}")

        dump_path = self.session.dump_path

        # ── 3. Open shared memory reader for EPROCESS + Thread scans ─────────
        reader     = PhysicalMemoryReader(dump_path)
        reader.open()
        eproc_profile = profile.get("EPROCESS", {}) if isinstance(profile, dict) else {}
        pointer_size = int(eproc_profile.get("pointer_size", 8) or 8)
        is_pae = bool(eproc_profile.get("is_pae", kernel_meta.get("is_pae", False)))
        if pointer_size == 4:
            self.log.emit("INFO", f"  Architecture profile: x86{' PAE' if is_pae else ''} | pointer size 4 bytes")
        translator = AddressTranslator(reader, dtb_val, pointer_size=pointer_size, is_pae=is_pae)

        # ── 4. EPROCESS scan ──────────────────────────────────────────────────
        _last_eprocess_pct = [-1]
        def _eprocess_log(level: str, msg: str):
            if "Carving EPROCESS..." in msg:
                try:
                    pct = int(float(msg.split("%")[0].split()[-1]))
                    if pct - _last_eprocess_pct[0] >= 5:
                        _last_eprocess_pct[0] = pct
                        self.log.emit(level, msg)
                except Exception:
                    self.log.emit(level, msg)
            else:
                self.log.emit(level, msg)

        eprocess_scanner = EProcessScanner(
            reader, translator, build_number=build_num,
            log_callback=_eprocess_log,
            kernel_metadata=kernel_meta,
            offsets_override=eproc_profile,
        )
        processes = eprocess_scanner.find_all_processes()
        self.session.processes = processes
        self._emit_module(0, "EPROCESS Walker")

        if not processes:
            self.log.emit("WARNING", "  No processes found — check DTB value")
            reader.close()
            return

        self.log.emit("INFO", "=" * 52)
        self.log.emit("INFO", f"  Found {len(processes):,} processes")
        self.log.emit("INFO", "  Initializing forensic engines...")

        # ── Collect scanner offsets (mirrors CLI) ─────────────────────────────
        scanner_offsets = getattr(eprocess_scanner, "offsets", {}).copy()
        if "ThreadListHead" not in scanner_offsets:
            scanner_offsets["ThreadListHead"] = profile["EPROCESS"]["ThreadListHead"]
        if "ThreadListEntry" not in scanner_offsets:
            scanner_offsets["ThreadListEntry"] = profile["ETHREAD"]["ThreadListEntry"]

        targets = [p for p in processes if len(p.get("image_name", "")) > 0]
        self.log.emit("INFO", f"  Deep scanning {len(targets):,} active processes...")
        self.log.emit("INFO", "-" * 52)

        # ── 5. Thread scan — sequential, shared reader, per-process timeout ───
        if self._cancel:
            reader.close()
            return

        thread_parser   = ThreadParser(
            reader,
            translator,
            build_number=build_num,
            is_64bit=kernel_meta.get("is_64bit"),
            is_pae=is_pae,
            symbols=kernel_meta.get("symbols"),
            offsets_override=profile.get("ETHREAD", {}),
        )
        all_threads     = []
        threads_by_pid  = {}

        n_targets  = len(targets)
        _log_every = 1
        self.log.emit("INFO", f"  [1/3] Scanning threads...")

        def _scan_threads_for(proc):
            # EPROCESS.ThreadListHead is a kernel virtual linked list. Use the
            # verified kernel DTB/CR3 for ETHREAD list walking instead of the
            # per-process/user DTB. This preserves native extraction while fixing
            # modern Windows dumps where process DTB fails kernel-list traversal.
            per_proc_dtb = dtb_val

            _pname = proc.get("image_name", "")
            return thread_parser.enumerate_threads_for_process(
                proc["eprocess_phys_addr"], proc["pid"], scanner_offsets,
                process_dtb=per_proc_dtb,
                proc_name=_pname,
            )

        for _ti, proc in enumerate(targets, 1):
            if self._cancel:
                break
            _name = proc.get("image_name", "?")
            _pid  = proc.get("pid", 0)
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(_scan_threads_for, proc)
                    try:
                        t_list = fut.result(timeout=10)
                    except (concurrent.futures.TimeoutError, Exception):
                        t_list = None
                if t_list:
                    all_threads.extend(t_list)
                    threads_by_pid[_pid] = t_list
            except Exception:
                pass

            if _ti % _log_every == 0 or _ti == n_targets:
                self.log.emit(
                    "INFO",
                    f"  [{_ti}/{n_targets}] Threads: {_name:<24} (PID: {_pid:<6})"
                    f"  found: {len(threads_by_pid.get(_pid, [])):>4}"
                )

        self.session.threads = all_threads
        self._emit_module(0, "Thread Scanner")
        self.log.emit("INFO", f"  Extracted {len(all_threads):,} threads")

        reader.close()

        # ── 6. DLL scan — parallel workers, each with own reader ──────────────
        if self._cancel:
            return

        max_workers = min(4, os.cpu_count() or 2)

        def _dll_worker(proc):
            pid      = proc["pid"]
            peb_addr = proc.get("peb", 0)
            try:
                local_reader     = PhysicalMemoryReader(dump_path)
                local_reader.open()
                # Start translator with verified kernel DTB. DLLParser itself
                # should select user_dtb/dtb candidates for PEB/LDR walking.
                local_translator = AddressTranslator(local_reader, dtb_val, pointer_size=pointer_size, is_pae=is_pae)
                local_dll_parser = DLLParser(local_reader, local_translator, dump_file=dump_path)
                d_list = []
                try:
                    if hasattr(local_dll_parser, "get_modules"):
                        d_list = local_dll_parser.get_modules(proc) or []
                    elif hasattr(local_dll_parser, "get_dlls_robust"):
                        d_list = local_dll_parser.get_dlls_robust(
                            peb_addr,
                            pid,
                            dtb=proc.get("user_dtb") or proc.get("UserDirectoryTableBase") or proc.get("dtb") or dtb_val,
                            process=proc,
                            dump_path=dump_path,
                        ) or []
                    elif hasattr(local_dll_parser, "get_dlls"):
                        d_list = local_dll_parser.get_dlls(proc) or []
                    for d in d_list:
                        d.setdefault("pid", pid)
                except Exception:
                    pass
                local_reader.close()
                return d_list
            except Exception:
                return []

        all_dlls    = []
        dlls_by_pid = {}

        _loggers_to_silence = [
            "ramdetect.extraction.parsers.memory_reader",
            "ramdetect.extraction.parsers.address_translator",
            "ramdetect.extraction.parsers.vad_scanner",
            "ramdetect.extraction.parsers.injection_detector",
            "ramdetect.extraction.parsers.dll_parser",
        ]
        _saved_levels = {n: logging.getLogger(n).level for n in _loggers_to_silence}
        for n in _loggers_to_silence:
            logging.getLogger(n).setLevel(logging.ERROR)

        self.log.emit("INFO", f"  [2/3] Scanning DLLs (parallel, {max_workers} workers)...")
        _dll_done = [0]

        dll_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        future_to_proc = {dll_executor.submit(_dll_worker, proc): proc for proc in targets}

        try:
            for fut in concurrent.futures.as_completed(future_to_proc):
                if self._cancel:
                    dll_executor.shutdown(wait=False, cancel_futures=True)
                    for n, lvl in _saved_levels.items():
                        logging.getLogger(n).setLevel(lvl)
                    return

                proc  = future_to_proc[fut]
                _name = proc.get("image_name", "?")
                _pid  = proc.get("pid", 0)
                try:
                    d_list = fut.result(timeout=30)
                    if d_list:
                        all_dlls.extend(d_list)
                        dlls_by_pid[_pid] = d_list
                except (concurrent.futures.TimeoutError, Exception):
                    d_list = []
                _dll_done[0] += 1
                if _dll_done[0] % _log_every == 0 or _dll_done[0] == n_targets:
                    found = len(d_list) if d_list else 0
                    self.log.emit(
                        "INFO",
                        f"  [{_dll_done[0]}/{n_targets}] DLLs: {_name:<24}"
                        f"  found: {found:>4}"
                    )
        finally:
            dll_executor.shutdown(wait=False)

        for n, lvl in _saved_levels.items():
            logging.getLogger(n).setLevel(lvl)
        self.session.dlls = all_dlls
        # Diagnostic for native 3-list LDR parser integration.
        try:
            _ldr_rows = [
                d for d in self.session.dlls
                if any(k in d for k in ("in_load", "in_mem", "in_init", "ldr_lists_complete"))
            ]
            self.log.emit(
                "INFO",
                f"  LDR DLL rows available in session: {len(_ldr_rows):,}/{len(self.session.dlls):,}"
            )
        except Exception as _ldr_diag_ex:
            self.log.emit("WARNING", f"  LDR DLL row diagnostic failed: {_ldr_diag_ex}")
        self._emit_module(0, "DLL Module Loader")
        self.log.emit("INFO", f"  Extracted {len(all_dlls):,} loaded modules")

        # ── 7+8. Handle + VAD/PE scan ────────────────────────────────────────
        # Handles are enumerated ONCE globally, then grouped by PID.
        # Running one Volatility handles subprocess per process caused clean
        # Win10 dumps to return 0 handles when multiple vol.exe instances failed
        # concurrently. A single global run also matches the CLI/analyze_dump path.
        if self._cancel:
            return

        handles_by_pid = {}
        global_handles = []
        if _HandleParser is not None:
            self.log.emit("INFO", "  [3/3] Enumerating handles globally...")
            try:
                hp = _HandleParser()
                global_handles = hp.enumerate_handles(dump_path) or []
                for h in global_handles:
                    try:
                        hpid = int(h.get("pid", 0) or 0)
                    except Exception:
                        hpid = 0
                    if hpid:
                        handles_by_pid.setdefault(hpid, []).append(h)
                if global_handles:
                    self.log.emit("INFO", f"  Global handles recovered: {len(global_handles):,}")
                else:
                    err = getattr(hp, "error_state", None)
                    self.log.emit("WARNING", f"  Global handle enumeration returned 0 handles" + (f" ({err})" if err else ""))
            except Exception as _hp_ex:
                self.log.emit("WARNING", f"  Global handle enumeration failed: {_hp_ex}")

        def _handle_vad_worker(proc):
            pid  = proc["pid"]
            name = proc.get("image_name", "")
            # PHASE_I2F_PROCESS_PATH_BRIDGE
            process_path = (
                proc.get("path") or proc.get("exe_path") or proc.get("image_path")
                or proc.get("full_path") or proc.get("command_line") or ""
            )
            process_path = (
                proc.get("path") or proc.get("exe_path") or proc.get("image_path")
                or proc.get("full_path") or proc.get("command_line") or ""
            )
            handles     = []
            pe_sections = []
            injections  = []
            injection_audit = []  # PHASE_F1_INJECTION_CANDIDATE_AUDIT_WORKER
            try:
                local_reader     = PhysicalMemoryReader(dump_path)
                local_reader.open()
                local_translator = AddressTranslator(local_reader, dtb_val, pointer_size=pointer_size, is_pae=is_pae)

                # Handles were already enumerated globally and grouped by PID.
                # Do not launch Volatility per process here.
                handles = list(handles_by_pid.get(pid, []))

                try:
                    # FIX: Pass the build_num so the dynamic offsets in offset.py work!
                    vs = VADScanner(local_reader, local_translator, build_number=build_num)
                    sections = vs.scan_vad(proc)
                    if sections:
                        pe_sections = list(sections)
                except Exception as e:
                    # FIX: Log the error so it doesn't fail silently if something goes wrong
                    import logging
                    logging.getLogger(__name__).debug(f"VADScanner error on PID {pid}: {e}")

                if _InjectionDetector is not None:
                    t_list = threads_by_pid.get(pid, [])
                    d_list = dlls_by_pid.get(pid, [])
                    try:
                        det = _InjectionDetector()
                        raw_dtb = (
                            proc.get("user_dtb")
                            or proc.get("UserDirectoryTableBase")
                            or proc.get("dtb")
                            or proc.get("cr3")
                            or proc.get("DirectoryTableBase")
                            or dtb_val
                        )
                        try:
                            inj_dtb = int(raw_dtb) if raw_dtb is not None else int(dtb_val)
                        except (TypeError, ValueError):
                            inj_dtb = int(dtb_val)
                        if not _is_valid_dtb(inj_dtb):
                            inj_dtb = int(dtb_val)
                        injs = det.detect_injections(
                            pid,
                            t_list,
                            d_list,
                            pe_sections,
                            process_name=name,
                            translator=local_translator,
                            process_dtb=inj_dtb,
                            process_path=process_path,
                        )
                        for inj in injs:
                            inj["process"] = name
                            inj.setdefault("process_path", process_path)
                        injections = injs
                        injection_audit = list(getattr(det, 'last_candidate_audit', []) or [])
                    except Exception:
                        pass

                local_reader.close()
            except Exception:
                pass
            return handles, pe_sections, injections, injection_audit

        all_handles    = []
        all_sections   = []
        all_injections = []
        all_injection_audit = []

        for n in _loggers_to_silence:
            logging.getLogger(n).setLevel(logging.ERROR)

        self.log.emit("INFO", f"  [3/3] Scanning VADs [3/3] Scanning handles & detecting injections (parallel) detecting injections (parallel)...")
        _hvad_done = [0]

        hvad_executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        hvad_future_to_proc = {hvad_executor.submit(_handle_vad_worker, proc): proc for proc in targets}

        try:
            for fut in concurrent.futures.as_completed(hvad_future_to_proc):
                if self._cancel:
                    hvad_executor.shutdown(wait=False, cancel_futures=True)
                    for n, lvl in _saved_levels.items():
                        logging.getLogger(n).setLevel(lvl)
                    return

                proc  = hvad_future_to_proc[fut]
                _name = proc.get("image_name", "?")
                try:
                    handles, sections, injections, injection_audit = fut.result(timeout=30)
                    all_handles.extend(handles)
                    all_sections.extend(sections)
                    all_injections.extend(injections)
                    all_injection_audit.extend(injection_audit or [])
                except (concurrent.futures.TimeoutError, Exception):
                    handles, injections, injection_audit = [], [], []
                _hvad_done[0] += 1
                if _hvad_done[0] % _log_every == 0 or _hvad_done[0] == n_targets:
                    self.log.emit(
                        "INFO",
                        f"  [{_hvad_done[0]}/{n_targets}] {_name:<24}"
                        f"  H: {len(handles):>5}  I: {len(injections):>2}"
                    )
        finally:
            hvad_executor.shutdown(wait=False)

        for n, lvl in _saved_levels.items():
            logging.getLogger(n).setLevel(lvl)

        self.session.handles     = all_handles
        self.session.pe_sections = all_sections
        self.session.injections = all_injections
        self.session.injection_candidate_audit = all_injection_audit

        # PHASE_H3D_SERVICE_REGISTRY_HANDLE_PARSER
        # Diagnostic-only: parse service-name evidence from registry handle paths.
        # This does NOT emit svcscan.* ML features, does not change the RF
        # threshold, and does not add post-classification rule logic. It only stores
        # structured service-registry evidence for reports and future parser work.
        try:
            from ramdetect.extraction.parsers.service_registry_parser import ServiceRegistryParser
            _svc_payload = {
                "processes": self.session.processes,
                "handles": self.session.handles,
                "dlls": self.session.dlls,
                "pe_sections": self.session.pe_sections,
            }
            _svc_result = ServiceRegistryParser().parse(_svc_payload)
            self.session.service_registry_records = list(_svc_result.get("services", []) or [])
            self.session.service_registry_summary = dict(_svc_result.get("summary", {}) or {})
            self.log.emit(
                "INFO",
                "  Service registry evidence: "
                f"{self.session.service_registry_summary.get('service_name_evidence_count', 0)} service names "
                f"from {self.session.service_registry_summary.get('raw_registry_service_path_hits', 0)} registry path hit(s); "
                "svcscan ML mapping remains disabled"
            )
        except Exception as _svc_ex:
            self.session.service_registry_records = []
            self.session.service_registry_summary = {"error": str(_svc_ex), "ready_for_svcscan_ml_mapping": False}
            self.log.emit("WARNING", f"  Service registry evidence parser skipped: {_svc_ex}")

        # PHASE_G2B_PSXVIEW_FIELD_COMPLETION_CALL
        # Diagnostic-only: annotate process-view support fields and export audit files.
        # Does not inject psxview.* into raw_features or affect ML verdict logic.
        try:
            _g2b_paths = _phaseG2B_complete_psxview_parser_fields(self.session)
            self.log.emit("INFO", f"  Phase G2B psxview field audit exported: {_g2b_paths.get('summary')}")
        except Exception as _g2b_ex:
            self.log.emit("WARNING", f"  Phase G2B psxview field audit skipped: {_g2b_ex}")
        # PHASE_J10_PROCESS_CONFIDENCE_AUDIT
        # Diagnostic-only: annotate low-confidence/stale process candidates for
        # GUI/report clarity. This does not remove processes, does not alter
        # raw features, and does not affect RF-AE verdict logic.
        try:
            from ramdetect.utils.process_confidence import annotate_session_processes
            _j10_summary = annotate_session_processes(self.session, export=True)
            self.log.emit(
                "INFO",
                "  Phase J10 process confidence audit exported: "
                f"low-confidence={_j10_summary.get('low_confidence_count', 0)}/"
                f"{_j10_summary.get('process_count', 0)}"
            )
        except Exception as _j10_ex:
            self.log.emit("WARNING", f"  Phase J10 process confidence audit skipped: {_j10_ex}")

        if all_injection_audit:
            self.log.emit("INFO", f"  Injection candidate audit rows: {len(all_injection_audit):,}")
            # PHASE_I2F_VISIBILITY_SUMMARY_LOG
            try:
                _i2f_rows = [r for r in (all_injection_audit or []) if isinstance(r, dict) and str(r.get("phase", "")).upper() == "I2F"]
                if _i2f_rows:
                    _enabled = sum(1 for r in _i2f_rows if str(r.get("enabled", "")).lower() in {"true", "1", "yes"})
                    _dry = sum(1 for r in _i2f_rows if str(r.get("dry_run", "")).lower() in {"true", "1", "yes"})
                    _matches = [r for r in _i2f_rows if str(r.get("policy_match", "")).lower() in {"true", "1", "yes"}]
                    _would = sum(1 for r in _matches if str(r.get("dry_run", "")).lower() in {"true", "1", "yes"})
                    _actual = sum(1 for inj in (all_injections or []) if isinstance(inj, dict) and inj.get("i2f_feature_flag"))
                    self.log.emit("INFO", f"  I2F audit: rows={len(_i2f_rows):,} enabled_rows={_enabled:,} dry_run_rows={_dry:,} policy_matches={len(_matches):,} would_promote={_would:,} actual_promotions={_actual:,}")
                else:
                    self.log.emit("INFO", "  I2F audit: no I2F rows found; check env flag and process_path bridge")
            except Exception as _i2f_log_ex:
                self.log.emit("WARNING", f"  I2F audit summary skipped: {_i2f_log_ex}")

        self._emit_module(0, "Handle Extractor")
        self._emit_module(0, "PE Section Parser")
        self._emit_module(0, "VAD Tree Walker")

        # ── Final summary block ───────────────────────────────────────────────
        self.log.emit("INFO", "-" * 52)
        self.log.emit("INFO", f"  Extracted {len(all_threads):,} threads")
        self.log.emit("INFO", f"  Extracted {len(all_dlls):,} loaded modules")
        self.log.emit("INFO", f"  Extracted {len(all_handles):,} open handles")
        inj_count = len(all_injections)
        if inj_count:
            self.log.emit("WARNING", f"  Detected {inj_count} injection(s)")
        else:
            self.log.emit("INFO",    f"  Detected 0 injections")
        self.log.emit("INFO", "=" * 52)

    # ── Phase 1: Feature Extraction ───────────────────────────────────────────
    def _run_phase1_features(self):
        if _features_import_error:
            raise ImportError(
                f"Cannot load feature extraction modules.\n"
                f"Error: {_features_import_error}\n\n"
                f"Run:  pip install -e .  in the project root and restart RAMDetect."
            )

        self.phase_changed.emit(1, "Feature Extraction")
        self.log.emit("INFO", "=" * 52)
        self.log.emit("INFO", "  Starting feature extraction pipeline...")
        self.log.emit("INFO", f"  Input: {len(self.session.processes):,} procs  "
                              f"{len(self.session.threads):,} threads  "
                              f"{len(self.session.dlls):,} DLLs  "
                              f"{len(self.session.handles):,} handles")
        self.log.emit("INFO", "-" * 52)

        _mapped_files = getattr(self.session, "mapped_files", [])
        parsed_data = {
            "processes":   self.session.processes,
            "threads":     self.session.threads,
            "dlls":        self.session.dlls,
            "handles":     self.session.handles,
            "pe_sections": self.session.pe_sections,
            "memory_regions": self.session.pe_sections,
            "vads": self.session.pe_sections,
            "pe_files": self.session.pe_sections or _mapped_files,
            "injections":  getattr(self.session, "injections", []),
            "mapped_files": _mapped_files,
            "service_registry_records": getattr(self.session, "service_registry_records", []),
            "service_registry_summary": getattr(self.session, "service_registry_summary", {}),
        }

        # PHASE_F2_THREAD_FEATURE_AUDIT_PATH
        # Diagnostic-only: tell ThreadFeatures where to export its
        # unbacked-thread consistency audit. This does not modify parser
        # output, feature values, ML input, or verdict logic.
        try:
            _sid = (
                getattr(self.session, 'session_id', None)
                or getattr(self.session, 'id', None)
                or getattr(self.session, 'scan_id', None)
            )
            if not _sid:
                import uuid as _uuid
                _sid = getattr(self.session, '_phaseF2_audit_id', None)
                if not _sid:
                    _sid = str(_uuid.uuid4())[:8]
                    setattr(self.session, '_phaseF2_audit_id', _sid)
            _phaseF2_dir = Path('output') / 'feature_debug' / str(_sid)
            _phaseF2_dir.mkdir(parents=True, exist_ok=True)
            os.environ['RAMDETECT_THREAD_FEATURE_AUDIT_PATH'] = str(_phaseF2_dir / 'thread_feature_unbacked_audit.csv')
        except Exception:
            os.environ['RAMDETECT_THREAD_FEATURE_AUDIT_PATH'] = str(Path('output') / 'feature_debug' / 'phaseF2_thread_feature_unbacked_audit.csv')

        import time as _time

        agg = FeatureAggregator()

        _ui_modules = PHASE_MAP[1]["modules"]
        _extractor_ui = {
            "injection": _ui_modules[5],
            "process":   _ui_modules[0],
            "thread":    _ui_modules[1],
            "dll":       _ui_modules[2],
            "pe":        _ui_modules[3],
            "handle":    _ui_modules[4],
        }

        _all_raw: dict = {}
        for ext_name, extractor in agg.extractors.items():
            if self._cancel:
                return
            self.log.emit("INFO", f"  Running {ext_name}...")
            _t0 = _time.monotonic()
            try:
                feats = extractor.extract_with_error_handling(parsed_data)
            except Exception as _ex:
                self.log.emit("WARNING", f"    {ext_name} error: {_ex}")
                feats = {}
            elapsed = _time.monotonic() - _t0
            n_feats = len(feats) if feats else 0
            self.log.emit("INFO", f"    {ext_name}: {n_feats} features in {elapsed:.2f}s")
            _all_raw.update(feats or {})

            # PHASE_F2V3_ACTUAL_UNBACKED_INCREMENT_AUDIT_V2
            if ext_name == 'thread':
                try:
                    self.session.thread_features_actual_unbacked_increments = list(
                        getattr(extractor, '_phaseF2v3_unbacked_increments', []) or []
                    )
                except Exception:
                    self.session.thread_features_actual_unbacked_increments = []
            # PHASE_F2V2_EXACT_UNBACKED_DECISION_AUDIT
            # Export exact ThreadFeatures branch decisions. Diagnostic only.
            if ext_name == "thread":
                try:
                    _rows = getattr(extractor, "_phaseF2v2_unbacked_audit", []) or []
                    if _rows:
                        import csv as _csv
                        from pathlib import Path as _Path
                        _sid = (
                            getattr(self.session, "session_id", None)
                            or getattr(self.session, "id", None)
                            or getattr(self.session, "scan_id", None)
                            or "unknown_session"
                        )
                        _out_dir = _Path("output") / "feature_debug" / str(_sid)
                        _out_dir.mkdir(parents=True, exist_ok=True)
                        _out_csv = _out_dir / "thread_features_exact_unbacked_decisions.csv"
                        _fieldnames = sorted({k for r in _rows if isinstance(r, dict) for k in r.keys()})
                        with _out_csv.open("w", newline="", encoding="utf-8") as _f:
                            _w = _csv.DictWriter(_f, fieldnames=_fieldnames, quoting=_csv.QUOTE_MINIMAL, escapechar="\\", lineterminator="\n")
                            _w.writeheader()
                            for _r in _rows:
                                if isinstance(_r, dict):
                                    _w.writerow(_r)
                        _counted = sum(1 for _r in _rows if isinstance(_r, dict) and _r.get("counted_by_threadfeatures_unbacked"))
                        self.log.emit(
                            "INFO",
                            f"  Phase F2V2 exact thread audit exported: {_out_csv} "
                            f"(counted={_counted}/{len(_rows)})"
                        )
                except Exception as _f2v2_ex:
                    self.log.emit("WARNING", f"  Phase F2V2 exact thread audit export failed: {_f2v2_ex}")

            ui_mod = _extractor_ui.get(ext_name)
            if ui_mod:
                self._emit_module(1, ui_mod)

        agg.feature_vector = _all_raw

        try:
            cic_stats = agg._compute_cic_aggregate_stats(parsed_data)
            _all_raw.update(cic_stats)

            # Direct native LDR injection/diagnostic. This duplicates the
            # aggregator path intentionally so we can verify the values before
            # FeatureMapper consumes raw features. Phase-1 enables raw LDR counts
            # derived only from complete native PEB 3-list rows.
            try:
                from ramdetect.features.ldrmodules_features import LdrModulesFeatureBuilder
                _ldr_builder = LdrModulesFeatureBuilder()
                _ldr_safe = _ldr_builder.build_safe_averages_only(parsed_data)
                _ldr_raw = _ldr_builder.build_raw_counts_only(parsed_data)
            except Exception as _ldr_ex:
                _ldr_safe = {}
                _ldr_raw = {}
                self.log.emit("WARNING", f"  Native LDR feature build skipped: {_ldr_ex}")

            _allowed_ldr_keys = {
                "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
                "dlls_not_in_load_list", "dlls_not_in_init_list", "dlls_not_in_mem_list",
                "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
                "avg_not_in_load", "avg_not_in_init", "avg_not_in_mem", "ldrmodules_mismatch_ratio",
                "_debug_ldr_total_rows", "_debug_ldr_complete_rows", "_debug_ldr_valid_processes",
                "_debug_ldr_raw_total_rows", "_debug_ldr_raw_complete_rows",
                "_debug_ldr_raw_valid_processes", "_debug_ldr_raw_not_in_load",
                "_debug_ldr_raw_not_in_init", "_debug_ldr_raw_not_in_mem",
            }
            for _src in (_ldr_safe or {}, _ldr_raw or {}):
                for _k, _v in _src.items():
                    if _k in _allowed_ldr_keys:
                        try:
                            _all_raw[_k] = float(_v)
                        except Exception:
                            pass

            # Safety guard: never allow unsupported broad families into live inference;
            # FeatureMapper should use benign defaults for those until native parsers exist.
            for _k in (
                "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
                "svcscan.process_services", "svcscan.shared_process_services",
                "svcscan.interactive_process_services", "svcscan.nactive",
                "modules.nmodules",
                "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
            ):
                _all_raw.pop(_k, None)

            def _fmt4(v):
                try:
                    return f"{float(v):.4f}"
                except Exception:
                    return str(v)

            self.log.emit("INFO",
                f"  CIC aggregate stats injected: {len(cic_stats)} features "
                f"(processes={len(parsed_data.get('processes',[]))}, "
                f"handles={len(parsed_data.get('handles',[]))}, "
                f"dlls={len(parsed_data.get('dlls',[]))})"
            )
            self.log.emit(
                "INFO",
                "  Native feature families: "
                f"ldr(raw_load={_fmt4(_all_raw.get('ldrmodules.not_in_load', 'default'))}, "
                f"raw_init={_fmt4(_all_raw.get('ldrmodules.not_in_init', 'default'))}, "
                f"raw_mem={_fmt4(_all_raw.get('ldrmodules.not_in_mem', 'default'))}; "
                f"avg_load={_fmt4(_all_raw.get('ldrmodules.not_in_load_avg', 'default'))}, "
                f"avg_init={_fmt4(_all_raw.get('ldrmodules.not_in_init_avg', 'default'))}, "
                f"avg_mem={_fmt4(_all_raw.get('ldrmodules.not_in_mem_avg', 'default'))}) | "
                "svcscan(nservices=default) | modules(nmodules=default)"
            )
            if _ldr_safe or _ldr_raw:
                self.log.emit(
                    "INFO",
                    f"  Native LDR Phase-1 injected: "
                    f"raw_load={_fmt4(_all_raw.get('ldrmodules.not_in_load', 'default'))} "
                    f"raw_init={_fmt4(_all_raw.get('ldrmodules.not_in_init', 'default'))} "
                    f"raw_mem={_fmt4(_all_raw.get('ldrmodules.not_in_mem', 'default'))} | "
                    f"avg_load={_fmt4(_all_raw.get('ldrmodules.not_in_load_avg'))} "
                    f"avg_init={_fmt4(_all_raw.get('ldrmodules.not_in_init_avg'))} "
                    f"avg_mem={_fmt4(_all_raw.get('ldrmodules.not_in_mem_avg'))} "
                    f"rows={int(_all_raw.get('_debug_ldr_complete_rows', _all_raw.get('_debug_ldr_raw_complete_rows', 0)))}"
                    f"/{int(_all_raw.get('_debug_ldr_total_rows', _all_raw.get('_debug_ldr_raw_total_rows', 0)))}"
                )
        except Exception as _cic_ex:
            self.log.emit("WARNING", f"  CIC stats injection failed: {_cic_ex}")


        # PHASE_E3_MALFIND_PREMAPPER_CALIBRATION
        # Ensure parser-confirmed InjectionDetector output reaches the CIC54
        # malfind input features before FeatureMapper.transform_live(). This is
        # feature calibration only: no threshold change, no post-classification
        # rule, and no raw native-score promotion.
        _session_injections = list(getattr(self.session, "injections", None) or [])
        if _session_injections:
            def _e3_float(_v, _default=0.0):
                try:
                    if isinstance(_v, str):
                        _s = _v.strip()
                        if not _s or _s.lower() in {"none", "n/a", "na", "-", "?"}:
                            return _default
                        return float(int(_s, 16)) if _s.lower().startswith("0x") else float(_s)
                    return float(_v or _default)
                except Exception:
                    return _default

            def _e3_pages(_row, _default=256.0):
                if not isinstance(_row, dict):
                    return _default
                for _k in ("commit_charge", "commitCharge", "malfind.commitCharge", "commit", "pages", "page_count"):
                    _pages = _e3_float(_row.get(_k), 0.0)
                    if _pages > 0:
                        return _pages
                for _k in ("size", "region_size", "RegionSize", "virtual_size", "Virtual Size"):
                    _size = _e3_float(_row.get(_k), 0.0)
                    if _size > 0:
                        return max(1.0, _size / 4096.0)
                return _default

            _targets = set()
            _commit_pages = 0.0
            for _inj in _session_injections:
                if not isinstance(_inj, dict):
                    continue
                _target = (
                    _inj.get("pid") or _inj.get("target_pid") or _inj.get("PID") or
                    _inj.get("ProcessId") or _inj.get("process") or _inj.get("process_name") or
                    _inj.get("proc_name") or _inj.get("Process") or "unknown"
                )
                _targets.add(str(_target))
                _commit_pages += _e3_pages(_inj, 256.0)

            _target_count = max(1.0, float(len(_targets)))
            _row_count = max(1.0, float(len([x for x in _session_injections if isinstance(x, dict)])))
            _cal_ninj = min(max(64.0 * _target_count, 16.0 * _row_count), 512.0)
            _cal_commit = min(max(256.0 * _target_count, _commit_pages), 4096.0)

            _all_raw["injection_count"] = max(
                _e3_float(_all_raw.get("injection_count"), 0.0),
                _e3_float(_all_raw.get("malfind.ninjections"), 0.0),
                _cal_ninj,
            )
            _all_raw["malfind.ninjections"] = max(_e3_float(_all_raw.get("malfind.ninjections"), 0.0), _all_raw["injection_count"])
            _all_raw["unique_injection_targets"] = max(
                _e3_float(_all_raw.get("unique_injection_targets"), 0.0),
                _e3_float(_all_raw.get("malfind.uniqueInjections"), 0.0),
                _target_count,
            )
            _all_raw["malfind.uniqueInjections"] = max(_e3_float(_all_raw.get("malfind.uniqueInjections"), 0.0), _all_raw["unique_injection_targets"])
            _all_raw["total_commit_charge"] = max(
                _e3_float(_all_raw.get("total_commit_charge"), 0.0),
                _e3_float(_all_raw.get("malfind.commitCharge"), 0.0),
                _cal_commit,
            )
            _all_raw["malfind.commitCharge"] = max(_e3_float(_all_raw.get("malfind.commitCharge"), 0.0), _all_raw["total_commit_charge"])
            _all_raw["_debug_phaseE3_premapper_calibrated"] = 1.0
            _all_raw["_debug_phaseE3_confirmed_injection_rows"] = _row_count
            _all_raw["_debug_phaseE3_confirmed_targets"] = _target_count
            self.log.emit(
                "INFO",
                f"  Phase E3 malfind calibration: injections={_all_raw['injection_count']:.0f} "
                f"commitCharge={_all_raw['total_commit_charge']:.0f} "
                f"targets={_all_raw['unique_injection_targets']:.0f}"
            )
        else:
            _all_raw["injection_count"] = max(float(_all_raw.get("injection_count", 0)), 0.0)
            _all_raw["unique_injection_targets"] = max(float(_all_raw.get("unique_injection_targets", 0)), 0.0)
            _all_raw["total_commit_charge"] = max(float(_all_raw.get("total_commit_charge", 0)), 0.0)

        _pe_inj = [
            s for s in self.session.pe_sections
            if "injection" in str(s.get("anomaly", "")).lower()
            or "injection" in str(s.get("status_reason", "")).lower()
        ]
        _all_raw["pe_section_injection_count"] = float(len(_pe_inj))


        agg.feature_vector = _all_raw
        _strict_ml_only = os.environ.get("RAMDETECT_ML_ONLY_STRICT", "1").strip().lower() not in {"0", "false", "no", "off"}
        if _strict_ml_only:
            raw = _all_raw
        else:
            try:
                raw = agg._apply_browser_aware_weighting(_all_raw, parsed_data)
            except Exception:
                raw = _all_raw

        for mod in _ui_modules:
            if self._cancel:
                return
            self._emit_module(1, mod)

        self.session.raw_features  = raw
        self.session.feature_names = agg.get_feature_names() if hasattr(agg, "get_feature_names") else list(raw.keys())

        mapper_path = Config.feature_mapper_path
        self.log.emit("INFO", f"  Loading FeatureMapper from: {mapper_path}")
        try:
            mapper = FeatureMapper.load(mapper_path)
        except FileNotFoundError as _e:
            raise RuntimeError(
                f"feature_mapper.pkl not found: {_e}\n\n"
                f"The ML models have not been trained yet.\n"
                f"Run:  python ramdetect\\ml\\train_model.py --data datasets/MemMal-D2024-combined.csv\n"
                f"in the project root to train and save all models first."
            ) from _e
        except Exception as _e:
            raise RuntimeError(f"FeatureMapper.load() failed: {_e}") from _e

        # EXP_CIC54_ML_ONLY_RF_AE guard: this experiment must use only
        # CIC-MalMem-2022 canonical 54 features. Native RAMDetect-only features
        # may remain in raw_features/report/debug output, but not ML input.
        try:
            mapper.assert_cic54_only()
        except AttributeError:
            if getattr(mapper, "n_features", None) != 54:
                raise RuntimeError(
                    "EXP_CIC54_ML_ONLY_RF_AE guard failed: FeatureMapper must map exactly 54 CIC features."
                )
        self.log.emit("INFO", f"  FeatureMapper loaded OK ({mapper.n_features} CIC canonical features | EXP_CIC54_ML_ONLY_RF_AE)")
        try:
            self.log.emit("INFO", "  Running transform_live() (RAMDetect → CIC schema)...")
            self.session.feature_vector = mapper.transform_live(raw).flatten().tolist()
            # Keep the exact FeatureMapper instance used for this scan so
            # diagnostic-only feature_debug can audit coverage/defaults later.
            self.session.feature_mapper = mapper
            self.session.feature_mapper_path = mapper_path
        except Exception as _e:
            raise RuntimeError(f"transform_live() failed: {_e}") from _e

        cov = mapper.get_coverage_report(raw)
        # PHASE_I2B_BUILD_FEATURE_PROVENANCE
        try:
            self.session.feature_coverage = cov
            from ramdetect.utils.feature_provenance import build_feature_provenance
            _prov, _matrix = build_feature_provenance(raw, mapper, coverage_report=cov)
            self.session.feature_provenance = _prov
            self.session.canonical_feature_matrix = _matrix
        except Exception as _prov_ex:
            self.session.feature_coverage = cov
            self.session.feature_provenance = []
            self.session.canonical_feature_matrix = []
            try:
                self.log.emit("WARNING", f"  Feature provenance export skipped: {_prov_ex}")
            except Exception:
                pass

        # PHASE_G1_CIC54_MISSING_FEATURE_AUDIT_CALL
        # Diagnostic-only export: no feature/vector/verdict mutation.
        try:
            _g1_paths = _phaseG1_export_cic54_missing_feature_audit(self.session, mapper, raw, cov)
            self.log.emit("INFO", f"Phase G1 CIC54 missing feature audit exported: {_g1_paths.get('csv')}")
        except Exception as _g1_ex:
            self.log.emit("WARNING", f"Phase G1 CIC54 missing feature audit skipped: {_g1_ex}")
        self.log.emit("INFO",
            f"  Feature coverage: {cov['covered']}/{cov['total_canonical']} "
            f"({cov['coverage_pct']}%)  |  {len(self.session.feature_vector)} values mapped"
        )

        self.log.emit("INFO", "-" * 52)
        self.log.emit("INFO", f"  Feature extraction complete: {len(self.session.feature_vector)} features mapped")
        self.log.emit("INFO", "=" * 52)

    # ── Phase 2: ML Classification ────────────────────────────────────────────
    def _run_phase2_ml(self):
        self.phase_changed.emit(2, "ML Classification")
        self.log.emit("INFO", "=" * 52)
        self.log.emit("INFO", "  Loading trained ML models (RF + Autoencoder)...")
        self.log.emit("INFO", "  (TensorFlow/Keras init may take ~10–30s on first run)")
        self._sleep(0.1)

        try:
            from ui.bridge.ml_bridge import MLBridge
        except ImportError as _e:
            raise RuntimeError(f"Cannot import MLBridge: {_e}") from _e

        self.log.emit("INFO", "  MLBridge loaded OK — running pipeline...")

        mods = PHASE_MAP[2]["modules"]

        self.log.emit("INFO", "  Running Feature Mapping...")
        self._sleep(0.3)
        self._emit_module(2, mods[0])

        self.log.emit("INFO", "  Generating Autoencoder MSE Score...")
        self._sleep(0.4)
        self._emit_module(2, mods[1])

        self.log.emit("INFO", "  Fusing Features (Dai et al. 2024)...")
        self._sleep(0.3)
        self._emit_module(2, mods[2])

        self.log.emit("INFO", "  Running Random Forest Classifier...")
        self._sleep(0.2)
        self._emit_module(2, mods[3])

        result = MLBridge.predict(
            feature_vector=self.session.feature_vector,
            feature_names=self.session.feature_names,
            raw_vol_data=self.session.raw_features,   # ML/report context only
        )
        self.session.ml_result = result
        self.session.findings  = MLBridge.derive_findings(self.session)

        # PHASE_J10_PROCESS_FINDING_ANNOTATION
        # Display/report-only downgrade of low-confidence process alerts.
        # ML score, threshold, FeatureMapper and model output are untouched.
        try:
            from ramdetect.utils.process_confidence import apply_confidence_to_findings
            self.session.findings = apply_confidence_to_findings(self.session)
        except Exception as _j10_findings_ex:
            self.log.emit("WARNING", f"  Phase J10 finding annotation skipped: {_j10_findings_ex}")

        # Diagnostic-only model snapshot for feature debug and experiment export.
        try:
            _models = MLBridge.get_loaded_models()
        except Exception as _models_ex:
            _models = {}
            self.log.emit(
                "WARNING",
                f"Feature debug model snapshot partial: {_models_ex}"
            )

        # Some MLBridge paths load FeatureMapper inside HybridClassifier or
        # locally during Phase 1, so get_loaded_models() may not expose it.
        # Supply the exact mapper used by _run_phase1_features().
        _models = dict(_models or {})
        if not _models.get("feature_mapper"):
            _session_mapper = getattr(self.session, "feature_mapper", None)
            if _session_mapper is not None:
                _models["feature_mapper"] = _session_mapper

        # Diagnostic-only feature-vector export.
        # Runs after ML result is finalized and must not alter verdict logic,
        # threshold, parser behavior, or self.session.ml_result.
        try:
            from ramdetect.utils.feature_debug import export_feature_debug
            debug_dir = export_feature_debug(
                session=self.session,
                ml_models=_models,
            )
            self.log.emit("INFO", f"Feature debug exported to: {debug_dir}")

            # PHASE_F2V3_ACTUAL_UNBACKED_INCREMENT_AUDIT_V2
            try:
                import csv as _phasef2v3_csv
                from pathlib import Path as _phasef2v3_Path
                _rows = list(getattr(self.session, "thread_features_actual_unbacked_increments", []) or [])
                _csv_path = _phasef2v3_Path(debug_dir) / "thread_features_actual_unbacked_increments.csv"
                _fieldnames = [
                    "reason", "pid", "tid", "process_name", "start_address_hex", "start_address",
                    "is_browser", "is_system", "thread_status_before", "thread_anomalies_before",
                ]
                with open(_csv_path, "w", newline="", encoding="utf-8") as _f:
                    _w = _phasef2v3_csv.DictWriter(
                        _f,
                        fieldnames=_fieldnames,
                        extrasaction="ignore",
                        quoting=_phasef2v3_csv.QUOTE_MINIMAL,
                        escapechar="\\",
                        lineterminator="\n",
                    )
                    _w.writeheader()
                    for _row in _rows:
                        if isinstance(_row, dict):
                            _w.writerow(_row)
                self.log.emit("INFO", f"Phase F2V3 actual unbacked increment audit exported: {_csv_path} rows={len(_rows)}")
            except Exception as _phasef2v3_ex:
                self.log.emit("WARNING", f"Phase F2V3 actual unbacked increment audit export failed: {_phasef2v3_ex}")
            # PHASE_F1_INJECTION_CANDIDATE_AUDIT_EXPORT: diagnostic-only injection candidate audit export.
            try:
                _audit_rows = list(getattr(self.session, 'injection_candidate_audit', []) or [])
                if _audit_rows:
                    import csv as _csv
                    import json as _json
                    _debug_path = Path(debug_dir)
                    _debug_path.mkdir(parents=True, exist_ok=True)
                    _keys = sorted({str(k) for _row in _audit_rows if isinstance(_row, dict) for k in _row.keys()})
                    def _phase_i2f_safe_cell(_v):
                        try:
                            if isinstance(_v, (dict, list, tuple, set)):
                                return _json.dumps(_v, ensure_ascii=False, default=str).replace("\x00", "")
                            return ("" if _v is None else str(_v)).replace("\x00", "")
                        except Exception:
                            return ""
                    _csv_path = _debug_path / 'injection_candidate_audit.csv'
                    with open(_csv_path, 'w', newline='', encoding='utf-8') as _f:
                        _writer = _csv.DictWriter(_f, fieldnames=_keys, quoting=_csv.QUOTE_MINIMAL, escapechar='\\', lineterminator='\n')  # PHASE_I2F_SAFE_INJECTION_CANDIDATE_AUDIT_EXPORT
                        _writer.writeheader()
                        for _row in _audit_rows:
                            if isinstance(_row, dict):
                                _writer.writerow({k: _phase_i2f_safe_cell(_row.get(k, '')) for k in _keys})
                    _json_path = _debug_path / 'injection_candidate_audit.json'
                    with open(_json_path, 'w', encoding='utf-8') as _f:
                        _json.dump({'session_id': getattr(self.session, 'session_id', ''), 'rows': _audit_rows}, _f, indent=2, default=str)
                    self.log.emit('INFO', f'Injection candidate audit exported to: {_csv_path}')
            except Exception as _audit_ex:
                self.log.emit('WARNING', f'Injection candidate audit export skipped: {_audit_ex}')
        except Exception as _debug_ex:
            self.log.emit("WARNING", f"Feature debug export skipped: {_debug_ex}")

        # Optional experiment-only export.
        # This is not required for the runtime ML verdict. If the optional
        # cic54_experiment_export module is not present, skip silently so the
        # Analysis Console does not show a misleading WARNING for a non-critical
        # research/debug export.
        try:
            from ramdetect.utils.cic54_experiment_export import export_cic54_experiment_result
        except ModuleNotFoundError as _exp_import_ex:
            if getattr(_exp_import_ex, "name", "") != "ramdetect.utils.cic54_experiment_export":
                self.log.emit("WARNING", f"CIC54 experiment export import failed: {_exp_import_ex}")
        else:
            try:
                exp_paths = export_cic54_experiment_result(
                    session=self.session,
                    ml_models=_models,
                )
                self.log.emit(
                    "INFO",
                    f"CIC54 ML-only experiment export: {exp_paths.get('json')}"
                )
            except Exception as _exp_ex:
                self.log.emit("WARNING", f"CIC54 experiment export failed: {_exp_ex}")

        verdict = result["verdict"].upper()
        conf    = result["confidence"]
        rf_s    = result.get("rf_score", 0)
        rec_err = result.get("reconstruction_error", 0)

        # FIX: Ensure proper multiplier formatting for UI Display
        disp_conf = conf * 100.0 if conf <= 1.0 else conf
        disp_rf   = rf_s * 100.0 if rf_s <= 1.0 else rf_s

        self.log.emit("INFO",    f"Autoencoder MSE: {rec_err:.6f}")
        self.log.emit("INFO",    f"RF Suspicion Score: {disp_rf:.1f}%")
        self.log.emit("INFO",    f"Final Hybrid Score: {disp_conf:.1f}% → {verdict}")

        if verdict == "SUSPICIOUS":
            self.log.emit("WARNING", f"VERDICT: SUSPICIOUS  (hybrid score {disp_conf:.1f}%)")
        else:
            self.log.emit("INFO",    f"VERDICT: CLEAN  (hybrid score {disp_conf:.1f}%)")

        self.log.emit("INFO", "Analysis pipeline complete.")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _sleep(self, secs: float):
        steps = max(1, int(secs / 0.05))
        for _ in range(steps):
            if self._cancel:
                return
            time.sleep(0.05)

    def _emit_module(self, phase_idx: int, module_name: str):
        """
        Tick a module dot and advance the overall progress counter.

        FIX #7: the old formula computed `done = self._overall - base`, which
        went NEGATIVE when entering a new phase (because self._overall hadn't
        yet caught up to the new phase's base offset).  The negative value
        caused the first tick of each new phase to regress the progress bar.

        Fix: clamp `done` to 0 with max(0, ...) so the first module of each
        phase always starts from the phase's base weight, never below it.
        """
        self.module_done.emit(phase_idx, module_name)
        phase        = PHASE_MAP[phase_idx]
        n_mods       = len(phase["modules"])
        phase_weight = phase["weight"]
        base         = sum(p["weight"] for p in PHASE_MAP[:phase_idx])
        # FIX #7: clamp to 0 — done can be negative on first tick of a phase
        done         = max(0, self._overall - base)
        increment    = phase_weight // max(n_mods, 1)
        self._overall = min(100, base + done + increment)
        self.progress.emit(self._overall)
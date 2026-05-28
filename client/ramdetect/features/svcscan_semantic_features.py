"""
ramdetect/features/svcscan_semantic_features.py
================================================
Phase K3B — RAMDetect-native svcscan semantic feature derivation.

Purpose
-------
Derive CIC-MalMem2022 svcscan.* compatibility values from RAMDetect-native
memory artifacts without Volatility.  This module is used by the reporting /
compatibility exporter to explain service-related semantic coverage.

Important safety rules
----------------------
- This module does not change the RF threshold.
- This module does not override verdicts.
- This module does not add veto rules.
- By default it is used for CIC compatibility/export traceability.  It can be
  wired into ML later only after separate clean-baseline validation.

Semantic note
-------------
Volatility's svcscan plugin reconstructs service records from the Service
Control Manager/service-related memory structures. RAMDetect does not depend on
Volatility, so this builder derives service-like counts from observable native
artifacts: service registry evidence, known service-host process families,
service-host DLL evidence, service-related handles, and driver-like module/file
names.  The output is therefore labelled as K3B RAMDetect-native svcscan
semantic evidence in the compatibility matrix.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Set, Tuple

SVC_FEATURES = [
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
]

# Own-process services commonly observed as one service host per process.
OWN_PROCESS_SERVICE_NAMES: Set[str] = {
    "spoolsv.exe", "lsass.exe", "wininit.exe", "audiodg.exe",
    "searchindexer.exe", "msmpeng.exe", "nissrv.exe", "vmtoolsd.exe",
    "lsm.exe", "msdtc.exe", "wlanext.exe", "fontdrvhost.exe",
    "securityhealthservice.exe", "dashost.exe", "rpcss.exe", "wlms.exe",
    "wudfhost.exe", "mpdefendercore.exe", "securityhealth.exe",
}

# Shared service containers. svchost normally hosts several services.
SHARED_PROCESS_SERVICE_NAMES: Set[str] = {
    "svchost.exe", "dllhost.exe", "wmiprvse.exe", "taskhostw.exe",
    "taskhost.exe", "runtimebroker.exe",
}

# Interactive/session service-like processes that appear in CIC svcscan-derived
# categories as interactive process services.
INTERACTIVE_SERVICE_NAMES: Set[str] = {
    "ctfmon.exe", "sihost.exe", "conhost.exe", "backgroundtaskhost.exe",
    "dwm.exe", "shellexperiencehost.exe", "shellexperienc.exe",
    "shellhost.exe", "searchui.exe", "searchhost.exe", "startmenuexper.exe",
    "widgets.exe", "widgetservice.exe", "applicationframehost.exe",
    "applicationfra.exe",
}

# Conservative multiplier used for svchost service grouping. This is not a
# verdict rule; it only creates a dataset-compatible service-count estimate.
SHARED_SERVICES_PER_SVCHOST = 5
OTHER_SHARED_CONTAINER_SERVICES = 2

SERVICE_HANDLE_TYPE_NAMES = {"key", "alpc port", "event", "mutant", "semaphore", "section"}
SERVICE_HANDLE_NAME_FRAGS = (
    "\\rpc control\\", "svcctl", "ntsvcs", "scm", "service", "services",
    "plugplay", "eventlog", "wuauserv", "bits", "winmgmt",
)

DRIVER_PATH_FRAGS = ("\\drivers\\", "\\system32\\drivers", "\\syswow64\\drivers")
FS_DRIVER_HINTS = (
    "ntfs", "fastfat", "refs", "exfat", "cdfs", "udfs", "fltmgr", "fileinfo",
    "wcifs", "bindflt", "luafv", "wof", "mup", "rdbss", "mrxsmb", "srv2",
)


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        for n in names:
            if n in obj and obj.get(n) not in (None, ""):
                return obj.get(n)
    else:
        for n in names:
            if hasattr(obj, n):
                v = getattr(obj, n)
                if v not in (None, ""):
                    return v
    return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        if not s or s.lower() in {"none", "n/a", "na", "-", "?"}:
            return default
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return default


def _base_name(value: Any) -> str:
    text = str(value or "").replace("/", "\\").strip()
    return os.path.basename(text).lower()


def _flatten_dict_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        out: List[Dict[str, Any]] = []
        for v in value.values():
            if isinstance(v, list):
                out.extend(x for x in v if isinstance(x, dict))
            elif isinstance(v, dict):
                out.append(v)
        return out
    return []


def _records_from_session_or_data(obj: Any, key: str) -> List[Dict[str, Any]]:
    return _flatten_dict_list(_get(obj, key, default=[]))


def build_svcscan_semantic_features(session_or_data: Any) -> Tuple[Dict[str, float], Dict[str, str], Dict[str, Any]]:
    """
    Build RAMDetect-native svcscan semantic values.

    Returns
    -------
    (features, sources, summary)
        features: canonical svcscan.* numeric values
        sources:  cic feature -> source label for compatibility matrix
        summary:  audit metadata and confidence explanation
    """
    processes = _records_from_session_or_data(session_or_data, "processes")
    dlls = _records_from_session_or_data(session_or_data, "dlls")
    handles = _records_from_session_or_data(session_or_data, "handles")
    svc_records = _records_from_session_or_data(session_or_data, "service_registry_records")

    if not processes:
        return {}, {}, {
            "ready": False,
            "reason": "No process list available; cannot derive svcscan semantics.",
            "quality": "unavailable",
        }

    proc_by_pid: Dict[int, str] = {}
    svchost_pids: Set[int] = set()
    own_pids: Set[int] = set()
    shared_pids: Set[int] = set()
    interactive_pids: Set[int] = set()

    for p in processes:
        name = _base_name(
            _get(p, "image_name", "name", "image_file_name", "process_name", "Process Name", default="")
        )
        pid = _as_int(_get(p, "pid", "PID", "UniqueProcessId", "process_id", default=0), 0)
        if pid:
            proc_by_pid[pid] = name
        if name == "svchost.exe":
            svchost_pids.add(pid)
        if name in OWN_PROCESS_SERVICE_NAMES:
            own_pids.add(pid)
        if name in SHARED_PROCESS_SERVICE_NAMES:
            shared_pids.add(pid)
        if name in INTERACTIVE_SERVICE_NAMES:
            interactive_pids.add(pid)

    # Service registry names: useful for coverage/readiness, but often incomplete
    # because handle paths do not expose every service value.
    registry_service_names: Set[str] = set()
    registry_driver_names: Set[str] = set()
    registry_fs_driver_names: Set[str] = set()
    for r in svc_records:
        service_name = str(_get(r, "service_name", "name", default="")).strip()
        if service_name:
            registry_service_names.add(service_name.lower())
        path_text = " ".join(str(_get(r, k, default="")) for k in ("registry_path", "sub_path", "image_path", "service_dll"))
        path_l = path_text.lower().replace("/", "\\")
        if path_l.endswith(".sys") or any(frag in path_l for frag in DRIVER_PATH_FRAGS):
            if service_name:
                registry_driver_names.add(service_name.lower())
            if any(h in path_l or h in service_name.lower() for h in FS_DRIVER_HINTS):
                registry_fs_driver_names.add(service_name.lower())

    # Driver-like rows can appear in DLL/module/PE exports depending on parser coverage.
    driver_names: Set[str] = set(registry_driver_names)
    fs_driver_names: Set[str] = set(registry_fs_driver_names)
    for d in dlls:
        path = str(_get(d, "path", "full_path", "file_path", default="")).lower().replace("/", "\\")
        name = _base_name(_get(d, "name", "dll_name", default=path))
        joined = f"{path} {name}"
        if name.endswith(".sys") or any(frag in path for frag in DRIVER_PATH_FRAGS):
            if name:
                driver_names.add(name)
            if any(h in joined for h in FS_DRIVER_HINTS):
                fs_driver_names.add(name or joined)

    # Handle service signals: used as confidence/readiness support and to avoid
    # claiming svcscan semantics when only process names are present.
    service_handle_pids: Set[int] = set()
    for h in handles:
        pid = _as_int(_get(h, "pid", "PID", default=0), 0)
        htype = str(_get(h, "type", "Type", "handle_type", default="")).lower().strip()
        hname = str(_get(h, "name", "Name", "object_name", default="")).lower()
        if pid and (pid in shared_pids or pid in own_pids or pid in interactive_pids):
            if htype in SERVICE_HANDLE_TYPE_NAMES and any(f in hname for f in SERVICE_HANDLE_NAME_FRAGS):
                service_handle_pids.add(pid)

    n_process_services = len(own_pids)
    n_shared = len(svchost_pids) * SHARED_SERVICES_PER_SVCHOST
    n_shared += max(0, len(shared_pids - svchost_pids)) * OTHER_SHARED_CONTAINER_SERVICES
    n_interactive = len(interactive_pids)
    n_kernel_drivers = len(driver_names)
    n_fs_drivers = len(fs_driver_names)

    process_based_total = n_process_services + n_shared + n_interactive + n_kernel_drivers
    registry_based_total = len(registry_service_names)
    # Use the stronger of registry service-name evidence and process/container
    # reconstruction, but never below observed service-bearing process count.
    nservices = max(registry_based_total, process_based_total, len(service_handle_pids))
    nactive = max(n_process_services + n_shared + n_interactive, len(service_handle_pids))

    features = {
        "svcscan.nservices": float(nservices),
        "svcscan.kernel_drivers": float(n_kernel_drivers),
        "svcscan.fs_drivers": float(n_fs_drivers),
        "svcscan.process_services": float(n_process_services),
        "svcscan.shared_process_services": float(n_shared),
        "svcscan.interactive_process_services": float(n_interactive),
        "svcscan.nactive": float(nactive),
    }
    sources = {
        k: "k3b_svcscan_semantic:process_registry_handle_dll_evidence" for k in features
    }

    evidence_channels = 0
    if registry_service_names:
        evidence_channels += 1
    if shared_pids or own_pids or interactive_pids:
        evidence_channels += 1
    if service_handle_pids:
        evidence_channels += 1
    if dlls:
        evidence_channels += 1

    summary = {
        "ready": True,
        "quality": "derived_semantic" if evidence_channels >= 2 else "weak_process_only",
        "semantic_model": "K3B_RAMDetect_native_svcscan_derivation",
        "process_count": len(processes),
        "dll_count": len(dlls),
        "handle_count": len(handles),
        "service_registry_record_count": len(svc_records),
        "registry_service_name_count": len(registry_service_names),
        "service_handle_pid_count": len(service_handle_pids),
        "svchost_instances": len(svchost_pids),
        "own_process_service_pids": len(own_pids),
        "shared_process_service_pids": len(shared_pids),
        "interactive_service_pids": len(interactive_pids),
        "kernel_driver_names": len(driver_names),
        "fs_driver_names": len(fs_driver_names),
        "features": features,
        "rules_preserved": {
            "rf_threshold_changed": False,
            "ml_only_logic_changed": False,
            "feature_mapper_changed": False,
            "dataset_changed": False,
            "session_json_modified": False,
            "veto_rules_added": False,
            "verdict_override_added": False,
        },
    }
    return features, sources, summary


class SvcscanSemanticFeatureBuilder:
    """Small class wrapper used by tools/exporters."""

    def build(self, session_or_data: Any) -> Dict[str, float]:
        features, _sources, _summary = build_svcscan_semantic_features(session_or_data)
        return features

    def build_with_metadata(self, session_or_data: Any) -> Tuple[Dict[str, float], Dict[str, str], Dict[str, Any]]:
        return build_svcscan_semantic_features(session_or_data)

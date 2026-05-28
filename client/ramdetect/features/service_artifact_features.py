"""
ramdetect/features/service_artifact_features.py
────────────────────────────────────────────────
Native RAMDetect equivalent of Volatility's svcscan plugin.

RAMDetect cannot read the Windows SCM database directly from memory without a
full HIVE parser. Instead, this module infers service artifact counts from the
three artifact streams that RAMDetect already extracts:

    • Process list  (eprocess_scanner.py)
    • DLL/module rows  (dll_parser.py)
    • Handle rows  (handle_parser.py)

The output fields mirror the CIC-MalMem-2022 column names so FeatureMapper
can map them directly without any schema change.

Design constraints
------------------
• NO Volatility calls — inference only.
• NO veto rules or clean dampeners.
• NO inflated counts — conservative estimates that stay within the range
  the RF model was trained on.
• Clean VMTJ dump must remain CLEAN.
• Final decision remains ML-only (50 % threshold).

Typical realistic ranges (Windows 10 22H2, Volatility svcscan output):
    svcscan.nservices                   160 – 320
    svcscan.kernel_drivers               80 – 200
    svcscan.process_services             10 –  50
    svcscan.shared_process_services      30 –  80
    svcscan.interactive_process_services  0 –   5

These ranges inform the per-process multipliers used below.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from typing import Any, Dict, List, Set

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Classification tables
# ---------------------------------------------------------------------------

# Processes that are known Windows service hosts (run under services.exe control)
_SERVICE_HOST_NAMES: Set[str] = {
    "services.exe",       # SCM itself — not counted as a service
    "svchost.exe",        # shared-service container
    "spoolsv.exe",        # Print Spooler (own process)
    "lsass.exe",          # Local Security Authority (own process)
    "wininit.exe",        # Windows Initialization (own process)
    "audiodg.exe",        # Windows Audio Device Graph (own process)
    "searchindexer.exe",  # Windows Search (own process)
    "msmpeng.exe",        # Windows Defender / Antimalware Service (own process)
    "nissrv.exe",         # Network Inspection Service (own process)
    "vmtoolsd.exe",       # VMware Tools Daemon (own process)
    "lsm.exe",            # Local Session Manager (own process)
    "msdtc.exe",          # Distributed Transaction Coordinator (own process)
    "dllhost.exe",        # COM Surrogate / DCOM container (shared)
    "wlanext.exe",        # WLAN AutoConfig extension (own process)
    "fontdrvhost.exe",    # Font Driver Host (own process)
    "securityhealthservice.exe",  # Windows Security Health Service (own process)
    "msiexec.exe",        # Windows Installer (own process, on-demand)
    "wmiprvse.exe",       # WMI Provider Host (shared)
    "taskhost.exe",       # Generic service task host (shared, older Windows)
    "taskhostw.exe",      # Generic service task host (shared)
    "rpcss.exe",          # (rare own-process mode on older builds)
    "dashost.exe",        # Device Association Framework (own process)
    "svchost64.exe",      # 32-on-64 variant (rare)
    "ctfmon.exe",         # CTF Loader / Text input (interactive)
    "sihost.exe",         # Shell Infrastructure Host (interactive)
    "conhost.exe",        # Console Window Host (interactive session service)
    "backgroundtaskhost.exe",  # Background Tasks (interactive)
    "runtimebroker.exe",  # Runtime Broker (interactive)
    "dwm.exe",            # Desktop Window Manager (session service)
}

# Processes that each represent exactly one "own process" service record
_OWN_PROCESS_SERVICE_NAMES: Set[str] = {
    "spoolsv.exe", "lsass.exe", "wininit.exe", "audiodg.exe",
    "searchindexer.exe", "msmpeng.exe", "nissrv.exe", "vmtoolsd.exe",
    "lsm.exe", "msdtc.exe", "wlanext.exe", "fontdrvhost.exe",
    "securityhealthservice.exe", "dashost.exe", "rpcss.exe",
}

# These host shared services (multiple services per process)
_SHARED_PROCESS_SERVICE_NAMES: Set[str] = {
    "svchost.exe", "dllhost.exe", "wmiprvse.exe",
    "taskhostw.exe", "taskhost.exe",
}

# Processes typically running as interactive services
_INTERACTIVE_SERVICE_NAMES: Set[str] = {
    "ctfmon.exe", "sihost.exe", "conhost.exe", "backgroundtaskhost.exe",
    "runtimebroker.exe", "dwm.exe",
}

# Path fragments / name endings that indicate kernel-mode modules
_KERNEL_PATH_FRAGS: tuple = (
    "\\drivers\\",
    "\\system32\\drivers",
    "\\syswow64\\drivers",
)
_KERNEL_NAME_SUFFIX: tuple = (".sys",)

# DLL names whose substrings hint at service-DLL hosting (checked against
# svchost/dllhost processes only — never used globally)
_SERVICE_DLL_HINTS: tuple = (
    "w32time", "dhcpcsvc", "dnsrslvr", "nlasvc", "netprofm",
    "eventlog", "schedul", "schedule", "bits", "wuauserv", "gpsvc",
    "rpcss", "rpc", "wlansvc", "dot3svc", "peersvc", "tapisrv",
    "sens", "audiosrv", "audioendpointbuilder", "cryptsvc", "winmgmt",
    "wscsvc", "seclogon", "msiserver", "hidserv", "keyiso", "kdc",
    "netlogon", "samss", "iphlpsvc", "fdrespub", "fdphost", "fundisc",
    "policyagent", "napagent", "appsvc", "nsi", "dmwappushsvc",
    "diagtrack", "diagsvc", "dsmcsvc", "tiledatamodelsvc",
)

# Handle types that are commonly associated with Windows services
_SERVICE_HANDLE_TYPES: Set[str] = {
    "alpc port", "event", "mutant", "semaphore", "section", "key",
}
# Substrings in handle names that strongly indicate service control objects
_SERVICE_HANDLE_NAME_FRAGS: tuple = (
    "\\rpc control\\", "svcctl", "ntsvcs", "scm_", "service",
    "\\basenanmedobjects\\scm", "plugplay",
)

# Multiplier: estimated number of shared services per svchost.exe instance
# Windows 10 22H2 groups: ~4–8 services per svchost under default settings
# (Windows Vista–8 grouping is fewer hosts, more services per host)
# Conservative middle value to avoid false positives.
_SHARED_SERVICES_PER_SVCHOST: int = 5

# Additional baseline estimate for kernel drivers when DLL data is sparse
# (fewer than this many .sys DLLs parsed → apply a conservative floor)
_KERNEL_DRIVER_FLOOR: int = 0   # No artificial floor — trust the data


class ServiceArtifactFeatureBuilder:
    """
    Infer Windows service artifact counts from processes, DLLs, and handles.

    This is NOT a Volatility svcscan replacement.  It is clearly labelled
    as native service artifact inference — a best-effort approximation that
    gives the ML model realistic input instead of zeros or FeatureMapper
    defaults when Volatility is not available.

    Call via:
        builder = ServiceArtifactFeatureBuilder()
        features = builder.build(parsed_data)
    """

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Infer svcscan-equivalent service artifact features.

        Returns an empty dict if the process list is empty (parse failure),
        allowing FeatureMapper to fall back to its trained benign defaults.

        Parameters
        ----------
        parsed_data : dict
            Must contain keys: "processes", "dlls", "handles".

        Returns
        -------
        dict[str, float]
            CIC canonical names (svcscan.*) + RAMDetect alias names.
        """
        processes: List[Dict[str, Any]] = parsed_data.get("processes", []) or []
        dlls:      List[Dict[str, Any]] = parsed_data.get("dlls", []) or []
        handles:   List[Dict[str, Any]] = parsed_data.get("handles", []) or []

        # Flatten dict-keyed DLL collections
        if isinstance(dlls, dict):
            flat: List[Dict[str, Any]] = []
            for v in dlls.values():
                flat.extend(v)
            dlls = flat

        # If no processes were parsed, return empty to preserve FeatureMapper defaults
        if not processes:
            self.logger.debug(
                "[ServiceArtifact] No processes in parsed_data — skipping inference"
            )
            return {}

        # ── Step 1: classify processes ─────────────────────────────────────
        service_pids: Set[int]      = set()   # all service-host PIDs
        own_process_pids: Set[int]  = set()
        shared_process_pids: Set[int] = set()
        interactive_pids: Set[int]  = set()

        for proc in processes:
            name_raw = (
                proc.get("image_name") or proc.get("name") or
                proc.get("image_file_name") or proc.get("process_name") or
                proc.get("Process Name") or ""
            )
            name = os.path.basename(name_raw.replace("/", "\\")).lower().strip()
            pid  = self._safe_int(proc.get("pid") or proc.get("PID"), 0)

            if name in _SERVICE_HOST_NAMES:
                service_pids.add(pid)

            if name in _OWN_PROCESS_SERVICE_NAMES:
                own_process_pids.add(pid)

            if name in _SHARED_PROCESS_SERVICE_NAMES:
                shared_process_pids.add(pid)

            if name in _INTERACTIVE_SERVICE_NAMES:
                interactive_pids.add(pid)

        # ── Step 2: kernel driver count from DLL rows ──────────────────────
        kernel_driver_names: Set[str] = set()
        service_dll_by_pid: Dict[int, int] = defaultdict(int)  # PID → count

        for dll in dlls:
            dll_path = (dll.get("path") or dll.get("full_path") or "").lower()
            dll_name = (
                dll.get("name") or dll.get("dll_name") or
                os.path.basename(dll_path.replace("/", "\\"))
            ).lower().strip()
            dll_pid = self._safe_int(dll.get("pid") or dll.get("PID"), 0)

            # Kernel driver detection
            is_kernel = (
                any(frag in dll_path for frag in _KERNEL_PATH_FRAGS) or
                any(dll_name.endswith(suf) for suf in _KERNEL_NAME_SUFFIX)
            )
            if is_kernel and dll_name:
                kernel_driver_names.add(dll_name)

            # Service DLL hint (only for known service host processes)
            if dll_pid in shared_process_pids or dll_pid in own_process_pids:
                if any(hint in dll_name for hint in _SERVICE_DLL_HINTS):
                    service_dll_by_pid[dll_pid] += 1

        kernel_driver_count = len(kernel_driver_names)

        # ── Step 3: handle-based service signal (informational) ───────────
        service_handle_pids: Set[int] = set()
        for handle in handles:
            h_pid  = self._safe_int(handle.get("pid"), 0)
            h_type = (handle.get("type") or "").lower().strip()
            h_name = (handle.get("name") or "").lower()

            # Only count service-relevant handles from service host processes
            if h_pid not in service_pids:
                continue

            type_is_service = h_type in _SERVICE_HANDLE_TYPES
            name_is_service = any(frag in h_name for frag in _SERVICE_HANDLE_NAME_FRAGS)

            if type_is_service and (name_is_service or h_pid in shared_process_pids):
                service_handle_pids.add(h_pid)

        # ── Step 4: estimate service counts ───────────────────────────────
        n_own_process      = len(own_process_pids)
        n_svchost          = sum(
            1 for p in processes
            if os.path.basename(
                (p.get("image_name") or p.get("name") or
                 p.get("image_file_name") or "").replace("/", "\\")
            ).lower() == "svchost.exe"
        )

        # Shared services: each svchost hosts N services.
        # We also add DLLHost/WmiPrvSE instances scaled down.
        n_dllhost = len(shared_process_pids) - n_svchost
        n_shared = (
            n_svchost * _SHARED_SERVICES_PER_SVCHOST +
            max(0, n_dllhost) * 2
        )

        n_interactive = len(interactive_pids)

        # nservices = all service records across all types
        # (own + shared + kernel drivers + interactive)
        # Kernel drivers are also service records in SCM terminology.
        n_services = (
            n_own_process +
            n_shared +
            kernel_driver_count +
            n_interactive
        )

        # Sanity: if we have processes but somehow got 0, provide a
        # conservative process-based floor to avoid an all-zero vector.
        if n_services == 0 and processes:
            n_services   = max(n_own_process, 1)
            kernel_driver_count = 0
            n_shared     = 0
            n_interactive = 0

        self.logger.info(
            "[ServiceArtifact] Native service artifact features: "
            "nservices=%d  shared=%d  drivers=%d  process_services=%d  interactive=%d  "
            "(svchost_instances=%d)",
            n_services, n_shared, kernel_driver_count,
            n_own_process, n_interactive, n_svchost,
        )

        # ── Step 5: build output dict ──────────────────────────────────────
        # CIC canonical names (svcscan.*)
        cic = {
            "svcscan.nservices":                    float(n_services),
            "svcscan.kernel_drivers":               float(kernel_driver_count),
            "svcscan.process_services":             float(n_own_process),
            "svcscan.shared_process_services":      float(n_shared),
            "svcscan.interactive_process_services": float(n_interactive),
        }

        # RAMDetect aggregate alias names (used by _compute_cic_aggregate_stats)
        aliases = {
            "service_artifacts_total":      float(n_services),
            "service_kernel_drivers":       float(kernel_driver_count),
            "service_process_hosts":        float(n_own_process),
            "service_shared_hosts":         float(n_shared),
            "service_interactive_processes": float(n_interactive),
            # Names used by _compute_cic_aggregate_stats routing
            "total_services":              float(n_services),
            "kernel_driver_services":      float(kernel_driver_count),
            "process_services":            float(n_own_process),
            "shared_process_services":     float(n_shared),
            "interactive_process_services": float(n_interactive),
            "active_services":             float(n_services),   # conservative: assume all active
        }

        return {**cic, **aliases}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """Parse int/hex string safely."""
        try:
            if value is None:
                return default
            if isinstance(value, (int, float)):
                return int(value)
            value = str(value).strip()
            if not value or value in {"-", "?", "None", "none", "N/A", "n/a"}:
                return default
            if value.lower().startswith("0x"):
                return int(value, 16)
            return int(value)
        except Exception:
            return default

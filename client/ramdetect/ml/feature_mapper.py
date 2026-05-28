"""
feature_mapper.py - CIC ↔ RAMDetect Feature Mapper
====================================================
Phase 5, Module 2/8 — RAMDetect ML Pipeline

Bridges two feature spaces:
  A) CIC-MalMem-2022 features  (54 features, used for TRAINING)
  B) RAMDetect live features   (100+ features, used for INFERENCE)

The model is trained on CIC features.
At inference time, RAMDetect extracts live features from a RAM dump,
this mapper aligns them into the exact same vector the model expects.

Responsibilities:
  - Define the canonical 54-feature training vector (CIC columns)
  - Map RAMDetect feature names → CIC feature equivalents
  - Transform a RAMDetect feature dict → aligned numpy array
  - Handle missing features gracefully (fill with safe defaults)
  - Apply log1p compression to count columns BEFORE MinMaxScaler
    (fixes domain-shift saturation: lab Win7 VMs vs real Win10/11 systems)
  - Normalize the aligned vector to [0, 1] using fitted scaler

IMPORTANT CHANGE vs previous version
--------------------------------------
The old version applied sqrt() AFTER MinMaxScaler, which was ineffective
because clipped values (1.0) stay at 1.0 after sqrt.

This version applies np.log1p() BEFORE MinMaxScaler is fitted, so the
scaler's min/max range is learned on compressed values. Real-world dumps
with 15,000+ handles no longer saturate at 1.0 — they fall within the
compressed range the scaler was trained on.

Usage:
    # During training (fit scaler on CIC data):
    mapper = FeatureMapper()
    mapper.fit(X_train, cic_feature_names)
    mapper.save("models/feature_mapper.pkl")

    # During inference (live RAM dump):
    mapper = FeatureMapper.load("models/feature_mapper.pkl")
    ramdetect_features = aggregator.get_feature_dict()   # from your Phase 4
    x = mapper.transform_live(ramdetect_features)        # → (1, 52) array
    verdict = model.predict(x)
"""

import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

import numpy as np
from sklearn.preprocessing import MinMaxScaler

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# CANONICAL FEATURE ORDER
# This is the exact 54-feature vector the model will be trained on.
# Order matters — must stay consistent between training & inference.
# ─────────────────────────────────────────────────────────────────

CANONICAL_FEATURES: List[str] = [
    # ── Process list features ──────────────────────────────────
    "pslist.nproc",              # total number of processes
    "pslist.nppid",              # number of unique parent PIDs
    "pslist.avg_threads",        # average threads per process
    "pslist.nprocs64bit",        # number of 64-bit processes
    "pslist.avg_handlers",       # average handles per process

    # ── DLL list features ──────────────────────────────────────
    "dlllist.ndlls",             # total DLLs loaded system-wide
    "dlllist.avg_dlls_per_proc", # average DLLs per process

    # ── Handle features ────────────────────────────────────────
    "handles.nhandles",
    "handles.avg_handles_per_proc",
    "handles.nport",
    "handles.nfile",
    "handles.nevent",
    "handles.ndesktop",
    "handles.nkey",
    "handles.nthread",
    "handles.ndirectory",
    "handles.nsemaphore",
    "handles.ntimer",
    "handles.nsection",
    "handles.nmutant",

    # ── LDR modules (loaded module list cross-check) ───────────
    "ldrmodules.not_in_load",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",

    # ── Malfind (memory injection indicators) ─────────────────
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.uniqueInjections",

    # ── PSXview (process hiding cross-view) ───────────────────
    "psxview.not_in_pslist",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg",
    "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",

    # ── Modules ───────────────────────────────────────────────
    "modules.nmodules",

    # ── Service scan ──────────────────────────────────────────
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",

    # ── Callbacks ─────────────────────────────────────────────
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
]

assert len(CANONICAL_FEATURES) == 54, \
    f"Expected 54 canonical features, got {len(CANONICAL_FEATURES)}"


# ─────────────────────────────────────────────────────────────────
# PHASE 8 — RAMDetect-native expanded ML feature vector
#
# These features are NOT deterministic verdict rules. They are additional
# memory-forensic input variables for the same Dai et al. RF-AE fusion logic:
#   expanded_base_features → AE clean-MSE threshold → append AE_MSE → RF verdict
#
# Keep names aligned with FeatureAggregator/raw_features.json output.
# Values are expected to be numeric and usually normalized to [0, 1] by the
# existing feature extractors. Broad raw counters should stay in the canonical
# CIC 54 list unless specifically calibrated.
# ─────────────────────────────────────────────────────────────────
EXPANDED_NATIVE_FEATURES: List[str] = [
    # Process identity / lineage
    "known_malicious_process_count",
    "suspicious_parent_child_count",
    "ppid_spoofing_count",
    "orphan_process_count",
    "missing_path_count",
    "suspicious_path_count",
    "malware_path_pattern_count",
    "duplicate_system_process_count",
    "typosquat_count",

    # Thread / execution context
    "unbacked_thread_start_count",
    "private_executable_region_count",
    "rwx_private_memory_ratio",
    "remote_injection_thread_count",
    "apc_injection_indicator_count",

    # DLL / module trust and loading behaviour
    "unsigned_dll_count",
    "suspicious_path_dll_count",
    "temp_folder_dll_count",
    "late_loaded_system_dll_count",
    "early_loaded_user_dll_count",
    "ldrmodules_mismatch_ratio",

    # PE / packing / obfuscation
    "packer_section_count",
    "rwx_section_count",
    "high_entropy_section_count",
    "unusual_section_name_count",
    "manual_mapped_pe_count",

    # Handle / filesystem / persistence behaviour
    "suspicious_file_handle_count",
    "temp_folder_file_count",
    "encrypted_file_handle_count",
    "suspicious_executable_handle_count",
    "persistence_registry_key_count",
    "service_registry_key_count",
    "autostart_location_count",
    "suspicious_mutex_count",
    "named_pipe_handle_count",
]

# Full expanded base vector. The final RF-AE fused vector appends one more
# feature: "ae_reconstruction_error".
EXPANDED_FEATURES: List[str] = CANONICAL_FEATURES + EXPANDED_NATIVE_FEATURES

# Direct live mapping for native features. Canonical CIC aliases still use
# RAMDETECT_TO_CIC. Native features map to themselves.
RAMDETECT_NATIVE_TO_EXPANDED: Dict[str, str] = {name: name for name in EXPANDED_NATIVE_FEATURES}

# Native indicators are already normalized/scored by RAMDetect extractors in
# most cases. Missing native indicators default to 0 = no observed evidence.
NATIVE_FEATURE_DEFAULTS: Dict[str, float] = {name: 0.0 for name in EXPANDED_NATIVE_FEATURES}


# ─────────────────────────────────────────────────────────────────
# COUNT COLUMNS — receive log1p compression before MinMaxScaler
#
# These are raw integer count features whose values differ greatly
# between the CIC lab VMs (small values) and real Windows 10/11
# (much larger values, causing MinMaxScaler saturation).
#
# Average/ratio features (avg_*) are intentionally excluded because
# they are already in a bounded range and are stable across systems.
# ─────────────────────────────────────────────────────────────────

COUNT_FEATURE_NAMES: Set[str] = {
    "pslist.nproc",
    "pslist.nppid",
    "pslist.nprocs64bit",
    "dlllist.ndlls",
    "handles.nhandles",
    "handles.nport",
    "handles.nfile",
    "handles.nevent",
    "handles.ndesktop",
    "handles.nkey",
    "handles.nthread",
    "handles.ndirectory",
    "handles.nsemaphore",
    "handles.ntimer",
    "handles.nsection",
    "handles.nmutant",
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.uniqueInjections",
    "modules.nmodules",
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
    # PSXview raw counts (not averages)
    "psxview.not_in_pslist",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    # LDR raw counts (not averages)
    "ldrmodules.not_in_load",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem",
}

# Pre-compute column indices once (used by _log1p_cols)
_COUNT_COL_INDICES: List[int] = [
    i for i, name in enumerate(CANONICAL_FEATURES)
    if name in COUNT_FEATURE_NAMES
]


# ─────────────────────────────────────────────────────────────────
# RAMDetect → CIC feature name mapping
#
# Keys   = RAMDetect feature names (from your Phase 4 extractors)
# Values = CIC canonical feature names (from CANONICAL_FEATURES)
# ─────────────────────────────────────────────────────────────────

RAMDETECT_TO_CIC: Dict[str, str] = {

    # ── From process_features.py ──────────────────────────────
    "total_processes":              "pslist.nproc",
    "unique_parent_pids":           "pslist.nppid",
    "avg_threads_per_process":      "pslist.avg_threads",
    "total_procs_64bit":            "pslist.nprocs64bit",
    "avg_handles_per_process":      "pslist.avg_handlers",

    # ── From dll_features.py ──────────────────────────────────
    "total_dlls_loaded":            "dlllist.ndlls",
    "avg_dlls_per_process":         "dlllist.avg_dlls_per_proc",
    "dlls_not_in_load_list":        "ldrmodules.not_in_load",
    "dlls_not_in_init_list":        "ldrmodules.not_in_init",
    "dlls_not_in_mem_list":         "ldrmodules.not_in_mem",
    "avg_not_in_load":              "ldrmodules.not_in_load_avg",
    "avg_not_in_init":              "ldrmodules.not_in_init_avg",
    "avg_not_in_mem":               "ldrmodules.not_in_mem_avg",

    # ── From handle_features.py ───────────────────────────────
    "total_handles":                "handles.nhandles",
    "avg_handles":                  "handles.avg_handles_per_proc",
    "port_handles":                 "handles.nport",
    "file_handles":                 "handles.nfile",
    "event_handles":                "handles.nevent",
    "desktop_handles":              "handles.ndesktop",
    "key_handles":                  "handles.nkey",
    "thread_handles":               "handles.nthread",
    "directory_handles":            "handles.ndirectory",
    "semaphore_handles":            "handles.nsemaphore",
    "timer_handles":                "handles.ntimer",
    "section_handles":              "handles.nsection",
    "mutant_handles":               "handles.nmutant",

    # ── From injection_features.py ────────────────────────────
    "injection_count":              "malfind.ninjections",
    "total_commit_charge":          "malfind.commitCharge",
    "unique_injection_targets":     "malfind.uniqueInjections",

    # ── From process_features.py (cross-view hiding) ──────────
    "hidden_from_pslist":           "psxview.not_in_pslist",
    "hidden_from_eprocess_pool":    "psxview.not_in_eprocess_pool",
    "hidden_from_ethread_pool":     "psxview.not_in_ethread_pool",
    "hidden_from_pspcid":           "psxview.not_in_pspcid_list",
    "hidden_from_csrss":            "psxview.not_in_csrss_handles",
    "hidden_from_session":          "psxview.not_in_session",
    "hidden_from_desktop_thread":   "psxview.not_in_deskthrd",
    "avg_hidden_pslist":            "psxview.not_in_pslist_false_avg",
    "avg_hidden_eprocess":          "psxview.not_in_eprocess_pool_false_avg",
    "avg_hidden_ethread":           "psxview.not_in_ethread_pool_false_avg",
    "avg_hidden_pspcid":            "psxview.not_in_pspcid_list_false_avg",
    "avg_hidden_csrss":             "psxview.not_in_csrss_handles_false_avg",
    "avg_hidden_session":           "psxview.not_in_session_false_avg",
    "avg_hidden_desktop":           "psxview.not_in_deskthrd_false_avg",

    # ── From pe_features.py / thread_features.py ──────────────
    "total_modules":                "modules.nmodules",

    # ── From handle_features.py (services) ────────────────────
    "total_services":               "svcscan.nservices",
    "kernel_driver_services":       "svcscan.kernel_drivers",
    "filesystem_driver_services":   "svcscan.fs_drivers",
    "process_services":             "svcscan.process_services",
    "shared_process_services":      "svcscan.shared_process_services",
    "interactive_process_services": "svcscan.interactive_process_services",
    "active_services":              "svcscan.nactive",

    # ── From thread_features.py / pe_features.py (callbacks) ──
    "total_callbacks":              "callbacks.ncallbacks",
    "anonymous_callbacks":          "callbacks.nanonymous",
    "generic_callbacks":            "callbacks.ngeneric",
}


# ─────────────────────────────────────────────────────────────────
# Safe default values for missing features
# ─────────────────────────────────────────────────────────────────

FEATURE_DEFAULTS: Dict[str, float] = {
    # ── Average / ratio features (stable across systems) ──────────────────────
    "pslist.avg_threads":           8.5,   # typical for Win10/11
    "pslist.avg_handlers":          50.0,
    "dlllist.avg_dlls_per_proc":    45.0,
    "handles.avg_handles_per_proc": 50.0,

    # ── ldrmodules averages (not_in_*_avg) ────────────────────────────────────
    # Benign medians from MemMal-D2024 benign CSV.
    # If RAMDetect's dll_parser doesn't compute these, we fall back to benign
    # baseline rather than 0 (which looks like malware in training data).
    "ldrmodules.not_in_load_avg": 0.0363,
    "ldrmodules.not_in_init_avg": 0.0549,
    "ldrmodules.not_in_mem_avg":  0.0363,

    # ── svcscan features (Volatility plugin — NOT implemented in RAMDetect) ───
    # RAMDetect doesn't run Volatility's svcscan.  Defaulting to 0 makes the
    # model treat a clean dump as if it has far fewer services than any malware
    # sample (malware min nservices = 94, benign min = 388). Using the benign
    # median prevents this catastrophic false positive.
    "svcscan.nservices":                  395.0,
    "svcscan.kernel_drivers":             222.0,
    "svcscan.fs_drivers":                  26.0,
    "svcscan.process_services":            27.0,
    "svcscan.shared_process_services":    118.0,
    "svcscan.interactive_process_services": 4.0,  # benign median; GUI has no svcscan
    "svcscan.nactive":                    123.0,

    # ── modules feature (Volatility windows.modules — NOT in RAMDetect) ──────
    "modules.nmodules": 138.0,

    # ── callbacks feature (Volatility windows.callbacks — NOT in RAMDetect) ──
    "callbacks.ncallbacks": 88.0,

    # ── All other count features default to 0 ─────────────────────────────────
    # (pslist, handles, dlllist, ldrmodules raw counts, malfind, psxview)
}


# ─────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────

def _log1p_cols(X: np.ndarray, col_indices: List[int]) -> np.ndarray:
    """
    Apply np.log1p to the specified column indices of X in-place.

    log1p(x) = log(1 + x)
      x=0     → 0.000   (sparse counts stay sparse)
      x=10    → 2.398   (small VM counts)
      x=100   → 4.615   (medium system counts)
      x=1000  → 6.909   (real Windows counts)
      x=15000 → 9.616   (large handle counts)

    This compresses the huge range of real-world Windows values so the
    MinMaxScaler trained on CIC lab data no longer clips them to 1.0.
    """
    out = X.copy().astype(np.float32)
    for ci in col_indices:
        if ci < out.shape[1]:
            out[:, ci] = np.log1p(np.maximum(out[:, ci], 0.0))
    return out


# ─────────────────────────────────────────────────────────────────
# FeatureMapper class
# ─────────────────────────────────────────────────────────────────

class FeatureMapper:
    """
    Aligns feature vectors between CIC training data and
    RAMDetect live extraction output.

    Key design change (v2)
    ----------------------
    log1p() is now applied to count columns BEFORE MinMaxScaler is fitted.
    This means the scaler's range is learned on compressed log-space values,
    so real-world Windows dumps (with far more handles/processes than the CIC
    lab VMs) fall inside the scaler's range instead of being clipped to 1.0.

    The same log1p transform is applied at inference time before scaling.

    Workflow
    --------
    Training time:
        mapper = FeatureMapper()
        mapper.fit(X_cic_train, cic_column_names)
        mapper.save("models/feature_mapper.pkl")

    Inference time:
        mapper = FeatureMapper.load("models/feature_mapper.pkl")
        live_dict = ramdetect_aggregator.get_all_features()
        x = mapper.transform_live(live_dict)   # shape (1, 54)
        prediction = model.predict(x)
    """

    # bumped so old pickles (v1, no log1p) are rejected with a clear error
    _VERSION = "2.0"

    def __init__(self, feature_mode: str = "canonical54", expanded_native_features: Optional[List[str]] = None):
        """
        Parameters
        ----------
        feature_mode:
            "canonical54" keeps the original CIC/Obfuscated-MalMem 54-vector.
            "expanded" uses CIC 54 + RAMDetect-native memory-artifact features.

        Notes
        -----
        Expanded mode does not add rules or verdict overrides. It only changes
        the ML input feature space. AE and RF must be retrained on the same
        expanded feature dimensions.
        """
        # FYP experiment lock: CIC-MalMem-2022 only.
        # Expanded/native RAMDetect features may be exported for explanation/debug,
        # but they must not become ML input features for EXP_CIC54_ML_ONLY_RF_AE.
        self.feature_mode = str(feature_mode or "canonical54")
        if self.feature_mode != "canonical54":
            raise ValueError(
                "EXP_CIC54_ML_ONLY_RF_AE only permits FeatureMapper(feature_mode='canonical54'). "
                f"Received feature_mode={self.feature_mode!r}."
            )

        self.expanded_native_features = []
        self.canonical_features = CANONICAL_FEATURES.copy()

        self.n_features: int = len(self.canonical_features)
        self.scaler: Optional[MinMaxScaler] = None
        self._is_fitted: bool = False
        self._cic_col_index: Dict[str, int] = {}
        self._count_col_indices: List[int] = [
            i for i, name in enumerate(self.canonical_features)
            if name in COUNT_FEATURE_NAMES
        ]

    # ─────────────────────────────────────────
    # Fit (training time)
    # ─────────────────────────────────────────

    def fit(
        self,
        X_train: np.ndarray,
        cic_feature_names: List[str],
    ) -> "FeatureMapper":
        """
        Fit a MinMaxScaler on the CIC training data.

        Steps:
          1. Reorder X_train columns to match CANONICAL_FEATURES
          2. Apply log1p to count columns
          3. Fit MinMaxScaler on the log-compressed data

        Parameters
        ----------
        X_train          : Training feature matrix from DatasetLoader (N x F)
        cic_feature_names: Feature names in the same order as X_train columns
        """
        self._cic_col_index = {name: i for i, name in enumerate(cic_feature_names)}

        # Step 1: reorder to canonical order
        X_aligned = self._reorder_cic_matrix(X_train, cic_feature_names)

        # Step 2: log1p on count columns (BEFORE scaler)
        X_compressed = _log1p_cols(X_aligned, self._count_col_indices)

        # Step 3: fit scaler on compressed data
        self.scaler = MinMaxScaler(feature_range=(0, 1), clip=True)
        self.scaler.fit(X_compressed)
        self._is_fitted = True

        logger.info(
            f"FeatureMapper v2 fitted on {X_compressed.shape[0]:,} samples, "
            f"{X_compressed.shape[1]} features  "
            f"(log1p applied to {len(self._count_col_indices)} count columns)"
        )
        self._print_fit_summary(cic_feature_names)
        return self

    def _reorder_cic_matrix(
        self,
        X: np.ndarray,
        source_names: List[str],
    ) -> np.ndarray:
        """
        Reorder columns of X to match CANONICAL_FEATURES order.
        Fills zeros for any canonical feature missing from source.
        """
        n_samples = X.shape[0]
        X_out = np.zeros((n_samples, self.n_features), dtype=np.float32)
        source_index = {name: i for i, name in enumerate(source_names)}

        for out_idx, feat_name in enumerate(self.canonical_features):
            if feat_name in source_index:
                X_out[:, out_idx] = X[:, source_index[feat_name]]
            else:
                default = FEATURE_DEFAULTS.get(feat_name, NATIVE_FEATURE_DEFAULTS.get(feat_name, 0.0))
                X_out[:, out_idx] = default

        return X_out

    # ─────────────────────────────────────────
    # Transform CIC data (training / eval time)
    # ─────────────────────────────────────────

    def transform_cic(
        self,
        X: np.ndarray,
        feature_names: List[str],
    ) -> np.ndarray:
        """
        Transform a CIC feature matrix → scaled canonical vector.

        Pipeline:
          1. Reorder columns to canonical order
          2. Apply log1p to count columns
          3. Scale with fitted MinMaxScaler

        Parameters
        ----------
        X             : Raw feature matrix from DatasetLoader
        feature_names : Column names matching X

        Returns
        -------
        np.ndarray shape (N, 54), values in [0, 1]
        """
        self._check_fitted()
        X_aligned    = self._reorder_cic_matrix(X, feature_names)
        X_compressed = _log1p_cols(X_aligned, self._count_col_indices)
        X_scaled     = self.scaler.transform(X_compressed).astype(np.float32)
        return X_scaled

    # ─────────────────────────────────────────
    # Transform live RAMDetect data (inference)
    # ─────────────────────────────────────────

    def transform_live(
        self,
        ramdetect_features: Dict[str, float],
    ) -> np.ndarray:
        """
        Transform a RAMDetect feature dictionary → scaled canonical vector.

        Pipeline:
          1. Translate RAMDetect feature names → CIC canonical names
          2. Build the 54-element raw vector
          3. Apply log1p to count columns
          4. Scale with fitted MinMaxScaler

        Parameters
        ----------
        ramdetect_features : Dict from feature_aggregator.get_all_features()

        Returns
        -------
        np.ndarray shape (1, 54), values in [0, 1]
        """
        self._check_fitted()

        # Step 1: translate RAMDetect names → CIC names
        cic_values: Dict[str, float] = {}
        unmapped: List[str] = []

        for rd_name, value in ramdetect_features.items():
            # 1) Existing RAMDetect → CIC canonical mapping.
            cic_name = RAMDETECT_TO_CIC.get(rd_name)
            if cic_name and cic_name in self.canonical_features:
                cic_values[cic_name] = float(value)
                continue

            # 2) Native RAMDetect-only features are intentionally ignored in
            #    this experiment. They may appear in raw reports/debug exports,
            #    but must not become ML input unless they map to CIC canonical names.

            # 3) Also accept exact CIC canonical feature-name matches for tools that emit
            #    canonical or expanded names directly.
            if rd_name in self.canonical_features:
                cic_values[rd_name] = float(value)
                continue

            unmapped.append(rd_name)

        if unmapped:
            logger.debug(
                f"{len(unmapped)} RAMDetect features have no CIC mapping "
                f"(ignored): {unmapped[:5]}{'...' if len(unmapped) > 5 else ''}"
            )

        # Step 2: build raw canonical vector
        x_raw = np.array(
            [cic_values.get(feat, FEATURE_DEFAULTS.get(feat, NATIVE_FEATURE_DEFAULTS.get(feat, 0.0)))
             for feat in self.canonical_features],
            dtype=np.float32,
        ).reshape(1, -1)

        # Step 3: log1p on count columns (same transform as training)
        x_compressed = _log1p_cols(x_raw, self._count_col_indices)

        # Step 4: scale
        x_scaled = self.scaler.transform(x_compressed).astype(np.float32)

        # Log coverage
        filled   = sum(1 for f in self.canonical_features if f in cic_values)
        coverage = filled / self.n_features * 100
        if coverage < 70:
            logger.warning(
                f"Low feature coverage: {filled}/{self.n_features} "
                f"({coverage:.0f}%) — prediction reliability may be reduced"
            )
        else:
            logger.debug(f"Feature coverage: {filled}/{self.n_features} ({coverage:.0f}%)")

        return x_scaled

    def transform_live_batch(
        self,
        feature_dicts: List[Dict[str, float]],
    ) -> np.ndarray:
        """Transform a list of RAMDetect feature dicts → batch array (N, 54)."""
        return np.vstack([self.transform_live(d) for d in feature_dicts])

    # ─────────────────────────────────────────
    # Introspection helpers
    # ─────────────────────────────────────────

    def get_coverage_report(
        self,
        ramdetect_features: Dict[str, float],
    ) -> Dict:
        """Returns which RAMDetect features map to CIC and which CIC features are missing."""
        cic_covered = set()
        mapped = {}

        for rd_name in ramdetect_features:
            cic_name = RAMDETECT_TO_CIC.get(rd_name)
            if cic_name and cic_name in self.canonical_features:
                cic_covered.add(cic_name)
                mapped[rd_name] = cic_name
                continue

            # Native RAMDetect-only features are ignored for CIC54 ML input.
            if rd_name in self.canonical_features:
                cic_covered.add(rd_name)
                mapped[rd_name] = rd_name

        missing_cic = [f for f in self.canonical_features if f not in cic_covered]

        return {
            "total_canonical":   self.n_features,
            "covered":           len(cic_covered),
            "missing":           len(missing_cic),
            "coverage_pct":      round(len(cic_covered) / self.n_features * 100, 1),
            "mapped_features":   mapped,
            "missing_features":  missing_cic,
        }

    def get_canonical_features(self) -> List[str]:
        return list(self.canonical_features)

    def get_ramdetect_mapping(self) -> Dict[str, str]:
        return dict(RAMDETECT_TO_CIC)

    # ─────────────────────────────────────────
    # Save / load
    # ─────────────────────────────────────────

    def save(self, path: Union[str, Path]) -> None:
        """Serialize mapper (including fitted scaler) to disk."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            pickle.dump({
                "canonical_features":  self.canonical_features,
                "scaler":              self.scaler,
                "cic_col_index":       self._cic_col_index,
                "count_col_indices":   self._count_col_indices,
                "is_fitted":           self._is_fitted,
                "version":             self._VERSION,
                "feature_mode":        getattr(self, "feature_mode", "canonical54"),
                "expanded_native_features": getattr(self, "expanded_native_features", []),
            }, f)
        logger.info(f"FeatureMapper v{self._VERSION} saved → {out}")
        print(f"  💾 FeatureMapper saved: {out}")

    @classmethod
    def load(cls, path: Union[str, Path]) -> "FeatureMapper":
        """Load a previously saved FeatureMapper from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"FeatureMapper not found: {p}")
        with open(p, "rb") as f:
            data = pickle.load(f)

        # Version guard — v1 pickles (no log1p) must be retrained
        saved_ver = data.get("version", "1.0")
        if saved_ver != cls._VERSION:
            raise RuntimeError(
                f"FeatureMapper version mismatch: saved={saved_ver}, "
                f"current={cls._VERSION}. "
                "Please retrain the models (python train_model.py)."
            )

        saved_mode = data.get("feature_mode", "canonical54")
        if saved_mode != "canonical54":
            raise RuntimeError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: loaded FeatureMapper was saved "
                f"with feature_mode={saved_mode!r}. Retrain/load a CIC-MalMem-2022 "
                "canonical54 mapper."
            )

        saved_features = list(data["canonical_features"])
        if len(saved_features) != 54 or saved_features != CANONICAL_FEATURES:
            raise RuntimeError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: loaded FeatureMapper does not "
                "match the CIC-MalMem-2022 canonical 54-feature order."
            )

        mapper = cls(feature_mode="canonical54")
        mapper.canonical_features   = saved_features
        mapper.scaler               = data["scaler"]
        mapper._cic_col_index       = data["cic_col_index"]
        mapper._count_col_indices   = data.get("count_col_indices", [
            i for i, name in enumerate(mapper.canonical_features)
            if name in COUNT_FEATURE_NAMES
        ])
        mapper._is_fitted           = data["is_fitted"]
        mapper.n_features           = len(mapper.canonical_features)
        mapper.feature_mode         = "canonical54"
        mapper.expanded_native_features = []
        mapper.assert_cic54_only()
        logger.info(f"FeatureMapper v{saved_ver} loaded ← {p}")
        return mapper

    # ─────────────────────────────────────────
    # Experiment guard
    # ─────────────────────────────────────────

    def assert_cic54_only(self) -> None:
        """Fail fast if this mapper is not the CIC-MalMem-2022 canonical 54-feature mapper."""
        if getattr(self, "feature_mode", "canonical54") != "canonical54":
            raise RuntimeError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: feature_mode must be canonical54."
            )
        if self.n_features != 54:
            raise RuntimeError(
                f"EXP_CIC54_ML_ONLY_RF_AE guard failed: mapper has {self.n_features} "
                "features; expected 54 CIC canonical features."
            )
        if list(self.canonical_features) != list(CANONICAL_FEATURES):
            raise RuntimeError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: canonical feature order differs "
                "from CIC-MalMem-2022 canonical order."
            )

    # ─────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────

    def _check_fitted(self):
        if not self._is_fitted or self.scaler is None:
            raise RuntimeError(
                "FeatureMapper is not fitted. "
                "Call .fit(X_train, feature_names) first, or load a saved mapper."
            )

    def _print_fit_summary(self, cic_names: List[str]):
        matched      = sum(1 for n in cic_names if n in self.canonical_features)
        unmapped_cic = [n for n in self.canonical_features if n not in cic_names]
        print("\n" + "=" * 60)
        print("  🗺  FEATURE MAPPER FITTED  (v2 — log1p pre-scaling)")
        print("=" * 60)
        print(f"  Feature mode         : {getattr(self, 'feature_mode', 'canonical54')}")
        print(f"  ML base features     : {self.n_features}")
        print(f"  Count cols (log1p)   : {len(self._count_col_indices)}")
        print(f"  CIC cols matched     : {matched}/{len(cic_names)}")
        print(f"  CIC cols unmatched   : {len(unmapped_cic)}")
        if unmapped_cic:
            print(f"  Unmatched            : {unmapped_cic}")
        print(f"  RAMDetect mappings   : {len(RAMDETECT_TO_CIC)} features registered")
        print("=" * 60)


# ─────────────────────────────────────────────────────────────────
# Quick test / demo
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

    from ramdetect.ml.dataset_loader import load_cic_malmem

    if len(sys.argv) < 2:
        print("Usage: python feature_mapper.py <path/to/CIC-MalMem-2022.csv>")
        sys.exit(1)

    # ── Load dataset ──────────────────────────────────────────
    loader, splits = load_cic_malmem(sys.argv[1])
    X_train, y_train = splits["train"]

    # ── Fit mapper ────────────────────────────────────────────
    mapper = FeatureMapper()
    mapper.fit(X_train, loader.get_feature_names())

    # ── Transform training data ───────────────────────────────
    X_train_scaled = mapper.transform_cic(X_train, loader.get_feature_names())
    print(f"\n  X_train scaled : {X_train_scaled.shape}  "
          f"range [{X_train_scaled.min():.3f}, {X_train_scaled.max():.3f}]")

    # ── Simulate a real Windows 10 live dump (high counts) ────
    live_real_world = {
        "total_processes":          87,      # real Win10: 80-120 procs
        "unique_parent_pids":       32,
        "avg_threads_per_process":  8.4,
        "avg_handles_per_process":  180.0,
        "total_dlls_loaded":        890,     # real Win10: 600-1200 DLLs
        "avg_dlls_per_process":     10.2,
        "total_handles":            15600,   # real Win10: 10k-20k handles
        "avg_handles":              179.3,
        "file_handles":             820,
        "port_handles":             12,
        "event_handles":            1240,
        "key_handles":              640,
        "mutant_handles":           95,
        "injection_count":          0,       # clean system
        "total_commit_charge":      0,
        "unique_injection_targets": 0,
    }

    x_live = mapper.transform_live(live_real_world)
    print(f"\n  Real-world Win10 vector shape : {x_live.shape}")
    print(f"  Scaled values (first 8)       : {x_live[0, :8].round(3)}")
    print(f"  Max value                     : {x_live.max():.3f}  (should be < 1.0 for clean)")
    print(f"  Mean value                    : {x_live.mean():.3f}")

    # ── Coverage report ───────────────────────────────────────
    report = mapper.get_coverage_report(live_real_world)
    print(f"\n  Coverage: {report['covered']}/{report['total_canonical']} "
          f"({report['coverage_pct']}%)")

    # ── Save ──────────────────────────────────────────────────
    mapper.save("models/feature_mapper.pkl")
    print("\n✅ feature_mapper.py v2 working correctly!")
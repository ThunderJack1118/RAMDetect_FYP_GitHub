"""
ramdetect/features/ldrmodules_features.py
==========================================
Native LDR/VAD Module Consistency Feature Builder
--------------------------------------------------
Produces CIC-MalMem-2022 compatible ldrmodules.* features WITHOUT using
Volatility.

Two complementary approaches are combined:

  1. PEB LDR flag approach  (primary)
     DLL rows emitted by the updated DLLParser carry in_load / in_mem / in_init
     flags and ldr_lists_complete.  This approach counts true discrepancies
     between the three PEB LDR lists per process.

  2. VAD cross-check  (supplementary)
     Image-backed VAD regions whose path ends in .dll/.exe/.sys but whose
     basename/base-address is absent from ALL three PEB LDR lists for that
     PID are counted as hidden-from-load modules.  This catches manually
     mapped or reflectively injected DLLs that the PEB doesn't know about.

Safety constraints
------------------
* Never counts System (PID 4) or unmapped VAD rows (no module name/path).
* VAD cross-check only considers confirmed image/file-backed regions with a
  recognised extension.
* not_in_init is suppressed if the init list could not be read for a process
  (ldr_lists_complete=False), preventing false-positive inflation.
* No Volatility dependency.
* No veto rules, clean dampeners, or ML-threshold changes.

Outputs
-------
Both canonical CIC names (used directly by FeatureMapper) and RAMDetect
alias names (used by FeatureAggregator) are returned in the same dict so
either lookup path works without double calls.

Usage
-----
    from ramdetect.features.ldrmodules_features import LdrModulesFeatureBuilder

    feats = LdrModulesFeatureBuilder().build(parsed_data)
    # feats["ldrmodules.not_in_load"] → float
    # feats["ldrmodules.not_in_init"] → float
    # feats["ldrmodules.not_in_mem"]  → float
    # ... etc.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Set, Tuple

_MODULE_EXTENSIONS = {".dll", ".exe", ".sys", ".drv", ".ocx"}
_SYSTEM_PID = 4

logger = logging.getLogger(__name__)


def _normalise_path(raw: str) -> str:
    """Lower-case and normalise path separators."""
    return (raw or "").lower().replace("/", "\\").strip()


def _basename(path: str) -> str:
    """Return the final filename component of a (possibly Windows) path."""
    normalised = path.replace("\\", "/")
    return os.path.basename(normalised)


def _has_module_extension(name: str) -> bool:
    ext = os.path.splitext(name)[-1].lower()
    return ext in _MODULE_EXTENSIONS


class LdrModulesFeatureBuilder:
    """
    Builds native ldrmodules.* ML features from RAMDetect parsed artifacts.

    Instantiate once per analysis run and call build(parsed_data).
    The object is stateless between calls.
    """

    def build(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Compute LDR/VAD module consistency features.

        Parameters
        ----------
        parsed_data : dict produced by AnalysisWorker._run_phase0_parsing
            Expected keys (all optional; missing → treated as empty):
                "dlls"          list of DLL dicts from DLLParser
                "pe_sections"   VAD/PE-section rows from VADScanner
                "memory_regions" alias for pe_sections
                "vads"          alias for pe_sections
                "mapped_files"  rows from MappedFileCarver
                "processes"     process list (used only for process count)

        Returns
        -------
        dict mapping feature names → float
        """
        dlls: List[Dict] = parsed_data.get("dlls") or []
        pe_sections: List[Dict] = (
            parsed_data.get("pe_sections")
            or parsed_data.get("memory_regions")
            or parsed_data.get("vads")
            or []
        )
        mapped_files: List[Dict] = parsed_data.get("mapped_files") or []
        processes: List[Dict] = parsed_data.get("processes") or []

        # Flatten DLLs if they arrive as a PID-keyed dict (older callers)
        if isinstance(dlls, dict):
            flat: List[Dict] = []
            for v in dlls.values():
                if isinstance(v, list):
                    flat.extend(v)
            dlls = flat

        # ── Step 1: Count from DLL-row LDR flags (primary) ──────────────────
        (
            total_not_load_flags,
            total_not_mem_flags,
            total_not_init_flags,
            pids_with_ldr_data,
        ) = self._count_from_dll_flags(dlls)

        # ── Step 2: VAD cross-check — modules hidden from all PEB lists ──────
        (
            vad_extra_not_in_load,
            vad_pids,
        ) = self._vad_cross_check(dlls, pe_sections, mapped_files)

        # ── Step 3: Combine ──────────────────────────────────────────────────
        combined_not_in_load = total_not_load_flags + vad_extra_not_in_load
        combined_not_in_mem  = total_not_mem_flags
        combined_not_in_init = total_not_init_flags

        # Process count denominator: use PIDs actually seen in LDR data + VAD,
        # falling back to total process count if no LDR data was collected.
        all_pids = pids_with_ldr_data | vad_pids
        if not all_pids and processes:
            all_pids = {
                int(p.get("pid", 0) or 0)
                for p in processes
                if int(p.get("pid", 0) or 0) not in (0, _SYSTEM_PID)
            }
        n_procs = max(len(all_pids), 1)

        logger.debug(
            "[LdrModules] not_in_load=%d (flags=%d vad=%d) "
            "not_in_init=%d not_in_mem=%d procs=%d",
            combined_not_in_load,
            total_not_load_flags,
            vad_extra_not_in_load,
            combined_not_in_init,
            combined_not_in_mem,
            n_procs,
        )

        return {
            # ── Canonical CIC names (FeatureMapper picks these up directly) ──
            "ldrmodules.not_in_load":     float(combined_not_in_load),
            "ldrmodules.not_in_init":     float(combined_not_in_init),
            "ldrmodules.not_in_mem":      float(combined_not_in_mem),
            "ldrmodules.not_in_load_avg": float(combined_not_in_load / n_procs),
            "ldrmodules.not_in_init_avg": float(combined_not_in_init / n_procs),
            "ldrmodules.not_in_mem_avg":  float(combined_not_in_mem  / n_procs),
            # ── RAMDetect alias names (FeatureAggregator / heuristic layer) ──
            "dlls_not_in_load_list": float(combined_not_in_load),
            "dlls_not_in_init_list": float(combined_not_in_init),
            "dlls_not_in_mem_list":  float(combined_not_in_mem),
            "avg_not_in_load":       float(combined_not_in_load / n_procs),
            "avg_not_in_init":       float(combined_not_in_init  / n_procs),
            "avg_not_in_mem":        float(combined_not_in_mem   / n_procs),
        }


    def build_safe_averages_only(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Clean-safe live-inference path.

        Returns ONLY normalized / clamped average features. Raw canonical count
        features such as ``ldrmodules.not_in_load`` are intentionally omitted
        because previous live tests showed that raw LDR counts can make a clean
        Windows dump false-positive.

        This method uses only DLL rows where ``ldr_lists_complete`` is True,
        because partial LDR list reads should not be interpreted as suspicious
        list mismatches.
        """
        dlls: List[Dict] = parsed_data.get("dlls") or []
        if isinstance(dlls, dict):
            flat: List[Dict] = []
            for v in dlls.values():
                if isinstance(v, list):
                    flat.extend(v)
            dlls = flat

        total_rows = 0
        complete_rows = 0
        total_not_load = 0
        total_not_mem = 0
        total_not_init = 0
        complete_pids: Set[int] = set()

        for dll in dlls:
            if not isinstance(dll, dict):
                continue
            total_rows += 1
            try:
                pid = int(dll.get("pid") or dll.get("PID") or 0)
            except Exception:
                pid = 0
            if pid in (0, _SYSTEM_PID):
                continue

            # Only consume rows produced by the 3-list native LDR parser.
            if not any(k in dll for k in ("in_load", "in_mem", "in_init", "ldr_lists_complete")):
                continue

            complete = dll.get("ldr_lists_complete")
            if isinstance(complete, str):
                complete = complete.strip().lower() in {"1", "true", "yes", "y"}
            complete = bool(complete)
            if not complete:
                # Partial list reads are not suspicious in safe mode.
                continue

            complete_rows += 1
            complete_pids.add(pid)
            if bool(dll.get("not_in_load", False)):
                total_not_load += 1
            if bool(dll.get("not_in_mem", False)):
                total_not_mem += 1
            if bool(dll.get("not_in_init", False)):
                total_not_init += 1

        if complete_rows <= 0 or not complete_pids:
            logger.info(
                "[LdrModules/safe] no complete LDR rows available (rows=%d); preserving FeatureMapper defaults",
                total_rows,
            )
            return {}

        n_procs = max(len(complete_pids), 1)
        avg_load = min(max(float(total_not_load) / n_procs, 0.0), 10.0)
        avg_init = min(max(float(total_not_init) / n_procs, 0.0), 10.0)
        avg_mem = min(max(float(total_not_mem) / n_procs, 0.0), 10.0)
        ratio = max(avg_load, avg_init, avg_mem)

        logger.info(
            "[LdrModules/safe] rows=%d complete=%d pids=%d avg_not_load=%.4f avg_not_init=%.4f avg_not_mem=%.4f",
            total_rows,
            complete_rows,
            n_procs,
            avg_load,
            avg_init,
            avg_mem,
        )

        return {
            "ldrmodules.not_in_load_avg": avg_load,
            "ldrmodules.not_in_init_avg": avg_init,
            "ldrmodules.not_in_mem_avg": avg_mem,
            "avg_not_in_load": avg_load,
            "avg_not_in_init": avg_init,
            "avg_not_in_mem": avg_mem,
            "ldrmodules_mismatch_ratio": ratio,
            "_debug_ldr_total_rows": float(total_rows),
            "_debug_ldr_complete_rows": float(complete_rows),
            "_debug_ldr_valid_processes": float(n_procs),
        }



    def build_raw_counts_only(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Phase-1 native 54-feature completion path.

        Returns raw CIC ldrmodules count features derived ONLY from confirmed
        native PEB 3-list DLL rows.  This deliberately avoids the broader VAD
        cross-check used by ``build()`` so the first 54-feature expansion stays
        low-risk and based on evidence already produced by ``DLLParser``.

        Consumed by FeatureMapper through RAMDetect aliases:
          dlls_not_in_load_list -> ldrmodules.not_in_load
          dlls_not_in_init_list -> ldrmodules.not_in_init
          dlls_not_in_mem_list  -> ldrmodules.not_in_mem

        Also emits the canonical names directly for diagnostics/debug export.
        """
        dlls: List[Dict] = parsed_data.get("dlls") or []
        if isinstance(dlls, dict):
            flat: List[Dict] = []
            for v in dlls.values():
                if isinstance(v, list):
                    flat.extend(v)
            dlls = flat

        total_rows = 0
        complete_rows = 0
        total_not_load = 0
        total_not_mem = 0
        total_not_init = 0
        complete_pids: Set[int] = set()

        for dll in dlls:
            if not isinstance(dll, dict):
                continue
            total_rows += 1
            try:
                pid = int(dll.get("pid") or dll.get("PID") or 0)
            except Exception:
                pid = 0
            if pid in (0, _SYSTEM_PID):
                continue

            if not any(k in dll for k in ("in_load", "in_mem", "in_init", "ldr_lists_complete")):
                continue

            complete = dll.get("ldr_lists_complete")
            if isinstance(complete, str):
                complete = complete.strip().lower() in {"1", "true", "yes", "y"}
            complete = bool(complete)
            if not complete:
                continue

            complete_rows += 1
            complete_pids.add(pid)
            if bool(dll.get("not_in_load", False)):
                total_not_load += 1
            if bool(dll.get("not_in_mem", False)):
                total_not_mem += 1
            if bool(dll.get("not_in_init", False)):
                total_not_init += 1

        if complete_rows <= 0 or not complete_pids:
            logger.info(
                "[LdrModules/raw] no complete LDR rows available (rows=%d); preserving FeatureMapper defaults",
                total_rows,
            )
            return {}

        n_procs = max(len(complete_pids), 1)
        avg_load = float(total_not_load) / n_procs
        avg_init = float(total_not_init) / n_procs
        avg_mem = float(total_not_mem) / n_procs

        logger.info(
            "[LdrModules/raw] rows=%d complete=%d pids=%d raw_not_load=%d raw_not_init=%d raw_not_mem=%d",
            total_rows,
            complete_rows,
            n_procs,
            total_not_load,
            total_not_init,
            total_not_mem,
        )

        return {
            "ldrmodules.not_in_load": float(total_not_load),
            "ldrmodules.not_in_init": float(total_not_init),
            "ldrmodules.not_in_mem": float(total_not_mem),
            "dlls_not_in_load_list": float(total_not_load),
            "dlls_not_in_init_list": float(total_not_init),
            "dlls_not_in_mem_list": float(total_not_mem),
            # Keep averages too, so one call can replace the safe-only helper.
            "ldrmodules.not_in_load_avg": min(max(avg_load, 0.0), 10.0),
            "ldrmodules.not_in_init_avg": min(max(avg_init, 0.0), 10.0),
            "ldrmodules.not_in_mem_avg": min(max(avg_mem, 0.0), 10.0),
            "avg_not_in_load": min(max(avg_load, 0.0), 10.0),
            "avg_not_in_init": min(max(avg_init, 0.0), 10.0),
            "avg_not_in_mem": min(max(avg_mem, 0.0), 10.0),
            "ldrmodules_mismatch_ratio": max(avg_load, avg_init, avg_mem),
            "_debug_ldr_raw_total_rows": float(total_rows),
            "_debug_ldr_raw_complete_rows": float(complete_rows),
            "_debug_ldr_raw_valid_processes": float(n_procs),
            "_debug_ldr_raw_not_in_load": float(total_not_load),
            "_debug_ldr_raw_not_in_init": float(total_not_init),
            "_debug_ldr_raw_not_in_mem": float(total_not_mem),
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _count_from_dll_flags(
        self,
        dlls: List[Dict],
    ) -> Tuple[int, int, int, Set[int]]:
        """
        Count LDR membership discrepancies directly from DLL-row flags set
        by the updated DLLParser (in_load / in_mem / in_init flags).

        Returns
        -------
        (not_in_load, not_in_mem, not_in_init, pid_set)
        """
        total_not_load = 0
        total_not_mem  = 0
        total_not_init = 0
        pids: Set[int] = set()

        for dll in dlls:
            try:
                pid = int(dll.get("pid") or dll.get("PID") or 0)
            except (TypeError, ValueError):
                pid = 0

            if pid in (0, _SYSTEM_PID):
                continue

            # Only process rows that carry the new LDR flags
            if "in_load" not in dll and "not_in_load" not in dll:
                continue

            pids.add(pid)

            if dll.get("not_in_load", False):
                total_not_load += 1

            if dll.get("not_in_mem", False):
                total_not_mem += 1

            # not_in_init is only trustworthy when the init list was readable
            ldr_complete = dll.get("ldr_lists_complete", False)
            if ldr_complete and dll.get("not_in_init", False):
                total_not_init += 1

        return total_not_load, total_not_mem, total_not_init, pids

    def _vad_cross_check(
        self,
        dlls: List[Dict],
        pe_sections: List[Dict],
        mapped_files: List[Dict],
    ) -> Tuple[int, Set[int]]:
        """
        Compare image-backed VAD entries against the PEB module set.

        A VAD entry that:
          • has a path ending in .dll / .exe / .sys / .drv / .ocx
          • is an image or file-backed region
          • has no matching entry in the PEB LDR load list for the same PID
            (matched by basename OR by base address)

        … is counted as a hidden-from-load module.

        Returns
        -------
        (extra_not_in_load_count, pids_seen_in_vad)
        """
        # Build PEB lookup tables per PID
        peb_basenames: Dict[int, Set[str]] = {}   # pid → set of lowercase basenames
        peb_bases:     Dict[int, Set[int]] = {}   # pid → set of base addresses

        for dll in dlls:
            try:
                pid = int(dll.get("pid") or dll.get("PID") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid in (0, _SYSTEM_PID):
                continue

            name = (dll.get("name") or dll.get("dll_name") or "").lower().strip()
            if not name:
                raw_path = _normalise_path(dll.get("path") or "")
                name = _basename(raw_path)

            base = int(dll.get("base_address") or dll.get("base") or dll.get("Base Address") or 0)

            if name:
                peb_basenames.setdefault(pid, set()).add(name)
            if base:
                peb_bases.setdefault(pid, set()).add(base)

        extra_not_in_load = 0
        vad_pids: Set[int] = set()

        all_vad_rows: List[Dict] = list(pe_sections) + list(mapped_files)

        for vad in all_vad_rows:
            try:
                pid = int(vad.get("pid") or vad.get("PID") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid in (0, _SYSTEM_PID):
                continue

            # ── Path / name resolution ────────────────────────────────────
            raw_path = _normalise_path(
                vad.get("path") or vad.get("name") or vad.get("file")
                or vad.get("mapped_file_name") or vad.get("filename") or ""
            )
            if not raw_path or raw_path in ("-", "none", "n/a"):
                continue

            if not _has_module_extension(raw_path):
                continue

            basename = _basename(raw_path)
            if not basename:
                continue

            # ── Image / file-backed filter ────────────────────────────────
            vad_type = (
                vad.get("type") or vad.get("Type")
                or vad.get("protection") or vad.get("Protection") or ""
            ).lower()

            is_image_or_mapped = (
                "image" in vad_type
                or "mapped" in vad_type
                or "file" in vad_type
                or vad.get("file_backed")
                or vad.get("carve_candidate")
                or vad.get("is_image")
            )
            if not is_image_or_mapped:
                continue

            # ── PEB membership check ──────────────────────────────────────
            vad_base = int(
                vad.get("base") or vad.get("start") or vad.get("start_va")
                or vad.get("Base") or 0
            )

            pid_basenames = peb_basenames.get(pid, set())
            pid_bases     = peb_bases.get(pid, set())

            in_peb_by_name = basename in pid_basenames
            in_peb_by_base = bool(vad_base and vad_base in pid_bases)

            if not in_peb_by_name and not in_peb_by_base:
                extra_not_in_load += 1
                vad_pids.add(pid)
                logger.debug(
                    "[LdrModules/VAD] PID %d: %s (base=0x%x) not in PEB LDR load list",
                    pid, basename, vad_base,
                )

        return extra_not_in_load, vad_pids

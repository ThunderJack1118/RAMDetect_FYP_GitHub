"""
ramdetect/features/native_indicator_features.py
────────────────────────────────────────────────
Clean-safe native indicator feature builder for RAMDetect live inference.

Enabled:
  - malfind: confirmed InjectionDetector alerts only, calibrated to CIC/Volatility
    malfind-style feature names.
  - ldrmodules: safe average values plus Phase-1 raw count values from native DLL parser.

Disabled intentionally:
  - svcscan.* native inference
  - modules.* native inference
  - psxview/callback approximations

This file does not change the ML threshold, add veto rules, add clean dampeners,
or call Volatility. It only decides which native live features are safe enough to
feed into the 54-feature ML mapping. The RF threshold is fixed at 0.5 by the
RAMDetect master rule.
"""

from __future__ import annotations

from typing import Any, Dict, List
import logging
import os
import re


class NativeIndicatorFeatureBuilder:
    """Build clean-safe RAMDetect-native equivalents for selected canonical features."""

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)

    def build(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}
        features.update(self._build_malfind_equivalent(parsed_data))

        # PHASE_E_PARSER_CONFIRMED_THREAD_MALFIND_BRIDGE: merge parser-confirmed thread injection artifacts into malfind.*.
        # This is feature extraction only. It does not change ML threshold or verdict logic.
        try:
            _thread_mf = self._build_thread_confirmed_malfind_equivalent(parsed_data)
            for _k, _v in (_thread_mf or {}).items():
                if _k.startswith("_debug_"):
                    features[_k] = float(_v)
                else:
                    features[_k] = max(float(features.get(_k, 0.0) or 0.0), float(_v or 0.0))
        except Exception as exc:
            self.logger.warning("Thread-confirmed malfind bridge disabled: %s", exc)
        features.update(self._build_ldr_safe_averages(parsed_data))

        # Phase-1 native 54-feature completion: enable raw LDR count features
        # derived from already-confirmed native PEB 3-list DLL rows.  This does
        # not add a rule, threshold change, or Volatility dependency.  Set
        # RAMDETECT_ENABLE_RAW_LDR_COUNTS=0 to roll back to avg-only mode.
        if os.environ.get("RAMDETECT_ENABLE_RAW_LDR_COUNTS", "1").strip().lower() not in {"0", "false", "no", "off"}:
            features.update(self._build_ldr_raw_counts(parsed_data))

        # Hard safety guard: never emit broad unsupported families from live data.
        for k in list(features.keys()):
            if (
                k.startswith("svcscan.")
                or k.startswith("modules.")
                or k.startswith("callbacks.")
                or k.startswith("psxview.")
                or k in {
                    "total_services",
                    "kernel_driver_services",
                    "filesystem_driver_services",
                    "process_services",
                    "shared_process_services",
                    "interactive_process_services",
                    "active_services",
                    "total_modules",
                    "total_callbacks",
                    "anonymous_callbacks",
                    "generic_callbacks",
                }
            ):
                features.pop(k, None)
        return features


    # PHASE_E_PARSER_CONFIRMED_THREAD_MALFIND_BRIDGE
    def _build_thread_confirmed_malfind_equivalent(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Build CIC-compatible malfind.* values from confirmed thread artifacts.

        Safety policy:
        - Does NOT read or promote raw_features["unbacked_thread_start_count"].
        - Requires parser-level thread evidence such as is_injected=True,
          is_remote_thread=True, or explicit anomaly/status text mentioning
          unbacked/private injection style execution.
        - Suppresses common JIT/browser/modern Windows processes unless a thread
          is explicitly marked injected by the parser.
        - Produces features only; final verdict remains ML-only at threshold 0.5.
        """
        threads: List[Dict[str, Any]] = parsed_data.get("threads", []) or []
        processes: List[Dict[str, Any]] = parsed_data.get("processes", []) or []

        if not threads:
            return {}

        def _safe_int(v, default=0) -> int:
            try:
                if isinstance(v, str):
                    s = v.strip()
                    if not s or s.lower() in {"none", "n/a", "-", "?"}:
                        return default
                    return int(s, 16) if s.lower().startswith("0x") else int(s)
                return int(v or default)
            except Exception:
                return default

        def _basename(v: Any) -> str:
            s = str(v or "").strip().lower().replace("/", "\\")
            return s.rsplit("\\", 1)[-1]

        pid_name = {}
        for p in processes:
            pid = _safe_int(p.get("pid") or p.get("PID"), 0)
            name = (
                p.get("image_name") or p.get("ImageFileName") or p.get("name")
                or p.get("process_name") or p.get("Process Name") or ""
            )
            if pid:
                pid_name[pid] = _basename(name)

        jit_or_modern = {
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "javaw.exe", "node.exe", "electron.exe", "code.exe", "discord.exe",
            "slack.exe", "teams.exe", "spotify.exe", "atom.exe", "vscode.exe",
            "msedge", "msedgewebview2.exe", "runtimebroker.exe", "searchapp.exe",
            "searchhost.exe", "startmenuexperiencehost.exe", "applicationframehost.exe",
            "winstore.app.exe", "smartscreen.exe", "textinputhost.exe", "lockapp.exe",
            "widgets.exe", "sihost.exe", "dwm.exe",
        }

        explicit_terms = (
            "unbacked code", "unbacked", "unusual start address", "private mem",
            "private+x", "private executable", "remote injection", "injected",
            "code injection", "potential injection", "shellcode", "hollow",
            "malfind", "thread start in private", "start address outside module",
        )

        confirmed = []
        seen = set()

        for t in threads:
            if not isinstance(t, dict):
                continue
            pid = _safe_int(t.get("pid") or t.get("PID"), 0)
            tid = _safe_int(t.get("tid") or t.get("TID") or t.get("thread_id"), 0)
            start = _safe_int(
                t.get("start_address") or t.get("StartAddress") or t.get("start")
                or t.get("entry_point") or t.get("EntryPoint"),
                0,
            )
            proc_name = _basename(
                t.get("process_name") or t.get("process") or t.get("Process")
                or pid_name.get(pid, "")
            )

            anomalies = t.get("anomalies", [])
            if isinstance(anomalies, (list, tuple, set)):
                anomaly_text = " ".join(str(x) for x in anomalies)
            else:
                anomaly_text = str(anomalies or "")
            text = " ".join(str(t.get(k, "")) for k in (
                "anomaly", "Anomaly", "status", "Status", "status_reason",
                "reason", "Reason", "description", "Description", "details", "Details",
                "finding", "Finding", "type", "Type"
            ))
            all_text = (anomaly_text + " " + text).lower()

            explicit_flag = bool(t.get("is_injected") or t.get("is_remote_thread") or t.get("injected"))
            explicit_text = any(term in all_text for term in explicit_terms)

            if not explicit_flag and not explicit_text:
                continue

            # Browser/JIT/modern app private executable memory can be normal. Only
            # keep these if the parser explicitly marked the thread injected.
            if proc_name in jit_or_modern and not explicit_flag:
                continue

            # Require at least a PID or process name, and preferably a concrete thread/start.
            if not pid and not proc_name:
                continue

            key = (pid, tid, start, proc_name)
            if key in seen:
                continue
            seen.add(key)
            confirmed.append({"pid": pid, "tid": tid, "start": start, "process": proc_name})

        if not confirmed:
            return {
                "_debug_thread_malfind_confirmed_count": 0.0,
                "_debug_thread_malfind_confirmed_targets": 0.0,
            }

        target_ids = {str(x["pid"] or x["process"]) for x in confirmed if x.get("pid") or x.get("process")}
        n_threads = len(confirmed)
        n_targets = max(1, len(target_ids))

        # Keep calibration conservative and CIC-like. Existing successful live
        # detections use malfind.ninjections≈64 and commitCharge≈256 for one
        # confirmed injection target. Cap to avoid one noisy process dominating.
        ninj = float(min(64 * n_targets, 128))
        commit = float(min(256 * n_targets, 512))

        return {
            "malfind.ninjections": ninj,
            "malfind.commitCharge": commit,
            "malfind.uniqueInjections": float(n_targets),
            "injection_count": ninj,
            "total_commit_charge": commit,
            "unique_injection_targets": float(n_targets),
            "_debug_thread_malfind_confirmed_count": float(n_threads),
            "_debug_thread_malfind_confirmed_targets": float(n_targets),
        }

    def _build_ldr_safe_averages(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """Return only normalized LDR average features; preserve defaults if unavailable."""
        try:
            from ramdetect.features.ldrmodules_features import LdrModulesFeatureBuilder
            ldr = LdrModulesFeatureBuilder().build_safe_averages_only(parsed_data)
        except Exception as exc:
            self.logger.warning("Native LDR safe features disabled: %s", exc)
            return {}

        if not ldr:
            return {}

        def _f(key: str, default: float = 0.0) -> float:
            try:
                return float(ldr.get(key, default) or default)
            except Exception:
                return default

        avg_load = min(max(_f("ldrmodules.not_in_load_avg") or _f("avg_not_in_load"), 0.0), 10.0)
        avg_init = min(max(_f("ldrmodules.not_in_init_avg") or _f("avg_not_in_init"), 0.0), 10.0)
        avg_mem = min(max(_f("ldrmodules.not_in_mem_avg") or _f("avg_not_in_mem"), 0.0), 10.0)
        ratio = max(avg_load, avg_init, avg_mem)

        self.logger.info(
            "Native LDR safe features: avg_not_load=%.4f avg_not_init=%.4f avg_not_mem=%.4f",
            avg_load,
            avg_init,
            avg_mem,
        )

        out = {
            "ldrmodules.not_in_load_avg": avg_load,
            "ldrmodules.not_in_init_avg": avg_init,
            "ldrmodules.not_in_mem_avg": avg_mem,
            "avg_not_in_load": avg_load,
            "avg_not_in_init": avg_init,
            "avg_not_in_mem": avg_mem,
            "ldrmodules_mismatch_ratio": ratio,
        }
        # Keep debug keys out of canonical mapping, but available to logs if caller inspects them.
        for k in ("_debug_ldr_total_rows", "_debug_ldr_complete_rows", "_debug_ldr_valid_processes"):
            if k in ldr:
                out[k] = float(ldr[k])
        return out


    def _build_ldr_raw_counts(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """Return raw LDR count features from complete native PEB 3-list DLL rows."""
        try:
            from ramdetect.features.ldrmodules_features import LdrModulesFeatureBuilder
            ldr = LdrModulesFeatureBuilder().build_raw_counts_only(parsed_data)
        except Exception as exc:
            self.logger.warning("Native LDR raw count features disabled: %s", exc)
            return {}

        if not ldr:
            return {}

        out: Dict[str, float] = {}
        allowed = {
            "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
            "dlls_not_in_load_list", "dlls_not_in_init_list", "dlls_not_in_mem_list",
            "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
            "avg_not_in_load", "avg_not_in_init", "avg_not_in_mem", "ldrmodules_mismatch_ratio",
            "_debug_ldr_raw_total_rows", "_debug_ldr_raw_complete_rows",
            "_debug_ldr_raw_valid_processes", "_debug_ldr_raw_not_in_load",
            "_debug_ldr_raw_not_in_init", "_debug_ldr_raw_not_in_mem",
        }
        for k in allowed:
            if k in ldr:
                try:
                    out[k] = float(ldr[k])
                except Exception:
                    pass

        self.logger.info(
            "Native LDR raw count features: not_load=%s not_init=%s not_mem=%s",
            out.get("ldrmodules.not_in_load", "default"),
            out.get("ldrmodules.not_in_init", "default"),
            out.get("ldrmodules.not_in_mem", "default"),
        )
        return out

    # ── malfind equivalent ────────────────────────────────────────────────────


    # PHASE_E2_PRESERVE_AND_CALIBRATE_MALFIND
    def _build_malfind_equivalent(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Build CIC-compatible malfind.* values from parser-confirmed evidence.

        Phase E2 safety policy:
        - Do NOT use raw normalized native scores such as unbacked_thread_start_count.
        - Do NOT add a verdict rule, veto rule, layer rule, or threshold change.
        - Count only parser-confirmed injection evidence:
            1) InjectionDetector alert rows in parsed_data['injections'];
            2) explicit injection-labelled memory/VAD/PE rows;
            3) explicit thread rows marked injected/remote or with injection text.
        - Preserve strong values: never collapse parser-confirmed evidence to 1/0/1.
          A single confirmed injection target is calibrated to CIC-like values
          malfind.ninjections ~= 64 and malfind.commitCharge ~= 256 because the
          existing successful RAMDetect detections used that scale.
        """
        injections: List[Dict[str, Any]] = parsed_data.get("injections", []) or []
        threads: List[Dict[str, Any]] = parsed_data.get("threads", []) or []
        processes: List[Dict[str, Any]] = parsed_data.get("processes", []) or []
        pe_sections: List[Dict[str, Any]] = (
            parsed_data.get("pe_sections") or parsed_data.get("memory_regions")
            or parsed_data.get("vads") or []
        )

        def _safe_int(v, default=0) -> int:
            try:
                if isinstance(v, str):
                    s = v.strip()
                    if not s or s.lower() in {"none", "n/a", "na", "-", "?"}:
                        return default
                    return int(s, 16) if s.lower().startswith("0x") else int(float(s))
                return int(v or default)
            except Exception:
                return default

        def _safe_float(v, default=0.0) -> float:
            try:
                if isinstance(v, str):
                    s = v.strip()
                    if not s or s.lower() in {"none", "n/a", "na", "-", "?"}:
                        return default
                    return float(int(s, 16)) if s.lower().startswith("0x") else float(s)
                return float(v or default)
            except Exception:
                return default

        def _basename(v: Any) -> str:
            s = str(v or "").strip().lower().replace("/", "\\")
            return s.rsplit("\\", 1)[-1]

        def _text_of(row: Dict[str, Any]) -> str:
            parts = []
            for k in (
                "anomaly", "Anomaly", "anomalies", "status_reason", "Status", "status",
                "reason", "Reason", "description", "Description", "finding", "Finding",
                "type", "Type", "section", "Section", "details", "Details",
                "protection", "Protection", "vad_type", "VadType", "tag", "Tag",
            ):
                v = row.get(k, "")
                if isinstance(v, (list, tuple, set)):
                    parts.extend(str(x) for x in v)
                else:
                    parts.append(str(v))
            return " ".join(parts).lower()

        explicit_terms = (
            "injection", "inject", "injected", "shellcode", "hollow", "hollowing",
            "reflective", "remote thread", "apc", "atom bombing", "malfind",
            "mz/pe in private", "pe header in private", "pe in private",
            "pe in anonymous", "anonymous private memory", "thread start in private",
            "start address outside module", "unbacked code", "unbacked",
            "private+x", "private executable", "manual mapped", "manual-map",
        )

        def _explicit_injection_text(row: Dict[str, Any]) -> bool:
            text = _text_of(row)
            return any(term in text for term in explicit_terms)

        def _extract_size_pages_from_text(text: str) -> int:
            if not text:
                return 0
            # Accept common forms such as size=0x200000, size: 8192, region_size=...
            m = re.search(r"(?:size|region_size|commit|commit_charge)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", str(text))
            if not m:
                return 0
            size = _safe_int(m.group(1), 0)
            return max(1, size // 4096) if size > 0 else 0

        def _row_pages(row: Dict[str, Any], default_pages: int = 256) -> int:
            for k in (
                "commit_charge", "commitCharge", "malfind.commitCharge",
                "commit", "pages", "page_count", "PageCount",
            ):
                pages = _safe_int(row.get(k), 0)
                if pages > 0:
                    return pages
            for k in ("size", "region_size", "RegionSize", "Virtual Size", "virtual_size", "Raw Size", "raw_size"):
                size = _safe_int(row.get(k), 0)
                if size > 0:
                    return max(1, size // 4096)
            pages = _extract_size_pages_from_text(_text_of(row))
            return pages if pages > 0 else default_pages

        def _target_id(row: Dict[str, Any]) -> str:
            pid = row.get("pid") or row.get("target_pid") or row.get("PID") or row.get("ProcessId")
            if pid not in (None, "", 0, "0"):
                return str(pid)
            pname = (
                row.get("process") or row.get("process_name") or row.get("proc_name")
                or row.get("Process") or row.get("ImageFileName") or row.get("name")
            )
            return _basename(pname)

        def _is_confirmed_injection_alert(row: Dict[str, Any]) -> bool:
            if not isinstance(row, dict):
                return False
            # parsed_data['injections'] is already the output of InjectionDetector;
            # still accept explicit flags/text for compatibility with older exports.
            if row.get("is_injected") or row.get("injected") or row.get("pe_confirmed") or row.get("PE Confirmed"):
                return True
            if _explicit_injection_text(row):
                return True
            # If it is present in parsed_data['injections'] and has a pid/process or
            # address-like field, treat it as parser-confirmed.
            return bool(
                _target_id(row)
                or row.get("start_address") or row.get("StartAddress")
                or row.get("address") or row.get("Address")
            )

        # Build pid->process_name for thread rows.
        pid_name: Dict[int, str] = {}
        for p in processes:
            if not isinstance(p, dict):
                continue
            pid = _safe_int(p.get("pid") or p.get("PID") or p.get("ProcessId"), 0)
            name = (
                p.get("image_name") or p.get("ImageFileName") or p.get("name")
                or p.get("process_name") or p.get("Process Name") or ""
            )
            if pid:
                pid_name[pid] = _basename(name)

        # Conservative JIT/browser suppression for text-only thread evidence.
        jit_or_modern = {
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "javaw.exe", "node.exe", "electron.exe", "code.exe", "discord.exe",
            "slack.exe", "teams.exe", "spotify.exe", "atom.exe", "vscode.exe",
            "msedgewebview2.exe", "runtimebroker.exe", "searchapp.exe",
            "searchhost.exe", "startmenuexperiencehost.exe", "applicationframehost.exe",
            "winstore.app.exe", "smartscreen.exe", "textinputhost.exe", "lockapp.exe",
            "widgets.exe", "sihost.exe", "dwm.exe",
        }

        confirmed_rows: List[Dict[str, Any]] = []
        confirmed_targets: set[str] = set()
        commit_pages = 0

        # 1) InjectionDetector alerts: strongest and safest evidence source.
        for row in injections:
            if not isinstance(row, dict) or not _is_confirmed_injection_alert(row):
                continue
            confirmed_rows.append(row)
            target = _target_id(row)
            if target:
                confirmed_targets.add(target)
            commit_pages += _row_pages(row, default_pages=256)

        # 2) Explicit injection-labelled VAD/PE/memory rows.
        for row in pe_sections:
            if not isinstance(row, dict) or not _explicit_injection_text(row):
                continue
            confirmed_rows.append(row)
            target = _target_id(row)
            if target:
                confirmed_targets.add(target)
            commit_pages += _row_pages(row, default_pages=64)

        # 3) Explicit thread-level injection markers. This is used only when the
        # parser gives explicit flags/text, not from aggregate raw scores.
        seen_threads = set()
        for row in threads:
            if not isinstance(row, dict):
                continue
            pid = _safe_int(row.get("pid") or row.get("PID") or row.get("ProcessId"), 0)
            tid = _safe_int(row.get("tid") or row.get("TID") or row.get("thread_id"), 0)
            start = _safe_int(row.get("start_address") or row.get("StartAddress") or row.get("start"), 0)
            proc_name = _basename(
                row.get("process_name") or row.get("process") or row.get("Process")
                or pid_name.get(pid, "")
            )

            explicit_flag = bool(row.get("is_injected") or row.get("is_remote_thread") or row.get("injected"))
            explicit_text = _explicit_injection_text(row)
            if not explicit_flag and not explicit_text:
                continue
            if proc_name in jit_or_modern and not explicit_flag:
                continue
            if not pid and not proc_name:
                continue

            key = (pid, tid, start, proc_name)
            if key in seen_threads:
                continue
            seen_threads.add(key)
            confirmed_rows.append(row)
            confirmed_targets.add(str(pid or proc_name))
            commit_pages += _row_pages(row, default_pages=256)

        if not confirmed_rows:
            return {
                "malfind.ninjections": 0.0,
                "malfind.commitCharge": 0.0,
                "malfind.uniqueInjections": 0.0,
                "injection_count": 0.0,
                "unique_injection_targets": 0.0,
                "total_commit_charge": 0.0,
                "pe_section_injection_count": 0.0,
                "_debug_phaseE2_confirmed_rows": 0.0,
                "_debug_phaseE2_confirmed_targets": 0.0,
            }

        n_targets = max(1, len(confirmed_targets))
        n_rows = max(1, len(confirmed_rows))

        # CIC-like calibration:
        # - One confirmed target should not become 1. It should be strong enough
        #   to match the scale the RF saw during the already-successful cases.
        # - Multiple confirmed rows/targets increase the value but are capped.
        calibrated_ninj = max(64, 64 * n_targets, 16 * n_rows)
        calibrated_commit = max(256, commit_pages, 256 * n_targets)

        # Hard caps avoid one noisy parser output dominating the vector.
        calibrated_ninj = min(calibrated_ninj, 512)
        calibrated_commit = min(calibrated_commit, 4096)

        return {
            # Canonical names; required because FeatureMapper can consume the
            # exact canonical key even when no explicit source alias exists.
            "malfind.ninjections": float(calibrated_ninj),
            "malfind.commitCharge": float(calibrated_commit),
            "malfind.uniqueInjections": float(n_targets),
            # Legacy aliases used by the current FeatureMapper mapping.
            "injection_count": float(calibrated_ninj),
            "unique_injection_targets": float(n_targets),
            "total_commit_charge": float(calibrated_commit),
            "pe_section_injection_count": float(len([r for r in confirmed_rows if r not in injections])),
            "_debug_phaseE2_confirmed_rows": float(n_rows),
            "_debug_phaseE2_confirmed_targets": float(n_targets),
            "_debug_phaseE2_commit_pages": float(commit_pages),
        }


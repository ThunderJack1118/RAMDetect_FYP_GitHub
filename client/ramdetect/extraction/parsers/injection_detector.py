"""
ramdetect/extraction/parsers/injection_detector.py
==================================================
Engine 9: Injection Detector
Heuristic engine: Finds threads in unbacked memory and RWX regions.
FIXED: Robust process name matching (Fix 1) to prevent Browser False Positives.
"""

from typing import List, Dict, Set, Any
import logging
import struct
import re
import os

class InjectionDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # [LOG] Confirm initialization so log file isn't empty
        self.logger.info("InjectionDetector initialized and ready.")
        # PHASE_F1_INJECTION_CANDIDATE_AUDIT_INIT: diagnostic-only candidate rows from the last detect_injections() call.
        # This is never used for verdict logic; analysis_bridge only exports it for experiments.
        self.last_candidate_audit = []

    @staticmethod
    def _is_user_address(value: int) -> bool:
        """Return True for plausible Windows x64 user-mode virtual addresses."""
        try:
            v = int(value or 0)
        except Exception:
            return False
        return 0x10000 <= v < 0x0000800000000000

    @staticmethod
    def _is_executable_protection(protection: Any) -> bool:
        """Normalize RAMDetect/Windows VAD protection strings and flags."""
        if isinstance(protection, int):
            return bool(protection & (0x10 | 0x20 | 0x40 | 0x80))
        p = str(protection or '').upper()
        return 'EXECUTE' in p or 'X' in p

    @staticmethod
    def _is_writable_protection(protection: Any) -> bool:
        if isinstance(protection, int):
            return bool(protection & (0x04 | 0x40 | 0x80))
        p = str(protection or '').upper()
        return 'WRITE' in p or 'W' in p or 'RWX' in p or 'WCX' in p

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            if isinstance(value, str):
                value = value.strip()
                if not value or value.lower() in {'none', 'n/a', '-'}:
                    return default
                return int(value, 16) if value.lower().startswith('0x') else int(value)
            return int(value or default)
        except Exception:
            return default

    @classmethod
    def _size_to_pages(cls, size: Any) -> int:
        size_i = cls._safe_int(size, 0)
        return max(1, size_i // 4096) if size_i > 0 else 1

    @classmethod
    def _vad_contains_thread_start(cls, vad: Dict, threads: List[Dict]) -> bool:
        start = cls._safe_int(vad.get('start'), 0)
        end = cls._safe_int(vad.get('end'), 0)
        if not start or not end:
            return False
        for t in threads or []:
            addr = cls._safe_int(t.get('start_address'), 0)
            if addr and start <= addr <= end:
                return True
        return False

    @staticmethod
    def _clear_translator_tlb(translator) -> None:
        try:
            if hasattr(translator, 'tlb'):
                translator.tlb.clear()
        except Exception:
            pass



    # PHASE_J8_INJECTION_ARTIFACT_COMPLETENESS
    # Parser evidence enrichment only.  This does not alter the RF threshold,
    # FeatureMapper, model files, dataset, or post-classification verdict logic.
    @classmethod
    def _find_vad_for_address(cls, address: Any, vads: List[Dict]) -> Dict[str, Any]:
        """Return the VAD row containing a virtual address, if available."""
        addr = cls._safe_int(address, 0)
        if not addr:
            return {}
        for v in vads or []:
            if not isinstance(v, dict):
                continue
            start = cls._safe_int(v.get('start') or v.get('base_address') or v.get('address'), 0)
            end = cls._safe_int(v.get('end'), 0)
            size = cls._safe_int(v.get('size') or v.get('region_size') or v.get('RegionSize'), 0)
            if start and not end and size:
                end = start + size - 1
            if start and end and start <= addr <= end:
                return v
        return {}

    @staticmethod
    def _parse_address_from_details(details: Any) -> int:
        """Parse '@ 0x...' style addresses from detector details."""
        text = str(details or '')
        m = re.search(r'@\s*(0x[0-9a-fA-F]+)', text)
        if not m:
            return 0
        try:
            return int(m.group(1), 16)
        except Exception:
            return 0

    @classmethod
    def _parse_size_from_details(cls, details: Any) -> int:
        """Parse size=0x... / region_size=... style values from details."""
        text = str(details or '')
        m = re.search(r'(?:size|region_size|vad_size)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)', text)
        if not m:
            return 0
        return cls._safe_int(m.group(1), 0)

    @staticmethod
    def _parse_protection_from_details(details: Any) -> str:
        """Parse prot=... / protection=... from detector details."""
        text = str(details or '')
        m = re.search(r'\b(?:prot|protection|permissions?)\s*[:=]\s*([^\)\],;\s]+)', text, re.I)
        return m.group(1).strip() if m else ''

    @classmethod
    def _normalize_detection_evidence(cls, det: Dict[str, Any], vads: List[Dict], *, pid: int, process_name: str) -> Dict[str, Any]:
        """Add explicit address / size / protection fields for UI and audits.

        Older detector branches mainly stored human-readable details.  J8 keeps
        the same detection decision but makes the evidence structured so the GUI,
        reports and K3G/J7 audits do not have to reverse-engineer every string.
        """
        if not isinstance(det, dict):
            return det

        det.setdefault('pid', pid)
        det.setdefault('process_name', process_name)

        details = det.get('details') or det.get('description') or det.get('status_reason') or ''

        raw_addr = (
            det.get('address') or det.get('virtual_address') or det.get('start_address')
            or det.get('base_address') or det.get('vad_start') or det.get('matched_vad_start')
            or det.get('thread_start_address')
        )
        addr = cls._safe_int(raw_addr, 0) or cls._parse_address_from_details(details)

        # Preserve parsed thread-start addresses even when they are kernel-mode
        # addresses.  Only user-mode addresses are promoted to the generic
        # artifact address field because the GUI's Virtual Address column is
        # intended for user VAD / code-region addresses.
        if addr:
            det.setdefault('thread_start_address', addr)
            if cls._is_user_address(addr):
                det.setdefault('address', addr)
                det.setdefault('virtual_address', addr)
                det.setdefault('start_address', addr)
                det.setdefault('address_source', 'detector_details_or_existing_field')
            else:
                det.setdefault('address_source', 'kernel_thread_start_not_user_vad')

        vad = cls._find_vad_for_address(det.get('address') or addr, vads)
        if vad:
            v_start = cls._safe_int(vad.get('start') or vad.get('base_address') or vad.get('address'), 0)
            v_size = cls._safe_int(vad.get('size') or vad.get('region_size') or vad.get('RegionSize'), 0)
            v_end = cls._safe_int(vad.get('end'), 0)
            if v_start:
                det.setdefault('vad_start', v_start)
                det.setdefault('matched_vad_start', v_start)
            if v_end:
                det.setdefault('vad_end', v_end)
                det.setdefault('matched_vad_end', v_end)
            if v_size:
                det.setdefault('size', v_size)
                det.setdefault('region_size', v_size)
                det.setdefault('vad_size', v_size)
                det.setdefault('matched_vad_size', v_size)
                det.setdefault('size_source', 'matched_vad')
                det.setdefault('commit_charge', cls._size_to_pages(v_size))
            prot = vad.get('protection') or vad.get('vad_protection') or vad.get('permissions') or ''
            if prot:
                det.setdefault('protection', prot)
                det.setdefault('vad_protection', prot)
                det.setdefault('matched_vad_protection', prot)
            vtype = vad.get('type') or vad.get('vad_type') or ''
            if vtype:
                det.setdefault('region_type', vtype)
                det.setdefault('matched_vad_type', vtype)

        # String fallback for branches that include values only inside details.
        parsed_size = cls._parse_size_from_details(details)
        if parsed_size:
            det.setdefault('size', parsed_size)
            det.setdefault('region_size', parsed_size)
            det.setdefault('vad_size', parsed_size)
            det.setdefault('size_source', 'detector_details')
            det.setdefault('commit_charge', cls._size_to_pages(parsed_size))

        parsed_prot = cls._parse_protection_from_details(details)
        if parsed_prot:
            det.setdefault('protection', parsed_prot)
            det.setdefault('vad_protection', parsed_prot)
            det.setdefault('protection_source', 'detector_details')

        # If we only have commit charge, provide a clearly labelled estimate for
        # reports.  Do not pretend this is a real VAD size.
        if not det.get('size'):
            pages = cls._safe_int(det.get('commit_charge') or det.get('commitCharge') or det.get('pages'), 0)
            if pages > 0:
                det.setdefault('size_estimate', pages * 4096)
                det.setdefault('size_source', 'commit_charge_estimate')

        if not det.get('protection'):
            det.setdefault('protection', 'UNKNOWN')
            det.setdefault('vad_protection', 'UNKNOWN')
            det.setdefault('protection_source', 'not_observed')

        return det

    # PHASE_I2F_CONTROLLED_MALFIND_PROMOTION
    # Official parser-level evidence enhancement validated through Phase I2G/K1.
    # It creates InjectionDetector rows only when the narrow clean-safe policy
    # is satisfied: kernel/thread start evidence + suspicious path evidence in
    # a non-JIT, non-trusted process. It does not change RF threshold, model,
    # dataset, FeatureMapper, or verdict logic.
    I2F_BROWSER_JIT_NAMES = (
        "chrome", "msedge", "edge", "firefox", "iexplore", "opera",
        "brave", "vivaldi", "webview", "searchapp", "searchhost",
        "runtimebroker", "textinputhost", "startmenuexperiencehost",
        "applicationframehost", "winstore", "lockapp", "widgets",
        "electron", "node", "code.exe", "teams.exe", "slack.exe",
        "discord.exe", "spotify.exe",
    )
    I2F_TRUSTED_NAMES = (
        "system", "registry", "memcompression", "svchost", "csrss",
        "wininit", "winlogon", "services", "lsass", "smss", "dwm",
        "fontdrvhost", "spoolsv", "searchindexer", "wmi", "wmiprvse",
        "msmpeng", "mpdefendercore", "securityhealth", "vgauthservice",
        "vmtoolsd",
        # PHASE_I2G_CLEAN_SAFE_SHELL_SUPPRESSION
        # Clean-baseline validation showed that benign shell/UI hosts can satisfy
        # the broad I2F kernel-start + suspicious-path policy. These names are
        # trusted only when _i2f_is_trusted_context() has already confirmed that
        # the process path is not corrupt/non-printable. Corrupt paths still
        # remain untrusted and can be promoted by I2F.
        "explorer", "explorer.exe",
        "shellexperiencehost", "shellexperiencehost.exe",
        "shellexperienc", "shellexperienc.exe",

    )
    I2F_SUSPICIOUS_PATH_RE = re.compile(
        r"(\\users\\|\\temp\\|\\appdata\\|\\programdata\\|desktop|downloads|powershell|cmd\.exe|procexp|skype|onedrive)",
        re.I,
    )
    I2F_NONPRINTABLE_RE = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")

    @staticmethod
    def _env_enabled(name: str, default: str = "0") -> bool:
        return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _basename_from_path(value: Any) -> str:
        s = str(value or "").strip().lower().replace("/", "\\")
        return s.rsplit("\\", 1)[-1]

    @classmethod
    def _i2f_is_jit_or_browser(cls, name: str, path: str = "") -> bool:
        s = f"{name} {path}".lower()
        return any(token in s for token in cls.I2F_BROWSER_JIT_NAMES)

    @classmethod
    def _i2f_path_is_corrupt(cls, path: str) -> bool:
        return bool(path and cls.I2F_NONPRINTABLE_RE.search(str(path)))

    @classmethod
    def _i2f_is_trusted_context(cls, name: str, path: str = "") -> bool:
        # Corrupt paths are intentionally not trusted, even when the process name
        # looks common (for example explorer.exe with a corrupted image path).
        if cls._i2f_path_is_corrupt(path):
            return False
        s = f"{name} {path}".lower().replace("/", "\\")
        if any(token in s for token in cls.I2F_TRUSTED_NAMES):
            return True
        trusted_path_markers = (
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\windows\\systemapps\\",
            "\\program files\\windowsapps\\",
            "\\program files (x86)\\microsoft\\edgewebview\\",
        )
        return any(marker in s for marker in trusted_path_markers)

    @classmethod
    def _i2f_path_is_suspicious(cls, value: Any) -> bool:
        s = str(value or "").replace("/", "\\")
        if not s:
            return False
        return bool(cls.I2F_SUSPICIOUS_PATH_RE.search(s) or cls._i2f_path_is_corrupt(s))

    @classmethod
    def _i2f_collect_kernel_start_signals(cls, threads: List[Dict]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for t in threads or []:
            if not isinstance(t, dict):
                continue
            start = cls._safe_int(t.get('start_address') or t.get('StartAddress') or t.get('start'), 0)
            anomalies = t.get('anomalies', [])
            if isinstance(anomalies, (list, tuple, set)):
                anomaly_text = " ".join(str(x) for x in anomalies).lower()
            else:
                anomaly_text = str(anomalies or "").lower()
            if start >= 0xFFFF000000000000 or "kernel mode start address" in anomaly_text:
                rows.append({
                    'tid': t.get('tid') or t.get('TID') or t.get('thread_id'),
                    'start_address': start,
                    'anomalies': anomalies,
                })
        return rows

    @classmethod
    def _i2f_collect_suspicious_path_signals(cls, process_path: str, vads: List[Dict]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if cls._i2f_path_is_suspicious(process_path):
            rows.append({'source': 'process_path', 'path': process_path, 'commit_charge': 0})
        path_keys = (
            'path', 'file_path', 'mapped_path', 'mapped_file', 'filename', 'file_name',
            'name', 'details', 'status_reason', 'description', 'section_name', 'vad_path',
        )
        for v in vads or []:
            if not isinstance(v, dict):
                continue
            text_parts = []
            for k in path_keys:
                val = v.get(k)
                if val not in (None, ''):
                    text_parts.append(str(val))
            text = " ".join(text_parts)
            if cls._i2f_path_is_suspicious(text):
                size = cls._safe_int(v.get('size') or v.get('region_size') or v.get('RegionSize'), 0)
                rows.append({
                    'source': 'vad_or_section_path',
                    'path': text[:500],
                    'start': cls._safe_int(v.get('start') or v.get('base_address') or v.get('address'), 0),
                    'end': cls._safe_int(v.get('end'), 0),
                    'size': size,
                    'protection': v.get('protection') or v.get('vad_protection') or v.get('permissions') or '',
                    'commit_charge': max(1, size // 4096) if size > 0 else 1,
                })
        return rows

    def _maybe_promote_i2f_kernel_start_path(
        self,
        *,
        pid: int,
        process_name: str,
        process_path: str,
        proc_base: str,
        threads: List[Dict],
        vads: List[Dict],
        detections: List[Dict],
        max_detections: int,
    ) -> None:
        """Feature-flagged Phase I2F policy promotion.

        This is intentionally narrow and parser-level only. It appends a
        detection row to the same InjectionDetector output consumed by the
        existing CIC malfind feature builder. The final verdict remains RF-only.
        """
        # PHASE_K1_OFFICIAL_MALFIND_PROMOTION_DEFAULT_ON
        # I2G was validated against clean baselines and injection-like malicious dumps.
        # It is now enabled by default as RAMDetect's official parser-level evidence
        # enhancement. It still does NOT override verdicts; it only improves
        # session.injections -> malfind.* feature quality before ML classification.
        # Developer override for baseline comparison:
        #   RAMDETECT_DISABLE_MALFIND_PROMOTION=1
        disabled = self._env_enabled('RAMDETECT_DISABLE_MALFIND_PROMOTION', '0')
        enabled = not disabled
        dry_run = self._env_enabled('RAMDETECT_I2F_MALFIND_PROMOTION_DRYRUN', '0')

        kernel_rows = self._i2f_collect_kernel_start_signals(threads)
        suspicious_rows = self._i2f_collect_suspicious_path_signals(process_path, vads)
        is_jit = self._i2f_is_jit_or_browser(proc_base or process_name, process_path)
        is_trusted = self._i2f_is_trusted_context(proc_base or process_name, process_path)

        policy_match = bool(kernel_rows and suspicious_rows and not is_jit and not is_trusted)

        # Always add diagnostic context to last_candidate_audit so dry-run scans
        # can be inspected without changing session.injections.
        try:
            self.last_candidate_audit.append({
                'pid': pid,
                'process_name': process_name,
                'proc_base': proc_base,
                'process_path': process_path,
                'phase': 'I2F',
                'policy': 'kernel_start_plus_suspicious_path_nontrusted',
                'kernel_start_rows': len(kernel_rows),
                'suspicious_path_rows': len(suspicious_rows),
                'is_jit_or_browser': bool(is_jit),
                'is_trusted': bool(is_trusted),
                'policy_match': bool(policy_match),
                'enabled': bool(enabled),
                'dry_run': bool(dry_run),
                'skip_reason': (
                    'disabled' if not enabled else
                    'dry_run' if dry_run and policy_match else
                    'policy_match' if policy_match else
                    'no_kernel_start_plus_suspicious_path_or_suppressed'
                ),
            })
        except Exception:
            pass

        if not (enabled and policy_match) or dry_run:
            return
        if len(detections) >= max_detections:
            return

        commit_pages = sum(self._safe_int(r.get('commit_charge'), 0) for r in suspicious_rows)
        if commit_pages <= 0:
            commit_pages = 256
        commit_pages = max(1, min(int(commit_pages), 512))

        first_thread = kernel_rows[0] if kernel_rows else {}
        start_addr = self._safe_int(first_thread.get('start_address'), 0)
        tid = first_thread.get('tid')
        first_region = next((r for r in suspicious_rows if self._safe_int(r.get('start'), 0)), {})
        first_region_start = self._safe_int(first_region.get('start'), 0)
        first_region_end = self._safe_int(first_region.get('end'), 0)
        first_region_size = self._safe_int(first_region.get('size'), 0)
        first_protection = ''
        try:
            first_protection = next((str(r.get('protection', '') or '') for r in suspicious_rows if r.get('protection')), '')
        except Exception:
            first_protection = ''

        # Mark only the representative kernel-start thread as parser-confirmed
        # context for reports. The actual malfind values still flow through the
        # generated InjectionDetector row below.
        try:
            for t in threads or []:
                if tid and (t.get('tid') == tid or t.get('TID') == tid):
                    t['is_injected'] = True
                    t['is_remote_thread'] = True
                    anomalies = t.setdefault('anomalies', [])
                    if isinstance(anomalies, list) and 'I2F Kernel Start + Suspicious Path Promotion' not in anomalies:
                        anomalies.append('I2F Kernel Start + Suspicious Path Promotion')
                    break
        except Exception:
            pass

        detections.append({
            'type': 'Kernel Start + Suspicious Path Injection Candidate',
            'severity': 'HIGH',
            'pid': pid,
            'tid': tid,
            'details': (
                f"I2F policy match: kernel_start_rows={len(kernel_rows)}, "
                f"suspicious_path_rows={len(suspicious_rows)}"
                + (f" @ {start_addr:#x}" if start_addr else "")
            ),
            'process_name': process_name,
            'process_path': process_path,
            'confidence': 'Medium',
            'source': 'ramdetect_i2f_kernel_start_plus_suspicious_path',
            'policy': 'kernel_start_plus_suspicious_path_nontrusted',
            'kernel_start_rows': len(kernel_rows),
            'suspicious_path_rows': len(suspicious_rows),
            'thread_start_address': start_addr,
            'address': first_region_start or None,
            'virtual_address': first_region_start or None,
            'start_address': first_region_start or None,
            'vad_start': first_region_start or None,
            'vad_end': first_region_end or None,
            'size': first_region_size or None,
            'region_size': first_region_size or None,
            'vad_size': first_region_size or None,
            'address_source': 'i2f_suspicious_path_vad' if first_region_start else 'kernel_thread_start_only',
            'commit_charge': float(commit_pages),
            # PHASE_K3G_MALFIND_PROTECTION_TRACE
            # Preserve any VAD/section protection evidence attached to the
            # suspicious path signal for export-only CIC malfind.protection
            # compatibility. This does not alter verdict logic.
            'protection': first_protection or 'UNKNOWN',
            'vad_protection': first_protection or 'UNKNOWN',
            'i2f_feature_flag': True,
        })

        
    def detect_injections(self, pid: int, threads: List[Dict], dlls: List[Dict],
                         vads: List[Dict], process_name: str = "",
                         translator=None, process_dtb: int = 0,
                         process_path: str = "") -> List[Dict]:
        """
        Detect code injection with reduced false positives.

        Parameters
        ----------
        translator   : AddressTranslator instance (optional).  Required for
                       CHECK 4 (MZ signature in anonymous private memory).
        process_dtb  : Page-table base for this process.  Must be supplied
                       together with translator for CHECK 4 to run.
        """
        detections = []
        threads = threads or []
        dlls = dlls or []
        vads = vads or []
            
        # =========================================================================
        # [FIX 1] LOGIC UPDATE: Handle Full Paths correctly
        # Convert "C:\Program Files\Edge\msedge.exe" -> "msedge.exe"
        # =========================================================================
        raw_name = process_name.lower().strip() if process_name else ""
        if '\\' in raw_name:
            proc_base = raw_name.split('\\')[-1]
        else:
            proc_base = raw_name
        if not process_path and raw_name and ('\\' in raw_name or '/' in raw_name):
            process_path = process_name
            
        # ================================================
        # 1. WHITELISTS (Reduced False Positives)
        # ================================================
        
        # System processes that legitimately have complex memory patterns
        SYSTEM_PROCESS_WHITELIST = {
            'system', 'svchost.exe', 'lsass.exe', 'wininit.exe', 
            'services.exe', 'csrss.exe', 'winlogon.exe', 'smss.exe',
            'explorer.exe', 'taskhostw.exe', 'dwm.exe', 'ctfmon.exe',
            'sihost.exe', 'runtimebroker.exe', 'dllhost.exe'
        }
        
        # JIT/Electron apps that legitimately use RWX memory
        # [FIX] Added common browser variants
        JIT_APP_WHITELIST = {
            'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 
            'opera.exe', 'javaw.exe', 'node.exe', 'electron.exe',
            'code.exe', 'discord.exe', 'slack.exe', 'teams.exe',
            'spotify.exe', 'atom.exe', 'vscode.exe', 'msedge',  # Handle case without extension
            'msedgewebview2.exe'
        }

        # Modern Windows/UWP processes frequently allocate private executable
        # or JIT-like memory during normal operation. They should not be
        # counted as malfind-equivalent injections unless stronger evidence
        # exists, such as a confirmed PE in private memory or thread execution
        # from an unbacked private executable VAD.
        MODERN_WINDOWS_APP_WHITELIST = {
            'runtimebroker.exe', 'runtimebroker.',
            'searchapp.exe', 'searchhost.exe',
            'startmenuexperiencehost.exe', 'startmenuexper.exe',
            'applicationframehost.exe', 'applicationfra.exe',
            'winstore.app.exe', 'winstore.app.e.exe',
            'microsoftedgeupdate.exe', 'microsoftedgeu.exe',
            'smartscreen.exe', 'smartscreen.ex.exe',
            'textinputhost.exe', 'lockapp.exe', 'widgets.exe',
            'winstore.app'
        }
        
        # High-confidence malware indicators
        MALWARE_INDICATORS = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'rundll32.exe', 'regsvr32.exe'
        }
        
        # Check whitelists using the CLEANED base name
        is_system_proc = proc_base in SYSTEM_PROCESS_WHITELIST
        is_jit_app = proc_base in JIT_APP_WHITELIST or proc_base in MODERN_WINDOWS_APP_WHITELIST
        is_modern_windows_app = proc_base in MODERN_WINDOWS_APP_WHITELIST
        is_malware_suspect = proc_base in MALWARE_INDICATORS
        
        # System processes are not skipped completely. Weak VAD-only checks are
        # restricted below, but strong malfind-style evidence (for example, a
        # confirmed PE/MZ in private executable memory) must still be observable
        # because real injections often target trusted Windows processes.
        if is_system_proc:
            self.logger.debug(f"Restricting weak checks for system process: {process_name}")
            
        # ================================================
        # 2. THRESHOLDS & LIMITS
        # ================================================
        MAX_DETECTIONS_PER_PROCESS = 5
        MIN_DLLS_FOR_ANALYSIS = 15 
        MIN_VADS_FOR_ANALYSIS = 5

        # PHASE_F1_INJECTION_CANDIDATE_AUDIT_HELPER: diagnostic-only audit helper.
        # Records candidate thread-start evidence and skip reasons without creating detections.
        self.last_candidate_audit = []
        def _audit_thread_candidate(row: Dict[str, Any]) -> None:
            try:
                if len(self.last_candidate_audit) >= 2000:
                    return
                base = {
                    'pid': pid,
                    'process_name': process_name,
                    'proc_base': proc_base,
                    'is_system_proc': bool(is_system_proc),
                    'is_jit_app': bool(is_jit_app),
                    'is_modern_windows_app': bool(is_modern_windows_app),
                    'is_malware_suspect': bool(is_malware_suspect),
                }
                base.update(row or {})
                self.last_candidate_audit.append(base)
            except Exception:
                pass
        
        # ================================================
        # CHECK 1: Thread Start Address Analysis
        # ================================================
        if threads and (len(dlls) >= MIN_DLLS_FOR_ANALYSIS or vads):
            # Build valid memory ranges from loaded DLLs
            valid_ranges = []
            for d in dlls:
                base = d.get('base_address') or d.get('base')
                size = d.get('size', 0)
                if base and size > 0:
                    # Add some padding for DLL sections
                    valid_ranges.append((base, base + size + 0x1000))
            
            # Also consider VAD ranges as valid
            for v in vads:
                if v.get('type') in ['Image', 'Mapped']:
                    valid_ranges.append((v['start'], v['end']))
            
            unbacked_thread_count = 0
            for t in threads:
                if len(detections) >= MAX_DETECTIONS_PER_PROCESS:
                    break
                    
                start_addr = t.get('start_address')
                if not start_addr or start_addr == 0:
                    continue
                
                # Check if thread start is in a valid DLL/VAD range
                is_backed = False
                backed_range_start = 0
                backed_range_end = 0
                for v_start, v_end in valid_ranges:
                    if v_start <= start_addr < v_end:
                        is_backed = True
                        backed_range_start = v_start
                        backed_range_end = v_end
                        break

                # PHASE_F1_INJECTION_CANDIDATE_AUDIT_BACKED
                if is_backed:
                    _audit_thread_candidate({
                        'tid': t.get('tid'),
                        'start_address': hex(start_addr) if isinstance(start_addr, int) else str(start_addr),
                        'start_address_int': int(start_addr or 0),
                        'is_user_address': bool(self._is_user_address(start_addr)),
                        'is_backed_by_module_or_mapped_vad': True,
                        'backed_range_start': hex(backed_range_start) if backed_range_start else '',
                        'backed_range_end': hex(backed_range_end) if backed_range_end else '',
                        'matched_vad_start': '',
                        'matched_vad_end': '',
                        'matched_vad_type': '',
                        'matched_vad_protection': '',
                        'matched_vad_size': 0,
                        'would_detect_private_x': False,
                        'skip_reason': 'backed_by_loaded_module_or_image_mapped_vad',
                    })
                
                if not is_backed:
                    # Check VAD type at this address
                    region_type = "Unknown"
                    region_protection = ""
                    region_size = 0
                    for v in vads:
                        if v.get('start', 0) <= start_addr <= v.get('end', 0):
                            region_type = v.get('type', 'Unknown')
                            region_protection = v.get('protection', '')
                            region_size = v.get('size', 0)
                            break
                    
                    # High-confidence detection criteria:
                    # 1. Thread in Private memory (not Image/Mapped)
                    # 2. Thread in executable memory
                    # 3. Not a JIT app (browsers create lots of private executable memory)

                    # PHASE_F1_INJECTION_CANDIDATE_AUDIT_PRIVATE_X
                    _is_private_region = str(region_type).lower() == 'private'
                    _is_exec_region = self._is_executable_protection(region_protection)
                    _is_user_thread_start = self._is_user_address(start_addr)
                    _would_detect_private_x = bool(
                        _is_private_region and _is_exec_region and
                        not (is_jit_app or is_system_proc) and
                        unbacked_thread_count < 2 and
                        _is_user_thread_start
                    )
                    if _would_detect_private_x:
                        _skip_reason = 'would_detect_private_x'
                    elif not _is_user_thread_start:
                        _skip_reason = 'non_user_mode_start_address'
                    elif not _is_private_region:
                        _skip_reason = f'vad_not_private:{region_type}'
                    elif not _is_exec_region:
                        _skip_reason = f'vad_not_executable:{region_protection}'
                    elif is_jit_app:
                        _skip_reason = 'jit_or_modern_app_whitelisted'
                    elif is_system_proc:
                        _skip_reason = 'system_process_weak_thread_private_x_suppressed'
                    elif unbacked_thread_count >= 2:
                        _skip_reason = 'max_private_x_detections_per_process_reached'
                    else:
                        _skip_reason = 'unknown_private_x_skip'

                    _audit_thread_candidate({
                        'tid': t.get('tid'),
                        'start_address': hex(start_addr) if isinstance(start_addr, int) else str(start_addr),
                        'start_address_int': int(start_addr or 0),
                        'is_user_address': bool(_is_user_thread_start),
                        'is_backed_by_module_or_mapped_vad': False,
                        'matched_vad_start': hex(v.get('start', 0)) if 'v' in locals() and isinstance(v, dict) and v.get('start', 0) else '',
                        'matched_vad_end': hex(v.get('end', 0)) if 'v' in locals() and isinstance(v, dict) and v.get('end', 0) else '',
                        'matched_vad_type': str(region_type),
                        'matched_vad_protection': str(region_protection),
                        'matched_vad_size': int(region_size or 0),
                        'is_private_vad': bool(_is_private_region),
                        'is_executable_vad': bool(_is_exec_region),
                        'would_detect_private_x': bool(_would_detect_private_x),
                        'skip_reason': _skip_reason,
                    })
                    
                    # [FIX 1 Applied] 'is_jit_app' is now calculated correctly using proc_base
                    if (str(region_type).lower() == 'private' and
                        self._is_executable_protection(region_protection) and
                        not (is_jit_app or is_system_proc) and
                        unbacked_thread_count < 2):

                        # Keep only plausible user-mode thread starts.  Do not
                        # reject high-but-valid x64 user addresses.
                        if not self._is_user_address(start_addr):
                            continue

                        # [CRITICAL FIX] Tag the thread object immediately!
                        t['is_injected'] = True
                        t['is_remote_thread'] = True
                        if 'anomalies' not in t: t['anomalies'] = []
                        t['anomalies'].append("Unbacked Code (Potential Injection)")

                        detections.append({
                            'type': 'Code Injection',
                            'severity': 'HIGH',
                            'pid': pid,
                            'tid': t.get('tid'),
                            'details': f"Thread {t.get('tid')} in Private+X memory @ {start_addr:#x}",
                            'process_name': process_name,
                            'confidence': 'Medium',
                            'source': 'ramdetect_thread_private_x',
                            'commit_charge': self._size_to_pages(region_size),
                            # PHASE_K3G_MALFIND_PROTECTION_TRACE
                            'protection': region_protection,
                            'vad_protection': region_protection,
                            'vad_size': region_size,
                        })
                        unbacked_thread_count += 1
        
        # ================================================
        # CHECK 2: VAD Anomaly Detection
        # ================================================
        # Calibration rule:
        # Private executable memory alone is not enough to count as
        # malfind-equivalent injection because Windows modern apps,
        # RuntimeBroker, SearchApp, SmartScreen, Store apps, Edge components,
        # and JIT runtimes commonly create private executable regions.
        #
        # Count as injection only when the VAD-only evidence is stronger:
        #   1. Private RWX/write-execute memory in a non-whitelisted process, or
        #   2. Private executable memory in a suspicious LOLBin process.
        #
        # PE/MZ confirmation is handled separately in CHECK 4.
        if vads and len(vads) >= MIN_VADS_FOR_ANALYSIS:
            private_rwx_count = 0
            for v in vads:
                if len(detections) >= MAX_DETECTIONS_PER_PROCESS:
                    break

                vad_type = str(v.get('type', '')).lower()
                protection = str(v.get('protection', '')).upper()
                size = int(v.get('size', 0) or 0)
                start = v.get('start', 0)

                is_private = vad_type == 'private'
                is_executable = self._is_executable_protection(protection)
                is_writable = self._is_writable_protection(protection)
                thread_start_inside = self._vad_contains_thread_start(v, threads)

                if not (is_private and is_executable and size >= 0x1000):
                    continue

                # Keep weak VAD-only evidence as an observation, not as a
                # Code Injection anomaly. The native feature builder only
                # counts VADs tagged with anomaly/status_reason as injections.
                observations = v.setdefault('observations', [])
                obs = (
                    f"Private executable memory observed @ {start:#x} "
                    f"(size={size:#x}, protection={protection})"
                )
                if isinstance(observations, list) and obs not in observations:
                    observations.append(obs)

                # Whitelisted JIT/modern Windows apps are ignored at VAD-only
                # level. They are checked again by CHECK 4, where only a
                # confirmed PE in private memory is allowed to count.
                if is_jit_app:
                    continue

                # Private RX alone is weak evidence.  Count it as
                # malfind-equivalent only when execution is observed inside the
                # region, or when the process is a LOLBin.  This remains feature
                # extraction only; the final verdict stays RF-only at threshold 0.5.
                weak_whitelist = is_jit_app or is_system_proc
                strong_vad_evidence = bool(is_writable or is_malware_suspect or (thread_start_inside and not weak_whitelist))
                if not strong_vad_evidence:
                    continue

                # Reduce JIT-like noise from huge private executable regions.
                if size > 0x2000000 and not is_malware_suspect and not thread_start_inside:
                    continue

                if is_writable:
                    private_rwx_count += 1
                    if private_rwx_count > 2:
                        continue
                    detection_type = 'Private RWX/Write-Execute Memory'
                    severity = 'HIGH'
                    confidence = 'High'
                elif thread_start_inside:
                    detection_type = 'Thread Start in Private Executable Memory'
                    severity = 'HIGH'
                    confidence = 'High'
                else:
                    detection_type = 'Private Executable Memory in LOLBin'
                    severity = 'MEDIUM'
                    confidence = 'Medium'

                v['anomaly'] = 'Code Injection'
                v['status_reason'] = (
                    f"{detection_type} @ {start:#x} "
                    f"(size={size:#x}, protection={protection})"
                )

                detections.append({
                    'type': detection_type,
                    'severity': severity,
                    'pid': pid,
                    'details': (
                        f"{detection_type} @ {start:#x} "
                        f"(size={size:#x}, prot={protection})"
                    ),
                    'process_name': process_name,
                    'confidence': confidence,
                    'source': 'ramdetect_vad_only_strong',
                    'commit_charge': self._size_to_pages(size),
                    'thread_start_inside': thread_start_inside,
                    # PHASE_K3G_MALFIND_PROTECTION_TRACE
                    'protection': protection,
                    'vad_protection': protection,
                    'vad_size': size,
                })

        # ================================================
        # CHECK 3: Suspicious Process Patterns
        # ================================================
        if is_malware_suspect and threads:
            # Check for threads with start addresses in system DLL ranges
            system_dlls = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
            system_dll_ranges = []
            
            for d in dlls:
                dll_name = d.get('name', '').lower()
                if any(sys_dll in dll_name for sys_dll in system_dlls):
                    base = d.get('base_address') or d.get('base')
                    size = d.get('size', 0)
                    if base and size > 0:
                        system_dll_ranges.append((base, base + size))
            
            suspicious_threads = 0
            for t in threads:
                start_addr = t.get('start_address')
                if not start_addr:
                    continue
                    
                in_system_dll = False
                for s_start, s_end in system_dll_ranges:
                    if s_start <= start_addr < s_end:
                        in_system_dll = True
                        offset = start_addr - s_start
                        if offset > 0x10000: 
                            suspicious_threads += 1
                            if suspicious_threads == 1:
                                t['is_injected'] = True
                                if 'anomalies' not in t: t['anomalies'] = []
                                t['anomalies'].append("Thread at suspicious System DLL offset")

                                detections.append({
                                    'type': 'Suspicious Thread Location',
                                    'severity': 'MEDIUM',
                                    'pid': pid,
                                    'details': f"Thread at unusual offset in system DLL @ {start_addr:#x}",
                                    'process_name': process_name,
                                    'confidence': 'Low'
                                })
                            break
        
        # ================================================
        # CHECK 4: MZ/PE Signature in Anonymous Private Memory
        # (Malfind-style — catches injections where no thread has started yet)
        # ================================================
        # Volatility-style malfind evidence is converted into CIC-compatible
        # features only.  It does not override the verdict and does not change
        # the RF threshold, which remains fixed at 0.5.
        if (translator and vads and len(detections) < MAX_DETECTIONS_PER_PROCESS):

            original_dtb = translator.dtb
            candidate_dtbs = []
            for cand in (process_dtb, original_dtb):
                try:
                    cand_i = int(cand or 0)
                except Exception:
                    cand_i = 0
                if cand_i and cand_i not in candidate_dtbs:
                    candidate_dtbs.append(cand_i)

            try:
                for v in vads:
                    if len(detections) >= MAX_DETECTIONS_PER_PROCESS:
                        break

                    vad_type    = str(v.get('type', '')).lower()
                    protection  = v.get('protection', '')
                    start_addr  = self._safe_int(v.get('start'), 0)
                    size        = self._safe_int(v.get('size'), 0)

                    if vad_type != 'private':
                        continue
                    if not self._is_executable_protection(protection):
                        continue
                    if size < 0x1000 or not self._is_user_address(start_addr):
                        continue

                    pe_confirmed = False
                    mz_seen = False
                    used_dtb = 0

                    for cand_dtb in candidate_dtbs:
                        try:
                            translator.dtb = cand_dtb
                            self._clear_translator_tlb(translator)

                            header = translator.read_virtual(start_addr, 0x1000)
                            if not header or len(header) < 2:
                                continue
                            if header[:2] == b'MZ':
                                mz_seen = True
                                if len(header) >= 0x40:
                                    e_lfanew = struct.unpack('<I', header[0x3C:0x40])[0]
                                    if 0x40 <= e_lfanew <= 0x400:
                                        if start_addr + e_lfanew + 4 <= start_addr + len(header):
                                            pe_sig = header[e_lfanew:e_lfanew + 4]
                                        else:
                                            pe_sig = translator.read_virtual(start_addr + e_lfanew, 4)
                                        if pe_sig == b'PE\x00\x00':
                                            pe_confirmed = True
                                used_dtb = cand_dtb
                                break
                        except Exception:
                            continue

                    thread_start_inside = self._vad_contains_thread_start(v, threads)

                    # JIT/modern/system processes are noisy for generic private
                    # executable memory, so count them only when a PE header is
                    # confirmed.  Non-whitelisted processes may also count when
                    # execution starts inside the private executable region.
                    weak_whitelist = is_jit_app or is_system_proc
                    if not (pe_confirmed or (mz_seen and not is_jit_app) or (thread_start_inside and not weak_whitelist)):
                        if mz_seen:
                            observations = v.setdefault('observations', [])
                            obs = f"MZ-like header observed but not counted @ {start_addr:#x}"
                            if isinstance(observations, list) and obs not in observations:
                                observations.append(obs)
                        continue

                    if pe_confirmed:
                        detection_type = 'PE in Anonymous Private Memory'
                        severity = 'HIGH'
                        confidence = 'High'
                    elif mz_seen:
                        detection_type = 'MZ Header in Private Executable Memory'
                        severity = 'MEDIUM'
                        confidence = 'Medium'
                    else:
                        detection_type = 'Thread Start in Private Executable Memory'
                        severity = 'HIGH'
                        confidence = 'High'

                    v['anomaly'] = 'Code Injection'
                    v['status_reason'] = f'{detection_type} @ {start_addr:#x}'

                    detections.append({
                        'type': detection_type,
                        'severity': severity,
                        'pid': pid,
                        'details': (
                            f"{detection_type} @ {start_addr:#x} "
                            f"(size={size:#x}, prot={protection})"
                        ),
                        'process_name': process_name,
                        'confidence': confidence,
                        'pe_confirmed': pe_confirmed,
                        'mz_seen': mz_seen,
                        'thread_start_inside': thread_start_inside,
                        'commit_charge': self._size_to_pages(size),
                        'dtb_used': used_dtb,
                        'source': 'ramdetect_malfind_equivalent',
                        # PHASE_K3G_MALFIND_PROTECTION_TRACE
                        'protection': protection,
                        'vad_protection': protection,
                        'vad_size': size,
                    })

                    self.logger.warning(
                        f"[CHECK 4] {detection_type} in {process_name} "
                        f"(PID {pid}) @ {start_addr:#x}  prot={protection}  "
                        f"size={size:#x}  pe_confirmed={pe_confirmed}  dtb=0x{used_dtb:x}"
                    )

            except Exception as exc:
                self.logger.debug(f"CHECK 4 error for PID {pid}: {exc}")
            finally:
                translator.dtb = original_dtb
                self._clear_translator_tlb(translator)

        # ================================================
        # CHECK 5: Phase I2F controlled malfind promotion
        # ================================================
        self._maybe_promote_i2f_kernel_start_path(
            pid=pid,
            process_name=process_name,
            process_path=process_path,
            proc_base=proc_base,
            threads=threads,
            vads=vads,
            detections=detections,
            max_detections=MAX_DETECTIONS_PER_PROCESS,
        )

        # ================================================
        # 3. DEDUPLICATION & FINAL PROCESSING
        # ================================================
        
        unique_detections = []
        seen_keys = set()
        
        for det in detections:
            det = self._normalize_detection_evidence(det, vads, pid=pid, process_name=process_name)
            if 'details' in det:
                addr_match = re.search(r'@\s*(0x[0-9a-fA-F]+)', det['details'])
                if addr_match:
                    key = f"{det['type']}_{addr_match.group(1)}"
                else:
                    key = f"{det['type']}_{det['details'][:50]}"
            else:
                key = f"{det['type']}_{pid}"
            
            if key not in seen_keys:
                seen_keys.add(key)
                unique_detections.append(det)
        
        unique_detections = unique_detections[:MAX_DETECTIONS_PER_PROCESS]
        
        if unique_detections:
            self.logger.info(f"Injection detection for {process_name} (PID {pid}): "
                           f"Found {len(unique_detections)} potential injections")
        
        return unique_detections
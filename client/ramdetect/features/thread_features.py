"""
ramdetect/features/thread_features.py - FIXED VERSION
=====================================================
Fixed critical bug: Browser processes were incorrectly incrementing
unbacked_thread_start_count despite whitelisting.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
import statistics
import csv
import os
import re
from .feature_base import FeatureExtractor

class ThreadFeatures(FeatureExtractor):
    """
    Extract 15 thread-related features for malware detection.
    """
    
    KERNEL_BASE = 0xFFFF000000000000 
    NORMAL_PRIORITIES = range(8, 12)
    
    SUSPICIOUS_WAIT_REASONS = [
        'Suspended',
        'UserRequest',
        'DelayExecution'
    ]
    
    # System processes that should never trigger alerts
    SYSTEM_PROCESS_WHITELIST = {
        'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe',
        'services.exe', 'lsass.exe', 'winlogon.exe', 'registry.exe',
        'svchost.exe', 'dwm.exe', 'explorer.exe', 'sihost.exe',
        'taskhostw.exe', 'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe',
        'conhost.exe', 'fontdrvhost.exe', 'spoolsv.exe', 'audiodg.exe',
        'vmtoolsd.exe', 'mscorsvw.exe', 'wmiadap.exe', 'wuauclt.exe',
        'searchui.exe', 'shellexperiencehost.exe', 'memory compression',
        # [FIX] Additional system/platform processes missing from original whitelist.
        # 'memory compression' (old name) and 'memcompression.exe' (EPROCESS name) both needed.
        'memcompression.exe',       # MemCompression — virtual memory manager
        'searchapp.exe',            # Windows Search UI (UWP shell component)
        'searchindexer.exe',        # Windows Search Indexer service
        'skypeapp.exe',             # Skype UWP app
        'securityhealth.exe',       # Windows Security Health service
        'securityhealthservice.exe',
        'sgrmbroker.exe',           # System Guard Runtime Monitor
        'textinputhost.exe',        # Touch keyboard / handwriting
        'applicationframehost.exe', # UWP window frame host
        'startmenuexperiencehost.exe',
        'shellexperiencehost.exe',
        'smartscreen.exe',
        'tiworker.exe',             # Windows Update TiWorker
        'trustedinstaller.exe',
        'msdtc.exe',               # Distributed Transaction Coordinator
        'msmpeng.exe',             # Windows Defender (known to use private mem)
        'nissrv.exe', 'mssense.exe',
        'olk.exe', 'gamebar.exe', 'gamebarft.exe', 'widgets.exe',
        'crossdeviceres.exe', 'crossdeviceservice.exe',
        'dataexchangeho.exe', 'dataexchangehost.exe',
        'backgroundtran.exe', 'backgroundtransferhost.exe',
        'onedrivesetup.exe', 'onedrivesetu.exe', 'onedrive.exe',
        'startmenuexper.exe', 'startmenuexperiencehost.exe',
        'shellhost.exe', 'smartscreen.ex.exe', 'smartscreen.exe',
        'searchfilterho.exe', 'searchfilterhost.exe',
        'searchprotocol.exe', 'searchprotocolhost.exe',
    }
    
    # Browser processes (known to use JIT compilation and multi-process architecture)
    BROWSER_WHITELIST = {
        'msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
        'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'microsoftedge.exe',
        'msedgewebview2.exe', 'chromium.exe', 'waterfox.exe',
    }
    
    # Processes allowed to have kernel mode threads
    KERNEL_THREAD_WHITELIST = SYSTEM_PROCESS_WHITELIST | BROWSER_WHITELIST | {
        "system", "registry", "registry.exe", "smss.exe", "memory compression",
        "memcompression.exe", "fontdrvhost.exe", "dwm.exe", "audiodg.exe",
        # PHASE_F3_KERNEL_DISPATCHER_SAFE_ADDITIONS
        "winstore.app.exe",
        "winstore.app.e.exe",
        "microsoftedgeupdate.exe",
        "microsoftedgeu.exe",
        "dashost.exe",
        "wmiprvse.exe",
        "vgauthservice.exe",
        "vmacthlp.exe",
        "procexp.exe",
        "procexp64.exe",
    }
    
    # Browser-specific JIT module patterns (DLLs that contain JIT code)
    BROWSER_JIT_MODULES = {
        'v8.dll', 'chakra.dll', 'javascriptcore.dll', 'spartan.dll',
        'edgehtml.dll', 'jscript9.dll', 'chakra.dll', 'jsrt.dll',
        'pepper_flash.dll', 'chrome_elf.dll'
    }
    
    def __init__(self, logger=None):
        super().__init__(name="ThreadFeatures", logger=logger)
        # Cache for performance
        self._browser_cache = {}
        self._system_cache = {}
        self._phaseF2v2_unbacked_audit = []  # PHASE_F2V2_EXACT_UNBACKED_DECISION_AUDIT
    
    @staticmethod
    def extract_process_basename(proc_info: Dict[str, Any]) -> str:
        """
        Robustly extract the base executable name from process info.
        Handles both 'path' and 'image_name' fields, normalizes case.
        """
        # Try path first (most reliable)
        path = proc_info.get('path', '')
        if path:
            basename = os.path.basename(path.replace('\\', os.sep))
            if basename:
                return basename.lower()
        
        # Fall back to image_name
        image_name = proc_info.get('image_name', '')
        if image_name:
            return image_name.lower()
        
        # Last resort: check for any other name-like field
        for key in ['name', 'process_name', 'executable']:
            if key in proc_info and proc_info[key]:
                return str(proc_info[key]).lower()
        
        return ''
    
    def is_browser_process(self, proc_info: Dict[str, Any]) -> bool:
        """
        Check if a process is a known browser with caching.
        """
        # Check cache first
        pid = proc_info.get('pid', -1)
        if pid in self._browser_cache:
            return self._browser_cache[pid]
        
        basename = self.extract_process_basename(proc_info)
        is_browser = basename in self.BROWSER_WHITELIST
        
        # Also check by parent process for browser renderers
        if not is_browser and 'ppid' in proc_info:
            parent_proc = self._get_parent_process(proc_info.get('ppid'))
            if parent_proc:
                parent_basename = self.extract_process_basename(parent_proc)
                is_browser = parent_basename in self.BROWSER_WHITELIST
        
        self._browser_cache[pid] = is_browser
        return is_browser
    
    def is_system_process(self, proc_info: Dict[str, Any]) -> bool:
        """
        Check if a process is a system process with caching.
        """
        pid = proc_info.get('pid', -1)
        if pid in self._system_cache:
            return self._system_cache[pid]
        
        basename = self.extract_process_basename(proc_info)
        is_system = basename in self.SYSTEM_PROCESS_WHITELIST
        self._system_cache[pid] = is_system
        return is_system
    
    def _get_parent_process(self, ppid: int) -> Optional[Dict]:
        """Helper to get parent process info (implement based on your data structure)"""
        # This needs to be implemented based on how you store process data
        # For now, returns None - you'll need to pass process list to ThreadFeatures
        return None
    

    def _suppress_kernel_mode_fp_tags(self, threads: List[Dict], pid_map: Dict[int, Dict],
                                      browser_pids: set, system_pids: set):
        """
        Remove parser-level 'Kernel Mode Start Address' alerts for Windows/UWP,
        browser, setup, and acquisition-context processes where kernel dispatcher
        thread starts are normal.
        """
        for thread in threads:
            pid = thread.get('pid', 0)
            proc_info = pid_map.get(pid, {})
            proc_base = self.extract_process_basename(proc_info)
            safe = (
                pid == 4 or pid in browser_pids or pid in system_pids
                or proc_base in self.KERNEL_THREAD_WHITELIST
            )
            if not safe:
                continue

            anomalies = thread.get('anomalies', []) or []
            if isinstance(anomalies, str):
                anomalies = [anomalies]

            cleaned = [
                a for a in anomalies
                if 'kernel mode start address' not in str(a).lower()
            ]

            if len(cleaned) != len(anomalies):
                thread['anomalies'] = cleaned
                thread.setdefault('info_notes', []).append(
                    'Kernel-mode dispatcher start address suppressed for known Windows/UWP or trusted process.'
                )
                if not cleaned:
                    thread['status'] = 'CLEAN'

    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract 15 thread features from parsed memory data.
        FIXED: Browser processes completely excluded from unbacked_thread_start_count.
        """
        threads = parsed_data.get('threads', [])
        processes = parsed_data.get('processes', [])
        dlls = parsed_data.get('dlls', [])
        handles = parsed_data.get('handles', [])
        # PHASE_F2_THREAD_FEATURE_CONSISTENCY_AUDIT: keep VAD/region context
        # available to audit the gap between normalized thread features and
        # parser-confirmed malfind-style Private+X evidence.
        memory_regions = (
            parsed_data.get('memory_regions')
            or parsed_data.get('pe_sections')
            or parsed_data.get('vads')
            or []
        )
        
        if not threads:
            self.logger.warning(f"[{self.name}] No threads found in parsed_data")
            return self._get_zero_features()
        
        # Build process lookup maps
        valid_pids = {p['pid'] for p in processes} if processes else set()
        pid_map = {p['pid']: p for p in processes}
        
        # Initialize caches
        self._browser_cache = {}
        self._system_cache = {}
        
        # Build browser and system PID sets WITH proper checking
        browser_pids = set()
        system_pids = set()
        
        for pid, proc in pid_map.items():
            if self.is_browser_process(proc):
                browser_pids.add(pid)
            if self.is_system_process(proc):
                system_pids.add(pid)
        
        # Clear known kernel-dispatcher false positives before feature counting/reporting.
        self._suppress_kernel_mode_fp_tags(threads, pid_map, browser_pids, system_pids)

        total_threads = len(threads)
        
        # DLL and handle maps
        dll_map = defaultdict(list)
        for dll in dlls:
            dll_map[dll.get('pid', 0)].append(dll)
        
        handle_map = defaultdict(list)
        for handle in handles:
            handle_map[handle.get('pid', 0)].append(handle)
        
        features = {}
        
        # Extract features with browser awareness
        features.update(self._extract_orphan_features(
            threads, valid_pids, total_threads, browser_pids, system_pids
        ))
        
        # CRITICAL FIX: Pass browser_pids to injection features
        features.update(self._extract_injection_features(
            threads, total_threads, pid_map, browser_pids, system_pids, dll_map, memory_regions
        ))
        
        # PHASE_F2V3_ACTUAL_UNBACKED_INCREMENT_AUDIT_V2
        features['_debug_threadfeatures_unbacked_raw_count'] = float(
            len(getattr(self, '_phaseF2v3_unbacked_increments', []) or [])
        )

        features.update(self._extract_context_features(
            threads, total_threads, browser_pids, system_pids
        ))
        
        features.update(self._extract_statistical_features(threads, processes))
        
        self._apply_context_tags(threads, pid_map, dll_map, handle_map, browser_pids, system_pids)
        
        return features
    
    def _tag_thread(self, thread: Dict, anomaly_msg: str):
        """Helper to tag a thread with an anomaly for the UI."""
        if 'anomalies' not in thread:
            thread['anomalies'] = []
        if anomaly_msg not in thread['anomalies']:
            thread['anomalies'].append(anomaly_msg)
        
        if thread.get('status', 'CLEAN') == 'CLEAN':
            thread['status'] = 'SUSPICIOUS'
    
    def _extract_orphan_features(self, threads: List[Dict], valid_pids: set, 
                                 total: int, browser_pids: set, 
                                 system_pids: set) -> Dict[str, float]:
        """
        Extract features related to orphan threads.
        FIXED: Browsers and system processes never count as orphans.
        """
        orphan_count = 0
        orphan_in_user = 0
        
        for thread in threads:
            pid = thread.get('pid', 0)
            start_address = thread.get('start_address', 0)
            
            # Skip browsers and system processes entirely
            if pid in browser_pids or pid in system_pids:
                continue
            
            # Orphan: thread's PID doesn't match any existing process
            if pid not in valid_pids and pid > 4:
                orphan_count += 1
                self._tag_thread(thread, "Orphan Thread (No Parent Process)")
                
                if start_address < self.KERNEL_BASE:
                    orphan_in_user += 1
        
        return {
            'orphan_thread_count': self.normalize_count(orphan_count, max_threshold=5),
            'orphan_thread_ratio': self.normalize_ratio(orphan_count, total),
            'orphan_user_space_count': self.normalize_count(orphan_in_user, max_threshold=3)
        }
    

    # PHASE_F2V3_ACTUAL_UNBACKED_INCREMENT_AUDIT_V2
    def _phaseF2v3_record_unbacked_increment(self, *, reason: str, thread: Dict, pid: int,
                                             proc_basename: str, start_address: int,
                                             is_browser: bool, is_system: bool) -> None:
        """Diagnostic-only record of the exact ThreadFeatures increment path."""
        try:
            rows = getattr(self, "_phaseF2v3_unbacked_increments", None)
            if rows is None:
                rows = []
                self._phaseF2v3_unbacked_increments = rows
            rows.append({
                "reason": str(reason or ""),
                "pid": int(pid or 0),
                "tid": int((thread or {}).get("tid") or (thread or {}).get("TID") or 0),
                "process_name": str(proc_basename or ""),
                "start_address_hex": f"0x{int(start_address or 0):x}",
                "start_address": int(start_address or 0),
                "is_browser": bool(is_browser),
                "is_system": bool(is_system),
                "thread_status_before": str((thread or {}).get("status", "")),
                "thread_anomalies_before": ";".join(str(x) for x in ((thread or {}).get("anomalies", []) or []))
                    if isinstance((thread or {}).get("anomalies", []), (list, tuple, set))
                    else str((thread or {}).get("anomalies", "")),
            })
        except Exception:
            pass

    def _extract_injection_features(self, threads: List[Dict], total: int, 
                                   pid_map: Dict, browser_pids: set,
                                   system_pids: set, dll_map: Dict[int, List],
                                   memory_regions: List[Dict] = None) -> Dict[str, float]:
        """
        Extract features related to thread injection.
        FIXED: Browser threads NEVER increment unbacked_thread_start_count.
        Added DLL-based JIT detection.
        """
        remote_thread_count = 0
        apc_injection_count = 0
        unusual_start_address_count = 0  # CRITICAL: This should be ZERO for browsers
        cross_process_thread_count = 0
        alertable_thread_count = 0
        # PHASE_F2V3_ACTUAL_UNBACKED_INCREMENT_AUDIT_V2
        self._phaseF2v3_unbacked_increments = []

        # PHASE_F2_THREAD_FEATURE_CONSISTENCY_AUDIT
        # Build a VAD lookup only for audit visibility. By default this does
        # not change the live feature value; it explains whether the loose
        # ThreadFeatures 'unbacked' count corresponds to parser-confirmed
        # Private+Executable VAD evidence.
        memory_regions = memory_regions or []
        vad_map = defaultdict(list)
        for _r in memory_regions:
            try:
                _pid = int(_r.get('pid') or _r.get('PID') or 0)
            except Exception:
                _pid = 0
            if _pid:
                vad_map[_pid].append(_r)

        def _f2_int(_v, _default=0):
            try:
                if isinstance(_v, str):
                    _s = _v.strip()
                    if not _s or _s.lower() in {'none', 'n/a', 'na', '-', '?'}:
                        return _default
                    return int(_s, 16) if _s.lower().startswith('0x') else int(float(_s))
                return int(_v or _default)
            except Exception:
                return _default

        def _f2_is_exec(_prot):
            _p = str(_prot or '').upper()
            return 'EXECUTE' in _p or 'X' in _p

        def _f2_find_vad(_pid, _addr):
            if not _addr:
                return None
            for _v in vad_map.get(_pid, []):
                _s = _f2_int(_v.get('start') or _v.get('Start') or _v.get('base') or _v.get('base_address'), 0)
                _e = _f2_int(_v.get('end') or _v.get('End'), 0)
                if _s and _e and _s <= _addr <= _e:
                    return _v
            return None

        _phaseF2_audit_rows = []
        
        for thread in threads:
            pid = thread.get('pid', 0)
            start_address = thread.get('start_address', 0)
            is_remote = thread.get('is_remote_thread', False)
            has_apc = thread.get('has_apc_queued', False)
            alertable = thread.get('alertable', False)
            cross_process = thread.get('cross_process', False)
            
            # Check if this is a browser or system process
            is_browser = pid in browser_pids
            is_system = pid in system_pids
            
            # Get process info
            proc_info = pid_map.get(pid, {})
            proc_basename = self.extract_process_basename(proc_info)

            # PHASE_F2 audit context for this thread.
            _f2_vad = _f2_find_vad(pid, start_address)
            _f2_vad_type = str((_f2_vad or {}).get('type') or (_f2_vad or {}).get('vad_type') or 'None')
            _f2_vad_prot = str((_f2_vad or {}).get('protection') or (_f2_vad or {}).get('Protection') or '')
            _f2_vad_private = _f2_vad_type.lower() == 'private'
            _f2_vad_exec = _f2_is_exec(_f2_vad_prot)
            _f2_filetime = 0x01C0000000000000 <= int(start_address or 0) <= 0x01F5000000000000
            _f2_typical_module = self._is_typical_module_address(start_address) if start_address else False
            _f2_counted_unusual = False
            _f2_count_reason = ''
            
            # Remote thread detection
            if is_remote:
                remote_thread_count += 1
                self._tag_thread(thread, "Remote Injection")
            
            # APC injection detection
            if has_apc:
                apc_injection_count += 1
                self._tag_thread(thread, "APC Queued (Potential Injection)")
            
            if alertable:
                alertable_thread_count += 1
            
            if cross_process:
                cross_process_thread_count += 1
                self._tag_thread(thread, "Cross-Process Activity")
            
            # UNBACKED THREAD START DETECTION - CRITICAL FIX
            if start_address > 0:
                # [FIX] FILETIME guard — must run before any address-range check.
                #
                # When thread_parser reads a wrong ETHREAD field offset, the value
                # it lands on is often a Windows FILETIME timestamp stored in
                # CreateTime or ExitTime.  FILETIME ticks since Jan 1 1601 place
                # dates in the range 0x01C0...–0x01F5... for years 2000–2035.
                # These values are in user-mode VA space but are NOT code pointers.
                # Flagging them as "Unusual Start Address" is always a false positive.
                #
                # This check must come before _is_typical_module_address because
                # FILETIME values fail that check (they're outside all normal ranges)
                # which would otherwise cause a false "Unusual Start Address" flag
                # for every affected thread — producing a 100% FP rate.
                _FILETIME_LO = 0x01C0_0000_0000_0000
                _FILETIME_HI = 0x01F5_0000_0000_0000
                if _FILETIME_LO <= start_address <= _FILETIME_HI:
                    # Parser artifact — silently skip, do not count or tag
                    continue
                # Kernel mode threads
                if start_address >= self.KERNEL_BASE:
                    if pid != 4 and proc_basename not in self.KERNEL_THREAD_WHITELIST:
                        # Exclude browsers from kernel mode detection too
                        if not is_browser and not is_system:
                            unusual_start_address_count += 1
                            self._phaseF2v3_record_unbacked_increment(reason='kernel_mode_start_non_whitelisted', thread=thread, pid=pid, proc_basename=proc_basename, start_address=start_address, is_browser=is_browser, is_system=is_system)
                            self._tag_thread(thread, "Kernel Mode Start Address")
                
                # User-mode unbacked addresses - THE FIX IS HERE
                elif not self._is_typical_module_address(start_address):
                    # FIRST CHECK: Is this a browser process?
                    if is_browser:
                        # Check if this might be legitimate JIT code
                        if self._is_likely_browser_jit(pid, start_address, dll_map):
                            # Tag for visibility but DO NOT COUNT as suspicious
                            if 'anomalies' not in thread:
                                thread['anomalies'] = []
                            if "JIT Compiled Code (Browser)" not in thread['anomalies']:
                                thread['anomalies'].append("JIT Compiled Code (Browser)")
                            # CRITICAL: Continue without incrementing counter
                            continue
                    
                    # SECOND CHECK: Is this a system process?
                    elif is_system:
                        # System processes might have legitimate private memory
                        continue
                    
                    # THIRD: Non-whitelisted process with unbacked code
                    unusual_start_address_count += 1
                    self._phaseF2v3_record_unbacked_increment(reason='user_mode_outside_typical_module_address', thread=thread, pid=pid, proc_basename=proc_basename, start_address=start_address, is_browser=is_browser, is_system=is_system)
                    _f2_counted_unusual = True
                    _f2_count_reason = 'non_browser_non_system_not_typical_module_address'
                    self._tag_thread(thread, "Unusual Start Address (Private Mem)")
        
            # PHASE_F2 audit row is appended once per thread. It records
            # whether ThreadFeatures counted this row and whether VAD context
            # actually confirms Private+Executable memory.
            try:
                _phaseF2_audit_rows.append({
                    'pid': pid,
                    'process_name': proc_basename,
                    'tid': thread.get('tid') or thread.get('TID') or thread.get('thread_id') or '',
                    'start_address': hex(int(start_address or 0)) if start_address else '0x0',
                    'is_browser': bool(is_browser),
                    'is_system': bool(is_system),
                    'is_filetime_artifact': bool(_f2_filetime),
                    'typical_module_address_by_threadfeatures': bool(_f2_typical_module),
                    'matched_vad': bool(_f2_vad),
                    'matched_vad_type': _f2_vad_type,
                    'matched_vad_protection': _f2_vad_prot,
                    'matched_vad_private': bool(_f2_vad_private),
                    'matched_vad_executable': bool(_f2_vad_exec),
                    'vad_confirmed_private_x': bool(_f2_vad_private and _f2_vad_exec),
                    'counted_by_threadfeatures_unbacked': bool(_f2_counted_unusual),
                    'count_reason': _f2_count_reason,
                    'anomalies_after_threadfeatures': '|'.join(str(x) for x in (thread.get('anomalies') or [])),
                })
            except Exception:
                pass

        self._phaseF2_export_thread_feature_audit(
            _phaseF2_audit_rows,
            unusual_start_address_count,
            total,
        )


        # PHASE_F2V2_EXACT_UNBACKED_DECISION_AUDIT
        # Diagnostic only: reconstruct the exact branch logic used above so the
        # experiment can show which threads caused unbacked_thread_start_count.
        # This does not modify any feature value or verdict logic.
        try:
            self._phaseF2v2_unbacked_audit = self._build_phaseF2v2_unbacked_audit(
                threads=threads,
                pid_map=pid_map,
                browser_pids=browser_pids,
                system_pids=system_pids,
                dll_map=dll_map,
            )
        except Exception as _f2v2_exc:
            self._phaseF2v2_unbacked_audit = [{
                "error": str(_f2v2_exc),
                "counted_by_threadfeatures_unbacked": False,
            }]

        return {
            'remote_injection_thread_count': self.normalize_count(remote_thread_count, max_threshold=3),
            'apc_injection_count': self.normalize_count(apc_injection_count, max_threshold=5),
            'unbacked_thread_start_count': self.normalize_count(unusual_start_address_count, max_threshold=5),
            'cross_process_thread_count': self.normalize_count(cross_process_thread_count, max_threshold=3),
            'alertable_thread_ratio': self.normalize_ratio(alertable_thread_count, total)
        }
    

    # PHASE_F2_THREAD_FEATURE_CONSISTENCY_AUDIT
    def _phaseF2_export_thread_feature_audit(self, rows: List[Dict[str, Any]], raw_count: int, total_threads: int) -> None:
        """Write diagnostic CSV for ThreadFeatures unbacked-thread counting."""
        path = os.environ.get("RAMDETECT_THREAD_FEATURE_AUDIT_PATH", "").strip()
        if not path:
            return
        try:
            out = os.path.abspath(path)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            fieldnames = [
                "pid", "process_name", "tid", "start_address",
                "is_browser", "is_system", "is_filetime_artifact",
                "typical_module_address_by_threadfeatures",
                "matched_vad", "matched_vad_type", "matched_vad_protection",
                "matched_vad_private", "matched_vad_executable", "vad_confirmed_private_x",
                "counted_by_threadfeatures_unbacked", "count_reason",
                "anomalies_after_threadfeatures",
            ]
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows or []:
                    writer.writerow({k: row.get(k, "") for k in fieldnames})
            meta_path = out.replace(".csv", ".summary.txt")
            counted = sum(1 for r in (rows or []) if r.get("counted_by_threadfeatures_unbacked"))
            private_x = sum(1 for r in (rows or []) if r.get("vad_confirmed_private_x"))
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write("Phase F2 Thread Feature Consistency Audit\n")
                f.write(f"rows={len(rows or [])}\n")
                f.write(f"raw_unusual_start_count={raw_count}\n")
                f.write(f"counted_rows={counted}\n")
                f.write(f"vad_confirmed_private_x_rows={private_x}\n")
                f.write(f"total_threads={total_threads}\n")
        except Exception as exc:
            try:
                self.logger.warning("Phase F2 thread feature audit export failed: %s", exc)
            except Exception:
                pass

    def _is_likely_browser_jit(self, pid: int, address: int, dll_map: Dict[int, List]) -> bool:
        """
        Determine if an address is likely browser JIT code.
        Uses loaded DLLs and known JIT patterns.
        """
        # Get DLLs loaded by this process
        process_dlls = dll_map.get(pid, [])
        
        # Check if any loaded DLLs are known JIT modules
        for dll in process_dlls:
            dll_name = dll.get('name', '').lower()
            if any(jit_module in dll_name for jit_module in self.BROWSER_JIT_MODULES):
                # This process has JIT capabilities
                # Check if address is in a reasonable range for JIT
                if 0x0000020000000000 <= address <= 0x00007FFFFFFFFFFF:
                    return True
        
        return False
    

    # PHASE_F2V2_EXACT_UNBACKED_DECISION_AUDIT
    def _build_phaseF2v2_unbacked_audit(self, threads, pid_map, browser_pids, system_pids, dll_map):
        """Reconstruct exact decision path for unbacked_thread_start_count."""
        rows = []
        _FILETIME_LO = 0x01C0_0000_0000_0000
        _FILETIME_HI = 0x01F5_0000_0000_0000

        for thread in threads:
            try:
                pid = int(thread.get('pid', 0) or 0)
            except Exception:
                pid = 0
            try:
                tid = int(thread.get('tid', thread.get('TID', 0)) or 0)
            except Exception:
                tid = 0
            try:
                start_address = int(thread.get('start_address', 0) or 0)
            except Exception:
                start_address = 0

            proc_info = pid_map.get(pid, {})
            proc_basename = self.extract_process_basename(proc_info)
            is_browser = pid in browser_pids
            is_system = pid in system_pids
            counted = False
            reason = "not_evaluated"

            if start_address <= 0:
                reason = "zero_or_missing_start_address"
            elif _FILETIME_LO <= start_address <= _FILETIME_HI:
                reason = "filetime_artifact_suppressed"
            elif start_address >= self.KERNEL_BASE:
                if pid != 4 and proc_basename not in self.KERNEL_THREAD_WHITELIST:
                    if not is_browser and not is_system:
                        counted = True
                        reason = "kernel_mode_start_non_whitelisted"
                    else:
                        reason = "kernel_mode_browser_or_system_suppressed"
                else:
                    reason = "kernel_mode_whitelisted"
            elif not self._is_typical_module_address(start_address):
                if is_browser:
                    if self._is_likely_browser_jit(pid, start_address, dll_map):
                        reason = "browser_jit_suppressed"
                    else:
                        reason = "browser_non_jit_suppressed_by_whitelist"
                elif is_system:
                    reason = "system_process_suppressed"
                else:
                    counted = True
                    reason = "user_start_outside_typical_module_range"
            else:
                reason = "typical_module_address"

            anomalies = thread.get("anomalies", [])
            if isinstance(anomalies, (list, tuple, set)):
                anomalies_text = " | ".join(str(x) for x in anomalies)
            else:
                anomalies_text = str(anomalies or "")

            rows.append({
                "pid": pid,
                "process_name": proc_basename,
                "tid": tid,
                "start_address": hex(start_address) if start_address else "",
                "is_browser": bool(is_browser),
                "is_system": bool(is_system),
                "typical_module_address_by_threadfeatures": bool(self._is_typical_module_address(start_address)) if start_address and start_address < self.KERNEL_BASE else False,
                "counted_by_threadfeatures_unbacked": bool(counted),
                "count_reason": reason,
                "anomalies_after_threadfeatures": anomalies_text,
            })

        return rows


    def _extract_context_features(self, threads: List[Dict], total: int,
                                  browser_pids: set, system_pids: set) -> Dict[str, float]:
        """Extract features related to thread context anomalies."""
        high_priority_count = 0
        suspended_count = 0
        unusual_wait_count = 0
        zero_context_count = 0
        
        for thread in threads:
            pid = thread.get('pid', 0)
            raw_priority = thread.get('priority', 8)
            priority = raw_priority & 0x1F
            thread['priority'] = priority
            
            state = str(thread.get('state', '')).lower()
            wait_reason = str(thread.get('wait_reason', ''))
            context = thread.get('context', {})
            
            is_browser = pid in browser_pids
            is_system = pid in system_pids
            
            # High priority (exclude system processes and browsers)
            if priority > 15 and pid > 4 and not is_system and not is_browser:
                high_priority_count += 1
            
            # Suspended threads
            if 'suspend' in state or 'init' in state:
                suspended_count += 1
            
            # Unusual wait reasons
            if any(reason in wait_reason for reason in self.SUSPICIOUS_WAIT_REASONS):
                unusual_wait_count += 1
                if 'UserRequest' in wait_reason and pid == 4:
                    self._tag_thread(thread, "System Thread UserRequest")
            
            # Zeroed context (anti-forensics)
            if context and all(v == 0 for v in context.values()):
                zero_context_count += 1
                self._tag_thread(thread, "Zero Context (Anti-Forensics)")
        
        return {
            'high_priority_thread_count': self.normalize_count(high_priority_count, max_threshold=5),
            'suspended_thread_count': self.normalize_count(suspended_count, max_threshold=3),
            'unusual_wait_reason_count': self.normalize_count(unusual_wait_count, max_threshold=5),
            'zero_context_count': self.normalize_count(zero_context_count, max_threshold=2)
        }
    
    def _extract_statistical_features(self, threads: List[Dict], 
                                      processes: List[Dict]) -> Dict[str, float]:
        """Extract statistical anomaly features."""
        if not processes:
            return {
                'thread_distribution_anomaly': 0.0,
                'single_thread_process_ratio': 0.0,
                'excessive_thread_process_ratio': 0.0
            }
        
        thread_counts = defaultdict(int)
        for thread in threads:
            pid = thread.get('pid', 0)
            thread_counts[pid] += 1
        
        counts = list(thread_counts.values())
        if not counts:
            return self._get_zero_features()
        
        single_thread_count = sum(1 for c in counts if c == 1)
        excessive_thread_count = sum(1 for c in counts if c > 50)
        
        distribution_anomaly = 0.0
        if len(counts) > 1:
            try:
                mean = statistics.mean(counts)
                stdev = statistics.stdev(counts)
                cv = stdev / mean if mean > 0 else 0
                distribution_anomaly = min(1.0, cv / 2.0)
            except statistics.StatisticsError:
                distribution_anomaly = 0.0
        
        total_processes = len(processes)
        
        return {
            'thread_distribution_anomaly': distribution_anomaly,
            'single_thread_process_ratio': self.normalize_ratio(single_thread_count, total_processes),
            'excessive_thread_process_ratio': self.normalize_ratio(excessive_thread_count, total_processes)
        }
    
    def _apply_context_tags(self, threads: List[Dict], pid_map: Dict, 
                           dll_map: Dict, handle_map: Dict,
                           browser_pids: set, system_pids: set):
        """
        Apply context-aware tags to threads for UI display.
        FIXED: Browsers and system processes don't inherit suspicious tags.
        """
        for thread in threads:
            pid = thread.get('pid', 0)
            
            if pid not in pid_map:
                continue
            
            # Skip tagging for browsers and system processes
            if pid in browser_pids or pid in system_pids:
                continue
            
            proc = pid_map[pid]
            proc_anomalies = proc.get('anomalies', [])
            
            proc_dlls = dll_map.get(pid, [])
            has_suspicious_dll = any(d.get('is_suspicious') for d in proc_dlls)
            
            proc_handles = handle_map.get(pid, [])
            has_persistence = any(
                h.get('type', '').lower() == 'key' and 
                'run' in h.get('name', '').lower()
                for h in proc_handles
            )
            has_security_access = any(
                h.get('type', '').lower() == 'file' and
                any(db in h.get('name', '').lower() for db in ['sam', 'security', 'ntds.dit'])
                for h in proc_handles
            )
            
            # Context-aware tagging
            if thread.get('is_remote_thread') and has_suspicious_dll:
                self._tag_thread(thread, "Code Injection Detected")
            
            if thread.get('is_remote_thread') and has_persistence:
                self._tag_thread(thread, "Persistence + Injection")
            
            if thread.get('is_remote_thread') and has_security_access:
                self._tag_thread(thread, "Credential Theft Attempt")
            
            # Parent process review notes must NOT make a thread suspicious by
            # themselves. Under the ML-only RAMDetect rules, thread artifacts need
            # direct thread evidence (remote thread, APC, cross-process activity,
            # or confirmed private executable start address) before status changes.
            if proc_anomalies:
                real_parent_anoms = [
                    a for a in proc_anomalies
                    if "Unusual Start" not in a and "Kernel Mode" not in a
                ]
                if real_parent_anoms:
                    thread.setdefault("info_notes", []).append(
                        "Owner process has parser review notes; thread not marked suspicious without direct thread evidence."
                    )
            
            # Dropper detection. Exempt forensic/acquisition tools that are
            # commonly executed from Downloads/Desktop during RAM acquisition.
            proc_path = proc.get('path', '').lower()
            proc_base = self.extract_process_basename(proc)
            forensic_tools = {
                'dumpit.exe', 'ftkimager.exe', 'winpmem.exe',
                'winpmem_mini_x64.exe', 'winpmem_mini_x86.exe',
                'rammap.exe', 'procdump.exe', 'livekd.exe',
                'ramdetect.exe', 'ramdetect_gui.exe',
            }
            is_suspicious_location = any(loc in proc_path for loc in ['temp', 'appdata', 'downloads'])
            if (
                proc_base not in forensic_tools
                and is_suspicious_location
                and (thread.get('is_remote_thread') or has_suspicious_dll)
            ):
                self._tag_thread(thread, "Dropper/Staged Malware")
    
    def _is_typical_module_address(self, address: int) -> bool:
        """Check if address falls within typical user-mode module ranges."""
        if address >= self.KERNEL_BASE:
            return False
        
        common_ranges = [
            (0x00007FF000000000, 0x00007FFFFFFFFFFF),
            (0x0000000100000000, 0x00007FEFFFFFFFFF),
            (0x0000000000100000, 0x00000000FFFFFFFF),
        ]
        
        for low, high in common_ranges:
            if low <= address <= high:
                return True
        
        if 0x0000100000000000 <= address <= 0x00007FFFFFFFFFFF:
            return True
        
        return False
    
    def _get_zero_features(self) -> Dict[str, float]:
        """Return all features set to 0.0."""
        keys = [
            'orphan_thread_count', 'orphan_thread_ratio', 'orphan_user_space_count',
            'remote_injection_thread_count', 'apc_injection_count', 'unbacked_thread_start_count',
            'cross_process_thread_count', 'alertable_thread_ratio',
            'high_priority_thread_count', 'suspended_thread_count', 'unusual_wait_reason_count',
            'zero_context_count', 'thread_distribution_anomaly', 'single_thread_process_ratio',
            'excessive_thread_process_ratio'
        ]
        return {k: 0.0 for k in keys}
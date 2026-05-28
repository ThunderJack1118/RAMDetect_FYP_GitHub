"""
RAMDetect - Feature Aggregator (FIXED VERSION)
===============================================
Fixed: Now properly handles browser processes to eliminate false positives.
Added: Browser-aware feature weighting and context passing.
"""

from typing import Dict, List, Any, Optional, Set
import logging
import json
import csv
import time
import re
import os
from datetime import datetime
from pathlib import Path

# Import all individual feature extractors
from .feature_base import FeatureExtractor
from .process_features import ProcessFeatures
from .thread_features import ThreadFeatures
from .dll_features import DLLFeatures
from .pe_features import PEFeatures
from .handle_features import HandleFeatures
from .injection_features import InjectionFeatures


class FeatureAggregator:
    """
    Aggregates features from all separate extractors with browser-aware weighting.
    """
    
    # Browser process whitelist for ALL aggregator operations
    BROWSER_WHITELIST = {
        'msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
        'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'microsoftedge.exe',
        'msedgewebview2.exe', 'chromium.exe', 'waterfox.exe',
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize feature aggregator with browser-aware configuration.
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize dictionary of all available extractors
        self.extractors: Dict[str, FeatureExtractor] = {
            'injection': InjectionFeatures(logger),
            'process': ProcessFeatures(logger),
            'thread': ThreadFeatures(logger),
            'dll': DLLFeatures(logger),
            'pe': PEFeatures(logger),
            'handle': HandleFeatures(logger)
        }
        
        # Storage for the final aggregated results
        self.feature_vector = {}

        # Diagnostic-only raw indicator cache. Under the RAMDetect master
        # rules this must never feed a post-classification rule, confidence
        # adjustment, or threshold change.
        self.heuristic_data: Dict[str, Any] = {}
        
        # Browser context tracking
        self.browser_pids: Set[int] = set()
        self.browser_process_count = 0
        self.browser_thread_count = 0
        
        # Metadata tracking
        self.metadata = {
            'extraction_start': None,
            'extraction_end': None,
            'total_duration': 0.0,
            'total_features': 0,
            'successful_extractors': 0,
            'failed_extractors': 0,
            'extractor_stats': {},
            'browser_context': {
                'browser_process_count': 0,
                'browser_pids': [],
                'browser_aware_adjustment': False
            }
        }
        
        self.logger.info(f"[FeatureAggregator] Initialized with {len(self.extractors)} extractors")
    
    def _identify_browser_context(self, parsed_data: Dict[str, Any]) -> None:
        """
        Identify browser processes in the parsed data.
        This context is used to adjust feature scoring.
        """
        self.browser_pids.clear()
        self.browser_process_count = 0
        
        processes = parsed_data.get('processes', [])
        threads = parsed_data.get('threads', [])
        
        # Identify browser processes
        for proc in processes:
            if self._is_browser_process(proc):
                pid = proc.get('pid', 0)
                self.browser_pids.add(pid)
                self.browser_process_count += 1
        
        # Count browser threads
        self.browser_thread_count = 0
        for thread in threads:
            if thread.get('pid', 0) in self.browser_pids:
                self.browser_thread_count += 1
        
        # Update metadata
        self.metadata['browser_context'] = {
            'browser_process_count': self.browser_process_count,
            'browser_pids': list(self.browser_pids),
            'browser_thread_count': self.browser_thread_count,
            'browser_aware_adjustment': self.browser_process_count > 0
        }
        
        if self.browser_process_count > 0:
            self.logger.info(
                f"[FeatureAggregator] Identified {self.browser_process_count} browser processes "
                f"({self.browser_thread_count} threads)"
            )
    
    def _is_browser_process(self, proc_info: Dict[str, Any]) -> bool:
        """
        Check if a process is a known browser.
        Uses robust basename extraction.
        """
        # Extract basename from path or image_name
        path = proc_info.get('path', '')
        if path:
            import os
            basename = os.path.basename(path.replace('\\', os.sep))
            if basename:
                return basename.lower() in self.BROWSER_WHITELIST
        
        image_name = proc_info.get('image_name', '')
        if image_name:
            return image_name.lower() in self.BROWSER_WHITELIST
        
        return False
    
    def _extract_process_basename(self, proc_info: Dict[str, Any]) -> str:
        """
        Extract base process name from process info.
        """
        # Try path first (most reliable)
        path = proc_info.get('path', '')
        if path:
            import os
            basename = os.path.basename(path.replace('\\', os.sep))
            if basename:
                return basename.lower()
        
        # Fall back to image_name
        image_name = proc_info.get('image_name', '')
        if image_name:
            return image_name.lower()
        
        return ''
    
    def _apply_browser_aware_weighting(self, features: Dict[str, float], parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Apply browser-aware adjustments ONLY to browser processes.
        Malware processes get NO reduction and may even get boosted.
        """
        if not self.browser_pids:
            return features
        
        adjusted_features = features.copy()

        # Features that are commonly false positives for browsers
        browser_sensitive_features = {
            'orphan_process_count': 0.3,      # Less aggressive reduction
            'orphan_process_ratio': 0.3,
            'unbacked_thread_start_count': 0.4,  # Less aggressive
            'unusual_start_address_count': 0.4,
            'suspicious_path_count': 0.2,     # Keep low - this is malware indicator!
            'missing_path_count': 0.5,
            'unsigned_dll_count': 0.3,        # Less aggressive
            'unsigned_dll_ratio': 0.3,
            'late_loaded_dll_count': 0.7,
            'high_entropy_dll_count': 0.8,
            'duplicate_system_process_count': 0.9,
        }
        
        # [NEW] Identify which processes are suspicious (potential malware)
        suspicious_pids = self._identify_suspicious_processes(parsed_data)
        
        # [NEW] Analyze feature contributions per process
        feature_contributions = self._analyze_feature_contributions(parsed_data)
        
        # Apply intelligent adjustments per feature
        for feature_name in list(adjusted_features.keys()):
            original_value = adjusted_features[feature_name]
            if original_value <= 0:
                continue
            
            # [CRITICAL] Check what percentage of this feature comes from browsers vs malware
            browser_contribution = self._get_contribution_percentage(
                feature_name, feature_contributions, self.browser_pids
            )
            
            malware_contribution = self._get_contribution_percentage(
                feature_name, feature_contributions, suspicious_pids
            )
            
            # [FIXED] Get base adjustment from browser_sensitive_features
            base_adjustment = browser_sensitive_features.get(feature_name, 1.0)
            
            # [SMART LOGIC] Apply adjustments based on source analysis
            if browser_contribution > 0.8 and malware_contribution < 0.1:
                # This feature is almost entirely from browsers - apply browser-sensitive reduction
                adjustment = base_adjustment * 0.2  # Additional 80% reduction
                adjusted = original_value * adjustment
                adjusted_features[feature_name] = adjusted
                
                self.logger.info(
                    f"[BrowserAdjust] {feature_name}: {original_value:.2f} → {adjusted:.2f} "
                    f"(Browser: {browser_contribution:.0%}, BaseAdj: {base_adjustment})"
                )
            
            elif malware_contribution > 0.3:
                # This feature has significant malware contribution - BOOST it!
                # Ignore browser adjustment for malware-dominated features
                boost = 2.0  # Double the score
                adjusted = min(1.0, original_value * boost)
                adjusted_features[feature_name] = adjusted
                
                self.logger.warning(
                    f"[MalwareBoost] {feature_name}: {original_value:.2f} → {adjusted:.2f} "
                    f"(Malware: {malware_contribution:.0%}, browser adjustment bypassed)"
                )
            
            elif browser_contribution > 0.5 and malware_contribution < 0.3:
                # Mixed but browser-heavy - apply moderate browser adjustment
                adjustment = base_adjustment * 0.5  # Additional 50% reduction
                adjusted = original_value * adjustment
                adjusted_features[feature_name] = adjusted
                
                self.logger.debug(
                    f"[MixedAdjust] {feature_name}: {original_value:.2f} → {adjusted:.2f} "
                    f"(Browser: {browser_contribution:.0%}, BaseAdj: {base_adjustment})"
                )
            
            elif feature_name in browser_sensitive_features:
                # Feature is browser-sensitive but not dominated by browsers
                # Apply base adjustment only (not additional reduction)
                adjustment = base_adjustment
                adjusted = original_value * adjustment
                adjusted_features[feature_name] = adjusted
                
                if adjustment < 0.5:
                    self.logger.debug(
                        f"[BaseAdjust] {feature_name}: {original_value:.2f} → {adjusted:.2f} "
                        f"(Base adjustment: {adjustment})"
                    )
        
        return adjusted_features
    
    def _identify_suspicious_processes(self, parsed_data: Dict[str, Any]) -> Set[int]:
        """
        Identify processes with high-confidence malware indicators.
        These processes get NO browser reduction.
        """
        suspicious_pids = set()
        processes = parsed_data.get('processes', [])
        
        for proc in processes:
            pid = proc.get('pid', 0)
            path = proc.get('path', '').lower()
            name = self._extract_process_basename(proc)
            
            # Skip browsers (they're already in browser_pids)
            if pid in self.browser_pids:
                continue
            
            # High confidence malware indicators
            # 1. Running from TEMP/AppData with .exe extension
            temp_patterns = ['\\temp\\', '\\appdata\\', '\\downloads\\', '\\recycler\\']
            if any(pattern in path for pattern in temp_patterns):
                if path.endswith('.exe'):
                    suspicious_pids.add(pid)
                    continue
            
            # 2. Process name is a known system process typosquat
            typosquats = ['svch0st.exe', 'lsasss.exe', 'csrsss.exe', 'explorrer.exe', 'scvhost.exe']
            if name in typosquats:
                suspicious_pids.add(pid)
                continue
            
            # 3. Check if process has malware path pattern
            if self._is_malware_path(path):
                suspicious_pids.add(pid)
                continue
        
        if suspicious_pids:
            self.logger.warning(f"[MalwareDetect] Found {len(suspicious_pids)} suspicious processes")
        
        return suspicious_pids

    def _analyze_feature_contributions(self, parsed_data: Dict[str, Any]) -> Dict[str, Dict[int, float]]:
        """
        Analyze which processes contribute to each feature score.
        Returns: {feature_name: {pid: contribution_score}}
        """
        contributions = {}
        processes = parsed_data.get('processes', [])
        threads = parsed_data.get('threads', [])
        
        for proc in processes:
            pid = proc.get('pid', 0)
            path = proc.get('path', '').lower()
            
            # Unbacked threads per process
            proc_threads = [t for t in threads if t.get('pid', 0) == pid]
            unbacked_count = sum(1 for t in proc_threads 
                            if 'Unusual Start Address' in ' '.join(t.get('anomalies', [])))
            
            if unbacked_count > 0:
                if 'unbacked_thread_start_count' not in contributions:
                    contributions['unbacked_thread_start_count'] = {}
                contributions['unbacked_thread_start_count'][pid] = unbacked_count
            
            # Check for suspicious path
            suspicious_paths = ['\\temp\\', '\\appdata\\', '\\downloads\\', '\\recycler\\']
            if any(susp in path for susp in suspicious_paths):
                if 'suspicious_path_count' not in contributions:
                    contributions['suspicious_path_count'] = {}
                contributions['suspicious_path_count'][pid] = 1.0
            
            # Check for malware path pattern
            if self._is_malware_path(path):
                if 'malware_path_pattern_count' not in contributions:
                    contributions['malware_path_pattern_count'] = {}
                contributions['malware_path_pattern_count'][pid] = 1.0
        
        return contributions

    def _get_contribution_percentage(self, feature_name: str, 
                                    contributions: Dict[str, Dict[int, float]], 
                                    target_pids: Set[int]) -> float:
        """
        Calculate what percentage of a feature comes from specific PIDs.
        """
        if feature_name not in contributions:
            return 0.0
        
        feature_contribs = contributions[feature_name]
        if not feature_contribs:
            return 0.0
        
        total = sum(feature_contribs.values())
        if total == 0:
            return 0.0
        
        target_total = sum(value for pid, value in feature_contribs.items() if pid in target_pids)
        return target_total / total

    def _is_malware_path(self, path: str) -> bool:
        """
        Detect high-confidence malware path patterns.
        """
        if not path:
            return False
        
        path_lower = path.lower()
        
        # Malware-specific patterns (NOT browser patterns)
        malware_patterns = [
            # ANY exe under AppData\Local\Temp or AppData\Roaming\Temp
            # (covers oneetx-style drops: \AppData\Local\Temp\c3912af058\oneetx.exe)
            r'\\appdata\\local\\temp\\.+\.exe$',
            r'\\appdata\\roaming\\temp\\.+\.exe$',

            # Random hex/number folders under temp — any length (8+ chars)
            r'\\temp\\[a-f0-9]{8,}\\.*\.exe$',
            r'\\appdata\\[a-f0-9]{8,}\\.*\.exe$',

            # Direct execution from system temp root
            r'\\temp\\[^\\]+\.exe$',
            r'\\windows\\temp\\[^\\]+\.exe$',

            # Downloads folder execution
            r'\\users\\[^\\]+\\downloads\\.*\.exe$',

            # Recycler/Trash folders
            r'\\recycler\\[^\\]+\.exe$',
            r'\\\$recycle\.bin\\.*\.exe$',

            # Users\Public — world-writable, no legit long-running exes here
            r'\\users\\public\\.*\.exe$',
        ]
        
        import re
        for pattern in malware_patterns:
            if re.search(pattern, path_lower):
                return True
        
        return False
    
    def _normalize_features_with_context(self, features: Dict[str, float]) -> Dict[str, float]:
        """
        Apply context-aware normalization to prevent 100% scores.
        """
        normalized = {}
        
        for feature_name, value in features.items():
            if value <= 0:
                normalized[feature_name] = 0.0
                continue
            
            # Apply feature-specific caps
            cap = 1.0
            
            # Count-based features should never be 1.0 unless extreme
            if 'count' in feature_name and 'ratio' not in feature_name:
                # Counts > 5 are suspicious, but cap at 0.8
                cap = min(0.8, value)
            
            # Ratio features get sigmoid-like normalization
            elif 'ratio' in feature_name:
                # Smooth ratio: 0.1 -> 0.2, 0.5 -> 0.6, 1.0 -> 0.9
                cap = 0.2 + (0.7 * (value ** 0.5))
            
            # Anomaly scores (0-1 range) get slight boost for visibility
            elif 'anomaly' in feature_name:
                cap = min(1.0, value * 1.2)
            
            normalized[feature_name] = min(cap, value)
        
        return normalized
    
    def _compute_cic_aggregate_stats(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Compute CIC-MalMem compatible live aggregate statistics in a clean-safe way.

        Safety policy for live inference:
        - Use RAMDetect-observable process, DLL, handle and confirmed injection fields.
        - Add safe LDR averages and Phase-1 raw LDR counts from complete native PEB 3-list DLL rows.
        - Do NOT emit unsupported svcscan/modules/callbacks/psxview approximations;
          FeatureMapper benign defaults should remain active for those.
        """
        processes = parsed_data.get('processes', []) or []
        threads = parsed_data.get('threads', []) or []
        dlls = parsed_data.get('dlls', []) or []
        handles = parsed_data.get('handles', []) or []

        if isinstance(dlls, dict):
            flat_dlls = []
            for v in dlls.values():
                if isinstance(v, list):
                    flat_dlls.extend(v)
            dlls = flat_dlls

        n_procs = len(processes)
        n_threads = len(threads)
        n_dlls = len(dlls)
        n_handles = len(handles)
        safe_procs = max(n_procs, 1)

        def _as_int(v, default=0):
            try:
                if isinstance(v, str):
                    v = v.strip()
                    if not v or v in {'-', 'None', 'none', 'N/A', 'n/a'}:
                        return default
                    if v.lower().startswith('0x'):
                        return int(v, 16)
                return int(v or default)
            except Exception:
                return default

        def _field(row, *names, default=None):
            for name in names:
                if isinstance(row, dict) and name in row and row.get(name) not in (None, ''):
                    return row.get(name)
            return default

        # Process-level aggregates
        unique_ppids = len({
            _as_int(_field(p, 'ppid', 'PPID', 'parent_pid', 'Parent PID'), 0)
            for p in processes
            if _as_int(_field(p, 'ppid', 'PPID', 'parent_pid', 'Parent PID'), 0) > 0
        })

        # Optional pslist.nprocs64bit support.  We only emit this feature when
        # the process parser has explicit architecture/bitness evidence.  If no
        # such evidence exists, we preserve the FeatureMapper default instead of
        # guessing from the host OS.
        def _process_bitness(row) -> int | None:
            val = _field(
                row,
                'is_64bit', 'is_64_bit', 'process_is_64bit', 'is64',
                'wow64', 'is_wow64', 'process_is_wow64',
                'bitness', 'arch', 'architecture', 'machine',
                default=None,
            )
            if val is None:
                return None
            if isinstance(val, bool):
                # wow64=True means a 32-bit process on 64-bit Windows.
                key_text = ' '.join(str(k).lower() for k in row.keys())
                if 'wow64' in key_text and val is True:
                    return 32
                return 64 if val else 32
            text = str(val).strip().lower()
            if text in {'', '-', 'none', 'n/a', 'unknown'}:
                return None
            if 'wow64' in text or text in {'x86', 'i386', '32', '32-bit', '32bit'}:
                return 32
            if text in {'x64', 'amd64', '64', '64-bit', '64bit'} or '64' in text:
                return 64
            return None

        bitness_values = [_process_bitness(p) for p in processes]
        known_bitness = [b for b in bitness_values if b in (32, 64)]
        n_procs64 = sum(1 for b in known_bitness if b == 64)

        # DLL-per-process counts
        dll_pid_counts: Dict[int, int] = {}
        for dll in dlls:
            pid = _as_int(_field(dll, 'pid', 'PID'), 0)
            if pid:
                dll_pid_counts[pid] = dll_pid_counts.get(pid, 0) + 1
        avg_dlls = (sum(dll_pid_counts.values()) / len(dll_pid_counts)) if dll_pid_counts else 0.0

        # Handle type counts
        handle_type_counts: Dict[str, int] = {}
        for h in handles:
            htype = str(_field(h, 'type', 'Type', 'handle_type', default='')).lower().strip()
            handle_type_counts[htype] = handle_type_counts.get(htype, 0) + 1

        stats: Dict[str, float] = {
            # pslist aliases/canonical mappings
            'total_processes': float(n_procs),
            'unique_parent_pids': float(unique_ppids),
            'avg_threads_per_process': float(n_threads) / safe_procs,
            'avg_handles_per_process': float(n_handles) / safe_procs,

            # dlllist aliases/canonical mappings
            'total_dlls_loaded': float(n_dlls),
            'avg_dlls_per_process': float(avg_dlls),

            # handles aliases/canonical mappings
            'total_handles': float(n_handles),
            'avg_handles': float(n_handles) / safe_procs,
            'port_handles': float(handle_type_counts.get('port', 0)),
            'file_handles': float(handle_type_counts.get('file', 0)),
            'event_handles': float(handle_type_counts.get('event', 0)),
            'desktop_handles': float(handle_type_counts.get('desktop', 0)),
            'key_handles': float(handle_type_counts.get('key', 0)),
            'thread_handles': float(handle_type_counts.get('thread', 0)),
            'directory_handles': float(handle_type_counts.get('directory', 0)),
            'semaphore_handles': float(handle_type_counts.get('semaphore', 0)),
            'timer_handles': float(handle_type_counts.get('timer', 0)),
            'section_handles': float(handle_type_counts.get('section', 0)),
            'mutant_handles': float(handle_type_counts.get('mutant', 0)),
        }

        if known_bitness:
            stats['total_procs_64bit'] = float(n_procs64)
            stats['_debug_nprocs64bit_known_processes'] = float(len(known_bitness))
            stats['_debug_nprocs64bit_value'] = float(n_procs64)

        # Confirmed malfind + LDR native indicators.
        try:
            from ramdetect.features.native_indicator_features import NativeIndicatorFeatureBuilder
            native = NativeIndicatorFeatureBuilder(logger=self.logger).build(parsed_data)
        except Exception as exc:
            self.logger.warning('[CICStats] Native indicator builder skipped: %s', exc)
            native = {}

        # Merge only approved live native keys.
        allowed_native_prefixes = ('malfind.',)
        allowed_native_keys = {
            'injection_count', 'unique_injection_targets', 'total_commit_charge',
            'pe_section_injection_count',
            'ldrmodules.not_in_load', 'ldrmodules.not_in_init', 'ldrmodules.not_in_mem',
            'dlls_not_in_load_list', 'dlls_not_in_init_list', 'dlls_not_in_mem_list',
            'ldrmodules.not_in_load_avg', 'ldrmodules.not_in_init_avg', 'ldrmodules.not_in_mem_avg',
            'avg_not_in_load', 'avg_not_in_init', 'avg_not_in_mem', 'ldrmodules_mismatch_ratio',
        }
        for k, v in native.items():
            if k.startswith('_debug_'):
                stats[k] = float(v)
                continue
            if k in allowed_native_keys or k.startswith(allowed_native_prefixes):
                try:
                    stats[k] = float(v)
                except Exception:
                    pass


        # PHASE_E3_MALFIND_PREMAPPER_CALIBRATION
        # Final safety net for CIC-compatible malfind values. This uses only
        # parser-confirmed InjectionDetector rows from parsed_data['injections'].
        # It does not change the RF threshold or add post-classification rule logic,
        # and does not read raw normalized native scores such as
        # unbacked_thread_start_count.
        try:
            _confirmed_injs = parsed_data.get('injections', []) or []
            if _confirmed_injs:
                def _e3_float(_v, _default=0.0):
                    try:
                        if isinstance(_v, str):
                            _s = _v.strip()
                            if not _s or _s.lower() in {'none', 'n/a', 'na', '-', '?'}:
                                return _default
                            return float(int(_s, 16)) if _s.lower().startswith('0x') else float(_s)
                        return float(_v or _default)
                    except Exception:
                        return _default

                def _e3_pages(_row, _default=256.0):
                    if not isinstance(_row, dict):
                        return _default
                    for _k in ('commit_charge', 'commitCharge', 'malfind.commitCharge', 'commit', 'pages', 'page_count'):
                        _pages = _e3_float(_row.get(_k), 0.0)
                        if _pages > 0:
                            return _pages
                    for _k in ('size', 'region_size', 'RegionSize', 'virtual_size', 'Virtual Size'):
                        _size = _e3_float(_row.get(_k), 0.0)
                        if _size > 0:
                            return max(1.0, _size / 4096.0)
                    return _default

                _targets = set()
                _commit_pages = 0.0
                for _inj in _confirmed_injs:
                    if not isinstance(_inj, dict):
                        continue
                    _target = (
                        _inj.get('pid') or _inj.get('target_pid') or _inj.get('PID') or
                        _inj.get('ProcessId') or _inj.get('process') or _inj.get('process_name') or
                        _inj.get('proc_name') or _inj.get('Process') or 'unknown'
                    )
                    _targets.add(str(_target))
                    _commit_pages += _e3_pages(_inj, 256.0)

                _target_count = max(1.0, float(len(_targets)))
                _row_count = max(1.0, float(len([x for x in _confirmed_injs if isinstance(x, dict)])))
                _cal_ninj = min(max(64.0 * _target_count, 16.0 * _row_count), 512.0)
                _cal_commit = min(max(256.0 * _target_count, _commit_pages), 4096.0)

                stats['injection_count'] = max(
                    _e3_float(stats.get('injection_count'), 0.0),
                    _e3_float(stats.get('malfind.ninjections'), 0.0),
                    _cal_ninj,
                )
                stats['malfind.ninjections'] = max(_e3_float(stats.get('malfind.ninjections'), 0.0), stats['injection_count'])
                stats['unique_injection_targets'] = max(
                    _e3_float(stats.get('unique_injection_targets'), 0.0),
                    _e3_float(stats.get('malfind.uniqueInjections'), 0.0),
                    _target_count,
                )
                stats['malfind.uniqueInjections'] = max(_e3_float(stats.get('malfind.uniqueInjections'), 0.0), stats['unique_injection_targets'])
                stats['total_commit_charge'] = max(
                    _e3_float(stats.get('total_commit_charge'), 0.0),
                    _e3_float(stats.get('malfind.commitCharge'), 0.0),
                    _cal_commit,
                )
                stats['malfind.commitCharge'] = max(_e3_float(stats.get('malfind.commitCharge'), 0.0), stats['total_commit_charge'])
                stats['_debug_phaseE3_premapper_calibrated'] = 1.0
                stats['_debug_phaseE3_confirmed_injection_rows'] = _row_count
                stats['_debug_phaseE3_confirmed_targets'] = _target_count
        except Exception as _phase_e3_ex:
            self.logger.warning('[CICStats] Phase E3 malfind pre-mapper calibration skipped: %s', _phase_e3_ex)

        # Explicitly suppress unsupported broad families so FeatureMapper defaults are preserved.
        for k in list(stats.keys()):
            if (
                k.startswith('svcscan.')
                or k.startswith('modules.')
                or k.startswith('callbacks.')
                or k.startswith('psxview.')
                or k in {'total_services', 'kernel_driver_services', 'filesystem_driver_services',
                         'process_services', 'shared_process_services', 'interactive_process_services',
                         'active_services', 'total_modules', 'total_callbacks', 'anonymous_callbacks',
                         'generic_callbacks'}
            ):
                stats.pop(k, None)

        self.logger.info(
            '[CICStats] total_processes=%s total_dlls=%s total_handles=%s avg_handles/proc=%.1f injections=%s ldr_raw=(load=%s init=%s mem=%s) ldr_avg=(load=%s init=%s mem=%s) nprocs64=%s',
            n_procs,
            n_dlls,
            n_handles,
            float(n_handles) / safe_procs,
            stats.get('malfind.ninjections', stats.get('injection_count', 0.0)),
            stats.get('ldrmodules.not_in_load', 'default'),
            stats.get('ldrmodules.not_in_init', 'default'),
            stats.get('ldrmodules.not_in_mem', 'default'),
            stats.get('ldrmodules.not_in_load_avg', 'default'),
            stats.get('ldrmodules.not_in_init_avg', 'default'),
            stats.get('ldrmodules.not_in_mem_avg', 'default'),
            stats.get('total_procs_64bit', 'default'),
        )
        return stats

    def build_heuristic_data(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the raw_vol_data dict required by HeuristicEngine.compute_extra_features().

        Called automatically at the end of extract_all_features() and cached in
        self.heuristic_data.  Callers retrieve it via get_heuristic_data() and
        pass it straight to the engine:

            extra  = engine.compute_extra_features(aggregator.get_heuristic_data())
            result = engine.evaluate(ml_result, extra)

        Fields populated
        ----------------
        Existing (heuristic_engine Rules 1-4):
            total_processes, hidden_from_pslist, injection_count,
            total_dlls_loaded, dlls_not_in_load_list/init/mem, dll_paths

        New (heuristic_engine Rules 5-6 — process path quality):
            process_paths              : list of (image_name, path) tuples
            malware_path_process_count : processes whose path matches _is_malware_path()
            named_malware_process_count: processes whose name matches MALWARE_PROCESS_INDICATORS
        """
        from ramdetect.ml.heuristic_engine import MALWARE_PROCESS_INDICATORS, SUSPICIOUS_PROCESS_DIRS

        processes  = parsed_data.get('processes', [])
        dlls       = parsed_data.get('dlls', [])
        injections = parsed_data.get('injections', [])

        # Flatten DLLs if dict-keyed by PID
        if isinstance(dlls, dict):
            flat_dlls: list = []
            for v in dlls.values():
                flat_dlls.extend(v)
            dlls = flat_dlls

        n_procs = max(len(processes), 1)

        # ── Existing heuristic fields ──────────────────────────────────────────
        hidden_pslist = sum(
            1 for p in processes
            if any('hidden' in str(a).lower() for a in p.get('anomalies', []))
        )

        dll_paths = [
            d.get('path', '') or d.get('full_path', '')
            for d in dlls
        ]

        not_in_load = sum(1 for d in dlls if d.get('not_in_load', False))
        not_in_init = sum(1 for d in dlls if d.get('not_in_init', False))
        not_in_mem  = sum(1 for d in dlls if d.get('not_in_mem',  False))

        # ── New process path quality fields ───────────────────────────────────
        # Import SUSPICIOUS_PROCESS_DIRS here so we can use it as a direct
        # secondary check alongside the regex-based _is_malware_path().
        # This covers cases like \AppData\Local\Temp\<8-char-hex>\oneetx.exe
        # that the regex patterns may miss.
        from ramdetect.ml.heuristic_engine import SUSPICIOUS_PROCESS_DIRS as _SUSP_DIRS

        process_paths: list = []
        malware_path_count = 0
        named_malware_count = 0

        for proc in processes:
            # Try multiple field names for process name (internal parsers differ)
            name = (
                proc.get('image_name') or
                proc.get('name') or
                proc.get('process_name') or
                proc.get('Process Name') or
                ''
            )
            name = str(name).lower().strip()

            # Try multiple field names for path; skip placeholder dash values
            raw_path = (
                proc.get('path') or
                proc.get('exe_path') or
                proc.get('image_path') or
                proc.get('full_path') or
                proc.get('Path') or
                ''
            )
            raw_path = str(raw_path).strip()
            # Treat '-' and 'none' as missing (used by the CSV exporter)
            if raw_path in ('-', 'None', 'none', 'N/A', 'n/a'):
                raw_path = ''
            path = raw_path.lower().replace('/', '\\')

            process_paths.append((name, path))

            # Rule 5a: regex-based high-risk path detection
            is_malware = self._is_malware_path(path)

            # Rule 5b: SUSPICIOUS_PROCESS_DIRS direct substring match
            # (catches paths where the regex doesn't fire — e.g. short hex folders)
            if not is_malware and path:
                is_malware = any(s in path for s in _SUSP_DIRS)

            if is_malware:
                malware_path_count += 1

            # Rule 6: name matches known malware family
            if name and any(ind in name for ind in MALWARE_PROCESS_INDICATORS):
                named_malware_count += 1

        # Fallback: check anomaly tags set by the extraction layer.
        # Handles both list-of-strings and single-string anomaly fields.
        if malware_path_count == 0:
            for proc in processes:
                # Try list key first, then singular string key
                anomalies = proc.get('anomalies') or proc.get('anomaly') or []
                if isinstance(anomalies, str):
                    anomaly_text = anomalies
                else:
                    anomaly_text = ' '.join(str(a) for a in anomalies)
                if 'MALWARE PATH PATTERN' in anomaly_text:
                    malware_path_count += 1

        # Fallback for named malware: check anomaly tags too
        if named_malware_count == 0:
            for proc in processes:
                name_check = (
                    proc.get('image_name') or proc.get('name') or
                    proc.get('process_name') or proc.get('Process Name') or ''
                )
                name_check = str(name_check).lower()
                if name_check and any(ind in name_check for ind in MALWARE_PROCESS_INDICATORS):
                    named_malware_count += 1

        data = {
            # existing fields
            "total_processes":        float(n_procs),
            "hidden_from_pslist":     float(hidden_pslist),
            "injection_count":        float(len(injections)),
            "total_dlls_loaded":      float(len(dlls)),
            "dlls_not_in_load_list":  float(not_in_load),
            "dlls_not_in_init_list":  float(not_in_init),
            "dlls_not_in_mem_list":   float(not_in_mem),
            "dll_paths":              dll_paths,
            # new fields for Rules 5 & 6
            "process_paths":                 process_paths,
            "malware_path_process_count":    malware_path_count,
            "named_malware_process_count":   named_malware_count,
        }

        if malware_path_count > 0 or named_malware_count > 0:
            self.logger.warning(
                "[HeuristicData] Malware signals: malware_path_procs=%d  named_malware=%d",
                malware_path_count, named_malware_count,
            )

        self.heuristic_data = data
        return data

    def get_heuristic_data(self) -> Dict[str, Any]:
        """
        Return the heuristic data dict built during extract_all_features().
        If extract_all_features() has not been called yet, returns an empty dict.
        """
        return self.heuristic_data.copy()

    def extract_all_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Main execution pipeline with browser-aware adjustments.
        
        Steps:
        1. Identify browser processes in the data
        2. Run all feature extractors
        3. Apply browser-aware weighting
        4. Apply context-aware normalization
        5. Return adjusted features
        
        Args:
            parsed_data: Dictionary containing all raw parsed memory artifacts
        
        Returns:
            Browser-aware adjusted feature dictionary
        """
        # Timestamp start for performance metrics
        self.metadata['extraction_start'] = datetime.now().isoformat()
        start_time = time.time()
        
        self.logger.info("[FeatureAggregator] Starting browser-aware feature extraction...")
        
        # Reset state
        self.feature_vector = {}
        self.metadata['extractor_stats'] = {}
        
        # Step 1: Identify browser context
        self._identify_browser_context(parsed_data)
        
        # Step 2: Extract features from all modules
        self.logger.info("[FeatureAggregator] Running individual feature extractors...")
        
        for extractor_name, extractor in self.extractors.items():
            try:
                self.logger.debug(f"[FeatureAggregator] Running {extractor_name} extractor...")
                
                # Run extractor with error handling
                features = extractor.extract_with_error_handling(parsed_data)
                
                if features:
                    self.feature_vector.update(features)
                    self.metadata['successful_extractors'] += 1
                    
                    self.logger.debug(
                        f"[FeatureAggregator] ✓ {extractor_name}: "
                        f"extracted {len(features)} features"
                    )
                else:
                    self.metadata['failed_extractors'] += 1
                    self.logger.warning(
                        f"[FeatureAggregator] ✗ {extractor_name}: "
                        f"no features extracted"
                    )
                
                # Store extractor metadata
                self.metadata['extractor_stats'][extractor_name] = extractor.get_metadata()
                
            except Exception as e:
                self.metadata['failed_extractors'] += 1
                self.logger.error(
                    f"[FeatureAggregator] ✗ {extractor_name} failed: {str(e)}",
                    exc_info=True
                )
                self.metadata['extractor_stats'][extractor_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        # Step 2b: Add CIC-compatible aggregate stats to the feature vector.
        # This is critical — without this, transform_live() maps few or no canonical features
        # because the extractor output names (orphan_process_count etc.) don't
        # appear in RAMDETECT_TO_CIC. The aggregate stats DO appear there.
        cic_stats = self._compute_cic_aggregate_stats(parsed_data)
        self.feature_vector.update(cic_stats)
        self.logger.info(
            f"[FeatureAggregator] CIC stats added: "
            f"{len(cic_stats)} aggregate features merged into vector"
        )

        # Step 2c: Optional diagnostic-only heuristic data.  Disabled by
        # default because RAMDetect's final verdict must remain ML-only.
        # Enable only for report/debug export with:
        #   RAMDETECT_ENABLE_DIAGNOSTIC_HEURISTIC_DATA=1
        if os.environ.get("RAMDETECT_ENABLE_DIAGNOSTIC_HEURISTIC_DATA", "0").strip().lower() in {"1", "true", "yes", "on"}:
            self.build_heuristic_data(parsed_data)
            self.logger.info(
                "[FeatureAggregator] Diagnostic heuristic data built: "
                "malware_path_procs=%d  named_malware=%d",
                self.heuristic_data.get("malware_path_process_count", 0),
                self.heuristic_data.get("named_malware_process_count", 0),
            )
        else:
            self.heuristic_data = {}

        strict_ml_only = os.environ.get("RAMDETECT_ML_ONLY_STRICT", "1").strip().lower() not in {"0", "false", "no", "off"}

        # Step 3/4: Browser-aware weighting and context normalization are
        # disabled in strict ML-only mode. They are legacy feature-layer
        # adjustments and are therefore kept out of the experiment/official ML
        # path unless explicitly enabled for diagnostics.
        if not strict_ml_only and self.browser_pids:
            self.logger.info("[FeatureAggregator] Applying legacy browser-aware adjustments...")
            self.feature_vector = self._apply_browser_aware_weighting(self.feature_vector, parsed_data)

        if not strict_ml_only:
            self.feature_vector = self._normalize_features_with_context(self.feature_vector)
        
        # Step 5: Finalize metadata
        self.metadata['extraction_end'] = datetime.now().isoformat()
        self.metadata['total_duration'] = time.time() - start_time
        self.metadata['total_features'] = len(self.feature_vector)
        
        # Calculate browser impact summary
        browser_impact = self._calculate_browser_impact()
        self.metadata['browser_context'].update(browser_impact)
        
        self.logger.info(
            f"[FeatureAggregator] Feature extraction complete: "
            f"{self.metadata['total_features']} features extracted in "
            f"{self.metadata['total_duration']:.2f}s"
        )
        
        if self.browser_pids:
            self.logger.info(
                f"[FeatureAggregator] Browser context: {self.browser_process_count} processes, "
                f"score reduction: {browser_impact.get('score_reduction_percent', 0)}%"
            )
        
        return self.feature_vector
    
    def _calculate_browser_impact(self) -> Dict[str, Any]:
        """
        Calculate how much browsers affected the final scores.
        """
        if not self.browser_pids:
            return {
                'score_reduction_percent': 0,
                'features_adjusted': 0,
                'average_adjustment': 0
            }
        
        # Estimate impact by comparing browser-sensitive features to others
        browser_sensitive_keys = [
            'orphan_process', 'unbacked_thread', 'suspicious_path',
            'unsigned_dll', 'missing_path'
        ]
        
        sensitive_scores = []
        other_scores = []
        
        for key, value in self.feature_vector.items():
            key_lower = key.lower()
            is_sensitive = any(browser_key in key_lower for browser_key in browser_sensitive_keys)
            
            if is_sensitive:
                sensitive_scores.append(value)
            else:
                other_scores.append(value)
        
        # Calculate averages
        avg_sensitive = sum(sensitive_scores) / max(1, len(sensitive_scores))
        avg_other = sum(other_scores) / max(1, len(other_scores))
        
        # Estimate reduction percentage
        if avg_other > 0:
            reduction = max(0, (avg_other - avg_sensitive) / avg_other * 100)
        else:
            reduction = 0
        
        return {
            'score_reduction_percent': round(reduction, 1),
            'features_adjusted': len(sensitive_scores),
            'average_adjustment': round(avg_sensitive, 3),
            'average_other_features': round(avg_other, 3)
        }
    
    def get_browser_context(self) -> Dict[str, Any]:
        """Get browser context information."""
        return self.metadata['browser_context'].copy()
    
    def get_feature_vector(self) -> Dict[str, float]:
        """Returns a copy of the aggregated feature dictionary."""
        return self.feature_vector.copy()
    
    def get_feature_names(self) -> List[str]:
        """Returns a list of all feature names."""
        return list(self.feature_vector.keys())
    
    def get_feature_values(self) -> List[float]:
        """Returns a list of all feature values."""
        return list(self.feature_vector.values())
    
    def get_metadata(self) -> Dict[str, Any]:
        """Returns the metadata dictionary with browser context."""
        return self.metadata.copy()
    
    def export_to_csv(self, output_path: str, include_metadata: bool = True) -> bool:
        """
        Exports the features to a CSV file with browser context notes.
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                # Write metadata header
                if include_metadata:
                    f.write(f"# RAMDetect Browser-Aware Feature Export\n")
                    f.write(f"# Extraction Date: {self.metadata.get('extraction_start', 'N/A')}\n")
                    f.write(f"# Total Features: {self.metadata['total_features']}\n")
                    f.write(f"# Browser Processes: {self.browser_process_count}\n")
                    f.write(f"# Browser-Aware Adjustment: {self.metadata['browser_context']['browser_aware_adjustment']}\n")
                    f.write(f"# Score Reduction: {self.metadata['browser_context'].get('score_reduction_percent', 0)}%\n")
                    f.write(f"#\n")
                
                # Write CSV data
                writer = csv.writer(f)
                writer.writerow(self.get_feature_names())  # Header Row
                writer.writerow(self.get_feature_values()) # Data Row
            
            self.logger.info(f"[FeatureAggregator] Features exported to CSV: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"[FeatureAggregator] CSV export failed: {str(e)}", exc_info=True)
            return False
    
    def export_to_json(self, output_path: str, include_metadata: bool = True) -> bool:
        """
        Exports features to a JSON file with browser context.
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            output_data = {
                'features': self.feature_vector,
                'browser_context': self.metadata['browser_context']
            }
            
            if include_metadata:
                output_data['metadata'] = self.metadata
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            self.logger.info(f"[FeatureAggregator] Features exported to JSON: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"[FeatureAggregator] JSON export failed: {str(e)}", exc_info=True)
            return False
    
    def get_feature_importance_summary(self) -> Dict[str, Any]:
        """
        Analyzes the feature vector with browser awareness.
        """
        summary = {
            'process_features': 0,
            'thread_features': 0,
            'dll_features': 0,
            'pe_features': 0,
            'handle_features': 0,
            'injection_features': 0,
            'total': len(self.feature_vector),
            'non_zero_features': 0,
            'high_value_features': 0,  # Features > 0.5
            'browser_sensitive_features': 0,
            'browser_adjusted_features': 0
        }
        
        browser_sensitive_keys = [
            'orphan_process', 'unbacked_thread', 'suspicious_path',
            'unsigned_dll', 'missing_path', 'late_loaded'
        ]
        
        for feature_name, value in self.feature_vector.items():
            # Count active features
            if value > 0.0:
                summary['non_zero_features'] += 1
            
            # Count highly suspicious features
            if value > 0.5:
                summary['high_value_features'] += 1
            
            # Check if browser-sensitive
            key_lower = feature_name.lower()
            is_browser_sensitive = any(browser_key in key_lower for browser_key in browser_sensitive_keys)
            
            if is_browser_sensitive and value > 0:
                summary['browser_sensitive_features'] += 1
                if value < 0.3:  # Likely adjusted down
                    summary['browser_adjusted_features'] += 1
            
            # Categorize features
            if any(keyword in feature_name for keyword in ['process', 'pid', 'ppid', 'orphan']):
                summary['process_features'] += 1
            elif any(keyword in feature_name for keyword in ['thread', 'apc']):
                summary['thread_features'] += 1
            elif 'dll' in feature_name:
                summary['dll_features'] += 1
            elif any(keyword in feature_name for keyword in ['pe', 'section', 'import', 'export']):
                summary['pe_features'] += 1
            elif any(keyword in feature_name for keyword in ['handle', 'mutex', 'registry']):
                summary['handle_features'] += 1
            elif any(keyword in feature_name for keyword in ['injection', 'reflective', 'hollow']):
                summary['injection_features'] += 1
        
        return summary
    
    def print_summary(self):
        """
        Prints a formatted report with browser context.
        """
        print("\n" + "="*70)
        print("RAMDetect Browser-Aware Feature Extraction Summary")
        print("="*70)
        
        print(f"\n📊 Extraction Statistics:")
        print(f"  Total Features:        {self.metadata['total_features']}")
        print(f"  Extraction Duration:   {self.metadata['total_duration']:.2f}s")
        print(f"  Successful Extractors: {self.metadata['successful_extractors']}/{len(self.extractors)}")
        print(f"  Browser Processes:     {self.browser_process_count}")
        
        if self.browser_pids:
            print(f"  Browser-Aware Adjust:  ✓ Applied")
            reduction = self.metadata['browser_context'].get('score_reduction_percent', 0)
            print(f"  Score Reduction:       {reduction}%")
        
        importance = self.get_feature_importance_summary()
        print(f"\n🔍 Feature Breakdown:")
        print(f"  Process Features:      {importance['process_features']}")
        print(f"  Thread Features:       {importance['thread_features']}")
        print(f"  DLL Features:          {importance['dll_features']}")
        print(f"  PE Features:           {importance['pe_features']}")
        print(f"  Handle Features:       {importance['handle_features']}")
        print(f"  Injection Features:    {importance['injection_features']}")
        
        print(f"\n⚠️  Alert Features:")
        print(f"  Non-Zero Features:     {importance['non_zero_features']}")
        print(f"  High-Value Features:   {importance['high_value_features']} (>0.5)")
        
        if self.browser_pids:
            print(f"\n🔄 Browser Adjustments:")
            print(f"  Browser-Sensitive:    {importance['browser_sensitive_features']}")
            print(f"  Likely Adjusted:      {importance['browser_adjusted_features']}")
        
        # Sort features by value to show the most suspicious ones first
        sorted_features = sorted(
            self.feature_vector.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        print(f"\n🚨 Top 10 Suspicious Features:")
        for i, (name, value) in enumerate(sorted_features[:10], 1):
            if value > 0:
                # Mark browser-sensitive features
                is_sensitive = any(key in name.lower() for key in ['orphan', 'unbacked', 'unsigned'])
                marker = "[B]" if is_sensitive and self.browser_pids else ""
                print(f"  {i:2d}. {name:40s} = {value:.3f} {marker}")
        
        print("\n" + "="*70 + "\n")
    
    def reset(self):
        """
        Resets the aggregator state.
        """
        self.feature_vector = {}
        self.heuristic_data = {}
        self.browser_pids.clear()
        self.browser_process_count = 0
        self.browser_thread_count = 0
        
        self.metadata = {
            'extraction_start': None,
            'extraction_end': None,
            'total_duration': 0.0,
            'total_features': 0,
            'successful_extractors': 0,
            'failed_extractors': 0,
            'extractor_stats': {},
            'browser_context': {
                'browser_process_count': 0,
                'browser_pids': [],
                'browser_aware_adjustment': False
            }
        }
        
        # Reset all individual extractors
        for extractor in self.extractors.values():
            extractor.reset()
        
        self.logger.debug("[FeatureAggregator] State reset")
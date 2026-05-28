"""
ramdetect/features/dll_features.py
==================================
Extracts 20 features from DLL data to detect:
- Unsigned/untrusted DLLs
- High entropy (packed/encrypted)
- Suspicious paths and locations
- DLL injection patterns
- Export/Import anomalies

Author: RAMDetect Development Team
"""

from typing import Dict, List, Any
import math
from collections import defaultdict
from .feature_base import FeatureExtractor # Relative import

class DLLFeatures(FeatureExtractor):
    """
    Extract 20 DLL-related features for malware detection.
    """
    
    # Legitimate system DLL paths
    LEGITIMATE_PATHS = [
        # Core Windows directories
        'c:\\windows\\system32',
        'c:\\windows\\syswow64',
        'c:\\windows\\winsxs',
        'c:\\windows\\',             # Explorer.EXE, other root-level OS binaries
        # [FIX] UWP / Store app bundles — all DLLs here are legitimately "unsigned"
        # because they use the Authenticode-free Windows Store code-signing model.
        # NOT flagging these as suspicious removes ~91 false positives per clean scan.
        'c:\\windows\\systemapps\\',      # UWP system apps (Start Menu, Search, etc.)
        'c:\\windows\\shellcomponents\\',  # Composable Shell components
        'c:\\windows\\shellexperiences\\', # Shell experience DLLs
        'c:\\windows\\uus\\',              # Universal Update Service packages
        'c:\\windows\\immersivecontrolpanel\\',  # Settings app
        # Standard install locations
        'c:\\program files\\',        # 64-bit program installs
        'c:\\program files (x86)\\',  # 32-bit program installs
        'c:\\windows\\microsoft.net\\',   # .NET runtime
    ]
    
    # Suspicious DLL paths (common malware locations)
    SUSPICIOUS_PATHS = [
        'temp', 'tmp', 'appdata\\local\\temp', 'appdata\\roaming',
        'downloads', 'desktop', 'public', 'recycler', 'users\\public'
    ]
    
    # Critical System DLLs that MUST be signed by Microsoft.
    # If any of these are unsigned, it's almost certainly a replacement attack (DLL Sideloading).
    # System DLLs that should always be signed
    CRITICAL_SYSTEM_DLLS = {
        'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll',
        'advapi32.dll', 'ws2_32.dll', 'ole32.dll', 'msvcrt.dll'
    }
    
    # Suspicious export names (commonly used by malware)
    SUSPICIOUS_EXPORTS = [
        'reflectiveloader', 'dllmain', 'start', 'run', 'exec',
        'inject', 'hook', 'bypass', 'elevate', 'exploit'
    ]
    
    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.0  # Likely packed/encrypted
    LOW_ENTROPY_THRESHOLD = 3.0   # Unusual (very repetitive)

    TRUSTED_UNSIGNED_NAMES = {
        'explorer.exe', 'dumpit.exe', 'ftkimager.exe', 'winpmem.exe',
        'rammap.exe', 'procdump.exe', 'livekd.exe', 'ramdetect.exe', 'ramdetect_gui.exe',
    }

    @classmethod
    def _is_trusted_unsigned_or_unresolved(cls, dll: Dict[str, Any]) -> bool:
        """
        Memory parsing cannot perform true Authenticode verification. A signed=False
        value from trusted Windows/acquisition paths is treated as signature
        unresolved, not malicious evidence.
        """
        name = str(dll.get('name', '') or '').lower()
        path = str(dll.get('path', '') or '').lower().replace('/', '\\')
        if name in cls.TRUSTED_UNSIGNED_NAMES:
            return True
        if name == 'explorer.exe' and path.startswith('c:\\windows\\'):
            return True
        if any(path.startswith(p) for p in cls.LEGITIMATE_PATHS):
            return not bool(dll.get('is_suspicious', False))
        return False

    
    def __init__(self, logger=None):
        super().__init__(name="DLLFeatures", logger=logger)
    
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract 20 DLL features from parsed memory data.
        """
        dlls = parsed_data.get('dlls', [])
        
        # Flatten structure if it comes as {pid: [dlls]}
        if isinstance(dlls, dict):
            flat_dlls = []
            for pid_dlls in dlls.values():
                flat_dlls.extend(pid_dlls)
            dlls = flat_dlls
        
        if not dlls:
            self.logger.warning(f"[{self.name}] No DLLs found in parsed_data")
            return self._get_zero_features()
        
        total_dlls = len(dlls)
        features = {}
        
        # ===== CATEGORY 1: Signature & Trust (4 features) =====
        features.update(self._extract_signature_features(dlls, total_dlls))
        
        # ===== CATEGORY 2: Entropy Analysis (4 features) =====
        features.update(self._extract_entropy_features(dlls, total_dlls))
        
        # ===== CATEGORY 3: Path & Location (5 features) =====
        features.update(self._extract_path_features(dlls, total_dlls))
        
        # ===== CATEGORY 4: Load Order Anomalies (4 features) =====
        features.update(self._extract_load_order_features(dlls, total_dlls))
        
        # ===== CATEGORY 5: Export/Import Anomalies (3 features) =====
        features.update(self._extract_export_import_features(dlls, total_dlls))
        
        return features
    
    def _extract_signature_features(self, dlls: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to code signing and trust."""
        unsigned_count = 0
        invalid_signature_count = 0
        unsigned_system_dll_count = 0
        
        for dll in dlls:
            # Default to True: assume signed unless parser explicitly says otherwise.
            # Defaulting to False caused every DLL to be treated as unsigned
            # when the parser didn't set the field, producing 330 false positives.
            is_signed = dll.get('signed', True)
            signature_valid = dll.get('signature_valid', True)
            dll_name = dll.get('name', '').lower()
            
            if not is_signed:
                if self._is_trusted_unsigned_or_unresolved(dll):
                    dll.setdefault('info_notes', []).append(
                        'Signature unresolved in memory, but trusted path/name; excluded from unsigned DLL risk feature.'
                    )
                else:
                    unsigned_count += 1
                    # Critical Check: Is a core Windows DLL unsigned?
                    if dll_name in self.CRITICAL_SYSTEM_DLLS:
                        unsigned_system_dll_count += 1
            
            if is_signed and not signature_valid:
                invalid_signature_count += 1
        
        return {
            # Real Windows systems routinely have 50-100+ third-party PE-unsigned DLLs
            # (drivers, AV, software). max_threshold=10 made even a clean system score ~0.97.
            'unsigned_dll_count': self.normalize_count(unsigned_count, max_threshold=50),
            'unsigned_dll_ratio': self.normalize_ratio(unsigned_count, total),
            'invalid_signature_count': self.normalize_count(invalid_signature_count, max_threshold=3),
            'unsigned_system_dll_count': self.normalize_count(unsigned_system_dll_count, max_threshold=1)
        }
    
    def _extract_entropy_features(self, dlls: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to entropy analysis."""
        high_entropy_count = 0
        low_entropy_count = 0
        section_entropy_variance_sum = 0.0
        
        for dll in dlls:
            dll_entropy = dll.get('entropy', 0.0)
            section_entropies = dll.get('section_entropies', [])
            
            # Entropy measures randomness (0.0 to 8.0).
            # Text/Code is usually low entropy (patterns).
            # Encrypted data or Packed code (compressed) looks random (High Entropy).
            
            # Threshold 7.0 is widely used as a cutoff for "Packed/Encrypted".
            if dll_entropy >= self.HIGH_ENTROPY_THRESHOLD:
                high_entropy_count += 1
            
            if dll_entropy > 0 and dll_entropy <= self.LOW_ENTROPY_THRESHOLD:
                low_entropy_count += 1
            
            if len(section_entropies) > 1:
                try:
                    variance = self._calculate_variance(section_entropies)
                    section_entropy_variance_sum += variance
                except:
                    pass
        
        avg_section_variance = section_entropy_variance_sum / total if total > 0 else 0.0
        
        return {
            'high_entropy_dll_count': self.normalize_count(high_entropy_count, max_threshold=5),
            'high_entropy_dll_ratio': self.normalize_ratio(high_entropy_count, total),
            'low_entropy_dll_count': self.normalize_count(low_entropy_count, max_threshold=3),
            'section_entropy_variance': min(1.0, avg_section_variance / 4.0)
        }
    
    @staticmethod
    def _is_corrupted_path(path: str) -> bool:
        """
        Detect corrupted or partially decoded DLL paths caused by bad DTB/PEB
        reads. These should be treated as parser warnings, not malware evidence.
        """
        if not path:
            return False

        cleaned = str(path).strip()
        if cleaned.lower() in {"unknown", "-", "none", "n/a"}:
            return False

        control_chars = sum(1 for c in cleaned if ord(c) < 32)
        non_ascii = sum(1 for c in cleaned if ord(c) > 126)

        if control_chars > 0:
            return True

        if len(cleaned) > 0 and (non_ascii / len(cleaned)) > 0.10:
            return True

        lowered = cleaned.lower().replace("/", "\\")
        # Common symptom: truncated/corrupted System32 path such as
        # C:\Windows\SYSTE<garbage>.
        if lowered.startswith("c:\\windows\\syste") and not lowered.startswith("c:\\windows\\system32"):
            return True

        return False

    def _extract_path_features(self, dlls: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to DLL paths and locations."""
        suspicious_path_count = 0
        missing_from_disk_count = 0
        temp_folder_count = 0
        no_path_count = 0
        user_writable_count = 0
        
        # [FIX] Forensic / IR tools that legitimately live in Downloads/Desktop.
        # They match the SUSPICIOUS_PATHS rules but are NOT malware.
        _FORENSIC_DLL_NAMES = {
            'dumpit.exe', 'ftkimager.exe', 'winpmem.exe',
            'winpmem_mini_x64.exe', 'winpmem_mini_x86.exe',
            'winpmem_x64.exe', 'winpmem_x86.exe',
            'rammap.exe', 'procdump.exe', 'livekd.exe',
            'volatility.exe', 'volatility3.exe',
            'rekal.exe', 'rekall.exe',
            'ramdetect.exe', 'ramdetect_gui.exe',
        }

        for dll in dlls:
            raw_path = str(dll.get('path', '') or '')
            exists_on_disk = dll.get('exists_on_disk', True)

            if self._is_corrupted_path(raw_path):
                dll.setdefault('parse_warnings', []).append(
                    'Corrupted or partially decoded DLL path; excluded from suspicious path scoring.'
                )
                # Do not convert corrupted parser output into a suspicious DLL.
                if str(dll.get('status', '')).upper() != 'SUSPICIOUS':
                    dll['status'] = dll.get('status', 'CLEAN')
                dll['anomaly'] = dll.get('anomaly', '-')
                continue

            path = raw_path.lower()

            if not path or path == 'unknown':
                no_path_count += 1
                continue

            # [FIX] Extract DLL/EXE basename to check forensic tool whitelist
            import os as _os
            _dll_basename = _os.path.basename(path.replace('\\', _os.sep)).lower()
            _is_forensic_tool = _dll_basename in _FORENSIC_DLL_NAMES

            if not exists_on_disk:
                missing_from_disk_count += 1

            # Skip suspicious-path counting for forensic acquisition tools
            if not _is_forensic_tool:
                if any(susp in path for susp in self.SUSPICIOUS_PATHS):
                    suspicious_path_count += 1

                if 'temp' in path or 'tmp' in path:
                    temp_folder_count += 1

                # [FIX] Filter out forensic tools and program-data DLLs
                # from user_writable count — they inflate the ratio on clean systems.
                _USER_WRITABLE_DIRS = ['appdata\\local\\temp', 'appdata\\roaming\\temp',
                                       'users\\public\\', 'documents\\']
                if any(loc in path for loc in _USER_WRITABLE_DIRS):
                    user_writable_count += 1
        
        return {
            'suspicious_path_dll_count': self.normalize_count(suspicious_path_count, max_threshold=10),
            'missing_from_disk_count': self.normalize_count(missing_from_disk_count, max_threshold=3),
            'temp_folder_dll_count': self.normalize_count(temp_folder_count, max_threshold=3),
            # Many legitimate NT kernel modules have no path in memory.
            # max_threshold=2 caused instant high score from normal system DLLs.
            'no_path_dll_count': self.normalize_count(no_path_count, max_threshold=20),
            'user_writable_dll_ratio': self.normalize_ratio(user_writable_count, total)
        }
    
    def _extract_load_order_features(self, dlls: List[Dict], total: int) -> Dict[str, float]:
        """
        Extract features related to DLL load order anomalies.

        The parser populates DLLs in InLoadOrderLinks list order, so the list
        index within each process is a valid proxy for load order even when
        the parser doesn't emit an explicit 'load_order' field.
        """
        late_loaded_system_count  = 0
        early_loaded_user_count   = 0
        injection_pattern_count   = 0
        load_order_anomaly_count  = 0

        process_dlls = defaultdict(list)
        for dll in dlls:
            pid = dll.get('pid', 0)
            process_dlls[pid].append(dll)

        for pid_dlls in process_dlls.values():
            for idx, dll in enumerate(pid_dlls):
                dll_name   = dll.get('name', '').lower()
                path       = str(dll.get('path', '')).lower()

                # Use explicit load_order if present, otherwise fall back to
                # list index (valid because the PEB walk preserves list order).
                load_order = dll.get('load_order', idx)

                # Late-loaded critical system DLL → possible hijacking
                if dll_name in self.CRITICAL_SYSTEM_DLLS and load_order > 50:
                    late_loaded_system_count += 1

                # Non-system DLL appearing before index 5 → possible injection
                if (load_order < 5 and
                        not any(leg in path for leg in self.LEGITIMATE_PATHS) and
                        path and path not in ('', '?', 'unknown')):
                    early_loaded_user_count += 1

                # Gap in load order (only meaningful with explicit field)
                if idx > 0 and dll.get('load_order') is not None:
                    prev_order = pid_dlls[idx - 1].get('load_order', idx - 1)
                    if load_order - prev_order > 100:
                        load_order_anomaly_count += 1

        return {
            'late_loaded_system_dll_count': self.normalize_count(late_loaded_system_count, max_threshold=2),
            'early_loaded_user_dll_count':  self.normalize_count(early_loaded_user_count,  max_threshold=3),
            'injection_pattern_count':      self.normalize_count(injection_pattern_count,   max_threshold=3),
            'load_order_anomaly_count':     self.normalize_count(load_order_anomaly_count,  max_threshold=5),
        }
    
    def _extract_export_import_features(self, dlls: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to export/import tables."""
        suspicious_export_count = 0
        no_imports_count = 0
        excessive_exports_count = 0
        
        for dll in dlls:
            exports = dll.get('exports', [])
            imports = dll.get('imports', [])
            
            for export_name in exports:
                if any(susp in export_name.lower() for susp in self.SUSPICIOUS_EXPORTS):
                    suspicious_export_count += 1
                    break
            
            dll_name = dll.get('name', '').lower()
            # Kernel32 and ntdll might appear to have no imports in some views
            if not imports and dll_name not in ['kernel32.dll', 'ntdll.dll']:
                no_imports_count += 1
                
            if len(exports) > 500:
                excessive_exports_count += 1
        
        return {
            'suspicious_export_count': self.normalize_count(suspicious_export_count, max_threshold=3),
            'no_imports_dll_count': self.normalize_count(no_imports_count, max_threshold=2),
            'excessive_exports_count': self.normalize_count(excessive_exports_count, max_threshold=2)
        }
    
    def _calculate_variance(self, values: List[float]) -> float:
        if len(values) < 2: return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)
    
    def _get_zero_features(self) -> Dict[str, float]:
        """Return zeroed features."""
        # Returns dictionary with all 20 keys set to 0.0
        keys = [
            'unsigned_dll_count', 'unsigned_dll_ratio', 'invalid_signature_count', 'unsigned_system_dll_count',
            'high_entropy_dll_count', 'high_entropy_dll_ratio', 'low_entropy_dll_count', 'section_entropy_variance',
            'suspicious_path_dll_count', 'missing_from_disk_count', 'temp_folder_dll_count', 'no_path_dll_count', 'user_writable_dll_ratio',
            'late_loaded_system_dll_count', 'early_loaded_user_dll_count', 'injection_pattern_count', 'load_order_anomaly_count',
            'suspicious_export_count', 'no_imports_dll_count', 'excessive_exports_count'
        ]
        return {k: 0.0 for k in keys}
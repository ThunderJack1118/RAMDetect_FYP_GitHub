"""
ramdetect/features/injection_features.py
=============================================
Extracts 10 advanced features to detect sophisticated injection techniques:
- Reflective DLL injection
- Process hollowing
- AtomBombing
- PE injection patterns
- Memory patching
- Shellcode signatures

It combines raw memory scanning with alerts from the Injection Detector (Engine 9).
Updated: JIT Whitelisting added to reduce False Positives in Risk Score.
"""

from typing import Dict, List, Any, Union
from .feature_base import FeatureExtractor # Relative import

class InjectionFeatures(FeatureExtractor):
    """
    Extract 10 advanced code injection features for malware detection.
    This class inherits from FeatureExtractor to standardize output format and logging.
    """
    
    # PE signature "MZ" (0x5A4D) - The magic bytes that start every Windows Executable.
    # Detection logic: Finding this signature in memory regions that are NOT mapped files
    # (Private Memory) is a primary indicator of injected code (PE Injection).
    PE_SIGNATURE = b'MZ'
    
    # Common shellcode patterns (x86/x64)
    # These byte sequences are typical prologues (start of functions) found in shellcode.
    # Malware uses shellcode to execute arbitrary commands after exploiting a vulnerability.
    SHELLCODE_PATTERNS = [
        b'\x55\x8B\xEC',  # push ebp; mov ebp, esp (Standard x86 function prologue)
        b'\x48\x89\x5C\x24',  # mov [rsp+XX], rbx (Common x64 function prologue)
        b'\xE8\x00\x00\x00\x00',  # call $+5 (GetPC technique) - Used to find current memory address (Position Independent Code)
        b'\x60\x8B\xEC',  # pushad; mov ebp, esp - Saving state before execution
        b'\xEB\xFE',  # jmp $ (Infinite loop) - Used in dev/testing stubs to pause execution for debugger attach
        b'\x33\xC0\x64\x8B',  # xor eax, eax; mov eax, fs:[XX] (Accessing Process Environment Block in x86)
        b'\x65\x48\x8B',  # mov rax, gs:[XX] (Accessing TEB/PEB in x64)
    ]
    
    # Reflective loader patterns
    # Reflective DLL Injection allows loading a DLL from memory without writing to disk.
    # These strings/function names are specific artifacts of known reflective loader implementations (like Stephen Fewer's).
    REFLECTIVE_LOADER_SIGNATURES = [
        b'ReflectiveLoader',
        b'reflective_dll',
        b'_ReflectiveLoader@',
        b'DllMain',
    ]
    
    # Memory protection flags (Constants)
    # Windows memory pages have permissions. Malware requires Execute (X) permission to run.
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40 # RWX - Highly suspicious (W+X is rare in legit apps)
    PAGE_EXECUTE_WRITECOPY = 0x80
    
    # VAD types (Matches vad_scanner strings)
    # UPDATED: Changed from Int to String to match the new VAD Scanner output
    VAD_TYPE_PRIVATE = 'Private'  # Private memory (not file-backed)
    VAD_TYPE_IMAGE = 'Image'      # Image (PE file)
    
    # JIT Applications to Ignore for Private RWX checks
    # These browsers and Electron apps legitimately allocate Private RWX memory for their JavaScript engines.
    # Whitelisting them prevents "False Positive Storms" in the risk score.
    JIT_APPS = {
        'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 
        'javaw.exe', 'node.exe', 'discord.exe', 'code.exe', 'teams.exe', 
        'slack.exe', 'spotify.exe', 'searchui.exe', 'shellexperiencehost.exe'
    }
    
    def __init__(self, logger=None):
        # Initialize parent class
        super().__init__(name="InjectionFeatures", logger=logger)
    
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract 10 advanced injection features.
        Main execution method for this feature extractor.
        Aggregates data from multiple parsing sources (VADs, Threads, Engine 9 Alerts) to build a risk profile.
        
        Args:
            parsed_data: The master dictionary containing all extracted memory artifacts.
            
        Returns:
            Dictionary of normalized feature scores (0.0 to 1.0).
        """
        # Retrieve necessary datasets from the parser output
        memory_regions = (parsed_data.get('memory_regions') or parsed_data.get('pe_sections') or parsed_data.get('vads') or [])
        processes = parsed_data.get('processes', [])
        threads = parsed_data.get('threads', [])
        injections = parsed_data.get('injections', []) # High-confidence alerts from the heuristics engine
        
        # Create Process Map for Name lookup (Required for JIT Whitelisting)
        pid_map = {}
        for p in processes:
            try:
                _pid = int(p.get('pid') or p.get('PID') or 0)
            except Exception:
                _pid = 0
            _name = (
                p.get('image_name') or p.get('ImageFileName') or
                p.get('process_name') or p.get('Process Name') or p.get('name') or ''
            )
            if _pid:
                pid_map[_pid] = str(_name).lower()
        
        # Even if no memory regions, we might have alerts, so we process if either exists
        if not memory_regions and not injections:
            return self._get_zero_features()
        
        total_regions = len(memory_regions) if memory_regions else 1
        features = {}
        
        # ===== CATEGORY 1: Memory Injection Patterns (3 features) =====
        # Looks for raw indicators in memory pages (e.g., RWX permissions, Shellcode bytes).
        features.update(self._extract_memory_injection_patterns(memory_regions, total_regions, pid_map))
        
        # ===== CATEGORY 2: Advanced Injection Techniques (4 features) =====
        # Detects complex attacks like AtomBombing or Process Hollowing by correlating Process + Memory data.
        features.update(self._extract_advanced_techniques(
            memory_regions, processes, threads, injections, total_regions
        ))
        
        # ===== CATEGORY 3: PE Injection Indicators (2 features) =====
        # Specifically looks for full Executable headers (MZ/PE) floating in private memory.
        features.update(self._extract_pe_injection_indicators(memory_regions, total_regions))
        
        # ===== CATEGORY 4: Memory Protection Anomalies (1 feature) =====
        # Calculates the ratio of RWX memory in the system.
        features.update(self._extract_protection_anomalies(memory_regions, total_regions, pid_map))
        
        return features
    
    def _extract_memory_injection_patterns(self, memory_regions: List[Dict], total: int, pid_map: Dict[int, str]) -> Dict[str, float]:
        """
        Extracts basic memory injection pattern features.
        Iterates through all VAD regions to find suspicious allocations.
        """
        private_executable_count = 0
        shellcode_signature_count = 0
        patched_memory_count = 0
        
        for region in memory_regions:
            # 1. Check Whitelist: Is this a JIT app?
            pid = region.get('pid', 0)
            proc_name = pid_map.get(pid, '')
            if proc_name in self.JIT_APPS:
                continue # Skip detection for browsers to avoid JIT false positives
            
            vad_type = region.get('type') or region.get('vad_type') or region.get('Section') or region.get('section') or 'Unknown'
            protection = self._resolve_protection(region.get('protection') or region.get('Permissions') or region.get('permissions') or 0)
            data = region.get('data', b'') or region.get('bytes', b'')
            is_patched = region.get('is_patched', False) # "Copy-on-Write" modification indicator
            
            # Check 1: Private Memory with Execute Permissions
            # Normal code runs from 'Image' memory. 'Private' + 'Execute' usually means
            # shellcode or manually mapped malware.
            if vad_type == self.VAD_TYPE_PRIVATE:
                if self._is_executable(protection):
                    private_executable_count += 1
                    
                    # Check 2: Shellcode Pattern Matching
                    # If we have the memory content, scan the start for known shellcode prologues.
                    if data and len(data) >= 2:
                        # Optimization: Only scan the first 256 bytes. Shellcode entry points are usually at the start.
                        if self._contains_shellcode_pattern(data[:256]):
                            shellcode_signature_count += 1
            
            # Check 3: Patched Memory (Hooks)
            # Memory that was originally file-backed ('Image') but has been modified ('Patched').
            # This indicates Inline Hooking (Userland Rootkits).
            if is_patched:
                patched_memory_count += 1
        
        return {
            'private_executable_region_count': self.normalize_count(private_executable_count, max_threshold=5),
            'shellcode_signature_count': self.normalize_count(shellcode_signature_count, max_threshold=3),
            'patched_memory_region_count': self.normalize_count(patched_memory_count, max_threshold=5)
        }
    
    def _extract_advanced_techniques(self, 
                                     memory_regions: List[Dict], 
                                     processes: List[Dict], 
                                     threads: List[Dict], 
                                     injections: List[Dict],
                                     total: int) -> Dict[str, float]:
        """
        Extracts advanced injection technique indicators (Raw Scans + Alerts).
        This method combines raw memory analysis with pre-calculated alerts from 'InjectionDetector'.
        """
        reflective_dll_count = 0
        process_hollowing_count = 0
        atombombing_count = 0
        apc_injection_count = 0
        
        # --- PART A: Raw Memory Analysis (Deep Scan) ---
        
        # 1. Group memory regions by Process ID to analyze per-process context.
        process_regions = {}
        for region in memory_regions:
            pid = region.get('pid', 0)
            if pid not in process_regions: process_regions[pid] = []
            process_regions[pid].append(region)
        
        for pid, regions in process_regions.items():
            process_info = next((p for p in processes if (p.get('pid') or p.get('PID')) == pid), None)
            
            # 2. Reflective DLL Scan
            # Look for PE files (MZ header) inside Private Executable memory that also contain
            # specific export names like "ReflectiveLoader".
            for region in regions:
                data = region.get('data', b'') or region.get('bytes', b'')
                protection = self._resolve_protection(region.get('protection') or region.get('Permissions') or region.get('permissions') or 0)
                vad_type = region.get('type') or region.get('vad_type') or region.get('Section') or region.get('section') or 'Unknown'
                
                if vad_type == self.VAD_TYPE_PRIVATE and self._is_executable(protection):
                    # Minimum size check (512 bytes for header) + MZ signature
                    if len(data) >= 512 and data[:2] == self.PE_SIGNATURE:
                        if self._contains_reflective_loader_signature(data):
                            reflective_dll_count += 1
                            break
            
            # 3. Process Hollowing Scan
            # Hollowing replaces the legitimate code of a process.
            # Indicator: The Base Address of the main module in memory (VAD) does NOT match the 
            # expected ImageBase in the PEB (Process Environment Block).
            if process_info:
                hollowing_indicators = 0
                main_image_base = process_info.get('image_base', 0)
                for region in regions:
                    if (region.get('type') or region.get('vad_type') or region.get('Section') or region.get('section')) == self.VAD_TYPE_IMAGE: # Updated key
                        base_addr = region.get('base_address', 0)
                        # Anomaly: Mapped image address != PEB ImageBase
                        if main_image_base != 0 and base_addr != main_image_base:
                            hollowing_indicators += 1
                if hollowing_indicators >= 2:
                    process_hollowing_count += 1
            
            # 4. APC / AtomBombing Scan
            # AtomBombing uses Global Atom Tables to inject code without allocating memory in the target.
            # Indicator: Process accesses Global Atoms AND has Asynchronous Procedure Calls (APCs) queued.
            has_apc = any(t.get('pid') == pid and t.get('has_apc_queued', False) for t in threads)
            if process_info and process_info.get('accesses_global_atoms', False) and has_apc:
                atombombing_count += 1
            if has_apc:
                apc_injection_count += 1

        # --- PART B: Engine 9 Integration (High-Level Alerts) ---
        # "InjectionDetector" (Engine 9) runs before feature extraction and produces high-confidence alerts.
        # We aggregate these alerts here to ensure nothing is missed.
        for alert in injections:
            alert_type = str(alert.get('type', '')).lower()
            
            if 'reflective' in alert_type:
                reflective_dll_count += 1
            elif 'hollowing' in alert_type:
                process_hollowing_count += 1
            elif 'atom' in alert_type:
                atombombing_count += 1
            elif 'apc' in alert_type or 'queueuserapc' in alert_type:
                apc_injection_count += 1
            # Add generic Code Injection count to Reflective for scoring weight
            elif 'code injection' in alert_type:
                reflective_dll_count += 1

        return {
            'reflective_dll_injection_count': self.normalize_count(reflective_dll_count, max_threshold=2),
            'process_hollowing_count': self.normalize_count(process_hollowing_count, max_threshold=2),
            'atombombing_indicator_count': self.normalize_count(atombombing_count, max_threshold=1),
            'apc_injection_indicator_count': self.normalize_count(apc_injection_count, max_threshold=5)
        }
    
    def _extract_pe_injection_indicators(self, memory_regions: List[Dict], total: int) -> Dict[str, float]:
        """
        Extract PE injection pattern indicators.
        Detects full Executables hiding in memory allocations.
        """
        manual_mapped_pe_count = 0
        pe_in_private_memory_count = 0
        
        for region in memory_regions:
            vad_type = region.get('type') or region.get('vad_type') or region.get('Section') or region.get('section') or 'Unknown'
            data = region.get('data', b'') or region.get('bytes', b'')
            protection = self._resolve_protection(region.get('protection') or region.get('Permissions') or region.get('permissions') or 0)
            
            # Logic: If Private memory contains an MZ header, it's suspicious.
            if vad_type == self.VAD_TYPE_PRIVATE:
                if len(data) >= 2 and data[:2] == self.PE_SIGNATURE:
                    pe_in_private_memory_count += 1
                    # If it's also Executable, it's likely a "Manually Mapped" PE (running malware).
                    if self._is_executable(protection):
                        manual_mapped_pe_count += 1
        
        return {
            'manual_mapped_pe_count': self.normalize_count(manual_mapped_pe_count, max_threshold=2),
            'pe_in_private_memory_count': self.normalize_count(pe_in_private_memory_count, max_threshold=3)
        }
    
    def _extract_protection_anomalies(self, memory_regions: List[Dict], total: int, pid_map: Dict[int, str]) -> Dict[str, float]:
        """
        Extract memory protection anomaly features.
        Specifically targets RWX (Read-Write-Execute) permissions.
        """
        rwx_private_region_count = 0
        
        for region in memory_regions:
            # JIT Filter (Browser Safety Check)
            pid = region.get('pid', 0)
            if pid_map.get(pid, '') in self.JIT_APPS: continue

            vad_type = region.get('type') or region.get('vad_type') or region.get('Section') or region.get('section') or 'Unknown'
            protection = self._resolve_protection(region.get('protection') or region.get('Permissions') or region.get('permissions') or 0)
            
            # RWX in private memory is the "Golden Flag" for basic injection/shellcode.
            if vad_type == self.VAD_TYPE_PRIVATE:
                if protection == self.PAGE_EXECUTE_READWRITE:
                    rwx_private_region_count += 1
        
        return {
            'rwx_private_memory_ratio': self.normalize_ratio(rwx_private_region_count, total)
        }
    
    def _resolve_protection(self, protection: Union[int, str]) -> int:
        """Normalize protection flags from ints or strings (PAGE_* / RWX / RX / X)."""
        if isinstance(protection, int):
            return protection
        prot_str = str(protection or '').upper()
        if not prot_str:
            return 0
        if 'EXECUTE_READWRITE' in prot_str or 'RWX' in prot_str:
            return self.PAGE_EXECUTE_READWRITE
        if 'EXECUTE_WRITECOPY' in prot_str or 'WRITECOPY' in prot_str:
            return self.PAGE_EXECUTE_WRITECOPY
        if 'EXECUTE_READ' in prot_str or prot_str == 'RX':
            return self.PAGE_EXECUTE_READ
        if 'EXECUTE' in prot_str or prot_str == 'X' or 'X' in prot_str:
            return self.PAGE_EXECUTE
        return 0

    def _is_executable(self, protection: int) -> bool:
        """Helper to check if any Execute bit is set."""
        execute_flags = (self.PAGE_EXECUTE | self.PAGE_EXECUTE_READ | 
                         self.PAGE_EXECUTE_READWRITE | self.PAGE_EXECUTE_WRITECOPY)
        return (protection & execute_flags) != 0
    
    def _contains_shellcode_pattern(self, data: bytes) -> bool:
        """Scans byte data for known shellcode prologues."""
        for pattern in self.SHELLCODE_PATTERNS:
            if pattern in data: return True
        return False
    
    def _contains_reflective_loader_signature(self, data: bytes) -> bool:
        """Scans byte data for Reflective DLL Loader artifacts."""
        search_area = data[:8192]
        for signature in self.REFLECTIVE_LOADER_SIGNATURES:
            if signature in search_area: return True
        return False
    
    def _get_zero_features(self) -> Dict[str, float]:
        """Return zeroed features to handle empty input gracefully."""
        keys = [
            'private_executable_region_count', 'shellcode_signature_count', 'patched_memory_region_count',
            'reflective_dll_injection_count', 'process_hollowing_count', 'atombombing_indicator_count',
            'apc_injection_indicator_count', 'manual_mapped_pe_count', 'pe_in_private_memory_count',
            'rwx_private_memory_ratio'
        ]
        return {k: 0.0 for k in keys}
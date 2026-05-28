"""
ramdetect/features/handle_features.py
=====================================
Extracts 12 features from handle tables to detect:
- Suspicious file handles
- Registry persistence mechanisms
- Mutex/Event markers (malware identifiers)
- Inter-process handle abuse

Author: RAMDetect Development Team
"""

from typing import Dict, List, Any
import re
from .feature_base import FeatureExtractor # Relative import

class HandleFeatures(FeatureExtractor):
    """
    Extract 12 handle-related features for malware detection.
    """
    
    # Files in these locations are suspicious if locked/open by a process
    SUSPICIOUS_FILE_PATTERNS = [
        r'temp', r'tmp', r'appdata\\local\\temp', r'recycler',
        r'\.exe$', r'\.dll$', r'\.scr$', r'\.bat$', r'\.vbs$',
        r'users\\public', r'programdata', r'startup'
    ]
    
    # Registry Keys used for Persistence (Survive Reboot)
    PERSISTENCE_REGISTRY_KEYS = [
        r'software\\microsoft\\windows\\currentversion\\run',
        r'software\\microsoft\\windows\\currentversion\\runonce',
        r'software\\wow6432node\\microsoft\\windows\\currentversion\\run',
        r'software\\microsoft\\windows\\currentversion\\policies\\explorer\\run',
        r'system\\currentcontrolset\\services',
        r'software\\microsoft\\windows nt\\currentversion\\winlogon',
        r'software\\microsoft\\windows\\currentversion\\explorer\\shell folders',
        r'software\\classes\\exefile\\shell\\open\\command',
        r'software\\microsoft\\office\\.*\\addins'
    ]
    
    # Mutexes (Mutual Exclusion Objects) are often used by malware to ensure 
    # only one instance of itself is running. They often use hardcoded names.
    # Suspicious mutex/event patterns
    SUSPICIOUS_MUTEX_PATTERNS = [
        r'global\\', r'local\\', r'[a-f0-9]{32}', r'[a-f0-9]{40}', 
        r'(mutex|mtx|lock|sync)_[0-9]+', r'bot_', r'rat_', r'trojan_',
        r'\\sessions\\[0-9]+\\'
    ]
    
    # Encrypted file extensions
    ENCRYPTED_EXTENSIONS = [
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.locky', '.cerber', '.zepto', '.odin', '.thor'
    ]
    
    # Named pipe patterns (C2 communication)
    NAMED_PIPE_PATTERNS = [
        r'pipe\\[a-f0-9]{8,}',  # Random hex names
        r'pipe\\(psexec|winexe|meterpreter|cobalt|paexec)',  # Known tools
    ]
    
    def __init__(self, logger=None):
        super().__init__(name="HandleFeatures", logger=logger)
    
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        handles = parsed_data.get('handles', [])
        processes = parsed_data.get('processes', [])
        dlls = parsed_data.get('dlls', [])
        threads = parsed_data.get('threads', [])
        
        if not handles:
            self.logger.warning(f"[{self.name}] No handles found")
            return self._get_zero_features()
        
        # Build lookup maps for cross-table context
        pid_map = {p['pid']: p for p in processes} if processes else {}
        
        # DLL map (PID -> list of DLLs)
        dll_map = {}
        for dll in dlls:
            dll_pid = dll.get('pid', 0)
            if dll_pid not in dll_map:
                dll_map[dll_pid] = []
            dll_map[dll_pid].append(dll)
        
        # Thread map (PID -> list of threads)
        thread_map = {}
        for thread in threads:
            t_pid = thread.get('pid', 0)
            if t_pid not in thread_map:
                thread_map[t_pid] = []
            thread_map[t_pid].append(thread)
        
        total_handles = len(handles)
        
        features = {}
        # Pass context to extraction methods
        features.update(self._extract_file_handle_features(handles, total_handles, pid_map, dll_map, thread_map))
        features.update(self._extract_registry_features(handles, total_handles, pid_map, dll_map))
        features.update(self._extract_sync_object_features(handles, total_handles, pid_map, dll_map))
        features.update(self._extract_interprocess_features(handles, pid_map, thread_map, total_handles))
        
        return features
    
    def _extract_file_handle_features(self, handles: List[Dict], total: int,
                                    pid_map: Dict, dll_map: Dict, 
                                    thread_map: Dict) -> Dict[str, float]:
        """
        Context-aware file handle analysis.
        """
        suspicious_file_count = 0
        temp_folder_file_count = 0
        encrypted_file_count = 0
        executable_file_count = 0
        
        for handle in handles:
            handle_type = str(handle.get('type', '')).lower()
            object_name = str(handle.get('name', '')).lower()
            pid = handle.get('pid', 0)
            
            if handle_type != 'file' or not object_name: 
                continue
            
            # Get process context
            proc = pid_map.get(pid, {})
            proc_name = proc.get('image_name', '').lower()
            proc_path = proc.get('path', '').lower()
            
            # Get DLL context
            proc_dlls = dll_map.get(pid, [])
            has_suspicious_dll = any(dll.get('is_suspicious') for dll in proc_dlls)
            
            # Get Thread context
            proc_threads = thread_map.get(pid, [])
            has_remote_thread = any(t.get('is_remote_thread') for t in proc_threads)
            
            # Security databases (SAM, SECURITY, NTDS.dit)
            if any(db in object_name for db in ['sam', 'security', 'ntds.dit']):
                # [FIX P2-a] The kernel (PID 4 / "System") and lsass always hold
                # SAM/SECURITY hive handles.  Flagging them is a structural FP.
                authorized = pid == 4 or proc_name in ['lsass.exe', 'services.exe', 'smss.exe', 'system']
                
                # Only flag if unauthorized OR has remote thread injection
                if not authorized or has_remote_thread:
                    suspicious_file_count += 1

            # [FIX P2-c] Windows Update servicing writes credential-provider DLLs to
            # WinSxS/InFlight staging directories.  TiWorker always holds handles here
            # during patching — flagging it is always a FP on a patching system.
            elif any(p in object_name for p in ['\\winsxs\\temp\\', '\\winsxs\\inflight\\',
                                                  '\\windows\\servicing\\', 'pendingrenames']):
                UPDATE_STAGING_EXEMPT = {'tiworker.exe', 'trustedinstaller', 'wuauclt.exe',
                                          'svchost.exe', 'system'}
                if proc_name not in UPDATE_STAGING_EXEMPT and pid != 4:
                    suspicious_file_count += 1
            
            # Encrypted files (ransomware indicator)
            if any(ext in object_name for ext in self.ENCRYPTED_EXTENSIONS):
                encrypted_file_count += 1
            
            # Temp folder files
            if 'temp' in object_name or 'tmp' in object_name:
                temp_folder_file_count += 1
                
                # Temp executables (dropper behavior)
                if object_name.endswith(('.exe', '.bat', '.vbs', '.ps1')):
                    # Check parent process
                    parent_suspicious = False
                    if proc.get('ppid', 0) in pid_map:
                        parent = pid_map[proc['ppid']]
                        if parent.get('anomalies'):
                            parent_suspicious = True
                    
                    if parent_suspicious or has_suspicious_dll or has_remote_thread:
                        executable_file_count += 1
            
            # Credential/password files
            # [FIX P2-b] lsass and svchost (CredentialManager) always hold credential
            # store paths open — only flag if accessed by an unexpected process.
            if 'password' in object_name or 'credential' in object_name or '.kdbx' in object_name:
                CRED_EXEMPT = {'lsass.exe', 'svchost.exe', 'system'}
                if proc_name not in CRED_EXEMPT and pid != 4:
                    if 'temp' in proc_path or has_suspicious_dll:
                        suspicious_file_count += 1
        
        return {
            'suspicious_file_handle_count': self.normalize_count(suspicious_file_count, 10),
            'temp_folder_file_count': self.normalize_count(temp_folder_file_count, 5),
            'encrypted_file_handle_count': self.normalize_count(encrypted_file_count, 50),
            'suspicious_executable_handle_count': self.normalize_count(executable_file_count, 3)
        }
    
    def _extract_registry_features(self, handles: List[Dict], total: int, 
                                pid_map: Dict, dll_map: Dict) -> Dict[str, float]:
        """
        Context-aware registry persistence detection.
        Only flags as suspicious if owner process is not legitimate.
        """
        persistence_key_count = 0
        service_key_count = 0
        autostart_location_count = 0
        
        # Legitimate processes allowed to access persistence keys
        # [FIX P2-d] Expanded: ctfmon, OneDrive, edge, vmtoolsd legitimately self-register
        # in Run keys by design — flagging them is always a FP on a clean system.
        legitimate_processes = {
            'services.exe', 'svchost.exe', 'explorer.exe',
            'taskeng.exe', 'taskhost.exe', 'taskhostw.exe',
            'lsass.exe', 'winlogon.exe',
            # Known self-registering processes
            'ctfmon.exe',           # Text Input — always registers itself in Run
            'onedrive.exe',         # OneDrive client
            'onedrive.sync.exe',    # OneDrive sync engine (truncated name)
            'microsoftedgeu.exe',   # MicrosoftEdgeUpdate (truncated)
            'msedge.exe',           # Edge browser
            'chrome.exe',           # Chrome
            'firefox.exe',          # Firefox
            'vmtoolsd.exe',         # VMware Tools
            'securityhealths',      # (truncated) SecurityHealthSystray
            'dropbox.exe',
            'slack.exe', 'teams.exe', 'discord.exe', 'zoom.exe',
            'system',               # PID 4 kernel
        }
        
        for handle in handles:
            if str(handle.get('type', '')).lower() != 'key': 
                continue
                
            object_name = str(handle.get('name', '')).lower()
            pid = handle.get('pid', 0)
            
            # Get process context
            proc = pid_map.get(pid, {})
            proc_name = proc.get('image_name', '').lower()
            proc_path = proc.get('path', '').lower()
            
            # Get DLL context
            proc_dlls = dll_map.get(pid, [])
            has_suspicious_dll = any(dll.get('is_suspicious') for dll in proc_dlls)
            
            # Check against persistence keys
            for pattern in self.PERSISTENCE_REGISTRY_KEYS:
                if re.search(pattern, object_name):
                    # CONTEXT CHECK: Only count if suspicious
                    is_legitimate = proc_name in legitimate_processes
                    is_suspicious_location = 'temp' in proc_path or 'appdata' in proc_path
                    
                    # Flag as suspicious if:
                    # - Non-legitimate process, OR
                    # - Suspicious location, OR
                    # - Has malicious DLLs
                    if not is_legitimate or is_suspicious_location or has_suspicious_dll:
                        persistence_key_count += 1
                        
                        if 'services' in object_name: 
                            service_key_count += 1
                        if any(k in object_name for k in ['\\run', 'runonce', 'winlogon', 'startup']):
                            autostart_location_count += 1
                    break
        
        return {
            'persistence_registry_key_count': self.normalize_count(persistence_key_count, 5),
            'service_registry_key_count': self.normalize_count(service_key_count, 3),
            'autostart_location_count': self.normalize_count(autostart_location_count, 3)
        }
    
    def _extract_sync_object_features(self, handles: List[Dict], total: int, pid_map: Dict = None, dll_map: Dict = None) -> Dict[str, float]:
        suspicious_mutex_count = 0
        named_pipe_count = 0
        mutex_names = []
        
        for handle in handles:
            handle_type = str(handle.get('type', '')).lower()
            object_name = str(handle.get('object_name', '')).lower()
            if not object_name: continue
            
            # Mutexes
            if handle_type == 'mutant':
                mutex_names.append(object_name)
                for pattern in self.SUSPICIOUS_MUTEX_PATTERNS:
                    if re.search(pattern, object_name):
                        suspicious_mutex_count += 1
                        break
            
            # Named pipes - FIXED LOGIC
            # Checks for both standard Kernel format (\Device\NamedPipe\) and user-mode (\pipe\)
            if handle_type == 'file' and ('namedpipe' in object_name or '\\pipe\\' in object_name):
                named_pipe_count += 1
                for pattern in self.NAMED_PIPE_PATTERNS:
                    if re.search(pattern, object_name):
                        # If a known bad pipe name is found, we can count it as suspicious mutex/sync object
                        # or just rely on the high named_pipe_count
                        suspicious_mutex_count += 1
                        break
        
        unique_mutex_ratio = 0.0
        if mutex_names:
            unique_mutex_ratio = 1.0 - (len(set(mutex_names)) / len(mutex_names))
        
        return {
            'suspicious_mutex_count': self.normalize_count(suspicious_mutex_count, 5),
            'named_pipe_handle_count': self.normalize_count(named_pipe_count, 3),
            'low_unique_mutex_ratio': unique_mutex_ratio
        }
    
    def _extract_interprocess_features(self, handles: List[Dict], 
                                    pid_map: Dict[int, Dict],
                                    thread_map: Dict,
                                    total: int) -> Dict[str, float]:
        """
        Context-aware inter-process handle analysis.
        """
        cross_process_handle_count = 0
        process_handle_to_system_count = 0
        system_procs = {'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe'}
        
        for handle in handles:
            if str(handle.get('type', '')).lower() not in ['process', 'thread']: 
                continue
            
            owner_pid = handle.get('pid', 0)
            target_pid = handle.get('target_pid', 0)
            access = handle.get('access_mask', 0)
            
            # Get owner thread context
            owner_threads = thread_map.get(owner_pid, [])
            has_remote_thread = any(t.get('is_remote_thread') for t in owner_threads)
            has_apc_injection = any(t.get('has_apc_queued') for t in owner_threads)
            
            if target_pid != 0 and target_pid != owner_pid:
                cross_process_handle_count += 1
                
                if target_pid in pid_map:
                    target_name = pid_map[target_pid].get('image_name', '').lower()
                    
                    if target_name in system_procs:
                        # Dangerous access (VM_WRITE | VM_OPERATION | CREATE_THREAD)
                        VM_WRITE = 0x0020
                        VM_OPERATION = 0x0008
                        CREATE_THREAD = 0x0002
                        
                        dangerous_access = access & (VM_WRITE | VM_OPERATION | CREATE_THREAD)
                        
                        # Only flag if dangerous access + injection indicators
                        if dangerous_access and (has_remote_thread or has_apc_injection):
                            process_handle_to_system_count += 1
                                
        return {
            'cross_process_handle_count': self.normalize_count(cross_process_handle_count, 10),
            'system_process_handle_count': self.normalize_count(process_handle_to_system_count, 2)
        }

    def _get_zero_features(self) -> Dict[str, float]:
        keys = [
            'suspicious_file_handle_count', 'temp_folder_file_count', 'encrypted_file_handle_count',
            'suspicious_executable_handle_count', 'persistence_registry_key_count', 'service_registry_key_count',
            'autostart_location_count', 'suspicious_mutex_count', 'named_pipe_handle_count',
            'low_unique_mutex_ratio', 'cross_process_handle_count', 'system_process_handle_count'
        ]
        return {k: 0.0 for k in keys}
"""
tests/test_handle_features.py
=============================
Unit Test for Engine 5 (Handle Features).
"""

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.handle_features import HandleFeatures

def test_handle_features():
    extractor = HandleFeatures()
    
    # Mock Process Data (needed for inter-process check)
    processes = [
        {'pid': 400, 'image_name': 'lsass.exe'},
        {'pid': 1000, 'image_name': 'malware.exe'}
    ]
    
    # Mock Handle Data
    handles = [
        # 1. RANSOMWARE: Encrypted file
        {'type': 'File', 'object_name': 'C:\\Users\\Admin\\Documents\\report.doc.locked'},
        
        # 2. PERSISTENCE: Run Key
        {'type': 'Key', 'object_name': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'},
        
        # 3. C2: Named Pipe (PsExec style)
        {'type': 'File', 'object_name': '\\Device\\NamedPipe\\psexec_service'},
        
        # 4. EXECUTABLE IN TEMP
        {'type': 'File', 'object_name': 'C:\\Users\\Admin\\AppData\\Local\\Temp\\dropper.exe'},
        
        # 5. CREDENTIAL THEFT: Handle to LSASS with high access
        {'type': 'Process', 'pid': 1000, 'target_pid': 400, 'access_mask': 0x1FFFFF}, # All Access
        
        # 6. MUTEX MARKER (Globa\...)
        {'type': 'Mutant', 'object_name': '\\BaseNamedObjects\\Global\\X892_Mutex'}
    ]
    
    data = {'handles': handles, 'processes': processes}
    
    print("\n--- Testing Handle Feature Extraction ---")
    feats = extractor.extract_with_error_handling(data)
    
    print(f"Encrypted Files:    {feats['encrypted_file_handle_count']:.2f} (.locked)")
    print(f"Persistence Key:    {feats['persistence_registry_key_count']:.2f}")
    print(f"Named Pipe:         {feats['named_pipe_handle_count']:.2f}")
    print(f"Exec in Temp:       {feats['suspicious_executable_handle_count']:.2f}")
    print(f"System Process Access: {feats['system_process_handle_count']:.2f} (LSASS)")
    print(f"Suspicious Mutex:   {feats['suspicious_mutex_count']:.2f}")

if __name__ == "__main__":
    test_handle_features()
"""
tests/test_dll_features.py
==========================
Unit Test for Engine 3 (DLL Features).
Verifies Signature, Path, Load Order, and Export/Import anomalies.
"""

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.dll_features import DLLFeatures

def test_dll_features():
    extractor = DLLFeatures()
    
    # Mock Data
    mock_data = {
        'dlls': [
            # 1. Normal System DLL
            {'pid': 100, 'name': 'kernel32.dll', 'path': 'c:\\windows\\system32\\kernel32.dll', 
             'signed': True, 'load_order': 1},
            
            # 2. UNSIGNED SYSTEM DLL (Critical Alert)
            {'pid': 100, 'name': 'ntdll.dll', 'path': 'c:\\windows\\system32\\ntdll.dll', 
             'signed': False, 'load_order': 2},
             
            # 3. SUSPICIOUS PATH (Temp)
            {'pid': 100, 'name': 'malware.dll', 'path': 'c:\\users\\admin\\appdata\\local\\temp\\malware.dll',
             'signed': False, 'load_order': 50},
             
            # 4. LOAD ORDER ANOMALY (System DLL loaded very late)
            {'pid': 100, 'name': 'ws2_32.dll', 'path': 'c:\\windows\\system32\\ws2_32.dll',
             'signed': True, 'load_order': 99},
             
            # 5. SUSPICIOUS EXPORT ('ReflectiveLoader')
            {'pid': 100, 'name': 'inject.dll', 'path': 'c:\\windows\\temp\\inject.dll',
             'exports': ['ReflectiveLoader', 'Start'], 'load_order': 51},
             
            # 6. HIGH ENTROPY (Packed)
            {'pid': 100, 'name': 'packed.dll', 'path': 'c:\\program files\\app\\packed.dll',
             'entropy': 7.8, 'signed': True}
        ]
    }
    
    print("\n--- Testing DLL Feature Extraction ---")
    feats = extractor.extract_with_error_handling(mock_data)
    
    # Validation
    
    # Signature
    print(f"Unsigned System DLL:  {feats['unsigned_system_dll_count']:.2f} (ntdll.dll)")
    
    # Path
    print(f"Suspicious Path:      {feats['suspicious_path_dll_count']:.2f} (Temp folder)")
    
    # Load Order
    print(f"Late Loaded System:   {feats['late_loaded_system_dll_count']:.2f} (ws2_32.dll)")
    
    # Exports
    print(f"Suspicious Export:    {feats['suspicious_export_count']:.2f} (ReflectiveLoader)")
    
    # Entropy
    print(f"High Entropy Count:   {feats['high_entropy_dll_count']:.2f} (Packed.dll)")

if __name__ == "__main__":
    test_dll_features()
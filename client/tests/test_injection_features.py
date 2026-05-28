"""
tests/test_injection_features.py
================================
Unit Test for Engine 6/7 (Injection Features).
Verifies byte-level scanning for Shellcode and Reflective Loaders.
"""

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.injection_features import InjectionFeatures

def test_injection_features():
    extractor = InjectionFeatures()
    
    # Mock Data
    mock_data = {
        'processes': [{'pid': 100, 'image_base': 0x400000}],
        'threads': [{'pid': 100, 'has_apc_queued': True}],
        'memory_regions': [
            # 1. SHELLCODE: Private RWX with "JMP $" (Infinite Loop)
            {
                'pid': 100,
                'vad_type': 1, # Private
                'protection': 'PAGE_EXECUTE_READWRITE', # RWX string
                'data': b'\x90\x90\xEB\xFE\x90\x90' # NOPs + JMP $
            },
            
            # 2. REFLECTIVE DLL: Private Executable with "ReflectiveLoader" string
            {
                'pid': 100,
                'vad_type': 1, # Private
                'protection': 0x20, # PAGE_EXECUTE_READ (int)
                'data': b'MZ\x90\x00ReflectiveLoader\x00\x00' # MZ header + Signature
            },
            
            # 3. Normal Data
            {
                'pid': 100,
                'vad_type': 1,
                'protection': 0x04, # READWRITE
                'data': b'\x00\x00\x00\x00'
            }
        ]
    }
    
    print("\n--- Testing Injection Feature Extraction ---")
    feats = extractor.extract_with_error_handling(mock_data)
    
    # 1. Shellcode Signature
    print(f"Shellcode Found:      {feats['shellcode_signature_count']:.2f} (JMP $)")
    
    # 2. Reflective DLL
    print(f"Reflective DLL Count: {feats['reflective_dll_injection_count']:.2f} (ReflectiveLoader)")
    
    # 3. Private RWX
    print(f"RWX Private Ratio:    {feats['rwx_private_memory_ratio']:.2f} (1/3 regions)")
    
    # 4. APC Injection (from Thread)
    print(f"APC Injection:        {feats['apc_injection_indicator_count']:.2f} (Queued APC)")
    
    # 5. PE in Private Memory
    print(f"Manual Mapped PE:     {feats['manual_mapped_pe_count']:.2f} (MZ Header)")

if __name__ == "__main__":
    test_injection_features()
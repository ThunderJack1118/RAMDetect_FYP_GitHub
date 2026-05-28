"""
tests/test_pe_features.py
=========================
Unit Test for Engine 4 (PE Features).
Verifies Packing, TLS Callbacks, and RWX Section detection.
"""

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.pe_features import PEFeatures

def test_pe_features():
    extractor = PEFeatures()
    
    # Mock Data
    mock_data = {
        'pe_files': [
            # 1. UPX PACKED BINARY
            {
                'sections': [
                    {'name': 'UPX0', 'characteristics': 0xE0000000, 'entropy': 0.0, 'virtual_size': 0x10000, 'raw_size': 0}, # RWX, Empty Raw
                    {'name': 'UPX1', 'characteristics': 0xE0000000, 'entropy': 7.9, 'virtual_size': 0x5000, 'raw_size': 0x5000} # RWX, High Entropy
                ],
                'packer_detected': 'UPX',
                'imports': {'kernel32.dll': ['LoadLibraryA', 'GetProcAddress']}, # Few Imports
                'tls_callbacks': [0x12345678] # Anti-debug trick
            },
            
            # 2. MALICIOUS DOWNLOADER
            {
                'sections': [
                    {'name': '.text', 'characteristics': 0x60000000, 'entropy': 6.0} # RX
                ],
                'imports': {
                    'urlmon.dll': ['URLDownloadToFile'],
                    'shell32.dll': ['ShellExecute']
                }
            }
        ]
    }
    
    print("\n--- Testing PE Feature Extraction ---")
    feats = extractor.extract_with_error_handling(mock_data)
    
    # 1. RWX (Both UPX sections are RWX 0xE0000000)
    print(f"RWX Sections:        {feats['rwx_section_count']:.2f} (UPX0 & UPX1)")
    
    # 2. Packer Section (UPX0/UPX1)
    print(f"Packer Sections:     {feats['packer_section_count']:.2f} (Expected 0.33)")
    
    # 3. High Entropy
    print(f"High Entropy Count:  {feats['high_entropy_section_count']:.2f} (UPX1 is 7.9)")
    
    # 4. TLS Callbacks
    print(f"TLS Callback Count:  {feats['tls_callback_count']:.2f} (Expected 0.50)")
    
    # 5. Suspicious Imports (URLDownloadToFile, ShellExecute)
    print(f"Suspicious Imports:  {feats['suspicious_import_count']:.2f} (Expected > 0)")
    
    # 6. Zero Raw Size (UPX0 has raw_size=0)
    print(f"Zero Raw Size Count: {feats['zero_raw_size_section_count']:.2f} (UPX0)")

if __name__ == "__main__":
    test_pe_features()
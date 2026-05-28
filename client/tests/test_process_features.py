"""
examples/test_process_features.py
=================================
Unit Test for Engine 1 (Process Features).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.process_features import ProcessFeatures

def test_process_features():
    extractor = ProcessFeatures()
    
    # 1. Benign Data
    benign_data = {
        'processes': [
            {'pid': 4, 'ppid': 0, 'image_name': 'System'},
            {'pid': 400, 'ppid': 4, 'image_name': 'smss.exe'},
            {'pid': 600, 'ppid': 400, 'image_name': 'winlogon.exe'},
            {'pid': 1000, 'ppid': 600, 'image_name': 'explorer.exe'}
        ]
    }
    
    # 2. Malicious Data (Triggers your features)
    malicious_data = {
        'processes': [
            {'pid': 4, 'ppid': 0, 'image_name': 'System'},
            
            # ORPHAN: Parent 9999 missing
            {'pid': 2000, 'ppid': 9999, 'image_name': 'malware.exe'}, 
            
            # TYPOSQUAT: scvhost.exe
            {'pid': 2001, 'ppid': 4, 'image_name': 'scvhost.exe'}, 
            
            # PARENT ANOMALY: Explorer spawning PowerShell
            {'pid': 1000, 'ppid': 4, 'image_name': 'explorer.exe'},
            {'pid': 2002, 'ppid': 1000, 'image_name': 'powershell.exe'},

            # PATH ANOMALY: Running from Temp
            {'pid': 2003, 'ppid': 1000, 'image_name': 'dropper.exe', 'path': 'c:\\users\\admin\\appdata\\local\\temp\\dropper.exe'},
        ]
    }

    print("\n--- Testing Malicious Data ---")
    feats = extractor.extract_with_error_handling(malicious_data)
    
    print(f"Orphan Count:      {feats['orphan_process_count']:.2f}")
    print(f"Typosquat Count:   {feats['typosquat_count']:.2f} (Expected > 0)")
    print(f"Parent Anomaly:    {feats['suspicious_parent_child_count']:.2f} (Explorer->PowerShell)")
    print(f"Suspicious Path:   {feats['suspicious_path_count']:.2f} (Temp folder)")

if __name__ == "__main__":
    test_process_features()
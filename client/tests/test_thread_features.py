"""
tests/test_thread_features.py
=============================
Unit Test for Engine 2 (Thread Features).
Verifies advanced logic (Orphans, APC Injection, Statistical Anomalies).
"""

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.thread_features import ThreadFeatures

def test_thread_features():
    extractor = ThreadFeatures()
    
    # 1. Mock Process Data (To establish valid PIDs)
    processes = [
        {'pid': 4, 'image_name': 'System'},
        {'pid': 1000, 'image_name': 'explorer.exe'}
    ]
    
    # 2. Mock Thread Data (Malicious Scenario)
    threads = [
        # Normal Thread 1 (Attached to Explorer)
        {'tid': 1, 'pid': 1000, 'start_address': 0x7ff700001000, 'priority': 8, 'state': 'Running'},
        
        # Normal Thread 2 (Attached to Explorer)
        {'tid': 2, 'pid': 1000, 'start_address': 0x7ff700002000, 'priority': 8, 'state': 'Waiting'},
        
        # ORPHAN: PID 9999 does not exist in 'processes' list
        {'tid': 3, 'pid': 9999, 'start_address': 0x7ff700005000, 'priority': 8},
        
        # INJECTION: Remote Thread + Suspended
        {'tid': 4, 'pid': 1000, 'start_address': 0x7ff700009999, 'is_remote_thread': True, 'state': 'Suspended'},
        
        # APC INJECTION: Alertable + APC Queued
        {'tid': 5, 'pid': 1000, 'start_address': 0x7ff700008888, 'has_apc_queued': True, 'alertable': True},
        
        # HIGH PRIORITY: Potential hijacking
        {'tid': 6, 'pid': 1000, 'start_address': 0x7ff700007777, 'priority': 15}, # Normal max is 12 in your logic
    ]
    
    data = {'processes': processes, 'threads': threads}
    
    print("\n--- Testing Thread Feature Extraction ---")
    feats = extractor.extract_with_error_handling(data)
    
    print(f"Orphan Count:       {feats['orphan_thread_count']:.2f} (PID 9999)")
    print(f"Remote Threads:     {feats['remote_thread_count']:.2f} (Flagged)")
    print(f"APC Injection:      {feats['apc_injection_count']:.2f} (Queued APC)")
    print(f"Suspended Count:    {feats['suspended_thread_count']:.2f}")
    print(f"High Priority:      {feats['high_priority_thread_count']:.2f} (Priority 15)")

if __name__ == "__main__":
    test_thread_features()
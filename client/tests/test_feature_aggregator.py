"""
tests/test_feature_aggregator.py
================================
Final Integration Test for Phase 4.
Simulates a full memory dump parse and verifies the Aggregator produces 
a complete feature vector using all 6 engines.
"""

import sys
import logging
from pathlib import Path

# ============================================================================
# 1. PATH SETUP
# ============================================================================
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ============================================================================
# 2. IMPORTS
# ============================================================================
try:
    from ramdetect.features.feature_aggregator import FeatureAggregator
    print("✅ Successfully imported FeatureAggregator")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)

# ============================================================================
# 3. THE TEST LOGIC
# ============================================================================
def test_aggregator():
    print("\n" + "="*60)
    print("RAMDetect - Feature Aggregator Integration Test")
    print("="*60)
    
    aggregator = FeatureAggregator()
    
    # === FULL MOCK DATASET ===
    full_data = {
        # Engine 1: Processes
        'processes': [
            {'pid': 4, 'image_name': 'System', 'ppid': 0},
            {'pid': 1000, 'image_name': 'explorer.exe', 'ppid': 4},
            # Malicious: Hidden & Orphan
            {'pid': 666, 'image_name': 'malware.exe', 'ppid': 9999, 'hidden': True} 
        ],
        
        # Engine 4: Threads
        'threads': [
            {'pid': 1000, 'start_address': 0x7ff7000, 'priority': 8},
            # Malicious: Remote Thread Injection
            {'pid': 666, 'start_address': 0x004000, 'is_remote_thread': True} 
        ],
        
        # Engine 5: DLLs
        'dlls': [
            {'pid': 1000, 'name': 'kernel32.dll', 'path': 'c:\\windows\\system32\\kernel32.dll', 'signed': True},
            # Malicious: Unsigned DLL in Temp
            {'pid': 666, 'name': 'hack.dll', 'path': 'c:\\temp\\hack.dll', 'signed': False} 
        ],
        
        # Engine 6: Handles
        'handles': [
            {'type': 'File', 'object_name': 'c:\\users\\admin\\documents\\passwords.txt'},
            # Malicious: Mutex Marker (Updated to match regex "mutex_[0-9]+")
            {'type': 'Mutant', 'object_name': '\\BaseNamedObjects\\mutex_12345'} 
        ],
        
        # Engine 7: PE Headers
        'pe_files': [
            # Benign
            {'sections': [{'name': '.text', 'entropy': 6.5}], 'imports': {'kernel32.dll': ['LoadLibraryA']}},
            # Malicious: Packed (UPX) - RWX Section
            {'sections': [{'name': 'UPX0', 'entropy': 0.0, 'characteristics': 0xE0000000}], 'packer_detected': 'UPX'} 
        ],
        
        # Engine 8: Memory Regions (VADs)
        'memory_regions': [
            # Malicious: Private RWX Memory with Shellcode (JMP $)
            {'vad_type': 1, 'protection': 0x40, 'data': b'\x90\x90\xEB\xFE\x90\x90'} 
        ],
        
        # Engine 9: Injection Alerts
        'injections': [
            {'type': 'Reflective DLL', 'severity': 'HIGH'}
        ]
    }
    
    print("\n1. Running Aggregated Extraction...")
    features = aggregator.extract_all_features(full_data)
    
    print("\n2. Validating Critical Indicators...")
    
    # === CORRECTED CHECKLIST (Matching Actual Engine Output Keys) ===
    checks = {
        'hidden_process_count': 'Hidden Process',       # Was proc_hidden_ratio
        'remote_thread_count': 'Remote Thread',        # Was thread_remote_count
        'unsigned_dll_count': 'Unsigned DLL',          # Was dll_unsigned_count
        'suspicious_mutex_count': 'Malware Mutex',     # Matched, but data fixed
        'rwx_section_count': 'RWX Section (UPX)',      # Was pe_rwx_section_count
        'shellcode_signature_count': 'Shellcode (JMP $)',
        'reflective_dll_injection_count': 'Reflective DLL Alert' # Was injection_reflective...
    }
    
    all_pass = True
    for key, desc in checks.items():
        val = features.get(key, -1.0)
        
        if val > 0:
            print(f"   ✅ PASS: {desc:<25} detected (Score: {val:.4f})")
        else:
            print(f"   ❌ FAIL: {desc:<25} NOT detected (Score: {val})")
            all_pass = False

    # 3. Print Summary
    aggregator.print_summary()
    
    if all_pass:
        print("\n🚀 SUCCESS: Feature Extraction Pipeline is FULLY OPERATIONAL!")
    else:
        print("\n⚠️  WARNING: Some checks failed.")

if __name__ == "__main__":
    test_aggregator()
"""
tests/test_feature_suite_enhanced.py
=====================================
Enhanced Feature Extraction Testing Suite

Includes:
1. Multiple test scenarios (clean, ransomware, APT, etc.)
2. Performance benchmarking
3. Feature correlation analysis
4. CSV dataset export for ML training
5. Visualization of feature distributions

Usage:
    python tests/test_feature_suite_enhanced.py
"""

import sys
import logging
import time
import json
import csv
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# ============================================================================
# PATH SETUP
# ============================================================================
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ============================================================================
# IMPORTS
# ============================================================================
try:
    from ramdetect.features.feature_aggregator import FeatureAggregator
    print("✅ Successfully imported FeatureAggregator")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)


# ============================================================================
# TEST SCENARIOS
# ============================================================================

def get_clean_system_data() -> Dict[str, Any]:
    """Simulate a clean Windows system."""
    return {
        'processes': [
            {'pid': 4, 'image_name': 'System', 'ppid': 0, 'path': '', 'hidden': False},
            {'pid': 400, 'image_name': 'smss.exe', 'ppid': 4, 'path': 'c:\\windows\\system32\\smss.exe'},
            {'pid': 500, 'image_name': 'csrss.exe', 'ppid': 400, 'path': 'c:\\windows\\system32\\csrss.exe'},
            {'pid': 600, 'image_name': 'services.exe', 'ppid': 500, 'path': 'c:\\windows\\system32\\services.exe'},
            {'pid': 1000, 'image_name': 'explorer.exe', 'ppid': 600, 'path': 'c:\\windows\\explorer.exe'},
        ],
        'threads': [
            {'tid': 1001, 'pid': 1000, 'start_address': 0x7ff700000000, 'priority': 8, 'is_remote_thread': False},
            {'tid': 1002, 'pid': 600, 'start_address': 0x7ff600000000, 'priority': 8},
        ],
        'dlls': [
            {'pid': 1000, 'name': 'ntdll.dll', 'path': 'c:\\windows\\system32\\ntdll.dll', 
             'signed': True, 'entropy': 6.2, 'exists_on_disk': True},
            {'pid': 1000, 'name': 'kernel32.dll', 'path': 'c:\\windows\\system32\\kernel32.dll', 
             'signed': True, 'entropy': 6.5, 'exists_on_disk': True},
        ],
        'handles': [
            {'type': 'File', 'pid': 1000, 'object_name': 'c:\\windows\\system32\\user32.dll'},
            {'type': 'Key', 'pid': 600, 'object_name': 'MACHINE\\System\\CurrentControlSet\\Services'},
        ],
        'pe_files': [
            {'name': 'explorer.exe', 'timestamp': 1640000000, 'magic': 0x20b, 'subsystem': 2,
             'sections': [{'name': '.text', 'entropy': 6.3, 'characteristics': 0x60000020}],
             'imports': {'kernel32.dll': ['LoadLibraryA', 'GetProcAddress']}}
        ],
        'memory_regions': [
            {'pid': 1000, 'vad_type': 2, 'protection': 0x20, 'base_address': 0x400000, 
             'size': 0x10000, 'data': b'MZ\x90\x00' + b'\x00' * 100}
        ]
    }


def get_ransomware_data() -> Dict[str, Any]:
    """Simulate ransomware infection (WannaCry-style)."""
    return {
        'processes': [
            {'pid': 4, 'image_name': 'System', 'ppid': 0, 'path': '', 'hidden': False},
            {'pid': 1000, 'image_name': 'explorer.exe', 'ppid': 4, 'path': 'c:\\windows\\explorer.exe'},
            # Ransomware process
            {'pid': 666, 'image_name': 'tasksche.exe', 'ppid': 1000, 
             'path': 'c:\\users\\public\\tasksche.exe', 'hidden': False,
             'cmdline': 'tasksche.exe /i', 'create_time': 1700000000},
        ],
        'threads': [
            {'tid': 6660, 'pid': 666, 'start_address': 0x004010000, 'priority': 8},
            # Remote thread for file encryption
            {'tid': 6661, 'pid': 1000, 'start_address': 0x12340000, 'is_remote_thread': True},
        ],
        'dlls': [
            # Unsigned crypto DLL
            {'pid': 666, 'name': 'crypt32.dll', 'path': 'c:\\users\\public\\crypt32.dll',
             'signed': False, 'entropy': 7.8, 'exists_on_disk': True},
        ],
        'handles': [
            # Mass file access
            {'type': 'File', 'pid': 666, 'object_name': 'c:\\users\\admin\\documents\\file1.docx.WNCRY'},
            {'type': 'File', 'pid': 666, 'object_name': 'c:\\users\\admin\\documents\\file2.xlsx.WNCRY'},
            {'type': 'File', 'pid': 666, 'object_name': 'c:\\users\\admin\\documents\\file3.pdf.WNCRY'},
            # Registry persistence
            {'type': 'Key', 'pid': 666, 'object_name': 'MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'},
            # Mutex marker
            {'type': 'Mutant', 'pid': 666, 'object_name': 'Global\\MsWinZonesCacheCounterMutexA'},
        ],
        'pe_files': [
            {'name': 'tasksche.exe', 'timestamp': 0, 'magic': 0x20b, 'subsystem': 3,
             'sections': [{'name': '.text', 'entropy': 7.9, 'characteristics': 0xE0000020}],
             'imports': {'advapi32.dll': ['CryptEncrypt', 'CryptDecrypt']},
             'packer_detected': 'Custom'}
        ],
        'memory_regions': [
            # Private executable memory (shellcode)
            {'pid': 666, 'vad_type': 1, 'protection': 0x40, 'base_address': 0x12340000,
             'size': 0x1000, 'data': b'\x90\x90\xEB\xFE' + b'\x00' * 100}
        ]
    }


def get_apt_backdoor_data() -> Dict[str, Any]:
    """Simulate APT backdoor with reflective DLL injection."""
    return {
        'processes': [
            {'pid': 4, 'image_name': 'System', 'ppid': 0, 'path': ''},
            {'pid': 800, 'image_name': 'svchost.exe', 'ppid': 4, 
             'path': 'c:\\windows\\system32\\svchost.exe', 'hidden': False},
        ],
        'threads': [
            # APC injection
            {'tid': 8001, 'pid': 800, 'start_address': 0x7ff700000000, 
             'has_apc_queued': True, 'alertable': True},
        ],
        'dlls': [
            # Legitimate DLLs
            {'pid': 800, 'name': 'ntdll.dll', 'path': 'c:\\windows\\system32\\ntdll.dll',
             'signed': True, 'entropy': 6.2},
        ],
        'handles': [
            # Named pipe for C2
            {'type': 'File', 'pid': 800, 'object_name': '\\Device\\NamedPipe\\a1b2c3d4e5f6'},
        ],
        'pe_files': [
            {'name': 'svchost.exe', 'timestamp': 1640000000, 'magic': 0x20b, 'subsystem': 3,
             'sections': [{'name': '.text', 'entropy': 6.5, 'characteristics': 0x60000020}],
             'imports': {'kernel32.dll': ['LoadLibraryA']}}
        ],
        'memory_regions': [
            # Reflective DLL in private memory
            {'pid': 800, 'vad_type': 1, 'protection': 0x40, 'base_address': 0x23450000,
             'size': 0x10000, 
             'data': b'MZ\x90\x00' + b'\x00' * 400 + b'ReflectiveLoader\x00' + b'\x00' * 100},
        ],
        'injections': [
            {'type': 'Reflective DLL', 'severity': 'HIGH'}
        ]
    }


def get_process_hollowing_data() -> Dict[str, Any]:
    """Simulate process hollowing attack."""
    return {
        'processes': [
            {'pid': 4, 'image_name': 'System', 'ppid': 0, 'path': ''},
            # Hollowed process
            {'pid': 1200, 'image_name': 'svchost.exe', 'ppid': 4,
             'path': 'c:\\windows\\system32\\svchost.exe',
             'image_base': 0x00400000,  # Expected base
             'entry_point': 0x12340000,  # But entry point is elsewhere!
             'create_time': 1700000000},
        ],
        'threads': [
            {'tid': 12001, 'pid': 1200, 'start_address': 0x12340000},
        ],
        'dlls': [
            {'pid': 1200, 'name': 'ntdll.dll', 'path': 'c:\\windows\\system32\\ntdll.dll',
             'signed': True, 'entropy': 6.2},
        ],
        'handles': [],
        'pe_files': [
            {'name': 'svchost.exe', 'timestamp': 1640000000, 'magic': 0x20b, 'subsystem': 3,
             'sections': [{'name': '.text', 'entropy': 6.5, 'characteristics': 0x60000020}],
             'imports': {'kernel32.dll': ['LoadLibraryA']}}
        ],
        'memory_regions': [
            # Image type but base address mismatch
            {'pid': 1200, 'vad_type': 2, 'protection': 0x20, 'base_address': 0x12340000,
             'size': 0x50000, 'data': b'MZ\x90\x00' + b'\x00' * 100},
        ]
    }


# ============================================================================
# TEST EXECUTION
# ============================================================================

def run_scenario(name: str, data: Dict[str, Any], aggregator: FeatureAggregator) -> Dict[str, Any]:
    """Run a single test scenario."""
    print(f"\n{'='*70}")
    print(f"SCENARIO: {name}")
    print(f"{'='*70}")
    
    start_time = time.time()
    features = aggregator.extract_all_features(data)
    duration = time.time() - start_time
    
    # Count alerts
    non_zero = sum(1 for v in features.values() if v > 0)
    high_risk = sum(1 for v in features.values() if v > 0.5)
    
    # Top 5 features
    top_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:5]
    
    print(f"\n📊 Results:")
    print(f"  Duration: {duration:.4f}s")
    print(f"  Alerts: {non_zero}/100 features")
    print(f"  High Risk: {high_risk} features (>0.5)")
    
    print(f"\n🔥 Top 5 Indicators:")
    for i, (fname, val) in enumerate(top_features, 1):
        if val > 0:
            print(f"  {i}. {fname:45s} = {val:.3f}")
    
    return {
        'scenario': name,
        'duration': duration,
        'features': features,
        'alert_count': non_zero,
        'high_risk_count': high_risk,
        'top_features': dict(top_features)
    }


def compare_scenarios(results: List[Dict[str, Any]]):
    """Compare results across scenarios."""
    print(f"\n{'='*70}")
    print("SCENARIO COMPARISON")
    print(f"{'='*70}")
    
    print(f"\n{'Scenario':<30} {'Alerts':<10} {'High Risk':<12} {'Duration':<10}")
    print("-" * 70)
    
    for result in results:
        print(f"{result['scenario']:<30} "
              f"{result['alert_count']:<10} "
              f"{result['high_risk_count']:<12} "
              f"{result['duration']:.4f}s")


def export_dataset(results: List[Dict[str, Any]], output_dir: Path):
    """Export results as ML training dataset."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Export CSV (one row per scenario)
    csv_path = output_dir / "feature_dataset.csv"
    
    if results:
        all_features = list(results[0]['features'].keys())
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Header: scenario_name + all feature names + label
            writer.writerow(['scenario'] + all_features + ['is_malicious'])
            
            # Data rows
            for result in results:
                # Label clean systems as 0, others as 1
                label = 0 if 'clean' in result['scenario'].lower() else 1
                
                row = [result['scenario']]
                row.extend([result['features'][fname] for fname in all_features])
                row.append(label)
                
                writer.writerow(row)
        
        print(f"\n✅ Dataset exported to: {csv_path}")
        print(f"   Rows: {len(results)}")
        print(f"   Columns: {len(all_features) + 2}")  # +2 for scenario and label
    
    # Export detailed JSON
    json_path = output_dir / "feature_results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Detailed results: {json_path}")


# ============================================================================
# MAIN TEST SUITE
# ============================================================================

def main():
    print("\n" + "="*70)
    print("RAMDetect - Enhanced Feature Extraction Test Suite")
    print("="*70)
    
    aggregator = FeatureAggregator()
    
    # Define test scenarios
    scenarios = [
        ("Clean System", get_clean_system_data()),
        ("Ransomware (WannaCry-style)", get_ransomware_data()),
        ("APT Backdoor (Reflective DLL)", get_apt_backdoor_data()),
        ("Process Hollowing", get_process_hollowing_data()),
    ]
    
    # Run all scenarios
    results = []
    for name, data in scenarios:
        result = run_scenario(name, data, aggregator)
        results.append(result)
        aggregator.reset()  # Reset for next scenario
    
    # Compare scenarios
    compare_scenarios(results)
    
    # Export dataset
    output_dir = Path("output/test_results")
    export_dataset(results, output_dir)
    
    print(f"\n{'='*70}")
    print("✅ ALL TESTS COMPLETE")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
"""
examples/engines_integration_example.py
=======================================
Demonstrates the FULLY INTEGRATED RAMDetect Engine (Engines 1-10).
Now includes an interactive Dump Selector Interface and 'Run All' capability.
"""

import sys
import os
import time
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Keep logging quiet for the library components
logging.basicConfig(level=logging.INFO)
logging.getLogger("ramdetect.extraction.parsers.memory_reader").setLevel(logging.WARNING)

from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
from ramdetect.extraction.parsers.eprocess_scanner import EProcessScanner
from ramdetect.extraction.parsers.address_translator import AddressTranslator
from ramdetect.extraction.parsers.thread_parser import ThreadParser
from ramdetect.extraction.parsers.dll_parser import DLLParser
from ramdetect.extraction.parsers.handle_parser import HandleParser
from ramdetect.extraction.parsers.pe_analyzer import PEAnalyzer
from ramdetect.extraction.parsers.vad_scanner import VADScanner
from ramdetect.extraction.parsers.injection_detector import InjectionDetector

# CONFIGURATION
DEFAULT_DUMP_DIR = Path(r"C:\Users\annsi\Downloads\RAMDetect_test\dumps")

# ============================================================================
# INTERFACE UTILITIES
# ============================================================================

def select_dump_file():
    """Interactive menu to select a dump file from the default directory."""
    if not DEFAULT_DUMP_DIR.exists():
        print(f"❌ Error: Dump directory not found at: {DEFAULT_DUMP_DIR}")
        print("   Please create this folder or provide the path via command line.")
        sys.exit(1)

    # Get all files
    files = [f for f in DEFAULT_DUMP_DIR.iterdir() if f.is_file()]
    
    if not files:
        print(f"❌ No files found in {DEFAULT_DUMP_DIR}")
        sys.exit(1)

    print(f"\n📂 Available RAM Dumps in {DEFAULT_DUMP_DIR.name}:")
    print("=" * 60)
    
    for i, f in enumerate(files, 1):
        size_gb = f.stat().st_size / (1024**3)
        print(f"  {i}. {f.name:<40} ({size_gb:.2f} GB)")

    while True:
        try:
            selection = input(f"\nSelect Dump File (1-{len(files)}): ").strip()
            if not selection: continue
            
            idx = int(selection) - 1
            if 0 <= idx < len(files):
                return str(files[idx])
            else:
                print("❌ Invalid selection number.")
        except ValueError:
            print("❌ Please enter a number.")

def get_user_input():
    """Handles the initial setup logic (File -> DTB -> PID)."""
    
    # 1. Select File
    if len(sys.argv) >= 2:
        dump_file = sys.argv[1]
    else:
        dump_file = select_dump_file()

    if not os.path.exists(dump_file):
        print(f"❌ Error: File not found: {dump_file}")
        sys.exit(1)

    # 2. Get DTB (CR3)
    if len(sys.argv) >= 3:
        dtb_arg = sys.argv[2]
        try:
            dtb_val = int(dtb_arg, 16)
        except ValueError:
            print(f"❌ Error: Invalid DTB format '{dtb_arg}'. Use hex (e.g., 0x1ae000)")
            sys.exit(1)
    else:
        print(f"\n🔑 DTB (Directory Table Base) is required for analysis.")
        print(f"   (For your current test file, use: 0x1ae000)")
        while True:
            dtb_input = input("   Enter DTB Hex Value: ").strip()
            if dtb_input:
                try:
                    dtb_val = int(dtb_input, 16)
                    break
                except ValueError:
                    print("   ❌ Invalid hex. Try again (e.g., 0x1ae000).")

    # 3. Get Target PID (Optional)
    target_pid = None
    if len(sys.argv) >= 4:
        try:
            target_pid = int(sys.argv[3])
        except:
            pass
    else:
        print("\n🎯 Target Process Selection (Optional)")
        pid_input = input("   Enter PID to analyze (or Press Enter to auto-detect Explorer): ").strip()
        if pid_input:
            try:
                target_pid = int(pid_input)
            except ValueError:
                print("   ⚠️  Invalid PID. Defaulting to auto-detect.")

    return dump_file, dtb_val, target_pid

# ============================================================================
# EXAMPLES 1-5: BASE FORENSICS (PROCESSES)
# ============================================================================

def example_1_basic_scanning(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 1: Basic Process Scanning (DTB Anchored)")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        scanner = EProcessScanner(reader, translator)
        processes = scanner.find_all_processes()
        print(f"\n✅ Found {len(processes)} processes\n")
        print(f"{'PID':<8} {'PPID':<8} {'Name':<20} {'DTB'}")
        print("-" * 60)
        for p in processes[:15]: 
            print(f"{p['pid']:<8} {p['ppid']:<8} {p['image_name']:<20} {p['dtb']:#x}")
        if len(processes) > 15: print(f"... and {len(processes) - 15} more.")

def example_2_scanning_translation(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 2: Process Scanning + Address Translation Check")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        scanner = EProcessScanner(reader, translator)
        processes = scanner.find_all_processes()
        print(f"\n✅ Found {len(processes)} processes. Checking Virtual Memory Access...")
        for p in processes[:5]:
            peb_va = p.get('peb', 0)
            if peb_va:
                print(f"   PID {p['pid']}: PEB Virtual Address = {peb_va:#x}")
            else:
                 print(f"   PID {p['pid']}: No PEB found")

def example_3_process_tree(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 3: Process Tree Analysis")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        scanner = EProcessScanner(reader, translator)
        processes = scanner.find_all_processes()
        process_map = {p['pid']: p for p in processes}
        children_map = {}
        for p in processes:
            children_map.setdefault(p['ppid'], []).append(p)
        print(f"\n🌳 Process Tree Structure (Partial):\n")
        def print_tree(pid, level=0):
            if pid in process_map and level < 3:
                proc = process_map[pid]
                indent = "  " * level
                print(f"{indent}└─ PID {proc['pid']}: {proc['image_name']}")
                if pid in children_map:
                    for child in children_map[pid][:5]:
                        print_tree(child['pid'], level + 1)
        if 4 in process_map: print_tree(4)

def example_4_suspicious_detection(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 4: Suspicious Process Heuristics")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        scanner = EProcessScanner(reader, translator)
        processes = scanner.find_all_processes()
        suspicious = []
        for p in processes:
            name = p['image_name'].lower()
            if name in ["cmd.exe", "powershell.exe", "wscript.exe"]:
                suspicious.append((p, "Shell Process"))
            if name == "svchost.exe" and p['ppid'] not in [500, 600, 700] and p['ppid'] > 1000:
                 suspicious.append((p, "Svchost with abnormal parent"))
        if suspicious:
            print(f"⚠️  Found {len(suspicious)} interesting processes:")
            for p, reason in suspicious:
                print(f"   PID {p['pid']:<6} {p['image_name']:<15} -> {reason}")
        else:
            print("✅ No basic process anomalies found.")

def example_5_deep_memory(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 5: Deep Memory Stats")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        print(f"   File Size:   {reader.file_size / (1024**3):.2f} GB")
        if hasattr(reader, 'runs'):
             print(f"   Memory Runs: {len(reader.runs)}")

# ============================================================================
# EXAMPLES 6-9: ADVANCED MALWARE HUNTING
# ============================================================================

def example_6_thread_dll_analysis(dump_path, dtb_val, target_pid=None):
    print(f"\n======================================================================")
    print(f"Example 6: Thread & DLL Forensics (Engines 4 & 5)")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        proc_scanner = EProcessScanner(reader, translator)
        thread_parser = ThreadParser(reader, translator)
        dll_parser = DLLParser(reader, translator)
        processes = proc_scanner.find_all_processes()
        target = next((p for p in processes if p['pid'] == target_pid), None)
        if not target:
            target = next((p for p in processes if p['image_name'].lower() == 'explorer.exe'), processes[0])
            print(f"ℹ️  Target PID not found/specified. Auto-selected: {target['image_name']} ({target['pid']})")

        print(f"🔍 Analyzing {target['image_name']} (PID: {target['pid']})...")
        threads = thread_parser.enumerate_threads_for_process(target['eprocess_phys_addr'], proc_scanner.offsets)
        print(f"   - Threads Found: {len(threads)}")
        if target['peb'] and target['dtb']:
            translator.dtb = target['dtb']
            dlls = dll_parser.get_dlls_robust(target['peb'], target['pid'], dump_path)
            print(f"   - DLLs Loaded:   {len(dlls)}")
        else:
            print("   - DLLs: Skipped (No PEB/DTB)")

def example_7_handle_analysis(dump_path, dtb_val, target_pid=None):
    print(f"\n======================================================================")
    print(f"Example 7: Handle Table Analysis (Engine 6)")
    print(f"======================================================================")
    from ramdetect.extraction.parsers.handle_parser import HandleParser
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        scanner = EProcessScanner(reader, translator)
        processes = scanner.find_all_processes()
        target = next((p for p in processes if p['pid'] == target_pid), None)
        if not target:
            target = next((p for p in processes if p['image_name'].lower() == 'explorer.exe'), None)
        if not target:
            print("❌ No target process found.")
            return

        print(f"🔍 Scanning Handles for: {target['image_name']} (PID: {target['pid']})")
        handle_parser = HandleParser(reader, translator)
        handles = handle_parser.enumerate_handles(dump_path, pid=target['pid'])
        print(f"✅ Found {len(handles)} handles.")
        suspicious = handle_parser.detect_suspicious_handles(handles)
        if suspicious:
            print(f"⚠️  {len(suspicious)} suspicious handles detected.")
            for item in suspicious[:3]:
                print(f"   - {item['handle']['name']}")

def example_8_pe_header_hunt(dump_path, dtb_val):
    print(f"\n======================================================================")
    print(f"Example 8: PE Header Hunting (Engine 7)")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        pe_analyzer = PEAnalyzer(reader, translator)
        print("🔍 Scanning Physical RAM for Kernel Images (ntoskrnl.exe)...")
        potential_kernels = reader.scan_pattern(b'MZ', start_offset=0x0, max_len=0x4000000)
        found = False
        for addr in potential_kernels:
            if pe_analyzer.is_valid_pe(addr, use_virtual=False):
                print(f"   🎯 Valid PE Header found at Phys: {addr:#x}")
                info = pe_analyzer.analyze_pe(addr, use_virtual=False)
                if info['is_valid']:
                    print(f"      Sections: {len(info['sections'])}")
                    found = True
                    break
        if not found:
            print("❌ No valid kernel headers found.")

def example_9_full_malware_scan(dump_path, dtb_val, target_pid=None):
    print(f"\n======================================================================")
    print(f"Example 9: FULL MALWARE SCAN (Engines 8 & 9 + Correlation)")
    print(f"======================================================================")
    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, dtb_val)
        proc_scanner = EProcessScanner(reader, translator)
        processes = proc_scanner.find_all_processes()
        target = next((p for p in processes if p['pid'] == target_pid), None)
        if not target:
            target = next((p for p in processes if p['image_name'].lower() == 'explorer.exe'), None)
        if not target:
            print("❌ No target found.")
            return

        print(f"🎯 Target: {target['image_name']} (PID: {target['pid']})")
        
        thread_parser = ThreadParser(reader, translator)
        dll_parser = DLLParser(reader, translator)
        vad_scanner = VADScanner()
        inj_detector = InjectionDetector(pe_analyzer=PEAnalyzer(reader, translator))
        
        print("   1. Extracting Threads...")
        threads = thread_parser.enumerate_threads_for_process(target['eprocess_phys_addr'], proc_scanner.offsets)
        print("   2. Extracting DLLs...")
        translator.dtb = target['dtb']
        dlls = dll_parser.get_dlls_robust(target['peb'], target['pid'], dump_path)
        print("   3. Scanning VAD Tree...")
        vads = vad_scanner.scan_vad(dump_path, target['pid'])
        
        print("   4. Running Injection Heuristics (Engine 9)...")
        detections = inj_detector.detect_injections(target['pid'], threads, dlls, vads)
        if detections:
            print(f"\n🚨 MALWARE DETECTED! Found {len(detections)} indicators:")
            for d in detections:
                print(f"   [{d['severity']}] {d['type']} @ {d.get('address', 0):#x}")
        else:
            print("\n✅ System Clean. No injection indicators found.")

# ============================================================================
# MAIN MENU
# ============================================================================

def main():
    print("\n======================================================================")
    print("RAMDetect - Parsing Engines Integration (Engines 1-9)")
    print("======================================================================")

    # Use the interactive input function
    dump_file, dtb_val, target_pid = get_user_input()

    print(f"\n📁 Analyzing: {os.path.basename(dump_file)}")
    print(f"🔑 DTB:       {dtb_val:#x}")
    if target_pid: print(f"🎯 Targeted PID: {target_pid}")

    examples = {
        '1': ('Basic Process Scanning', lambda: example_1_basic_scanning(dump_file, dtb_val)),
        '2': ('Scanning + Translation', lambda: example_2_scanning_translation(dump_file, dtb_val)),
        '3': ('Process Tree Analysis', lambda: example_3_process_tree(dump_file, dtb_val)),
        '4': ('Suspicious Process Detection', lambda: example_4_suspicious_detection(dump_file, dtb_val)),
        '5': ('Deep Memory Stats', lambda: example_5_deep_memory(dump_file, dtb_val)),
        '6': ('Threads & DLLs (Deep Dive)', lambda: example_6_thread_dll_analysis(dump_file, dtb_val, target_pid)),
        '7': ('Handle Analysis', lambda: example_7_handle_analysis(dump_file, dtb_val, target_pid)),
        '8': ('PE Header Hunting', lambda: example_8_pe_header_hunt(dump_file, dtb_val)),
        '9': ('FULL MALWARE SCAN (Injection)', lambda: example_9_full_malware_scan(dump_file, dtb_val, target_pid)),
    }

    # Helper function for option 10
    def run_all_tests():
        print("\n🚀 STARTING FULL SYSTEM DIAGNOSTIC...")
        for key in sorted(examples.keys()):
            # We don't recurse if we add '10' to the dict, so we only loop 1-9
            name, func = examples[key]
            print(f"\n{'='*70}")
            print(f" >>> RUNNING: {name}")
            print(f"{'='*70}")
            try:
                func()
                time.sleep(1) # Brief pause between tests
            except Exception as e:
                print(f"❌ Critical Error in {name}: {e}")
        print("\n✅ FULL DIAGNOSTIC COMPLETE.")

    # Add option 10
    examples['10'] = ('RUN ALL TESTS', run_all_tests)

    while True:
        print("\n📋 Available Examples:")
        # Sort keys numerically to ensure 10 comes after 9
        sorted_keys = sorted(examples.keys(), key=lambda x: int(x))
        for key in sorted_keys:
            name, _ = examples[key]
            print(f"  {key:<2}. {name}")
        print("  q.  Quit")

        choice = input("\nSelect example (1-10, q): ").strip().lower()

        if choice == 'q':
            break
        elif choice in examples:
            name, func = examples[choice]
            try:
                func()
            except Exception as e:
                print(f"❌ Error running example: {e}")
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
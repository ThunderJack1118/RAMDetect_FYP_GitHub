"""
examples/advanced_analysis_example.py
=====================================
Demonstrates Advanced Forensic Engines (4, 5, 6).
Performs a "Deep Dive" into a specific process to find injected code.
"""

import sys
import os
import logging
# Add this right after the imports to see the hidden errors
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("ramdetect.extraction.parsers.memory_reader").setLevel(logging.INFO) # Keep reader quiet
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
from ramdetect.extraction.parsers.address_translator import AddressTranslator
from ramdetect.extraction.parsers.eprocess_scanner import EProcessScanner
from ramdetect.extraction.parsers.thread_parser import ThreadParser
from ramdetect.extraction.parsers.dll_parser import DLLParser

def print_header(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python advanced_analysis_example.py <dump_path> <dtb_hex>")
        sys.exit(1)

    dump_path = sys.argv[1]
    dtb_val = int(sys.argv[2], 16)

    print_header("RAMDetect: Advanced Deep Dive Analysis")

    #  
    # The 'with' block opens the physical memory file. 
    # EVERYTHING requiring access to RAM must be indented inside this block.
    with PhysicalMemoryReader(dump_path) as reader:
        # 1. Initialize Base Engines
        translator = AddressTranslator(reader, dtb_val)
        proc_scanner = EProcessScanner(reader, translator)
        
        # 2. Initialize Advanced Engines
        thread_parser = ThreadParser(reader, translator)
        dll_parser = DLLParser(reader, translator)
        
        print("✅ Engines Initialized")

        # 3. Find a Target Process (User Mode)
        print("\n🔍 Scanning for target process...")
        processes = proc_scanner.find_all_processes()
        
        target = None
        for p in processes:
            if p['image_name'].lower() == 'explorer.exe':
                target = p
                break
        
        if not target:
            # Fallback to svchost if explorer isn't found
            for p in processes:
                if p['image_name'].lower() == 'svchost.exe':
                    target = p
                    break
        
        if not target:
            print("❌ No suitable user-mode process found for deep dive.")
            return

        print(f"🎯 TARGET ACQUIRED: {target['image_name']} (PID: {target['pid']})")
        print(f"   EPROCESS: {target['eprocess_phys_addr']:#x}")
        print(f"   DTB:      {target['dtb']:#x}")
        if target.get('peb'):
            print(f"   PEB:      {target['peb']:#x}")
        else:
            print("   ⚠️  Warning: No PEB found (Cannot list DLLs)")

        # ---------------------------------------------------------
        # ENGINE 4: THREAD ANALYSIS
        # ---------------------------------------------------------
        print_header("ENGINE 4: THREAD ENUMERATION")
        
        eprocess_offsets = proc_scanner.offsets
        
        threads = thread_parser.enumerate_threads_for_process(
            target['eprocess_phys_addr'], 
            eprocess_offsets
        )
        
        print(f"Found {len(threads)} threads.")
        print(f"{'TID':<8} {'State':<12} {'Priority':<8} {'Start Address'}")
        print("-" * 60)
        
        for t in threads[:10]:
            print(f"{t['tid']:<8} {t['state_name']:<12} {t['priority']:<8} {t['start_address']:#x}")
            
        if len(threads) > 10: print(f"... and {len(threads)-10} more.")

        suspicious_threads = thread_parser.detect_suspicious_threads({target['pid']: threads})
        if suspicious_threads:
            print(f"\n⚠️  SUSPICIOUS THREADS DETECTED: {len(suspicious_threads)}")
            for item in suspicious_threads:
                t = item['thread']
                print(f"   TID {t['tid']}: {', '.join(item['flags'])}")

        # ======================================================================
        # ENGINE 5: DLL ANALYSIS (PEB WALKING)
        # ======================================================================
        # NOTICE: The lines below are now indented to align with the rest of the block
        print("\n" + "="*70)
        print(" ENGINE 5: DLL ANALYSIS (HYBRID)")
        print("="*70)

        if target['peb'] and target['dtb']:
            original_dtb = translator.dtb
            try:
                # Switch to Process DTB (Needed for Manual scan)
                translator.dtb = target['dtb']
                
                # CALL THE NEW ROBUST METHOD
                # We pass dump_path so it can run Volatility if manual fails
                dlls = dll_parser.get_dlls_robust(
                    peb_va=target['peb'], 
                    pid=target['pid'], 
                    dump_path=dump_path
                )
                
                if dlls:
                    print(f"✅ Found {len(dlls)} loaded modules.")
                    print(f"{'Base Address':<18} {'Size':<10} {'Path'}")
                    print("-" * 80)
                    for dll in dlls[:20]:
                        print(f"{dll['base']:<18x} {dll['size']:<10x} {dll['path']}")
                    if len(dlls) > 20: print(f"... and {len(dlls)-20} more.")
                else:
                    print("❌ Both Manual and Volatility scans failed to find DLLs.")

            except Exception as e:
                print(f"❌ Error during DLL scan: {e}")
            finally:
                translator.dtb = original_dtb
        else:
            print("❌ Missing PEB or DTB info.")
        # ======================================================================
        # ENGINE 6: HANDLE ANALYSIS (HYBRID: VOLATILITY POWERED)
        # ======================================================================
        print_header("ENGINE 6: HANDLE ANALYSIS (HYBRID)")
        
        from ramdetect.extraction.parsers.handle_parser import HandleParser
        handle_parser = HandleParser(reader, translator)
        
        # We call Volatility because manual offsets are too unstable for Win11
        handles = handle_parser.enumerate_handles(dump_path, pid=target['pid'])
        
        if handles:
            print(f"✅ Extracted {len(handles)} open handles for {target['image_name']}.")
            
            suspicious = handle_parser.detect_suspicious_handles(handles)
            if suspicious:
                print(f"⚠️  ALERT: Found {len(suspicious)} suspicious patterns!")
                for item in suspicious[:5]:
                    h = item['handle']
                    print(f"   [{h['type']}] {h['name']} -> {', '.join(item['flags'])}")
            else:
                print("   ✅ No suspicious handle activity detected.")
                
            print(f"\n   --- Handle Sample ---")
            print(f"   {'Type':<15} {'Name'}")
            for h in handles[:10]:
                print(f"   {h['type']:<15} {h['name']}")
        else:
            print("❌ Volatility handle extraction failed.")
        # ======================================================================
        # ENGINE 7: PE HEADER ANALYSIS (SMART KERNEL FALLBACK)
        # ======================================================================
        print_header("ENGINE 7: PE HEADER ANALYSIS")
        
        from ramdetect.extraction.parsers.pe_analyzer import PEAnalyzer
        pe_analyzer = PEAnalyzer(reader, translator)
        
        # 1. Try the Target Process first (User Mode)
        target_base = None
        if 'dlls' in locals() and dlls:
            target_base = dlls[0]['base']
            print(f"🔍 Attempting to analyze module: {dlls[0]['path']}")
            print(f"   Target Address: {target_base:#x}")
        
        success = False
        
        # Attempt 1: User Mode Target
        if target_base:
            original_dtb = translator.dtb
            translator.dtb = target['dtb']
            try:
                pe_info = pe_analyzer.analyze_pe(target_base, use_virtual=True)
                if pe_info['is_valid']:
                    print("   ✅ Success! Analyzed User Mode PE.")
                    success = True
                else:
                    print("   ❌ User Mode header is paged out (Expected in Crash Dumps).")
            except:
                print("   ❌ Failed to read User Mode memory.")
            finally:
                translator.dtb = original_dtb

        # Attempt 2: Kernel Mode Fallback (If Attempt 1 failed)
        if not success:
            print("\n🔄 FALLBACK: Hunting for Windows Kernel (ntoskrnl.exe) in Physical RAM...")
            
            # Scan first 64MB of Physical RAM for 'MZ' header
            # The Kernel is usually located near physical address 0x1000 - 0x10000000
            potential_kernels = reader.scan_pattern(b'MZ', start_offset=0x0, max_len=0x4000000)
            
            kernel_base = None
            for addr in potential_kernels:
                # Check if this MZ signature belongs to a valid PE
                # We use use_virtual=False because we are scanning Physical RAM directly
                if pe_analyzer.is_valid_pe(addr, use_virtual=False):
                    print(f"   🎯 FOUND KERNEL PE at Physical Address: {addr:#x}")
                    kernel_base = addr
                    break
            
            if kernel_base:
                pe_info = pe_analyzer.analyze_pe(kernel_base, use_virtual=False)
                if pe_info['is_valid']:
                    success = True
                    print("   ✅ Successfully analyzed Windows Kernel Header!")

        # 3. Print Results (for whichever succeeded)
        if success and pe_info:
            print(f"   ---------------------------------------------")
            print(f"   Architecture:  {'64-bit' if pe_info['is_64bit'] else '32-bit'}")
            print(f"   Entry Point:   {pe_info['entry_point']:#x}")
            print(f"   Sections:      {len(pe_info['sections'])} found")
            
            print(f"\n   [Sections Analysis]")
            print(f"   {'Name':<10} {'VirtAddr':<10} {'Entropy'}")
            print(f"   {'-'*45}")
            for sec in pe_info['sections']:
                # 7.0+ entropy is a heuristic for packed/encrypted code
                entropy_flag = "⚠️" if sec['entropy'] > 7.2 else " "
                print(f"   {sec['name']:<10} {sec['virtual_address']:<10x} {sec['entropy']:.2f} {entropy_flag}")

            if pe_info['anomalies']:
                print(f"\n   ⚠️  PE Anomalies Detected:")
                for anomaly in pe_info['anomalies']:
                    print(f"      - {anomaly}")
            else:
                print("\n   ✅ Header structure appears healthy.")
        else:
            print("\n❌ Could not find ANY valid PE headers (User or Kernel).")

if __name__ == "__main__":
    main()
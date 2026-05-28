"""
examples/ramdetect_extraction_tool.py
=====================================
RAMDetect Pro - Forensic Extraction & Analysis Suite
----------------------------------------------------
This is the main entry point for the forensic analysis workflow.
It orchestrates:
  1. Memory Acquisition (Reading raw/crash dumps)
  2. Structure Parsing (EPROCESS, ETHREAD, VAD, Handles)
  3. Feature Extraction (Heuristic Anomaly Detection)
  4. Reporting (Interactive UI + CSV/JSON Export)
"""

import sys
import os
import time
import logging
import json
import csv
import math
import datetime
import re
import concurrent.futures
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, List, Optional
from queue import Queue

# ============================================================================
# 1. ENVIRONMENT SETUP & DEPENDENCY INJECTION
# ============================================================================

# [BROWSER FIX] Centralized browser whitelist constant
BROWSER_WHITELIST = {
    'msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
    'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'microsoftedge.exe',
    'msedgewebview2.exe', 'chromium.exe', 'waterfox.exe'
}

SYSTEM_PROCESS_WHITELIST = {
    'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'winlogon.exe', 'registry.exe',
    'svchost.exe', 'dwm.exe', 'explorer.exe', 'sihost.exe',
    'taskhostw.exe', 'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe',
    'conhost.exe', 'fontdrvhost.exe', 'spoolsv.exe', 'audiodg.exe',
    'vmtoolsd.exe', 'searchui.exe', 'shellexperiencehost.exe',
    'memory compression'
}

current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RAMDetect")

class LocalFeatureAggregator:
    def extract_all_features(self, parsed_data): return {}

try:
    from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
    from ramdetect.extraction.parsers.address_translator import AddressTranslator
    from ramdetect.extraction.parsers.eprocess_scanner import EProcessScanner
    from ramdetect.extraction.parsers.thread_parser import ThreadParser
    from ramdetect.extraction.parsers.dll_parser import DLLParser
    from ramdetect.extraction.parsers.vad_scanner import VADScanner 
    from ramdetect.extraction.parsers.injection_detector import InjectionDetector
    from ramdetect.features.dll_features import FeatureExtractor
    
    try:
        from ramdetect.utils.offset import get_offsets
    except ImportError:
        print("⚠️  Warning: ramdetect.utils.offset not found. Defaulting to Win11 24H2 hardcodes.")
        def get_offsets(build):
            return {
                "EPROCESS": {"ThreadListHead": 0x370}, 
                "ETHREAD": {"ThreadListEntry": 0x578}
            }

    try:
        from ramdetect.extraction.parsers.handle_parser import HandleParser
    except ImportError:
        HandleParser = None

    try:
        from ramdetect.features.feature_aggregator import FeatureAggregator
    except ImportError:
        FeatureAggregator = LocalFeatureAggregator

except ImportError as e:
    print(f"❌ Critical Import Error: {e}")
    sys.exit(1)

DEFAULT_DUMP_DIR = project_root / "dumps"
OUTPUT_DIR = project_root / "output" / "test_results"

# ============================================================================
# 2. UTILITY FUNCTIONS
# ============================================================================

# [BROWSER FIX] Helper function to extract process basename robustly
def extract_process_basename(proc_info):
    """
    Robustly extract the base executable name from process info.
    Handles full paths like 'C:\\Program Files\\...\\msedge.exe' -> 'msedge.exe'
    """
    if not isinstance(proc_info, dict):
        return ''
    
    # Try path first (most reliable)
    path = proc_info.get('path', '')
    if path and isinstance(path, str):
        basename = os.path.basename(path.replace('\\', os.sep))
        if basename:
            return basename.lower()
    
    # Fall back to image_name
    image_name = proc_info.get('image_name', '')
    if image_name and isinstance(image_name, str):
        return image_name.lower()
    
    return ''

# ============================================================================
# 3. RISK ASSESSMENT ENGINE
# ============================================================================

def calculate_risk_verdict(features: Dict[str, float], parsed_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Calculate risk score with MALWARE-FOCUSED weighting.
    """
    if not features:
        return {'score': 0, 'verdict': 'CLEAN', 'level': 'LOW'}
    
    # [CRITICAL] Malware-specific weights (NOT browser-focused)
    weights = {
        # === SMOKING GUN INDICATORS (Always Malware) ===
        'code_injection_detected': 100.0,    # Direct code injection
        'process_hollowing': 100.0,          # Process hollowing detected
        'reflective_dll_injection': 100.0,   # Reflective DLL injection
        'shellcode_pattern': 100.0,          # Shellcode in memory
        'svchost_wrong_parent': 100.0,       # svchost.exe with wrong parent
        
        # === HIGH CONFIDENCE MALWARE ===
        'unbacked_thread_start': 50.0,
        'malware_path_pattern': 40.0,       # [INCREASED] Threads from unbacked memory
        'ppid_spoofing': 40.0,               # [INCREASED] Time anomaly in parent-child
        'orphan_process': 40.0,              # [INCREASED] Process with no parent
        
        # === INJECTION TECHNIQUES ===
        'apc_injection': 30.0,
        'atombombing': 30.0,
        'rwx_memory': 25.0,                  # Writable+Executable memory
        
        # === MEDIUM CONFIDENCE ===
        'suspicious_path': 15.0,             # [INCREASED] Running from Temp/AppData
        'hidden_process': 15.0,
        'private_executable': 15.0,
        'suspicious_parent_child': 10.0,
        
        # === LOW CONFIDENCE (Noise) ===
        'unsigned_dll': 2.0,                 # [REDUCED] Common false positive
        'missing_path': 2.0,                 # [REDUCED] Common in dumps
        'system_orphan': 0.5,                # [REDUCED] System noise
        'duplicate': 1.0,
        'late_loaded': 0.5,
        'no_imports': 0.5
    }
    
    total_score = 0.0
    
    for key, value in features.items():
        if value <= 0: 
            continue
        
        # Find weight (default to 1.0 for unknown features)
        weight = 1.0
        for k, w in weights.items():
            if k in key.lower():
                weight = w
                break
        
        # [NEW] Apply exponential scoring for high-confidence malware
        # Malware indicators should spike quickly
        if weight >= 40.0:  # High confidence malware
            impact = value * weight * 2.0
        elif weight >= 20.0:  # Medium confidence
            impact = value * weight * 1.5
        else:  # Low confidence
            impact = value * weight * 0.3
        
        total_score += impact
    
    # [STRICT MALWARE THRESHOLDS]
    # Only clean if VERY low score
    if total_score >= 50:  # Moderate evidence
        verdict = "SUSPICIOUS"
        level = "HIGH" if total_score >= 80 else "MEDIUM"
    elif total_score >= 20:  # Some evidence
        verdict = "SUSPICIOUS"
        level = "MEDIUM"
    elif total_score >= 10:  # Weak evidence
        verdict = "SUSPICIOUS"
        level = "LOW"
    else:
        verdict = "CLEAN"
        level = "LOW"
    
    final_risk = min(100, int(total_score))
    
    return {
        'score': final_risk, 
        'verdict': verdict, 
        'level': level,
        'raw_score': total_score
    }

# ============================================================================
# 3. SETUP WIZARD (IMPROVED METADATA DETECTION)
# ============================================================================

def select_dump_file() -> str:
    search_paths = [DEFAULT_DUMP_DIR, Path(r"C:\Users\annsi\Downloads\RAMDetect_test\dumps")]
    files = []
    for p in search_paths:
        if p.exists():
            files.extend(list(p.glob("*.dmp")) + list(p.glob("*.raw")) + list(p.glob("*.mem")))
    files = sorted(list(set([f.resolve() for f in files])))

    if not files:
        print(f"❌ No dump files found in: {DEFAULT_DUMP_DIR}")
        sys.exit(1)

    print(f"\n📂 Available RAM Dumps:")
    print("=" * 60)
    for i, f in enumerate(files, 1):
        size_gb = f.stat().st_size / (1024**3)
        print(f"  {i}. {f.name:<40} ({size_gb:.2f} GB)")

    while True:
        try:
            selection = input(f"\nSelect Dump File (1-{len(files)}): ").strip()
            if not selection: continue
            idx = int(selection) - 1
            if 0 <= idx < len(files): return str(files[idx])
            else: print("❌ Invalid selection number.")
        except ValueError: print("❌ Please enter a number.")

def display_metadata(dump_path: str):
    """
    Attempts to find and load the sidecar JSON metadata file.
    It checks multiple naming conventions to ensure it finds your file.
    """
    p = Path(dump_path)
    
    # Check all possible naming conventions for the metadata file
    candidates = [
        p.with_suffix('.json'),                 # memdump.json
        Path(str(p) + ".json"),                 # memdump.dmp.json
        p.with_suffix('.dmp.metadata.json'),    # memdump.dmp.metadata.json
        Path(str(p) + ".metadata.json")         # memdump.dmp.metadata.json
    ]
    
    json_path = None
    for candidate in candidates:
        if candidate.exists():
            json_path = candidate
            break
            
    if json_path:
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            print(f"\n📄 DUMP METADATA Found: {json_path.name}")
            print("=" * 60)
            
            # Extract Critical Info
            cr3 = meta.get('kernel_info', {}).get('dtb_hex') or meta.get('cr3')
            build = meta.get('kernel_info', {}).get('build_number') or meta.get('build_number')
            
            # Extract System Info for confirmation
            sys_info = meta.get('system', {})
            hostname = sys_info.get('hostname', 'Unknown')
            
            print(f"   💻 Hostname:   {hostname}")
            print(f"   🔑 DTB (Cr3):  {cr3 if cr3 else 'Unknown'}")
            print(f"   🛠️  OS Build:   {build if build else 'Unknown'}")
            print("=" * 60)
            return cr3, build
        except Exception as e: 
            print(f"⚠️  Error reading metadata: {e}")
            return None, None
            
    print("\n⚠️  No JSON metadata file found. Analysis may be inaccurate.")
    return None, None

def get_session_config():
    print("\n" + "="*60)
    print("RAMDetect Extraction Tool - Setup")
    print("="*60)
    dump_file = select_dump_file()
    
    # Robustly check for metadata
    auto_dtb_hex, auto_build = display_metadata(dump_file)
    
    # 1. DTB CONFIGURATION
    selected_dtb = 0x1ae000 # Default fallback
    
    if auto_dtb_hex:
        print(f"\n🔑 DTB Configuration")
        print(f"   [Enter] Use Auto-Detected: {auto_dtb_hex}")
        print(f"   [Manual] Enter new hex value")
        inp = input("   Selection: ").strip()
        if inp:
            try: selected_dtb = int(inp, 16)
            except: pass
        else:
            try: selected_dtb = int(auto_dtb_hex, 16)
            except: pass
    else:
        print(f"\n🔑 DTB Configuration")
        print("   [Enter] Use Default (0x1ae000)")
        while True:
            dtb_input = input("   Enter DTB Hex: ").strip().lower()
            if not dtb_input: break
            try: 
                selected_dtb = int(dtb_input, 16)
                break
            except ValueError: print("   ❌ Invalid hex.")

    # 2. BUILD NUMBER CONFIGURATION
    selected_build = auto_build
    
    # Logic: If auto_build found, use it by default. If not, ask.
    if selected_build:
        print(f"\n🛠️  Windows Build Configuration")
        print(f"   [Enter] Use Detected Build: {selected_build}")
        print(f"   [Manual] Enter build number (e.g. 26100)")
        build_inp = input("   Selection: ").strip()
        if build_inp and build_inp.isdigit():
            selected_build = int(build_inp)
    else:
        # Fallback if no JSON found
        print(f"\n🛠️  Windows Build Number")
        print("   (Required for correct thread/DLL offsets)")
        print("   [Enter] Default (26100 / Win11)")
        print("   [17134] Windows 10 1803")
        print("   [19045] Windows 10 22H2")
        
        build_input = input("   Enter Build Number: ").strip()
        if build_input and build_input.isdigit():
            selected_build = int(build_input)
        else:
            selected_build = 26100 # Default for modern systems

    return dump_file, selected_dtb, selected_build

# ============================================================================
# 4. REPORTING & DISPLAY
# ============================================================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(dump_file, dtb_val, build_num=None):
    clear_screen()
    print("\n" + "#"*80)
    print(f"{'RAMDetect v1.0 - Extraction & Discovery Tool':^80}")
    print("#"*80)
    print(f"  File:       {Path(dump_file).name}")
    
    # Determine profile name based on build number
    profile_name = "Unknown"
    if build_num == 17134: profile_name = "Win10 1803 (Redstone 4)"
    elif build_num == 18362 or build_num == 18363: profile_name = "Win10 1903/1909"
    elif build_num and build_num >= 19041 and build_num < 22000: profile_name = "Win10 20H1+"
    elif build_num and build_num >= 22000: profile_name = "Win11 21H2+"
    
    build_str = str(build_num) if build_num else "Unknown (Default 26100)"
    print(f"  Profile:    Build {build_str} ({profile_name}) | DTB: {hex(dtb_val)}")
    print("-" * 80)

def determine_status(item):
    """Generic status checker for any item (Proc, Thread, DLL)."""
    anomalies = item.get('anomalies', [])
    if item.get('status') == 'SUSPICIOUS' or len(anomalies) > 0 or item.get('is_suspicious'):
        return "SUSPICIOUS"
    return "CLEAN"

def format_status_cli(item):
    """Formatted CLI string with color."""
    status = determine_status(item)
    if status == "SUSPICIOUS":
        return "[⚠ SUSPICIOUS]"
    return "[✓ CLEAN    ]"

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def count_artifacts_by_pid(data_list):
    """Helper to count items (threads/handles) per PID."""
    counts = defaultdict(int)
    for item in data_list:
        counts[item.get('pid', 0)] += 1
    return counts

# --- Process Tree View ---
def show_process_tree(parsed_data, page_size=20):
    processes = parsed_data.get('processes', [])
    threads_counts = count_artifacts_by_pid(parsed_data.get('threads', []))
    handles_counts = count_artifacts_by_pid(parsed_data.get('handles', []))
    
    if not processes:
        print("\n[!] No process data available.")
        return

    # Build Tree Structure
    children = defaultdict(list)
    proc_map = {}
    for p in processes:
        pid = p['pid']
        ppid = p['ppid']
        proc_map[pid] = p
        children[ppid].append(pid)
    
    # Identify Roots (PID 4 or processes whose parent isn't in the list)
    roots = [pid for pid in proc_map if pid not in proc_map or proc_map[pid]['ppid'] not in proc_map]
    if 4 in proc_map and 4 not in roots: roots = [4] + [r for r in roots if r != 4] 

    # Flatten Tree for Display
    display_rows = []
    
    def add_node(pid, indent_level, prefix=""):
        proc = proc_map.get(pid)
        if not proc: return
        
        name = proc['image_name']
        t_count = threads_counts.get(pid, 0)
        h_count = handles_counts.get(pid, 0)
        status = format_status_cli(proc)
        
        branch = "  " * indent_level + ("> " if indent_level > 0 else "")
        tree_name = branch + name
        
        display_rows.append([tree_name, str(pid), str(proc['ppid']), str(t_count), str(h_count), status])
        
        kid_pids = sorted(children.get(pid, []))
        for kid in kid_pids:
            add_node(kid, indent_level + 1)

    for root in sorted(roots):
        add_node(root, 0)

    # Render Table
    RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"
    clear_screen()
    print_table_banner(
        "🌳 PROCESS TREE EXPLORER",
        f"Hierarchical View | {len(processes)} Processes | {sum(threads_counts.values())} Threads"
    )

    headers = ["Process Name", "PID", "PPID", "Threads", "Handles", "Status"]
    col_widths = [50, 8, 8, 10, 10, 20] 
    
    header_str = ""
    for i, h in enumerate(headers):
        header_str += f"{h:<{col_widths[i]}}"
    print(header_str)
    print("-" * 110)
    
    total = len(display_rows)
    total_pages = (total + page_size - 1) // page_size
    current_page = 1
    
    while True:
        start = (current_page - 1) * page_size
        end = min(start + page_size, total)
        
        print(f"Page {current_page}/{total_pages}")
        
        for row in display_rows[start:end]:
            row_str = ""
            for i, val in enumerate(row):
                if i == 5: # Status column (colored)
                    if "SUSPICIOUS" in val: color = RED
                    else: color = GREEN
                    clean_val = strip_ansi(val)
                    padding = col_widths[i] - len(clean_val)
                    row_str += f"{color}{clean_val}{RESET}" + " " * padding
                else:
                    clean_val = val
                    if len(clean_val) > col_widths[i] - 1:
                        clean_val = clean_val[:col_widths[i]-4] + "..."
                    row_str += f"{clean_val:<{col_widths[i]}}"
            print(row_str)
            
        print("-" * 110)
        print(f"[n]ext | [p]revious | [q]uit view")
        choice = input("Action: ").strip().lower()
        if choice == 'n' and current_page < total_pages: 
            clear_screen()
            print_table_banner(
                "🌳 PROCESS TREE EXPLORER",
                f"Hierarchical View | {len(processes)} Processes | {sum(threads_counts.values())} Threads"
            )
            print(header_str)
            print("-" * 110)
            current_page += 1
        elif choice == 'p' and current_page > 1: 
            clear_screen()
            print_table_banner(
                "🌳 PROCESS TREE EXPLORER",
                f"Hierarchical View | {len(processes)} Processes | {sum(threads_counts.values())} Threads"
            )
            print(header_str)
            print("-" * 110)
            current_page -= 1
        elif choice == 'q': break
        else: clear_screen()

# --- Process List View (Detailed) ---
def show_process_list_detailed(parsed_data, page_size=20):
    processes = parsed_data.get('processes', [])
    threads_counts = count_artifacts_by_pid(parsed_data.get('threads', []))
    handles_counts = count_artifacts_by_pid(parsed_data.get('handles', []))
    
    if not processes:
        print("\n[!] No process data.")
        return
    
    clear_screen()
    print_table_banner(
        "📋 PROCESS LIST - DETAILED VIEW",
        f"Complete Process Information | Total: {len(processes)} Processes"
    )

    headers = ["PID", "Process Name", "PPID", "Path", "Threads", "Handles", "Status", "Anomaly"]
    formatted_rows = []
    
    RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"

    for p in processes:
        pid = p['pid']
        status = determine_status(p)
        
        if status == "SUSPICIOUS":
            status_str = f"{RED}[!] SUSP{RESET}"
        else:
            status_str = f"{GREEN}[✓] CLEAN{RESET}"
            
        anom = ", ".join(p.get('anomalies', []))
        if len(anom) > 30: anom = anom[:27] + "..."
        if not anom: anom = "-"
        
        path = p.get('path', '')
        if len(path) > 30: path = "..." + path[-27:]
        
        formatted_rows.append([
            str(pid), 
            p['image_name'], 
            str(p['ppid']), 
            path, 
            str(threads_counts.get(pid, 0)), 
            str(handles_counts.get(pid, 0)), 
            status_str, 
            anom
        ])
        
    show_paginated_table(headers, formatted_rows, page_size, title="📋 PROCESS LIST", subtitle=f"{len(processes)} Processes")

# --- Threads List View (Detailed) ---
def show_detailed_threads_table(parsed_data, page_size=20):
    from collections import defaultdict
    threads = parsed_data.get('threads', [])
    processes = parsed_data.get('processes', [])
    dlls = parsed_data.get('dlls', [])
    
    if not threads:
        print("\n[!] No thread data available.")
        return

    # Map PID to Process Info for cross-referencing
    pid_map = {p['pid']: p for p in processes}
    
    # [SMART CHECK] Count DLLs per PID. 
    dll_counts = defaultdict(int)
    for d in dlls:
        dll_counts[d.get('pid', 0)] += 1

    # [WHITELIST] Use centralized whitelists
    SYSTEM_WHITELIST = SYSTEM_PROCESS_WHITELIST
    BROWSER_WHITELIST_LOCAL = BROWSER_WHITELIST

    KERNEL_THREAD_WHITELIST = {
        "system", "registry.exe", "smss.exe", "memory compression"
    }

    clear_screen()
    unsigned_count = sum(1 for d in dlls if not d.get('is_signed'))
    suspicious_count = sum(1 for d in dlls if d.get('is_suspicious') or d.get('anomalies'))
    
    print_table_banner(
        "🧵 THREAD ANALYSIS",
        f"Total: {len(threads)} Threads | Suspicious: {suspicious_count} | Running: {len(threads) - suspicious_count}"
    )

    RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"
    headers = ["TID", "PID", "PROCESS", "START ADDRESS", "STATE", "STATUS", "ANOMALY"]
    formatted_rows = []

    for t in threads:
        tid = str(t.get('tid', 0))
        pid_val = t.get('pid', 0)
        pid_str = str(pid_val)
        start_addr = hex(t.get('start_address', 0))
        state = str(t.get('state_name', t.get('state', 'Unknown')))
        
        # --- [FIX 1] Improved Parent Process Analysis ---
        parent_proc = pid_map.get(pid_val)
        proc_name = "Unknown"
        parent_is_malicious = False
        is_browser = False
        
        if parent_proc:
            # Use robust basename extraction
            proc_name = extract_process_basename(parent_proc)
            if not proc_name:
                proc_name = parent_proc.get('image_name', 'Unknown')
            
            # Check if this is a browser process
            is_browser = proc_name.lower() in BROWSER_WHITELIST_LOCAL
            
            # Logic: Only inherit malice if the parent has CRITICAL anomalies.
            # We ignore "Unusual Start" and "Kernel Mode" in the parent's record 
            # to prevent false positive chains (like OneDrive > Threads).
            p_anoms = parent_proc.get('anomalies', [])
            
            real_parent_anoms = [
                a for a in p_anoms 
                if "Unusual Start" not in a and "Kernel Mode" not in a
            ]
            
            if real_parent_anoms:
                parent_is_malicious = True

        if len(proc_name) > 19: proc_name = proc_name[:17] + ".."
        proc_lower = proc_name.lower()

        # --- [FIX 2] Advanced False Positive Filtering ---
        raw_anomalies = t.get('anomalies', [])
        clean_anomalies = []
        
        for anom in raw_anomalies:
            skip_anomaly = False
            
            # Filter A: "Unusual Start Address" (Private Memory)
            # CRITICAL: Browsers use JIT compilation, system apps might have paged memory
            if "Unusual Start Address" in anom or "Private Mem" in anom or "JIT" in anom:
                is_whitelisted = proc_lower in SYSTEM_WHITELIST
                has_no_dlls = dll_counts[pid_val] == 0
                
                # [BROWSER FIX] Check if parent process is a browser using robust basename
                is_browser = False
                if parent_proc:
                    browser_name = extract_process_basename(parent_proc)
                    is_browser = browser_name in BROWSER_WHITELIST
                
                # Skip if: (1) Browser, OR (2) Whitelisted system + no DLLs
                if is_browser or (is_whitelisted and has_no_dlls):
                    skip_anomaly = True
            
            # Filter B: "Kernel Mode Start Address"
            # Allow specific processes (Registry, SMSS, System) to have kernel threads.
            elif "Kernel Mode Start Address" in anom:
                if proc_lower in KERNEL_THREAD_WHITELIST or pid_val == 4:
                    skip_anomaly = True
            
            # Filter C: "Zero Start Address" (Always keep - never skip)
            
            if not skip_anomaly:
                clean_anomalies.append(anom)

        # --- Status Determination ---
        status_val = "CLEAN"
        
        # Priority 1: Direct Anomalies
        if clean_anomalies:
            status_val = "SUSPICIOUS"
        
        # Priority 2: Parent Inheritance (only if thread itself is clean)
        elif parent_is_malicious:
            status_val = "SUSPICIOUS"
            clean_anomalies.append("Parent Process Malicious")
        
        # Priority 3: Zero Start Address Sanity Check
        if int(t.get('start_address', 0)) == 0:
             if "Zero Start Addr" not in clean_anomalies:
                 clean_anomalies.append("Zero Start Addr")
             status_val = "SUSPICIOUS"

        # --- Visual Formatting ---
        if status_val == "SUSPICIOUS":
            status_str = f"{RED}[!] SUSPICIOUS{RESET}"
            anomaly_str = ", ".join(clean_anomalies) if clean_anomalies else "-"
            formatted_rows.append([tid, pid_str, proc_name, start_addr, state, status_str, anomaly_str])
    
    show_paginated_table(headers, formatted_rows, page_size, title="🧵 THREAD ANALYSIS", subtitle=f"{len(threads)} Threads")

# --- Detailed DLL Table Function ---
def show_detailed_dlls_table(parsed_data, page_size=20):
    dlls = parsed_data.get('dlls', [])
    processes = parsed_data.get('processes', [])
    threads = parsed_data.get('threads', [])
    handles = parsed_data.get('handles', [])
    
    if not dlls:
        print("\n[!] No DLL data available.")
        return

    # Calculate features if missing
    if dlls and 'is_signed' not in dlls[0]:
        print("⏳ Calculating DLL features (Entropy, Signature check)... please wait.")
        try:
            extractor = FeatureExtractor()
            extractor.extract_features(parsed_data)
        except Exception as e:
            logger.error(f"Failed to extract DLL features: {e}")

    # Build lookup maps for cross-table context
    pid_map = {p['pid']: p for p in processes}
    
    # Thread map (PID -> list of threads)
    thread_map = {}
    for thread in threads:
        t_pid = thread.get('pid', 0)
        if t_pid not in thread_map:
            thread_map[t_pid] = []
        thread_map[t_pid].append(thread)
    
    # Handle map (PID -> list of handles)
    handle_map = {}
    for handle in handles:
        h_pid = handle.get('pid', 0)
        if h_pid not in handle_map:
            handle_map[h_pid] = []
        handle_map[h_pid].append(handle)

    clear_screen()
    suspicious_count = sum(1 for t in threads if t.get('status') == 'SUSPICIOUS')
    print_table_banner(
        "🧵 THREAD ANALYSIS",
        f"Total: {len(threads)} Threads | Suspicious: {suspicious_count} | Running: {len(threads) - suspicious_count}"
    )

    RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"
    headers = ["PID", "DLL Name", "Path", "Size", "Signed", "Status", "Anomaly"]
    formatted_rows = []

    for d in dlls:
        pid = d.get('pid', 0)
        name = d.get('name', 'Unknown')
        
        # Clean path (remove timestamp garbage)
        raw_path = d.get('path', '')
        if raw_path:
            clean_path = raw_path.split(' 20')[0].strip()
        else:
            clean_path = ""
        
        size_bytes = d.get('size', 0)
        size_str = f"{size_bytes/1024:.0f}KB"

        # Get existing anomalies from DLL parser
        anomalies = list(d.get('anomalies', []))
        is_suspicious = d.get('is_suspicious', False)
        
        # Get process context
        parent_proc = pid_map.get(pid, {})
        proc_name = parent_proc.get('image_name', '').lower()
        proc_path = parent_proc.get('path', '').lower()
        proc_anomalies = parent_proc.get('anomalies', [])
        
        # Get thread context
        proc_threads = thread_map.get(pid, [])
        has_remote_thread = any(t.get('is_remote_thread') for t in proc_threads)
        has_apc_injection = any(t.get('has_apc_queued') for t in proc_threads)
        
        # Get handle context
        proc_handles = handle_map.get(pid, [])
        has_persistence_handle = any(
            h.get('type', '').lower() == 'key' and 
            'run' in h.get('name', '').lower()
            for h in proc_handles
        )
        
        # --- CONTEXT-AWARE CHECKS ---
        
        # [CHECK 1] Inherit Process Suspicion
        if proc_anomalies:
            is_suspicious = True
            if "Parent Process Suspicious" not in anomalies:
                anomalies.append("Parent Process Suspicious")
        
        # [CHECK 2] Unsigned DLLs (Context: Process location + Threads)
        if not d.get('is_signed', False):
            # Legitimate system processes
            system_processes = ['system', 'smss.exe', 'csrss.exe', 'services.exe', 'lsass.exe']
            
            # Unsigned is ONLY suspicious if:
            # - NOT a known system process, AND
            # - (Process in temp/appdata OR has injection indicators)
            if proc_name not in system_processes:
                is_temp_location = any(loc in proc_path for loc in ['temp', 'appdata', 'downloads'])
                
                if is_temp_location or has_remote_thread or has_apc_injection:
                    is_suspicious = True
                    if "Unsigned (Suspicious Context)" not in anomalies:
                        anomalies.append("Unsigned (Suspicious Context)")
        
        # [CHECK 3] DLL in Windows Root (NOT System32/SysWOW64)
        # FIXED: Only flag DLLs DIRECTLY in C:\Windows\, not subdirectories
        if clean_path.lower().startswith("c:\\windows\\"):
            # Count backslashes: C:\Windows\file.dll = 2 slashes (suspicious)
            #                    C:\Windows\System32\file.dll = 3 slashes (legitimate)
            if clean_path.lower().count('\\') == 2:
                # DLL directly in Windows root (e.g., C:\Windows\malware.dll)
                is_suspicious = True
                if "Suspicious Path (Windows Root)" not in anomalies:
                    anomalies.append("Suspicious Path (Windows Root)")
        
        # [CHECK 4] Suspicious Directories (Context: Combined with other indicators)
        suspicious_dirs = ["\\temp\\", "\\appdata\\", "\\users\\public", "\\downloads"]
        if any(s in clean_path.lower() for s in suspicious_dirs):
            # Only flag if ALSO has injection or persistence indicators
            if has_remote_thread or has_persistence_handle or proc_anomalies:
                is_suspicious = True
                if "Suspicious Directory" not in anomalies:
                    anomalies.append("Suspicious Directory")
        
        # [CHECK 5] High Entropy (Packing) + Injection
        entropy = d.get('entropy', 0.0)
        if entropy > 7.0:  # High entropy = likely packed/encrypted
            if has_remote_thread or has_apc_injection:
                is_suspicious = True
                if "Packed DLL + Injection" not in anomalies:
                    anomalies.append("Packed DLL + Injection")
        
        # --- FINAL VERDICT ---
        if is_suspicious:
            status_str = f"{RED}[!] SUSPICIOUS{RESET}"
        else:
            status_str = f"{GREEN}[✓] CLEAN{RESET}"
        
        anomaly_str = ", ".join(anomalies) if anomalies else "-"
        
        # Truncate path for display
        display_path = clean_path
        if len(display_path) > 40: 
            display_path = "..." + display_path[-37:]
        
        # FIXED: Use actual signature status
        signed_status = "Yes" if d.get('is_signed', False) else "No"
        
        formatted_rows.append([
            str(pid), 
            name, 
            display_path, 
            size_str, 
            signed_status,  # <-- FIXED: Was hardcoded "No"
            status_str, 
            anomaly_str
        ])

    show_paginated_table(headers, formatted_rows, page_size, title="📦 LOADED MODULES", subtitle=f"{len(dlls)} DLLs")

# --- Detailed Handle Table Function ---
def show_detailed_handles_table(parsed_data, page_size=20):
    handles = parsed_data.get('handles', [])
    processes = parsed_data.get('processes', [])
    
    if not handles:
        print("\n[!] No handle data available.")
        return

    clear_screen()
    file_handles = sum(1 for h in handles if h.get('type') == 'File')
    reg_handles = sum(1 for h in handles if h.get('type') == 'Key')
    
    print_table_banner(
        "🔎 HANDLE TABLE ANALYSIS",
        f"Total: {len(handles)} | Files: {file_handles} | Registry: {reg_handles}"
    )

    pid_map = {p['pid']: p.get('image_name', 'Unknown') for p in processes}
    RED, GREEN, RESET = "\033[91m", "\033[92m", "\033[0m"
    
    headers = ["Type", "Handle Name", "PID", "Process", "Status", "Anomaly"]
    formatted_rows = []

    for h in handles:
        h_type = h.get('type', 'Unknown')
        h_name = h.get('name', '')
        pid = h.get('pid', 0)
        proc_name = pid_map.get(pid, 'Unknown')
        
        # --- Handle Heuristics (Display-time check) ---
        anomalies = []
        name_lower = h_name.lower()
        
        # Registry Persistence Checks
        if h_type == "Key":
            if 'currentversion\\run' in name_lower or 'runonce' in name_lower:
                anomalies.append("Persistence Mechanism")
            if 'services' in name_lower and 'currentcontrolset' in name_lower:
                anomalies.append("Service Manipulation")
        
        # File Sensitivity Checks
        if h_type == "File":
            if 'sam' in name_lower or 'security' in name_lower or 'config' in name_lower:
                anomalies.append("Security Database Access")
            if 'password' in name_lower or 'credential' in name_lower or '.kdbx' in name_lower:
                anomalies.append("Sensitive File Access")
            if 'temp' in name_lower and ('.exe' in name_lower or '.bat' in name_lower):
                anomalies.append("Suspicious Temp Execution")

        # Determine Status
        if anomalies:
            status_str = f"{RED}[!] SUSPICIOUS{RESET}"
        else:
            status_str = f"{GREEN}[✓] CLEAN{RESET}"

        anomaly_str = "; ".join(anomalies) if anomalies else "-"
        
        # Truncate Name for display
        if len(h_name) > 50: h_name = "..." + h_name[-47:]
        
        formatted_rows.append([h_type, h_name, str(pid), proc_name, status_str, anomaly_str])

    show_paginated_table(headers, formatted_rows, page_size, title="🔎 HANDLE TABLE", subtitle=f"{len(handles)} Handles")

def print_table_banner(title: str, subtitle: str = "", width: int = None):
    """
    Print a styled banner for tables
    
    Args:
        title: Main title text
        subtitle: Optional subtitle/description
        width: Banner width in characters (auto-calculated if None)
    """
    if width is None:
        # Calculate based on longest text
        max_text_len = max(len(title), len(subtitle) if subtitle else 0)
        width = max(max_text_len + 10, 100)  # At least 100 chars
    
    print("\n" + "="*width)
    print(f"{title:^{width}}")
    if subtitle:
        print(f"{subtitle:^{width}}")
    print("="*width)


def print_section_header(title: str, icon: str = "📊", width: int = 100):
    """
    Print a section header with icon
    
    Args:
        title: Section title
        icon: Emoji icon
        width: Header width
    """
    print("\n" + "─"*width)
    print(f"{icon} {title}")
    print("─"*width)

def show_paginated_table(headers, rows, page_size=20, title=None, subtitle=None):
    if not rows:
        print("  (No data to display)")
        input("  Press Enter to return...")
        return
    
    col_widths = [len(h) + 2 for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            clean_val = strip_ansi(str(val))
            col_widths[i] = max(col_widths[i], len(clean_val) + 2)

    final_display_rows = []
    
    for row in rows:
        new_row = []
        for i, val in enumerate(row):
            clean_val = strip_ansi(val)
            padding = col_widths[i] - len(clean_val)
            new_row.append(val + " " * padding)
        final_display_rows.append(new_row)

    total = len(final_display_rows)
    total_pages = (total + page_size - 1) // page_size
    current_page = 1

    table_width = sum(col_widths)
    
    while True:
        clear_screen()
        if title:
            print_table_banner(title, subtitle or f"Page {current_page}/{total_pages}")
            print(f"\n📊 Data View - Page {current_page}/{total_pages} (Total: {total})")
        else:
            print(f"\n📊 Data View - Page {current_page}/{total_pages} (Total: {total})")
            print("=" * table_width)
        
        header_str = ""
        for i, h in enumerate(headers):
            header_str += f"{h:<{col_widths[i]}}"
        print(header_str)
        print("-" * table_width)
        
        start = (current_page - 1) * page_size
        end = min(start + page_size, total)
        for row in final_display_rows[start:end]:
            print("".join(row))
            
        print("=" * table_width)
        print(f"[n]ext | [p]revious | [q]uit view")
        choice = input("Action: ").strip().lower()
        if choice == 'n' and current_page < total_pages: current_page += 1
        elif choice == 'p' and current_page > 1: current_page -= 1
        elif choice == 'q': break

def print_extraction_summary(data):
    p_count = len(data.get('processes', []))
    t_count = len(data.get('threads', []))
    d_count = len(data.get('dlls', []))
    h_count = len(data.get('handles', []))
    i_count = len(data.get('injections', []))
    risk_info = data.get('risk_assessment', {})
    verdict = risk_info.get('verdict', 'NOT ANALYZED')
    
    print("\n" + "="*80)
    print(f"{'EXTRACTION DASHBOARD':^80}")
    print("="*80)
    print(f"  Processes Found:     {p_count:>6}    |    Threads Extracted:   {t_count:>6}")
    print(f"  DLLs Loaded:         {d_count:>6}    |    Handles Open:        {h_count:>6}")
    print("-" * 80)
    print(f"  💉 Injections Detected: {i_count:>6}")
    if verdict != 'NOT ANALYZED':
        color_icon = "🔴" if verdict == "SUSPICIOUS" else "🟢"
        print(f"  🛡️  Risk Verdict:       {color_icon} {verdict} (Score: {risk_info.get('score',0)}/100)")
        print(f"      Risk Level:         {risk_info.get('level', 'Unknown')}")
    print("="*80 + "\n")

def export_all_data(data: Dict[str, Any], dump_name: str):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = Path(dump_name).stem.replace(" ", "_")
    folder_name = f"Analysis_{safe_name}_{timestamp}"
    export_dir = OUTPUT_DIR / folder_name
    
    try: os.makedirs(export_dir, exist_ok=True)
    except: return

    print(f"\n💾 Exporting results to: {export_dir}")
    
    pid_map = {p['pid']: p.get('image_name', 'Unknown') for p in data.get('processes', [])}

    try:
        with open(export_dir / f"full_extraction.json", 'w') as f:
            json.dump(data, f, default=str, indent=2)
        print(f"   ✓ JSON Full Dump saved")
    except: pass

    try:
        risk_data = data.get('risk_assessment', {})
        with open(export_dir / "summary_verdict.txt", 'w') as f:
            f.write(f"RAMDetect Final Analysis Report\n")
            f.write(f"=============================\n")
            f.write(f"Dump File: {dump_name}\n")
            f.write(f"Date: {datetime.datetime.now()}\n\n")
            f.write(f"FINAL VERDICT: {risk_data.get('verdict', 'UNKNOWN')}\n")
            f.write(f"Risk Score: {risk_data.get('score', 0)}/100\n")
            f.write(f"Risk Level: {risk_data.get('level', 'Unknown')}\n\n")
        print(f"   ✓ Summary Verdict saved")
    except: pass

    # --- PROCESSES ---
    proc_headers = ["PID", "Process Name", "PPID", "Path", "Threads", "Handles", "Status", "Anomaly"]
    t_counts = count_artifacts_by_pid(data.get('threads', []))
    h_counts = count_artifacts_by_pid(data.get('handles', []))
    proc_rows = []
    for p in data.get('processes', []):
        row = {
            "PID": p['pid'], "Process Name": p['image_name'], "PPID": p['ppid'],
            "Path": p.get('path', ''),
            "Threads": t_counts.get(p['pid'], 0), "Handles": h_counts.get(p['pid'], 0),
            "Status": determine_status(p), "Anomaly": "; ".join(p.get('anomalies', []))
        }
        proc_rows.append(row)
    _write_csv(export_dir / "processes.csv", proc_headers, proc_rows)

    # --- THREADS ---
    thread_headers = ["TID", "PID", "Process Name", "Start Address", "State", "Priority", "Status", "Anomalies"]
    thread_rows = []
    for t in data.get('threads', []):
        pid = t.get('pid', 0)
        row = {
            "TID": t.get('tid'), "PID": pid, "Process Name": pid_map.get(pid, "Unknown"),
            "Start Address": hex(t.get('start_address', 0)),
            "State": t.get('state_name', 'Unknown'), "Priority": t.get('priority', 0),
            "Status": determine_status(t), "Anomalies": "; ".join(t.get('anomalies', []))
        }
        thread_rows.append(row)
    _write_csv(export_dir / "threads.csv", thread_headers, thread_rows)

    # --- DLLS ---
    dll_headers = ["DLL Name", "Path", "Base Address", "Size", "Signed", "Entropy", "Status", "Anomaly"]
    dll_rows = []
    for d in data.get('dlls', []):
        is_susp = d.get('is_suspicious', False) or d.get('anomalies')
        row = {
            "DLL Name": d.get('name'), "Path": d.get('path'),
            "Base Address": hex(d.get('base_address', 0)), "Size": d.get('size', 0),
            "Signed": "Yes" if d.get('is_signed') else "No",
            "Entropy": f"{d.get('entropy', 0.0):.2f}",
            "Status": "SUSPICIOUS" if is_susp else "CLEAN",
            "Anomaly": "; ".join(d.get('anomalies', []))
        }
        dll_rows.append(row)
    _write_csv(export_dir / "dlls.csv", dll_headers, dll_rows)

    # --- HANDLES ---
    handle_headers = ["PID", "Type", "Name", "Object Address"]
    handle_rows = []
    for h in data.get('handles', []):
        row = {
            "PID": h.get('pid'), "Type": h.get('type'),
            "Name": h.get('name'), "Object Address": h.get('object_address')
        }
        handle_rows.append(row)
    _write_csv(export_dir / "handles.csv", handle_headers, handle_rows)

    print("✅ Export Complete.")
    input("Press Enter...")

def _write_csv(path, headers, rows):
    if not rows: return
    try:
        # [FIX] Added 'escapechar' and 'utf-8' to handle weird characters in malware paths
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f, 
                fieldnames=headers, 
                escapechar='\\',             # Allows escaping of delimiters
                quoting=csv.QUOTE_MINIMAL    # Quotes fields only when necessary
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"   ✓ {path.name} saved")
    except Exception as e:
        print(f"   ⚠️  Failed to save {path.name}: {e}")

# ============================================================================
# 5. CORE PARSING PIPELINE
# ============================================================================

def is_valid_dtb_for_dlls(dtb: int) -> bool:
    if dtb == 0 or dtb == 0xFFFFFFFFFFFFFFFF: return False
    if (dtb & 0xFFF) != 0: return False  
    if dtb < 0x1000: return False        
    if dtb > 0x7FFFFFFF: return False    
    return True

def run_parsing_phase(dump_file: str, dtb_val: int, build_num: Optional[int]) -> Dict[str, Any]:
    print(f"\n[{time.strftime('%H:%M:%S')}] PHASE 1: Parsing Memory Artifacts...")
    print("-" * 60)
    
    parsed_data = {'processes': [], 'threads': [], 'dlls': [], 'handles': [], 'injections': [], 'risk_assessment': {}}
    target_build = build_num if build_num else 26100 
    
    profile = get_offsets(target_build)
    print(f"   ℹ️  Applied Profile: Build {target_build}")
    
    try:
        with PhysicalMemoryReader(dump_file) as reader:
            print(f"   ✓ Memory Reader initialized ({reader.file_size / 1024**3:.2f} GB)")
            translator = AddressTranslator(reader, dtb_val)
            
            print("   > Scanning EPROCESS structures...")
            eprocess_scanner = EProcessScanner(reader, translator, build_number=build_num)
            processes = eprocess_scanner.find_all_processes()
            parsed_data['processes'] = processes
            print(f"   ✓ Found {len(processes)} processes")
            
            if not processes:
                print("   ⚠️  No processes found. Check DTB value.")
                return parsed_data

            print("   > Initializing forensic engines...")
            
            # Store scanner offsets (EXACTLY like original)
            scanner_offsets = getattr(eprocess_scanner, 'offsets', {}).copy()
            if 'ThreadListHead' not in scanner_offsets:
                scanner_offsets['ThreadListHead'] = profile['EPROCESS']['ThreadListHead']
            if 'ThreadListEntry' not in scanner_offsets:
                scanner_offsets['ThreadListEntry'] = profile['ETHREAD']['ThreadListEntry']
            
            # FULL SCAN MODE ENABLED (EXACTLY like original)
            targets = [p for p in processes if len(p['image_name']) > 0]
            total_targets = len(targets)

            print(f"   > Deep scanning {total_targets} active processes...")
            print("   " + "-"*50)
            
            # ============================================
            # PHASE 1: Thread Scanning (Sequential)
            # ============================================
            print("   [1/3] Scanning threads...")
            
            # Create thread parser ONCE (like original)
            thread_parser = ThreadParser(reader, translator, build_number=build_num)
            
            thread_count = 0
            threads_by_pid = {}  # Store for Phase 2
            
            for i, proc in enumerate(targets, 1):
                pid = proc['pid']
                name = proc['image_name']
                
                # Update progress less frequently to reduce console spam
                if i % 10 == 0 or i == total_targets or i == 1:
                    print(f"\r   [{i}/{total_targets}] Threads: {name:<15} (PID: {pid:<6}){' '*10}", end="")
                
                try:
                    # Thread scanning (EXACTLY like original)
                    t_list = thread_parser.enumerate_threads_for_process(
                        proc['eprocess_phys_addr'], pid, scanner_offsets
                    )
                    
                    if t_list:
                        parsed_data['threads'].extend(t_list)  # EXACTLY like original
                        thread_count += len(t_list)
                        threads_by_pid[pid] = t_list  # Store for injection detection
                        
                except Exception:
                    # EXACTLY like original: silent catch
                    pass
            
            print(f"\n   ✓ Extracted {thread_count} threads")
            
            # ============================================
            # PHASE 2: DLL Scanning (Parallel)
            # ============================================
            print("\n   [2/3] Scanning DLLs (parallel)...")
            
            def scan_dlls_worker(proc):
                """Worker for DLL scanning only"""
                pid = proc['pid']
                name = proc['image_name']
                
                result = {
                    'pid': pid,
                    'name': name,
                    'dlls': [],
                    'error': None
                }
                
                try:
                    # Create local instances (each worker needs its own)
                    local_reader = PhysicalMemoryReader(dump_file)
                    local_translator = AddressTranslator(local_reader, dtb_val)
                    local_dll_parser = DLLParser(local_reader, local_translator, dump_file=dump_file)
                    
                    # DLL scanning (EXACTLY like original logic)
                    d_list = []
                    user_dtb = proc.get('dtb')
                    if user_dtb and is_valid_dtb_for_dlls(user_dtb):
                        try:
                            original_dtb = local_translator.dtb
                            local_translator.dtb = user_dtb
                            if hasattr(local_dll_parser, 'get_modules'):
                                d_list = local_dll_parser.get_modules(proc)
                            else:
                                d_list = local_dll_parser.get_dlls_robust(proc.get('peb', 0), pid, dump_file)
                            for d in d_list:
                                d['pid'] = pid
                            local_translator.dtb = original_dtb
                            result['dlls'] = d_list
                        except Exception:
                            local_translator.dtb = dtb_val
                    
                    local_reader.close()
                    
                except Exception:
                    # EXACTLY like original: silent catch
                    pass
                
                return result
            
            # Configure parallel execution for DLL scanning
            cpu_count = os.cpu_count() or 2
            max_workers = min(4, cpu_count)
            
            # Reduce logging noise during parallel scan
            original_log_level = logging.getLogger("ramdetect.extraction.parsers.memory_reader").level
            logging.getLogger("ramdetect.extraction.parsers.memory_reader").setLevel(logging.WARNING)
            
            dll_count = 0
            dlls_by_pid = {}  # Store for injection detection
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit DLL scanning tasks
                futures = []
                for proc in targets:
                    future = executor.submit(scan_dlls_worker, proc)
                    futures.append((future, proc))
                
                # Process results
                completed = 0
                for future, proc in futures:
                    completed += 1
                    
                    try:
                        result = future.result(timeout=30)
                        
                        if result['dlls']:
                            parsed_data['dlls'].extend(result['dlls'])  # EXACTLY like original
                            dll_count += len(result['dlls'])
                            dlls_by_pid[proc['pid']] = result['dlls']
                        
                        # Update progress every 5 processes
                        if completed % 5 == 0 or completed == total_targets:
                            print(f"\r   [{completed}/{total_targets}] DLLs: {proc['image_name']:<15} "
                                  f"Found: {len(result['dlls']):3d}{' '*10}", end="")
                            
                    except concurrent.futures.TimeoutError:
                        pass
                    except Exception:
                        pass
            
            print(f"\n   ✓ Extracted {dll_count} DLLs")
            
            # ============================================
            # PHASE 3: Handle Scanning & Injection Detection (Parallel)
            # ============================================
            print("\n   [3/3] Scanning handles & detecting injections (parallel)...")
            
            def scan_handles_and_injections_worker(proc):
                """Worker for handles and injection detection"""
                pid = proc['pid']
                name = proc['image_name']
                
                result = {
                    'pid': pid,
                    'name': name,
                    'handles': [],
                    'injections': [],
                    'error': None
                }
                
                try:
                    # Create local instances
                    local_reader = PhysicalMemoryReader(dump_file)
                    local_translator = AddressTranslator(local_reader, dtb_val)
                    local_handle_parser = HandleParser(local_reader, local_translator) if HandleParser else None
                    local_vad_scanner = VADScanner(local_reader, local_translator)
                    local_injector = InjectionDetector()
                    
                    # Handle scanning (if available)
                    if local_handle_parser:
                        try:
                            handles = local_handle_parser.enumerate_handles(dump_file, pid)
                            result['handles'] = handles
                        except Exception:
                            pass
                    
                    # VAD scanning (EXACTLY like original)
                    vad_regions = []
                    try:
                        vad_regions = local_vad_scanner.scan_vad(proc)
                    except:
                        pass
                    
                    # Injection detection (EXACTLY like original)
                    t_list = threads_by_pid.get(pid, [])
                    d_list = dlls_by_pid.get(pid, [])
                    
                    if t_list:
                        try:
                            injs = local_injector.detect_injections(pid, t_list, d_list, vad_regions, process_name=name)
                            for inj in injs:
                                inj['process'] = name
                            result['injections'] = injs
                        except Exception:
                            pass
                    
                    local_reader.close()
                    
                except Exception:
                    # EXACTLY like original: silent catch
                    pass
                
                return result
            
            handle_count = 0
            injection_count = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit handle/injection scanning tasks
                futures = []
                for proc in targets:
                    future = executor.submit(scan_handles_and_injections_worker, proc)
                    futures.append((future, proc))
                
                # Process results
                completed = 0
                for future, proc in futures:
                    completed += 1
                    
                    try:
                        result = future.result(timeout=30)
                        
                        if result['handles']:
                            parsed_data['handles'].extend(result['handles'])  # EXACTLY like original
                            handle_count += len(result['handles'])
                        
                        if result['injections']:
                            # EXACTLY like original: use .append() for injections
                            for inj in result['injections']:
                                parsed_data['injections'].append(inj)
                            injection_count += len(result['injections'])
                        
                        # Update progress every 5 processes
                        if completed % 5 == 0 or completed == total_targets:
                            handles_found = len(result['handles'])
                            injections_found = len(result['injections'])
                            print(f"\r   [{completed}/{total_targets}] {proc['image_name']:<15} "
                                  f"H:{handles_found:4d} I:{injections_found:2d}{' '*10}", end="")
                            
                    except concurrent.futures.TimeoutError:
                        pass
                    except Exception:
                        pass
            
            # Restore logging
            logging.getLogger("ramdetect.extraction.parsers.memory_reader").setLevel(original_log_level)
            
            print(f"\n   " + "-"*50)
            print(f"   ✓ Extracted {thread_count} threads")
            print(f"   ✓ Extracted {dll_count} loaded modules")
            print(f"   ✓ Extracted {handle_count} open handles")
            print(f"   ✓ Detected {injection_count} injections")
            
    except Exception as e:
        logger.error(f"Parsing Phase Failed: {e}", exc_info=True)
        return None
        
    print("-" * 60)
    return parsed_data

def show_suspicious_analysis(parsed_data):
    # [FIX] Clear screen first so previous menu doesn't clutter view
    clear_screen()
    
    print(f"\n🧠 Phase 2: Feature Extraction & Risk Analysis")
    print("-" * 60)
    
    print("   > Initializing Feature Aggregator...")
    aggregator = FeatureAggregator(logger)
    
    # [ADDED] verbose feedback on extraction
    print("   > Extracting Process features...")
    print("   > Extracting DLL features...")
    print("   > Extracting Injection/VAD features...")
    
    features = aggregator.extract_all_features(parsed_data)
    
    count_features = len(features)
    count_non_zero = sum(1 for v in features.values() if v > 0)
    print(f"   ✓ Generated {count_features} feature vectors ({count_non_zero} active signals)")
    
    print("   > Calculating Risk Score...")
    # [FIXED] Pass parsed_data to calculate_risk_verdict
    risk = calculate_risk_verdict(features, parsed_data)
    parsed_data['risk_assessment'] = risk
    
    # [NEW] Show browser context in results
    if risk.get('context', {}).get('browser_processes_detected', 0) > 0:
        print(f"   ⚠️  Detected {risk['context']['browser_processes_detected']} browser processes")
        print(f"   📉 Applied browser-aware scoring adjustment")
    
    input("\n   Risk calculation complete. Press Enter to view Analysis Verdict...")
    clear_screen()

    # ============================================================================
    # ENHANCED VERDICT DISPLAY
    # ============================================================================
    
    print("\n" + "="*80)
    print(f"{'RAMDETECT ANALYSIS VERDICT':^80}")
    print("="*80)
    
    # Verdict with icon
    if risk['verdict'] == "CLEAN":
        verdict_icon = "🟢"
    else:
        verdict_icon = "🔴"
    
    # Calculate overall confidence (average of non-zero features)
    overall_confidence = calculate_overall_confidence(features)
    
    print(f"  Verdict:       {verdict_icon} {risk['verdict']}")
    print(f"  Risk Score:    {risk['score']}/100")
    print(f"  Confidence:    {overall_confidence}% (Based on strongest indicator)")
    print("-" * 80)
    
    # ============================================================================
    # DETECTED THREATS TABLE (Enhanced with context)
    # ============================================================================
    
    print(f"{'DETECTED THREATS':^80}")
    
    # Classify and weight threats
    detected_threats = []
    for key, score in features.items():
        if score <= 0:
            continue
        
        # Get threat classification
        severity, confidence_level, confidence_weight = classify_threat(key)
        
        detected_threats.append({
            'name': key,
            'raw_score': score,
            'severity': severity,
            'confidence': confidence_level,
            'weight': confidence_weight,
            'weighted_score': score * confidence_weight
        })
    
    if not detected_threats:
        print("  [✓] No threats detected. System appears clean.")
    else:
        # Sort by weighted score
        detected_threats.sort(key=lambda x: x['weighted_score'], reverse=True)
        
        # Table header
        print(f"  {'Threat Indicator':<45} | {'Raw Score':<10} | {'Severity':<10} | {'Confidence'}")
        print(f"  {'-'*45}+{'-'*12}+{'-'*12}+{'-'*15}")
        
        # Display threats with context
        for threat in detected_threats:
            display_name = threat['name'][:42] + "..." if len(threat['name']) > 45 else threat['name']
            raw_fmt = f"{threat['raw_score']:.2f}"
            
            # Format severity
            severity_label = format_severity_label(threat['severity'])
            
            # Format confidence badge
            conf_badge = format_confidence_badge_cli(threat['confidence'])
            
            print(f"  {display_name:<45} | {raw_fmt:<10} | {severity_label:<10} | {conf_badge}")
            
            # Add context line (what this means)
            context = get_threat_context_cli(threat['name'], threat['raw_score'], parsed_data)
            if context:
                print(f"    └─ {context}")
    
    print("="*80)
    
    # ============================================================================
    # ANALYSIS SUMMARY (Enhanced breakdown)
    # ============================================================================
    
    total_indicators = len(features)
    zero_score = sum(1 for score in features.values() if score <= 0)
    
    # Categorize by severity
    critical_threats = [t for t in detected_threats if t['severity'] == 'CRITICAL']
    high_threats = [t for t in detected_threats if t['severity'] == 'HIGH']
    medium_threats = [t for t in detected_threats if t['severity'] == 'MEDIUM']
    low_threats = [t for t in detected_threats if t['severity'] == 'LOW']
    
    print(f"\n{'ANALYSIS SUMMARY':^80}")
    print(f"  Total indicators checked: {total_indicators}")
    print(f"  Indicators with no detection: {zero_score}")
    print(f"  🔴 Critical threats (high severity): {len(critical_threats)}")
    print(f"  🟠 High severity threats: {len(high_threats)}")
    print(f"  🟡 Medium severity threats: {len(medium_threats)}")
    print(f"  🟢 Low priority findings: {len(low_threats)}")
    
    # ============================================================================
    # TOP FINDINGS (Enhanced with affected artifacts)
    # ============================================================================
    
    if detected_threats:
        print(f"\n{'TOP FINDINGS (by impact)':^80}")
        
        for i, threat in enumerate(detected_threats[:10], 1):
            conf_label = threat['confidence']
            severity_label = threat['severity']
            
            print(f"  {i}. {threat['name']}: {threat['raw_score']:.2f} "
                  f"({severity_label} severity, {conf_label} confidence)")
            
            # Show affected artifacts
            affected = get_affected_artifacts_cli(threat['name'], parsed_data)
            if affected:
                print(f"     └─ {affected}")
    
    print("="*80 + "\n")
    input("Press Enter to return to menu...")


# ============================================================================
# HELPER FUNCTIONS FOR ENHANCED VERDICT
# ============================================================================

def calculate_overall_confidence(features: Dict[str, float]) -> int:
    """
    Calculate confidence based on the 'Strongest Signal' principle.
    If we find a Smoking Gun, confidence is 100%, regardless of other noise.
    """
    confidence_map = {
        # CRITICAL (Immediate Confirmation)
        'code_injection_detected': 100,
        'process_hollowing_detected': 100,
        'reflective_dll_injection': 100,
        'svchost_wrong_parent_count': 100,
        'critical_violation': 100,
        
        # HIGH (Strong Indicators)
        'shellcode_pattern_count': 90,
        'rwx_memory_count': 85,
        'private_executable_count': 85,
        'apc_injection_count': 80,
        
        # MEDIUM (Heuristic)
        'hidden_process_count': 70,
        'unbacked_memory_count': 60,
        'orphan_process_count': 50,
        
        # LOW (Statistical)
        'unsigned_dll_count': 40,
        'unsigned_dll_ratio': 30,
        'missing_path_count': 20
    }
    
    # Get all confidence scores for active features
    active_scores = []
    for name, val in features.items():
        if val > 0:
            # Default to 40% if feature not in map
            active_scores.append(confidence_map.get(name, 40))
            
    if not active_scores:
        return 100 # Default confidence for "Clean" state
        
    # [LOGIC CHANGE] Take the MAX confidence, not average.
    # A single confirmed injection means we are 100% confident it's malware.
    return max(active_scores)


def classify_threat(feature_name: str) -> tuple:
    """
    Classify threat by severity and confidence
    Returns: (severity_level, confidence_label, confidence_weight)
    """
    key_lower = feature_name.lower()
    
    # CRITICAL SEVERITY
    if any(kw in key_lower for kw in ['svchost_wrong_parent', 'process_hollowing', 
                                       'reflective_dll', 'code_injection_detected']):
        return ('CRITICAL', 'HIGH', 3.0)
    
    # HIGH SEVERITY
    if any(kw in key_lower for kw in ['injection', 'shellcode', 'rwx', 
                                       'private_executable', 'apc_injection']):
        return ('HIGH', 'HIGH', 2.5)
    
    # MEDIUM SEVERITY
    if any(kw in key_lower for kw in ['hidden', 'unbacked', 'atombombing', 
                                       'orphan_process', 'suspicious_parent']):
        return ('MEDIUM', 'MEDIUM', 1.5)
    
    # LOW SEVERITY (common false positives)
    return ('LOW', 'LOW', 0.3)


def format_severity_label(severity: str) -> str:
    """Format severity for display"""
    severity_map = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW'
    }
    return severity_map.get(severity, 'UNKNOWN')


def format_confidence_badge_cli(confidence: str) -> str:
    """Format confidence badge for CLI"""
    if confidence == 'HIGH':
        return "🔴 HIGH"
    elif confidence == 'MEDIUM':
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"


def get_threat_context_cli(feature_name: str, raw_score: float, parsed_data: Dict) -> str:
    """Provide context for what this threat means"""
    contexts = {
        'orphan_process_count': f"{int(raw_score)} process(es) with PPID=0 (no parent)",
        'hidden_process_count': f"{int(raw_score)} process(es) hidden from normal enumeration",
        'code_injection_detected': f"{int(raw_score)} injection pattern(s) detected",
        'unsigned_dll_count': f"{int(raw_score)} unsigned DLL(s) loaded",
        'svchost_wrong_parent_count': f"{int(raw_score)} svchost.exe with non-standard parent",
        'suspicious_file_handle_count': f"{int(raw_score)} handle(s) to suspicious files",
        'unsigned_dll_ratio': f"{raw_score:.1%} of DLLs are unsigned",
        'thread_distribution_anomaly': f"Anomaly score: {raw_score:.2f}",
        'suspicious_parent_child_count': f"{int(raw_score)} abnormal parent-child relationship(s)",
        'rwx_memory_count': f"{int(raw_score)} memory region(s) with RWX permissions",
        'shellcode_pattern_count': f"{int(raw_score)} potential shellcode pattern(s)",
        'process_hollowing_detected': f"{int(raw_score)} process hollowing indicator(s)",
        'reflective_dll_injection': f"{int(raw_score)} reflective DLL injection(s)",
    }
    return contexts.get(feature_name, "")


def get_affected_artifacts_cli(feature_name: str, parsed_data: Dict) -> Optional[str]:
    """
    Show which specific artifacts triggered this feature.
    Enhanced with browser context awareness.
    """
    
    # 1. SVCHOST PARENT GROUPING (Smart Display)
    if feature_name == 'svchost_wrong_parent_count':
        suspicious_svchost = [p for p in parsed_data.get('processes', []) 
                              if 'svchost.exe' == p.get('image_name', '').lower() 
                              and any('wrong parent' in a.lower() for a in p.get('anomalies', []))]
        
        if not suspicious_svchost: return None
        
        # Group by parent to detect massive spawning
        parent_map = {} # { "explorer.exe(4824)": [pid1, pid2...] }
        
        for p in suspicious_svchost:
            parent_info = f"Unknown({p['ppid']})" # Default
            # Extract parent name from anomalies string if available
            for a in p.get('anomalies', []):
                if "Wrong Parent:" in a:
                    parent_info = a.split("Wrong Parent:")[1].strip()
                    break
            
            if parent_info not in parent_map: parent_map[parent_info] = []
            parent_map[parent_info].append(str(p['pid']))
            
        # Format the output
        lines = []
        for parent, pids in parent_map.items():
            pid_str = ", ".join(pids)
            lines.append(f"PIDs: {pid_str} (Parent: {parent})")
            
        return f"Affected: {'; '.join(lines)}"

    # 2. UNSIGNED DLL NOISE FILTERING
    elif feature_name == 'unsigned_dll_count':
        unsigned = [d for d in parsed_data.get('dlls', []) if not d.get('is_signed')]
        
        # Whitelist common system files that often appear unsigned in memory dumps
        NOISE_FILTER = {
            'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'svchost.exe',
            'ucrtbase.dll', 'advapi32.dll', 'user32.dll', 'gdi32.dll',
            'rpcrt4.dll', 'msvcrt.dll', 'sechost.dll', 'combase.dll'
        }
        
        # Filter the list
        relevant_dlls = [d.get('name') for d in unsigned 
                         if d.get('name', '').lower() not in NOISE_FILTER]
        
        if relevant_dlls:
            names = ', '.join(relevant_dlls[:3])
            remaining = len(relevant_dlls) - 3
            if remaining > 0: names += f" and {remaining} more"
            return f"Suspicious Files: {names}"
        elif len(unsigned) > 0:
            return f"Files: {len(unsigned)} system modules (likely false positives)"

    # 3. ORPHAN PROCESSES (ENHANCED WITH BROWSER AWARENESS)
    elif feature_name == 'orphan_process_count':
        # Get all valid PIDs to detect "Dead Parents"
        valid_pids = {p['pid'] for p in parsed_data.get('processes', [])}
        
        # [ENHANCED] Extended safe orphan list
        SAFE_ORPHANS_DISPLAY = {
            "tiworker.exe", "audiodg.exe", "werfault.exe", "wermgr.exe",
            "sgrmbroker.exe", "useroobebroker.exe", "searchindexer.exe",
            "smss.exe", "registry", "secure system", "memcompression.exe",
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe"
        }
        
        # [BROWSER FIX] Add browsers to safe orphan list
        SAFE_ORPHANS_DISPLAY = SAFE_ORPHANS_DISPLAY.union(BROWSER_WHITELIST)

        orphans = []
        browser_orphans = []
        
        for p in parsed_data.get('processes', []):
            pid = p.get('pid', 0)
            ppid = p.get('ppid', 0)
            
            # Use robust basename extraction
            name = extract_process_basename(p)
            if not name:
                name = p.get('image_name', '').lower()
            
            # Skip Kernel (0/4)
            if pid <= 4:
                continue
            
            # Check if parent exists
            is_null_parent = (ppid == 0)
            is_dead_parent = (ppid not in valid_pids and ppid > 0)
            
            if is_null_parent or is_dead_parent:
                # Categorize as browser or regular orphan
                if name in BROWSER_WHITELIST:
                    browser_orphans.append(p)
                elif name not in SAFE_ORPHANS_DISPLAY:
                    orphans.append(p)
        
        # Format output with browser context
        if orphans:
            names = ', '.join([f"{p['image_name']}({p['pid']})" for p in orphans[:3]])
            if len(orphans) > 3:
                names += f" and {len(orphans) - 3} more"
            
            # Add browser context if present
            if browser_orphans:
                browser_count = len(browser_orphans)
                names += f" (+{browser_count} browser orphans excluded from score)"
            
            return f"Orphans: {names}"
        elif browser_orphans:
            # Only browser orphans found
            browser_names = ', '.join([f"{p['image_name']}({p['pid']})" for p in browser_orphans[:2]])
            if len(browser_orphans) > 2:
                browser_names += f" and {len(browser_orphans) - 2} more"
            return f"Browser Processes: {browser_names} (excluded from scoring)"
        
        return None

    # 4. UNBACKED THREAD START (BROWSER AWARE)
    elif 'unbacked_thread_start' in feature_name.lower():
        # Count unbacked threads with browser context
        browser_unbacked = 0
        non_browser_unbacked = 0
        
        for t in parsed_data.get('threads', []):
            if 'Unusual Start Address' in ' '.join(t.get('anomalies', [])):
                pid = t.get('pid', 0)
                # Find parent process
                parent = None
                for p in parsed_data.get('processes', []):
                    if p.get('pid', 0) == pid:
                        parent = p
                        break
                
                if parent:
                    name = extract_process_basename(parent)
                    if name in BROWSER_WHITELIST:
                        browser_unbacked += 1
                    else:
                        non_browser_unbacked += 1
        
        if non_browser_unbacked > 0:
            return f"Non-browser unbacked threads: {non_browser_unbacked}"
        elif browser_unbacked > 0:
            return f"Browser JIT threads: {browser_unbacked} (excluded from scoring)"
    
    # 5. INJECTIONS
    elif 'injection' in feature_name.lower():
        injections = parsed_data.get('injections', [])
        if injections:
            unique_targets = sorted(list(set([f"{inj.get('process')}({inj.get('pid')})" for inj in injections])))
            names = ', '.join(unique_targets[:3])
            if len(unique_targets) > 3: names += f" and {len(unique_targets) - 3} more"
            return f"Targets: {names}"

    return None

def main():
    dump_file, dtb_val, build_num = get_session_config()
    current_parsed_data = None
    
    while True:
        print_header(dump_file, dtb_val, build_num)
        if current_parsed_data: print_extraction_summary(current_parsed_data)
        else: print("\n  ⚠️  No data loaded. Run extraction first.\n")

        print("  [1] 🚀 Run Full Extraction (Parse + Scan)")
        print("  [2] 🔍 Run Risk & Feature Analysis")
        print("  [3] 🌳 View Process Tree")
        print("  [4] 📋 View Process List")
        print("  [5] 🧵 View Threads")
        print("  [6] 📦 View Loaded DLLs")
        print("  [7] 📎 View Handles")
        print("  [8] 💾 Export All Data (CSV/JSON)")
        print("  [9] 🔄 Change Dump / DTB")
        print("  [q] Quit")
        
        choice = input("\n  Select Action: ").strip().lower()
        
        if choice == '1':
            current_parsed_data = run_parsing_phase(dump_file, dtb_val, build_num)
            if current_parsed_data: input("\nExtraction Complete. Press Enter...")
        elif choice == '2':
            if current_parsed_data: show_suspicious_analysis(current_parsed_data)
            else: input("❌ Run Extraction first!")
        elif choice == '3':
            if current_parsed_data: show_process_tree(current_parsed_data)
            else: input("❌ No data.")
        elif choice == '4':
            if current_parsed_data: show_process_list_detailed(current_parsed_data)
            else: input("❌ No data.")
        elif choice == '5':
            if current_parsed_data and current_parsed_data['threads']:
                if not current_parsed_data.get('risk_assessment'):
                    try: FeatureAggregator(logger).extract_all_features(current_parsed_data)
                    except: pass
                show_detailed_threads_table(current_parsed_data)
            else: input("❌ No thread data.")
        elif choice == '6':
            if current_parsed_data and current_parsed_data['dlls']:
                show_detailed_dlls_table(current_parsed_data)
            else: input("❌ No DLL data.")
        elif choice == '7':
            if current_parsed_data and current_parsed_data.get('handles'):
                show_detailed_handles_table(current_parsed_data) # Use new detailed view
            else: input("❌ No handles found.")
        elif choice == '8':
            if current_parsed_data: export_all_data(current_parsed_data, Path(dump_file).name)
            else: input("❌ No data to export.")
        elif choice == '9':
            dump_file, dtb_val, build_num = get_session_config()
            current_parsed_data = None
        elif choice == 'q':
            print("Goodbye!")
            break

if __name__ == "__main__":
    main()
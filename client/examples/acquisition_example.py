"""
Example: RAM Acquisition with RAMDetect
========================================

This script demonstrates how to use the RAM acquisition module
Updated for current DumpItAcquisition class (December 2025)
"""

import sys
import time
from pathlib import Path

# Add RAMDetect to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.acquisition.dumpit import DumpItAcquisition
from ramdetect.acquisition.converter_todmp import RawDumpConverter
from ramdetect.acquisition.metadata_reader import MetadataReader
from ramdetect.acquisition.metadata import MetadataManager
from ramdetect.utils.logger import get_logger
from ramdetect.utils.helpers import is_admin, format_bytes, format_timestamp

logger = get_logger("RAMDetect_Examples")

def example_1_basic_acquisition():
    """Example 1: Basic RAM acquisition"""
    print("\n" + "=" * 70)
    print("Example 1: Basic RAM Acquisition")
    print("=" * 70)
    
    if not is_admin():
        print("❌ Administrator privileges required!")
        return
    
    try:
        print("\n🔄 Starting RAM acquisition...")
        acquisition = DumpItAcquisition()
        dump_path = acquisition.acquire()
        
        print(f"\n✅ Success! Dump saved to:")
        print(f"   {dump_path}")
        print(f"   Size: {format_bytes(dump_path.stat().st_size)}")
        
        # List recent dumps directly
        dumps_dir = acquisition.dumps_dir
        recent = sorted(dumps_dir.glob("*.dmp"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
        if recent:
            print("\nRecent dumps:")
            for d in recent:
                print(f"  • {d.name} ({format_bytes(d.stat().st_size)}) - {format_timestamp(d.stat().st_mtime)}")
                
    except Exception as e:
        print(f"\n❌ Acquisition failed: {e}")
        if "Access is denied" in str(e) or "driver" in str(e).lower():
            print("\n" + "=" * 70)
            print("💡 Windows 11 Driver Signing Issue?")
            print("=" * 70)
            print("Try booting with Driver Signature Enforcement disabled (F7)")
            print("Or use a signed tool like WinPmem or Magnet RAM Capture")
            print("=" * 70)


def example_2_custom_output_path():
    """Example 2: Custom output path"""
    print("\n" + "=" * 70)
    print("Example 2: Custom Output Path")
    print("=" * 70)
    
    if not is_admin():
        print("❌ Administrator privileges required!")
        return
    
    try:
        custom_path = Path("custom_dumps/custom_case_001.dmp")
        print(f"\n🔄 Saving to: {custom_path.absolute()}")
        
        acquisition = DumpItAcquisition()
        dump_path = acquisition.acquire(output_path=str(custom_path))
        
        print(f"✅ Dump created: {dump_path}")
        
    except Exception as e:
        print(f"❌ Failed: {e}")


def example_3_verify_dump():
    """Example 3: Simple dump verification"""
    print("\n" + "=" * 70)
    print("Example 3: Verify Latest Dump")
    print("=" * 70)
    
    dumps_dir = Path("dumps")
    if not dumps_dir.exists():
        print("No dumps directory found.")
        return

    dumps = list(dumps_dir.glob("*.dmp"))
    if not dumps:
        print("No .dmp files found in dumps/ folder")
        return
    
    latest = max(dumps, key=lambda p: p.stat().st_mtime)
    size = latest.stat().st_size
    
    print(f"Latest dump: {latest.name}")
    print(f"Size: {format_bytes(size)}")
    print(f"Created: {format_timestamp(latest.stat().st_ctime)}")
    
    if size > 1_000_000_000:  # > 1GB
        print("✅ Basic integrity check passed (file large and recent)")
    else:
        print("⚠️  Dump appears too small – may be incomplete")


def example_4_list_all_dumps():
    """Example 4: List all dumps"""
    print("\n" + "=" * 70)
    print("Example 4: List All Dumps")
    print("=" * 70)
    
    dumps_dir = Path("dumps")
    if not dumps_dir.exists():
        print("No dumps directory found.")
        return

    dumps = sorted(dumps_dir.glob("*.dmp"), key=lambda p: p.stat().st_mtime, reverse=True)
    
    if not dumps:
        print("No dumps found in dumps/ folder")
        return
    
    print(f"\nFound {len(dumps)} dump(s):\n")
    for i, d in enumerate(dumps, 1):
        print(f"{i:2}. {d.name}")
        print(f"     Size: {format_bytes(d.stat().st_size)}")
        print(f"     Date: {format_timestamp(d.stat().st_mtime)}\n")


def example_5_simple_metadata():
    """Example 5: Show basic file info (no MetadataManager needed yet)"""
    print("\n" + "=" * 70)
    print("Example 5: Dump File Information")
    print("=" * 70)
    
    dumps = sorted(Path("dumps").glob("*.dmp"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dumps:
        print("No dumps available")
        return
    
    latest = dumps[0]
    print(f"Latest dump: {latest.name}")
    print(f"Full path: {latest.absolute()}")
    print(f"Size: {format_bytes(latest.stat().st_size)}")
    print(f"Created: {format_timestamp(latest.stat().st_ctime)}")
    
    # Look for JSON metadata
    json_file = latest.with_suffix('.json')
    if json_file.exists():
        import json
        with open(json_file, 'r', encoding='utf-8') as f:
            meta = json.load(f)
        print("\nMetadata found:")
        if 'acquisition' in meta:
            acq = meta['acquisition']
            print(f"  Tool: {acq.get('tool', 'Unknown')}")
            print(f"  Duration: {acq.get('duration_seconds', 'N/A')}s")
        if 'hashes' in meta:
            print("  Hashes:")
            for algo, h in meta['hashes'].items():
                print(f"    {algo.upper()}: {h}")
        if 'kernel_info' in meta:
            print("  Kernel Info:")
            for k, v in meta['kernel_info'].items():
                print(f"    {k}: {v}")
    else:
        print("\nNo JSON metadata file found (normal if not saved separately)")


def example_6_generate_metadata():
    """Example 6: Generate JSON metadata with Auto-Detection"""
    print("\n" + "=" * 70)
    print("Example 6: Generate JSON Metadata for Existing Dump")
    print("=" * 70)
    print("Use this for dumps uploaded manually or from other tools.")
    
    # 1. Find Dumps
    dumps_dir = Path("dumps")
    if not dumps_dir.exists(): dumps_dir.mkdir()
    
    candidates = list(dumps_dir.glob("*.dmp")) + list(Path(".").glob("*.dmp"))
    candidates = sorted(list(set(candidates)), key=lambda p: p.stat().st_mtime, reverse=True)
    
    if not candidates:
        print("\n❌ No .dmp files found in ./dumps or current directory.")
        return

    print(f"\nSelect a dump file:")
    for i, d in enumerate(candidates, 1):
        has_json = "✅ JSON" if d.with_suffix('.json').exists() else "❌ No JSON"
        print(f"  {i}. {d.name:<40} [{has_json}] ({format_bytes(d.stat().st_size)})")
    
    # 2. Select File
    selection = input("\nEnter number (or full path): ").strip()
    target_path = None
    
    if selection.isdigit():
        idx = int(selection) - 1
        if 0 <= idx < len(candidates):
            target_path = candidates[idx]
    else:
        target_path = Path(selection)
        
    if not target_path or not target_path.exists():
        print("❌ Invalid file.")
        return

    print(f"\nProcessing: {target_path.name}")
    
    # 3. Auto-Detect Metadata
    reader = MetadataReader()
    print("🔍 Scanning file header for metadata...")
    detected_info = reader.get_metadata(target_path)
    
    dtb_val = None
    build_val = None
    
    if detected_info.get('is_valid'):
        print(f"\n✅ DETECTED IN HEADER:")
        print(f"   DTB (CR3):     {detected_info['dtb_hex']} ({detected_info['dtb']})")
        print(f"   Build Number:  {detected_info['build_number']}")
        
        use_auto = input("\nUse these values? (Y/n): ").strip().lower()
        if use_auto != 'n':
            dtb_val = detected_info['dtb_hex']
            build_val = detected_info['build_number']
    else:
        print("⚠️  No header info found (File might be RAW or encrypted).")

    # 4. Manual Input (Fallback)
    print("\n--- Metadata Configuration ---")
    
    # Ask for DTB if not auto-detected
    if not dtb_val:
        dtb_input = input("  Directory Table Base (Hex, e.g. 0x1ae000): ").strip()
        if dtb_input:
            dtb_val = dtb_input if dtb_input.startswith("0x") else f"0x{dtb_input}"
    else:
        print(f"  Directory Table Base: {dtb_val} (Auto-filled)")

    # Ask for Build if not auto-detected
    if not build_val:
        build_input = input("  Windows Build Number (e.g. 19045): ").strip()
        if build_input and build_input.isdigit():
            build_val = int(build_input)
    else:
        print(f"  Windows Build Number: {build_val} (Auto-filled)")

    tool_name = input("  Acquisition Tool Name (default: 'External'): ").strip() or "Imported/External"
    
    # Prepare data
    extra_data = {}
    if dtb_val: extra_data['dtb_hex'] = dtb_val
    if build_val: extra_data['build_number'] = build_val
    
    # 5. Generate Metadata
    print("\n🔄 Generating metadata (Calculating Hashes)...")
    try:
        mgr = MetadataManager()
        json_path = mgr.create_acquisition_metadata(
            dump_path=target_path,
            tool=tool_name,
            duration=0.0,
            extra_data=extra_data if extra_data else None
        )
        print(f"\n✅ Success! Metadata saved to:\n   {json_path.absolute()}")
        
    except Exception as e:
        print(f"❌ Error generating metadata: {e}")

def example_7_convert_raw_to_dmp():
    """Example 7: Convert .raw, .mem, .vmem dumps to .dmp format"""
    print("\n" + "=" * 70)
    print("Example 7: Convert OTHERS to DMP")
    print("=" * 70)
    print("Convert other memory dumps (.raw, .vmem, .mem) to .dmp format")
    
    converter = RawDumpConverter()
    
    # Find files in dumps directory
    dumps_dir = Path("dumps")
    if not dumps_dir.exists():
        dumps_dir.mkdir()
    
    # --- UPDATED TO FIND .mem and .bin ---
    source_exts = ['*.raw', '*.vmem', '*.mem', '*.bin']
    raw_files = []
    for ext in source_exts:
        raw_files.extend(dumps_dir.glob(ext))
    
    # Remove duplicates if any
    raw_files = sorted(list(set(raw_files)), key=lambda p: p.name)
    # -------------------------------------

    if not raw_files:
        print("\n❌ No .raw, .vmem, or .mem files found in dumps/ directory")
        print("Place your dumps there first")
        return
    
    print(f"\nFound {len(raw_files)} file(s):\n")
    
    for i, raw_file in enumerate(raw_files, 1):
        info = converter.get_dump_info(raw_file)
        print(f"{i}. {raw_file.name}")
        print(f"   Size: {info['size_gb']:.2f} GB")
        print(f"   Format: {info['format']}")
        print(f"   Signature: {info['signature']}")
        print()
    
    # Ask which files to convert
    choice = input("Convert: (a)ll, (n)umber, or (q)uit: ").strip().lower()
    
    if choice == 'q':
        return
    
    to_convert = []
    
    if choice == 'a':
        to_convert = raw_files
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(raw_files):
            to_convert = [raw_files[idx]]
        else:
            print("Invalid number")
            return
    else:
        print("Invalid choice")
        return
    
    # Ask conversion mode
    print("\nConversion mode:")
    print("  1. Rename (changes extension to .dmp)")
    print("  2. Copy (keeps original file)")
    
    mode = input("Select mode (1 or 2): ").strip()
    copy_mode = (mode == '2')
    
    # Perform conversions
    print("\n" + "=" * 70)
    print("Converting...")
    print("=" * 70)
    
    successful = 0
    failed = 0
    
    for raw_file in to_convert:
        print(f"\n[*] Processing: {raw_file.name}")
        # converter.convert_raw_to_dmp handles all extensions
        success, msg, output = converter.convert_raw_to_dmp(
            str(raw_file),
            copy=copy_mode
        )
        
        if success:
            print(f"✅ {msg}")
            successful += 1
        else:
            print(f"❌ {msg}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Conversion complete: {successful} successful, {failed} failed")
    print("=" * 70)

def example_8_batch_convert():
    """Example 8: Batch convert all dumps in directory"""
    print("\n" + "=" * 70)
    print("Example 8: Batch Convert Dumps")
    print("=" * 70)
    
    # Local import to ensure clean context
    from ramdetect.utils.converter_raw import RawDumpConverter
    
    converter = RawDumpConverter()
    dumps_dir = Path("dumps")
    
    if not dumps_dir.exists():
        print("❌ dumps/ directory not found")
        return
    
    print(f"Directory: {dumps_dir.absolute()}\n")
    
    # Count files - Updated for .mem and .vmem
    raw_count = len(list(dumps_dir.glob("*.raw")))
    vmem_count = len(list(dumps_dir.glob("*.vmem")))
    mem_count = len(list(dumps_dir.glob("*.mem")))
    dmp_count = len(list(dumps_dir.glob("*.dmp")))
    
    total_sources = raw_count + vmem_count + mem_count
    
    print(f"Current status:")
    print(f"  .dmp  files: {dmp_count} (Ready)")
    print(f"  .raw  files: {raw_count}")
    print(f"  .vmem files: {vmem_count}")
    print(f"  .mem  files: {mem_count}")
    
    if total_sources == 0:
        print("\n❌ No convertible files (.raw/.vmem/.mem) found")
        return
    
    print(f"\nThis will convert all {total_sources} source files to .dmp")
    confirm = input("Continue? (y/n): ").strip().lower()
    
    if confirm != 'y':
        print("Cancelled")
        return
    
    print("\n🔄 Converting...")
    results = converter.batch_convert(str(dumps_dir), target_ext='.dmp', copy=False)
    
    if 'error' in results:
        print(f"❌ {results['error']}")
        return
    
    print(f"\n✅ Batch conversion complete!")
    print(f"   Total: {results['total']}")
    print(f"   Successful: {results['successful']}")
    print(f"   Failed: {results['failed']}")
    
    if results['failed'] > 0:
        print("\n❌ Failed conversions:")
        for conv in results['conversions']:
            if not conv['success']:
                print(f"   - {conv['file']}: {conv['message']}")

def main():
    print("\n" + "=" * 70)
    print("RAMDetect - RAM Acquisition Examples")
    print("=" * 70)
    
    examples = {
        '1': ('Basic RAM Acquisition', example_1_basic_acquisition),
        '2': ('Custom Output Path', example_2_custom_output_path),
        '3': ('Verify Latest Dump', example_3_verify_dump),
        '4': ('List All Dumps', example_4_list_all_dumps),
        '5': ('Show Dump Information', example_5_simple_metadata),
        '6': ('Generate JSON for Existing Dump', example_6_generate_metadata),
        '7': ('Convert OTHERS to DMP', example_7_convert_raw_to_dmp),
        '8': ('Batch Convert All Dumps', example_8_batch_convert),
        'all': ('Run All Examples (1-5)', None),
    }
    
    print("Available Examples:")
    for key, (desc, _) in examples.items():
        if key != 'all':
            print(f"  {key}. {desc}")
    print("  all. Run All Examples")
    print("  q. Quit")
    
    choice = input("\nSelect example (1-6, all, q): ").strip().lower()
    
    if choice == 'q':
        print("Goodbye!")
        return
    
    if choice == 'all':
        for key, (_, func) in examples.items():
            if key != 'all' and func:
                # Skip 6 in 'all' run as it is interactive
                if key == '6': continue
                if not is_admin() and key in ['1', '2']: continue
                func()
    elif choice in examples:
        _, func = examples[choice]
        if func:
            func()
    else:
        print("Invalid selection")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
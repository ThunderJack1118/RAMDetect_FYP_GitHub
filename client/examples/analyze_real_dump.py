"""
tests/analyze_real_dump.py
===========================
Analyze REAL RAM dumps using RAMDetect feature extraction.

Features:
- Auto-detects dump files (Deduplicated)
- Interactive selection menu
- Full parsing and feature extraction pipeline

Usage:
    python tests/analyze_real_dump.py
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# ============================================================================
# PATH SETUP
# ============================================================================
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# ============================================================================
# IMPORTS
# ============================================================================
try:
    from ramdetect.features.feature_aggregator import FeatureAggregator
    from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
    from ramdetect.extraction.parsers.address_translator import AddressTranslator
    from ramdetect.extraction.parsers.eprocess_scanner import EProcessScanner
    from ramdetect.utils.logger import get_logger
    
    print("✅ Successfully imported RAMDetect modules")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)


class RealDumpAnalyzer:
    """Analyzes real RAM dumps using RAMDetect parsers + feature extractors."""
    
    def __init__(self, dump_path: str, dtb: int, logger: logging.Logger):
        self.dump_path = Path(dump_path)
        self.dtb = dtb
        self.logger = logger
        
        if not self.dump_path.exists():
            raise FileNotFoundError(f"Dump file not found: {dump_path}")
        
        self.logger.info(f"Initialized analyzer for: {self.dump_path}")
        if self.dtb:
            self.logger.info(f"Target DTB: {self.dtb:#x}")
        else:
            self.logger.warning("Target DTB: Auto-Detect (Not fully guaranteed)")
    
    def parse_memory_dump(self) -> Dict[str, Any]:
        """Parse the RAM dump."""
        self.logger.info("="*70)
        self.logger.info("PHASE 1: Parsing Memory Dump")
        self.logger.info("="*70)
        
        parsed_data = {
            'processes': [], 'threads': [], 'dlls': [],
            'pe_files': [], 'handles': [], 'memory_regions': [],
            'injections': []
        }
        
        try:
            # 1. Initialize Reader
            self.logger.info("[1/3] Initializing Physical Memory Reader...")
            with PhysicalMemoryReader(str(self.dump_path)) as reader:
                
                # 2. Initialize Translator
                self.logger.info(f"[2/3] Initializing Address Translator...")
                translator = AddressTranslator(reader, self.dtb)
                
                # 3. Scan Processes
                self.logger.info("[3/3] Scanning EPROCESS structures...")
                eprocess_scanner = EProcessScanner(reader, translator)
                
                processes = eprocess_scanner.find_all_processes()
                parsed_data['processes'] = processes
                self.logger.info(f"✓ Found {len(processes)} processes")
                
            self.logger.info("PHASE 1 COMPLETE: Memory Parsing")
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Memory parsing failed: {str(e)}", exc_info=True)
            raise
    
    def analyze(self, export_csv: bool = False, export_json: bool = False):
        try:
            # Parse
            parsed_data = self.parse_memory_dump()
            
            # Extract
            self.logger.info("\n" + "="*70)
            self.logger.info("PHASE 2: Feature Extraction")
            self.logger.info("="*70)
            
            aggregator = FeatureAggregator(logger=self.logger)
            features = aggregator.extract_all_features(parsed_data)
            
            # Export
            if export_csv or export_json:
                output_dir = Path("output/real_dump_analysis")
                output_dir.mkdir(parents=True, exist_ok=True)
                dump_name = self.dump_path.stem
                
                aggregator.feature_vector = features
                aggregator.metadata['total_features'] = len(features)
                
                if export_csv:
                    csv_path = output_dir / f"{dump_name}_features.csv"
                    aggregator.export_to_csv(str(csv_path))
                    self.logger.info(f"Exported CSV: {csv_path}")
                
                if export_json:
                    json_path = output_dir / f"{dump_name}_features.json"
                    aggregator.export_to_json(str(json_path))
                    self.logger.info(f"Exported JSON: {json_path}")

            aggregator.print_summary()
            return features
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            raise

# ============================================================================
# FILE SELECTION LOGIC (FIXED)
# ============================================================================
def find_dump_files() -> List[Path]:
    """Search common directories for memory dumps."""
    search_paths = [
        Path("dumps"),
        project_root / "dumps",
        Path(r"C:\Users\annsi\Downloads\RAMDetect_test\dumps")
    ]
    
    extensions = ["*.raw", "*.dmp", "*.mem"]
    
    # FIX: Use a set of STRINGS (absolute paths) to prevent duplicates
    found_paths_set = set()
    found_files_list = []
    
    for path in search_paths:
        if path.exists():
            for ext in extensions:
                for f in path.glob(ext):
                    # Resolve to absolute path to ensure uniqueness
                    abs_path = f.resolve()
                    
                    if str(abs_path) not in found_paths_set:
                        found_paths_set.add(str(abs_path))
                        found_files_list.append(abs_path)
    
    return sorted(found_files_list)

def select_dump_file_interactively() -> Optional[Path]:
    """Present a menu to the user to select a dump file."""
    files = find_dump_files()
    
    if not files:
        print("\n❌ No dump files found in 'dumps/' or configured paths.")
        print("   Please place a .raw, .dmp, or .mem file in the 'dumps' folder.")
        return None
        
    print("\n🔎 Found Memory Dumps:")
    print("="*60)
    for i, f in enumerate(files, 1):
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"  [{i}] {f.name:<30} ({size_mb:.1f} MB)")
        print(f"      Path: {f.parent}")
    print("="*60)
    
    while True:
        try:
            selection = input(f"\nSelect a file [1-{len(files)}] (or 'q' to quit): ").strip()
            if selection.lower() == 'q':
                return None
            
            idx = int(selection) - 1
            if 0 <= idx < len(files):
                return files[idx]
            else:
                print("❌ Invalid selection. Try again.")
        except ValueError:
            print("❌ Please enter a number.")

# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Analyze real RAM dumps with RAMDetect")
    parser.add_argument('dump_path', nargs='?', type=str, help='Path to RAM dump file')
    parser.add_argument('--dtb', type=str, default="0", help='Directory Table Base (Hex)')
    parser.add_argument('--export-csv', action='store_true')
    parser.add_argument('--export-json', action='store_true')
    
    args = parser.parse_args()
    logger = get_logger("RAMDetect_CLI")

    # 1. Determine Dump Path
    target_path = None
    
    if args.dump_path:
        target_path = Path(args.dump_path)
        if not target_path.exists():
            print(f"❌ Error: File not found: {target_path}")
            return 1
    else:
        target_path = select_dump_file_interactively()
        if not target_path:
            return 0 

    # 2. Parse DTB
    try:
        dtb_val = int(args.dtb, 16)
    except ValueError:
        print("❌ Error: DTB must be a hex value (e.g., 0x1ae000)")
        return 1

    print("\n" + "="*70)
    print(f"🚀 STARTING ANALYSIS: {target_path.name}")
    print("="*70)

    try:
        analyzer = RealDumpAnalyzer(str(target_path), dtb_val, logger)
        analyzer.analyze(export_csv=args.export_csv, export_json=args.export_json)
        return 0
    except Exception as e:
        print(f"\n❌ Critical Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
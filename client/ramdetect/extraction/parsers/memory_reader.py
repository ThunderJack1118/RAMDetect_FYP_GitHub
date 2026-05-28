"""
ramdetect/extraction/parsers/memory_reader.py
=============================================
Hybrid Memory Reader
- RAW: Fast mmap
- CRASH DUMP: Heuristic Header Hunter (Finds the table wherever it hides)
"""

import mmap
import struct
from pathlib import Path
from typing import Union, List

from ramdetect.utils.logger import get_logger

class PhysicalMemoryReader:
    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path).resolve()
        self.logger = get_logger(__name__)
        self.file_handle = None
        self.mmap_obj = None
        self.file_size = 0
        self.mode = "UNKNOWN"
        self.runs = []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        if not self.file_path.exists():
            raise FileNotFoundError(f"Dump file not found: {self.file_path}")
            
        self.file_size = self.file_path.stat().st_size
        
        # 1. Check Magic Bytes to distinguish Raw vs Crash Dump
        try:
            with open(self.file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"PAGEDU") or header.startswith(b"PAGE"):
                    self._init_manual_dump_mode()
                else:
                    self._init_raw_mode()
        except Exception as e:
            self.logger.warning(f"Header check failed: {e}")
            self._init_raw_mode()

    def _init_raw_mode(self):
        """Standard raw file mode. Maps file 1:1 with physical memory."""
        self.mode = "RAW"
        # Uses memory mapping (mmap) for high-performance reading
        self.logger.info(f"Opening as RAW Memory: {self.file_path.name}")
        self.file_handle = open(self.file_path, "rb")
        self.mmap_obj = mmap.mmap(self.file_handle.fileno(), 0, access=mmap.ACCESS_READ)

    def _init_manual_dump_mode(self):
        """
        Parsing logic for Microsoft Crash Dumps.
        These files are sparse; a header describes where physical pages are stored in the file.
        Uses heuristics to find the _PHYSICAL_MEMORY_DESCRIPTOR if the header isn't standard.
        """
        self.mode = "MANUAL_DUMP"
        self.logger.info(f"Opening as CRASH DUMP (Heuristic Mode): {self.file_path.name}")
        
        self.file_handle = open(self.file_path, "rb")
        
        # Read 16KB header to be safe
        header = self.file_handle.read(0x4000)
        
        # We know Total Pages * 4096 should be roughly File Size (minus header overhead)
        target_pages_min = (self.file_size * 0.9) // 4096
        target_pages_max = (self.file_size * 1.0) // 4096
        
        self.logger.info(f"    Hunting for Page Count between {target_pages_min} and {target_pages_max}...")
        
        valid_offset = None
        runs_count = 0
        
        # Scan aligned offsets
        for offset in range(0, 0x2000, 4):
            try:
                candidate_runs = struct.unpack_from("<I", header, offset)[0]
                candidate_pages = struct.unpack_from("<Q", header, offset + 8)[0]
                
                if target_pages_min <= candidate_pages <= target_pages_max:
                    if 0 < candidate_runs < 100:
                        self.logger.info(f"    🎯 MATCH at offset {offset:#x}!")
                        self.logger.info(f"       Runs: {candidate_runs}")
                        self.logger.info(f"       Pages: {candidate_pages} (Matches file size)")
                        
                        valid_offset = offset
                        runs_count = candidate_runs
                        break
            except:
                continue

        if valid_offset is not None:
            # Parse the runs
            run_array_offset = valid_offset + 16
            current_file_offset = 0x2000 # Standard data start
            
            for i in range(runs_count):
                base_page, page_count = struct.unpack_from("<QQ", header, run_array_offset)

                # Populate 'self.runs' list which maps Physical Addr Ranges -> File Offsets
                start_phys = base_page * 4096
                end_phys = (base_page + page_count) * 4096
                # ... [Parse Run array] ...
                self.runs.append({
                    'start': start_phys,
                    'end': end_phys,
                    'file_offset': current_file_offset,
                    'length': page_count * 4096
                })
                
                if i < 3:
                     self.logger.info(f"      Run {i}: Phys {start_phys:#x}-{end_phys:#x}")
                
                current_file_offset += (page_count * 4096)
                run_array_offset += 16
                
            self.logger.info("    ✅ Memory Map Built Successfully")
            
        else:
            self.logger.error("    ❌ Heuristic scan failed. Could not find memory map.")
            self.logger.warning("    Falling back to RAW mode.")
            self._init_raw_mode()

    def close(self):
        if self.mmap_obj:
            self.mmap_obj.close()
            self.mmap_obj = None
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        self.logger.info("Memory reader closed")

    def read_physical(self, offset: int, size: int) -> bytes:
        """
        Reads bytes from 'Physical' offset.
        If Crash Dump: Translates physical offset to file offset using the Runs map.
        If Raw: Reads directly.
        """
        if self.mode == "RAW":
            # Direct slice access on mmap
            if offset + size > self.file_size: return b""
            return self.mmap_obj[offset : offset + size]
            
        elif self.mode == "MANUAL_DUMP":
            # Iterate through runs to find which block contains the requested address
            for run in self.runs:
                if run['start'] <= offset < run['end']:
                    offset_in_run = offset - run['start']
                    file_pos = run['file_offset'] + offset_in_run
                    
                    if offset_in_run + size > run['length']:
                        read_len = run['length'] - offset_in_run
                    else:
                        read_len = size
                        
                    self.file_handle.seek(file_pos)
                    return self.file_handle.read(read_len)
            return b"\x00" * size
        return b""

    def read_uint64(self, offset: int) -> int:
        data = self.read_physical(offset, 8)
        if len(data) < 8: return 0
        return int.from_bytes(data, byteorder='little', signed=False)
        
    def read_uint32(self, offset: int) -> int:
        data = self.read_physical(offset, 4)
        if len(data) < 4: return 0
        return int.from_bytes(data, byteorder='little', signed=False)
        
    def read_uint16(self, offset: int) -> int:
        data = self.read_physical(offset, 2)
        if len(data) < 2: return 0
        return int.from_bytes(data, byteorder='little', signed=False)

    def scan_pattern(self, pattern: bytes, start_offset: int = 0, max_len: int = None, alignment: int = 0x1000) -> List[int]:
        """
        Scans physical memory for a byte pattern.
        
        Args:
            pattern: The byte sequence to find (e.g., b'MZ')
            start_offset: Physical address to start searching
            max_len: How many bytes to scan (default: entire file)
            alignment: Only accept matches aligned to this boundary (default: 4KB page)
            
        Returns:
            List of physical addresses where the pattern was found.
        """
        matches = []
        chunk_size = 1024 * 1024  # Read 1MB at a time
        
        # Determine actual file size if not set properly
        total_size = self.file_size
        if max_len is None:
            max_len = total_size - start_offset
            
        current_offset = start_offset
        end_offset = start_offset + max_len
        
        self.logger.info(f"Scanning {max_len // (1024*1024)}MB for pattern {pattern}...")
        
        try:
            # Ensure we are at start
            if self.mode == "RAW":
                self.mmap_obj.seek(current_offset)
            else:
                # For manual dump, seeking is complex, we will just iterate chunks
                pass
                
            while current_offset < end_offset:
                # Calculate read size
                bytes_to_read = min(chunk_size, end_offset - current_offset)
                
                # Use read_physical to handle the "Runs" logic automatically
                data = self.read_physical(current_offset, bytes_to_read)
                
                if not data:
                    break
                
                # Search in current chunk
                buffer_offset = 0
                while True:
                    found_index = data.find(pattern, buffer_offset)
                    if found_index == -1:
                        break
                    
                    # Calculate absolute physical address
                    phys_addr = current_offset + found_index
                    
                    # Check alignment (PE headers always align to 0x1000 in RAM)
                    if alignment == 0 or (phys_addr % alignment == 0):
                        matches.append(phys_addr)
                    
                    # Move past this match
                    buffer_offset = found_index + 1
                
                current_offset += len(data)
                
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            
        return matches
#!/usr/bin/env python3
"""
Windows Crash Dump KDBG Scanner
Scans crash dump files for Kernel Debugger Data Block structures
"""

import struct
import sys
import os
from pathlib import Path

class KDBGScanner:
    """Scanner for KDBG structures in Windows crash dumps"""
    
    # KDBG signature patterns for different Windows versions
    KDBG_SIGNATURES = [
        b'KDBG',  # Standard signature
        b'\x00\x00\x00\x00\x00\x00\x00\x00KDBG',  # With padding
    ]
    
    # Known KDBG owner tag values
    OWNER_TAGS = [0x4742444B]  # 'KDBG' in little-endian
    
    def __init__(self, dump_path):
        self.dump_path = Path(dump_path)
        self.file_size = 0
        self.kdbg_candidates = []
        
    def validate_dump(self):
        """Validate the crash dump file"""
        if not self.dump_path.exists():
            raise FileNotFoundError(f"Dump file not found: {self.dump_path}")
        
        self.file_size = self.dump_path.stat().st_size
        
        if self.file_size < 0x1000:  # Minimum reasonable size
            raise ValueError(f"File too small to be a valid crash dump: {self.file_size} bytes")
        
        # Check for common crash dump headers
        with open(self.dump_path, 'rb') as f:
            header = f.read(8)
            
            # Check for PAGEDUMP signature (0x45474150 = 'PAGE')
            if header[:4] == b'PAGE' or header[:4] == b'DU64':
                print(f"[+] Detected crash dump format")
                return True
            else:
                print(f"[!] Warning: Unknown header format, attempting scan anyway...")
                return True
    
    def read_chunk(self, f, offset, size=0x1000):
        """Read a chunk of data from the dump file"""
        f.seek(offset)
        return f.read(size)
    
    def validate_kdbg_structure(self, data, offset):
        """Validate potential KDBG structure"""
        try:
            if len(data) < 0x300:  # Minimum KDBG structure size
                return False
            
            # Check for reasonable pointer values (kernel space addresses)
            # Typical kernel space: 0xFFFF8000_00000000 on x64, 0x80000000 on x86
            ptr_offset = 0x10
            if len(data) >= ptr_offset + 8:
                ptr_val = struct.unpack('<Q', data[ptr_offset:ptr_offset+8])[0]
                
                # Check if it looks like a kernel pointer
                if ptr_val > 0xFFFF800000000000 or (0x80000000 < ptr_val < 0xFFFFFFFF):
                    return True
                
            return False
        except:
            return False
    
    def scan_for_kdbg(self):
        """Scan the dump file for KDBG structures"""
        print(f"[*] Scanning {self.dump_path}")
        print(f"[*] File size: {self.file_size:,} bytes")
        print("[*] Searching for KDBG signatures...")
        
        chunk_size = 0x100000  # 1MB chunks
        overlap = 0x1000  # Overlap to catch structures spanning chunks
        
        with open(self.dump_path, 'rb') as f:
            offset = 0
            
            while offset < self.file_size:
                # Update progress
                progress = (offset / self.file_size) * 100
                print(f"\r[*] Progress: {progress:.1f}%", end='', flush=True)
                
                # Read chunk with overlap
                chunk = self.read_chunk(f, offset, chunk_size + overlap)
                
                if not chunk:
                    break
                
                # Search for KDBG signatures
                for sig in self.KDBG_SIGNATURES:
                    pos = 0
                    while True:
                        pos = chunk.find(sig, pos)
                        if pos == -1:
                            break
                        
                        actual_offset = offset + pos
                        
                        # Extract surrounding data for validation
                        start = max(0, pos - 0x20)
                        end = min(len(chunk), pos + 0x300)
                        context = chunk[start:end]
                        
                        if self.validate_kdbg_structure(context, actual_offset):
                            self.kdbg_candidates.append({
                                'offset': actual_offset,
                                'signature': sig,
                                'context': context[:0x100]
                            })
                        
                        pos += len(sig)
                
                offset += chunk_size
        
        print("\n[*] Scan complete!")
        return self.kdbg_candidates
    
    def display_results(self):
        """Display scan results"""
        if not self.kdbg_candidates:
            print("\n[-] No KDBG structures found")
            return
        
        print(f"\n[+] Found {len(self.kdbg_candidates)} potential KDBG structure(s):\n")
        
        for idx, candidate in enumerate(self.kdbg_candidates, 1):
            print(f"Candidate #{idx}:")
            print(f"  Offset: 0x{candidate['offset']:08X} ({candidate['offset']:,} bytes)")
            print(f"  Signature: {candidate['signature']}")
            
            # Display hex dump of first 64 bytes
            print(f"  Data preview:")
            data = candidate['context'][:64]
            for i in range(0, len(data), 16):
                hex_str = ' '.join(f'{b:02X}' for b in data[i:i+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
                print(f"    {i:04X}: {hex_str:<48} {ascii_str}")
            print()
    
    def export_results(self, output_file):
        """Export results to a text file"""
        with open(output_file, 'w') as f:
            f.write(f"KDBG Scan Results\n")
            f.write(f"Dump File: {self.dump_path}\n")
            f.write(f"File Size: {self.file_size:,} bytes\n")
            f.write(f"Candidates Found: {len(self.kdbg_candidates)}\n")
            f.write("=" * 80 + "\n\n")
            
            for idx, candidate in enumerate(self.kdbg_candidates, 1):
                f.write(f"Candidate #{idx}:\n")
                f.write(f"  Offset: 0x{candidate['offset']:08X}\n")
                f.write(f"  Signature: {candidate['signature']}\n\n")
        
        print(f"[+] Results exported to {output_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python kdbg_scanner.py <crash_dump_file> [output_file]")
        print("\nExample:")
        print("  python kdbg_scanner.py memory.dmp")
        print("  python kdbg_scanner.py memory.dmp results.txt")
        sys.exit(1)
    
    dump_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        scanner = KDBGScanner(dump_file)
        
        # Validate dump file
        scanner.validate_dump()
        
        # Perform scan
        scanner.scan_for_kdbg()
        
        # Display results
        scanner.display_results()
        
        # Export if requested
        if output_file:
            scanner.export_results(output_file)
        
        # Provide next steps
        if scanner.kdbg_candidates:
            print("\n[*] Next steps:")
            print("  - Use the offset(s) with Volatility framework for deeper analysis")
            print("  - Example: volatility -f memory.dmp --kdbg=0x<offset> pslist")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
tools/measure_offset.py
=======================
The Ruler.
Finds "System" string and measures the exact distance to PID 4.
This solves the version conflict by measuring the file directly.
"""
import sys
import struct

def measure_offset(dump_path):
    print(f"\n📏 MEASURING OFFSET DISTANCE")
    print(f"   Target: {dump_path}")
    print("-" * 60)
    
    target_name = b"System\x00"
    
    with open(dump_path, "rb") as f:
        # Scan first 4GB
        MAX_SCAN = 4 * 1024 * 1024 * 1024
        CHUNK_SIZE = 16 * 1024 * 1024
        
        offset = 0
        while offset < MAX_SCAN:
            chunk = f.read(CHUNK_SIZE)
            if not chunk: break
            
            search_idx = 0
            while True:
                # 1. Find "System"
                idx = chunk.find(target_name, search_idx)
                if idx == -1: break
                
                name_abs = offset + idx
                
                # 2. Look backwards up to 1000 bytes for PID 4
                # We scan every 4 bytes alignment
                found = False
                for delta in range(0, 1000, 4):
                    check_idx = idx - delta
                    if check_idx >= 0:
                        try:
                            # Read 64-bit value
                            val = struct.unpack("<Q", chunk[check_idx:check_idx+8])[0]
                            if val == 4:
                                # Candidate found!
                                # Check for a valid pointer at PID+8 (ActiveProcessLinks) to confirm
                                if check_idx + 16 < len(chunk):
                                    flink = struct.unpack("<Q", chunk[check_idx+8:check_idx+16])[0]
                                    # Flink should be a kernel pointer (huge number)
                                    if flink > 0xffff000000000000:
                                        print(f"   🎯 MATCH FOUND!")
                                        print(f"      Name Location: {name_abs:#x}")
                                        print(f"      PID Location:  {offset + check_idx:#x}")
                                        print(f"      DISTANCE:      {delta:#x} (Hex)")
                                        print("-" * 60)
                                        return
                        except:
                            pass
                
                search_idx = idx + 1
            
            offset += CHUNK_SIZE
            print(f"   Scanning... {offset // (1024*1024)} MB", end="\r")

    print("\n❌ Could not find System PID 4 nearby any 'System' string.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/measure_offset.py <dump_file>")
    else:
        measure_offset(sys.argv[1])
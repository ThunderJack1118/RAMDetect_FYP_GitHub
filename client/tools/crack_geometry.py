"""
tools/crack_geometry.py
=======================
The "Geometry Cracker"
Uses the Trusted DTB (from DumpIt) to find the True System Process
and calculate the exact EPROCESS offsets for this specific build.
"""
import sys
import struct

def scan_for_geometry(dump_path, target_dtb):
    print(f"\n📐 GEOMETRY CRACKER")
    print(f"   Target: {dump_path}")
    print(f"   Trusted DTB: {target_dtb:#x}")
    print("-" * 60)
    
    # We search for the DTB. 
    # NOTE: In memory, the lower 12 bits might be used for PCID.
    # So 0x1ae000 might appear as 0x1ae002.
    # We search for the upper 52 bits.
    
    target_page = target_dtb >> 12
    
    with open(dump_path, "rb") as f:
        # Scan first 8GB
        chunk_size = 32 * 1024 * 1024
        limit = 8 * 1024 * 1024 * 1024
        offset = 0
        
        candidates = []
        
        while offset < limit:
            chunk = f.read(chunk_size)
            if not chunk: break
            
            # Helper to read u64 from chunk
            def get_u64(pos):
                if 0 <= pos < len(chunk) - 8:
                    return struct.unpack("<Q", chunk[pos:pos+8])[0]
                return 0

            # Scan 8-byte aligned
            for i in range(0, len(chunk), 8):
                val = struct.unpack("<Q", chunk[i:i+8])[0]
                
                # Check if this value is our DTB (ignoring lower 12 bits)
                if (val >> 12) == target_page:
                    # FOUND THE DTB! 
                    # Now assume this is KPROCESS.DirectoryTableBase (Offset 0x28)
                    # Let's verify by finding PID 4 and Name "System" relative to this.
                    
                    dtb_loc = offset + i
                    
                    # Hypotheses to check:
                    # 1. Compact (24H2): PID is at DTB + 0x1A8 (0x1d0 - 0x28)
                    # 2. Standard:       PID is at DTB + 0x418 (0x440 - 0x28)
                    
                    # Check Compact
                    pid_compact = get_u64(i + 0x1A8)
                    # Check Standard
                    pid_std = get_u64(i + 0x418)
                    
                    detected_profile = None
                    pid_offset_found = 0
                    
                    if pid_compact == 4:
                        detected_profile = "Compact (24H2)"
                        pid_offset_found = 0x1d0
                        name_check_dist = 0x338 - 0x28 # 0x310
                    elif pid_std == 4:
                        detected_profile = "Standard"
                        pid_offset_found = 0x440
                        name_check_dist = 0x5a8 - 0x28 # 0x580
                    
                    if detected_profile:
                        # Verify Name "System"
                        name_idx = i + name_check_dist
                        if name_idx + 6 < len(chunk):
                            name_bytes = chunk[name_idx : name_idx+15]
                            if b"System" in name_bytes:
                                print(f"   🎯 CRACKED!")
                                print(f"      DTB Location: {dtb_loc:#x}")
                                print(f"      Profile:      {detected_profile}")
                                print("-" * 40)
                                print(f"      [OFFSETS FOR CONFIG]")
                                print(f"      PID Offset:   0x{pid_offset_found:x}")
                                print(f"      DTB Offset:   0x28")
                                print(f"      Name Offset:  0x{pid_offset_found + 0x168:x}") # Standard dist
                                print("-" * 40)
                                return

            offset += chunk_size
            print(f"   Scanning... {offset // (1024*1024)} MB", end="\r")

    print("\n❌ Failed to crack geometry using the Trusted DTB.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tools/crack_geometry.py <dump_file> <dtb_hex>")
    else:
        scan_for_geometry(sys.argv[1], int(sys.argv[2], 16))
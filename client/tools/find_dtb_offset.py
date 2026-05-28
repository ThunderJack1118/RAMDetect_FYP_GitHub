"""
tools/find_offsets_brute.py
===========================
Offset Geometry Hunter
Ignores profiles. Scans raw memory to find the relative distances
between PID (4), Name ("System"), and DTB (0x1ae000).
"""
import sys
import struct

def brute_force_offsets(dump_path, known_dtb):
    print(f"\n🔍 BRUTE FORCE OFFSET HUNTER")
    print(f"   Target: {dump_path}")
    print(f"   Anchor DTB: {known_dtb:#x}")
    print("-" * 60)
    
    target_name = b"System\x00"
    dtb_pattern = struct.pack("<Q", known_dtb)
    
    with open(dump_path, "rb") as f:
        # Scan first 8GB (System is usually early, but let's be safe)
        chunk_size = 32 * 1024 * 1024
        limit = 8 * 1024 * 1024 * 1024
        
        offset = 0
        while offset < limit:
            chunk = f.read(chunk_size)
            if not chunk: break
            
            # Strategy: Find "System" string first (it's the most unique text)
            search_idx = 0
            while True:
                name_idx = chunk.find(target_name, search_idx)
                if name_idx == -1: break
                
                # We found "System". Now let's look backwards for PID 4.
                # Standard distance is ~0x168, but we search a range: 0x0 to 0x1000
                
                start_scan = max(0, name_idx - 0x600)
                
                # 1. Look for PID 4 in this window
                for p_idx in range(start_scan, name_idx, 4): # 4-byte alignment
                    try:
                        val = struct.unpack("<Q", chunk[p_idx:p_idx+8])[0]
                        if val == 4:
                            # Candidate PID Found!
                            # Now look for the DTB (0x1ae000) BEFORE the PID.
                            # Standard dist is ~0x400 before PID. We search 0x800 range.
                            
                            pid_abs = offset + p_idx
                            name_abs = offset + name_idx
                            
                            dtb_search_start = max(0, p_idx - 0x800)
                            dtb_search_end = p_idx # DTB is usually before PID
                            
                            sub_chunk = chunk[dtb_search_start:dtb_search_end]
                            dtb_match = sub_chunk.find(dtb_pattern)
                            
                            if dtb_match != -1:
                                # TRIANGULATION SUCCESS!
                                dtb_rel_pos = dtb_search_start + dtb_match
                                dtb_abs = offset + dtb_rel_pos
                                
                                # Calculate Distances relative to PID
                                dist_name = name_abs - pid_abs
                                dist_dtb = dtb_abs - pid_abs # Should be negative
                                
                                print(f"   🎯 MATCH FOUND!")
                                print(f"      PID (4) Location: {pid_abs:#x}")
                                print(f"      [Offsets Relative to PID]")
                                print(f"      Name Offset:      +0x{dist_name:x}")
                                print(f"      DTB Offset:       -0x{abs(dist_dtb):x} (or 0x{dist_dtb & 0xFFFFFFFFFFFFFFFF:x})")
                                print("-" * 60)
                                print(f"      [CONFIG FOR SCANNER]")
                                print(f"      'UniqueProcessId': 0,")
                                print(f"      'ImageFileName': 0x{dist_name:x},")
                                print(f"      'DirectoryTableBase': -0x{abs(dist_dtb):x},")
                                print("-" * 60)
                                return
                    except:
                        pass
                
                search_idx = name_idx + 1
            
            offset += chunk_size
            print(f"   Scanning... {offset // (1024*1024)} MB", end="\r")

    print("\n❌ Could not find the pattern. The DTB might be virtual or scrambled.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python tools/find_offsets_brute.py <dump_file> <dtb_hex>")
    else:
        brute_force_offsets(sys.argv[1], int(sys.argv[2], 16))
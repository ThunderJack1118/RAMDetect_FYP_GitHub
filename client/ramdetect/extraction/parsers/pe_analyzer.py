"""
ramdetect/extraction/parsers/pe_analyzer.py
===========================================
PE Analyzer - Header analysis and anomaly detection.
"""

from typing import Dict
import struct

try:
    import pefile
except ImportError:
    pefile = None

class PEAnalyzer:
    def __init__(self, memory_reader, translator=None):
        self.memory = memory_reader
        self.translator = translator

        # [LOG] Initialization status
        if pefile:
            self.logger.info("PEAnalyzer initialized (pefile available)")
        else:
            self.logger.warning("PEAnalyzer initialized but 'pefile' module is missing. Advanced features disabled.")

    def is_valid_pe(self, base_address: int, use_virtual: bool = False) -> bool:
        """Quick check for MZ and PE signature."""
        try:
            # 1. Read the first 0x200 bytes (DOS Header)
            if use_virtual and self.translator:
                header = self.translator.read_virtual(base_address, 0x200)
            else:
                header = self.memory.read_physical(base_address, 0x200)
            
            if not header or len(header) < 0x100: return False

            # 2. Check for DOS Signature 'MZ' (0x5A4D)
            if header[:2] != b'MZ': return False
            
            # 3. Read e_lfanew (Offset to PE header) at offset 0x3C
            e_lfanew = struct.unpack('<I', header[60:64])[0]
            if e_lfanew > 0x200: 
                # [LOG] Debug info for malformed headers
                self.logger.debug(f"Invalid e_lfanew at 0x{base_address:x}: {e_lfanew}")
                return False
            
            # 4. Read PE Signature 'PE\0\0' (0x4550)
            if use_virtual and self.translator:
                sig = self.translator.read_virtual(base_address + e_lfanew, 4)
            else:
                sig = self.memory.read_physical(base_address + e_lfanew, 4)
                
            is_valid = (sig == b'PE\x00\x00')
            
            # [LOG] Log success for valid PE files found
            if is_valid:
                self.logger.info(f"Valid PE header found at 0x{base_address:x}")
                
            return is_valid
            
        except Exception as e:
            self.logger.debug(f"Error checking PE at 0x{base_address:x}: {e}")
            return False
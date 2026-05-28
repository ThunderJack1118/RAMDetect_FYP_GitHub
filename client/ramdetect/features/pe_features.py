"""
ramdetect/features/pe_features.py
=======================================================
Extracts 18 features from PE headers and sections to detect:
- RWX memory sections
- Import/Export anomalies
- PE header manipulation
- Packing indicators
- TLS callbacks and code caves

Author: RAMDetect Development Team
"""

from typing import Dict, List, Any
import time
import os
from .feature_base import FeatureExtractor # Relative import

class PEFeatures(FeatureExtractor):
    """
    Extract 18 PE-related features for malware detection.
    """
    
    # Suspicious API imports (commonly used by malware)
    SUSPICIOUS_IMPORTS = {
        'virtualallocex', 'virtualprotect', 'writeprocessmemory',
        'createremotethread', 'ntcreatethreadex', 'rtlcreateuserthread',
        'queueuserapc', 'setwindowshookex', 'keybd_event',
        'cryptencrypt', 'cryptdecrypt', 'internetopen', 'internetreadfile',
        'urldownloadtofile', 'shellexecute', 'winexec', 'process32first'
    }
    
    # Known packer sections
    PACKER_SECTIONS = {
        'upx0', 'upx1', 'upx2',  # UPX
        'aspack', 'adata',        # ASPack
        'pecompact', 'pec1', 'pec2',  # PECompact
        'themida', '.vmp0', '.vmp1',  # VMProtect/Themida
        'mpress1', 'mpress2',     # MPRESS
        'enigma1', 'enigma2'      # Enigma
    }
    
    # Standard PE sections
    STANDARD_SECTIONS = {'.text', '.data', '.rdata', '.idata', '.rsrc', '.reloc'}
    
    # Entropy threshold for packed sections
    HIGH_SECTION_ENTROPY = 7.0
    
    # Reasonable timestamp range (1990 - present)
    MIN_TIMESTAMP = 631152000  # Jan 1, 1990
    MAX_TIMESTAMP = int(time.time()) + 86400  # Tomorrow
    
    def __init__(self, logger=None):
        super().__init__(name="PEFeatures", logger=logger)
    
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract 18 PE features from parsed memory data.
        """
        # Historical versions expected parsed_data["pe_files"], but the live
        # native pipeline emits VAD/PE-section rows under "pe_sections" /
        # "memory_regions".  Normalize those rows into PE-like single-section
        # records so VAD evidence is not silently ignored.
        pe_files = self._normalize_pe_inputs(parsed_data)
        
        if not pe_files:
            self.logger.warning(f"[{self.name}] No PE/VAD rows found in parsed_data")
            return self._get_zero_features()
        
        total_pes = len(pe_files)
        features = {}
        
        # ===== CATEGORY 1: Section Analysis (5 features) =====
        features.update(self._extract_section_features(pe_files, total_pes))
        
        # ===== CATEGORY 2: Import/Export Anomalies (4 features) =====
        features.update(self._extract_import_export_features(pe_files, total_pes))
        
        # ===== CATEGORY 3: PE Header Anomalies (4 features) =====
        features.update(self._extract_header_features(pe_files, total_pes))
        
        # ===== CATEGORY 4: Packing Indicators (3 features) =====
        features.update(self._extract_packing_features(pe_files, total_pes))
        
        # ===== CATEGORY 5: Advanced Techniques (2 features) =====
        features.update(self._extract_advanced_features(pe_files, total_pes))
        
        return features
    
    @staticmethod
    def _coerce_int(value: Any, default: int = 0) -> int:
        """Accept int, decimal string, or hex string such as 0x1000."""
        try:
            if value is None:
                return default
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                return int(value)
            text = str(value).strip()
            if not text or text in {"-", "?", "None", "none", "N/A", "n/a"}:
                return default
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(float(text))
        except Exception:
            return default

    @staticmethod
    def _coerce_float(value: Any, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            text = str(value).strip()
            if not text or text in {"-", "?", "None", "none", "N/A", "n/a"}:
                return default
            return float(text)
        except Exception:
            return default

    @staticmethod
    def _protection_to_characteristics(protection: Any) -> int:
        """Convert VAD permission strings (RWX/RX/X) into PE section flags."""
        prot = str(protection or "").upper()
        flags = 0
        if "R" in prot or "READ" in prot:
            flags |= 0x40000000  # IMAGE_SCN_MEM_READ
        if "W" in prot or "WRITE" in prot:
            flags |= 0x80000000  # IMAGE_SCN_MEM_WRITE
        if "X" in prot or "EXECUTE" in prot:
            flags |= 0x20000000  # IMAGE_SCN_MEM_EXECUTE
        return flags

    def _normalize_pe_inputs(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize RAMDetect live VAD/PE-section rows into PE-like dictionaries.

        Existing PE analyzer rows with a `sections` list are preserved. VAD rows
        are converted to one PE-like item with one section.  This prevents the
        live pipeline from producing all-zero PEFeatures simply because the
        bridge stored VAD data under `pe_sections` instead of `pe_files`.
        """
        sources: List[Dict[str, Any]] = []
        for key in ("pe_files", "pe_sections", "memory_regions", "mapped_files", "vads"):
            value = parsed_data.get(key, []) or []
            if isinstance(value, list):
                sources.extend([x for x in value if isinstance(x, dict)])

        if not sources:
            return []

        normalized: List[Dict[str, Any]] = []
        seen = set()

        for row in sources:
            # Already a PE analyzer record.
            if isinstance(row.get("sections"), list):
                key = (row.get("path") or row.get("name") or id(row), len(row.get("sections") or []))
                if key not in seen:
                    seen.add(key)
                    normalized.append(row)
                continue

            name = (
                row.get("name") or row.get("section") or row.get("Section")
                or row.get("path") or row.get("Path") or row.get("type") or row.get("Type") or ""
            )
            path = str(row.get("path") or row.get("Path") or "")
            proc = str(row.get("process") or row.get("Process") or "")
            anomaly = str(row.get("anomaly") or row.get("Anomaly") or row.get("status_reason") or "")
            status = str(row.get("status") or row.get("Status") or "")
            protection = row.get("protection") or row.get("Permissions") or row.get("permissions") or ""
            vad_type = str(row.get("type") or row.get("vad_type") or row.get("Section") or "")
            lower_name = str(name).lower()
            lower_path = path.lower()

            # Keep PE-like and security-relevant rows only; avoid treating every
            # mapped data file as a PE header and creating noisy PE features.
            is_pe_like = any(ext in lower_name or ext in lower_path for ext in (".exe", ".dll", ".sys", ".ocx"))
            is_exec = "X" in str(protection).upper() or "EXECUTE" in str(protection).upper()
            is_alert = "suspicious" in status.lower() or "injection" in anomaly.lower()
            is_image = vad_type.lower() == "image"
            if not (is_pe_like or is_exec or is_alert or is_image):
                continue

            start = self._coerce_int(row.get("start") or row.get("base_address") or row.get("Virtual Addr"), 0)
            vsize = self._coerce_int(row.get("virtual_size") or row.get("size") or row.get("Virtual Size"), 0)
            raw_size = self._coerce_int(row.get("raw_size") or row.get("Raw Size"), vsize)
            entropy = self._coerce_float(row.get("entropy") or row.get("Entropy"), 0.0)
            chars = self._protection_to_characteristics(protection)

            section_name = os.path.basename(str(name).replace("\\", os.sep)).strip() or str(vad_type or "section")
            section = {
                "name": section_name,
                "characteristics": chars,
                "entropy": entropy,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "virtual_address": start,
                "code_caves": [],
            }

            norm = {
                "name": section_name,
                "path": path,
                "process": proc,
                "pid": row.get("pid") or row.get("PID"),
                "sections": [section],
                "imports": row.get("imports", {}) if isinstance(row.get("imports", {}), dict) else {},
                "exports": row.get("exports", []) if isinstance(row.get("exports", []), list) else [],
                "iat_rva": self._coerce_int(row.get("iat_rva"), 0),
                # Neutral defaults: these headers were not parsed from disk, so
                # do not falsely mark every VAD row as a bad timestamp/magic.
                "timestamp": int(time.time()),
                "magic": 0x20B,
                "subsystem": 2,
                "checksum_header": 0,
                "checksum_calculated": 0,
                "size_on_disk": raw_size,
                "size_of_image": vsize,
                "tls_callbacks": row.get("tls_callbacks", []),
            }

            key = (norm.get("pid"), norm.get("process"), norm.get("name"), start, vsize)
            if key not in seen:
                seen.add(key)
                normalized.append(norm)

        return normalized

    def _extract_section_features(self, pe_files: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to PE sections."""
        rwx_section_count = 0
        high_entropy_section_count = 0
        size_mismatch_count = 0
        unusual_section_name_count = 0
        zero_raw_size_count = 0
        
        for pe in pe_files:
            sections = pe.get('sections', [])
            
            for section in sections:
                section_name = section.get('name', '').lower().strip('\x00')
                characteristics = section.get('characteristics', 0)
                entropy = section.get('entropy', 0.0)
                virtual_size = section.get('virtual_size', 0)
                raw_size = section.get('raw_size', 0)
                
                # RWX (Read-Write-Execute) section - highly suspicious
                # IMAGE_SCN_MEM_READ (0x40000000) | WRITE (0x80000000) | EXECUTE (0x20000000)
                is_readable = characteristics & 0x40000000
                is_writable = characteristics & 0x80000000
                is_executable = characteristics & 0x20000000
                
                if is_readable and is_writable and is_executable:
                    rwx_section_count += 1
                
                # High entropy section (packed/encrypted)
                if entropy >= self.HIGH_SECTION_ENTROPY:
                    high_entropy_section_count += 1
                
                # Virtual size significantly different from raw size (packing indicator)
                # Size Mismatch: Virtual Size > Raw Size
                # Indicates data is compressed on disk (Raw) and expands in memory (Virtual).
                # A ratio > 3.0 is a strong indicator of Packing.
                if virtual_size > 0 and raw_size > 0:
                    ratio = max(virtual_size, raw_size) / min(virtual_size, raw_size)
                    if ratio > 3.0:  # More than 3x difference
                        size_mismatch_count += 1
                
                # Unusual section names (not standard)
                if section_name not in self.STANDARD_SECTIONS and section_name:
                    # Check if it's not a known packer section
                    if not any(packer in section_name for packer in self.PACKER_SECTIONS):
                        unusual_section_name_count += 1
                
                # Zero raw size but non-zero virtual size (unpacking stub)
                if raw_size == 0 and virtual_size > 0:
                    zero_raw_size_count += 1
        
        return {
            'rwx_section_count': self.normalize_count(rwx_section_count, max_threshold=2),
            'high_entropy_section_count': self.normalize_count(high_entropy_section_count, max_threshold=5),
            'section_size_mismatch_count': self.normalize_count(size_mismatch_count, max_threshold=3),
            'unusual_section_name_count': self.normalize_count(unusual_section_name_count, max_threshold=3),
            'zero_raw_size_section_count': self.normalize_count(zero_raw_size_count, max_threshold=2)
        }
    
    def _extract_import_export_features(self, pe_files: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to imports and exports."""
        """Analyzes the Import Address Table (IAT)."""
        suspicious_import_count = 0
        few_imports_count = 0
        forwarded_export_count = 0
        iat_in_unusual_section_count = 0
        
        for pe in pe_files:
            imports = pe.get('imports', {})
            exports = pe.get('exports', [])
            iat_rva = pe.get('iat_rva', 0)
            sections = pe.get('sections', [])
            
            # Count suspicious imports
            suspicious_apis_found = set()
            for dll_name, functions in imports.items():
                for func in functions:
                    func_lower = func.lower()
                    if func_lower in self.SUSPICIOUS_IMPORTS:
                        suspicious_apis_found.add(func_lower)
            
            if suspicious_apis_found:
                suspicious_import_count += len(suspicious_apis_found)
            
            # Few imports (obfuscation technique)
            # Packed malware often imports only 'GetProcAddress' and 'LoadLibrary'.
            total_imports = sum(len(funcs) for funcs in imports.values())
            if total_imports < 5 and total_imports > 0:
                few_imports_count += 1
            
            # Forwarded exports (can be used for hooking)
            for export in exports:
                if export.get('forwarded', False):
                    forwarded_export_count += 1
            
            # IAT in unusual section (should be in .idata or .rdata)
            if iat_rva > 0:
                iat_section = self._find_section_for_rva(iat_rva, sections)
                if iat_section:
                    section_name = iat_section.get('name', '').lower().strip('\x00')
                    if section_name not in ['.idata', '.rdata', '.data']:
                        iat_in_unusual_section_count += 1
        
        return {
            'suspicious_import_count': self.normalize_count(suspicious_import_count, max_threshold=10),
            'few_imports_pe_count': self.normalize_count(few_imports_count, max_threshold=2),
            'forwarded_export_count': self.normalize_count(forwarded_export_count, max_threshold=3),
            'iat_unusual_section_count': self.normalize_count(iat_in_unusual_section_count, max_threshold=2)
        }
    
    def _extract_header_features(self, pe_files: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to PE header anomalies."""
        invalid_timestamp_count = 0
        wrong_magic_count = 0
        unusual_subsystem_count = 0
        checksum_mismatch_count = 0
        
        for pe in pe_files:
            timestamp = pe.get('timestamp', 0)
            magic = pe.get('magic', 0)
            subsystem = pe.get('subsystem', 0)
            checksum_header = pe.get('checksum_header', 0)
            checksum_calculated = pe.get('checksum_calculated', 0)
            
            if timestamp < self.MIN_TIMESTAMP or timestamp > self.MAX_TIMESTAMP:
                invalid_timestamp_count += 1
            
            if magic not in [0x10b, 0x20b]:
                wrong_magic_count += 1
            
            # 2 = GUI, 3 = CUI (console)
            if subsystem not in [2, 3] and subsystem != 0:
                unusual_subsystem_count += 1
            
            if checksum_header != 0 and checksum_calculated != 0:
                if checksum_header != checksum_calculated:
                    checksum_mismatch_count += 1
        
        return {
            'invalid_timestamp_count': self.normalize_count(invalid_timestamp_count, max_threshold=2),
            'wrong_magic_count': self.normalize_count(wrong_magic_count, max_threshold=1),
            'unusual_subsystem_count': self.normalize_count(unusual_subsystem_count, max_threshold=2),
            'checksum_mismatch_count': self.normalize_count(checksum_mismatch_count, max_threshold=2)
        }
    
    def _extract_packing_features(self, pe_files: List[Dict], total: int) -> Dict[str, float]:
        """Extract features indicating executable packing."""
        known_packer_count = 0
        high_compression_ratio_count = 0
        packer_section_count = 0
        
        for pe in pe_files:
            packer_detected = pe.get('packer_detected', '')
            sections = pe.get('sections', [])
            size_of_image = pe.get('size_of_image', 0)
            size_on_disk = pe.get('size_on_disk', 0)
            
            if packer_detected:
                known_packer_count += 1
            
            if size_on_disk > 0 and size_of_image > 0:
                compression_ratio = size_of_image / size_on_disk
                if compression_ratio > 5.0:  # More than 5x expansion
                    high_compression_ratio_count += 1
            
            for section in sections:
                section_name = section.get('name', '').lower().strip('\x00')
                if any(packer in section_name for packer in self.PACKER_SECTIONS):
                    packer_section_count += 1
                    break 
        
        return {
            'known_packer_count': self.normalize_count(known_packer_count, max_threshold=3),
            'high_compression_ratio_count': self.normalize_count(high_compression_ratio_count, max_threshold=2),
            'packer_section_count': self.normalize_count(packer_section_count, max_threshold=3)
        }
    
    def _extract_advanced_features(self, pe_files: List[Dict], total: int) -> Dict[str, float]:
        """Extract advanced technique indicators."""
        tls_callback_count = 0
        code_cave_count = 0
        
        for pe in pe_files:
            tls_callbacks = pe.get('tls_callbacks', [])
            sections = pe.get('sections', [])
            
            if tls_callbacks:
                tls_callback_count += len(tls_callbacks)
            
            for section in sections:
                characteristics = section.get('characteristics', 0)
                is_executable = characteristics & 0x20000000
                
                if is_executable:
                    code_caves_found = section.get('code_caves', [])
                    if code_caves_found:
                        code_cave_count += len(code_caves_found)
        
        return {
            'tls_callback_count': self.normalize_count(tls_callback_count, max_threshold=2),
            'code_cave_count': self.normalize_count(code_cave_count, max_threshold=3)
        }
    
    def _find_section_for_rva(self, rva: int, sections: List[Dict]) -> Dict:
        """Find which section contains a given RVA."""
        for section in sections:
            virtual_address = section.get('virtual_address', 0)
            virtual_size = section.get('virtual_size', 0)
            
            if virtual_address <= rva < (virtual_address + virtual_size):
                return section
        return {}
    
    def _get_zero_features(self) -> Dict[str, float]:
        """Return all features set to 0.0 (for empty input)."""
        keys = [
            'rwx_section_count', 'high_entropy_section_count', 'section_size_mismatch_count',
            'unusual_section_name_count', 'zero_raw_size_section_count',
            'suspicious_import_count', 'few_imports_pe_count', 'forwarded_export_count',
            'iat_unusual_section_count',
            'invalid_timestamp_count', 'wrong_magic_count', 'unusual_subsystem_count',
            'checksum_mismatch_count',
            'known_packer_count', 'high_compression_ratio_count', 'packer_section_count',
            'tls_callback_count', 'code_cave_count'
        ]
        return {k: 0.0 for k in keys}
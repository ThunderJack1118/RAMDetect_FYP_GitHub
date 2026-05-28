"""
ramdetect/acquisition/metadata.py
==================================
Metadata management for RAM dumps
Features: Single-Pass Multi-Hashing (MD5 + SHA256) 🚀
"""

import json
import hashlib
import platform
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from ramdetect.utils.logger import get_logger
from ramdetect.utils.helpers import format_timestamp, save_json, load_json, format_bytes


def calculate_hashes(file_path: Path | str, algorithms: List[str] = ["md5", "sha256"]) -> Dict[str, str]:
    """
    Calculates multiple hashes in a SINGLE pass of the file.
    This is 2x faster than calculating them sequentially.
    """
    # Initialize all hashers
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    file_path = Path(file_path)
    
    # 4MB chunks for optimal disk IO
    chunk_size = 4 * 1024 * 1024 
    
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            for h in hashers.values():
                h.update(chunk)
    
    # Return dictionary of results
    return {algo: h.hexdigest() for algo, h in hashers.items()}


class MetadataManager:
    """
    Manages metadata for acquired RAM dumps
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def create_acquisition_metadata(self, 
                                  dump_path: Path, 
                                  tool: str, 
                                  duration: float, 
                                  extra_data: Optional[Dict[str, Any]] = None) -> Path:
        """
        Generates full forensic metadata for a newly acquired dump.
        :param extra_data: Dictionary of additional info (e.g., Cr3, Build Number)
        """
        self.logger.info(f"Generating forensic metadata for {dump_path.name}...")
        
        # 1. System Information
        sys_info = {
            'hostname': platform.node(),
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor()
        }
        
        # 2. File Statistics
        stat = dump_path.stat()
        dump_info = {
            'filename': dump_path.name,
            'path': str(dump_path.absolute()),
            'size_bytes': stat.st_size,
            'size_formatted': format_bytes(stat.st_size),
            'created': format_timestamp(stat.st_ctime),
            'modified': format_timestamp(stat.st_mtime)
        }
        
        # 3. Acquisition Details
        acq_info = {
            'tool': tool,
            'duration_seconds': round(duration, 2),
            'timestamp': format_timestamp(time.time()),
            'successful': True
        }
        
        # 4. Multi-Hashing (MD5 + SHA256)
        self.logger.info("⏳ Calculating MD5 & SHA256 (Single-pass)...")
        try:
            hashes = calculate_hashes(dump_path, ["md5", "sha256"])
            self.logger.info(f"   MD5:    {hashes['md5']}")
            self.logger.info(f"   SHA256: {hashes['sha256']}")
        except Exception as e:
            self.logger.error(f"Hashing failed: {e}")
            hashes = {"error": str(e)}
            
        # 5. Assemble & Save
        full_metadata = {
            'acquisition': acq_info,
            'system': sys_info,
            'dump': dump_info,
            'hashes': hashes
        }

        # MERGE EXTRA DATA (e.g., Kernel Info)
        if extra_data:
            full_metadata['kernel_info'] = extra_data
        
        return self.save(full_metadata, dump_path)

    def save(self, metadata: Dict[str, Any], dump_path: Path) -> Path:
        metadata_path = dump_path.with_suffix('.json')
        
        if 'metadata' not in metadata:
            metadata['metadata'] = {}
            
        metadata['metadata'].update({
            'version': '1.0',
            'saved_at': format_timestamp(),
            'format': 'json',
            'tool': 'RAMDetect'
        })
        
        save_json(metadata, metadata_path, indent=4)
        self.logger.info(f"✅ Metadata saved to: {metadata_path.name}")
        return metadata_path
    
    def load(self, dump_path: Path) -> Optional[Dict[str, Any]]:
        metadata_path = dump_path.with_suffix('.json')
        if not metadata_path.exists(): return None
        try:
            return load_json(metadata_path)
        except Exception:
            return None
    
    def update(self, dump_path: Path, updates: Dict[str, Any]):
        metadata = self.load(dump_path)
        if metadata is None: metadata = {}
        
        for key, value in updates.items():
            if key in metadata and isinstance(metadata[key], dict) and isinstance(value, dict):
                metadata[key].update(value)
            else:
                metadata[key] = value
        
        self.save(metadata, dump_path)



    def update_kernel_profile(self,
                              dump_path: Path | str,
                              build_number: int | str | None = None,
                              os_name: str | None = None,
                              version: str | None = None,
                              dtb_hex: str | int | None = None,
                              profile_source: str = "user_selected",
                              extra: Optional[Dict[str, Any]] = None) -> Path:
        """
        Create or update the JSON sidecar with Windows kernel/profile data.

        This is used when RAMDetect receives a raw-style dump (.raw/.vmem/.mem)
        that has no crash-dump header. The user-selected build number is saved
        into <dump_name>.json so the analysis pipeline can load the correct
        Windows offsets instead of falling back to a default profile.

        The values are written in two places for compatibility:
          1. metadata['kernel_info']       — canonical RAMDetect location
          2. top-level build_number/dtb    — fallback for older bridge code
        """
        dump_path = Path(dump_path)
        metadata = self.load(dump_path) or {}

        # Keep minimum forensic metadata shape if the JSON did not exist yet.
        if 'dump' not in metadata:
            try:
                stat = dump_path.stat()
                metadata['dump'] = {
                    'filename': dump_path.name,
                    'path': str(dump_path.absolute()),
                    'size_bytes': stat.st_size,
                    'size_formatted': format_bytes(stat.st_size),
                    'created': format_timestamp(stat.st_ctime),
                    'modified': format_timestamp(stat.st_mtime),
                }
            except Exception:
                metadata['dump'] = {
                    'filename': dump_path.name,
                    'path': str(dump_path.absolute()),
                }

        if 'acquisition' not in metadata:
            metadata['acquisition'] = {
                'tool': 'RAMDetect Manual Profile Update',
                'duration_seconds': 0.0,
                'timestamp': format_timestamp(time.time()),
                'successful': True,
            }

        kernel = metadata.get('kernel_info')
        if not isinstance(kernel, dict):
            kernel = {}

        # Normalize build number.
        if build_number not in (None, '', 'Auto', 'auto'):
            try:
                build_int = int(build_number)
                kernel['build_number'] = build_int
                metadata['build_number'] = build_int
            except (TypeError, ValueError):
                self.logger.warning(f"Invalid build_number ignored: {build_number}")

        if os_name:
            kernel['os'] = os_name
            metadata['os'] = os_name

        if version:
            kernel['version'] = version
            metadata['version'] = version

        # Normalize DTB/CR3. Accept either int or hex string.
        if dtb_hex not in (None, '', 'None'):
            try:
                if isinstance(dtb_hex, int):
                    dtb_int = dtb_hex
                    dtb_str = hex(dtb_int)
                else:
                    dtb_str = str(dtb_hex).strip()
                    dtb_int = int(dtb_str, 16) if dtb_str.lower().startswith('0x') else int(dtb_str)
                    dtb_str = hex(dtb_int)

                kernel['dtb'] = dtb_int
                kernel['cr3'] = dtb_int
                kernel['dtb_hex'] = dtb_str
                metadata['dtb'] = dtb_int
                metadata['cr3'] = dtb_int
                metadata['dtb_hex'] = dtb_str
            except (TypeError, ValueError):
                self.logger.warning(f"Invalid DTB/CR3 ignored: {dtb_hex}")

        kernel['profile_source'] = profile_source
        kernel['profile_updated_at'] = format_timestamp(time.time())

        if extra:
            for key, value in extra.items():
                if value is not None:
                    kernel[key] = value

        metadata['kernel_info'] = kernel
        return self.save(metadata, dump_path)

    def export_summary(self, dump_path: Path) -> str:
        """Generates a text summary for the CLI"""
        metadata = self.load(dump_path)
        if not metadata: return "No metadata found."
        
        lines = ["="*60, f"METADATA: {dump_path.name}", "="*60]
        
        # Show Kernel Info if available
        if 'kernel_info' in metadata:
            k = metadata['kernel_info']
            lines.append(f"DTB (Cr3): {k.get('dtb_hex', 'N/A')}")
            lines.append(f"Build:     {k.get('build_number', 'N/A')}")
            lines.append("-" * 60)

        if 'hashes' in metadata:
            for algo, val in metadata['hashes'].items():
                lines.append(f"{algo.upper():<8}: {val}")
                
        if 'acquisition' in metadata:
            acq = metadata['acquisition']
            lines.append(f"Acquired: {acq.get('timestamp')}")
            lines.append(f"Duration: {acq.get('duration_seconds')}s")

        return "\n".join(lines)
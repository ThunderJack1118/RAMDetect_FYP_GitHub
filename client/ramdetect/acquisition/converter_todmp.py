"""
Memory Dump Converter
Converts .raw, .mem, and .vmem memory dumps to .dmp format (and vice versa).
Handles file renaming and format validation.
"""

import os
import shutil
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime


class RawDumpConverter:
    """
    Converts memory dumps between raw formats (.raw, .mem, .vmem) and crash dump format (.dmp).
    Handles both simple renaming and crash dump detection.
    """
    
    def __init__(self):
        # Supported extensions for detection
        self.supported_extensions = ['.raw', '.dmp', '.mem', '.bin', '.vmem']
    
    def is_crash_dump(self, file_path: Path) -> bool:
        """
        Check if file is a Windows crash dump (has PAGEDUMP/KDMP header).
        """
        try:
            with open(file_path, 'rb') as f:
                signature = f.read(8)
                # Check for crash dump signatures
                if signature.startswith(b'PAGE') or signature.startswith(b'DUMP'):
                    return True
                # Check for other dump formats (Kernel Dump)
                if signature.startswith(b'KDMP'):
                    return True
            return False
        except Exception:
            return False
    
    def get_dump_info(self, file_path: Path) -> dict:
        """
        Get information about a dump file.
        """
        if not file_path.exists():
            return {'exists': False}
        
        stat = file_path.stat()
        is_crash = self.is_crash_dump(file_path)
        
        # Read signature safely
        try:
            with open(file_path, 'rb') as f:
                sig_bytes = f.read(16)
                signature = sig_bytes[:8].decode('ascii', errors='ignore')
        except:
            signature = "Unknown"
        
        return {
            'exists': True,
            'path': str(file_path.absolute()),
            'name': file_path.name,
            'size_bytes': stat.st_size,
            'size_gb': stat.st_size / (1024**3),
            'extension': file_path.suffix,
            'is_crash_dump': is_crash,
            'format': 'Crash Dump (PAGEDUMP)' if is_crash else 'Raw Memory',
            'signature': signature,
            'created': datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.fromtimestamp(stat.st_mtime),
        }
    
    def convert_raw_to_dmp(self, source_path: str, dmp_path: Optional[str] = None,
                           copy: bool = False) -> Tuple[bool, str, Optional[Path]]:
        """
        Convert .raw, .mem, or .vmem file to .dmp file.
        """
        source_file = Path(source_path)
        
        # Validate input
        if not source_file.exists():
            return False, f"File not found: {source_path}", None
        
        if source_file.suffix.lower() not in self.supported_extensions:
            return False, f"Unsupported file extension: {source_file.suffix}", None
        
        # Determine output path
        if dmp_path is None:
            dmp_file = source_file.with_suffix('.dmp')
        else:
            dmp_file = Path(dmp_path)
        
        # Check if output already exists
        if dmp_file.exists():
            return False, f"Output file already exists: {dmp_file}", None
        
        try:
            # Get dump info
            info = self.get_dump_info(source_file)
            
            # Perform conversion (copy or rename)
            if copy:
                print(f"[*] Copying {source_file.name} -> {dmp_file.name}")
                shutil.copy2(source_file, dmp_file)
                action = "copied"
            else:
                print(f"[*] Renaming {source_file.name} -> {dmp_file.name}")
                source_file.rename(dmp_file)
                action = "renamed"
            
            # Verify output
            if not dmp_file.exists():
                return False, "Conversion failed: output file not created", None
            
            msg = (f"Successfully {action} to {dmp_file.name}\n"
                   f"Original Format: {source_file.suffix}\n"
                   f"Size: {info['size_gb']:.2f} GB")
            
            return True, msg, dmp_file
            
        except Exception as e:
            return False, f"Conversion error: {e}", None
    
    def convert_dmp_to_raw(self, dmp_path: str, raw_path: Optional[str] = None,
                           copy: bool = False, output_ext: str = '.raw') -> Tuple[bool, str, Optional[Path]]:
        """
        Convert .dmp file to raw format (.raw, .mem, or .vmem).
        
        Args:
            dmp_path: Path to .dmp file
            raw_path: Output path
            copy: If True, copy file; if False, rename file
            output_ext: Target extension (.raw, .mem, .vmem)
        """
        dmp_file = Path(dmp_path)
        
        # Validate input
        if not dmp_file.exists():
            return False, f"File not found: {dmp_path}", None
            
        # Validate target extension
        if output_ext not in ['.raw', '.mem', '.vmem', '.bin']:
             return False, f"Invalid target extension: {output_ext}", None
        
        # Determine output path
        if raw_path is None:
            raw_file = dmp_file.with_suffix(output_ext)
        else:
            raw_file = Path(raw_path)
        
        # Check if output already exists
        if raw_file.exists():
            return False, f"Output file already exists: {raw_file}", None
        
        try:
            # Get dump info
            info = self.get_dump_info(dmp_file)
            
            # Perform conversion (copy or rename)
            if copy:
                print(f"[*] Copying {dmp_file.name} -> {raw_file.name}")
                shutil.copy2(dmp_file, raw_file)
                action = "copied"
            else:
                print(f"[*] Renaming {dmp_file.name} -> {raw_file.name}")
                dmp_file.rename(raw_file)
                action = "renamed"
            
            # Verify output
            if not raw_file.exists():
                return False, "Conversion failed: output file not created", None
            
            msg = (f"Successfully {action} to {raw_file.name}\n"
                   f"Format: {info['format']}\n"
                   f"Size: {info['size_gb']:.2f} GB")
            
            return True, msg, raw_file
            
        except Exception as e:
            return False, f"Conversion error: {e}", None
    
    def batch_convert(self, directory: str, target_ext: str = '.dmp',
                      copy: bool = False) -> dict:
        """
        Batch convert all dumps in a directory.
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return {'error': f"Directory not found: {directory}"}
        
        # Define source extensions based on target
        if target_ext == '.dmp':
            source_exts = ['.raw', '.mem', '.vmem', '.bin']
        else:
            # If target is raw/mem, source is usually .dmp
            source_exts = ['.dmp']
        
        # Find files
        files_to_convert = []
        for ext in source_exts:
            # Avoid converting if it matches target (e.g. .raw -> .raw)
            if ext == target_ext:
                continue
            files_to_convert.extend(dir_path.glob(f"*{ext}"))
        
        if not files_to_convert:
            return {'error': f"No files found to convert to {target_ext} in {directory}"}
        
        results = {
            'total': len(files_to_convert),
            'successful': 0,
            'failed': 0,
            'conversions': []
        }
        
        for file in files_to_convert:
            if target_ext == '.dmp':
                # Convert TO .dmp
                success, msg, output = self.convert_raw_to_dmp(str(file), copy=copy)
            else:
                # Convert TO .raw/.mem/.vmem
                success, msg, output = self.convert_dmp_to_raw(str(file), copy=copy, output_ext=target_ext)
            
            if success:
                results['successful'] += 1
            else:
                results['failed'] += 1
            
            results['conversions'].append({
                'file': file.name,
                'success': success,
                'message': msg,
                'output': str(output) if output else None
            })
        
        return results
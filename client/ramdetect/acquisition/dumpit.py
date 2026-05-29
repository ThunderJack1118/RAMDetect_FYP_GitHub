"""
ramdetect/acquisition/dumpit.py
================================
DumpIt integration for RAM memory acquisition
Features: 
  - Real-time progress bar
  - Captures Cr3 (DTB) and Build Number from DumpIt console output
  - Auto-answers "y" prompt
"""

import subprocess
import sys
import time
import os
import psutil
import re
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from ramdetect.utils.logger import get_logger
from ramdetect.utils.config import get_config
from ramdetect.acquisition.metadata import MetadataManager
from ramdetect.utils.helpers import (
    format_bytes,
    is_admin,
    sanitize_filename
)



def _hidden_subprocess_kwargs() -> dict:
    """Hide/minimize external DumpIt console window where Windows allows it."""
    kwargs = {}
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        kwargs["startupinfo"] = startupinfo
    except Exception:
        pass

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if creationflags:
        kwargs["creationflags"] = creationflags

    return kwargs



def _runtime_root() -> Path:
    """Return the active RAMDetect runtime root."""
    try:
        import sys as _sys
        if getattr(_sys, "frozen", False):
            return Path(_sys.executable).resolve().parent
    except Exception:
        pass

    here = Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass

    return Path.cwd().resolve()


def _resolve_dumpit_exe(configured: str | Path | None = None) -> Path | None:
    """Resolve DumpIt.exe from the active installed/source folder."""
    import sys as _sys

    candidates = []

    if configured:
        try:
            clean = str(configured).strip().strip('"').strip("'")
            if clean:
                candidates.append(Path(clean))
        except Exception:
            pass

    try:
        exe_dir = Path(_sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "tools" / "DumpIt.exe")
        candidates.append(exe_dir / "tools" / "DumpIt.exe")
    except Exception:
        pass

    try:
        meipass = getattr(_sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "tools" / "DumpIt.exe")
    except Exception:
        pass

    try:
        root = _runtime_root()
        candidates.append(root / "_internal" / "tools" / "DumpIt.exe")
        candidates.append(root / "tools" / "DumpIt.exe")
    except Exception:
        pass

    try:
        candidates.append(Path.cwd() / "_internal" / "tools" / "DumpIt.exe")
        candidates.append(Path.cwd() / "tools" / "DumpIt.exe")
    except Exception:
        pass

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except Exception:
            continue

    return None



class DumpItAcquisition:
    """
    Reliable RAM acquisition using Magnet DumpIt (v3.6+)
    """
    
    def __init__(self, dumpit_path: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # Resolve DumpIt path
        configured_dumpit = dumpit_path
        if not configured_dumpit:
            try:
                configured_dumpit = self.config.get_path('dumpit_path')
            except Exception:
                configured_dumpit = None

        resolved_dumpit = _resolve_dumpit_exe(configured_dumpit)
        if not resolved_dumpit:
            raise FileNotFoundError(
                "DumpIt.exe not found. Expected bundled path such as "
                "<RAMDetect install>/_internal/tools/DumpIt.exe. "
                f"Configured path was: {configured_dumpit}"
            )

        self.dumpit_path = resolved_dumpit

        try:
            configured_dumps_dir = self.config.get_path('dumps_dir')
        except Exception:
            configured_dumps_dir = None

        if configured_dumps_dir:
            self.dumps_dir = Path(configured_dumps_dir).resolve()
        else:
            self.dumps_dir = (_runtime_root() / "dumps").resolve()

        self.dumps_dir.mkdir(parents=True, exist_ok=True)
        
        # Config options
        acq_config = self.config.get('acquisition', {})
        self.silent_mode = acq_config.get('silent_mode', True)
        
        self.logger.info(f"DumpIt executable: {self.dumpit_path}")
        self.logger.info(f"Dump output directory: {self.dumps_dir}")
    
    def check_prerequisites(self) -> bool:
        self.logger.info("Checking prerequisites...")
        
        if not is_admin():
            self.logger.error("Administrator privileges required")
            return False
        
        disk = psutil.disk_usage(str(self.dumps_dir))
        ram = psutil.virtual_memory().total
        if disk.free < ram + 5 * 1024**3:  # RAM size + 5GB buffer
            self.logger.warning(f"Low free space: {format_bytes(disk.free)}")
        
        self.logger.info("✅ All checks passed")
        return True
    
    def generate_dump_filename(self) -> Path:
        hostname = os.getenv('COMPUTERNAME', 'UNKNOWN')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = sanitize_filename(f"{hostname}_{timestamp}.dmp")
        return self.dumps_dir / name

    def _print_progress_bar(self, current: int, total: int, prefix: str = '', length: int = 40):
        if total == 0: total = 1 
        percent = float(current) * 100 / total
        filled_length = int(length * current // total)
        bar = '█' * filled_length + '-' * (length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% ({format_bytes(current)})')
        sys.stdout.flush()

    def _parse_dumpit_output(self, stdout_data: str) -> Dict[str, Any]:
        """
        Extracts Cr3 and Windows Version from DumpIt console output.
        """
        extracted = {}
        
        # Regex to find "Cr3: 0x1ae000"
        cr3_match = re.search(r"Cr3:\s+(0x[0-9a-fA-F]+)", stdout_data)
        if cr3_match:
            extracted['dtb_hex'] = cr3_match.group(1)
            # Normalize to integer for JSON serialization if needed, currently string
            self.logger.info(f"   🔑 Captured DTB from output: {extracted['dtb_hex']}")

        # Regex to find "Windows version: 10.0.26200"
        ver_match = re.search(r"Windows version:\s+([0-9\.]+)", stdout_data)
        if ver_match:
            extracted['windows_version_str'] = ver_match.group(1)
            # Extract build number (last part)
            try:
                build_num = extracted['windows_version_str'].split('.')[-1]
                extracted['build_number'] = int(build_num)
                self.logger.info(f"   🛠️  Captured Build Number: {build_num}")
            except:
                pass
                
        return extracted

    def acquire(self, output_path: Optional[str] = None) -> Path:
        self.logger.info("=" * 70)
        self.logger.info("Starting RAM Acquisition (Magnet DumpIt)")
        self.logger.info("=" * 70)
        
        if not self.check_prerequisites():
            raise RuntimeError("Failed prerequisites")
        
        dump_path = Path(output_path) if output_path else self.generate_dump_filename()
        dump_path = dump_path.with_suffix('.dmp')
        dump_path.parent.mkdir(parents=True, exist_ok=True)
        
        full_output = str(dump_path.absolute())
        total_ram = psutil.virtual_memory().total

        cmd = [str(self.dumpit_path)]
        if self.silent_mode:
            cmd += ['/Q']
        cmd += ['/O', full_output]
        
        self.logger.info(f"Target dump: {dump_path}")
        self.logger.info("Initializing hardware drivers... (This may take a moment)")
        
        start_time = time.time()
        
        try:
            # Popen with TEXT mode to simplify parsing output later
            # stdin=PIPE to send 'y' if needed
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.dumpit_path.parent),
                **_hidden_subprocess_kwargs(),
                text=True 
            )
            
            # If not silent mode, DumpIt might wait for input. 
            # We proactively write 'y' just in case it hangs.
            if not self.silent_mode:
                try:
                    process.stdin.write('y\n')
                    process.stdin.flush()
                except (OSError, ValueError):
                    pass # Process might have closed stdin or doesn't need it

            # Monitoring Loop
            while process.poll() is None:
                if dump_path.exists():
                    try:
                        current_size = dump_path.stat().st_size
                        display_size = min(current_size, total_ram)
                        self._print_progress_bar(display_size, total_ram, prefix="Acquiring RAM")
                    except OSError:
                        pass
                
                time.sleep(0.5)
            
            print() # New line after progress bar
            
            # CAPTURE OUTPUT (stdout contains the Cr3 info)
            stdout_data, stderr_data = process.communicate()
            
            if process.returncode != 0:
                self.logger.error("DumpIt execution failed")
                if stdout_data: self.logger.error(f"STDOUT:\n{stdout_data}")
                if stderr_data: self.logger.error(f"STDERR:\n{stderr_data}")
                raise RuntimeError("DumpIt failed – see log for details")
            
            if not dump_path.exists():
                raise RuntimeError(f"Dump file not created: {dump_path}")
            
            duration = time.time() - start_time
            size = dump_path.stat().st_size
            
            self.logger.info(f"✅ Acquisition successful ({duration:.1f}s)")
            self.logger.info(f"   Size: {format_bytes(size)}")

            # --- EXTRACT CR3 & BUILD INFO ---
            captured_info = self._parse_dumpit_output(stdout_data)
            # --------------------------------

            # --- METADATA GENERATION ---
            meta_mgr = MetadataManager()
            meta_mgr.create_acquisition_metadata(
                dump_path=dump_path,
                tool="Magnet DumpIt",
                duration=duration,
                extra_data=captured_info  # PASS THE CAPTURED INFO HERE
            )
            # ---------------------------
            
        except KeyboardInterrupt:
            self.logger.warning("\n❌ Acquisition cancelled by user. Terminating DumpIt...")
            try: process.terminate()
            except: pass
            if dump_path.exists():
                time.sleep(1)
                try: dump_path.unlink(); self.logger.info("   Partial dump deleted.")
                except: pass
            raise

        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise
        
        self.logger.info("=" * 70)
        self.logger.info("✅ RAM ACQUISITION COMPLETE")
        self.logger.info("=" * 70)
        
        return dump_path


if __name__ == "__main__":
    if not is_admin():
        print("Run as Administrator!")
        sys.exit(1)
    
    try:
        acq = DumpItAcquisition()
        dump = acq.acquire()
        print(f"\nSuccess! Dump saved to:\n   {dump}")
    except Exception as e:
        sys.exit(1)
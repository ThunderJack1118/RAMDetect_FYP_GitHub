"""
ramdetect/extraction/parsers/handle_parser.py
=============================================
Handle Parser - Volatility-Assisted Exception
Uses Volatility 3 only for handle enumeration because native Windows
handle-table parsing is not yet fully solved in this FYP prototype.

This module must not change the RF-AE verdict, RF threshold, FeatureMapper,
Autoencoder MSE fusion, or report-only artifact policy.
"""

import subprocess
import sys
import os
import shutil
from typing import List, Dict, Optional



def _vol_handles_timeout(default: int = 900) -> int:
    """Timeout for windows.handles. If it times out/fails, RAMDetect continues without handle artifacts."""
    try:
        return int(os.environ.get("RAMDETECT_VOL_HANDLES_TIMEOUT", str(default)))
    except Exception:
        return default



def _resolve_volatility_exe() -> str | None:
    """Resolve Volatility CLI in development and installed PyInstaller mode."""
    import sys as _sys
    import shutil as _shutil
    from pathlib import Path as _Path

    candidates = []

    # Installed / PyInstaller onedir mode: bundled console Volatility runner.
    try:
        exe_dir = _Path(_sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "tools" / "vol.exe")
        candidates.append(exe_dir / "tools" / "vol.exe")
    except Exception:
        pass

    try:
        meipass = getattr(_sys, "_MEIPASS", None)
        if meipass:
            candidates.append(_Path(meipass) / "tools" / "vol.exe")
    except Exception:
        pass

    # Development mode: normal venv/PATH command.
    for item in (_shutil.which("vol"), _shutil.which("vol.exe")):
        if item:
            candidates.append(_Path(item))

    # Source fallback: project tools folder.
    try:
        here = _Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidates.append(parent / "tools" / "vol.exe")
    except Exception:
        pass

    try:
        candidates.append(_Path.cwd() / "tools" / "vol.exe")
    except Exception:
        pass

    for candidate in candidates:
        try:
            if candidate and candidate.exists():
                return str(candidate)
        except Exception:
            continue

    return None

def _hidden_subprocess_kwargs() -> dict:
    """Hide Volatility subprocess console windows on Windows."""
    if os.name != "nt":
        return {}
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

import logging

class HandleParser:
    """
    Documented exception wrapper for the Volatility 3 'windows.handles' plugin.
    Includes logic to detect memory smears and page faults. Output is artifact
    evidence only and must not alter the ML verdict.
    """
    def __init__(self, memory_reader=None, translator=None):
        self.logger = logging.getLogger(__name__)
        # Remove the Console Handler (Screen)
        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                self.logger.removeHandler(handler)
        
        # Stop propagation to root
        self.logger.propagate = False
        self.vol_path = self._find_volatility()
        self.error_state = None  # Store last error

        # [LOG] Confirm initialization
        if self.vol_path:
            self.logger.info(f"HandleParser initialized")
        else:
            self.logger.warning("HandleParser initialized but NOT found.")

    def _find_volatility(self):
        """Robustly locates the 'vol.exe' executable."""
        # 1. Check same directory as python interpreter (venv)
        python_dir = os.path.dirname(sys.executable)
        chk = os.path.join(python_dir, "vol.exe")
        if os.path.exists(chk): return chk
        
        # 2. Check global PATH
        chk = shutil.which("vol")
        if chk: return chk
        
        # 3. Check relative path
        base = os.path.dirname(os.path.abspath(__file__))
        chk = os.path.abspath(os.path.join(base, "../../../../venv/Scripts/vol.exe"))
        if os.path.exists(chk): return chk
        
        return None

    def enumerate_handles(self, dump_path: str, pid: Optional[int] = None) -> List[Dict]:
        """
        Executes Volatility and parses output, checking for corruption errors.
        """
        self.error_state = None
        
        if not self.vol_path:
            self.logger.warning("Volatility executable not found.")
            return []
            
        if not os.path.exists(dump_path):
            self.logger.error(f"Dump file not found: {dump_path}")
            return []
        
        # Command: vol.exe -f <dump> windows.handles
        cmd = [self.vol_path, "-f", dump_path, "windows.handles"]
        if pid: 
            cmd.extend(["--pid", str(pid)])

        handles = []
        try:
            # FIX 1: Set PYTHONUTF8=1 in the subprocess environment so Volatility
            # outputs UTF-8 correctly on Windows, preventing UnicodeEncodeError
            # when handle names contain non-ASCII characters (device paths, etc.)
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors='replace',   # Replace undecodable bytes instead of crashing
                encoding='utf-8',
                env=env,            # Pass the UTF-8 env
                timeout=300
                            **_hidden_subprocess_kwargs(),
            )
            
            # --- Error Checking Logic ---
            full_output = proc.stdout + proc.stderr
            
            if "Page error" in full_output or "Page Fault" in full_output:
                self.error_state = "Memory Corruption (Page Fault)"
                self.logger.error(f"Handle enumeration failed: Memory smear detected in dump. (Page Fault)")
                return []

            if "No suitable" in full_output and "symbol" in full_output:
                self.error_state = "Missing Symbols"
                self.logger.error("Handle enumeration failed: Volatility could not load symbols.")
                return []

            # --- Parsing Logic ---
            lines = proc.stdout.splitlines()
            start_parse = False
            
            for line in lines:
                # Detect header row and begin parsing after it
                if "PID" in line and "Type" in line and "GrantedAccess" in line:
                    start_parse = True
                    continue
                if not start_parse:
                    continue

                # FIX 2: Volatility output is TAB-separated.
                # The old code used line.split() (whitespace), which broke on
                # multi-word process names like "FTK Imager.exe" — shifting all
                # subsequent column indices and causing Type to receive the hex
                # HandleValue (e.g. "0x11c") instead of the actual type string
                # (e.g. "EtwRegistration"), and ALPC Port to be read as just "ALPC".
                parts = line.split('\t')

                # Volatility columns: PID | Process | Offset | HandleValue | Type | GrantedAccess | Name
                if len(parts) < 7:
                    continue

                try:
                    h_pid         = int(parts[0].strip())
                    h_process     = parts[1].strip()
                    h_offset      = parts[2].strip()
                    h_handle_val  = parts[3].strip()
                    h_type        = parts[4].strip()   # Always correct now (tab-split)
                    h_access_str  = parts[5].strip()
                    h_name        = parts[6].strip()   # Full name including spaces

                    # Parse access mask
                    access_mask = 0
                    try:
                        if h_access_str.startswith('0x'):
                            access_mask = int(h_access_str, 16)
                    except (ValueError, AttributeError):
                        pass

                    # FIX 3: The old code filtered out handles where name == "-"
                    # (Volatility's placeholder for unnamed handles like Events,
                    # Mutants, etc.), discarding ~half of all handles.
                    # We now include ALL handles; unnamed ones use "-" as name.
                    # This is why RAMDetect had 18k handles vs Volatility's 34k.
                    if not h_type:
                        continue

                    handles.append({
                        'pid':            h_pid,
                        'process':        h_process,
                        'type':           h_type,
                        'name':           h_name,          # "-" for unnamed handles
                        'object_address': h_offset,
                        'handle_value':   h_handle_val,
                        'access_mask':    access_mask
                    })

                except (ValueError, IndexError):
                    pass
            
            if handles:
                self.logger.info(f"Extracted {len(handles)} handles (pid filter: {pid})")
            elif proc.returncode != 0:
                snippet = (proc.stderr or proc.stdout or "").strip().replace("\r", " ").replace("\n", " ")[:500]
                self.error_state = f"Volatility exited with code {proc.returncode}: {snippet}"
                self.logger.warning(self.error_state)
                        
        except Exception as e:
            self.logger.error(f"Handle enumeration execution failed: {e}")
            
        return handles
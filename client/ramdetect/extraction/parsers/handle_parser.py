"""
ramdetect/extraction/parsers/handle_parser.py
=============================================
Handle Parser - Volatility-Assisted Exception

Uses Volatility 3 only for handle enumeration because native Windows
handle-table parsing is not yet fully solved in this FYP prototype.

This module must not change the RF-AE verdict, RF threshold, FeatureMapper,
Autoencoder MSE fusion, or report-only artifact policy.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


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


def _vol_handles_timeout(default: int = 900) -> int:
    """Timeout for windows.handles.Handles.

    If it times out/fails, RAMDetect continues without handle artifacts.
    """
    try:
        return int(os.environ.get("RAMDETECT_VOL_HANDLES_TIMEOUT", str(default)))
    except Exception:
        return default


def _resolve_volatility_exe() -> str | None:
    """Resolve Volatility CLI in development and installed PyInstaller mode.

    Installed RAMDetect must prefer:
      <RAMDetect install>\\_internal\\tools\\vol.exe

    This avoids accidentally using:
      RAMDetect\\venv\\Scripts\\vol.exe
    """
    candidates: list[Path] = []

    # 1. Installed / PyInstaller one-dir mode
    try:
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "tools" / "vol.exe")
        candidates.append(exe_dir / "tools" / "vol.exe")
    except Exception:
        pass

    # 2. PyInstaller _MEIPASS fallback
    try:
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "tools" / "vol.exe")
    except Exception:
        pass

    # 3. Source/project fallback
    try:
        here = Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidates.append(parent / "tools" / "vol.exe")
    except Exception:
        pass

    # 4. Current working directory fallback
    try:
        candidates.append(Path.cwd() / "_internal" / "tools" / "vol.exe")
        candidates.append(Path.cwd() / "tools" / "vol.exe")
    except Exception:
        pass

    # 5. Development PATH / venv fallback only after bundled candidates
    for item in (shutil.which("vol.exe"), shutil.which("vol")):
        if item:
            candidates.append(Path(item))

    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = str(candidate.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)

            if candidate.is_file():
                return resolved
        except Exception:
            continue

    return None


class HandleParser:
    """
    Documented exception wrapper for Volatility 3 handle enumeration.

    Uses windows.handles.Handles as a report-only artifact source.
    It must not alter the ML-only final verdict.
    """

    def __init__(self, memory_reader=None, translator=None):
        self.logger = logging.getLogger(__name__)

        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                self.logger.removeHandler(handler)

        self.logger.propagate = False
        self.vol_path = self._find_volatility()
        self.error_state = None

        if self.vol_path:
            self.logger.info("HandleParser initialized with Volatility: %s", self.vol_path)
        else:
            self.logger.warning("HandleParser initialized but vol.exe was not found.")

    def _find_volatility(self) -> str | None:
        return _resolve_volatility_exe()

    def enumerate_handles(self, dump_path: str, pid: Optional[int] = None) -> List[Dict]:
        """Execute Volatility and parse handle output.

        Failure is non-fatal. RAMDetect continues without handle artifacts if
        Volatility fails, times out, or produces unsupported output.
        """
        self.error_state = None

        if not self.vol_path:
            self.error_state = "Volatility executable not found"
            self.logger.warning(self.error_state)
            return []

        if not os.path.exists(dump_path):
            self.error_state = f"Dump file not found: {dump_path}"
            self.logger.error(self.error_state)
            return []

        cmd = [self.vol_path, "-f", dump_path, "windows.handles.Handles"]
        if pid:
            cmd.extend(["--pid", str(pid)])

        handles: List[Dict] = []

        try:
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"

            self.logger.info("Running Volatility handles command: %s", " ".join(cmd))

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                encoding="utf-8",
                env=env,
                timeout=_vol_handles_timeout(),
                **_hidden_subprocess_kwargs(),
            )

            full_output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            # Volatility may return a non-zero exit code even when useful
            # rows are printed to stdout. Parse stdout first; only treat the
            # command as failed if no handle rows can be extracted.
            pre_parsed_handles = self._parse_handles_output(proc.stdout or "")

            if proc.returncode != 0:
                snippet = full_output.strip().replace("\r", " ").replace("\n", " ")[:800]
                if pre_parsed_handles:
                    self.logger.warning(
                        "Volatility handles returned code %s but %d handle rows were parsed; accepting partial output.",
                        proc.returncode,
                        len(pre_parsed_handles),
                    )
                    self.error_state = None
                    return pre_parsed_handles

                self.error_state = f"Volatility handles exited with code {proc.returncode}: {snippet}"
                self.logger.warning(self.error_state)
                return []

            if "Unsatisfied requirement" in full_output:
                self.error_state = "Volatility handles unsatisfied requirement"
                self.logger.warning("%s: %s", self.error_state, full_output[:800])
                return []

            if "Page error" in full_output or "Page Fault" in full_output:
                self.error_state = "Memory Corruption / Page Fault during handle enumeration"
                self.logger.warning(self.error_state)
                return []

            if "No suitable" in full_output and "symbol" in full_output:
                self.error_state = "Missing symbols for handle enumeration"
                self.logger.warning(self.error_state)
                return []

            handles = self._parse_handles_output(proc.stdout or "")

            if handles:
                self.logger.info("Extracted %d handles (pid filter: %s)", len(handles), pid)
            else:
                self.error_state = "Volatility handles completed but no parseable handle rows were found"
                self.logger.warning(self.error_state)

        except subprocess.TimeoutExpired:
            self.error_state = f"windows.handles.Handles timed out after {_vol_handles_timeout()} seconds"
            self.logger.warning(self.error_state)
            return []

        except Exception as exc:
            self.error_state = f"Handle enumeration execution failed: {exc}"
            self.logger.warning(self.error_state)
            return []

        return handles

    def _parse_handles_output(self, output: str) -> List[Dict]:
        """Parse tabular Volatility 3 windows.handles.Handles output."""
        handles: List[Dict] = []
        start_parse = False

        for raw_line in output.splitlines():
            line = raw_line.strip("\r\n")
            if not line.strip():
                continue

            # Header usually contains:
            # PID | Process | Offset | HandleValue | Type | GrantedAccess | Name
            if "PID" in line and "Process" in line and "Type" in line and "GrantedAccess" in line:
                start_parse = True
                continue

            if not start_parse:
                continue

            if line.startswith("*") or line.startswith("Volatility"):
                continue

            if "\t" in line:
                parts = [p.strip() for p in line.split("\t")]
            else:
                # Fallback for whitespace table output.
                # Keep the final Name column as a joined remainder.
                parts = line.split(None, 6)

            if len(parts) < 6:
                continue

            try:
                h_pid = int(parts[0].strip())
                h_process = parts[1].strip()
                h_offset = parts[2].strip()
                h_handle_val = parts[3].strip()
                h_type = parts[4].strip()
                h_access_str = parts[5].strip()
                h_name = parts[6].strip() if len(parts) >= 7 else "-"

                access_mask = 0
                try:
                    if h_access_str.lower().startswith("0x"):
                        access_mask = int(h_access_str, 16)
                except Exception:
                    pass

                if not h_type:
                    continue

                handles.append({
                    "pid": h_pid,
                    "process": h_process,
                    "type": h_type,
                    "name": h_name or "-",
                    "object_address": h_offset,
                    "handle_value": h_handle_val,
                    "access_mask": access_mask,
                })

            except Exception:
                continue

        return handles

    def get_error_state(self):
        return self.error_state

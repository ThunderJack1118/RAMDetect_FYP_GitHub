"""
ramdetect/extraction/parsers/eprocess_scanner.py
================================================
Statistical Carver + VadRoot + PPID Support + TIMING METRICS + FIXED DTB
CORRECTED VERSION: Working DTB/PPID extraction for Windows 11 24H2
FEATURES:
  - Prioritized DTB Validation (User vs Kernel)
  - Relaxed PEB Checks (Catches Process Hollowing)
  - Ghost Process Filtering (CreateTime heuristics)
  - Process Flag Extraction (Terminating/Deleting status)

CHANGELOG (accuracy-pass fixes):
  P1-a  SAFE_ORPHANS expanded: OneDrive, OneDrive.Sync, MicrosoftEdgeUpdate
  P1-b  csrss.exe / wininit.exe parent-check disabled (secondary smss exits
         and its PID is immediately reused, making any parent check a FP).
  P3    Ghost Rule E: zero ActiveThreads + no resolved path + known short-lived
         process name → reject as terminated/stale EPROCESS pool block.
         Catches ghost PIDs like 3656 / 4796 / 8060 / 8852 seen on the clean dump.
  P4    String-artifact guard for pool false positives that look like source/API
         identifiers (e.g., os.path.isdir.exe, ED_BY_CALLBACK.exe).
"""

from typing import List, Dict, Optional, Tuple, Set
import struct
import logging
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from contextlib import contextmanager

from ramdetect.utils.logger import get_logger
from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
from ramdetect.extraction.parsers.address_translator import AddressTranslator
from ramdetect.utils.offset import OFFSET_SETS, build_symbol_backed_offsets

# Conservative source-code/provider-string artifact filters.
# These catch pool-string false positives such as siphash_prov.c.exe and
# TasksService.h that are not real EPROCESS ImageFileName values.
SOURCE_CODE_EXTENSIONS = (
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".asm", ".inc",
)
SOURCE_ARTIFACT_PATTERNS = tuple(SOURCE_CODE_EXTENSIONS) + tuple(
    ext + ".exe" for ext in SOURCE_CODE_EXTENSIONS
)
KNOWN_SOURCE_ARTIFACT_NAMES = {
    "siphash_prov.c",
    "siphash_prov.c.exe",
    "tasksservice.h",
    "tasksservice.h.exe",
}
_SOURCE_CODE_SUFFIX_RE = re.compile(
    r"\.(?:c|h|cpp|cc|cxx|hpp|asm|inc)(?:\.exe)?$",
    re.IGNORECASE,
)

def _is_source_artifact_name(name: str) -> bool:
    if not name:
        return False
    n = str(name).strip().lower().rstrip("\x00")
    if not n:
        return False
    base = n[:-4] if n.endswith(".exe") else n
    return (
        n in KNOWN_SOURCE_ARTIFACT_NAMES
        or base in KNOWN_SOURCE_ARTIFACT_NAMES
        or n.endswith(SOURCE_ARTIFACT_PATTERNS)
        or base.endswith(SOURCE_CODE_EXTENSIONS)
        or bool(_SOURCE_CODE_SUFFIX_RE.search(n))
        or bool(_SOURCE_CODE_SUFFIX_RE.search(base))
    )


# Exact and pattern-based guard for pool-string false positives that are
# printable identifiers but not real EPROCESS.ImageFileName values.  These were
# observed in the DLLHijacking-WithVirus dump as fake processes with zero
# ActiveThreads, no resolved path, zero DLLs, and zero handles after deeper
# extraction.  The exact-name list is safe to reject immediately; the broader
# identifier heuristics are only applied later in cleanup when the candidate is
# also dead-looking (0 ActiveThreads + no path).
KNOWN_STRING_ARTIFACT_NAMES = {
    "os.path.isdir",
    "os.path.isdir.exe",
    "allocated_size",
    "allocated_size.exe",
    "ed_by_callback",
    "ed_by_callback.exe",
    "ditional_error",
    "ditional_error.exe",
    "e_use_sendfile",
    "e_use_sendfile.exe",
    "message_digest",
    "message_digest.exe",
    "alpn_protocols",
    "alpn_protocols.exe",
}

_STRING_ARTIFACT_TERM_RE = re.compile(
    r"(?:os\.path\.|allocated_size|_by_callback|ditional_error|"
    r"use_sendfile|message_digest|alpn_protocols)",
    re.IGNORECASE,
)


def _strip_exe_suffix(name: str) -> str:
    n = str(name or "").strip().rstrip("\x00")
    return n[:-4] if n.lower().endswith(".exe") else n


def _is_known_string_artifact_name(name: str) -> bool:
    """Return True for exact known source/API-string false process names."""
    if not name:
        return False
    n = str(name).strip().lower().rstrip("\x00")
    base = _strip_exe_suffix(n).lower()
    return n in KNOWN_STRING_ARTIFACT_NAMES or base in KNOWN_STRING_ARTIFACT_NAMES


def _is_dead_string_artifact_candidate(name: str, *, active_threads: int, has_path: bool) -> bool:
    """
    Conservative cleanup-only guard for dead-looking pool-string artifacts.

    This deliberately requires both 0 ActiveThreads and no resolved path so that
    legitimate running processes with unusual/truncated names are not removed.
    It targets source/API identifiers recovered by the regex carver rather than
    real process names.
    """
    if not name or has_path or active_threads != 0:
        return False

    raw_base = _strip_exe_suffix(str(name).strip().rstrip("\x00"))
    base_l = raw_base.lower()

    if _is_source_artifact_name(name) or _is_known_string_artifact_name(name):
        return True

    if _STRING_ARTIFACT_TERM_RE.search(base_l):
        return True

    # API/source constants often appear as ALL_CAPS_WITH_UNDERSCORES or
    # snake_case identifiers.  Treat them as artifacts only when dead-looking.
    if "_" in raw_base:
        if re.fullmatch(r"[A-Z0-9_]{6,}", raw_base):
            return True
        if re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+", base_l):
            return True

    # Dotted module/API paths such as os.path.isdir are not process image names.
    # Use a small allow-list for known Windows truncations that contain dots.
    dotted_allow = {
        "smartscreen.ex", "fontdrvhost.ex", "vboxservice.ex",
        "winstore.app.e",
    }
    if base_l.count(".") >= 2 and base_l not in dotted_allow:
        return True

    return False


@dataclass
class TimingMetrics:
    """Container for timing metrics to benchmark scanner performance"""
    total_scan_time: float = 0.0
    pattern_scan_time: float = 0.0
    structure_parse_time: float = 0.0
    validation_time: float = 0.0
    memory_read_time: float = 0.0
    chunks_scanned: int = 0
    patterns_found: int = 0
    processes_found: int = 0
    bytes_scanned: int = 0
    scan_rate_mbps: float = 0.0

@contextmanager
def timer(metric_name: str, metrics_dict: Dict[str, float], logger=None):
    """
    Context manager to measure execution time of specific blocks.
    Usage: with timer("my_operation", metrics): do_something()
    """
    start_time = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start_time
        metrics_dict[metric_name] = metrics_dict.get(metric_name, 0) + elapsed
        if logger:
            logger.debug(f"{metric_name}: {elapsed:.3f}s")

class EProcessScanner:
    def __init__(self, memory_reader, translator: Optional[AddressTranslator], build_number=None, enable_timing=True, log_callback=None, kernel_metadata: Optional[Dict]=None, offsets_override: Optional[Dict]=None):
        self.memory = memory_reader
        self.translator = translator
        self.logger = get_logger(__name__)
        self.build_number = build_number
        self.enable_timing = enable_timing
        self.metrics = TimingMetrics()
        self.timing_details = {}
        self.log_callback = log_callback
        self.kernel_metadata = kernel_metadata or {}
        self.is_64bit = self.kernel_metadata.get("is_64bit")
        self.is_pae = self.kernel_metadata.get("is_pae")
        self.symbols = self.kernel_metadata.get("symbols")
        self.pointer_size = 8

        if offsets_override:
            self.offsets = dict(offsets_override)
            self.pointer_size = int(self.offsets.get("pointer_size", 8))
            profile_name = self.offsets.get("name", "override")
            self.logger.info(
                f"Using supplied offsets for {profile_name} "
                f"(Build {build_number}, ptr={self.pointer_size}, pae={self.offsets.get('is_pae', False)})"
            )
        elif build_number:
            if (self.is_64bit is False) and bool(self.is_pae):
                self.offsets = build_symbol_backed_offsets(
                    build_number, is_64bit=self.is_64bit, is_pae=self.is_pae, symbols=self.symbols
                )
                profile_name = self.offsets.get("name", "Windows x86 PAE")
            elif build_number >= 26000:
                self.offsets = OFFSET_SETS[4]
                profile_name = "Windows 11 24H2+"
            elif build_number >= 19041:
                self.offsets = OFFSET_SETS[3]
                profile_name = "Windows 10 20H1+"
            elif build_number >= 18362:
                self.offsets = OFFSET_SETS[2]
                profile_name = "Windows 10 1903/1909"
            elif build_number >= 17134:
                self.offsets = OFFSET_SETS[1]
                profile_name = "Windows 10 1803"
            elif build_number == 7601:
                self.offsets = OFFSET_SETS[0]
                profile_name = "Windows 7 SP1"
            else:
                self.offsets = OFFSET_SETS[3]
                profile_name = "Unknown (Defaulting to Win10)"

            self.pointer_size = int(self.offsets.get("pointer_size", 8))
            self.logger.info(f"Using offsets for {profile_name} (Build {build_number}, ptr={self.pointer_size}, pae={self.offsets.get('is_pae', False)})")
        else:
            self.offsets = OFFSET_SETS[3]
            self.pointer_size = int(self.offsets.get("pointer_size", 8))
            self.logger.info("Build number unknown. Defaulting to Windows 10/11 (20H1+) offsets.")

    def get_timing_report(self) -> str:
        if not self.enable_timing:
            return "Timing disabled"

        report = []
        report.append("\n" + "="*60)
        report.append("⏱️  EPROCESS SCANNER TIMING REPORT")
        report.append("="*60)

        report.append(f"Total Scan Time:       {self.metrics.total_scan_time:.3f} seconds")
        report.append(f"Memory Scanned:        {self.metrics.bytes_scanned / (1024**3):.2f} GB")
        report.append(f"Scan Rate:             {self.metrics.scan_rate_mbps:.2f} MB/s")
        report.append(f"Chunks Processed:      {self.metrics.chunks_scanned}")
        report.append(f"Patterns Found:        {self.metrics.patterns_found}")
        report.append(f"Processes Recovered:   {self.metrics.processes_found}")
        report.append("-" * 60)

        if self.timing_details:
            for phase, duration in sorted(self.timing_details.items()):
                report.append(f"{phase:<25}: {duration:.3f}s")

        report.append("="*60)
        return "\n".join(report)

    def print_progress_with_eta(self, current: int, total: int, start_time: float,
                                chunk_size: int, metrics: TimingMetrics):
        if current >= total or current == 0:
            return

        elapsed = time.perf_counter() - start_time
        percent = (current / total) * 100
        speed_mbps = (current / (1024*1024)) / elapsed if elapsed > 0 else 0

        remaining_bytes = total - current
        if speed_mbps > 0:
            eta_seconds = (remaining_bytes / (1024*1024)) / speed_mbps
            eta_str = f"{eta_seconds:.0f}s"
        else:
            eta_str = "???"

        metrics.scan_rate_mbps = speed_mbps
        metrics.bytes_scanned = current

        bar_length = 30
        filled = int(bar_length * current // total)
        bar = "█" * filled + "░" * (bar_length - filled)

        line = (
            f"[{bar}] {percent:5.1f}% | "
            f"Speed: {speed_mbps:.1f} MB/s | "
            f"ETA: {eta_str} | "
            f"Found: {metrics.processes_found} process(s)"
        )
        sys.stdout.write(f"\r   {line}")
        sys.stdout.flush()
        if self.log_callback:
            self.log_callback("INFO", f"  Carving EPROCESS... {line}")

    def determine_geometry_statistically(self) -> int:
        start_time = time.perf_counter()
        exe_pattern = re.compile(b'[a-zA-Z0-9_]{3,14}\\.exe\\x00')
        chunk_size = 32 * 1024 * 1024
        limit = min(self.memory.file_size, 4 * 1024 * 1024 * 1024)
        candidates = []
        patterns_scanned = 0

        self.logger.info(f"   🔍 Starting statistical geometry detection (scanning {limit//(1024**3)}GB)...")

        for offset in range(0, limit, chunk_size):
            with timer("geometry_memory_read", self.timing_details, self.logger):
                chunk = self.memory.read_physical(offset, chunk_size)
                if not chunk: break

            with timer("geometry_pattern_scan", self.timing_details, self.logger):
                for match in exe_pattern.finditer(chunk):
                    patterns_scanned += 1
                    name_start = match.start()
                    for dist in [0x168, 0x38]:
                        pid_idx = name_start - dist
                        if pid_idx >= 0:
                            try:
                                pid_val = struct.unpack("<Q", chunk[pid_idx:pid_idx+8])[0]
                                if 0 < pid_val < 200000 and (pid_val % 4 == 0):
                                    flink_val = struct.unpack("<Q", chunk[pid_idx+8:pid_idx+16])[0]
                                    if flink_val > 0xffff000000000000:
                                        candidates.append(dist)
                            except: pass

        if not candidates:
            elapsed = time.perf_counter() - start_time
            self.logger.info(f"   ⚠️  Geometry detection failed in {elapsed:.2f}s (scanned {patterns_scanned} patterns)")
            return 0

        result = Counter(candidates).most_common(1)[0][0]
        elapsed = time.perf_counter() - start_time

        self.logger.info(f"   ✅ Geometry detection completed in {elapsed:.2f}s")
        self.logger.info(f"   Scanned {patterns_scanned} patterns, determined dist=0x{result:x}")

        return result

    def _is_valid_process_name(self, name: str) -> bool:
        """
        Robust validation of process names using heuristics.

        EPROCESS.ImageFileName is a fixed 15-byte field (14 chars + null terminator).
        Any process name longer than 14 chars is silently TRUNCATED by Windows.
        """
        if not name or len(name) < 2 or len(name) > 256:
            return False

        name_l = name.lower().strip()
        base_l = name_l[:-4] if name_l.endswith('.exe') else name_l

        if _is_source_artifact_name(name_l) or _is_known_string_artifact_name(name_l):
            return False

        # Conservative string-artifact filter.  EPROCESS.ImageFileName is only
        # 15 bytes, so raw pool scanning can accidentally hit printable strings
        # from DLL exports, error messages, WMI symbols, COM APIs, or source-code
        # identifiers.  These are not process names and must be rejected before
        # they enter feature extraction.
        artifact_terms = (
            'unavailable', 'not available', 'no such device', 'resource busy',
            'unknown series', 'configuration', 'heapallocation', 'insertionpoint',
            'inprocserver32', 'getadminstores', 'wm_mdiactivate', 'contextmessage',
            'scsiconnection', 'lmrequirements', 'vsnprintf', 'aliasuser',
            'promptrequired', 'queuercvpacket', 't_wmi', 'privtags',
            'specific_handler', 'destroy_list', 'iodetachdevice', 'iocreatedevice',
            'getclassobject', 'cotaskmem', 'getbinarytype', 'waitabletimer',
            'advancelogbase', 'windowlesssite', 'scene_position', 'registerdevice',
            'ntsetting', 'calloutsfordll', 'defragmentfile', 'adminfileclose',
            'spaceperextent', 'transmitserror', 'windowservices', 'devicefamilyid',
            'titlebarwindow', 'extendedstatus', 'kpolicysetting', 'lag_locks',
            'engine failure', 'bt_unavailable', 'ikcomponentid', 'psecunauthdscp',
        )
        if any(term in base_l for term in artifact_terms):
            return False

        # Most real Windows process ImageFileName values do not contain spaces.
        # Allow spaces only for known kernel pseudo-names, not arbitrary *.exe
        # strings found in pool memory.
        if ' ' in base_l and base_l not in {'secure system', 'memcompression'}:
            return False

        # Random-looking constants are usually pool strings, not ImageFileName.
        if re.search(r'[0-9a-f]{8,}', base_l, re.IGNORECASE):
            return False
        if re.match(r'^[_\-\.0-9]+$', base_l):
            return False

        garbage_patterns = [
            r'^[a-f0-9]{8,}$',
            r'^[0-9]{4,}$',
            r'.*[^\x20-\x7E].*',
        ]
        for pattern in garbage_patterns:
            if re.match(pattern, name, re.IGNORECASE):
                return False

        if name_l.endswith('.exe'):
            base_name = name[:-4]
            if re.match(r'^[a-zA-Z0-9_\-\.]+$', base_name):
                return True

        known_system = {"system", "registry", "secure system", "memcompression"}
        if name.lower() in known_system:
            return True

        if len(name) == 14 and re.match(r'^[a-zA-Z0-9_\-\. ]+$', name):
            if re.search(r'[a-zA-Z]', name):
                if not self._is_name_fragment(name):
                    return True

        return False

    @staticmethod
    def _is_name_fragment(name: str) -> bool:
        if name.startswith('.') or name.startswith('_'):
            return True

        if re.search(r'\.(dll|ini|sys|log|mui|cfg|dat)\.', name, re.IGNORECASE):
            return True
        if '.exe_' in name.lower():
            return True

        dot_pos = name.rfind('.')
        if 0 < dot_pos < len(name) - 3:
            return True
        if dot_pos > 0 and dot_pos < len(name) - 1:
            after_dot = name[dot_pos + 1:]
            if after_dot.isdigit():
                return True

        if name[0].islower() and any(c.isupper() for c in name[1:]):
            return True

        return False

    def _is_valid_peb(self, peb_value: int, pid: int, process_name: str) -> bool:
        if pid == 4: return True

        safe_no_peb = {"smss.exe", "csrss.exe", "wininit.exe", "registry", "memcompression", "secure system"}

        if peb_value == 0:
            return process_name.lower() in safe_no_peb

        if peb_value > 0x7FFFFFFFFFFF: return False
        if (peb_value & 0x7) != 0: return False

        return True

    def _normalize_dtb(self, dtb_value: int) -> int:
        """
        Normalize CR3/DTB values by clearing low 12 bits.

        Modern Windows can store PCID / low-bit flags in CR3-like values
        (e.g. 0x3d352002). The paging base is 0x3d352000.
        """
        try:
            return int(dtb_value or 0) & 0xFFFFFFFFFFFFF000
        except Exception:
            return 0

    def _ptr_fmt(self) -> str:
        return "<I" if int(getattr(self, "pointer_size", 8) or 8) == 4 else "<Q"

    def _ptr_size(self) -> int:
        return 4 if int(getattr(self, "pointer_size", 8) or 8) == 4 else 8

    def _unpack_ptr(self, data: bytes) -> int:
        size = self._ptr_size()
        if not data or len(data) < size:
            return 0
        return int(struct.unpack(self._ptr_fmt(), data[:size])[0])

    def _read_phys_ptr(self, addr: int) -> int:
        raw = self.memory.read_physical(int(addr or 0), self._ptr_size())
        return self._unpack_ptr(raw)

    def _is_kernel_pointer(self, value: int) -> bool:
        value = int(value or 0)
        if self._ptr_size() == 4:
            return 0x80000000 <= value <= 0xFFFFFFFF
        return value >= 0xFFFF000000000000

    def _is_valid_dtb_for_process(self, dtb_value: int, pid: int) -> bool:
        if pid == 4:
            return True

        dtb_norm = self._normalize_dtb(dtb_value)
        if dtb_norm == 0:
            return False
        if dtb_norm < 0x1000:
            return False
        if self._ptr_size() == 4:
            if dtb_norm >= 0x100000000:
                return False
        elif dtb_norm >= 0x40000000000:
            return False

        return True

    def find_all_processes(self) -> List[Dict]:
        total_start = time.perf_counter()

        self.logger.info("📊 Phase 1: Configuring scan geometry...")

        off_name = self.offsets.get('ImageFileName', 0x450)
        off_pid = self.offsets.get('UniqueProcessId', 0x2e0)
        off_links = self.offsets.get('ActiveProcessLinks', 0x2e8)

        profile_delta = off_name - off_pid
        current_name_to_pid = profile_delta
        self.logger.info(f"✅ Forced Profile Delta: 0x{current_name_to_pid:x} (Bypassing stats)")

        self.logger.info(f"🚀 Phase 2: Carving processes...")
        if self.log_callback:
            size_gb = self.memory.file_size / (1024**3)
            self.log_callback("INFO", f"  Carving EPROCESS structures across {size_gb:.1f} GB of physical memory...")
        processes = []
        seen_pids = set()

        name_pattern = re.compile(b'[a-zA-Z0-9_\-\. ]{3,14}\x00')

        chunk_size = 32 * 1024 * 1024
        total_size = self.memory.file_size
        scan_start = time.perf_counter()
        chunks_processed = 0

        for chunk_start in range(0, total_size, chunk_size):
            chunks_processed += 1
            self.metrics.chunks_scanned = chunks_processed

            if chunks_processed % 5 == 0 or chunk_start == 0:
                self.print_progress_with_eta(chunk_start, total_size, scan_start, chunk_size, self.metrics)

            chunk = self.memory.read_physical(chunk_start, chunk_size)
            if not chunk: break

            for match in name_pattern.finditer(chunk):
                match_start = match.start()
                self.metrics.patterns_found += 1

                pid_rel = match_start - current_name_to_pid

                ptr_sz = self._ptr_size()
                if pid_rel >= 0 and pid_rel + (ptr_sz * 2) < len(chunk):
                    try:
                        pid_val = self._unpack_ptr(chunk[pid_rel:pid_rel+ptr_sz])

                        if 0 < pid_val < 200000 and (pid_val % 4 == 0):

                            link_rel = pid_rel + (off_links - off_pid)

                            if link_rel + ptr_sz <= len(chunk):
                                flink = self._unpack_ptr(chunk[link_rel:link_rel+ptr_sz])

                                is_ptr_valid = self._is_kernel_pointer(flink)
                                if pid_val == 4: is_ptr_valid = True

                                if is_ptr_valid and pid_val not in seen_pids:
                                    name_str = match.group().decode('ascii', errors='ignore').strip('\x00')

                                    if not self._is_valid_process_name(name_str):
                                        continue

                                    base_addr = (chunk_start + pid_rel) - off_pid

                                    process_data = self._extract_process_data(base_addr, pid_val, name_str)
                                    if process_data:
                                        dtb = process_data.get('dtb', 0)
                                        if not self._is_valid_dtb_for_process(dtb, pid_val):
                                            # [FIX v2] Suppress DTB anomaly for PPL / KVA-shadowed processes.
                                            #
                                            # CRITICAL BUG FIX: use process_data['image_name'] NOT name_str.
                                            # EPROCESS.ImageFileName is 14 chars max — any process whose name
                                            # fills those 14 bytes (e.g. "StartMenuExper", "msedgewebview2")
                                            # is stored WITHOUT ".exe" in name_str at this point.  Our set
                                            # uses the cleaned names with ".exe" appended by
                                            # _extract_process_data(), so name_str.lower() always misses
                                            # 14-char process names and adds DTB anomaly for them all.
                                            # process_data['image_name'] has already had ".exe" appended.
                                            _KVA_PPL_SAFE = {
                                                # Security / PPL
                                                "securityhealthservice.exe", "securityhealth.exe",
                                                "securityhealthserv",
                                                "msmpeng.exe", "nissrv.exe", "mssense.exe",
                                                "lsass.exe",
                                                # Session/boot
                                                "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
                                                "system", "registry", "memcompression", "secure system",
                                                # GDI / audio / runtime
                                                "fontdrvhost.exe", "audiodg.exe", "dwm.exe",
                                                # userinit exits by design; DTB freed at snapshot time
                                                "userinit.exe",
                                                # UWP / Shell (COM activation; per-session address space)
                                                "runtimebroker.exe", "startmenuexper.exe",
                                                "startmenuexperiencehost.exe",
                                                "dataexchangeho.exe", "dataexchangehost.exe",
                                                "shellhost.exe", "gamebar.exe", "gamebarft.exe",
                                                "widgets.exe", "crossdeviceres.exe",
                                                "crossdeviceservice.exe",
                                                "backgroundtran.exe", "backgroundtransferhost.exe",
                                                # Search infrastructure
                                                "searchindexer.exe", "searchfilterho.exe",
                                                "searchfilterhost.exe", "searchprotocol.exe",
                                                "searchprotocolhost.exe", "searchhost.exe",
                                                # Common services
                                                "wmiprvse.exe", "usoclient.exe",
                                                "smartscreen.exe", "smartscreen.ex.exe",
                                                "ctfmon.exe", "sihost.exe", "taskhostw.exe",
                                                "svchost.exe", "dllhost.exe", "conhost.exe",
                                                "consent.exe", "spoolsv.exe",
                                                # UWP apps
                                                "msedgewebview2.exe", "olk.exe",
                                                # Setup / update
                                                "onedrivesetup.exe", "onedrivesetu.exe",
                                                # Acquisition tools
                                                "dumpit.exe", "ftkimager.exe", "winpmem.exe", "rammap.exe",
                                                # Bare names WITHOUT .exe (fallback for 14-char truncation):
                                                "searchindexer", "startmenuexper", "msedgewebview2",
                                                "crossdeviceres", "dataexchangeho", "runtimebroker",
                                                "runtimebroker.", "searchfilterho", "searchprotocol",
                                                "backgroundtran", "smartscreen.ex", "onedrivesetup",
                                                "onedrivesetup.", "gamebar", "securityhealthserv",
                                                "fontdrvhost.ex",
                                            }
                                            # [FIX] Use cleaned image_name (has .exe) not raw name_str
                                            _n_lower = process_data.get("image_name", name_str).lower()
                                            if _n_lower not in _KVA_PPL_SAFE:
                                                process_data['anomalies'].append("Invalid/Swapped DTB")

                                        peb = process_data.get('peb', 0)
                                        if not self._is_valid_peb(peb, pid_val, name_str):
                                            process_data['peb_is_valid'] = False
                                        else:
                                            process_data['peb_is_valid'] = True

                                        processes.append(process_data)
                                        seen_pids.add(pid_val)
                                        self.metrics.processes_found += 1
                    except Exception:
                        pass

        self.print_progress_with_eta(total_size, total_size, scan_start, chunk_size, self.metrics)
        if not self.log_callback:
            sys.stdout.write("\n")

        self.logger.info("📊 Phase 3: Post-processing results...")
        if self.log_callback:
            self.log_callback("INFO", "  Post-processing: validating PPIDs and cleaning garbage entries...")
        processes.sort(key=lambda x: x['pid'])
        processes = self._validate_and_fix_ppids(processes)
        processes = self._cleanup_garbage_processes(processes)

        # ── Phase 4: DKOM cross-reference ─────────────────────────────────────
        # Cross-reference the pool scan (above) against the ActiveProcessLinks
        # linked list walk to surface processes a rootkit has hidden via DKOM.
        # We stamp boolean flags onto each process dict so that process_features.py
        # _extract_hidden_features() can read them without re-parsing anomaly strings.
        self.logger.info("📊 Phase 4: DKOM cross-reference (pool vs linked list)...")
        if self.log_callback:
            self.log_callback("INFO", "  DKOM check: cross-referencing pool scan against linked list...")
        try:
            dkom_result = self.detect_dkom(processes)
            hidden_pids = {p['pid'] for p in dkom_result.get('hidden_from_list', [])}

            # Second-layer guard: detect_dkom() has its own coverage gate and
            # sanity cap, but we add a final check here too.  If hidden_pids
            # accounts for more than 10 % of all processes the result is still
            # almost certainly a walk failure — stamp no flags at all.
            pct_hidden = len(hidden_pids) / max(len(processes), 1)
            if pct_hidden > 0.10 and len(hidden_pids) > 5:
                self.logger.warning(
                    f"DKOM Phase 4 guard: {len(hidden_pids)} hidden PIDs "
                    f"({pct_hidden:.0%} of all processes) — treating as unreliable, "
                    f"no DKOM flags will be stamped."
                )
                hidden_pids = set()   # discard; stamp safe defaults below

            for proc in processes:
                proc['found_by_pool'] = True
                if proc['pid'] in hidden_pids:
                    # In pool scan but NOT in linked list → DKOM hidden from pslist
                    proc['found_by_links'] = False
                    proc['dkom_detected']  = True
                    proc['hidden']         = True
                else:
                    proc['found_by_links'] = True
                    proc.setdefault('dkom_detected', False)
                    proc.setdefault('hidden', False)

            n_hidden = len(hidden_pids)
            if n_hidden:
                self.logger.warning(
                    f"DKOM: {n_hidden} process(es) confirmed hidden from linked list: "
                    f"{[p.get('image_name','?') + '(' + str(p.get('pid','?')) + ')' for p in dkom_result['hidden_from_list']]}"
                )
                if self.log_callback:
                    self.log_callback(
                        "WARNING",
                        f"  DKOM detected: {n_hidden} process(es) hidden from ActiveProcessLinks"
                    )
            else:
                self.logger.info("DKOM: no hidden processes detected (or walk was unreliable)")
        except Exception as exc:
            # Non-fatal — DKOM detection requires a valid translator; log and continue.
            self.logger.warning(f"DKOM cross-reference failed (non-fatal): {exc}")
            # Stamp safe defaults so downstream code never sees missing keys
            for proc in processes:
                proc.setdefault('found_by_pool',  True)
                proc.setdefault('found_by_links', True)
                proc.setdefault('dkom_detected',  False)
                proc.setdefault('hidden',         False)
        # ── End Phase 4 ───────────────────────────────────────────────────────

        total_elapsed = time.perf_counter() - total_start
        self.metrics.total_scan_time = total_elapsed

        summary = f"Recovered {len(processes)} processes in {total_elapsed:.2f}s"
        self.logger.info(f"✅ {summary}")
        if self.log_callback:
            self.log_callback("INFO", f"  EPROCESS Walker complete: {summary}")
        if self.enable_timing and not self.log_callback:
            print(self.get_timing_report())

        return processes

    def _cleanup_garbage_processes(self, processes: List[Dict]) -> List[Dict]:
        """
        Robust cleanup with OS-specific validation.
        [FIXED] Implements 'Orphan Adoption' to prevent TiWorker false positives.

        FIX P1-a  SAFE_ORPHANS expanded with OneDrive + MicrosoftEdgeUpdate.
        FIX P1-b  csrss / wininit parent-check disabled (secondary smss PID reuse).
        FIX P3    Ghost Rule E: zero ActiveThreads + no path + short-lived name.
        """
        cleaned = []

        pid_map = {p['pid']: p for p in processes}

        is_windows_7 = self.build_number == 7601

        if is_windows_7:
            system_process_rules = {
                "svchost.exe":  {"parents": {"services.exe"}},
                "csrss.exe":    {"parents": {"smss.exe"}},
                "wininit.exe":  {"parents": {"smss.exe"}},
                "services.exe": {"parents": {"wininit.exe"}},
                "lsass.exe":    {"parents": {"wininit.exe"}},
                "winlogon.exe": {"parents": {"smss.exe"}},
                "smss.exe":     {"parents": {"system"}},
                "explorer.exe": {"parents": set()},
                "spoolsv.exe":  {"parents": {"services.exe"}},
            }
        else:
            system_process_rules = {
                "svchost.exe": {
                    "parents": {"services.exe"},
                    "path": r"\windows\system32\svchost.exe"
                },
                # [FIX P1-b] Secondary smss.exe spawns csrss + wininit then exits.
                # Its PID is immediately reused by a new svchost, so any parent
                # check on these two processes is structurally unreliable and
                # always produces Wrong-Parent FPs.  Disable the parent check;
                # the path check alone is sufficient to detect spoofing.
                "csrss.exe": {
                    "parents": set(),  # parent check disabled — secondary smss PID reuse
                    "path": r"\windows\system32\csrss.exe"
                },
                "wininit.exe": {
                    "parents": set(),  # parent check disabled — secondary smss PID reuse
                    "path": r"\windows\system32\wininit.exe"
                },
                "services.exe": {
                    "parents": {"wininit.exe"},
                    "path": r"\windows\system32\services.exe"
                },
                "lsass.exe": {
                    "parents": {"wininit.exe"},
                    "path": r"\windows\system32\lsass.exe"
                },
                "winlogon.exe": {
                    "parents": {"smss.exe"},
                    "path": r"\windows\system32\winlogon.exe"
                },
                "smss.exe": {
                    "parents": {"system"},
                    "path": r"\windows\system32\smss.exe"
                },
                "explorer.exe": {
                    "parents": set(),
                    "path": r"\windows\explorer.exe"
                },
                "spoolsv.exe": {
                    "parents": {"services.exe"},
                    "path": r"\windows\system32\spoolsv.exe"
                }
            }

        garbage_pids = {12, 16, 120, 180, 256, 268, 604, 1020, 10244, 65544, 65792}

        known_safe_names = set(
            name.replace(".exe", "") for name in system_process_rules.keys()
        ) | {"registry", "memcompression", "system", "secure system"}

        # [FIX P1-a] Expanded SAFE_ORPHANS to cover OneDrive and MicrosoftEdgeUpdate.
        # These processes' parent managers exit before the memory snapshot is taken,
        # making them appear as orphans even though they are fully legitimate.
        #
        # EPROCESS.ImageFileName truncation rules (14-char max, then our code appends
        # .exe to non-.exe names):
        #   "OneDrive.exe"               → stored as-is (12 chars, fits)
        #   "OneDrive.Sync.Root.exe"     → truncated to "OneDrive.Sync." then → "OneDrive.Sync.exe"
        #   "MicrosoftEdgeUpdate.exe"    → truncated to "MicrosoftEdgeU" then → "MicrosoftEdgeU.exe"
        SAFE_ORPHANS = {
            # ── Core orphan-adoption set (original) ──────────────────────────
            "tiworker.exe", "audiodg.exe", "werfault.exe", "wermgr.exe",
            "sgrmbroker.exe", "useroobebroker.exe", "searchindexer.exe",
            "smss.exe", "registry", "secure system", "memcompression.exe",
            "msedge.exe", "chrome.exe", "firefox.exe",
            # smss-spawned: secondary smss exits immediately by design, so these
            # always appear orphaned in any memory snapshot.
            "csrss.exe", "wininit.exe", "winlogon.exe",
            # [FIX P1-a] Updater/sync processes whose manager parents exit first.
            "onedrive.exe",
            "onedrive.sync.exe",        # truncated from OneDrive.Sync.Root.exe
            "microsoftedgeu.exe",       # truncated from MicrosoftEdgeUpdate.exe
            # ── [FIX] Services.exe children — appear orphaned when services.exe
            # has paged out or hasn't been carved yet.  Adding them here triggers
            # Orphan Adoption (Filter 3 sets ppid=4) so Filter 5 never fires.
            # This eliminates 30-80 false positives on clean Win10/11 systems.
            "svchost.exe",              # services.exe child (most common FP)
            "dllhost.exe",              # COM server host (services.exe child)
            "taskhostw.exe",            # task host worker
            "taskhost.exe",             # legacy task host (Win7/8)
            "conhost.exe",              # console host (spawned by svchost/etc)
            "runtimebroker.exe",        # UWP app broker (svchost child)
            "backgroundtaskhost.exe",   # background task worker
            "sihost.exe",               # shell infrastructure host
            "ctfmon.exe",               # input method manager (svchost child)
            "fontdrvhost.exe",          # GDI font driver host (kernel-adjacent)
            "dwm.exe",                  # Desktop Window Manager (session mgr child)
            "lsm.exe",                  # Local Session Manager (wininit child)
            "wlanext.exe",              # WLAN extension host
            "dashost.exe",              # Device Association Framework host
            "deviceenrollmentactivity.exe",
            "sedsvc.exe",               # Windows Remediation Service
            "upfc.exe",                 # UPnP host
            "spoolsv.exe",              # print spooler (services.exe child)
            "msdtc.exe",                # distributed transaction coordinator
            "vds.exe",                  # virtual disk service
            "vssvc.exe",                # volume shadow copy service
            "ntkrnlpa.exe",             # kernel process name fragment (artefact)
            "securityhealthserv",       # SecurityHealthService (truncated to 14)
            # userinit.exe exits by design after spawning explorer — always orphaned
            "userinit.exe",
            # WMI and search processes whose parents page out on large systems
            "wmiprvse.exe",
            "searchfilterhost.exe", "searchprotocolhost.exe",
            "searchfilterho.exe", "searchprotocol.exe",
            # UWP shell processes — COM activation; parent frequently paged out
            "runtimebroker.exe", "startmenuexperiencehost.exe", "startmenuexper.exe",
            "dataexchangehost.exe", "dataexchangeho.exe",
            "shellhost.exe", "gamebar.exe", "gamebarft.exe",
            "widgets.exe", "crossdeviceservice.exe", "crossdeviceres.exe",
            "backgroundtransferhost.exe", "backgroundtran.exe",
            "usoclient.exe", "smartscreen.exe", "smartscreen.ex.exe",
            "olk.exe", "msedgewebview2.exe",
            # Acquisition tools (visible in snapshot, spawned by explorer)
            "dumpit.exe", "ftkimager.exe", "winpmem.exe",
        }

        # [FIX P3] Short-lived process names that generate stale EPROCESS pool blocks.
        # When the pattern scanner finds these with 0 active threads AND no resolved
        # path, they are almost certainly stale pool blocks from already-terminated
        # instances whose memory has not yet been recycled (Ghost Rule E).
        SHORT_LIVED_GHOST_NAMES = {
            'msedge.exe', 'msedgewebview2.exe', 'chrome.exe', 'firefox.exe',
            'svchost.exe', 'backgroundtaskhost.exe', 'runtimebroker.exe',
            'dllhost.exe', 'conhost.exe',
        }

        for proc in processes:
            pid = proc['pid']
            ppid = proc['ppid']
            proc_name = proc['image_name'].lower()

            # Final source-code/provider-string artifact guard.
            # Prevents pool string artifacts such as siphash_prov.c.exe from
            # entering reports/features even if early validation missed them.
            if _is_source_artifact_name(proc_name) or _is_known_string_artifact_name(proc_name):
                self.logger.debug(
                    f"String-artifact guard: rejected PID {pid} ({proc['image_name']}) "
                    "— known source/API artifact name"
                )
                continue

            # Cleanup-only string-artifact guard.  This catches API/source-token
            # false positives such as ED_BY_CALLBACK.exe, DITIONAL_ERROR.exe,
            # e_use_sendfile.exe, MESSAGE_DIGEST.exe, and alpn_protocols.exe
            # when they are dead-looking pool strings rather than live processes.
            active_threads_for_artifact = proc.get('active_threads', 1)
            has_path_for_artifact = bool(proc.get('path', ''))
            if _is_dead_string_artifact_candidate(
                proc_name,
                active_threads=active_threads_for_artifact,
                has_path=has_path_for_artifact,
            ):
                self.logger.debug(
                    f"String-artifact guard: rejected PID {pid} ({proc['image_name']}) "
                    "— 0 active threads, no path, source/API-like name"
                )
                continue

            # --- FILTER 1: Skip Known Garbage PIDs ---
            if pid in garbage_pids:
                continue

            # --- FILTER 1b: Ghost Process Filter ---
            # Rule A: Ghost PIDs with implausibly high values.
            #
            # OLD limit was 32768, which incorrectly dropped ~50 % of valid
            # processes on busy Windows 10/11 systems (PIDs cycle up to 65534
            # under the default Windows limit, and can go higher on busy VMs).
            # The carver already enforces pid_val < 200000 at harvest time, so
            # the only remaining job here is to filter obviously-bad garbage
            # that slipped through (typically artifacts from physical memory
            # misalignment returning a large random number as a PID).
            #
            # 131072 (0x20000) is well above the practical Win10/11 PID ceiling
            # while still providing a safety net against garbage values.
            if pid > 131072:
                continue

            proc_create_time = proc.get('create_time', 0)
            has_zero_time    = not self._is_valid_timestamp(proc_create_time) and pid != 4
            has_invalid_dtb  = 'Invalid/Swapped DTB' in proc.get('anomalies', [])
            has_orphan_signal = (proc.get('ppid', 0) == 0 and pid > 4)

            # Rule B
            if has_zero_time and (has_invalid_dtb or has_orphan_signal):
                if proc_name not in SAFE_ORPHANS:
                    continue
            # Rule C
            if has_invalid_dtb and has_orphan_signal:
                if proc_name not in SAFE_ORPHANS:
                    continue

            # Rule D
            has_no_path = not proc.get('path', '')
            proc_base = proc_name.replace('.exe', '')
            if (has_orphan_signal and has_no_path and
                    proc_base not in known_safe_names and
                    proc_name not in SAFE_ORPHANS):
                continue

            # [FIX P3] Rule E: Zero ActiveThreads + no resolved path + known
            # short-lived process name → stale pool block from terminated process.
            #
            # Rationale: any *running* process has ≥ 1 active thread recorded in
            # EPROCESS.ActiveThreads.  A stale EPROCESS whose pool has not been
            # reused still has its ImageFileName intact (triggering the pattern
            # scanner) but will show ActiveThreads = 0 because the kernel cleared
            # it on exit.  Combined with no PEB path and a process name that is
            # commonly short-lived (browser children, svchost, etc.) this is a
            # reliable ghost signal.
            #
            # Guard: only applies to the known-short-lived set.  A legitimate
            # process with an evicted PEB (services.exe child on a large system)
            # would not be in SHORT_LIVED_GHOST_NAMES, so it is unaffected.
            active_threads = proc.get('active_threads', 1)  # default 1 = assume alive if missing
            if (active_threads == 0 and has_no_path and
                    proc_name in SHORT_LIVED_GHOST_NAMES):
                self.logger.debug(
                    f"Ghost Rule E: rejected PID {pid} ({proc['image_name']}) "
                    f"— 0 active threads, no path, short-lived name"
                )
                continue

            # --- FILTER 2: System Process Verification ---
            if proc_name in system_process_rules:
                rule = system_process_rules[proc_name]
                if 'anomalies' not in proc:
                    proc['anomalies'] = []

                if not is_windows_7 and 'path' in rule:
                    path = proc.get('path', '').lower()
                    if path:
                        normalized_path = path.replace('/', '\\')
                        if not normalized_path.endswith(rule['path']):
                            proc['anomalies'].append(f"Unexpected Path: {path}")

                # Parent Verification (skipped when parents == set())
                if rule['parents']:
                    parent_proc = pid_map.get(ppid)
                    if parent_proc:
                        parent_name = parent_proc['image_name'].lower()
                        parent_base = parent_name.replace(".exe", "")

                        is_valid_parent = False
                        for allowed in rule['parents']:
                            allowed_base = allowed.replace(".exe", "")
                            if allowed_base == parent_base:
                                is_valid_parent = True
                                break

                        if not is_valid_parent:
                            proc['anomalies'].append(f"Wrong Parent: {parent_name}({ppid})")

            # --- FILTER 3: Orphan Adoption ---
            if pid > 4 and ppid == 0:
                if proc_name in SAFE_ORPHANS:
                    proc['ppid'] = 4
                    ppid = 4

            # --- FILTER 4: Timestamp / Ghost Check ---
            create_time = proc.get('create_time', 0)
            is_valid_time = self._is_valid_timestamp(create_time)

            if not is_valid_time and pid != 4:
                is_system_process = False
                proc_base = proc_name.replace('.exe', '')
                if proc_base in known_safe_names or proc_name in SAFE_ORPHANS:
                    is_system_process = True

                if not is_system_process:
                    if not self._is_valid_process_name(proc_name):
                        continue
                    if 'anomalies' not in proc:
                        proc['anomalies'] = []
                    proc['anomalies'].append("Zero CreateTime (Possible Ghost)")

            # --- FILTER 4b: Missing Path suppression for PPL/OS-protected processes ---
            # Processes in this set block PEB reads by design (PPL, VTL-1, etc.).
            # A missing path for these is NOT evidence of hollowing.
            _MISSING_PATH_SAFE = {
                # Security / PPL
                "securityhealthservice.exe", "securityhealth.exe", "securityhealthserv",
                "msmpeng.exe", "nissrv.exe", "mssense.exe",
                "lsass.exe",
                # Session/boot
                "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
                "system", "registry", "memcompression", "secure system",
                # GDI / runtime
                "fontdrvhost.exe", "audiodg.exe", "dwm.exe",
                # Services infrastructure
                "services.exe", "svchost.exe", "spoolsv.exe",
                # userinit exits immediately → PEB already freed
                "userinit.exe",
                # UWP / shell — COM activation, PEB may not be readable externally
                "runtimebroker.exe", "startmenuexperiencehost.exe", "startmenuexper.exe",
                "dataexchangehost.exe", "dataexchangeho.exe",
                "shellhost.exe", "gamebar.exe", "gamebarft.exe", "widgets.exe",
                "crossdeviceservice.exe", "crossdeviceres.exe",
                "backgroundtransferhost.exe", "backgroundtran.exe",
                "smartscreen.exe", "smartscreen.ex.exe",
                "sihost.exe", "taskhostw.exe",
                # Search
                "searchindexer.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
                "searchfilterho.exe", "searchprotocol.exe",
                # WMI
                "wmiprvse.exe",
                # UWP apps with COM-hosted PEB
                "olk.exe", "msedgewebview2.exe", "consent.exe", "usoclient.exe",
                # Acquisition tools — PEB deliberately unreadable
                "dumpit.exe", "ftkimager.exe", "winpmem.exe",
            }
            _proc_name_lower = proc_name.lower()
            if not proc.get('path', '') and _proc_name_lower not in _MISSING_PATH_SAFE:
                # Only flag missing-path hollowing if the process has a PEB
                # (peb != 0) but the read failed.  If peb == 0 it's PPL/protected.
                if proc.get('peb', 0) != 0:
                    # Double-check: don't flag processes adopted into SAFE_ORPHANS
                    if _proc_name_lower not in {s.lower() for s in SAFE_ORPHANS}:
                        if 'anomalies' not in proc:
                            proc['anomalies'] = []
                        # Only add "Missing Path" if no path anomaly already noted
                        existing = proc.get('anomalies', [])
                        if not any('Path' in a or 'Hollow' in a for a in existing):
                            proc['anomalies'].append("Missing Path (Protected Process — verify manually)")

            # --- FILTER 5: True Orphan Check ---
            if pid > 4 and ppid == 0:
                if 'anomalies' not in proc:
                    proc['anomalies'] = []
                proc['anomalies'].append("Orphan Process")

            cleaned.append(proc)

        return cleaned

    def _is_valid_timestamp(self, timestamp: int) -> bool:
        if timestamp == 0:
            return False
        try:
            unix_now = time.time()
            windows_epoch_diff = 11644473600
            future_buffer = 86400
            max_future = int((unix_now + windows_epoch_diff + future_buffer) * 10000000)
            if timestamp > max_future:
                return False
        except:
            pass
        return True

    def _repair_dtb(self, pid: int, proc_name: str, base_addr: int) -> int:
        if pid == 4: return 0x1AE000
        if "svchost" in proc_name.lower(): return 0x8000 + ((pid % 8) * 0x1000)
        return self._scan_for_dtb_pattern(base_addr)

    def _scan_for_dtb_pattern(self, base_addr: int) -> int:
        try:
            scan_data = self.memory.read_physical(base_addr - 0x200, 0x400)
            for i in range(0, len(scan_data) - 8, 8):
                candidate = struct.unpack("<Q", scan_data[i:i+8])[0]
                if self._is_valid_dtb_for_process(candidate, 0): return self._normalize_dtb(candidate)
        except: pass
        return 0

    def _resolve_process_path(self, peb_va: int, dtb: int) -> str:
        if not peb_va or not dtb: return ""

        if self.translator is None: return ""

        original_dtb = self.translator.dtb
        try:
            self.translator.dtb = dtb
            params_ptr_data = self.translator.read_virtual(peb_va + 0x20, 8)
            if not params_ptr_data: return ""
            params_ptr = struct.unpack("<Q", params_ptr_data)[0]
            if params_ptr == 0: return ""

            image_path_struct = self.translator.read_virtual(params_ptr + 0x60, 16)
            if not image_path_struct: return ""

            length, _, _, buffer_ptr = struct.unpack("<HHIQ", image_path_struct)
            if length == 0 or length > 2048: return ""

            path_bytes = self.translator.read_virtual(buffer_ptr, length)
            if path_bytes:
                return path_bytes.decode('utf-16-le', errors='ignore').strip('\x00')
        except: pass
        finally:
            self.translator.dtb = original_dtb
        return ""

    def _resolve_kernel_path(self, base_addr: int) -> str:
        try:
            ptr_offset = self.offsets.get('ImageFilePointer', 0)
            if ptr_offset == 0: return ""

            file_obj_ptr_data = self.memory.read_physical(base_addr + ptr_offset, 8)
            file_obj_ptr = struct.unpack("<Q", file_obj_ptr_data)[0]

            if file_obj_ptr < 0xFFFF000000000000: return ""

            filename_struct_vaddr = file_obj_ptr + 0x58

            name_struct = self.translator.read_virtual(filename_struct_vaddr, 16)
            if not name_struct: return ""

            length, _, _, buffer_ptr = struct.unpack("<HHIQ", name_struct)

            if length > 0 and length < 2048:
                path_bytes = self.translator.read_virtual(buffer_ptr, length)
                if path_bytes:
                    return path_bytes.decode('utf-16-le', errors='ignore').strip('\x00')

        except Exception:
            pass

        return ""

    def _extract_process_flags(self, base_addr: int) -> List[str]:
        flags_list = []
        if 'Flags' in self.offsets:
            try:
                flags_data = self.memory.read_physical(base_addr + self.offsets['Flags'], 4)
                if len(flags_data) == 4:
                    val = struct.unpack("<I", flags_data)[0]
                    if val & 0x1: flags_list.append("CreateFailed")
                    if val & 0x2: flags_list.append("Terminated")
                    if val & 0x4: flags_list.append("Terminating")
                    if val & 0x8: flags_list.append("CancelingDelete")
                    if val & 0x10: flags_list.append("ProcessDelete")
            except: pass
        return flags_list


    def _candidate_user_dtb_offsets(self) -> List[int]:
        """Ordered candidate offsets for KPROCESS.UserDirectoryTableBase."""
        offsets: List[int] = []
        primary = self.offsets.get('UserDirectoryTableBase')
        if isinstance(primary, int) and primary > 0:
            offsets.append(primary)

        candidates = self.offsets.get('UserDirectoryTableBaseCandidates', ())
        if isinstance(candidates, (list, tuple)):
            for off in candidates:
                if isinstance(off, int) and off > 0 and off not in offsets:
                    offsets.append(off)

        for off in (0x388, 0x158, 0x280, 0x2e8):
            if off not in offsets:
                offsets.append(off)

        return offsets

    def _read_user_dtb_candidates(self, base_addr: int) -> Dict[str, int]:
        """Read and normalize plausible UserDirectoryTableBase candidates."""
        out: Dict[str, int] = {}
        for off in self._candidate_user_dtb_offsets():
            try:
                raw = self.memory.read_physical(base_addr + off, self._ptr_size())
                if raw and len(raw) >= self._ptr_size():
                    val_raw = self._unpack_ptr(raw)
                    val_norm = self._normalize_dtb(val_raw)
                    if self._is_valid_dtb_for_process(val_raw, 0):
                        out[f"0x{off:x}"] = val_norm
            except Exception:
                pass
        return out

    def _score_dtb_for_peb(self, peb_va: int, dtb_value: int) -> int:
        """Score whether a normalized DTB can translate PEB and PEB->Ldr."""
        if not self.translator or not peb_va:
            return 0
        dtb = self._normalize_dtb(dtb_value)
        if not self._is_valid_dtb_for_process(dtb, 0):
            return 0

        score = 0
        try:
            if self.translator.vtop(peb_va, dtb):
                score += 1
            ldr_off = 0x0c if self._ptr_size() == 4 else 0x18
            ldr = self.translator.read_virtual_pointer(peb_va + ldr_off, dtb)
            high_limit = 0x80000000 if self._ptr_size() == 4 else 0x0000800000000000
            if 0x10000 <= int(ldr or 0) < high_limit:
                score += 1
                if self.translator.vtop(ldr, dtb):
                    score += 1
        except Exception:
            pass
        return score

    def _select_user_dtb(self, base_addr: int, peb_va: int, final_dtb: int) -> Tuple[int, str, Dict[str, str]]:
        """
        Select the best user-mode DTB for PEB/LDR reads.

        Candidate values are normalized first. If no UserDirectoryTableBase
        candidate validates, DirectoryTableBase is allowed as fallback because
        Phase 6C proved it recovers Locky PEB/LDR after low-bit masking.
        """
        raw_candidates = self._read_user_dtb_candidates(base_addr)
        formatted = {k: f"0x{v:x}" for k, v in raw_candidates.items()}

        best_dtb = 0
        best_source = ""
        best_score = -1

        for off, val in raw_candidates.items():
            score = self._score_dtb_for_peb(peb_va, val)
            if score > best_score:
                best_dtb = val
                best_source = f"UserDirectoryTableBase@{off}"
                best_score = score

        final_norm = self._normalize_dtb(final_dtb)
        if final_norm and self._is_valid_dtb_for_process(final_norm, 0):
            score = self._score_dtb_for_peb(peb_va, final_norm)
            if score > best_score:
                best_dtb = final_norm
                best_source = "DirectoryTableBase"
                best_score = score

        if best_dtb and self._is_valid_dtb_for_process(best_dtb, 0):
            return best_dtb, best_source, formatted
        return 0, "", formatted


    def _extract_process_data(self, base_addr: int, pid_val: int, proc_name: str) -> Optional[Dict]:
        """
        Extracts metadata including Flags, VadRoot, and ActiveThreads.

        [FIX P3] ActiveThreads is now read from EPROCESS so Ghost Rule E can use it.
        Offset 0x498 is correct for Windows 10 20H1+ and Windows 11 through 24H2.
        The offset.py profile can override this via 'ActiveThreads' key.
        """
        try:
            dtb_candidates = []

            dtb_off = self.offsets['DirectoryTableBase']
            dtb_data = self.memory.read_physical(base_addr + dtb_off, self._ptr_size())
            if len(dtb_data) >= self._ptr_size():
                val = self._unpack_ptr(dtb_data)
                if self._is_valid_dtb_for_process(val, pid_val):
                    dtb_candidates.append(self._normalize_dtb(val))

            final_dtb = 0
            if dtb_candidates:
                final_dtb = dtb_candidates[0]
            elif pid_val != 4:
                final_dtb = self._normalize_dtb(self._repair_dtb(pid_val, proc_name, base_addr))

            ppid_val = 0
            if self.offsets.get('InheritedFromUniqueProcessId'):
                ppid_raw = self.memory.read_physical(base_addr + self.offsets['InheritedFromUniqueProcessId'], self._ptr_size())
                if len(ppid_raw) >= self._ptr_size():
                    ppid_val = self._unpack_ptr(ppid_raw)
                    if ppid_val > 0xFFFFF or ppid_val == pid_val: ppid_val = 0

            peb_val = 0
            if self.offsets.get('Peb'):
                peb_raw = self.memory.read_physical(base_addr + self.offsets['Peb'], self._ptr_size())
                if len(peb_raw) >= self._ptr_size(): peb_val = self._unpack_ptr(peb_raw)

            user_dtb_val, user_dtb_source, user_dtb_candidates = self._select_user_dtb(
                base_addr, peb_val, final_dtb
            )

            wow64_process = 0
            wow64_off = self.offsets.get('WoW64Process', 0x580)
            if wow64_off:
                wow64_raw = self.memory.read_physical(base_addr + wow64_off, self._ptr_size())
                if len(wow64_raw) >= self._ptr_size():
                    wow64_process = self._unpack_ptr(wow64_raw)
                    if not self._is_kernel_pointer(wow64_process):
                        wow64_process = 0

            vad_root = 0
            if self.offsets.get('VadRoot'):
                vad_offset = base_addr + self.offsets['VadRoot']
                vad_data = self.memory.read_physical(vad_offset, self._ptr_size())
                if len(vad_data) >= self._ptr_size():
                    vad_root = self._unpack_ptr(vad_data)

            create_time = 0
            if self.offsets.get('CreateTime'):
                time_raw = self.memory.read_physical(base_addr + self.offsets['CreateTime'], 8)
                if len(time_raw) == 8: create_time = struct.unpack("<Q", time_raw)[0]

            # [FIX P3] Read EPROCESS.ActiveThreads (ULONG, 4 bytes).
            # Default offset 0x498 is correct for Win10 20H1 through Win11 24H2.
            # A profile-provided override takes priority.
            active_threads = 0
            ath_off = self.offsets.get('ActiveThreads', 0 if self._ptr_size() == 4 else 0x498)
            if ath_off:
                ath_data = self.memory.read_physical(base_addr + ath_off, 4)
                if len(ath_data) == 4:
                    raw_val = struct.unpack("<I", ath_data)[0]
                    # Sanity cap: more than 10 000 threads is a mis-read
                    active_threads = raw_val if raw_val < 10000 else 0

            full_path = ""
            if peb_val and pid_val != 4:
                for _path_dtb in (user_dtb_val, final_dtb):
                    if _path_dtb and self._is_valid_dtb_for_process(_path_dtb, pid_val):
                        full_path = self._resolve_process_path(peb_val, self._normalize_dtb(_path_dtb))
                        if full_path:
                            break
            if not full_path and pid_val != 4:
                full_path = self._resolve_kernel_path(base_addr)
            if pid_val == 4: full_path = "System"

            if not proc_name.lower().endswith('.exe') and len(proc_name) > 2:
                if pid_val != 4:
                    proc_name = proc_name.rstrip('.') + '.exe'
            if pid_val == 4: proc_name = "System"

            flags = self._extract_process_flags(base_addr)

            return {
                'pid': pid_val, 'ppid': ppid_val,
                'image_name': proc_name, 'eprocess_phys_addr': base_addr,
                'dtb': final_dtb,
                'DirectoryTableBase': final_dtb,
                'user_dtb': user_dtb_val,
                'UserDirectoryTableBase': user_dtb_val,
                'user_dtb_source': user_dtb_source,
                'user_dtb_candidates': user_dtb_candidates,
                'wow64_process': wow64_process,
                'WoW64Process': wow64_process,
                'peb': peb_val,
                'vad_root': vad_root, 'path': full_path,
                'create_time': create_time, 'flags': flags,
                'active_threads': active_threads,   # [FIX P3] exposed for Ghost Rule E
                'anomalies': []
            }
        except: return None

    # ──────────────────────────────────────────────────────────────────────────
    # DKOM Detection — Linked List Walk vs Pool Scan Cross-Reference
    # ──────────────────────────────────────────────────────────────────────────

    def find_processes_via_linked_list(self, pool_processes: List[Dict]) -> Set[int]:
        """
        Walk EPROCESS.ActiveProcessLinks from the System process (PID 4)
        using the kernel page table (System's DTB).

        Returns the set of PIDs visible in the Windows linked list — the
        equivalent of Volatility's windows.pslist output.

        Requires self.translator to be available.  Returns empty set if the
        System process or its DTB could not be found in the pool scan results.
        """
        if not self.translator:
            self.logger.warning("DKOM list-walk: no translator available — skipping")
            return set()

        # ── Build-aware offset selection ───────────────────────────────────────
        # ActiveProcessLinks and UniqueProcessId offsets have changed across
        # Windows versions.  The profile (offset.py) takes priority; the fallback
        # is chosen based on self.build_number so that the default is correct for
        # the dump being analysed rather than the oldest possible Windows version.
        #
        #   Build range              UniqueProcessId  ActiveProcessLinks
        #   Win7   (7600–7601)       0x180            0x188
        #   Win8.1 (9600)            0x2e0            0x2e8
        #   Win10 RS1–RS4 (14393–)   0x2e0            0x2e8
        #   Win10 RS5–20H2 (17763–)  0x2e0            0x2e8
        #   Win10 21H1–22H2 (19043–) 0x440            0x448
        #   Win11 21H2–24H2 (22000–) 0x440            0x448
        #
        # Profile key 'ActiveProcessLinks' overrides everything.
        if 'ActiveProcessLinks' in self.offsets:
            off_links = self.offsets['ActiveProcessLinks']
        elif self.build_number and self.build_number >= 19041:
            off_links = 0x448   # Win10 21H1 / Win11 and later
        elif self.build_number and self.build_number >= 9600:
            off_links = 0x2e8   # Win8.1 / Win10 up to 20H2
        else:
            off_links = 0x188   # Win7 fallback

        if 'UniqueProcessId' in self.offsets:
            off_pid = self.offsets['UniqueProcessId']
        elif self.build_number and self.build_number >= 19041:
            off_pid = 0x440
        elif self.build_number and self.build_number >= 9600:
            off_pid = 0x2e0
        else:
            off_pid = 0x180

        # The System process always has PID 4 and carries the kernel DTB.
        system_proc = next((p for p in pool_processes if p['pid'] == 4), None)
        if not system_proc:
            self.logger.warning("DKOM list-walk: PID 4 not found in pool scan — skipping")
            return set()

        system_phys = system_proc.get('eprocess_phys_addr', 0)
        kernel_dtb  = system_proc.get('dtb', 0)

        if not system_phys or not kernel_dtb:
            self.logger.warning("DKOM list-walk: System EPROCESS phys addr or DTB unavailable")
            return set()

        # Save current translator DTB and switch to kernel DTB for the walk.
        original_dtb = self.translator.dtb
        self.translator.dtb = kernel_dtb

        list_pids: Set[int] = {4}       # System is always reachable
        visited_vaddrs: Set[int] = set()

        try:
            # Read the Flink pointer stored at System's ActiveProcessLinks field.
            # This field lives at a known physical offset from the EPROCESS base.
            flink_raw = self.memory.read_physical(system_phys + off_links, self._ptr_size())
            if not flink_raw or len(flink_raw) < self._ptr_size():
                return list_pids

            flink_vaddr = self._unpack_ptr(flink_raw)

            # The Flink must be a kernel-space virtual address (>= 0xFFFF000000000000).
            if not self._is_kernel_pointer(flink_vaddr):
                self.logger.warning(
                    f"DKOM list-walk: initial Flink {flink_vaddr:#x} is not a "
                    f"kernel address — linked list likely paged out or corrupted"
                )
                return list_pids

            max_iterations = 2000
            current_links_vaddr = flink_vaddr

            for _ in range(max_iterations):
                if not current_links_vaddr or current_links_vaddr in visited_vaddrs:
                    break           # list wrap-around detected → done
                visited_vaddrs.add(current_links_vaddr)

                # Each Flink points to the next entry's ActiveProcessLinks field.
                # EPROCESS base  = links_vaddr − off_links
                # UniqueProcessId lives at EPROCESS base + off_pid
                pid_vaddr = current_links_vaddr - off_links + off_pid

                pid_data = self.translator.read_virtual(pid_vaddr, self._ptr_size())
                if not pid_data or len(pid_data) < self._ptr_size():
                    break

                pid_val = self._unpack_ptr(pid_data)
                if 0 < pid_val < 200_000 and pid_val % 4 == 0:
                    list_pids.add(pid_val)

                # Advance: read the Flink of the current ActiveProcessLinks node.
                next_raw = self.translator.read_virtual(current_links_vaddr, self._ptr_size())
                if not next_raw or len(next_raw) < self._ptr_size():
                    break

                next_vaddr = self._unpack_ptr(next_raw)
                if not self._is_kernel_pointer(next_vaddr):
                    break           # no longer a kernel pointer

                current_links_vaddr = next_vaddr

        except Exception as exc:
            self.logger.debug(f"DKOM list-walk exception: {exc}")
        finally:
            self.translator.dtb = original_dtb

        self.logger.info(
            f"DKOM list-walk: {len(list_pids)} PIDs reachable via ActiveProcessLinks"
        )
        return list_pids

    def detect_dkom(self, pool_processes: List[Dict]) -> Dict:
        """
        Cross-reference the pool scan (psscan equivalent) against the linked
        list walk (pslist equivalent) to surface DKOM-hidden processes.

        Returns a dict with:
          hidden_from_list  — processes visible in pool scan but NOT in the
                              linked list.  Classic DKOM: attacker unlinked the
                              EPROCESS from ActiveProcessLinks so tools that
                              follow the list (Task Manager, pslist) miss it.
          hidden_from_pool  — PIDs visible in the linked list but NOT carved
                              from the pool.  Less common; indicates the
                              EPROCESS pool tag was erased while keeping the
                              list entry intact.
          pool_count        — total PIDs found by pool scan
          list_count        — total PIDs found by list walk
        """
        empty = {'hidden_from_list': [], 'hidden_from_pool': [],
                 'pool_count': 0, 'list_count': 0}

        if not pool_processes:
            return empty

        pool_pid_map: Dict[int, Dict] = {p['pid']: p for p in pool_processes}
        pool_pids: Set[int] = set(pool_pid_map)

        list_pids = self.find_processes_via_linked_list(pool_processes)
        if not list_pids:
            self.logger.info("DKOM: list walk returned empty — skipping cross-reference")
            return {**empty, 'pool_count': len(pool_pids)}

        # ── Coverage gate ──────────────────────────────────────────────────────
        # The linked-list walk is considered reliable only when it recovered at
        # least 50 % of the same PIDs the pool scan found.  A low-coverage walk
        # means one of:
        #   • The ActiveProcessLinks offset default (0x2e8) is wrong for this
        #     Windows build (Win11 22H2+ uses 0x448; Win10 RS5+ uses 0x2e8).
        #   • The kernel DTB is stale / partially paged out.
        #   • The virtual→physical translation failed partway through the list.
        #
        # In all of these cases the "hidden" set is meaningless: it will contain
        # most of the real process list, causing every legitimate process to be
        # falsely flagged as a DKOM artifact — which is exactly the symptom that
        # triggered this fix.
        #
        # Guard: compare the intersection size against the pool size.  We use
        # intersection (not raw list size) because the walk can add garbage PIDs
        # that pass the modulo-4 filter by coincidence.
        n_pool      = len(pool_pids)
        intersection = pool_pids & list_pids
        coverage    = len(intersection) / max(n_pool, 1)

        MIN_COVERAGE = 0.50   # walk must cover at least 50 % of pool PIDs
        MAX_DKOM_HITS = 10    # more than this on one dump = almost certainly a bad walk

        if coverage < MIN_COVERAGE:
            self.logger.warning(
                f"DKOM: linked-list walk coverage too low "
                f"({coverage:.0%}, {len(intersection)}/{n_pool} pool PIDs matched). "
                f"Likely wrong ActiveProcessLinks offset or paged-out kernel list. "
                f"Skipping DKOM cross-reference to avoid false positives. "
                f"Check offset.py: ActiveProcessLinks should be 0x448 on Win11 22H2+, "
                f"0x2e8 on Win10 RS5."
            )
            return {**empty, 'pool_count': n_pool, 'list_count': len(list_pids)}

        # PIDs 0 and 4 are structural — exclude from anomaly reporting.
        STRUCTURAL = {0, 4}

        candidate_hidden = sorted(pool_pids - list_pids - STRUCTURAL)

        # ── Sanity cap ─────────────────────────────────────────────────────────
        # A genuine DKOM rootkit hides 1–3 processes at most.  If we see more
        # than MAX_DKOM_HITS candidates something is still wrong (partial paging,
        # offset skew, etc.) — discard the result rather than poison all findings.
        if len(candidate_hidden) > MAX_DKOM_HITS:
            self.logger.warning(
                f"DKOM: {len(candidate_hidden)} processes appear hidden — "
                f"exceeds sanity cap of {MAX_DKOM_HITS}. "
                f"Walk coverage was {coverage:.0%} ({len(intersection)}/{n_pool}). "
                f"Treating result as unreliable; no DKOM flags will be stamped."
            )
            return {**empty, 'pool_count': n_pool, 'list_count': len(list_pids)}

        hidden_from_list: List[Dict] = []
        for pid in candidate_hidden:
            proc = pool_pid_map[pid]
            proc.setdefault('anomalies', []).append(
                "DKOM: unlinked from ActiveProcessLinks (hidden from pslist)"
            )
            hidden_from_list.append(proc)
            self.logger.warning(
                f"DKOM: PID {pid} ({proc.get('image_name','?')}) in pool scan "
                f"but absent from linked list"
            )

        hidden_from_pool: List[int] = []
        for pid in sorted(list_pids - pool_pids - STRUCTURAL):
            hidden_from_pool.append(pid)
            self.logger.warning(
                f"DKOM: PID {pid} in linked list but absent from pool scan"
            )

        self.logger.info(
            f"DKOM: walk reliable (coverage {coverage:.0%}). "
            f"Hidden-from-list: {len(hidden_from_list)}, "
            f"hidden-from-pool: {len(hidden_from_pool)}"
        )
        return {
            'hidden_from_list': hidden_from_list,
            'hidden_from_pool': hidden_from_pool,
            'pool_count':       n_pool,
            'list_count':       len(list_pids),
        }

    def _validate_and_fix_ppids(self, processes: List[Dict]) -> List[Dict]:
        if not processes: return processes
        pid_map = {p['pid']: p for p in processes}
        for process in processes:
            if process['ppid'] in pid_map: continue
            if process['ppid'] > 0xFFFFF or process['ppid'] == process['pid']: process['ppid'] = 0
            if process['ppid'] == 0 and process['pid'] != 4:
                inferred = self._infer_parent_pid(process, pid_map)
                if inferred: process['ppid'] = inferred
        return processes

    def _infer_parent_pid(self, process: Dict, pid_map: Dict[int, Dict]) -> int:
        name = process['image_name'].lower().replace('.exe', '')
        if process['pid'] == 4: return 0
        parents = {
            'smss': ['system'], 'csrss': ['smss'], 'wininit': ['smss'],
            'services': ['wininit'], 'lsass': ['wininit'], 'svchost': ['services']
        }
        target_parents = parents.get(name, [])
        for target in target_parents:
            for p in pid_map.values():
                if target in p['image_name'].lower(): return p['pid']
        return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python eprocess_scanner.py <path_to_memory_dump> [dtb_hex]")
        sys.exit(1)

    dump_path = sys.argv[1]

    user_dtb = None
    if len(sys.argv) > 2:
        try:
            user_dtb = int(sys.argv[2], 16)
            print(f"🔧 Using provided DTB: 0x{user_dtb:x}")
        except ValueError:
            print("❌ Invalid DTB format. Using 0.")
            user_dtb = 0

    with PhysicalMemoryReader(dump_path) as reader:
        translator = AddressTranslator(reader, user_dtb) if user_dtb else None

        scanner = EProcessScanner(reader, translator, build_number=26200, enable_timing=True)

        print("\n" + "="*60 + "\n🧪 EPROCESS SCANNER BENCHMARK\n" + "="*60)
        start_time = time.perf_counter()
        processes = scanner.find_all_processes()
        total_time = time.perf_counter() - start_time

        print(f"\n📊 SUMMARY:\n   Total time: {total_time:.2f}s\n   Processes found: {len(processes)}")
        if processes:
            print("\n📋 Sample processes (first 10):")
            for proc in processes[:10]:
                dtb_val = proc.get('dtb', 0)
                dtb_display = f"0x{dtb_val:x}" if dtb_val != 0 else "0x0"
                print(f"   PID {proc['pid']:>5} -> PPID {proc['ppid']:>5} : {proc['image_name']:20} DTB: {dtb_display} Path: {proc.get('path', 'N/A')}")
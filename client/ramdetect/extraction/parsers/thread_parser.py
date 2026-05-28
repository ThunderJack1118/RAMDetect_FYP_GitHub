"""
ramdetect/extraction/parsers/thread_parser.py
=============================================
Native Thread Parser — Zero-Volatility Mode
============================================
Enumerates ETHREAD structures directly from physical memory by walking the
ThreadListHead doubly-linked list embedded in each EPROCESS.

No external tools (Volatility, vol.exe, winpmem, etc.) are required or used.

Architecture:
  ThreadParser.__init__()              — loads dynamic offsets via offset.py
  parse_ethread()                      — parse one ETHREAD at a physical address
  enumerate_threads_for_process()      — walk ThreadListHead for a given PID
  _check_thread_anomalies()            — start-address heuristic anomaly checks
  detect_suspicious_threads()          — legacy helper over all-thread dict
"""

import logging
import os
import struct
from typing import Dict, List, Optional, Set

from ramdetect.utils.logger import get_logger
from ramdetect.extraction.parsers.memory_reader import PhysicalMemoryReader
from ramdetect.extraction.parsers.address_translator import AddressTranslator
from ramdetect.utils.offset import get_thread_offsets


class ThreadParser:
    """
    Parse ETHREAD structures and enumerate threads natively.

    Supports Windows 10 (1803+) through Windows 11 (24H2).
    """

    # ──────────────────────────────────────────────────────────────────────────
    # Static lookup tables
    # ──────────────────────────────────────────────────────────────────────────

    THREAD_STATES: Dict[int, str] = {
        0: "Initialized", 1: "Ready",        2: "Running",       3: "Standby",
        4: "Terminated",  5: "Waiting",       6: "Transition",    7: "DeferredReady",
        8: "GateWait",    9: "DeferredReady",
    }

    WAIT_REASONS: Dict[int, str] = {
        0:  "Executive",        1:  "FreePage",          2:  "PageIn",
        3:  "PoolAllocation",   4:  "DelayExecution",    5:  "Suspended",
        6:  "UserRequest",      7:  "WrExecutive",       8:  "WrVirtualMemory",
        9:  "WrPageOut",        10: "WrPageIn",          11: "WrPoolAllocation",
        12: "WrDelayExecution", 13: "WrSuspended",       14: "WrUserRequest",
        15: "WrEventPair",
    }

    # Processes whose threads are legitimately dispatched with kernel-mode start
    # addresses.  On Windows 10/11 the kernel dispatcher records 0xFFFF… in
    # ETHREAD.StartAddress for these processes rather than the user-mode entry
    # point.  Flagging them produces 150-250 false positives per clean-system
    # scan.
    KERNEL_THREAD_SAFE: frozenset = frozenset({
        # GDI / graphics
        "fontdrvhost.exe", "dwm.exe", "win32kfull.sys",
        # Audio
        "audiodg.exe",
        # Security / PPL
        "lsass.exe", "securityhealthservice.exe", "securityhealth.exe",
        "securityhealthserv", "msmpeng.exe", "nissrv.exe", "mssense.exe",
        # Session management / bootstrap
        "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "lsm.exe",
        # Service infrastructure
        "services.exe", "svchost.exe", "dllhost.exe", "spoolsv.exe", "msdtc.exe",
        # Runtime brokers / UWP
        "runtimebroker.exe", "sihost.exe", "ctfmon.exe",
        # Shell / search
        "explorer.exe", "searchhost.exe", "searchindexer.exe",
        # Modern apps (truncated EPROCESS names included)
        "olk.exe",
        "startmenuexper.exe", "startmenuexperiencehost.exe",
        "crossdeviceres.exe", "crossdeviceservice.exe",
        "dataexchangeho.exe", "dataexchangehost.exe",
        "shellhost.exe",
        "backgroundtran.exe", "backgroundtransferhost.exe",
        "smartscreen.ex.exe", "smartscreen.exe",
        "searchfilterho.exe", "searchfilterhost.exe",
        "searchprotocol.exe", "searchprotocolhost.exe",
        "widgets.exe", "gamebar.exe", "gamebarft.exe",
        # VMware tools (hypervisor kernel traps)
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        # Edge WebView2 (COM/OLE host threads)
        "msedgewebview2.exe",
        # UWP update / background work
        "usoclient.exe", "onedrivesetup.exe",
    })

    # ──────────────────────────────────────────────────────────────────────────
    # Initialisation
    # ──────────────────────────────────────────────────────────────────────────

    def __init__(
        self,
        memory_reader: PhysicalMemoryReader,
        translator: AddressTranslator,
        build_number: int = None,
        *,
        is_64bit: Optional[bool] = None,
        is_pae: Optional[bool] = None,
        symbols: Optional[str] = None,
        offsets_override: Optional[Dict] = None,
    ) -> None:
        """
        Parameters
        ----------
        memory_reader : PhysicalMemoryReader
        translator    : AddressTranslator
        build_number  : Windows build number (e.g. 19041).  Used to select the
                        correct ETHREAD/KTHREAD field offsets via offset.py.
        """
        self.memory     = memory_reader
        self.translator = translator
        self.logger     = get_logger(__name__)

        # Suppress console output — the GUI / CLI caller owns the console.
        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and \
               not isinstance(handler, logging.FileHandler):
                self.logger.removeHandler(handler)
        self.logger.propagate = False

        if offsets_override:
            self.offsets = dict(offsets_override)
        else:
            self.offsets = get_thread_offsets(
                build_number,
                is_64bit=is_64bit,
                is_pae=is_pae,
                symbols=symbols,
            )
        self.pointer_size = int(self.offsets.get("pointer_size", getattr(self.translator, "pointer_size", 8)) or 8)
        self.is_pae = bool(self.offsets.get("is_pae", is_pae))

        self.stats: Dict[str, int] = {
            "threads_found":    0,
            "orphan_threads":   0,
            "suspicious_threads": 0,
        }

        self.logger.info(
            f"ThreadParser initialised (native, zero-Volatility, build={build_number}, "
            f"ptr={self.pointer_size}, pae={self.is_pae}, "
            f"profile={self.offsets.get('name', 'unknown')})"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Low-level memory helpers
    # ──────────────────────────────────────────────────────────────────────────

    def read_uint64(self, physical_addr: int) -> int:
        """Read a little-endian 64-bit value from *physical_addr*."""
        try:
            data = self.memory.read_physical(physical_addr, 8)
            if len(data) == 8:
                return struct.unpack("<Q", data)[0]
        except Exception:
            pass
        return 0

    def read_uint32(self, physical_addr: int) -> int:
        """Read a little-endian 32-bit value from *physical_addr*."""
        try:
            data = self.memory.read_physical(physical_addr, 4)
            if len(data) == 4:
                return struct.unpack("<I", data)[0]
        except Exception:
            pass
        return 0

    def _ptr_size(self) -> int:
        return 4 if int(getattr(self, "pointer_size", 8) or 8) == 4 else 8

    def read_ptr(self, physical_addr: int) -> int:
        """Read a native pointer-sized value from physical memory."""
        try:
            size = self._ptr_size()
            data = self.memory.read_physical(int(physical_addr or 0), size)
            if data and len(data) >= size:
                return struct.unpack("<I" if size == 4 else "<Q", data[:size])[0]
        except Exception:
            pass
        return 0

    def _is_kernel_va(self, value: int) -> bool:
        try:
            value = int(value or 0)
        except Exception:
            return False
        if self._ptr_size() == 4:
            return 0x80000000 <= value <= 0xFFFFFFFF
        return value >= 0xFFFF000000000000


    # ──────────────────────────────────────────────────────────────────────────
    # Anomaly detection
    # ──────────────────────────────────────────────────────────────────────────

    def _check_thread_anomalies(
        self,
        start_addr: int,
        pid:        int,
        proc_name:  str = "",
    ) -> List[str]:
        """
        Evaluate a thread's start address for genuinely suspicious patterns.

        Parameters
        ----------
        start_addr : ETHREAD.StartAddress value
        pid        : owning process ID (PID 4 = System, always kernel)
        proc_name  : owning process image name (used for KERNEL_THREAD_SAFE
                     allow-list to suppress PPL / GDI / session-manager FPs)

        Returns
        -------
        List of anomaly strings (empty → clean).
        """
        anomalies: List[str] = []
        name_lower = (proc_name or "").lower().strip()

        # 1. Zero start address — zombie thread or memory zeroed after termination.
        if start_addr == 0:
            anomalies.append("Zero Start Address")

        # 2. Kernel-mode start address (0xFFFF000000000000+).
        #    PID 4 (System) always runs kernel threads — never flag.
        #    Whitelisted processes (PPL, GDI, session managers) are also exempt.
        elif self._is_kernel_va(start_addr):
            if pid != 4 and name_lower not in self.KERNEL_THREAD_SAFE:
                anomalies.append("Kernel Mode Start Address")

        return anomalies

    # ──────────────────────────────────────────────────────────────────────────
    # ETHREAD parsing
    # ──────────────────────────────────────────────────────────────────────────

    def parse_ethread(
        self,
        ethread_pa:  int,
        target_pid:  int = None,
        proc_name:   str = "",
    ) -> Optional[Dict]:
        """
        Parse a single ETHREAD structure at physical address *ethread_pa*.

        Parameters
        ----------
        ethread_pa : physical address of the ETHREAD block
        target_pid : when set, discard threads whose PID does not match
        proc_name  : image name forwarded to _check_thread_anomalies for
                     the KERNEL_THREAD_SAFE allow-list

        Returns
        -------
        Thread dict on success, None on parse failure or PID mismatch.
        """
        try:
            # 1. CLIENT_ID (UniqueProcess / UniqueThread)
            cid_offset = ethread_pa + self.offsets["Cid"]
            ptr_sz = self._ptr_size()
            pid = self.read_ptr(cid_offset)
            tid = self.read_ptr(cid_offset + ptr_sz)

            # Discard garbage entries
            if tid == 0 or tid > 0x100000:
                return None
            if target_pid is not None and pid != target_pid:
                return None

            # 2. Forensically critical addresses
            start_addr  = self.read_ptr(ethread_pa + self.offsets["StartAddress"])
            win32_start = self.read_ptr(ethread_pa + self.offsets["Win32StartAddress"])
            teb_addr    = self.read_ptr(ethread_pa + self.offsets["Teb"])

            # 3. Execution state
            state_raw  = self.memory.read_physical(ethread_pa + self.offsets["State"],      1)
            state      = state_raw[0]  if state_raw  else 0
            wait_raw   = self.memory.read_physical(ethread_pa + self.offsets["WaitReason"], 1)
            wait_reason = wait_raw[0] if wait_raw   else 0
            prio_raw   = self.memory.read_physical(ethread_pa + self.offsets["Priority"],   1)
            priority   = prio_raw[0]  if prio_raw   else 0

            # 4. Stack bounds (used for future stack-walk analysis)
            stack_base  = self.read_ptr(ethread_pa + self.offsets["StackBase"])
            stack_limit = self.read_ptr(ethread_pa + self.offsets["StackLimit"])

            self.stats["threads_found"] += 1

            anomalies = self._check_thread_anomalies(start_addr, pid, proc_name)
            status    = "SUSPICIOUS" if anomalies else "CLEAN"

            return {
                "ethread_phys_addr":  ethread_pa,
                "tid":                tid,
                "pid":                pid,
                "start_address":      start_addr,
                "win32_start_address": win32_start,
                "teb":                teb_addr,
                "state":              state,
                "state_name":         self.THREAD_STATES.get(state, f"Unknown({state})"),
                "wait_reason":        wait_reason,
                "wait_reason_name":   self.WAIT_REASONS.get(wait_reason, "Unknown"),
                "priority":           priority,
                "stack_base":         stack_base,
                "stack_limit":        stack_limit,
                "anomalies":          anomalies,
                "status":             status,
            }

        except Exception as exc:
            self.logger.debug(f"Failed to parse ETHREAD at 0x{ethread_pa:x}: {exc}")
            return None

    # ──────────────────────────────────────────────────────────────────────────
    # Thread enumeration
    # ──────────────────────────────────────────────────────────────────────────

    def enumerate_threads_for_process(
        self,
        eprocess_pa:      int,
        target_pid:       int,
        eprocess_offsets: Dict = None,
        process_dtb:      int  = None,
        proc_name:        str  = "",
    ) -> List[Dict]:
        """
        Walk process thread lists and return all ETHREADs belonging to target_pid.

        Phase 9 fix:
        - Windows thread list pointers are kernel virtual addresses, even though
          the EPROCESS base passed here is a physical address.
        - The previous implementation could still return 0 threads when a stale
          EPROCESS offset profile overrode the correct ETHREAD profile, or when
          only one list family was tried.
        - This method now tries both supported list families:

            A) EPROCESS.ThreadListHead + ETHREAD.ThreadListEntry
            B) KPROCESS.ThreadListHead + KTHREAD.ThreadListEntry

          It keeps the candidate walk that recovers the most PID-matching
          threads. This is parser recovery only; it does not affect ML verdict
          logic, thresholds, or feature decisions.
        """
        threads: List[Dict] = []

        if not self.translator:
            self.logger.warning(f"PID {target_pid}: no AddressTranslator available — skipping thread walk")
            return threads

        def _norm_dtb(value: int) -> int:
            try:
                v = int(value or 0)
                if self._ptr_size() == 4 and self.is_pae:
                    return v & 0xFFFFFFE0
                if self._ptr_size() == 4:
                    return v & 0xFFFFF000
                return v & 0xFFFFFFFFFFFFF000
            except Exception:
                return 0

        def _dtb_ok(value: int) -> bool:
            value = _norm_dtb(value)
            if self._ptr_size() == 4:
                return bool(value and value >= 0x1000 and value < 0x100000000)
            return bool(value and value >= 0x1000 and value < 0x40000000000)

        # DTB candidates: process DTB first, then current/global translator DTB.
        # DirectoryTableBase is the correct choice for kernel object addresses;
        # UserDirectoryTableBase is intentionally not used here.
        dtb_candidates: List[int] = []
        for candidate in (process_dtb, getattr(self.translator, "dtb", 0)):
            candidate = _norm_dtb(candidate)
            if _dtb_ok(candidate) and candidate not in dtb_candidates:
                dtb_candidates.append(candidate)

        if not dtb_candidates:
            self.logger.warning(
                f"PID {target_pid}: no valid kernel DTB available "
                f"(process_dtb={hex(process_dtb or 0)}, global={hex(getattr(self.translator, 'dtb', 0) or 0)})"
            )
            return threads

        # Build candidate walk modes. Prefer the dedicated ETHREAD profile
        # offsets because eprocess_offsets may come from an older/stale profile.
        modes = []
        seen_modes = set()

        def _add_mode(name: str, list_head_off: Optional[int], link_off: Optional[int]) -> None:
            if not isinstance(list_head_off, int) or not isinstance(link_off, int):
                return
            if list_head_off <= 0 or link_off <= 0:
                return
            key = (list_head_off, link_off)
            if key in seen_modes:
                return
            seen_modes.add(key)
            modes.append((name, list_head_off, link_off))

        _add_mode(
            "EPROCESS.ThreadListHead + ETHREAD.ThreadListEntry",
            self.offsets.get("EPROCESS_ThreadListHead"),
            self.offsets.get("ThreadListEntry"),
        )

        if eprocess_offsets:
            _add_mode(
                "EPROCESS profile ThreadListHead + ETHREAD.ThreadListEntry",
                eprocess_offsets.get("ThreadListHead"),
                self.offsets.get("ThreadListEntry"),
            )

        _add_mode(
            "KPROCESS.ThreadListHead + KTHREAD.ThreadListEntry",
            self.offsets.get("KPROCESS_ThreadListHead"),
            self.offsets.get("KTHREAD_ThreadListEntry"),
        )

        if not modes:
            self.logger.warning(
                f"PID {target_pid}: no thread-list walk modes available — add "
                f"EPROCESS_ThreadListHead/ThreadListEntry or "
                f"KPROCESS_ThreadListHead/KTHREAD_ThreadListEntry to offset.py"
            )
            return threads

        def _read_ptr_phys(pa: int) -> int:
            return self.read_ptr(pa)

        def _is_kernel_va(value: int) -> bool:
            return self._is_kernel_va(value)

        best_threads: List[Dict] = []
        best_mode = ""
        best_dtb = 0

        for mode_name, list_head_off, thread_link_off in modes:
            list_head_pa = int(eprocess_pa or 0) + list_head_off
            first_link_va = _read_ptr_phys(list_head_pa)

            # Empty thread list or wrong offset usually gives 0 / non-kernel ptr.
            if not _is_kernel_va(first_link_va):
                self.logger.debug(
                    f"PID {target_pid}: {mode_name} skipped — first Flink "
                    f"{hex(first_link_va or 0)} is not a kernel VA "
                    f"(list_head_off={hex(list_head_off)})"
                )
                continue

            for dtb in dtb_candidates:
                # If this cannot translate, either DTB is wrong or the offset is wrong.
                if not self.translator.vtop(first_link_va, dtb):
                    self.logger.debug(
                        f"PID {target_pid}: {mode_name} skipped for DTB {hex(dtb)} — "
                        f"cannot translate first Flink {hex(first_link_va)}"
                    )
                    continue

                current_va = first_link_va
                visited: Set[int] = set()
                mode_threads: List[Dict] = []
                seen_tids: Set[int] = set()

                # Hard cap prevents corrupt lists from looping forever.
                for _ in range(2048):
                    if not _is_kernel_va(current_va) or current_va in visited:
                        break
                    visited.add(current_va)

                    ethread_va = current_va - thread_link_off
                    if not _is_kernel_va(ethread_va):
                        break

                    ethread_pa = self.translator.vtop(ethread_va, dtb)
                    if ethread_pa:
                        thread = self.parse_ethread(ethread_pa, target_pid, proc_name)
                        if thread:
                            tid = int(thread.get("tid", 0) or 0)
                            if tid and tid not in seen_tids:
                                thread["ethread_virt_addr"] = ethread_va
                                thread["thread_list_mode"] = mode_name
                                thread["thread_list_head_offset"] = list_head_off
                                thread["thread_list_entry_offset"] = thread_link_off
                                thread["thread_dtb"] = dtb
                                mode_threads.append(thread)
                                seen_tids.add(tid)

                    # Advance: current_va points to LIST_ENTRY.Flink, so reading
                    # that address gives the next LIST_ENTRY virtual address.
                    current_link_pa = self.translator.vtop(current_va, dtb)
                    if not current_link_pa:
                        break
                    next_va = _read_ptr_phys(current_link_pa)
                    if not _is_kernel_va(next_va):
                        break
                    current_va = next_va

                if len(mode_threads) > len(best_threads):
                    best_threads = mode_threads
                    best_mode = mode_name
                    best_dtb = dtb

                # If one mode already found a reasonable number, no need to try
                # stale duplicate candidates. Keep going only when 0 or tiny.
                if len(best_threads) >= 1 and mode_name.startswith("EPROCESS.ThreadListHead"):
                    # Continue to allow KPROCESS mode to beat it if it recovers more.
                    pass

        if best_threads:
            self.logger.info(
                f"PID {target_pid}: Extracted {len(best_threads)} threads "
                f"using {best_mode} (DTB={hex(best_dtb)})"
            )
            return best_threads

        # L3B fallback: for x86 PAE, list walking can fail when LIST_ENTRY offsets
        # are not fully validated. Pool scan ETHREAD-like objects by CLIENT_ID and
        # match UniqueProcessId to the recovered process PID. This is native parsing;
        # it does not call Volatility and does not affect verdict logic directly.
        if self._ptr_size() == 4 and self.is_pae:
            fallback = self.enumerate_threads_by_pool_scan(target_pid, proc_name=proc_name)
            if fallback:
                self.logger.info(
                    f"PID {target_pid}: Extracted {len(fallback)} threads using x86 PAE ETHREAD pool-scan fallback"
                )
                return fallback

        self.logger.debug(
            f"PID {target_pid}: no PID-matching threads recovered. Tried modes="
            f"{[(name, hex(h), hex(l)) for name, h, l in modes]} "
            f"DTBs={[hex(d) for d in dtb_candidates]}"
        )
        return threads

    def enumerate_threads_by_pool_scan(self, target_pid: int, proc_name: str = "") -> List[Dict]:
        """
        Native ETHREAD pool-scan fallback for Windows x86 PAE.

        Volatility's windows.threads can recover these objects even when list
        walking is fragile. This fallback uses the same principle: scan physical
        memory for plausible CLIENT_ID values at the symbol-backed ETHREAD.Cid
        offset and validate candidate TIDs/start addresses.
        """
        results: List[Dict] = []
        seen_tids: Set[int] = set()
        try:
            file_size = int(getattr(self.memory, "file_size", 0) or getattr(self.memory, "size", 0) or getattr(self.memory, "dump_size", 0) or 0)
            if not file_size and hasattr(self.memory, "get_size"):
                file_size = int(self.memory.get_size() or 0)
            if not file_size:
                for attr in ("filepath", "file_path", "path", "dump_path", "filename"):
                    val = getattr(self.memory, attr, None)
                    if val and os.path.exists(str(val)):
                        file_size = os.path.getsize(str(val))
                        break
            if not file_size:
                return results

            cid = int(self.offsets.get("Cid", 0) or 0)
            if cid <= 0:
                return results

            step = 0x40
            chunk_size = 8 * 1024 * 1024
            overlap = 0x1000
            pos = 0
            while pos < file_size:
                data = self.memory.read_physical(pos, min(chunk_size + overlap, file_size - pos))
                if not data:
                    break
                limit = max(0, len(data) - (cid + 0x20))
                for rel in range(0, limit, step):
                    try:
                        # Candidate ETHREAD base if CLIENT_ID.UniqueProcess equals target_pid.
                        pid = struct.unpack("<I", data[rel + cid:rel + cid + 4])[0]
                        if pid != int(target_pid):
                            continue
                        tid = struct.unpack("<I", data[rel + cid + 4:rel + cid + 8])[0]
                        if tid == 0 or tid > 0x100000 or tid in seen_tids:
                            continue
                        ethread_pa = pos + rel
                        thread = self.parse_ethread(ethread_pa, target_pid, proc_name)
                        if not thread:
                            continue
                        thread["thread_list_mode"] = "x86_pae_ethread_pool_scan"
                        thread["ethread_phys_addr"] = ethread_pa
                        results.append(thread)
                        seen_tids.add(tid)
                    except Exception:
                        continue
                pos += chunk_size
        except Exception as exc:
            self.logger.debug(f"x86 PAE ETHREAD pool-scan fallback failed for PID {target_pid}: {exc}")
        return results

    # ──────────────────────────────────────────────────────────────────────────
    # Legacy helper
    # ──────────────────────────────────────────────────────────────────────────

    def detect_suspicious_threads(
        self, all_threads: Dict[int, List[Dict]]
    ) -> List[Dict]:
        """
        Scan a {pid: [thread_dict, …]} mapping and return a flat list of
        threads that exhibit basic suspicious characteristics.

        Kept for backwards compatibility with older callers; the primary
        anomaly detection path is now inside parse_ethread →
        _check_thread_anomalies.
        """
        suspicious: List[Dict] = []

        for pid, threads in all_threads.items():
            for thread in threads:
                flags: List[str] = []
                state = thread.get("state_name", "")
                addr  = thread.get("start_address", 0)

                if state == "Terminated":
                    flags.append("Terminated state (Zombie)")

                if addr < 0x10000 and state == "Running":
                    flags.append("Invalid Start Address (Null/Low)")

                # Kept for legacy reports; primary check is in parse_ethread
                if pid == 4 and addr < 0xFFFF800000000000:
                    flags.append("System thread with user-space address")

                if flags:
                    suspicious.append({"thread": thread, "flags": flags, "pid": pid})

        return suspicious
"""
ramdetect/extraction/parsers/dll_parser.py
==========================================
Native-only DLL Parser — zero Volatility dependency.

PEB/LDR walk strategy
---------------------
Windows x64 maintains three doubly-linked lists inside PEB_LDR_DATA for
every loaded module.  Walking all three lets us detect stealth DLLs that
have been unlinked from a subset of the lists (a classic hollowing / manual-
map artefact).

  PEB_LDR_DATA + 0x10  InLoadOrderModuleList
  PEB_LDR_DATA + 0x20  InMemoryOrderModuleList
  PEB_LDR_DATA + 0x30  InInitializationOrderModuleList

Each FLINK in list N points at the LIST_ENTRY *node* embedded inside an
LDR_DATA_TABLE_ENTRY.  The node sits at a different offset depending on
which list we are walking:

  InLoadOrder   → node at entry offset 0x00  → entry_base = flink - 0x00
  InMemoryOrder → node at entry offset 0x10  → entry_base = flink - 0x10
  InInitOrder   → node at entry offset 0x20  → entry_base = flink - 0x20

Once we have entry_base the field layout is fixed (x64 Windows 10/11):

  +0x30  DllBase         PVOID
  +0x38  EntryPoint      PVOID
  +0x40  SizeOfImage     ULONG (4 bytes + 4 bytes padding)
  +0x48  FullDllName     UNICODE_STRING
  +0x58  BaseDllName     UNICODE_STRING

DTB priority
------------
For user-mode PEB/LDR walking the correct page-table is the *user* page-
table, not the kernel (System-process) one.  Windows 10/11 KPROCESS stores
UserDirectoryTableBase separately from DirectoryTableBase.  We try:

  1. proc_info['user_dtb']           (UserDirectoryTableBase, best for user VA)
  2. proc_info['dtb']                (DirectoryTableBase / CR3)
  3. proc_info['cr3']                (alias used by some callers)
  4. proc_info['DirectoryTableBase'] (raw struct field name alias)
  5. self.translator.dtb             (fall-through to current translator state)
"""

import struct
import logging
import mmap
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_SIGNED_PATH_FRAGMENTS = (
    'system32', 'syswow64', 'winsxs',
    'windows\\microsoft.net',
    'program files\\windows',
    'windows\\systemapps\\',
    'windows\\shellcomponents\\',
    'windows\\shellexperiences\\',
    'windows\\immersivecontrolpanel\\',
    'windows\\uus\\',
    'program files\\',
    'program files (x86)\\',
)

_HIGH_RISK_DIRS = (
    '\\appdata\\local\\temp\\',
    '\\appdata\\roaming\\temp\\',
    '\\users\\public\\',
    '\\downloads\\',
    '\\temp\\',
)

# (ldr_head_offset_in_ldr_data, node_within_entry_offset, flag_key)
_LDR_LISTS: tuple = (
    (0x10, 0x00, 'in_load'),   # InLoadOrderModuleList
    (0x20, 0x10, 'in_mem'),    # InMemoryOrderModuleList
    (0x30, 0x20, 'in_init'),   # InInitializationOrderModuleList
)

_MAX_LDR_ENTRIES = 512        # loop-guard
_MAX_SIZE_BYTES  = 0x10000000 # 256 MB sanity cap on SizeOfImage


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _coerce_int(value: Any) -> int:
    try:
        if value in (None, '', 'None'):
            return 0
        if isinstance(value, str):
            return int(value, 16) if value.lower().startswith('0x') else int(value)
        return int(value)
    except Exception:
        return 0


def _normalize_dtb(value: Any) -> int:
    """Clear low 12 CR3/PCID flag bits before page-table use."""
    return _coerce_int(value) & 0xFFFFFFFFFFFFF000


def _is_plausible_dtb(dtb: int) -> bool:
    """Plausible normalized DTB. Raw values with low bits are accepted."""
    d = _normalize_dtb(dtb)
    return bool(d and d >= 0x1000 and d < 0x40000000000)


def _build_dtb_candidates(proc_info: Dict[str, Any], explicit_dtb: Optional[int], fallback_dtb: int) -> List[Tuple[str, int]]:
    ordered: List[Tuple[str, int]] = []

    def add(source: str, value: Any) -> None:
        val = _normalize_dtb(value)
        if _is_plausible_dtb(val):
            ordered.append((source, val))

    add('user_dtb', proc_info.get('user_dtb'))
    add('UserDirectoryTableBase', proc_info.get('UserDirectoryTableBase'))

    cand = proc_info.get('user_dtb_candidates')
    if isinstance(cand, dict):
        for off, val in cand.items():
            add(f'user_dtb_candidate@{off}', val)
    elif isinstance(cand, (list, tuple)):
        for i, val in enumerate(cand):
            add(f'user_dtb_candidate[{i}]', val)

    add('explicit_dtb', explicit_dtb)
    add('dtb', proc_info.get('dtb'))
    add('cr3', proc_info.get('cr3'))
    add('DirectoryTableBase', proc_info.get('DirectoryTableBase'))
    add('translator_dtb', fallback_dtb)

    deduped: List[Tuple[str, int]] = []
    seen = set()
    for source, val in ordered:
        if val not in seen:
            deduped.append((source, val))
            seen.add(val)
    return deduped


def _pick_dtb(proc_info: Dict[str, Any], fallback_dtb: int) -> int:
    candidates = _build_dtb_candidates(proc_info, None, fallback_dtb)
    return candidates[0][1] if candidates else _normalize_dtb(fallback_dtb)


def _is_user64(value: int) -> bool:
    return bool(value and 0x10000 <= int(value) < 0x0000800000000000)


def _is_user32(value: int) -> bool:
    return bool(value and 0x10000 <= int(value) <= 0xFFFFFFFF)


def _path_signed(path: str) -> bool:
    pl = (path or '').lower()
    return any(f in pl for f in _SIGNED_PATH_FRAGMENTS)


def _basename_lower(s: str) -> str:
    if not s:
        return ''
    return os.path.basename(s.replace('\\', os.sep)).lower()


# ---------------------------------------------------------------------------
# DLLParser
# ---------------------------------------------------------------------------

class DLLParser:
    """
    Pure-native DLL parser.
    No Volatility, no subprocess, no external tools of any kind.
    """

    def __init__(self, reader, translator, dump_file=None, logger=None):
        self.reader     = reader
        self.translator = translator
        self.dump_file  = dump_file          # kept for API compat; unused
        self.logger     = logger or logging.getLogger(__name__)

        # Silence console handler so output does not pollute the UI log pane
        for h in list(self.logger.handlers):
            if isinstance(h, logging.StreamHandler) and \
               not isinstance(h, logging.FileHandler):
                self.logger.removeHandler(h)
        self.logger.propagate = False

        # x86 PAE fallback cache.  This is native address-translation
        # recovery only; it does not call Volatility or change verdict logic.
        self._pae_peb_dtb_cache = {}      # peb_page -> dtb
        self._pae_known_dtb_pool = []     # discovered DTBs that may help later PEBs
        self._pae_dtb_discovery_attempts = 0
        self._pae_dtb_discovery_max_attempts = 12

        self.logger.info('DLLParser (native-only) initialized')

    def _ptr_size(self) -> int:
        return 4 if int(getattr(self.translator, 'pointer_size', 8) or 8) == 4 else 8

    def _is_x86_native(self) -> bool:
        return self._ptr_size() == 4

    # ------------------------------------------------------------------
    # Public orchestrator
    # ------------------------------------------------------------------

    def get_modules(self, proc_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Walk PEB LDR lists for one process and return DLL rows.

        Phase 6D:
        DTB values are normalized before validation/use. No global DTB switch
        is required; all reads pass an explicit DTB into AddressTranslator.
        """
        pid = proc_info.get('pid', 0)
        peb_addr = proc_info.get('peb', 0)
        original_dtb = self.translator.dtb

        try:
            dlls = self.get_dlls_robust(
                peb_va=peb_addr,
                pid=pid,
                dtb=None,
                process=proc_info,
            )

            ldr_count = sum(1 for d in dlls if d.get('ldr_lists_complete'))
            working_dtb = proc_info.get('_dll_working_dtb', 0)
            working_source = proc_info.get('_dll_working_dtb_source', 'none')
            tried = proc_info.get('_dll_dtb_candidates_tried', '')

            self.logger.info(
                f'PID {pid}: native walk -> {len(dlls)} modules '
                f'({ldr_count} with LDR flags, '
                f'working_dtb={working_source}:0x{int(working_dtb or 0):x}, '
                f'tried=[{tried}])'
            )
            return dlls

        finally:
            if self.translator.dtb != original_dtb:
                self.translator.dtb = original_dtb
                self.translator.tlb.clear()

    # ------------------------------------------------------------------
    # Native 3-list LDR walker
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # x86 PAE PEB DTB discovery fallback
    # ------------------------------------------------------------------

    def _dump_path_for_mmap(self) -> str:
        """Return the backing dump path when available for fast native scans."""
        for value in (
            self.dump_file,
            getattr(self.reader, 'file_path', None),
            getattr(self.reader, 'filepath', None),
            getattr(self.reader, 'path', None),
            getattr(self.reader, 'dump_path', None),
            getattr(self.reader, 'filename', None),
        ):
            if value:
                try:
                    p = Path(str(value))
                    if p.exists() and p.is_file():
                        return str(p)
                except Exception:
                    pass
        return ''

    @staticmethod
    def _mm_u64(mm, off: int) -> int:
        try:
            if off < 0 or off + 8 > len(mm):
                return 0
            return struct.unpack_from('<Q', mm, off)[0]
        except Exception:
            return 0

    @staticmethod
    def _mm_u32(mm, off: int) -> int:
        try:
            if off < 0 or off + 4 > len(mm):
                return 0
            return struct.unpack_from('<I', mm, off)[0]
        except Exception:
            return 0

    def _mm_pae_vtop(self, mm, va: int, dtb: int) -> int:
        """Fast x86 PAE VA->PA translation over a flat RAW memory mmap."""
        try:
            va = int(va or 0) & 0xFFFFFFFF
            dtb = int(dtb or 0) & 0xFFFFFFE0
            if not va or not dtb:
                return 0

            pdpt_i = (va >> 30) & 0x3
            pd_i   = (va >> 21) & 0x1FF
            pt_i   = (va >> 12) & 0x1FF
            off     = va & 0xFFF

            pdpte = self._mm_u64(mm, dtb + pdpt_i * 8)
            if not (pdpte & 1):
                return 0

            pd_base = pdpte & 0x000ffffffffff000
            pde = self._mm_u64(mm, pd_base + pd_i * 8)
            if not (pde & 1):
                return 0

            if pde & 0x80:
                return (pde & 0x000fffffffe00000) + (va & 0x1FFFFF)

            pt_base = pde & 0x000ffffffffff000
            pte = self._mm_u64(mm, pt_base + pt_i * 8)
            if not (pte & 1):
                return 0

            return (pte & 0x000ffffffffff000) + off
        except Exception:
            return 0

    def _mm_read_u32_va(self, mm, va: int, dtb: int) -> int:
        pa = self._mm_pae_vtop(mm, va, dtb)
        if not pa:
            return 0
        return self._mm_u32(mm, pa)

    def _mm_validate_peb32_dtb(self, mm, peb_va: int, dtb: int) -> bool:
        """
        Validate that a PAE DTB can read PEB32 -> LDR -> first LDR entry.

        This uses only native page-table walking and basic structural checks.
        It does not call Volatility and does not influence the ML verdict.
        """
        try:
            peb_pa = self._mm_pae_vtop(mm, peb_va, dtb)
            if not peb_pa:
                return False

            ldr = self._mm_read_u32_va(mm, peb_va + 0x0C, dtb)
            if not _is_user32(ldr):
                return False
            if not self._mm_pae_vtop(mm, ldr, dtb):
                return False

            # PEB_LDR_DATA32.InLoadOrderModuleList = Ldr + 0x0C
            flink = self._mm_read_u32_va(mm, ldr + 0x0C, dtb)
            if not _is_user32(flink) or flink == ldr + 0x0C:
                return False

            # LDR_DATA_TABLE_ENTRY32.DllBase = entry + 0x18 for InLoadOrder.
            dll_base = self._mm_read_u32_va(mm, flink + 0x18, dtb)
            if not _is_user32(dll_base):
                return False

            # SizeOfImage should be plausible.  Some entries may be zero, but
            # the first image entry normally has a sane non-zero size.
            size_img = self._mm_read_u32_va(mm, flink + 0x20, dtb)
            if size_img and size_img > _MAX_SIZE_BYTES:
                return False

            return True
        except Exception:
            return False

    def _discover_pae_dtb_for_peb32(self, peb_va: int, pid: int = 0) -> int:
        """
        Discover an x86 PAE DTB that can translate a process PEB32.

        Used only when stored EPROCESS DTB/UserDirectoryTableBase candidates fail.
        This is a bounded native fallback for old/x86 PAE dumps where the
        process-layer DTB is not recovered correctly by the EPROCESS carver.
        """
        peb_va = _coerce_int(peb_va)
        if not peb_va or not _is_user32(peb_va):
            return 0

        cache_key = peb_va & 0xFFFFF000
        cached = self._pae_peb_dtb_cache.get(cache_key)
        if cached:
            return cached

        dump_path = self._dump_path_for_mmap()
        if not dump_path:
            return 0

        # First test DTBs found for earlier processes.  This avoids repeated
        # full-dump scans when several PEBs share a process/session mapping.
        try:
            with open(dump_path, 'rb') as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    for known in list(self._pae_known_dtb_pool):
                        if self._mm_validate_peb32_dtb(mm, peb_va, known):
                            self._pae_peb_dtb_cache[cache_key] = known
                            return known
                finally:
                    mm.close()
        except Exception:
            pass

        if self._pae_dtb_discovery_attempts >= self._pae_dtb_discovery_max_attempts:
            return 0
        self._pae_dtb_discovery_attempts += 1

        try:
            with open(dump_path, 'rb') as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    size = len(mm)
                    for dtb in range(0x1000, max(0x1000, size - 0x1000), 0x1000):
                        if self._mm_validate_peb32_dtb(mm, peb_va, dtb):
                            self._pae_peb_dtb_cache[cache_key] = dtb
                            if dtb not in self._pae_known_dtb_pool:
                                self._pae_known_dtb_pool.append(dtb)
                            self.logger.info(
                                f'PID {pid}: discovered x86 PAE PEB DTB 0x{dtb:x} '
                                f'for PEB 0x{peb_va:x}'
                            )
                            return dtb
                finally:
                    mm.close()
        except Exception as exc:
            self.logger.debug(f'PID {pid}: x86 PAE PEB DTB discovery failed: {exc}')

        return 0

    def get_dlls_robust(
            self,
            peb_va:    int,
            pid:       int,
            dtb:       Optional[int] = None,
            process:   Optional[Dict[str, Any]] = None,
            dump_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Walk native x86 PEB32 LDR lists for x86/PAE dumps, x64 PEB LDR lists for x64 dumps, and WOW64 PEB32 lists when present.
        """
        if not peb_va:
            return []

        process = process if process is not None else {}
        registry: Dict[Tuple[str, int], Dict[str, Any]] = {}
        candidates = _build_dtb_candidates(process, dtb, self.translator.dtb)

        tried_labels: List[str] = []
        best_source = ''
        best_dtb = 0
        best_total = 0

        for source, cand_dtb in candidates:
            tried_labels.append(f'{source}=0x{cand_dtb:x}')
            local_registry: Dict[Tuple[str, int], Dict[str, Any]] = {}

            # Native x86/PAE dumps use the 32-bit PEB directly. They are not
            # WOW64 processes, so the old WOW64-only PEB32 path never ran.
            if self._is_x86_native():
                try:
                    ldr32 = self._read_u32(peb_va + 0x0C, cand_dtb)
                    if _is_user32(ldr32) and self._vtop(ldr32, cand_dtb):
                        self._walk_ldr32(
                            pid, ldr32, cand_dtb, local_registry,
                            source_name='native_peb32_x86_pae',
                            wow64=False,
                        )
                except Exception as exc:
                    self.logger.debug(f'PID {pid}: native x86 LDR candidate {source} failed: {exc}')
            else:
                try:
                    ldr64 = self._read_ptr(peb_va + 0x18, cand_dtb)
                    if _is_user64(ldr64) and self._vtop(ldr64, cand_dtb):
                        self._walk_ldr64(pid, ldr64, cand_dtb, local_registry)
                except Exception as exc:
                    self.logger.debug(f'PID {pid}: x64 LDR candidate {source} failed: {exc}')

                wow64 = process.get('wow64_process') or process.get('WoW64Process') or 0
                if wow64:
                    try:
                        peb32 = self._read_wow64_peb32(wow64, cand_dtb)
                        if peb32:
                            ldr32 = self._read_u32(peb32 + 0x0C, cand_dtb)
                            if _is_user32(ldr32) and self._vtop(ldr32, cand_dtb):
                                self._walk_ldr32(
                                    pid, ldr32, cand_dtb, local_registry,
                                    source_name='native_peb32_wow64',
                                    wow64=True,
                                )
                    except Exception as exc:
                        self.logger.debug(f'PID {pid}: WOW64 LDR candidate {source} failed: {exc}')

            if len(local_registry) > best_total:
                registry = local_registry
                best_source = source
                best_dtb = cand_dtb
                best_total = len(local_registry)

        # Fallback for native Windows x86 PAE dumps where the EPROCESS carver
        # recovers a valid PEB VA but the stored DirectoryTableBase /
        # UserDirectoryTableBase candidates cannot translate user-mode PEB pages.
        # This remains native RAMDetect parsing: it discovers a usable PAE DTB
        # by validating PEB32->LDR structure, then feeds the normal LDR walker.
        if not registry and self._is_x86_native():
            discovered_dtb = self._discover_pae_dtb_for_peb32(peb_va, pid)
            if discovered_dtb:
                tried_labels.append(f'pae_peb_dtb_discovery=0x{discovered_dtb:x}')
                local_registry = {}
                try:
                    ldr32 = self._read_u32(peb_va + 0x0C, discovered_dtb)
                    if _is_user32(ldr32) and self._vtop(ldr32, discovered_dtb):
                        self._walk_ldr32(
                            pid, ldr32, discovered_dtb, local_registry,
                            source_name='native_peb32_x86_pae_dtb_discovery',
                            wow64=False,
                        )
                except Exception as exc:
                    self.logger.debug(f'PID {pid}: discovered PAE DTB LDR walk failed: {exc}')

                if len(local_registry) > best_total:
                    registry = local_registry
                    best_source = 'pae_peb_dtb_discovery'
                    best_dtb = discovered_dtb
                    best_total = len(local_registry)
                    process['_dll_discovered_pae_dtb'] = discovered_dtb

        process['_dll_dtb_candidates_tried'] = ';'.join(tried_labels)
        process['_dll_working_dtb'] = best_dtb
        process['_dll_working_dtb_source'] = best_source

        if not registry:
            self.logger.debug(
                f'PID {pid}: no PEB LDR modules recovered across DTB candidates '
                f'(peb=0x{peb_va:x}, tried={tried_labels})'
            )
            return []

        result: List[Dict[str, Any]] = []
        for row in registry.values():
            row['not_in_load'] = not row.get('in_load', False)
            row['not_in_mem'] = not row.get('in_mem', False)
            row['not_in_init'] = not row.get('in_init', False)
            row['ldr_lists_complete'] = True
            row['ldr_source'] = row.get('ldr_source', 'native_peb')
            row['ldr_dtb_source'] = best_source
            row['ldr_dtb'] = best_dtb
            result.append(row)

        return result

    def _walk_ldr64(self, pid: int, ldr_ptr: int, dtb: int, registry: Dict[Tuple[str, int], Dict[str, Any]]) -> None:
        for (ldr_offset, node_delta, flag_key) in _LDR_LISTS:
            list_head = ldr_ptr + ldr_offset
            next_link = self._read_ptr(list_head, dtb)
            if not next_link or next_link == list_head:
                continue

            visited: set = set()
            count = 0
            while next_link and next_link != list_head and count < _MAX_LDR_ENTRIES:
                if next_link in visited:
                    break
                visited.add(next_link)

                entry_addr = next_link - node_delta
                base_addr = self._read_ptr(entry_addr + 0x30, dtb)
                if base_addr and base_addr > 0x10000:
                    key = ('x64', base_addr)
                    if key not in registry:
                        registry[key] = self._read_ldr_entry(entry_addr, base_addr, pid, dtb)
                        registry[key]['arch'] = 'x64'
                        registry[key]['ldr_source'] = 'native_peb64'
                    registry[key][flag_key] = True

                nxt = self._read_ptr(next_link, dtb)
                if not nxt or nxt == next_link:
                    break
                next_link = nxt
                count += 1

    def _walk_ldr32(self, pid: int, ldr32: int, dtb: int, registry: Dict[Tuple[str, int], Dict[str, Any]], source_name: str = 'native_peb32', wow64: bool = False) -> None:
        ldr32_lists = (
            (0x0C, 0x00, 'in_load'),
            (0x14, 0x08, 'in_mem'),
            (0x1C, 0x10, 'in_init'),
        )
        for (ldr_offset, node_delta, flag_key) in ldr32_lists:
            list_head = ldr32 + ldr_offset
            next_link = self._read_u32(list_head, dtb)
            if not next_link or next_link == list_head:
                continue

            visited: set = set()
            count = 0
            while next_link and next_link != list_head and count < _MAX_LDR_ENTRIES:
                if next_link in visited:
                    break
                visited.add(next_link)

                entry_addr = next_link - node_delta
                base_addr = self._read_u32(entry_addr + 0x18, dtb)
                if base_addr and base_addr > 0x10000:
                    key = ('x86', base_addr)
                    if key not in registry:
                        registry[key] = self._read_ldr32_entry(entry_addr, base_addr, pid, dtb, source_name=source_name, wow64=wow64)
                    registry[key][flag_key] = True

                nxt = self._read_u32(next_link, dtb)
                if not nxt or nxt == next_link:
                    break
                next_link = nxt
                count += 1

    def _read_wow64_peb32(self, wow64_ptr: int, dtb: int) -> int:
        for off in (0x0, 0x8, 0x10, 0x18, 0x20, 0x28):
            v64 = self._read_ptr(wow64_ptr + off, self.translator.dtb)
            lo = v64 & 0xFFFFFFFF
            if _is_user32(lo):
                return lo
            v32 = self._read_u32(wow64_ptr + off, self.translator.dtb)
            if _is_user32(v32):
                return v32
            v64p = self._read_ptr(wow64_ptr + off, dtb)
            lop = v64p & 0xFFFFFFFF
            if _is_user32(lop):
                return lop
            v32p = self._read_u32(wow64_ptr + off, dtb)
            if _is_user32(v32p):
                return v32p
        return 0

    # ------------------------------------------------------------------
    # LDR entry metadata reader
    # ------------------------------------------------------------------

    def _read_ldr_entry(
            self,
            entry_addr: int,
            base_addr:  int,
            pid:        int,
            dtb:        Optional[int],
    ) -> Dict[str, Any]:
        """
        Read SizeOfImage, FullDllName, BaseDllName from one
        LDR_DATA_TABLE_ENTRY and return a fully-populated row dict.

        LDR presence flags (in_load / in_mem / in_init) start as False;
        the walk loop sets them as it discovers the entry in each list.
        """
        # SizeOfImage at entry_addr + 0x40  (ULONG, 4 bytes)
        size   = 0
        size_pa = self._vtop(entry_addr + 0x40, dtb)
        if size_pa:
            s_bytes = self.reader.read_physical(size_pa, 4)
            if len(s_bytes) == 4:
                size = struct.unpack('<I', s_bytes)[0]
                if size > _MAX_SIZE_BYTES:
                    size = 0

        # FullDllName at +0x48, BaseDllName at +0x58
        path = self._read_unicode_string(entry_addr + 0x48, dtb)
        name = self._read_unicode_string(entry_addr + 0x58, dtb)

        # Fall back to extracting a name from the path if BaseDllName is empty
        if not name and path:
            name = _basename_lower(path)

        anomalies  = self._is_suspicious_dll(name, path, base_addr, size)
        signed_val = _path_signed(path)
        is_susp    = bool(anomalies)
        status     = 'suspicious' if is_susp else 'clean'
        # Real section entropy requires PE parsing; placeholder kept as 0.0
        entropy    = 0.0

        row: Dict[str, Any] = {
            # -- Primary keys used by feature_aggregator / ML pipeline --
            'pid':           pid,
            'name':          name,
            'path':          path,
            'base':          base_addr,
            'base_address':  base_addr,
            'size':          size,
            'signed':        signed_val,
            'entropy':       entropy,
            'anomalies':     anomalies,
            'is_suspicious': is_susp,
            'status':        status,
            'anomaly':       '; '.join(anomalies) if anomalies else '',

            # -- UI / CSV export aliases --
            'PID':           pid,
            'process':       '',           # populated by caller when available
            'Process':       '',
            'dll_name':      name,
            'DLL Name':      name,
            'Path':          path,
            'Base Address':  f'0x{base_addr:x}',
            'Size':          size,
            'Signed':        'Yes' if signed_val else 'No',
            'Entropy':       f'{entropy:.2f}',
            'Status':        status.upper(),
            'Anomaly':       '; '.join(anomalies) if anomalies else '-',

            # -- LDR presence flags (caller sets these) --
            'in_load':  False,
            'in_mem':   False,
            'in_init':  False,
        }
        return row

    def _read_ldr32_entry(self, entry_addr: int, base_addr: int, pid: int, dtb: int, source_name: str = "native_peb32", wow64: bool = False) -> Dict[str, Any]:
        """Read x86 LDR_DATA_TABLE_ENTRY metadata for native x86/PAE or WOW64."""
        size = self._read_u32(entry_addr + 0x20, dtb)
        if size > _MAX_SIZE_BYTES:
            size = 0

        path = self._read_unicode_string32(entry_addr + 0x24, dtb)
        name = self._read_unicode_string32(entry_addr + 0x2C, dtb)
        if not name and path:
            name = _basename_lower(path)

        anomalies = self._is_suspicious_dll(name, path, base_addr, size)
        signed_val = _path_signed(path)
        is_susp = bool(anomalies)
        status = 'suspicious' if is_susp else 'clean'
        entropy = 0.0

        return {
            'pid': pid,
            'name': name,
            'path': path,
            'base': base_addr,
            'base_address': base_addr,
            'size': size,
            'signed': signed_val,
            'entropy': entropy,
            'anomalies': anomalies,
            'is_suspicious': is_susp,
            'status': status,
            'anomaly': '; '.join(anomalies) if anomalies else '',
            'arch': 'x86',
            'wow64': bool(wow64),

            'PID': pid,
            'process': '',
            'Process': '',
            'dll_name': name,
            'DLL Name': name,
            'Path': path,
            'Base Address': f'0x{base_addr:x}',
            'Size': size,
            'Signed': 'Yes' if signed_val else 'No',
            'Entropy': f'{entropy:.2f}',
            'Status': status.upper(),
            'Anomaly': '; '.join(anomalies) if anomalies else '-',

            'in_load': False,
            'in_mem': False,
            'in_init': False,
            'ldr_source': source_name,
        }

    # ------------------------------------------------------------------
    # Anomaly heuristics
    # ------------------------------------------------------------------

    def _is_suspicious_dll(
            self,
            module_name: str,
            path:        str,
            base_addr:   int,
            size:        int,
    ) -> List[str]:
        anomalies:  List[str] = []
        path_lower = (path or '').lower()
        name_lower = (module_name or '').lower()

        # DLL sitting at the Windows root but not in a legitimate sub-folder
        if path_lower.startswith('c:\\windows\\') and path_lower.count('\\') == 2:
            if 'system32' not in path_lower and 'syswow64' not in path_lower:
                anomalies.append('Suspicious Path (Windows Root)')

        # High-risk user-writable directories
        if any(d in path_lower for d in _HIGH_RISK_DIRS):
            anomalies.append('Suspicious Directory')

        # svchost outside System32 → likely masquerading
        if name_lower == 'svchost.exe' and 'system32' not in path_lower:
            anomalies.append('Masquerading (svchost outside System32)')

        return anomalies

    # ------------------------------------------------------------------
    # Low-level virtual-memory helpers
    # ------------------------------------------------------------------

    def _vtop(self, va: int, dtb: Optional[int] = None) -> int:
        """Translate a virtual address to physical, using explicit dtb if given."""
        if dtb is not None:
            return self.translator.vtop(va, dtb)
        return self.translator.vtop(va)

    def _read_ptr(self, va: int, dtb: Optional[int] = None) -> int:
        """Read a pointer using the active translator pointer width."""
        size = self._ptr_size()
        if dtb is not None:
            data = self.translator.read_virtual(va, size, dtb)
        else:
            data = self.translator.read_virtual(va, size)
        if data and len(data) >= size:
            return struct.unpack('<I' if size == 4 else '<Q', data[:size])[0]
        return 0

    def _read_u32(self, va: int, dtb: Optional[int] = None) -> int:
        if dtb is not None:
            data = self.translator.read_virtual(va, 4, dtb)
        else:
            data = self.translator.read_virtual(va, 4)
        if data and len(data) >= 4:
            return struct.unpack('<I', data[:4])[0]
        return 0

    def _read_unicode_string(self, struct_addr: int, dtb: Optional[int] = None) -> str:
        """
        Parse x64 UNICODE_STRING:
          +0x00 Length USHORT
          +0x08 Buffer PWSTR
        """
        try:
            struct_pa = self.translator.vtop(struct_addr, dtb)
            if not struct_pa:
                return ''

            l_bytes = self.reader.read_physical(struct_pa, 2)
            if len(l_bytes) < 2:
                return ''
            length = struct.unpack('<H', l_bytes)[0]
            if length == 0 or length > 2048 or length % 2 != 0:
                return ''

            buf_ptr = self.translator.read_virtual_pointer(struct_addr + 8, dtb)
            if not buf_ptr or buf_ptr < 0x10000:
                return ''

            buf_pa = self.translator.vtop(buf_ptr, dtb)
            if not buf_pa:
                return ''

            raw = self.reader.read_physical(buf_pa, length)
            if not raw or len(raw) < 2:
                return ''

            return raw.decode('utf-16-le', errors='ignore').strip('\x00')
        except Exception:
            return ''

    def _read_unicode_string32(self, struct_addr: int, dtb: Optional[int] = None) -> str:
        """
        Parse x86 WOW64 UNICODE_STRING:
          +0x00 Length USHORT
          +0x04 Buffer uint32
        """
        try:
            struct_pa = self.translator.vtop(struct_addr, dtb)
            if not struct_pa:
                return ''

            hdr = self.reader.read_physical(struct_pa, 8)
            if not hdr or len(hdr) < 8:
                return ''
            length, _max_len, buf_ptr = struct.unpack('<HHI', hdr[:8])
            if length == 0 or length > 2048 or length % 2 != 0:
                return ''
            if not _is_user32(buf_ptr):
                return ''

            buf_pa = self.translator.vtop(buf_ptr, dtb)
            if not buf_pa:
                return ''

            raw = self.reader.read_physical(buf_pa, length)
            if not raw or len(raw) < 2:
                return ''

            return raw.decode('utf-16-le', errors='ignore').strip('\x00')
        except Exception:
            return ''


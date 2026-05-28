"""
ramdetect/extraction/parsers/address_translator.py
================================================
Virtual to Physical Address Translator
Supports AMD64 4-level paging, large pages, DTB-aware TLB caching,
and cross-page virtual reads.
"""

import struct
import logging
from typing import Optional


class AddressTranslator:
    def __init__(self, memory_reader, dtb: int, *, pointer_size: int = 8, is_pae: bool = False):
        self.reader = memory_reader
        self.dtb = int(dtb or 0)
        self.pointer_size = 4 if int(pointer_size or 8) == 4 else 8
        self.is_pae = bool(is_pae)
        self.logger = logging.getLogger(__name__)
        # DTB-aware cache: (dtb, virtual_page) -> physical_page
        # The previous VA-only cache could reuse translations across processes.
        self.tlb = {}
        self.CACHE_SIZE = 4096
        self.logger.info(f"AddressTranslator initialized with DTB: 0x{self.dtb:x} (ptr={self.pointer_size}, pae={self.is_pae})")

    @staticmethod
    def _page_align(value: int) -> int:
        return int(value or 0) & 0xFFFFFFFFFFFFF000

    def clear_tlb(self) -> None:
        try:
            self.tlb.clear()
        except Exception:
            pass

    def set_dtb(self, dtb: int) -> None:
        dtb = int(dtb or 0)
        if dtb != self.dtb:
            self.dtb = dtb
            self.clear_tlb()

    def vtop(self, va: int, dtb: Optional[int] = None) -> int:
        """Translate a 64-bit virtual address to a physical address."""
        try:
            va = int(va or 0)
            dtb = int(self.dtb if dtb is None else (dtb or 0))
        except Exception:
            return 0

        if not va or not dtb:
            return 0

        if self.pointer_size == 4 and self.is_pae:
            return self._vtop_x86_pae(va, dtb)
        if self.pointer_size == 4:
            return self._vtop_x86_nonpae(va, dtb)

        page_va = va & 0xFFFFFFFFFFFFF000
        offset = va & 0xFFF
        cache_key = (dtb & 0xFFFFFFFFFF000, page_va)
        if cache_key in self.tlb:
            return self.tlb[cache_key] + offset

        pml4_i = (va >> 39) & 0x1FF
        pdpt_i = (va >> 30) & 0x1FF
        pd_i   = (va >> 21) & 0x1FF
        pt_i   = (va >> 12) & 0x1FF

        try:
            pml4_base = dtb & 0xFFFFFFFFFF000
            pml4e = self._read_phys_u64(pml4_base + (pml4_i * 8))
            if not (pml4e & 1):
                return 0

            pdpt_base = pml4e & 0xFFFFFFFFFF000
            pdpte = self._read_phys_u64(pdpt_base + (pdpt_i * 8))
            if not (pdpte & 1):
                return 0

            # 1 GB large page
            if pdpte & 0x80:
                phys_base = pdpte & 0xFFFFFC0000000
                return phys_base + (va & 0x3FFFFFFF)

            pd_base = pdpte & 0xFFFFFFFFFF000
            pde = self._read_phys_u64(pd_base + (pd_i * 8))
            if not (pde & 1):
                return 0

            # 2 MB large page
            if pde & 0x80:
                phys_base = pde & 0xFFFFFFFE00000
                return phys_base + (va & 0x1FFFFF)

            pt_base = pde & 0xFFFFFFFFFF000
            pte = self._read_phys_u64(pt_base + (pt_i * 8))
            if not (pte & 1):
                return 0

            phys_base = pte & 0xFFFFFFFFFF000
            if len(self.tlb) < self.CACHE_SIZE:
                self.tlb[cache_key] = phys_base
            return phys_base + offset

        except Exception:
            return 0

    def _vtop_x86_pae(self, va: int, dtb: int) -> int:
        """Translate 32-bit x86 PAE VA to physical address."""
        va &= 0xFFFFFFFF
        dtb &= 0xFFFFFFE0
        page_va = va & 0xFFFFF000
        offset = va & 0xFFF
        cache_key = (dtb, page_va, "pae")
        if cache_key in self.tlb:
            return self.tlb[cache_key] + offset

        pdpt_i = (va >> 30) & 0x3
        pd_i = (va >> 21) & 0x1FF
        pt_i = (va >> 12) & 0x1FF
        try:
            pdpte = self._read_phys_u64(dtb + (pdpt_i * 8))
            if not (pdpte & 1):
                return 0
            pd_base = pdpte & 0x000ffffffffff000
            pde = self._read_phys_u64(pd_base + (pd_i * 8))
            if not (pde & 1):
                return 0
            if pde & 0x80:  # 2 MB large page
                phys = (pde & 0x000fffffffe00000) + (va & 0x1FFFFF)
                return phys
            pt_base = pde & 0x000ffffffffff000
            pte = self._read_phys_u64(pt_base + (pt_i * 8))
            if not (pte & 1):
                return 0
            phys_base = pte & 0x000ffffffffff000
            if len(self.tlb) < self.CACHE_SIZE:
                self.tlb[cache_key] = phys_base
            return phys_base + offset
        except Exception:
            return 0

    def _vtop_x86_nonpae(self, va: int, dtb: int) -> int:
        """Translate 32-bit non-PAE VA to physical address."""
        va &= 0xFFFFFFFF
        dtb &= 0xFFFFF000
        page_va = va & 0xFFFFF000
        offset = va & 0xFFF
        cache_key = (dtb, page_va, "x86")
        if cache_key in self.tlb:
            return self.tlb[cache_key] + offset
        pd_i = (va >> 22) & 0x3FF
        pt_i = (va >> 12) & 0x3FF
        try:
            pde = self._read_phys_u32(dtb + (pd_i * 4))
            if not (pde & 1):
                return 0
            if pde & 0x80:  # 4 MB large page
                return (pde & 0xFFC00000) + (va & 0x3FFFFF)
            pt_base = pde & 0xFFFFF000
            pte = self._read_phys_u32(pt_base + (pt_i * 4))
            if not (pte & 1):
                return 0
            phys_base = pte & 0xFFFFF000
            if len(self.tlb) < self.CACHE_SIZE:
                self.tlb[cache_key] = phys_base
            return phys_base + offset
        except Exception:
            return 0

    def read_virtual(self, va: int, size: int, dtb: Optional[int] = None) -> bytes:
        """Read virtual memory, safely handling page boundaries."""
        try:
            va = int(va or 0)
            size = int(size or 0)
        except Exception:
            return b""
        if not va or size <= 0:
            return b""

        out = bytearray()
        remaining = size
        current = va

        while remaining > 0:
            page_remaining = 0x1000 - (current & 0xFFF)
            to_read = min(remaining, page_remaining)
            pa = self.vtop(current, dtb)
            if not pa:
                # Preserve contiguous reads where possible. For pointer/struct reads,
                # a missing page means caller receives short/empty data.
                break
            chunk = self.reader.read_physical(pa, to_read)
            if not chunk:
                break
            out.extend(chunk)
            if len(chunk) < to_read:
                break
            current += to_read
            remaining -= to_read

        return bytes(out)

    def read_virtual_pointer(self, va: int, dtb: Optional[int] = None) -> int:
        size = 4 if self.pointer_size == 4 else 8
        data = self.read_virtual(va, size, dtb)
        if data and len(data) >= size:
            return struct.unpack("<I" if size == 4 else "<Q", data[:size])[0]
        return 0

    def _read_phys_u32(self, addr: int) -> int:
        data = self.reader.read_physical(int(addr or 0), 4)
        if not data or len(data) < 4:
            return 0
        return struct.unpack("<I", data[:4])[0]

    def _read_phys_u64(self, addr: int) -> int:
        data = self.reader.read_physical(int(addr or 0), 8)
        if not data or len(data) < 8:
            return 0
        return struct.unpack("<Q", data[:8])[0]
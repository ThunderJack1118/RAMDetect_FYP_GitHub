"""
ramdetect/extraction/parsers/vad_scanner.py
===========================================
Native VAD Tree Walker (Full Mode)

Robust Win10/Win11 VAD scanner for RAMDetect.

Fixes included:
  - Tries multiple DTB contexts for VAD metadata scanning:
      1) current/kernel translator DTB
      2) process DTB from EPROCESS.DirectoryTableBase
    This is needed because on modern Windows/KVA-shadowed dumps the DTB that
    maps kernel VAD structures may differ depending on acquisition/crash-dump
    representation.
  - Clears AddressTranslator.tlb before and after every DTB context switch.
  - Supports StartingVpnHigh and EndingVpnHigh for modern VAD ranges.
  - Decodes Win11 24H2 _MMVAD_FLAGS bitfields from Vergilius.
  - Uses Subsection -> ControlArea -> FilePointer, with _MMVAD.FileObject
    fallback.
  - Exports mapped-file metadata for MappedFileCarver.
"""

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

from ramdetect.utils.offset import get_vad_offsets, get_offsets


class VADScanner:
    def __init__(self, reader, translator, build_number=0):
        self.reader = reader
        self.translator = translator
        self.logger = logging.getLogger(__name__)
        self.build_number = build_number or 0

        self.db_offsets = get_vad_offsets(self.build_number)
        db_offsets = self.db_offsets

        self.offsets = {
            "vpn_start": db_offsets.get("StartingVpn", 0x18),
            "ending_vpn": db_offsets.get("EndingVpn", 0x1C),
            "starting_vpn_high": db_offsets.get("StartingVpnHigh"),
            "ending_vpn_high": db_offsets.get("EndingVpnHigh"),
            "flags": db_offsets.get("VadFlags", 0x30),
            "subsection": db_offsets.get("Subsection", 0x48),
            "file_object": db_offsets.get("FileObject", 0x80),
            "control_area_file_pointer": db_offsets.get("ControlArea_FilePointer", 0x40),
            "file_object_filename": db_offsets.get("FileObject_FileName", 0x58),
            "unicode_length": db_offsets.get("UnicodeString_Length", 0x00),
            "unicode_buffer": db_offsets.get("UnicodeString_Buffer", 0x08),
        }

        self.last_scan_dtb = 0
        self.last_scan_reason = ""

        self.logger.info(
            "VADScanner initialized for Build %s (VadFlags=%s, Subsection=%s)",
            self.build_number,
            hex(self.offsets["flags"]),
            hex(self.offsets["subsection"]),
        )

    def scan_vad(self, proc_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Traverse one process VAD tree and return normalized region dicts.

        Important:
        VAD structures are kernel virtual memory, but the DTB that translates
        those addresses is not always the same across acquisition formats.
        Therefore this method tries both the current/kernel DTB and the
        process DTB, then keeps the first non-empty result.
        """
        pid = int(proc_info.get("pid", 0) or 0)
        proc_name = proc_info.get("image_name", proc_info.get("name", "?"))
        vad_root = self._resolve_vad_root(proc_info)
        proc_dtb = int(proc_info.get("dtb", 0) or 0)

        if not vad_root or vad_root == 0xFFFFFFFFFFFFFFFF:
            self.last_scan_reason = "missing_vad_root"
            return []

        original_dtb = int(getattr(self.translator, "dtb", 0) or 0)

        candidate_dtbs: List[Tuple[str, int]] = []
        if self._is_plausible_dtb(original_dtb):
            candidate_dtbs.append(("kernel/current", original_dtb))
        if self._is_plausible_dtb(proc_dtb) and proc_dtb != original_dtb:
            candidate_dtbs.append(("process", proc_dtb))

        # If no valid candidate, still try current DTB as best effort.
        if not candidate_dtbs:
            candidate_dtbs.append(("current_unverified", original_dtb))

        best_regions: List[Dict[str, Any]] = []
        best_label = ""
        best_error = ""

        try:
            for label, dtb in candidate_dtbs:
                self.translator.dtb = dtb
                self._clear_tlb()

                try:
                    regions = self._scan_vad_with_current_dtb(proc_info, vad_root)
                except Exception as exc:
                    regions = []
                    best_error = f"{label}: {exc}"

                if len(regions) > len(best_regions):
                    best_regions = regions
                    best_label = label

                # Stop early once we have a meaningful tree. Even a normal process
                # should have multiple VADs; however some short-lived processes have
                # very few, so any non-empty result is acceptable.
                if regions:
                    break

        finally:
            self.translator.dtb = original_dtb
            self._clear_tlb()

        if best_regions:
            self.last_scan_dtb = dict(candidate_dtbs).get(best_label, original_dtb)
            self.last_scan_reason = f"ok:{best_label}"
            self.logger.info(
                "PID %s (%s): scanned %d VAD regions using %s DTB",
                pid, proc_name, len(best_regions), best_label,
            )
        else:
            self.last_scan_dtb = 0
            self.last_scan_reason = best_error or (
                f"no_regions: vad_root={vad_root:#x}, "
                f"kernel_dtb={original_dtb:#x}, process_dtb={proc_dtb:#x}"
            )
            self.logger.debug(
                "PID %s (%s): VAD scan returned 0 regions (%s)",
                pid, proc_name, self.last_scan_reason,
            )

        return best_regions

    def _resolve_vad_root(self, proc_info: Dict[str, Any]) -> int:
        """Return a plausible VAD root pointer, with physical EPROCESS fallback."""
        try:
            root = int(proc_info.get("vad_root", 0) or 0)
            if self._is_kernel_pointer(root):
                return root
        except Exception:
            pass

        phys = int(proc_info.get("eprocess_phys_addr", 0) or 0)
        if not phys:
            return 0

        candidates = []
        try:
            profile = get_offsets(self.build_number).get("EPROCESS", {})
            if profile.get("VadRoot") is not None:
                candidates.append(int(profile["VadRoot"]))
        except Exception:
            pass

        # Modern Windows fallback candidates around EPROCESS.VadRoot.
        for off in (0x7d8, 0x7e0, 0x7e8, 0x800, 0x808):
            if off not in candidates:
                candidates.append(off)

        for off in candidates:
            try:
                raw = self.reader.read_physical(phys + off, 8)
                if raw and len(raw) >= 8:
                    val = struct.unpack("<Q", raw[:8])[0]
                    if self._is_kernel_pointer(val):
                        return val
            except Exception:
                pass
        return 0

    def _scan_vad_with_current_dtb(
        self,
        proc_info: Dict[str, Any],
        vad_root: int,
    ) -> List[Dict[str, Any]]:
        pid = proc_info.get("pid", 0)

        regions: List[Dict[str, Any]] = []
        stack = [vad_root]
        visited = set()
        count = 0

        while stack and count < 2000:
            node_addr = stack.pop()
            if not node_addr or node_addr in visited or node_addr == 0xFFFFFFFFFFFFFFFF:
                continue
            visited.add(node_addr)
            count += 1

            # 1. VAD AVL children. Read children independently; if child reads
            # fail, still try to parse the current node range.
            left = self.translator.read_virtual_pointer(node_addr)
            right = self.translator.read_virtual_pointer(node_addr + 8)

            if self._is_kernel_pointer(left) and left not in visited:
                stack.append(left)
            if self._is_kernel_pointer(right) and right not in visited:
                stack.append(right)

            # 2. VAD virtual address range.
            range_info = self._read_vad_range(node_addr)
            if range_info is None:
                continue

            start_addr, end_addr, size = range_info

            # Keep a wider cap than before. Some image mappings are large; the
            # carver's max_file_size will do output limiting later.
            if size < 0x1000 or size > 0x80000000:  # 4 KB to 2 GB
                continue

            # 3. Mapped-file pointer chain.
            filename = ""
            subsection = 0
            control_area = 0
            file_obj = 0

            try:
                subsection = self.translator.read_virtual_pointer(
                    node_addr + self.offsets["subsection"]
                )
                if self._is_kernel_pointer(subsection):
                    ca_off = self.db_offsets.get("Subsection_ControlArea", 0x00)
                    control_area = self.translator.read_virtual_pointer(subsection + ca_off)
                    if self._is_kernel_pointer(control_area):
                        fp_off = self.offsets["control_area_file_pointer"]
                        file_obj_ptr = self.translator.read_virtual_pointer(control_area + fp_off)
                        file_obj = self._decode_ex_fast_ref(file_obj_ptr)
                        if self._is_kernel_pointer(file_obj):
                            filename = self._read_file_object_name(file_obj)
            except Exception:
                pass

            # 3b. Fallback direct _MMVAD.FileObject (+0x80 on Win11 24H2).
            if not filename:
                try:
                    direct_file_obj = self.translator.read_virtual_pointer(
                        node_addr + self.offsets["file_object"]
                    )
                    direct_file_obj = self._decode_ex_fast_ref(direct_file_obj)
                    if self._is_kernel_pointer(direct_file_obj):
                        fallback_name = self._read_file_object_name(direct_file_obj)
                        if fallback_name:
                            file_obj = direct_file_obj
                            filename = fallback_name
                except Exception:
                    pass

            flags_info = self._read_vad_flags(node_addr)
            flags_value = flags_info["vad_flags_raw"]
            protection_str = flags_info["protection"]
            vad_type_name = flags_info["vad_type_name"]
            private_memory = flags_info["private_memory"]

            filename_l = filename.lower()
            if filename and any(ext in filename_l for ext in (".exe", ".dll", ".sys", ".ocx")):
                vad_type = "Image"
            elif filename:
                vad_type = "Mapped"
            elif private_memory:
                vad_type = "Private"
            else:
                vad_type = "Private"

            is_executable = self._is_executable_protection(protection_str)
            is_writable = self._is_writable_protection(protection_str)
            is_private_executable = bool(vad_type == "Private" and is_executable)

            regions.append({
                "start": start_addr,
                "end": end_addr,
                "size": size,
                "type": vad_type,
                "path": filename,
                "name": filename.split("\\")[-1] if filename else "",
                "protection": protection_str,
                "pid": pid,
                "node_address": node_addr,
                "subsection": subsection,
                "control_area": control_area,
                "file_object": file_obj,
                "file_backed": bool(filename),
                "carve_candidate": bool(filename and vad_type in ("Image", "Mapped")),
                "vad_flags_raw": flags_value,
                "vad_type_name": vad_type_name,
                "private_memory": private_memory,
                "is_executable": is_executable,
                "is_writable": is_writable,
                "is_private_executable": is_private_executable,
                "commit_charge": max(1, size // 4096),
            })

        return regions

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _clear_tlb(self) -> None:
        if hasattr(self.translator, "tlb"):
            try:
                self.translator.tlb.clear()
            except Exception:
                pass

    @staticmethod
    def _is_plausible_dtb(dtb: int) -> bool:
        return bool(
            dtb
            and dtb > 0x1000
            and dtb < 0x40000000000
            and (dtb & 0xFFF) == 0
        )

    @staticmethod
    def _is_kernel_pointer(value: int) -> bool:
        return bool(value and 0xFFFF000000000000 <= value < 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def _decode_ex_fast_ref(value: int) -> int:
        if not value:
            return 0
        return value & 0xFFFFFFFFFFFFFFF0

    def _read_u8(self, va: int) -> int:
        data = self.translator.read_virtual(va, 1)
        return data[0] if data and len(data) == 1 else 0

    def _read_vad_range(self, node_addr: int) -> Optional[Tuple[int, int, int]]:
        start_raw = self.translator.read_virtual(node_addr + self.offsets["vpn_start"], 4)
        end_raw = self.translator.read_virtual(node_addr + self.offsets["ending_vpn"], 4)
        if not start_raw or not end_raw or len(start_raw) != 4 or len(end_raw) != 4:
            return None

        start_vpn_low = struct.unpack("<I", start_raw)[0]
        end_vpn_low = struct.unpack("<I", end_raw)[0]

        start_vpn_high = 0
        end_vpn_high = 0

        start_high_off = self.offsets.get("starting_vpn_high")
        end_high_off = self.offsets.get("ending_vpn_high")

        if start_high_off is not None:
            start_vpn_high = self._read_u8(node_addr + start_high_off)
        if end_high_off is not None:
            end_vpn_high = self._read_u8(node_addr + end_high_off)

        start_vpn = (start_vpn_high << 32) | start_vpn_low
        end_vpn = (end_vpn_high << 32) | end_vpn_low

        if start_vpn == 0 or end_vpn == 0 or start_vpn > end_vpn:
            return None

        start_addr = start_vpn << 12
        end_addr = (end_vpn << 12) + 0xFFF
        size = end_addr - start_addr + 1
        return start_addr, end_addr, size

    def _read_file_object_name(self, file_obj: int) -> str:
        try:
            name_struct = file_obj + self.offsets["file_object_filename"]
            len_bytes = self.translator.read_virtual(
                name_struct + self.offsets["unicode_length"], 2
            )
            buf_ptr = self.translator.read_virtual_pointer(
                name_struct + self.offsets["unicode_buffer"]
            )
            if not buf_ptr or not len_bytes or len(len_bytes) != 2:
                return ""

            length = struct.unpack("<H", len_bytes)[0]
            if not (0 < length < 2048) or length % 2 != 0:
                return ""

            raw = self.translator.read_virtual(buf_ptr, length)
            if raw and len(raw) >= length:
                return raw.decode("utf-16le", "ignore").strip("\x00")
        except Exception:
            pass
        return ""

    def _read_vad_flags(self, node_addr: int) -> Dict[str, Any]:
        flags_value = 0
        try:
            flags = self.translator.read_virtual(node_addr + self.offsets["flags"], 4)
            if flags and len(flags) == 4:
                flags_value = struct.unpack("<I", flags)[0]
        except Exception:
            flags_value = 0

        return {
            "vad_flags_raw": flags_value,
            "protection": self._decode_vad_protection(flags_value),
            "vad_type_name": self._decode_vad_type(flags_value),
            "private_memory": self._is_private_memory(flags_value),
        }

    @staticmethod
    def _is_executable_protection(protection: str) -> bool:
        p = str(protection or "").upper()
        return "X" in p or "EXECUTE" in p

    @staticmethod
    def _is_writable_protection(protection: str) -> bool:
        p = str(protection or "").upper()
        return "W" in p or "WRITE" in p or "RWX" in p or "WCX" in p

    def _decode_vad_protection(self, flags_value: int) -> str:
        shift = self.db_offsets.get("VadFlags_Protection_Shift", 7)
        bits = self.db_offsets.get("VadFlags_Protection_Bits", 5)
        mask = (1 << bits) - 1
        prot = (flags_value >> shift) & mask

        protection_map = {
            0: "NOACCESS",
            1: "R",
            2: "X",
            3: "RX",
            4: "RW",
            5: "WC",
            6: "RWX",
            7: "WCX",
        }
        return protection_map.get(prot, f"UNKNOWN({prot})")

    def _decode_vad_type(self, flags_value: int) -> str:
        shift = self.db_offsets.get("VadFlags_VadType_Shift", 4)
        bits = self.db_offsets.get("VadFlags_VadType_Bits", 3)
        mask = (1 << bits) - 1
        vad_type_id = (flags_value >> shift) & mask

        vad_type_map = {
            0: "VadNone",
            1: "VadDevicePhysicalMemory",
            2: "VadImageMap",
            3: "VadAwe",
            4: "VadWriteWatch",
            5: "VadLargePages",
            6: "VadRotatePhysical",
            7: "VadLargePageSection",
        }
        return vad_type_map.get(vad_type_id, f"VadUnknown({vad_type_id})")

    def _is_private_memory(self, flags_value: int) -> bool:
        bit = self.db_offsets.get("VadFlags_PrivateMemory_Bit", 21)
        return bool((flags_value >> bit) & 1)

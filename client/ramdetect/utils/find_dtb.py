"""
ramdetect/utils/find_dtb.py
===========================
Native DTB/CR3 candidate scanner for RAW/.VMEM-style Windows RAM dumps.

v3 improvements:
- Designed to live at ramdetect/utils/find_dtb.py.
- Adds KDBG/KDDEBUGGER_DATA64 anchor discovery for kernel validation.
- Uses strict EPROCESS ImageFileName matching to avoid false matches such as
  SystemTime/SystemUpdateCom.
- Validates candidate DTBs with PML4 sanity and, when KDBG is found, kernel-base
  virtual-to-physical translation (MZ/PE check).
- Adds KPCR/KPRCB CR3 discovery based on the KPCR → KPRCB → ProcessorState
  → SpecialRegisters → CR3 research route.
- Optionally uses x64 PML4 self-reference discovery as an additional candidate
  source, but accepts it only when kernel/KPCR validation supports it.
- Writes only high-confidence candidates into the dump sidecar JSON.

Usage as module:
    python -m ramdetect.utils.find_dtb <dump_file> --build 22621 --scan-mb 0 --write-json

Legacy wrapper usage after replacing tools/find_dtb.py:
    python tools/find_dtb.py <dump_file> --build 22621 --scan-mb 0 --write-json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Optional



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


DEFAULT_SCAN_MB = 1024
CHUNK_SIZE = 16 * 1024 * 1024
OVERLAP = 0x3000
DTB_OFFSET = 0x28  # _KPROCESS.DirectoryTableBase on Windows x64
PAGE_SIZE = 0x1000
PTE_ADDR_MASK = 0x000FFFFFFFFFF000
MIN_ACCEPT_SCORE = 80

PROFILES = [
    {
        "name": "Windows 10 2004-22H2 / Windows 11 21H2-24H2",
        "build_min": 19041,
        "build_max": 26200,
        "name_off": 0x5A8,
        "pid_off": 0x440,
        "links_off": 0x448,
    },
    {
        "name": "Windows 10 1903/1909",
        "build_min": 18362,
        "build_max": 18363,
        "name_off": 0x450,
        "pid_off": 0x2E8,
        "links_off": 0x2F0,
    },
    {
        "name": "Windows 10 1803",
        "build_min": 17134,
        "build_max": 17134,
        "name_off": 0x450,
        "pid_off": 0x2E0,
        "links_off": 0x2E8,
    },
    {
        "name": "Windows 7 SP1 x64",
        "build_min": 7601,
        "build_max": 7601,
        "name_off": 0x2E0,
        "pid_off": 0x180,
        "links_off": 0x188,
    },
]

KNOWN_PROCESS_NAMES = [
    b"System", b"Registry", b"smss.exe", b"csrss.exe", b"wininit.exe",
    b"services.exe", b"lsass.exe", b"svchost.exe", b"explorer.exe",
    b"winlogon.exe", b"dwm.exe", b"fontdrvhost.exe", b"conhost.exe",
    b"dllhost.exe", b"RuntimeBroker", b"SearchIndexer.", b"taskhostw.exe",
]

EXACT_IMAGE_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
    "dllhost.exe", "runtimebroker", "searchindexer.", "taskhostw.exe",
}

EARLY_PROCESS_SCORE = {
    "system": 45,
    "registry": 20,
    "smss.exe": 22,
    "csrss.exe": 20,
    "wininit.exe": 20,
    "services.exe": 20,
    "lsass.exe": 20,
    "winlogon.exe": 16,
    "svchost.exe": 14,
    "explorer.exe": 12,
}

# x64 KPCR/KPRCB CR3 discovery. The exact path described in memory-forensics
# literature is KPCR -> KPRCB -> ProcessorState -> SpecialRegisters -> CR3.
# Windows x64 stores KPCR.Self at +0x18 and KPCR.CurrentPrcb at +0x20; for
# most NT 6.x/10/11 x64 builds CurrentPrcb == Self + 0x180. The final CR3
# byte offset varies slightly across builds and symbol layouts, so we test a
# small conservative list around the commonly observed KPRCB processor-state
# area instead of assuming one hard-coded value.
KPCR_SELF_OFF = 0x18
KPCR_CURRENT_PRCB_OFF = 0x20
KPCR_KD_VERSION_BLOCK_OFF = 0x108
KPCR_EXPECTED_PRCB_DELTA = 0x180
KPCR_CR3_OFFSETS = [
    0x7B8,  # common x64 KPCR.Prcb.ProcessorState.SpecialRegisters.Cr3
    0x7A8, 0x7B0, 0x7C0, 0x7C8,
    0x700, 0x708, 0x710, 0x718, 0x720, 0x728,
]


@dataclass
class DebugAnchor:
    physical_offset: int
    tag_offset: int
    size: int
    kern_base: int = 0
    ps_loaded_module_list: int = 0
    source: str = "KDBG"

    @property
    def summary(self) -> str:
        return f"{self.source}@{self.physical_offset:#x} kern={self.kern_base:#x} modules={self.ps_loaded_module_list:#x}"


@dataclass
class DtbCandidate:
    dtb: int
    profile: str
    eprocess_base: int = 0
    system_name_addr: int = 0
    process_name: str = ""
    pid: int = 0
    method: str = "unknown"
    hits: int = 1
    score: int = 0
    evidence: list[str] = field(default_factory=list)

    @property
    def dtb_hex(self) -> str:
        return hex(self.dtb)


class RawPhysicalReader:
    """Minimal file-offset reader for flat raw/vmem-style memory dumps."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.f: Optional[BinaryIO] = None
        self.size = self.path.stat().st_size

    def __enter__(self) -> "RawPhysicalReader":
        self.f = self.path.open("rb")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.f:
            self.f.close()

    def read_at(self, offset: int, size: int) -> bytes:
        if not self.f:
            raise RuntimeError("Reader is not open")
        if offset < 0 or offset >= self.size:
            return b""
        self.f.seek(offset)
        return self.f.read(size)

    def read_u16(self, offset: int) -> Optional[int]:
        data = self.read_at(offset, 2)
        return struct.unpack("<H", data)[0] if len(data) == 2 else None

    def read_u32(self, offset: int) -> Optional[int]:
        data = self.read_at(offset, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else None

    def read_u64(self, offset: int) -> Optional[int]:
        data = self.read_at(offset, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else None


def _profiles_for_build(build: Optional[int]) -> list[dict]:
    if not build:
        return PROFILES
    exact = [p for p in PROFILES if p["build_min"] <= build <= p["build_max"]]
    return exact or PROFILES


def _is_kernel_ptr(v: Optional[int]) -> bool:
    return isinstance(v, int) and 0xFFFF000000000000 <= v <= 0xFFFFFFFFFFFFFFFF


def _is_plausible_pid(pid: Optional[int], process_name: str) -> bool:
    if not isinstance(pid, int):
        return False
    lname = process_name.lower()
    if lname == "system":
        return pid == 4
    if pid <= 4 or pid > 1_000_000:
        return False
    return pid % 4 == 0


def _is_plausible_dtb(dtb: Optional[int], file_size: int) -> bool:
    if not isinstance(dtb, int) or not dtb:
        return False
    if dtb & 0xFFF:
        return False
    # Reject extremely small CR3 values. They are almost always false positives
    # in flat VMEM scans; the earlier 0x1000 result was an example.
    if dtb < 0x10000:
        return False
    if dtb >= file_size:
        return False
    return True


def _pml4_sanity(reader: RawPhysicalReader, dtb: int) -> tuple[bool, int, bool]:
    page = reader.read_at(dtb, PAGE_SIZE)
    if len(page) != PAGE_SIZE:
        return False, 0, False
    present = 0
    nonzero = 0
    selfref = False
    for i in range(0, PAGE_SIZE, 8):
        entry = struct.unpack_from("<Q", page, i)[0]
        if entry:
            nonzero += 1
        if entry & 1:
            present += 1
            if (entry & PTE_ADDR_MASK) == dtb:
                selfref = True
    if present < 1 or nonzero < 1:
        return False, present, selfref
    if present > 256:
        return False, present, selfref
    return True, present, selfref


def _read_image_name(reader: RawPhysicalReader, base: int, name_off: int) -> str:
    raw = reader.read_at(base + name_off, 15)
    if not raw:
        return ""
    raw = raw.split(b"\x00", 1)[0]
    try:
        name = raw.decode("ascii", errors="ignore")
    except Exception:
        return ""
    if not name or any(ord(ch) < 32 or ord(ch) > 126 for ch in name):
        return ""
    return name


def _name_matches_hit(field_name: str, needle: bytes) -> bool:
    if not field_name:
        return False
    got = field_name.lower()
    wanted = needle.decode("ascii", "ignore").lower()
    if wanted.endswith("."):
        return got.startswith(wanted) and got in EXACT_IMAGE_NAMES
    return got == wanted and got in EXACT_IMAGE_NAMES


def _translate_x64(reader: RawPhysicalReader, dtb: int, va: int) -> Optional[int]:
    """Translate x64 canonical VA through a candidate DTB. Returns physical address."""
    try:
        pml4_i = (va >> 39) & 0x1FF
        pdpt_i = (va >> 30) & 0x1FF
        pd_i = (va >> 21) & 0x1FF
        pt_i = (va >> 12) & 0x1FF
        off = va & 0xFFF

        pml4e = reader.read_u64((dtb & PTE_ADDR_MASK) + pml4_i * 8)
        if not pml4e or not (pml4e & 1):
            return None
        pdpt_base = pml4e & PTE_ADDR_MASK
        pdpte = reader.read_u64(pdpt_base + pdpt_i * 8)
        if not pdpte or not (pdpte & 1):
            return None
        if pdpte & (1 << 7):
            return (pdpte & 0x000FFFFFC0000000) + (va & 0x3FFFFFFF)
        pd_base = pdpte & PTE_ADDR_MASK
        pde = reader.read_u64(pd_base + pd_i * 8)
        if not pde or not (pde & 1):
            return None
        if pde & (1 << 7):
            return (pde & 0x000FFFFFFFE00000) + (va & 0x1FFFFF)
        pt_base = pde & PTE_ADDR_MASK
        pte = reader.read_u64(pt_base + pt_i * 8)
        if not pte or not (pte & 1):
            return None
        return (pte & PTE_ADDR_MASK) + off
    except Exception:
        return None


def _is_mz_pe(reader: RawPhysicalReader, phys: int) -> bool:
    head = reader.read_at(phys, 0x200)
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if not (0x40 <= e_lfanew < 0x200):
            return False
        return head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    except Exception:
        return False


def find_debug_anchors(dump_path: str | Path, scan_mb: int = 0, max_anchors: int = 12) -> list[DebugAnchor]:
    """Find KDBG/KDDEBUGGER_DATA64-like anchors in a flat dump."""
    dump_path = Path(dump_path)
    anchors: list[DebugAnchor] = []
    if not dump_path.is_file():
        return anchors
    file_size = dump_path.stat().st_size
    scan_limit = file_size if scan_mb <= 0 else min(scan_mb * 1024 * 1024, file_size)
    with RawPhysicalReader(dump_path) as reader:
        offset = 0
        carry = b""
        while offset < scan_limit and len(anchors) < max_anchors:
            to_read = min(CHUNK_SIZE, scan_limit - offset)
            chunk = reader.read_at(offset, to_read)
            if not chunk:
                break
            buf = carry + chunk
            base0 = offset - len(carry)
            idx = 0
            while len(anchors) < max_anchors:
                idx = buf.find(b"KDBG", idx)
                if idx == -1:
                    break
                tag_phys = base0 + idx
                size = reader.read_u32(tag_phys + 4) or 0
                # KDBG is often OwnerTag at DBGKD_DEBUG_DATA_HEADER64 + 0x10.
                kd_base = tag_phys - 0x10
                if 0x20 <= size <= 0x4000 and kd_base >= 0:
                    kern_base = reader.read_u64(kd_base + 0x18) or 0
                    modules = reader.read_u64(kd_base + 0x48) or 0
                    if _is_kernel_ptr(kern_base) or _is_kernel_ptr(modules):
                        anchors.append(DebugAnchor(kd_base, tag_phys, size, kern_base, modules))
                idx += 1
            offset += CHUNK_SIZE
            carry = buf[-OVERLAP:]
    # Deduplicate by physical offset
    dedup: dict[int, DebugAnchor] = {}
    for a in anchors:
        dedup[a.physical_offset] = a
    return list(dedup.values())


def _validate_kernel_translation(reader: RawPhysicalReader, dtb: int, anchors: list[DebugAnchor]) -> tuple[bool, str]:
    """Validate DTB by translating a KDBG kernel base VA to an MZ/PE image."""
    for a in anchors:
        if not _is_kernel_ptr(a.kern_base):
            continue
        phys = _translate_x64(reader, dtb, a.kern_base)
        if phys is not None and 0 <= phys < reader.size and _is_mz_pe(reader, phys):
            return True, f"kernel_base_translates_to_mz:{a.kern_base:#x}->{phys:#x}"
    return False, ""


def _score_candidate(
    cand: DtbCandidate,
    *,
    links_ok: bool,
    pml4_ok: bool,
    selfref: bool,
    kernel_ok: bool,
    build: Optional[int],
) -> int:
    lname = cand.process_name.lower()
    score = 0
    if cand.method == "selfref_pml4":
        score += 35 if selfref else 0
    elif cand.method == "kpcr_cr3":
        # KPCR consistency is strong evidence because the candidate comes from
        # the processor state path rather than from a loose process-name string.
        score += 42
    elif lname == "system" and cand.pid == 4:
        score += 50
    else:
        score += EARLY_PROCESS_SCORE.get(lname, 8)
        score += 12
    if pml4_ok:
        score += 15
    if links_ok:
        score += 12
    if selfref:
        score += 10 if cand.method == "kpcr_cr3" else 8
    if build:
        score += 5
    if cand.hits > 1:
        score += min(10, cand.hits * 2)
    if kernel_ok:
        score += 28
    elif cand.method == "kpcr_cr3":
        # No KDBG anchor is common in raw/converted dumps. If the KPCR layout is
        # internally consistent and the DTB is a sane PML4, keep it high enough
        # to be considered but still below kernel-validated candidates.
        if any(ev.startswith("kpcr_self:") for ev in cand.evidence):
            score += 12
    elif cand.method != "system_pid4":
        # Without kernel validation, fallback candidates must remain conservative.
        score -= 10
    return max(0, min(score, 100))


def _iter_ep_candidates(reader: RawPhysicalReader, scan_limit: int, profiles: list[dict], names: list[bytes], build: Optional[int], anchors: list[DebugAnchor]) -> dict[tuple[int, str], DtbCandidate]:
    candidates: dict[tuple[int, str], DtbCandidate] = {}
    offset = 0
    carry = b""
    while offset < scan_limit:
        to_read = min(CHUNK_SIZE, scan_limit - offset)
        chunk = reader.read_at(offset, to_read)
        if not chunk:
            break
        search_buf = carry + chunk
        carry_base = offset - len(carry)
        for needle in names:
            search_idx = 0
            while True:
                idx = search_buf.find(needle, search_idx)
                if idx == -1:
                    break
                phys_name = carry_base + idx
                for prof in profiles:
                    base = phys_name - prof["name_off"]
                    if base <= 0:
                        continue
                    field_name = _read_image_name(reader, base, prof["name_off"])
                    if not _name_matches_hit(field_name, needle):
                        continue
                    pid_val = reader.read_u64(base + prof["pid_off"])
                    if not _is_plausible_pid(pid_val, field_name):
                        continue
                    dtb_val = reader.read_u64(base + DTB_OFFSET)
                    if not _is_plausible_dtb(dtb_val, reader.size):
                        continue
                    flink = reader.read_u64(base + prof["links_off"])
                    blink = reader.read_u64(base + prof["links_off"] + 8)
                    links_ok = _is_kernel_ptr(flink) and _is_kernel_ptr(blink)
                    pml4_ok, present_count, selfref = _pml4_sanity(reader, dtb_val)
                    if not pml4_ok:
                        continue
                    kernel_ok, kernel_evidence = _validate_kernel_translation(reader, dtb_val, anchors)
                    if anchors and not kernel_ok and field_name.lower() != "system":
                        continue
                    key = (dtb_val, prof["name"])
                    if key in candidates:
                        candidates[key].hits += 1
                        continue
                    method = "system_pid4" if field_name.lower() == "system" and pid_val == 4 else "multiprocess_eprocess"
                    cand = DtbCandidate(dtb=dtb_val, profile=prof["name"], eprocess_base=base, system_name_addr=phys_name, process_name=field_name, pid=int(pid_val), method=method)
                    if kernel_evidence:
                        cand.evidence.append(kernel_evidence)
                    cand.score = _score_candidate(cand, links_ok=links_ok, pml4_ok=pml4_ok, selfref=selfref, kernel_ok=kernel_ok, build=build)
                    candidates[key] = cand
                    print(f"   🎯 HIT | {field_name:<15} PID={pid_val:<6} DTB={dtb_val:#x} EPROCESS={base:#x} PML4={present_count} KERN={'OK' if kernel_ok else '--'} Profile={prof['name']}")
                search_idx = idx + 1
        offset += CHUNK_SIZE
        carry = search_buf[-OVERLAP:]
        print(f"   Scanned: {min(offset, scan_limit) // (1024 * 1024)} MB", end="\r")
    return candidates


def _u64_from_buf(buf: bytes, offset: int) -> Optional[int]:
    if offset < 0 or offset + 8 > len(buf):
        return None
    return struct.unpack_from("<Q", buf, offset)[0]


def _kpcr_layout_ok(buf: bytes, page_off: int) -> tuple[bool, str, int, int, int]:
    """Validate likely x64 KPCR header fields inside a chunk buffer."""
    self_ptr = _u64_from_buf(buf, page_off + KPCR_SELF_OFF) or 0
    prcb_ptr = _u64_from_buf(buf, page_off + KPCR_CURRENT_PRCB_OFF) or 0
    kd_version = _u64_from_buf(buf, page_off + KPCR_KD_VERSION_BLOCK_OFF) or 0

    if not (_is_kernel_ptr(self_ptr) and _is_kernel_ptr(prcb_ptr)):
        return False, "", self_ptr, prcb_ptr, kd_version

    delta = prcb_ptr - self_ptr
    # Most x64 builds point CurrentPrcb to KPCR + 0x180. Allow a tight range to
    # avoid rejecting minor structure variations while filtering random pointers.
    if not (0x100 <= delta <= 0x300):
        return False, "", self_ptr, prcb_ptr, kd_version

    evidence = f"kpcr_self:{self_ptr:#x};prcb_delta:{delta:#x}"
    if _is_kernel_ptr(kd_version):
        evidence += f";kdversion:{kd_version:#x}"
    return True, evidence, self_ptr, prcb_ptr, kd_version


def _find_kpcr_cr3_candidates(
    reader: RawPhysicalReader,
    scan_limit: int,
    anchors: list[DebugAnchor],
    build: Optional[int],
) -> dict[tuple[int, str], DtbCandidate]:
    """Find DTB/CR3 values from x64 KPCR/KPRCB processor-state candidates.

    This implements the RAMDetect-native version of the academic route:
    KPCR -> KPRCB -> ProcessorState -> SpecialRegisters -> CR3. Because exact
    KPRCB offsets can vary, a small set of CR3 offsets is tested only after a
    KPCR-like header is validated. The result is accepted only if the CR3 points
    to a plausible PML4 page.
    """
    candidates: dict[tuple[int, str], DtbCandidate] = {}
    offset = 0
    while offset < scan_limit:
        to_read = min(CHUNK_SIZE, scan_limit - offset)
        chunk = reader.read_at(offset, to_read)
        if not chunk:
            break

        # KPCR is page-aligned in practical x64 dumps. Scan page starts only to
        # keep the search fast and reduce false positives.
        page_off = 0
        while page_off + max(KPCR_CR3_OFFSETS) + 8 <= len(chunk):
            phys_base = offset + page_off
            ok, kpcr_evidence, self_ptr, prcb_ptr, kd_version = _kpcr_layout_ok(chunk, page_off)
            if not ok:
                page_off += PAGE_SIZE
                continue

            for cr3_off in KPCR_CR3_OFFSETS:
                raw_cr3 = _u64_from_buf(chunk, page_off + cr3_off)
                if not raw_cr3:
                    continue
                # CR3 may carry PCID/low flag bits; page-align for the DTB value.
                dtb_val = raw_cr3 & PTE_ADDR_MASK
                if not _is_plausible_dtb(dtb_val, reader.size):
                    continue
                pml4_ok, present_count, selfref = _pml4_sanity(reader, dtb_val)
                if not pml4_ok:
                    continue
                kernel_ok, kernel_evidence = _validate_kernel_translation(reader, dtb_val, anchors)

                key = (dtb_val, "kpcr_cr3")
                if key in candidates:
                    candidates[key].hits += 1
                    # Preserve extra CPU/KPCR evidence without flooding.
                    if len(candidates[key].evidence) < 8:
                        candidates[key].evidence.append(f"kpcr_phys:{phys_base:#x};cr3_off:{cr3_off:#x}")
                    continue

                cand = DtbCandidate(
                    dtb=dtb_val,
                    profile="kpcr_cr3",
                    eprocess_base=phys_base,
                    system_name_addr=0,
                    process_name="<kpcr>",
                    pid=0,
                    method="kpcr_cr3",
                )
                cand.evidence.append(kpcr_evidence)
                cand.evidence.append(f"kpcr_phys:{phys_base:#x};cr3_off:{cr3_off:#x};raw_cr3:{raw_cr3:#x}")
                if kernel_evidence:
                    cand.evidence.append(kernel_evidence)
                cand.score = _score_candidate(
                    cand,
                    links_ok=False,
                    pml4_ok=pml4_ok,
                    selfref=selfref,
                    kernel_ok=kernel_ok,
                    build=build,
                )
                candidates[key] = cand
                print(
                    f"   🧩 KPCR | DTB={dtb_val:#x} KPCR={phys_base:#x} "
                    f"CR3_OFF={cr3_off:#x} PML4={present_count} SELFREF={'Y' if selfref else 'N'} "
                    f"KERN={'OK' if kernel_ok else '--'}"
                )

            page_off += PAGE_SIZE

        offset += CHUNK_SIZE
        print(f"   KPCR scanned: {min(offset, scan_limit) // (1024 * 1024)} MB", end="\r")

    if candidates:
        print()
    return candidates


def _find_selfref_candidates(reader: RawPhysicalReader, scan_limit: int, anchors: list[DebugAnchor]) -> dict[tuple[int, str], DtbCandidate]:
    """Find self-referencing PML4 pages. Only useful when KDBG kernel-base validation succeeds."""
    candidates: dict[tuple[int, str], DtbCandidate] = {}
    if not anchors:
        return candidates
    max_pages = scan_limit // PAGE_SIZE
    for page_no in range(max_pages):
        phys = page_no * PAGE_SIZE
        ok, present, selfref = _pml4_sanity(reader, phys)
        if not (ok and selfref):
            continue
        kernel_ok, evidence = _validate_kernel_translation(reader, phys, anchors)
        if not kernel_ok:
            continue
        cand = DtbCandidate(dtb=phys, profile="selfref_pml4", method="selfref_pml4", process_name="<kernel>", pid=0)
        cand.evidence.append(evidence)
        cand.score = _score_candidate(cand, links_ok=False, pml4_ok=True, selfref=True, kernel_ok=True, build=None)
        candidates[(phys, cand.profile)] = cand
        print(f"   🧭 SELFREF | DTB={phys:#x} PML4={present} KERN=OK")
    return candidates


def find_dtb(dump_path: str | Path, scan_mb: int = DEFAULT_SCAN_MB, build: Optional[int] = None, strict_system: bool = False, use_selfref: bool = True, use_kpcr: bool = True) -> Optional[DtbCandidate]:
    dump_path = Path(dump_path)
    print(f"\n🔎 Hunting for DTB/CR3 in: {dump_path.name}")
    print(f"   Max Scan Size: {'FULL DUMP' if scan_mb <= 0 else str(scan_mb) + ' MB'}")
    if build:
        print(f"   Selected Build: {build}")
    print(f"   Mode: KDBG/KPCR-assisted {'System PID 4 only' if strict_system else 'multi-process candidate scoring'}")
    print("=" * 60)

    if not dump_path.is_file():
        print(f"❌ File not found: {dump_path}")
        return None

    file_size = dump_path.stat().st_size
    scan_limit = file_size if scan_mb <= 0 else min(scan_mb * 1024 * 1024, file_size)
    profiles = _profiles_for_build(build)
    names = [b"System"] if strict_system else KNOWN_PROCESS_NAMES

    anchors = find_debug_anchors(dump_path, scan_mb=scan_mb, max_anchors=8)
    if anchors:
        print(f"   KDBG anchors: {len(anchors)}")
        for a in anchors[:3]:
            print(f"      - {a.summary}")
    else:
        print("   KDBG anchors: none found; using stricter EPROCESS-only validation")

    with RawPhysicalReader(dump_path) as reader:
        candidates: dict[tuple[int, str], DtbCandidate] = {}
        if use_kpcr:
            kpcr_candidates = _find_kpcr_cr3_candidates(reader, scan_limit, anchors, build)
            candidates.update(kpcr_candidates)
        ep_candidates = _iter_ep_candidates(reader, scan_limit, profiles, names, build, anchors)
        candidates.update(ep_candidates)
        if use_selfref:
            selfref_candidates = _find_selfref_candidates(reader, scan_limit, anchors)
            candidates.update(selfref_candidates)

        print("\n" + "=" * 60)
        if not candidates:
            print("❌ Could not find a valid DTB candidate.")
            print("   Try a different --build profile, verify the dump format, or inspect sidecar metadata.")
            return None

        # Recompute after hit aggregation.
        # Important safety rule: KPCR-only CR3 values are useful candidate
        # sources, but they are not accepted unless they are corroborated by
        # kernel translation or an EPROCESS-derived candidate with the same DTB.
        # This prevents earlier false positives such as 0x100000 from being
        # written to JSON merely because a KPCR-like layout was found.
        for cand in candidates.values():
            prof = next((p for p in PROFILES if p["name"] == cand.profile), None)
            links_ok = False
            if prof and cand.eprocess_base:
                flink = reader.read_u64(cand.eprocess_base + prof["links_off"])
                blink = reader.read_u64(cand.eprocess_base + prof["links_off"] + 8)
                links_ok = _is_kernel_ptr(flink) and _is_kernel_ptr(blink)
            pml4_ok, _, selfref = _pml4_sanity(reader, cand.dtb)
            kernel_ok, evidence = _validate_kernel_translation(reader, cand.dtb, anchors)
            if evidence and evidence not in cand.evidence:
                cand.evidence.append(evidence)

            same_dtb_eprocess = any(
                other.dtb == cand.dtb and other.method != "kpcr_cr3"
                for other in candidates.values()
            )

            cand.score = _score_candidate(
                cand,
                links_ok=links_ok,
                pml4_ok=pml4_ok,
                selfref=selfref,
                kernel_ok=kernel_ok,
                build=build,
            )

            if cand.method == "kpcr_cr3" and not kernel_ok and not same_dtb_eprocess:
                cand.score = min(cand.score, MIN_ACCEPT_SCORE - 1)
                cand.evidence.append("kpcr_only_not_accepted_without_kernel_or_eprocess_corroboration")

    ranked = list(candidates.values())
    ranked.sort(key=lambda c: (c.score, c.hits, 1 if c.process_name.lower() == "system" else 0), reverse=True)
    best = ranked[0]

    print("Candidates:")
    for cand in ranked[:12]:
        ev = f" evidence={';'.join(cand.evidence[:1])}" if cand.evidence else ""
        print(f"   DTB={cand.dtb_hex:<14} score={cand.score:>3}% hits={cand.hits:<2} proc={cand.process_name:<15} pid={cand.pid:<6} method={cand.method} eprocess={cand.eprocess_base:#x}{ev}")
    print("-" * 60)

    if best.score < MIN_ACCEPT_SCORE:
        print(f"❌ Best candidate is too weak: {best.dtb_hex} (confidence {best.score}%, required ≥ {MIN_ACCEPT_SCORE}%).")
        print("   Not accepting this DTB. This is safer than writing a wrong CR3 into JSON.")
        return None

    print(f"✅ Recommended DTB: {best.dtb_hex}  (confidence {best.score}%)")
    return best


def _find_sidecar_path(dump_path: Path) -> Path:
    candidates = [
        dump_path.with_suffix(".json"),
        Path(str(dump_path) + ".json"),
        dump_path.with_suffix(".dmp.metadata.json"),
        Path(str(dump_path) + ".metadata.json"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return dump_path.with_suffix(".json")


def write_dtb_to_sidecar(dump_path: str | Path, candidate: DtbCandidate, build: Optional[int] = None) -> Path:
    dump_path = Path(dump_path)
    sidecar_path = _find_sidecar_path(dump_path)
    if sidecar_path.is_file():
        try:
            metadata = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
    else:
        metadata = {}
    kernel = metadata.get("kernel_info")
    if not isinstance(kernel, dict):
        kernel = {}
    kernel.update({
        "dtb": candidate.dtb,
        "cr3": candidate.dtb,
        "dtb_hex": candidate.dtb_hex,
        "cr3_hex": candidate.dtb_hex,
        "dtb_source": f"detected_by_{candidate.method}",
        "dtb_confidence": candidate.score,
        "dtb_eprocess_base": hex(candidate.eprocess_base) if candidate.eprocess_base else None,
        "dtb_process_name": candidate.process_name,
        "dtb_process_pid": candidate.pid,
        "dtb_profile_match": candidate.profile,
        "dtb_evidence": candidate.evidence,
    })
    if build:
        kernel["build_number"] = build
        metadata["build_number"] = build
    metadata["kernel_info"] = kernel
    metadata["dtb"] = candidate.dtb
    metadata["cr3"] = candidate.dtb
    metadata["dtb_hex"] = candidate.dtb_hex
    metadata["cr3_hex"] = candidate.dtb_hex
    sidecar_path.write_text(json.dumps(metadata, indent=4), encoding="utf-8")
    return sidecar_path


def _parse_volatility_windows_info(output: str) -> Optional[dict]:
    """Parse noisy `vol -f <dump> windows.info.Info` output."""
    def grab(pattern: str) -> Optional[str]:
        m = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    dtb_hex = grab(r"^\s*DTB\s+(0x[0-9a-fA-F]+)\s*$")
    kernel_base = grab(r"^\s*Kernel Base\s+(0x[0-9a-fA-F]+)\s*$")
    kd_version = grab(r"^\s*KdVersionBlock\s+(0x[0-9a-fA-F]+)\s*$")
    major_minor_line = grab(r"^\s*Major/Minor\s+([0-9]+\.[0-9]+)\s*$")
    symbols = grab(r"^\s*Symbols\s+(.+)\s*$")
    is64 = grab(r"^\s*Is64Bit\s+(\w+)\s*$")
    ispae = grab(r"^\s*IsPAE\s+(\w+)\s*$")
    memory_layer = grab(r"^\s*memory_layer\s+\d+\s+(.+)\s*$")
    machine_type = grab(r"^\s*MachineType\s+(\d+)\s*$")
    processors = grab(r"^\s*KeNumberProcessors\s+(\d+)\s*$")
    system_time = grab(r"^\s*SystemTime\s+(.+)\s*$")
    nt_major = grab(r"^\s*NtMajorVersion\s+(\d+)\s*$")
    nt_minor = grab(r"^\s*NtMinorVersion\s+(\d+)\s*$")

    if not dtb_hex:
        return None
    try:
        dtb = int(dtb_hex, 16)
    except ValueError:
        return None
    if not _is_plausible_dtb(dtb, 1 << 52):
        return None

    build_number = None
    if major_minor_line:
        mm = re.search(r"([0-9]+)\.([0-9]+)", major_minor_line)
        if mm:
            build_number = int(mm.group(2))
    if not build_number or not (7600 <= build_number <= 30000):
        return None

    os_name = "Microsoft Windows 11" if build_number >= 22000 else "Microsoft Windows 10"

    def _to_bool(value: Optional[str]) -> Optional[bool]:
        if value is None:
            return None
        return str(value).strip().lower() == "true"

    return {
        "build_number": build_number,
        "os": os_name,
        "version": f"10.0.{build_number}",
        "dtb": dtb,
        "cr3": dtb,
        "dtb_hex": hex(dtb),
        "cr3_hex": hex(dtb),
        "dtb_source": "volatility_windows_info",
        "dtb_confidence": 100,
        "kernel_base_hex": kernel_base,
        "kd_version_block_hex": kd_version,
        "is_64bit": _to_bool(is64),
        "is_pae": _to_bool(ispae),
        "memory_layer": memory_layer,
        "machine_type": int(machine_type) if machine_type else None,
        "processor_count": int(processors) if processors else None,
        "nt_major_version": int(nt_major) if nt_major else None,
        "nt_minor_version": int(nt_minor) if nt_minor else None,
        "system_time_utc": system_time,
        "symbols": symbols,
    }


def volatility_recalibrate_kernel_info(dump_path: str | Path, timeout: int = 900) -> Optional[dict]:
    """
    External kernel metadata resolver limited to:
      vol -f <dump> windows.info.Info

    Scope: OS build/profile and kernel DTB/CR3 only. Do not use this output
    for artifact extraction, feature engineering, or verdict logic.
    """
    dump_path = str(dump_path)
    vol_path = _resolve_volatility_exe()
    if not vol_path:
        return None

    try:
        proc = subprocess.run(
            [vol_path, "-f", dump_path, "windows.info.Info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env={**os.environ, "PYTHONUTF8": "1"},
                        **_hidden_subprocess_kwargs(),
            )
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return _parse_volatility_windows_info(combined)
    except Exception:
        return None


def write_volatility_kernel_info_to_sidecar(dump_path: str | Path, info: dict) -> Path:
    """Write Volatility-recalibrated kernel metadata to sidecar JSON."""
    dump_path = Path(dump_path)
    sidecar_path = _find_sidecar_path(dump_path)
    if sidecar_path.is_file():
        try:
            metadata = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
    else:
        metadata = {}

    previous = metadata.get("kernel_info")
    if isinstance(previous, dict):
        metadata["previous_kernel_info_before_recalibration"] = previous

    kernel = dict(info)
    kernel["profile_source"] = "volatility_windows_info"
    kernel["profile_updated_at"] = datetime.now(timezone.utc).isoformat()

    metadata["kernel_info"] = kernel
    metadata["build_number"] = info["build_number"]
    metadata["os"] = info["os"]
    metadata["version"] = info["version"]
    metadata["dtb"] = info["dtb"]
    metadata["cr3"] = info["cr3"]
    metadata["dtb_hex"] = info["dtb_hex"]
    metadata["cr3_hex"] = info["cr3_hex"]
    sidecar_path.write_text(json.dumps(metadata, indent=4), encoding="utf-8")
    return sidecar_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Find Windows DTB/CR3 from raw/vmem RAM dump using KDBG/KPCR-assisted validation.")
    parser.add_argument("dump_file", help="Path to .dmp/.vmem/.raw memory dump")
    parser.add_argument("--scan-mb", type=int, default=DEFAULT_SCAN_MB, help="Scan limit in MB. Use 0 for full dump scan.")
    parser.add_argument("--build", type=int, default=None, help="Optional Windows build number, e.g. 19045 or 22621")
    parser.add_argument("--write-json", action="store_true", help="Write detected DTB into sidecar JSON")
    parser.add_argument("--strict-system", action="store_true", help="Only accept System/PID 4 EPROCESS candidate")
    parser.add_argument("--no-selfref", action="store_true", help="Disable self-referencing PML4 fallback")
    parser.add_argument("--no-kpcr", action="store_true", help="Disable KPCR/KPRCB CR3 discovery")
    parser.add_argument("--volatility-only", action="store_true", help="Resolve only OS profile/kernel DTB using: vol -f <dump> windows.info.Info")
    args = parser.parse_args()
    if args.volatility_only:
        info = volatility_recalibrate_kernel_info(args.dump_file)
        if not info:
            print("   Kernel metadata resolver failed. Ensure `vol` is installed and the dump is supported.")
            return 2
        if args.write_json:
            sidecar = write_volatility_kernel_info_to_sidecar(args.dump_file, info)
            print(f"💾 Sidecar updated: {sidecar}")
        print(f"✅ Kernel metadata resolved: DTB {info['dtb_hex']} | Build {info['build_number']}")
        return 0

    best = find_dtb(
        args.dump_file,
        scan_mb=args.scan_mb,
        build=args.build,
        strict_system=args.strict_system,
        use_selfref=not args.no_selfref,
        use_kpcr=not args.no_kpcr,
    )
    if not best:
        print("   Weak confidence detected, recalibrating kernel metadata...")
        info = volatility_recalibrate_kernel_info(args.dump_file)
        if not info:
            print("   Kernel metadata recalibration failed. Please verify the dump and OS profile.")
            return 2
        if args.write_json:
            sidecar = write_volatility_kernel_info_to_sidecar(args.dump_file, info)
            print(f"💾 Sidecar updated: {sidecar}")
        print(f"✅ Kernel metadata recalibrated successfully: DTB {info['dtb_hex']} | Build {info['build_number']}")
        return 0
    if args.write_json:
        sidecar = write_dtb_to_sidecar(args.dump_file, best, build=args.build)
        print(f"💾 Sidecar updated: {sidecar}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

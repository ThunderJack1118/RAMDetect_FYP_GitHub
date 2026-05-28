"""
ramdetect/utils/offset.py
=========================
Database of Windows Kernel Structure Offsets (EPROCESS, KPROCESS, ETHREAD, KTHREAD)
Used for memory carving, geometry detection, and structure parsing.
Data sourced from Vergilius Project and User Provided Structs.
"""

from typing import Dict, Any, Optional
import json
import lzma
import re
from urllib.parse import urlparse, unquote

# ============================================================================
# 1. EPROCESS OFFSETS (Context: Process Identification & Enumeration)
# ============================================================================
OFFSET_SETS = [
    # 0. Windows 7 SP1 x64 (Build 7601) - [UPDATED from User Struct]
    {
        'name': 'Windows 7 SP1 x64 (Build 7601)',
        'UniqueProcessId': 0x180,
        'InheritedFromUniqueProcessId': 0x290, 
        'ImageFileName': 0x2e0, 
        'ImageFilePointer': 0x2d8, 
        'ActiveProcessLinks': 0x188, 
        'ThreadListHead': 0x308, 
        'ThreadListEntry': 0x420, # ETHREAD offset
        'Peb': 0x338, 
        'DirectoryTableBase': 0x28, 
        'CreateTime': 0x168, 
        'ExitTime': 0x170,   
        'VadRoot': 0x448,    
        'Flags': 0x440       
    },
    # 1. Windows 10 1803 (Redstone 4)
    {
        'name': 'Windows 10 1803 (Redstone 4)',
        'UniqueProcessId': 0x2e0, 
        'InheritedFromUniqueProcessId': 0x3e0, 
        'ImageFileName': 0x450, 
        'ImageFilePointer': 0x448,
        'ActiveProcessLinks': 0x2e8,
        'ThreadListHead': 0x488, 
        'ThreadListEntry': 0x2f8, 
        'Peb': 0x3f8, 
        'DirectoryTableBase': 0x28, 
        'CreateTime': 0x308, 
        'ExitTime': 0x690,
        'VadRoot': 0x628,
        'Flags': 0x304
    },
    # 2. Windows 10 1903/1909 (19H1/19H2)
    # Verified from Vergilius/user-provided Win10 1909 structs.
    {
        'name': 'Windows 10 1903/1909',
        # _KPROCESS / Pcb
        'DirectoryTableBase': 0x28,
        'KPROCESS_ThreadListHead': 0x30,
        'UserDirectoryTableBase': 0x280,
        'UserDirectoryTableBaseCandidates': (0x280, 0x158, 0x388),

        # _EPROCESS
        'UniqueProcessId': 0x2e8,
        'ActiveProcessLinks': 0x2f0,
        'Flags2': 0x308,
        'Flags': 0x30c,
        'CreateTime': 0x310,
        'InheritedFromUniqueProcessId': 0x3e8,
        'Peb': 0x3f8,
        'ObjectTable': 0x418,
        'WoW64Process': 0x428,
        'ImageFilePointer': 0x448,
        'ImageFileName': 0x450,
        'ThreadListHead': 0x488,
        'ActiveThreads': 0x498,
        # ETHREAD.ThreadListEntry, retained for legacy callers that read it
        # from the EPROCESS profile instead of OFFSETS_ETHREAD.
        'ThreadListEntry': 0x6b8,
        'VadRoot': 0x658,
        'ExitTime': 0x6c0,
        'ActiveThreadsHighWatermark': 0x6d8,
    },
    # 3. Windows 10 2004+ / Windows 11 21H2 (Vibranium/Iron/Cobalt)
    {
        'name': 'Windows 10 2004+ / Win 11 21H2',
        'UniqueProcessId': 0x440, 
        'InheritedFromUniqueProcessId': 0x540, 
        'ImageFileName': 0x5a8, 
        'ImageFilePointer': 0x5a0,
        'ActiveProcessLinks': 0x448,
        'ThreadListHead': 0x5e0, 
        'Peb': 0x550, 
        'DirectoryTableBase': 0x28,
        # Phase 6D: Win11 22H2 / build 22621 uses PCID/low-bit CR3 flags.
        # Raw DTB values such as 0x3d352002 must be normalized to 0x3d352000.
        # Vergilius _KPROCESS.UserDirectoryTableBase for build 22621 is 0x388.
        'UserDirectoryTableBase': 0x388,
        'UserDirectoryTableBaseCandidates': (0x388, 0x158, 0x280, 0x2e8),
        'WoW64Process': 0x580,
        'ObjectTable': 0x570,
        'CreateTime': 0x468, 
        'ExitTime': 0x470, 
        'VadRoot': 0x7d8,
        'Flags': 0x464
    },
    # 4. Windows 11 24H2 / Germanium (Build 26100+)
    # Vergilius _EPROCESS / _KPROCESS layout supplied for RAMDetect.
    # IMPORTANT: these are true _EPROCESS-relative offsets. The previous
    # compatibility profile used pseudo-offsets shifted by +0x270, which still
    # let the pool scanner find process names but broke Peb, VadRoot, and
    # UserDirectoryTableBase-dependent recovery.
    {
        'name': 'Windows 11 24H2 (Build 26100+)',
        # _KPROCESS / Pcb
        'DirectoryTableBase': 0x28,
        'KPROCESS_ThreadListHead': 0x30,
        'UserDirectoryTableBase': 0x158,

        # _EPROCESS
        'UniqueProcessId': 0x1d0,
        'ActiveProcessLinks': 0x1d8,
        'Flags2': 0x1f0,
        'Flags': 0x1f4,
        'CreateTime': 0x1f8,
        'InheritedFromUniqueProcessId': 0x2d0,
        'Peb': 0x2e0,
        'ObjectTable': 0x300,
        'ImageFilePointer': 0x330,
        'ImageFileName': 0x338,
        'ThreadListHead': 0x370,
        'ActiveThreads': 0x380,
        'ExitStatus': 0x554,
        'VadRoot': 0x558,
        'VadHint': 0x560,
        'VadCount': 0x568,
        'ExitTime': 0x5c0,
        'ActiveThreadsHighWatermark': 0x5d8,
    },
    # 5. Windows XP SP3 x86 (Build 2600) — BlackEnergy/CyberDefenders support
    # Verified from Vergilius x86 Windows XP SP3 structures.
    {
        'name': 'Windows XP SP3 x86 (Build 2600)',
        'arch': 'x86',
        'pointer_size': 4,
        'is_pae': False,

        # _KPROCESS / Pcb
        'DirectoryTableBase': 0x18,
        'KPROCESS_ThreadListHead': 0x50,

        # _EPROCESS
        'CreateTime': 0x70,
        'ExitTime': 0x78,
        'UniqueProcessId': 0x84,
        'ActiveProcessLinks': 0x88,
        'ObjectTable': 0x0c4,
        'VadRoot': 0x11c,
        'VadHint': 0x120,
        'InheritedFromUniqueProcessId': 0x14c,
        'ImageFileName': 0x174,
        'ThreadListHead': 0x190,
        'ActiveThreads': 0x1a0,
        'Peb': 0x1b0,
        'Flags': 0x248,

        # XP x86 has no KVA-shadow UserDirectoryTableBase.
        'UserDirectoryTableBase': None,
        'UserDirectoryTableBaseCandidates': (),

        # ETHREAD.ThreadListEntry, retained for legacy callers.
        'ThreadListEntry': 0x22c,
    }
    ,
    # 6. Windows 10 19041 x86 PAE — dynamic-symbol preferred fallback
    # These values are conservative fallbacks. At runtime, RAMDetect tries to
    # load the exact Volatility ISF symbol JSON for ntkrpamp.pdb and overlays
    # the verified _EPROCESS/_KPROCESS field offsets.
    {
        'name': 'Windows 10 19041 x86 PAE (dynamic symbol preferred)',
        'arch': 'x86',
        'pointer_size': 4,
        'is_pae': True,
        'DirectoryTableBase': 0x18,
        'KPROCESS_ThreadListHead': 0x50,
        'UniqueProcessId': 0xb4,
        'ActiveProcessLinks': 0xb8,
        'CreateTime': 0x0,
        'ExitTime': 0x0,
        'InheritedFromUniqueProcessId': 0x0,
        'Peb': 0x0,
        'ObjectTable': 0x0,
        'VadRoot': 0x0,
        'ImageFileName': 0x174,
        'ThreadListHead': 0x0,
        'ActiveThreads': 0x0,
        'Flags': 0x0,
        'UserDirectoryTableBase': None,
        'UserDirectoryTableBaseCandidates': (),
        'ThreadListEntry': 0x0,
    }


]

# ============================================================================
# 2. ETHREAD OFFSETS (Context: Thread Analysis & Stack Walking)
# ============================================================================
OFFSETS_ETHREAD = {
    # Windows XP SP3 x86 (Build 2600)
    # Verified from Vergilius x86 Windows XP SP3 _KTHREAD/_ETHREAD structs.
    'WinXP_SP3_X86': {
        'pointer_size': 4,
        'arch': 'x86',
        'is_pae': False,

        # KTHREAD members (Tcb at ETHREAD + 0x0)
        'Teb': 0x020,
        'State': 0x02d,
        'Priority': 0x033,
        'WaitReason': 0x05b,
        'BasePriority': 0x06c,
        'StackLimit': 0x01c,
        'StackBase': 0x168,
        'KTHREAD_ThreadListEntry': 0x1b0,

        # ETHREAD members
        'Cid': 0x1ec,
        'StartAddress': 0x224,
        'Win32StartAddress': 0x228,
        'ThreadListEntry': 0x22c,

        # Process thread-list heads
        'EPROCESS_ThreadListHead': 0x190,
        'KPROCESS_ThreadListHead': 0x50,
    },

    # Windows 7 SP1 x64 (Build 7601) - [UPDATED with User Struct]
    'Win7_SP1': {
        # KTHREAD members (Inside Tcb at 0x0)
        'LockEntries': 0x2a0, 'Teb': 0x0b8, 'State': 0x164,
        'WaitReason': 0x165, 'Priority': 0x166, 'BasePriority': 0x167,
        'StackBase': 0x028, 'StackLimit': 0x020,

        # ETHREAD members (After Tcb)
        'ThreadListEntry': 0x420,  # ETHREAD offset into the EPROCESS ThreadListHead list
        'Cid': 0x3b0,
        'StartAddress': 0x388,
        'Win32StartAddress': 0x410,

        # EPROCESS.ThreadListHead offset — needed by ThreadParser to walk threads.
        # Stored here so ThreadParser is self-contained without needing eprocess_offsets.
        'EPROCESS_ThreadListHead': 0x308,  # EPROCESS[Win7 SP1].ThreadListHead
    },

    # Windows 10 1803 (Redstone 4)
    'Win10_1803': {
        'LockEntries': 0x320, 'Teb': 0x098, 'State': 0x070, 
        'WaitReason': 0x071, 'Priority': 0x074, 'BasePriority': 0x23A,
        'StackBase': 0x030, 'StackLimit': 0x038,
        'ThreadListEntry': 0x488,  'Cid': 0x418,
        'StartAddress': 0x3d0,     'Win32StartAddress': 0x450,
        'EPROCESS_ThreadListHead': 0x488,  # EPROCESS[1803].ThreadListHead
    },
    
    # Windows 10 1903/1909 (19H1/19H2) — build 18362/18363
    # Verified from Vergilius/user-provided structs.
    'Win10_1903': {
        'LockEntries': 0x320,
        'Teb': 0x0f0,
        'State': 0x184,
        'WaitReason': 0x283,
        'Priority': 0x0c3,
        'BasePriority': 0x233,
        'StackBase': 0x038,
        'StackLimit': 0x030,

        # EPROCESS.ThreadListHead + ETHREAD.ThreadListEntry mode
        'EPROCESS_ThreadListHead': 0x488,
        'ThreadListEntry': 0x6b8,
        'Cid': 0x648,
        'StartAddress': 0x620,
        'Win32StartAddress': 0x6a0,

        # Optional secondary KPROCESS/KTHREAD mode
        'KPROCESS_ThreadListHead': 0x30,
        'KTHREAD_ThreadListEntry': 0x2f8,
    },

    # Windows 10 2004 / 20H2 / 21H1 / 21H2 / 22H2 (Build 19041-19045)
    # Verified from Vergilius/user-provided structs for Win10 21H1/21H2/22H2.
    'Win10_2004': {
        'LockEntries': 0x320,
        'Teb': 0x0f0,
        'State': 0x184,
        'WaitReason': 0x283,
        'Priority': 0x0c3,
        'BasePriority': 0x233,
        'StackBase': 0x038,
        'StackLimit': 0x030,
        'ThreadListEntry': 0x4e8,
        'Cid': 0x478,
        'StartAddress': 0x450,
        'Win32StartAddress': 0x4d0,
        'EPROCESS_ThreadListHead': 0x5e0,  # EPROCESS[19041-19045].ThreadListHead
    },

    # Windows 11 21H2 (Cobalt)
    'Win11_21H2': {
        'LockEntries': 0x320, 'Teb': 0x098, 'State': 0x070,
        'WaitReason': 0x071, 'Priority': 0x074, 'BasePriority': 0x23A,
        'StackBase': 0x030, 'StackLimit': 0x038,
        'ThreadListEntry': 0x538,
        'Cid': 0x4c8,
        'StartAddress': 0x480,
        'Win32StartAddress': 0x500,
        'EPROCESS_ThreadListHead': 0x5e0,  # EPROCESS[21H2].ThreadListHead
    },

    # Windows 11 22H2 (Nickel)
    'Win11_22H2': {
        'LockEntries': 0x320, 'Teb': 0x098, 'State': 0x070,
        'WaitReason': 0x071, 'Priority': 0x074, 'BasePriority': 0x23A,
        'StackBase': 0x030, 'StackLimit': 0x038,
        'ThreadListEntry': 0x568,
        'Cid': 0x4f8,
        'StartAddress': 0x4b0,
        'Win32StartAddress': 0x530,
        'EPROCESS_ThreadListHead': 0x5e0,  # EPROCESS[22H2].ThreadListHead
    },

    # Windows 11 23H2 (Build 22631)
    # Verified from Vergilius/user-provided Win11 23H2 structs.
    'Win11_23H2': {
        'LockEntries': 0x320,
        'Teb': 0x0f0,
        'State': 0x184,
        'WaitReason': 0x283,
        'Priority': 0x0c3,
        'BasePriority': 0x233,
        'StackBase': 0x038,
        'StackLimit': 0x030,
        'ThreadListEntry': 0x538,
        'Cid': 0x4c8,
        'StartAddress': 0x4a0,
        'Win32StartAddress': 0x520,
        'EPROCESS_ThreadListHead': 0x5e0,  # EPROCESS[22631].ThreadListHead
    },

    # Windows 11 24H2 (Germanium)
    'Win11_24H2': {
        'LockEntries': 0x320, 'Teb': 0x098, 'State': 0x070,
        'WaitReason': 0x071, 'Priority': 0x074, 'BasePriority': 0x23A,
        'StackBase': 0x030, 'StackLimit': 0x038,
        'ThreadListEntry': 0x538,
        'Cid': 0x4c8,
        'StartAddress': 0x4a0,
        'Win32StartAddress': 0x520,
        'EPROCESS_ThreadListHead': 0x370,  # EPROCESS[24H2].ThreadListHead
    }
}

# --- GEOMETRY SCANNER DATABASE (Legacy Support) ---
WINDOWS_OFFSETS = {
    'win7_sp1':   OFFSET_SETS[0],
    'win10_1803': OFFSET_SETS[1], 
    'win10_1909': OFFSET_SETS[2],
    'win10_11':   OFFSET_SETS[3],
    'win11_24h2': OFFSET_SETS[4],
    'winxp_sp3_x86': OFFSET_SETS[5]
}

DUMP_SIGNATURES = {
    'CRASH_DUMP': [
        (0, b'PAGEDUMP'), 
        (0, b'DUMP'), 
        (0x8, b'DUMPHDR'), 
        (0, b'MDMP')
    ]
}

# --- HELPER FUNCTIONS ---


def _is_false(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"false", "0", "x86", "i386"}


def _is_x86_pae_profile(build_number: Optional[int] = None, is_64bit: Optional[bool] = None, is_pae: Optional[bool] = None) -> bool:
    """Return True for Windows x86 PAE metadata such as Volatility WindowsIntelPAE."""
    if build_number is None:
        return False
    try:
        b = int(build_number)
    except Exception:
        return False
    return b >= 10240 and _is_false(is_64bit) and bool(is_pae)


def _symbol_path_from_uri(symbols_uri: Optional[str]) -> Optional[str]:
    if not symbols_uri:
        return None
    value = str(symbols_uri).strip()
    if value.startswith("file://"):
        parsed = urlparse(value)
        return unquote(parsed.path.lstrip("/") if re.match(r"^/[A-Za-z]:/", parsed.path) else parsed.path)
    return value


def _load_isf_json(symbols_uri: Optional[str]) -> Optional[Dict[str, Any]]:
    """Load a Volatility ISF JSON or JSON.XZ file if available."""
    path = _symbol_path_from_uri(symbols_uri)
    if not path:
        return None
    try:
        if str(path).lower().endswith(".xz"):
            with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return json.load(fh)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _field_offset(type_obj: Dict[str, Any], field_name: str) -> Optional[int]:
    fields = type_obj.get("fields") if isinstance(type_obj, dict) else None
    if not isinstance(fields, dict) or field_name not in fields:
        return None
    f = fields[field_name]
    try:
        if isinstance(f, dict):
            if "offset" in f:
                return int(f["offset"])
            if "relative_child_offset" in f:
                return int(f["relative_child_offset"])
        if isinstance(f, (list, tuple)) and f:
            return int(f[0])
        return int(f)
    except Exception:
        return None


def build_symbol_backed_offsets(
    build_number: Optional[int] = None,
    *,
    is_64bit: Optional[bool] = None,
    is_pae: Optional[bool] = None,
    symbols: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return EPROCESS offsets for the requested profile, overlaying exact offsets
    from Volatility's ISF symbol JSON when available.

    This is especially important for Windows 10 x86 PAE dumps: build number
    alone (e.g. 19041) is not enough because the x86 _EPROCESS layout differs
    from the common x64 19041 layout.
    """
    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        profile = dict(OFFSET_SETS[6])
    else:
        profile = dict(get_offsets(build_number).get("EPROCESS", {}))

    isf = _load_isf_json(symbols)
    if not isf:
        return profile

    user_types = isf.get("user_types") or isf.get("types") or {}
    eproc = user_types.get("_EPROCESS") or user_types.get("EPROCESS") or {}
    kproc = user_types.get("_KPROCESS") or user_types.get("KPROCESS") or {}

    eprocess_fields = {
        "UniqueProcessId": "UniqueProcessId",
        "ActiveProcessLinks": "ActiveProcessLinks",
        "CreateTime": "CreateTime",
        "ExitTime": "ExitTime",
        "InheritedFromUniqueProcessId": "InheritedFromUniqueProcessId",
        "Peb": "Peb",
        "ObjectTable": "ObjectTable",
        "VadRoot": "VadRoot",
        "ImageFileName": "ImageFileName",
        "ThreadListHead": "ThreadListHead",
        "ActiveThreads": "ActiveThreads",
        "Flags": "Flags",
        "WoW64Process": "WoW64Process",
    }
    for out_name, sym_name in eprocess_fields.items():
        off = _field_offset(eproc, sym_name)
        if off is not None:
            profile[out_name] = off

    for out_name, sym_name in {
        "DirectoryTableBase": "DirectoryTableBase",
        "KPROCESS_ThreadListHead": "ThreadListHead",
        "UserDirectoryTableBase": "UserDirectoryTableBase",
    }.items():
        off = _field_offset(kproc, sym_name)
        if off is not None:
            profile[out_name] = off

    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        profile["arch"] = "x86"
        profile["pointer_size"] = 4
        profile["is_pae"] = True
        profile["UserDirectoryTableBase"] = None
        profile["UserDirectoryTableBaseCandidates"] = ()

    return profile




def build_symbol_backed_thread_offsets(
    build_number: Optional[int] = None,
    *,
    is_64bit: Optional[bool] = None,
    is_pae: Optional[bool] = None,
    symbols: Optional[str] = None,
    eprocess_offsets: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Return ETHREAD/KTHREAD offsets, overlaying exact values from Volatility's
    ISF symbol JSON when available. This is required for Windows x86 PAE dumps
    because Win10 build 19041 x86 uses a very different ETHREAD layout from the
    normal x64 19041 profile.
    """
    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        # Start with XP x86 only as a shape fallback; exact Win10 x86 fields
        # should be overlaid from ntkrpamp.pdb when the ISF is available.
        profile: Dict[str, Any] = dict(OFFSETS_ETHREAD['WinXP_SP3_X86'])
        profile.update({
            'name': 'Windows 10 x86 PAE symbol-backed thread offsets',
            'arch': 'x86',
            'pointer_size': 4,
            'is_pae': True,
        })
    else:
        profile = dict(get_thread_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae))

    isf = _load_isf_json(symbols)
    if not isf:
        return profile

    user_types = isf.get('user_types') or isf.get('types') or {}
    ethread = user_types.get('_ETHREAD') or user_types.get('ETHREAD') or {}
    kthread = user_types.get('_KTHREAD') or user_types.get('KTHREAD') or {}

    # ETHREAD fields
    for out_name, sym_name in {
        'Cid': 'Cid',
        'StartAddress': 'StartAddress',
        'Win32StartAddress': 'Win32StartAddress',
        'ThreadListEntry': 'ThreadListEntry',
        'CreateTime': 'CreateTime',
        'ExitTime': 'ExitTime',
    }.items():
        off = _field_offset(ethread, sym_name)
        if off is not None:
            profile[out_name] = off

    # KTHREAD fields. ETHREAD starts with KTHREAD/Tcb at offset 0 on Windows, so
    # these are also ETHREAD-relative in practice.
    for out_name, sym_name in {
        'Teb': 'Teb',
        'State': 'State',
        'WaitReason': 'WaitReason',
        'Priority': 'Priority',
        'BasePriority': 'BasePriority',
        'StackBase': 'StackBase',
        'StackLimit': 'StackLimit',
        'KTHREAD_ThreadListEntry': 'ThreadListEntry',
    }.items():
        off = _field_offset(kthread, sym_name)
        if off is not None:
            profile[out_name] = off

    if eprocess_offsets:
        if eprocess_offsets.get('ThreadListHead') is not None:
            profile['EPROCESS_ThreadListHead'] = int(eprocess_offsets['ThreadListHead'])
        if eprocess_offsets.get('KPROCESS_ThreadListHead') is not None:
            profile['KPROCESS_ThreadListHead'] = int(eprocess_offsets['KPROCESS_ThreadListHead'])

    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        profile['arch'] = 'x86'
        profile['pointer_size'] = 4
        profile['is_pae'] = True

    return profile

def get_thread_offsets(build_number: Optional[int] = None, is_64bit: Optional[bool] = None, is_pae: Optional[bool] = None, symbols: Optional[str] = None, eprocess_offsets: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """
    Returns the ETHREAD offsets for the given build.
    """
    if not build_number:
        return OFFSETS_ETHREAD['Win11_24H2'] 
    
    if build_number == 2600:   return OFFSETS_ETHREAD['WinXP_SP3_X86']
    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        return build_symbol_backed_thread_offsets(
            build_number,
            is_64bit=is_64bit,
            is_pae=is_pae,
            symbols=symbols,
            eprocess_offsets=eprocess_offsets,
        )
    if build_number >= 26000:   return OFFSETS_ETHREAD['Win11_24H2']
    elif build_number >= 22631: return OFFSETS_ETHREAD['Win11_23H2']
    elif build_number >= 22621: return OFFSETS_ETHREAD['Win11_22H2']
    elif build_number >= 22000: return OFFSETS_ETHREAD['Win11_21H2']
    elif build_number >= 19041: return OFFSETS_ETHREAD['Win10_2004']
    elif build_number >= 18362: return OFFSETS_ETHREAD['Win10_1903']
    elif build_number >= 17134: return OFFSETS_ETHREAD['Win10_1803']
    elif build_number == 7601:  return OFFSETS_ETHREAD['Win7_SP1'] 
    
    return OFFSETS_ETHREAD['Win11_24H2']

def get_offsets(build_number: Optional[int] = None, is_64bit: Optional[bool] = None, is_pae: Optional[bool] = None, symbols: Optional[str] = None) -> Dict[str, Dict[str, int]]:
    """
    Returns the Unified Profile (EPROCESS + ETHREAD) required by the Extraction Tool.
    """
    # 1. Select EPROCESS Offsets
    if _is_x86_pae_profile(build_number, is_64bit, is_pae):
        eprocess_selected = build_symbol_backed_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae, symbols=symbols)
        ethread_selected = get_thread_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae, symbols=symbols, eprocess_offsets=eprocess_selected)
        return {"EPROCESS": eprocess_selected, "ETHREAD": ethread_selected}

    eprocess_selected = OFFSET_SETS[3] # Default to Win10/11 common
    
    if build_number:
        if build_number == 2600:   eprocess_selected = OFFSET_SETS[5] # WinXP SP3 x86
        elif build_number >= 26000: eprocess_selected = OFFSET_SETS[4] # Win11 24H2
        elif build_number >= 19041: eprocess_selected = OFFSET_SETS[3] # Win10 20H1+
        elif build_number >= 18362: eprocess_selected = OFFSET_SETS[2] # Win10 1903
        elif build_number >= 17134: eprocess_selected = OFFSET_SETS[1] # Win10 1803
        elif build_number == 7601:  eprocess_selected = OFFSET_SETS[0] # Win7 SP1
    
    # 2. Select ETHREAD Offsets (Reusing the helper logic)
    ethread_selected = get_thread_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae, symbols=symbols, eprocess_offsets=eprocess_selected)

    # 3. Return Nested Dictionary to satisfy ramdetect_extraction_tool.py
    return {
        "EPROCESS": eprocess_selected,
        "ETHREAD": ethread_selected
    }

def get_pointer_size(build_number: Optional[int] = None, is_64bit: Optional[bool] = None, is_pae: Optional[bool] = None) -> int:
    """
    Returns pointer size for the selected OS profile.
    XP x86 uses 4-byte pointers; modern x64 profiles use 8-byte pointers.
    """
    profile = get_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae).get("EPROCESS", {})
    return int(profile.get('pointer_size', 8))


def is_x86_build(build_number: Optional[int] = None, is_64bit: Optional[bool] = None, is_pae: Optional[bool] = None) -> bool:
    """Returns True for profiles marked as x86."""
    profile = get_offsets(build_number, is_64bit=is_64bit, is_pae=is_pae).get("EPROCESS", {})
    return str(profile.get('arch', 'x64')).lower() == 'x86'


def get_vad_offsets(build_number: int) -> dict:
    """
    Returns the dynamic _MMVAD offsets for VAD Tree parsing.
    Used by: ramdetect/extraction/parsers/vad_scanner.py
    """
    # Windows 10 & Windows 11 (Build 10240 and higher)
    if build_number >= 10240:
        return {
            "StartingVpn": 0x18,
            "VadFlags": 0x20,
            "Subsection": 0x48
        }
    
    # Windows 8 / 8.1 (Builds 9200 - 9600)
    elif build_number >= 9200:
        return {
            "StartingVpn": 0x18,
            "VadFlags": 0x28, 
            "Subsection": 0x48
        }
        
    # Windows 7 x64 SP1 (Build 7600 / 7601)
    else:
        return {
            "StartingVpn": 0x18,
            "VadFlags": 0x28,
            "Subsection": 0x48
        }
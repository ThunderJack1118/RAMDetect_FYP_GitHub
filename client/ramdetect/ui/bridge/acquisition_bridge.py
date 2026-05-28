"""
ui/bridge/acquisition_bridge.py
────────────────────────────────
Wraps  ramdetect/acquisition/  for:
  1. Live RAM acquisition via DumpIt
  2. Validation of existing .dmp / .raw / .bin / .mem files
  3. Session-folder organisation (new)

── Folder layout (both modes) ──────────────────────────────────────────────
  <output_dir>/
    memdump_20241217_143022/          ← live acquisition
        memdump_20241217_143022.dmp
        memdump_20241217_143022.json

    Win10_malware_20241217_150500/    ← load-file (organised copy)
        Win10_malware.dmp
        Win10_malware.json

Every public method returns a normalised dict so pages never need to
know about backend internals.

validate_file() returns:
{
  'valid':        bool,
  'path':         str,
  'filename':     str,
  'size_bytes':   int,
  'size_str':     str,
  'format':       str,   e.g. "DMP"
  'architecture': str,   e.g. "x64 Windows (build 19045)"
  'os_hint':      str,   e.g. "Windows"
  'est_load_time':str,   e.g. "~45 s"
  'sha256':       str,   first 16 hex chars + "..."
  'error':        str,   non-empty if valid=False
}

start_live_dump() → returns a LiveDumpWorker
  finished_cb receives the same dict PLUS:
    'session_dir': str   ← the folder that holds both .dmp and .json

organize_loaded_file() → dict
{
  'success':     bool,
  'session_dir': str,          full path of the new folder
  'dump_path':   str,          final path of the dump inside session_dir
  'json_path':   str | None,   path of the sidecar JSON (if available)
  'message':     str,          human-readable result or error
}
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import struct
import subprocess
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Dict, Any



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


from ui.bridge.config_bridge import Config

# ── Import real acquisition backend ──────────────────────────────────────────
_IMPORT_ERROR: Optional[str] = None
try:
    from ramdetect.acquisition.dumpit          import DumpItAcquisition
    from ramdetect.acquisition.converter_todmp import RawDumpConverter
    from ramdetect.acquisition.metadata_reader import MetadataReader
    from ramdetect.acquisition.metadata        import MetadataManager
except ImportError as _e:
    _IMPORT_ERROR = (
        f"Acquisition backend unavailable: {_e}. "
        "Ensure ramdetect is installed and on sys.path."
    )

SUPPORTED_EXTENSIONS = {".dmp", ".raw", ".bin", ".mem", ".vmem", ".lime"}


def _project_root() -> Path:
    """Return current RAMDetect project root independent of install location."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        try:
            if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
                return parent
        except OSError:
            pass
    return Path.cwd().resolve()


def _canonical_dumps_dir(_configured: Optional[str] = None, create: bool = True) -> Path:
    """Canonical dump output directory for this RAMDetect installation.

    The acquisition pipeline must never reuse stale absolute paths copied from
    another workstation. Therefore imported dumps and DumpIt acquisitions always
    go into <current_project_root>/dumps.
    """
    target = _project_root() / "dumps"
    if create:
        target.mkdir(parents=True, exist_ok=True)
    return target


def _is_inside_managed_session(path_obj: Path, create_base: bool = False) -> bool:
    """Return True only for <current_project>/dumps/<session>/<file>.

    This prevents metadata helpers from creating sidecar JSON beside a dump
    located in Downloads/Desktop or any external folder. Sidecars should only
    be written after the dump is inside RAMDetect's managed session folder.
    """
    try:
        base = _canonical_dumps_dir(create=create_base).resolve()
        path_resolved = path_obj.resolve()
        rel = path_resolved.relative_to(base)
        return len(rel.parts) >= 2 and path_resolved.parent != base
    except Exception:
        return False


def _safe_unlink_sidecar(sidecar: Optional[Path], managed_session_dir: Optional[Path] = None) -> None:
    """Best-effort deletion of a stale sidecar outside the managed session."""
    if not sidecar:
        return
    try:
        sidecar = sidecar.resolve()
        if managed_session_dir is not None:
            try:
                sidecar.relative_to(managed_session_dir.resolve())
                return  # never delete the managed copy
            except ValueError:
                pass
        if sidecar.is_file():
            sidecar.unlink()
    except Exception as exc:
        print(f"[AcquisitionBridge] Could not remove stale sidecar {sidecar}: {exc}")


# Manual profile choices for dumps that do not contain a crash-dump header
# or sidecar JSON. Do not silently default to Win11 offsets.
OS_PROFILES: list[dict] = [
    {"label": "Auto / use sidecar or crash-dump header", "build_number": None, "os": "Auto", "version": ""},
    {"label": "Windows 10 22H2 — build 19045", "build_number": 19045, "os": "Microsoft Windows 10", "version": "10.0.19045"},
    {"label": "Windows 10 21H2 — build 19044", "build_number": 19044, "os": "Microsoft Windows 10", "version": "10.0.19044"},
    {"label": "Windows 10 2004/20H2/21H1 — build 19041", "build_number": 19041, "os": "Microsoft Windows 10", "version": "10.0.19041"},
    {"label": "Windows 11 21H2 — build 22000", "build_number": 22000, "os": "Microsoft Windows 11", "version": "10.0.22000"},
    {"label": "Windows 11 22H2/23H2 — build 22621/22631", "build_number": 22621, "os": "Microsoft Windows 11", "version": "10.0.22621"},
    {"label": "Windows 11 24H2 — build 26100", "build_number": 26100, "os": "Microsoft Windows 11", "version": "10.0.26100"},
    {"label": "Windows 11 Insider/Canary — build 26200", "build_number": 26200, "os": "Microsoft Windows 11", "version": "10.0.26200"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_str(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _estimate_load_time(size_bytes: int) -> str:
    """Rough estimate: ~100 MB/s parsing speed."""
    secs = size_bytes / (100 * 1024 * 1024)
    if secs < 60:
        return f"~{int(secs)} s"
    return f"~{int(secs / 60)} min"


def _quick_hash(path: str) -> str:
    """SHA-256 of first 4 MB — returns full hex digest or 'error' on failure."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(4 * 1024 * 1024))
    except Exception:
        return "error"
    return h.hexdigest()


def _quick_md5(path: str) -> str:
    """MD5 of first 4 MB — returns full hex digest or 'error' on failure."""
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            h.update(f.read(4 * 1024 * 1024))
    except Exception:
        return "error"
    return h.hexdigest()


def _error_dict(path: str, message: str) -> dict:
    """Uniform error shape returned by validate_file on any failure."""
    return {
        "valid":         False,
        "path":          path,
        "filename":      os.path.basename(path),
        "error":         message,
        "size_bytes":    0,
        "size_str":      "—",
        "format":        "—",
        "architecture":  "—",
        "os_hint":       "—",
        "est_load_time": "—",
        "sha256":        "—",
        "md5":           "—",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Session-folder helpers  (shared by both modes)
# ─────────────────────────────────────────────────────────────────────────────

def _make_session_dir(base_dir: str, stem: str) -> Path:
    """
    Create and return  <base_dir>/<stem>/

    If the folder already exists a numeric suffix (_2, _3 …) is appended
    so we never silently overwrite a previous session.
    """
    base_path = _canonical_dumps_dir(base_dir)
    candidate = base_path / stem
    if not candidate.exists():
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    # Folder name collision — append counter
    idx = 2
    while True:
        candidate = base_path / f"{stem}_{idx}"
        if not candidate.exists():
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        idx += 1


def _find_sidecar(dump_path: Path) -> Optional[Path]:
    """
    Return the first sidecar JSON found next to *dump_path*, or None.
    Checks the same candidate names as analysis_bridge._load_sidecar().
    """
    candidates = [
        dump_path.with_suffix(".json"),
        Path(str(dump_path) + ".json"),
        dump_path.with_suffix(".dmp.metadata.json"),
        Path(str(dump_path) + ".metadata.json"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def _normalise_profile(profile: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return a clean profile dict or None if Auto/unknown was selected."""
    if not profile:
        return None
    build = profile.get("build_number") or profile.get("build")
    if build in (None, "", "auto", "Auto"):
        return None
    try:
        build_int = int(build)
    except (TypeError, ValueError):
        return None
    if not (7600 <= build_int <= 99999):
        return None

    version = str(profile.get("version") or profile.get("os_version") or "")
    if not version:
        version = f"10.0.{build_int}"
    return {
        "build_number": build_int,
        "os": str(profile.get("os") or profile.get("os_name") or "Windows"),
        "version": version,
        "dtb_hex": profile.get("dtb_hex") or profile.get("dtb"),
        "profile_source": str(profile.get("profile_source") or "user_selected"),
    }


def _profile_to_extra(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert a user-selected profile to MetadataManager kernel_info fields."""
    profile = _normalise_profile(profile)
    if not profile:
        return {}
    extra = {
        "build_number": profile["build_number"],
        "os": profile["os"],
        "version": profile["version"],
        "profile_source": profile["profile_source"],
    }
    if profile.get("dtb_hex"):
        extra["dtb_hex"] = profile["dtb_hex"]
    return extra


def _relocate_into(src: Path, dest_dir: Path) -> Path:
    """
    Move *src* into *dest_dir* if it isn't already there.
    Returns the final path of the file inside *dest_dir*.
    """
    dest = dest_dir / src.name
    if src.resolve() != dest.resolve():
        shutil.move(str(src), str(dest))
    return dest


def _generate_sidecar(dump_path: Path, tool: str, selected_profile: Optional[Dict[str, Any]] = None) -> Optional[Path]:
    """
    Call MetadataManager to write a JSON sidecar next to *dump_path*.

    Sidecar writing is intentionally restricted to RAMDetect's managed
    dumps/<session>/ folder. This prevents imports from creating stray JSON
    files beside the user's original dump in Downloads/Desktop.
    """
    if _IMPORT_ERROR:
        return None
    if not _is_inside_managed_session(dump_path):
        print(f"[AcquisitionBridge] Skipping sidecar outside managed dumps folder: {dump_path}")
        return None
    try:
        header = MetadataReader().get_metadata(str(dump_path))
        extra: Dict[str, Any] = {}

        if header.get("is_valid"):
            extra["dtb_hex"] = header.get("dtb_hex")
            extra["build_number"] = header.get("build_number")
            extra["profile_source"] = "crash_dump_header"
        else:
            extra.update(_profile_to_extra(selected_profile))

        mgr = MetadataManager()
        json_path = mgr.create_acquisition_metadata(
            dump_path=dump_path,
            tool=tool,
            duration=0.0,
            extra_data=extra or None,
        )
        return Path(json_path).absolute() if json_path else None
    except Exception as exc:
        print(f"[AcquisitionBridge] sidecar generation failed: {exc}")
        return None


def _update_sidecar_profile(dump_path: Path, selected_profile: Optional[Dict[str, Any]] = None) -> Optional[Path]:
    """
    Edit/create the sidecar JSON for *dump_path* using a manual OS profile.

    This is intentionally separate from _generate_sidecar(): _generate_sidecar
    creates a full metadata file, while this helper only patches kernel/profile
    fields into an existing JSON when the user selects or changes the profile.
    """
    if _IMPORT_ERROR:
        return None
    profile = _normalise_profile(selected_profile)
    if not profile:
        return _find_sidecar(dump_path)
    if not _is_inside_managed_session(dump_path):
        print(f"[AcquisitionBridge] Skipping profile sidecar update outside managed dumps folder: {dump_path}")
        return None
    try:
        mgr = MetadataManager()
        # Newer metadata.py exposes update_kernel_profile(). If the old metadata
        # module is still loaded, fall back to MetadataManager.update().
        if hasattr(mgr, "update_kernel_profile"):
            json_path = mgr.update_kernel_profile(
                dump_path=dump_path,
                build_number=profile.get("build_number"),
                os_name=profile.get("os"),
                version=profile.get("version"),
                dtb_hex=profile.get("dtb_hex"),
                profile_source=profile.get("profile_source", "user_selected"),
            )
            return Path(json_path).absolute()

        kernel_info = {
            "build_number": profile["build_number"],
            "os": profile["os"],
            "version": profile["version"],
            "profile_source": profile.get("profile_source", "user_selected"),
        }
        if profile.get("dtb_hex"):
            kernel_info["dtb_hex"] = profile["dtb_hex"]
        mgr.update(dump_path, {
            "kernel_info": kernel_info,
            "build_number": profile["build_number"],
            "os": profile["os"],
            "version": profile["version"],
        })
        return dump_path.with_suffix(".json").absolute()
    except Exception as exc:
        print(f"[AcquisitionBridge] sidecar profile update failed: {exc}")
        return _find_sidecar(dump_path)



def _parse_vol_windows_info_output(output: str) -> Dict[str, Any]:
    """Parse `vol -f <dump> windows.info.Info` text output into kernel metadata."""
    rows: Dict[str, str] = {}
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Volatility ") or line.startswith("Progress:"):
            continue
        if line.lower().startswith("variable"):
            continue
        # Volatility table output is usually separated by 2+ spaces or tabs.
        parts = re.split(r"\t+|\s{2,}", line, maxsplit=1)
        if len(parts) == 2:
            rows[parts[0].strip()] = parts[1].strip()

    def _int_auto(v: Any) -> Optional[int]:
        if v in (None, "", "-"):
            return None
        try:
            s = str(v).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except Exception:
            return None

    dtb_hex = rows.get("DTB") or rows.get("CR3")
    kernel_base_hex = rows.get("Kernel Base")
    is64 = str(rows.get("Is64Bit", "")).lower() in {"true", "1", "yes"}
    build = None

    # Common modern and XP output examples:
    # NTBuildLab      2600.xpsp.080413-2111
    # Major/Minor     15.2600
    ntbuild = rows.get("NTBuildLab") or ""
    m = re.search(r"(\d{4,5})", ntbuild)
    if m:
        build = int(m.group(1))
    if build is None:
        mm = rows.get("Major/Minor") or ""
        nums = re.findall(r"\d+", mm)
        if nums:
            # Usually the last number is the Windows build.
            try:
                build = int(nums[-1])
            except Exception:
                pass
    if build is None:
        build = _int_auto(rows.get("NtBuildNumber") or rows.get("Build"))

    nt_major = _int_auto(rows.get("NtMajorVersion"))
    nt_minor = _int_auto(rows.get("NtMinorVersion"))

    os_name = "Windows"
    version = ""
    if nt_major is not None and nt_minor is not None and build is not None:
        version = f"{nt_major}.{nt_minor}.{build}"
        if nt_major == 5 and nt_minor == 1:
            os_name = "Microsoft Windows XP"
        elif nt_major == 6 and nt_minor == 1:
            os_name = "Microsoft Windows 7"
        elif nt_major == 10:
            os_name = "Microsoft Windows 10/11"

    return {
        "success": bool(dtb_hex and build),
        "dtb_hex": dtb_hex,
        "cr3_hex": dtb_hex,
        "dtb": _int_auto(dtb_hex),
        "cr3": _int_auto(dtb_hex),
        "build_number": build,
        "kernel_base_hex": kernel_base_hex,
        "is_64bit": is64,
        "architecture": "x64" if is64 else "x86",
        "memory_layer": rows.get("memory_layer"),
        "layer_name": rows.get("layer_name"),
        "symbols": rows.get("Symbols"),
        "nt_build_lab": rows.get("NTBuildLab"),
        "csd_version": rows.get("CSDVersion"),
        "major_minor": rows.get("Major/Minor"),
        "machine_type": rows.get("MachineType"),
        "os": os_name,
        "version": version,
        "raw_rows": rows,
    }


def _run_vol_windows_info(dump_path: Path, timeout: int = 900) -> Dict[str, Any]:
    """Run Volatility only for kernel metadata: OS build/profile and DTB/CR3."""
    cmd = ["vol", "-f", str(dump_path), "windows.info.Info"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
                        **_hidden_subprocess_kwargs(),
            )
    except FileNotFoundError as exc:
        return {"success": False, "error": "vol command not found in PATH", "exception": str(exc)}
    except Exception as exc:
        return {"success": False, "error": f"vol execution failed: {type(exc).__name__}: {exc}"}

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    parsed = _parse_vol_windows_info_output(combined)
    parsed["returncode"] = proc.returncode
    parsed["command"] = " ".join(cmd)
    if not parsed.get("success"):
        parsed["error"] = parsed.get("error") or "windows.info output did not contain both DTB and build"
        parsed["output_tail"] = "\n".join(combined.splitlines()[-30:])
    return parsed


def _write_kernel_metadata_sidecar(dump_path: Path, meta: Dict[str, Any]) -> Optional[Path]:
    """Create/update sidecar JSON with resolver-scoped kernel metadata only."""
    if not _is_inside_managed_session(dump_path):
        print(f"[AcquisitionBridge] Skipping kernel sidecar outside managed dumps folder: {dump_path}")
        return None
    sidecar = _find_sidecar(dump_path) or dump_path.with_suffix(".json")
    blob: Dict[str, Any] = {}
    if sidecar.exists():
        try:
            blob = json.loads(sidecar.read_text(encoding="utf-8"))
        except Exception:
            blob = {}

    kernel = blob.get("kernel_info") if isinstance(blob.get("kernel_info"), dict) else {}
    build = meta.get("build_number")
    dtb_hex = meta.get("dtb_hex") or meta.get("cr3_hex")

    kernel.update({
        "os": meta.get("os") or kernel.get("os") or "Windows",
        "architecture": meta.get("architecture") or kernel.get("architecture"),
        "is_64bit": bool(meta.get("is_64bit")),
        "build_number": int(build) if build is not None else kernel.get("build_number"),
        "version": meta.get("version") or kernel.get("version"),
        "dtb": dtb_hex,
        "cr3": dtb_hex,
        "dtb_hex": dtb_hex,
        "cr3_hex": dtb_hex,
        "kernel_base_hex": meta.get("kernel_base_hex") or kernel.get("kernel_base_hex"),
        "memory_layer": meta.get("memory_layer") or kernel.get("memory_layer"),
        "layer_name": meta.get("layer_name") or kernel.get("layer_name"),
        "symbols": meta.get("symbols") or kernel.get("symbols"),
        "nt_build_lab": meta.get("nt_build_lab") or kernel.get("nt_build_lab"),
        "csd_version": meta.get("csd_version") or kernel.get("csd_version"),
        "machine_type": meta.get("machine_type") or kernel.get("machine_type"),
        "dtb_source": "volatility_windows_info",
        "profile_source": "volatility_windows_info",
        "dtb_confidence": 100,
    })

    blob["kernel_info"] = kernel
    if build is not None:
        blob["build_number"] = int(build)
    if dtb_hex:
        blob["dtb_hex"] = dtb_hex
        blob["cr3_hex"] = dtb_hex
    blob["metadata_source"] = "kernel_metadata_resolver"
    blob["resolver"] = "volatility3_windows_info"
    blob["resolver_scope"] = "os_profile_and_kernel_dtb_only"
    blob["ramdetect_policy"] = {
        "volatility_used_for_artifact_extraction": False,
        "volatility_used_for_ml_features": False,
        "volatility_used_for_verdict": False,
        "allowed_usage": [
            "OS build detection",
            "kernel DTB/CR3 discovery",
            "architecture/profile metadata",
        ],
    }

    sidecar.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    return sidecar.absolute()



# ─────────────────────────────────────────────────────────────────────────────
# Legacy DTB/CR3 scanner for raw-style dumps
# ─────────────────────────────────────────────────────────────────────────────
# DEPRECATED: kept only for backward compatibility with older local branches.
# The active scanner is ramdetect.utils.find_dtb.find_dtb(), called by
# AcquisitionBridge.detect_dtb() and AnalysisWorker before deep parsing.
# Do not add new DTB logic here.

_DTB_SCAN_CHUNK_SIZE = 16 * 1024 * 1024
_DTB_SCAN_OVERLAP    = 0x2000
_DTB_OFFSET          = 0x28  # _KPROCESS.DirectoryTableBase on Windows x64

_DTB_PROFILES = [
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


_DTB_KNOWN_PROCESS_NAMES = [
    b"System", b"Registry", b"smss.exe", b"csrss.exe", b"wininit.exe",
    b"services.exe", b"lsass.exe", b"svchost.exe", b"explorer.exe",
    b"winlogon.exe", b"dwm.exe", b"fontdrvhost.exe", b"conhost.exe",
    b"dllhost.exe", b"RuntimeBroker", b"SearchIndexer.", b"taskhostw.exe",
]

_DTB_EARLY_PROCESS_SCORE = {
    "system": 25,
    "registry": 16,
    "smss.exe": 18,
    "csrss.exe": 18,
    "wininit.exe": 18,
    "services.exe": 18,
    "lsass.exe": 18,
    "winlogon.exe": 14,
    "svchost.exe": 12,
    "explorer.exe": 10,
}


@dataclass
class _DtbCandidate:
    dtb: int
    profile: str
    eprocess_base: int
    system_name_addr: int
    process_name: str
    pid: int
    method: str
    hits: int = 1
    score: int = 0

    @property
    def dtb_hex(self) -> str:
        return hex(self.dtb)


def _dtb_profiles_for_build(build: Optional[int]) -> list[dict]:
    if not build:
        return _DTB_PROFILES
    exact = [p for p in _DTB_PROFILES if p["build_min"] <= build <= p["build_max"]]
    return exact or _DTB_PROFILES


def _is_plausible_dtb(dtb: int, file_size: int) -> bool:
    if not dtb:
        return False
    if dtb & 0xFFF:
        return False
    if dtb < 0x1000:
        return False
    # For flat raw/VMEM dumps, the DTB normally points inside the physical file.
    if dtb >= file_size:
        return False
    return True


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
    if pid % 4 != 0:
        return False
    return True


def _read_image_name_at(f, base: int, name_off: int, file_size: int) -> str:
    if base < 0 or base + name_off + 15 > file_size:
        return ""
    f.seek(base + name_off)
    raw = f.read(15)
    raw = raw.split(b"\x00", 1)[0]
    try:
        name = raw.decode("ascii", errors="ignore")
    except Exception:
        return ""
    if not name:
        return ""
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in name):
        return ""
    return name


_DTB_MIN_ACCEPT_SCORE = 75
_DTB_EXACT_IMAGE_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
    "dllhost.exe", "runtimebroker", "searchindexer.", "taskhostw.exe",
}


def _name_matches_dtb_hit(field_name: str, needle: bytes) -> bool:
    """Strict EPROCESS.ImageFileName match to avoid SystemTime/SystemUpdateCom FPs."""
    if not field_name:
        return False
    got = field_name.lower()
    wanted = needle.decode("ascii", "ignore").lower()
    if wanted.endswith("."):
        return got.startswith(wanted)
    return got == wanted and got in _DTB_EXACT_IMAGE_NAMES


def _pml4_sanity_at(f, dtb: int, file_size: int) -> tuple[bool, int]:
    if dtb < 0 or dtb + 4096 > file_size:
        return False, 0
    f.seek(dtb)
    page = f.read(4096)
    if len(page) != 4096:
        return False, 0
    present = 0
    nonzero = 0
    for i in range(0, 4096, 8):
        entry = struct.unpack_from("<Q", page, i)[0]
        if entry:
            nonzero += 1
        if entry & 1:
            present += 1
    if present < 1 or nonzero < 1:
        return False, present
    if present > 256:
        return False, present
    return True, present


def _score_dtb_candidate(candidate: _DtbCandidate,
                         file_size: int,
                         selected_build: Optional[int],
                         links_ok: bool = False,
                         pml4_ok: bool = False) -> int:
    lname = candidate.process_name.lower()
    score = 0
    if lname == "system" and candidate.pid == 4:
        score += 45
    else:
        score += _DTB_EARLY_PROCESS_SCORE.get(lname, 8)
        score += 15
    score += 15  # DTB is aligned, non-zero, and inside dump
    if links_ok:
        score += 15
    if pml4_ok:
        score += 15
    if selected_build:
        score += 5
    if candidate.hits > 1:
        score += min(10, candidate.hits * 2)
    return min(score, 100)


def _read_u64_at(f, offset: int, file_size: int) -> Optional[int]:
    if offset < 0 or offset + 8 > file_size:
        return None
    f.seek(offset)
    data = f.read(8)
    if len(data) != 8:
        return None
    return struct.unpack("<Q", data)[0]


def _scan_system_dtb(dump_path: Path, build_number: Optional[int] = None, scan_mb: int = 4096) -> Optional[_DtbCandidate]:
    """
    Scan flat raw/VMEM-style physical memory for DTB/CR3 candidates.

    v2 scanner: first-class System/PID4 hits are still preferred, but if the
    System EPROCESS is not discoverable, the scanner can fall back to other
    known Windows EPROCESS names such as smss.exe, csrss.exe, services.exe,
    and lsass.exe. This is useful for malware/snapshot dumps where the old
    System-only string search fails.
    """
    file_size = dump_path.stat().st_size
    scan_mb_int = int(scan_mb) if scan_mb is not None else 4096
    scan_limit = file_size if scan_mb_int <= 0 else min(max(1, scan_mb_int) * 1024 * 1024, file_size)
    profiles = _dtb_profiles_for_build(build_number)
    candidates_by_key: dict[tuple[int, str], _DtbCandidate] = {}

    with dump_path.open("rb") as f:
        offset = 0
        carry = b""
        while offset < scan_limit:
            to_read = min(_DTB_SCAN_CHUNK_SIZE, scan_limit - offset)
            f.seek(offset)
            chunk = f.read(to_read)
            if not chunk:
                break

            search_buf = carry + chunk
            carry_base = offset - len(carry)

            for needle in _DTB_KNOWN_PROCESS_NAMES:
                search_idx = 0
                while True:
                    idx = search_buf.find(needle, search_idx)
                    if idx == -1:
                        break
                    phys_name = carry_base + idx

                    for prof in profiles:
                        base_addr = phys_name - prof["name_off"]
                        if base_addr <= 0:
                            continue

                        field_name = _read_image_name_at(f, base_addr, prof["name_off"], file_size)
                        if not _name_matches_dtb_hit(field_name, needle):
                            continue

                        pid_val = _read_u64_at(f, base_addr + prof["pid_off"], file_size)
                        if not _is_plausible_pid(pid_val, field_name):
                            continue

                        dtb_val = _read_u64_at(f, base_addr + _DTB_OFFSET, file_size)
                        if dtb_val is None or not _is_plausible_dtb(dtb_val, file_size):
                            continue

                        flink = _read_u64_at(f, base_addr + prof.get("links_off", prof["pid_off"] + 8), file_size)
                        blink = _read_u64_at(f, base_addr + prof.get("links_off", prof["pid_off"] + 8) + 8, file_size)
                        links_ok = _is_kernel_ptr(flink) and _is_kernel_ptr(blink)

                        pml4_ok, _present_count = _pml4_sanity_at(f, dtb_val, file_size)
                        # Non-System fallback must pass PML4 sanity, otherwise a random
                        # embedded process-name string may be misread as EPROCESS.
                        if not pml4_ok and field_name.lower() != "system":
                            continue

                        key = (dtb_val, prof["name"])
                        if key in candidates_by_key:
                            candidates_by_key[key].hits += 1
                        else:
                            method = "system_pid4" if field_name.lower() == "system" and pid_val == 4 else "multiprocess_eprocess"
                            cand = _DtbCandidate(
                                dtb=dtb_val,
                                profile=prof["name"],
                                eprocess_base=base_addr,
                                system_name_addr=phys_name,
                                process_name=field_name,
                                pid=int(pid_val),
                                method=method,
                            )
                            cand.score = _score_dtb_candidate(cand, file_size, build_number, links_ok, pml4_ok)
                            candidates_by_key[key] = cand

                    search_idx = idx + 1

            offset += _DTB_SCAN_CHUNK_SIZE
            carry = search_buf[-_DTB_SCAN_OVERLAP:]

    if not candidates_by_key:
        return None

    candidates = list(candidates_by_key.values())
    with dump_path.open("rb") as f:
        for cand in candidates:
            prof = next((p for p in _DTB_PROFILES if p["name"] == cand.profile), None)
            links_ok = False
            pml4_ok = False
            if prof:
                links_off = prof.get("links_off", prof["pid_off"] + 8)
                flink = _read_u64_at(f, cand.eprocess_base + links_off, file_size)
                blink = _read_u64_at(f, cand.eprocess_base + links_off + 8, file_size)
                links_ok = _is_kernel_ptr(flink) and _is_kernel_ptr(blink)
                pml4_ok, _ = _pml4_sanity_at(f, cand.dtb, file_size)
            cand.score = _score_dtb_candidate(cand, file_size, build_number, links_ok, pml4_ok)

    candidates.sort(key=lambda c: (c.score, c.hits, 1 if c.process_name.lower() == "system" else 0), reverse=True)
    return candidates[0]


def _load_build_from_sidecar(dump_path: Path) -> Optional[int]:
    sidecar = _find_sidecar(dump_path)
    if not sidecar:
        return None
    try:
        with open(sidecar, "r", encoding="utf-8") as f:
            meta = json.load(f)
        kernel = meta.get("kernel_info", {}) if isinstance(meta, dict) else {}
        build = kernel.get("build_number") or meta.get("build_number")
        if not build:
            return None
        build = int(build)
        return build if 7600 <= build <= 30000 else None
    except Exception:
        return None


def _write_dtb_to_sidecar(dump_path: Path, candidate: _DtbCandidate, build_number: Optional[int] = None) -> Path:
    sidecar_path = _find_sidecar(dump_path) or dump_path.with_suffix(".json")
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
        "dtb_eprocess_base": hex(candidate.eprocess_base),
        "dtb_process_name": candidate.process_name,
        "dtb_process_pid": candidate.pid,
        "dtb_profile_match": candidate.profile,
    })
    if build_number:
        kernel.setdefault("build_number", int(build_number))
        metadata.setdefault("build_number", int(build_number))

    metadata["kernel_info"] = kernel
    metadata["dtb"] = candidate.dtb
    metadata["cr3"] = candidate.dtb
    metadata["dtb_hex"] = candidate.dtb_hex
    metadata["cr3_hex"] = candidate.dtb_hex
    sidecar_path.write_text(json.dumps(metadata, indent=4), encoding="utf-8")
    return sidecar_path

# ─────────────────────────────────────────────────────────────────────────────
# AcquisitionBridge
# ─────────────────────────────────────────────────────────────────────────────

class AcquisitionBridge:
    """Static helper — no instance needed."""

    @staticmethod
    def get_os_profiles() -> list[dict]:
        """Return supported manual OS profile choices for the acquisition UI."""
        return OS_PROFILES.copy()

    @staticmethod
    def validate_file(path: str) -> dict:
        """
        Validate an existing memory dump file.
        Returns a normalised dict — always safe to read, never raises.
        """
        if _IMPORT_ERROR:
            return _error_dict(path, _IMPORT_ERROR)

        try:
            converter = RawDumpConverter()
            info      = converter.get_dump_info(Path(path))

            if not info.get("exists", False):
                return _error_dict(path, "File not found.")

            ext = info.get("extension", "").lower()
            if ext not in SUPPORTED_EXTENSIONS:
                return _error_dict(
                    path,
                    f"Unsupported format '{ext}'. "
                    f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
                )

            # Enrich with crash-dump header (DTB, build number).
            header_meta = MetadataReader().get_metadata(path)
            header_valid = header_meta.get("is_valid") and header_meta.get("type") == "Crash Dump"
            build_number = header_meta.get("build_number") if header_valid else None
            dtb_hex = header_meta.get("dtb_hex") if header_valid else None
            profile_source = "crash_dump_header" if build_number else None

            # If no crash header exists, check a sidecar JSON that may have
            # been generated by the manual OS profile selector.
            if not build_number:
                sidecar = _find_sidecar(Path(path))
                if sidecar:
                    try:
                        with open(sidecar, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        kernel = meta.get("kernel_info", {}) if isinstance(meta, dict) else {}
                        build_number = kernel.get("build_number") or meta.get("build_number")
                        dtb_hex = kernel.get("dtb_hex") or meta.get("dtb_hex")
                        if build_number:
                            build_number = int(build_number)
                            profile_source = kernel.get("profile_source") or "sidecar_json"
                    except Exception:
                        build_number = None

            profile_required = not bool(build_number)

            if build_number:
                arch = f"x64 Windows (build {build_number})"
            else:
                arch = f"{info.get('format', 'Raw Memory')} — OS profile required"

            size = info["size_bytes"]

            return {
                "valid":         True,
                "path":          path,
                "filename":      info["name"],
                "size_bytes":    size,
                "size_str":      _bytes_to_str(size),
                "format":        info.get("format", ext.upper().lstrip(".")),
                "architecture":  arch,
                "os_hint":       "Windows" if ext in (".dmp", ".raw") else "Unknown",
                "est_load_time": _estimate_load_time(size),
                "sha256":        _quick_hash(path),
                "md5":           _quick_md5(path),
                "build_number":  build_number,
                "dtb_hex":       dtb_hex,
                "profile_required": profile_required,
                "profile_source": profile_source,
                "available_profiles": OS_PROFILES,
                "error":         "",
            }

        except Exception as e:
            return _error_dict(path, f"Validation error: {e}")

    # ── Load-file: organise into a session folder ─────────────────────────────

    @staticmethod
    def organize_loaded_file(src_path: str, output_base_dir: str, selected_profile: Optional[Dict[str, Any]] = None) -> dict:
        """
        Organise any loaded dump into the RAMDetect dumps/<session>/ layout.

        Phase 6A-safe rules:
          1. .dmp already in dumps/<session>/      -> keep in place, ensure sidecar
          2. non-.dmp already in dumps/<session>/  -> convert to .dmp in same folder
          3. non-.dmp outside dumps/<session>/     -> create session folder, copy+convert there
          4. .dmp outside dumps/<session>/         -> create session folder, move/copy there

        A file in the top-level dumps/ directory, e.g. dumps/mem.dmp, is NOT
        considered organised. It must still be moved into dumps/<session>/.

        Returns the final .dmp path whenever conversion succeeds.
        """
        _FAIL = lambda msg: {          # noqa: E731
            "success":     False,
            "session_dir": "",
            "dump_path":   src_path,
            "json_path":   None,
            "message":     msg,
        }

        def _is_inside_session_folder(path_obj: Path, base_obj: Path) -> bool:
            """True only for dumps/<session>/<file>, not dumps/<file>."""
            try:
                rel = path_obj.resolve().relative_to(base_obj.resolve())
            except ValueError:
                return False
            return len(rel.parts) >= 2 and path_obj.parent.resolve() != base_obj.resolve()

        def _copy_sidecar_for(source_dump: Path, dest_dump: Path, session_dir: Path) -> Optional[Path]:
            """Copy source sidecar to destination sidecar location if available."""
            source_sidecar = _find_sidecar(source_dump)
            if not source_sidecar or not source_sidecar.is_file():
                return None
            dest_sidecar = session_dir / f"{dest_dump.stem}.json"
            try:
                shutil.copy2(str(source_sidecar), str(dest_sidecar))
                return dest_sidecar
            except Exception as exc:
                print(f"[AcquisitionBridge] Could not copy existing sidecar: {exc}")
                return None

        def _ensure_sidecar(final_dump: Path, copied_json: Optional[Path] = None) -> Optional[Path]:
            """Ensure a JSON sidecar exists beside final_dump."""
            sidecar = copied_json or _find_sidecar(final_dump)
            if sidecar is None:
                sidecar = _generate_sidecar(final_dump, tool="Imported/External", selected_profile=selected_profile)
            patched = _update_sidecar_profile(final_dump, selected_profile)
            return patched or sidecar

        def _convert_in_place(input_path: Path) -> tuple[bool, str, Optional[Path]]:
            """Convert a non-DMP file to DMP beside itself."""
            try:
                result = AcquisitionBridge.convert_to_dmp(str(input_path), copy=True)
                if not result.get("success") or not result.get("output_path"):
                    return False, result.get("message", "Conversion failed."), None
                out = Path(result["output_path"])
                if not out.is_file():
                    return False, f"Converter returned missing output: {out}", None
                return True, result.get("message", "Converted."), out
            except Exception as exc:
                return False, f"Conversion error: {type(exc).__name__}: {exc}", None

        src = Path(src_path)
        if not src.is_file():
            return _FAIL(f"Source file not found: {src_path}")

        ext = src.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return _FAIL(
                f"Unsupported format '{ext}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
            )

        try:
            base_dir = _canonical_dumps_dir(output_base_dir)
        except Exception as exc:
            return _FAIL(f"Could not create RAMDetect dumps directory: {exc}")

        already_in_session = _is_inside_session_folder(src, base_dir)

        # ── Case 1: .dmp already correctly organised ────────────────────────
        if already_in_session and ext == ".dmp":
            sidecar = _ensure_sidecar(src)
            return {
                "success":     True,
                "session_dir": str(src.parent),
                "dump_path":   str(src),
                "json_path":   str(sidecar) if sidecar else None,
                "message":     "File already organised in dumps/<session>/.",
            }

        # ── Case 2: non-.dmp already in a session folder: convert there ─────
        if already_in_session and ext != ".dmp":
            ok, msg, converted = _convert_in_place(src)
            if not ok or not converted:
                return _FAIL(msg)
            sidecar = _ensure_sidecar(converted)
            return {
                "success":     True,
                "session_dir": str(converted.parent),
                "dump_path":   str(converted),
                "json_path":   str(sidecar) if sidecar else None,
                "message":     f"File converted to .dmp inside existing session folder.\n{msg}",
            }

        # ── Cases 3/4: source is outside dumps/<session>/ or only in dumps/ root ──
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_stem = f"{src.stem}_{ts}"
        try:
            session_dir = _make_session_dir(str(base_dir), folder_stem)
        except Exception as exc:
            return _FAIL(f"Could not create session folder: {exc}")

        delete_errors: list[str] = []

        # Preserve any sidecar before source deletion.
        copied_json: Optional[Path] = None

        if ext == ".dmp":
            # Case 4: copy .dmp into new session folder, verify, then remove original.
            dest_dump = session_dir / src.name
            src_size = src.stat().st_size
            copied_json = _copy_sidecar_for(src, dest_dump, session_dir)
            try:
                shutil.copy2(str(src), str(dest_dump))
                if dest_dump.stat().st_size != src_size:
                    try:
                        dest_dump.unlink()
                    except OSError:
                        pass
                    return _FAIL("Copy size mismatch. Original file kept; please retry.")
                try:
                    src.unlink()
                except OSError as exc:
                    delete_errors.append(f"Could not delete original dump: {exc}")
            except Exception as exc:
                return _FAIL(f"Failed to copy dump into session folder: {exc}")

            sidecar = _ensure_sidecar(dest_dump, copied_json)
            # Remove stale JSON beside the original imported dump after the
            # managed session copy has its own sidecar.
            original_sidecar = _find_sidecar(src)
            if original_sidecar and original_sidecar.resolve() != (sidecar.resolve() if sidecar else original_sidecar.resolve()):
                _safe_unlink_sidecar(original_sidecar, session_dir)
            msg_parts = [f"Moved into: {session_dir.name}"]
            msg_parts.append("JSON sidecar included." if sidecar else "No sidecar JSON generated.")
            if delete_errors:
                msg_parts.append("⚠ " + "  ".join(delete_errors))
            return {
                "success":     True,
                "session_dir": str(session_dir),
                "dump_path":   str(dest_dump),
                "json_path":   str(sidecar) if sidecar else None,
                "message":     "\n".join(msg_parts),
            }

        # Case 3: non-.dmp outside session folder. Copy raw into session folder,
        # convert the copy there, then remove raw copy and original if safe.
        dest_raw = session_dir / src.name
        src_size = src.stat().st_size
        copied_json = _copy_sidecar_for(src, dest_raw, session_dir)
        try:
            shutil.copy2(str(src), str(dest_raw))
            if dest_raw.stat().st_size != src_size:
                try:
                    dest_raw.unlink()
                except OSError:
                    pass
                return _FAIL("Copy size mismatch. Original file kept; please retry.")
        except Exception as exc:
            return _FAIL(f"Failed to copy dump into session folder: {exc}")

        ok, msg, converted = _convert_in_place(dest_raw)
        if not ok or not converted:
            return _FAIL(msg)

        # Remove the copied raw file after successful conversion. Keep the final .dmp.
        try:
            if dest_raw.exists() and dest_raw.resolve() != converted.resolve():
                dest_raw.unlink()
        except OSError as exc:
            delete_errors.append(f"Could not delete copied raw file: {exc}")

        # Keep the original raw/mem/vmem file untouched. However, if a previous
        # converter run created a sibling .dmp/.json beside the original input,
        # remove that duplicate so the converted dump only lives in dumps/<session>/.
        sibling_dmp = src.with_suffix(".dmp")
        sibling_json = src.with_suffix(".json")
        for duplicate in (sibling_dmp, sibling_json):
            try:
                if duplicate.exists() and duplicate.resolve() not in {converted.resolve(), (copied_json.resolve() if copied_json else converted.resolve())}:
                    duplicate.unlink()
            except OSError as exc:
                delete_errors.append(f"Could not delete duplicate {duplicate.name}: {exc}")

        sidecar = _ensure_sidecar(converted, copied_json)
        original_sidecar = _find_sidecar(src)
        if original_sidecar and original_sidecar.resolve() != (sidecar.resolve() if sidecar else original_sidecar.resolve()):
            _safe_unlink_sidecar(original_sidecar, session_dir)
        msg_parts = [f"Converted and moved into: {session_dir.name}", msg]
        msg_parts.append("JSON sidecar included." if sidecar else "No sidecar JSON generated.")
        if delete_errors:
            msg_parts.append("⚠ " + "  ".join(delete_errors))

        return {
            "success":     True,
            "session_dir": str(session_dir),
            "dump_path":   str(converted),
            "json_path":   str(sidecar) if sidecar else None,
            "message":     "\n".join(msg_parts),
        }

    # ── Existing helpers (unchanged public API) ───────────────────────────────

    @staticmethod
    def convert_to_dmp(path: str, copy: bool = True) -> dict:
        """
        Convert a .raw / .mem / .vmem / .bin dump to .dmp format.

        Returns:
        {
          'success':     bool,
          'message':     str,
          'output_path': str | None
        }
        """
        if _IMPORT_ERROR:
            return {"success": False, "message": _IMPORT_ERROR, "output_path": None}

        ext = Path(path).suffix.lower()
        if ext == ".dmp":
            return {
                "success":     False,
                "message":     "File is already in .dmp format — no conversion needed.",
                "output_path": None,
            }

        try:
            converter = RawDumpConverter()
            success, msg, output = converter.convert_raw_to_dmp(path, copy=copy)
            return {
                "success":     success,
                "message":     msg,
                "output_path": str(output) if output else None,
            }
        except Exception as e:
            return {
                "success":     False,
                "message":     f"Conversion error: {type(e).__name__}: {e}",
                "output_path": None,
            }


    @staticmethod
    def update_json_profile(path: str,
                            selected_profile: Optional[Dict[str, Any]] = None,
                            build_number: Optional[int] = None,
                            os_name: str = "Windows",
                            version: Optional[str] = None,
                            dtb_hex: Optional[str] = None) -> dict:
        """
        Edit/create the sidecar JSON for a dump and write the selected Windows
        build/profile into kernel_info.

        This is the quick manual fix for raw-style dumps where RAMDetect cannot
        infer the build from the file header.
        """
        if _IMPORT_ERROR:
            return {"success": False, "json_path": None, "message": _IMPORT_ERROR, "build": None}

        try:
            dump_path = Path(path)
            if not dump_path.is_file():
                raise FileNotFoundError(f"File not found: {path}")

            profile = _normalise_profile(selected_profile)
            if profile is None and build_number:
                build_int = int(build_number)
                profile = {
                    "build_number": build_int,
                    "os": os_name or "Windows",
                    "version": version or f"10.0.{build_int}",
                    "dtb_hex": dtb_hex,
                    "profile_source": "manual_user_selected",
                }
            if profile is None:
                return {
                    "success": False,
                    "json_path": None,
                    "message": "No valid build/profile supplied.",
                    "build": None,
                }

            json_path = _update_sidecar_profile(dump_path, profile)
            if not json_path:
                raise RuntimeError("Sidecar update failed")

            return {
                "success": True,
                "json_path": str(Path(json_path).absolute()),
                "message": "JSON sidecar profile updated.",
                "build": profile.get("build_number"),
                "dtb_hex": profile.get("dtb_hex"),
            }
        except Exception as e:
            return {
                "success": False,
                "json_path": None,
                "message": f"Profile update error: {type(e).__name__}: {e}",
                "build": None,
            }


    @staticmethod
    def detect_dtb(path: str,
                   build_number: Optional[int] = None,
                   scan_mb: int = 4096,
                   write_json: bool = True) -> dict:
        """
        Resolve kernel metadata for a dump and write/update the sidecar JSON.

        Phase 6A scope:
          1. Reuse verified sidecar metadata when available.
          2. Parse crash-dump header when available.
          3. Use `vol -f <dump> windows.info.Info` only for OS profile and
             kernel DTB/CR3 metadata.
          4. Fall back to RAMDetect's native DTB scanner when metadata
             resolution fails.

        This method does not use Volatility for processes, DLLs, handles, VADs,
        malfind, features, or verdicts.
        """
        if _IMPORT_ERROR:
            return {
                "success": False,
                "message": _IMPORT_ERROR,
                "dtb_hex": None,
                "confidence": 0,
                "json_path": None,
            }

        try:
            dump_path = Path(path)
            if not dump_path.is_file():
                raise FileNotFoundError(f"File not found: {path}")

            effective_write_json = bool(write_json and _is_inside_managed_session(dump_path))
            if write_json and not effective_write_json:
                print(f"[AcquisitionBridge] Metadata write disabled for external dump path: {dump_path}")

            # Optional manual build hint. This is only a hint for profile/offset
            # selection and for native fallback; external windows.info may
            # overwrite it with a verified build.
            if build_number:
                try:
                    _update_sidecar_profile(
                        dump_path,
                        {
                            "build_number": int(build_number),
                            "os": "Windows",
                            "version": f"10.0.{int(build_number)}",
                            "profile_source": "manual_user_selected_before_metadata_resolution",
                        },
                    )
                except Exception:
                    pass

            # Phase 6B: Prefer Volatility windows.info FIRST for kernel metadata only.
            # This fixes raw/converted dumps where RAMDetect's native DTB scanner
            # does not reliably find OS profile + kernel DTB. No artifact output
            # from Volatility is used for processes/DLLs/handles/VADs/features.
            vol_meta = _run_vol_windows_info(dump_path, timeout=900)
            if vol_meta.get("success"):
                json_path = _write_kernel_metadata_sidecar(dump_path, vol_meta) if effective_write_json else (_find_sidecar(dump_path) or dump_path.with_suffix(".json"))
                return {
                    "success": True,
                    "message": "Kernel metadata resolved and sidecar updated." if effective_write_json else "Kernel metadata resolved.",
                    "dtb": vol_meta.get("dtb"),
                    "dtb_hex": str(vol_meta.get("dtb_hex")),
                    "confidence": 100,
                    "json_path": str(json_path) if json_path else None,
                    "build": int(vol_meta.get("build_number")) if vol_meta.get("build_number") else None,
                    "metadata_source": "kernel_metadata_resolver",
                    "source": "volatility_windows_info",
                    "dtb_source": "volatility_windows_info",
                    "method": "volatility_windows_info",
                    "profile_match": "volatility_windows_info",
                    "kernel_base_hex": vol_meta.get("kernel_base_hex"),
                    "memory_layer": vol_meta.get("memory_layer"),
                    "volatility_used_for_artifacts": False,
                    "scan_mb": scan_mb,
                }
            else:
                print(f"[AcquisitionBridge] windows.info metadata resolver failed: {vol_meta.get('error')}")

            # Fallback: Prefer the new Phase 6A resolver. In older checkouts the
            # resolver may live under ramdetect.acquisition; in the patched
            # checkout it may live under ramdetect.utils.
            try:
                from ramdetect.utils.metadata_reader import MetadataReader as KernelMetadataReader
            except Exception:
                from ramdetect.acquisition.metadata_reader import MetadataReader as KernelMetadataReader

            reader = KernelMetadataReader()

            try:
                meta = reader.get_metadata(
                    dump_path,
                    allow_external=True,
                    allow_native_fallback=True,
                    write_sidecar=bool(effective_write_json),
                    timeout=900,
                )
            except TypeError:
                # Backward compatibility for older MetadataReader signatures.
                meta = reader.get_metadata(str(dump_path)) or {}

            dtb = meta.get("dtb") or meta.get("cr3")
            dtb_hex = meta.get("dtb_hex") or meta.get("cr3_hex")
            build = meta.get("build_number") or build_number
            confidence = meta.get("dtb_confidence") or meta.get("confidence") or 0
            source = meta.get("resolver_stage") or meta.get("profile_source") or meta.get("dtb_source") or "kernel_metadata_resolver"
            dtb_source = meta.get("dtb_source") or source
            kernel_info = meta.get("kernel_info") if isinstance(meta.get("kernel_info"), dict) else {}

            # Sidecar path may be embedded in metadata, or we can rediscover it.
            json_path = None
            metadata_blob = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
            nested_metadata = metadata_blob.get("metadata") if isinstance(metadata_blob.get("metadata"), dict) else {}
            json_path = nested_metadata.get("sidecar_path") or metadata_blob.get("sidecar_path")
            if not json_path:
                sidecar = _find_sidecar(dump_path)
                json_path = str(sidecar) if sidecar else None

            if dtb_hex and str(dtb_hex) != "0x0" and build:
                return {
                    "success": True,
                    "message": "Kernel metadata resolved and sidecar updated." if effective_write_json else "Kernel metadata resolved.",
                    "dtb": dtb,
                    "dtb_hex": str(dtb_hex),
                    "confidence": int(confidence or 0),
                    "json_path": json_path,
                    "build": int(build) if build else None,
                    "metadata_source": source,
                    "source": source,
                    "dtb_source": dtb_source,
                    "method": source,
                    "profile_match": meta.get("profile_source") or source,
                    "kernel_base_hex": kernel_info.get("kernel_base_hex") or meta.get("kernel_base_hex"),
                    "memory_layer": kernel_info.get("memory_layer") or meta.get("memory_layer"),
                    "volatility_used_for_artifacts": False,
                    "scan_mb": scan_mb,
                }

            # Last-resort compatibility fallback to the legacy native scanner if
            # the resolver in this checkout cannot produce valid metadata.
            from ramdetect.utils.find_dtb import find_dtb, write_dtb_to_sidecar, MIN_ACCEPT_SCORE

            build = build or _load_build_from_sidecar(dump_path)
            if build:
                build = int(build)

            file_mb = max(1, int(dump_path.stat().st_size / (1024 * 1024)))
            requested = int(scan_mb) if scan_mb is not None else 4096
            if requested <= 0:
                scan_plan = [0]
            else:
                scan_plan = [requested]
                if requested < 8192 and file_mb > requested:
                    scan_plan.append(min(8192, file_mb))
                if file_mb > max(scan_plan):
                    scan_plan.append(0)

            candidate = None
            used_scan = None
            for scan_range in scan_plan:
                candidate = find_dtb(
                    dump_path,
                    scan_mb=scan_range,
                    build=build,
                    strict_system=False,
                    use_selfref=True,
                    use_kpcr=True,
                )
                used_scan = scan_range
                if candidate:
                    break

            if not candidate:
                scanned_desc = "full dump" if scan_plan and scan_plan[-1] == 0 else f"first {scan_plan[-1]} MB"
                return {
                    "success": False,
                    "message": (
                        f"No accepted kernel DTB metadata found after resolving metadata and scanning {scanned_desc}. "
                        f"Weak candidates below {MIN_ACCEPT_SCORE}% are intentionally rejected."
                    ),
                    "dtb_hex": None,
                    "confidence": 0,
                    "json_path": json_path,
                    "scan_mb": used_scan,
                    "metadata_source": "unresolved",
                    "dtb_source": "unresolved",
                }

            sidecar_path = None
            if effective_write_json:
                sidecar_path = write_dtb_to_sidecar(dump_path, candidate, build=build)

            return {
                "success": True,
                "message": "Kernel metadata resolved by native fallback and sidecar updated." if effective_write_json else "Kernel metadata resolved by native fallback.",
                "dtb": candidate.dtb,
                "dtb_hex": candidate.dtb_hex,
                "confidence": candidate.score,
                "eprocess_base": hex(candidate.eprocess_base),
                "process_name": candidate.process_name,
                "process_pid": candidate.pid,
                "method": f"native_{candidate.method}",
                "profile_match": candidate.profile,
                "build": build,
                "json_path": str(sidecar_path) if sidecar_path else json_path,
                "scan_mb": used_scan,
                "metadata_source": "native_dtb_fallback",
                "source": "native_dtb_fallback",
                "dtb_source": f"native_{candidate.method}",
                "volatility_used_for_artifacts": False,
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"Kernel metadata resolution error: {type(e).__name__}: {e}",
                "dtb_hex": None,
                "confidence": 0,
                "json_path": None,
                "metadata_source": "error",
                "dtb_source": "error",
            }

    @staticmethod
    def generate_json_metadata(path: str, tool: str = "Imported/External", selected_profile: Optional[Dict[str, Any]] = None) -> dict:
        """
        Generate (or regenerate) a JSON sidecar metadata file for any dump.

        Returns:
        {
          'success':   bool,
          'json_path': str | None,
          'message':   str,
          'dtb_hex':   str | None,
          'build':     int | None,
        }
        """
        if _IMPORT_ERROR:
            return {
                "success": False, "json_path": None,
                "message": _IMPORT_ERROR, "dtb_hex": None, "build": None,
            }

        try:
            dump_path = Path(path)
            if not dump_path.is_file():
                raise FileNotFoundError(f"File not found: {path}")

            if not _is_inside_managed_session(dump_path):
                # This method may be called by the UI immediately after file
                # selection. Do not create metadata beside the user's original
                # dump. The organized copy inside RAMDetect/dumps/<session> will
                # receive its JSON sidecar during organize_loaded_file().
                stray = _find_sidecar(dump_path)
                _safe_unlink_sidecar(stray)
                return {
                    "success": True,
                    "json_path": None,
                    "message": "Metadata sidecar deferred until dump is organized in RAMDetect/dumps/<session>/.",
                    "dtb_hex": None,
                    "build": None,
                }

            header      = MetadataReader().get_metadata(str(dump_path))
            extra       = {}
            dtb_hex_out = None
            build_out   = None

            if header.get("is_valid"):
                dtb_hex_out           = header.get("dtb_hex")
                build_out             = header.get("build_number")
                extra["dtb_hex"]      = dtb_hex_out
                extra["build_number"] = build_out
                extra["profile_source"] = "crash_dump_header"
            else:
                profile_extra = _profile_to_extra(selected_profile)
                extra.update(profile_extra)
                build_out = profile_extra.get("build_number")
                dtb_hex_out = profile_extra.get("dtb_hex")

            mgr       = MetadataManager()
            json_path = mgr.create_acquisition_metadata(
                dump_path  = dump_path,
                tool       = tool,
                duration   = 0.0,
                extra_data = extra if extra else None,
            )

            return {
                "success":   True,
                "json_path": str(Path(json_path).absolute()),
                "message":   "",
                "dtb_hex":   dtb_hex_out,
                "build":     build_out,
            }

        except FileNotFoundError as e:
            return {
                "success": False, "json_path": None,
                "message": str(e), "dtb_hex": None, "build": None,
            }
        except Exception as e:
            return {
                "success": False, "json_path": None,
                "message": f"Metadata generation error: {type(e).__name__}: {e}",
                "dtb_hex": None, "build": None,
            }

    @staticmethod
    def start_live_dump(
        dumpit_path: str,
        output_dir:  str,
        progress_cb: Callable[[int, str], None],
        finished_cb: Callable[[dict], None],
        error_cb:    Callable[[str], None],
    ) -> "LiveDumpWorker":
        """
        Launch a DumpIt acquisition in a background thread.

        Calls progress_cb(pct, message) as work proceeds.
        Calls finished_cb(info_dict) on success — info_dict includes
          'session_dir': the new subfolder holding both .dmp and .json.
        Calls error_cb(message) on any failure.
        Returns the worker so the caller can cancel() it.
        """
        canonical_output_dir = str(_canonical_dumps_dir(output_dir))
        worker = LiveDumpWorker(
            dumpit_path, canonical_output_dir,
            progress_cb, finished_cb, error_cb,
        )
        worker.start()
        return worker


# ─────────────────────────────────────────────────────────────────────────────
# LiveDumpWorker
# ─────────────────────────────────────────────────────────────────────────────

class LiveDumpWorker(threading.Thread):
    """Background thread that runs DumpItAcquisition.acquire()."""

    def __init__(self, dumpit_path, output_dir, progress_cb, finished_cb, error_cb):
        super().__init__(daemon=True)
        self.dumpit_path = dumpit_path
        self.output_dir  = str(_canonical_dumps_dir(output_dir))
        self.progress_cb = progress_cb
        self.finished_cb = finished_cb
        self.error_cb    = error_cb
        self._cancel     = False

    def cancel(self):
        """Signal the worker to stop. DumpItAcquisition handles its own cleanup."""
        self._cancel = True

    def run(self):
        if _IMPORT_ERROR:
            self.error_cb(_IMPORT_ERROR)
            return
        self._run()

    def _run(self):
        try:
            if self._cancel:
                self.error_cb("Acquisition cancelled before start.")
                return

            self.progress_cb(5, "Checking prerequisites...")

            if not os.path.isfile(self.dumpit_path):
                raise FileNotFoundError(
                    f"DumpIt not found at: {self.dumpit_path}"
                )

            self.progress_cb(10, "Creating session folder...")

            # ── Create a dedicated session subfolder ──────────────────────────
            # Named:  memdump_YYYYMMDD_HHMMSS/
            # The .dmp and sidecar .json will both live inside it.
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            folder_stem = f"memdump_{ts}"
            session_dir = _make_session_dir(self.output_dir, folder_stem)

            out_name = f"{folder_stem}.dmp"
            out_path = session_dir / out_name          # desired final location

            self.progress_cb(15, "Initialising DumpItAcquisition...")

            # Tell Config about the DumpIt path so DumpItAcquisition can find it
            Config.set("acquisition.dumpit_path", self.dumpit_path)
            acquisition = DumpItAcquisition()

            self.progress_cb(20, "Starting memory acquisition (this may take several minutes)...")

            if self._cancel:
                self.error_cb("Acquisition cancelled.")
                return

            # acquire() is blocking — runs in this background thread
            raw_dump_path = acquisition.acquire(output_path=str(out_path))

            if self._cancel:
                self.error_cb("Acquisition cancelled.")
                return

            # ── Resolve actual output location ────────────────────────────────
            # DumpIt sometimes ignores the requested path and writes to its own
            # default location; the fallback scanner catches that case.
            if raw_dump_path and Path(str(raw_dump_path)).is_file():
                dump_path = Path(str(raw_dump_path))
            else:
                # Search the base output_dir (and the session subfolder) for a
                # recently created .dmp file
                fallback = self._find_recent_dump(
                    str(session_dir)
                ) or self._find_recent_dump(self.output_dir)

                if fallback:
                    dump_path = fallback
                else:
                    raise RuntimeError(
                        "Acquisition completed but no output file was found. "
                        "Check the output directory and run as Administrator."
                    )

            # ── Move the dump into the session folder if DumpIt wrote it ──────
            # elsewhere (e.g. directly into output_dir).
            if dump_path.parent.resolve() != session_dir.resolve():
                self.progress_cb(88, "Moving dump into session folder...")
                dump_path = _relocate_into(dump_path, session_dir)

            self.progress_cb(90, "Verifying dump and reading metadata...")

            sha256_full = _quick_hash(str(dump_path))

            # ── Move any sidecar JSON that DumpIt may have created next to ────
            # the dump in its original location, then generate a fresh one
            # inside session_dir if nothing is present yet.
            stray_sidecar = _find_sidecar(
                # check original location before move
                Path(str(raw_dump_path)) if raw_dump_path else dump_path
            )
            if stray_sidecar and stray_sidecar.parent.resolve() != session_dir.resolve():
                _relocate_into(stray_sidecar, session_dir)

            # Generate (or refresh) sidecar JSON inside session_dir
            self.progress_cb(93, "Writing JSON sidecar metadata...")
            sidecar_path = _generate_sidecar(dump_path, tool="DumpIt/Live")

            # Ensure sidecar sits inside session_dir even if MetadataManager
            # placed it somewhere else
            if sidecar_path and sidecar_path.parent.resolve() != session_dir.resolve():
                sidecar_path = _relocate_into(sidecar_path, session_dir)

            # ── Load metadata for the finished_cb dict ────────────────────────
            try:
                meta = MetadataManager().load(dump_path) or {}
            except Exception:
                meta = {}

            hashes       = meta.get("hashes", {})
            sha256_final = hashes.get("sha256") or sha256_full
            md5_final    = _quick_md5(str(dump_path))

            kernel   = meta.get("kernel_info", {})
            build    = kernel.get("build_number", "")
            arch_str = f"x64 Windows (build {build})" if build else "x64 Windows"

            size = dump_path.stat().st_size

            self.progress_cb(100, "Acquisition complete.")
            self.finished_cb({
                "valid":         True,
                "path":          str(dump_path),
                "filename":      dump_path.name,
                "session_dir":   str(session_dir),   # ← NEW: folder path
                "json_path":     str(sidecar_path) if sidecar_path else None,
                "size_bytes":    size,
                "size_str":      _bytes_to_str(size),
                "format":        "DMP",
                "architecture":  arch_str,
                "os_hint":       "Windows",
                "est_load_time": _estimate_load_time(size),
                "sha256":        sha256_final,
                "md5":           md5_final,
                "error":         "",
            })

        except FileNotFoundError:
            self.error_cb(
                f"DumpIt executable not found.\n"
                f"Check the path in Settings:\n{self.dumpit_path}"
            )
        except PermissionError:
            self.error_cb(
                "Permission denied.\n"
                "Live acquisition requires Administrator privileges.\n"
                "Right-click your terminal and Run as administrator."
            )
        except RuntimeError as e:
            self.error_cb(str(e))
        except Exception as e:
            self.error_cb(
                f"Acquisition failed: {type(e).__name__}: {e}\n\n"
                f"Common causes:\n"
                f"  - Run terminal as Administrator\n"
                f"  - Antivirus blocking DumpIt\n"
                f"  - Driver signing issue (disable in boot options)"
            )

    @staticmethod
    def _find_recent_dump(directory: str, max_age_secs: int = 120) -> Optional[Path]:
        import time
        now        = time.time()
        candidates = []
        try:
            for entry in os.scandir(directory):
                if entry.name.lower().endswith(".dmp"):
                    mtime = entry.stat().st_mtime
                    if now - mtime <= max_age_secs:
                        candidates.append((mtime, Path(entry.path)))
        except Exception:
            pass
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
        return None
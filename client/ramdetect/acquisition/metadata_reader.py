"""
ramdetect/utils/metadata_reader.py
----------------------------------
Kernel metadata resolver for RAMDetect.

Scope of optional external resolver:
  - Windows build / OS profile
  - kernel DTB / CR3
  - kernel base and layer metadata when available

It never uses external framework output for artifacts such as processes,
threads, DLLs, handles, VADs, malfind, features, or verdicts.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union



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



class MetadataReader:
    """
    Resolves minimal kernel metadata required by RAMDetect native parsers.

    Priority order:
      1. Existing sidecar JSON with verified kernel_info
      2. Windows crash dump header
      3. Optional external metadata resolver: `vol -f <dump> windows.info.Info`
      4. Optional native RAMDetect DTB scanner fallback
    """

    def get_metadata(
        self,
        file_path: Union[str, Path],
        *,
        allow_external: bool = True,
        allow_native_fallback: bool = True,
        write_sidecar: bool = True,
        timeout: int = 900,
    ) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {}

        # 1. Existing verified sidecar.
        sidecar_meta = self._read_sidecar(path)
        if self._has_verified_kernel_info(sidecar_meta):
            return self._normalize(sidecar_meta, source_stage="sidecar")

        # 2. Crash dump header. Useful for crash dumps, not raw/vmem.
        try:
            header = self._parse_crash_dump_header(path)
            if header.get("is_valid"):
                merged = self._merge_kernel_info(sidecar_meta, header.get("kernel_info", {}))
                if write_sidecar:
                    self._write_sidecar(path, merged)
                return self._normalize(merged, source_stage="crash_dump_header")
        except Exception:
            pass

        # 3. External metadata resolver, limited to windows.info only.
        if allow_external:
            info = self._run_vol_windows_info(path, timeout=timeout)
            if info:
                merged = self._merge_kernel_info(sidecar_meta, info)
                if write_sidecar:
                    self._write_sidecar(path, merged)
                return self._normalize(merged, source_stage="external_kernel_metadata_resolver")

        # 4. Native fallback only if external unavailable/fails.
        if allow_native_fallback:
            info = self._run_native_dtb_fallback(path, sidecar_meta)
            if info:
                merged = self._merge_kernel_info(sidecar_meta, info)
                if write_sidecar:
                    self._write_sidecar(path, merged)
                return self._normalize(merged, source_stage="native_dtb_fallback")

        # Return whatever sidecar/header data exists even if incomplete.
        return self._normalize(sidecar_meta, source_stage="unresolved")

    # ------------------------------------------------------------------
    # Sidecar handling
    # ------------------------------------------------------------------
    def _sidecar_candidates(self, dump_path: Path) -> list[Path]:
        candidates = [
            dump_path.with_suffix(".json"),
            Path(str(dump_path) + ".json"),
            dump_path.with_suffix(".dmp.metadata.json"),
            Path(str(dump_path) + ".metadata.json"),
        ]
        stem = dump_path.stem
        try:
            for subdir in sorted(dump_path.parent.glob(f"{stem}_*"), reverse=True):
                if subdir.is_dir():
                    candidates.append(subdir / f"{stem}.json")
                    candidates.append(subdir / f"{stem}.metadata.json")
        except Exception:
            pass
        return candidates

    def _sidecar_path(self, dump_path: Path) -> Path:
        for c in self._sidecar_candidates(dump_path):
            if c.exists():
                return c
        return dump_path.with_suffix(".json")

    def _read_sidecar(self, dump_path: Path) -> Dict[str, Any]:
        for p in self._sidecar_candidates(dump_path):
            if not p.exists():
                continue
            try:
                meta = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(meta, dict):
                    meta.setdefault("metadata", {})
                    meta["metadata"]["sidecar_path"] = str(p)
                    return meta
            except Exception:
                return {}
        return {}

    def _write_sidecar(self, dump_path: Path, metadata: Dict[str, Any]) -> Path:
        p = self._sidecar_path(dump_path)
        metadata.setdefault("metadata", {})
        metadata["metadata"].update({
            "tool": "RAMDetect",
            "format": "json",
            "saved_at": datetime.now(timezone.utc).isoformat(),
        })
        p.write_text(json.dumps(metadata, indent=4), encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    # Normalisation / validation
    # ------------------------------------------------------------------
    def _parse_int(self, value: Any) -> Optional[int]:
        if value in (None, "", "None"):
            return None
        try:
            if isinstance(value, str):
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            return int(value)
        except Exception:
            return None

    def _is_valid_dtb(self, value: Any) -> bool:
        dtb = self._parse_int(value)
        return bool(dtb and dtb >= 0x1000 and (dtb & 0xFFF) == 0 and dtb < 0x40000000000)

    def _has_verified_kernel_info(self, meta: Dict[str, Any]) -> bool:
        if not isinstance(meta, dict):
            return False
        k = meta.get("kernel_info") if isinstance(meta.get("kernel_info"), dict) else {}
        dtb = k.get("dtb") or k.get("cr3") or k.get("dtb_hex") or k.get("cr3_hex") or meta.get("dtb") or meta.get("cr3")
        build = k.get("build_number") or meta.get("build_number")
        source = str(k.get("dtb_source") or meta.get("dtb_source") or "").lower()
        confidence = self._parse_int(k.get("dtb_confidence") or meta.get("dtb_confidence"))
        bad = any(x in source for x in ("default", "placeholder", "unverified", "kpcr_cr3"))
        return bool(
            self._is_valid_dtb(dtb)
            and build
            and not bad
            and (confidence is None or confidence >= 80)
        )

    def _normalize(self, meta: Dict[str, Any], *, source_stage: str) -> Dict[str, Any]:
        if not isinstance(meta, dict):
            meta = {}
        k = meta.get("kernel_info") if isinstance(meta.get("kernel_info"), dict) else {}
        dtb = self._parse_int(k.get("dtb") or k.get("cr3") or k.get("dtb_hex") or k.get("cr3_hex") or meta.get("dtb") or meta.get("cr3"))
        build = self._parse_int(k.get("build_number") or meta.get("build_number"))
        return {
            "type": "Kernel Metadata",
            "dtb": dtb or 0,
            "cr3": dtb or 0,
            "dtb_hex": hex(dtb) if dtb else "0x0",
            "cr3_hex": hex(dtb) if dtb else "0x0",
            "build_number": build,
            "os": k.get("os") or meta.get("os") or "Windows",
            "version": k.get("version") or meta.get("version"),
            "architecture": k.get("architecture") or k.get("machine_type") or meta.get("architecture"),
            "dtb_source": k.get("dtb_source") or meta.get("dtb_source") or "",
            "dtb_confidence": self._parse_int(k.get("dtb_confidence") or meta.get("dtb_confidence")),
            "profile_source": k.get("profile_source") or k.get("dtb_source") or source_stage,
            "resolver_stage": source_stage,
            "is_valid": bool(dtb and build and self._is_valid_dtb(dtb)),
            "kernel_info": k,
            "metadata": meta,
        }

    def _merge_kernel_info(self, existing: Dict[str, Any], kernel_info: Dict[str, Any]) -> Dict[str, Any]:
        meta = dict(existing or {})
        old = meta.get("kernel_info") if isinstance(meta.get("kernel_info"), dict) else {}
        if old:
            meta.setdefault("previous_kernel_info_before_recalibration", old)
        k = dict(old)
        k.update({kk: vv for kk, vv in (kernel_info or {}).items() if vv is not None})
        meta["kernel_info"] = k
        for key in ("build_number", "os", "version", "dtb", "cr3", "dtb_hex", "cr3_hex"):
            if key in k and k[key] is not None:
                meta[key] = k[key]
        meta.setdefault("ramdetect_policy", {})
        meta["ramdetect_policy"].update({
            "external_resolver_scope": "os_profile_and_kernel_dtb_only",
            "external_used_for_artifact_extraction": False,
            "external_used_for_ml_features": False,
            "external_used_for_verdict": False,
        })
        return meta

    # ------------------------------------------------------------------
    # Crash dump header
    # ------------------------------------------------------------------
    def _parse_crash_dump_header(self, path: Path) -> Dict[str, Any]:
        with path.open("rb") as f:
            data = f.read(1024)
        if len(data) < 0x48:
            raise ValueError("Header too small")
        sig = data[0:4]
        if sig not in [b"PAGE", b"DU64", b"DUMP"]:
            raise ValueError("Invalid crash dump signature")
        major = struct.unpack("<I", data[0x18:0x1C])[0]
        build = struct.unpack("<I", data[0x1C:0x20])[0]
        dtb = struct.unpack("<Q", data[0x40:0x48])[0]
        if build and not (7600 <= build <= 99999):
            build = None
        return {
            "type": "Crash Dump",
            "is_valid": bool(build and self._is_valid_dtb(dtb)),
            "kernel_info": {
                "build_number": build,
                "dtb": dtb,
                "cr3": dtb,
                "dtb_hex": hex(dtb),
                "cr3_hex": hex(dtb),
                "dtb_source": "crash_dump_header",
                "dtb_confidence": 85,
                "nt_major_version": major,
                "profile_source": "crash_dump_header",
                "profile_updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    # ------------------------------------------------------------------
    # External resolver: vol -f <dump> windows.info.Info
    # ------------------------------------------------------------------
    def _grab(self, output: str, pattern: str) -> Optional[str]:
        m = re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    def _parse_windows_info_output(self, output: str) -> Optional[Dict[str, Any]]:
        dtb_hex = self._grab(output, r"^\s*DTB\s+(0x[0-9a-fA-F]+)\s*$")
        if not dtb_hex:
            return None
        dtb = self._parse_int(dtb_hex)
        if not self._is_valid_dtb(dtb):
            return None

        kernel_base = self._grab(output, r"^\s*Kernel Base\s+(0x[0-9a-fA-F]+)\s*$")
        kd_version = self._grab(output, r"^\s*KdVersionBlock\s+(0x[0-9a-fA-F]+)\s*$")
        major_minor = self._grab(output, r"^\s*Major/Minor\s+([0-9]+\.[0-9]+)\s*$")
        symbols = self._grab(output, r"^\s*Symbols\s+(.+)\s*$")
        is64 = self._grab(output, r"^\s*Is64Bit\s+(\w+)\s*$")
        ispae = self._grab(output, r"^\s*IsPAE\s+(\w+)\s*$")
        memory_layer = self._grab(output, r"^\s*memory_layer\s+\d+\s+(.+)\s*$") or self._grab(output, r"^\s*Layer Name\s+(.+)\s*$")
        machine_type = self._grab(output, r"^\s*MachineType\s+(\d+)\s*$")
        processors = self._grab(output, r"^\s*KeNumberProcessors\s+(\d+)\s*$")
        system_time = self._grab(output, r"^\s*SystemTime\s+(.+)\s*$")
        nt_major = self._grab(output, r"^\s*NtMajorVersion\s+(\d+)\s*$")
        nt_minor = self._grab(output, r"^\s*NtMinorVersion\s+(\d+)\s*$")

        build = None
        if major_minor:
            parts = major_minor.split(".")
            if len(parts) >= 2:
                build = self._parse_int(parts[-1])
        if not build or not (7600 <= build <= 99999):
            # Fallback from symbol path/version string if present.
            build_match = re.search(r"\b(10\.0\.)?(1[7-9]\d{3}|2[0-9]\d{3})\b", output)
            if build_match:
                build = self._parse_int(build_match.group(2))
        if not build or not (7600 <= build <= 99999):
            return None

        def to_bool(v: Optional[str]) -> Optional[bool]:
            if v is None:
                return None
            return str(v).strip().lower() == "true"

        os_name = "Microsoft Windows 11" if build >= 22000 else "Microsoft Windows 10"
        is64_bool = to_bool(is64)
        ispae_bool = to_bool(ispae)
        if is64_bool is True:
            arch_value = "x64"
        elif is64_bool is False and ispae_bool:
            arch_value = "x86 PAE"
        elif is64_bool is False:
            arch_value = "x86"
        else:
            arch_value = None
        return {
            "build_number": build,
            "os": os_name,
            "version": f"10.0.{build}",
            "architecture": arch_value,
            "dtb": dtb,
            "cr3": dtb,
            "dtb_hex": hex(dtb),
            "cr3_hex": hex(dtb),
            "dtb_source": "volatility_windows_info",
            "dtb_confidence": 100,
            "kernel_base_hex": kernel_base,
            "kd_version_block_hex": kd_version,
            "is_64bit": is64_bool,
            "is_pae": ispae_bool,
            "memory_layer": memory_layer,
            "machine_type": int(machine_type) if machine_type else None,
            "processor_count": int(processors) if processors else None,
            "nt_major_version": int(nt_major) if nt_major else None,
            "nt_minor_version": int(nt_minor) if nt_minor else None,
            "system_time_utc": system_time,
            "symbols": symbols,
            "profile_source": "volatility_windows_info",
            "profile_updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _run_vol_windows_info(self, path: Path, *, timeout: int = 900) -> Optional[Dict[str, Any]]:
        vol_path = _resolve_volatility_exe()
        if not vol_path:
            return None
        try:
            proc = subprocess.run(
                [vol_path, "-f", str(path), "windows.info.Info"],
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
            return self._parse_windows_info_output(combined)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Native fallback
    # ------------------------------------------------------------------
    def _run_native_dtb_fallback(self, path: Path, existing: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            from ramdetect.utils.find_dtb import find_dtb
        except Exception:
            return None
        build = None
        k = existing.get("kernel_info") if isinstance(existing.get("kernel_info"), dict) else {}
        build = self._parse_int(k.get("build_number") or existing.get("build_number"))
        try:
            cand = find_dtb(path, scan_mb=4096, build=build, strict_system=False, use_selfref=True, use_kpcr=True)
        except Exception:
            cand = None
        if not cand:
            return None
        return {
            "build_number": build,
            "dtb": cand.dtb,
            "cr3": cand.dtb,
            "dtb_hex": cand.dtb_hex,
            "cr3_hex": cand.dtb_hex,
            "dtb_source": f"native_{cand.method}",
            "dtb_confidence": cand.score,
            "dtb_evidence": getattr(cand, "evidence", []),
            "profile_source": "native_dtb_scanner",
            "profile_updated_at": datetime.now(timezone.utc).isoformat(),
        }

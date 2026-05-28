"""
ramdetect/extraction/parsers/service_registry_parser.py
=======================================================
Phase H3D diagnostic Service Registry Handle Parser.

Purpose
-------
Extract structured Windows service-name evidence from registry HANDLE paths
already recovered by RAMDetect's handle parser, for example:

    \\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip
    Machine\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Parameters
    HKLM\\SYSTEM\\ControlSet002\\Services\\W32Time

Important RAMDetect rules
-------------------------
This module is diagnostic/parser evidence only.  It does not emit official
svcscan.* ML features, does not change the RF threshold, and does not add veto,
layer, dampener, or override logic.  Official svcscan.* mapping still requires
real service metadata such as Type, Start, ImagePath, ServiceDll and active
SCM/service-state evidence.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# Registry path fragments that mean "this path may contain service records".
# The parser normalizes all separators to a single backslash before matching.
_SERVICE_PATH_RE = re.compile(
    r"(?:^|\\)(?:registry\\)?(?:machine|hklm)?\\?system\\"
    r"(?P<control>currentcontrolset|controlset\d{3})\\services\\"
    r"(?P<service>[^\\/]+)(?P<rest>(?:\\[^\\/]*)*)",
    re.IGNORECASE,
)

# Fallback for rows that only retain the tail of the registry path.
_SERVICES_TAIL_RE = re.compile(
    r"(?:^|\\)services\\(?P<service>[^\\/]+)(?P<rest>(?:\\[^\\/]*)*)",
    re.IGNORECASE,
)

# Subkey/value-name fragments that should never be treated as service names.
_SERVICE_NAME_DENYLIST = {
    "parameters", "enum", "security", "triggerinfo", "triggerinfo0",
    "linkage", "networkprovider", "performance", "configuration", "instances",
    "settings", "control", "class", "currentcontrolset", "controlset001",
    "controlset002", "controlset003", "services", "type", "start",
    "imagepath", "servicedll", "displayname", "description", "errorcontrol",
}

_VALUE_NAMES = {
    "type", "start", "imagepath", "displayname", "objectname", "servicedll",
    "description", "errorcontrol", "group", "dependonservice", "dependongroup",
    "failureactions", "requiredprivileges", "servicemain", "delayedautostart",
}

_REGISTRY_FIELD_HINTS = (
    "name", "object", "path", "key", "handle", "target", "details",
    "description", "registry", "value", "full", "filename",
)


@dataclass
class ServiceRegistryEvidence:
    """One normalized service-registry evidence record."""

    service_name: str
    registry_path: str
    control_set: str = ""
    sub_path: str = ""
    source_field: str = ""
    source_type: str = ""
    pid: Optional[int] = None
    process_name: str = ""
    evidence_count: int = 1
    evidence_strength: str = "service_key_name_only"
    has_type: bool = False
    has_start: bool = False
    has_image_path: bool = False
    has_service_dll: bool = False
    has_display_name: bool = False
    has_state: bool = False
    source_fields_seen: List[str] = field(default_factory=list)
    example_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["ready_for_service_type_classification"] = bool(
            self.has_type and (self.has_image_path or self.has_service_dll)
        )
        data["ready_for_svcscan_ml_mapping"] = False
        return data


class ServiceRegistryParser:
    """
    Extract diagnostic service-registry evidence from arbitrary RAMDetect
    session/parsed_data dictionaries.
    """

    def parse(self, parsed_or_session: Mapping[str, Any]) -> Dict[str, Any]:
        rows = list(self._collect_dict_rows(parsed_or_session))
        evidences: Dict[Tuple[str, str], ServiceRegistryEvidence] = {}
        raw_evidence_rows: List[Dict[str, Any]] = []

        for row in rows:
            if not isinstance(row, Mapping):
                continue
            for field_name, value in row.items():
                if not isinstance(value, str):
                    continue
                # Prefer likely path/key fields, but still allow any string field
                # that clearly contains a Services registry path.
                field_l = str(field_name).lower()
                if not any(h in field_l for h in _REGISTRY_FIELD_HINTS) and "services" not in value.lower():
                    continue

                normalized = self._normalize_path(value)
                extracted = self._extract_service_path(normalized)
                if not extracted:
                    continue

                service_name, control_set, sub_path = extracted
                key = (control_set.lower(), service_name.lower())

                pid = self._safe_int(
                    row.get("pid") or row.get("PID") or row.get("owner_pid") or row.get("ProcessId")
                )
                process_name = str(
                    row.get("process") or row.get("process_name") or row.get("image_name")
                    or row.get("Process") or row.get("Process Name") or ""
                )
                source_type = str(row.get("type") or row.get("Type") or row.get("handle_type") or "")

                raw_hit = {
                    "service_name": service_name,
                    "control_set": control_set,
                    "sub_path": sub_path,
                    "registry_path": normalized,
                    "source_field": str(field_name),
                    "source_type": source_type,
                    "pid": pid if pid is not None else "",
                    "process_name": process_name,
                }
                raw_evidence_rows.append(raw_hit)

                ev = evidences.get(key)
                if ev is None:
                    ev = ServiceRegistryEvidence(
                        service_name=service_name,
                        control_set=control_set,
                        sub_path=sub_path,
                        registry_path=normalized,
                        source_field=str(field_name),
                        source_type=source_type,
                        pid=pid,
                        process_name=process_name,
                        source_fields_seen=[str(field_name)],
                        example_paths=[normalized],
                    )
                    evidences[key] = ev
                else:
                    ev.evidence_count += 1
                    if str(field_name) not in ev.source_fields_seen:
                        ev.source_fields_seen.append(str(field_name))
                    if normalized not in ev.example_paths and len(ev.example_paths) < 5:
                        ev.example_paths.append(normalized)
                    if not ev.pid and pid:
                        ev.pid = pid
                    if not ev.process_name and process_name:
                        ev.process_name = process_name
                    if not ev.source_type and source_type:
                        ev.source_type = source_type

                # Mark value/subkey evidence when the retained path or row text
                # mentions known service value names. This still does not prove
                # the actual value contents; it only shows the handle/path reached
                # a more specific service-value area.
                value_names = self._detect_value_names(row, sub_path)
                ev.has_type = ev.has_type or "type" in value_names
                ev.has_start = ev.has_start or "start" in value_names
                ev.has_image_path = ev.has_image_path or "imagepath" in value_names
                ev.has_service_dll = ev.has_service_dll or "servicedll" in value_names
                ev.has_display_name = ev.has_display_name or "displayname" in value_names
                ev.has_state = False
                if value_names:
                    ev.evidence_strength = "service_key_with_value_name_evidence"

        service_rows = [ev.to_dict() for ev in evidences.values()]
        service_rows.sort(key=lambda r: (str(r.get("control_set", "")).lower(), str(r.get("service_name", "")).lower()))

        records_with_type = [r for r in service_rows if r.get("has_type")]
        records_with_start = [r for r in service_rows if r.get("has_start")]
        records_with_path = [r for r in service_rows if r.get("has_image_path") or r.get("has_service_dll")]
        ready_type = [r for r in service_rows if r.get("ready_for_service_type_classification")]

        summary = {
            "service_name_evidence_count": len(service_rows),
            "raw_registry_service_path_hits": len(raw_evidence_rows),
            "records_with_type_value": len(records_with_type),
            "records_with_start_value": len(records_with_start),
            "records_with_imagepath_or_servicedll": len(records_with_path),
            "records_ready_for_service_type_classification": len(ready_type),
            "can_infer_service_names": len(service_rows) > 0,
            "can_infer_service_type": len(records_with_type) > 0,
            "can_infer_service_state": False,
            "ready_for_svcscan_ml_mapping": False,
            "reason": (
                "Service names can be extracted from registry handle paths, but official svcscan.* "
                "mapping requires parsed Type/Start/ImagePath/ServiceDll values and active state evidence."
            ),
            "rules_preserved": {
                "diagnostic_only": True,
                "ml_only": True,
                "threshold_changed": False,
                "training_dataset_changed": False,
                "verdict_logic_changed": False,
                "native_feature_override_added": False,
            },
        }
        return {
            "summary": summary,
            "services": service_rows,
            "evidence_rows": raw_evidence_rows,
            "value_gaps": self._build_gaps(service_rows),
        }

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_service_path(self, text: str) -> Optional[Tuple[str, str, str]]:
        if not text:
            return None
        m = _SERVICE_PATH_RE.search(text)
        control_set = ""
        if not m:
            m = _SERVICES_TAIL_RE.search(text)
        else:
            control_set = (m.group("control") or "").strip()
        if not m:
            return None

        service_name = (m.group("service") or "").strip().strip("\\/")
        sub_path = (m.group("rest") or "").strip("\\/")
        if not self._valid_service_name(service_name):
            return None
        return service_name, control_set, sub_path

    @staticmethod
    def _valid_service_name(name: str) -> bool:
        if not name:
            return False
        n = name.strip().strip("\\/")
        nl = n.lower()
        if nl in _SERVICE_NAME_DENYLIST:
            return False
        if len(n) > 128:
            return False
        # Service names may contain dots, underscores, hyphens and digits, but
        # should not be full paths, DLL module names, device paths, or pure '-'.
        if n in {"-", ".", ".."}:
            return False
        if "\\" in n or "/" in n:
            return False
        return True

    @staticmethod
    def _detect_value_names(row: Mapping[str, Any], sub_path: str) -> set[str]:
        text_parts = [str(sub_path or "").lower()]
        for key in ("value_name", "ValueName", "name", "Name", "details", "Details"):
            value = row.get(key)
            if isinstance(value, str):
                text_parts.append(value.lower())
        text = " ".join(text_parts)
        found = set()
        for vn in _VALUE_NAMES:
            if re.search(rf"(?:^|[^a-z0-9_]){re.escape(vn)}(?:[^a-z0-9_]|$)", text):
                found.add(vn)
        return found

    def _collect_dict_rows(self, obj: Any) -> Iterable[Mapping[str, Any]]:
        if isinstance(obj, Mapping):
            yield obj
            for v in obj.values():
                yield from self._collect_dict_rows(v)
        elif isinstance(obj, list):
            for item in obj:
                yield from self._collect_dict_rows(item)

    @staticmethod
    def _normalize_path(value: str) -> str:
        text = str(value or "").strip().replace("/", "\\")
        # Remove common NT object prefixes but keep registry structure.
        text = text.replace("\\REGISTRY\\", "\\Registry\\")
        text = re.sub(r"\\+", r"\\", text)
        text = text.strip()
        # Normalize HKLM aliases into Machine for easier matching.
        text = re.sub(r"^(?:\\)?hkey_local_machine\\", r"\\Machine\\", text, flags=re.I)
        text = re.sub(r"^(?:\\)?hklm\\", r"\\Machine\\", text, flags=re.I)
        return text

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            if value in (None, "", "-", "None", "none", "N/A", "n/a"):
                return None
            if isinstance(value, int):
                return value
            s = str(value).strip()
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(float(s))
        except Exception:
            return None

    @staticmethod
    def _build_gaps(service_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        gaps: List[Dict[str, Any]] = []
        for row in service_rows:
            missing = []
            if not row.get("has_type"):
                missing.append("Type")
            if not row.get("has_start"):
                missing.append("Start")
            if not (row.get("has_image_path") or row.get("has_service_dll")):
                missing.append("ImagePath/ServiceDll")
            missing.append("ActiveState")
            gaps.append({
                "service_name": row.get("service_name", ""),
                "control_set": row.get("control_set", ""),
                "missing_for_safe_svcscan": ";".join(missing),
                "ready_for_ml_mapping": False,
                "registry_path": row.get("registry_path", ""),
                "evidence_strength": row.get("evidence_strength", ""),
            })
        return gaps

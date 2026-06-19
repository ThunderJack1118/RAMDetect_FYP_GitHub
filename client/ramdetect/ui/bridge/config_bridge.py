"""
ui/bridge/config_bridge.py
──────────────────────────
Reads and writes  config.yaml  at the project root.

Usage:
    from ui.bridge.config_bridge import Config

    dumpit  = Config.get("acquisition.dumpit_path", default="DumpIt.exe")
    rf_w    = Config.get("ml.rf_weight", default=0.6)
    Config.set("ml.rf_weight", 0.7)   # writes back to config.yaml
    all_cfg = Config.all()
"""

from __future__ import annotations

import os

def _runtime_root() -> str:
    """Return active RAMDetect runtime root.

    In PyInstaller packaged mode, __file__ points into _internal. Runtime-owned
    folders such as models, dumps, reports, logs, and datasets must be resolved
    beside RAMDetect.exe instead:
      C:/RAMDetect Admin/models
      C:/RAMDetect Analyst/models
    """
    import sys as _sys

    try:
        if getattr(_sys, "frozen", False):
            return os.path.dirname(os.path.abspath(_sys.executable))
    except Exception:
        pass

    bridge_dir = os.path.dirname(os.path.abspath(__file__))
    ui_dir = os.path.dirname(bridge_dir)
    pkg_dir = os.path.dirname(ui_dir)
    return os.path.dirname(pkg_dir)

from typing import Any, Dict

# ── Locate config.yaml (project root) ───────────────────────────────────────
# File lives at:  ramdetect/ui/bridge/config_bridge.py
#   dirname x1 → ramdetect/ui/bridge/
#   dirname x2 → ramdetect/ui/
#   dirname x3 → ramdetect/
#   dirname x4 → RAMDetect/   ← project root
_BRIDGE_DIR  = os.path.dirname(os.path.abspath(__file__))
_UI_DIR      = os.path.dirname(_BRIDGE_DIR)
_PKG_DIR     = os.path.dirname(_UI_DIR)
_PROJECT_DIR = _runtime_root()
_CONFIG_PATH = os.path.join(_PROJECT_DIR, "config.yaml")

# ── Try importing PyYAML ──────────────────────────────────────────────────────
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
    print("[ConfigBridge] PyYAML not installed — using built-in defaults only.")

# ─────────────────────────────────────────────────────────────────────────────
# Hard-coded defaults
# (mirrors the expected structure of config.yaml so the GUI always has values)
# ─────────────────────────────────────────────────────────────────────────────
_DEFAULTS: Dict[str, Any] = {
    "acquisition": {
        "dumpit_path": "tools/DumpIt.exe",
        "output_dir":     "dumps/",
        "timeout_seconds": 300,
    },
    "paths": {
        "models_dir":     "models/",
        "reports_dir":    "reports/",
        "logs_dir":       "logs/",
        "datasets_dir":   "datasets/",
    },
    "ml": {
        "default_model":  "hybrid",
        "rf_weight":      0.75,
        "ae_weight":      0.25,
        "ae_threshold":   0.03280220925807953,
        "rf_model_path":  "models/experiments/Phase4B_CIC_clean_malfind_zero/f0_full54_rf_ae_malfind_clean_zero.joblib",
        "ae_model_path":  "models/autoencoder.pkl",
        "feature_mapper_path": "models/feature_mapper.pkl",
    },
    "analysis": {
        "auto_start":         True,
        "enable_logging":     True,
        "auto_save_results":  True,
        "include_raw_features": False,
        "default_modules":    [
            "process", "thread", "dll", "handle", "pe_section", "code_injection"
        ],
    },
    "reports": {
        "default_format":   "pdf",
        "pdf_page_size":    "A4",
        "header_text":      "RAMDetect Forensic Report",
        "organisation":     "",
    },
    "theme": {
        "name":        "dark",
        "font_size":   14,
        "accent_color": "#06b6d4",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins)."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result

def _norm_path(value: str) -> str:
    return os.path.normpath(os.path.expandvars(os.path.expanduser(str(value))))


def _is_stale_ramdetect_absolute(path: str) -> bool:
    """Return True when a copied config still points to another RAMDetect folder.

    Example problem:
        Current project: C:/Users/annsi/Downloads/RAMDetect
        Copied config:   C:/Users/annsi/Downloads/GITHUB/RAMDetect/dumps

    For project-owned folders, RAMDetect should rebase that path to the current
    project root instead of writing back to the old workstation/repository path.
    """
    try:
        p = _norm_path(path)
        current = _norm_path(_PROJECT_DIR)

        if os.path.commonpath([p, current]) == current:
            return False

        parts = [part.lower() for part in p.split(os.sep)]
        return "ramdetect" in parts
    except Exception:
        return False


def _rebase_from_ramdetect_root(path: str) -> str | None:
    """If path contains a stale RAMDetect root, rebase its suffix to this project."""
    try:
        p = _norm_path(path)
        parts = p.split(os.sep)
        lower = [part.lower() for part in parts]

        indices = [i for i, part in enumerate(lower) if part == "ramdetect"]
        if not indices:
            return None

        idx = indices[-1]
        suffix = parts[idx + 1:]
        if not suffix:
            return _PROJECT_DIR

        return os.path.join(_PROJECT_DIR, *suffix)
    except Exception:
        return None


def _resolve_project_path(raw: str, default: str, *, allow_external_absolute: bool = False) -> str:
    """Resolve config paths safely for copied/deployed RAMDetect folders.

    Relative paths are resolved from the current project root. Project-owned
    absolute paths copied from another RAMDetect folder are rebased to this
    current project folder. External absolute paths are allowed only when
    allow_external_absolute=True, such as for DumpIt.exe.
    """
    value = raw or default
    value = _norm_path(value)

    if os.path.isabs(value):
        if allow_external_absolute:
            return value

        rebased = _rebase_from_ramdetect_root(value) if _is_stale_ramdetect_absolute(value) else None
        if rebased:
            return rebased

        return value

    return os.path.join(_PROJECT_DIR, value)


class _ConfigBridge:
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._load()

    # ── Load ──────────────────────────────────────────────────────────────────
    def _load(self):
        file_data = {}
        if _HAS_YAML and os.path.exists(_CONFIG_PATH):
            try:
                with open(_CONFIG_PATH, "r") as f:
                    file_data = _yaml.safe_load(f) or {}
            except Exception as e:
                print(f"[ConfigBridge] Failed to load {_CONFIG_PATH}: {e}")
        self._data = _deep_merge(_DEFAULTS, file_data)

    def reload(self):
        """Re-read config.yaml from disk."""
        self._load()

    def reset(self):
        """Reset the configuration entirely to hard-coded defaults and save."""
        import copy
        # Deep copy ensures we don't accidentally mutate the original _DEFAULTS dict later
        self._data = copy.deepcopy(_DEFAULTS)
        
        # Write the defaults back to config.yaml
        self._save()

    # ── Read ──────────────────────────────────────────────────────────────────
    def get(self, key: str, default: Any = None) -> Any:
        """
        Dot-separated key lookup, e.g. Config.get("ml.rf_weight")
        Returns default if the key doesn't exist.
        """
        parts = key.split(".")
        node  = self._data
        for p in parts:
            if not isinstance(node, dict) or p not in node:
                return default
            node = node[p]
        return node

    def all(self) -> Dict[str, Any]:
        """Return the full merged config dict."""
        import copy
        return copy.deepcopy(self._data)

    # ── Write ─────────────────────────────────────────────────────────────────
    def set(self, key: str, value: Any):
        """
        Set a dot-separated key and write back to config.yaml.
        Creates intermediate dicts if needed.
        """
        parts = key.split(".")
        node  = self._data
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
        self._save()

    def _save(self):
        if not _HAS_YAML:
            print("[ConfigBridge] Cannot save — PyYAML not installed.")
            return
        try:
            with open(_CONFIG_PATH, "w") as f:
                _yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
        except Exception as e:
            print(f"[ConfigBridge] Failed to write {_CONFIG_PATH}: {e}")

    # ── Convenience accessors ─────────────────────────────────────────────────
    @property
    def dumpit_path(self) -> str:
        raw = self.get("acquisition.dumpit_path", "tools/DumpIt.exe")
        return _resolve_project_path(raw, "tools/DumpIt.exe", allow_external_absolute=True)

    @property
    def output_dir(self) -> str:
        raw = self.get("acquisition.output_dir", "dumps/")
        return _resolve_project_path(raw, "dumps/")

    @property
    def models_dir(self) -> str:
        raw = self.get("paths.models_dir", "models/")
        return _resolve_project_path(raw, "models/")

    @property
    def reports_dir(self) -> str:
        raw = self.get("paths.reports_dir", "reports/")
        return _resolve_project_path(raw, "reports/")

    @property
    def rf_model_path(self) -> str:
        raw = self.get("ml.rf_model_path", "models/random_forest.pkl")
        return _resolve_project_path(raw, "models/random_forest.pkl")

    @property
    def ae_model_path(self) -> str:
        raw = self.get("ml.ae_model_path", "models/autoencoder.pkl")
        return _resolve_project_path(raw, "models/autoencoder.pkl")

    @property
    def feature_mapper_path(self) -> str:
        raw = self.get("ml.feature_mapper_path", "models/feature_mapper.pkl")
        return _resolve_project_path(raw, "models/feature_mapper.pkl")

    @property
    def ae_threshold(self) -> float:
        return float(self.get("ml.ae_threshold", 0.004))

    @property
    def rf_weight(self) -> float:
        return float(self.get("ml.rf_weight", 0.6))

    @property
    def ae_weight(self) -> float:
        return float(self.get("ml.ae_weight", 0.4))


# Module-level singleton
Config = _ConfigBridge()
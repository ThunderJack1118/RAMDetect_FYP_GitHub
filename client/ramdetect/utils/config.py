"""
ramdetect/utils/config.py
=========================
Configuration management for RAMDetect
"""

import yaml
from pathlib import Path
from typing import Any, Dict, Optional
import os


class ConfigManager:
    """
    Manages RAMDetect configuration from YAML file
    """
    
    _instance = None
    _config = None
    
    def __new__(cls):
        """Singleton: return the same instance every time"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to config.yaml file
        """
        # Only initialize once
        if self._config is not None:
            return  # Already initialized

        if config_path is None:
            # Look for config.yaml in current directory or parent
            config_path = self._find_config_file()
        
        self.config_path = Path(config_path)
        self._load_config()
        self._create_directories()
    
    def _find_config_file(self) -> str:
        """Find config.yaml in current or parent directories"""
        search_paths = [
            Path.cwd() / "config.yaml",
            Path(__file__).parent.parent.parent / "config.yaml",
            Path.home() / ".ramdetect" / "config.yaml",
        ]
        
        for path in search_paths:
            if path.exists():
                return str(path)
        
        # Return default path if not found
        return str(Path.cwd() / "config.yaml")
    
    def _load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f)
        
        # Expand environment variables in paths
        self._expand_env_vars(self._config)
    
    def _expand_env_vars(self, config_dict: Dict):
        """Recursively expand environment variables in config"""
        for key, value in config_dict.items():
            if isinstance(value, dict):
                self._expand_env_vars(value)
            elif isinstance(value, str):
                config_dict[key] = os.path.expandvars(value)
    
    def _create_directories(self):
        """Create necessary directories from paths configuration"""
        paths = self._config.get('paths', {})
        
        for key, path in paths.items():
            if key.endswith('_dir'):
                Path(path).mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'ml.random_forest.n_estimators')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, output_path: Optional[str] = None):
        """
        Save configuration to YAML file
        
        Args:
            output_path: Optional output path (defaults to original config path)
        """
        save_path = Path(output_path) if output_path else self.config_path
        
        with open(save_path, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config()
    
    @property
    def config(self) -> Dict:
        """Get entire configuration dictionary"""
        return self._config
    
    # Convenience methods for common config access
    
    def get_path(self, path_key: str) -> Path:
        """Get path from paths configuration"""
        path_str = self.get(f'paths.{path_key}')
        if path_str:
            return Path(path_str)
        raise KeyError(f"Path '{path_key}' not found in configuration")
    
    def get_ml_config(self, model_name: str) -> Dict:
        """Get ML model configuration"""
        return self.get(f'ml.{model_name}', {})
    
    def get_feature_config(self) -> Dict:
        """Get feature engineering configuration"""
        return self.get('features', {})
    
    def get_volatility_exceptions(self) -> Dict[str, Any]:
        """Return the documented Volatility exception policy.

        RAMDetect is not configured as a broad Volatility plugin wrapper.
        Volatility-assisted support is limited to the explicitly documented
        exceptions:
          1. handle enumeration via windows.handles
          2. DTB / OS profile metadata resolution via windows.info.Info
        """
        return self.get('volatility_exceptions', {})

    def get_volatility_plugins(self) -> list:
        """Backward-compatible helper returning only allowed exception plugins.

        Older scripts may still call this method, but RAMDetect no longer uses
        a broad Volatility plugin pipeline. Return only the allowed plugin names
        from volatility_exceptions.allowed_components.
        """
        exceptions = self.get_volatility_exceptions()
        components = exceptions.get('allowed_components', {}) if isinstance(exceptions, dict) else {}
        plugins = []
        for cfg in components.values():
            if isinstance(cfg, dict) and cfg.get('enabled', True):
                plugin = cfg.get('allowed_plugin')
                if plugin:
                    plugins.append(plugin)
        return plugins
    
    def get_report_formats(self) -> Dict[str, bool]:
        """Get enabled report formats"""
        return self.get('reporting.formats', {})
    
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get('advanced.debug_mode', False)
    
    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging.level', 'INFO')


# Singleton instance
_config_manager = None


def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get configuration manager instance
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()               # Create instance without args
        _config_manager.__init__(config_path)           # Explicitly call __init__ with config_path
    return _config_manager


# Example usage
if __name__ == "__main__":
    # Load configuration
    config = get_config()
    
    # Access configuration
    print(f"Application Name: {config.get('app.name')}")
    print(f"Version: {config.get('app.version')}")
    print(f"Dumps Directory: {config.get_path('dumps_dir')}")
    print(f"Random Forest Trees: {config.get('ml.random_forest.n_estimators')}")
    print(f"Volatility Exceptions: {config.get_volatility_exceptions()}")
    print(f"Allowed Exception Plugins: {config.get_volatility_plugins()}")
    
    # Modify and save
    config.set('ml.random_forest.n_estimators', 300)
    config.save('config_modified.yaml')
    
    print("\n✅ Configuration loaded and tested successfully!")
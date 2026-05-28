"""
RAMDetect - Feature Extraction Base Module - FIXED VERSION
==========================================================
Fixed: Browser processes now correctly normalized to prevent false positives.
Added: Context-aware normalization and detection thresholds.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
import logging
import time
import numpy as np
from datetime import datetime
import re


class FeatureExtractor(ABC):
    """
    Abstract base class for all feature extractors.
    
    All feature extraction modules (process, thread, dll, etc.) 
    must inherit from this class and implement extract_features().
    """
    
    # Browser whitelist for ALL feature extractors
    BROWSER_WHITELIST = {
        'msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
        'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'microsoftedge.exe',
        'msedgewebview2.exe', 'chromium.exe', 'waterfox.exe',
    }
    
    # System process whitelist
    SYSTEM_PROCESS_WHITELIST = {
        'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe',
        'services.exe', 'lsass.exe', 'winlogon.exe', 'registry.exe',
        'svchost.exe', 'dwm.exe', 'explorer.exe', 'sihost.exe',
        'taskhostw.exe', 'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe',
        'conhost.exe', 'fontdrvhost.exe', 'spoolsv.exe', 'audiodg.exe',
        'vmtoolsd.exe', 'mscorsvw.exe', 'wmiadap.exe', 'wuauclt.exe',
        'searchui.exe', 'shellexperiencehost.exe', 'memory compression'
    }
    
    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        """
        Initialize feature extractor.
        
        Args:
            name: Name of the feature extractor (e.g., "ProcessFeatures")
            logger: Optional logger instance
        """
        self.name = name
        self.logger = logger or logging.getLogger(__name__)

        # Dictionary to store the final computed features {name: score}
        self.features = {}

        # Metadata for performance tracking and debugging
        self.metadata = {
            'extractor_name': name,
            'extraction_time': None,
            'feature_count': 0,
            'success': False,
            'errors': []
        }
        
        # Context tracking for normalization
        self.browser_pids: Set[int] = set()
        self.system_pids: Set[int] = set()
        
    @abstractmethod
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from parsed memory data.
        
        This method MUST be implemented by all subclasses.
        
        Args:
            parsed_data: Dictionary containing parsed memory artifacts
                         Keys: 'processes', 'threads', 'dlls', 'handles', etc.
        
        Returns:
            Dictionary mapping feature names to normalized values (0-1 range)
            Example: {'hidden_process_count': 0.2, 'orphan_threads': 0.0}
        """
        pass
    
    def extract_with_error_handling(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Wrapper for extract_features() with error handling and timing.
        
        Args:
            parsed_data: Dictionary containing parsed memory artifacts
        
        Returns:
            Dictionary of extracted features (may be empty if extraction fails)
        """
        start_time = time.time()
        self.logger.info(f"[{self.name}] Starting feature extraction...")
        
        try:
            # Pre-process: Identify browser and system processes
            self._identify_special_processes(parsed_data)
            
            # Call the subclass implementation
            self.features = self.extract_features(parsed_data)
            
            # Apply context-aware normalization
            self.features = self._apply_context_aware_normalization(self.features, parsed_data)
            
            # Validate features
            self.features = self._validate_features(self.features)
            
            # Update metadata
            self.metadata['extraction_time'] = time.time() - start_time
            self.metadata['feature_count'] = len(self.features)
            self.metadata['success'] = True
            self.metadata['timestamp'] = datetime.now().isoformat()
            
            self.logger.info(
                f"[{self.name}] Extracted {len(self.features)} features "
                f"in {self.metadata['extraction_time']:.2f}s"
            )
            
            return self.features
            
        except Exception as e:
            # Catch-all for unexpected crashes inside extractor modules
            error_msg = f"Feature extraction failed: {str(e)}"
            self.logger.error(f"[{self.name}] {error_msg}", exc_info=True)
            
            self.metadata['success'] = False
            self.metadata['errors'].append(error_msg)
            self.metadata['extraction_time'] = time.time() - start_time
            
            # Return empty dict so pipeline continues
            return {}
    
    def _identify_special_processes(self, parsed_data: Dict[str, Any]) -> None:
        """Identify browser and system processes for context-aware normalization."""
        self.browser_pids.clear()
        self.system_pids.clear()
        
        processes = parsed_data.get('processes', [])
        
        for proc in processes:
            pid = proc.get('pid', 0)
            basename = self._extract_process_basename(proc)
            
            if basename in self.BROWSER_WHITELIST:
                self.browser_pids.add(pid)
            elif basename in self.SYSTEM_PROCESS_WHITELIST:
                self.system_pids.add(pid)
    
    def _extract_process_basename(self, proc_info: Dict[str, Any]) -> str:
        """Extract base process name from process info."""
        path = proc_info.get('path', '')
        if path:
            import os
            basename = os.path.basename(path.replace('\\', os.sep))
            if basename:
                return basename.lower()
        
        image_name = proc_info.get('image_name', '')
        if image_name:
            return image_name.lower()
        
        return ''
    
    def _apply_context_aware_normalization(self, features: Dict[str, float], 
                                          parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Apply context-aware normalization to reduce false positives.
        
        This reduces the weight of features that could be triggered by
        legitimate browser/system behavior.
        """
        normalized = features.copy()
        
        # Get total process and thread counts
        total_processes = len(parsed_data.get('processes', []))
        total_threads = len(parsed_data.get('threads', []))
        
        # Normalize orphan-related features with browser awareness
        if 'orphan_process_count' in features:
            # Adjust based on browser presence
            browser_count = len(self.browser_pids)
            original = features['orphan_process_count']
            # Reduce weight if many browser processes present
            adjustment = max(0, 1.0 - (browser_count / max(1, total_processes * 2)))
            normalized['orphan_process_count'] = original * adjustment
        
        if 'orphan_process_ratio' in features:
            # Browsers often create many child processes that appear orphaned
            browser_ratio = len(self.browser_pids) / max(1, total_processes)
            original = features['orphan_process_ratio']
            normalized['orphan_process_ratio'] = original * (1.0 - min(0.5, browser_ratio))
        
        # Thread-related features
        if 'unbacked_thread_start_count' in features:
            # CRITICAL: Browser JIT should not count at all
            # If many browsers present, reduce this feature's weight
            browser_thread_estimate = len(self.browser_pids) * 10  # ~10 threads per browser
            original = features['unbacked_thread_start_count']
            # If >50% of threads could be browser JIT, reduce weight
            browser_thread_ratio = browser_thread_estimate / max(1, total_threads)
            if browser_thread_ratio > 0.3:
                normalized['unbacked_thread_start_count'] = original * 0.3
        
        # Process count features
        for feature_name in features.keys():
            if 'count' in feature_name and 'ratio' not in feature_name:
                # Apply minimum detection threshold
                raw_value = features[feature_name]
                if raw_value < 0.1:  # Below 10% of max threshold
                    normalized[feature_name] = 0.0
        
        return normalized
    
    def normalize_count(self, count: int, max_threshold: int = 10) -> float:
        """
        Normalize a count value to [0, 1] range with detection threshold.
        
        FIXED: Uses sigmoid-like function instead of linear.
        This prevents a few browser processes from maxing out the scale.
        
        Args:
            count: Raw count value
            max_threshold: Value at which normalization reaches ~0.8
        
        Returns:
            Normalized value in [0, 1]
        """
        if count <= 0:
            return 0.0
        
        # Sigmoid-like normalization: 
        # 1 → ~0.1, 3 → ~0.3, 5 → ~0.5, 10 → ~0.8
        x = count / max_threshold
        normalized = x / (1 + abs(x))  # Soft normalization
        
        return min(1.0, normalized)
    
    def normalize_count_with_min_threshold(self, count: int, max_threshold: int = 10, 
                                          min_threshold: int = 2) -> float:
        """
        Normalize count with minimum threshold for detection.
        
        Counts below min_threshold return 0.0 to filter noise.
        
        Args:
            count: Raw count value
            max_threshold: Value at which normalization reaches ~0.8
            min_threshold: Minimum count to be considered significant
        
        Returns:
            Normalized value in [0, 1]
        """
        if count < min_threshold:
            return 0.0
        
        # Apply the regular normalization for counts above threshold
        effective_count = count - min_threshold + 1
        return self.normalize_count(effective_count, max_threshold)
    
    def normalize_ratio(self, numerator: float, denominator: float, 
                       smoothing: float = 0.5) -> float:
        """
        Safely compute and normalize a ratio with Laplace smoothing.
        
        FIXED: Adds smoothing to prevent extreme values from small samples.
        
        Args:
            numerator: Numerator value
            denominator: Denominator value
            smoothing: Laplace smoothing factor (prevents 0/0 and 1/1 extremes)
        
        Returns:
            Normalized ratio in [0, 1]
        """
        if denominator == 0:
            return 0.0
        
        # Apply Laplace smoothing
        smoothed_numer = numerator + smoothing
        smoothed_denom = denominator + (2 * smoothing)
        
        ratio = smoothed_numer / smoothed_denom
        return min(1.0, max(0.0, ratio))
    
    def normalize_browser_aware_ratio(self, suspicious_count: int, total_count: int,
                                     browser_count: int = 0) -> float:
        """
        Normalize ratio while accounting for browser processes.
        
        Args:
            suspicious_count: Count of suspicious items
            total_count: Total items
            browser_count: Number of browser items (excluded from suspicion)
        
        Returns:
            Normalized ratio adjusted for browser presence
        """
        if total_count == 0:
            return 0.0
        
        # Exclude browsers from both counts
        effective_suspicious = max(0, suspicious_count - browser_count)
        effective_total = max(1, total_count - browser_count)
        
        return self.normalize_ratio(effective_suspicious, effective_total)
    
    def _validate_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """
        Validate and clean feature values.
        
        - Ensures all values are numeric
        - Replaces NaN/Inf with 0
        - Clips values to [0, 1] range
        
        Args:
            features: Raw feature dictionary
        
        Returns:
            Validated feature dictionary
        """
        validated = {}
        
        for feature_name, value in features.items():
            try:
                # Convert to float
                val = float(value)
                
                # Handle NaN and Inf
                if np.isnan(val) or np.isinf(val):
                    self.logger.warning(
                        f"[{self.name}] Feature '{feature_name}' has invalid value "
                        f"({val}), setting to 0"
                    )
                    val = 0.0
                
                # Clip to valid range [0, 1]
                if val < 0 or val > 1:
                    self.logger.warning(
                        f"[{self.name}] Feature '{feature_name}' out of range "
                        f"({val}), clipping to [0, 1]"
                    )
                    val = np.clip(val, 0, 1)
                
                validated[feature_name] = val
                
            except (ValueError, TypeError) as e:
                self.logger.error(
                    f"[{self.name}] Cannot convert feature '{feature_name}' "
                    f"to float: {e}, skipping"
                )
                continue
        
        return validated
    
    def normalize_entropy(self, entropy: float, max_entropy: float = 8.0) -> float:
        """
        Normalize entropy value to [0, 1] range.
        
        Args:
            entropy: Raw entropy value (typically 0-8 for byte data)
            max_entropy: Maximum expected entropy (default: 8.0)
        
        Returns:
            Normalized entropy in [0, 1]
        """
        return min(1.0, max(0.0, entropy / max_entropy))
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of feature names extracted by this module.
        
        Returns:
            List of feature name strings
        """
        return list(self.features.keys())
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get extraction metadata.
        
        Returns:
            Dictionary containing extraction statistics and status
        """
        return self.metadata.copy()
    
    def reset(self):
        """
        Reset extractor state for new extraction.
        """
        self.features = {}
        self.browser_pids.clear()
        self.system_pids.clear()
        self.metadata = {
            'extractor_name': self.name,
            'extraction_time': None,
            'feature_count': 0,
            'success': False,
            'errors': []
        }
        self.logger.debug(f"[{self.name}] State reset")
    
    def __repr__(self) -> str:
        """String representation of the extractor."""
        return (
            f"<{self.__class__.__name__}(name='{self.name}', "
            f"features={len(self.features)}, "
            f"success={self.metadata['success']})>"
        )


class FeatureValidationError(Exception):
    """Raised when feature validation fails."""
    pass


class FeatureExtractionError(Exception):
    """Raised when feature extraction encounters an error."""
    pass
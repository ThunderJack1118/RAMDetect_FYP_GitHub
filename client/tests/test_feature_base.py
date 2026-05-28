"""
tests/test_feature_base.py
=============================
Unit Test for the Feature Extraction Base Class.
Verifies normalization, validation, and error handling logic.
"""

import sys
import os
import logging
from pathlib import Path
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ramdetect.features.feature_base import FeatureExtractor

# Configure logging
logging.basicConfig(level=logging.INFO)

# ============================================================================
# 1. CREATE A MOCK EXTRACTOR
# ============================================================================
class MockProcessExtractor(FeatureExtractor):
    """
    A dummy implementation to test the base class logic.
    Simulates extracting features from a process list.
    """
    
    def extract_features(self, parsed_data: dict) -> dict:
        print(f"   [MockExtractor] Receiving data keys: {list(parsed_data.keys())}")
        
        # Simulate processing logic
        processes = parsed_data.get('processes', [])
        process_count = len(processes)
        
        # 1. Test Normalization Helpers
        hidden_count = parsed_data.get('hidden_count', 0)
        entropy_val = parsed_data.get('entropy', 0.0)
        
        features = {
            # Test Count Normalization (10 is threshold)
            'proc_hidden_ratio': self.normalize_count(hidden_count, max_threshold=10),
            
            # Test Ratio Normalization
            'proc_ratio': self.normalize_ratio(hidden_count, process_count),
            
            # Test Entropy Normalization
            'proc_entropy': self.normalize_entropy(entropy_val),
            
            # Test Validation Logic (These should be fixed by _validate_features)
            'invalid_high': 999.0,         # Should be clipped to 1.0
            'invalid_low': -5.0,           # Should be clipped to 0.0
            'invalid_nan': float('nan'),   # Should be converted to 0.0
            'invalid_inf': float('inf'),   # Should be converted to 0.0
        }
        
        return features

# ============================================================================
# 2. RUN THE TEST
# ============================================================================
def run_test():
    print("RAMDetect - Feature Base Class Test")
    print("===================================")
    
    # Initialize
    extractor = MockProcessExtractor(name="TestEngine")
    
    # Mock Data Input
    mock_data = {
        'processes': ['p1', 'p2', 'p3', 'p4', 'p5'], # 5 processes
        'hidden_count': 2,                           # 2 hidden
        'entropy': 7.5                               # High entropy
    }
    
    print("\n1. Running Extraction...")
    features = extractor.extract_with_error_handling(mock_data)
    
    # Verification
    print("\n2. Verifying Results:")
    print("-" * 50)
    print(f"{'Feature Name':<20} | {'Raw Value (Simulated)':<20} | {'Final Value'}")
    print("-" * 50)
    
    # Expected behavior
    checks = [
        ('proc_hidden_ratio', 2/10, features['proc_hidden_ratio']), # 0.2
        ('proc_ratio', 2/5, features['proc_ratio']),                # 0.4
        ('proc_entropy', 7.5/8.0, features['proc_entropy']),        # 0.9375
        ('invalid_high', 1.0, features['invalid_high']),            # Clipped
        ('invalid_low', 0.0, features['invalid_low']),              # Clipped
        ('invalid_nan', 0.0, features['invalid_nan']),              # Zeroed
    ]
    
    all_passed = True
    for name, expected, actual in checks:
        status = "✅ PASS" if abs(expected - actual) < 0.001 else "❌ FAIL"
        print(f"{name:<20} | {expected:<20} | {actual:<10.4f} {status}")
        if "FAIL" in status: all_passed = False
            
    print("-" * 50)
    
    # Metadata Check
    meta = extractor.get_metadata()
    print("\n3. Metadata Check:")
    print(f"   Success: {meta['success']}")
    print(f"   Time Taken: {meta['extraction_time']:.6f} sec")
    
    if all_passed and meta['success']:
        print("\n🎉 SUCCESS: Base class is robust and ready for implementation.")
    else:
        print("\n⚠️  WARNING: Base class logic needs review.")

if __name__ == "__main__":
    run_test()
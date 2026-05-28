"""
RAMDetect - ML-Powered RAM Forensics Analysis Tool
===================================================

RAMDetect combines Volatility 3's robust parsing capabilities with
custom feature engineering and hybrid machine learning to automatically
detect malware in RAM dumps.

Author: Your Name
Version: 1.0.0
License: MIT
"""

__version__ = '1.0.0'
__author__ = 'Your Name'
__license__ = 'MIT'

# Import main components for easy access
from ramdetect.utils.logger import get_logger
from ramdetect.utils.config import get_config

__all__ = [
    'get_logger',
    'get_config',
    '__version__',
]
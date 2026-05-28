"""
ramdetect.acquisition
=====================
RAM memory acquisition module

This module handles the acquisition of RAM dumps using multiple tools
(DumpIt, WinPmem) and manages associated metadata.
"""

from .dumpit import DumpItAcquisition
from .metadata import MetadataManager

__all__ = [
    'DumpItAcquisition',
    'WinPmemAcquisition', 
]

__version__ = '1.0.0'
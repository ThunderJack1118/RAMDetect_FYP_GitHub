"""
ramdetect.extraction.parsers
============================
Custom RAM parsing engines for advanced forensic analysis

Engines 1-6 Complete:
- Engine 1: Physical Memory Reader (mmap-based)
- Engine 2: Address Translator (virtual→physical, caching)
- Engine 3: EPROCESS Scanner (pool + list walking)
- Engine 4: Thread Parser (ETHREAD enumeration)
- Engine 5: DLL Parser (PEB→Ldr→Module walking)
- Engine 6: Handle Parser (handle table analysis)
"""

from .memory_reader import PhysicalMemoryReader
from .address_translator import AddressTranslator
from .eprocess_scanner import EProcessScanner
from .thread_parser import ThreadParser
from .dll_parser import DLLParser
from .handle_parser import HandleParser

__all__ = [
    'PhysicalMemoryReader',
    'AddressTranslator',
    'EProcessScanner',
    'ThreadParser',
    'DLLParser',
    'HandleParser',
]

__version__ = '1.0.0'
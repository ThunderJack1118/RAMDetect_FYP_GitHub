"""
tests/test_parsers.py
=====================
Unit tests for custom parsing engines
"""

import pytest
import tempfile
from pathlib import Path
import struct

from ramdetect.extraction.parsers import (
    PhysicalMemoryReader,
    AddressTranslator,
    EProcessScanner,
)


class TestPhysicalMemoryReader:
    """Tests for Physical Memory Reader"""
    
    @pytest.fixture
    def temp_dump(self):
        """Create temporary test dump"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dmp') as f:
            # Write 10MB of test data
            test_data = b'TEST' * (10 * 1024 * 1024 // 4)
            f.write(test_data)
            f.flush()
            yield Path(f.name)
        
        Path(f.name).unlink()
    
    def test_initialization(self, temp_dump):
        """Test reader initialization"""
        with PhysicalMemoryReader(str(temp_dump)) as reader:
            assert reader.file_size == 10 * 1024 * 1024
            assert reader.chunk_size == 1024 * 1024
    
    def test_read_physical(self, temp_dump):
        """Test reading from physical address"""
        with PhysicalMemoryReader(str(temp_dump)) as reader:
            data = reader.read_physical(0, 4)
            assert data == b'TEST'
    
    def test_read_uint32(self, temp_dump):
        """Test reading uint32"""
        with PhysicalMemoryReader(str(temp_dump)) as reader:
            # Write known value
            with open(temp_dump, 'r+b') as f:
                f.write(struct.pack('<I', 0x12345678))
            
            value = reader.read_uint32(0)
            assert value == 0x12345678
    
    def test_search_pattern(self, temp_dump):
        """Test pattern searching"""
        with PhysicalMemoryReader(str(temp_dump)) as reader:
            # Search for 'TEST' pattern
            offsets = reader.scan_pattern(b'TEST')
            assert len(offsets) > 0


class TestAddressTranslator:
    """Tests for Address Translator"""
    
    @pytest.fixture
    def test_memory(self):
        """Create test memory with mock page tables"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dmp') as f:
            # Create 16MB test dump
            size = 16 * 1024 * 1024
            f.write(b'\x00' * size)
            f.flush()
            
            # Write mock PML4 entry at DTB
            dtb = 0x1000
            f.seek(dtb)
            # PML4 entry pointing to PDPT at 0x2000 (present)
            f.write(struct.pack('<Q', 0x2001))  # 0x2000 | PRESENT
            
            # Write mock PDPT entry
            f.seek(0x2000)
            # PDPT entry pointing to PD at 0x3000 (present)
            f.write(struct.pack('<Q', 0x3001))
            
            # Write mock PD entry
            f.seek(0x3000)
            # PD entry pointing to PT at 0x4000 (present)
            f.write(struct.pack('<Q', 0x4001))
            
            # Write mock PT entry
            f.seek(0x4000)
            # PT entry pointing to physical page at 0x5000 (present)
            f.write(struct.pack('<Q', 0x5001))
            
            f.flush()
            yield Path(f.name), dtb
        
        Path(f.name).unlink()
    
    def test_initialization(self, test_memory):
        """Test translator initialization"""
        dump_path, dtb = test_memory
        
        with PhysicalMemoryReader(str(dump_path)) as reader:
            translator = AddressTranslator(reader, dtb, is_64bit=True)
            
            assert translator.dtb == dtb
            assert translator.is_64bit == True
    
    def test_cache(self, test_memory):
        """Test translation caching"""
        dump_path, dtb = test_memory
        
        with PhysicalMemoryReader(str(dump_path)) as reader:
            translator = AddressTranslator(reader, dtb)
            
            # First translation (miss)
            result1 = translator.vtop(0xFFFF800000000000)
            stats1 = translator.get_cache_stats()
            assert stats1['cache_misses'] == 1
            
            # Second translation (hit)
            result2 = translator.vtop(0xFFFF800000000000)
            stats2 = translator.get_cache_stats()
            assert stats2['cache_hits'] == 1
            assert result1 == result2
    
    def test_kernel_address_detection(self, test_memory):
        """Test kernel address detection"""
        dump_path, dtb = test_memory
        
        with PhysicalMemoryReader(str(dump_path)) as reader:
            translator = AddressTranslator(reader, dtb)
            
            # x64 kernel address
            assert translator.is_kernel_address(0xFFFF800000000000) == True
            
            # x64 user address
            assert translator.is_user_address(0x000000007FFE0000) == True
    
    def test_bulk_translation(self, test_memory):
        """Test bulk address translation"""
        dump_path, dtb = test_memory
        
        with PhysicalMemoryReader(str(dump_path)) as reader:
            translator = AddressTranslator(reader, dtb)
            
            addresses = [
                0xFFFF800000000000,
                0xFFFF800000001000,
                0xFFFF800000002000,
            ]
            
            results = translator.vtop_bulk(addresses)
            assert len(results) == 3


class TestEProcessScanner:
    """Tests for EPROCESS Scanner"""
    
    @pytest.fixture
    def test_dump_with_processes(self):
        """Create test dump with mock EPROCESS structures"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dmp') as f:
            # Create 50MB test dump
            size = 50 * 1024 * 1024
            f.write(b'\x00' * size)
            
            # Write mock EPROCESS at offset 0x10000
            eprocess_offset = 0x10000
            
            # Write pool header with 'Proc' tag
            f.seek(eprocess_offset - 0x10)
            f.write(b'\x00' * 4)  # Pool header
            f.write(b'Proc')      # Pool tag
            f.write(b'\x00' * 8)  # Rest of header
            
            # Write EPROCESS fields (Win10_2004 offsets)
            f.seek(eprocess_offset + 0x440)  # UniqueProcessId
            f.write(struct.pack('<Q', 1234))  # PID = 1234
            
            f.seek(eprocess_offset + 0x570)  # InheritedFromUniqueProcessId
            f.write(struct.pack('<Q', 4))     # PPID = 4 (System)
            
            f.seek(eprocess_offset + 0x5a8)  # ImageFileName
            f.write(b'test.exe\x00')          # Process name
            
            f.seek(eprocess_offset + 0x550)  # Peb
            f.write(struct.pack('<Q', 0x7FFE0000))  # PEB address
            
            f.flush()
            yield Path(f.name)
        
        Path(f.name).unlink()
    
    def test_scanner_initialization(self, test_dump_with_processes):
        """Test scanner initialization"""
        with PhysicalMemoryReader(str(test_dump_with_processes)) as reader:
            scanner = EProcessScanner(reader)
            
            assert scanner.version in ['Win10_2004', 'Win11_21H2']
            assert 'UniqueProcessId' in scanner.offsets
    
    def test_pool_tag_scanning(self, test_dump_with_processes):
        """Test pool tag scanning"""
        with PhysicalMemoryReader(str(test_dump_with_processes)) as reader:
            scanner = EProcessScanner(reader)
            
            candidates = scanner.scan_pool_tags()
            assert len(candidates) > 0
    
    def test_eprocess_parsing(self, test_dump_with_processes):
        """Test EPROCESS parsing"""
        with PhysicalMemoryReader(str(test_dump_with_processes)) as reader:
            scanner = EProcessScanner(reader)
            
            # Parse mock EPROCESS at 0x10000
            proc = scanner.parse_eprocess(0x10000)
            
            assert proc is not None
            assert proc['pid'] == 1234
            assert proc['ppid'] == 4
            assert 'test.exe' in proc['image_name']
    
    def test_process_tree_building(self, test_dump_with_processes):
        """Test process tree building"""
        with PhysicalMemoryReader(str(test_dump_with_processes)) as reader:
            scanner = EProcessScanner(reader)
            
            processes = scanner.find_all_processes()
            
            # Check that children lists are added
            for proc in processes:
                assert 'children' in proc
                assert isinstance(proc['children'], list)
    
    def test_statistics(self, test_dump_with_processes):
        """Test scanner statistics"""
        with PhysicalMemoryReader(str(test_dump_with_processes)) as reader:
            scanner = EProcessScanner(reader)
            scanner.find_all_processes()
            
            stats = scanner.get_statistics()
            
            assert 'windows_version' in stats
            assert 'valid_processes' in stats
            assert stats['valid_processes'] >= 0


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
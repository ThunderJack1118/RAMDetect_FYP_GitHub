"""
tests/test_acquisition.py
==========================
Unit tests for RAM acquisition module
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json

from ramdetect.acquisition.dumpit import DumpItAcquisition
from ramdetect.acquisition.metadata import MetadataManager


class TestDumpItAcquisition:
    """Test cases for DumpItAcquisition class"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def mock_dumpit(self, temp_dir):
        """Create mock DumpIt executable"""
        dumpit_path = temp_dir / "DumpIt.exe"
        dumpit_path.touch()
        return dumpit_path
    
    @pytest.fixture
    def mock_config(self, temp_dir, mock_dumpit):
        """Mock configuration"""
        with patch('ramdetect.acquisition.dumpit.get_config') as mock:
            config = Mock()
            config.get_path.side_effect = lambda key: {
                'dumpit_exe': mock_dumpit,
                'dumps_dir': temp_dir / "dumps",
            }.get(key)
            config.get.return_value = {
                'auto_hash': True,
                'hash_algorithms': ['md5', 'sha256'],
                'compress_dumps': False,
                'silent_mode': True,
            }
            mock.return_value = config
            yield config
    
    def test_initialization(self, mock_config):
        """Test DumpItAcquisition initialization"""
        acquisition = DumpItAcquisition()
        
        assert acquisition.dumpit_path.exists()
        assert acquisition.auto_hash is True
        assert 'md5' in acquisition.hash_algorithms
        assert 'sha256' in acquisition.hash_algorithms
    
    def test_generate_dump_filename(self, mock_config):
        """Test dump filename generation"""
        acquisition = DumpItAcquisition()
        filename = acquisition.generate_dump_filename()
        
        assert filename.endswith('.dmp')
        assert '_' in filename  # Should contain timestamp separator
    
    @patch('ramdetect.acquisition.dumpit.is_admin')
    def test_check_prerequisites_no_admin(self, mock_admin, mock_config):
        """Test prerequisites check without admin privileges"""
        mock_admin.return_value = False
        
        acquisition = DumpItAcquisition()
        result = acquisition.check_prerequisites()
        
        assert result is False
    
    @patch('ramdetect.acquisition.dumpit.is_admin')
    @patch('ramdetect.acquisition.dumpit.psutil.disk_usage')
    def test_check_prerequisites_insufficient_space(
        self, mock_disk, mock_admin, mock_config
    ):
        """Test prerequisites check with insufficient disk space"""
        mock_admin.return_value = True
        mock_disk.return_value = Mock(free=1024 * 1024 * 1024)  # 1GB
        
        acquisition = DumpItAcquisition()
        result = acquisition.check_prerequisites()
        
        assert result is False
    
    @patch('ramdetect.acquisition.dumpit.is_admin')
    @patch('ramdetect.acquisition.dumpit.psutil.disk_usage')
    def test_check_prerequisites_success(
        self, mock_disk, mock_admin, mock_config
    ):
        """Test successful prerequisites check"""
        mock_admin.return_value = True
        mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)  # 10GB
        
        acquisition = DumpItAcquisition()
        result = acquisition.check_prerequisites()
        
        assert result is True
    
    def test_list_dumps(self, mock_config, temp_dir):
        """Test listing dumps"""
        # Create test dump files
        dumps_dir = temp_dir / "dumps"
        dumps_dir.mkdir(exist_ok=True)
        
        for i in range(3):
            (dumps_dir / f"test_{i}.dmp").touch()
        
        acquisition = DumpItAcquisition()
        dumps = acquisition.list_dumps()
        
        assert len(dumps) == 3
        assert all(d.suffix == '.dmp' for d in dumps)
    
    def test_verify_dump_file_not_found(self, mock_config, temp_dir):
        """Test dump verification with non-existent file"""
        acquisition = DumpItAcquisition()
        result = acquisition.verify_dump(temp_dir / "nonexistent.dmp")
        
        assert result is False
    
    def test_verify_dump_too_small(self, mock_config, temp_dir):
        """Test dump verification with small file"""
        small_dump = temp_dir / "small.dmp"
        small_dump.write_bytes(b"x" * 1024)  # 1KB file
        
        acquisition = DumpItAcquisition()
        result = acquisition.verify_dump(small_dump)
        
        assert result is False
    
    @patch('ramdetect.acquisition.dumpit.calculate_file_hash')
    def test_verify_dump_hash_mismatch(self, mock_hash, mock_config, temp_dir):
        """Test dump verification with hash mismatch"""
        # Create large enough file
        dump = temp_dir / "test.dmp"
        dump.write_bytes(b"x" * (200 * 1024 * 1024))  # 200MB
        
        mock_hash.return_value = "incorrect_hash"
        
        acquisition = DumpItAcquisition()
        result = acquisition.verify_dump(dump, expected_hash="correct_hash")
        
        assert result is False
    
    def test_get_dump_info(self, mock_config, temp_dir):
        """Test getting dump information"""
        dump = temp_dir / "test.dmp"
        dump.write_bytes(b"x" * 1024)
        
        acquisition = DumpItAcquisition()
        info = acquisition.get_dump_info(dump)
        
        assert 'dump' in info
        assert info['dump']['filename'] == 'test.dmp'
        assert 'size_bytes' in info['dump']


class TestMetadataManager:
    """Test cases for MetadataManager class"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def sample_metadata(self):
        """Sample metadata for testing"""
        return {
            'acquisition': {
                'timestamp': '2024-01-01T12:00:00',
                'duration_seconds': 45.3,
                'tool': 'DumpIt',
            },
            'system': {
                'hostname': 'TEST-PC',
                'platform': 'Windows',
            },
            'dump': {
                'filename': 'test.dmp',
                'size_bytes': 1073741824,
            },
            'hashes': {
                'md5': 'abc123',
                'sha256': 'def456',
            }
        }
    
    def test_save_and_load_metadata(self, temp_dir, sample_metadata):
        """Test saving and loading metadata"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        # Save metadata
        metadata_path = manager.save(sample_metadata, dump_path)
        assert metadata_path.exists()
        assert metadata_path.suffix == '.json'
        
        # Load metadata
        loaded = manager.load(dump_path)
        assert loaded is not None
        assert loaded['acquisition']['tool'] == 'DumpIt'
        assert loaded['system']['hostname'] == 'TEST-PC'
    
    def test_load_nonexistent_metadata(self, temp_dir):
        """Test loading non-existent metadata"""
        manager = MetadataManager()
        dump_path = temp_dir / "nonexistent.dmp"
        
        loaded = manager.load(dump_path)
        assert loaded is None
    
    def test_update_metadata(self, temp_dir, sample_metadata):
        """Test updating existing metadata"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        # Save initial metadata
        manager.save(sample_metadata, dump_path)
        
        # Update
        updates = {
            'analysis': {
                'verdict': 'Clean',
                'confidence': 0.95,
            }
        }
        manager.update(dump_path, updates)
        
        # Load and verify
        updated = manager.load(dump_path)
        assert 'analysis' in updated
        assert updated['analysis']['verdict'] == 'Clean'
    
    def test_get_acquisition_info(self, temp_dir, sample_metadata):
        """Test retrieving acquisition info"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        manager.save(sample_metadata, dump_path)
        
        acq_info = manager.get_acquisition_info(dump_path)
        assert acq_info is not None
        assert acq_info['tool'] == 'DumpIt'
        assert acq_info['duration_seconds'] == 45.3
    
    def test_get_system_info(self, temp_dir, sample_metadata):
        """Test retrieving system info"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        manager.save(sample_metadata, dump_path)
        
        sys_info = manager.get_system_info(dump_path)
        assert sys_info is not None
        assert sys_info['hostname'] == 'TEST-PC'
        assert sys_info['platform'] == 'Windows'
    
    def test_get_hashes(self, temp_dir, sample_metadata):
        """Test retrieving hashes"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        manager.save(sample_metadata, dump_path)
        
        hashes = manager.get_hashes(dump_path)
        assert hashes is not None
        assert hashes['md5'] == 'abc123'
        assert hashes['sha256'] == 'def456'
    
    @patch('ramdetect.acquisition.metadata.calculate_file_hash')
    def test_verify_integrity_success(
        self, mock_hash, temp_dir, sample_metadata
    ):
        """Test successful integrity verification"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.write_bytes(b"x" * 1024)
        
        manager.save(sample_metadata, dump_path)
        
        # Mock hash calculation to return expected values
        mock_hash.side_effect = lambda p, a: sample_metadata['hashes'][a]
        
        result = manager.verify_integrity(dump_path)
        assert result is True
    
    @patch('ramdetect.acquisition.metadata.calculate_file_hash')
    def test_verify_integrity_failure(
        self, mock_hash, temp_dir, sample_metadata
    ):
        """Test failed integrity verification"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.write_bytes(b"x" * 1024)
        
        manager.save(sample_metadata, dump_path)
        
        # Mock hash to return wrong values
        mock_hash.return_value = "wrong_hash"
        
        result = manager.verify_integrity(dump_path)
        assert result is False
    
    def test_export_summary(self, temp_dir, sample_metadata):
        """Test exporting metadata summary"""
        manager = MetadataManager()
        dump_path = temp_dir / "test.dmp"
        dump_path.touch()
        
        manager.save(sample_metadata, dump_path)
        
        summary = manager.export_summary(dump_path)
        assert 'TEST-PC' in summary
        assert 'DumpIt' in summary
        assert 'abc123' in summary
    
    def test_list_all_metadata(self, temp_dir, sample_metadata):
        """Test listing all metadata"""
        manager = MetadataManager()
        
        # Create multiple dumps with metadata
        for i in range(3):
            dump_path = temp_dir / f"test_{i}.dmp"
            dump_path.touch()
            manager.save(sample_metadata, dump_path)
        
        all_metadata = manager.list_all_metadata(temp_dir)
        assert len(all_metadata) == 3
        assert all('_dump_path' in m for m in all_metadata)
    
    def test_clean_orphaned_metadata(self, temp_dir, sample_metadata):
        """Test cleaning orphaned metadata files"""
        manager = MetadataManager()
        
        # Create metadata without corresponding dump
        orphan_path = temp_dir / "orphan.json"
        with open(orphan_path, 'w') as f:
            json.dump(sample_metadata, f)
        
        # Create valid dump with metadata
        valid_dump = temp_dir / "valid.dmp"
        valid_dump.touch()
        manager.save(sample_metadata, valid_dump)
        
        # Clean orphaned
        removed = manager.clean_orphaned_metadata(temp_dir)
        
        assert removed == 1
        assert not orphan_path.exists()
        assert (temp_dir / "valid.json").exists()


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])
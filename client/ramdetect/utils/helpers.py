"""
ramdetect/utils/helpers.py
==========================
Utility helper functions for RAMDetect
"""

import hashlib
import json
from pathlib import Path
from typing import Union, Dict, List, Any
from datetime import datetime
import psutil


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hexadecimal hash string
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Select hash algorithm
    if algorithm.lower() == "md5":
        hasher = hashlib.md5()
    elif algorithm.lower() == "sha1":
        hasher = hashlib.sha1()
    elif algorithm.lower() == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Calculate hash in chunks
    chunk_size = 8192
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes to human-readable string
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def format_timestamp(timestamp: Union[datetime, float, int] = None) -> str:
    """
    Format timestamp to ISO 8601 string
    
    Args:
        timestamp: Datetime object, Unix timestamp, or None for current time
        
    Returns:
        ISO 8601 formatted string
    """
    if timestamp is None:
        dt = datetime.now()
    elif isinstance(timestamp, (int, float)):
        dt = datetime.fromtimestamp(timestamp)
    else:
        dt = timestamp
    
    return dt.isoformat()


def get_file_metadata(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get comprehensive file metadata
    
    Args:
        file_path: Path to file
        
    Returns:
        Dictionary with metadata
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    stat = file_path.stat()
    
    return {
        'name': file_path.name,
        'path': str(file_path.absolute()),
        'size': stat.st_size,
        'size_formatted': format_bytes(stat.st_size),
        'created': format_timestamp(stat.st_ctime),
        'modified': format_timestamp(stat.st_mtime),
        'accessed': format_timestamp(stat.st_atime),
        'md5': calculate_file_hash(file_path, 'md5'),
        'sha256': calculate_file_hash(file_path, 'sha256'),
    }


def save_json(data: Any, output_path: Union[str, Path], indent: int = 2):
    """
    Save data to JSON file
    
    Args:
        data: Data to save
        output_path: Output file path
        indent: JSON indentation
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, default=str, ensure_ascii=False)


def load_json(file_path: Union[str, Path]) -> Any:
    """
    Load data from JSON file
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Loaded data
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_system_info() -> Dict[str, Any]:
    """
    Get system information
    
    Returns:
        Dictionary with system details
    """
    return {
        'hostname': psutil.os.uname().nodename,
        'platform': psutil.os.name,
        'cpu_count': psutil.cpu_count(),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_total': format_bytes(psutil.virtual_memory().total),
        'memory_available': format_bytes(psutil.virtual_memory().available),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_total': format_bytes(psutil.disk_usage('/').total),
        'disk_free': format_bytes(psutil.disk_usage('/').free),
        'disk_percent': psutil.disk_usage('/').percent,
    }


def validate_dump_file(dump_path: Union[str, Path]) -> bool:
    """
    Validate if file is a valid memory dump
    
    Args:
        dump_path: Path to dump file
        
    Returns:
        True if valid, False otherwise
    """
    dump_path = Path(dump_path)
    
    # Check file exists
    if not dump_path.exists():
        return False
    
    # Check file size (dumps should be > 100MB typically)
    min_size = 100 * 1024 * 1024  # 100MB
    if dump_path.stat().st_size < min_size:
        return False
    
    # Check file extension
    valid_extensions = ['.dmp', '.raw', '.mem', '.vmem', '.dump']
    if dump_path.suffix.lower() not in valid_extensions:
        return False
    
    # TODO: Add more validation (magic bytes, headers, etc.)
    
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:255 - len(ext) - 1] + '.' + ext if ext else name[:255]
    
    return filename


def create_directory_structure(base_path: Union[str, Path], structure: Dict[str, Any]):
    """
    Create directory structure from nested dictionary
    
    Args:
        base_path: Base directory path
        structure: Dictionary representing directory structure
    """
    base_path = Path(base_path)
    base_path.mkdir(parents=True, exist_ok=True)
    
    for name, content in structure.items():
        path = base_path / name
        
        if isinstance(content, dict):
            # Create subdirectory
            create_directory_structure(path, content)
        else:
            # Create file
            path.parent.mkdir(parents=True, exist_ok=True)
            if content is not None:
                with open(path, 'w') as f:
                    f.write(content)
            else:
                path.touch()


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Deep merge two dictionaries
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (overwrites dict1)
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result


def chunks(lst: List, chunk_size: int):
    """
    Split list into chunks
    
    Args:
        lst: List to split
        chunk_size: Size of each chunk
        
    Yields:
        Chunks of the list
    """
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def is_admin() -> bool:
    """
    Check if script is running with admin/root privileges
    
    Returns:
        True if admin, False otherwise
    """
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        # Linux/Mac
        import os
        return os.geteuid() == 0


# Example usage
if __name__ == "__main__":
    print("Testing helper functions...")
    
    # Test hash calculation
    test_file = Path(__file__)
    print(f"\nFile: {test_file.name}")
    print(f"SHA256: {calculate_file_hash(test_file, 'sha256')}")
    
    # Test byte formatting
    print(f"\nFormatted size: {format_bytes(1536000000)}")
    
    # Test system info
    print(f"\nSystem Info:")
    for key, value in get_system_info().items():
        print(f"  {key}: {value}")
    
    # Test admin check
    print(f"\nRunning as admin: {is_admin()}")
    
    print("\n✅ All helper functions tested!")
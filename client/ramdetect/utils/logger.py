"""
ramdetect/utils/logger.py
=========================
Centralized logging configuration for RAMDetect
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
import coloredlogs


class RAMDetectLogger:
    """
    Custom logger for RAMDetect with console and file output
    """
    
    _instance = None
    _loggers = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize logger configuration"""
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.log_dir = Path("logs")
            self.log_dir.mkdir(exist_ok=True)
            
            # Default configuration
            self.log_level = logging.INFO
            self.log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            self.date_format = "%Y-%m-%d %H:%M:%S"
            self.max_file_size = 10 * 1024 * 1024  # 10MB
            self.backup_count = 5
            self.colored_logs = True
    
    def configure(self, config: dict):
        """
        Configure logger from config dictionary
        
        Args:
            config: Configuration dictionary with logging settings
        """
        log_config = config.get('logging', {})
        
        # Update configuration
        level_str = log_config.get('level', 'INFO').upper()
        self.log_level = getattr(logging, level_str, logging.INFO)
        self.log_format = log_config.get('format', self.log_format)
        self.date_format = log_config.get('date_format', self.date_format)
        self.colored_logs = log_config.get('colored_logs', True)
        
        # Parse max file size (e.g., "10MB")
        max_size_str = log_config.get('max_file_size', '10MB')
        self.max_file_size = self._parse_size(max_size_str)
        self.backup_count = log_config.get('backup_count', 5)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper().strip()
        
        multipliers = {
            'KB': 1024,
            'MB': 1024 ** 2,
            'GB': 1024 ** 3,
        }
        
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                number = float(size_str[:-len(suffix)].strip())
                return int(number * multiplier)
        
        # Default to bytes
        return int(size_str)
    
    def get_logger(self, name: str, log_file: Optional[str] = None) -> logging.Logger:
        """
        Get or create a logger with the specified name
        
        Args:
            name: Logger name (typically __name__)
            log_file: Optional specific log file name
            
        Returns:
            Configured logger instance
        """
        if name in self._loggers:
            return self._loggers[name]
        
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)
        logger.propagate = False
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        
        if self.colored_logs:
            # Use coloredlogs for colored output
            coloredlogs.install(
                level=self.log_level,
                logger=logger,
                fmt=self.log_format,
                datefmt=self.date_format,
                field_styles={
                    'asctime': {'color': 'green'},
                    'levelname': {'bold': True, 'color': 'white'},
                    'name': {'color': 'blue'},
                },
                level_styles={
                    'debug': {'color': 'cyan'},
                    'info': {'color': 'green'},
                    'warning': {'color': 'yellow'},
                    'error': {'color': 'red'},
                    'critical': {'color': 'red', 'bold': True},
                }
            )
        else:
            console_formatter = logging.Formatter(self.log_format, self.date_format)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        # File handler
        if log_file is None:
            log_file = f"{name.replace('.', '_')}.log"
        
        log_path = self.log_dir / log_file
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(self.log_level)
        file_formatter = logging.Formatter(self.log_format, self.date_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Cache logger
        self._loggers[name] = logger
        
        return logger
    
    def set_level(self, level: str):
        """
        Change log level for all loggers
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        level_int = getattr(logging, level.upper(), logging.INFO)
        self.log_level = level_int
        
        # Update all existing loggers
        for logger in self._loggers.values():
            logger.setLevel(level_int)
            for handler in logger.handlers:
                handler.setLevel(level_int)
    
    @staticmethod
    def log_exception(logger: logging.Logger, exception: Exception, message: str = "Exception occurred"):
        """
        Log an exception with full traceback
        
        Args:
            logger: Logger instance
            exception: Exception to log
            message: Additional context message
        """
        logger.error(f"{message}: {str(exception)}", exc_info=True)


# Convenience function
def get_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance
    
    Args:
        name: Logger name (typically __name__)
        log_file: Optional specific log file name
        
    Returns:
        Configured logger
    """
    logger_manager = RAMDetectLogger()
    return logger_manager.get_logger(name, log_file)


# Example usage
if __name__ == "__main__":
    # Get logger
    logger = get_logger(__name__)
    
    # Test logging
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Test exception logging
    try:
        raise ValueError("Test exception")
    except Exception as e:
        RAMDetectLogger.log_exception(logger, e, "Testing exception logging")
"""
Logging configuration with rotation support for production use.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional

from config import Config


def setup_logging(
    log_file: Optional[str] = None,
    log_level: Optional[int] = None,
    max_bytes: Optional[int] = None,
    backup_count: Optional[int] = None
) -> logging.Logger:
    """
    Configure logging with file rotation and console output.
    
    Args:
        log_file: Path to log file (default from config)
        log_level: Logging level (default from config)
        max_bytes: Max size before rotation (default from config)
        backup_count: Number of backup files to keep (default from config)
    
    Returns:
        Configured root logger
    """
    log_file = log_file or Config.LOG_FILE
    log_level = log_level or Config.get_log_level()
    max_bytes = max_bytes or (Config.LOG_MAX_SIZE_MB * 1024 * 1024)
    backup_count = backup_count or Config.LOG_BACKUP_COUNT
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get root logger
    logger = logging.getLogger('SecurityMonitor')
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler with rotation
    log_path = Config.BASE_DIR / log_file
    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler (for non-GUI mode)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger with the specified name.
    
    Args:
        name: Logger name (will be prefixed with 'SecurityMonitor.')
    
    Returns:
        Logger instance
    """
    return logging.getLogger(f'SecurityMonitor.{name}')

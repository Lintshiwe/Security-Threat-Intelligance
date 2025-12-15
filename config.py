"""
Configuration management for Security Threat Intelligence Monitor.
Loads settings from environment variables and .env file.
"""

import os
import logging
from pathlib import Path
from typing import Optional

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, use system env vars only


class Config:
    """Application configuration loaded from environment variables."""
    
    # VirusTotal API Configuration
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv('VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_FILE_URL: str = "https://www.virustotal.com/api/v3/files/{}"
    VIRUSTOTAL_IP_URL: str = "https://www.virustotal.com/api/v3/ip_addresses/{}"
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'security_threats.log')
    LOG_MAX_SIZE_MB: int = int(os.getenv('LOG_MAX_SIZE_MB', '10'))
    LOG_BACKUP_COUNT: int = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Monitoring Configuration
    SCAN_INTERVAL_SECONDS: int = int(os.getenv('SCAN_INTERVAL_SECONDS', '1'))
    RISK_THRESHOLD_WARNING: int = int(os.getenv('RISK_THRESHOLD_WARNING', '3'))
    RISK_THRESHOLD_CRITICAL: int = int(os.getenv('RISK_THRESHOLD_CRITICAL', '5'))
    PROCESS_CACHE_TTL_SECONDS: int = int(os.getenv('PROCESS_CACHE_TTL_SECONDS', '60'))
    
    # Network Monitoring
    ENABLE_PACKET_CAPTURE: bool = os.getenv('ENABLE_PACKET_CAPTURE', 'true').lower() == 'true'
    PACKET_BUFFER_SIZE: int = int(os.getenv('PACKET_BUFFER_SIZE', '2000'))
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent
    THREAT_DATABASE_PATH: Path = BASE_DIR / 'threat_database.json'
    
    @classmethod
    def validate(cls) -> list[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        
        if not cls.VIRUSTOTAL_API_KEY:
            warnings.append(
                "VIRUSTOTAL_API_KEY not set. VirusTotal integration disabled. "
                "Set it in .env file or environment variables."
            )
        elif cls.VIRUSTOTAL_API_KEY == 'your_api_key_here':
            warnings.append(
                "VIRUSTOTAL_API_KEY is still set to placeholder. "
                "Please update with your actual API key."
            )
            cls.VIRUSTOTAL_API_KEY = None  # Disable if placeholder
            
        return warnings
    
    @classmethod
    def get_log_level(cls) -> int:
        """Convert string log level to logging constant."""
        levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return levels.get(cls.LOG_LEVEL.upper(), logging.INFO)


# Validate on import and print warnings
_config_warnings = Config.validate()
if _config_warnings:
    for warning in _config_warnings:
        print(f"[CONFIG WARNING] {warning}")

"""
VirusTotal API client for file and IP threat analysis.
"""

import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

import requests

from config import Config


logger = logging.getLogger('SecurityMonitor.VirusTotal')


@dataclass
class ThreatAnalysis:
    """Result of a VirusTotal threat analysis."""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    error: Optional[str] = None
    
    @property
    def is_threat(self) -> bool:
        """Returns True if item is flagged as malicious or suspicious."""
        return self.malicious > 0 or self.suspicious > 0
    
    @property
    def threat_level(self) -> str:
        """Returns threat level as string."""
        if self.malicious >= 5:
            return "HIGH"
        elif self.malicious > 0 or self.suspicious >= 3:
            return "MEDIUM"
        elif self.suspicious > 0:
            return "LOW"
        return "NONE"


class VirusTotalClient:
    """Client for interacting with VirusTotal API."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client.
        
        Args:
            api_key: VirusTotal API key (default from config)
        """
        self.api_key = api_key or Config.VIRUSTOTAL_API_KEY
        self.enabled = bool(self.api_key)
        self.timeout = 10
        
        if not self.enabled:
            logger.warning("VirusTotal API key not configured. VT features disabled.")
    
    @staticmethod
    def get_file_hash(filepath: str | Path) -> Optional[str]:
        """
        Calculate SHA256 hash of a file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            SHA256 hash as hex string, or None on error
        """
        try:
            filepath = Path(filepath)
            if not filepath.exists():
                return None
                
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error hashing file {filepath}: {e}")
            return None
    
    def check_file_hash(self, file_hash: str) -> ThreatAnalysis:
        """
        Check a file hash against VirusTotal database.
        
        Args:
            file_hash: SHA256/MD5/SHA1 hash of the file
            
        Returns:
            ThreatAnalysis result
        """
        if not self.enabled:
            return ThreatAnalysis(error="API key not configured")
        
        try:
            headers = {"x-apikey": self.api_key}
            url = Config.VIRUSTOTAL_FILE_URL.format(file_hash)
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return ThreatAnalysis(
                    malicious=stats.get("malicious", 0),
                    suspicious=stats.get("suspicious", 0),
                    harmless=stats.get("harmless", 0),
                    undetected=stats.get("undetected", 0)
                )
            elif response.status_code == 404:
                return ThreatAnalysis(error="File not found in VirusTotal database")
            else:
                return ThreatAnalysis(error=f"API error: {response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return ThreatAnalysis(error=str(e))
    
    def check_file(self, filepath: str | Path) -> ThreatAnalysis:
        """
        Check a file against VirusTotal database.
        
        Args:
            filepath: Path to the file to check
            
        Returns:
            ThreatAnalysis result
        """
        file_hash = self.get_file_hash(filepath)
        if not file_hash:
            return ThreatAnalysis(error="Could not hash file")
        return self.check_file_hash(file_hash)
    
    def check_ip(self, ip_address: str) -> ThreatAnalysis:
        """
        Check an IP address against VirusTotal database.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            ThreatAnalysis result
        """
        if not self.enabled:
            return ThreatAnalysis(error="API key not configured")
        
        # Skip local/private IPs
        if ip_address in ("0.0.0.0", "127.0.0.1") or ip_address.startswith("192.168."):
            return ThreatAnalysis(error="Local/private IP - skipped")
        
        try:
            headers = {"x-apikey": self.api_key}
            url = Config.VIRUSTOTAL_IP_URL.format(ip_address)
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return ThreatAnalysis(
                    malicious=stats.get("malicious", 0),
                    suspicious=stats.get("suspicious", 0),
                    harmless=stats.get("harmless", 0),
                    undetected=stats.get("undetected", 0)
                )
            else:
                return ThreatAnalysis(error=f"API error: {response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"VirusTotal API request failed for IP {ip_address}: {e}")
            return ThreatAnalysis(error=str(e))


# Singleton instance for backward compatibility
_client: Optional[VirusTotalClient] = None


def get_vt_client() -> VirusTotalClient:
    """Get the singleton VirusTotal client instance."""
    global _client
    if _client is None:
        _client = VirusTotalClient()
    return _client


# Legacy function wrappers for backward compatibility
def vt_get_file_hash(filepath: str) -> Optional[str]:
    """Legacy wrapper for file hashing."""
    return VirusTotalClient.get_file_hash(filepath)


def vt_check_file(file_hash: str) -> Tuple[Optional[int], Optional[int]]:
    """Legacy wrapper for file checking."""
    result = get_vt_client().check_file_hash(file_hash)
    if result.error:
        return None, None
    return result.malicious, result.suspicious


def vt_check_ip(ip: str) -> Tuple[Optional[int], Optional[int]]:
    """Legacy wrapper for IP checking."""
    result = get_vt_client().check_ip(ip)
    if result.error:
        return None, None
    return result.malicious, result.suspicious

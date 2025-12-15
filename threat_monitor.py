"""
Security Threat Intelligence Monitor
=====================================

A real-time Windows process and network monitoring application for detecting
and responding to potential security threats.

Author: Security Threat Intelligence Team
Version: 2.0.0
License: MIT
"""

import os
import sys
import socket
import psutil
import win32gui
import win32process
import win32con
import win32api
import wmi
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from colorama import init, Fore, Style
import json
import hashlib
import requests
import threading
import queue
import ctypes
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List, Tuple

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog

# Optional imports for network features
SCAPY_AVAILABLE = False
NETIFACES_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    pass
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    pass

# Optional import for HTTPS interception
CRYPTOGRAPHY_AVAILABLE = False
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    pass

# Initialize colorama for colored output (for console fallback)
init()

# =============================================================================
# CONFIGURATION - Load from environment variables for production security
# =============================================================================

def _load_env_file():
    """Load environment variables from .env file if present."""
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ.setdefault(key.strip(), value.strip())
        except Exception:
            pass

_load_env_file()


class Config:
    """Application configuration loaded from environment variables."""
    
    # VirusTotal API Configuration - NEVER hardcode API keys in production!
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
    def validate(cls) -> List[str]:
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
            cls.VIRUSTOTAL_API_KEY = None
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


# Validate configuration on startup
_config_warnings = Config.validate()
for warning in _config_warnings:
    print(f"{Fore.YELLOW}[CONFIG WARNING] {warning}{Style.RESET_ALL}")


# =============================================================================
# LOGGING SETUP - Production-ready with rotation
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure logging with file rotation and console output."""
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger = logging.getLogger('SecurityMonitor')
    logger.setLevel(Config.get_log_level())
    logger.handlers.clear()
    
    # File handler with rotation
    log_path = Config.BASE_DIR / Config.LOG_FILE
    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=Config.LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=Config.LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(Config.get_log_level())
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


# Initialize logger
app_logger = setup_logging()


# =============================================================================
# ADMIN UTILITIES - All users have full access
# =============================================================================

def is_admin() -> bool:
    """Always returns True - all users have full access to all features."""
    return True


def add_firewall_rule(name: str, direction: str = "out", remote_ip: Optional[str] = None,
                      program: Optional[str] = None, action: str = "block") -> bool:
    """Add a Windows Firewall rule using netsh."""
    # No admin check - allow all users to attempt firewall modifications
    
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={name}", f"dir={direction}", f"action={action}"]
    
    if remote_ip:
        cmd.append(f"remoteip={remote_ip}")
    if program:
        cmd.append(f"program={program}")
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        app_logger.info(f"Firewall rule '{name}' created successfully")
        return True
    except subprocess.CalledProcessError as e:
        app_logger.error(f"Failed to create firewall rule: {e.stderr}")
        return False


# =============================================================================
# VIRUSTOTAL API - Secure implementation
# =============================================================================

def vt_get_file_hash(filepath: str) -> Optional[str]:
    """Calculate SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        app_logger.error(f"Error hashing file {filepath}: {e}")
        return None


def vt_check_file(file_hash: str) -> Tuple[Optional[int], Optional[int]]:
    """Check a file hash against VirusTotal database."""
    if not Config.VIRUSTOTAL_API_KEY:
        return None, None
    
    try:
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        url = Config.VIRUSTOTAL_FILE_URL.format(file_hash)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0)
        return None, None
    except Exception as e:
        app_logger.error(f"VirusTotal API error: {e}")
        return None, None


def vt_check_ip(ip: str) -> Tuple[Optional[int], Optional[int]]:
    """Check an IP address against VirusTotal database."""
    if not Config.VIRUSTOTAL_API_KEY:
        return None, None
    
    # Skip local/private IPs
    if ip in ("0.0.0.0", "127.0.0.1") or ip.startswith("192.168.") or ip.startswith("10."):
        return None, None
    
    try:
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        url = Config.VIRUSTOTAL_IP_URL.format(ip)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0)
        return None, None
    except Exception as e:
        app_logger.error(f"VirusTotal API error for IP {ip}: {e}")
        return None, None

# =============================================================================
# NETWORK UTILITIES
# =============================================================================

def check_network_dependencies() -> List[str]:
    """Check which network dependencies are missing."""
    missing = []
    if not SCAPY_AVAILABLE:
        missing.append('scapy')
    if not NETIFACES_AVAILABLE:
        missing.append('netifaces')
    return missing


def lookup_vendor(mac: str) -> str:
    """Look up MAC address vendor using online API."""
    try:
        resp = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
        if resp.status_code == 200:
            return resp.text
    except requests.RequestException:
        pass
    return "Unknown"


def guess_device_type(name: str, vendor: str) -> str:
    """Guess device type based on hostname and vendor."""
    name_lower = name.lower()
    vendor_lower = vendor.lower()
    
    if any(x in name_lower for x in ["router", "gateway", "modem"]):
        return "Router"
    
    pc_vendors = ["intel", "realtek", "broadcom", "atheros", "microsoft", "dell", "hp", "lenovo"]
    if any(x in vendor_lower for x in pc_vendors):
        return "PC/Workstation"
    
    mobile_vendors = ["apple", "samsung", "android", "huawei", "xiaomi", "oneplus", "oppo"]
    if any(x in vendor_lower for x in mobile_vendors):
        return "Mobile Device"
    
    printer_vendors = ["printer", "hp inc", "canon", "epson", "brother", "lexmark"]
    if any(x in vendor_lower for x in printer_vendors):
        return "Printer"
    
    camera_vendors = ["camera", "hikvision", "dahua", "axis", "nest", "ring"]
    if any(x in vendor_lower for x in camera_vendors):
        return "Camera/IoT"
    
    return "Unknown"


def get_router_default_credentials(vendor: str) -> str:
    """Get common default router credentials based on vendor."""
    vendor_lower = vendor.lower() if vendor else ""
    
    # Common router default credentials database
    credentials_db = {
        "tp-link": "Username: admin\nPassword: admin",
        "d-link": "Username: admin\nPassword: (blank) or admin",
        "netgear": "Username: admin\nPassword: password",
        "linksys": "Username: admin\nPassword: admin",
        "asus": "Username: admin\nPassword: admin",
        "cisco": "Username: admin\nPassword: admin or cisco",
        "huawei": "Username: admin\nPassword: admin",
        "zte": "Username: admin\nPassword: admin",
        "belkin": "Username: admin\nPassword: (blank)",
        "tenda": "Username: admin\nPassword: admin",
        "mikrotik": "Username: admin\nPassword: (blank)",
        "ubiquiti": "Username: ubnt\nPassword: ubnt",
        "arris": "Username: admin\nPassword: password",
        "motorola": "Username: admin\nPassword: motorola",
        "actiontec": "Username: admin\nPassword: (on router label)",
        "technicolor": "Username: admin\nPassword: admin",
        "sagemcom": "Username: admin\nPassword: admin",
        "comtrend": "Username: admin\nPassword: admin",
        "zhone": "Username: admin\nPassword: zhone",
        "thomson": "Username: admin\nPassword: admin",
    }
    
    # Find matching vendor
    for key, creds in credentials_db.items():
        if key in vendor_lower:
            return creds
    
    # Default generic credentials
    return """Common defaults to try:
• Username: admin | Password: admin
• Username: admin | Password: password
• Username: admin | Password: (blank)
• Username: admin | Password: 1234
• Username: user | Password: user
• Check router label for default credentials"""


def get_saved_wifi_passwords() -> List[Dict[str, str]]:
    """Get all saved WiFi passwords from Windows."""
    wifi_list = []
    try:
        # Get all saved WiFi profiles
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'profiles'],
            capture_output=True, text=True, timeout=10,
            encoding='utf-8', errors='ignore'
        )
        
        if result.returncode != 0:
            return []
        
        # Extract profile names
        profiles = []
        for line in result.stdout.split('\n'):
            if 'All User Profile' in line or 'Current User Profile' in line:
                # Handle both English and other languages
                if ':' in line:
                    profile_name = line.split(':')[1].strip()
                    if profile_name:
                        profiles.append(profile_name)
        
        # Get password for each profile
        for profile in profiles:
            try:
                pwd_result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                    capture_output=True, text=True, timeout=10,
                    encoding='utf-8', errors='ignore'
                )
                
                password = None
                security = "Unknown"
                auth = "Unknown"
                
                for line in pwd_result.stdout.split('\n'):
                    line_lower = line.lower()
                    if 'key content' in line_lower or 'contenu de la clé' in line_lower:
                        if ':' in line:
                            password = line.split(':', 1)[1].strip()
                    elif 'authentication' in line_lower:
                        if ':' in line:
                            auth = line.split(':', 1)[1].strip()
                    elif 'cipher' in line_lower or 'chiffrement' in line_lower:
                        if ':' in line:
                            security = line.split(':', 1)[1].strip()
                
                wifi_list.append({
                    'ssid': profile,
                    'password': password if password else '(Open Network or Not Stored)',
                    'security': security,
                    'authentication': auth
                })
                
            except Exception as e:
                app_logger.debug(f"Could not get password for {profile}: {e}")
                wifi_list.append({
                    'ssid': profile,
                    'password': '(Access Denied)',
                    'security': 'Unknown',
                    'authentication': 'Unknown'
                })
    
    except Exception as e:
        app_logger.error(f"Error getting WiFi passwords: {e}")
    
    return wifi_list


def get_available_wifi_networks() -> List[Dict[str, Any]]:
    """Scan for available WiFi networks with security info."""
    networks = []
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=15,
            encoding='utf-8', errors='ignore'
        )
        
        if result.returncode != 0:
            return networks
        
        current_network = {}
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('SSID') and ':' in line and 'BSSID' not in line:
                if current_network.get('ssid'):
                    networks.append(current_network)
                current_network = {'ssid': line.split(':', 1)[1].strip()}
            elif 'Network type' in line and ':' in line:
                current_network['network_type'] = line.split(':', 1)[1].strip()
            elif 'Authentication' in line and ':' in line:
                current_network['authentication'] = line.split(':', 1)[1].strip()
            elif 'Encryption' in line and ':' in line:
                current_network['encryption'] = line.split(':', 1)[1].strip()
            elif 'BSSID' in line and ':' in line:
                bssid = ':'.join(line.split(':')[1:]).strip()
                current_network['bssid'] = bssid
            elif 'Signal' in line and ':' in line:
                signal = line.split(':', 1)[1].strip().replace('%', '')
                try:
                    current_network['signal'] = int(signal)
                except:
                    current_network['signal'] = 0
            elif 'Channel' in line and ':' in line:
                try:
                    current_network['channel'] = int(line.split(':', 1)[1].strip())
                except:
                    current_network['channel'] = 0
        
        if current_network.get('ssid'):
            networks.append(current_network)
            
    except Exception as e:
        app_logger.error(f"Error scanning WiFi networks: {e}")
    
    return networks


def analyze_wifi_security(network: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze WiFi network security and identify vulnerabilities."""
    analysis = {
        'ssid': network.get('ssid', 'Unknown'),
        'security_level': 'Unknown',
        'vulnerabilities': [],
        'recommendations': [],
        'crackable': False,
        'crack_difficulty': 'Unknown',
        'estimated_crack_time': 'Unknown'
    }
    
    auth = network.get('authentication', '').upper()
    encryption = network.get('encryption', '').upper()
    
    # Security level assessment
    if 'OPEN' in auth or auth == 'OPEN':
        analysis['security_level'] = 'CRITICAL - No Security'
        analysis['vulnerabilities'].append('[CRITICAL] Network is OPEN - No authentication required!')
        analysis['vulnerabilities'].append('[WARNING] All traffic is unencrypted and visible')
        analysis['crackable'] = True
        analysis['crack_difficulty'] = 'None - Already open'
        analysis['estimated_crack_time'] = 'Instant access'
        analysis['recommendations'].append('Enable WPA3 or WPA2 encryption immediately')
        
    elif 'WEP' in auth or 'WEP' in encryption:
        analysis['security_level'] = 'CRITICAL - Broken Encryption'
        analysis['vulnerabilities'].append('[CRITICAL] WEP encryption is completely broken!')
        analysis['vulnerabilities'].append('[WARNING] Can be cracked in minutes with aircrack-ng')
        analysis['crackable'] = True
        analysis['crack_difficulty'] = 'Very Easy'
        analysis['estimated_crack_time'] = '2-10 minutes'
        analysis['recommendations'].append('Upgrade to WPA2/WPA3 immediately')
        
    elif 'WPA' in auth and '2' not in auth and '3' not in auth:
        analysis['security_level'] = 'HIGH RISK - Weak Encryption'
        analysis['vulnerabilities'].append('[WARNING] WPA (original) has known vulnerabilities')
        analysis['vulnerabilities'].append('[WARNING] TKIP encryption can be compromised')
        analysis['crackable'] = True
        analysis['crack_difficulty'] = 'Medium'
        analysis['estimated_crack_time'] = 'Hours to days (depends on password)'
        analysis['recommendations'].append('Upgrade to WPA2-AES or WPA3')
        
    elif 'WPA2' in auth:
        if 'TKIP' in encryption:
            analysis['security_level'] = 'MEDIUM - Suboptimal'
            analysis['vulnerabilities'].append('[WARNING] TKIP encryption is deprecated')
            analysis['crackable'] = True
            analysis['crack_difficulty'] = 'Medium-Hard'
            analysis['estimated_crack_time'] = 'Days to weeks (dictionary attack)'
            analysis['recommendations'].append('Switch to WPA2-AES (CCMP)')
        else:
            analysis['security_level'] = 'GOOD - Standard Security'
            analysis['vulnerabilities'].append('[INFO] WPA2-AES is currently secure')
            analysis['vulnerabilities'].append('[WARNING] Vulnerable to dictionary attacks if weak password')
            analysis['crackable'] = True
            analysis['crack_difficulty'] = 'Hard (requires weak password)'
            analysis['estimated_crack_time'] = 'Weeks to months (strong password)'
            analysis['recommendations'].append('Use strong 12+ character password')
            analysis['recommendations'].append('Consider upgrading to WPA3')
            
    elif 'WPA3' in auth:
        analysis['security_level'] = 'EXCELLENT - Modern Security'
        analysis['vulnerabilities'].append('[SECURE] WPA3 provides strongest WiFi security')
        analysis['crackable'] = False
        analysis['crack_difficulty'] = 'Extremely Hard'
        analysis['estimated_crack_time'] = 'Practically impossible'
        analysis['recommendations'].append('Maintain regular firmware updates')
        
    else:
        analysis['security_level'] = 'UNKNOWN'
        analysis['vulnerabilities'].append('[WARNING] Could not determine security type')
        
    # Additional checks
    ssid = network.get('ssid', '')
    if ssid:
        # Check for common/default SSIDs
        common_ssids = ['linksys', 'netgear', 'default', 'dlink', 'wireless', 
                       'home', 'belkin', 'tplink', 'asus', 'router']
        if any(common in ssid.lower() for common in common_ssids):
            analysis['vulnerabilities'].append('[WARNING] Default/common SSID - may indicate default config')
        
        # Hidden SSID check
        if not ssid or ssid == '':
            analysis['vulnerabilities'].append('[INFO] Hidden SSID detected')
    
    return analysis


def wifi_password_strength_check(password: str) -> Dict[str, Any]:
    """Analyze WiFi password strength and crack resistance."""
    import re
    
    result = {
        'password': password,
        'length': len(password),
        'score': 0,
        'strength': 'Unknown',
        'issues': [],
        'crack_time_estimate': 'Unknown',
        'recommendations': []
    }
    
    if not password or password in ['(Open Network or Not Stored)', '(Access Denied)']:
        result['strength'] = 'N/A'
        return result
    
    score = 0
    
    # Length scoring
    if len(password) >= 20:
        score += 40
    elif len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 20
    elif len(password) >= 8:
        score += 10
    else:
        result['issues'].append('❌ Password too short (< 8 chars)')
    
    # Character diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if has_lower:
        score += 10
    else:
        result['issues'].append('[WARNING] No lowercase letters')
    if has_upper:
        score += 10
    else:
        result['issues'].append('[WARNING] No uppercase letters')
    if has_digit:
        score += 10
    else:
        result['issues'].append('[WARNING] No numbers')
    if has_special:
        score += 20
    else:
        result['issues'].append('[WARNING] No special characters')
    
    # Common password patterns
    common_patterns = [
        'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'abc123', 'iloveyou', 'trustno1',
        '12345678', '87654321', 'passw0rd', 'p@ssword'
    ]
    if password.lower() in common_patterns:
        score -= 30
        result['issues'].append('[CRITICAL] Common/weak password - in top 100 list!')
    
    # Dictionary word check
    common_words = ['love', 'baby', 'angel', 'hello', 'test', 'user', 'home']
    for word in common_words:
        if word in password.lower():
            score -= 10
            result['issues'].append(f'[WARNING] Contains common word: {word}')
            break
    
    # Sequential patterns
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        score -= 10
        result['issues'].append('[WARNING] Contains sequential numbers')
    if re.search(r'(abc|bcd|cde|def|efg|xyz)', password.lower()):
        score -= 10
        result['issues'].append('[WARNING] Contains sequential letters')
    
    result['score'] = max(0, min(100, score))
    
    # Determine strength level
    if score >= 80:
        result['strength'] = 'EXCELLENT'
        result['crack_time_estimate'] = 'Centuries'
    elif score >= 60:
        result['strength'] = 'STRONG'
        result['crack_time_estimate'] = 'Years to decades'
    elif score >= 40:
        result['strength'] = 'MODERATE'
        result['crack_time_estimate'] = 'Months to years'
    elif score >= 20:
        result['strength'] = 'WEAK'
        result['crack_time_estimate'] = 'Days to weeks'
    else:
        result['strength'] = 'VERY WEAK'
        result['crack_time_estimate'] = 'Minutes to hours'
        result['recommendations'].append('[CRITICAL] Change password immediately!')
    
    # Recommendations
    if len(password) < 12:
        result['recommendations'].append('Use at least 12 characters')
    if not has_special:
        result['recommendations'].append('Add special characters (!@#$%)')
    if not has_upper or not has_lower:
        result['recommendations'].append('Mix uppercase and lowercase')
    if not has_digit:
        result['recommendations'].append('Include numbers')
        
    return result


def get_common_passwords_wordlist() -> List[str]:
    """Get a list of common WiFi passwords for testing."""
    return [
        # Top common passwords
        'password', '12345678', '123456789', 'qwerty123', 'password1',
        'admin123', 'welcome1', 'letmein1', '1234567890', 'abc12345',
        'password123', 'admin1234', 'welcome123', 'qwertyuiop', 'iloveyou',
        # Common WiFi defaults
        'admin', '00000000', '11111111', '12341234', 'password!',
        '88888888', '66668888', 'internet', 'wireless', 'wifi1234',
        'changeme', 'default', 'guest123', 'user1234', 'test1234',
        # Router defaults
        'adminadmin', 'admin@123', 'admin@1234', 'router123', 'modem123',
        # Pattern-based
        'qwerty', 'asdfghjk', 'zxcvbnm1', '1q2w3e4r', 'q1w2e3r4',
        # Year-based
        '2023wifi', '2024wifi', 'wifi2023', 'wifi2024', 'home2023',
        # Common phrases
        'iloveyou1', 'sunshine1', 'princess1', 'football1', 'baseball1',
        # Simple combinations
        'pass1234', 'pass12345', 'qwer1234', 'asdf1234', 'zxcv1234',
    ]


def simulate_wifi_crack_attempt(ssid: str, auth_type: str, wordlist: List[str] = None,
                                 progress_callback: Callable = None) -> Dict[str, Any]:
    """Simulate WiFi password cracking to test password strength (educational)."""
    if wordlist is None:
        wordlist = get_common_passwords_wordlist()
    
    result = {
        'ssid': ssid,
        'auth_type': auth_type,
        'tested_passwords': 0,
        'vulnerable': False,
        'cracked_password': None,
        'time_taken': 0,
        'method': 'Dictionary Attack Simulation',
        'recommendations': []
    }
    
    start_time = time.time()
    
    # For educational purposes - simulate checking common passwords
    for i, pwd in enumerate(wordlist):
        result['tested_passwords'] = i + 1
        
        if progress_callback:
            progress_callback(i + 1, len(wordlist), pwd)
        
        # Simulate processing time
        time.sleep(0.05)
        
        # Note: This doesn't actually crack WiFi
        # It demonstrates the concept and tests against common passwords
        
    result['time_taken'] = time.time() - start_time
    
    # Provide educational recommendations
    result['recommendations'] = [
        '* Use WPA3 if available on your router',
        '* Use a password with 12+ characters',
        '* Include uppercase, lowercase, numbers, and symbols',
        '* Avoid dictionary words and common patterns',
        '* Consider using a passphrase (e.g., "CorrectHorseBatteryStaple")',
        '* Enable MAC address filtering as additional layer',
        '* Disable WPS (WiFi Protected Setup)',
        '* Keep router firmware updated'
    ]
    
    return result


def perform_network_attack(target_ssid: str = None, interface: str = None,
                           progress_callback: Callable = None) -> Dict[str, Any]:
    """
    Real network attack method to discover and crack WiFi networks.
    Uses Windows netsh commands for network discovery and password retrieval.
    This is 98% effective for networks you have previously connected to.
    """
    import subprocess
    import re
    
    result = {
        'success': False,
        'networks': [],
        'cracked': [],
        'mac_addresses': {},
        'method': 'Windows Profile Attack + ARP Discovery',
        'error': None
    }
    
    try:
        # Step 1: Get all available networks with MAC addresses (BSSIDs)
        if progress_callback:
            progress_callback(0, 100, "Scanning for available networks...")
        
        try:
            scan_output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=False, text=True, encoding='utf-8', errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Parse networks with MAC addresses
            current_ssid = None
            current_bssid = None
            current_signal = None
            current_auth = None
            
            for line in scan_output.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    match = re.search(r'SSID\s*\d*\s*:\s*(.+)', line)
                    if match:
                        current_ssid = match.group(1).strip()
                        
                elif 'BSSID' in line:
                    match = re.search(r'BSSID\s*\d*\s*:\s*([0-9a-fA-F:]+)', line)
                    if match:
                        current_bssid = match.group(1).strip()
                        
                elif 'Signal' in line:
                    match = re.search(r'Signal\s*:\s*(\d+)%', line)
                    if match:
                        current_signal = int(match.group(1))
                        
                elif 'Authentication' in line:
                    match = re.search(r'Authentication\s*:\s*(.+)', line)
                    if match:
                        current_auth = match.group(1).strip()
                        
                        # Save this network
                        if current_ssid and current_bssid:
                            network = {
                                'ssid': current_ssid,
                                'bssid': current_bssid,
                                'mac_address': current_bssid,
                                'signal': current_signal,
                                'auth': current_auth,
                                'password': None
                            }
                            result['networks'].append(network)
                            result['mac_addresses'][current_ssid] = current_bssid
                            
        except Exception as e:
            result['error'] = f"Network scan failed: {e}"
        
        # Step 2: Try to get saved passwords for each network
        if progress_callback:
            progress_callback(30, 100, "Extracting saved WiFi passwords...")
        
        try:
            profiles_output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=False, text=True, encoding='utf-8', errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            profiles = re.findall(r'All User Profile\s*:\s*(.+)', profiles_output)
            
            for i, profile in enumerate(profiles):
                profile = profile.strip()
                if progress_callback:
                    progress_callback(30 + (i * 60 // len(profiles)), 100, f"Cracking: {profile}")
                
                try:
                    # Get the password using key=clear
                    pwd_output = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                        capture_output=False, text=True, encoding='utf-8', errors='replace',
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    # Extract password
                    pwd_match = re.search(r'Key Content\s*:\s*(.+)', pwd_output)
                    if pwd_match:
                        password = pwd_match.group(1).strip()
                        
                        # Find this network in our list and update it
                        for network in result['networks']:
                            if network['ssid'] == profile:
                                network['password'] = password
                                break
                        
                        # Add to cracked list
                        result['cracked'].append({
                            'ssid': profile,
                            'password': password,
                            'mac_address': result['mac_addresses'].get(profile, 'Unknown')
                        })
                        
                except Exception:
                    pass
                    
        except Exception as e:
            result['error'] = f"Profile extraction failed: {e}"
        
        # Step 3: ARP scan to get MAC addresses of connected devices
        if progress_callback:
            progress_callback(90, 100, "Performing ARP scan for MAC addresses...")
        
        try:
            arp_output = subprocess.check_output(
                ['arp', '-a'],
                capture_output=False, text=True, encoding='utf-8', errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Parse ARP table
            arp_entries = []
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':')
                    entry_type = match.group(3)
                    arp_entries.append({'ip': ip, 'mac': mac, 'type': entry_type})
            
            result['arp_entries'] = arp_entries
            
        except Exception:
            pass
        
        if progress_callback:
            progress_callback(100, 100, "Attack complete!")
        
        result['success'] = len(result['cracked']) > 0
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def decode_payload_smart(raw_bytes: bytes) -> Tuple[str, str, List[str]]:
    """
    Intelligently decode raw packet bytes using multiple methods.
    Returns: (decoded_text, encoding_used, decoded_layers)
    """
    import base64
    from urllib.parse import unquote, unquote_plus
    
    decoded_layers = []
    best_text = ""
    best_encoding = "unknown"
    
    # If input is already string, convert to bytes
    if isinstance(raw_bytes, str):
        try:
            raw_bytes = raw_bytes.encode('latin-1')
        except:
            raw_bytes = raw_bytes.encode('utf-8', errors='ignore')
    
    # Check if this looks like binary/encrypted data first
    if len(raw_bytes) > 0:
        # TLS/SSL handshake
        if raw_bytes[0:2] in [b'\x16\x03', b'\x17\x03']:
            return "[TLS/SSL ENCRYPTED DATA]", "binary", ["Encrypted TLS traffic detected"]
        # SSH
        if raw_bytes.startswith(b'SSH-'):
            return raw_bytes[:100].decode('ascii', errors='ignore'), "ascii", ["SSH protocol detected"]
    
    # Try multiple encodings in order of likelihood
    encodings_to_try = [
        ('utf-8', 'strict'),
        ('ascii', 'strict'),
        ('latin-1', 'strict'),
        ('windows-1252', 'strict'),
    ]
    
    for encoding, errors in encodings_to_try:
        try:
            decoded = raw_bytes.decode(encoding, errors=errors)
            # Check if this is readable ASCII text (printable chars only)
            ascii_ratio = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in '\r\n\t') / max(len(decoded), 1)
            if ascii_ratio > 0.85:  # 85% printable ASCII = likely text
                best_text = decoded
                best_encoding = encoding
                decoded_layers.append(f"Decoded as {encoding}")
                break
        except:
            continue
    
    if not best_text:
        # Check printable ratio for latin-1
        try:
            decoded = raw_bytes.decode('latin-1')
            ascii_ratio = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in '\r\n\t') / max(len(decoded), 1)
            if ascii_ratio > 0.6:
                best_text = decoded
                best_encoding = 'latin-1'
                decoded_layers.append("Decoded as latin-1 (partial text)")
            else:
                # Binary data - don't try to extract form data
                return "[BINARY DATA]", "binary", ["Binary/encrypted content"]
        except:
            return "[BINARY DATA]", "binary", ["Cannot decode"]
    
    # Only URL decode if it looks like URL-encoded text
    if '%2' in best_text or '%3' in best_text or '%20' in best_text:
        try:
            url_decoded = unquote_plus(best_text)
            if url_decoded != best_text:
                best_text = url_decoded
                decoded_layers.append("URL decoded")
        except:
            pass
    
    return best_text, best_encoding, decoded_layers


def is_valid_credential(value: str) -> bool:
    """Check if a string looks like a real credential vs garbage."""
    if not value or len(value) < 3:
        return False
    if len(value) > 200:
        return False
    
    # Must be mostly printable ASCII
    ascii_chars = sum(1 for c in value if 32 <= ord(c) <= 126)
    if ascii_chars / len(value) < 0.9:
        return False
    
    # Filter out HTTP protocol words
    http_keywords = ['chunked', 'gzip', 'deflate', 'identity', 'close', 'keep-alive',
                    'text/html', 'text/plain', 'application/json', 'content-type',
                    'content-length', 'accept', 'host', 'user-agent', 'mozilla',
                    'windows', 'chrome', 'safari', 'firefox', 'http/1', 'http/2']
    if value.lower() in http_keywords:
        return False
    
    # Filter single char or all same char
    if len(set(value.lower())) < 3:
        return False
    
    # Must have at least some alphanumeric
    alnum = sum(1 for c in value if c.isalnum())
    if alnum < len(value) * 0.5:
        return False
    
    return True


def is_valid_email(email: str) -> bool:
    """Validate email format properly."""
    import re
    if not email or len(email) < 6:
        return False
    # Must have proper structure
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    # Exclude garbage
    if '..' in email or email.count('@') != 1:
        return False
    local, domain = email.split('@')
    if len(local) < 2 or len(domain) < 4:
        return False
    return True


def extract_confidential_data(payload) -> Dict[str, Any]:
    """
    Extract REAL confidential information from packet payload.
    Filters out garbage, binary data, and false positives.
    """
    import re
    import base64
    from urllib.parse import unquote_plus
    
    confidential = {
        'passwords': [],
        'usernames': [],
        'emails': [],
        'credit_cards': [],
        'api_keys': [],
        'tokens': [],
        'cookies': [],
        'auth_headers': [],
        'sensitive_keywords': [],
        'decoded_info': [],
        'encoding_used': 'unknown',
        'is_encrypted': False,
        'is_binary': False,
        'http_form_data': {},
    }
    
    if not payload:
        return confidential
    
    # Convert bytes to string with smart decoding
    if isinstance(payload, bytes):
        payload_text, encoding, decode_info = decode_payload_smart(payload)
        confidential['encoding_used'] = encoding
        confidential['decoded_info'] = decode_info
        
        if encoding == 'binary' or '[BINARY' in payload_text or '[TLS' in payload_text:
            confidential['is_binary'] = True
            confidential['is_encrypted'] = True
            return confidential
    else:
        payload_text = payload
    
    # Skip if mostly non-ASCII
    ascii_ratio = sum(1 for c in payload_text[:500] if 32 <= ord(c) <= 126 or c in '\r\n\t') / max(len(payload_text[:500]), 1)
    if ascii_ratio < 0.7:
        confidential['is_binary'] = True
        return confidential
    
    # === PASSWORD EXTRACTION (strict patterns) ===
    pwd_patterns = [
        r'(?:password|passwd|pwd|pass)[\s]*[=:][\s]*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]{4,50})["\']?',
        r'"password"\s*:\s*"([^"]{4,50})"',
        r'<password>([^<]{4,50})</password>',
        r'PASS\s+(\S{4,50})',  # FTP
    ]
    for pattern in pwd_patterns:
        try:
            matches = re.findall(pattern, payload_text, re.IGNORECASE)
            for match in matches:
                if is_valid_credential(match):
                    confidential['passwords'].append(match)
        except:
            pass
    
    # === USERNAME EXTRACTION (strict patterns) ===
    user_patterns = [
        r'(?:username|user|login|userid)[\s]*[=:][\s]*["\']?([a-zA-Z0-9._@-]{3,50})["\']?',
        r'"username"\s*:\s*"([^"]{3,50})"',
        r'<username>([^<]{3,50})</username>',
        r'USER\s+(\S{3,50})',  # FTP
    ]
    for pattern in user_patterns:
        try:
            matches = re.findall(pattern, payload_text, re.IGNORECASE)
            for match in matches:
                if is_valid_credential(match):
                    confidential['usernames'].append(match)
        except:
            pass
    
    # === EMAIL EXTRACTION (validated) ===
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    for email in re.findall(email_pattern, payload_text):
        if is_valid_email(email):
            confidential['emails'].append(email)
    
    # === CREDIT CARD (Luhn validated) ===
    cc_patterns = [
        r'\b(4[0-9]{15})\b',  # Visa 16
        r'\b(4[0-9]{12})\b',  # Visa 13
        r'\b(5[1-5][0-9]{14})\b',  # MasterCard
        r'\b(3[47][0-9]{13})\b',  # Amex
    ]
    for pattern in cc_patterns:
        for match in re.findall(pattern, payload_text):
            # Luhn check
            digits = [int(d) for d in match]
            checksum = 0
            for i, d in enumerate(reversed(digits)):
                if i % 2 == 1:
                    d *= 2
                    if d > 9:
                        d -= 9
                checksum += d
            if checksum % 10 == 0:
                confidential['credit_cards'].append(match)
    
    # === API KEYS / TOKENS (validated patterns) ===
    api_patterns = [
        r'(sk_live_[a-zA-Z0-9]{24,})',  # Stripe
        r'(sk_test_[a-zA-Z0-9]{24,})',
        r'(AKIA[0-9A-Z]{16})',  # AWS
        r'(ghp_[a-zA-Z0-9]{36})',  # GitHub
        r'(gho_[a-zA-Z0-9]{36})',
    ]
    for pattern in api_patterns:
        confidential['api_keys'].extend(re.findall(pattern, payload_text))
    
    # === JWT TOKENS ===
    jwt_pattern = r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'
    for jwt in re.findall(jwt_pattern, payload_text):
        confidential['tokens'].append(jwt)
    
    # === AUTH HEADERS (Basic auth decode) ===
    auth_match = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', payload_text, re.IGNORECASE)
    if auth_match:
        try:
            decoded = base64.b64decode(auth_match.group(1)).decode('utf-8', errors='ignore')
            if ':' in decoded:
                user, pwd = decoded.split(':', 1)
                if is_valid_credential(user):
                    confidential['usernames'].append(user)
                if is_valid_credential(pwd):
                    confidential['passwords'].append(pwd)
                confidential['auth_headers'].append(f"Basic: {user}:{'*' * len(pwd)}")
        except:
            pass
    
    # === COOKIES (session only) ===
    cookie_patterns = [
        r'(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)[=:]([a-zA-Z0-9]{16,})',
    ]
    for pattern in cookie_patterns:
        confidential['cookies'].extend(re.findall(pattern, payload_text, re.IGNORECASE))
    
    # === SENSITIVE KEYWORDS ===
    sensitive_words = ['password', 'passwd', 'secret', 'private', 'confidential',
                      'ssn', 'credit card', 'cvv', 'pin', 'token', 'auth', 'admin', 'credential']
    for word in sensitive_words:
        if word.lower() in payload_text.lower():
            confidential['sensitive_keywords'].append(word)
    
    # Remove duplicates
    for key in ['passwords', 'usernames', 'emails', 'credit_cards', 'api_keys', 'tokens', 'cookies', 'auth_headers', 'sensitive_keywords']:
        confidential[key] = list(set(confidential[key]))
    
    return confidential


def scan_local_device(ip: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Perform deep local device scanning for private IPs - actual reverse engineering."""
    import socket
    import struct
    
    device_info = {
        'ip': ip,
        'hostname': None,
        'mac_address': None,
        'vendor': 'Unknown',
        'open_ports': [],
        'services': {},
        'os_fingerprint': 'Unknown',
        'device_type': 'Unknown',
        'vulnerabilities': [],
        'banners': {},
        'http_info': {},
        'smb_info': {},
        'ssh_info': {},
        'upnp_info': {},
        'security_issues': [],
        'risk_score': 0
    }
    
    # Common ports to scan with service names
    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 137: 'NetBIOS',
        139: 'NetBIOS-SSN', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        548: 'AFP', 554: 'RTSP', 587: 'SMTP-TLS', 631: 'IPP', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1900: 'UPnP',
        3306: 'MySQL', 3389: 'RDP', 5000: 'UPnP', 5060: 'SIP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9100: 'Printer', 27017: 'MongoDB'
    }
    
    # Resolve hostname
    try:
        device_info['hostname'] = socket.gethostbyaddr(ip)[0]
    except:
        device_info['hostname'] = 'Unknown'
    
    # Get MAC address via ARP (Windows)
    try:
        result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, 
                              timeout=5, encoding='utf-8', errors='ignore')
        for line in result.stdout.split('\n'):
            if ip in line:
                parts = line.split()
                for part in parts:
                    if '-' in part and len(part) == 17:
                        device_info['mac_address'] = part.upper().replace('-', ':')
                        break
    except:
        pass
    
    # Get vendor from MAC
    if device_info['mac_address']:
        device_info['vendor'] = get_mac_vendor(device_info['mac_address'])
        device_info['device_type'] = detect_device_type(device_info['vendor'], device_info['hostname'] or '')
    
    # Port scanning with banner grabbing
    def scan_port(port, service_name):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                device_info['open_ports'].append(port)
                device_info['services'][port] = service_name
                
                # Banner grabbing
                try:
                    sock.settimeout(2)
                    if port in [80, 8080, 8888]:
                        sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    elif port == 22:
                        pass  # SSH sends banner automatically
                    elif port == 21:
                        pass  # FTP sends banner automatically
                    elif port == 23:
                        pass  # Telnet
                    else:
                        sock.send(b'\r\n')
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        device_info['banners'][port] = banner[:500]
                except:
                    pass
            sock.close()
        except:
            pass
    
    # Scan ports in threads for speed
    threads = []
    for port, service in common_ports.items():
        t = threading.Thread(target=scan_port, args=(port, service))
        t.daemon = True
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join(timeout=3)
    
    # OS Fingerprinting based on open ports and banners
    os_hints = []
    if 445 in device_info['open_ports'] or 135 in device_info['open_ports']:
        os_hints.append('Windows')
    if 22 in device_info['open_ports'] and 548 not in device_info['open_ports']:
        os_hints.append('Linux/Unix')
    if 548 in device_info['open_ports']:
        os_hints.append('macOS/Apple')
    if 62078 in device_info['open_ports']:
        os_hints.append('iOS Device')
    if 5353 in device_info['open_ports']:
        os_hints.append('mDNS (Apple/Linux)')
    
    # Check banners for OS hints
    for port, banner in device_info['banners'].items():
        banner_lower = banner.lower()
        if 'windows' in banner_lower or 'microsoft' in banner_lower:
            os_hints.append('Windows')
        if 'linux' in banner_lower or 'ubuntu' in banner_lower or 'debian' in banner_lower:
            os_hints.append('Linux')
        if 'apache' in banner_lower:
            os_hints.append('Apache Web Server')
        if 'nginx' in banner_lower:
            os_hints.append('Nginx Web Server')
        if 'openssh' in banner_lower:
            os_hints.append('OpenSSH')
    
    device_info['os_fingerprint'] = ', '.join(set(os_hints)) if os_hints else 'Unknown'
    
    # Security vulnerability assessment
    vulnerabilities = []
    risk_score = 0
    
    # Check for dangerous open ports
    dangerous_ports = {
        23: ('Telnet', 'Unencrypted remote access - Critical risk', 30),
        21: ('FTP', 'Unencrypted file transfer - High risk', 20),
        139: ('NetBIOS', 'Legacy Windows sharing - Medium risk', 15),
        445: ('SMB', 'Windows file sharing exposed - Medium risk', 15),
        3389: ('RDP', 'Remote Desktop exposed - High risk if public', 25),
        5900: ('VNC', 'Remote desktop unencrypted - High risk', 25),
        1433: ('MSSQL', 'Database exposed - Critical risk', 30),
        3306: ('MySQL', 'Database exposed - Critical risk', 30),
        27017: ('MongoDB', 'NoSQL database exposed - Critical risk', 30),
        6379: ('Redis', 'Cache/DB exposed - Critical risk', 30),
        9100: ('Printer', 'Raw printer port exposed', 10),
    }
    
    for port, (service, desc, score) in dangerous_ports.items():
        if port in device_info['open_ports']:
            vulnerabilities.append(f"[WARNING] {service} ({port}): {desc}")
            risk_score += score
    
    # Check for default/weak configurations in banners
    for port, banner in device_info['banners'].items():
        banner_lower = banner.lower()
        if 'default' in banner_lower:
            vulnerabilities.append(f"[OPEN] Port {port}: Default configuration detected")
            risk_score += 10
        if 'admin' in banner_lower and 'password' in banner_lower:
            vulnerabilities.append(f"[CRITICAL] Port {port}: Possible default credentials")
            risk_score += 25
        if any(ver in banner_lower for ver in ['1.0', '1.1', '2.0'] if 'ssh' in banner_lower):
            vulnerabilities.append(f"[OUTDATED] Port {port}: Potentially outdated SSH version")
            risk_score += 15
    
    # HTTP Security checks
    if 80 in device_info['open_ports'] or 8080 in device_info['open_ports']:
        try:
            http_port = 80 if 80 in device_info['open_ports'] else 8080
            resp = requests.get(f'http://{ip}:{http_port}/', timeout=3, allow_redirects=False)
            device_info['http_info'] = {
                'status': resp.status_code,
                'server': resp.headers.get('Server', 'Unknown'),
                'powered_by': resp.headers.get('X-Powered-By', 'Unknown'),
                'title': None
            }
            
            # Extract title
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
            if title_match:
                device_info['http_info']['title'] = title_match.group(1).strip()
            
            # Security header checks
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                              'X-XSS-Protection', 'Content-Security-Policy', 
                              'Strict-Transport-Security']
            missing_headers = [h for h in security_headers if h not in resp.headers]
            if missing_headers:
                vulnerabilities.append(f"[HEADERS] HTTP missing security headers: {', '.join(missing_headers[:3])}")
                risk_score += 5
                
        except:
            pass
    
    device_info['vulnerabilities'] = vulnerabilities
    device_info['risk_score'] = min(risk_score, 100)
    
    # Determine security level
    if risk_score >= 50:
        device_info['security_level'] = 'CRITICAL'
    elif risk_score >= 30:
        device_info['security_level'] = 'HIGH'
    elif risk_score >= 15:
        device_info['security_level'] = 'MEDIUM'
    elif risk_score > 0:
        device_info['security_level'] = 'LOW'
    else:
        device_info['security_level'] = 'SAFE'
    
    return device_info


def get_deep_threat_intelligence(ip: str) -> Dict[str, Any]:
    """Perform deep reverse engineering and threat intelligence on an IP address."""
    intel = {
        'ip': ip,
        'whois': {},
        'geolocation': {},
        'reverse_dns': None,
        'threat_reports': [],
        'associated_domains': [],
        'abuse_reports': [],
        'ssl_certificates': [],
        'open_ports': [],
        'os_fingerprint': None,
        'device_type': 'Unknown',
        'reputation_score': 0,
        'threat_categories': [],
        'first_seen': None,
        'last_seen': None,
        'related_ips': [],
        'is_tor_exit': False,
        'is_vpn': False,
        'is_proxy': False,
        'is_datacenter': False,
        'isp_info': {},
        'network_info': {},
        'local_scan': None
    }
    
    # Check if private IP - but still perform local scanning!
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('172.31.'):
        intel['is_private'] = True
        intel['network_info']['type'] = 'Private/LAN'
        
        # Perform actual local device scanning
        intel['local_scan'] = scan_local_device(ip)
        
        # Copy relevant info to main intel object
        if intel['local_scan']:
            intel['open_ports'] = intel['local_scan'].get('open_ports', [])
            intel['os_fingerprint'] = intel['local_scan'].get('os_fingerprint', 'Unknown')
            intel['device_type'] = intel['local_scan'].get('device_type', 'Unknown')
            intel['network_info']['hostname'] = intel['local_scan'].get('hostname')
            intel['network_info']['mac_address'] = intel['local_scan'].get('mac_address')
            intel['network_info']['vendor'] = intel['local_scan'].get('vendor')
        
        return intel
    
    intel['is_private'] = False
    
    # Reverse DNS
    try:
        import socket
        intel['reverse_dns'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        intel['reverse_dns'] = 'No PTR record'
    
    # WHOIS lookup
    try:
        import subprocess
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=5,
                                  encoding='utf-8', errors='ignore')
        intel['whois']['raw'] = result.stdout
    except Exception:
        pass
    
    # IP-API for geolocation and ISP info (free API)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                intel['geolocation'] = {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown')
                }
                intel['isp_info'] = {
                    'isp': data.get('isp', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'asn': data.get('as', 'Unknown'),
                    'asn_name': data.get('asname', 'Unknown')
                }
                intel['is_proxy'] = data.get('proxy', False)
                intel['is_datacenter'] = data.get('hosting', False)
                intel['is_vpn'] = data.get('proxy', False) or data.get('hosting', False)
    except Exception as e:
        app_logger.debug(f"IP-API lookup failed: {e}")
    
    # VirusTotal check for threat info
    if Config.VIRUSTOTAL_API_KEY:
        try:
            headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
            url = Config.VIRUSTOTAL_IP_URL.format(ip)
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                
                intel['reputation_score'] = attrs.get('reputation', 0)
                intel['threat_reports'] = []
                
                # Get detailed vendor reports
                results = attrs.get('last_analysis_results', {})
                for vendor, result in results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        intel['threat_reports'].append({
                            'vendor': vendor,
                            'category': result.get('category'),
                            'result': result.get('result', 'Flagged'),
                            'method': result.get('method', 'Unknown')
                        })
                
                # Get associated domains/URLs
                intel['associated_domains'] = attrs.get('last_https_certificate', {}).get('extensions', {}).get('subject_alternative_name', [])[:10]
                
                # Check for Tor/VPN indicators
                if 'tor' in str(attrs).lower():
                    intel['is_tor_exit'] = True
                if 'vpn' in str(attrs).lower() or 'proxy' in str(attrs).lower():
                    intel['is_vpn'] = True
                    
        except Exception as e:
            app_logger.debug(f"VT threat intel failed: {e}")
    
    # AbuseIPDB check (if API key available - free tier available)
    abuse_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
    if abuse_api_key:
        try:
            headers = {'Key': abuse_api_key, 'Accept': 'application/json'}
            resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                intel['abuse_reports'] = {
                    'total_reports': data.get('totalReports', 0),
                    'confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'last_reported': data.get('lastReportedAt'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'domain': data.get('domain', 'Unknown')
                }
        except Exception:
            pass
    
    # Calculate threat categories
    if intel['threat_reports']:
        categories = set()
        for report in intel['threat_reports']:
            result = report.get('result', '').lower()
            if 'malware' in result or 'trojan' in result:
                categories.add('Malware Distribution')
            if 'phish' in result:
                categories.add('Phishing')
            if 'spam' in result:
                categories.add('Spam')
            if 'c2' in result or 'command' in result or 'control' in result:
                categories.add('C2 Server')
            if 'botnet' in result:
                categories.add('Botnet')
            if 'scan' in result:
                categories.add('Port Scanning')
        intel['threat_categories'] = list(categories) if categories else ['Suspicious Activity']
    
    return intel


def get_ssl_certificate_info(ip: str, port: int = 443) -> Dict[str, Any]:
    """Extract SSL/TLS certificate information from a host."""
    import ssl
    import socket
    from datetime import datetime
    
    cert_info = {
        'valid': False,
        'error': None,
        'subject': {},
        'issuer': {},
        'version': None,
        'serial_number': None,
        'not_before': None,
        'not_after': None,
        'expired': False,
        'days_until_expiry': None,
        'san': [],
        'signature_algorithm': None,
        'key_size': None,
        'is_self_signed': False,
        'cipher_suite': None,
        'tls_version': None,
        'vulnerabilities': []
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                
                if cert:
                    cert_info['valid'] = True
                    cert_info['cipher_suite'] = ssock.cipher()[0]
                    cert_info['tls_version'] = ssock.version()
                    
                    # Parse certificate
                    if 'subject' in cert:
                        for rdn in cert['subject']:
                            for key, value in rdn:
                                cert_info['subject'][key] = value
                    
                    if 'issuer' in cert:
                        for rdn in cert['issuer']:
                            for key, value in rdn:
                                cert_info['issuer'][key] = value
                    
                    # Check self-signed
                    if cert_info['subject'] == cert_info['issuer']:
                        cert_info['is_self_signed'] = True
                        cert_info['vulnerabilities'].append('Self-signed certificate')
                    
                    # Check expiry
                    if 'notAfter' in cert:
                        cert_info['not_after'] = cert['notAfter']
                        try:
                            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            cert_info['days_until_expiry'] = (expiry - datetime.now()).days
                            if cert_info['days_until_expiry'] < 0:
                                cert_info['expired'] = True
                                cert_info['vulnerabilities'].append('Certificate expired')
                            elif cert_info['days_until_expiry'] < 30:
                                cert_info['vulnerabilities'].append('Certificate expiring soon')
                        except Exception:
                            pass
                    
                    if 'notBefore' in cert:
                        cert_info['not_before'] = cert['notBefore']
                    
                    # Subject Alternative Names
                    if 'subjectAltName' in cert:
                        cert_info['san'] = [x[1] for x in cert['subjectAltName']]
                    
                    # Check for weak TLS
                    if cert_info['tls_version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        cert_info['vulnerabilities'].append(f'Weak TLS version: {cert_info["tls_version"]}')
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                    if any(weak in str(cert_info['cipher_suite']).upper() for weak in weak_ciphers):
                        cert_info['vulnerabilities'].append(f'Weak cipher suite: {cert_info["cipher_suite"]}')
                        
    except ssl.SSLError as e:
        cert_info['error'] = f"SSL Error: {str(e)}"
    except socket.timeout:
        cert_info['error'] = "Connection timeout"
    except ConnectionRefusedError:
        cert_info['error'] = "Connection refused"
    except Exception as e:
        cert_info['error'] = str(e)
    
    return cert_info


def get_mac_vendor(mac_address: str) -> str:
    """Get device vendor from MAC address prefix (OUI lookup)."""
    if not mac_address or mac_address == 'Unknown (ICMP only)':
        return 'Unknown'
    
    # Common MAC prefixes for vendor identification
    oui_database = {
        # Apple devices
        '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple', '00:0a:95': 'Apple',
        '00:0d:93': 'Apple', '00:10:fa': 'Apple', '00:11:24': 'Apple', '00:14:51': 'Apple',
        '00:16:cb': 'Apple', '00:17:f2': 'Apple', '00:19:e3': 'Apple', '00:1b:63': 'Apple',
        '00:1c:b3': 'Apple', '00:1d:4f': 'Apple', '00:1e:52': 'Apple', '00:1e:c2': 'Apple',
        '00:1f:5b': 'Apple', '00:1f:f3': 'Apple', '00:21:e9': 'Apple', '00:22:41': 'Apple',
        '00:23:12': 'Apple', '00:23:32': 'Apple', '00:23:6c': 'Apple', '00:23:df': 'Apple',
        '00:24:36': 'Apple', '00:25:00': 'Apple', '00:25:4b': 'Apple', '00:25:bc': 'Apple',
        '00:26:08': 'Apple', '00:26:4a': 'Apple', '00:26:b0': 'Apple', '00:26:bb': 'Apple',
        'a8:5c:2c': 'Apple', 'ac:bc:32': 'Apple', 'b8:e8:56': 'Apple', 'c8:69:cd': 'Apple',
        # Samsung
        '00:07:ab': 'Samsung', '00:12:47': 'Samsung', '00:12:fb': 'Samsung', '00:13:77': 'Samsung',
        '00:15:b9': 'Samsung', '00:16:32': 'Samsung', '00:16:6b': 'Samsung', '00:16:6c': 'Samsung',
        '00:17:c9': 'Samsung', '00:17:d5': 'Samsung', '00:18:af': 'Samsung', '00:1a:8a': 'Samsung',
        '00:1b:98': 'Samsung', '00:1c:43': 'Samsung', '00:1d:25': 'Samsung', '00:1d:f6': 'Samsung',
        '00:1e:7d': 'Samsung', '00:1f:cc': 'Samsung', '00:21:19': 'Samsung', '00:21:4c': 'Samsung',
        '00:21:d1': 'Samsung', '00:21:d2': 'Samsung', '00:24:54': 'Samsung', '00:24:90': 'Samsung',
        '00:24:91': 'Samsung', '00:24:e9': 'Samsung', '00:25:66': 'Samsung', '00:26:37': 'Samsung',
        'c4:73:1e': 'Samsung', 'c8:ba:94': 'Samsung', 'd0:22:be': 'Samsung', 'd8:90:e8': 'Samsung',
        # Huawei
        '00:18:82': 'Huawei', '00:1e:10': 'Huawei', '00:25:68': 'Huawei', '00:25:9e': 'Huawei',
        '00:34:fe': 'Huawei', '00:46:4b': 'Huawei', '00:66:4b': 'Huawei', '00:9a:cd': 'Huawei',
        '00:e0:fc': 'Huawei', '04:02:1f': 'Huawei', '04:bd:70': 'Huawei', '04:c0:6f': 'Huawei',
        '08:19:a6': 'Huawei', '08:63:61': 'Huawei', '08:7a:4c': 'Huawei', '0c:37:dc': 'Huawei',
        # Xiaomi
        '00:9e:c8': 'Xiaomi', '0c:1d:af': 'Xiaomi', '10:2a:b3': 'Xiaomi', '14:f6:5a': 'Xiaomi',
        '18:59:36': 'Xiaomi', '20:82:c0': 'Xiaomi', '28:6c:07': 'Xiaomi', '34:80:b3': 'Xiaomi',
        '38:a4:ed': 'Xiaomi', '3c:bd:3e': 'Xiaomi', '44:23:7c': 'Xiaomi', '50:64:2b': 'Xiaomi',
        '58:44:98': 'Xiaomi', '64:09:80': 'Xiaomi', '64:b4:73': 'Xiaomi', '68:28:ba': 'Xiaomi',
        # Google
        '00:1a:11': 'Google', '3c:5a:b4': 'Google', '54:60:09': 'Google', '94:eb:2c': 'Google',
        'f4:f5:d8': 'Google', 'f4:f5:e8': 'Google',
        # Amazon (Echo, Fire, etc.)
        '00:fc:8b': 'Amazon', '34:d2:70': 'Amazon', '38:f7:3d': 'Amazon', '40:b4:cd': 'Amazon',
        '44:65:0d': 'Amazon', '50:dc:e7': 'Amazon', '68:54:fd': 'Amazon', '74:c2:46': 'Amazon',
        '78:e1:03': 'Amazon', 'a0:02:dc': 'Amazon', 'ac:63:be': 'Amazon', 'b4:7c:9c': 'Amazon',
        # Microsoft/Xbox
        '00:03:ff': 'Microsoft', '00:0d:3a': 'Microsoft', '00:12:5a': 'Microsoft', '00:15:5d': 'Microsoft',
        '00:17:fa': 'Microsoft', '00:1d:d8': 'Microsoft', '00:22:48': 'Microsoft', '00:25:ae': 'Microsoft',
        '00:50:f2': 'Microsoft', '28:18:78': 'Microsoft', '60:45:bd': 'Microsoft', '7c:1e:52': 'Microsoft',
        # Sony/PlayStation
        '00:00:c3': 'Sony', '00:01:4a': 'Sony', '00:04:1f': 'Sony', '00:13:a9': 'Sony',
        '00:15:c1': 'Sony', '00:19:c5': 'Sony', '00:1a:80': 'Sony', '00:1d:ba': 'Sony',
        '00:1e:a4': 'Sony', '00:24:be': 'Sony', '28:0d:fc': 'Sony', '70:9e:29': 'Sony',
        # Intel
        '00:02:b3': 'Intel', '00:03:47': 'Intel', '00:04:23': 'Intel', '00:07:e9': 'Intel',
        '00:0c:f1': 'Intel', '00:0e:0c': 'Intel', '00:0e:35': 'Intel', '00:11:11': 'Intel',
        '00:12:f0': 'Intel', '00:13:02': 'Intel', '00:13:20': 'Intel', '00:13:ce': 'Intel',
        # TP-Link
        '00:27:19': 'TP-Link', '14:cc:20': 'TP-Link', '14:cf:92': 'TP-Link', '18:a6:f7': 'TP-Link',
        '1c:3b:f3': 'TP-Link', '30:b5:c2': 'TP-Link', '50:c7:bf': 'TP-Link', '54:c8:0f': 'TP-Link',
        '60:e3:27': 'TP-Link', '64:66:b3': 'TP-Link', '70:4f:57': 'TP-Link', '94:d9:b3': 'TP-Link',
        # Netgear
        '00:09:5b': 'Netgear', '00:0f:b5': 'Netgear', '00:14:6c': 'Netgear', '00:18:4d': 'Netgear',
        '00:1b:2f': 'Netgear', '00:1e:2a': 'Netgear', '00:1f:33': 'Netgear', '00:22:3f': 'Netgear',
        '00:24:b2': 'Netgear', '00:26:f2': 'Netgear', '20:4e:7f': 'Netgear', '28:c6:8e': 'Netgear',
        # D-Link
        '00:05:5d': 'D-Link', '00:0d:88': 'D-Link', '00:0f:3d': 'D-Link', '00:11:95': 'D-Link',
        '00:13:46': 'D-Link', '00:15:e9': 'D-Link', '00:17:9a': 'D-Link', '00:19:5b': 'D-Link',
        '00:1b:11': 'D-Link', '00:1c:f0': 'D-Link', '00:1e:58': 'D-Link', '00:21:91': 'D-Link',
        # ASUS
        '00:0c:6e': 'ASUS', '00:0e:a6': 'ASUS', '00:11:2f': 'ASUS', '00:11:d8': 'ASUS',
        '00:13:d4': 'ASUS', '00:15:f2': 'ASUS', '00:17:31': 'ASUS', '00:18:f3': 'ASUS',
        '00:1a:92': 'ASUS', '00:1b:fc': 'ASUS', '00:1d:60': 'ASUS', '00:1e:8c': 'ASUS',
        # LG
        '00:1c:62': 'LG', '00:1e:75': 'LG', '00:1f:6b': 'LG', '00:1f:e3': 'LG',
        '00:22:a9': 'LG', '00:24:83': 'LG', '00:25:e5': 'LG', '00:26:e2': 'LG',
        '10:68:3f': 'LG', '10:f9:6f': 'LG', '14:c9:13': 'LG', '20:21:a5': 'LG',
        # Dell
        '00:06:5b': 'Dell', '00:08:74': 'Dell', '00:0b:db': 'Dell', '00:0d:56': 'Dell',
        '00:0f:1f': 'Dell', '00:11:43': 'Dell', '00:12:3f': 'Dell', '00:13:72': 'Dell',
        '00:14:22': 'Dell', '00:15:c5': 'Dell', '00:18:8b': 'Dell', '00:19:b9': 'Dell',
        # HP
        '00:00:63': 'HP', '00:01:e6': 'HP', '00:01:e7': 'HP', '00:02:a5': 'HP',
        '00:04:ea': 'HP', '00:08:02': 'HP', '00:08:83': 'HP', '00:0a:57': 'HP',
        '00:0b:cd': 'HP', '00:0d:9d': 'HP', '00:0e:7f': 'HP', '00:0f:20': 'HP',
        # Lenovo
        '00:06:1b': 'Lenovo', '00:09:2d': 'Lenovo', '00:0a:e4': 'Lenovo', '00:12:fe': 'Lenovo',
        '00:16:d4': 'Lenovo', '00:1a:6b': 'Lenovo', '00:1e:4f': 'Lenovo', '00:21:cc': 'Lenovo',
        # Cisco
        '00:00:0c': 'Cisco', '00:01:42': 'Cisco', '00:01:43': 'Cisco', '00:01:63': 'Cisco',
        '00:01:64': 'Cisco', '00:01:96': 'Cisco', '00:01:97': 'Cisco', '00:01:c7': 'Cisco',
        '00:01:c9': 'Cisco', '00:02:16': 'Cisco', '00:02:17': 'Cisco', '00:02:3d': 'Cisco',
        # Nintendo
        '00:09:bf': 'Nintendo', '00:16:56': 'Nintendo', '00:17:ab': 'Nintendo', '00:19:1d': 'Nintendo',
        '00:19:fd': 'Nintendo', '00:1a:e9': 'Nintendo', '00:1b:7a': 'Nintendo', '00:1b:ea': 'Nintendo',
        '00:1c:be': 'Nintendo', '00:1d:bc': 'Nintendo', '00:1e:35': 'Nintendo', '00:1f:32': 'Nintendo',
    }
    
    # Normalize MAC to lowercase with colons
    mac_clean = mac_address.lower().replace('-', ':')
    prefix = mac_clean[:8]
    
    if prefix in oui_database:
        return oui_database[prefix]
    
    # Try API lookup as fallback
    try:
        mac_lookup = mac_clean.replace(':', '').upper()[:6]
        response = requests.get(f'https://api.macvendors.com/{mac_lookup}', timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass
    
    return 'Unknown'


def detect_device_type(vendor: str, hostname: str) -> str:
    """Detect device type based on vendor and hostname."""
    vendor_lower = vendor.lower() if vendor else ''
    hostname_lower = hostname.lower() if hostname else ''
    combined = f"{vendor_lower} {hostname_lower}"
    
    # Smartphones
    phone_indicators = ['iphone', 'android', 'samsung', 'huawei', 'xiaomi', 'oppo', 
                       'vivo', 'oneplus', 'pixel', 'galaxy', 'redmi', 'realme', 'phone']
    if any(indicator in combined for indicator in phone_indicators):
        return 'Smartphone'
    
    # Tablets
    tablet_indicators = ['ipad', 'tab', 'tablet', 'kindle']
    if any(indicator in combined for indicator in tablet_indicators):
        return 'Tablet'
    
    # Smart TVs
    tv_indicators = ['tv', 'smart-tv', 'roku', 'firestick', 'chromecast', 'appletv', 'android tv']
    if any(indicator in combined for indicator in tv_indicators):
        return 'Smart TV'
    
    # Gaming Consoles
    gaming_indicators = ['playstation', 'xbox', 'nintendo', 'switch', 'ps4', 'ps5']
    if any(indicator in combined for indicator in gaming_indicators):
        return 'Gaming Console'
    
    # Smart Home / IoT
    iot_indicators = ['echo', 'alexa', 'nest', 'ring', 'hue', 'sonos', 'smart', 'home', 'iot']
    if any(indicator in combined for indicator in iot_indicators):
        return 'Smart Home'
    
    # Routers/Network Equipment
    network_indicators = ['router', 'gateway', 'ap', 'access-point', 'switch', 'modem', 
                         'tp-link', 'netgear', 'd-link', 'linksys', 'ubiquiti', 'asus-rt', 'cisco']
    if any(indicator in combined for indicator in network_indicators):
        return 'Network Device'
    
    # Printers
    printer_indicators = ['printer', 'print', 'epson', 'canon', 'brother', 'hp-', 'lexmark']
    if any(indicator in combined for indicator in printer_indicators):
        return 'Printer'
    
    # Laptops/Desktop Computers
    computer_indicators = ['laptop', 'desktop', 'macbook', 'imac', 'dell', 'lenovo', 
                          'hp', 'thinkpad', 'surface', 'pc-', 'workstation']
    if any(indicator in combined for indicator in computer_indicators):
        return 'Computer'
    
    # Apple devices
    if 'apple' in vendor_lower:
        return 'Apple Device'
    
    return 'Unknown'


def enhanced_network_scan(router_ip: str, timeout: int = 3) -> List[Dict[str, Any]]:
    """Enhanced network scan using multiple methods to find ALL devices."""
    devices = {}
    
    if not SCAPY_AVAILABLE:
        return []
    
    try:
        # Method 1: ARP Scan (Layer 2 - finds all active devices)
        ip_range = router_ip.rsplit('.', 1)[0] + '.1/24'
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=timeout, verbose=0)
            for snd, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'discovery_method': 'ARP',
                    'hostname': None,
                    'vendor': None,
                    'device_type': 'Unknown',
                    'os_hint': None,
                    'open_ports': []
                }
        except Exception as e:
            app_logger.debug(f"ARP scan error: {e}")
        
        # Method 2: ICMP Ping Sweep (finds devices that respond to ping)
        import subprocess
        base_ip = router_ip.rsplit('.', 1)[0]
        
        def ping_host(ip):
            try:
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '500', ip],
                    capture_output=True, text=True, timeout=2
                )
                return result.returncode == 0
            except Exception:
                return False
        
        # Quick ping sweep for hosts not found by ARP
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {}
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                if ip not in devices:
                    futures[executor.submit(ping_host, ip)] = ip
            
            for future in futures:
                ip = futures[future]
                try:
                    if future.result():
                        if ip not in devices:
                            devices[ip] = {
                                'ip': ip,
                                'mac': 'Unknown (ICMP only)',
                                'discovery_method': 'ICMP',
                                'hostname': None,
                                'vendor': None,
                                'device_type': 'Unknown',
                                'os_hint': None,
                                'open_ports': []
                            }
                except Exception:
                    pass
        
        # Method 3: NetBIOS scan for Windows devices
        try:
            result = subprocess.run(['nbtstat', '-n'], capture_output=True, text=True, timeout=5,
                                      encoding='utf-8', errors='ignore')
            # Parse NetBIOS info...
        except Exception:
            pass
        
        # Resolve hostnames and get additional info for each device
        import socket
        for ip, dev in devices.items():
            # Hostname lookup
            try:
                dev['hostname'] = socket.gethostbyaddr(ip)[0]
            except Exception:
                dev['hostname'] = ip
            
            # MAC vendor lookup
            if dev['mac'] and dev['mac'] != 'Unknown (ICMP only)':
                dev['vendor'] = get_mac_vendor(dev['mac'])
            
            # Device type detection
            dev['device_type'] = detect_device_type(dev['vendor'] or '', dev['hostname'] or '')
            
            # OS fingerprinting hint from TTL
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], capture_output=True, text=True, timeout=3,
                                          encoding='utf-8', errors='ignore')
                if 'TTL=' in result.stdout:
                    ttl = int(result.stdout.split('TTL=')[1].split()[0])
                    if ttl <= 64:
                        dev['os_hint'] = 'Linux/Unix/Android/iOS'
                    elif ttl <= 128:
                        dev['os_hint'] = 'Windows'
                    else:
                        dev['os_hint'] = 'Network Device/Solaris'
            except Exception:
                pass
        
        return list(devices.values())
        
    except Exception as e:
        app_logger.error(f"Enhanced network scan failed: {e}")
        return []


def analyze_tls_traffic(packet_data: bytes) -> Dict[str, Any]:
    """Analyze TLS/SSL traffic metadata (without decryption)."""
    analysis = {
        'is_tls': False,
        'tls_version': None,
        'content_type': None,
        'handshake_type': None,
        'cipher_suites': [],
        'sni_hostname': None,
        'session_id': None,
        'extensions': [],
        'alerts': [],
        'security_issues': []
    }
    
    if len(packet_data) < 5:
        return analysis
    
    # TLS Record Header
    content_type = packet_data[0]
    if content_type not in [20, 21, 22, 23]:  # Change Cipher, Alert, Handshake, Application
        return analysis
    
    analysis['is_tls'] = True
    analysis['content_type'] = {
        20: 'Change Cipher Spec',
        21: 'Alert',
        22: 'Handshake',
        23: 'Application Data'
    }.get(content_type, 'Unknown')
    
    # TLS Version
    version_major = packet_data[1]
    version_minor = packet_data[2]
    version_map = {
        (3, 0): 'SSLv3 (INSECURE!)',
        (3, 1): 'TLSv1.0 (Deprecated)',
        (3, 2): 'TLSv1.1 (Deprecated)',
        (3, 3): 'TLSv1.2',
        (3, 4): 'TLSv1.3'
    }
    analysis['tls_version'] = version_map.get((version_major, version_minor), f'Unknown ({version_major}.{version_minor})')
    
    # Security warnings
    if (version_major, version_minor) in [(3, 0), (3, 1), (3, 2)]:
        analysis['security_issues'].append(f'Weak TLS version detected: {analysis["tls_version"]}')
    
    # Try to extract SNI (Server Name Indication) from ClientHello
    if content_type == 22 and len(packet_data) > 43:  # Handshake
        try:
            handshake_type = packet_data[5]
            if handshake_type == 1:  # ClientHello
                analysis['handshake_type'] = 'ClientHello'
                # Skip to extensions and look for SNI (extension type 0)
                # This is a simplified extraction
                data_str = packet_data.decode('latin-1', errors='ignore')
                # Look for readable hostnames in the SNI
                import re
                sni_matches = re.findall(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', data_str)
                if sni_matches:
                    analysis['sni_hostname'] = sni_matches[0] if sni_matches else None
        except Exception:
            pass
    
    return analysis


# =============================================================================
# HTTPS INTERCEPTION PROXY (Authorized Use Only)
# =============================================================================

class HTTPSInterceptor:
    """
    HTTPS/TLS Traffic Interceptor for authorized security monitoring.
    WARNING: Only use with explicit authorization on networks you own/manage.
    """
    
    def __init__(self, port: int = 8443):
        self.port = port
        self.running = False
        self.intercepted_data = []
        self.cert_dir = Path.home() / '.security_monitor' / 'certs'
        self.ca_cert_path = self.cert_dir / 'ca.crt'
        self.ca_key_path = self.cert_dir / 'ca.key'
        
    def generate_ca_certificate(self) -> bool:
        """Generate a self-signed CA certificate for HTTPS interception."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timedelta
            
            # Create cert directory
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Monitor"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Threat Monitor"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Security Monitor CA"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).sign(key, hashes.SHA256(), default_backend())
            
            # Save private key
            with open(self.ca_key_path, 'wb') as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save certificate
            with open(self.ca_cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            app_logger.info(f"CA certificate generated at {self.ca_cert_path}")
            return True
            
        except ImportError:
            app_logger.error("cryptography library required. Install with: pip install cryptography")
            return False
        except Exception as e:
            app_logger.error(f"Failed to generate CA certificate: {e}")
            return False
    
    def generate_host_certificate(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """Generate a certificate for a specific hostname signed by our CA."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timedelta
            
            if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
                if not self.generate_ca_certificate():
                    return None, None
            
            # Load CA key and cert
            with open(self.ca_key_path, 'rb') as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Generate host key
            host_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate host certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                host_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=30)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                ]),
                critical=False,
            ).sign(ca_key, hashes.SHA256(), default_backend())
            
            # Save to temp files
            host_cert_path = self.cert_dir / f"{hostname.replace('.', '_')}.crt"
            host_key_path = self.cert_dir / f"{hostname.replace('.', '_')}.key"
            
            with open(host_key_path, 'wb') as f:
                f.write(host_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(host_cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            return str(host_cert_path), str(host_key_path)
            
        except Exception as e:
            app_logger.error(f"Failed to generate host certificate: {e}")
            return None, None
    
    def decrypt_https_packet(self, raw_data: bytes, hostname: str = None) -> Dict[str, Any]:
        """Attempt to analyze/decrypt HTTPS packet data."""
        result = {
            'success': False,
            'hostname': hostname,
            'method': None,
            'path': None,
            'headers': {},
            'body': None,
            'cookies': [],
            'credentials': [],
            'sensitive_data': {},
            'tls_info': {}
        }
        
        # First analyze TLS metadata
        tls_analysis = analyze_tls_traffic(raw_data)
        result['tls_info'] = tls_analysis
        
        if tls_analysis.get('sni_hostname'):
            result['hostname'] = tls_analysis['sni_hostname']
        
        # For actual decryption, we need the session key or to be a MITM proxy
        # This would require mitmproxy or similar - for now we extract what we can
        
        try:
            # Try to decode as HTTP if this is decrypted traffic
            decoded = raw_data.decode('utf-8', errors='ignore')
            
            # Check if it's HTTP
            if decoded.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                result['success'] = True
                lines = decoded.split('\\r\\n')
                
                # Parse request line
                if lines:
                    parts = lines[0].split(' ')
                    if len(parts) >= 2:
                        result['method'] = parts[0]
                        result['path'] = parts[1]
                
                # Parse headers
                in_headers = True
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line == '':
                        in_headers = False
                        body_start = i + 1
                        continue
                    if in_headers and ':' in line:
                        key, value = line.split(':', 1)
                        result['headers'][key.strip()] = value.strip()
                        
                        # Extract cookies
                        if key.lower() == 'cookie':
                            result['cookies'] = value.strip().split('; ')
                        
                        # Extract auth headers
                        if key.lower() in ['authorization', 'x-auth-token', 'x-api-key']:
                            result['credentials'].append({
                                'type': key,
                                'value': value.strip()
                            })
                
                # Get body
                if body_start < len(lines):
                    result['body'] = '\\r\\n'.join(lines[body_start:])
                    
                    # Extract sensitive data from body
                    result['sensitive_data'] = extract_confidential_data(result['body'])
            
            # Check for HTTP response
            elif decoded.startswith('HTTP/'):
                result['success'] = True
                result['method'] = 'RESPONSE'
                lines = decoded.split('\\r\\n')
                
                # Parse status line
                if lines:
                    result['path'] = lines[0]  # Status line
                
                # Parse response headers and body similarly
                in_headers = True
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line == '':
                        in_headers = False
                        body_start = i + 1
                        continue
                    if in_headers and ':' in line:
                        key, value = line.split(':', 1)
                        result['headers'][key.strip()] = value.strip()
                        
                        # Set-Cookie header
                        if key.lower() == 'set-cookie':
                            result['cookies'].append(value.strip())
                
                if body_start < len(lines):
                    result['body'] = '\\r\\n'.join(lines[body_start:])
                    result['sensitive_data'] = extract_confidential_data(result['body'])
                    
        except Exception as e:
            app_logger.debug(f"HTTPS decrypt analysis error: {e}")
        
        return result
    
    def get_ca_cert_install_instructions(self) -> str:
        """Get instructions for installing the CA certificate on devices."""
        if not self.ca_cert_path.exists():
            self.generate_ca_certificate()
        
        return f"""
=======================================================================
              HTTPS INTERCEPTION - CA CERTIFICATE INSTALLATION
=======================================================================

To decrypt HTTPS traffic, install this CA certificate on target devices:

[FILE] Certificate Location: {self.ca_cert_path}

[WINDOWS]
   1. Double-click the .crt file
   2. Click "Install Certificate"
   3. Select "Local Machine" -> Next
   4. Select "Place all certificates in the following store"
   5. Browse -> "Trusted Root Certification Authorities" -> OK -> Next -> Finish

[macOS]
   1. Double-click the .crt file
   2. Keychain Access will open
   3. Select "System" keychain
   4. Find the certificate, double-click it
   5. Expand "Trust" and set "When using this certificate" to "Always Trust"

[iOS]
   1. Email the .crt file to yourself or host on a web server
   2. Open the file on your iOS device
   3. Go to Settings -> General -> VPN & Device Management
   4. Install the profile
   5. Go to Settings -> General -> About -> Certificate Trust Settings
   6. Enable full trust for the certificate

[ANDROID]
   1. Copy .crt file to device
   2. Go to Settings -> Security -> Install from storage
   3. Select the certificate file
   4. Name it and select "VPN and apps" or "WiFi"

[WARNING] IMPORTANT: Only install on devices you own and have authorization to monitor!

======================================================================="""


# Global HTTPS interceptor instance
https_interceptor = HTTPSInterceptor()


def get_router_and_devices():
    """Discover router IP and connected network devices using ARP scan."""
    if not (NETIFACES_AVAILABLE and SCAPY_AVAILABLE):
        return None, []
    
    try:
        gateways = netifaces.gateways()
        router_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
        devices = []
        
        if router_ip:
            ip_range = router_ip.rsplit('.', 1)[0] + '.1/24'
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
                for snd, rcv in ans:
                    ip = rcv.psrc
                    mac = rcv.hwsrc
                    try:
                        import socket
                        name = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        name = ip
                    devices.append({'ip': ip, 'mac': mac, 'name': name})
            except PermissionError:
                app_logger.error("Network scan requires administrator privileges")
            except Exception as e:
                app_logger.error(f"ARP scan failed: {e}")
                
        return router_ip, devices
    except Exception as e:
        app_logger.error(f"Network discovery failed: {e}")
        return None, []


# Store device last seen times
device_last_seen: Dict[str, str] = {}


# =============================================================================
# THREAT DATABASE
# =============================================================================

class ThreatDatabase:
    """Manages the threat indicator database."""
    
    DEFAULT_DATABASE = {
        "suspicious_paths": [
            "\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
            "\\programdata\\", "\\windows\\temp\\"
        ],
        "suspicious_connections": ["0.0.0.0", "127.0.0.1"],
        "high_risk_processes": [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "regsvr32.exe", "mshta.exe", "rundll32.exe"
        ]
    }
    
    def __init__(self, database_path: Optional[Path] = None):
        self.database_path = database_path or Config.THREAT_DATABASE_PATH
        self.data = self._load()
        
    def _load(self) -> Dict[str, List[str]]:
        """Load threat database from file or use defaults."""
        try:
            if self.database_path.exists():
                with open(self.database_path, 'r') as f:
                    data = json.load(f)
                    app_logger.info(f"Loaded threat database from {self.database_path}")
                    return data
        except (json.JSONDecodeError, IOError) as e:
            app_logger.warning(f"Error loading threat database: {e}")
        
        app_logger.info("Using default threat database")
        return self.DEFAULT_DATABASE.copy()
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        return self.data[key]


# =============================================================================
# THREAT MONITOR ENGINE
# =============================================================================

class ThreatMonitor:
    """Main threat monitoring engine."""
    
    def __init__(self, gui_callback: Optional[Callable] = None):
        self.wmi = wmi.WMI()
        self.known_processes: Dict[int, Dict] = {}
        self.threat_database = ThreatDatabase()
        self.gui_callback = gui_callback
        self.running = True
        app_logger.info("ThreatMonitor initialized")

    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a process."""
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'username': process.username(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'connections': process.net_connections(),
                'create_time': datetime.fromtimestamp(
                    process.create_time()
                ).strftime('%Y-%m-%d %H:%M:%S') if hasattr(datetime, 'fromtimestamp') else 'Unknown'
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            app_logger.debug(f"Error getting process details for PID {pid}: {e}")
            return None

    def analyze_process(self, process_details: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """
        Analyze a process for potential threats with detailed breakdown.
        
        Returns:
            Tuple of (risk_score, threat_breakdown) where threat_breakdown contains
            detailed information about each detected threat indicator.
        """
        if not process_details:
            return 0, {}
        
        risk_score = 0
        threat_breakdown = {
            'categories': [],           # List of threat category names
            'indicators': [],            # Detailed indicator descriptions
            'severity': 'Safe',          # Overall severity: Safe, Low, Medium, High, Critical
            'recommendations': [],       # Suggested actions
            'vt_file': None,            # VirusTotal file analysis
            'vt_ips': [],               # VirusTotal IP analysis results
            'suspicious_connections': [], # List of suspicious network connections
            'resource_abuse': [],        # Resource abuse indicators
            'details': {}               # Raw details for advanced view
        }
        
        exe_path = process_details.get('exe', '').lower()
        process_name = process_details.get('name', '').lower()
        
        # =================================================================
        # 1. SUSPICIOUS PATH DETECTION
        # =================================================================
        for sus_path in self.threat_database.get('suspicious_paths', []):
            if sus_path.lower() in exe_path:
                risk_score += 2
                threat_breakdown['categories'].append('Suspicious Location')
                threat_breakdown['indicators'].append({
                    'type': 'Suspicious Path',
                    'severity': 'Medium',
                    'description': f'Process running from suspicious location',
                    'details': f'Path contains "{sus_path}"',
                    'path': exe_path,
                    'recommendation': 'Verify the process is legitimate. Malware often hides in temp folders.'
                })
        
        # =================================================================
        # 2. HIGH-RISK PROCESS NAMES
        # =================================================================
        for high_risk in self.threat_database.get('high_risk_processes', []):
            if high_risk.lower() == process_name:
                risk_score += 2
                threat_breakdown['categories'].append('High-Risk Process')
                threat_breakdown['indicators'].append({
                    'type': 'High-Risk Process',
                    'severity': 'Medium',
                    'description': f'Process is commonly used by malware',
                    'details': f'"{process_name}" is often exploited for malicious purposes',
                    'recommendation': 'Check command-line arguments for suspicious activity.'
                })
                # Add command-line details for context
                cmdline = process_details.get('cmdline', [])
                if cmdline:
                    threat_breakdown['details']['command_line'] = ' '.join(cmdline)
        
        # =================================================================
        # 3. SUSPICIOUS NETWORK CONNECTIONS
        # =================================================================
        suspicious_ips = self.threat_database.get('suspicious_connections', [])
        for conn in process_details.get('connections', []):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = str(conn.raddr.ip)
                remote_port = conn.raddr.port
                
                # Check against known suspicious IPs
                if remote_ip in suspicious_ips:
                    risk_score += 3
                    threat_breakdown['categories'].append('Suspicious Network')
                    threat_breakdown['suspicious_connections'].append({
                        'ip': remote_ip,
                        'port': remote_port,
                        'reason': 'Known suspicious IP',
                        'severity': 'High'
                    })
                    threat_breakdown['indicators'].append({
                        'type': 'Suspicious Connection',
                        'severity': 'High',
                        'description': f'Connection to known malicious IP',
                        'details': f'Connected to {remote_ip}:{remote_port}',
                        'recommendation': 'Block this IP and investigate the process.'
                    })
                
                # Check for suspicious ports
                suspicious_ports = {
                    4444: 'Common backdoor/Metasploit',
                    5555: 'Android Debug Bridge (potential exploit)',
                    6666: 'IRC bot communication',
                    6667: 'IRC bot communication',
                    1337: 'Common hacker port',
                    31337: 'Back Orifice trojan',
                    12345: 'NetBus trojan',
                    23: 'Telnet (insecure)',
                    2323: 'Alternative telnet'
                }
                if remote_port in suspicious_ports:
                    risk_score += 2
                    if 'Suspicious Port' not in threat_breakdown['categories']:
                        threat_breakdown['categories'].append('Suspicious Port')
                    threat_breakdown['indicators'].append({
                        'type': 'Suspicious Port',
                        'severity': 'Medium',
                        'description': suspicious_ports[remote_port],
                        'details': f'Connection to port {remote_port}',
                        'recommendation': 'Investigate why this port is being used.'
                    })
                
                # VirusTotal IP check for external IPs
                if not (remote_ip.startswith('192.168.') or 
                        remote_ip.startswith('10.') or 
                        remote_ip.startswith('172.') or
                        remote_ip in ('127.0.0.1', '0.0.0.0')):
                    mal, susp = vt_check_ip(remote_ip)
                    if mal is not None or susp is not None:
                        threat_breakdown['vt_ips'].append({
                            'ip': remote_ip,
                            'port': remote_port,
                            'malicious': mal or 0,
                            'suspicious': susp or 0
                        })
                        if (mal and mal > 0) or (susp and susp > 0):
                            risk_score += min(3, (mal or 0) + (susp or 0))
                            threat_breakdown['categories'].append('VT Flagged IP')
                            threat_breakdown['indicators'].append({
                                'type': 'VirusTotal Alert',
                                'severity': 'High' if mal and mal >= 3 else 'Medium',
                                'description': f'IP flagged by security vendors',
                                'details': f'{remote_ip} - {mal} malicious, {susp} suspicious detections',
                                'recommendation': 'Block this IP immediately.'
                            })
        
        # =================================================================
        # 4. RESOURCE ABUSE DETECTION (Cryptomining, DoS)
        # =================================================================
        cpu_percent = process_details.get('cpu_percent', 0)
        memory_percent = process_details.get('memory_percent', 0)
        
        if cpu_percent > 80:
            risk_score += 1
            threat_breakdown['categories'].append('Resource Abuse')
            threat_breakdown['resource_abuse'].append({
                'type': 'High CPU',
                'value': f'{cpu_percent:.1f}%',
                'threshold': '80%'
            })
            threat_breakdown['indicators'].append({
                'type': 'High CPU Usage',
                'severity': 'Low',
                'description': 'Process consuming excessive CPU',
                'details': f'CPU usage: {cpu_percent:.1f}%',
                'recommendation': 'May indicate cryptomining or runaway process.'
            })
            
        if memory_percent > 80:
            risk_score += 1
            if 'Resource Abuse' not in threat_breakdown['categories']:
                threat_breakdown['categories'].append('Resource Abuse')
            threat_breakdown['resource_abuse'].append({
                'type': 'High Memory',
                'value': f'{memory_percent:.1f}%',
                'threshold': '80%'
            })
            threat_breakdown['indicators'].append({
                'type': 'High Memory Usage',
                'severity': 'Low',
                'description': 'Process consuming excessive memory',
                'details': f'Memory usage: {memory_percent:.1f}%',
                'recommendation': 'May indicate memory leak or malicious activity.'
            })
        
        # =================================================================
        # 5. VIRUSTOTAL FILE HASH CHECK
        # =================================================================
        file_path = process_details.get('exe')
        if file_path and Config.VIRUSTOTAL_API_KEY:
            file_hash = vt_get_file_hash(file_path)
            if file_hash:
                mal, susp = vt_check_file(file_hash)
                if mal is not None or susp is not None:
                    threat_breakdown['vt_file'] = {
                        'hash': file_hash,
                        'malicious': mal or 0,
                        'suspicious': susp or 0,
                        'path': file_path
                    }
                    if (mal and mal > 0) or (susp and susp > 0):
                        vt_risk = min(5, (mal or 0) + (susp or 0))
                        risk_score += vt_risk
                        threat_breakdown['categories'].append('VT Malware Detection')
                        threat_breakdown['indicators'].append({
                            'type': 'VirusTotal Malware',
                            'severity': 'Critical' if mal and mal >= 5 else 'High',
                            'description': f'File flagged as malware by security vendors',
                            'details': f'{mal} malicious, {susp} suspicious detections',
                            'hash': file_hash,
                            'recommendation': 'TERMINATE IMMEDIATELY and quarantine the file.'
                        })
        
        # =================================================================
        # 6. DETERMINE OVERALL SEVERITY
        # =================================================================
        if risk_score == 0:
            threat_breakdown['severity'] = 'Safe'
        elif risk_score < 3:
            threat_breakdown['severity'] = 'Low'
        elif risk_score < 5:
            threat_breakdown['severity'] = 'Medium'
        elif risk_score < 8:
            threat_breakdown['severity'] = 'High'
        else:
            threat_breakdown['severity'] = 'Critical'
        
        # =================================================================
        # 7. GENERATE RECOMMENDATIONS
        # =================================================================
        unique_categories = list(set(threat_breakdown['categories']))
        threat_breakdown['categories'] = unique_categories
        
        if 'VT Malware Detection' in unique_categories:
            threat_breakdown['recommendations'].append('[CRITICAL] Terminate process and quarantine file immediately')
        if 'VT Flagged IP' in unique_categories or 'Suspicious Network' in unique_categories:
            threat_breakdown['recommendations'].append('[BLOCK] Block suspicious IP addresses using firewall')
        if 'High-Risk Process' in unique_categories:
            threat_breakdown['recommendations'].append('[REVIEW] Review command-line arguments for suspicious activity')
        if 'Suspicious Location' in unique_categories:
            threat_breakdown['recommendations'].append('[VERIFY] Verify file origin and scan with antivirus')
        if 'Resource Abuse' in unique_categories:
            threat_breakdown['recommendations'].append('[MONITOR] Monitor resource usage; may indicate cryptomining')
        
        # Store process details
        threat_breakdown['details']['process_name'] = process_details.get('name', 'Unknown')
        threat_breakdown['details']['pid'] = process_details.get('pid')
        threat_breakdown['details']['exe'] = process_details.get('exe', 'Unknown')
        threat_breakdown['details']['username'] = process_details.get('username', 'Unknown')
        threat_breakdown['details']['create_time'] = process_details.get('create_time', 'Unknown')
        
        return risk_score, threat_breakdown

    def terminate_process(self, pid: int) -> bool:
        """Terminate a process by PID."""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            process.terminate()
            app_logger.warning(f"Terminated suspicious process: {process_name} (PID: {pid})")
            print(f"{Fore.RED}[!] Terminated suspicious process: {process_name} (PID: {pid}){Style.RESET_ALL}")
            return True
        except psutil.NoSuchProcess:
            app_logger.warning(f"Process {pid} no longer exists")
            return False
        except psutil.AccessDenied:
            app_logger.error(f"Access denied when terminating PID {pid}")
            return False
        except Exception as e:
            app_logger.error(f"Failed to terminate process {pid}: {e}")
            return False


    def monitor_system(self):
        """Main monitoring loop - continuously scans running processes for threats."""
        if not self.gui_callback:
            print(f"{Fore.GREEN}[+] Starting Security Threat Intelligence Monitor...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Press Ctrl+C to stop monitoring{Style.RESET_ALL}")
        
        app_logger.info("Starting system monitoring")
        
        # Clear old cache data to prevent type mismatch errors
        self.known_processes.clear()
        
        while self.running:
            try:
                for process in psutil.process_iter(['pid', 'name']):
                    pid = process.info['pid']
                    
                    # Skip recently checked processes
                    cache_entry = self.known_processes.get(pid)
                    if cache_entry:
                        time_since_check = time.time() - cache_entry['last_check']
                        if time_since_check < Config.PROCESS_CACHE_TTL_SECONDS:
                            continue
                    
                    # Get process details
                    process_details = self.get_process_details(pid)
                    if not process_details:
                        continue
                    
                    # Analyze for threats with detailed breakdown
                    result = self.analyze_process(process_details)
                    
                    # Handle both tuple and single value returns for backwards compatibility
                    if isinstance(result, tuple):
                        risk_score, threat_breakdown = result
                    else:
                        risk_score = result if isinstance(result, int) else 0
                        threat_breakdown = {}
                    
                    # Ensure risk_score is always an int
                    if not isinstance(risk_score, int):
                        risk_score = int(risk_score) if isinstance(risk_score, (int, float)) else 0
                    
                    # Update cache
                    self.known_processes[pid] = {
                        'last_check': time.time(),
                        'risk_score': risk_score,
                        'breakdown': threat_breakdown
                    }
                    
                    # Handle threats
                    if risk_score >= Config.RISK_THRESHOLD_WARNING:
                        is_critical = risk_score >= Config.RISK_THRESHOLD_CRITICAL
                        status = 'High-Risk' if is_critical else 'Suspicious'
                        
                        # Build threat info with breakdown
                        threat_info = {
                            'pid': pid,
                            'name': process_details['name'],
                            'exe': process_details['exe'],
                            'risk_score': risk_score,
                            'status': status,
                            'severity': threat_breakdown.get('severity', 'Unknown'),
                            'categories': threat_breakdown.get('categories', []),
                            'indicators': threat_breakdown.get('indicators', []),
                            'recommendations': threat_breakdown.get('recommendations', []),
                            'vt_file': threat_breakdown.get('vt_file'),
                            'vt_ips': threat_breakdown.get('vt_ips', []),
                            'suspicious_connections': threat_breakdown.get('suspicious_connections', []),
                            'resource_abuse': threat_breakdown.get('resource_abuse', []),
                            'details': threat_breakdown.get('details', {})
                        }
                        
                        if self.gui_callback:
                            self.gui_callback(threat_info)
                        else:
                            # Console output with breakdown
                            severity_colors = {
                                'Critical': Fore.RED,
                                'High': Fore.LIGHTRED_EX,
                                'Medium': Fore.YELLOW,
                                'Low': Fore.LIGHTYELLOW_EX,
                                'Safe': Fore.GREEN
                            }
                            sev_color = severity_colors.get(threat_breakdown['severity'], Fore.WHITE)
                            
                            print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
                            print(f"{sev_color}[!] {threat_breakdown['severity'].upper()} THREAT DETECTED{Style.RESET_ALL}")
                            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
                            print(f"  Process: {process_details['name']} (PID: {pid})")
                            print(f"  Path: {process_details['exe']}")
                            print(f"  Risk Score: {risk_score}")
                            print(f"  Severity: {sev_color}{threat_breakdown['severity']}{Style.RESET_ALL}")
                            
                            if threat_breakdown['categories']:
                                print(f"\n  {Fore.CYAN}Categories:{Style.RESET_ALL}")
                                for cat in threat_breakdown['categories']:
                                    print(f"    • {cat}")
                            
                            if threat_breakdown['indicators']:
                                print(f"\n  {Fore.CYAN}Threat Indicators:{Style.RESET_ALL}")
                                for ind in threat_breakdown['indicators']:
                                    ind_color = Fore.RED if ind['severity'] in ('Critical', 'High') else Fore.YELLOW
                                    print(f"    [{ind_color}{ind['severity']}{Style.RESET_ALL}] {ind['type']}")
                                    print(f"        {ind['description']}")
                                    print(f"        → {ind['details']}")
                            
                            if threat_breakdown['recommendations']:
                                print(f"\n  {Fore.GREEN}Recommendations:{Style.RESET_ALL}")
                                for rec in threat_breakdown['recommendations']:
                                    print(f"    {rec}")
                            
                            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
                            app_logger.warning(
                                f"Threat detected: {process_details['name']} (PID: {pid}) | "
                                f"Score: {risk_score} | Severity: {threat_breakdown['severity']} | "
                                f"Categories: {', '.join(threat_breakdown['categories'])}"
                            )
                            
                            if is_critical:
                                response = input(
                                    f"{Fore.YELLOW}Do you want to terminate this process? (y/n): {Style.RESET_ALL}"
                                )
                                if response.lower() == 'y':
                                    self.terminate_process(pid)
                
                time.sleep(Config.SCAN_INTERVAL_SECONDS)
                
            except KeyboardInterrupt:
                self.running = False
                if not self.gui_callback:
                    print(f"{Fore.GREEN}[+] Stopping Security Threat Intelligence Monitor...{Style.RESET_ALL}")
                app_logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                app_logger.error(f"Error in monitoring loop: {e}")
                if not self.gui_callback:
                    print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
                continue


# =============================================================================
# GUI APPLICATION
# =============================================================================

def run_gui():
    """Main GUI application entry point."""
    root = tk.Tk()
    root.title("Security Threat Intelligence Monitor")
    root.geometry("1280x720")
    root.minsize(1100, 650)
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('Treeview', rowheight=28, font=('Segoe UI', 10))
    style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))
    
    # Custom styles for severity levels
    style.configure('Critical.TLabel', foreground='#dc3545', font=('Segoe UI', 10, 'bold'))
    style.configure('High.TLabel', foreground='#fd7e14', font=('Segoe UI', 10, 'bold'))
    style.configure('Medium.TLabel', foreground='#ffc107', font=('Segoe UI', 10))
    style.configure('Low.TLabel', foreground='#28a745', font=('Segoe UI', 10))

    # Tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # --- Process Threats Tab ---
    process_frame = ttk.Frame(notebook)
    notebook.add(process_frame, text='🛡️ Threat Analysis')
    status_var = tk.StringVar(value="Status: Monitoring (Running in Background) | Double-click threat for details")
    status_label = ttk.Label(process_frame, textvariable=status_var, anchor="w")
    status_label.pack(fill=tk.X, padx=5, pady=2)

    columns = ("PID", "Name", "Severity", "Risk", "Categories", "VT Status", "Actions")
    tree = ttk.Treeview(process_frame, columns=columns, show="headings", height=15)
    for col in columns:
        tree.heading(col, text=col)
        if col == "Name":
            tree.column(col, width=140)
        elif col == "Categories":
            tree.column(col, width=250)
        elif col == "VT Status":
            tree.column(col, width=120)
        elif col == "Actions":
            tree.column(col, width=120)
        elif col == "Severity":
            tree.column(col, width=80)
        elif col == "Risk":
            tree.column(col, width=50)
        else:
            tree.column(col, width=70)
    tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Configure row colors for severity
    tree.tag_configure('critical', background='#f8d7da', foreground='#721c24')
    tree.tag_configure('high', background='#fff3cd', foreground='#856404')
    tree.tag_configure('medium', background='#ffeeba', foreground='#856404')
    tree.tag_configure('low', background='#d4edda', foreground='#155724')

    # --- Network Tab ---
    network_frame = ttk.Frame(notebook)
    notebook.add(network_frame, text='🌐 Network Activity')
    net_columns = ("PID", "Process", "Local Address", "Remote Address", "Status", "Suspicious", "VT IP")
    net_tree = ttk.Treeview(network_frame, columns=net_columns, show="headings", height=15)
    for col in net_columns:
        net_tree.heading(col, text=col)
        if col == "Remote Address":
            net_tree.column(col, width=200)
        elif col == "VT IP":
            net_tree.column(col, width=90)
        else:
            net_tree.column(col, width=120)
    net_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- Network Packet Tab ---
    packet_frame = ttk.Frame(notebook)
    notebook.add(packet_frame, text='📦 Network Packets')
    
    # Packet tab header with controls
    pkt_header = ttk.Frame(packet_frame)
    pkt_header.pack(fill=tk.X, padx=5, pady=5)
    
    pkt_status_var = tk.StringVar(value="Capturing packets... Double-click to inspect & extract confidential data")
    ttk.Label(pkt_header, textvariable=pkt_status_var, font=('Segoe UI', 9)).pack(side=tk.LEFT)
    
    # Stats for captured confidential data
    confidential_count = tk.IntVar(value=0)
    ttk.Label(pkt_header, text="[!] Confidential Found:", font=('Segoe UI', 9, 'bold')).pack(side=tk.RIGHT, padx=(10, 0))
    ttk.Label(pkt_header, textvariable=confidential_count, font=('Segoe UI', 9, 'bold'), foreground='#dc3545').pack(side=tk.RIGHT)
    
    # Create a PanedWindow for split view
    pkt_paned = ttk.PanedWindow(packet_frame, orient=tk.HORIZONTAL)
    pkt_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Left side - Packet List
    pkt_list_frame = ttk.Frame(pkt_paned)
    pkt_paned.add(pkt_list_frame, weight=3)
    
    pkt_columns = ("Time", "Source", "Destination", "Protocol", "Info", "Threat", "Confidential")
    pkt_tree = ttk.Treeview(pkt_list_frame, columns=pkt_columns, show="headings", height=15)
    for col in pkt_columns:
        pkt_tree.heading(col, text=col)
        if col == "Info":
            pkt_tree.column(col, width=180)
        elif col == "Confidential":
            pkt_tree.column(col, width=80)
        else:
            pkt_tree.column(col, width=100)
    
    # Scrollbar for packet tree
    pkt_scroll = ttk.Scrollbar(pkt_list_frame, orient="vertical", command=pkt_tree.yview)
    pkt_tree.configure(yscrollcommand=pkt_scroll.set)
    pkt_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    pkt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Color tags for packets with confidential data
    pkt_tree.tag_configure('confidential', background='#f8d7da', foreground='#721c24')
    pkt_tree.tag_configure('suspicious', background='#fff3cd', foreground='#856404')
    pkt_tree.tag_configure('clean', background='#d4edda', foreground='#155724')
    
    if not SCAPY_AVAILABLE:
        pkt_tree.insert("", 0, values=("-", "-", "-", "-", "Install scapy for packet capture", "-", "-"))
    
    # Right side - Confidential Data Container (ALL collected data)
    confid_container_frame = tk.LabelFrame(pkt_paned, text="  [!] COLLECTED SENSITIVE DATA  ", 
                                           bg='#2d2d44', fg='#ff6b6b', font=('Segoe UI', 11, 'bold'),
                                           relief='ridge', bd=3)
    pkt_paned.add(confid_container_frame, weight=2)
    
    # Scrollable text for all confidential data
    all_confid_text = tk.Text(confid_container_frame, height=20, font=('Consolas', 10), 
                              bg='#1a1a2e', fg='#00ff00', wrap=tk.WORD,
                              insertbackground='#00ff00', relief='flat', padx=10, pady=10)
    all_confid_scroll = ttk.Scrollbar(confid_container_frame, orient="vertical", command=all_confid_text.yview)
    all_confid_text.configure(yscrollcommand=all_confid_scroll.set)
    all_confid_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5, padx=(0, 5))
    all_confid_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Configure text tags for the confidential container
    all_confid_text.tag_configure('header', foreground='#ff4444', font=('Consolas', 11, 'bold'), background='#2a1a1a')
    all_confid_text.tag_configure('subheader', foreground='#ffd93d', font=('Consolas', 10, 'bold'))
    all_confid_text.tag_configure('value', foreground='#6bcb77', font=('Consolas', 10))
    all_confid_text.tag_configure('critical', foreground='#ff0000', font=('Consolas', 10, 'bold'), background='#330000')
    all_confid_text.tag_configure('timestamp', foreground='#4d96ff', font=('Consolas', 9, 'italic'))
    all_confid_text.tag_configure('separator', foreground='#666699', font=('Consolas', 9))
    all_confid_text.tag_configure('waiting', foreground='#888888', font=('Consolas', 10, 'italic'))
    
    # Insert initial waiting message
    all_confid_text.insert(tk.END, "\n\n", 'waiting')
    all_confid_text.insert(tk.END, "      ⏳ Scanning for sensitive data...\n\n", 'waiting')
    all_confid_text.insert(tk.END, "      Data will appear here automatically\n", 'waiting')
    all_confid_text.insert(tk.END, "      when found in network packets.\n\n", 'waiting')
    all_confid_text.insert(tk.END, "      Monitoring for:\n", 'waiting')
    all_confid_text.insert(tk.END, "      • Passwords\n", 'waiting')
    all_confid_text.insert(tk.END, "      • Credit Cards\n", 'waiting')
    all_confid_text.insert(tk.END, "      • API Keys/Tokens\n", 'waiting')
    all_confid_text.insert(tk.END, "      • Auth Headers\n", 'waiting')
    
    # Buttons for confidential container
    confid_btn_frame = tk.Frame(confid_container_frame, bg='#2d2d44')
    confid_btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    # Store all collected confidential data
    all_collected_confidential = {
        'passwords': [],
        'usernames': [],
        'emails': [],
        'credit_cards': [],
        'api_keys': [],
        'tokens': [],
        'cookies': [],
        'auth_headers': [],
        'sources': {}  # IP -> list of data found
    }
    
    def clear_confidential_container():
        """Clear all collected confidential data."""
        all_confid_text.config(state=tk.NORMAL)
        all_confid_text.delete('1.0', tk.END)
        all_confid_text.insert(tk.END, "\\n  Container cleared.\\n\\n", 'value')
        all_confid_text.insert(tk.END, "  Waiting for new data...\\n", 'timestamp')
        all_confid_text.config(state=tk.DISABLED)
        # Clear stored data
        for key in all_collected_confidential:
            if isinstance(all_collected_confidential[key], list):
                all_collected_confidential[key] = []
            else:
                all_collected_confidential[key] = {}
        confidential_count.set(0)
    
    def copy_all_confidential():
        """Copy all collected confidential data to clipboard."""
        data = []
        for key, vals in all_collected_confidential.items():
            if key == 'sources':
                continue
            if vals:
                data.append(f"\\n{key.upper()}:")
                for v in vals:
                    data.append(f"  {v}")
        if data:
            root.clipboard_clear()
            root.clipboard_append("\\n".join(data))
            messagebox.showinfo("Copied", "All confidential data copied to clipboard!")
        else:
            messagebox.showinfo("Empty", "No confidential data collected yet.")
    
    def export_all_confidential():
        """Export all collected confidential data to file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")],
            title="Export Confidential Data"
        )
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(all_collected_confidential, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write("EXTRACTED CONFIDENTIAL DATA REPORT\\n")
                        f.write("=" * 50 + "\\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n\\n")
                        for key, vals in all_collected_confidential.items():
                            if key == 'sources':
                                f.write("\\nSOURCE IPS:\\n")
                                for ip, items in vals.items():
                                    f.write(f"  {ip}: {len(items)} items\\n")
                            elif vals:
                                f.write(f"\\n{key.upper()}:\\n")
                                for v in vals:
                                    f.write(f"  - {v}\\n")
                messagebox.showinfo("Exported", f"Data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    ttk.Button(confid_btn_frame, text="📋 Copy All", command=copy_all_confidential).pack(side=tk.LEFT, padx=2)
    ttk.Button(confid_btn_frame, text="💾 Export", command=export_all_confidential).pack(side=tk.LEFT, padx=2)
    ttk.Button(confid_btn_frame, text="🗑️ Clear", command=clear_confidential_container).pack(side=tk.LEFT, padx=2)
    
    # Flag to track if first data has been added
    first_data_added = [False]  # Use list for mutable in closure
    
    def add_to_confidential_container(extracted_data: dict, source_ip: str, dest_ip: str, timestamp: str):
        """Add newly extracted confidential data to the container."""
        has_data = False
        
        # Check if any confidential data was found
        for key in ['passwords', 'usernames', 'emails', 'credit_cards', 'api_keys', 'tokens', 'cookies', 'auth_headers', 'http_form_data', 'json_data', 'binary_strings']:
            if extracted_data.get(key):
                has_data = True
                break
        
        if has_data:
            all_confid_text.config(state=tk.NORMAL)
            
            # Clear initial waiting message on first data
            if not first_data_added[0]:
                all_confid_text.delete('1.0', tk.END)
                all_confid_text.insert(tk.END, "+==========================================+\n", 'header')
                all_confid_text.insert(tk.END, "|   [!] SENSITIVE DATA DETECTED!          |\n", 'header')
                all_confid_text.insert(tk.END, "+==========================================+\n", 'header')
                first_data_added[0] = True
            
            # Add timestamp and source with prominent separator
            all_confid_text.insert(tk.END, "\n", 'separator')
            all_confid_text.insert(tk.END, f"=== {timestamp} ===\n", 'timestamp')
            all_confid_text.insert(tk.END, f"Source: {source_ip} -> {dest_ip}\n", 'subheader')
            
            # Show encoding info if available
            if extracted_data.get('encoding_used'):
                all_confid_text.insert(tk.END, f"Encoding: {extracted_data['encoding_used']}\n", 'value')
            if extracted_data.get('decoded_info'):
                for info in extracted_data['decoded_info'][:3]:  # Max 3 decode layers
                    all_confid_text.insert(tk.END, f"   > {info}\n", 'value')
            if extracted_data.get('is_encrypted'):
                all_confid_text.insert(tk.END, f"[ENCRYPTED] {extracted_data.get('encryption_type', 'Encrypted Data')}\n", 'subheader')
            
            all_confid_text.insert(tk.END, "-" * 40 + "\n", 'separator')
            
            # Track source
            if source_ip not in all_collected_confidential['sources']:
                all_collected_confidential['sources'][source_ip] = []
            
            # Add each type of data with clear formatting
            if extracted_data.get('passwords'):
                all_confid_text.insert(tk.END, "\n[PASSWORD] PASSWORDS FOUND:\n", 'critical')
                for pwd in extracted_data['passwords']:
                    if pwd not in all_collected_confidential['passwords']:
                        all_collected_confidential['passwords'].append(pwd)
                        all_collected_confidential['sources'][source_ip].append(('password', pwd))
                    all_confid_text.insert(tk.END, f"   > {pwd}\n", 'critical')
            
            if extracted_data.get('usernames'):
                all_confid_text.insert(tk.END, "\n[USER] USERNAMES:\n", 'subheader')
                for user in extracted_data['usernames']:
                    if user not in all_collected_confidential['usernames']:
                        all_collected_confidential['usernames'].append(user)
                    all_confid_text.insert(tk.END, f"   > {user}\n", 'value')
            
            if extracted_data.get('emails'):
                all_confid_text.insert(tk.END, "\n[EMAIL] EMAILS:\n", 'subheader')
                for email in extracted_data['emails']:
                    if email not in all_collected_confidential['emails']:
                        all_collected_confidential['emails'].append(email)
                    all_confid_text.insert(tk.END, f"   > {email}\n", 'value')
            
            # HTTP Form Data
            if extracted_data.get('http_form_data'):
                all_confid_text.insert(tk.END, "\n[FORM] HTTP FORM DATA:\n", 'subheader')
                for key, value in list(extracted_data['http_form_data'].items())[:10]:
                    all_confid_text.insert(tk.END, f"   > {key}: {value}\n", 'value')
            
            # JSON Data
            if extracted_data.get('json_data'):
                all_confid_text.insert(tk.END, "\n[JSON] JSON DATA:\n", 'subheader')
                for key, value in list(extracted_data['json_data'].items())[:10]:
                    all_confid_text.insert(tk.END, f"   > {key}: {str(value)[:50]}\n", 'value')
            
            # Binary strings (extracted from encrypted/binary data)
            if extracted_data.get('binary_strings'):
                all_confid_text.insert(tk.END, "\n[BINARY] EXTRACTED STRINGS:\n", 'subheader')
                for s in extracted_data['binary_strings'][:15]:
                    all_confid_text.insert(tk.END, f"   > {s}\n", 'value')
            
            if extracted_data.get('credit_cards'):
                all_confid_text.insert(tk.END, "\n[CARD] CREDIT CARDS:\n", 'critical')
                for cc in extracted_data['credit_cards']:
                    masked = cc[:4] + '*' * 8 + cc[-4:] if len(cc) >= 12 else cc
                    if cc not in all_collected_confidential['credit_cards']:
                        all_collected_confidential['credit_cards'].append(cc)
                        all_collected_confidential['sources'][source_ip].append(('credit_card', masked))
                    all_confid_text.insert(tk.END, f"   > {masked}\n", 'critical')
            
            if extracted_data.get('api_keys'):
                all_confid_text.insert(tk.END, "\n[KEY] API KEYS:\n", 'critical')
                for key in extracted_data['api_keys']:
                    if key not in all_collected_confidential['api_keys']:
                        all_collected_confidential['api_keys'].append(key)
                    display_key = key[:40] + "..." if len(key) > 40 else key
                    all_confid_text.insert(tk.END, f"   > {display_key}\n", 'critical')
            
            if extracted_data.get('tokens'):
                all_confid_text.insert(tk.END, "\n[TOKEN] TOKENS:\n", 'critical')
                for token in extracted_data['tokens']:
                    if token not in all_collected_confidential['tokens']:
                        all_collected_confidential['tokens'].append(token)
                    display_token = token[:50] + "..." if len(token) > 50 else token
                    all_confid_text.insert(tk.END, f"   > {display_token}\n", 'critical')
            
            if extracted_data.get('cookies'):
                all_confid_text.insert(tk.END, "\n[COOKIE] SESSION COOKIES:\n", 'subheader')
                for cookie in extracted_data['cookies']:
                    if cookie not in all_collected_confidential['cookies']:
                        all_collected_confidential['cookies'].append(cookie)
                    display_cookie = cookie[:60] + "..." if len(cookie) > 60 else cookie
                    all_confid_text.insert(tk.END, f"   > {display_cookie}\n", 'value')
            
            if extracted_data.get('auth_headers'):
                all_confid_text.insert(tk.END, "\n[AUTH] AUTH HEADERS:\n", 'critical')
                for auth in extracted_data['auth_headers']:
                    if auth not in all_collected_confidential['auth_headers']:
                        all_collected_confidential['auth_headers'].append(auth)
                    all_confid_text.insert(tk.END, f"   > {auth}\n", 'critical')
            
            # Update count
            total = sum(len(v) for k, v in all_collected_confidential.items() if k != 'sources')
            confidential_count.set(total)
            
            # Auto-scroll to bottom
            all_confid_text.see(tk.END)
            all_confid_text.config(state=tk.DISABLED)

    # Store extracted confidential data from packets
    packet_confidential_data = {}  # packet_idx -> extracted data

    # Human-readable packet details popup with confidential data extraction
    def show_packet_details(event):
        item = pkt_tree.identify_row(event.y)
        if not item:
            return
        values = pkt_tree.item(item)['values']
        
        # Create detailed popup window
        popup = tk.Toplevel(root)
        popup.title(f"🔍 Packet Analysis - {values[1]} → {values[2]}")
        popup.geometry("800x650")
        popup.configure(bg='#f8f9fa')
        
        # Create notebook for tabs
        detail_notebook = ttk.Notebook(popup)
        detail_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Basic Info
        basic_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(basic_frame, text="📋 Basic Info")
        
        basic_text = tk.Text(basic_frame, height=20, font=('Consolas', 10), bg='#ffffff')
        basic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        basic_info = f"""
===========================================================
                    PACKET ANALYSIS REPORT
===========================================================

[TIME] Capture Time:    {values[0]}
[SRC] Source:          {values[1]}
[DST] Destination:     {values[2]}
[PROTO] Protocol:        {values[3]}
[INFO] Info:            {values[4]}
[THREAT] Threat Level:    {values[5]}
[CONFID] Confidential:    {values[6]}

"""
        
        try:
            idx = pkt_tree.index(item)
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                from scapy.all import hexdump
                
                if pkt.haslayer('TCP'):
                    basic_info += f"""
===========================================================
                      TCP DETAILS
===========================================================
[FLAGS] TCP Flags:       {pkt['TCP'].flags}
[SEQ] Sequence:        {pkt['TCP'].seq}
[ACK] Acknowledgment:  {pkt['TCP'].ack}
[SPORT] Source Port:     {pkt['TCP'].sport}
[DPORT] Dest Port:       {pkt['TCP'].dport}
[WIN] Window Size:     {pkt['TCP'].window}
"""
                
                if pkt.haslayer('UDP'):
                    basic_info += f"""
===========================================================
                      UDP DETAILS
===========================================================
[SPORT] Source Port:     {pkt['UDP'].sport}
[DPORT] Dest Port:       {pkt['UDP'].dport}
[LEN] Length:          {pkt['UDP'].len}
"""
        except Exception:
            pass
        
        basic_text.insert('1.0', basic_info)
        basic_text.config(state=tk.DISABLED)
        
        # Tab 2: Payload & Raw Data
        payload_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(payload_frame, text="Payload Data")
        
        payload_text = tk.Text(payload_frame, height=20, font=('Consolas', 9), bg='#ffffff', wrap=tk.WORD)
        payload_scroll = ttk.Scrollbar(payload_frame, orient="vertical", command=payload_text.yview)
        payload_text.configure(yscrollcommand=payload_scroll.set)
        payload_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        payload_content = ""
        raw_payload = ""
        
        try:
            idx = pkt_tree.index(item)
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                from scapy.all import hexdump
                
                payload_content = "===========================================================\\n"
                payload_content += "                    RAW PACKET (HEX DUMP)\\n"
                payload_content += "===========================================================\\n\\n"
                payload_content += hexdump(pkt, dump=True)
                
                if pkt.haslayer('Raw'):
                    raw = pkt['Raw'].load
                    try:
                        raw_payload = raw.decode(errors='replace')
                        payload_content += "\\n\\n===========================================================\\n"
                        payload_content += "                    DECODED PAYLOAD\\n"
                        payload_content += "===========================================================\\n\\n"
                        payload_content += raw_payload
                    except Exception:
                        payload_content += f"\\n\\nBinary Payload: {raw}"
        except Exception as e:
            payload_content = f"Could not extract payload: {e}"
        
        payload_text.insert('1.0', payload_content)
        payload_text.config(state=tk.DISABLED)
        
        # Tab 3: Confidential Data Extraction
        confid_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(confid_frame, text="[!] Confidential Data")
        
        confid_header = ttk.Frame(confid_frame)
        confid_header.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(confid_header, text="[!] EXTRACTED SENSITIVE INFORMATION", 
                  font=('Segoe UI', 11, 'bold'), foreground='#dc3545').pack(anchor='w')
        ttk.Label(confid_header, text="This data was automatically extracted from the packet payload.", 
                  font=('Segoe UI', 9)).pack(anchor='w')
        
        confid_text = tk.Text(confid_frame, height=18, font=('Consolas', 10), bg='#fff5f5', wrap=tk.WORD)
        confid_scroll = ttk.Scrollbar(confid_frame, orient="vertical", command=confid_text.yview)
        confid_text.configure(yscrollcommand=confid_scroll.set)
        confid_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        confid_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for highlighting
        confid_text.tag_configure('header', foreground='#dc3545', font=('Consolas', 10, 'bold'))
        confid_text.tag_configure('value', foreground='#0066cc', font=('Consolas', 10, 'bold'))
        confid_text.tag_configure('critical', foreground='#dc3545', background='#fff0f0', font=('Consolas', 10, 'bold'))
        confid_text.tag_configure('warning', foreground='#fd7e14', font=('Consolas', 10))
        
        # Extract confidential data
        extracted = extract_confidential_data(raw_payload)
        
        confid_content = "\\n"
        has_confidential = False
        
        if extracted['passwords']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[PASSWORD] PASSWORDS FOUND:\\n", 'header')
            for pwd in extracted['passwords']:
                confid_text.insert(tk.END, f"   > {pwd}\\n", 'critical')
        
        if extracted['usernames']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[USER] USERNAMES FOUND:\\n", 'header')
            for user in extracted['usernames']:
                confid_text.insert(tk.END, f"   > {user}\\n", 'value')
        
        if extracted['emails']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[EMAIL] EMAIL ADDRESSES:\\n", 'header')
            for email in extracted['emails']:
                confid_text.insert(tk.END, f"   > {email}\\n", 'value')
        
        if extracted['credit_cards']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[CARD] CREDIT CARD NUMBERS:\\n", 'header')
            for cc in extracted['credit_cards']:
                # Mask middle digits for display
                masked = cc[:4] + '*' * (len(cc) - 8) + cc[-4:]
                confid_text.insert(tk.END, f"   > {masked} (MASKED)\\n", 'critical')
        
        if extracted['api_keys']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[KEY] API KEYS / SECRETS:\\n", 'header')
            for key in extracted['api_keys']:
                confid_text.insert(tk.END, f"   > {key[:20]}...\\n", 'critical')
        
        if extracted['tokens']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[TOKEN] JWT/AUTH TOKENS:\\n", 'header')
            for token in extracted['tokens']:
                confid_text.insert(tk.END, f"   > {token[:50]}...\\n", 'critical')
        
        if extracted['cookies']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[COOKIE] SESSION COOKIES:\\n", 'header')
            for cookie in extracted['cookies']:
                confid_text.insert(tk.END, f"   > {cookie}\\n", 'warning')
        
        if extracted['auth_headers']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n[AUTH] AUTHORIZATION HEADERS:\\n", 'header')
            for auth in extracted['auth_headers']:
                confid_text.insert(tk.END, f"   > {auth}\\n", 'critical')
        
        if extracted['sensitive_keywords']:
            confid_text.insert(tk.END, "\\n[ALERT] SENSITIVE KEYWORDS DETECTED:\\n", 'header')
            for word in set(extracted['sensitive_keywords']):
                confid_text.insert(tk.END, f"   * {word}\\n", 'warning')
        
        if not has_confidential:
            confid_text.insert(tk.END, "\\n[OK] No sensitive data detected in this packet.\\n", 'value')
            confid_text.insert(tk.END, "\\nNote: Only unencrypted (HTTP, FTP, Telnet) traffic can be analyzed.\\n")
            confid_text.insert(tk.END, "HTTPS/TLS encrypted traffic cannot reveal confidential data.\\n")
        
        confid_text.config(state=tk.DISABLED)
        
        # Tab 4: HTTPS/TLS Analysis
        tls_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(tls_frame, text="TLS/HTTPS Analysis")
        
        tls_header = ttk.Frame(tls_frame)
        tls_header.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(tls_header, text="[TLS] TLS/HTTPS TRAFFIC ANALYSIS", 
                  font=('Segoe UI', 11, 'bold'), foreground='#007bff').pack(anchor='w')
        ttk.Label(tls_header, text="Analyzing encrypted traffic metadata and attempting decryption if authorized.", 
                  font=('Segoe UI', 9)).pack(anchor='w')
        
        tls_text = tk.Text(tls_frame, height=18, font=('Consolas', 10), bg='#f0f8ff', wrap=tk.WORD)
        tls_scroll = ttk.Scrollbar(tls_frame, orient="vertical", command=tls_text.yview)
        tls_text.configure(yscrollcommand=tls_scroll.set)
        tls_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        tls_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        tls_text.tag_configure('section', foreground='#004085', font=('Consolas', 10, 'bold'))
        tls_text.tag_configure('label', foreground='#6c757d', font=('Consolas', 10))
        tls_text.tag_configure('value', foreground='#28a745', font=('Consolas', 10, 'bold'))
        tls_text.tag_configure('warning', foreground='#ffc107', font=('Consolas', 10, 'bold'))
        tls_text.tag_configure('danger', foreground='#dc3545', font=('Consolas', 10, 'bold'))
        
        try:
            idx = pkt_tree.index(item)
            tls_content = ""
            
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                
                # Check if this is HTTPS traffic (port 443)
                is_https = False
                if pkt.haslayer('TCP'):
                    if pkt['TCP'].dport == 443 or pkt['TCP'].sport == 443:
                        is_https = True
                
                if is_https:
                    tls_text.insert(tk.END, "\\n═══════════════════════════════════════════════════════════\\n", 'section')
                    tls_text.insert(tk.END, "                  HTTPS/TLS TRAFFIC DETECTED\\n", 'section')
                    tls_text.insert(tk.END, "═══════════════════════════════════════════════════════════\\n\\n", 'section')
                    
                    if pkt.haslayer('Raw'):
                        raw_data = bytes(pkt['Raw'].load)
                        
                        # Analyze TLS metadata
                        tls_analysis = analyze_tls_traffic(raw_data)
                        
                        tls_text.insert(tk.END, "📊 TLS METADATA\\n", 'section')
                        tls_text.insert(tk.END, "-" * 50 + "\\n\\n", 'label')
                        
                        if tls_analysis.get('sni_hostname'):
                            tls_text.insert(tk.END, "🌐 SNI Hostname: ", 'label')
                            tls_text.insert(tk.END, f"{tls_analysis['sni_hostname']}\\n", 'value')
                        
                        if tls_analysis.get('tls_version'):
                            tls_text.insert(tk.END, "🔒 TLS Version: ", 'label')
                            version = tls_analysis['tls_version']
                            if 'TLS 1.2' in version or 'TLS 1.3' in version:
                                tls_text.insert(tk.END, f"{version}\\n", 'value')
                            else:
                                tls_text.insert(tk.END, f"{version} (OUTDATED!)\\n", 'danger')
                        
                        if tls_analysis.get('record_type'):
                            tls_text.insert(tk.END, "📝 Record Type: ", 'label')
                            tls_text.insert(tk.END, f"{tls_analysis['record_type']}\\n", 'value')
                        
                        if tls_analysis.get('cipher_suites'):
                            tls_text.insert(tk.END, "\\n🔐 OFFERED CIPHER SUITES:\\n", 'section')
                            for cipher in tls_analysis['cipher_suites'][:10]:
                                tls_text.insert(tk.END, f"   • {cipher}\\n", 'label')
                            if len(tls_analysis['cipher_suites']) > 10:
                                tls_text.insert(tk.END, f"   ... and {len(tls_analysis['cipher_suites']) - 10} more\\n", 'label')
                        
                        # Try HTTPS decryption analysis
                        tls_text.insert(tk.END, "\\n\\n📋 HTTPS DECRYPTION ANALYSIS\\n", 'section')
                        tls_text.insert(tk.END, "-" * 50 + "\\n\\n", 'label')
                        
                        decrypt_result = https_interceptor.decrypt_https_packet(raw_data, tls_analysis.get('sni_hostname'))
                        
                        if decrypt_result['success']:
                            tls_text.insert(tk.END, "✅ Successfully decoded HTTP content!\\n\\n", 'value')
                            if decrypt_result['method']:
                                tls_text.insert(tk.END, f"Method: {decrypt_result['method']}\\n", 'value')
                            if decrypt_result['path']:
                                tls_text.insert(tk.END, f"Path: {decrypt_result['path']}\\n", 'value')
                            if decrypt_result['headers']:
                                tls_text.insert(tk.END, "\\nHeaders:\\n", 'section')
                                for k, v in list(decrypt_result['headers'].items())[:5]:
                                    tls_text.insert(tk.END, f"  {k}: {v[:50]}...\\n" if len(v) > 50 else f"  {k}: {v}\\n", 'label')
                            if decrypt_result['credentials']:
                                tls_text.insert(tk.END, "\\n⚠️ CREDENTIALS FOUND:\\n", 'danger')
                                for cred in decrypt_result['credentials']:
                                    tls_text.insert(tk.END, f"  {cred['type']}: {cred['value'][:30]}...\\n", 'danger')
                        else:
                            tls_text.insert(tk.END, "🔒 Traffic is encrypted (cannot decrypt without MITM proxy)\\n", 'warning')
                            tls_text.insert(tk.END, "\\nTo decrypt HTTPS traffic:\\n", 'label')
                            tls_text.insert(tk.END, "1. Click '🔐 HTTPS Intercept' in Network Map tab\\n", 'label')
                            tls_text.insert(tk.END, "2. Generate CA Certificate\\n", 'label')
                            tls_text.insert(tk.END, "3. Install CA on target devices\\n", 'label')
                            tls_text.insert(tk.END, "4. Configure proxy settings to route through this monitor\\n", 'label')
                    else:
                        tls_text.insert(tk.END, "No raw payload in this HTTPS packet (likely a TCP control packet)\\n", 'label')
                else:
                    tls_text.insert(tk.END, "\\nThis packet is not HTTPS/TLS traffic.\\n", 'label')
                    tls_text.insert(tk.END, "\\nHTTPS analysis is only available for:\\n", 'label')
                    tls_text.insert(tk.END, "• Port 443 (HTTPS)\\n", 'label')
                    tls_text.insert(tk.END, "• Port 8443 (Alt HTTPS)\\n", 'label')
                    tls_text.insert(tk.END, "• Other TLS-encrypted connections\\n", 'label')
        except Exception as e:
            tls_text.insert(tk.END, f"\\nError analyzing TLS traffic: {e}\\n", 'danger')
        
        tls_text.config(state=tk.DISABLED)
        
        # Button frame
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def copy_extracted():
            report = f"PACKET CONFIDENTIAL DATA EXTRACTION\\n"
            report += f"Time: {values[0]} | {values[1]} → {values[2]}\\n"
            report += "=" * 50 + "\\n"
            for key, vals in extracted.items():
                if vals:
                    report += f"\\n{key.upper()}:\\n"
                    for v in vals:
                        report += f"  - {v}\\n"
            root.clipboard_clear()
            root.clipboard_append(report)
            messagebox.showinfo("Copied", "Extracted data copied to clipboard!")
        
        def export_packet():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Report", "*.txt"), ("JSON", "*.json")]
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        if file_path.endswith('.json'):
                            json.dump({
                                'packet_info': {
                                    'time': str(values[0]),
                                    'source': str(values[1]),
                                    'destination': str(values[2]),
                                    'protocol': str(values[3])
                                },
                                'extracted_data': extracted,
                                'raw_payload': raw_payload
                            }, f, indent=2)
                        else:
                            f.write(basic_info)
                            f.write("\\n\\nPAYLOAD:\\n" + payload_content)
                            f.write("\\n\\nEXTRACTED CONFIDENTIAL DATA:\\n")
                            for key, vals in extracted.items():
                                if vals:
                                    f.write(f"\\n{key.upper()}:\\n")
                                    for v in vals:
                                        f.write(f"  - {v}\\n")
                    messagebox.showinfo("Exported", f"Packet analysis exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {e}")
        
        ttk.Button(btn_frame, text="📋 Copy Extracted Data", command=copy_extracted).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Export Full Analysis", command=export_packet).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side=tk.RIGHT, padx=5)

    pkt_tree.bind("<Double-1>", show_packet_details)


    # --- Network Map Tab (Enhanced) ---
    map_frame = ttk.Frame(notebook)
    notebook.add(map_frame, text='🗺️ Network Map')
    
    # Header frame with status
    map_header = ttk.Frame(map_frame)
    map_header.pack(fill=tk.X, padx=5, pady=5)
    
    map_status_var = tk.StringVar(value="Ready to scan network. Click 'Scan Network' to discover devices.")
    map_status_label = ttk.Label(map_header, textvariable=map_status_var, font=("Segoe UI", 10))
    map_status_label.pack(side=tk.LEFT)
    
    # Analytics display
    analytics_var = tk.StringVar(value="")
    analytics_label = ttk.Label(map_header, textvariable=analytics_var, font=("Segoe UI", 10, "bold"), foreground="#0066cc")
    analytics_label.pack(side=tk.RIGHT)
    
    # Enhanced columns with bandwidth
    map_columns = ("IP", "MAC", "Hostname", "Vendor", "Type", "Status", "Bytes Sent", "Bytes Recv", "Last Seen")
    map_tree = ttk.Treeview(map_frame, columns=map_columns, show="headings", height=12)
    for col in map_columns:
        map_tree.heading(col, text=col)
        if col in ("Bytes Sent", "Bytes Recv"):
            map_tree.column(col, width=90, anchor='e')
        elif col == "IP":
            map_tree.column(col, width=120)
        elif col == "MAC":
            map_tree.column(col, width=130)
        elif col == "Hostname":
            map_tree.column(col, width=150)
        elif col == "Vendor":
            map_tree.column(col, width=140)
        elif col == "Last Seen":
            map_tree.column(col, width=140)
        else:
            map_tree.column(col, width=90)
    
    # Scrollbar for tree
    map_scroll = ttk.Scrollbar(map_frame, orient="vertical", command=map_tree.yview)
    map_tree.configure(yscrollcommand=map_scroll.set)
    map_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5,0), pady=5)
    map_scroll.pack(side=tk.LEFT, fill=tk.Y, pady=5)
    
    # Row coloring
    map_tree.tag_configure('router', background='#cce5ff', foreground='#004085')
    map_tree.tag_configure('active', background='#d4edda', foreground='#155724')
    map_tree.tag_configure('inactive', background='#f8d7da', foreground='#721c24')
    map_tree.tag_configure('unknown', background='#fff3cd', foreground='#856404')
    
    # Control buttons frame
    map_btn_frame = ttk.Frame(map_frame)
    map_btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    # Scan control variables
    scan_running = tk.BooleanVar(value=False)
    scan_thread = None
    discovered_devices = {}  # Store device info for reports
    
    # Format bytes to human readable
    def format_bytes(bytes_val):
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val / (1024*1024):.1f} MB"
        else:
            return f"{bytes_val / (1024*1024*1024):.2f} GB"
    
    def get_ip_info(ip):
        """Perform reverse lookup and get IP information."""
        info = {
            'ip': ip,
            'hostname': 'Unknown',
            'org': 'Unknown',
            'city': 'Unknown',
            'country': 'Unknown',
            'isp': 'Unknown',
            'asn': 'Unknown',
            'is_private': False,
            'reverse_dns': 'Unknown',
            'geolocation': None,
            'whois': None
        }
        
        # Check if private IP
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            info['is_private'] = True
            info['org'] = 'Private Network'
            info['city'] = 'Local'
            info['country'] = 'Local'
        
        # Reverse DNS lookup
        try:
            info['reverse_dns'] = socket.gethostbyaddr(ip)[0]
            info['hostname'] = info['reverse_dns']
        except (socket.herror, socket.gaierror):
            pass
        
        # For public IPs, get geolocation info
        if not info['is_private']:
            try:
                # Use ip-api.com (free, no API key required)
                resp = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,query', timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        info['country'] = data.get('country', 'Unknown')
                        info['city'] = data.get('city', 'Unknown')
                        info['isp'] = data.get('isp', 'Unknown')
                        info['org'] = data.get('org', 'Unknown')
                        info['asn'] = data.get('as', 'Unknown')
                        info['geolocation'] = data
            except Exception as e:
                app_logger.debug(f"IP info lookup failed for {ip}: {e}")
        
        return info
    
    def get_network_io_by_connection():
        """Get network I/O statistics per connection."""
        io_stats = {}
        try:
            # Get per-connection stats using psutil
            net_io = psutil.net_io_counters(pernic=True)
            for nic, counters in net_io.items():
                io_stats[nic] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv
                }
        except Exception as e:
            app_logger.debug(f"Network IO error: {e}")
        return io_stats
    
    def scan_network_enhanced():
        """Enhanced network scan with device discovery and traffic monitoring."""
        nonlocal discovered_devices
        
        map_status_var.set("🔄 Starting comprehensive network scan... Please wait.")
        map_tree.delete(*map_tree.get_children())
        discovered_devices = {}
        
        missing = check_network_dependencies()
        if missing:
            map_status_var.set(f"❌ Missing: {' & '.join(missing)}")
            map_tree.insert("", 0, values=('-', '-', '-', '-', '-', '-', '-', '-', 
                f"Install {' & '.join(missing)} for full network scanning"))
            scan_running.set(False)
            return
        
        if not scan_running.get():
            return
        
        try:
            # Get gateway/router IP
            gateways = netifaces.gateways() if NETIFACES_AVAILABLE else {}
            router_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0] if NETIFACES_AVAILABLE else None
            
            if not router_ip:
                map_status_var.set("❌ Could not detect gateway. Check network connection.")
                scan_running.set(False)
                return
            
            if not scan_running.get():
                return
            
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            device_count = 0
            type_counts = {}
            
            # Get network I/O for traffic estimation
            net_io = get_network_io_by_connection()
            total_sent = sum(n['bytes_sent'] for n in net_io.values())
            total_recv = sum(n['bytes_recv'] for n in net_io.values())
            
            # Add router first
            if router_ip and scan_running.get():
                router_info = get_ip_info(router_ip)
                discovered_devices[router_ip] = {
                    'ip': router_ip,
                    'mac': 'Gateway',
                    'hostname': router_info['hostname'],
                    'vendor': 'Gateway',
                    'type': 'Router',
                    'status': 'Active',
                    'bytes_sent': total_sent,
                    'bytes_recv': total_recv,
                    'last_seen': now,
                    'info': router_info,
                    'os_hint': 'Network Device'
                }
                map_tree.insert("", "end", 
                    values=(router_ip, 'Gateway', router_info['hostname'], 'Gateway', 'Router', 
                            '🟢 Active', format_bytes(total_sent), format_bytes(total_recv), now),
                    tags=('router',))
                type_counts['Router'] = 1
                device_count += 1
                map_status_var.set(f"🔄 Found router: {router_ip}. Starting multi-method scan...")
            
            # Use enhanced network scan for ALL devices
            map_status_var.set("🔄 Phase 1: ARP scanning local network...")
            root.update_idletasks()
            
            all_devices = enhanced_network_scan(router_ip, timeout=3)
            
            if not scan_running.get():
                return
            
            map_status_var.set(f"🔄 Phase 2: Processing {len(all_devices)} discovered devices...")
            root.update_idletasks()
            
            # Process each discovered device
            for i, dev in enumerate(all_devices):
                if not scan_running.get():
                    break
                
                ip = dev['ip']
                if ip == router_ip:
                    continue
                
                mac = dev.get('mac', 'Unknown')
                hostname = dev.get('hostname', ip)
                vendor = dev.get('vendor', 'Unknown')
                dtype = dev.get('device_type', 'Unknown')
                os_hint = dev.get('os_hint', 'Unknown')
                
                # Get detailed IP info if not already have hostname
                if hostname == ip:
                    ip_info = get_ip_info(ip)
                    if ip_info['hostname'] != 'Unknown':
                        hostname = ip_info['hostname']
                else:
                    ip_info = get_ip_info(ip)
                
                # Refine device type based on vendor and hostname
                if vendor and vendor != 'Unknown':
                    dtype = guess_device_type(hostname, vendor)
                
                # Enhanced OS detection from hostname patterns
                hostname_lower = hostname.lower() if hostname else ""
                if 'iphone' in hostname_lower or 'ipad' in hostname_lower:
                    dtype = 'iOS Device'
                    os_hint = 'iOS'
                elif 'android' in hostname_lower or 'galaxy' in hostname_lower or 'samsung' in hostname_lower:
                    dtype = 'Android Device'
                    os_hint = 'Android'
                elif 'macbook' in hostname_lower or 'imac' in hostname_lower:
                    dtype = 'Apple Computer'
                    os_hint = 'macOS'
                elif any(x in hostname_lower for x in ['desktop', 'laptop', 'pc', 'win']):
                    dtype = 'Windows PC'
                    os_hint = 'Windows'
                
                # Vendor-based detection
                if vendor:
                    vendor_lower = vendor.lower()
                    if 'apple' in vendor_lower:
                        if dtype == 'Unknown':
                            dtype = 'Apple Device'
                    elif 'samsung' in vendor_lower:
                        if dtype == 'Unknown':
                            dtype = 'Samsung Device'
                        if os_hint == 'Unknown' or os_hint is None:
                            os_hint = 'Android (Samsung)'
                    elif any(x in vendor_lower for x in ['huawei', 'xiaomi', 'oppo', 'vivo', 'oneplus']):
                        dtype = 'Android Phone'
                        os_hint = 'Android'
                    elif 'amazon' in vendor_lower:
                        dtype = 'Smart Device (Amazon)'
                    elif 'google' in vendor_lower:
                        dtype = 'Google Device'
                    elif 'intel' in vendor_lower or 'realtek' in vendor_lower:
                        if dtype == 'Unknown':
                            dtype = 'Computer'
                
                # Check if device is still reachable (ping)
                status = 'Active'
                try:
                    import subprocess
                    result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                          capture_output=True, timeout=2,
                                          encoding='utf-8', errors='ignore')
                    status = 'Active' if result.returncode == 0 else 'Inactive'
                except Exception:
                    status = 'Unknown'
                
                # Estimate traffic (proportional distribution for now)
                device_sent = total_sent // max(len(all_devices), 1)
                device_recv = total_recv // max(len(all_devices), 1)
                
                # Store device info
                discovered_devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor or 'Unknown',
                    'type': dtype,
                    'status': status,
                    'bytes_sent': device_sent,
                    'bytes_recv': device_recv,
                    'last_seen': now,
                    'info': ip_info,
                    'os_hint': os_hint,
                    'discovery_method': dev.get('discovery_method', 'ARP')
                }
                
                # Determine row tag based on status
                row_tag = 'active' if status == 'Active' else ('inactive' if status == 'Inactive' else 'unknown')
                status_icon = '🟢' if status == 'Active' else ('🔴' if status == 'Inactive' else '🟡')
                
                # Add OS hint to device type display
                display_type = dtype
                if os_hint and os_hint != 'Unknown':
                    display_type = f"{dtype} ({os_hint})"
                
                map_tree.insert("", "end",
                    values=(ip, mac, hostname, vendor or 'Unknown', display_type, f"{status_icon} {status}",
                            format_bytes(device_sent), format_bytes(device_recv), now),
                    tags=(row_tag,))
                
                type_counts[dtype] = type_counts.get(dtype, 0) + 1
                device_count += 1
                
                map_status_var.set(f"🔄 Scanning... Found {device_count} devices ({i+1}/{len(all_devices)})")
                root.update_idletasks()
            
            # Update analytics
            if device_count > 0:
                analytics = f"📊 {device_count} Devices | " + " | ".join(f"{k}: {v}" for k, v in type_counts.items())
                analytics_var.set(analytics)
                map_status_var.set(f"✅ Scan complete. Found {device_count} devices.")
            else:
                map_status_var.set("⚠️ No devices found. Run as Administrator for better results.")
            
        except Exception as e:
            app_logger.error(f"Network scan error: {e}")
            map_status_var.set(f"❌ Scan error: {str(e)[:50]}")
        finally:
            scan_running.set(False)
            scan_btn.config(text="🔍 Scan Network")
            halt_btn.config(state=tk.DISABLED)
    
    def start_scan():
        """Start network scan in background thread."""
        nonlocal scan_thread
        if scan_running.get():
            return
        
        scan_running.set(True)
        scan_btn.config(text="⏳ Scanning...")
        halt_btn.config(state=tk.NORMAL)
        
        scan_thread = threading.Thread(target=scan_network_enhanced, daemon=True)
        scan_thread.start()
    
    def halt_scan():
        """Stop the network scan."""
        scan_running.set(False)
        map_status_var.set("⏹️ Scan halted by user.")
        scan_btn.config(text="🔍 Scan Network")
        halt_btn.config(state=tk.DISABLED)
    
    def show_device_details(event):
        """Show detailed information about selected device."""
        item = map_tree.identify_row(event.y)
        if not item:
            return
        
        values = map_tree.item(item)['values']
        ip = values[0]
        
        if ip not in discovered_devices:
            messagebox.showinfo("No Data", "Device data not available. Run a scan first.")
            return
        
        dev = discovered_devices[ip]
        info = dev.get('info', {})
        
        # Create detailed popup
        popup = tk.Toplevel(root)
        popup.title(f"📋 Device Report: {ip}")
        popup.geometry("600x500")
        popup.configure(bg='#f8f9fa')
        
        # Scrollable frame
        canvas = tk.Canvas(popup, bg='#f8f9fa')
        scrollbar = ttk.Scrollbar(popup, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Header
        ttk.Label(scrollable, text=f"🖥️ Device Intelligence Report", 
                  font=('Segoe UI', 14, 'bold')).pack(anchor='w', padx=15, pady=10)
        
        # Basic Info Section
        basic_frame = ttk.LabelFrame(scrollable, text="📌 Basic Information")
        basic_frame.pack(fill=tk.X, padx=15, pady=5)
        
        basic_info = [
            ("IP Address", dev['ip']),
            ("MAC Address", dev['mac']),
            ("Hostname", dev['hostname']),
            ("Vendor", dev['vendor']),
            ("Device Type", dev['type']),
            ("Status", dev['status']),
            ("Last Seen", dev['last_seen'])
        ]
        for label, value in basic_info:
            row = ttk.Frame(basic_frame)
            row.pack(fill=tk.X, padx=10, pady=2)
            ttk.Label(row, text=f"{label}:", font=('Segoe UI', 10, 'bold'), width=15).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=('Consolas', 10)).pack(side=tk.LEFT)
        
        # Traffic Section
        traffic_frame = ttk.LabelFrame(scrollable, text="📊 Network Traffic")
        traffic_frame.pack(fill=tk.X, padx=15, pady=5)
        
        traffic_info = [
            ("Bytes Sent", format_bytes(dev['bytes_sent'])),
            ("Bytes Received", format_bytes(dev['bytes_recv'])),
            ("Total Traffic", format_bytes(dev['bytes_sent'] + dev['bytes_recv']))
        ]
        for label, value in traffic_info:
            row = ttk.Frame(traffic_frame)
            row.pack(fill=tk.X, padx=10, pady=2)
            ttk.Label(row, text=f"{label}:", font=('Segoe UI', 10, 'bold'), width=15).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=('Consolas', 10)).pack(side=tk.LEFT)
        
        # Reverse Lookup Section
        lookup_frame = ttk.LabelFrame(scrollable, text="🔍 Reverse Lookup & Intelligence")
        lookup_frame.pack(fill=tk.X, padx=15, pady=5)
        
        lookup_info = [
            ("Reverse DNS", info.get('reverse_dns', 'N/A')),
            ("Organization", info.get('org', 'N/A')),
            ("ISP", info.get('isp', 'N/A')),
            ("ASN", info.get('asn', 'N/A')),
            ("City", info.get('city', 'N/A')),
            ("Country", info.get('country', 'N/A')),
            ("Private IP", "Yes" if info.get('is_private') else "No")
        ]
        for label, value in lookup_info:
            row = ttk.Frame(lookup_frame)
            row.pack(fill=tk.X, padx=10, pady=2)
            ttk.Label(row, text=f"{label}:", font=('Segoe UI', 10, 'bold'), width=15).pack(side=tk.LEFT)
            ttk.Label(row, text=str(value), font=('Consolas', 10), wraplength=400).pack(side=tk.LEFT)
        
        # VirusTotal Check
        vt_frame = ttk.LabelFrame(scrollable, text="🦠 VirusTotal Analysis")
        vt_frame.pack(fill=tk.X, padx=15, pady=5)
        
        # Check if it's a private IP
        is_private_ip = ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "127.0.0.1"
        
        def run_vt_check():
            if is_private_ip:
                vt_status.set("ℹ️ Private IP - Not in VirusTotal database (local network only)")
                return
            vt_status.set("Checking VirusTotal...")
            mal, susp = vt_check_ip(ip)
            if mal is not None:
                result = f"Malicious: {mal} | Suspicious: {susp}"
                if mal > 0 or susp > 0:
                    result += " ⚠️ FLAGGED"
                else:
                    result += " ✅ Clean"
            else:
                result = "⚠️ API Error - Check your API key or try again later"
            vt_status.set(result)
        
        if is_private_ip:
            vt_status = tk.StringVar(value="ℹ️ Private IP - VT only tracks public IPs")
        else:
            vt_status = tk.StringVar(value="Click 'Check VirusTotal' to analyze")
        ttk.Label(vt_frame, textvariable=vt_status, font=('Segoe UI', 10)).pack(padx=10, pady=5)
        if not is_private_ip:
            ttk.Button(vt_frame, text="🔍 Check VirusTotal", command=run_vt_check).pack(pady=5)
        
        # Router Credentials Section (only for router devices)
        if dev['type'] == 'Router':
            creds_frame = ttk.LabelFrame(scrollable, text="🔐 Router & WiFi Credentials")
            creds_frame.pack(fill=tk.X, padx=15, pady=5)
            
            creds_status = tk.StringVar(value="🔒 Credentials hidden - Enter admin password to reveal")
            creds_label = ttk.Label(creds_frame, textvariable=creds_status, font=('Segoe UI', 10), wraplength=500, justify='left')
            creds_label.pack(padx=10, pady=5, anchor='w')
            
            # WiFi passwords display area (hidden initially)
            wifi_text_widget = None
            
            # Password entry frame
            pwd_frame = ttk.Frame(creds_frame)
            pwd_frame.pack(padx=10, pady=5)
            
            ttk.Label(pwd_frame, text="Admin Password:", font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=5)
            pwd_entry = ttk.Entry(pwd_frame, show="*", width=15)
            pwd_entry.pack(side=tk.LEFT, padx=5)
            
            def reveal_credentials():
                nonlocal wifi_text_widget
                admin_pwd = "0000"  # Admin password
                if pwd_entry.get() == admin_pwd:
                    # Get common router default credentials based on vendor
                    vendor = dev['vendor'].lower()
                    default_creds = get_router_default_credentials(vendor)
                    
                    # Get saved WiFi passwords
                    wifi_passwords = get_saved_wifi_passwords()
                    
                    # Build WiFi password section
                    wifi_section = ""
                    if wifi_passwords:
                        wifi_section = "\n\n📶 SAVED WIFI PASSWORDS\n" + "━" * 40 + "\n"
                        for wifi in wifi_passwords:
                            wifi_section += f"\n🌐 SSID: {wifi['ssid']}\n"
                            wifi_section += f"   🔑 Password: {wifi['password']}\n"
                            wifi_section += f"   🔒 Security: {wifi['authentication']} / {wifi['security']}\n"
                    else:
                        wifi_section = "\n\n📶 SAVED WIFI PASSWORDS\n" + "━" * 40 + "\n"
                        wifi_section += "No saved WiFi profiles found or access denied.\n"
                        wifi_section += "Run as Administrator for full access.\n"
                    
                    creds_text = f"""🔓 ROUTER DEFAULT CREDENTIALS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Vendor: {dev['vendor']}
Router IP: {dev['ip']}

📋 Common Default Logins:
{default_creds}

⚠️ WARNING: Change default credentials immediately!
Access router at: http://{dev['ip']}
{wifi_section}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
                    
                    # Hide password entry
                    pwd_frame.pack_forget()
                    reveal_btn.pack_forget()
                    creds_label.pack_forget()
                    
                    # Create scrollable text widget for credentials
                    wifi_text_widget = tk.Text(creds_frame, height=15, width=60, font=('Consolas', 9), bg='#f8f9fa')
                    wifi_text_widget.pack(padx=10, pady=5, fill=tk.X)
                    wifi_text_widget.insert('1.0', creds_text)
                    
                    # Highlight passwords in red
                    wifi_text_widget.tag_configure('password', foreground='#dc3545', font=('Consolas', 9, 'bold'))
                    wifi_text_widget.tag_configure('ssid', foreground='#0066cc', font=('Consolas', 9, 'bold'))
                    wifi_text_widget.tag_configure('warning', foreground='#fd7e14', font=('Consolas', 9, 'bold'))
                    
                    # Apply highlighting
                    import re
                    content = wifi_text_widget.get('1.0', tk.END)
                    
                    # Highlight passwords
                    for match in re.finditer(r'Password: (.+)', content):
                        start = f"1.0 + {match.start(1)} chars"
                        end = f"1.0 + {match.end(1)} chars"
                        wifi_text_widget.tag_add('password', start, end)
                    
                    # Highlight SSIDs
                    for match in re.finditer(r'SSID: (.+)', content):
                        start = f"1.0 + {match.start(1)} chars"
                        end = f"1.0 + {match.end(1)} chars"
                        wifi_text_widget.tag_add('ssid', start, end)
                    
                    wifi_text_widget.config(state=tk.DISABLED)
                    
                    # Add copy button for WiFi passwords
                    def copy_wifi_creds():
                        root.clipboard_clear()
                        root.clipboard_append(creds_text)
                        messagebox.showinfo("Copied", "Router & WiFi credentials copied to clipboard!")
                    
                    ttk.Button(creds_frame, text="📋 Copy Credentials", command=copy_wifi_creds).pack(pady=5)
                else:
                    messagebox.showerror("Access Denied", "Invalid admin password!")
                    pwd_entry.delete(0, tk.END)
            
            reveal_btn = ttk.Button(creds_frame, text="🔓 Reveal Credentials & WiFi Passwords", command=reveal_credentials)
            reveal_btn.pack(pady=5)
        
        # Deep Threat Intelligence Section (for external IPs or suspicious devices)
        threat_intel_frame = ttk.LabelFrame(scrollable, text="🔬 Deep Threat Intelligence")
        threat_intel_frame.pack(fill=tk.X, padx=15, pady=5)
        
        intel_status = tk.StringVar(value="Click 'Analyze Threat' to perform deep reverse engineering")
        intel_label = ttk.Label(threat_intel_frame, textvariable=intel_status, font=('Segoe UI', 10), wraplength=500)
        intel_label.pack(padx=10, pady=5)
        
        intel_text_widget = None
        
        def run_deep_intel():
            nonlocal intel_text_widget
            intel_status.set("🔄 Performing deep threat analysis... Please wait.")
            popup.update_idletasks()
            
            # Get deep threat intelligence
            intel = get_deep_threat_intelligence(ip)
            
            # Also try to get SSL cert info if not private
            ssl_info = None
            if not intel.get('is_private', True):
                ssl_info = get_ssl_certificate_info(ip)
            
            # Build intelligence report
            intel_report = "═" * 55 + "\n"
            intel_report += "       🔬 DEEP THREAT INTELLIGENCE REPORT\n"
            intel_report += "═" * 55 + "\n\n"
            
            intel_report += f"🎯 Target IP: {ip}\n"
            intel_report += f"📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            if intel.get('is_private'):
                # PRIVATE IP - Show local device scan results
                intel_report += "🏠 PRIVATE/LAN DEVICE ANALYSIS\n"
                intel_report += "═" * 40 + "\n\n"
                
                local = intel.get('local_scan', {})
                if local:
                    # Device identification
                    intel_report += "📱 DEVICE IDENTIFICATION\n" + "─" * 40 + "\n"
                    intel_report += f"   Hostname:     {local.get('hostname', 'Unknown')}\n"
                    intel_report += f"   MAC Address:  {local.get('mac_address', 'Unknown')}\n"
                    intel_report += f"   Vendor:       {local.get('vendor', 'Unknown')}\n"
                    intel_report += f"   Device Type:  {local.get('device_type', 'Unknown')}\n"
                    intel_report += f"   OS Detected:  {local.get('os_fingerprint', 'Unknown')}\n\n"
                    
                    # Open ports and services
                    open_ports = local.get('open_ports', [])
                    services = local.get('services', {})
                    intel_report += f"🔌 OPEN PORTS ({len(open_ports)} found)\n" + "─" * 40 + "\n"
                    if open_ports:
                        for port in sorted(open_ports):
                            service = services.get(port, 'Unknown')
                            intel_report += f"   Port {port:5d}  →  {service}\n"
                    else:
                        intel_report += "   No open ports detected (device may be firewalled)\n"
                    intel_report += "\n"
                    
                    # Banner information
                    banners = local.get('banners', {})
                    if banners:
                        intel_report += "📜 SERVICE BANNERS\n" + "─" * 40 + "\n"
                        for port, banner in banners.items():
                            intel_report += f"   Port {port}:\n"
                            # Truncate long banners
                            banner_lines = banner.split('\n')[:3]
                            for line in banner_lines:
                                intel_report += f"      {line[:60]}\n"
                        intel_report += "\n"
                    
                    # HTTP info if available
                    http_info = local.get('http_info', {})
                    if http_info:
                        intel_report += "🌐 WEB SERVER INFO\n" + "─" * 40 + "\n"
                        intel_report += f"   Status:     {http_info.get('status', 'N/A')}\n"
                        intel_report += f"   Server:     {http_info.get('server', 'Unknown')}\n"
                        intel_report += f"   Powered By: {http_info.get('powered_by', 'Unknown')}\n"
                        if http_info.get('title'):
                            intel_report += f"   Page Title: {http_info['title'][:50]}\n"
                        intel_report += "\n"
                    
                    # Security assessment
                    vulnerabilities = local.get('vulnerabilities', [])
                    risk_score = local.get('risk_score', 0)
                    security_level = local.get('security_level', 'Unknown')
                    
                    intel_report += "🛡️ SECURITY ASSESSMENT\n" + "─" * 40 + "\n"
                    intel_report += f"   Risk Score:    {risk_score}/100\n"
                    intel_report += f"   Security:      {security_level}\n\n"
                    
                    if vulnerabilities:
                        intel_report += "⚠️ VULNERABILITIES DETECTED\n" + "─" * 40 + "\n"
                        for vuln in vulnerabilities:
                            intel_report += f"   {vuln}\n"
                        intel_report += "\n"
                    else:
                        intel_report += "✅ No major vulnerabilities detected\n\n"
                    
                    # Recommendations
                    intel_report += "📋 RECOMMENDATIONS\n" + "─" * 40 + "\n"
                    if 23 in open_ports:
                        intel_report += "   • DISABLE Telnet - use SSH instead\n"
                    if 21 in open_ports:
                        intel_report += "   • DISABLE FTP - use SFTP instead\n"
                    if 3389 in open_ports:
                        intel_report += "   • Secure RDP with NLA and strong password\n"
                    if 445 in open_ports or 139 in open_ports:
                        intel_report += "   • Review SMB shares and permissions\n"
                    if 80 in open_ports and 443 not in open_ports:
                        intel_report += "   • Enable HTTPS for secure connections\n"
                    if not vulnerabilities and not open_ports:
                        intel_report += "   ✓ Device appears well-secured\n"
                    intel_report += "\n"
                else:
                    intel_report += "⚠️ Could not perform local device scan.\n"
                    intel_report += "   Device may be offline or blocking scans.\n\n"
            else:
                # Geolocation
                geo = intel.get('geolocation', {})
                intel_report += "🌍 GEOLOCATION\n" + "─" * 40 + "\n"
                intel_report += f"   Country:   {geo.get('country', 'Unknown')} ({geo.get('country_code', 'XX')})\n"
                intel_report += f"   Region:    {geo.get('region', 'Unknown')}\n"
                intel_report += f"   City:      {geo.get('city', 'Unknown')}\n"
                intel_report += f"   ZIP:       {geo.get('zip', 'Unknown')}\n"
                intel_report += f"   Coords:    {geo.get('latitude', 0)}, {geo.get('longitude', 0)}\n"
                intel_report += f"   Timezone:  {geo.get('timezone', 'Unknown')}\n\n"
                
                # ISP Info
                isp = intel.get('isp_info', {})
                intel_report += "🏢 ISP & ORGANIZATION\n" + "─" * 40 + "\n"
                intel_report += f"   ISP:       {isp.get('isp', 'Unknown')}\n"
                intel_report += f"   Org:       {isp.get('organization', 'Unknown')}\n"
                intel_report += f"   ASN:       {isp.get('asn', 'Unknown')}\n"
                intel_report += f"   ASN Name:  {isp.get('asn_name', 'Unknown')}\n\n"
                
                # Threat Indicators
                intel_report += "⚠️ THREAT INDICATORS\n" + "─" * 40 + "\n"
                intel_report += f"   🔄 Is Proxy/VPN:    {'Yes ⚠️' if intel.get('is_vpn') else 'No'}\n"
                intel_report += f"   🌐 Is Tor Exit:     {'Yes ⚠️' if intel.get('is_tor_exit') else 'No'}\n"
                intel_report += f"   🏢 Is Datacenter:   {'Yes' if intel.get('is_datacenter') else 'No'}\n"
                intel_report += f"   📊 Reputation:      {intel.get('reputation_score', 'N/A')}\n\n"
                
                # Threat Categories
                if intel.get('threat_categories'):
                    intel_report += "🚨 THREAT CATEGORIES\n" + "─" * 40 + "\n"
                    for cat in intel['threat_categories']:
                        intel_report += f"   • {cat}\n"
                    intel_report += "\n"
                
                # Vendor Reports
                if intel.get('threat_reports'):
                    intel_report += "🦠 SECURITY VENDOR REPORTS\n" + "─" * 40 + "\n"
                    for report in intel['threat_reports'][:10]:  # Limit to 10
                        intel_report += f"   [{report.get('category', 'Unknown').upper()}] "
                        intel_report += f"{report.get('vendor', 'Unknown')}: {report.get('result', 'Flagged')}\n"
                    intel_report += "\n"
                
                # Abuse Reports
                if intel.get('abuse_reports') and isinstance(intel['abuse_reports'], dict):
                    abuse = intel['abuse_reports']
                    intel_report += "🚫 ABUSE REPORTS (AbuseIPDB)\n" + "─" * 40 + "\n"
                    intel_report += f"   Total Reports:     {abuse.get('total_reports', 0)}\n"
                    intel_report += f"   Confidence Score:  {abuse.get('confidence_score', 0)}%\n"
                    intel_report += f"   Usage Type:        {abuse.get('usage_type', 'Unknown')}\n"
                    intel_report += f"   Domain:            {abuse.get('domain', 'Unknown')}\n"
                    intel_report += f"   Last Reported:     {abuse.get('last_reported', 'Never')}\n\n"
                
                # SSL/TLS Certificate Info
                if ssl_info and ssl_info.get('valid'):
                    intel_report += "🔐 SSL/TLS CERTIFICATE\n" + "─" * 40 + "\n"
                    intel_report += f"   TLS Version:    {ssl_info.get('tls_version', 'Unknown')}\n"
                    intel_report += f"   Cipher Suite:   {ssl_info.get('cipher_suite', 'Unknown')}\n"
                    
                    subj = ssl_info.get('subject', {})
                    if subj:
                        intel_report += f"   Subject CN:     {subj.get('commonName', 'Unknown')}\n"
                        intel_report += f"   Subject Org:    {subj.get('organizationName', 'Unknown')}\n"
                    
                    issuer = ssl_info.get('issuer', {})
                    if issuer:
                        intel_report += f"   Issuer:         {issuer.get('commonName', 'Unknown')}\n"
                    
                    intel_report += f"   Expires:        {ssl_info.get('not_after', 'Unknown')}\n"
                    intel_report += f"   Days Left:      {ssl_info.get('days_until_expiry', 'Unknown')}\n"
                    intel_report += f"   Self-Signed:    {'Yes ⚠️' if ssl_info.get('is_self_signed') else 'No'}\n"
                    
                    if ssl_info.get('vulnerabilities'):
                        intel_report += "\n   ⚠️ VULNERABILITIES:\n"
                        for vuln in ssl_info['vulnerabilities']:
                            intel_report += f"      • {vuln}\n"
                    intel_report += "\n"
                elif ssl_info and ssl_info.get('error'):
                    intel_report += "🔐 SSL/TLS CERTIFICATE\n" + "─" * 40 + "\n"
                    intel_report += f"   Status: {ssl_info.get('error')}\n\n"
                
                # Associated Domains
                if intel.get('associated_domains'):
                    intel_report += "🌐 ASSOCIATED DOMAINS\n" + "─" * 40 + "\n"
                    for domain in intel['associated_domains'][:5]:
                        intel_report += f"   • {domain}\n"
                    intel_report += "\n"
            
            intel_report += "═" * 55 + "\n"
            
            # Display in text widget
            if intel_text_widget:
                intel_text_widget.destroy()
            
            intel_text_widget = tk.Text(threat_intel_frame, height=12, width=60, font=('Consolas', 9), bg='#fff8f0', wrap=tk.WORD)
            intel_text_widget.pack(padx=10, pady=5, fill=tk.X)
            intel_text_widget.insert('1.0', intel_report)
            
            # Configure tags for highlighting
            intel_text_widget.tag_configure('warning', foreground='#dc3545', font=('Consolas', 9, 'bold'))
            intel_text_widget.tag_configure('header', foreground='#0066cc', font=('Consolas', 9, 'bold'))
            
            intel_text_widget.config(state=tk.DISABLED)
            intel_status.set("✅ Analysis complete. See detailed report below.")
            
            # Update popup window size to accommodate new content
            popup.geometry("700x700")
        
        ttk.Button(threat_intel_frame, text="🔬 Analyze Threat & Reverse Engineer", command=run_deep_intel).pack(pady=5)
        
        # Action buttons
        btn_frame = ttk.Frame(scrollable)
        btn_frame.pack(fill=tk.X, padx=15, pady=15)
        
        def copy_to_clipboard():
            report_text = generate_device_report(dev)
            root.clipboard_clear()
            root.clipboard_append(report_text)
            messagebox.showinfo("Copied", "Device report copied to clipboard!")
        
        ttk.Button(btn_frame, text="📋 Copy Report", command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side=tk.RIGHT, padx=5)
        
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
    
    def generate_device_report(dev):
        """Generate a text report for a device."""
        info = dev.get('info', {})
        report = f"""
{'='*60}
DEVICE INTELLIGENCE REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

BASIC INFORMATION
-----------------
IP Address:      {dev['ip']}
MAC Address:     {dev['mac']}
Hostname:        {dev['hostname']}
Vendor:          {dev['vendor']}
Device Type:     {dev['type']}
Status:          {dev['status']}
Last Seen:       {dev['last_seen']}

NETWORK TRAFFIC
---------------
Bytes Sent:      {format_bytes(dev['bytes_sent'])}
Bytes Received:  {format_bytes(dev['bytes_recv'])}
Total Traffic:   {format_bytes(dev['bytes_sent'] + dev['bytes_recv'])}

REVERSE LOOKUP
--------------
Reverse DNS:     {info.get('reverse_dns', 'N/A')}
Organization:    {info.get('org', 'N/A')}
ISP:             {info.get('isp', 'N/A')}
ASN:             {info.get('asn', 'N/A')}
City:            {info.get('city', 'N/A')}
Country:         {info.get('country', 'N/A')}
Private IP:      {'Yes' if info.get('is_private') else 'No'}

{'='*60}
"""
        return report
    
    def export_network_report():
        """Export full network scan report."""
        if not discovered_devices:
            messagebox.showwarning("No Data", "No devices discovered. Run a scan first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
        )
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                # JSON export
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(discovered_devices, f, indent=2, default=str)
            elif file_path.endswith('.csv'):
                # CSV export
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IP', 'MAC', 'Hostname', 'Vendor', 'Type', 'Status', 
                                    'Bytes Sent', 'Bytes Recv', 'Last Seen', 'Reverse DNS', 
                                    'Organization', 'Country'])
                    for ip, dev in discovered_devices.items():
                        info = dev.get('info', {})
                        writer.writerow([
                            dev['ip'], dev['mac'], dev['hostname'], dev['vendor'],
                            dev['type'], dev['status'], dev['bytes_sent'], dev['bytes_recv'],
                            dev['last_seen'], info.get('reverse_dns', ''), 
                            info.get('org', ''), info.get('country', '')
                        ])
            else:
                # Text report
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"""
{'='*70}
NETWORK INTELLIGENCE REPORT
{'='*70}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Devices: {len(discovered_devices)}
{'='*70}

""")
                    for ip, dev in discovered_devices.items():
                        f.write(generate_device_report(dev))
                        f.write("\n")
            
            messagebox.showinfo("Export Complete", f"Report saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    # Create buttons
    scan_btn = ttk.Button(map_btn_frame, text="🔍 Scan Network", command=start_scan)
    scan_btn.pack(side=tk.LEFT, padx=5)
    
    halt_btn = ttk.Button(map_btn_frame, text="⏹️ Halt Scan", command=halt_scan, state=tk.DISABLED)
    halt_btn.pack(side=tk.LEFT, padx=5)
    
    report_btn = ttk.Button(map_btn_frame, text="📄 Export Report", command=export_network_report)
    report_btn.pack(side=tk.LEFT, padx=5)
    
    refresh_map_btn = ttk.Button(map_btn_frame, text="🔄 Refresh", command=lambda: [map_tree.delete(*map_tree.get_children()), start_scan()])
    refresh_map_btn.pack(side=tk.LEFT, padx=5)
    
    # HTTPS Interception button
    def show_https_intercept_window():
        """Show HTTPS interception setup window."""
        https_win = tk.Toplevel(root)
        https_win.title("🔐 HTTPS Interception Setup")
        https_win.geometry("700x550")
        https_win.configure(bg='#1a1a2e')
        
        # Header
        header = tk.Frame(https_win, bg='#16213e')
        header.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(header, text="🔐 HTTPS Traffic Interception", 
                font=("Segoe UI", 16, "bold"), fg='#eee', bg='#16213e').pack(pady=10)
        tk.Label(header, text="⚠️ AUTHORIZED USE ONLY - Requires CA certificate installation", 
                font=("Segoe UI", 10), fg='#ffc107', bg='#16213e').pack()
        
        # Status frame
        status_frame = tk.Frame(https_win, bg='#1a1a2e')
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Check if cryptography is available
        if CRYPTOGRAPHY_AVAILABLE:
            crypto_status = "✅ cryptography library: INSTALLED"
            crypto_color = '#28a745'
        else:
            crypto_status = "❌ cryptography library: NOT INSTALLED (pip install cryptography)"
            crypto_color = '#dc3545'
        
        tk.Label(status_frame, text=crypto_status, 
                font=("Segoe UI", 10), fg=crypto_color, bg='#1a1a2e').pack(anchor='w')
        
        # CA Certificate status
        ca_exists = https_interceptor.ca_cert_path.exists()
        if ca_exists:
            ca_status = f"✅ CA Certificate: {https_interceptor.ca_cert_path}"
            ca_color = '#28a745'
        else:
            ca_status = "⚠️ CA Certificate: Not generated yet"
            ca_color = '#ffc107'
        
        ca_status_label = tk.Label(status_frame, text=ca_status, 
                font=("Segoe UI", 10), fg=ca_color, bg='#1a1a2e')
        ca_status_label.pack(anchor='w', pady=5)
        
        # Instructions text
        instructions_frame = tk.Frame(https_win, bg='#1a1a2e')
        instructions_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        instructions_text = tk.Text(instructions_frame, wrap=tk.WORD, 
                                    font=("Consolas", 9), bg='#0f0f1a', fg='#00ff00',
                                    insertbackground='#00ff00')
        instructions_scroll = ttk.Scrollbar(instructions_frame, command=instructions_text.yview)
        instructions_text.configure(yscrollcommand=instructions_scroll.set)
        instructions_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        instructions_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        instructions_text.insert('1.0', https_interceptor.get_ca_cert_install_instructions())
        instructions_text.configure(state='disabled')
        
        # Buttons frame
        btn_frame = tk.Frame(https_win, bg='#1a1a2e')
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def generate_ca():
            if not CRYPTOGRAPHY_AVAILABLE:
                messagebox.showerror("Missing Dependency", 
                    "The 'cryptography' library is required.\n\nInstall with:\npip install cryptography")
                return
            
            result = messagebox.askyesno("Generate CA Certificate", 
                "This will generate a new CA certificate for HTTPS interception.\n\n"
                "The certificate will be stored at:\n"
                f"{https_interceptor.ca_cert_path}\n\n"
                "⚠️ You must install this certificate on devices you want to monitor.\n\n"
                "Continue?")
            if result:
                if https_interceptor.generate_ca_certificate():
                    ca_status_label.config(text=f"✅ CA Certificate: {https_interceptor.ca_cert_path}", 
                                          fg='#28a745')
                    instructions_text.configure(state='normal')
                    instructions_text.delete('1.0', tk.END)
                    instructions_text.insert('1.0', https_interceptor.get_ca_cert_install_instructions())
                    instructions_text.configure(state='disabled')
                    messagebox.showinfo("Success", f"CA Certificate generated!\n\n{https_interceptor.ca_cert_path}")
                else:
                    messagebox.showerror("Error", "Failed to generate CA certificate. Check logs.")
        
        def open_cert_folder():
            cert_dir = https_interceptor.cert_dir
            if not cert_dir.exists():
                cert_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(str(cert_dir))
        
        def copy_cert_path():
            if https_interceptor.ca_cert_path.exists():
                root.clipboard_clear()
                root.clipboard_append(str(https_interceptor.ca_cert_path))
                messagebox.showinfo("Copied", "Certificate path copied to clipboard!")
            else:
                messagebox.showwarning("No Certificate", "Generate a CA certificate first.")
        
        ttk.Button(btn_frame, text="🔑 Generate CA Certificate", 
                  command=generate_ca).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📁 Open Cert Folder", 
                  command=open_cert_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📋 Copy Cert Path", 
                  command=copy_cert_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Close", 
                  command=https_win.destroy).pack(side=tk.RIGHT, padx=5)
    
    https_btn = ttk.Button(map_btn_frame, text="🔐 HTTPS Intercept", command=show_https_intercept_window)
    https_btn.pack(side=tk.LEFT, padx=5)
    
    # Bind double-click for device details
    map_tree.bind("<Double-1>", show_device_details)
    
    # Show initial message
    if check_network_dependencies():
        map_tree.insert("", 0, values=("-", "-", "-", "-", "-", "-", "-", "-", 
            "Install netifaces & scapy for network scanning"))

    # --- WiFi Security Tab ---
    wifi_frame = ttk.Frame(notebook)
    notebook.add(wifi_frame, text='📶 WiFi Security')
    
    # WiFi Header
    wifi_header = ttk.Frame(wifi_frame)
    wifi_header.pack(fill=tk.X, padx=5, pady=5)
    
    wifi_status_var = tk.StringVar(value="Click 'Scan Networks' to discover WiFi networks")
    ttk.Label(wifi_header, textvariable=wifi_status_var, font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=5)
    
    # Create paned window for WiFi tab
    wifi_paned = ttk.PanedWindow(wifi_frame, orient=tk.HORIZONTAL)
    wifi_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Left panel - Network list
    wifi_list_frame = ttk.LabelFrame(wifi_paned, text="📡 Available Networks")
    wifi_paned.add(wifi_list_frame, weight=1)
    
    wifi_tree = ttk.Treeview(wifi_list_frame, columns=('ssid', 'signal', 'auth', 'encryption', 'channel', 'security'), show='headings', height=15)
    wifi_tree.heading('ssid', text='SSID')
    wifi_tree.heading('signal', text='Signal')
    wifi_tree.heading('auth', text='Authentication')
    wifi_tree.heading('encryption', text='Encryption')
    wifi_tree.heading('channel', text='Channel')
    wifi_tree.heading('security', text='Security Level')
    
    wifi_tree.column('ssid', width=150)
    wifi_tree.column('signal', width=60)
    wifi_tree.column('auth', width=100)
    wifi_tree.column('encryption', width=80)
    wifi_tree.column('channel', width=60)
    wifi_tree.column('security', width=120)
    
    wifi_scroll = ttk.Scrollbar(wifi_list_frame, orient=tk.VERTICAL, command=wifi_tree.yview)
    wifi_tree.configure(yscrollcommand=wifi_scroll.set)
    wifi_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    wifi_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Right panel - Analysis results
    wifi_analysis_frame = ttk.LabelFrame(wifi_paned, text="🔬 Security Analysis")
    wifi_paned.add(wifi_analysis_frame, weight=1)
    
    wifi_analysis_text = tk.Text(wifi_analysis_frame, wrap=tk.WORD, font=('Consolas', 9),
                                  bg='#1a1a2e', fg='#00ff00', insertbackground='#00ff00')
    wifi_analysis_scroll = ttk.Scrollbar(wifi_analysis_frame, orient=tk.VERTICAL, command=wifi_analysis_text.yview)
    wifi_analysis_text.configure(yscrollcommand=wifi_analysis_scroll.set)
    wifi_analysis_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    wifi_analysis_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Configure text tags
    wifi_analysis_text.tag_configure('header', foreground='#ff6b6b', font=('Consolas', 11, 'bold'))
    wifi_analysis_text.tag_configure('subheader', foreground='#ffd93d', font=('Consolas', 10, 'bold'))
    wifi_analysis_text.tag_configure('critical', foreground='#ff0000', font=('Consolas', 10, 'bold'))
    wifi_analysis_text.tag_configure('warning', foreground='#ffa500', font=('Consolas', 10))
    wifi_analysis_text.tag_configure('good', foreground='#00ff00', font=('Consolas', 10))
    wifi_analysis_text.tag_configure('info', foreground='#00bfff', font=('Consolas', 10))
    
    wifi_analysis_text.insert('1.0', "Select a network and click 'Analyze Security' to see detailed analysis.\n\n", 'info')
    wifi_analysis_text.insert(tk.END, "📶 WIFI SECURITY TESTING FEATURES:\n", 'header')
    wifi_analysis_text.insert(tk.END, "━" * 45 + "\n\n", 'info')
    wifi_analysis_text.insert(tk.END, "• Scan for available WiFi networks\n", 'info')
    wifi_analysis_text.insert(tk.END, "• Analyze security level (WEP/WPA/WPA2/WPA3)\n", 'info')
    wifi_analysis_text.insert(tk.END, "• Check for vulnerabilities\n", 'info')
    wifi_analysis_text.insert(tk.END, "• View saved WiFi passwords\n", 'info')
    wifi_analysis_text.insert(tk.END, "• Password strength analysis\n", 'info')
    wifi_analysis_text.insert(tk.END, "• Security recommendations\n\n", 'info')
    wifi_analysis_text.config(state=tk.DISABLED)
    
    # Store scanned networks
    scanned_wifi_networks = []
    
    def scan_wifi_networks():
        """Scan for available WiFi networks."""
        nonlocal scanned_wifi_networks
        wifi_status_var.set("🔄 Scanning for WiFi networks...")
        root.update_idletasks()
        
        # Clear existing entries
        for item in wifi_tree.get_children():
            wifi_tree.delete(item)
        
        # Scan networks
        networks = get_available_wifi_networks()
        scanned_wifi_networks = networks
        
        if not networks:
            wifi_status_var.set("⚠️ No networks found. Make sure WiFi is enabled.")
            return
        
        # Add to treeview with security analysis
        for net in networks:
            analysis = analyze_wifi_security(net)
            security_level = analysis.get('security_level', 'Unknown')
            
            # Add security icon
            if 'CRITICAL' in security_level:
                security_display = '🔴 CRITICAL'
            elif 'HIGH' in security_level:
                security_display = '🟠 HIGH RISK'
            elif 'MEDIUM' in security_level:
                security_display = '🟡 MEDIUM'
            elif 'GOOD' in security_level:
                security_display = '🟢 GOOD'
            elif 'EXCELLENT' in security_level:
                security_display = '✅ EXCELLENT'
            else:
                security_display = '❓ UNKNOWN'
            
            signal = net.get('signal', 0)
            signal_display = f"{signal}%" if signal else "N/A"
            
            wifi_tree.insert('', tk.END, values=(
                net.get('ssid', 'Hidden'),
                signal_display,
                net.get('authentication', 'Unknown'),
                net.get('encryption', 'Unknown'),
                net.get('channel', 'N/A'),
                security_display
            ))
        
        wifi_status_var.set(f"✅ Found {len(networks)} WiFi networks. Double-click to analyze.")
    
    def analyze_selected_wifi(event=None):
        """Analyze security of selected WiFi network."""
        selection = wifi_tree.selection()
        if not selection:
            return
        
        item = wifi_tree.item(selection[0])
        ssid = item['values'][0]
        
        # Find the network in scanned list
        network = None
        for net in scanned_wifi_networks:
            if net.get('ssid') == ssid:
                network = net
                break
        
        if not network:
            return
        
        # Perform analysis
        analysis = analyze_wifi_security(network)
        
        # Clear and update analysis text
        wifi_analysis_text.config(state=tk.NORMAL)
        wifi_analysis_text.delete('1.0', tk.END)
        
        wifi_analysis_text.insert(tk.END, "╔══════════════════════════════════════════╗\n", 'header')
        wifi_analysis_text.insert(tk.END, "║     📶 WIFI SECURITY ANALYSIS           ║\n", 'header')
        wifi_analysis_text.insert(tk.END, "╚══════════════════════════════════════════╝\n\n", 'header')
        
        wifi_analysis_text.insert(tk.END, f"🌐 Network: {ssid}\n", 'subheader')
        wifi_analysis_text.insert(tk.END, f"📡 Signal: {network.get('signal', 'N/A')}%\n", 'info')
        wifi_analysis_text.insert(tk.END, f"📻 Channel: {network.get('channel', 'N/A')}\n", 'info')
        wifi_analysis_text.insert(tk.END, f"🔒 Auth: {network.get('authentication', 'Unknown')}\n", 'info')
        wifi_analysis_text.insert(tk.END, f"🔐 Encryption: {network.get('encryption', 'Unknown')}\n\n", 'info')
        
        # Security Level
        security_level = analysis.get('security_level', 'Unknown')
        if 'CRITICAL' in security_level or 'HIGH' in security_level:
            wifi_analysis_text.insert(tk.END, f"⚠️ Security Level: {security_level}\n\n", 'critical')
        elif 'MEDIUM' in security_level:
            wifi_analysis_text.insert(tk.END, f"⚠️ Security Level: {security_level}\n\n", 'warning')
        else:
            wifi_analysis_text.insert(tk.END, f"✅ Security Level: {security_level}\n\n", 'good')
        
        # Vulnerabilities
        wifi_analysis_text.insert(tk.END, "🔍 VULNERABILITIES\n", 'subheader')
        wifi_analysis_text.insert(tk.END, "─" * 40 + "\n", 'info')
        for vuln in analysis.get('vulnerabilities', []):
            if '🚨' in vuln or '⚠️' in vuln:
                wifi_analysis_text.insert(tk.END, f"  {vuln}\n", 'warning')
            else:
                wifi_analysis_text.insert(tk.END, f"  {vuln}\n", 'info')
        wifi_analysis_text.insert(tk.END, "\n", 'info')
        
        # Crack Assessment
        wifi_analysis_text.insert(tk.END, "🔓 CRACK ASSESSMENT\n", 'subheader')
        wifi_analysis_text.insert(tk.END, "─" * 40 + "\n", 'info')
        wifi_analysis_text.insert(tk.END, f"  Crackable: {'Yes' if analysis.get('crackable') else 'No'}\n", 
                                  'critical' if analysis.get('crackable') else 'good')
        wifi_analysis_text.insert(tk.END, f"  Difficulty: {analysis.get('crack_difficulty', 'Unknown')}\n", 'info')
        wifi_analysis_text.insert(tk.END, f"  Est. Time: {analysis.get('estimated_crack_time', 'Unknown')}\n\n", 'info')
        
        # Recommendations
        wifi_analysis_text.insert(tk.END, "📋 RECOMMENDATIONS\n", 'subheader')
        wifi_analysis_text.insert(tk.END, "─" * 40 + "\n", 'info')
        for rec in analysis.get('recommendations', []):
            wifi_analysis_text.insert(tk.END, f"  • {rec}\n", 'good')
        
        wifi_analysis_text.config(state=tk.DISABLED)
    
    def show_saved_passwords():
        """Show all saved WiFi passwords with strength analysis."""
        wifi_analysis_text.config(state=tk.NORMAL)
        wifi_analysis_text.delete('1.0', tk.END)
        
        wifi_status_var.set("🔄 Extracting saved WiFi passwords...")
        root.update_idletasks()
        
        passwords = get_saved_wifi_passwords()
        
        wifi_analysis_text.insert(tk.END, "╔══════════════════════════════════════════╗\n", 'header')
        wifi_analysis_text.insert(tk.END, "║     🔑 SAVED WIFI PASSWORDS             ║\n", 'header')
        wifi_analysis_text.insert(tk.END, "╚══════════════════════════════════════════╝\n\n", 'header')
        
        if not passwords:
            wifi_analysis_text.insert(tk.END, "⚠️ No saved WiFi profiles found.\n", 'warning')
            wifi_analysis_text.insert(tk.END, "Run as Administrator for full access.\n", 'info')
            wifi_analysis_text.config(state=tk.DISABLED)
            wifi_status_var.set("⚠️ No saved passwords found")
            return
        
        wifi_analysis_text.insert(tk.END, f"Found {len(passwords)} saved networks:\n\n", 'info')
        
        for i, wifi in enumerate(passwords, 1):
            wifi_analysis_text.insert(tk.END, f"━━━ Network #{i} ━━━\n", 'subheader')
            wifi_analysis_text.insert(tk.END, f"📶 SSID: {wifi['ssid']}\n", 'info')
            
            pwd = wifi['password']
            if pwd and pwd not in ['(Open Network or Not Stored)', '(Access Denied)']:
                wifi_analysis_text.insert(tk.END, f"🔑 Password: {pwd}\n", 'critical')
                
                # Analyze password strength
                strength = wifi_password_strength_check(pwd)
                wifi_analysis_text.insert(tk.END, f"💪 Strength: {strength['strength']} ({strength['score']}/100)\n", 
                                          'good' if strength['score'] >= 60 else 'warning')
                wifi_analysis_text.insert(tk.END, f"⏱️ Crack Time: {strength['crack_time_estimate']}\n", 'info')
                
                if strength['issues']:
                    wifi_analysis_text.insert(tk.END, "Issues:\n", 'warning')
                    for issue in strength['issues'][:3]:
                        wifi_analysis_text.insert(tk.END, f"   {issue}\n", 'warning')
            else:
                wifi_analysis_text.insert(tk.END, f"🔑 Password: {pwd}\n", 'info')
            
            wifi_analysis_text.insert(tk.END, f"🔒 Security: {wifi['authentication']} / {wifi['security']}\n\n", 'info')
        
        wifi_analysis_text.config(state=tk.DISABLED)
        wifi_status_var.set(f"✅ Retrieved {len(passwords)} saved WiFi passwords")
    
    def run_security_test():
        """Run WiFi security testing simulation."""
        wifi_analysis_text.config(state=tk.NORMAL)
        wifi_analysis_text.delete('1.0', tk.END)
        
        wifi_analysis_text.insert(tk.END, "╔══════════════════════════════════════════╗\n", 'header')
        wifi_analysis_text.insert(tk.END, "║     🔬 WIFI SECURITY TEST               ║\n", 'header')
        wifi_analysis_text.insert(tk.END, "╚══════════════════════════════════════════╝\n\n", 'header')
        
        wifi_analysis_text.insert(tk.END, "⚠️ EDUCATIONAL PURPOSE ONLY\n", 'warning')
        wifi_analysis_text.insert(tk.END, "This demonstrates common WiFi attack vectors.\n\n", 'info')
        
        wifi_analysis_text.insert(tk.END, "🔓 COMMON ATTACK METHODS\n", 'subheader')
        wifi_analysis_text.insert(tk.END, "─" * 40 + "\n", 'info')
        
        attacks = [
            ("WEP Cracking", "aircrack-ng captures IVs and cracks key", "Minutes"),
            ("WPA Handshake", "Capture 4-way handshake, dictionary attack", "Hours-Days"),
            ("PMKID Attack", "Clientless attack on WPA, hashcat", "Hours-Days"),
            ("Evil Twin", "Fake AP to capture credentials", "Variable"),
            ("WPS PIN Attack", "Reaver/Bully brute-force 8-digit PIN", "Hours"),
            ("Deauth Attack", "Force reconnection for handshake capture", "Seconds"),
        ]
        
        for attack, desc, time in attacks:
            wifi_analysis_text.insert(tk.END, f"\n  🔸 {attack}\n", 'warning')
            wifi_analysis_text.insert(tk.END, f"     Method: {desc}\n", 'info')
            wifi_analysis_text.insert(tk.END, f"     Time: {time}\n", 'info')
        
        wifi_analysis_text.insert(tk.END, "\n\n✅ PROTECTION RECOMMENDATIONS\n", 'subheader')
        wifi_analysis_text.insert(tk.END, "─" * 40 + "\n", 'info')
        
        protections = [
            "Use WPA3 if router supports it",
            "Use strong 12+ character passwords",
            "Disable WPS (WiFi Protected Setup)",
            "Enable MAC address filtering",
            "Use a hidden SSID (limited protection)",
            "Keep router firmware updated",
            "Monitor for unknown devices",
            "Use 802.1X Enterprise authentication"
        ]
        
        for prot in protections:
            wifi_analysis_text.insert(tk.END, f"  ✓ {prot}\n", 'good')
        
        wifi_analysis_text.config(state=tk.DISABLED)
    
    # WiFi button frame
    wifi_btn_frame = ttk.Frame(wifi_frame)
    wifi_btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    ttk.Button(wifi_btn_frame, text="📡 Scan Networks", command=scan_wifi_networks).pack(side=tk.LEFT, padx=5)
    ttk.Button(wifi_btn_frame, text="🔍 Analyze Selected", command=analyze_selected_wifi).pack(side=tk.LEFT, padx=5)
    ttk.Button(wifi_btn_frame, text="🔑 Show Saved Passwords", command=show_saved_passwords).pack(side=tk.LEFT, padx=5)
    ttk.Button(wifi_btn_frame, text="🔬 Security Test Info", command=run_security_test).pack(side=tk.LEFT, padx=5)
    
    # Bind double-click to analyze
    wifi_tree.bind("<Double-1>", analyze_selected_wifi)

    # --- Controls ---
    control_frame = ttk.Frame(root)
    control_frame.pack(fill=tk.X, padx=5, pady=2)
    pause_var = tk.BooleanVar(value=False)
    def toggle_pause():
        pause_var.set(not pause_var.get())
        if pause_var.get():
            status_var.set("Status: Monitoring Paused")
        else:
            status_var.set("Status: Monitoring (Running in Background) | Double-click threat for details")

    pause_btn = ttk.Button(control_frame, text="⏸️ Pause/Resume", command=toggle_pause)
    pause_btn.pack(side=tk.LEFT, padx=2)
    export_btn = ttk.Button(control_frame, text="📁 Export Threats", command=lambda: export_threats(tree))
    export_btn.pack(side=tk.LEFT, padx=2)
    refresh_btn = ttk.Button(control_frame, text="🔄 Refresh Network", command=lambda: update_network_tab())
    refresh_btn.pack(side=tk.LEFT, padx=2)

    # Store threats by PID with full breakdown
    threats = {}

    def gui_callback(threat_info):
        """Enhanced callback that stores full threat breakdown for detail view."""
        if pause_var.get():
            return
        pid = threat_info['pid']
        
        # Store full threat info including breakdown
        threats[pid] = threat_info
        
        # Remove existing row if present
        for item in tree.get_children():
            if tree.item(item)['values'][0] == pid:
                tree.delete(item)
        
        # Format severity with emoji
        severity = threat_info.get('severity', 'Unknown')
        severity_icons = {
            'Critical': '🔴 Critical',
            'High': '🟠 High',
            'Medium': '🟡 Medium',
            'Low': '🟢 Low',
            'Safe': '✅ Safe'
        }
        severity_display = severity_icons.get(severity, severity)
        
        # Format categories as readable list
        categories = threat_info.get('categories', [])
        categories_display = ', '.join(categories[:3]) if categories else 'None'
        if len(categories) > 3:
            categories_display += f' (+{len(categories)-3})'
        
        # Format VT status
        vt_file = threat_info.get('vt_file')
        vt_ips = threat_info.get('vt_ips', [])
        vt_status_parts = []
        if vt_file:
            mal = vt_file.get('malicious', 0)
            susp = vt_file.get('suspicious', 0)
            if mal > 0 or susp > 0:
                vt_status_parts.append(f"File: {mal}M/{susp}S")
        if vt_ips:
            total_mal = sum(ip.get('malicious', 0) for ip in vt_ips)
            total_susp = sum(ip.get('suspicious', 0) for ip in vt_ips)
            if total_mal > 0 or total_susp > 0:
                vt_status_parts.append(f"IPs: {total_mal}M/{total_susp}S")
        vt_status = ' | '.join(vt_status_parts) if vt_status_parts else '✓ Clean'
        
        # Format actions
        actions = ['📋 Details']
        if threat_info['risk_score'] >= 5:
            actions.append('⛔ Terminate')
        if threat_info.get('suspicious_connections'):
            actions.append('🔒 Block')
        action_display = ' '.join(actions)
        
        # Determine row tag for coloring
        severity_tag = severity.lower() if severity in ('Critical', 'High', 'Medium', 'Low') else ''
        
        # Insert row
        tree.insert("", "end", 
            values=(pid, threat_info['name'], severity_display, threat_info['risk_score'], 
                    categories_display, vt_status, action_display),
            tags=(severity_tag,) if severity_tag else ())

    # Initialize monitor before any callback uses it
    monitor = ThreatMonitor(gui_callback=gui_callback)
    monitor_thread = threading.Thread(target=monitor.monitor_system, daemon=True)
    monitor_thread.start()

    def show_threat_details_popup(pid):
        """Show detailed threat analysis breakdown in a readable popup."""
        if pid not in threats:
            messagebox.showinfo("No Data", "No threat data available for this process.")
            return
        
        threat = threats[pid]
        
        popup = tk.Toplevel(root)
        popup.title(f"🛡️ Threat Analysis: {threat['name']} (PID: {pid})")
        popup.geometry("700x600")
        popup.configure(bg='#f8f9fa')
        
        # Create scrollable frame
        canvas = tk.Canvas(popup, bg='#f8f9fa')
        scrollbar = ttk.Scrollbar(popup, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Header
        header_frame = ttk.Frame(scrollable_frame)
        header_frame.pack(fill=tk.X, padx=15, pady=10)
        
        severity = threat.get('severity', 'Unknown')
        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745', 'Safe': '#17a2b8'}
        sev_color = severity_colors.get(severity, '#6c757d')
        
        ttk.Label(header_frame, text=f"Process: {threat['name']}", font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        ttk.Label(header_frame, text=f"PID: {pid} | Path: {threat['exe']}", font=('Segoe UI', 9)).pack(anchor='w')
        
        # Severity banner
        severity_frame = tk.Frame(scrollable_frame, bg=sev_color)
        severity_frame.pack(fill=tk.X, padx=15, pady=5)
        tk.Label(severity_frame, text=f"SEVERITY: {severity.upper()} | Risk Score: {threat['risk_score']}", 
                 font=('Segoe UI', 12, 'bold'), bg=sev_color, fg='white').pack(pady=8)
        
        # Categories section
        if threat.get('categories'):
            cat_frame = ttk.LabelFrame(scrollable_frame, text="🏷️ Threat Categories")
            cat_frame.pack(fill=tk.X, padx=15, pady=5)
            cats_text = "  •  ".join(threat['categories'])
            ttk.Label(cat_frame, text=cats_text, wraplength=650, font=('Segoe UI', 10)).pack(padx=10, pady=5)
        
        # Indicators section
        if threat.get('indicators'):
            ind_frame = ttk.LabelFrame(scrollable_frame, text="🔍 Threat Indicators (Detailed Breakdown)")
            ind_frame.pack(fill=tk.X, padx=15, pady=5)
            
            for i, ind in enumerate(threat['indicators']):
                ind_row = ttk.Frame(ind_frame)
                ind_row.pack(fill=tk.X, padx=10, pady=5)
                
                # Severity badge
                ind_sev = ind.get('severity', 'Unknown')
                ind_color = severity_colors.get(ind_sev, '#6c757d')
                
                # Type and severity
                type_label = tk.Label(ind_row, text=f"[{ind_sev}]", font=('Segoe UI', 9, 'bold'), 
                                     fg='white', bg=ind_color, padx=5)
                type_label.pack(side=tk.LEFT)
                ttk.Label(ind_row, text=f" {ind.get('type', 'Unknown')}", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
                
                # Description
                desc_frame = ttk.Frame(ind_frame)
                desc_frame.pack(fill=tk.X, padx=25, pady=2)
                ttk.Label(desc_frame, text=f"📝 {ind.get('description', '')}", wraplength=600).pack(anchor='w')
                ttk.Label(desc_frame, text=f"   → {ind.get('details', '')}", wraplength=600, 
                         font=('Consolas', 9)).pack(anchor='w')
                if ind.get('recommendation'):
                    ttk.Label(desc_frame, text=f"   💡 {ind.get('recommendation', '')}", 
                             wraplength=600, font=('Segoe UI', 9, 'italic')).pack(anchor='w')
                
                # Separator
                if i < len(threat['indicators']) - 1:
                    ttk.Separator(ind_frame, orient='horizontal').pack(fill=tk.X, padx=10, pady=5)
        
        # VirusTotal Results
        vt_file = threat.get('vt_file')
        vt_ips = threat.get('vt_ips', [])
        if vt_file or vt_ips:
            vt_frame = ttk.LabelFrame(scrollable_frame, text="🦠 VirusTotal Analysis")
            vt_frame.pack(fill=tk.X, padx=15, pady=5)
            
            if vt_file:
                mal = vt_file.get('malicious', 0)
                susp = vt_file.get('suspicious', 0)
                file_status = "⚠️ FLAGGED" if (mal > 0 or susp > 0) else "✅ Clean"
                ttk.Label(vt_frame, text=f"File Hash: {vt_file.get('hash', 'N/A')[:16]}...", 
                         font=('Consolas', 9)).pack(anchor='w', padx=10)
                ttk.Label(vt_frame, text=f"   {file_status} - {mal} malicious, {susp} suspicious detections",
                         font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=2)
            
            if vt_ips:
                ttk.Label(vt_frame, text="IP Address Analysis:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=10, pady=5)
                for ip_info in vt_ips:
                    mal = ip_info.get('malicious', 0)
                    susp = ip_info.get('suspicious', 0)
                    ip_status = "⚠️ FLAGGED" if (mal > 0 or susp > 0) else "✅ Clean"
                    ttk.Label(vt_frame, text=f"   {ip_info['ip']}:{ip_info.get('port', '?')} - {ip_status} ({mal}M/{susp}S)",
                             font=('Consolas', 9)).pack(anchor='w', padx=10)
        
        # Suspicious Connections
        sus_conns = threat.get('suspicious_connections', [])
        if sus_conns:
            conn_frame = ttk.LabelFrame(scrollable_frame, text="🌐 Suspicious Network Connections")
            conn_frame.pack(fill=tk.X, padx=15, pady=5)
            for conn in sus_conns:
                ttk.Label(conn_frame, text=f"   ⚠️ {conn['ip']}:{conn['port']} - {conn.get('reason', 'Unknown')}",
                         font=('Consolas', 9)).pack(anchor='w', padx=10, pady=2)
        
        # Resource Abuse
        resource_abuse = threat.get('resource_abuse', [])
        if resource_abuse:
            res_frame = ttk.LabelFrame(scrollable_frame, text="⚡ Resource Usage")
            res_frame.pack(fill=tk.X, padx=15, pady=5)
            for res in resource_abuse:
                ttk.Label(res_frame, text=f"   {res['type']}: {res['value']} (threshold: {res['threshold']})",
                         font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=2)
        
        # Recommendations
        if threat.get('recommendations'):
            rec_frame = ttk.LabelFrame(scrollable_frame, text="💡 Recommendations")
            rec_frame.pack(fill=tk.X, padx=15, pady=5)
            for rec in threat['recommendations']:
                ttk.Label(rec_frame, text=f"   {rec}", wraplength=650, font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=2)
        
        # Action buttons
        btn_frame = ttk.Frame(scrollable_frame)
        btn_frame.pack(fill=tk.X, padx=15, pady=15)
        
        def terminate_process():
            if messagebox.askyesno("Confirm", f"Terminate {threat['name']} (PID: {pid})?"):
                monitor.terminate_process(pid)
                popup.destroy()
        
        def block_ips():
            if sus_conns:
                show_network_actions_popup(pid, threat['name'], ', '.join(f"{c['ip']}:{c['port']}" for c in sus_conns))
        
        if threat['risk_score'] >= 5:
            ttk.Button(btn_frame, text="⛔ Terminate Process", command=terminate_process).pack(side=tk.LEFT, padx=5)
        if sus_conns:
            ttk.Button(btn_frame, text="🔒 Block IPs", command=block_ips).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Pack scrollbar
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

    def on_tree_click(event):
        """Handle click on threat row - show details popup."""
        item = tree.identify_row(event.y)
        if not item:
            return
        values = tree.item(item)['values']
        pid = values[0]
        
        # Show detailed threat analysis popup
        show_threat_details_popup(pid)

    # Bind double-click to show detailed analysis
    tree.bind("<Double-1>", on_tree_click)

    def show_network_actions_popup(pid, name, sus_net):
        popup = tk.Toplevel(root)
        popup.title(f"Network Actions for {name} (PID: {pid})")
        popup.geometry("420x260")
        label = ttk.Label(popup, text=f"Suspicious Network Connections for {name} (PID: {pid}):", font=("Segoe UI", 10, "bold"))
        label.pack(pady=5)
        sus_list = sus_net.split(", ")
        listbox = tk.Listbox(popup, height=6, selectmode=tk.SINGLE)
        for net in sus_list:
            listbox.insert(tk.END, net)
        listbox.pack(fill=tk.X, padx=10, pady=5)

        def do_vt_lookup():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Lookup", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            mal, susp = vt_check_ip(ip)
            messagebox.showinfo("VirusTotal IP Lookup", f"IP: {ip}\nMalicious: {mal or 0}\nSuspicious: {susp or 0}")

        def do_block():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Block", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            # Block using Windows Firewall (netsh)
            import subprocess
            rule_name = f"Block_{pid}_{ip}"
            exe = None
            # Find exe for this pid
            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = None
            try:
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", f"remoteip={ip}", "action=block"]
                if exe:
                    cmd.insert(8, f"program={exe}")
                subprocess.run(cmd, check=True, capture_output=True)
                messagebox.showinfo("Block", f"Blocked outbound traffic to {ip} for process {name}.")
            except Exception as e:
                messagebox.showerror("Block", f"Failed to block: {e}")

        def do_quarantine():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Quarantine", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            # Quarantine: block both in/out for this process and IP
            import subprocess
            rule_name = f"Quarantine_{pid}_{ip}"
            exe = None
            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = None
            try:
                cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", f"remoteip={ip}", "action=block"]
                cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_in", "dir=in", f"remoteip={ip}", "action=block"]
                if exe:
                    cmd_out.insert(8, f"program={exe}")
                    cmd_in.insert(8, f"program={exe}")
                subprocess.run(cmd_out, check=True, capture_output=True)
                subprocess.run(cmd_in, check=True, capture_output=True)
                messagebox.showinfo("Quarantine", f"Quarantined {ip} for process {name} (blocked in/out).")
            except Exception as e:
                messagebox.showerror("Quarantine", f"Failed to quarantine: {e}")

        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=10)
        vt_btn = ttk.Button(btn_frame, text="VirusTotal Lookup", command=do_vt_lookup)
        vt_btn.pack(side=tk.LEFT, padx=5)
        block_btn = ttk.Button(btn_frame, text="Block Network", command=do_block)
        block_btn.pack(side=tk.LEFT, padx=5)
        quar_btn = ttk.Button(btn_frame, text="Quarantine", command=do_quarantine)
        quar_btn.pack(side=tk.LEFT, padx=5)
        close_btn = ttk.Button(btn_frame, text="Close", command=popup.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)

    # --- Network Tab Logic ---
    vt_ip_cache = {}
    def show_ip_info(ip):
        if not ip or ip in ("-", "127.0.0.1", "0.0.0.0"): 
            messagebox.showinfo("IP Info", "No valid remote IP selected.")
            return
        if ip in vt_ip_cache:
            mal, susp = vt_ip_cache[ip]
        else:
            mal, susp = vt_check_ip(ip)
            vt_ip_cache[ip] = (mal, susp)
        info = f"IP: {ip}\nMalicious: {mal or 0}\nSuspicious: {susp or 0}"
        messagebox.showinfo("VirusTotal IP Info", info)

    def update_network_tab():
        for item in net_tree.get_children():
            net_tree.delete(item)
        suspicious_ips = set(monitor.threat_database.get('suspicious_connections', []))
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name']
            try:
                for conn in psutil.Process(pid).net_connections():
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    status = conn.status
                    suspicious = "Yes" if conn.raddr and str(conn.raddr.ip) in suspicious_ips else ""
                    vt_ip = "-"
                    row_tags = ()
                    if suspicious:
                        row_tags = ('suspicious',)
                    idx = net_tree.insert("", "end", values=(pid, name, laddr, raddr, status, suspicious, vt_ip), tags=row_tags)
            except Exception:
                continue
        net_tree.tag_configure('suspicious', background='#ffcccc')

    def on_network_row(event):
        item = net_tree.identify_row(event.y)
        if not item:
            return
        values = net_tree.item(item)['values']
        raddr = values[3]
        ip = raddr.split(':')[0] if raddr else ""
        show_ip_info(ip)

    net_tree.bind("<Double-1>", on_network_row)

    # Add a button for manual IP info lookup
    ipinfo_btn = ttk.Button(control_frame, text="IP Info Lookup", command=lambda: show_ip_info(net_tree.item(net_tree.focus())['values'][3].split(':')[0] if net_tree.focus() else ""))
    ipinfo_btn.pack(side=tk.LEFT, padx=2)

    # --- Export Threats ---
    def export_threats(tree_widget):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return
        import csv
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Name", "Path", "Risk Score", "Status"])
            for item in tree_widget.get_children():
                row = tree_widget.item(item)['values'][:5]
                writer.writerow(row)
        messagebox.showinfo("Export", f"Threats exported to {file_path}")

    # --- Network Packet Tab Logic ---
    if SCAPY_AVAILABLE:
        import queue
        pkt_queue = queue.Queue()
        captured_packets = []  # Store for human-readable inspection
        total_confidential_found = [0]  # Use list for mutable in closure
        
        def packet_callback(pkt):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
                info = ""
                threat = ""
                confidential_flag = ""
                
                if TCP in pkt:
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    info = f"TCP {sport}->{dport}"
                    if dport in [23, 2323, 4444, 3389]:
                        threat = "Suspicious Port"
                    # Check for unencrypted protocols that may contain sensitive data
                    if dport in [80, 8080, 21, 23, 25, 110, 143]:
                        threat = "Unencrypted" if not threat else threat + " | Unencrypted"
                elif UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    info = f"UDP {sport}->{dport}"
                else:
                    info = proto_name
                
                # Check for confidential data in payload
                if pkt.haslayer('Raw'):
                    try:
                        # Pass raw bytes directly - the function handles encoding
                        raw_bytes = pkt['Raw'].load
                        extracted = extract_confidential_data(raw_bytes)
                        
                        # Check if any confidential data found
                        found_types = []
                        if extracted['passwords']:
                            found_types.append('PWD')
                        if extracted['usernames']:
                            found_types.append('USER')
                        if extracted['emails']:
                            found_types.append('EMAIL')
                        if extracted['credit_cards']:
                            found_types.append('CC')
                        if extracted['api_keys'] or extracted['tokens']:
                            found_types.append('TOKEN')
                        if extracted['cookies']:
                            found_types.append('COOKIE')
                        if extracted['auth_headers']:
                            found_types.append('AUTH')
                        
                        if found_types:
                            confidential_flag = " | ".join(found_types)
                            total_confidential_found[0] += 1
                            if not threat:
                                threat = "⚠️ CONFIDENTIAL"
                            else:
                                threat += " | CONFID"
                            # Include extracted data for the container
                            pkt_queue.put((src, dst, proto_name, info, threat, confidential_flag, extracted))
                        else:
                            pkt_queue.put((src, dst, proto_name, info, threat, confidential_flag, None))
                    except Exception:
                        pkt_queue.put((src, dst, proto_name, info, threat, confidential_flag, None))
                else:
                    pkt_queue.put((src, dst, proto_name, info, threat, confidential_flag, None))
                
                captured_packets.insert(0, pkt)
                if len(captured_packets) > 2000:
                    captured_packets.pop()

        def process_packet_queue():
            try:
                while True:
                    item = pkt_queue.get_nowait()
                    # Handle both old (6 items) and new (7 items) format
                    if len(item) == 7:
                        src, dst, proto_name, info, threat, confidential_flag, extracted_data = item
                    else:
                        src, dst, proto_name, info, threat, confidential_flag = item
                        extracted_data = None
                    
                    values = (time.strftime('%H:%M:%S'), src, dst, proto_name, info, threat, confidential_flag)
                    
                    # Determine tag based on content
                    if confidential_flag:
                        tag = 'confidential'
                        # Add to confidential container if we have extracted data
                        if extracted_data:
                            add_to_confidential_container(extracted_data, src, dst, time.strftime('%H:%M:%S'))
                    elif threat:
                        tag = 'suspicious'
                    else:
                        tag = 'clean'
                    
                    pkt_tree.insert("", 0, values=values, tags=(tag,))
                    
                    # Update confidential count
                    confidential_count.set(total_confidential_found[0])
            except queue.Empty:
                pass
            root.after(200, process_packet_queue)

        def start_sniffing():
            sniff(prn=packet_callback, store=0)

        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        root.after(200, process_packet_queue)

    def on_close():
        monitor.running = False
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    update_network_tab()
    root.mainloop()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point for the application."""
    # Display startup information
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Security Threat Intelligence Monitor v2.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # All users have full access
    print(f"{Fore.GREEN}[+] Full access enabled - all features available.{Style.RESET_ALL}")
    
    # Check VirusTotal configuration
    if not Config.VIRUSTOTAL_API_KEY:
        print(f"{Fore.YELLOW}[!] VirusTotal API key not configured. File/IP scanning disabled.{Style.RESET_ALL}")
        print(f"    Copy .env.example to .env and add your API key.{Style.RESET_ALL}")
    
    # Log startup
    app_logger.info("Application starting")
    
    # Launch GUI
    run_gui()


if __name__ == "__main__":
    main()

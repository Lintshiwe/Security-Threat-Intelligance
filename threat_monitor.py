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
# ADMIN UTILITIES
# =============================================================================

def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def add_firewall_rule(name: str, direction: str = "out", remote_ip: Optional[str] = None,
                      program: Optional[str] = None, action: str = "block") -> bool:
    """Add a Windows Firewall rule using netsh."""
    if not is_admin():
        app_logger.error("Firewall modification requires administrator privileges")
        return False
    
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


def extract_confidential_data(payload: str) -> Dict[str, List[str]]:
    """Extract potentially confidential information from packet payload."""
    import re
    
    confidential = {
        'passwords': [],
        'usernames': [],
        'emails': [],
        'credit_cards': [],
        'api_keys': [],
        'tokens': [],
        'urls': [],
        'ips': [],
        'cookies': [],
        'auth_headers': [],
        'sensitive_keywords': []
    }
    
    if not payload:
        return confidential
    
    # Password patterns
    pwd_patterns = [
        r'password[=:"\s]+([^\s&"<>]{3,50})',
        r'passwd[=:"\s]+([^\s&"<>]{3,50})',
        r'pwd[=:"\s]+([^\s&"<>]{3,50})',
        r'pass[=:"\s]+([^\s&"<>]{3,50})',
        r'secret[=:"\s]+([^\s&"<>]{3,50})',
    ]
    for pattern in pwd_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        confidential['passwords'].extend(matches)
    
    # Username patterns
    user_patterns = [
        r'username[=:"\s]+([^\s&"<>]{3,50})',
        r'user[=:"\s]+([^\s&"<>]{3,50})',
        r'login[=:"\s]+([^\s&"<>]{3,50})',
        r'userid[=:"\s]+([^\s&"<>]{3,50})',
        r'email[=:"\s]+([^\s&"<>@]{3,50}@[^\s&"<>]{3,50})',
    ]
    for pattern in user_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        confidential['usernames'].extend(matches)
    
    # Email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    confidential['emails'] = re.findall(email_pattern, payload)
    
    # Credit card patterns (basic detection)
    cc_patterns = [
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',  # Visa
        r'\b(?:5[1-5][0-9]{14})\b',  # MasterCard
        r'\b(?:3[47][0-9]{13})\b',  # Amex
        r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',  # Discover
    ]
    for pattern in cc_patterns:
        matches = re.findall(pattern, payload)
        confidential['credit_cards'].extend(matches)
    
    # API Keys / Tokens
    api_patterns = [
        r'api[_-]?key[=:"\s]+([a-zA-Z0-9_-]{20,})',
        r'apikey[=:"\s]+([a-zA-Z0-9_-]{20,})',
        r'access[_-]?token[=:"\s]+([a-zA-Z0-9_.-]{20,})',
        r'bearer[\s]+([a-zA-Z0-9_.-]{20,})',
        r'authorization[=:"\s]+([a-zA-Z0-9_.-]{20,})',
    ]
    for pattern in api_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        confidential['api_keys'].extend(matches)
    
    # JWT Tokens
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
    confidential['tokens'] = re.findall(jwt_pattern, payload)
    
    # Cookies
    cookie_patterns = [
        r'cookie[=:"\s]+([^\s;]{5,})',
        r'session[_-]?id[=:"\s]+([^\s;"]{5,})',
        r'PHPSESSID[=:]+([^\s;"]{5,})',
        r'JSESSIONID[=:]+([^\s;"]{5,})',
    ]
    for pattern in cookie_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        confidential['cookies'].extend(matches)
    
    # Auth headers
    auth_patterns = [
        r'Authorization:\s*([^\r\n]{10,})',
        r'X-Auth-Token:\s*([^\r\n]{10,})',
        r'X-API-Key:\s*([^\r\n]{10,})',
    ]
    for pattern in auth_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        confidential['auth_headers'].extend(matches)
    
    # Sensitive keywords
    sensitive_words = [
        'password', 'passwd', 'secret', 'private', 'confidential',
        'ssn', 'social security', 'credit card', 'cvv', 'pin',
        'bank', 'account', 'routing', 'swift', 'iban'
    ]
    for word in sensitive_words:
        if word.lower() in payload.lower():
            confidential['sensitive_keywords'].append(word)
    
    return confidential


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
        'network_info': {}
    }
    
    # Check if private IP
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
        intel['is_private'] = True
        intel['network_info']['type'] = 'Private/LAN'
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
                ).strftime('%Y-%m-%d %H:%M:%S')
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
            threat_breakdown['recommendations'].append('🚨 CRITICAL: Terminate process and quarantine file immediately')
        if 'VT Flagged IP' in unique_categories or 'Suspicious Network' in unique_categories:
            threat_breakdown['recommendations'].append('🔒 Block suspicious IP addresses using firewall')
        if 'High-Risk Process' in unique_categories:
            threat_breakdown['recommendations'].append('🔍 Review command-line arguments for suspicious activity')
        if 'Suspicious Location' in unique_categories:
            threat_breakdown['recommendations'].append('📁 Verify file origin and scan with antivirus')
        if 'Resource Abuse' in unique_categories:
            threat_breakdown['recommendations'].append('⚡ Monitor resource usage; may indicate cryptomining')
        
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
                    risk_score, threat_breakdown = self.analyze_process(process_details)
                    
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
    
    pkt_status_var = tk.StringVar(value="📡 Capturing packets... Double-click to inspect & extract confidential data")
    ttk.Label(pkt_header, textvariable=pkt_status_var, font=('Segoe UI', 9)).pack(side=tk.LEFT)
    
    # Stats for captured confidential data
    confidential_count = tk.IntVar(value=0)
    ttk.Label(pkt_header, text="🔴 Confidential Found:", font=('Segoe UI', 9, 'bold')).pack(side=tk.RIGHT, padx=(10, 0))
    ttk.Label(pkt_header, textvariable=confidential_count, font=('Segoe UI', 9, 'bold'), foreground='#dc3545').pack(side=tk.RIGHT)
    
    pkt_columns = ("Time", "Source", "Destination", "Protocol", "Info", "Threat", "Confidential")
    pkt_tree = ttk.Treeview(packet_frame, columns=pkt_columns, show="headings", height=15)
    for col in pkt_columns:
        pkt_tree.heading(col, text=col)
        if col == "Info":
            pkt_tree.column(col, width=200)
        elif col == "Confidential":
            pkt_tree.column(col, width=100)
        else:
            pkt_tree.column(col, width=110)
    
    # Color tags for packets with confidential data
    pkt_tree.tag_configure('confidential', background='#f8d7da', foreground='#721c24')
    pkt_tree.tag_configure('suspicious', background='#fff3cd', foreground='#856404')
    pkt_tree.tag_configure('clean', background='#d4edda', foreground='#155724')
    
    pkt_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    if not SCAPY_AVAILABLE:
        pkt_tree.insert("", 0, values=("-", "-", "-", "-", "Install scapy for packet capture", "-", "-"))

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
═══════════════════════════════════════════════════════════
                    PACKET ANALYSIS REPORT
═══════════════════════════════════════════════════════════

📅 Capture Time:    {values[0]}
📤 Source:          {values[1]}
📥 Destination:     {values[2]}
📡 Protocol:        {values[3]}
ℹ️  Info:            {values[4]}
⚠️  Threat Level:    {values[5]}
🔐 Confidential:    {values[6]}

"""
        
        try:
            idx = pkt_tree.index(item)
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                from scapy.all import hexdump
                
                if pkt.haslayer('TCP'):
                    basic_info += f"""
═══════════════════════════════════════════════════════════
                      TCP DETAILS
═══════════════════════════════════════════════════════════
🚩 TCP Flags:       {pkt['TCP'].flags}
🔢 Sequence:        {pkt['TCP'].seq}
✅ Acknowledgment:  {pkt['TCP'].ack}
🚪 Source Port:     {pkt['TCP'].sport}
🚪 Dest Port:       {pkt['TCP'].dport}
📊 Window Size:     {pkt['TCP'].window}
"""
                
                if pkt.haslayer('UDP'):
                    basic_info += f"""
═══════════════════════════════════════════════════════════
                      UDP DETAILS
═══════════════════════════════════════════════════════════
🚪 Source Port:     {pkt['UDP'].sport}
🚪 Dest Port:       {pkt['UDP'].dport}
📏 Length:          {pkt['UDP'].len}
"""
        except Exception:
            pass
        
        basic_text.insert('1.0', basic_info)
        basic_text.config(state=tk.DISABLED)
        
        # Tab 2: Payload & Raw Data
        payload_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(payload_frame, text="📦 Payload Data")
        
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
                
                payload_content = "═══════════════════════════════════════════════════════════\\n"
                payload_content += "                    RAW PACKET (HEX DUMP)\\n"
                payload_content += "═══════════════════════════════════════════════════════════\\n\\n"
                payload_content += hexdump(pkt, dump=True)
                
                if pkt.haslayer('Raw'):
                    raw = pkt['Raw'].load
                    try:
                        raw_payload = raw.decode(errors='replace')
                        payload_content += "\\n\\n═══════════════════════════════════════════════════════════\\n"
                        payload_content += "                    DECODED PAYLOAD\\n"
                        payload_content += "═══════════════════════════════════════════════════════════\\n\\n"
                        payload_content += raw_payload
                    except Exception:
                        payload_content += f"\\n\\nBinary Payload: {raw}"
        except Exception as e:
            payload_content = f"Could not extract payload: {e}"
        
        payload_text.insert('1.0', payload_content)
        payload_text.config(state=tk.DISABLED)
        
        # Tab 3: Confidential Data Extraction
        confid_frame = ttk.Frame(detail_notebook)
        detail_notebook.add(confid_frame, text="🔴 Confidential Data")
        
        confid_header = ttk.Frame(confid_frame)
        confid_header.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(confid_header, text="⚠️ EXTRACTED SENSITIVE INFORMATION", 
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
            confid_text.insert(tk.END, "\\n🔑 PASSWORDS FOUND:\\n", 'header')
            for pwd in extracted['passwords']:
                confid_text.insert(tk.END, f"   → {pwd}\\n", 'critical')
        
        if extracted['usernames']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n👤 USERNAMES FOUND:\\n", 'header')
            for user in extracted['usernames']:
                confid_text.insert(tk.END, f"   → {user}\\n", 'value')
        
        if extracted['emails']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n📧 EMAIL ADDRESSES:\\n", 'header')
            for email in extracted['emails']:
                confid_text.insert(tk.END, f"   → {email}\\n", 'value')
        
        if extracted['credit_cards']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n💳 CREDIT CARD NUMBERS:\\n", 'header')
            for cc in extracted['credit_cards']:
                # Mask middle digits for display
                masked = cc[:4] + '*' * (len(cc) - 8) + cc[-4:]
                confid_text.insert(tk.END, f"   → {masked} (MASKED)\\n", 'critical')
        
        if extracted['api_keys']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n🔐 API KEYS / SECRETS:\\n", 'header')
            for key in extracted['api_keys']:
                confid_text.insert(tk.END, f"   → {key[:20]}...\\n", 'critical')
        
        if extracted['tokens']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n🎫 JWT/AUTH TOKENS:\\n", 'header')
            for token in extracted['tokens']:
                confid_text.insert(tk.END, f"   → {token[:50]}...\\n", 'critical')
        
        if extracted['cookies']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n🍪 SESSION COOKIES:\\n", 'header')
            for cookie in extracted['cookies']:
                confid_text.insert(tk.END, f"   → {cookie}\\n", 'warning')
        
        if extracted['auth_headers']:
            has_confidential = True
            confid_text.insert(tk.END, "\\n🔒 AUTHORIZATION HEADERS:\\n", 'header')
            for auth in extracted['auth_headers']:
                confid_text.insert(tk.END, f"   → {auth}\\n", 'critical')
        
        if extracted['sensitive_keywords']:
            confid_text.insert(tk.END, "\\n⚠️ SENSITIVE KEYWORDS DETECTED:\\n", 'header')
            for word in set(extracted['sensitive_keywords']):
                confid_text.insert(tk.END, f"   • {word}\\n", 'warning')
        
        if not has_confidential:
            confid_text.insert(tk.END, "\\n✅ No sensitive data detected in this packet.\\n", 'value')
            confid_text.insert(tk.END, "\\nNote: Only unencrypted (HTTP, FTP, Telnet) traffic can be analyzed.\\n")
            confid_text.insert(tk.END, "HTTPS/TLS encrypted traffic cannot reveal confidential data.\\n")
        
        confid_text.config(state=tk.DISABLED)
        
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
                intel_report += "ℹ️ This is a PRIVATE/LAN IP address.\n"
                intel_report += "   External threat databases do not track private IPs.\n"
                intel_report += "   Monitor this device locally for suspicious behavior.\n\n"
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
    
    # Bind double-click for device details
    map_tree.bind("<Double-1>", show_device_details)
    
    # Show initial message
    if check_network_dependencies():
        map_tree.insert("", 0, values=("-", "-", "-", "-", "-", "-", "-", "-", 
            "Install netifaces & scapy for network scanning"))

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
                        raw_data = pkt['Raw'].load.decode(errors='replace')
                        extracted = extract_confidential_data(raw_data)
                        
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
                    except Exception:
                        pass
                
                pkt_queue.put((src, dst, proto_name, info, threat, confidential_flag))
                captured_packets.insert(0, pkt)
                if len(captured_packets) > 2000:
                    captured_packets.pop()

        def process_packet_queue():
            try:
                while True:
                    src, dst, proto_name, info, threat, confidential_flag = pkt_queue.get_nowait()
                    values = (time.strftime('%H:%M:%S'), src, dst, proto_name, info, threat, confidential_flag)
                    
                    # Determine tag based on content
                    if confidential_flag:
                        tag = 'confidential'
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
    
    # Check admin rights
    if not is_admin():
        print(f"{Fore.YELLOW}[!] Running without administrator privileges.")
        print(f"    Some features may be limited (packet capture, firewall rules).{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Running with administrator privileges.{Style.RESET_ALL}")
    
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

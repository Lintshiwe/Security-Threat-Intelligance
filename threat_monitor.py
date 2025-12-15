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
    root.geometry("950x550")
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
    pkt_columns = ("Time", "Source", "Destination", "Protocol", "Info", "Threat")
    pkt_tree = ttk.Treeview(packet_frame, columns=pkt_columns, show="headings", height=15)
    for col in pkt_columns:
        pkt_tree.heading(col, text=col)
        pkt_tree.column(col, width=120 if col!="Info" else 220)
    pkt_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    if not SCAPY_AVAILABLE:
        pkt_tree.insert("", 0, values=("-", "-", "-", "-", "Install scapy for packet capture", "-"))

    # Human-readable packet details popup
    def show_packet_details(event):
        item = pkt_tree.identify_row(event.y)
        if not item:
            return
        values = pkt_tree.item(item)['values']
        details = f"Time: {values[0]}\nSource: {values[1]}\nDestination: {values[2]}\nProtocol: {values[3]}\nInfo: {values[4]}\nThreat: {values[5]}"
        try:
            idx = pkt_tree.index(item)
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                from scapy.all import hexdump
                details += "\n\nRaw Packet (hex):\n" + hexdump(pkt, dump=True)
                if pkt.haslayer('TCP'):
                    details += f"\nTCP Flags: {pkt['TCP'].flags} Seq: {pkt['TCP'].seq} Ack: {pkt['TCP'].ack}"
                if pkt.haslayer('UDP'):
                    details += f"\nUDP Len: {pkt['UDP'].len}"
                if pkt.haslayer('Raw'):
                    raw = pkt['Raw'].load
                    try:
                        details += f"\nPayload: {raw.decode(errors='replace')}"
                    except Exception:
                        details += f"\nPayload: {raw}"
        except Exception:
            pass
        messagebox.showinfo("Packet Details", details)

    pkt_tree.bind("<Double-1>", show_packet_details)


    # --- Network Map Tab ---
    map_frame = ttk.Frame(notebook)
    notebook.add(map_frame, text='🗺️ Network Map')
    map_label = ttk.Label(map_frame, text="Discover router and connected devices on your network.", font=("Segoe UI", 10))
    map_label.pack(pady=5)
    analytics_var = tk.StringVar(value="")
    analytics_label = ttk.Label(map_frame, textvariable=analytics_var, font=("Segoe UI", 10, "italic"), foreground="#444")
    analytics_label.pack(pady=2)
    map_columns = ("IP", "MAC", "Name", "Vendor", "Type", "Last Seen")
    map_tree = ttk.Treeview(map_frame, columns=map_columns, show="headings", height=15)
    for col in map_columns:
        map_tree.heading(col, text=col)
        map_tree.column(col, width=140 if col!="Name" else 180)
    map_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    # Always enable the button, check for modules at click time
    map_btn = ttk.Button(map_frame, text="🔍 Scan Network", state=tk.NORMAL)
    map_btn.pack(pady=5)
    
    if check_network_dependencies():
        map_tree.insert("", 0, values=("-", "-", "-", "-", "-", "Install netifaces & scapy for network map"))

    # --- Controls ---
    control_frame = ttk.Frame(root)
    control_frame.pack(fill=tk.X, padx=5, pady=2)
    pause_var = tk.BooleanVar(value=False)
    def toggle_pause():
        pause_var.set(not pause_var.get())
        if pause_var.get():
            status_var.set("Status: Monitoring Paused")
        else:
            status_var.set("Status: Monitoring (Running in Background)")

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
        def packet_callback(pkt):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
                info = ""
                threat = ""
                if TCP in pkt:
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    info = f"TCP {sport}->{dport}"
                    if dport in [23, 2323, 4444, 3389]:
                        threat = "Suspicious Port"
                elif UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    info = f"UDP {sport}->{dport}"
                else:
                    info = proto_name
                pkt_queue.put((src, dst, proto_name, info, threat))
                captured_packets.insert(0, pkt)
                if len(captured_packets) > 2000:
                    captured_packets.pop()

        def process_packet_queue():
            try:
                while True:
                    src, dst, proto_name, info, threat = pkt_queue.get_nowait()
                    values = (time.strftime('%H:%M:%S'), src, dst, proto_name, info, threat)
                    pkt_tree.insert("", 0, values=values)
                    if threat:
                        pkt_tree.item(pkt_tree.get_children()[0], tags=('threat',))
                        pkt_tree.tag_configure('threat', background='#ffcccc')
            except queue.Empty:
                pass
            root.after(200, process_packet_queue)

        def start_sniffing():
            sniff(prn=packet_callback, store=0)

        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        root.after(200, process_packet_queue)

    # --- Network Map Logic ---
    def scan_network():
        map_tree.delete(*map_tree.get_children())
        analytics_var.set("")
        missing = check_network_dependencies()
        if missing:
            map_tree.insert("", 0, values=('-', '-', '-', '-', '-', f"Install {' & '.join(missing)} for network map"))
            return
        router_ip, devices = get_router_and_devices()
        device_count = 0
        type_counts = {}
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if router_ip:
            map_tree.insert("", "end", values=(router_ip, '', 'Router', 'N/A', 'Router', now))
            device_last_seen[router_ip] = now
            type_counts['Router'] = 1
            device_count += 1
        for dev in devices:
            if dev['ip'] != router_ip:
                mac = dev['mac']
                name = dev['name']
                vendor = lookup_vendor(mac)
                dtype = guess_device_type(name, vendor)
                last_seen = now
                device_last_seen[dev['ip']] = last_seen
                map_tree.insert("", "end", values=(dev['ip'], mac, name, vendor, dtype, last_seen))
                type_counts[dtype] = type_counts.get(dtype, 0) + 1
                device_count += 1
        if not device_count:
            messagebox.showinfo("Scan", "No devices found or admin rights required.")
        else:
            analytics = f"Devices: {device_count} | " + ", ".join(f"{k}: {v}" for k,v in type_counts.items())
            analytics_var.set(analytics)

    map_btn.config(command=scan_network)

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

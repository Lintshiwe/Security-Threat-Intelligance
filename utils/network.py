"""
Network utilities for device discovery and analysis.
"""

import logging
import socket
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass

import requests

logger = logging.getLogger('SecurityMonitor.Network')

# Check for optional dependencies
_scapy_available = False
_netifaces_available = False

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    _scapy_available = True
except ImportError:
    logger.info("scapy not available - packet capture disabled")

try:
    import netifaces  # type: ignore
    _netifaces_available = True
except ImportError:
    logger.info("netifaces not available - network discovery disabled")

# Export as module-level constants
SCAPY_AVAILABLE: bool = _scapy_available
NETIFACES_AVAILABLE: bool = _netifaces_available


@dataclass
class NetworkDevice:
    """Represents a discovered network device."""
    ip: str
    mac: str
    name: str
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'name': self.name,
            'vendor': self.vendor,
            'device_type': self.device_type
        }


def get_router_and_devices() -> Tuple[Optional[str], List[NetworkDevice]]:
    """
    Discover router IP and connected network devices using ARP scan.
    
    Returns:
        Tuple of (router_ip, list of NetworkDevice objects)
    """
    if not (NETIFACES_AVAILABLE and SCAPY_AVAILABLE):
        logger.warning("Network discovery requires netifaces and scapy packages")
        return None, []
    
    try:
        # Get default gateway
        gateways = netifaces.gateways()
        router_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
        
        if not router_ip:
            logger.warning("Could not determine default gateway")
            return None, []
        
        devices = []
        ip_range = router_ip.rsplit('.', 1)[0] + '.1/24'
        
        try:
            # ARP scan the subnet
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),
                timeout=2,
                verbose=0
            )
            
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                
                # Try to resolve hostname
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    name = ip
                
                device = NetworkDevice(ip=ip, mac=mac, name=name)
                device.vendor = lookup_vendor(mac)
                device.device_type = guess_device_type(name, device.vendor)
                devices.append(device)
                
        except PermissionError:
            logger.error("Network scan requires administrator privileges")
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            
        return router_ip, devices
        
    except Exception as e:
        logger.error(f"Network discovery failed: {e}")
        return None, []


def lookup_vendor(mac: str) -> str:
    """
    Look up MAC address vendor using online API.
    
    Args:
        mac: MAC address string
        
    Returns:
        Vendor name or "Unknown"
    """
    try:
        response = requests.get(
            f'https://api.macvendors.com/{mac}',
            timeout=2
        )
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return "Unknown"


def guess_device_type(name: str, vendor: str) -> str:
    """
    Guess device type based on hostname and vendor.
    
    Args:
        name: Device hostname
        vendor: Device vendor name
        
    Returns:
        Guessed device type
    """
    name_lower = name.lower()
    vendor_lower = vendor.lower()
    
    # Check for routers/gateways
    if any(x in name_lower for x in ["router", "gateway", "modem"]):
        return "Router"
    
    # Check for PCs/NICs
    pc_vendors = ["intel", "realtek", "broadcom", "atheros", "microsoft", "dell", "hp", "lenovo"]
    if any(x in vendor_lower for x in pc_vendors):
        return "PC/Workstation"
    
    # Check for mobile devices
    mobile_vendors = ["apple", "samsung", "android", "huawei", "xiaomi", "oneplus", "oppo"]
    if any(x in vendor_lower for x in mobile_vendors):
        return "Mobile Device"
    
    # Check for printers
    printer_vendors = ["printer", "hp inc", "canon", "epson", "brother", "lexmark"]
    if any(x in vendor_lower for x in printer_vendors):
        return "Printer"
    
    # Check for cameras/IoT
    camera_vendors = ["camera", "hikvision", "dahua", "axis", "nest", "ring"]
    if any(x in vendor_lower for x in camera_vendors):
        return "Camera/IoT"
    
    # Check for smart home devices
    smart_vendors = ["amazon", "google", "sonos", "philips", "tp-link", "netgear"]
    if any(x in vendor_lower for x in smart_vendors):
        return "Smart Device"
    
    return "Unknown"


def check_network_dependencies() -> List[str]:
    """
    Check which network dependencies are missing.
    
    Returns:
        List of missing package names
    """
    missing = []
    if not SCAPY_AVAILABLE:
        missing.append('scapy')
    if not NETIFACES_AVAILABLE:
        missing.append('netifaces')
    return missing

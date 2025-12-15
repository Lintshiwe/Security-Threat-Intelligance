"""
Administrative utilities for Windows system operations.
"""

import ctypes
import logging
import subprocess
import sys
from typing import Optional

logger = logging.getLogger('SecurityMonitor.Admin')


def is_admin() -> bool:
    """
    Check if the current process has administrator privileges.
    
    Returns:
        True if running as administrator, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def request_admin_elevation() -> bool:
    """
    Request UAC elevation and restart the application with admin rights.
    
    Returns:
        True if elevation was requested (process will exit), False on error
    """
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1  # SW_SHOWNORMAL
        )
        return True
    except Exception as e:
        logger.error(f"Failed to request elevation: {e}")
        return False


def add_firewall_rule(
    name: str,
    direction: str = "out",
    remote_ip: Optional[str] = None,
    program: Optional[str] = None,
    action: str = "block"
) -> bool:
    """
    Add a Windows Firewall rule using netsh.
    
    Args:
        name: Rule name
        direction: "in" or "out"
        remote_ip: Remote IP to block (optional)
        program: Program path to restrict (optional)
        action: "block" or "allow"
    
    Returns:
        True if rule was created successfully
    """
    if not is_admin():
        logger.error("Firewall modification requires administrator privileges")
        return False
    
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        f"dir={direction}",
        f"action={action}"
    ]
    
    if remote_ip:
        cmd.append(f"remoteip={remote_ip}")
    if program:
        cmd.append(f"program={program}")
    
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"Firewall rule '{name}' created successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create firewall rule: {e.stderr}")
        return False


def remove_firewall_rule(name: str) -> bool:
    """
    Remove a Windows Firewall rule by name.
    
    Args:
        name: Rule name to remove
    
    Returns:
        True if rule was removed successfully
    """
    if not is_admin():
        logger.error("Firewall modification requires administrator privileges")
        return False
    
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name}"
    ]
    
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"Firewall rule '{name}' removed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to remove firewall rule: {e.stderr}")
        return False


def block_ip_for_process(pid: int, ip: str, process_name: str, exe_path: Optional[str] = None) -> bool:
    """
    Block network traffic to a specific IP for a process.
    
    Args:
        pid: Process ID
        ip: IP address to block
        process_name: Process name for rule naming
        exe_path: Path to executable (optional, for program-specific rules)
    
    Returns:
        True if blocking was successful
    """
    rule_name = f"Block_{process_name}_{pid}_{ip}"
    return add_firewall_rule(
        name=rule_name,
        direction="out",
        remote_ip=ip,
        program=exe_path,
        action="block"
    )


def quarantine_ip_for_process(pid: int, ip: str, process_name: str, exe_path: Optional[str] = None) -> bool:
    """
    Quarantine (block both in and out) traffic to an IP for a process.
    
    Args:
        pid: Process ID
        ip: IP address to quarantine
        process_name: Process name for rule naming
        exe_path: Path to executable (optional)
    
    Returns:
        True if quarantine was successful
    """
    rule_name_base = f"Quarantine_{process_name}_{pid}_{ip}"
    
    success_out = add_firewall_rule(
        name=rule_name_base,
        direction="out",
        remote_ip=ip,
        program=exe_path,
        action="block"
    )
    
    success_in = add_firewall_rule(
        name=f"{rule_name_base}_in",
        direction="in",
        remote_ip=ip,
        program=exe_path,
        action="block"
    )
    
    return success_out and success_in

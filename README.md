# Windows Security Threat Intelligence Monitor

A production-ready Windows security monitoring application that provides real-time process and network threat detection, analysis, and response capabilities.

## Features

### Core Monitoring

- **Real-time Process Monitoring**: Continuously scans running processes for suspicious behavior
- **Network Activity Tracking**: Monitors active connections and identifies suspicious traffic
- **Packet Capture**: Deep packet inspection for advanced threat detection (requires scapy)
- **Network Device Discovery**: ARP-based network mapping to identify connected devices

### Threat Detection

- **Risk Assessment Engine**: Multi-factor risk scoring based on:
  - Process location and execution path
  - Network connections to suspicious IPs
  - Resource usage anomalies (CPU/Memory)
  - Known high-risk process patterns
- **VirusTotal Integration**: Real-time file hash and IP reputation checking
- **Customizable Threat Database**: JSON-based indicator definitions

### Response Capabilities

- **Process Termination**: Terminate suspicious processes
- **Network Blocking**: Create Windows Firewall rules to block malicious connections
- **Quarantine Mode**: Full network isolation for compromised processes
- **Threat Export**: Export detected threats to CSV for analysis

### Production Features

- **Secure Configuration**: Environment variable-based secrets management
- **Rotating Log Files**: Automatic log rotation to prevent disk exhaustion
- **Graceful Error Handling**: Robust exception handling throughout
- **Configurable Thresholds**: Adjustable risk scoring and monitoring intervals

## Requirements

- **OS**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.8 or higher
- **Privileges**: Administrator recommended for full functionality

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Lintshiwe/Security-Threat-Intelligance.git
cd Security-Threat-Intelligance
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
# Copy the example environment file
copy .env.example .env

# Edit .env and add your VirusTotal API key
# Get your free API key at: https://www.virustotal.com/gui/join-us
```

## Configuration

All configuration is managed through environment variables or the `.env` file:

| Variable                    | Default              | Description                                        |
| --------------------------- | -------------------- | -------------------------------------------------- |
| `VIRUSTOTAL_API_KEY`        | -                    | Your VirusTotal API key (required for VT features) |
| `LOG_LEVEL`                 | INFO                 | Logging level (DEBUG, INFO, WARNING, ERROR)        |
| `LOG_FILE`                  | security_threats.log | Log file name                                      |
| `LOG_MAX_SIZE_MB`           | 10                   | Max log file size before rotation                  |
| `LOG_BACKUP_COUNT`          | 5                    | Number of backup log files to keep                 |
| `SCAN_INTERVAL_SECONDS`     | 1                    | Process scanning interval                          |
| `RISK_THRESHOLD_WARNING`    | 3                    | Minimum risk score for warnings                    |
| `RISK_THRESHOLD_CRITICAL`   | 5                    | Minimum risk score for critical alerts             |
| `PROCESS_CACHE_TTL_SECONDS` | 60                   | Cache duration for analyzed processes              |
| `ENABLE_PACKET_CAPTURE`     | true                 | Enable/disable packet capture                      |
| `PACKET_BUFFER_SIZE`        | 2000                 | Number of packets to buffer                        |

## Usage

### GUI Mode (Recommended)

```bash
python threat_monitor.py
```

### With Administrator Privileges

```bash
# Right-click Command Prompt -> Run as Administrator
python threat_monitor.py
```

## Threat Database

Customize threat indicators in `threat_database.json`:

```json
{
  "suspicious_paths": ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"],
  "suspicious_connections": ["0.0.0.0", "127.0.0.1"],
  "high_risk_processes": ["cmd.exe", "powershell.exe", "wscript.exe"]
}
```

## Logging

- Logs are written to `security_threats.log` with automatic rotation
- Log files rotate when they reach the configured size (default: 10MB)
- Previous logs are kept as `.log.1`, `.log.2`, etc.

## Security Best Practices

1. **Never commit `.env` file** - Contains API keys
2. **Run as Administrator** - Required for process termination and firewall rules
3. **Keep threat database updated** - Regularly update indicators
4. **Review logs regularly** - Monitor for patterns and false positives
5. **Use in conjunction with other security tools** - This is a supplementary tool

## Project Structure

```text
threat_monitor.py      # Main application with GUI
config.py              # Configuration management
threat_database.json   # Threat indicators
.env                   # Environment variables (not committed)
.env.example           # Environment template
requirements.txt       # Python dependencies
utils/                 # Utility modules
  ├── __init__.py
  ├── logging_config.py
  ├── virustotal.py
  ├── network.py
  └── admin.py
```

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security monitoring purposes only. Use responsibly and in compliance with applicable laws and regulations. This should not be used as the sole security solution for any environment.

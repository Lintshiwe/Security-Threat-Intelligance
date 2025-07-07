# Windows Security Threat Intelligence Monitor

This application monitors Windows systems for potential security threats by analyzing running processes, their behavior, and characteristics. It helps identify and optionally terminate suspicious processes that might pose security risks.

## Features

- Real-time process monitoring
- Risk assessment based on multiple factors:
  - Process location and path
  - Network connections
  - Resource usage (CPU, Memory)
  - Known high-risk processes
- Logging of security events
- Interactive process termination for high-risk threats
- Customizable threat database
- Colored console output for better visibility

## Requirements

- Python 3.6+
- Windows OS
- Required packages:
  - psutil
  - wmi
  - pywin32
  - requests
  - colorama
  - pandas

## Installation

1. Clone or download this repository
2. Install required packages:

```bash
pip install psutil wmi pywin32 requests colorama pandas
```

## Usage

Run the monitor with:

```bash
python threat_monitor.py
```

The application will start monitoring your system and display:

- Warnings for suspicious processes (risk score ≥ 3)
- Alerts for high-risk processes (risk score ≥ 5)
- Prompts to terminate high-risk processes

## Customization

You can modify the `threat_database.json` file to customize:

- Suspicious paths
- Suspicious network connections
- High-risk process names

## Logs

Security events are logged to `security_threats.log` in the application directory.

## Note

This tool requires administrative privileges to access certain process information and perform process termination.

## Disclaimer

This is a basic security monitoring tool and should not be used as the sole security solution. It's recommended to use this alongside other security measures and professional security software.

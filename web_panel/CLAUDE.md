# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Running the HTTP Server
```bash
# Development (default: admin/admin credentials)
python3 server.py

# Production with custom credentials
ADMIN_USER=admin ADMIN_PASS='supersecret' SECRET_KEY='your-secret-key' python3 server.py

# Custom host/port
python3 server.py --host 0.0.0.0 --port 8080
# OR
HOST=192.168.1.100 PORT=8080 python3 server.py
```

### Testing
```bash
# Run all tests
python3 -m pytest tests/

# Run specific test
python3 -m pytest tests/test_server.py::test_http_time_endpoint -v
```

### Logging Configuration
Set environment variables to control logging:
```bash
LOG_LEVEL=DEBUG python3 server.py           # DEBUG/INFO/WARNING/ERROR
LOG_DIR=/var/log/timeserver python3 server.py    # Log to rotating files
LOG_FILE=/path/to/specific.log python3 server.py # Custom log file
```

### GPS/NTP Setup on Raspberry Pi
```bash
# Quick setup (from raspi-ntp/ directory)
sudo ./setup.sh

# Custom GPS device
DEVICE=/dev/ttyUSB0 sudo ./setup.sh

# Without PPS support
USE_PPS=0 sudo ./setup.sh

# Health check
sudo ./healthcheck.sh
```

### Deployment Commands
```bash
# Install on Armbian/Debian system
sudo apt-get install -y git python3-venv python3-pip nftables gpsd gpsd-clients chrony
git clone <repo> /opt/offline_timeserver
sudo install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/offline_timeserver.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now offline_timeserver
```

## Architecture Overview

This is an offline time server system designed for isolated networks, consisting of two main components:

### 1. Python HTTP Server (`server.py`)
- **Purpose**: Web-based admin panel and time API for network clients
- **Key Features**:
  - RESTful time API (`/time` endpoint) returning UTC time in multiple formats
  - Session-based authentication using HMAC-signed cookies
  - Real-time status monitoring of GPS, NTP, and network components
  - Wi-Fi configuration via NetworkManager integration
  - Structured logging with rotating file support

- **Core Modules**:
  - `TimeHandler`: HTTP request handler with auth middleware
  - Status collectors: `get_gps_status()`, `get_ntp_status()`, `get_network_status()`
  - Security: HMAC cookie signing, session management
  - System integration: `nmcli` wrapper for network config, `chronyc`/`gpspipe` system calls

### 2. NTP Server Infrastructure
- **GPS Time Source**: Configured via `gpsd` reading NMEA data from USB GPS modules
- **Time Synchronization**: `chrony` daemon serves as NTP server for LAN clients
- **PPS Support**: Optional high-precision timing via GPIO PPS signals
- **Local Stratum**: Falls back to local system clock when GPS unavailable

### Key Architectural Patterns

**Offline-First Design**: System operates without internet connectivity, using GPS as primary time source and local fallbacks.

**Security Model**: 
- Admin panel protected by session cookies with HMAC signatures
- Environment-based credential configuration
- No sensitive data logging (PSK masking in Wi-Fi operations)

**System Integration**:
- Uses `subprocess.run()` with `shlex.split()` for safe command execution
- Integrates with systemd services for GPS/NTP coordination
- NetworkManager integration for runtime network configuration

**Multi-Platform Support**:
- Primary: Raspberry Pi/Armbian deployment
- Development: Pure Python HTTP server for testing
- Hardware abstraction for different GPS interfaces (`/dev/ttyACM0`, `/dev/ttyUSB0`, UART)

### Deployment Models

1. **Development**: Single Python process for web panel testing
2. **Production**: Systemd service with GPS+NTP integration
3. **Offline LAN**: Complete time server serving NTP to network clients

The system bridges hardware time sources (GPS) with network time protocols (NTP) through a unified web-based management interface.
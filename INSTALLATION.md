# Installation Guide - Network Packet Analyzer

This guide covers installation for Linux, macOS, and Windows.

## Table of Contents

1. [Linux Installation](#linux-installation)
2. [Windows Installation](#windows-installation)
3. [macOS Installation](#macos-installation)
4. [Pip Installation](#pip-installation)
5. [Docker Installation](#docker-installation)
6. [Troubleshooting](#troubleshooting)

---

## Linux Installation

### Ubuntu / Debian

**Quick Install:**

```bash
# Clone the repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Run installation script
chmod +x install.sh
sudo ./install.sh

# Run the sniffer
sudo python3 network_sniffer.py
```

**Manual Installation:**

```bash
# Update package manager
sudo apt-get update
sudo apt-get upgrade

# Install Python 3 (if not installed)
sudo apt-get install -y python3 python3-pip

# Install raw socket access tools (optional)
sudo apt-get install -y libpcap-dev

# Navigate to project directory
cd network-packet-analyzer

# Run the sniffer with sudo
sudo python3 network_sniffer.py
```

### Fedora / RHEL / CentOS

```bash
# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Install Python 3
sudo dnf install -y python3 python3-pip

# Install packet capture tools (optional)
sudo dnf install -y libpcap-devel

# Run the sniffer
sudo python3 network_sniffer.py
```

### Arch Linux

```bash
# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Install Python 3
sudo pacman -S python python-pip

# Install packet capture tools (optional)
sudo pacman -S libpcap

# Run the sniffer
sudo python3 network_sniffer.py
```

---

## Windows Installation

### Prerequisites

1. **Python 3.8 or higher**
   - Download from: https://www.python.org/downloads/
   - During installation, **CHECK** "Add Python to PATH"
   - Click "Disable path length limit"

2. **Npcap (for packet capturing)**
   - Download from: https://npcap.org/
   - Run the installer with Administrator privileges

### Installation Steps

**Method 1: Automated Installation**

```batch
# Right-click install.bat and select "Run as Administrator"
# Or run Command Prompt as Administrator and execute:
install.bat
```

**Method 2: Manual Installation**

```batch
# Open Command Prompt as Administrator

# Clone the repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Run Python (verify it's installed)
python --version

# Run the sniffer
python network_sniffer.py
```

### Windows-Specific Notes

- **Administrator Required**: Raw socket access requires Administrator privileges
- **Npcap Installation**: Some features need Npcap for packet capture
- **Path Setting**: Ensure Python is in your system PATH
  - Open: Settings → System → Environment Variables
  - Click "Edit the environment variables for your account"
  - Ensure Python path is listed (usually `C:\Users\YourName\AppData\Local\Programs\Python\Python39`)

---

## macOS Installation

### Using Homebrew (Recommended)

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Run the sniffer (may require sudo)
sudo python3 network_sniffer.py
```

### Using MacPorts

```bash
# Install MacPorts from: https://www.macports.org/install.php

# Install Python 3
sudo port install python39

# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Run the sniffer
sudo python3 network_sniffer.py
```

### Manual Installation

```bash
# Download Python 3 from https://www.python.org/downloads/
# Run the installer

# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Run the sniffer
sudo python3 network_sniffer.py
```

---

## Pip Installation

Install as a Python package:

```bash
# Clone the repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Install in development mode
pip install -e .

# Or install from PyPI (when published)
pip install network-packet-analyzer

# Run from anywhere
network-analyzer
```

---

## Docker Installation

### Docker Setup

**Build Docker Image:**

```bash
# Clone repository
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer

# Build image
docker build -t network-analyzer .

# Run container
docker run --net=host -it network-analyzer
```

**Docker Compose:**

```bash
# Run with compose
docker-compose up
```

---

## Usage After Installation

### Basic Usage

```bash
# Start sniffer (capture until Ctrl+C)
sudo python3 network_sniffer.py

# Capture specific number of packets
sudo python3 network_sniffer.py 100

# Save packets to file
sudo python3 network_sniffer.py 50 -o packets.json
```

### Web Dashboard

```bash
# Open in your browser:
open network_sniffer_dashboard.html

# Or on Windows:
start network_sniffer_dashboard.html

# Or manually navigate to the file in your browser
```

### Advanced Options

```bash
# Show all available options
python3 network_sniffer.py --help

# Capture from specific interface
sudo python3 network_sniffer.py -i eth0

# Verbose output
sudo python3 network_sniffer.py -v

# Combine options
sudo python3 network_sniffer.py 1000 -i eth0 -o capture.json -v
```

---

## Troubleshooting

### Linux/macOS

**Permission Denied Error:**
```bash
# Error: Permission denied
# Solution: Use sudo
sudo python3 network_sniffer.py
```

**Port Already in Use:**
```bash
# Check what's using the port
lsof -i :8000
# Kill the process
kill -9 <PID>
```

**Raw Socket Error:**
```bash
# Error: PermissionError: [Errno 13] Permission denied
# Solution: Run with sudo
sudo python3 network_sniffer.py
```

### Windows

**Python Not Found:**
```batch
# Add Python to PATH manually
setx PATH "%PATH%;C:\Users\YourName\AppData\Local\Programs\Python\Python39"

# Restart Command Prompt and try again
```

**Npcap Not Installed:**
```
Error: WinPcap/Npcap not found
Solution: Download and install from https://npcap.org/
```

**Administrator Required:**
```batch
# Right-click Command Prompt and select "Run as Administrator"
# Then run the sniffer
python network_sniffer.py
```

### macOS

**Address Already in Use:**
```bash
# Find process using port
lsof -i :8000
# Kill the process
kill -9 <PID>
```

**Python Command Not Found:**
```bash
# Use python3 instead of python
python3 network_sniffer.py

# Or create alias
alias python=python3
```

---

## System Requirements

### Minimum Requirements
- **Python**: 3.6 or higher
- **RAM**: 256MB
- **Disk Space**: 50MB
- **Permissions**: Root/Administrator

### Recommended Requirements
- **Python**: 3.8 or higher
- **RAM**: 512MB or more
- **Disk Space**: 100MB
- **Network**: Gigabit Ethernet

### Supported Operating Systems
- Ubuntu 18.04+
- Debian 10+
- Fedora 30+
- CentOS 7+
- Windows 7+
- macOS 10.7+

---

## Uninstallation

### Linux/macOS

```bash
# Remove source directory
rm -rf network-packet-analyzer/

# If installed via pip
pip uninstall network-packet-analyzer
```

### Windows

```batch
# Delete the directory
rmdir /s network-packet-analyzer

# If installed via pip
pip uninstall network-packet-analyzer
```

---

## Getting Help

- **Documentation**: See README.md
- **Issues**: Report on GitHub
- **Examples**: Check EXAMPLES_AND_TESTS.md
- **Design**: See UI_DESIGN_GUIDE.md

---

## Next Steps

1. ✅ Installation complete
2. Read the [README.md](README.md)
3. Try the [examples](EXAMPLES_AND_TESTS.md)
4. Open the [web dashboard](network_sniffer_dashboard.html)
5. Explore the [technical guide](NETWORK_SNIFFER_GUIDE.md)

Happy analyzing! 🔍

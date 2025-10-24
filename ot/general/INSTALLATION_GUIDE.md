# OT Cybersecurity Scripts - Installation Guide

## 🚨 CRITICAL SAFETY WARNING

**THESE SCRIPTS ARE DESIGNED FOR OT ENVIRONMENTS AND MUST BE USED WITH EXTREME CAUTION**

- **NEVER** run these scripts on production OT systems without proper authorization
- **ALWAYS** test in isolated environments first
- **ALWAYS** have a rollback plan
- **ALWAYS** coordinate with operations teams

## 📋 Quick Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Administrator/root privileges (for network operations)

### 1. Download Scripts
```bash
# Clone repository or download files
git clone <repository-url>
cd ot/general
```

### 2. Install Dependencies
```bash
# Install required packages
pip install -r requirements.txt

# Install optional packages (recommended)
pip install scapy scikit-learn numpy
```

### 3. Run Scripts
```bash
# Linux/Mac
./run_ot_scripts.sh

# Windows
run_ot_scripts.bat
```

## 🖥️ Platform-Specific Installation

### Windows Installation

#### Method 1: Automated Installation
1. **Download Python** from [python.org](https://python.org)
2. **Run the batch file**:
   ```cmd
   run_ot_scripts.bat
   ```
3. **Follow the prompts** for automatic setup

#### Method 2: Manual Installation
1. **Install Python 3.7+**:
   - Download from [python.org](https://python.org)
   - Check "Add Python to PATH" during installation

2. **Install Git** (optional):
   - Download from [git-scm.com](https://git-scm.com)

3. **Open Command Prompt as Administrator**:
   ```cmd
   cd C:\path\to\ot\general
   pip install -r requirements.txt
   pip install scapy scikit-learn numpy
   ```

4. **Run scripts**:
   ```cmd
   python asset_enumeration.py 192.168.1.0/24 --safe-mode --report
   ```

### Linux Installation

#### Ubuntu/Debian
```bash
# Update package manager
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Create virtual environment (recommended)
python3 -m venv ot-env
source ot-env/bin/activate

# Install packages
pip install -r requirements.txt
pip install scapy scikit-learn numpy

# Run scripts
./run_ot_scripts.sh
```

#### CentOS/RHEL
```bash
# Update package manager
sudo yum update

# Install Python and pip
sudo yum install python3 python3-pip

# Install packages
pip3 install -r requirements.txt
pip3 install scapy scikit-learn numpy

# Run scripts
./run_ot_scripts.sh
```

#### Arch Linux
```bash
# Install Python and pip
sudo pacman -S python python-pip

# Install packages
pip install -r requirements.txt
pip install scapy scikit-learn numpy

# Run scripts
./run_ot_scripts.sh
```

### macOS Installation

#### Method 1: Using Homebrew
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3

# Install packages
pip3 install -r requirements.txt
pip3 install scapy scikit-learn numpy

# Run scripts
./run_ot_scripts.sh
```

#### Method 2: Using MacPorts
```bash
# Install MacPorts (if not already installed)
# Download from https://www.macports.org/

# Install Python
sudo port install python39

# Install packages
pip3 install -r requirements.txt
pip3 install scapy scikit-learn numpy

# Run scripts
./run_ot_scripts.sh
```

## 🔧 Advanced Configuration

### Virtual Environment Setup
```bash
# Create virtual environment
python3 -m venv ot-env

# Activate virtual environment
# Linux/Mac:
source ot-env/bin/activate
# Windows:
ot-env\Scripts\activate

# Install packages
pip install -r requirements.txt

# Deactivate when done
deactivate
```

### Docker Installation
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "asset_enumeration.py", "--help"]
```

```bash
# Build and run
docker build -t ot-scripts .
docker run -it ot-scripts
```

### Configuration Files
Create `config.json`:
```json
{
  "scan_timeout": 3,
  "max_threads": 20,
  "safe_mode": true,
  "ml_enabled": true,
  "alert_threshold": 5,
  "correlation_window": 300,
  "monitor_sources": [
    {
      "type": "syslog",
      "port": 514
    },
    {
      "type": "file",
      "path": "/var/log/firewall.log"
    }
  ]
}
```

## 🚀 Quick Start Examples

### 1. Asset Discovery
```bash
# Basic asset discovery
python asset_enumeration.py 192.168.1.0/24 --safe-mode --report

# Custom timeout and threads
python asset_enumeration.py 192.168.1.0/24 --timeout 5 --threads 10 --safe-mode
```

### 2. Network Segmentation Validation
```bash
# Basic validation
python network_segmentation.py --report

# With custom segments
python network_segmentation.py --segments segments.json --report
```

### 3. Anomaly Detection
```bash
# Real-time monitoring
python anomaly_detection.py --interface eth0 --ml-enabled --report

# Analyze PCAP file
python anomaly_detection.py --pcap traffic.pcap --report
```

### 4. Security Event Monitoring
```bash
# Syslog monitoring
python security_monitoring.py --syslog-port 514 --report

# File monitoring
python security_monitoring.py --monitor-file /var/log/firewall.log --report
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Linux: Run with sudo for network operations
sudo python3 asset_enumeration.py 192.168.1.0/24

# Windows: Run as Administrator
# Right-click Command Prompt -> "Run as administrator"
```

#### 2. Python Not Found
```bash
# Check Python installation
python3 --version

# Install Python if missing
# Ubuntu/Debian:
sudo apt install python3 python3-pip

# CentOS/RHEL:
sudo yum install python3 python3-pip
```

#### 3. Package Installation Failed
```bash
# Update pip
pip install --upgrade pip

# Install packages individually
pip install requests numpy scapy scikit-learn

# Use virtual environment
python3 -m venv ot-env
source ot-env/bin/activate
pip install -r requirements.txt
```

#### 4. Scapy Not Available
```bash
# Install Scapy
pip install scapy

# Or use without advanced features
python script.py --no-scapy
```

#### 5. Network Interface Issues
```bash
# List available interfaces
python3 -c "import scapy.all; print(scapy.get_if_list())"

# Use specific interface
python anomaly_detection.py --interface eth0
```

#### 6. Memory Issues
```bash
# Reduce thread count
python script.py --threads 10

# Use safe mode
python script.py --safe-mode
```

### Debug Mode
```bash
# Enable verbose logging
python script.py --verbose

# Debug specific issues
python script.py --debug --log-level DEBUG
```

## 📊 System Requirements

### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 1 GB free space
- **Network**: Ethernet or Wi-Fi adapter
- **OS**: Windows 10, Ubuntu 18.04+, CentOS 7+, macOS 10.14+

### Recommended Requirements
- **CPU**: 4 cores, 3.0 GHz
- **RAM**: 8 GB
- **Storage**: 5 GB free space
- **Network**: Gigabit Ethernet
- **OS**: Windows 11, Ubuntu 20.04+, CentOS 8+, macOS 11+

### Performance Optimization
```bash
# Increase thread count for faster scanning
python asset_enumeration.py 192.168.1.0/24 --threads 50

# Use safe mode for production
python script.py --safe-mode

# Monitor system resources
htop  # Linux
top   # macOS
Task Manager  # Windows
```

## 🔐 Security Considerations

### Access Control
```bash
# Use principle of least privilege
sudo -u ot-user python script.py

# Implement role-based access
chmod 750 ot-scripts/
chown ot-user:ot-group ot-scripts/
```

### Data Protection
```bash
# Encrypt sensitive data
gpg --symmetric --cipher-algo AES256 results.json

# Secure data transmission
scp -P 2222 results.json user@secure-server:/backup/
```

### Network Security
```bash
# Use VPN for remote access
openvpn --config client.ovpn

# Monitor network traffic
tcpdump -i eth0 -w capture.pcap
```

## 📞 Support and Help

### Getting Help
1. **Check the documentation**: [README.md](README.md)
2. **Review safety guidelines**: [SAFETY_GUIDELINES.md](SAFETY_GUIDELINES.md)
3. **Run with verbose output**: `python script.py --verbose`
4. **Check system logs**: `/var/log/syslog` (Linux) or Event Viewer (Windows)

### Reporting Issues
- **GitHub Issues**: [Repository Issues]
- **Email Support**: [Support Email]
- **Emergency Hotline**: [Emergency Contact]

### Community Support
- **Discord**: [Discord Server]
- **Slack**: [Slack Workspace]
- **Forum**: [Community Forum]

## 🔄 Updates and Maintenance

### Regular Updates
```bash
# Update packages
pip install --upgrade -r requirements.txt

# Update scripts
git pull origin main

# Check for security updates
pip audit
```

### Backup and Recovery
```bash
# Backup configuration
cp config.json config.json.backup

# Backup results
tar -czf ot-scripts-backup-$(date +%Y%m%d).tar.gz *.json *.txt

# Restore from backup
tar -xzf ot-scripts-backup-20240101.tar.gz
```

---

**Remember: Safety is everyone's responsibility. When in doubt, stop and ask for guidance.**

**Last Updated**: [Date]
**Version**: 1.0
**Next Review**: [Date]

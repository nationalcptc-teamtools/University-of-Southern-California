# OT Cybersecurity Automation Scripts

A comprehensive collection of cybersecurity automation scripts for Operational Technology (OT) environments, focusing on asset enumeration, network segmentation validation, anomaly detection, and security event monitoring.

## 🚨 CRITICAL SAFETY WARNING

**THESE SCRIPTS ARE DESIGNED FOR OT ENVIRONMENTS AND MUST BE USED WITH EXTREME CAUTION**

- **NEVER** run these scripts on production OT systems without proper authorization
- **ALWAYS** test in isolated environments first
- **ALWAYS** have a rollback plan
- **ALWAYS** coordinate with operations teams

See [SAFETY_GUIDELINES.md](SAFETY_GUIDELINES.md) for detailed safety information.

## 📋 Overview

This collection provides four main cybersecurity automation scripts for OT environments:

1. **Asset Enumeration** - Safe discovery of OT assets and protocols
2. **Network Segmentation** - Validation of network isolation and security
3. **Anomaly Detection** - Real-time detection of unusual patterns and threats
4. **Security Monitoring** - Comprehensive security event collection and analysis

## 🛠️ Features

### Core Capabilities
- **OT Protocol Support**: Modbus, DNP3, EtherNet/IP, S7, IEC 61850, IEC 104, BACnet
- **Safety-First Design**: Conservative timeouts, minimal disruption, safe monitoring
- **Cross-Platform**: Compatible with Linux and Windows systems
- **Real-Time Monitoring**: Live traffic analysis and event detection
- **Machine Learning**: AI-powered anomaly detection (optional)
- **Comprehensive Reporting**: Detailed JSON and text reports

### Safety Features
- Passive monitoring where possible
- Conservative scanning with configurable timeouts
- Safe mode with delays between operations
- Non-intrusive testing techniques
- Graceful error handling
- Minimal system impact

## 📁 Scripts Overview

### 1. Asset Enumeration (`asset_enumeration.py`)

**Purpose**: Safely discover and catalog OT assets, protocols, and services.

**Key Features**:
- Passive network discovery
- OT protocol detection
- Asset fingerprinting
- Vendor identification
- Risk assessment
- Safe scanning with timeouts

**Usage**:
```bash
# Basic enumeration
python asset_enumeration.py 192.168.1.0/24

# Safe mode with custom timeout
python asset_enumeration.py 192.168.1.0/24 --safe-mode --timeout 5

# Generate report
python asset_enumeration.py 192.168.1.0/24 --report --output assets.json
```

### 2. Network Segmentation (`network_segmentation.py`)

**Purpose**: Validate network segmentation and isolation in OT environments.

**Key Features**:
- Network isolation validation
- Firewall rule analysis
- OT/IT boundary detection
- Segmentation compliance checking
- Safe testing with minimal impact

**Usage**:
```bash
# Basic validation
python network_segmentation.py

# With custom segments
python network_segmentation.py --segments segments.json

# With firewall rules
python network_segmentation.py --firewall-rules firewall.json --report
```

### 3. Anomaly Detection (`anomaly_detection.py`)

**Purpose**: Detect unusual patterns and potential threats in OT traffic.

**Key Features**:
- Real-time traffic analysis
- Protocol-specific anomaly detection
- Machine learning-based detection (optional)
- OT-specific threat detection
- Safe monitoring with minimal impact

**Usage**:
```bash
# Real-time monitoring
python anomaly_detection.py --interface eth0

# Analyze PCAP file
python anomaly_detection.py --pcap traffic.pcap

# With ML detection
python anomaly_detection.py --interface eth0 --ml-enabled --report
```

### 4. Security Monitoring (`security_monitoring.py`)

**Purpose**: Comprehensive security event collection and analysis.

**Key Features**:
- Multi-source event collection
- Real-time event correlation
- OT-specific threat detection
- Automated alerting and notifications
- Compliance reporting

**Usage**:
```bash
# Syslog monitoring
python security_monitoring.py --syslog-port 514

# File monitoring
python security_monitoring.py --monitor-file /var/log/firewall.log

# With configuration
python security_monitoring.py --config monitoring_config.json --report
```

## 🔧 Installation

### Prerequisites

**Required**:
- Python 3.7 or higher
- pip package manager

**Optional** (for enhanced features):
- Scapy (for advanced network analysis)
- Scikit-learn (for machine learning)
- NumPy (for numerical operations)

### Installation Steps

1. **Clone or download the scripts**:
   ```bash
   git clone <repository-url>
   cd ot/general
   ```

2. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install optional packages** (recommended):
   ```bash
   pip install scapy scikit-learn numpy
   ```

### Windows Installation

1. **Install Python** from [python.org](https://python.org)
2. **Install Git** from [git-scm.com](https://git-scm.com)
3. **Open Command Prompt** as Administrator
4. **Install packages**:
   ```cmd
   pip install -r requirements.txt
   pip install scapy scikit-learn numpy
   ```

### Linux Installation

1. **Update package manager**:
   ```bash
   sudo apt update  # Ubuntu/Debian
   sudo yum update  # CentOS/RHEL
   ```

2. **Install Python and pip**:
   ```bash
   sudo apt install python3 python3-pip  # Ubuntu/Debian
   sudo yum install python3 python3-pip  # CentOS/RHEL
   ```

3. **Install packages**:
   ```bash
   pip3 install -r requirements.txt
   pip3 install scapy scikit-learn numpy
   ```

## 🚀 Quick Start

### 1. Safety First
- Read [SAFETY_GUIDELINES.md](SAFETY_GUIDELINES.md)
- Ensure you have proper authorization
- Test in isolated environment first

### 2. Basic Asset Discovery
```bash
# Discover assets in OT network
python asset_enumeration.py 192.168.1.0/24 --safe-mode --report
```

### 3. Validate Network Segmentation
```bash
# Check network segmentation
python network_segmentation.py --report
```

### 4. Monitor for Anomalies
```bash
# Start anomaly detection
python anomaly_detection.py --interface eth0 --ml-enabled
```

### 5. Security Event Monitoring
```bash
# Monitor security events
python security_monitoring.py --syslog-port 514 --report
```

## 📊 Output and Reports

### JSON Output
All scripts generate structured JSON output with:
- Timestamps and metadata
- Detailed results and findings
- Configuration information
- Analysis summaries

### Text Reports
Human-readable reports include:
- Executive summaries
- Detailed findings
- Risk assessments
- Recommendations
- Action items

### Example Output Structure
```
ot_assets_20240101_120000.json
├── scan_info
│   ├── timestamp
│   ├── total_assets
│   └── config
├── assets
│   ├── ip_address
│   ├── hostname
│   ├── vendor
│   ├── ot_protocols
│   ├── open_ports
│   └── risk_level
└── recommendations
```

## ⚙️ Configuration

### Environment Variables
```bash
export OT_SAFE_MODE=true
export OT_TIMEOUT=5
export OT_MAX_THREADS=20
export OT_LOG_LEVEL=INFO
```

### Configuration Files
Create JSON configuration files for custom settings:

**Example: `config.json`**
```json
{
  "scan_timeout": 3,
  "max_threads": 20,
  "safe_mode": true,
  "ml_enabled": true,
  "alert_threshold": 5,
  "correlation_window": 300
}
```

## 🔍 Troubleshooting

### Common Issues

**1. Permission Denied**
```bash
# Linux: Run with sudo for network operations
sudo python asset_enumeration.py 192.168.1.0/24

# Windows: Run as Administrator
```

**2. Scapy Not Available**
```bash
# Install Scapy
pip install scapy

# Or use without advanced features
python script.py --no-scapy
```

**3. Network Interface Issues**
```bash
# List available interfaces
python -c "import scapy.all; print(scapy.get_if_list())"

# Use specific interface
python anomaly_detection.py --interface eth0
```

**4. Memory Issues**
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

## 📚 Documentation

### Script Documentation
- [Asset Enumeration](asset_enumeration.py) - Detailed usage and options
- [Network Segmentation](network_segmentation.py) - Configuration and validation
- [Anomaly Detection](anomaly_detection.py) - Monitoring and detection
- [Security Monitoring](security_monitoring.py) - Event collection and analysis

### Safety Documentation
- [Safety Guidelines](SAFETY_GUIDELINES.md) - Critical safety information
- [Emergency Procedures](SAFETY_GUIDELINES.md#emergency-procedures) - What to do if something goes wrong
- [Risk Assessment](SAFETY_GUIDELINES.md#risk-assessment) - Understanding and managing risks

## 🤝 Contributing

### Reporting Issues
- Use GitHub Issues for bug reports
- Include system information and logs
- Provide steps to reproduce
- Follow security disclosure guidelines

### Contributing Code
- Follow Python PEP 8 style guidelines
- Include comprehensive documentation
- Add appropriate safety checks
- Test thoroughly in isolated environments

### Code Review Process
- All contributions require review
- Safety considerations are paramount
- Documentation must be updated
- Tests must pass

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: These scripts are provided for educational and authorized testing purposes only. Users assume all risks and responsibilities for their use. The authors and contributors are not liable for any damages or consequences resulting from the use of these scripts.

## 📞 Support

### Technical Support
- GitHub Issues: [Repository Issues]
- Email: [Support Email]
- Documentation: [Documentation URL]

### Emergency Support
- 24/7 Hotline: [Emergency Contact]
- Emergency Email: [Emergency Email]

## 🔄 Updates and Maintenance

### Regular Updates
- Monthly security updates
- Quarterly feature releases
- Annual major version releases
- Continuous bug fixes

### Maintenance Schedule
- **Daily**: Monitor for critical issues
- **Weekly**: Review performance metrics
- **Monthly**: Update dependencies
- **Quarterly**: Security assessments

## 📈 Roadmap

### Planned Features
- Enhanced ML algorithms
- Additional OT protocols
- Cloud integration
- Advanced correlation
- Mobile app interface

### Future Enhancements
- Real-time dashboards
- Automated response
- Integration with SIEM
- Compliance reporting
- Threat intelligence

---

**Remember: Safety is everyone's responsibility. When in doubt, stop and ask for guidance.**

**Last Updated**: [Date]
**Version**: 1.0
**Next Review**: [Date]

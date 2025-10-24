# Reconnaissance Scripts for CPTC Competition
=============================================

This directory contains comprehensive reconnaissance and vulnerability scanning scripts designed for general IT environments in CPTC competitions. These scripts perform host discovery, port scanning, service enumeration, and vulnerability identification across Linux and Windows systems.

## Scripts Overview

### 1. Host Discovery (`discovery.py`)
**Purpose**: Performs efficient host discovery and network reconnaissance with stealth and modular design.

**Features**:
- ICMP ping sweep for live host discovery
- ARP scan for local network hosts
- TCP SYN scan for port discovery
- UDP scan for UDP services
- DNS enumeration and subdomain discovery
- Stealth scanning techniques

**Usage**:
```bash
# Ping sweep network
python3 discovery.py --network 192.168.1.0/24

# DNS enumeration
python3 discovery.py --dns example.com

# Comprehensive discovery
python3 discovery.py --comprehensive --stealth
```

### 2. Port Scanner (`portscan.py`)
**Purpose**: Advanced port scanning with service enumeration and vulnerability identification.

**Features**:
- TCP SYN scanning for stealth
- TCP connect scanning for reliability
- UDP scanning for UDP services
- Service identification and banner grabbing
- SSL/TLS vulnerability checking
- Comprehensive vulnerability assessment

**Usage**:
```bash
# TCP SYN scan
python3 portscan.py --targets 192.168.1.1,192.168.1.2 --scan-type tcp_syn

# Stealth scan
python3 portscan.py --targets 192.168.1.0/24 --stealth

# Comprehensive scan with vulnerability checks
python3 portscan.py --targets 192.168.1.1 --comprehensive --vulnerability-scan
```

### 3. Service Enumeration (`service_enum.py`)
**Purpose**: Comprehensive service enumeration and fingerprinting with vulnerability identification.

**Features**:
- Service banner grabbing and parsing
- Version identification
- Service-specific enumeration modules
- Vulnerability pattern matching
- Information disclosure detection
- Default credential checking

**Usage**:
```bash
# Enumerate specific services
python3 service_enum.py --targets 192.168.1.1:80:http,192.168.1.1:443:https

# Aggressive enumeration
python3 service_enum.py --targets 192.168.1.1:22:ssh --aggressive

# Vulnerability scanning
python3 service_enum.py --targets 192.168.1.1:3306:mysql --vulnerability-scan
```

### 4. Vulnerability Scanner (`vuln_scan.py`)
**Purpose**: Comprehensive vulnerability scanning with CVE identification and risk assessment.

**Features**:
- Web application vulnerability detection
- Database vulnerability assessment
- Remote access vulnerability checking
- File sharing vulnerability identification
- SSL/TLS vulnerability assessment
- CVE database integration

**Usage**:
```bash
# Scan for vulnerabilities
python3 vuln_scan.py --targets 192.168.1.1:80:http,192.168.1.1:443:https

# CVE checking
python3 vuln_scan.py --targets 192.168.1.1:22:ssh --check-cves

# Aggressive scanning
python3 vuln_scan.py --targets 192.168.1.1:3306:mysql --aggressive
```

### 5. Reconnaissance Master (`recon_master.py`)
**Purpose**: Master script that provides a comprehensive menu-driven interface for reconnaissance operations.

**Features**:
- Menu-driven interface for all reconnaissance tools
- Quick assessment templates
- Comprehensive assessment orchestration
- Results management and viewing
- Interactive and command-line modes

**Usage**:
```bash
# Interactive mode (recommended)
python3 recon_master.py

# Quick assessment templates
python3 recon_master.py --quick 1  # Network Discovery Assessment
python3 recon_master.py --quick 2  # Service Enumeration Assessment

# Run specific category
python3 recon_master.py --category 2  # Port Scanning Assessment

# Comprehensive assessment
python3 recon_master.py --comprehensive

# View results
python3 recon_master.py --results
```

## Installation

1. **Install Python Dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **System Requirements**:
   - Python 3.7+
   - Network access to target systems
   - Appropriate permissions for scanning/auditing
   - Linux/Unix environment (for some tools)

## Configuration

### Host Discovery
- Default networks: 192.168.1.0/24, 10.0.0.0/24, 172.16.0.0/24
- Stealth scanning with rate limiting
- ARP scan for local networks
- DNS enumeration for domain reconnaissance

### Port Scanning
- Common ports: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 9300
- Stealth ports: 80, 443, 8080, 8443, 8000, 9000
- Rate limiting and timeout controls
- Service identification and banner grabbing

### Service Enumeration
- Service-specific enumeration modules
- Version identification and parsing
- Vulnerability pattern matching
- Information disclosure detection
- Default credential checking

### Vulnerability Scanning
- CVE database integration
- Web application vulnerability detection
- Database vulnerability assessment
- Remote access vulnerability checking
- SSL/TLS vulnerability assessment

## Security Considerations

⚠️ **IMPORTANT**: These scripts are designed for authorized penetration testing and security assessments only.

- Always obtain proper authorization before running these scripts
- Use stealth modes when available to minimize network impact
- Review and customize configurations for your specific environment
- Be mindful of rate limiting and network impact
- Ensure you have appropriate permissions for scanning/auditing

## Output Files

Each script generates detailed output files:
- `host_discovery_YYYYMMDD_HHMMSS.json`
- `port_scan_YYYYMMDD_HHMMSS.json`
- `service_enum_YYYYMMDD_HHMMSS.json`
- `vuln_scan_YYYYMMDD_HHMMSS.json`
- `recon_master_YYYYMMDD_HHMMSS.json`

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure you have appropriate permissions for the target systems
2. **Network Connectivity**: Verify network access to target systems
3. **Python Dependencies**: Install all required packages from requirements.txt
4. **Rate Limiting**: Adjust rate limits if scans are too aggressive

### Getting Help

Each script includes comprehensive help:
```bash
python3 discovery.py --help
python3 portscan.py --help
python3 service_enum.py --help
python3 vuln_scan.py --help
python3 recon_master.py --help
```

## Contributing

These scripts are designed for CPTC competition use. Feel free to modify and adapt them for your specific needs while maintaining security best practices.

## License

This toolkit is provided for educational and competition purposes. Use responsibly and in accordance with applicable laws and regulations.

# OT Security Scripts for CPTC Competition
==========================================

This directory contains operational technology (OT) security scripts designed for maritime environments in CPTC competitions. These scripts help with network segmentation verification, social engineering testing, access control auditing, and telemetry monitoring.

## Scripts Overview

### 1. Network Segmentation Verification (`segmentation.py`)
**Purpose**: Automates network segmentation verification for OT environments on maritime vessels, ensuring isolation between guest Wi-Fi, crew VLAN, and critical OT systems.

**Features**:
- Scans multiple network segments concurrently
- Tests cross-segment connectivity
- Identifies isolation violations
- Generates security recommendations
- Supports custom network ranges

**Usage**:
```bash
# Basic scan with default maritime networks
python3 segmentation.py

# Custom networks with more threads
python3 segmentation.py --networks "192.168.1.0/24,192.168.2.0/24" --threads 100

# Save results to specific file
python3 segmentation.py --timeout 10 --output results.json
```

### 2. Update Pipeline Security (`updates.py`)
**Purpose**: Validates update pipeline security for onboard operational technology software, ensuring protection against malicious updates.

**Features**:
- Digital signature verification
- Source authenticity validation
- Package integrity checks
- Rollback capability verification
- Comprehensive security assessment

**Usage**:
```bash
# Validate all update pipelines
python3 updates.py --validate-all

# Validate specific package
python3 updates.py --package /path/to/update.exe --checksum abc123

# Validate update source
python3 updates.py --source https://vendor.com/updates --category navigation
```

### 3. Vulnerability Scanner (`vulnscan.py`)
**Purpose**: Performs automated vulnerability scanning for operational technology devices on a ship's network, excluding safety-critical systems from testing.

**Features**:
- OT device discovery
- Vulnerability assessment
- Safety-critical system exclusions
- Multiple vulnerability types
- Comprehensive reporting

**Usage**:
```bash
# Run comprehensive scan
python3 vulnscan.py --scan-all

# Scan specific network
python3 vulnscan.py --network 192.168.10.0/24 --exclude-safety

# Scan specific device
python3 vulnscan.py --device 192.168.10.5 --output results.json
```

### 4. Privilege Activity Monitor (`privileges.py`)
**Purpose**: Logs and monitors privileged account activities on maritime OT systems for anomaly detection and forensic readiness.

**Features**:
- Real-time privilege monitoring
- Anomaly detection algorithms
- Forensic logging capabilities
- Alert generation
- Database storage for analysis

**Usage**:
```bash
# Start real-time monitoring
python3 privileges.py --start-monitoring

# Generate forensic report
python3 privileges.py --forensic-report --days 7

# Monitor for specific duration
python3 privileges.py --start-monitoring --duration 3600
```

### 5. RBAC Audit (`rbac.ps1`)
**Purpose**: Audits role-based access controls on critical OT systems and reports privilege escalation risks.

**Features**:
- Audits critical maritime groups
- Identifies privilege escalation risks
- Supports both domain and local system auditing
- Comprehensive risk assessment with recommendations
- PowerShell-based for Windows environments

**Usage**:
```powershell
# Audit local system
.\rbac.ps1

# Audit remote domain
.\rbac.ps1 -TargetDomain "OT-SERVER-01" -Verbose

# Save results to file
.\rbac.ps1 -TargetDomain "maritime.local" -Username "admin" -OutputFile "rbac_audit.json"
```

### 6. Telemetry Monitoring (`telemetry.py`)
**Purpose**: Monitors and analyzes telemetry data from remote fleet control systems to detect anomalies indicating command spoofing.

**Features**:
- Real-time anomaly detection
- Command spoofing detection
- Multiple OT system support
- Statistical baseline analysis
- Alert generation

**Usage**:
```bash
# Monitor for 5 minutes
python3 telemetry.py --duration 300

# Run simulation with specific systems
python3 telemetry.py --simulate --systems navigation,engine

# Use custom configuration
python3 telemetry.py --config config.json --output results.json
```

### 7. Compliance Checker (`compliance.py`)
**Purpose**: Verifies compliance with maritime cybersecurity standards such as IMO SOLAS within shipboard OT environments.

**Features**:
- Multiple maritime standards support
- Comprehensive compliance checking
- Detailed violation reporting
- Recommendations generation
- Standards: IMO SOLAS, IEC 62443, NIST Framework

**Usage**:
```bash
# Check all maritime standards
python3 compliance.py --check-all

# Check specific standard
python3 compliance.py --standard IMO_SOLAS --detailed

# Check multiple standards
python3 compliance.py --standard IEC_62443,NIST_Cybersecurity_Framework
```

### 8. OT Pentesting Master (`pentest.py`)
**Purpose**: Master script that provides a comprehensive menu-driven interface for fundamental OT pentesting operations.

**Features**:
- Menu-driven interface for all OT security tools
- Quick assessment templates
- Comprehensive assessment orchestration
- Results management and viewing
- Interactive and command-line modes

**Usage**:
```bash
# Interactive mode (recommended)
python3 pentest.py

# Quick assessment templates
python3 pentest.py --quick 1  # Critical Systems Assessment
python3 pentest.py --quick 2  # Network Security Assessment

# Run specific category
python3 pentest.py --category 2  # Vulnerability Assessment

# Comprehensive assessment
python3 pentest.py --comprehensive

# View results
python3 pentest.py --results
```

## Installation

1. **Install Python Dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **PowerShell Requirements** (for RBAC audit):
   - PowerShell 5.1 or later
   - Active Directory module (for domain audits)
   - Appropriate permissions

3. **System Requirements**:
   - Python 3.7+
   - Network access to target systems
   - Appropriate permissions for scanning/auditing

## Configuration

### Network Segmentation
- Default networks: Guest Wi-Fi (192.168.1.0/24), Crew VLAN (192.168.2.0/24), OT Systems (192.168.10.0/24)
- Customizable timeout and thread count
- JSON output with detailed results

### Update Pipeline Security
- Digital signature verification for all updates
- Source authenticity validation
- Package integrity checks
- Rollback capability verification

### Vulnerability Scanner
- OT device discovery and classification
- Safety-critical system exclusions
- Multiple vulnerability types
- Comprehensive reporting

### Privilege Activity Monitor
- Real-time monitoring of privileged accounts
- Anomaly detection using pattern analysis
- Forensic logging with hash verification
- SQLite database for activity storage

### RBAC Audit
- Critical groups: Domain Admins, OT Administrators, Maritime Engineers, etc.
- Risk levels: LOW, MEDIUM, HIGH, CRITICAL
- Comprehensive privilege escalation analysis

### Telemetry Monitoring
- Maritime OT systems: Navigation, Engine, Cargo, Safety
- Anomaly detection using statistical methods
- Command spoofing detection algorithms
- Real-time alerting system

### Compliance Checker
- Maritime standards: IMO SOLAS, IEC 62443, NIST Framework
- Comprehensive compliance checking
- Detailed violation reporting
- Recommendations generation

## Security Considerations

⚠️ **IMPORTANT**: These scripts are designed for authorized penetration testing and security assessments only.

- Always obtain proper authorization before running these scripts
- Use test mode for phishing simulations to avoid sending actual emails
- Ensure you have appropriate permissions for network scanning and system auditing
- Review and customize configurations for your specific environment

## Output Files

Each script generates detailed output files:
- `segmentation_verification_YYYYMMDD_HHMMSS.json`
- `update_validation_YYYYMMDD_HHMMSS.json`
- `vulnscan_YYYYMMDD_HHMMSS.json`
- `privilege_monitor_YYYYMMDD_HHMMSS.json`
- `rbac_audit_YYYYMMDD_HHMMSS.json`
- `telemetry_analysis_YYYYMMDD_HHMMSS.json`
- `compliance_check_YYYYMMDD_HHMMSS.json`

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure you have appropriate permissions for the target systems
2. **Network Connectivity**: Verify network access to target systems
3. **Python Dependencies**: Install all required packages from requirements.txt
4. **PowerShell Execution Policy**: May need to set execution policy for PowerShell scripts

### Getting Help

Each script includes comprehensive help:
```bash
python3 segmentation.py --help
python3 updates.py --help
python3 vulnscan.py --help
python3 privileges.py --help
python3 telemetry.py --help
python3 compliance.py --help
```

For PowerShell:
```powershell
.\rbac.ps1 -Help
```

## Contributing

These scripts are designed for CPTC competition use. Feel free to modify and adapt them for your specific needs while maintaining security best practices.

## License

This toolkit is provided for educational and competition purposes. Use responsibly and in accordance with applicable laws and regulations.
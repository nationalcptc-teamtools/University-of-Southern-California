#!/usr/bin/env python3
"""
Vulnerability Scanner for IT Environments
=========================================

This script performs comprehensive vulnerability scanning with CVE
identification and risk assessment for general IT environments.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import time
import socket
import subprocess
from datetime import datetime
import logging
import re
import ssl
import requests
from pathlib import Path

class VulnerabilityScanner:
    def __init__(self, config_file=None):
        """
        Initialize the vulnerability scanner
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "targets": [],
            "vulnerabilities": [],
            "statistics": {}
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('vuln_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Vulnerability categories
        self.vulnerability_categories = {
            'web': {
                'description': 'Web application vulnerabilities',
                'checks': ['sql_injection', 'xss', 'csrf', 'directory_traversal', 'file_inclusion']
            },
            'network': {
                'description': 'Network service vulnerabilities',
                'checks': ['buffer_overflow', 'denial_of_service', 'privilege_escalation', 'information_disclosure']
            },
            'authentication': {
                'description': 'Authentication and authorization vulnerabilities',
                'checks': ['weak_passwords', 'default_credentials', 'session_management', 'access_control']
            },
            'encryption': {
                'description': 'Encryption and SSL/TLS vulnerabilities',
                'checks': ['weak_ciphers', 'certificate_issues', 'protocol_vulnerabilities']
            },
            'configuration': {
                'description': 'Configuration and misconfiguration vulnerabilities',
                'checks': ['default_settings', 'information_disclosure', 'unnecessary_services']
            }
        }
        
        # CVE database (simplified)
        self.cve_database = {
            'CVE-2021-44228': {
                'name': 'Log4Shell',
                'severity': 'CRITICAL',
                'description': 'Apache Log4j2 remote code execution vulnerability',
                'cvss_score': 10.0,
                'affected_versions': ['2.0.0', '2.14.1'],
                'fix_version': '2.15.0'
            },
            'CVE-2021-34527': {
                'name': 'PrintNightmare',
                'severity': 'CRITICAL',
                'description': 'Windows Print Spooler remote code execution vulnerability',
                'cvss_score': 9.8,
                'affected_versions': ['Windows 10', 'Windows Server 2019'],
                'fix_version': 'Security Update'
            },
            'CVE-2020-1472': {
                'name': 'Zerologon',
                'severity': 'CRITICAL',
                'description': 'Netlogon elevation of privilege vulnerability',
                'cvss_score': 10.0,
                'affected_versions': ['Windows Server 2016', 'Windows Server 2019'],
                'fix_version': 'Security Update'
            },
            'CVE-2019-0708': {
                'name': 'BlueKeep',
                'severity': 'CRITICAL',
                'description': 'Windows Remote Desktop Services remote code execution vulnerability',
                'cvss_score': 10.0,
                'affected_versions': ['Windows 7', 'Windows Server 2008'],
                'fix_version': 'Security Update'
            },
            'CVE-2017-0144': {
                'name': 'EternalBlue',
                'severity': 'CRITICAL',
                'description': 'SMB remote code execution vulnerability',
                'cvss_score': 9.3,
                'affected_versions': ['Windows 7', 'Windows Server 2008'],
                'fix_version': 'Security Update'
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'scan_settings': {
                'max_threads': 50,
                'timeout': 10,
                'stealth_mode': True,
                'aggressive_mode': False
            },
            'vulnerability_checks': {
                'enabled': True,
                'check_cves': True,
                'check_web_vulns': True,
                'check_network_vulns': True,
                'check_auth_vulns': True,
                'check_ssl_vulns': True,
                'check_config_vulns': True
            },
            'scan_limits': {
                'max_targets': 100,
                'max_ports_per_target': 100,
                'rate_limit': 10  # scans per second
            },
            'common_vulnerabilities': {
                'web_ports': [80, 443, 8080, 8443, 8000, 9000],
                'database_ports': [1433, 3306, 5432, 6379, 9200],
                'remote_access_ports': [22, 23, 3389, 5900],
                'file_sharing_ports': [21, 135, 139, 445, 2049]
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def scan_target(self, target, port, service_type):
        """
        Scan a specific target for vulnerabilities
        
        Args:
            target (str): Target IP address
            port (int): Port number
            service_type (str): Type of service
            
        Returns:
            dict: Vulnerability scan results
        """
        self.logger.info(f"Scanning {target}:{port} for vulnerabilities")
        
        scan_result = {
            'target': target,
            'port': port,
            'service_type': service_type,
            'vulnerabilities': [],
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            # Get service banner
            banner = self._get_service_banner(target, port, service_type)
            
            # Run vulnerability checks based on service type
            if service_type in ['http', 'https']:
                vulns = self._check_web_vulnerabilities(target, port, banner)
            elif service_type in ['mysql', 'postgresql', 'mssql', 'redis']:
                vulns = self._check_database_vulnerabilities(target, port, banner)
            elif service_type in ['ssh', 'rdp', 'vnc', 'telnet']:
                vulns = self._check_remote_access_vulnerabilities(target, port, banner)
            elif service_type in ['ftp', 'smb']:
                vulns = self._check_file_sharing_vulnerabilities(target, port, banner)
            else:
                vulns = self._check_general_vulnerabilities(target, port, banner)
            
            scan_result['vulnerabilities'] = vulns
            
        except Exception as e:
            self.logger.error(f"Error scanning {target}:{port}: {e}")
            scan_result['error'] = str(e)
        
        return scan_result
    
    def _get_service_banner(self, target, port, service_type):
        """Get service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Send appropriate probe
            if service_type in ['http', 'https']:
                probe = f'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n'
            elif service_type == 'ftp':
                probe = ''  # FTP sends banner automatically
            elif service_type == 'ssh':
                probe = ''  # SSH sends banner automatically
            elif service_type == 'smtp':
                probe = ''  # SMTP sends banner automatically
            elif service_type == 'mysql':
                probe = ''  # MySQL sends banner automatically
            elif service_type == 'postgresql':
                probe = ''  # PostgreSQL sends banner automatically
            elif service_type == 'mssql':
                probe = ''  # SQL Server sends banner automatically
            elif service_type == 'redis':
                probe = 'PING\r\n'
            elif service_type == 'elasticsearch':
                probe = f'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n'
            else:
                probe = ''
            
            if probe:
                sock.send(probe.encode())
            
            # Receive response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            return response
            
        except Exception as e:
            self.logger.debug(f"Error getting banner from {target}:{port}: {e}")
            return ''
    
    def _check_web_vulnerabilities(self, target, port, banner):
        """Check for web vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for information disclosure
            if 'Server:' in banner:
                server_line = [line for line in banner.split('\n') if 'Server:' in line][0]
                server_info = server_line.split(':', 1)[1].strip()
                
                # Check for outdated versions
                if 'Apache/2.2.' in server_info or 'Apache/2.0.' in server_info:
                    vulnerabilities.append({
                        'type': 'OUTDATED_APACHE',
                        'severity': 'HIGH',
                        'description': 'Outdated Apache version detected',
                        'cve': 'CVE-2017-15715',
                        'cvss_score': 7.5
                    })
                elif 'IIS/6.0' in server_info or 'IIS/5.0' in server_info:
                    vulnerabilities.append({
                        'type': 'OUTDATED_IIS',
                        'severity': 'HIGH',
                        'description': 'Outdated IIS version detected',
                        'cve': 'CVE-2017-7269',
                        'cvss_score': 9.3
                    })
                elif 'nginx/1.0.' in server_info or 'nginx/1.1.' in server_info:
                    vulnerabilities.append({
                        'type': 'OUTDATED_NGINX',
                        'severity': 'MEDIUM',
                        'description': 'Outdated Nginx version detected',
                        'cve': 'CVE-2013-2028',
                        'cvss_score': 7.5
                    })
            
            # Check for directory listing
            if 'Index of' in banner or 'Directory listing' in banner:
                vulnerabilities.append({
                    'type': 'DIRECTORY_LISTING',
                    'severity': 'LOW',
                    'description': 'Directory listing enabled',
                    'cve': None,
                    'cvss_score': 3.7
                })
            
            # Check for common web vulnerabilities
            if 'Error:' in banner or 'Exception:' in banner:
                vulnerabilities.append({
                    'type': 'INFORMATION_DISCLOSURE',
                    'severity': 'MEDIUM',
                    'description': 'Error messages may disclose sensitive information',
                    'cve': None,
                    'cvss_score': 5.3
                })
            
            # Check for SQL injection vulnerabilities
            if 'mysql' in banner.lower() or 'sql' in banner.lower():
                vulnerabilities.append({
                    'type': 'SQL_INJECTION_POTENTIAL',
                    'severity': 'MEDIUM',
                    'description': 'Database backend detected, potential SQL injection vulnerability',
                    'cve': None,
                    'cvss_score': 6.5
                })
            
            # Check for XSS vulnerabilities
            if 'javascript' in banner.lower() or 'script' in banner.lower():
                vulnerabilities.append({
                    'type': 'XSS_POTENTIAL',
                    'severity': 'MEDIUM',
                    'description': 'JavaScript detected, potential XSS vulnerability',
                    'cve': None,
                    'cvss_score': 6.1
                })
            
        except Exception as e:
            self.logger.error(f"Error checking web vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_database_vulnerabilities(self, target, port, banner):
        """Check for database vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for default credentials
            if port == 3306:  # MySQL
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'MySQL default credentials may be in use',
                    'cve': 'CVE-2016-6662',
                    'cvss_score': 7.5
                })
                
                # Check for outdated MySQL versions
                if 'MySQL 4.' in banner or 'MySQL 5.0.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_MYSQL',
                        'severity': 'HIGH',
                        'description': 'Outdated MySQL version detected',
                        'cve': 'CVE-2016-6662',
                        'cvss_score': 7.5
                    })
            
            elif port == 1433:  # SQL Server
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'SQL Server default credentials may be in use',
                    'cve': 'CVE-2017-0144',
                    'cvss_score': 9.3
                })
                
                # Check for outdated SQL Server versions
                if 'SQL Server 2000' in banner or 'SQL Server 2005' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_MSSQL',
                        'severity': 'HIGH',
                        'description': 'Outdated SQL Server version detected',
                        'cve': 'CVE-2017-0144',
                        'cvss_score': 9.3
                    })
            
            elif port == 5432:  # PostgreSQL
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'PostgreSQL default credentials may be in use',
                    'cve': 'CVE-2019-10208',
                    'cvss_score': 7.5
                })
                
                # Check for outdated PostgreSQL versions
                if 'PostgreSQL 8.' in banner or 'PostgreSQL 7.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_POSTGRESQL',
                        'severity': 'HIGH',
                        'description': 'Outdated PostgreSQL version detected',
                        'cve': 'CVE-2019-10208',
                        'cvss_score': 7.5
                    })
            
            elif port == 6379:  # Redis
                vulnerabilities.append({
                    'type': 'REDIS_NO_AUTH',
                    'severity': 'CRITICAL',
                    'description': 'Redis may be running without authentication',
                    'cve': 'CVE-2015-8080',
                    'cvss_score': 9.8
                })
                
                # Check for outdated Redis versions
                if 'Redis 2.' in banner or 'Redis 3.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_REDIS',
                        'severity': 'HIGH',
                        'description': 'Outdated Redis version detected',
                        'cve': 'CVE-2015-8080',
                        'cvss_score': 9.8
                    })
            
            elif port == 9200:  # Elasticsearch
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'MEDIUM',
                    'description': 'Elasticsearch default credentials may be in use',
                    'cve': 'CVE-2015-1427',
                    'cvss_score': 7.5
                })
                
                # Check for outdated Elasticsearch versions
                if '1.' in banner or '2.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_ELASTICSEARCH',
                        'severity': 'HIGH',
                        'description': 'Outdated Elasticsearch version detected',
                        'cve': 'CVE-2015-1427',
                        'cvss_score': 7.5
                    })
            
        except Exception as e:
            self.logger.error(f"Error checking database vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_remote_access_vulnerabilities(self, target, port, banner):
        """Check for remote access vulnerabilities"""
        vulnerabilities = []
        
        try:
            if port == 22:  # SSH
                # Check for outdated SSH versions
                if 'OpenSSH_4.' in banner or 'OpenSSH_5.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_SSH',
                        'severity': 'HIGH',
                        'description': 'Outdated OpenSSH version detected',
                        'cve': 'CVE-2016-0777',
                        'cvss_score': 7.5
                    })
                
                # Check for SSH1 protocol
                if 'SSH-1.' in banner:
                    vulnerabilities.append({
                        'type': 'SSH1_PROTOCOL',
                        'severity': 'CRITICAL',
                        'description': 'SSH version 1 protocol detected',
                        'cve': 'CVE-1999-0128',
                        'cvss_score': 10.0
                    })
                
                # Check for weak algorithms
                if 'weak' in banner.lower() or 'deprecated' in banner.lower():
                    vulnerabilities.append({
                        'type': 'WEAK_SSH_ALGORITHMS',
                        'severity': 'MEDIUM',
                        'description': 'Weak SSH algorithms detected',
                        'cve': None,
                        'cvss_score': 5.3
                    })
            
            elif port == 23:  # Telnet
                vulnerabilities.append({
                    'type': 'TELNET_CLEARTEXT',
                    'severity': 'CRITICAL',
                    'description': 'Telnet transmits credentials in cleartext',
                    'cve': 'CVE-1999-0128',
                    'cvss_score': 10.0
                })
                
                # Check for outdated Telnet versions
                if 'Telnet' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_TELNET',
                        'severity': 'HIGH',
                        'description': 'Outdated Telnet version detected',
                        'cve': 'CVE-1999-0128',
                        'cvss_score': 10.0
                    })
            
            elif port == 3389:  # RDP
                # Check for BlueKeep vulnerability
                if 'Windows 7' in banner or 'Windows Server 2008' in banner:
                    vulnerabilities.append({
                        'type': 'BLUEKEEP_VULNERABILITY',
                        'severity': 'CRITICAL',
                        'description': 'BlueKeep vulnerability detected',
                        'cve': 'CVE-2019-0708',
                        'cvss_score': 10.0
                    })
                
                # Check for RDP brute force vulnerability
                vulnerabilities.append({
                    'type': 'RDP_BRUTE_FORCE',
                    'severity': 'MEDIUM',
                    'description': 'RDP service may be vulnerable to brute force attacks',
                    'cve': None,
                    'cvss_score': 6.5
                })
            
            elif port == 5900:  # VNC
                # Check for VNC weak authentication
                vulnerabilities.append({
                    'type': 'VNC_WEAK_AUTH',
                    'severity': 'HIGH',
                    'description': 'VNC may use weak authentication',
                    'cve': 'CVE-2006-2369',
                    'cvss_score': 7.5
                })
                
                # Check for outdated VNC versions
                if 'TightVNC 1.' in banner or 'RealVNC 3.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_VNC',
                        'severity': 'HIGH',
                        'description': 'Outdated VNC version detected',
                        'cve': 'CVE-2006-2369',
                        'cvss_score': 7.5
                    })
            
        except Exception as e:
            self.logger.error(f"Error checking remote access vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_file_sharing_vulnerabilities(self, target, port, banner):
        """Check for file sharing vulnerabilities"""
        vulnerabilities = []
        
        try:
            if port == 21:  # FTP
                # Check for anonymous FTP access
                if 'anonymous' in banner.lower():
                    vulnerabilities.append({
                        'type': 'ANONYMOUS_FTP',
                        'severity': 'MEDIUM',
                        'description': 'Anonymous FTP access enabled',
                        'cve': None,
                        'cvss_score': 5.3
                    })
                
                # Check for outdated FTP versions
                if 'vsftpd 2.2.' in banner or 'vsftpd 2.0.' in banner:
                    vulnerabilities.append({
                        'type': 'OUTDATED_FTP',
                        'severity': 'HIGH',
                        'description': 'Outdated vsftpd version detected',
                        'cve': 'CVE-2011-2523',
                        'cvss_score': 7.5
                    })
            
            elif port == 445:  # SMB
                # Check for SMB vulnerabilities
                vulnerabilities.append({
                    'type': 'SMB_VULNERABILITIES',
                    'severity': 'HIGH',
                    'description': 'SMB service may be vulnerable to various attacks',
                    'cve': 'CVE-2017-0144',
                    'cvss_score': 9.3
                })
                
                # Check for EternalBlue vulnerability
                if 'Windows 7' in banner or 'Windows Server 2008' in banner:
                    vulnerabilities.append({
                        'type': 'ETERNALBLUE_VULNERABILITY',
                        'severity': 'CRITICAL',
                        'description': 'EternalBlue vulnerability detected',
                        'cve': 'CVE-2017-0144',
                        'cvss_score': 9.3
                    })
                
                # Check for SMB null session
                vulnerabilities.append({
                    'type': 'SMB_NULL_SESSION',
                    'severity': 'HIGH',
                    'description': 'SMB may allow null session connections',
                    'cve': None,
                    'cvss_score': 7.5
                })
            
            elif port == 139:  # NetBIOS
                # Check for NetBIOS vulnerabilities
                vulnerabilities.append({
                    'type': 'NETBIOS_VULNERABILITIES',
                    'severity': 'MEDIUM',
                    'description': 'NetBIOS service may be vulnerable to various attacks',
                    'cve': None,
                    'cvss_score': 6.5
                })
            
        except Exception as e:
            self.logger.error(f"Error checking file sharing vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_general_vulnerabilities(self, target, port, banner):
        """Check for general vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for information disclosure
            if 'Server:' in banner or 'Version:' in banner:
                vulnerabilities.append({
                    'type': 'INFORMATION_DISCLOSURE',
                    'severity': 'LOW',
                    'description': 'Service information may be disclosed',
                    'cve': None,
                    'cvss_score': 3.7
                })
            
            # Check for error messages
            if 'Error:' in banner or 'Exception:' in banner:
                vulnerabilities.append({
                    'type': 'ERROR_MESSAGE_DISCLOSURE',
                    'severity': 'MEDIUM',
                    'description': 'Error messages may disclose sensitive information',
                    'cve': None,
                    'cvss_score': 5.3
                })
            
            # Check for default configurations
            if 'default' in banner.lower() or 'admin' in banner.lower():
                vulnerabilities.append({
                    'type': 'DEFAULT_CONFIGURATION',
                    'severity': 'MEDIUM',
                    'description': 'Default configuration may be in use',
                    'cve': None,
                    'cvss_score': 5.3
                })
            
        except Exception as e:
            self.logger.error(f"Error checking general vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_ssl_vulnerabilities(self, target, port):
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        vulnerabilities.append({
                            'type': 'SSL_CERTIFICATE_EXPIRY',
                            'severity': 'HIGH',
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'cve': None,
                            'cvss_score': 7.5
                        })
                    
                    # Check for weak ciphers
                    cipher = ssock.cipher()
                    if cipher and cipher[0] in ['RC4', 'DES', '3DES']:
                        vulnerabilities.append({
                            'type': 'WEAK_SSL_CIPHER',
                            'severity': 'MEDIUM',
                            'description': f'Weak SSL cipher detected: {cipher[0]}',
                            'cve': 'CVE-2013-2566',
                            'cvss_score': 5.3
                        })
                    
                    # Check for SSL protocol vulnerabilities
                    if cipher and cipher[1] in ['SSLv2', 'SSLv3']:
                        vulnerabilities.append({
                            'type': 'WEAK_SSL_PROTOCOL',
                            'severity': 'HIGH',
                            'description': f'Weak SSL protocol detected: {cipher[1]}',
                            'cve': 'CVE-2014-3566',
                            'cvss_score': 7.5
                        })
        
        except Exception as e:
            self.logger.debug(f"Error checking SSL vulnerabilities on {target}:{port}: {e}")
        
        return vulnerabilities
    
    def run_comprehensive_scan(self, targets):
        """
        Run comprehensive vulnerability scan
        
        Args:
            targets (list): List of target services (target:port:service)
            
        Returns:
            dict: Comprehensive scan results
        """
        self.logger.info(f"Starting comprehensive vulnerability scan on {len(targets)} targets")
        
        scan_results = {}
        
        for target_info in targets:
            if ':' in target_info:
                parts = target_info.split(':')
                if len(parts) >= 2:
                    target = parts[0]
                    port = int(parts[1])
                    service_type = parts[2] if len(parts) > 2 else 'unknown'
                    
                    result = self.scan_target(target, port, service_type)
                    scan_results[f"{target}:{port}"] = result
                    
                    self.logger.info(f"Scanned {target}:{port} - {service_type}")
        
        # Store results
        self.results['targets'] = targets
        self.results['vulnerabilities'] = scan_results
        
        # Generate statistics
        self._generate_scan_statistics(scan_results)
        
        self.logger.info("Comprehensive vulnerability scan completed")
        return scan_results
    
    def _generate_scan_statistics(self, results):
        """Generate scan statistics"""
        stats = {
            'total_targets': len(results),
            'total_vulnerabilities': sum(len(service.get('vulnerabilities', [])) for service in results.values()),
            'vulnerabilities_by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'vulnerabilities_by_type': {},
            'cve_count': 0
        }
        
        # Count vulnerabilities by severity and type
        for service in results.values():
            for vuln in service.get('vulnerabilities', []):
                severity = vuln.get('severity', 'LOW')
                vuln_type = vuln.get('type', 'UNKNOWN')
                
                stats['vulnerabilities_by_severity'][severity] += 1
                stats['vulnerabilities_by_type'][vuln_type] = stats['vulnerabilities_by_type'].get(vuln_type, 0) + 1
                
                if vuln.get('cve'):
                    stats['cve_count'] += 1
        
        self.results['statistics'] = stats
    
    def save_results(self, filename=None):
        """Save scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_scan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner for IT Environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vuln_scan.py --targets 192.168.1.1:80:http,192.168.1.1:443:https
  python3 vuln_scan.py --targets 192.168.1.1:22:ssh --check-cves
  python3 vuln_scan.py --targets 192.168.1.1:3306:mysql --aggressive
        """
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        required=True,
        help='Target services (format: ip:port:service, comma-separated)'
    )
    
    parser.add_argument(
        '--check-cves',
        action='store_true',
        help='Enable CVE checking'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Use aggressive scanning techniques'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output filename for results'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse targets
    targets = [target.strip() for target in args.targets.split(',')]
    
    # Create scanner instance
    scanner = VulnerabilityScanner(args.config)
    
    if args.verbose:
        scanner.logger.setLevel(logging.DEBUG)
    
    try:
        # Run scan
        results = scanner.run_comprehensive_scan(targets)
        
        # Save results
        scanner.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("VULNERABILITY SCAN SUMMARY")
        print("="*60)
        print(f"Targets Scanned: {len(results)}")
        
        total_vulnerabilities = sum(len(service.get('vulnerabilities', [])) for service in results.values())
        print(f"Total Vulnerabilities: {total_vulnerabilities}")
        
        print("\nVulnerabilities by Severity:")
        for severity, count in scanner.results['statistics']['vulnerabilities_by_severity'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print("\nVulnerabilities by Type:")
        for vuln_type, count in scanner.results['statistics']['vulnerabilities_by_type'].items():
            print(f"  {vuln_type}: {count}")
        
        print(f"\nCVE Count: {scanner.results['statistics']['cve_count']}")
        
        print("\n[*] Vulnerability scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

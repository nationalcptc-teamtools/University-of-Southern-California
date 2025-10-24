#!/usr/bin/env python3
"""
Advanced Port Scanner for IT Environments
=========================================

This script performs efficient and stealthy port scanning with service
enumeration and vulnerability identification across Linux and Windows systems.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import time
import threading
import socket
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import random
import re
import ssl

class PortScanner:
    def __init__(self, config_file=None):
        """
        Initialize the port scanner
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "targets": [],
            "scan_results": {},
            "vulnerabilities": [],
            "statistics": {}
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('port_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Port categories
        self.port_categories = {
            'web': [80, 443, 8080, 8443, 8000, 8008, 9000, 9080],
            'database': [1433, 3306, 5432, 6379, 27017, 9200, 9300],
            'email': [25, 110, 143, 993, 995, 587, 465],
            'remote_access': [22, 23, 3389, 5900, 5901, 5985, 5986],
            'file_sharing': [21, 22, 135, 139, 445, 2049],
            'dns': [53, 5353],
            'dhcp': [67, 68],
            'snmp': [161, 162],
            'ldap': [389, 636, 3268, 3269],
            'ftp': [21, 990, 989],
            'ssh': [22],
            'telnet': [23],
            'rdp': [3389],
            'vnc': [5900, 5901, 5902, 5903],
            'windows': [135, 139, 445, 3389, 5985, 5986],
            'linux': [22, 23, 80, 443, 631, 993, 995]
        }
        
        # Service fingerprints
        self.service_fingerprints = {
            'http': {
                'ports': [80, 8080, 8000, 8008, 9000, 9080],
                'banner_patterns': [r'HTTP', r'Apache', r'nginx', r'IIS', r'Server:']
            },
            'https': {
                'ports': [443, 8443],
                'banner_patterns': [r'HTTP', r'SSL', r'TLS']
            },
            'ssh': {
                'ports': [22],
                'banner_patterns': [r'SSH', r'OpenSSH']
            },
            'ftp': {
                'ports': [21, 990],
                'banner_patterns': [r'FTP', r'vsftpd', r'ProFTPD']
            },
            'smtp': {
                'ports': [25, 587, 465],
                'banner_patterns': [r'SMTP', r'Postfix', r'Sendmail', r'Exchange']
            },
            'pop3': {
                'ports': [110, 995],
                'banner_patterns': [r'POP3', r'Dovecot']
            },
            'imap': {
                'ports': [143, 993],
                'banner_patterns': [r'IMAP', r'Dovecot']
            },
            'rdp': {
                'ports': [3389],
                'banner_patterns': [r'RDP', r'TermService']
            },
            'vnc': {
                'ports': [5900, 5901, 5902, 5903],
                'banner_patterns': [r'VNC', r'TightVNC', r'RealVNC']
            },
            'mysql': {
                'ports': [3306],
                'banner_patterns': [r'MySQL', r'mariadb']
            },
            'postgresql': {
                'ports': [5432],
                'banner_patterns': [r'PostgreSQL']
            },
            'mssql': {
                'ports': [1433],
                'banner_patterns': [r'SQL Server', r'Microsoft SQL']
            },
            'redis': {
                'ports': [6379],
                'banner_patterns': [r'Redis']
            },
            'elasticsearch': {
                'ports': [9200, 9300],
                'banner_patterns': [r'elasticsearch']
            },
            'snmp': {
                'ports': [161, 162],
                'banner_patterns': [r'SNMP']
            },
            'ldap': {
                'ports': [389, 636, 3268, 3269],
                'banner_patterns': [r'LDAP', r'Active Directory']
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'scan_settings': {
                'max_threads': 200,
                'timeout': 3,
                'stealth_mode': True,
                'randomize_ports': True,
                'delay_between_scans': 0.1
            },
            'scan_limits': {
                'max_ports_per_host': 1000,
                'rate_limit': 200,  # packets per second
                'max_hosts': 100
            },
            'scan_types': {
                'tcp_syn': True,
                'tcp_connect': True,
                'udp': False,  # UDP scans are slower
                'stealth': True
            },
            'common_ports': [
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 9300
            ],
            'stealth_ports': [80, 443, 8080, 8443, 8000, 9000],
            'vulnerability_checks': {
                'enabled': True,
                'check_ssl': True,
                'check_weak_ciphers': True,
                'check_common_vulns': True
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
    
    def tcp_syn_scan(self, targets, ports=None):
        """
        Perform TCP SYN scan
        
        Args:
            targets (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Scan results
        """
        if not ports:
            ports = self.config['common_ports']
        
        self.logger.info(f"Starting TCP SYN scan on {len(targets)} targets")
        
        scan_results = {}
        
        for target in targets:
            scan_results[target] = {
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'services': {},
                'vulnerabilities': [],
                'scan_time': datetime.now().isoformat()
            }
            
            # Randomize port order for stealth
            if self.config['scan_settings']['randomize_ports']:
                ports = random.sample(ports, len(ports))
            
            with ThreadPoolExecutor(max_workers=self.config['scan_settings']['max_threads']) as executor:
                future_to_port = {
                    executor.submit(self._tcp_syn_scan_port, target, port): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                        if is_open:
                            scan_results[target]['open_ports'].append(port)
                            # Identify service
                            service = self._identify_service(target, port)
                            scan_results[target]['services'][port] = service
                            self.logger.info(f"Open port {port} on {target} - {service}")
                        else:
                            scan_results[target]['closed_ports'].append(port)
                    except Exception as e:
                        self.logger.error(f"Error scanning port {port} on {target}: {e}")
                        scan_results[target]['filtered_ports'].append(port)
            
            # Rate limiting
            time.sleep(1.0 / self.config['scan_limits']['rate_limit'])
        
        return scan_results
    
    def _tcp_syn_scan_port(self, target, port):
        """Scan a single port using TCP SYN"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['scan_settings']['timeout'])
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def tcp_connect_scan(self, targets, ports=None):
        """
        Perform TCP connect scan (more reliable but less stealthy)
        
        Args:
            targets (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Scan results
        """
        if not ports:
            ports = self.config['common_ports']
        
        self.logger.info(f"Starting TCP connect scan on {len(targets)} targets")
        
        scan_results = {}
        
        for target in targets:
            scan_results[target] = {
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'services': {},
                'vulnerabilities': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.config['scan_settings']['timeout'])
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        scan_results[target]['open_ports'].append(port)
                        # Identify service
                        service = self._identify_service(target, port)
                        scan_results[target]['services'][port] = service
                        self.logger.info(f"Open port {port} on {target} - {service}")
                    else:
                        scan_results[target]['closed_ports'].append(port)
                    
                    sock.close()
                    
                except Exception as e:
                    self.logger.error(f"Error scanning port {port} on {target}: {e}")
                    scan_results[target]['filtered_ports'].append(port)
                
                # Rate limiting
                time.sleep(1.0 / self.config['scan_limits']['rate_limit'])
        
        return scan_results
    
    def udp_scan(self, targets, ports=None):
        """
        Perform UDP scan (slower but important for some services)
        
        Args:
            targets (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Scan results
        """
        if not ports:
            ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500]
        
        self.logger.info(f"Starting UDP scan on {len(targets)} targets")
        
        scan_results = {}
        
        for target in targets:
            scan_results[target] = {
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'services': {},
                'vulnerabilities': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.config['scan_settings']['timeout'])
                    
                    # Send UDP packet
                    sock.sendto(b'\x00', (target, port))
                    
                    try:
                        data, addr = sock.recvfrom(1024)
                        scan_results[target]['open_ports'].append(port)
                        service = self._identify_udp_service(target, port)
                        scan_results[target]['services'][port] = service
                        self.logger.info(f"Open UDP port {port} on {target} - {service}")
                    except socket.timeout:
                        scan_results[target]['closed_ports'].append(port)
                    
                    sock.close()
                    
                except Exception as e:
                    self.logger.error(f"Error scanning UDP port {port} on {target}: {e}")
                    scan_results[target]['filtered_ports'].append(port)
                
                # Rate limiting for UDP (slower than TCP)
                time.sleep(2.0 / self.config['scan_limits']['rate_limit'])
        
        return scan_results
    
    def _identify_service(self, target, port):
        """Identify service running on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Get banner
            banner = self._get_banner(sock, port)
            service = self._parse_banner(banner, port)
            
            sock.close()
            return service
            
        except Exception as e:
            self.logger.debug(f"Error identifying service on {target}:{port}: {e}")
            return 'Unknown'
    
    def _identify_udp_service(self, target, port):
        """Identify UDP service"""
        # Common UDP services
        udp_services = {
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            69: 'TFTP',
            123: 'NTP',
            135: 'RPC',
            137: 'NetBIOS Name Service',
            138: 'NetBIOS Datagram',
            139: 'NetBIOS Session',
            161: 'SNMP',
            162: 'SNMP Trap',
            445: 'SMB',
            500: 'IKE',
            514: 'Syslog',
            520: 'RIP',
            631: 'IPP',
            1434: 'SQL Server',
            1900: 'SSDP',
            4500: 'IPSec NAT-T'
        }
        
        return udp_services.get(port, 'Unknown')
    
    def _get_banner(self, sock, port):
        """Get service banner"""
        try:
            # Send appropriate probe based on port
            if port in [80, 8080, 8000, 8008, 9000, 9080]:
                sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port in [443, 8443]:
                # HTTPS probe
                sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port == 21:
                # FTP probe
                pass  # FTP sends banner automatically
            elif port == 22:
                # SSH probe
                pass  # SSH sends banner automatically
            elif port == 25:
                # SMTP probe
                pass  # SMTP sends banner automatically
            elif port == 110:
                # POP3 probe
                pass  # POP3 sends banner automatically
            elif port == 143:
                # IMAP probe
                pass  # IMAP sends banner automatically
            elif port == 3389:
                # RDP probe
                pass  # RDP sends banner automatically
            elif port == 5900:
                # VNC probe
                pass  # VNC sends banner automatically
            elif port == 3306:
                # MySQL probe
                pass  # MySQL sends banner automatically
            elif port == 5432:
                # PostgreSQL probe
                pass  # PostgreSQL sends banner automatically
            elif port == 1433:
                # SQL Server probe
                pass  # SQL Server sends banner automatically
            elif port == 6379:
                # Redis probe
                sock.send(b'PING\r\n')
            elif port == 9200:
                # Elasticsearch probe
                sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port == 161:
                # SNMP probe
                pass  # SNMP sends banner automatically
            elif port == 389:
                # LDAP probe
                pass  # LDAP sends banner automatically
            
            # Receive response
            sock.settimeout(2)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            return response
            
        except Exception as e:
            self.logger.debug(f"Error getting banner: {e}")
            return ''
    
    def _parse_banner(self, banner, port):
        """Parse service banner to identify service"""
        if not banner:
            return 'Unknown'
        
        banner_lower = banner.lower()
        
        # Web servers
        if 'apache' in banner_lower:
            return 'Apache HTTP Server'
        elif 'nginx' in banner_lower:
            return 'Nginx'
        elif 'iis' in banner_lower or 'microsoft' in banner_lower:
            return 'Microsoft IIS'
        elif 'lighttpd' in banner_lower:
            return 'Lighttpd'
        elif 'tomcat' in banner_lower:
            return 'Apache Tomcat'
        
        # SSH
        elif 'ssh' in banner_lower:
            return 'SSH'
        
        # FTP
        elif 'ftp' in banner_lower:
            return 'FTP'
        
        # SMTP
        elif 'smtp' in banner_lower or 'postfix' in banner_lower:
            return 'SMTP'
        elif 'sendmail' in banner_lower:
            return 'Sendmail'
        elif 'exchange' in banner_lower:
            return 'Microsoft Exchange'
        
        # POP3
        elif 'pop3' in banner_lower:
            return 'POP3'
        
        # IMAP
        elif 'imap' in banner_lower:
            return 'IMAP'
        
        # RDP
        elif 'rdp' in banner_lower or 'termservice' in banner_lower:
            return 'RDP'
        
        # VNC
        elif 'vnc' in banner_lower:
            return 'VNC'
        
        # Database
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'sql server' in banner_lower or 'microsoft sql' in banner_lower:
            return 'Microsoft SQL Server'
        elif 'redis' in banner_lower:
            return 'Redis'
        elif 'elasticsearch' in banner_lower:
            return 'Elasticsearch'
        
        # SNMP
        elif 'snmp' in banner_lower:
            return 'SNMP'
        
        # LDAP
        elif 'ldap' in banner_lower:
            return 'LDAP'
        
        # Default based on port
        else:
            return self._get_default_service(port)
    
    def _get_default_service(self, port):
        """Get default service name for port"""
        default_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'SQL Server',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP Alt',
            8443: 'HTTPS Alt',
            9200: 'Elasticsearch',
            9300: 'Elasticsearch'
        }
        
        return default_services.get(port, 'Unknown')
    
    def stealth_scan(self, targets, ports=None):
        """
        Perform stealth scan using common web ports
        
        Args:
            targets (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Stealth scan results
        """
        if not ports:
            ports = self.config['stealth_ports']
        
        self.logger.info(f"Starting stealth scan on {len(targets)} targets")
        
        stealth_results = {}
        
        for target in targets:
            stealth_results[target] = {
                'open_ports': [],
                'services': {},
                'vulnerabilities': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        stealth_results[target]['open_ports'].append(port)
                        service = self._identify_service(target, port)
                        stealth_results[target]['services'][port] = service
                        self.logger.info(f"Stealth discovery: {target}:{port} - {service}")
                    
                    sock.close()
                    
                except Exception as e:
                    self.logger.debug(f"Error in stealth scan of {target}:{port}: {e}")
                
                # Random delay for stealth
                time.sleep(random.uniform(0.5, 2.0))
        
        return stealth_results
    
    def vulnerability_scan(self, targets, ports):
        """
        Perform basic vulnerability scanning
        
        Args:
            targets (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Vulnerability scan results
        """
        self.logger.info(f"Starting vulnerability scan on {len(targets)} targets")
        
        vuln_results = {}
        
        for target in targets:
            vuln_results[target] = {
                'vulnerabilities': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                vulnerabilities = self._check_vulnerabilities(target, port)
                vuln_results[target]['vulnerabilities'].extend(vulnerabilities)
        
        return vuln_results
    
    def _check_vulnerabilities(self, target, port):
        """Check for common vulnerabilities on a port"""
        vulnerabilities = []
        
        try:
            # Check for SSL/TLS vulnerabilities
            if port in [443, 8443, 993, 995]:
                ssl_vulns = self._check_ssl_vulnerabilities(target, port)
                vulnerabilities.extend(ssl_vulns)
            
            # Check for common web vulnerabilities
            if port in [80, 443, 8080, 8443, 8000, 9000]:
                web_vulns = self._check_web_vulnerabilities(target, port)
                vulnerabilities.extend(web_vulns)
            
            # Check for database vulnerabilities
            if port in [1433, 3306, 5432, 6379, 9200]:
                db_vulns = self._check_database_vulnerabilities(target, port)
                vulnerabilities.extend(db_vulns)
            
            # Check for remote access vulnerabilities
            if port in [22, 23, 3389, 5900]:
                remote_vulns = self._check_remote_access_vulnerabilities(target, port)
                vulnerabilities.extend(remote_vulns)
            
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities on {target}:{port}: {e}")
        
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
                            'port': port
                        })
                    
                    # Check for weak ciphers
                    cipher = ssock.cipher()
                    if cipher and cipher[0] in ['RC4', 'DES', '3DES']:
                        vulnerabilities.append({
                            'type': 'WEAK_SSL_CIPHER',
                            'severity': 'MEDIUM',
                            'description': f'Weak SSL cipher detected: {cipher[0]}',
                            'port': port
                        })
        
        except Exception as e:
            self.logger.debug(f"Error checking SSL vulnerabilities on {target}:{port}: {e}")
        
        return vulnerabilities
    
    def _check_web_vulnerabilities(self, target, port):
        """Check for web vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for common web vulnerabilities
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Send HTTP request
            request = f'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n'
            sock.send(request.encode())
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check for server information disclosure
            if 'Server:' in response:
                server_line = [line for line in response.split('\n') if 'Server:' in line][0]
                server_info = server_line.split(':', 1)[1].strip()
                
                if 'Apache' in server_info and '2.2' in server_info:
                    vulnerabilities.append({
                        'type': 'OUTDATED_APACHE',
                        'severity': 'MEDIUM',
                        'description': 'Outdated Apache version detected',
                        'port': port
                    })
                elif 'IIS' in server_info and '6.0' in server_info:
                    vulnerabilities.append({
                        'type': 'OUTDATED_IIS',
                        'severity': 'HIGH',
                        'description': 'Outdated IIS version detected',
                        'port': port
                    })
            
            # Check for directory listing
            if 'Index of' in response or 'Directory listing' in response:
                vulnerabilities.append({
                    'type': 'DIRECTORY_LISTING',
                    'severity': 'LOW',
                    'description': 'Directory listing enabled',
                    'port': port
                })
        
        except Exception as e:
            self.logger.debug(f"Error checking web vulnerabilities on {target}:{port}: {e}")
        
        return vulnerabilities
    
    def _check_database_vulnerabilities(self, target, port):
        """Check for database vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for default credentials
            if port == 3306:  # MySQL
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'MySQL default credentials may be in use',
                    'port': port
                })
            elif port == 1433:  # SQL Server
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'SQL Server default credentials may be in use',
                    'port': port
                })
            elif port == 5432:  # PostgreSQL
                vulnerabilities.append({
                    'type': 'DEFAULT_CREDENTIALS',
                    'severity': 'HIGH',
                    'description': 'PostgreSQL default credentials may be in use',
                    'port': port
                })
            elif port == 6379:  # Redis
                vulnerabilities.append({
                    'type': 'REDIS_NO_AUTH',
                    'severity': 'CRITICAL',
                    'description': 'Redis may be running without authentication',
                    'port': port
                })
        
        except Exception as e:
            self.logger.debug(f"Error checking database vulnerabilities on {target}:{port}: {e}")
        
        return vulnerabilities
    
    def _check_remote_access_vulnerabilities(self, target, port):
        """Check for remote access vulnerabilities"""
        vulnerabilities = []
        
        try:
            if port == 22:  # SSH
                vulnerabilities.append({
                    'type': 'SSH_BRUTE_FORCE',
                    'severity': 'MEDIUM',
                    'description': 'SSH service may be vulnerable to brute force attacks',
                    'port': port
                })
            elif port == 23:  # Telnet
                vulnerabilities.append({
                    'type': 'TELNET_CLEARTEXT',
                    'severity': 'HIGH',
                    'description': 'Telnet transmits credentials in cleartext',
                    'port': port
                })
            elif port == 3389:  # RDP
                vulnerabilities.append({
                    'type': 'RDP_BRUTE_FORCE',
                    'severity': 'MEDIUM',
                    'description': 'RDP service may be vulnerable to brute force attacks',
                    'port': port
                })
            elif port == 5900:  # VNC
                vulnerabilities.append({
                    'type': 'VNC_WEAK_AUTH',
                    'severity': 'HIGH',
                    'description': 'VNC may use weak authentication',
                    'port': port
                })
        
        except Exception as e:
            self.logger.debug(f"Error checking remote access vulnerabilities on {target}:{port}: {e}")
        
        return vulnerabilities
    
    def run_comprehensive_scan(self, targets, scan_type='tcp_syn'):
        """
        Run comprehensive port scan
        
        Args:
            targets (list): List of target IP addresses
            scan_type (str): Type of scan to perform
            
        Returns:
            dict: Comprehensive scan results
        """
        self.logger.info(f"Starting comprehensive {scan_type} scan on {len(targets)} targets")
        
        if scan_type == 'tcp_syn':
            results = self.tcp_syn_scan(targets)
        elif scan_type == 'tcp_connect':
            results = self.tcp_connect_scan(targets)
        elif scan_type == 'udp':
            results = self.udp_scan(targets)
        elif scan_type == 'stealth':
            results = self.stealth_scan(targets)
        else:
            self.logger.error(f"Unknown scan type: {scan_type}")
            return {}
        
        # Perform vulnerability scanning on open ports
        if self.config['vulnerability_checks']['enabled']:
            for target in targets:
                if target in results and results[target]['open_ports']:
                    vuln_results = self.vulnerability_scan([target], results[target]['open_ports'])
                    if target in vuln_results:
                        results[target]['vulnerabilities'] = vuln_results[target]['vulnerabilities']
        
        # Store results
        self.results['targets'] = targets
        self.results['scan_results'] = results
        
        # Generate statistics
        self._generate_scan_statistics(results)
        
        self.logger.info("Comprehensive scan completed")
        return results
    
    def _generate_scan_statistics(self, results):
        """Generate scan statistics"""
        stats = {
            'total_targets': len(results),
            'total_open_ports': sum(len(host['open_ports']) for host in results.values()),
            'total_vulnerabilities': sum(len(host.get('vulnerabilities', [])) for host in results.values()),
            'scan_duration': 'N/A',  # Would calculate from start/end times
            'success_rate': 'N/A'  # Would calculate from successful scans
        }
        
        self.results['statistics'] = stats
    
    def save_results(self, filename=None):
        """Save scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"port_scan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner for IT Environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 portscan.py --targets 192.168.1.1,192.168.1.2 --scan-type tcp_syn
  python3 portscan.py --targets 192.168.1.0/24 --ports 80,443,8080 --stealth
  python3 portscan.py --targets 192.168.1.1 --comprehensive --vulnerability-scan
        """
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        required=True,
        help='Target IP addresses (comma-separated or CIDR notation)'
    )
    
    parser.add_argument(
        '--ports',
        type=str,
        help='Ports to scan (comma-separated)'
    )
    
    parser.add_argument(
        '--scan-type',
        type=str,
        choices=['tcp_syn', 'tcp_connect', 'udp', 'stealth'],
        default='tcp_syn',
        help='Type of scan to perform'
    )
    
    parser.add_argument(
        '--comprehensive',
        action='store_true',
        help='Run comprehensive scan with vulnerability checks'
    )
    
    parser.add_argument(
        '--vulnerability-scan',
        action='store_true',
        help='Enable vulnerability scanning'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Use stealth scanning techniques'
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
    targets = []
    for target in args.targets.split(','):
        target = target.strip()
        if '/' in target:  # CIDR notation
            network = ipaddress.ip_network(target, strict=False)
            targets.extend([str(ip) for ip in network.hosts()])
        else:
            targets.append(target)
    
    # Parse ports
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Create scanner instance
    scanner = PortScanner(args.config)
    
    if args.verbose:
        scanner.logger.setLevel(logging.DEBUG)
    
    try:
        # Run scan
        if args.comprehensive:
            results = scanner.run_comprehensive_scan(targets, args.scan_type)
        else:
            if args.scan_type == 'tcp_syn':
                results = scanner.tcp_syn_scan(targets, ports)
            elif args.scan_type == 'tcp_connect':
                results = scanner.tcp_connect_scan(targets, ports)
            elif args.scan_type == 'udp':
                results = scanner.udp_scan(targets, ports)
            elif args.scan_type == 'stealth':
                results = scanner.stealth_scan(targets, ports)
            
            scanner.results['scan_results'] = results
        
        # Save results
        scanner.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("PORT SCAN SUMMARY")
        print("="*60)
        print(f"Targets Scanned: {len(targets)}")
        print(f"Scan Type: {args.scan_type}")
        
        total_open_ports = sum(len(host['open_ports']) for host in scanner.results['scan_results'].values())
        total_vulnerabilities = sum(len(host.get('vulnerabilities', [])) for host in scanner.results['scan_results'].values())
        
        print(f"Total Open Ports: {total_open_ports}")
        print(f"Total Vulnerabilities: {total_vulnerabilities}")
        
        print("\nOpen Ports by Target:")
        for target, result in scanner.results['scan_results'].items():
            if result['open_ports']:
                print(f"  {target}: {', '.join(map(str, result['open_ports']))}")
        
        print("\n[*] Port scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

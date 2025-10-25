#!/usr/bin/env python3
"""
Service Enumeration and Fingerprinting Tool
===========================================

This script performs comprehensive service enumeration and fingerprinting
for discovered services with vulnerability identification.

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
import base64
import hashlib

class ServiceEnumerator:
    def __init__(self, config_file=None):
        """
        Initialize the service enumerator
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "enumeration_timestamp": datetime.now().isoformat(),
            "targets": [],
            "services": {},
            "vulnerabilities": [],
            "statistics": {}
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('service_enum.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Service enumeration modules
        self.enumeration_modules = {
            'http': self._enumerate_http,
            'https': self._enumerate_https,
            'ssh': self._enumerate_ssh,
            'ftp': self._enumerate_ftp,
            'smtp': self._enumerate_smtp,
            'pop3': self._enumerate_pop3,
            'imap': self._enumerate_imap,
            'rdp': self._enumerate_rdp,
            'vnc': self._enumerate_vnc,
            'mysql': self._enumerate_mysql,
            'postgresql': self._enumerate_postgresql,
            'mssql': self._enumerate_mssql,
            'redis': self._enumerate_redis,
            'elasticsearch': self._enumerate_elasticsearch,
            'snmp': self._enumerate_snmp,
            'ldap': self._enumerate_ldap,
            'dns': self._enumerate_dns,
            'dhcp': self._enumerate_dhcp,
            'smb': self._enumerate_smb,
            'telnet': self._enumerate_telnet
        }
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            'outdated_versions': {
                'apache': [r'Apache/2\.2\.', r'Apache/2\.0\.'],
                'nginx': [r'nginx/1\.0\.', r'nginx/1\.1\.'],
                'iis': [r'IIS/6\.0', r'IIS/5\.0'],
                'openssh': [r'OpenSSH_4\.', r'OpenSSH_5\.'],
                'mysql': [r'MySQL 4\.', r'MySQL 5\.0\.'],
                'postgresql': [r'PostgreSQL 8\.', r'PostgreSQL 7\.']
            },
            'default_credentials': {
                'ftp': ['anonymous', 'ftp', 'admin', 'root'],
                'ssh': ['root', 'admin', 'user', 'guest'],
                'mysql': ['root', 'admin', 'user'],
                'postgresql': ['postgres', 'admin', 'user'],
                'redis': ['', 'default'],
                'elasticsearch': ['', 'elastic', 'admin']
            },
            'information_disclosure': {
                'server_info': [r'Server: .*', r'X-Powered-By: .*'],
                'version_info': [r'Version: .*', r'Build: .*'],
                'error_messages': [r'Error: .*', r'Exception: .*']
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'enumeration_settings': {
                'timeout': 10,
                'max_threads': 50,
                'stealth_mode': True,
                'aggressive_mode': False
            },
            'vulnerability_checks': {
                'enabled': True,
                'check_default_credentials': True,
                'check_outdated_versions': True,
                'check_information_disclosure': True,
                'check_ssl_vulnerabilities': True
            },
            'service_timeouts': {
                'http': 5,
                'https': 5,
                'ssh': 10,
                'ftp': 10,
                'smtp': 10,
                'pop3': 10,
                'imap': 10,
                'rdp': 10,
                'vnc': 10,
                'mysql': 10,
                'postgresql': 10,
                'mssql': 10,
                'redis': 10,
                'elasticsearch': 10,
                'snmp': 10,
                'ldap': 10,
                'dns': 5,
                'dhcp': 5,
                'smb': 10,
                'telnet': 10
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
    
    def enumerate_service(self, target, port, service_type):
        """
        Enumerate a specific service
        
        Args:
            target (str): Target IP address
            port (int): Port number
            service_type (str): Type of service
            
        Returns:
            dict: Enumeration results
        """
        self.logger.info(f"Enumerating {service_type} service on {target}:{port}")
        
        result = {
            'target': target,
            'port': port,
            'service_type': service_type,
            'banner': '',
            'version': '',
            'vulnerabilities': [],
            'enumeration_time': datetime.now().isoformat()
        }
        
        try:
            # Get service banner
            banner = self._get_service_banner(target, port, service_type)
            result['banner'] = banner
            
            # Parse version information
            version = self._parse_version(banner, service_type)
            result['version'] = version
            
            # Run service-specific enumeration
            if service_type in self.enumeration_modules:
                enum_result = self.enumeration_modules[service_type](target, port, banner)
                result.update(enum_result)
            
            # Check for vulnerabilities
            if self.config['vulnerability_checks']['enabled']:
                vulnerabilities = self._check_vulnerabilities(target, port, service_type, banner, version)
                result['vulnerabilities'] = vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error enumerating {service_type} on {target}:{port}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _get_service_banner(self, target, port, service_type):
        """Get service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['service_timeouts'].get(service_type, 10))
            sock.connect((target, port))
            
            # Send appropriate probe based on service type
            if service_type in ['http', 'https']:
                probe = f'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n'
            elif service_type == 'ftp':
                probe = ''  # FTP sends banner automatically
            elif service_type == 'ssh':
                probe = ''  # SSH sends banner automatically
            elif service_type == 'smtp':
                probe = ''  # SMTP sends banner automatically
            elif service_type == 'pop3':
                probe = ''  # POP3 sends banner automatically
            elif service_type == 'imap':
                probe = ''  # IMAP sends banner automatically
            elif service_type == 'rdp':
                probe = ''  # RDP sends banner automatically
            elif service_type == 'vnc':
                probe = ''  # VNC sends banner automatically
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
            elif service_type == 'snmp':
                probe = ''  # SNMP sends banner automatically
            elif service_type == 'ldap':
                probe = ''  # LDAP sends banner automatically
            elif service_type == 'dns':
                probe = ''  # DNS sends banner automatically
            elif service_type == 'dhcp':
                probe = ''  # DHCP sends banner automatically
            elif service_type == 'smb':
                probe = ''  # SMB sends banner automatically
            elif service_type == 'telnet':
                probe = ''  # Telnet sends banner automatically
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
    
    def _parse_version(self, banner, service_type):
        """Parse version information from banner"""
        if not banner:
            return 'Unknown'
        
        # Common version patterns
        version_patterns = {
            'apache': r'Apache/([0-9.]+)',
            'nginx': r'nginx/([0-9.]+)',
            'iis': r'IIS/([0-9.]+)',
            'openssh': r'OpenSSH_([0-9.]+)',
            'mysql': r'MySQL ([0-9.]+)',
            'postgresql': r'PostgreSQL ([0-9.]+)',
            'redis': r'Redis server v([0-9.]+)',
            'elasticsearch': r'"version":{"number":"([0-9.]+)"',
            'vsftpd': r'vsftpd ([0-9.]+)',
            'proftpd': r'ProFTPD ([0-9.]+)',
            'sendmail': r'Sendmail ([0-9.]+)',
            'postfix': r'Postfix ([0-9.]+)',
            'dovecot': r'Dovecot ([0-9.]+)',
            'tightvnc': r'TightVNC ([0-9.]+)',
            'realvnc': r'RealVNC ([0-9.]+)'
        }
        
        for service, pattern in version_patterns.items():
            if service in banner.lower():
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return 'Unknown'
    
    def _enumerate_http(self, target, port, banner):
        """Enumerate HTTP service"""
        result = {
            'http_methods': [],
            'http_headers': {},
            'http_directories': [],
            'http_files': [],
            'http_technologies': []
        }
        
        try:
            # Get HTTP response
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Send HTTP request
            request = f'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n'
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse HTTP headers
            headers = {}
            for line in response.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            result['http_headers'] = headers
            
            # Extract technologies
            if 'Server:' in headers:
                result['http_technologies'].append(headers['Server'])
            if 'X-Powered-By:' in headers:
                result['http_technologies'].append(headers['X-Powered-By'])
            if 'X-AspNet-Version:' in headers:
                result['http_technologies'].append(f"ASP.NET {headers['X-AspNet-Version']}")
            
            # Check for common directories
            common_dirs = ['/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin', '/cpanel']
            for directory in common_dirs:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((target, port))
                    
                    request = f'GET {directory} HTTP/1.1\r\nHost: {target}\r\n\r\n'
                    sock.send(request.encode())
                    
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if '200 OK' in response:
                        result['http_directories'].append(directory)
                        self.logger.info(f"Found directory: {directory}")
                
                except Exception:
                    pass
            
        except Exception as e:
            self.logger.error(f"Error enumerating HTTP service: {e}")
        
        return result
    
    def _enumerate_https(self, target, port, banner):
        """Enumerate HTTPS service"""
        result = {
            'ssl_certificate': {},
            'ssl_ciphers': [],
            'ssl_vulnerabilities': []
        }
        
        try:
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    result['ssl_certificate'] = {
                        'subject': cert.get('subject', []),
                        'issuer': cert.get('issuer', []),
                        'not_before': cert.get('notBefore', ''),
                        'not_after': cert.get('notAfter', ''),
                        'serial_number': cert.get('serialNumber', ''),
                        'version': cert.get('version', '')
                    }
                    
                    # Check for weak ciphers
                    cipher = ssock.cipher()
                    if cipher:
                        result['ssl_ciphers'].append({
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        })
                        
                        # Check for weak ciphers
                        if cipher[0] in ['RC4', 'DES', '3DES']:
                            result['ssl_vulnerabilities'].append({
                                'type': 'WEAK_CIPHER',
                                'severity': 'MEDIUM',
                                'description': f'Weak cipher detected: {cipher[0]}'
                            })
            
        except Exception as e:
            self.logger.error(f"Error enumerating HTTPS service: {e}")
        
        return result
    
    def _enumerate_ssh(self, target, port, banner):
        """Enumerate SSH service"""
        result = {
            'ssh_version': '',
            'ssh_algorithms': {},
            'ssh_vulnerabilities': []
        }
        
        try:
            # Parse SSH version
            if 'SSH' in banner:
                version_match = re.search(r'SSH-([0-9.]+)', banner)
                if version_match:
                    result['ssh_version'] = version_match.group(1)
            
            # Check for known vulnerabilities
            if 'OpenSSH_4.' in banner or 'OpenSSH_5.' in banner:
                result['ssh_vulnerabilities'].append({
                    'type': 'OUTDATED_SSH',
                    'severity': 'HIGH',
                    'description': 'Outdated OpenSSH version detected'
                })
            
            # Check for weak algorithms
            if 'SSH-1.' in banner:
                result['ssh_vulnerabilities'].append({
                    'type': 'SSH1_PROTOCOL',
                    'severity': 'CRITICAL',
                    'description': 'SSH version 1 protocol detected'
                })
        
        except Exception as e:
            self.logger.error(f"Error enumerating SSH service: {e}")
        
        return result
    
    def _enumerate_ftp(self, target, port, banner):
        """Enumerate FTP service"""
        result = {
            'ftp_version': '',
            'ftp_features': [],
            'ftp_vulnerabilities': []
        }
        
        try:
            # Parse FTP version
            if 'FTP' in banner:
                version_match = re.search(r'FTP server \(([^)]+)\)', banner)
                if version_match:
                    result['ftp_version'] = version_match.group(1)
            
            # Check for anonymous access
            if 'anonymous' in banner.lower():
                result['ftp_vulnerabilities'].append({
                    'type': 'ANONYMOUS_FTP',
                    'severity': 'MEDIUM',
                    'description': 'Anonymous FTP access enabled'
                })
            
            # Check for outdated versions
            if 'vsftpd 2.2.' in banner or 'vsftpd 2.0.' in banner:
                result['ftp_vulnerabilities'].append({
                    'type': 'OUTDATED_FTP',
                    'severity': 'HIGH',
                    'description': 'Outdated vsftpd version detected'
                })
        
        except Exception as e:
            self.logger.error(f"Error enumerating FTP service: {e}")
        
        return result
    
    def _enumerate_smtp(self, target, port, banner):
        """Enumerate SMTP service"""
        result = {
            'smtp_version': '',
            'smtp_features': [],
            'smtp_vulnerabilities': []
        }
        
        try:
            # Parse SMTP version
            if 'SMTP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['smtp_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Postfix' in banner:
                result['smtp_features'].append('Postfix')
            elif 'Sendmail' in banner:
                result['smtp_features'].append('Sendmail')
            elif 'Exchange' in banner:
                result['smtp_features'].append('Microsoft Exchange')
            
            # Check for open relay
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                
                # Send SMTP commands
                sock.recv(1024)  # Read banner
                sock.send(b'HELO test.com\r\n')
                sock.recv(1024)
                sock.send(b'MAIL FROM: test@test.com\r\n')
                sock.recv(1024)
                sock.send(b'RCPT TO: test@external.com\r\n')
                response = sock.recv(1024)
                sock.close()
                
                if '250' in response.decode():
                    result['smtp_vulnerabilities'].append({
                        'type': 'OPEN_RELAY',
                        'severity': 'HIGH',
                        'description': 'SMTP open relay detected'
                    })
            
            except Exception:
                pass
        
        except Exception as e:
            self.logger.error(f"Error enumerating SMTP service: {e}")
        
        return result
    
    def _enumerate_pop3(self, target, port, banner):
        """Enumerate POP3 service"""
        result = {
            'pop3_version': '',
            'pop3_features': [],
            'pop3_vulnerabilities': []
        }
        
        try:
            # Parse POP3 version
            if 'POP3' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['pop3_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Dovecot' in banner:
                result['pop3_features'].append('Dovecot')
            elif 'Cyrus' in banner:
                result['pop3_features'].append('Cyrus')
        
        except Exception as e:
            self.logger.error(f"Error enumerating POP3 service: {e}")
        
        return result
    
    def _enumerate_imap(self, target, port, banner):
        """Enumerate IMAP service"""
        result = {
            'imap_version': '',
            'imap_features': [],
            'imap_vulnerabilities': []
        }
        
        try:
            # Parse IMAP version
            if 'IMAP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['imap_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Dovecot' in banner:
                result['imap_features'].append('Dovecot')
            elif 'Cyrus' in banner:
                result['imap_features'].append('Cyrus')
        
        except Exception as e:
            self.logger.error(f"Error enumerating IMAP service: {e}")
        
        return result
    
    def _enumerate_rdp(self, target, port, banner):
        """Enumerate RDP service"""
        result = {
            'rdp_version': '',
            'rdp_features': [],
            'rdp_vulnerabilities': []
        }
        
        try:
            # Parse RDP version
            if 'RDP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['rdp_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'TermService' in banner:
                result['rdp_features'].append('TermService')
            
            # Check for known vulnerabilities
            result['rdp_vulnerabilities'].append({
                'type': 'RDP_BRUTE_FORCE',
                'severity': 'MEDIUM',
                'description': 'RDP service may be vulnerable to brute force attacks'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating RDP service: {e}")
        
        return result
    
    def _enumerate_vnc(self, target, port, banner):
        """Enumerate VNC service"""
        result = {
            'vnc_version': '',
            'vnc_features': [],
            'vnc_vulnerabilities': []
        }
        
        try:
            # Parse VNC version
            if 'VNC' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['vnc_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'TightVNC' in banner:
                result['vnc_features'].append('TightVNC')
            elif 'RealVNC' in banner:
                result['vnc_features'].append('RealVNC')
            elif 'UltraVNC' in banner:
                result['vnc_features'].append('UltraVNC')
            
            # Check for known vulnerabilities
            result['vnc_vulnerabilities'].append({
                'type': 'VNC_WEAK_AUTH',
                'severity': 'HIGH',
                'description': 'VNC may use weak authentication'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating VNC service: {e}")
        
        return result
    
    def _enumerate_mysql(self, target, port, banner):
        """Enumerate MySQL service"""
        result = {
            'mysql_version': '',
            'mysql_features': [],
            'mysql_vulnerabilities': []
        }
        
        try:
            # Parse MySQL version
            if 'MySQL' in banner:
                version_match = re.search(r'MySQL ([0-9.]+)', banner)
                if version_match:
                    result['mysql_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'MariaDB' in banner:
                result['mysql_features'].append('MariaDB')
            elif 'Percona' in banner:
                result['mysql_features'].append('Percona')
            
            # Check for known vulnerabilities
            if 'MySQL 4.' in banner or 'MySQL 5.0.' in banner:
                result['mysql_vulnerabilities'].append({
                    'type': 'OUTDATED_MYSQL',
                    'severity': 'HIGH',
                    'description': 'Outdated MySQL version detected'
                })
            
            # Check for default credentials
            result['mysql_vulnerabilities'].append({
                'type': 'DEFAULT_CREDENTIALS',
                'severity': 'HIGH',
                'description': 'MySQL default credentials may be in use'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating MySQL service: {e}")
        
        return result
    
    def _enumerate_postgresql(self, target, port, banner):
        """Enumerate PostgreSQL service"""
        result = {
            'postgresql_version': '',
            'postgresql_features': [],
            'postgresql_vulnerabilities': []
        }
        
        try:
            # Parse PostgreSQL version
            if 'PostgreSQL' in banner:
                version_match = re.search(r'PostgreSQL ([0-9.]+)', banner)
                if version_match:
                    result['postgresql_version'] = version_match.group(1)
            
            # Check for known vulnerabilities
            if 'PostgreSQL 8.' in banner or 'PostgreSQL 7.' in banner:
                result['postgresql_vulnerabilities'].append({
                    'type': 'OUTDATED_POSTGRESQL',
                    'severity': 'HIGH',
                    'description': 'Outdated PostgreSQL version detected'
                })
            
            # Check for default credentials
            result['postgresql_vulnerabilities'].append({
                'type': 'DEFAULT_CREDENTIALS',
                'severity': 'HIGH',
                'description': 'PostgreSQL default credentials may be in use'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating PostgreSQL service: {e}")
        
        return result
    
    def _enumerate_mssql(self, target, port, banner):
        """Enumerate Microsoft SQL Server service"""
        result = {
            'mssql_version': '',
            'mssql_features': [],
            'mssql_vulnerabilities': []
        }
        
        try:
            # Parse SQL Server version
            if 'SQL Server' in banner:
                version_match = re.search(r'SQL Server ([0-9.]+)', banner)
                if version_match:
                    result['mssql_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Microsoft SQL Server' in banner:
                result['mssql_features'].append('Microsoft SQL Server')
            
            # Check for known vulnerabilities
            if 'SQL Server 2000' in banner or 'SQL Server 2005' in banner:
                result['mssql_vulnerabilities'].append({
                    'type': 'OUTDATED_MSSQL',
                    'severity': 'HIGH',
                    'description': 'Outdated SQL Server version detected'
                })
            
            # Check for default credentials
            result['mssql_vulnerabilities'].append({
                'type': 'DEFAULT_CREDENTIALS',
                'severity': 'HIGH',
                'description': 'SQL Server default credentials may be in use'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating SQL Server service: {e}")
        
        return result
    
    def _enumerate_redis(self, target, port, banner):
        """Enumerate Redis service"""
        result = {
            'redis_version': '',
            'redis_features': [],
            'redis_vulnerabilities': []
        }
        
        try:
            # Parse Redis version
            if 'Redis' in banner:
                version_match = re.search(r'Redis server v([0-9.]+)', banner)
                if version_match:
                    result['redis_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Redis' in banner:
                result['redis_features'].append('Redis')
            
            # Check for known vulnerabilities
            result['redis_vulnerabilities'].append({
                'type': 'REDIS_NO_AUTH',
                'severity': 'CRITICAL',
                'description': 'Redis may be running without authentication'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating Redis service: {e}")
        
        return result
    
    def _enumerate_elasticsearch(self, target, port, banner):
        """Enumerate Elasticsearch service"""
        result = {
            'elasticsearch_version': '',
            'elasticsearch_features': [],
            'elasticsearch_vulnerabilities': []
        }
        
        try:
            # Parse Elasticsearch version
            if 'elasticsearch' in banner:
                version_match = re.search(r'"number":"([0-9.]+)"', banner)
                if version_match:
                    result['elasticsearch_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'elasticsearch' in banner:
                result['elasticsearch_features'].append('Elasticsearch')
            
            # Check for known vulnerabilities
            if '1.' in banner or '2.' in banner:
                result['elasticsearch_vulnerabilities'].append({
                    'type': 'OUTDATED_ELASTICSEARCH',
                    'severity': 'HIGH',
                    'description': 'Outdated Elasticsearch version detected'
                })
            
            # Check for default credentials
            result['elasticsearch_vulnerabilities'].append({
                'type': 'DEFAULT_CREDENTIALS',
                'severity': 'MEDIUM',
                'description': 'Elasticsearch default credentials may be in use'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating Elasticsearch service: {e}")
        
        return result
    
    def _enumerate_snmp(self, target, port, banner):
        """Enumerate SNMP service"""
        result = {
            'snmp_version': '',
            'snmp_features': [],
            'snmp_vulnerabilities': []
        }
        
        try:
            # Parse SNMP version
            if 'SNMP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['snmp_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'SNMP' in banner:
                result['snmp_features'].append('SNMP')
            
            # Check for known vulnerabilities
            result['snmp_vulnerabilities'].append({
                'type': 'SNMP_DEFAULT_COMMUNITY',
                'severity': 'HIGH',
                'description': 'SNMP may be using default community strings'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating SNMP service: {e}")
        
        return result
    
    def _enumerate_ldap(self, target, port, banner):
        """Enumerate LDAP service"""
        result = {
            'ldap_version': '',
            'ldap_features': [],
            'ldap_vulnerabilities': []
        }
        
        try:
            # Parse LDAP version
            if 'LDAP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['ldap_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Active Directory' in banner:
                result['ldap_features'].append('Active Directory')
            elif 'OpenLDAP' in banner:
                result['ldap_features'].append('OpenLDAP')
            
            # Check for known vulnerabilities
            result['ldap_vulnerabilities'].append({
                'type': 'LDAP_ANONYMOUS_BIND',
                'severity': 'MEDIUM',
                'description': 'LDAP may allow anonymous binding'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating LDAP service: {e}")
        
        return result
    
    def _enumerate_dns(self, target, port, banner):
        """Enumerate DNS service"""
        result = {
            'dns_version': '',
            'dns_features': [],
            'dns_vulnerabilities': []
        }
        
        try:
            # Parse DNS version
            if 'DNS' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['dns_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'BIND' in banner:
                result['dns_features'].append('BIND')
            elif 'PowerDNS' in banner:
                result['dns_features'].append('PowerDNS')
            elif 'Unbound' in banner:
                result['dns_features'].append('Unbound')
            
            # Check for known vulnerabilities
            result['dns_vulnerabilities'].append({
                'type': 'DNS_ZONE_TRANSFER',
                'severity': 'MEDIUM',
                'description': 'DNS may allow zone transfers'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating DNS service: {e}")
        
        return result
    
    def _enumerate_dhcp(self, target, port, banner):
        """Enumerate DHCP service"""
        result = {
            'dhcp_version': '',
            'dhcp_features': [],
            'dhcp_vulnerabilities': []
        }
        
        try:
            # Parse DHCP version
            if 'DHCP' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['dhcp_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'ISC DHCP' in banner:
                result['dhcp_features'].append('ISC DHCP')
            elif 'Microsoft DHCP' in banner:
                result['dhcp_features'].append('Microsoft DHCP')
            
            # Check for known vulnerabilities
            result['dhcp_vulnerabilities'].append({
                'type': 'DHCP_SPOOFING',
                'severity': 'HIGH',
                'description': 'DHCP may be vulnerable to spoofing attacks'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating DHCP service: {e}")
        
        return result
    
    def _enumerate_smb(self, target, port, banner):
        """Enumerate SMB service"""
        result = {
            'smb_version': '',
            'smb_features': [],
            'smb_vulnerabilities': []
        }
        
        try:
            # Parse SMB version
            if 'SMB' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['smb_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Samba' in banner:
                result['smb_features'].append('Samba')
            elif 'Microsoft' in banner:
                result['smb_features'].append('Microsoft SMB')
            
            # Check for known vulnerabilities
            result['smb_vulnerabilities'].append({
                'type': 'SMB_NULL_SESSION',
                'severity': 'HIGH',
                'description': 'SMB may allow null session connections'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating SMB service: {e}")
        
        return result
    
    def _enumerate_telnet(self, target, port, banner):
        """Enumerate Telnet service"""
        result = {
            'telnet_version': '',
            'telnet_features': [],
            'telnet_vulnerabilities': []
        }
        
        try:
            # Parse Telnet version
            if 'Telnet' in banner:
                version_match = re.search(r'([0-9.]+)', banner)
                if version_match:
                    result['telnet_version'] = version_match.group(1)
            
            # Check for information disclosure
            if 'Telnet' in banner:
                result['telnet_features'].append('Telnet')
            
            # Check for known vulnerabilities
            result['telnet_vulnerabilities'].append({
                'type': 'TELNET_CLEARTEXT',
                'severity': 'CRITICAL',
                'description': 'Telnet transmits credentials in cleartext'
            })
        
        except Exception as e:
            self.logger.error(f"Error enumerating Telnet service: {e}")
        
        return result
    
    def _check_vulnerabilities(self, target, port, service_type, banner, version):
        """Check for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for outdated versions
            if self.config['vulnerability_checks']['check_outdated_versions']:
                outdated_vulns = self._check_outdated_versions(service_type, version)
                vulnerabilities.extend(outdated_vulns)
            
            # Check for information disclosure
            if self.config['vulnerability_checks']['check_information_disclosure']:
                info_vulns = self._check_information_disclosure(banner)
                vulnerabilities.extend(info_vulns)
            
            # Check for default credentials
            if self.config['vulnerability_checks']['check_default_credentials']:
                cred_vulns = self._check_default_credentials(service_type)
                vulnerabilities.extend(cred_vulns)
            
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_outdated_versions(self, service_type, version):
        """Check for outdated versions"""
        vulnerabilities = []
        
        if service_type in self.vulnerability_patterns['outdated_versions']:
            patterns = self.vulnerability_patterns['outdated_versions'][service_type]
            for pattern in patterns:
                if re.search(pattern, version):
                    vulnerabilities.append({
                        'type': 'OUTDATED_VERSION',
                        'severity': 'HIGH',
                        'description': f'Outdated {service_type} version detected: {version}'
                    })
                    break
        
        return vulnerabilities
    
    def _check_information_disclosure(self, banner):
        """Check for information disclosure"""
        vulnerabilities = []
        
        for category, patterns in self.vulnerability_patterns['information_disclosure'].items():
            for pattern in patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'INFORMATION_DISCLOSURE',
                        'severity': 'LOW',
                        'description': f'Information disclosure detected: {category}'
                    })
                    break
        
        return vulnerabilities
    
    def _check_default_credentials(self, service_type):
        """Check for default credentials"""
        vulnerabilities = []
        
        if service_type in self.vulnerability_patterns['default_credentials']:
            vulnerabilities.append({
                'type': 'DEFAULT_CREDENTIALS',
                'severity': 'HIGH',
                'description': f'{service_type} default credentials may be in use'
            })
        
        return vulnerabilities
    
    def run_comprehensive_enumeration(self, targets):
        """
        Run comprehensive service enumeration
        
        Args:
            targets (list): List of target services (target:port:service)
            
        Returns:
            dict: Comprehensive enumeration results
        """
        self.logger.info(f"Starting comprehensive service enumeration on {len(targets)} targets")
        
        enumeration_results = {}
        
        for target_info in targets:
            if ':' in target_info:
                parts = target_info.split(':')
                if len(parts) >= 2:
                    target = parts[0]
                    port = int(parts[1])
                    service_type = parts[2] if len(parts) > 2 else 'unknown'
                    
                    result = self.enumerate_service(target, port, service_type)
                    enumeration_results[f"{target}:{port}"] = result
                    
                    self.logger.info(f"Enumerated {target}:{port} - {service_type}")
        
        # Store results
        self.results['targets'] = targets
        self.results['services'] = enumeration_results
        
        # Generate statistics
        self._generate_enumeration_statistics(enumeration_results)
        
        self.logger.info("Comprehensive enumeration completed")
        return enumeration_results
    
    def _generate_enumeration_statistics(self, results):
        """Generate enumeration statistics"""
        stats = {
            'total_services': len(results),
            'total_vulnerabilities': sum(len(service.get('vulnerabilities', [])) for service in results.values()),
            'services_by_type': {},
            'vulnerabilities_by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
        
        # Count services by type
        for service in results.values():
            service_type = service.get('service_type', 'unknown')
            stats['services_by_type'][service_type] = stats['services_by_type'].get(service_type, 0) + 1
        
        # Count vulnerabilities by severity
        for service in results.values():
            for vuln in service.get('vulnerabilities', []):
                severity = vuln.get('severity', 'LOW')
                stats['vulnerabilities_by_severity'][severity] += 1
        
        self.results['statistics'] = stats
    
    def save_results(self, filename=None):
        """Save enumeration results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"service_enum_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Service Enumeration and Fingerprinting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 service_enum.py --targets 192.168.1.1:80:http,192.168.1.1:443:https
  python3 service_enum.py --targets 192.168.1.1:22:ssh --vulnerability-scan
  python3 service_enum.py --targets 192.168.1.1:3306:mysql --aggressive
        """
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        required=True,
        help='Target services (format: ip:port:service, comma-separated)'
    )
    
    parser.add_argument(
        '--vulnerability-scan',
        action='store_true',
        help='Enable vulnerability scanning'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Use aggressive enumeration techniques'
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
    
    # Create enumerator instance
    enumerator = ServiceEnumerator(args.config)
    
    if args.verbose:
        enumerator.logger.setLevel(logging.DEBUG)
    
    try:
        # Run enumeration
        results = enumerator.run_comprehensive_enumeration(targets)
        
        # Save results
        enumerator.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("SERVICE ENUMERATION SUMMARY")
        print("="*60)
        print(f"Services Enumerated: {len(results)}")
        
        total_vulnerabilities = sum(len(service.get('vulnerabilities', [])) for service in results.values())
        print(f"Total Vulnerabilities: {total_vulnerabilities}")
        
        print("\nServices by Type:")
        for service_type, count in enumerator.results['statistics']['services_by_type'].items():
            print(f"  {service_type}: {count}")
        
        print("\nVulnerabilities by Severity:")
        for severity, count in enumerator.results['statistics']['vulnerabilities_by_severity'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print("\n[*] Service enumeration completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during enumeration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

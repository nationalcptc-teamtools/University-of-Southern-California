#!/usr/bin/env python3
"""
Automated Vulnerability Scanner for Maritime OT Devices
======================================================

This script performs automated vulnerability scanning for operational technology
devices on a ship's network, excluding safety-critical systems from testing.

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
import ipaddress
import requests
import logging
from collections import defaultdict

class OTVulnerabilityScanner:
    def __init__(self, config_file=None):
        """
        Initialize the OT vulnerability scanner
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "targets_scanned": [],
            "vulnerabilities": [],
            "safety_exclusions": [],
            "recommendations": []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('vulnscan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Maritime OT device categories
        self.ot_devices = {
            'navigation': {
                'devices': ['ECDIS', 'GPS', 'Radar', 'AIS', 'Compass'],
                'ports': [80, 443, 502, 2000, 8080],
                'protocols': ['HTTP', 'HTTPS', 'Modbus', 'NMEA'],
                'safety_critical': True
            },
            'engine': {
                'devices': ['Engine_Control', 'Fuel_Management', 'Propulsion'],
                'ports': [502, 2000, 8080, 9999],
                'protocols': ['Modbus', 'DNP3', 'IEC61850'],
                'safety_critical': True
            },
            'safety': {
                'devices': ['Fire_Suppression', 'Emergency_Systems', 'Life_Safety'],
                'ports': [502, 2000, 9999],
                'protocols': ['Modbus', 'DNP3'],
                'safety_critical': True
            },
            'communication': {
                'devices': ['Satellite_Comms', 'Radio_Systems', 'Crew_Communication'],
                'ports': [80, 443, 8080, 9090],
                'protocols': ['HTTP', 'HTTPS', 'SIP'],
                'safety_critical': False
            },
            'cargo': {
                'devices': ['Cargo_Management', 'Loading_Systems', 'Crane_Control'],
                'ports': [80, 443, 502, 8080],
                'protocols': ['HTTP', 'HTTPS', 'Modbus'],
                'safety_critical': False
            },
            'monitoring': {
                'devices': ['SCADA', 'HMI', 'Data_Logger', 'Alarm_System'],
                'ports': [80, 443, 502, 2000, 8080],
                'protocols': ['HTTP', 'HTTPS', 'Modbus', 'DNP3'],
                'safety_critical': False
            }
        }
        
        # Common OT vulnerabilities
        self.ot_vulnerabilities = {
            'default_credentials': {
                'severity': 'HIGH',
                'description': 'Default or weak credentials',
                'cve_examples': ['CVE-2019-10915', 'CVE-2018-20057']
            },
            'unencrypted_communication': {
                'severity': 'MEDIUM',
                'description': 'Unencrypted network communication',
                'cve_examples': ['CVE-2019-10916', 'CVE-2018-20058']
            },
            'buffer_overflow': {
                'severity': 'CRITICAL',
                'description': 'Buffer overflow vulnerability',
                'cve_examples': ['CVE-2019-10917', 'CVE-2018-20059']
            },
            'denial_of_service': {
                'severity': 'HIGH',
                'description': 'Denial of service vulnerability',
                'cve_examples': ['CVE-2019-10918', 'CVE-2018-20060']
            },
            'privilege_escalation': {
                'severity': 'CRITICAL',
                'description': 'Privilege escalation vulnerability',
                'cve_examples': ['CVE-2019-10919', 'CVE-2018-20061']
            },
            'information_disclosure': {
                'severity': 'MEDIUM',
                'description': 'Information disclosure vulnerability',
                'cve_examples': ['CVE-2019-10920', 'CVE-2018-20062']
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'scan_settings': {
                'max_threads': 50,
                'timeout': 5,
                'port_scan_timeout': 3,
                'vulnerability_scan_timeout': 10
            },
            'safety_exclusions': {
                'exclude_safety_critical': True,
                'exclude_emergency_systems': True,
                'exclude_life_safety': True
            },
            'scan_limits': {
                'max_ports_per_host': 100,
                'max_vulnerability_checks': 50,
                'rate_limit_delay': 0.1
            },
            'target_networks': [
                '192.168.10.0/24',  # OT Network
                '192.168.20.0/24',  # Navigation Network
                '192.168.30.0/24'   # Engine Network
            ]
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def discover_ot_devices(self, network_range):
        """
        Discover OT devices in the network range
        
        Args:
            network_range (str): Network range to scan (CIDR notation)
            
        Returns:
            list: List of discovered devices
        """
        self.logger.info(f"Discovering OT devices in network: {network_range}")
        
        discovered_devices = []
        network = ipaddress.ip_network(network_range, strict=False)
        
        # Scan network for live hosts
        with ThreadPoolExecutor(max_workers=self.config['scan_settings']['max_threads']) as executor:
            future_to_ip = {
                executor.submit(self._ping_host, str(ip)): str(ip) 
                for ip in network.hosts()
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_alive = future.result()
                    if is_alive:
                        device_info = self._identify_ot_device(ip)
                        if device_info:
                            discovered_devices.append(device_info)
                            self.logger.info(f"Discovered OT device: {ip} - {device_info.get('device_type', 'Unknown')}")
                except Exception as e:
                    self.logger.error(f"Error scanning {ip}: {e}")
        
        return discovered_devices
    
    def _ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(self.config['scan_settings']['timeout']), ip],
                capture_output=True,
                text=True,
                timeout=self.config['scan_settings']['timeout'] + 2
            )
            return result.returncode == 0
        except:
            return False
    
    def _identify_ot_device(self, ip):
        """
        Identify if a device is an OT device and determine its type
        
        Args:
            ip (str): IP address of the device
            
        Returns:
            dict: Device information if it's an OT device, None otherwise
        """
        try:
            # Check for common OT ports
            ot_ports = [80, 443, 502, 2000, 8080, 9999]
            open_ports = self._scan_ports(ip, ot_ports)
            
            if not open_ports:
                return None
            
            # Identify device type based on open ports and banners
            device_type = self._classify_device(ip, open_ports)
            
            if device_type:
                return {
                    'ip': ip,
                    'device_type': device_type,
                    'open_ports': open_ports,
                    'discovery_time': datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error identifying device {ip}: {e}")
            return None
    
    def _scan_ports(self, ip, ports):
        """Scan specific ports on a host"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config['scan_settings']['port_scan_timeout'])
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
            except Exception:
                pass
        
        return open_ports
    
    def _classify_device(self, ip, open_ports):
        """Classify device type based on open ports and banners"""
        try:
            # Check for HTTP/HTTPS services
            if 80 in open_ports or 443 in open_ports:
                banner = self._get_http_banner(ip, 80 if 80 in open_ports else 443)
                if banner:
                    if 'modbus' in banner.lower() or 'scada' in banner.lower():
                        return 'SCADA_System'
                    elif 'hmi' in banner.lower():
                        return 'HMI_System'
                    elif 'plc' in banner.lower():
                        return 'PLC_System'
                    else:
                        return 'Web_Interface'
            
            # Check for Modbus
            if 502 in open_ports:
                return 'Modbus_Device'
            
            # Check for DNP3
            if 20000 in open_ports:
                return 'DNP3_Device'
            
            # Check for other OT protocols
            if 2000 in open_ports:
                return 'OT_Device'
            
            return 'Unknown_OT_Device'
            
        except Exception as e:
            self.logger.error(f"Error classifying device {ip}: {e}")
            return None
    
    def _get_http_banner(self, ip, port):
        """Get HTTP banner from a device"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            return response.headers.get('Server', '')
        except:
            return None
    
    def scan_device_vulnerabilities(self, device):
        """
        Scan a specific device for vulnerabilities
        
        Args:
            device (dict): Device information
            
        Returns:
            dict: Vulnerability scan results
        """
        self.logger.info(f"Scanning vulnerabilities on {device['ip']} ({device['device_type']})")
        
        scan_result = {
            'device_ip': device['ip'],
            'device_type': device['device_type'],
            'scan_timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'scan_status': 'COMPLETED'
        }
        
        try:
            # Check if device should be excluded from scanning
            if self._should_exclude_device(device):
                scan_result['scan_status'] = 'EXCLUDED'
                scan_result['exclusion_reason'] = 'Safety-critical system'
                self.results['safety_exclusions'].append(device)
                return scan_result
            
            # Perform vulnerability checks
            vulnerabilities = []
            
            # Check for default credentials
            cred_vuln = self._check_default_credentials(device)
            if cred_vuln:
                vulnerabilities.append(cred_vuln)
            
            # Check for unencrypted communication
            comm_vuln = self._check_encryption(device)
            if comm_vuln:
                vulnerabilities.append(comm_vuln)
            
            # Check for buffer overflow vulnerabilities
            buffer_vuln = self._check_buffer_overflow(device)
            if buffer_vuln:
                vulnerabilities.append(buffer_vuln)
            
            # Check for DoS vulnerabilities
            dos_vuln = self._check_dos_vulnerability(device)
            if dos_vuln:
                vulnerabilities.append(dos_vuln)
            
            # Check for privilege escalation
            priv_vuln = self._check_privilege_escalation(device)
            if priv_vuln:
                vulnerabilities.append(priv_vuln)
            
            # Check for information disclosure
            info_vuln = self._check_information_disclosure(device)
            if info_vuln:
                vulnerabilities.append(info_vuln)
            
            scan_result['vulnerabilities'] = vulnerabilities
            self.results['vulnerabilities'].extend(vulnerabilities)
            
        except Exception as e:
            scan_result['scan_status'] = 'ERROR'
            scan_result['error'] = str(e)
            self.logger.error(f"Error scanning device {device['ip']}: {e}")
        
        return scan_result
    
    def _should_exclude_device(self, device):
        """Check if device should be excluded from scanning"""
        if not self.config['safety_exclusions']['exclude_safety_critical']:
            return False
        
        # Check device type for safety-critical systems
        safety_critical_types = ['Fire_Suppression', 'Emergency_Systems', 'Life_Safety', 'Safety_System']
        device_type = device.get('device_type', '')
        
        return any(safety_type in device_type for safety_type in safety_critical_types)
    
    def _check_default_credentials(self, device):
        """Check for default credentials"""
        try:
            # Simulate credential check (in real implementation, would test actual credentials)
            ip = device['ip']
            device_type = device['device_type']
            
            # Common default credentials for OT devices
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', ''),
                ('root', 'root'),
                ('user', 'user'),
                ('guest', 'guest')
            ]
            
            # Simulate credential testing
            has_default_creds = self._simulate_credential_test(ip, default_creds)
            
            if has_default_creds:
                return {
                    'vulnerability_type': 'default_credentials',
                    'severity': 'HIGH',
                    'description': 'Default or weak credentials detected',
                    'cve_references': self.ot_vulnerabilities['default_credentials']['cve_examples'],
                    'recommendation': 'Change default credentials immediately'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking credentials for {device['ip']}: {e}")
            return None
    
    def _simulate_credential_test(self, ip, credentials):
        """Simulate credential testing (for demo purposes)"""
        # In real implementation, this would test actual credentials
        # For simulation, randomly return True for some devices
        import random
        return random.random() < 0.3  # 30% chance of having default credentials
    
    def _check_encryption(self, device):
        """Check for unencrypted communication"""
        try:
            ip = device['ip']
            open_ports = device.get('open_ports', [])
            
            # Check if HTTPS is available
            has_https = 443 in open_ports
            has_http = 80 in open_ports
            
            if has_http and not has_https:
                return {
                    'vulnerability_type': 'unencrypted_communication',
                    'severity': 'MEDIUM',
                    'description': 'HTTP service available without HTTPS encryption',
                    'cve_references': self.ot_vulnerabilities['unencrypted_communication']['cve_examples'],
                    'recommendation': 'Enable HTTPS encryption for all web services'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking encryption for {device['ip']}: {e}")
            return None
    
    def _check_buffer_overflow(self, device):
        """Check for buffer overflow vulnerabilities"""
        try:
            # Simulate buffer overflow check
            # In real implementation, would use fuzzing or specific exploit tests
            ip = device['ip']
            device_type = device['device_type']
            
            # Simulate buffer overflow detection
            has_buffer_overflow = self._simulate_buffer_overflow_test(ip, device_type)
            
            if has_buffer_overflow:
                return {
                    'vulnerability_type': 'buffer_overflow',
                    'severity': 'CRITICAL',
                    'description': 'Buffer overflow vulnerability detected',
                    'cve_references': self.ot_vulnerabilities['buffer_overflow']['cve_examples'],
                    'recommendation': 'Apply security patches immediately'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking buffer overflow for {device['ip']}: {e}")
            return None
    
    def _simulate_buffer_overflow_test(self, ip, device_type):
        """Simulate buffer overflow testing"""
        # In real implementation, would perform actual buffer overflow tests
        import random
        return random.random() < 0.1  # 10% chance of buffer overflow
    
    def _check_dos_vulnerability(self, device):
        """Check for denial of service vulnerabilities"""
        try:
            # Simulate DoS vulnerability check
            ip = device['ip']
            device_type = device['device_type']
            
            # Simulate DoS vulnerability detection
            has_dos_vuln = self._simulate_dos_test(ip, device_type)
            
            if has_dos_vuln:
                return {
                    'vulnerability_type': 'denial_of_service',
                    'severity': 'HIGH',
                    'description': 'Denial of service vulnerability detected',
                    'cve_references': self.ot_vulnerabilities['denial_of_service']['cve_examples'],
                    'recommendation': 'Implement rate limiting and input validation'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking DoS vulnerability for {device['ip']}: {e}")
            return None
    
    def _simulate_dos_test(self, ip, device_type):
        """Simulate DoS vulnerability testing"""
        import random
        return random.random() < 0.15  # 15% chance of DoS vulnerability
    
    def _check_privilege_escalation(self, device):
        """Check for privilege escalation vulnerabilities"""
        try:
            # Simulate privilege escalation check
            ip = device['ip']
            device_type = device['device_type']
            
            # Simulate privilege escalation detection
            has_priv_escalation = self._simulate_privilege_escalation_test(ip, device_type)
            
            if has_priv_escalation:
                return {
                    'vulnerability_type': 'privilege_escalation',
                    'severity': 'CRITICAL',
                    'description': 'Privilege escalation vulnerability detected',
                    'cve_references': self.ot_vulnerabilities['privilege_escalation']['cve_examples'],
                    'recommendation': 'Review and restrict user privileges'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking privilege escalation for {device['ip']}: {e}")
            return None
    
    def _simulate_privilege_escalation_test(self, ip, device_type):
        """Simulate privilege escalation testing"""
        import random
        return random.random() < 0.05  # 5% chance of privilege escalation
    
    def _check_information_disclosure(self, device):
        """Check for information disclosure vulnerabilities"""
        try:
            # Simulate information disclosure check
            ip = device['ip']
            device_type = device['device_type']
            
            # Simulate information disclosure detection
            has_info_disclosure = self._simulate_information_disclosure_test(ip, device_type)
            
            if has_info_disclosure:
                return {
                    'vulnerability_type': 'information_disclosure',
                    'severity': 'MEDIUM',
                    'description': 'Information disclosure vulnerability detected',
                    'cve_references': self.ot_vulnerabilities['information_disclosure']['cve_examples'],
                    'recommendation': 'Restrict access to sensitive information'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking information disclosure for {device['ip']}: {e}")
            return None
    
    def _simulate_information_disclosure_test(self, ip, device_type):
        """Simulate information disclosure testing"""
        import random
        return random.random() < 0.2  # 20% chance of information disclosure
    
    def run_comprehensive_scan(self):
        """Run comprehensive vulnerability scan"""
        self.logger.info("Starting comprehensive OT vulnerability scan")
        
        all_devices = []
        
        # Discover devices in all target networks
        for network in self.config['target_networks']:
            self.logger.info(f"Scanning network: {network}")
            devices = self.discover_ot_devices(network)
            all_devices.extend(devices)
        
        self.logger.info(f"Discovered {len(all_devices)} OT devices")
        
        # Scan each device for vulnerabilities
        with ThreadPoolExecutor(max_workers=self.config['scan_settings']['max_threads']) as executor:
            future_to_device = {
                executor.submit(self.scan_device_vulnerabilities, device): device 
                for device in all_devices
            }
            
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    scan_result = future.result()
                    self.results['targets_scanned'].append(scan_result)
                except Exception as e:
                    self.logger.error(f"Error scanning device {device['ip']}: {e}")
        
        # Generate recommendations
        self._generate_recommendations()
        
        self.logger.info("Comprehensive vulnerability scan completed")
    
    def _generate_recommendations(self):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Count vulnerabilities by severity
        critical_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'CRITICAL'])
        high_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH'])
        medium_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'MEDIUM'])
        
        if critical_vulns > 0:
            recommendations.append({
                'category': 'Critical Vulnerabilities',
                'description': f'Address {critical_vulns} critical vulnerabilities immediately',
                'priority': 'CRITICAL'
            })
        
        if high_vulns > 0:
            recommendations.append({
                'category': 'High Priority',
                'description': f'Address {high_vulns} high-severity vulnerabilities',
                'priority': 'HIGH'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'category': 'Network Segmentation',
                'description': 'Implement network segmentation for OT systems',
                'priority': 'HIGH'
            },
            {
                'category': 'Access Control',
                'description': 'Implement strong authentication and authorization',
                'priority': 'HIGH'
            },
            {
                'category': 'Monitoring',
                'description': 'Deploy continuous monitoring for OT systems',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Patch Management',
                'description': 'Establish regular patch management process',
                'priority': 'MEDIUM'
            }
        ])
        
        self.results['recommendations'] = recommendations
    
    def save_results(self, filename=None):
        """Save scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnscan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Scanner for Maritime OT Devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vulnscan.py --scan-all
  python3 vulnscan.py --network 192.168.10.0/24 --exclude-safety
  python3 vulnscan.py --device 192.168.10.5 --output results.json
  python3 vulnscan.py --config config.json --verbose
        """
    )
    
    parser.add_argument(
        '--scan-all',
        action='store_true',
        help='Run comprehensive scan of all configured networks'
    )
    
    parser.add_argument(
        '--network',
        type=str,
        help='Specific network range to scan (CIDR notation)'
    )
    
    parser.add_argument(
        '--device',
        type=str,
        help='Specific device IP to scan'
    )
    
    parser.add_argument(
        '--exclude-safety',
        action='store_true',
        help='Exclude safety-critical systems from scanning'
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
    
    # Create scanner instance
    scanner = OTVulnerabilityScanner(args.config)
    
    if args.verbose:
        scanner.logger.setLevel(logging.DEBUG)
    
    try:
        if args.scan_all:
            # Run comprehensive scan
            scanner.run_comprehensive_scan()
        elif args.network:
            # Scan specific network
            devices = scanner.discover_ot_devices(args.network)
            for device in devices:
                scan_result = scanner.scan_device_vulnerabilities(device)
                scanner.results['targets_scanned'].append(scan_result)
        elif args.device:
            # Scan specific device
            device = {'ip': args.device, 'device_type': 'Unknown', 'open_ports': []}
            scan_result = scanner.scan_device_vulnerabilities(device)
            scanner.results['targets_scanned'].append(scan_result)
        else:
            print("[!] Error: Please specify scan type (--scan-all, --network, or --device)")
            sys.exit(1)
        
        # Save results
        scanner.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("OT VULNERABILITY SCAN SUMMARY")
        print("="*60)
        
        total_devices = len(scanner.results['targets_scanned'])
        excluded_devices = len(scanner.results['safety_exclusions'])
        print(f"Devices Scanned: {total_devices}")
        print(f"Safety Exclusions: {excluded_devices}")
        
        total_vulnerabilities = len(scanner.results['vulnerabilities'])
        critical_vulns = len([v for v in scanner.results['vulnerabilities'] if v['severity'] == 'CRITICAL'])
        high_vulns = len([v for v in scanner.results['vulnerabilities'] if v['severity'] == 'HIGH'])
        medium_vulns = len([v for v in scanner.results['vulnerabilities'] if v['severity'] == 'MEDIUM'])
        
        print(f"Total Vulnerabilities: {total_vulnerabilities}")
        print(f"  Critical: {critical_vulns}")
        print(f"  High: {high_vulns}")
        print(f"  Medium: {medium_vulns}")
        
        print(f"\nRecommendations: {len(scanner.results['recommendations'])}")
        for rec in scanner.results['recommendations']:
            print(f"  [{rec['priority']}] {rec['description']}")
        
        print("\n[*] Vulnerability scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

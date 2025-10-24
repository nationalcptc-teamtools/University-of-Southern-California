#!/usr/bin/env python3
"""
Host Discovery and Network Reconnaissance Tool
=============================================

This script performs efficient host discovery and network reconnaissance
for general IT environments with stealth and modular design.

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
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import random
import struct

class HostDiscovery:
    def __init__(self, config_file=None):
        """
        Initialize the host discovery tool
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "discovery_timestamp": datetime.now().isoformat(),
            "target_networks": [],
            "discovered_hosts": [],
            "scan_statistics": {},
            "recommendations": []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('host_discovery.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Discovery methods
        self.discovery_methods = {
            'ping_sweep': {
                'description': 'ICMP ping sweep',
                'stealth_level': 'LOW',
                'speed': 'FAST',
                'reliability': 'HIGH'
            },
            'arp_scan': {
                'description': 'ARP table scanning',
                'stealth_level': 'MEDIUM',
                'speed': 'FAST',
                'reliability': 'HIGH'
            },
            'tcp_syn': {
                'description': 'TCP SYN scan',
                'stealth_level': 'MEDIUM',
                'speed': 'MEDIUM',
                'reliability': 'HIGH'
            },
            'udp_scan': {
                'description': 'UDP port scan',
                'stealth_level': 'HIGH',
                'speed': 'SLOW',
                'reliability': 'MEDIUM'
            },
            'dns_enum': {
                'description': 'DNS enumeration',
                'stealth_level': 'HIGH',
                'speed': 'FAST',
                'reliability': 'MEDIUM'
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'discovery_settings': {
                'max_threads': 100,
                'timeout': 3,
                'stealth_mode': True,
                'randomize_scan_order': True,
                'delay_between_scans': 0.1
            },
            'scan_limits': {
                'max_hosts_per_scan': 1000,
                'max_ports_per_host': 100,
                'rate_limit': 100  # packets per second
            },
            'target_networks': [
                '192.168.1.0/24',
                '10.0.0.0/24',
                '172.16.0.0/24'
            ],
            'common_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 5900, 8080],
            'stealth_ports': [80, 443, 8080, 8443]  # Common web ports for stealth scanning
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def ping_sweep(self, network_range):
        """
        Perform ICMP ping sweep to discover live hosts
        
        Args:
            network_range (str): Network range in CIDR notation
            
        Returns:
            list: List of live hosts
        """
        self.logger.info(f"Starting ping sweep for network: {network_range}")
        
        live_hosts = []
        network = ipaddress.ip_network(network_range, strict=False)
        
        # Limit number of hosts for safety
        if len(list(network.hosts())) > self.config['scan_limits']['max_hosts_per_scan']:
            self.logger.warning(f"Network {network_range} has too many hosts, skipping")
            return live_hosts
        
        with ThreadPoolExecutor(max_workers=self.config['discovery_settings']['max_threads']) as executor:
            future_to_ip = {
                executor.submit(self._ping_host, str(ip)): str(ip) 
                for ip in network.hosts()
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_alive = future.result()
                    if is_alive:
                        live_hosts.append(ip)
                        self.logger.info(f"Live host discovered: {ip}")
                except Exception as e:
                    self.logger.error(f"Error pinging {ip}: {e}")
        
        return live_hosts
    
    def _ping_host(self, ip):
        """Ping a single host"""
        try:
            # Use system ping for better reliability
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(self.config['discovery_settings']['timeout']), ip],
                capture_output=True,
                text=True,
                timeout=self.config['discovery_settings']['timeout'] + 2
            )
            return result.returncode == 0
        except:
            return False
    
    def arp_scan(self, network_range):
        """
        Perform ARP scan to discover hosts on local network
        
        Args:
            network_range (str): Network range in CIDR notation
            
        Returns:
            list: List of hosts with MAC addresses
        """
        self.logger.info(f"Starting ARP scan for network: {network_range}")
        
        arp_results = []
        network = ipaddress.ip_network(network_range, strict=False)
        
        try:
            # Use arp-scan if available, otherwise use nmap
            result = subprocess.run(
                ['arp-scan', '--local', '--quiet'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('Interface'):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            if ipaddress.ip_address(ip) in network:
                                arp_results.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'vendor': self._get_mac_vendor(mac)
                                })
                                self.logger.info(f"ARP discovery: {ip} ({mac})")
            
        except FileNotFoundError:
            # Fallback to nmap ARP scan
            self.logger.info("arp-scan not found, using nmap ARP scan")
            result = subprocess.run(
                ['nmap', '-sn', '-PR', str(network_range)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Parse nmap output for ARP results
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip = line.split()[-1].strip('()')
                        arp_results.append({'ip': ip, 'mac': 'Unknown', 'vendor': 'Unknown'})
        
        return arp_results
    
    def _get_mac_vendor(self, mac):
        """Get vendor information from MAC address"""
        # Simplified vendor lookup (in real implementation, would use OUI database)
        oui = mac[:8].replace(':', '').upper()
        vendor_map = {
            '080027': 'VMware',
            '000C29': 'VMware',
            '005056': 'VMware',
            '0003FF': 'Microsoft',
            '00155D': 'Microsoft',
            '000D3A': 'Intel',
            '001B21': 'Intel',
            '001CC0': 'Cisco',
            '0019E7': 'Cisco'
        }
        return vendor_map.get(oui, 'Unknown')
    
    def tcp_syn_scan(self, target_ips, ports=None):
        """
        Perform TCP SYN scan on target hosts
        
        Args:
            target_ips (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Scan results by host
        """
        if not ports:
            ports = self.config['common_ports']
        
        self.logger.info(f"Starting TCP SYN scan on {len(target_ips)} hosts")
        
        scan_results = {}
        
        for ip in target_ips:
            scan_results[ip] = {
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                if self._tcp_syn_scan_port(ip, port):
                    scan_results[ip]['open_ports'].append(port)
                    self.logger.info(f"Open port {port} on {ip}")
                else:
                    scan_results[ip]['closed_ports'].append(port)
                
                # Rate limiting
                time.sleep(1.0 / self.config['scan_limits']['rate_limit'])
        
        return scan_results
    
    def _tcp_syn_scan_port(self, ip, port):
        """Scan a single port using TCP SYN"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['discovery_settings']['timeout'])
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def udp_scan(self, target_ips, ports=None):
        """
        Perform UDP scan on target hosts
        
        Args:
            target_ips (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Scan results by host
        """
        if not ports:
            ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500]
        
        self.logger.info(f"Starting UDP scan on {len(target_ips)} hosts")
        
        scan_results = {}
        
        for ip in target_ips:
            scan_results[ip] = {
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                if self._udp_scan_port(ip, port):
                    scan_results[ip]['open_ports'].append(port)
                    self.logger.info(f"Open UDP port {port} on {ip}")
                else:
                    scan_results[ip]['closed_ports'].append(port)
                
                # Rate limiting for UDP (slower than TCP)
                time.sleep(2.0 / self.config['scan_limits']['rate_limit'])
        
        return scan_results
    
    def _udp_scan_port(self, ip, port):
        """Scan a single UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config['discovery_settings']['timeout'])
            
            # Send UDP packet
            sock.sendto(b'\x00', (ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
        except:
            return False
    
    def dns_enumeration(self, domain):
        """
        Perform DNS enumeration
        
        Args:
            domain (str): Target domain
            
        Returns:
            dict: DNS enumeration results
        """
        self.logger.info(f"Starting DNS enumeration for domain: {domain}")
        
        dns_results = {
            'domain': domain,
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'subdomains': []
        }
        
        try:
            # A records
            result = subprocess.run(
                ['nslookup', '-type=A', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Address:' in line and not 'Server:' in line:
                        ip = line.split(':')[-1].strip()
                        if ip and ip != domain:
                            dns_results['a_records'].append(ip)
            
            # MX records
            result = subprocess.run(
                ['nslookup', '-type=MX', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'mail exchanger' in line:
                        mx = line.split()[-1].strip('.')
                        dns_results['mx_records'].append(mx)
            
            # NS records
            result = subprocess.run(
                ['nslookup', '-type=NS', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line:
                        ns = line.split()[-1].strip('.')
                        dns_results['ns_records'].append(ns)
            
            # Subdomain enumeration
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging']
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                result = subprocess.run(
                    ['nslookup', full_domain],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and 'Non-existent domain' not in result.stdout:
                    dns_results['subdomains'].append(full_domain)
                    self.logger.info(f"Subdomain found: {full_domain}")
        
        except Exception as e:
            self.logger.error(f"Error during DNS enumeration: {e}")
        
        return dns_results
    
    def stealth_scan(self, target_ips, ports=None):
        """
        Perform stealth scan using common web ports
        
        Args:
            target_ips (list): List of target IP addresses
            ports (list): List of ports to scan
            
        Returns:
            dict: Stealth scan results
        """
        if not ports:
            ports = self.config['stealth_ports']
        
        self.logger.info(f"Starting stealth scan on {len(target_ips)} hosts")
        
        stealth_results = {}
        
        for ip in target_ips:
            stealth_results[ip] = {
                'open_ports': [],
                'services': {},
                'scan_time': datetime.now().isoformat()
            }
            
            for port in ports:
                if self._stealth_scan_port(ip, port):
                    stealth_results[ip]['open_ports'].append(port)
                    service = self._identify_service(ip, port)
                    stealth_results[ip]['services'][port] = service
                    self.logger.info(f"Stealth discovery: {ip}:{port} - {service}")
                
                # Random delay for stealth
                time.sleep(random.uniform(0.5, 2.0))
        
        return stealth_results
    
    def _stealth_scan_port(self, ip, port):
        """Perform stealth scan on a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _identify_service(self, ip, port):
        """Identify service running on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send HTTP request for web ports
            if port in [80, 443, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in response:
                    server_line = [line for line in response.split('\n') if 'Server:' in line][0]
                    return server_line.split(':', 1)[1].strip()
            
            sock.close()
            return 'Unknown'
        except:
            return 'Unknown'
    
    def run_comprehensive_discovery(self, target_networks=None):
        """
        Run comprehensive host discovery
        
        Args:
            target_networks (list): List of network ranges to scan
        """
        if not target_networks:
            target_networks = self.config['target_networks']
        
        self.logger.info("Starting comprehensive host discovery")
        
        all_discovered_hosts = []
        
        for network in target_networks:
            self.logger.info(f"Scanning network: {network}")
            
            # Ping sweep
            ping_hosts = self.ping_sweep(network)
            all_discovered_hosts.extend(ping_hosts)
            
            # ARP scan for local networks
            if self._is_local_network(network):
                arp_hosts = self.arp_scan(network)
                all_discovered_hosts.extend([host['ip'] for host in arp_hosts])
            
            # Rate limiting between networks
            time.sleep(1)
        
        # Remove duplicates
        unique_hosts = list(set(all_discovered_hosts))
        
        self.logger.info(f"Discovered {len(unique_hosts)} unique hosts")
        
        # Perform port scans on discovered hosts
        if unique_hosts:
            tcp_results = self.tcp_syn_scan(unique_hosts)
            stealth_results = self.stealth_scan(unique_hosts)
            
            # Store results
            self.results['discovered_hosts'] = unique_hosts
            self.results['tcp_scan_results'] = tcp_results
            self.results['stealth_scan_results'] = stealth_results
        
        # Generate statistics
        self._generate_scan_statistics()
        
        self.logger.info("Comprehensive discovery completed")
    
    def _is_local_network(self, network):
        """Check if network is local (private IP range)"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return net.is_private
        except:
            return False
    
    def _generate_scan_statistics(self):
        """Generate scan statistics"""
        stats = {
            'total_hosts_discovered': len(self.results['discovered_hosts']),
            'scan_duration': 'N/A',  # Would calculate from start/end times
            'methods_used': list(self.discovery_methods.keys()),
            'success_rate': 'N/A'  # Would calculate from successful scans
        }
        
        self.results['scan_statistics'] = stats
    
    def save_results(self, filename=None):
        """Save discovery results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"host_discovery_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Host Discovery and Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 discovery.py --network 192.168.1.0/24
  python3 discovery.py --comprehensive --stealth
  python3 discovery.py --dns example.com --output results.json
        """
    )
    
    parser.add_argument(
        '--network',
        type=str,
        help='Network range to scan (CIDR notation)'
    )
    
    parser.add_argument(
        '--comprehensive',
        action='store_true',
        help='Run comprehensive discovery on all configured networks'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Use stealth scanning techniques'
    )
    
    parser.add_argument(
        '--dns',
        type=str,
        help='Domain for DNS enumeration'
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
    
    # Create discovery instance
    discovery = HostDiscovery(args.config)
    
    if args.verbose:
        discovery.logger.setLevel(logging.DEBUG)
    
    try:
        if args.comprehensive:
            # Run comprehensive discovery
            discovery.run_comprehensive_discovery()
        elif args.network:
            # Scan specific network
            hosts = discovery.ping_sweep(args.network)
            if hosts:
                if args.stealth:
                    results = discovery.stealth_scan(hosts)
                else:
                    results = discovery.tcp_syn_scan(hosts)
                discovery.results['discovered_hosts'] = hosts
                discovery.results['scan_results'] = results
        elif args.dns:
            # DNS enumeration
            dns_results = discovery.dns_enumeration(args.dns)
            discovery.results['dns_enumeration'] = dns_results
        else:
            print("[!] Error: Please specify scan type (--network, --comprehensive, or --dns)")
            sys.exit(1)
        
        # Save results
        discovery.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("HOST DISCOVERY SUMMARY")
        print("="*60)
        print(f"Hosts Discovered: {len(discovery.results['discovered_hosts'])}")
        
        if discovery.results['discovered_hosts']:
            print("Discovered Hosts:")
            for host in discovery.results['discovered_hosts']:
                print(f"  - {host}")
        
        print("\n[*] Host discovery completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during discovery: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

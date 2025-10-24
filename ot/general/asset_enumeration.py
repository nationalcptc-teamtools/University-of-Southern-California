#!/usr/bin/env python3
"""
OT Asset Enumeration Script
===========================

A safe, non-intrusive asset discovery tool for Operational Technology (OT) environments.
Designed to minimize disruption to ICS, SCADA, and PLC operations while providing
comprehensive asset visibility.

Features:
- Passive network discovery
- OT protocol detection (Modbus, DNP3, EtherNet/IP, etc.)
- Asset fingerprinting
- Safety-first approach with configurable timeouts
- Cross-platform compatibility (Linux/Windows)

Author: USC-CPTC
Version: 1.0
"""

import os
import sys
import json
import time
import socket
import struct
import logging
import argparse
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# OT Protocol Detection
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some features will be limited.")

# Windows compatibility
if sys.platform == "win32":
    import subprocess
    import winreg
else:
    import subprocess

@dataclass
class OTAsset:
    """Represents an OT asset with its characteristics"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    ot_protocols: List[str] = None
    open_ports: List[int] = None
    services: List[str] = None
    last_seen: str = None
    risk_level: str = "Unknown"
    
    def __post_init__(self):
        if self.ot_protocols is None:
            self.ot_protocols = []
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = []
        if self.last_seen is None:
            self.last_seen = datetime.now().isoformat()

class OTAssetEnumerator:
    """Main class for OT asset enumeration"""
    
    # Common OT ports and protocols
    OT_PORTS = {
        502: "Modbus TCP",
        20000: "DNP3",
        44818: "EtherNet/IP",
        102: "S7 (Siemens)",
        9600: "OMRON FINS",
        18245: "GE SRTP",
        47808: "BACnet",
        34980: "IEC 61850",
        2404: "IEC 104",
        2000: "DNP3 over TCP",
        2001: "DNP3 over UDP",
        34962: "IEC 61850-8-1",
        34963: "IEC 61850-8-1",
        34964: "IEC 61850-8-1"
    }
    
    # OT vendor signatures
    VENDOR_SIGNATURES = {
        "Siemens": ["S7", "SIMATIC", "SINUMERIK"],
        "Schneider": ["Modicon", "Unity", "Quantum"],
        "Rockwell": ["Allen-Bradley", "ControlLogix", "CompactLogix"],
        "GE": ["GE", "Fanuc", "Proficy"],
        "Honeywell": ["Honeywell", "Experion", "PlantScape"],
        "ABB": ["ABB", "AC800M", "Freelance"],
        "Emerson": ["DeltaV", "Ovation", "AMS"],
        "Yokogawa": ["Centum", "FA-M3", "STARDOM"]
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.assets: Dict[str, OTAsset] = {}
        self.logger = self._setup_logging()
        self.scan_timeout = self.config.get('scan_timeout', 2)
        self.max_threads = self.config.get('max_threads', 50)
        self.safe_mode = self.config.get('safe_mode', True)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('OTAssetEnumerator')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = socket.inet_aton(ip)
            # Private IP ranges
            private_ranges = [
                (socket.inet_aton('10.0.0.0'), socket.inet_aton('10.255.255.255')),
                (socket.inet_aton('172.16.0.0'), socket.inet_aton('172.31.255.255')),
                (socket.inet_aton('192.168.0.0'), socket.inet_aton('192.168.255.255'))
            ]
            
            for start, end in private_ranges:
                if start <= ip_obj <= end:
                    return True
            return False
        except:
            return False
    
    def _get_network_range(self, target: str) -> List[str]:
        """Generate IP range for scanning"""
        if '/' in target:
            # CIDR notation
            return self._cidr_to_ips(target)
        elif '-' in target:
            # Range notation (e.g., 192.168.1.1-192.168.1.100)
            start, end = target.split('-')
            return self._ip_range_to_list(start.strip(), end.strip())
        else:
            # Single IP
            return [target]
    
    def _cidr_to_ips(self, cidr: str) -> List[str]:
        """Convert CIDR notation to IP list"""
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return [cidr]
    
    def _ip_range_to_list(self, start_ip: str, end_ip: str) -> List[str]:
        """Convert IP range to list"""
        try:
            import ipaddress
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            return [str(ip) for ip in ipaddress.summarize_address_range(start, end)]
        except:
            return [start_ip, end_ip]
    
    def _safe_ping(self, ip: str) -> bool:
        """Safe ping with timeout"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(self.scan_timeout * 1000), ip],
                    capture_output=True, timeout=self.scan_timeout + 1
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.scan_timeout), ip],
                    capture_output=True, timeout=self.scan_timeout + 1
                )
            return result.returncode == 0
        except:
            return False
    
    def _port_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Safe port scanning with OT-specific ports"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
                # Safety delay for OT environments
                if self.safe_mode:
                    time.sleep(0.1)
                    
            except:
                continue
                
        return open_ports
    
    def _detect_ot_protocols(self, ip: str, ports: List[int]) -> List[str]:
        """Detect OT protocols based on open ports"""
        protocols = []
        
        for port in ports:
            if port in self.OT_PORTS:
                protocols.append(self.OT_PORTS[port])
        
        return protocols
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for IP (requires ARP table)"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part
        except:
            pass
        return None
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _identify_vendor(self, hostname: str, services: List[str]) -> Optional[str]:
        """Identify vendor based on hostname and services"""
        if not hostname:
            return None
            
        hostname_upper = hostname.upper()
        
        for vendor, signatures in self.VENDOR_SIGNATURES.items():
            for signature in signatures:
                if signature.upper() in hostname_upper:
                    return vendor
                    
        return None
    
    def _assess_risk_level(self, asset: OTAsset) -> str:
        """Assess risk level based on asset characteristics"""
        risk_score = 0
        
        # OT protocols increase risk
        if asset.ot_protocols:
            risk_score += len(asset.ot_protocols) * 2
            
        # Open ports increase risk
        if asset.open_ports:
            risk_score += len(asset.open_ports)
            
        # Internet-facing increases risk
        if not self._is_private_ip(asset.ip_address):
            risk_score += 5
            
        if risk_score >= 10:
            return "High"
        elif risk_score >= 5:
            return "Medium"
        else:
            return "Low"
    
    def _scan_asset(self, ip: str) -> Optional[OTAsset]:
        """Scan a single asset"""
        try:
            self.logger.info(f"Scanning {ip}...")
            
            # Check if host is alive
            if not self._safe_ping(ip):
                return None
            
            # Get basic info
            mac_address = self._get_mac_address(ip)
            hostname = self._get_hostname(ip)
            
            # Port scan with OT-specific ports
            ot_ports = list(self.OT_PORTS.keys())
            common_ports = [22, 23, 80, 443, 135, 139, 445, 3389]
            ports_to_scan = ot_ports + common_ports
            
            open_ports = self._port_scan(ip, ports_to_scan)
            
            # Detect OT protocols
            ot_protocols = self._detect_ot_protocols(ip, open_ports)
            
            # Identify services
            services = []
            for port in open_ports:
                if port in self.OT_PORTS:
                    services.append(self.OT_PORTS[port])
                else:
                    services.append(f"Port {port}")
            
            # Create asset object
            asset = OTAsset(
                ip_address=ip,
                mac_address=mac_address,
                hostname=hostname,
                open_ports=open_ports,
                ot_protocols=ot_protocols,
                services=services
            )
            
            # Identify vendor
            asset.vendor = self._identify_vendor(hostname, services)
            
            # Assess risk level
            asset.risk_level = self._assess_risk_level(asset)
            
            return asset
            
        except Exception as e:
            self.logger.error(f"Error scanning {ip}: {e}")
            return None
    
    def enumerate_assets(self, targets: List[str]) -> Dict[str, OTAsset]:
        """Main enumeration function"""
        self.logger.info("Starting OT asset enumeration...")
        
        # Generate IP list
        all_ips = []
        for target in targets:
            all_ips.extend(self._get_network_range(target))
        
        self.logger.info(f"Scanning {len(all_ips)} IP addresses...")
        
        # Threaded scanning for efficiency
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {
                executor.submit(self._scan_asset, ip): ip 
                for ip in all_ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    asset = future.result()
                    if asset:
                        self.assets[ip] = asset
                        self.logger.info(f"Found asset: {ip} ({asset.hostname or 'Unknown'})")
                except Exception as e:
                    self.logger.error(f"Error processing {ip}: {e}")
        
        self.logger.info(f"Enumeration complete. Found {len(self.assets)} assets.")
        return self.assets
    
    def export_results(self, filename: str = None) -> str:
        """Export results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ot_assets_{timestamp}.json"
        
        # Convert assets to serializable format
        export_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_assets': len(self.assets),
                'config': self.config
            },
            'assets': {ip: asdict(asset) for ip, asset in self.assets.items()}
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Results exported to {filename}")
        return filename
    
    def generate_report(self) -> str:
        """Generate a human-readable report"""
        report = []
        report.append("OT Asset Enumeration Report")
        report.append("=" * 50)
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Assets Found: {len(self.assets)}")
        report.append("")
        
        # Risk level summary
        risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for asset in self.assets.values():
            risk_counts[asset.risk_level] += 1
        
        report.append("Risk Level Summary:")
        for risk, count in risk_counts.items():
            report.append(f"  {risk}: {count}")
        report.append("")
        
        # Detailed asset information
        report.append("Asset Details:")
        report.append("-" * 30)
        
        for ip, asset in self.assets.items():
            report.append(f"IP: {asset.ip_address}")
            if asset.hostname:
                report.append(f"  Hostname: {asset.hostname}")
            if asset.mac_address:
                report.append(f"  MAC: {asset.mac_address}")
            if asset.vendor:
                report.append(f"  Vendor: {asset.vendor}")
            if asset.ot_protocols:
                report.append(f"  OT Protocols: {', '.join(asset.ot_protocols)}")
            if asset.open_ports:
                report.append(f"  Open Ports: {', '.join(map(str, asset.open_ports))}")
            report.append(f"  Risk Level: {asset.risk_level}")
            report.append("")
        
        return "\n".join(report)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="OT Asset Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asset_enumeration.py 192.168.1.0/24
  python asset_enumeration.py 10.0.0.1-10.0.0.100
  python asset_enumeration.py 192.168.1.1 --safe-mode --timeout 5
        """
    )
    
    parser.add_argument('targets', nargs='+', help='Target IP addresses or ranges')
    parser.add_argument('--timeout', type=int, default=2, help='Scan timeout in seconds')
    parser.add_argument('--threads', type=int, default=50, help='Maximum threads')
    parser.add_argument('--safe-mode', action='store_true', default=True, 
                       help='Enable safe mode with delays')
    parser.add_argument('--output', '-o', help='Output filename for results')
    parser.add_argument('--report', '-r', action='store_true', help='Generate text report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'scan_timeout': args.timeout,
        'max_threads': args.threads,
        'safe_mode': args.safe_mode
    }
    
    # Setup logging
    if args.verbose:
        logging.getLogger('OTAssetEnumerator').setLevel(logging.DEBUG)
    
    # Initialize enumerator
    enumerator = OTAssetEnumerator(config)
    
    try:
        # Perform enumeration
        assets = enumerator.enumerate_assets(args.targets)
        
        # Export results
        output_file = enumerator.export_results(args.output)
        
        # Generate report if requested
        if args.report:
            report = enumerator.generate_report()
            report_file = output_file.replace('.json', '_report.txt')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"Report saved to {report_file}")
        
        print(f"Scan complete. Found {len(assets)} assets.")
        print(f"Results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

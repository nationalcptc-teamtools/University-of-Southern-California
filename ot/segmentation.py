#!/usr/bin/env python3
"""
Network Segmentation Verification Tool for Maritime OT Environments
================================================================

This script automates network segmentation verification for OT environments on maritime vessels,
ensuring isolation between guest Wi-Fi, crew VLAN, and critical OT systems.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import subprocess
import sys
import json
import time
from datetime import datetime
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkSegmentationVerifier:
    def __init__(self, target_networks=None, timeout=5, threads=50):
        """
        Initialize the network segmentation verifier
        
        Args:
            target_networks (list): List of network ranges to scan
            timeout (int): Timeout for network operations
            threads (int): Number of threads for concurrent scanning
        """
        self.target_networks = target_networks or [
            "192.168.1.0/24",  # Guest Wi-Fi
            "192.168.2.0/24",  # Crew VLAN
            "192.168.10.0/24", # OT Systems
            "10.0.0.0/24"      # Management Network
        ]
        self.timeout = timeout
        self.threads = threads
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "network_segments": {},
            "isolation_violations": [],
            "recommendations": []
        }
    
    def ping_host(self, ip):
        """
        Ping a single host to check if it's alive
        
        Args:
            ip (str): IP address to ping
            
        Returns:
            dict: Result of ping operation
        """
        try:
            # Use system ping command for better reliability
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(self.timeout), ip],
                capture_output=True,
                text=True,
                timeout=self.timeout + 2
            )
            
            return {
                "ip": ip,
                "alive": result.returncode == 0,
                "response_time": self._extract_ping_time(result.stdout) if result.returncode == 0 else None
            }
        except Exception as e:
            return {
                "ip": ip,
                "alive": False,
                "error": str(e)
            }
    
    def _extract_ping_time(self, ping_output):
        """Extract response time from ping output"""
        try:
            # Extract time from ping output (works on most Unix systems)
            lines = ping_output.split('\n')
            for line in lines:
                if 'time=' in line:
                    time_part = line.split('time=')[1].split()[0]
                    return float(time_part.replace('ms', ''))
        except:
            pass
        return None
    
    def scan_network_segment(self, network):
        """
        Scan a network segment for live hosts
        
        Args:
            network (str): Network CIDR to scan
            
        Returns:
            dict: Scan results for the network
        """
        print(f"[*] Scanning network segment: {network}")
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = [str(ip) for ip in network_obj.hosts()]
            
            live_hosts = []
            dead_hosts = []
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in hosts}
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    if result["alive"]:
                        live_hosts.append(result)
                    else:
                        dead_hosts.append(result)
            
            return {
                "network": network,
                "total_hosts": len(hosts),
                "live_hosts": live_hosts,
                "dead_hosts": dead_hosts,
                "scan_completed": True
            }
            
        except Exception as e:
            return {
                "network": network,
                "error": str(e),
                "scan_completed": False
            }
    
    def check_cross_segment_connectivity(self, segment1, segment2):
        """
        Check if hosts in different segments can communicate
        
        Args:
            segment1 (dict): First network segment results
            segment2 (dict): Second network segment results
            
        Returns:
            dict: Cross-segment connectivity results
        """
        violations = []
        
        if not segment1.get("scan_completed") or not segment2.get("scan_completed"):
            return {"violations": [], "error": "One or both segments not scanned successfully"}
        
        # Test connectivity between live hosts in different segments
        for host1 in segment1.get("live_hosts", []):
            for host2 in segment2.get("live_hosts", []):
                if self._test_connectivity(host1["ip"], host2["ip"]):
                    violations.append({
                        "source": host1["ip"],
                        "destination": host2["ip"],
                        "source_segment": segment1["network"],
                        "dest_segment": segment2["network"],
                        "violation_type": "Cross-segment connectivity detected"
                    })
        
        return {"violations": violations}
    
    def _test_connectivity(self, ip1, ip2):
        """
        Test if two IPs can communicate
        
        Args:
            ip1 (str): Source IP
            ip2 (str): Destination IP
            
        Returns:
            bool: True if connectivity exists
        """
        try:
            # Use telnet-like test for common ports
            test_ports = [22, 23, 80, 443, 3389, 502]  # SSH, Telnet, HTTP, HTTPS, RDP, Modbus
            
            for port in test_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip2, port))
                sock.close()
                
                if result == 0:  # Connection successful
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def generate_recommendations(self):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Check for isolation violations
        if self.results["isolation_violations"]:
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Isolation",
                "description": "Cross-segment connectivity detected",
                "action": "Implement proper VLAN isolation and firewall rules"
            })
        
        # Check for exposed OT systems
        ot_segment = None
        for segment_name, segment_data in self.results["network_segments"].items():
            if "ot" in segment_name.lower() or "10.0" in segment_data.get("network", ""):
                ot_segment = segment_data
                break
        
        if ot_segment and ot_segment.get("live_hosts"):
            recommendations.append({
                "priority": "CRITICAL",
                "category": "OT Security",
                "description": f"OT systems detected in {ot_segment['network']}",
                "action": "Ensure OT systems are properly isolated and secured"
            })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "MEDIUM",
                "category": "Network Security",
                "description": "Implement network monitoring",
                "action": "Deploy network monitoring tools to detect unauthorized access"
            },
            {
                "priority": "MEDIUM",
                "category": "Access Control",
                "description": "Review network access policies",
                "action": "Regularly audit and update network access control lists"
            }
        ])
        
        self.results["recommendations"] = recommendations
    
    def run_verification(self):
        """
        Run the complete network segmentation verification
        
        Returns:
            dict: Complete verification results
        """
        print("[*] Starting network segmentation verification...")
        print(f"[*] Target networks: {', '.join(self.target_networks)}")
        print(f"[*] Using {self.threads} threads with {self.timeout}s timeout")
        
        # Scan each network segment
        for network in self.target_networks:
            segment_name = f"segment_{network.replace('/', '_')}"
            self.results["network_segments"][segment_name] = self.scan_network_segment(network)
        
        # Check for cross-segment connectivity violations
        segments = list(self.results["network_segments"].values())
        for i in range(len(segments)):
            for j in range(i + 1, len(segments)):
                connectivity_result = self.check_cross_segment_connectivity(segments[i], segments[j])
                self.results["isolation_violations"].extend(connectivity_result.get("violations", []))
        
        # Generate recommendations
        self.generate_recommendations()
        
        print(f"[*] Verification completed. Found {len(self.results['isolation_violations'])} isolation violations.")
        return self.results
    
    def save_results(self, filename=None):
        """
        Save results to JSON file
        
        Args:
            filename (str): Output filename
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"segmentation_verification_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[*] Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Network Segmentation Verification Tool for Maritime OT Environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 segmentation.py
  python3 segmentation.py --networks "192.168.1.0/24,192.168.2.0/24" --threads 100
  python3 segmentation.py --timeout 10 --output results.json
        """
    )
    
    parser.add_argument(
        '--networks',
        type=str,
        help='Comma-separated list of networks to scan (default: predefined maritime networks)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of concurrent threads for scanning (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Timeout for network operations in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output filename for results (default: auto-generated)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse networks if provided
    target_networks = None
    if args.networks:
        target_networks = [net.strip() for net in args.networks.split(',')]
    
    # Create verifier instance
    verifier = NetworkSegmentationVerifier(
        target_networks=target_networks,
        timeout=args.timeout,
        threads=args.threads
    )
    
    try:
        # Run verification
        results = verifier.run_verification()
        
        # Save results
        verifier.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("NETWORK SEGMENTATION VERIFICATION SUMMARY")
        print("="*60)
        
        for segment_name, segment_data in results["network_segments"].items():
            if segment_data.get("scan_completed"):
                live_count = len(segment_data.get("live_hosts", []))
                total_count = segment_data.get("total_hosts", 0)
                print(f"{segment_name}: {live_count}/{total_count} hosts alive")
        
        print(f"\nIsolation Violations: {len(results['isolation_violations'])}")
        for violation in results["isolation_violations"]:
            print(f"  - {violation['source']} -> {violation['destination']} "
                  f"({violation['source_segment']} -> {violation['dest_segment']})")
        
        print(f"\nRecommendations: {len(results['recommendations'])}")
        for rec in results["recommendations"]:
            print(f"  [{rec['priority']}] {rec['description']}")
        
        print("\n[*] Verification completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during verification: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

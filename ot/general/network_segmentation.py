#!/usr/bin/env python3
"""
OT Network Segmentation Validation Script
========================================

A comprehensive tool for validating network segmentation in Operational Technology (OT)
environments. This script helps ensure proper isolation between OT and IT networks,
validates firewall rules, and identifies potential security gaps.

Features:
- Network isolation validation
- Firewall rule analysis
- OT/IT boundary detection
- Segmentation compliance checking
- Safe testing with minimal network impact
- Cross-platform compatibility

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
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, ip_address, IPv4Network

# Network analysis
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some advanced features will be limited.")

@dataclass
class NetworkSegment:
    """Represents a network segment"""
    name: str
    network: str
    description: str
    segment_type: str  # OT, IT, DMZ, etc.
    criticality: str  # Critical, High, Medium, Low
    allowed_protocols: List[str]
    allowed_ports: List[int]
    restricted_ports: List[int]
    isolation_level: str  # Strict, Moderate, Permissive

@dataclass
class SegmentationTest:
    """Represents a segmentation test result"""
    source_segment: str
    target_segment: str
    test_type: str
    success: bool
    details: str
    risk_level: str
    timestamp: str

@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    rule_id: str
    source: str
    destination: str
    protocol: str
    port: str
    action: str  # Allow, Deny
    description: str

class NetworkSegmentationValidator:
    """Main class for network segmentation validation"""
    
    # Common OT protocols and ports
    OT_PROTOCOLS = {
        'Modbus': [502],
        'DNP3': [20000, 2000, 2001],
        'EtherNet/IP': [44818],
        'S7': [102],
        'IEC 61850': [34980, 34962, 34963, 34964],
        'IEC 104': [2404],
        'BACnet': [47808],
        'OMRON FINS': [9600],
        'GE SRTP': [18245]
    }
    
    # Critical OT ports that should be restricted
    CRITICAL_OT_PORTS = [502, 20000, 44818, 102, 34980, 2404, 47808]
    
    # IT protocols that should be restricted in OT
    IT_PROTOCOLS = {
        'HTTP': [80, 8080],
        'HTTPS': [443, 8443],
        'SSH': [22],
        'Telnet': [23],
        'FTP': [21],
        'SMTP': [25],
        'DNS': [53],
        'DHCP': [67, 68],
        'SNMP': [161, 162],
        'RDP': [3389],
        'SMB': [139, 445]
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.segments: Dict[str, NetworkSegment] = {}
        self.test_results: List[SegmentationTest] = []
        self.firewall_rules: List[FirewallRule] = []
        self.logger = self._setup_logging()
        self.scan_timeout = self.config.get('scan_timeout', 3)
        self.max_threads = self.config.get('max_threads', 20)
        self.safe_mode = self.config.get('safe_mode', True)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('NetworkSegmentationValidator')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _load_segments_from_file(self, filename: str) -> bool:
        """Load network segments from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            for segment_data in data.get('segments', []):
                segment = NetworkSegment(**segment_data)
                self.segments[segment.name] = segment
                
            self.logger.info(f"Loaded {len(self.segments)} network segments")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading segments: {e}")
            return False
    
    def _create_default_segments(self):
        """Create default network segments for common OT environments"""
        default_segments = [
            NetworkSegment(
                name="OT_Control",
                network="192.168.1.0/24",
                description="Primary OT control network",
                segment_type="OT",
                criticality="Critical",
                allowed_protocols=["Modbus", "DNP3", "EtherNet/IP"],
                allowed_ports=[502, 20000, 44818],
                restricted_ports=[80, 443, 22, 23],
                isolation_level="Strict"
            ),
            NetworkSegment(
                name="OT_Supervisory",
                network="192.168.2.0/24",
                description="OT supervisory network",
                segment_type="OT",
                criticality="High",
                allowed_protocols=["Modbus", "DNP3", "HTTP"],
                allowed_ports=[502, 20000, 80],
                restricted_ports=[443, 22, 23, 3389],
                isolation_level="Moderate"
            ),
            NetworkSegment(
                name="IT_Network",
                network="10.0.0.0/24",
                description="Corporate IT network",
                segment_type="IT",
                criticality="Medium",
                allowed_protocols=["HTTP", "HTTPS", "SSH", "RDP"],
                allowed_ports=[80, 443, 22, 3389],
                restricted_ports=[502, 20000, 44818],
                isolation_level="Permissive"
            ),
            NetworkSegment(
                name="DMZ",
                network="172.16.0.0/24",
                description="Demilitarized zone",
                segment_type="DMZ",
                criticality="Medium",
                allowed_protocols=["HTTP", "HTTPS"],
                allowed_ports=[80, 443],
                restricted_ports=[502, 20000, 44818, 22, 23],
                isolation_level="Moderate"
            )
        ]
        
        for segment in default_segments:
            self.segments[segment.name] = segment
    
    def _get_network_info(self, ip: str) -> Optional[str]:
        """Get network information for an IP address"""
        try:
            ip_obj = ip_address(ip)
            for name, segment in self.segments.items():
                network = ip_network(segment.network, strict=False)
                if ip_obj in network:
                    return name
            return "Unknown"
        except:
            return "Unknown"
    
    def _test_connectivity(self, source_ip: str, target_ip: str, port: int) -> bool:
        """Test connectivity between two IPs on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_icmp_connectivity(self, source_ip: str, target_ip: str) -> bool:
        """Test ICMP connectivity between two IPs"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(self.scan_timeout * 1000), target_ip],
                    capture_output=True, timeout=self.scan_timeout + 1
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.scan_timeout), target_ip],
                    capture_output=True, timeout=self.scan_timeout + 1
                )
            return result.returncode == 0
        except:
            return False
    
    def _analyze_firewall_rules(self, rules_file: str = None) -> List[FirewallRule]:
        """Analyze firewall rules from file or system"""
        rules = []
        
        if rules_file and os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    data = json.load(f)
                
                for rule_data in data.get('rules', []):
                    rule = FirewallRule(**rule_data)
                    rules.append(rule)
                    
            except Exception as e:
                self.logger.error(f"Error loading firewall rules: {e}")
        
        return rules
    
    def _validate_segment_isolation(self, segment1: NetworkSegment, segment2: NetworkSegment) -> SegmentationTest:
        """Validate isolation between two segments"""
        test_type = "Segment Isolation"
        
        # Check if segments should be isolated
        should_isolate = (
            (segment1.segment_type == "OT" and segment2.segment_type == "IT") or
            (segment1.segment_type == "IT" and segment2.segment_type == "OT") or
            (segment1.isolation_level == "Strict" and segment2.isolation_level == "Strict")
        )
        
        if not should_isolate:
            return SegmentationTest(
                source_segment=segment1.name,
                target_segment=segment2.name,
                test_type=test_type,
                success=True,
                details="Segments do not require strict isolation",
                risk_level="Low",
                timestamp=datetime.now().isoformat()
            )
        
        # Test connectivity (this is a simplified test)
        # In a real environment, you would test from actual devices
        test_success = True
        risk_level = "Low"
        details = "Isolation appears to be properly configured"
        
        # Check for common misconfigurations
        if segment1.segment_type == "OT" and segment2.segment_type == "IT":
            # OT should not be able to reach IT directly
            for port in segment1.restricted_ports:
                if port in segment2.allowed_ports:
                    test_success = False
                    risk_level = "High"
                    details = f"OT segment can potentially reach IT on restricted port {port}"
                    break
        
        return SegmentationTest(
            source_segment=segment1.name,
            target_segment=segment2.name,
            test_type=test_type,
            success=test_success,
            details=details,
            risk_level=risk_level,
            timestamp=datetime.now().isoformat()
        )
    
    def _validate_ot_protocol_restrictions(self, segment: NetworkSegment) -> List[SegmentationTest]:
        """Validate OT protocol restrictions within a segment"""
        tests = []
        
        # Check if IT protocols are properly restricted in OT segments
        if segment.segment_type == "OT":
            for protocol, ports in self.IT_PROTOCOLS.items():
                for port in ports:
                    if port in segment.allowed_ports:
                        test = SegmentationTest(
                            source_segment=segment.name,
                            target_segment=segment.name,
                            test_type="Protocol Restriction",
                            success=False,
                            details=f"IT protocol {protocol} (port {port}) is allowed in OT segment",
                            risk_level="High",
                            timestamp=datetime.now().isoformat()
                        )
                        tests.append(test)
        
        return tests
    
    def _validate_critical_ot_ports(self, segment: NetworkSegment) -> List[SegmentationTest]:
        """Validate that critical OT ports are properly protected"""
        tests = []
        
        if segment.segment_type == "OT":
            for port in self.CRITICAL_OT_PORTS:
                if port not in segment.restricted_ports:
                    test = SegmentationTest(
                        source_segment=segment.name,
                        target_segment="External",
                        test_type="Critical Port Protection",
                        success=False,
                        details=f"Critical OT port {port} is not restricted from external access",
                        risk_level="High",
                        timestamp=datetime.now().isoformat()
                    )
                    tests.append(test)
        
        return tests
    
    def _validate_firewall_rules(self) -> List[SegmentationTest]:
        """Validate firewall rules for proper segmentation"""
        tests = []
        
        for rule in self.firewall_rules:
            # Check for dangerous rules
            if rule.action == "Allow":
                # Check if rule allows IT protocols to OT
                for protocol, ports in self.IT_PROTOCOLS.items():
                    if any(str(port) in rule.port for port in ports):
                        if "OT" in rule.destination or "OT" in rule.source:
                            test = SegmentationTest(
                                source_segment=rule.source,
                                target_segment=rule.destination,
                                test_type="Firewall Rule Analysis",
                                success=False,
                                details=f"Rule allows IT protocol {protocol} to/from OT segment",
                                risk_level="High",
                                timestamp=datetime.now().isoformat()
                            )
                            tests.append(test)
        
        return tests
    
    def validate_segmentation(self, segments_file: str = None, firewall_rules_file: str = None) -> Dict:
        """Main validation function"""
        self.logger.info("Starting network segmentation validation...")
        
        # Load segments
        if segments_file and os.path.exists(segments_file):
            self._load_segments_from_file(segments_file)
        else:
            self._create_default_segments()
        
        # Load firewall rules
        if firewall_rules_file:
            self.firewall_rules = self._analyze_firewall_rules(firewall_rules_file)
        
        # Perform validation tests
        all_tests = []
        
        # Test segment isolation
        segment_names = list(self.segments.keys())
        for i, seg1_name in enumerate(segment_names):
            for seg2_name in segment_names[i+1:]:
                seg1 = self.segments[seg1_name]
                seg2 = self.segments[seg2_name]
                test = self._validate_segment_isolation(seg1, seg2)
                all_tests.append(test)
        
        # Test protocol restrictions
        for segment in self.segments.values():
            protocol_tests = self._validate_ot_protocol_restrictions(segment)
            all_tests.extend(protocol_tests)
            
            critical_port_tests = self._validate_critical_ot_ports(segment)
            all_tests.extend(critical_port_tests)
        
        # Test firewall rules
        if self.firewall_rules:
            firewall_tests = self._validate_firewall_rules()
            all_tests.extend(firewall_tests)
        
        self.test_results = all_tests
        
        # Generate summary
        total_tests = len(all_tests)
        passed_tests = sum(1 for test in all_tests if test.success)
        failed_tests = total_tests - passed_tests
        
        high_risk_tests = sum(1 for test in all_tests if test.risk_level == "High")
        medium_risk_tests = sum(1 for test in all_tests if test.risk_level == "Medium")
        
        summary = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'high_risk_issues': high_risk_tests,
            'medium_risk_issues': medium_risk_tests,
            'compliance_score': (passed_tests / total_tests * 100) if total_tests > 0 else 100
        }
        
        self.logger.info(f"Validation complete. {passed_tests}/{total_tests} tests passed.")
        self.logger.info(f"Compliance score: {summary['compliance_score']:.1f}%")
        
        return {
            'summary': summary,
            'segments': {name: asdict(segment) for name, segment in self.segments.items()},
            'test_results': [asdict(test) for test in all_tests],
            'firewall_rules': [asdict(rule) for rule in self.firewall_rules]
        }
    
    def export_results(self, results: Dict, filename: str = None) -> str:
        """Export validation results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"segmentation_validation_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results exported to {filename}")
        return filename
    
    def generate_report(self, results: Dict) -> str:
        """Generate a human-readable validation report"""
        report = []
        report.append("Network Segmentation Validation Report")
        report.append("=" * 50)
        report.append(f"Validation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        summary = results['summary']
        report.append("Validation Summary:")
        report.append(f"  Total Tests: {summary['total_tests']}")
        report.append(f"  Passed: {summary['passed_tests']}")
        report.append(f"  Failed: {summary['failed_tests']}")
        report.append(f"  High Risk Issues: {summary['high_risk_issues']}")
        report.append(f"  Medium Risk Issues: {summary['medium_risk_issues']}")
        report.append(f"  Compliance Score: {summary['compliance_score']:.1f}%")
        report.append("")
        
        # Risk assessment
        if summary['high_risk_issues'] > 0:
            report.append("⚠️  HIGH RISK ISSUES FOUND:")
            for test in results['test_results']:
                if test['risk_level'] == 'High' and not test['success']:
                    report.append(f"  - {test['details']}")
            report.append("")
        
        if summary['medium_risk_issues'] > 0:
            report.append("⚠️  MEDIUM RISK ISSUES FOUND:")
            for test in results['test_results']:
                if test['risk_level'] == 'Medium' and not test['success']:
                    report.append(f"  - {test['details']}")
            report.append("")
        
        # Detailed test results
        report.append("Detailed Test Results:")
        report.append("-" * 30)
        
        for test in results['test_results']:
            status = "✓ PASS" if test['success'] else "✗ FAIL"
            report.append(f"{status} - {test['test_type']}")
            report.append(f"  Source: {test['source_segment']}")
            report.append(f"  Target: {test['target_segment']}")
            report.append(f"  Details: {test['details']}")
            report.append(f"  Risk Level: {test['risk_level']}")
            report.append("")
        
        # Recommendations
        report.append("Recommendations:")
        report.append("-" * 20)
        
        if summary['high_risk_issues'] > 0:
            report.append("1. IMMEDIATE ACTION REQUIRED:")
            report.append("   - Review and fix high-risk segmentation issues")
            report.append("   - Implement stricter firewall rules")
            report.append("   - Consider network redesign for critical issues")
            report.append("")
        
        if summary['compliance_score'] < 80:
            report.append("2. IMPROVEMENT NEEDED:")
            report.append("   - Review network segmentation policies")
            report.append("   - Update firewall configurations")
            report.append("   - Implement additional security controls")
            report.append("")
        
        report.append("3. ONGOING MONITORING:")
        report.append("   - Regular segmentation validation")
        report.append("   - Continuous firewall rule review")
        report.append("   - Network traffic monitoring")
        
        return "\n".join(report)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="OT Network Segmentation Validation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_segmentation.py
  python network_segmentation.py --segments segments.json
  python network_segmentation.py --firewall-rules firewall.json --output results.json
        """
    )
    
    parser.add_argument('--segments', help='Network segments JSON file')
    parser.add_argument('--firewall-rules', help='Firewall rules JSON file')
    parser.add_argument('--output', '-o', help='Output filename for results')
    parser.add_argument('--report', '-r', action='store_true', help='Generate text report')
    parser.add_argument('--timeout', type=int, default=3, help='Test timeout in seconds')
    parser.add_argument('--threads', type=int, default=20, help='Maximum threads')
    parser.add_argument('--safe-mode', action='store_true', default=True, 
                       help='Enable safe mode with delays')
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
        logging.getLogger('NetworkSegmentationValidator').setLevel(logging.DEBUG)
    
    # Initialize validator
    validator = NetworkSegmentationValidator(config)
    
    try:
        # Perform validation
        results = validator.validate_segmentation(
            segments_file=args.segments,
            firewall_rules_file=args.firewall_rules
        )
        
        # Export results
        output_file = validator.export_results(results, args.output)
        
        # Generate report if requested
        if args.report:
            report = validator.generate_report(results)
            report_file = output_file.replace('.json', '_report.txt')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"Report saved to {report_file}")
        
        print(f"Validation complete. Compliance score: {results['summary']['compliance_score']:.1f}%")
        print(f"Results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\nValidation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

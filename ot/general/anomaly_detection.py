#!/usr/bin/env python3
"""
OT Anomaly Detection Script
===========================

An intelligent anomaly detection system for Operational Technology (OT) environments.
Designed to identify unusual patterns, potential security threats, and operational
anomalies in ICS, SCADA, and PLC systems while maintaining system stability.

Features:
- Real-time traffic analysis
- Protocol-specific anomaly detection
- Machine learning-based pattern recognition
- OT-specific threat detection
- Safe monitoring with minimal impact
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
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import queue

# Network analysis
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.modbus import ModbusADURequest, ModbusADUResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some features will be limited.")

# Machine learning
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: Scikit-learn not available. ML-based detection will be limited.")

@dataclass
class AnomalyEvent:
    """Represents an anomaly event"""
    timestamp: str
    event_type: str
    severity: str  # Low, Medium, High, Critical
    source_ip: str
    destination_ip: str
    protocol: str
    description: str
    details: Dict[str, Any]
    confidence: float
    recommended_action: str

@dataclass
class TrafficPattern:
    """Represents a traffic pattern for baseline analysis"""
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    packet_count: int
    byte_count: int
    frequency: float
    timestamp: str

class OTAnomalyDetector:
    """Main class for OT anomaly detection"""
    
    # OT Protocol signatures
    OT_PROTOCOLS = {
        'Modbus': {
            'ports': [502],
            'signatures': [b'\x00\x01', b'\x00\x02', b'\x00\x03', b'\x00\x04'],
            'normal_functions': [1, 2, 3, 4, 5, 6, 15, 16]
        },
        'DNP3': {
            'ports': [20000, 2000, 2001],
            'signatures': [b'\x05\x64'],
            'normal_functions': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
        },
        'EtherNet/IP': {
            'ports': [44818],
            'signatures': [b'\x65\x00'],
            'normal_functions': [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
        },
        'S7': {
            'ports': [102],
            'signatures': [b'\x03\x00\x00\x16'],
            'normal_functions': [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
        }
    }
    
    # Anomaly thresholds
    THRESHOLDS = {
        'packet_rate': 1000,  # packets per minute
        'byte_rate': 100000,  # bytes per minute
        'connection_rate': 100,  # new connections per minute
        'error_rate': 0.1,  # 10% error rate
        'unusual_hours': [22, 23, 0, 1, 2, 3, 4, 5],  # unusual hours for OT
        'weekend_activity': True  # weekend activity is unusual for OT
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = self._setup_logging()
        self.anomalies: List[AnomalyEvent] = []
        self.baseline_patterns: Dict[str, TrafficPattern] = {}
        self.traffic_history: deque = deque(maxlen=10000)
        self.monitoring = False
        self.ml_model = None
        self.scaler = None
        
        # Configuration
        self.monitor_interface = self.config.get('interface', 'eth0')
        self.baseline_duration = self.config.get('baseline_duration', 3600)  # 1 hour
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.1)
        self.ml_enabled = self.config.get('ml_enabled', ML_AVAILABLE)
        
        # Initialize ML model if available
        if self.ml_enabled:
            self._initialize_ml_model()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('OTAnomalyDetector')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _initialize_ml_model(self):
        """Initialize machine learning model for anomaly detection"""
        if not ML_AVAILABLE:
            return
            
        try:
            self.ml_model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.scaler = StandardScaler()
            self.logger.info("ML model initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML model: {e}")
            self.ml_enabled = False
    
    def _is_ot_protocol(self, packet) -> Tuple[bool, str]:
        """Check if packet is using OT protocol"""
        if not SCAPY_AVAILABLE:
            return False, "Unknown"
        
        try:
            # Check TCP layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                for protocol, info in self.OT_PROTOCOLS.items():
                    if tcp.dport in info['ports'] or tcp.sport in info['ports']:
                        return True, protocol
            
            # Check UDP layer
            if packet.haslayer(UDP):
                udp = packet[UDP]
                for protocol, info in self.OT_PROTOCOLS.items():
                    if udp.dport in info['ports'] or udp.sport in info['ports']:
                        return True, protocol
            
            return False, "Unknown"
        except:
            return False, "Unknown"
    
    def _extract_packet_features(self, packet) -> Dict[str, Any]:
        """Extract features from packet for analysis"""
        features = {
            'timestamp': time.time(),
            'size': len(packet),
            'protocol': 'Unknown',
            'source_ip': 'Unknown',
            'destination_ip': 'Unknown',
            'source_port': 0,
            'destination_port': 0,
            'is_ot': False,
            'ot_protocol': 'Unknown'
        }
        
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                features['source_ip'] = ip.src
                features['destination_ip'] = ip.dst
                features['protocol'] = ip.proto
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                features['source_port'] = tcp.sport
                features['destination_port'] = tcp.dport
            
            if packet.haslayer(UDP):
                udp = packet[UDP]
                features['source_port'] = udp.sport
                features['destination_port'] = udp.dport
            
            # Check if OT protocol
            is_ot, ot_protocol = self._is_ot_protocol(packet)
            features['is_ot'] = is_ot
            features['ot_protocol'] = ot_protocol
            
        except Exception as e:
            self.logger.debug(f"Error extracting packet features: {e}")
        
        return features
    
    def _detect_protocol_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect protocol-specific anomalies"""
        anomalies = []
        
        if not features['is_ot']:
            return anomalies
        
        protocol = features['ot_protocol']
        if protocol not in self.OT_PROTOCOLS:
            return anomalies
        
        # Check for unusual function codes
        if protocol == 'Modbus':
            anomalies.extend(self._detect_modbus_anomalies(features))
        elif protocol == 'DNP3':
            anomalies.extend(self._detect_dnp3_anomalies(features))
        elif protocol == 'EtherNet/IP':
            anomalies.extend(self._detect_ethernet_ip_anomalies(features))
        
        return anomalies
    
    def _detect_modbus_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect Modbus-specific anomalies"""
        anomalies = []
        
        # This is a simplified example - in practice, you would analyze the actual Modbus payload
        # Check for unusual function codes, addresses, or data patterns
        
        # Example: Detect unusual function codes
        # In a real implementation, you would parse the Modbus payload
        # and check against known normal function codes
        
        return anomalies
    
    def _detect_dnp3_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect DNP3-specific anomalies"""
        anomalies = []
        
        # Similar to Modbus, this would analyze DNP3-specific patterns
        # Check for unusual function codes, object groups, etc.
        
        return anomalies
    
    def _detect_ethernet_ip_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect EtherNet/IP-specific anomalies"""
        anomalies = []
        
        # Analyze EtherNet/IP specific patterns
        # Check for unusual service requests, class IDs, etc.
        
        return anomalies
    
    def _detect_traffic_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect traffic pattern anomalies"""
        anomalies = []
        
        # Check for unusual traffic patterns
        current_time = datetime.now()
        
        # Check for unusual hours
        if current_time.hour in self.THRESHOLDS['unusual_hours']:
            anomaly = AnomalyEvent(
                timestamp=current_time.isoformat(),
                event_type="Unusual Time Activity",
                severity="Medium",
                source_ip=features['source_ip'],
                destination_ip=features['destination_ip'],
                protocol=features['ot_protocol'],
                description=f"OT traffic detected during unusual hours ({current_time.hour}:00)",
                details={'hour': current_time.hour, 'day': current_time.weekday()},
                confidence=0.8,
                recommended_action="Review activity logs and verify authorized access"
            )
            anomalies.append(anomaly)
        
        # Check for weekend activity
        if self.THRESHOLDS['weekend_activity'] and current_time.weekday() >= 5:
            anomaly = AnomalyEvent(
                timestamp=current_time.isoformat(),
                event_type="Weekend Activity",
                severity="Medium",
                source_ip=features['source_ip'],
                destination_ip=features['destination_ip'],
                protocol=features['ot_protocol'],
                description=f"OT traffic detected during weekend",
                details={'day': current_time.weekday(), 'date': current_time.date()},
                confidence=0.7,
                recommended_action="Verify weekend maintenance activities"
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_network_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect network-level anomalies"""
        anomalies = []
        
        # Check for unusual packet sizes
        if features['size'] > 1500:  # Jumbo frames
            anomaly = AnomalyEvent(
                timestamp=datetime.now().isoformat(),
                event_type="Unusual Packet Size",
                severity="Low",
                source_ip=features['source_ip'],
                destination_ip=features['destination_ip'],
                protocol=features['ot_protocol'],
                description=f"Unusually large packet detected ({features['size']} bytes)",
                details={'packet_size': features['size']},
                confidence=0.6,
                recommended_action="Review network configuration"
            )
            anomalies.append(anomaly)
        
        # Check for unusual port usage
        if features['is_ot'] and features['destination_port'] not in [502, 20000, 44818, 102]:
            anomaly = AnomalyEvent(
                timestamp=datetime.now().isoformat(),
                event_type="Unusual Port Usage",
                severity="Medium",
                source_ip=features['source_ip'],
                destination_ip=features['destination_ip'],
                protocol=features['ot_protocol'],
                description=f"OT protocol on unusual port {features['destination_port']}",
                details={'port': features['destination_port']},
                confidence=0.7,
                recommended_action="Verify port configuration and security"
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_ml_anomalies(self, features: Dict[str, Any]) -> List[AnomalyEvent]:
        """Detect anomalies using machine learning"""
        anomalies = []
        
        if not self.ml_enabled or not self.ml_model:
            return anomalies
        
        try:
            # Prepare features for ML model
            feature_vector = np.array([
                features['size'],
                features['source_port'],
                features['destination_port'],
                features['timestamp'] % 86400,  # Time of day
                features['timestamp'] % 604800  # Day of week
            ]).reshape(1, -1)
            
            # Scale features
            feature_vector = self.scaler.transform(feature_vector)
            
            # Predict anomaly
            prediction = self.ml_model.predict(feature_vector)
            anomaly_score = self.ml_model.decision_function(feature_vector)[0]
            
            if prediction[0] == -1:  # Anomaly detected
                anomaly = AnomalyEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="ML Detected Anomaly",
                    severity="Medium",
                    source_ip=features['source_ip'],
                    destination_ip=features['destination_ip'],
                    protocol=features['ot_protocol'],
                    description=f"Machine learning model detected anomalous pattern (score: {anomaly_score:.3f})",
                    details={'anomaly_score': anomaly_score, 'ml_model': 'IsolationForest'},
                    confidence=abs(anomaly_score),
                    recommended_action="Investigate traffic patterns and verify legitimacy"
                )
                anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"ML anomaly detection error: {e}")
        
        return anomalies
    
    def _update_baseline(self, features: Dict[str, Any]):
        """Update baseline traffic patterns"""
        key = f"{features['source_ip']}:{features['destination_ip']}:{features['ot_protocol']}"
        
        if key not in self.baseline_patterns:
            self.baseline_patterns[key] = TrafficPattern(
                source_ip=features['source_ip'],
                destination_ip=features['destination_ip'],
                protocol=features['ot_protocol'],
                port=features['destination_port'],
                packet_count=1,
                byte_count=features['size'],
                frequency=1.0,
                timestamp=datetime.now().isoformat()
            )
        else:
            pattern = self.baseline_patterns[key]
            pattern.packet_count += 1
            pattern.byte_count += features['size']
            pattern.frequency = pattern.packet_count / (time.time() - datetime.fromisoformat(pattern.timestamp).timestamp())
    
    def _train_ml_model(self):
        """Train the ML model on baseline data"""
        if not self.ml_enabled or not self.ml_model:
            return
        
        try:
            # Prepare training data
            training_data = []
            for pattern in self.baseline_patterns.values():
                feature_vector = [
                    pattern.byte_count,
                    pattern.port,
                    pattern.frequency,
                    datetime.fromisoformat(pattern.timestamp).hour,
                    datetime.fromisoformat(pattern.timestamp).weekday()
                ]
                training_data.append(feature_vector)
            
            if len(training_data) > 10:  # Need minimum data for training
                training_data = np.array(training_data)
                self.scaler.fit(training_data)
                scaled_data = self.scaler.transform(training_data)
                self.ml_model.fit(scaled_data)
                self.logger.info("ML model trained successfully")
        
        except Exception as e:
            self.logger.error(f"ML model training error: {e}")
    
    def _packet_handler(self, packet):
        """Handle incoming packets for analysis"""
        try:
            # Extract features
            features = self._extract_packet_features(packet)
            
            # Add to traffic history
            self.traffic_history.append(features)
            
            # Update baseline
            self._update_baseline(features)
            
            # Detect anomalies
            all_anomalies = []
            
            # Protocol-specific anomalies
            protocol_anomalies = self._detect_protocol_anomalies(features)
            all_anomalies.extend(protocol_anomalies)
            
            # Traffic pattern anomalies
            traffic_anomalies = self._detect_traffic_anomalies(features)
            all_anomalies.extend(traffic_anomalies)
            
            # Network anomalies
            network_anomalies = self._detect_network_anomalies(features)
            all_anomalies.extend(network_anomalies)
            
            # ML-based anomalies
            ml_anomalies = self._detect_ml_anomalies(features)
            all_anomalies.extend(ml_anomalies)
            
            # Add anomalies to list
            for anomaly in all_anomalies:
                self.anomalies.append(anomaly)
                self.logger.warning(f"Anomaly detected: {anomaly.description}")
        
        except Exception as e:
            self.logger.error(f"Packet handler error: {e}")
    
    def start_monitoring(self, interface: str = None):
        """Start real-time monitoring"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot start monitoring.")
            return False
        
        interface = interface or self.monitor_interface
        self.monitoring = True
        
        self.logger.info(f"Starting anomaly detection on interface {interface}")
        
        try:
            # Start packet capture
            scapy.sniff(
                iface=interface,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.monitoring,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
            return False
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.logger.info("Monitoring stopped")
    
    def analyze_traffic_file(self, pcap_file: str) -> List[AnomalyEvent]:
        """Analyze traffic from a PCAP file"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot analyze PCAP file.")
            return []
        
        self.logger.info(f"Analyzing traffic from {pcap_file}")
        
        try:
            packets = scapy.rdpcap(pcap_file)
            
            for packet in packets:
                self._packet_handler(packet)
            
            # Train ML model on analyzed data
            self._train_ml_model()
            
            self.logger.info(f"Analysis complete. Found {len(self.anomalies)} anomalies.")
            return self.anomalies
        
        except Exception as e:
            self.logger.error(f"PCAP analysis error: {e}")
            return []
    
    def export_results(self, filename: str = None) -> str:
        """Export anomaly results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ot_anomalies_{timestamp}.json"
        
        export_data = {
            'analysis_info': {
                'timestamp': datetime.now().isoformat(),
                'total_anomalies': len(self.anomalies),
                'baseline_patterns': len(self.baseline_patterns),
                'config': self.config
            },
            'anomalies': [asdict(anomaly) for anomaly in self.anomalies],
            'baseline_patterns': {key: asdict(pattern) for key, pattern in self.baseline_patterns.items()}
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Results exported to {filename}")
        return filename
    
    def generate_report(self) -> str:
        """Generate a human-readable anomaly report"""
        report = []
        report.append("OT Anomaly Detection Report")
        report.append("=" * 50)
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Anomalies: {len(self.anomalies)}")
        report.append("")
        
        # Severity summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for anomaly in self.anomalies:
            severity_counts[anomaly.severity] += 1
        
        report.append("Severity Summary:")
        for severity, count in severity_counts.items():
            report.append(f"  {severity}: {count}")
        report.append("")
        
        # Event type summary
        event_types = defaultdict(int)
        for anomaly in self.anomalies:
            event_types[anomaly.event_type] += 1
        
        report.append("Event Types:")
        for event_type, count in event_types.items():
            report.append(f"  {event_type}: {count}")
        report.append("")
        
        # Detailed anomalies
        report.append("Detailed Anomalies:")
        report.append("-" * 30)
        
        for anomaly in self.anomalies:
            report.append(f"Timestamp: {anomaly.timestamp}")
            report.append(f"Type: {anomaly.event_type}")
            report.append(f"Severity: {anomaly.severity}")
            report.append(f"Source: {anomaly.source_ip}")
            report.append(f"Destination: {anomaly.destination_ip}")
            report.append(f"Protocol: {anomaly.protocol}")
            report.append(f"Description: {anomaly.description}")
            report.append(f"Confidence: {anomaly.confidence:.2f}")
            report.append(f"Action: {anomaly.recommended_action}")
            report.append("")
        
        return "\n".join(report)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="OT Anomaly Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python anomaly_detection.py --interface eth0
  python anomaly_detection.py --pcap traffic.pcap
  python anomaly_detection.py --baseline-duration 7200 --ml-enabled
        """
    )
    
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface to monitor')
    parser.add_argument('--pcap', help='PCAP file to analyze')
    parser.add_argument('--baseline-duration', type=int, default=3600, help='Baseline duration in seconds')
    parser.add_argument('--anomaly-threshold', type=float, default=0.1, help='Anomaly detection threshold')
    parser.add_argument('--ml-enabled', action='store_true', help='Enable machine learning detection')
    parser.add_argument('--output', '-o', help='Output filename for results')
    parser.add_argument('--report', '-r', action='store_true', help='Generate text report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'interface': args.interface,
        'baseline_duration': args.baseline_duration,
        'anomaly_threshold': args.anomaly_threshold,
        'ml_enabled': args.ml_enabled
    }
    
    # Setup logging
    if args.verbose:
        logging.getLogger('OTAnomalyDetector').setLevel(logging.DEBUG)
    
    # Initialize detector
    detector = OTAnomalyDetector(config)
    
    try:
        if args.pcap:
            # Analyze PCAP file
            anomalies = detector.analyze_traffic_file(args.pcap)
        else:
            # Start real-time monitoring
            print("Starting real-time monitoring. Press Ctrl+C to stop.")
            detector.start_monitoring()
        
        # Export results
        output_file = detector.export_results(args.output)
        
        # Generate report if requested
        if args.report:
            report = detector.generate_report()
            report_file = output_file.replace('.json', '_report.txt')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"Report saved to {report_file}")
        
        print(f"Analysis complete. Found {len(detector.anomalies)} anomalies.")
        print(f"Results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        detector.stop_monitoring()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

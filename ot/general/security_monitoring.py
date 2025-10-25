#!/usr/bin/env python3
"""
OT Security Event Monitoring Script
==================================

A comprehensive security event monitoring system for Operational Technology (OT) environments.
Designed to collect, analyze, and alert on security events from various sources including
firewalls, IDS/IPS, SIEM systems, and OT-specific security tools.

Features:
- Multi-source event collection
- Real-time event correlation
- OT-specific threat detection
- Automated alerting and notifications
- Compliance reporting
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
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import queue
import re

# Windows compatibility
if sys.platform == "win32":
    import winreg
    import subprocess
else:
    import subprocess

@dataclass
class SecurityEvent:
    """Represents a security event"""
    timestamp: str
    event_id: str
    event_type: str
    severity: str  # Critical, High, Medium, Low, Info
    source: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    description: str
    details: Dict[str, Any]
    raw_data: str
    correlation_id: Optional[str] = None
    status: str = "New"  # New, Investigating, Resolved, False Positive

@dataclass
class AlertRule:
    """Represents an alert rule"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    severity: str
    enabled: bool
    actions: List[str]

@dataclass
class NotificationConfig:
    """Represents notification configuration"""
    email_enabled: bool
    email_smtp_server: str
    email_smtp_port: int
    email_username: str
    email_password: str
    email_recipients: List[str]
    webhook_enabled: bool
    webhook_url: str
    slack_enabled: bool
    slack_webhook: str

class OTSecurityMonitor:
    """Main class for OT security event monitoring"""
    
    # OT-specific event types
    OT_EVENT_TYPES = {
        'OT_PROTOCOL_VIOLATION': 'OT Protocol Violation',
        'OT_DEVICE_COMPROMISE': 'OT Device Compromise',
        'OT_NETWORK_INTRUSION': 'OT Network Intrusion',
        'OT_MALWARE_DETECTION': 'OT Malware Detection',
        'OT_UNAUTHORIZED_ACCESS': 'Unauthorized OT Access',
        'OT_DATA_EXFILTRATION': 'OT Data Exfiltration',
        'OT_SYSTEM_MANIPULATION': 'OT System Manipulation',
        'OT_NETWORK_SCANNING': 'OT Network Scanning',
        'OT_PROTOCOL_ANOMALY': 'OT Protocol Anomaly',
        'OT_DEVICE_OFFLINE': 'OT Device Offline',
        'OT_CONFIGURATION_CHANGE': 'OT Configuration Change'
    }
    
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
    
    # Critical OT devices (example)
    CRITICAL_DEVICES = [
        '192.168.1.10',  # PLC 1
        '192.168.1.11',  # PLC 2
        '192.168.1.20',  # HMI 1
        '192.168.1.21',  # HMI 2
        '192.168.1.30',  # SCADA Server
        '192.168.1.31'   # Historian
    ]
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = self._setup_logging()
        self.events: List[SecurityEvent] = []
        self.alert_rules: List[AlertRule] = []
        self.notification_config: Optional[NotificationConfig] = None
        self.monitoring = False
        self.event_queue = queue.Queue()
        self.correlation_engine = CorrelationEngine()
        
        # Configuration
        self.monitor_sources = self.config.get('monitor_sources', [])
        self.alert_threshold = self.config.get('alert_threshold', 5)
        self.correlation_window = self.config.get('correlation_window', 300)  # 5 minutes
        self.retention_days = self.config.get('retention_days', 30)
        
        # Load configuration
        self._load_alert_rules()
        self._load_notification_config()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('OTSecurityMonitor')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _load_alert_rules(self):
        """Load alert rules from configuration"""
        # Default alert rules
        default_rules = [
            AlertRule(
                rule_id="OT_PROTOCOL_VIOLATION",
                name="OT Protocol Violation",
                description="Detect violations of OT protocols",
                conditions={
                    'event_type': 'OT_PROTOCOL_VIOLATION',
                    'severity': ['High', 'Critical']
                },
                severity="High",
                enabled=True,
                actions=["email", "webhook"]
            ),
            AlertRule(
                rule_id="OT_DEVICE_COMPROMISE",
                name="OT Device Compromise",
                description="Detect potential compromise of OT devices",
                conditions={
                    'event_type': 'OT_DEVICE_COMPROMISE',
                    'severity': ['Critical']
                },
                severity="Critical",
                enabled=True,
                actions=["email", "webhook", "slack"]
            ),
            AlertRule(
                rule_id="OT_NETWORK_INTRUSION",
                name="OT Network Intrusion",
                description="Detect network intrusions in OT environment",
                conditions={
                    'event_type': 'OT_NETWORK_INTRUSION',
                    'severity': ['High', 'Critical']
                },
                severity="High",
                enabled=True,
                actions=["email", "webhook"]
            )
        ]
        
        self.alert_rules = default_rules
    
    def _load_notification_config(self):
        """Load notification configuration"""
        # Default configuration (should be loaded from config file in production)
        self.notification_config = NotificationConfig(
            email_enabled=False,
            email_smtp_server="",
            email_smtp_port=587,
            email_username="",
            email_password="",
            email_recipients=[],
            webhook_enabled=False,
            webhook_url="",
            slack_enabled=False,
            slack_webhook=""
        )
    
    def _parse_syslog_event(self, raw_data: str) -> Optional[SecurityEvent]:
        """Parse syslog event"""
        try:
            # Basic syslog parsing (RFC 3164)
            parts = raw_data.split(' ', 5)
            if len(parts) < 6:
                return None
            
            timestamp_str = f"{parts[0]} {parts[1]} {parts[2]}"
            hostname = parts[3]
            tag = parts[4]
            message = parts[5]
            
            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
            
            # Extract IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, message)
            
            source_ip = ips[0] if ips else "Unknown"
            destination_ip = ips[1] if len(ips) > 1 else "Unknown"
            
            # Determine event type and severity
            event_type = "UNKNOWN"
            severity = "Info"
            
            if "denied" in message.lower() or "blocked" in message.lower():
                event_type = "OT_NETWORK_INTRUSION"
                severity = "High"
            elif "failed" in message.lower() or "error" in message.lower():
                event_type = "OT_DEVICE_COMPROMISE"
                severity = "Medium"
            elif "scan" in message.lower() or "probe" in message.lower():
                event_type = "OT_NETWORK_SCANNING"
                severity = "Medium"
            
            # Check if it's an OT protocol
            protocol = "Unknown"
            port = 0
            for proto, ports in self.OT_PROTOCOLS.items():
                for p in ports:
                    if str(p) in message:
                        protocol = proto
                        port = p
                        break
            
            event = SecurityEvent(
                timestamp=timestamp.isoformat(),
                event_id=f"syslog_{int(time.time())}_{hash(raw_data) % 10000}",
                event_type=event_type,
                severity=severity,
                source="syslog",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                description=message,
                details={"hostname": hostname, "tag": tag},
                raw_data=raw_data
            )
            
            return event
        
        except Exception as e:
            self.logger.error(f"Error parsing syslog event: {e}")
            return None
    
    def _parse_firewall_event(self, raw_data: str) -> Optional[SecurityEvent]:
        """Parse firewall event"""
        try:
            # Basic firewall log parsing
            # This would need to be customized based on the specific firewall vendor
            
            # Extract timestamp
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', raw_data)
            timestamp = datetime.now().isoformat()
            if timestamp_match:
                timestamp = datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S").isoformat()
            
            # Extract IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, raw_data)
            
            source_ip = ips[0] if ips else "Unknown"
            destination_ip = ips[1] if len(ips) > 1 else "Unknown"
            
            # Extract port
            port_match = re.search(r':(\d+)', raw_data)
            port = int(port_match.group(1)) if port_match else 0
            
            # Determine event type
            event_type = "OT_NETWORK_INTRUSION"
            severity = "Medium"
            
            if "DENY" in raw_data or "BLOCK" in raw_data:
                severity = "High"
            elif "ALLOW" in raw_data:
                severity = "Low"
            
            event = SecurityEvent(
                timestamp=timestamp,
                event_id=f"firewall_{int(time.time())}_{hash(raw_data) % 10000}",
                event_type=event_type,
                severity=severity,
                source="firewall",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="Unknown",
                port=port,
                description=raw_data,
                details={},
                raw_data=raw_data
            )
            
            return event
        
        except Exception as e:
            self.logger.error(f"Error parsing firewall event: {e}")
            return None
    
    def _parse_ot_device_event(self, raw_data: str) -> Optional[SecurityEvent]:
        """Parse OT device event"""
        try:
            # Parse OT device specific events
            # This would be customized based on the specific OT devices and protocols
            
            # Extract timestamp
            timestamp = datetime.now().isoformat()
            
            # Extract device information
            device_ip = "Unknown"
            if "192.168.1." in raw_data:
                ip_match = re.search(r'(192\.168\.1\.\d+)', raw_data)
                if ip_match:
                    device_ip = ip_match.group(1)
            
            # Determine event type based on content
            event_type = "OT_DEVICE_COMPROMISE"
            severity = "Medium"
            
            if "offline" in raw_data.lower() or "disconnected" in raw_data.lower():
                event_type = "OT_DEVICE_OFFLINE"
                severity = "High"
            elif "configuration" in raw_data.lower() or "config" in raw_data.lower():
                event_type = "OT_CONFIGURATION_CHANGE"
                severity = "Medium"
            elif "malware" in raw_data.lower() or "virus" in raw_data.lower():
                event_type = "OT_MALWARE_DETECTION"
                severity = "Critical"
            
            event = SecurityEvent(
                timestamp=timestamp,
                event_id=f"ot_device_{int(time.time())}_{hash(raw_data) % 10000}",
                event_type=event_type,
                severity=severity,
                source="ot_device",
                source_ip=device_ip,
                destination_ip="Unknown",
                protocol="Unknown",
                port=0,
                description=raw_data,
                details={},
                raw_data=raw_data
            )
            
            return event
        
        except Exception as e:
            self.logger.error(f"Error parsing OT device event: {e}")
            return None
    
    def _correlate_events(self, event: SecurityEvent) -> List[SecurityEvent]:
        """Correlate events to identify patterns"""
        correlated_events = []
        
        # Check for related events within correlation window
        correlation_time = datetime.fromisoformat(event.timestamp)
        window_start = correlation_time - timedelta(seconds=self.correlation_window)
        
        for existing_event in self.events:
            existing_time = datetime.fromisoformat(existing_event.timestamp)
            
            if window_start <= existing_time <= correlation_time:
                # Check for correlation criteria
                if (existing_event.source_ip == event.source_ip or 
                    existing_event.destination_ip == event.destination_ip):
                    
                    # Create correlation
                    correlation_id = f"corr_{int(time.time())}"
                    event.correlation_id = correlation_id
                    existing_event.correlation_id = correlation_id
                    
                    correlated_events.append(existing_event)
        
        return correlated_events
    
    def _check_alert_rules(self, event: SecurityEvent) -> List[AlertRule]:
        """Check if event matches any alert rules"""
        triggered_rules = []
        
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            
            # Check conditions
            conditions_met = True
            
            for condition, value in rule.conditions.items():
                if condition == 'event_type':
                    if event.event_type != value:
                        conditions_met = False
                        break
                elif condition == 'severity':
                    if event.severity not in value:
                        conditions_met = False
                        break
                elif condition == 'source_ip':
                    if event.source_ip not in value:
                        conditions_met = False
                        break
                elif condition == 'destination_ip':
                    if event.destination_ip not in value:
                        conditions_met = False
                        break
            
            if conditions_met:
                triggered_rules.append(rule)
        
        return triggered_rules
    
    def _send_email_alert(self, event: SecurityEvent, rule: AlertRule):
        """Send email alert"""
        if not self.notification_config or not self.notification_config.email_enabled:
            return
        
        try:
            # Create email content
            subject = f"OT Security Alert: {rule.name}"
            body = f"""
OT Security Event Alert

Event Details:
- Timestamp: {event.timestamp}
- Event Type: {event.event_type}
- Severity: {event.severity}
- Source IP: {event.source_ip}
- Destination IP: {event.destination_ip}
- Protocol: {event.protocol}
- Port: {event.port}
- Description: {event.description}

Rule: {rule.name}
Rule Description: {rule.description}

Please investigate this event immediately.

OT Security Monitoring System
            """
            
            # Send email
            server = smtplib.SMTP(self.notification_config.email_smtp_server, 
                                self.notification_config.email_smtp_port)
            server.starttls()
            server.login(self.notification_config.email_username, 
                        self.notification_config.email_password)
            
            for recipient in self.notification_config.email_recipients:
                message = f"Subject: {subject}\n\n{body}"
                server.sendmail(self.notification_config.email_username, recipient, message)
            
            server.quit()
            self.logger.info(f"Email alert sent for event {event.event_id}")
        
        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")
    
    def _send_webhook_alert(self, event: SecurityEvent, rule: AlertRule):
        """Send webhook alert"""
        if not self.notification_config or not self.notification_config.webhook_enabled:
            return
        
        try:
            payload = {
                'event_id': event.event_id,
                'event_type': event.event_type,
                'severity': event.severity,
                'timestamp': event.timestamp,
                'source_ip': event.source_ip,
                'destination_ip': event.destination_ip,
                'description': event.description,
                'rule_name': rule.name,
                'rule_description': rule.description
            }
            
            response = requests.post(
                self.notification_config.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook alert sent for event {event.event_id}")
            else:
                self.logger.error(f"Webhook alert failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")
    
    def _send_slack_alert(self, event: SecurityEvent, rule: AlertRule):
        """Send Slack alert"""
        if not self.notification_config or not self.notification_config.slack_enabled:
            return
        
        try:
            payload = {
                'text': f"🚨 OT Security Alert: {rule.name}",
                'attachments': [
                    {
                        'color': 'danger' if event.severity in ['Critical', 'High'] else 'warning',
                        'fields': [
                            {'title': 'Event Type', 'value': event.event_type, 'short': True},
                            {'title': 'Severity', 'value': event.severity, 'short': True},
                            {'title': 'Source IP', 'value': event.source_ip, 'short': True},
                            {'title': 'Destination IP', 'value': event.destination_ip, 'short': True},
                            {'title': 'Description', 'value': event.description, 'short': False}
                        ]
                    }
                ]
            }
            
            response = requests.post(
                self.notification_config.slack_webhook,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Slack alert sent for event {event.event_id}")
            else:
                self.logger.error(f"Slack alert failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {e}")
    
    def _process_event(self, event: SecurityEvent):
        """Process a security event"""
        try:
            # Add to events list
            self.events.append(event)
            
            # Correlate with existing events
            correlated_events = self._correlate_events(event)
            
            # Check alert rules
            triggered_rules = self._check_alert_rules(event)
            
            # Send alerts
            for rule in triggered_rules:
                self.logger.warning(f"Alert triggered: {rule.name} for event {event.event_id}")
                
                # Send notifications based on rule actions
                for action in rule.actions:
                    if action == "email":
                        self._send_email_alert(event, rule)
                    elif action == "webhook":
                        self._send_webhook_alert(event, rule)
                    elif action == "slack":
                        self._send_slack_alert(event, rule)
            
            # Log event
            self.logger.info(f"Processed event: {event.event_type} - {event.description}")
        
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
    
    def _event_processor_thread(self):
        """Event processor thread"""
        while self.monitoring:
            try:
                # Get event from queue
                event = self.event_queue.get(timeout=1)
                
                # Process event
                self._process_event(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Event processor error: {e}")
    
    def _syslog_listener(self, port: int = 514):
        """Listen for syslog events"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            sock.settimeout(1)
            
            self.logger.info(f"Syslog listener started on port {port}")
            
            while self.monitoring:
                try:
                    data, addr = sock.recvfrom(1024)
                    raw_data = data.decode('utf-8', errors='ignore')
                    
                    # Parse syslog event
                    event = self._parse_syslog_event(raw_data)
                    if event:
                        self.event_queue.put(event)
                
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Syslog listener error: {e}")
            
            sock.close()
        
        except Exception as e:
            self.logger.error(f"Syslog listener setup error: {e}")
    
    def _file_monitor(self, file_path: str):
        """Monitor log file for new events"""
        try:
            # Get initial file size
            last_size = os.path.getsize(file_path)
            
            while self.monitoring:
                try:
                    current_size = os.path.getsize(file_path)
                    
                    if current_size > last_size:
                        # Read new content
                        with open(file_path, 'r') as f:
                            f.seek(last_size)
                            new_content = f.read()
                        
                        # Parse new events
                        for line in new_content.strip().split('\n'):
                            if line.strip():
                                # Determine event type based on file path
                                if 'firewall' in file_path.lower():
                                    event = self._parse_firewall_event(line)
                                elif 'ot_device' in file_path.lower():
                                    event = self._parse_ot_device_event(line)
                                else:
                                    event = self._parse_syslog_event(line)
                                
                                if event:
                                    self.event_queue.put(event)
                        
                        last_size = current_size
                    
                    time.sleep(1)
                
                except Exception as e:
                    self.logger.error(f"File monitor error: {e}")
                    time.sleep(5)
        
        except Exception as e:
            self.logger.error(f"File monitor setup error: {e}")
    
    def start_monitoring(self, sources: List[Dict[str, Any]] = None):
        """Start security event monitoring"""
        self.monitoring = True
        
        # Start event processor thread
        processor_thread = threading.Thread(target=self._event_processor_thread)
        processor_thread.daemon = True
        processor_thread.start()
        
        # Start monitoring threads for each source
        monitor_threads = []
        
        for source in (sources or self.monitor_sources):
            source_type = source.get('type', 'syslog')
            
            if source_type == 'syslog':
                port = source.get('port', 514)
                thread = threading.Thread(target=self._syslog_listener, args=(port,))
                thread.daemon = True
                thread.start()
                monitor_threads.append(thread)
            
            elif source_type == 'file':
                file_path = source.get('path')
                if file_path and os.path.exists(file_path):
                    thread = threading.Thread(target=self._file_monitor, args=(file_path,))
                    thread.daemon = True
                    thread.start()
                    monitor_threads.append(thread)
        
        self.logger.info(f"Security monitoring started with {len(monitor_threads)} sources")
        
        # Wait for threads
        try:
            for thread in monitor_threads:
                thread.join()
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.logger.info("Security monitoring stopped")
    
    def export_results(self, filename: str = None) -> str:
        """Export monitoring results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ot_security_events_{timestamp}.json"
        
        export_data = {
            'monitoring_info': {
                'timestamp': datetime.now().isoformat(),
                'total_events': len(self.events),
                'config': self.config
            },
            'events': [asdict(event) for event in self.events],
            'alert_rules': [asdict(rule) for rule in self.alert_rules]
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Results exported to {filename}")
        return filename
    
    def generate_report(self) -> str:
        """Generate a human-readable security report"""
        report = []
        report.append("OT Security Event Monitoring Report")
        report.append("=" * 50)
        report.append(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Events: {len(self.events)}")
        report.append("")
        
        # Severity summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for event in self.events:
            severity_counts[event.severity] += 1
        
        report.append("Severity Summary:")
        for severity, count in severity_counts.items():
            report.append(f"  {severity}: {count}")
        report.append("")
        
        # Event type summary
        event_types = defaultdict(int)
        for event in self.events:
            event_types[event.event_type] += 1
        
        report.append("Event Types:")
        for event_type, count in event_types.items():
            report.append(f"  {event_type}: {count}")
        report.append("")
        
        # Recent events
        report.append("Recent Events (Last 10):")
        report.append("-" * 30)
        
        recent_events = sorted(self.events, key=lambda x: x.timestamp, reverse=True)[:10]
        for event in recent_events:
            report.append(f"Timestamp: {event.timestamp}")
            report.append(f"Type: {event.event_type}")
            report.append(f"Severity: {event.severity}")
            report.append(f"Source: {event.source_ip}")
            report.append(f"Description: {event.description}")
            report.append("")
        
        return "\n".join(report)

class CorrelationEngine:
    """Event correlation engine"""
    
    def __init__(self):
        self.correlation_rules = []
        self.correlation_window = 300  # 5 minutes
    
    def add_correlation_rule(self, rule):
        """Add correlation rule"""
        self.correlation_rules.append(rule)
    
    def correlate_events(self, events):
        """Correlate events based on rules"""
        correlated_events = []
        
        for rule in self.correlation_rules:
            matches = rule.match(events)
            if matches:
                correlated_events.extend(matches)
        
        return correlated_events

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="OT Security Event Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_monitoring.py --syslog-port 514
  python security_monitoring.py --monitor-file /var/log/firewall.log
  python security_monitoring.py --config monitoring_config.json
        """
    )
    
    parser.add_argument('--syslog-port', type=int, default=514, help='Syslog port to listen on')
    parser.add_argument('--monitor-file', help='Log file to monitor')
    parser.add_argument('--config', help='Configuration file')
    parser.add_argument('--output', '-o', help='Output filename for results')
    parser.add_argument('--report', '-r', action='store_true', help='Generate text report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'monitor_sources': [],
        'alert_threshold': 5,
        'correlation_window': 300,
        'retention_days': 30
    }
    
    # Add monitoring sources
    if args.syslog_port:
        config['monitor_sources'].append({
            'type': 'syslog',
            'port': args.syslog_port
        })
    
    if args.monitor_file:
        config['monitor_sources'].append({
            'type': 'file',
            'path': args.monitor_file
        })
    
    # Load configuration file if provided
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
    
    # Setup logging
    if args.verbose:
        logging.getLogger('OTSecurityMonitor').setLevel(logging.DEBUG)
    
    # Initialize monitor
    monitor = OTSecurityMonitor(config)
    
    try:
        # Start monitoring
        print("Starting security event monitoring. Press Ctrl+C to stop.")
        monitor.start_monitoring()
        
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        monitor.stop_monitoring()
        
        # Export results
        output_file = monitor.export_results(args.output)
        
        # Generate report if requested
        if args.report:
            report = monitor.generate_report()
            report_file = output_file.replace('.json', '_report.txt')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"Report saved to {report_file}")
        
        print(f"Monitoring complete. Found {len(monitor.events)} events.")
        print(f"Results saved to {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

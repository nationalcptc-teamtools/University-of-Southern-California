#!/usr/bin/env python3
"""
Privileged Account Activity Monitor for Maritime OT Systems
==========================================================

This script logs and monitors privileged account activities on maritime OT systems
for anomaly detection and forensic readiness.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import time
import threading
import queue
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import subprocess
import os
import hashlib
import sqlite3
from pathlib import Path

class PrivilegeActivityMonitor:
    def __init__(self, config_file=None):
        """
        Initialize the privilege activity monitor
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.monitoring_active = False
        self.activity_log = []
        self.anomalies = []
        self.privileged_accounts = set()
        self.baseline_activities = defaultdict(list)
        self.alert_queue = queue.Queue()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('privilege_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self.db_path = 'privilege_activities.db'
        self._init_database()
        
        # Maritime OT privileged accounts
        self.ot_privileged_accounts = {
            'navigation': {
                'accounts': ['nav_admin', 'gps_operator', 'radar_admin'],
                'privileges': ['system_admin', 'device_control', 'data_access'],
                'criticality': 'HIGH'
            },
            'engine': {
                'accounts': ['engine_admin', 'propulsion_operator', 'fuel_manager'],
                'privileges': ['system_admin', 'device_control', 'emergency_override'],
                'criticality': 'CRITICAL'
            },
            'safety': {
                'accounts': ['safety_admin', 'fire_system_operator', 'emergency_controller'],
                'privileges': ['system_admin', 'emergency_override', 'safety_control'],
                'criticality': 'CRITICAL'
            },
            'communication': {
                'accounts': ['comm_admin', 'radio_operator', 'satellite_controller'],
                'privileges': ['system_admin', 'communication_control'],
                'criticality': 'HIGH'
            },
            'cargo': {
                'accounts': ['cargo_admin', 'loading_operator', 'crane_controller'],
                'privileges': ['system_admin', 'cargo_control'],
                'criticality': 'MEDIUM'
            }
        }
        
        # Activity patterns for anomaly detection
        self.suspicious_patterns = {
            'unusual_hours': {
                'description': 'Activity outside normal business hours',
                'severity': 'MEDIUM',
                'pattern': r'(02:00|03:00|04:00|05:00|22:00|23:00)'
            },
            'rapid_commands': {
                'description': 'Rapid succession of commands',
                'severity': 'HIGH',
                'pattern': r'command.*command.*command'
            },
            'privilege_escalation': {
                'description': 'Attempts to escalate privileges',
                'severity': 'CRITICAL',
                'pattern': r'(sudo|su|runas|elevate)'
            },
            'system_modification': {
                'description': 'Modification of critical system files',
                'severity': 'HIGH',
                'pattern': r'(/etc/|/system32/|registry|config)'
            },
            'network_access': {
                'description': 'Unusual network access patterns',
                'severity': 'MEDIUM',
                'pattern': r'(telnet|ssh|ftp|http)'
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'monitoring': {
                'log_file_paths': [
                    '/var/log/auth.log',
                    '/var/log/secure',
                    '/var/log/syslog',
                    'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'
                ],
                'monitoring_interval': 1,
                'retention_days': 30,
                'real_time_monitoring': True
            },
            'anomaly_detection': {
                'baseline_period_days': 7,
                'anomaly_threshold': 0.8,
                'alert_threshold': 5
            },
            'alerting': {
                'email_alerts': False,
                'log_alerts': True,
                'console_alerts': True
            },
            'forensic': {
                'enable_forensic_logging': True,
                'hash_activities': True,
                'detailed_timestamps': True
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
    
    def _init_database(self):
        """Initialize SQLite database for activity logging"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create activities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    account TEXT NOT NULL,
                    system TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    command TEXT,
                    source_ip TEXT,
                    success BOOLEAN,
                    hash_value TEXT,
                    severity TEXT,
                    is_anomaly BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create anomalies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    account TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    activity_id INTEGER,
                    FOREIGN KEY (activity_id) REFERENCES activities (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
    
    def start_monitoring(self):
        """Start real-time monitoring of privileged activities"""
        self.logger.info("Starting privileged account activity monitoring")
        self.monitoring_active = True
        
        # Start monitoring threads
        threads = []
        
        # Log file monitoring thread
        log_thread = threading.Thread(target=self._monitor_log_files)
        log_thread.daemon = True
        log_thread.start()
        threads.append(log_thread)
        
        # Anomaly detection thread
        anomaly_thread = threading.Thread(target=self._detect_anomalies)
        anomaly_thread.daemon = True
        anomaly_thread.start()
        threads.append(anomaly_thread)
        
        # Alert processing thread
        alert_thread = threading.Thread(target=self._process_alerts)
        alert_thread.daemon = True
        alert_thread.start()
        threads.append(alert_thread)
        
        return threads
    
    def _monitor_log_files(self):
        """Monitor log files for privileged activities"""
        while self.monitoring_active:
            try:
                for log_path in self.config['monitoring']['log_file_paths']:
                    if os.path.exists(log_path):
                        self._parse_log_file(log_path)
                
                time.sleep(self.config['monitoring']['monitoring_interval'])
                
            except Exception as e:
                self.logger.error(f"Error monitoring log files: {e}")
                time.sleep(5)
    
    def _parse_log_file(self, log_path):
        """Parse log file for privileged activities"""
        try:
            # Simulate log parsing (in real implementation, would parse actual log files)
            activities = self._simulate_log_activities(log_path)
            
            for activity in activities:
                self._process_activity(activity)
                
        except Exception as e:
            self.logger.error(f"Error parsing log file {log_path}: {e}")
    
    def _simulate_log_activities(self, log_path):
        """Simulate log activities for demonstration"""
        import random
        
        activities = []
        
        # Simulate some privileged activities
        if random.random() < 0.3:  # 30% chance of activity
            activity = {
                'timestamp': datetime.now().isoformat(),
                'account': random.choice(['nav_admin', 'engine_admin', 'safety_admin']),
                'system': random.choice(['navigation', 'engine', 'safety']),
                'activity_type': random.choice(['login', 'command', 'file_access', 'system_change']),
                'command': random.choice(['sudo systemctl restart', 'chmod 777', 'useradd', 'systemctl stop']),
                'source_ip': f"192.168.10.{random.randint(1, 254)}",
                'success': random.choice([True, False])
            }
            activities.append(activity)
        
        return activities
    
    def _process_activity(self, activity):
        """Process and store a privileged activity"""
        try:
            # Calculate hash for forensic purposes
            activity_hash = self._calculate_activity_hash(activity)
            activity['hash_value'] = activity_hash
            
            # Determine severity
            severity = self._determine_activity_severity(activity)
            activity['severity'] = severity
            
            # Store in database
            self._store_activity(activity)
            
            # Add to activity log
            self.activity_log.append(activity)
            
            # Check for immediate anomalies
            if self._is_immediate_anomaly(activity):
                self._create_anomaly_alert(activity)
            
            self.logger.info(f"Processed activity: {activity['account']} - {activity['activity_type']}")
            
        except Exception as e:
            self.logger.error(f"Error processing activity: {e}")
    
    def _calculate_activity_hash(self, activity):
        """Calculate hash for forensic purposes"""
        activity_string = f"{activity['timestamp']}{activity['account']}{activity['command']}"
        return hashlib.sha256(activity_string.encode()).hexdigest()
    
    def _determine_activity_severity(self, activity):
        """Determine severity of an activity"""
        severity = 'LOW'
        
        # Check for high-severity activities
        high_severity_patterns = [
            r'sudo.*systemctl.*stop',
            r'chmod.*777',
            r'useradd.*admin',
            r'systemctl.*restart.*critical'
        ]
        
        command = activity.get('command', '')
        for pattern in high_severity_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                severity = 'HIGH'
                break
        
        # Check for critical activities
        critical_patterns = [
            r'sudo.*rm.*-rf',
            r'systemctl.*disable.*safety',
            r'chown.*root.*critical'
        ]
        
        for pattern in critical_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                severity = 'CRITICAL'
                break
        
        return severity
    
    def _is_immediate_anomaly(self, activity):
        """Check if activity is an immediate anomaly"""
        command = activity.get('command', '')
        timestamp = datetime.fromisoformat(activity['timestamp'])
        
        # Check for suspicious patterns
        for pattern_name, pattern_info in self.suspicious_patterns.items():
            if re.search(pattern_info['pattern'], command, re.IGNORECASE):
                return True
        
        # Check for unusual hours
        if timestamp.hour < 6 or timestamp.hour > 22:
            return True
        
        # Check for rapid commands (simplified)
        recent_activities = [a for a in self.activity_log[-10:] if a['account'] == activity['account']]
        if len(recent_activities) > 5:
            return True
        
        return False
    
    def _create_anomaly_alert(self, activity):
        """Create anomaly alert"""
        anomaly = {
            'timestamp': datetime.now().isoformat(),
            'account': activity['account'],
            'activity': activity,
            'anomaly_type': 'IMMEDIATE_ANOMALY',
            'description': 'Immediate anomaly detected',
            'severity': activity['severity']
        }
        
        self.anomalies.append(anomaly)
        self.alert_queue.put(anomaly)
        
        self.logger.warning(f"ANOMALY DETECTED: {activity['account']} - {activity['activity_type']}")
    
    def _store_activity(self, activity):
        """Store activity in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO activities 
                (timestamp, account, system, activity_type, command, source_ip, success, hash_value, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                activity['timestamp'],
                activity['account'],
                activity['system'],
                activity['activity_type'],
                activity.get('command', ''),
                activity.get('source_ip', ''),
                activity.get('success', True),
                activity['hash_value'],
                activity['severity']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing activity: {e}")
    
    def _detect_anomalies(self):
        """Detect anomalies in privileged activities"""
        while self.monitoring_active:
            try:
                if len(self.activity_log) > 100:  # Only analyze if we have enough data
                    self._analyze_activity_patterns()
                
                time.sleep(60)  # Analyze every minute
                
            except Exception as e:
                self.logger.error(f"Error in anomaly detection: {e}")
                time.sleep(60)
    
    def _analyze_activity_patterns(self):
        """Analyze activity patterns for anomalies"""
        try:
            # Group activities by account
            account_activities = defaultdict(list)
            for activity in self.activity_log:
                account_activities[activity['account']].append(activity)
            
            # Analyze each account's activities
            for account, activities in account_activities.items():
                if len(activities) < 10:  # Need minimum data for analysis
                    continue
                
                # Check for unusual patterns
                anomalies = self._find_account_anomalies(account, activities)
                
                for anomaly in anomalies:
                    self.anomalies.append(anomaly)
                    self.alert_queue.put(anomaly)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing activity patterns: {e}")
    
    def _find_account_anomalies(self, account, activities):
        """Find anomalies for a specific account"""
        anomalies = []
        
        try:
            # Check for unusual command frequency
            command_counts = defaultdict(int)
            for activity in activities:
                command_counts[activity['command']] += 1
            
            # Find commands used unusually frequently
            for command, count in command_counts.items():
                if count > 10:  # Threshold for unusual frequency
                    anomaly = {
                        'timestamp': datetime.now().isoformat(),
                        'account': account,
                        'anomaly_type': 'UNUSUAL_FREQUENCY',
                        'description': f'Command "{command}" used {count} times',
                        'severity': 'MEDIUM',
                        'activities': [a for a in activities if a['command'] == command]
                    }
                    anomalies.append(anomaly)
            
            # Check for unusual time patterns
            hours = [datetime.fromisoformat(a['timestamp']).hour for a in activities]
            if len(set(hours)) > 8:  # Activity across many different hours
                anomaly = {
                    'timestamp': datetime.now().isoformat(),
                    'account': account,
                    'anomaly_type': 'UNUSUAL_TIME_PATTERN',
                    'description': f'Activity across {len(set(hours))} different hours',
                    'severity': 'MEDIUM',
                    'activities': activities
                }
                anomalies.append(anomaly)
            
            # Check for privilege escalation attempts
            escalation_commands = [a for a in activities if 'sudo' in a.get('command', '')]
            if len(escalation_commands) > 5:
                anomaly = {
                    'timestamp': datetime.now().isoformat(),
                    'account': account,
                    'anomaly_type': 'PRIVILEGE_ESCALATION',
                    'description': f'{len(escalation_commands)} privilege escalation attempts',
                    'severity': 'HIGH',
                    'activities': escalation_commands
                }
                anomalies.append(anomaly)
            
        except Exception as e:
            self.logger.error(f"Error finding anomalies for account {account}: {e}")
        
        return anomalies
    
    def _process_alerts(self):
        """Process and handle alerts"""
        while self.monitoring_active:
            try:
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get()
                    self._handle_alert(alert)
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error processing alerts: {e}")
                time.sleep(1)
    
    def _handle_alert(self, alert):
        """Handle an alert"""
        try:
            # Log alert
            if self.config['alerting']['log_alerts']:
                self.logger.critical(f"ALERT: {alert['anomaly_type']} - {alert['description']}")
            
            # Console alert
            if self.config['alerting']['console_alerts']:
                print(f"\n[ALERT] {alert['anomaly_type']}: {alert['description']}")
                print(f"Account: {alert['account']}")
                print(f"Severity: {alert['severity']}")
                print(f"Timestamp: {alert['timestamp']}")
            
            # Store alert in database
            self._store_anomaly(alert)
            
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}")
    
    def _store_anomaly(self, anomaly):
        """Store anomaly in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies 
                (timestamp, account, anomaly_type, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                anomaly['timestamp'],
                anomaly['account'],
                anomaly['anomaly_type'],
                anomaly['description'],
                anomaly['severity']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing anomaly: {e}")
    
    def generate_forensic_report(self, start_time=None, end_time=None):
        """Generate forensic report of privileged activities"""
        try:
            if not start_time:
                start_time = datetime.now() - timedelta(days=7)
            if not end_time:
                end_time = datetime.now()
            
            # Query activities from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM activities 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_time.isoformat(), end_time.isoformat()))
            
            activities = cursor.fetchall()
            
            cursor.execute('''
                SELECT * FROM anomalies 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_time.isoformat(), end_time.isoformat()))
            
            anomalies = cursor.fetchall()
            conn.close()
            
            # Generate report
            report = {
                'report_timestamp': datetime.now().isoformat(),
                'report_period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                },
                'summary': {
                    'total_activities': len(activities),
                    'total_anomalies': len(anomalies),
                    'unique_accounts': len(set(a[2] for a in activities)),
                    'critical_activities': len([a for a in activities if a[9] == 'CRITICAL'])
                },
                'activities': activities,
                'anomalies': anomalies,
                'recommendations': self._generate_forensic_recommendations(activities, anomalies)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating forensic report: {e}")
            return None
    
    def _generate_forensic_recommendations(self, activities, anomalies):
        """Generate forensic recommendations"""
        recommendations = []
        
        # Count anomalies by type
        anomaly_types = defaultdict(int)
        for anomaly in anomalies:
            anomaly_types[anomaly[3]] += 1
        
        # Generate recommendations based on findings
        if anomaly_types['PRIVILEGE_ESCALATION'] > 0:
            recommendations.append({
                'category': 'Access Control',
                'description': 'Review privilege escalation attempts and implement additional controls',
                'priority': 'HIGH'
            })
        
        if anomaly_types['UNUSUAL_FREQUENCY'] > 0:
            recommendations.append({
                'category': 'Monitoring',
                'description': 'Implement real-time monitoring for unusual command patterns',
                'priority': 'MEDIUM'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'category': 'Forensic Readiness',
                'description': 'Maintain comprehensive audit logs for forensic analysis',
                'priority': 'HIGH'
            },
            {
                'category': 'Incident Response',
                'description': 'Develop incident response procedures for privilege abuse',
                'priority': 'HIGH'
            },
            {
                'category': 'Access Management',
                'description': 'Implement just-in-time access controls for privileged accounts',
                'priority': 'MEDIUM'
            }
        ])
        
        return recommendations
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        self.logger.info("Stopped privileged account activity monitoring")
    
    def save_results(self, filename=None):
        """Save monitoring results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"privilege_monitor_{timestamp}.json"
        
        results = {
            'monitoring_summary': {
                'total_activities': len(self.activity_log),
                'total_anomalies': len(self.anomalies),
                'monitoring_duration': 'N/A'
            },
            'activities': self.activity_log,
            'anomalies': self.anomalies,
            'forensic_report': self.generate_forensic_report()
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Privileged Account Activity Monitor for Maritime OT Systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 privileges.py --start-monitoring
  python3 privileges.py --forensic-report --days 7
  python3 privileges.py --config config.json --duration 3600
  python3 privileges.py --stop-monitoring
        """
    )
    
    parser.add_argument(
        '--start-monitoring',
        action='store_true',
        help='Start real-time monitoring of privileged activities'
    )
    
    parser.add_argument(
        '--stop-monitoring',
        action='store_true',
        help='Stop monitoring'
    )
    
    parser.add_argument(
        '--forensic-report',
        action='store_true',
        help='Generate forensic report'
    )
    
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days for forensic report (default: 7)'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        help='Monitoring duration in seconds'
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
    
    # Create monitor instance
    monitor = PrivilegeActivityMonitor(args.config)
    
    if args.verbose:
        monitor.logger.setLevel(logging.DEBUG)
    
    try:
        if args.start_monitoring:
            # Start monitoring
            print("[*] Starting privileged account activity monitoring...")
            threads = monitor.start_monitoring()
            
            if args.duration:
                print(f"[*] Monitoring for {args.duration} seconds...")
                time.sleep(args.duration)
                monitor.stop_monitoring()
            else:
                print("[*] Monitoring started. Press Ctrl+C to stop.")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    monitor.stop_monitoring()
            
        elif args.forensic_report:
            # Generate forensic report
            print(f"[*] Generating forensic report for last {args.days} days...")
            report = monitor.generate_forensic_report(
                start_time=datetime.now() - timedelta(days=args.days),
                end_time=datetime.now()
            )
            
            if report:
                monitor.save_results(args.output)
                
                # Print summary
                print("\n" + "="*60)
                print("FORENSIC REPORT SUMMARY")
                print("="*60)
                print(f"Report Period: {report['report_period']['start']} to {report['report_period']['end']}")
                print(f"Total Activities: {report['summary']['total_activities']}")
                print(f"Total Anomalies: {report['summary']['total_anomalies']}")
                print(f"Unique Accounts: {report['summary']['unique_accounts']}")
                print(f"Critical Activities: {report['summary']['critical_activities']}")
                
                print(f"\nRecommendations: {len(report['recommendations'])}")
                for rec in report['recommendations']:
                    print(f"  [{rec['priority']}] {rec['description']}")
                
                print("\n[*] Forensic report generated successfully!")
            else:
                print("[!] Error generating forensic report")
                sys.exit(1)
        
        elif args.stop_monitoring:
            # Stop monitoring
            monitor.stop_monitoring()
            print("[*] Monitoring stopped")
        
        else:
            print("[!] Error: Please specify an action (--start-monitoring, --forensic-report, or --stop-monitoring)")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n[*] Monitoring interrupted by user")
        monitor.stop_monitoring()
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during monitoring: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

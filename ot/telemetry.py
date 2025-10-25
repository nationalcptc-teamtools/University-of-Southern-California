#!/usr/bin/env python3
"""
Telemetry Monitoring and Anomaly Detection Tool for Maritime OT Systems
=======================================================================

This script monitors and analyzes telemetry data from remote fleet control systems
to detect anomalies indicating command spoofing or other security threats.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import time
import threading
import queue
import statistics
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict, deque
import socket
import struct
import random
import logging

class TelemetryMonitor:
    def __init__(self, config_file=None):
        """
        Initialize the telemetry monitoring system
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.7)
        self.baseline_window = self.config.get('baseline_window', 3600)  # 1 hour
        self.monitoring_active = False
        self.telemetry_data = defaultdict(lambda: deque(maxlen=1000))
        self.baselines = {}
        self.anomalies = []
        self.alerts = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('telemetry_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Maritime OT system parameters
        self.ot_systems = {
            'navigation': {
                'parameters': ['heading', 'speed', 'position_lat', 'position_lon', 'depth'],
                'normal_ranges': {
                    'heading': (0, 360),
                    'speed': (0, 30),
                    'depth': (0, 200)
                }
            },
            'engine': {
                'parameters': ['rpm', 'fuel_flow', 'temperature', 'pressure', 'vibration'],
                'normal_ranges': {
                    'rpm': (0, 2000),
                    'fuel_flow': (0, 100),
                    'temperature': (60, 120),
                    'pressure': (0, 10)
                }
            },
            'cargo': {
                'parameters': ['weight', 'temperature', 'humidity', 'pressure'],
                'normal_ranges': {
                    'weight': (0, 50000),
                    'temperature': (-20, 60),
                    'humidity': (0, 100),
                    'pressure': (0, 5)
                }
            },
            'safety': {
                'parameters': ['fire_detection', 'gas_levels', 'water_level', 'emergency_status'],
                'normal_ranges': {
                    'fire_detection': (0, 1),
                    'gas_levels': (0, 100),
                    'water_level': (0, 100),
                    'emergency_status': (0, 1)
                }
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'anomaly_threshold': 0.7,
            'baseline_window': 3600,
            'monitoring_interval': 1,
            'alert_threshold': 5,
            'telemetry_sources': [
                {'name': 'navigation_system', 'ip': '192.168.10.10', 'port': 502},
                {'name': 'engine_control', 'ip': '192.168.10.11', 'port': 502},
                {'name': 'cargo_management', 'ip': '192.168.10.12', 'port': 502},
                {'name': 'safety_systems', 'ip': '192.168.10.13', 'port': 502}
            ],
            'modbus_registers': {
                'navigation': {'start': 0, 'count': 20},
                'engine': {'start': 100, 'count': 30},
                'cargo': {'start': 200, 'count': 25},
                'safety': {'start': 300, 'count': 15}
            }
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file {config_file}: {e}")
        
        return default_config
    
    def generate_synthetic_telemetry(self, system_name, parameter, timestamp=None):
        """
        Generate synthetic telemetry data for testing
        
        Args:
            system_name (str): Name of the OT system
            parameter (str): Parameter name
            timestamp (datetime): Timestamp for the data point
            
        Returns:
            dict: Telemetry data point
        """
        if not timestamp:
            timestamp = datetime.now()
        
        # Get normal range for parameter
        normal_range = self.ot_systems.get(system_name, {}).get('normal_ranges', {}).get(parameter, (0, 100))
        
        # Generate realistic data with some noise
        base_value = random.uniform(normal_range[0], normal_range[1])
        noise = random.gauss(0, (normal_range[1] - normal_range[0]) * 0.05)  # 5% noise
        value = base_value + noise
        
        # Clamp to normal range
        value = max(normal_range[0], min(normal_range[1], value))
        
        return {
            'timestamp': timestamp.isoformat(),
            'system': system_name,
            'parameter': parameter,
            'value': round(value, 2),
            'unit': self._get_parameter_unit(parameter),
            'quality': 'good' if random.random() > 0.1 else 'poor'
        }
    
    def _get_parameter_unit(self, parameter):
        """Get unit for a parameter"""
        units = {
            'heading': 'degrees',
            'speed': 'knots',
            'depth': 'meters',
            'rpm': 'rpm',
            'fuel_flow': 'L/h',
            'temperature': 'C',
            'pressure': 'bar',
            'weight': 'kg',
            'humidity': '%',
            'fire_detection': 'boolean',
            'gas_levels': 'ppm',
            'water_level': '%',
            'emergency_status': 'boolean'
        }
        return units.get(parameter, 'unknown')
    
    def read_modbus_data(self, ip, port, start_register, count):
        """
        Read data from Modbus device (simulated for demo)
        
        Args:
            ip (str): IP address of the device
            port (int): Port number
            start_register (int): Starting register address
            count (int): Number of registers to read
            
        Returns:
            list: List of register values
        """
        # This is a simulation - in real implementation, you'd use pymodbus or similar
        try:
            # Simulate Modbus communication
            values = []
            for i in range(count):
                # Generate realistic values based on register type
                if start_register + i < 20:  # Navigation data
                    value = random.uniform(0, 360) if i % 2 == 0 else random.uniform(0, 30)
                elif start_register + i < 50:  # Engine data
                    value = random.uniform(0, 2000) if i % 3 == 0 else random.uniform(60, 120)
                else:  # Other systems
                    value = random.uniform(0, 100)
                
                values.append(int(value))
            
            return values
        except Exception as e:
            self.logger.error(f"Error reading Modbus data from {ip}:{port}: {e}")
            return []
    
    def collect_telemetry_data(self):
        """Collect telemetry data from all configured sources"""
        collected_data = []
        
        for source in self.config['telemetry_sources']:
            try:
                # Read Modbus data
                register_config = self.config['modbus_registers'].get(source['name'].split('_')[0], {})
                if register_config:
                    values = self.read_modbus_data(
                        source['ip'],
                        source['port'],
                        register_config['start'],
                        register_config['count']
                    )
                    
                    # Convert to telemetry data points
                    system_name = source['name'].split('_')[0]
                    parameters = self.ot_systems.get(system_name, {}).get('parameters', [])
                    
                    for i, value in enumerate(values):
                        if i < len(parameters):
                            data_point = {
                                'timestamp': datetime.now().isoformat(),
                                'system': system_name,
                                'parameter': parameters[i],
                                'value': value,
                                'unit': self._get_parameter_unit(parameters[i]),
                                'quality': 'good',
                                'source': source['name']
                            }
                            collected_data.append(data_point)
                            
                            # Store in internal data structure
                            key = f"{system_name}_{parameters[i]}"
                            self.telemetry_data[key].append(data_point)
                
            except Exception as e:
                self.logger.error(f"Error collecting data from {source['name']}: {e}")
        
        return collected_data
    
    def calculate_baseline(self, system_parameter, window_size=None):
        """
        Calculate baseline statistics for a system parameter
        
        Args:
            system_parameter (str): System and parameter name (e.g., 'navigation_heading')
            window_size (int): Number of data points to use for baseline
            
        Returns:
            dict: Baseline statistics
        """
        if not window_size:
            window_size = min(len(self.telemetry_data[system_parameter]), 100)
        
        if window_size == 0:
            return None
        
        data_points = list(self.telemetry_data[system_parameter])[-window_size:]
        values = [dp['value'] for dp in data_points]
        
        if not values:
            return None
        
        baseline = {
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
            'min': min(values),
            'max': max(values),
            'range': max(values) - min(values),
            'sample_size': len(values),
            'timestamp': datetime.now().isoformat()
        }
        
        return baseline
    
    def detect_anomaly(self, data_point, baseline):
        """
        Detect if a data point is anomalous based on baseline statistics
        
        Args:
            data_point (dict): Telemetry data point
            baseline (dict): Baseline statistics
            
        Returns:
            dict: Anomaly detection result
        """
        if not baseline:
            return {'is_anomaly': False, 'reason': 'No baseline available'}
        
        value = data_point['value']
        mean = baseline['mean']
        std_dev = baseline['std_dev']
        
        # Calculate z-score
        if std_dev > 0:
            z_score = abs((value - mean) / std_dev)
        else:
            z_score = 0
        
        # Check for statistical anomalies
        is_statistical_anomaly = z_score > 3  # 3-sigma rule
        
        # Check for range anomalies
        is_range_anomaly = value < baseline['min'] or value > baseline['max']
        
        # Check for trend anomalies (simplified)
        is_trend_anomaly = False
        if len(self.telemetry_data[f"{data_point['system']}_{data_point['parameter']}"]) > 5:
            recent_values = [dp['value'] for dp in list(self.telemetry_data[f"{data_point['system']}_{data_point['parameter']}"])[-5:]]
            if len(recent_values) >= 3:
                trend = np.polyfit(range(len(recent_values)), recent_values, 1)[0]
                is_trend_anomaly = abs(trend) > baseline['std_dev'] * 2
        
        # Check for command spoofing indicators
        is_command_spoofing = self._detect_command_spoofing(data_point, baseline)
        
        is_anomaly = is_statistical_anomaly or is_range_anomaly or is_trend_anomaly or is_command_spoofing
        
        anomaly_result = {
            'is_anomaly': is_anomaly,
            'anomaly_score': z_score,
            'reasons': [],
            'severity': 'LOW'
        }
        
        if is_statistical_anomaly:
            anomaly_result['reasons'].append(f"Statistical anomaly (z-score: {z_score:.2f})")
            anomaly_result['severity'] = 'HIGH'
        
        if is_range_anomaly:
            anomaly_result['reasons'].append("Value outside normal range")
            anomaly_result['severity'] = 'MEDIUM'
        
        if is_trend_anomaly:
            anomaly_result['reasons'].append("Unusual trend detected")
            anomaly_result['severity'] = 'MEDIUM'
        
        if is_command_spoofing:
            anomaly_result['reasons'].append("Potential command spoofing detected")
            anomaly_result['severity'] = 'CRITICAL'
        
        return anomaly_result
    
    def _detect_command_spoofing(self, data_point, baseline):
        """
        Detect potential command spoofing based on telemetry patterns
        
        Args:
            data_point (dict): Telemetry data point
            baseline (dict): Baseline statistics
            
        Returns:
            bool: True if command spoofing is suspected
        """
        # Check for rapid changes that might indicate spoofed commands
        system_param = f"{data_point['system']}_{data_point['parameter']}"
        recent_data = list(self.telemetry_data[system_param])[-10:]
        
        if len(recent_data) < 3:
            return False
        
        # Check for rapid oscillations (possible spoofing)
        values = [dp['value'] for dp in recent_data]
        changes = [abs(values[i] - values[i-1]) for i in range(1, len(values))]
        
        if len(changes) > 0:
            avg_change = statistics.mean(changes)
            max_change = max(changes)
            
            # If maximum change is much larger than average, might be spoofing
            if max_change > avg_change * 3 and max_change > baseline['std_dev'] * 2:
                return True
        
        # Check for impossible values (e.g., negative speed, impossible coordinates)
        if data_point['parameter'] == 'speed' and data_point['value'] < 0:
            return True
        
        if data_point['parameter'] == 'heading' and (data_point['value'] < 0 or data_point['value'] > 360):
            return True
        
        return False
    
    def analyze_telemetry_stream(self, duration=300):
        """
        Analyze telemetry stream for anomalies
        
        Args:
            duration (int): Duration to monitor in seconds
        """
        self.logger.info(f"Starting telemetry analysis for {duration} seconds")
        self.monitoring_active = True
        
        start_time = time.time()
        anomaly_count = 0
        
        while self.monitoring_active and (time.time() - start_time) < duration:
            try:
                # Collect telemetry data
                telemetry_data = self.collect_telemetry_data()
                
                for data_point in telemetry_data:
                    system_param = f"{data_point['system']}_{data_point['parameter']}"
                    
                    # Calculate baseline if not exists
                    if system_param not in self.baselines:
                        self.baselines[system_param] = self.calculate_baseline(system_param)
                    
                    # Detect anomalies
                    anomaly_result = self.detect_anomaly(data_point, self.baselines[system_param])
                    
                    if anomaly_result['is_anomaly']:
                        anomaly_count += 1
                        anomaly_record = {
                            'timestamp': data_point['timestamp'],
                            'system': data_point['system'],
                            'parameter': data_point['parameter'],
                            'value': data_point['value'],
                            'baseline_mean': self.baselines[system_param]['mean'],
                            'anomaly_score': anomaly_result['anomaly_score'],
                            'reasons': anomaly_result['reasons'],
                            'severity': anomaly_result['severity']
                        }
                        
                        self.anomalies.append(anomaly_record)
                        
                        # Generate alert for critical anomalies
                        if anomaly_result['severity'] == 'CRITICAL':
                            self._generate_alert(anomaly_record)
                        
                        self.logger.warning(f"Anomaly detected: {system_param} = {data_point['value']} "
                                         f"(severity: {anomaly_result['severity']})")
                
                # Update baselines periodically
                if len(self.anomalies) % 100 == 0:
                    for system_param in self.telemetry_data.keys():
                        self.baselines[system_param] = self.calculate_baseline(system_param)
                
                time.sleep(self.config.get('monitoring_interval', 1))
                
            except KeyboardInterrupt:
                self.logger.info("Monitoring interrupted by user")
                break
            except Exception as e:
                self.logger.error(f"Error during monitoring: {e}")
                time.sleep(1)
        
        self.monitoring_active = False
        self.logger.info(f"Monitoring completed. Detected {anomaly_count} anomalies.")
    
    def _generate_alert(self, anomaly_record):
        """Generate alert for critical anomalies"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'CRITICAL_ANOMALY',
            'system': anomaly_record['system'],
            'parameter': anomaly_record['parameter'],
            'value': anomaly_record['value'],
            'severity': anomaly_record['severity'],
            'description': f"Critical anomaly detected in {anomaly_record['system']} "
                          f"{anomaly_record['parameter']}: {anomaly_record['value']}",
            'recommendations': self._get_alert_recommendations(anomaly_record)
        }
        
        self.alerts.append(alert)
        self.logger.critical(f"ALERT: {alert['description']}")
    
    def _get_alert_recommendations(self, anomaly_record):
        """Get recommendations for handling alerts"""
        recommendations = []
        
        if 'command spoofing' in ' '.join(anomaly_record['reasons']).lower():
            recommendations.extend([
                "Immediately verify command source authenticity",
                "Check for unauthorized network access",
                "Review system logs for suspicious activity",
                "Consider isolating affected systems"
            ])
        
        if anomaly_record['severity'] == 'CRITICAL':
            recommendations.extend([
                "Immediate manual verification required",
                "Notify security team",
                "Document incident for forensic analysis"
            ])
        
        return recommendations
    
    def generate_report(self):
        """Generate comprehensive monitoring report"""
        report = {
            'monitoring_summary': {
                'total_anomalies': len(self.anomalies),
                'critical_alerts': len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
                'systems_monitored': len(set(a['system'] for a in self.anomalies)),
                'monitoring_duration': 'N/A'  # Would calculate from start/end times
            },
            'anomaly_breakdown': {},
            'system_health': {},
            'recommendations': []
        }
        
        # Analyze anomalies by system
        for anomaly in self.anomalies:
            system = anomaly['system']
            if system not in report['anomaly_breakdown']:
                report['anomaly_breakdown'][system] = {
                    'total_anomalies': 0,
                    'critical_count': 0,
                    'parameters_affected': set()
                }
            
            report['anomaly_breakdown'][system]['total_anomalies'] += 1
            report['anomaly_breakdown'][system]['parameters_affected'].add(anomaly['parameter'])
            
            if anomaly['severity'] == 'CRITICAL':
                report['anomaly_breakdown'][system]['critical_count'] += 1
        
        # Convert sets to lists for JSON serialization
        for system_data in report['anomaly_breakdown'].values():
            system_data['parameters_affected'] = list(system_data['parameters_affected'])
        
        # Generate recommendations
        report['recommendations'] = [
            {
                'category': 'Monitoring',
                'description': 'Implement continuous monitoring for all critical OT systems',
                'priority': 'HIGH'
            },
            {
                'category': 'Security',
                'description': 'Deploy anomaly detection systems with machine learning capabilities',
                'priority': 'HIGH'
            },
            {
                'category': 'Response',
                'description': 'Establish incident response procedures for telemetry anomalies',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Baseline',
                'description': 'Regularly update baseline statistics for accurate anomaly detection',
                'priority': 'MEDIUM'
            }
        ]
        
        return report
    
    def save_results(self, filename=None):
        """Save monitoring results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"telemetry_analysis_{timestamp}.json"
        
        results = {
            'monitoring_results': {
                'anomalies': self.anomalies,
                'alerts': self.alerts,
                'baselines': self.baselines
            },
            'report': self.generate_report()
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Telemetry Monitoring and Anomaly Detection Tool for Maritime OT Systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 telemetry.py --duration 300 --config config.json
  python3 telemetry.py --simulate --systems navigation,engine
  python3 telemetry.py --output results.json --verbose
        """
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        default=300,
        help='Monitoring duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--simulate',
        action='store_true',
        help='Run in simulation mode with synthetic data'
    )
    
    parser.add_argument(
        '--systems',
        type=str,
        help='Comma-separated list of systems to monitor'
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
    monitor = TelemetryMonitor(args.config)
    
    if args.verbose:
        monitor.logger.setLevel(logging.DEBUG)
    
    try:
        if args.simulate:
            # Run simulation mode
            print("[*] Running in simulation mode with synthetic data")
            
            # Generate synthetic data for testing
            systems_to_monitor = args.systems.split(',') if args.systems else ['navigation', 'engine', 'cargo', 'safety']
            
            for _ in range(100):  # Generate 100 data points
                for system in systems_to_monitor:
                    if system in monitor.ot_systems:
                        for parameter in monitor.ot_systems[system]['parameters']:
                            data_point = monitor.generate_synthetic_telemetry(system, parameter)
                            system_param = f"{system}_{parameter}"
                            monitor.telemetry_data[system_param].append(data_point)
                            
                            # Detect anomalies
                            baseline = monitor.calculate_baseline(system_param)
                            if baseline:
                                anomaly_result = monitor.detect_anomaly(data_point, baseline)
                                if anomaly_result['is_anomaly']:
                                    anomaly_record = {
                                        'timestamp': data_point['timestamp'],
                                        'system': system,
                                        'parameter': parameter,
                                        'value': data_point['value'],
                                        'baseline_mean': baseline['mean'],
                                        'anomaly_score': anomaly_result['anomaly_score'],
                                        'reasons': anomaly_result['reasons'],
                                        'severity': anomaly_result['severity']
                                    }
                                    monitor.anomalies.append(anomaly_record)
                                    
                                    if anomaly_result['severity'] == 'CRITICAL':
                                        monitor._generate_alert(anomaly_record)
        else:
            # Run real monitoring
            print(f"[*] Starting telemetry monitoring for {args.duration} seconds")
            monitor.analyze_telemetry_stream(args.duration)
        
        # Generate and save report
        report = monitor.generate_report()
        monitor.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("TELEMETRY MONITORING SUMMARY")
        print("="*60)
        print(f"Total Anomalies Detected: {report['monitoring_summary']['total_anomalies']}")
        print(f"Critical Alerts: {report['monitoring_summary']['critical_alerts']}")
        print(f"Systems Monitored: {report['monitoring_summary']['systems_monitored']}")
        
        print(f"\nAnomaly Breakdown by System:")
        for system, data in report['anomaly_breakdown'].items():
            print(f"  {system}: {data['total_anomalies']} anomalies "
                  f"({data['critical_count']} critical)")
        
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  [{rec['priority']}] {rec['description']}")
        
        print("\n[*] Telemetry monitoring completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Monitoring interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during monitoring: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

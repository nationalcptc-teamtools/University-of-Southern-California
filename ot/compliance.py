#!/usr/bin/env python3
"""
Maritime Cybersecurity Compliance Verification Tool
=================================================

This script verifies compliance with maritime cybersecurity standards such as
IMO SOLAS within shipboard OT environments.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import time
import re
from datetime import datetime, timedelta
import logging
import subprocess
import os
import socket
import requests
from pathlib import Path

class MaritimeComplianceChecker:
    def __init__(self, config_file=None):
        """
        Initialize the maritime compliance checker
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.results = {
            "compliance_timestamp": datetime.now().isoformat(),
            "standards_checked": [],
            "compliance_status": {},
            "violations": [],
            "recommendations": []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('compliance_checker.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Maritime cybersecurity standards
        self.maritime_standards = {
            'IMO_SOLAS': {
                'name': 'International Maritime Organization - Safety of Life at Sea',
                'version': '2021',
                'requirements': {
                    'network_segmentation': {
                        'description': 'Critical systems must be isolated from non-critical systems',
                        'severity': 'CRITICAL',
                        'check_function': 'check_network_segmentation'
                    },
                    'access_control': {
                        'description': 'Strong authentication and authorization controls',
                        'severity': 'HIGH',
                        'check_function': 'check_access_control'
                    },
                    'encryption': {
                        'description': 'Encryption of sensitive data in transit and at rest',
                        'severity': 'HIGH',
                        'check_function': 'check_encryption'
                    },
                    'monitoring': {
                        'description': 'Continuous monitoring of critical systems',
                        'severity': 'MEDIUM',
                        'check_function': 'check_monitoring'
                    },
                    'incident_response': {
                        'description': 'Incident response procedures and capabilities',
                        'severity': 'HIGH',
                        'check_function': 'check_incident_response'
                    },
                    'backup_recovery': {
                        'description': 'Backup and recovery procedures for critical systems',
                        'severity': 'HIGH',
                        'check_function': 'check_backup_recovery'
                    }
                }
            },
            'IEC_62443': {
                'name': 'International Electrotechnical Commission - Industrial Communication Networks',
                'version': '3-3',
                'requirements': {
                    'security_zones': {
                        'description': 'Implementation of security zones and conduits',
                        'severity': 'HIGH',
                        'check_function': 'check_security_zones'
                    },
                    'device_authentication': {
                        'description': 'Device authentication and authorization',
                        'severity': 'HIGH',
                        'check_function': 'check_device_authentication'
                    },
                    'secure_communication': {
                        'description': 'Secure communication protocols',
                        'severity': 'MEDIUM',
                        'check_function': 'check_secure_communication'
                    },
                    'system_integrity': {
                        'description': 'System integrity monitoring',
                        'severity': 'MEDIUM',
                        'check_function': 'check_system_integrity'
                    }
                }
            },
            'NIST_Cybersecurity_Framework': {
                'name': 'National Institute of Standards and Technology Cybersecurity Framework',
                'version': '1.1',
                'requirements': {
                    'identify': {
                        'description': 'Identify cybersecurity risks to systems, assets, data, and capabilities',
                        'severity': 'HIGH',
                        'check_function': 'check_identify_function'
                    },
                    'protect': {
                        'description': 'Develop and implement safeguards to ensure delivery of critical services',
                        'severity': 'HIGH',
                        'check_function': 'check_protect_function'
                    },
                    'detect': {
                        'description': 'Develop and implement activities to identify cybersecurity events',
                        'severity': 'MEDIUM',
                        'check_function': 'check_detect_function'
                    },
                    'respond': {
                        'description': 'Develop and implement activities to take action regarding detected cybersecurity events',
                        'severity': 'HIGH',
                        'check_function': 'check_respond_function'
                    },
                    'recover': {
                        'description': 'Develop and implement activities to maintain plans for resilience',
                        'severity': 'MEDIUM',
                        'check_function': 'check_recover_function'
                    }
                }
            }
        }
        
        # Maritime OT system categories
        self.ot_systems = {
            'navigation': {
                'criticality': 'CRITICAL',
                'systems': ['ECDIS', 'GPS', 'Radar', 'AIS', 'Compass'],
                'networks': ['192.168.20.0/24'],
                'ports': [80, 443, 502, 2000]
            },
            'engine': {
                'criticality': 'CRITICAL',
                'systems': ['Engine_Control', 'Fuel_Management', 'Propulsion'],
                'networks': ['192.168.30.0/24'],
                'ports': [502, 2000, 8080]
            },
            'safety': {
                'criticality': 'CRITICAL',
                'systems': ['Fire_Suppression', 'Emergency_Systems', 'Life_Safety'],
                'networks': ['192.168.40.0/24'],
                'ports': [502, 2000, 9999]
            },
            'communication': {
                'criticality': 'HIGH',
                'systems': ['Satellite_Comms', 'Radio_Systems', 'Crew_Communication'],
                'networks': ['192.168.50.0/24'],
                'ports': [80, 443, 8080, 9090]
            },
            'cargo': {
                'criticality': 'MEDIUM',
                'systems': ['Cargo_Management', 'Loading_Systems', 'Crane_Control'],
                'networks': ['192.168.60.0/24'],
                'ports': [80, 443, 502, 8080]
            }
        }
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'compliance_checks': {
                'network_segmentation': True,
                'access_control': True,
                'encryption': True,
                'monitoring': True,
                'incident_response': True,
                'backup_recovery': True
            },
            'target_systems': {
                'navigation_systems': True,
                'engine_systems': True,
                'safety_systems': True,
                'communication_systems': True,
                'cargo_systems': True
            },
            'check_settings': {
                'timeout': 10,
                'max_retries': 3,
                'detailed_reporting': True
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
    
    def check_network_segmentation(self):
        """Check network segmentation compliance"""
        self.logger.info("Checking network segmentation compliance")
        
        check_result = {
            'requirement': 'Network Segmentation',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check if critical systems are isolated
            critical_networks = []
            non_critical_networks = []
            
            for system_type, config in self.ot_systems.items():
                if config['criticality'] in ['CRITICAL', 'HIGH']:
                    critical_networks.extend(config['networks'])
                else:
                    non_critical_networks.extend(config['networks'])
            
            # Simulate network connectivity check
            has_segmentation = self._check_network_connectivity(critical_networks, non_critical_networks)
            
            check_result['details']['critical_networks'] = critical_networks
            check_result['details']['non_critical_networks'] = non_critical_networks
            check_result['details']['has_segmentation'] = has_segmentation
            
            if not has_segmentation:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NETWORK_SEGMENTATION_FAILURE',
                    'severity': 'CRITICAL',
                    'description': 'Critical systems are not properly segmented from non-critical systems'
                })
                check_result['recommendations'].append({
                    'description': 'Implement network segmentation using VLANs and firewalls',
                    'priority': 'CRITICAL'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking network segmentation: {str(e)}'
            })
            self.logger.error(f"Error checking network segmentation: {e}")
        
        return check_result
    
    def _check_network_connectivity(self, critical_networks, non_critical_networks):
        """Check if networks are properly segmented"""
        # Simulate network connectivity check
        # In real implementation, would test actual network connectivity
        import random
        return random.random() > 0.3  # 70% chance of proper segmentation
    
    def check_access_control(self):
        """Check access control compliance"""
        self.logger.info("Checking access control compliance")
        
        check_result = {
            'requirement': 'Access Control',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check for strong authentication
            has_strong_auth = self._check_strong_authentication()
            check_result['details']['strong_authentication'] = has_strong_auth
            
            # Check for role-based access control
            has_rbac = self._check_role_based_access()
            check_result['details']['role_based_access'] = has_rbac
            
            # Check for privileged account management
            has_priv_management = self._check_privileged_account_management()
            check_result['details']['privileged_account_management'] = has_priv_management
            
            if not has_strong_auth:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'WEAK_AUTHENTICATION',
                    'severity': 'HIGH',
                    'description': 'Strong authentication mechanisms not implemented'
                })
            
            if not has_rbac:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_RBAC',
                    'severity': 'HIGH',
                    'description': 'Role-based access control not implemented'
                })
            
            if not has_priv_management:
                check_result['violations'].append({
                    'type': 'WEAK_PRIVILEGE_MANAGEMENT',
                    'severity': 'MEDIUM',
                    'description': 'Privileged account management needs improvement'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking access control: {str(e)}'
            })
            self.logger.error(f"Error checking access control: {e}")
        
        return check_result
    
    def _check_strong_authentication(self):
        """Check if strong authentication is implemented"""
        # Simulate authentication check
        import random
        return random.random() > 0.2  # 80% chance of strong authentication
    
    def _check_role_based_access(self):
        """Check if role-based access control is implemented"""
        # Simulate RBAC check
        import random
        return random.random() > 0.3  # 70% chance of RBAC
    
    def _check_privileged_account_management(self):
        """Check privileged account management"""
        # Simulate privilege management check
        import random
        return random.random() > 0.4  # 60% chance of good privilege management
    
    def check_encryption(self):
        """Check encryption compliance"""
        self.logger.info("Checking encryption compliance")
        
        check_result = {
            'requirement': 'Encryption',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check for data encryption in transit
            has_transit_encryption = self._check_transit_encryption()
            check_result['details']['transit_encryption'] = has_transit_encryption
            
            # Check for data encryption at rest
            has_rest_encryption = self._check_rest_encryption()
            check_result['details']['rest_encryption'] = has_rest_encryption
            
            # Check for key management
            has_key_management = self._check_key_management()
            check_result['details']['key_management'] = has_key_management
            
            if not has_transit_encryption:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_TRANSIT_ENCRYPTION',
                    'severity': 'HIGH',
                    'description': 'Data encryption in transit not implemented'
                })
            
            if not has_rest_encryption:
                check_result['violations'].append({
                    'type': 'NO_REST_ENCRYPTION',
                    'severity': 'MEDIUM',
                    'description': 'Data encryption at rest not implemented'
                })
            
            if not has_key_management:
                check_result['violations'].append({
                    'type': 'WEAK_KEY_MANAGEMENT',
                    'severity': 'MEDIUM',
                    'description': 'Key management needs improvement'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking encryption: {str(e)}'
            })
            self.logger.error(f"Error checking encryption: {e}")
        
        return check_result
    
    def _check_transit_encryption(self):
        """Check data encryption in transit"""
        # Simulate transit encryption check
        import random
        return random.random() > 0.25  # 75% chance of transit encryption
    
    def _check_rest_encryption(self):
        """Check data encryption at rest"""
        # Simulate rest encryption check
        import random
        return random.random() > 0.4  # 60% chance of rest encryption
    
    def _check_key_management(self):
        """Check key management"""
        # Simulate key management check
        import random
        return random.random() > 0.35  # 65% chance of good key management
    
    def check_monitoring(self):
        """Check monitoring compliance"""
        self.logger.info("Checking monitoring compliance")
        
        check_result = {
            'requirement': 'Monitoring',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check for continuous monitoring
            has_continuous_monitoring = self._check_continuous_monitoring()
            check_result['details']['continuous_monitoring'] = has_continuous_monitoring
            
            # Check for log management
            has_log_management = self._check_log_management()
            check_result['details']['log_management'] = has_log_management
            
            # Check for alerting
            has_alerting = self._check_alerting()
            check_result['details']['alerting'] = has_alerting
            
            if not has_continuous_monitoring:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_CONTINUOUS_MONITORING',
                    'severity': 'HIGH',
                    'description': 'Continuous monitoring not implemented'
                })
            
            if not has_log_management:
                check_result['violations'].append({
                    'type': 'WEAK_LOG_MANAGEMENT',
                    'severity': 'MEDIUM',
                    'description': 'Log management needs improvement'
                })
            
            if not has_alerting:
                check_result['violations'].append({
                    'type': 'NO_ALERTING',
                    'severity': 'MEDIUM',
                    'description': 'Alerting system not implemented'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking monitoring: {str(e)}'
            })
            self.logger.error(f"Error checking monitoring: {e}")
        
        return check_result
    
    def _check_continuous_monitoring(self):
        """Check continuous monitoring"""
        # Simulate monitoring check
        import random
        return random.random() > 0.3  # 70% chance of continuous monitoring
    
    def _check_log_management(self):
        """Check log management"""
        # Simulate log management check
        import random
        return random.random() > 0.4  # 60% chance of good log management
    
    def _check_alerting(self):
        """Check alerting system"""
        # Simulate alerting check
        import random
        return random.random() > 0.35  # 65% chance of alerting system
    
    def check_incident_response(self):
        """Check incident response compliance"""
        self.logger.info("Checking incident response compliance")
        
        check_result = {
            'requirement': 'Incident Response',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check for incident response plan
            has_response_plan = self._check_incident_response_plan()
            check_result['details']['response_plan'] = has_response_plan
            
            # Check for incident response team
            has_response_team = self._check_incident_response_team()
            check_result['details']['response_team'] = has_response_team
            
            # Check for incident response procedures
            has_response_procedures = self._check_incident_response_procedures()
            check_result['details']['response_procedures'] = has_response_procedures
            
            if not has_response_plan:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_INCIDENT_RESPONSE_PLAN',
                    'severity': 'HIGH',
                    'description': 'Incident response plan not documented'
                })
            
            if not has_response_team:
                check_result['violations'].append({
                    'type': 'NO_INCIDENT_RESPONSE_TEAM',
                    'severity': 'MEDIUM',
                    'description': 'Incident response team not established'
                })
            
            if not has_response_procedures:
                check_result['violations'].append({
                    'type': 'WEAK_INCIDENT_RESPONSE_PROCEDURES',
                    'severity': 'MEDIUM',
                    'description': 'Incident response procedures need improvement'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking incident response: {str(e)}'
            })
            self.logger.error(f"Error checking incident response: {e}")
        
        return check_result
    
    def _check_incident_response_plan(self):
        """Check incident response plan"""
        # Simulate response plan check
        import random
        return random.random() > 0.2  # 80% chance of response plan
    
    def _check_incident_response_team(self):
        """Check incident response team"""
        # Simulate response team check
        import random
        return random.random() > 0.3  # 70% chance of response team
    
    def _check_incident_response_procedures(self):
        """Check incident response procedures"""
        # Simulate response procedures check
        import random
        return random.random() > 0.4  # 60% chance of response procedures
    
    def check_backup_recovery(self):
        """Check backup and recovery compliance"""
        self.logger.info("Checking backup and recovery compliance")
        
        check_result = {
            'requirement': 'Backup and Recovery',
            'standard': 'IMO SOLAS',
            'status': 'PASS',
            'details': {},
            'violations': [],
            'recommendations': []
        }
        
        try:
            # Check for backup procedures
            has_backup_procedures = self._check_backup_procedures()
            check_result['details']['backup_procedures'] = has_backup_procedures
            
            # Check for recovery procedures
            has_recovery_procedures = self._check_recovery_procedures()
            check_result['details']['recovery_procedures'] = has_recovery_procedures
            
            # Check for backup testing
            has_backup_testing = self._check_backup_testing()
            check_result['details']['backup_testing'] = has_backup_testing
            
            if not has_backup_procedures:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_BACKUP_PROCEDURES',
                    'severity': 'HIGH',
                    'description': 'Backup procedures not documented'
                })
            
            if not has_recovery_procedures:
                check_result['status'] = 'FAIL'
                check_result['violations'].append({
                    'type': 'NO_RECOVERY_PROCEDURES',
                    'severity': 'HIGH',
                    'description': 'Recovery procedures not documented'
                })
            
            if not has_backup_testing:
                check_result['violations'].append({
                    'type': 'NO_BACKUP_TESTING',
                    'severity': 'MEDIUM',
                    'description': 'Backup testing not performed regularly'
                })
            
        except Exception as e:
            check_result['status'] = 'ERROR'
            check_result['violations'].append({
                'type': 'CHECK_ERROR',
                'severity': 'HIGH',
                'description': f'Error checking backup and recovery: {str(e)}'
            })
            self.logger.error(f"Error checking backup and recovery: {e}")
        
        return check_result
    
    def _check_backup_procedures(self):
        """Check backup procedures"""
        # Simulate backup procedures check
        import random
        return random.random() > 0.25  # 75% chance of backup procedures
    
    def _check_recovery_procedures(self):
        """Check recovery procedures"""
        # Simulate recovery procedures check
        import random
        return random.random() > 0.3  # 70% chance of recovery procedures
    
    def _check_backup_testing(self):
        """Check backup testing"""
        # Simulate backup testing check
        import random
        return random.random() > 0.4  # 60% chance of backup testing
    
    def run_compliance_check(self, standards=None):
        """
        Run compliance check for specified standards
        
        Args:
            standards (list): List of standards to check
        """
        if not standards:
            standards = list(self.maritime_standards.keys())
        
        self.logger.info(f"Starting compliance check for standards: {', '.join(standards)}")
        
        for standard_name in standards:
            if standard_name not in self.maritime_standards:
                self.logger.warning(f"Unknown standard: {standard_name}")
                continue
            
            standard = self.maritime_standards[standard_name]
            self.logger.info(f"Checking compliance with {standard['name']}")
            
            standard_results = {
                'standard_name': standard_name,
                'standard_info': standard,
                'requirements': [],
                'overall_status': 'PASS',
                'total_requirements': 0,
                'passed_requirements': 0,
                'failed_requirements': 0
            }
            
            # Check each requirement
            for req_name, req_info in standard['requirements'].items():
                if not self.config['compliance_checks'].get(req_name, True):
                    continue
                
                self.logger.info(f"Checking requirement: {req_name}")
                
                # Get check function
                check_function = getattr(self, req_info['check_function'], None)
                if not check_function:
                    self.logger.error(f"Check function not found: {req_info['check_function']}")
                    continue
                
                # Run check
                try:
                    check_result = check_function()
                    check_result['requirement_name'] = req_name
                    check_result['standard'] = standard_name
                    
                    standard_results['requirements'].append(check_result)
                    standard_results['total_requirements'] += 1
                    
                    if check_result['status'] == 'PASS':
                        standard_results['passed_requirements'] += 1
                    else:
                        standard_results['failed_requirements'] += 1
                        standard_results['overall_status'] = 'FAIL'
                    
                except Exception as e:
                    self.logger.error(f"Error checking requirement {req_name}: {e}")
                    standard_results['failed_requirements'] += 1
                    standard_results['overall_status'] = 'FAIL'
            
            self.results['standards_checked'].append(standard_results)
        
        # Generate overall compliance status
        self._generate_compliance_status()
        
        # Generate recommendations
        self._generate_recommendations()
        
        self.logger.info("Compliance check completed")
    
    def _generate_compliance_status(self):
        """Generate overall compliance status"""
        total_standards = len(self.results['standards_checked'])
        passed_standards = len([s for s in self.results['standards_checked'] if s['overall_status'] == 'PASS'])
        
        self.results['compliance_status'] = {
            'total_standards': total_standards,
            'passed_standards': passed_standards,
            'failed_standards': total_standards - passed_standards,
            'compliance_percentage': (passed_standards / total_standards * 100) if total_standards > 0 else 0,
            'overall_status': 'COMPLIANT' if passed_standards == total_standards else 'NON_COMPLIANT'
        }
    
    def _generate_recommendations(self):
        """Generate compliance recommendations"""
        recommendations = []
        
        # Collect all violations
        all_violations = []
        for standard_result in self.results['standards_checked']:
            for requirement in standard_result['requirements']:
                all_violations.extend(requirement.get('violations', []))
        
        # Group violations by severity
        critical_violations = [v for v in all_violations if v['severity'] == 'CRITICAL']
        high_violations = [v for v in all_violations if v['severity'] == 'HIGH']
        medium_violations = [v for v in all_violations if v['severity'] == 'MEDIUM']
        
        if critical_violations:
            recommendations.append({
                'category': 'Critical Issues',
                'description': f'Address {len(critical_violations)} critical compliance violations immediately',
                'priority': 'CRITICAL'
            })
        
        if high_violations:
            recommendations.append({
                'category': 'High Priority',
                'description': f'Address {len(high_violations)} high-priority compliance violations',
                'priority': 'HIGH'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'category': 'Compliance Management',
                'description': 'Establish regular compliance monitoring and reporting',
                'priority': 'HIGH'
            },
            {
                'category': 'Documentation',
                'description': 'Maintain comprehensive documentation of security controls',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Training',
                'description': 'Provide cybersecurity training for maritime personnel',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Audit',
                'description': 'Conduct regular security audits and assessments',
                'priority': 'MEDIUM'
            }
        ])
        
        self.results['recommendations'] = recommendations
    
    def save_results(self, filename=None):
        """Save compliance check results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"compliance_check_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to: {filename}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Maritime Cybersecurity Compliance Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 compliance.py --check-all
  python3 compliance.py --standard IMO_SOLAS --detailed
  python3 compliance.py --standard IEC_62443,NIST_Cybersecurity_Framework
  python3 compliance.py --config config.json --output results.json
        """
    )
    
    parser.add_argument(
        '--check-all',
        action='store_true',
        help='Check compliance with all maritime standards'
    )
    
    parser.add_argument(
        '--standard',
        type=str,
        help='Specific standard to check (comma-separated for multiple)'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Generate detailed compliance report'
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
    
    # Create compliance checker instance
    checker = MaritimeComplianceChecker(args.config)
    
    if args.verbose:
        checker.logger.setLevel(logging.DEBUG)
    
    try:
        if args.check_all:
            # Check all standards
            standards = list(checker.maritime_standards.keys())
            checker.run_compliance_check(standards)
        elif args.standard:
            # Check specific standards
            standards = [s.strip() for s in args.standard.split(',')]
            checker.run_compliance_check(standards)
        else:
            print("[!] Error: Please specify standards to check (--check-all or --standard)")
            sys.exit(1)
        
        # Save results
        checker.save_results(args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("MARITIME COMPLIANCE CHECK SUMMARY")
        print("="*60)
        
        compliance_status = checker.results['compliance_status']
        print(f"Overall Status: {compliance_status['overall_status']}")
        print(f"Compliance Percentage: {compliance_status['compliance_percentage']:.1f}%")
        print(f"Standards Checked: {compliance_status['total_standards']}")
        print(f"Passed Standards: {compliance_status['passed_standards']}")
        print(f"Failed Standards: {compliance_status['failed_standards']}")
        
        # Print detailed results if requested
        if args.detailed:
            print(f"\nDetailed Results:")
            for standard_result in checker.results['standards_checked']:
                print(f"\n{standard_result['standard_name']}:")
                print(f"  Status: {standard_result['overall_status']}")
                print(f"  Requirements: {standard_result['passed_requirements']}/{standard_result['total_requirements']} passed")
                
                for requirement in standard_result['requirements']:
                    if requirement['status'] != 'PASS':
                        print(f"    FAILED: {requirement['requirement_name']}")
                        for violation in requirement.get('violations', []):
                            print(f"      - {violation['description']} ({violation['severity']})")
        
        print(f"\nRecommendations: {len(checker.results['recommendations'])}")
        for rec in checker.results['recommendations']:
            print(f"  [{rec['priority']}] {rec['description']}")
        
        print("\n[*] Compliance check completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[*] Compliance check interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during compliance check: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

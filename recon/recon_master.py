#!/usr/bin/env python3
"""
Reconnaissance Master Script
============================

This script provides a comprehensive menu-driven interface for reconnaissance
and vulnerability scanning operations in general IT environments.

Author: USC-CPTC
Version: 1.0
"""

import argparse
import json
import sys
import os
import subprocess
import time
from datetime import datetime
import logging
from pathlib import Path

class ReconMaster:
    def __init__(self):
        """Initialize the reconnaissance master"""
        self.results_dir = "recon_results"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'recon_master_{self.timestamp}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Create results directory
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Reconnaissance categories
        self.recon_categories = {
            '1': {
                'name': 'Host Discovery & Network Reconnaissance',
                'description': 'Discover hosts and perform network reconnaissance',
                'tools': [
                    {
                        'name': 'Host Discovery',
                        'script': 'discovery.py',
                        'description': 'Discover live hosts using ping sweep and ARP scan',
                        'command': 'python3 discovery.py --network {network} --verbose'
                    },
                    {
                        'name': 'DNS Enumeration',
                        'script': 'discovery.py',
                        'description': 'Enumerate DNS records and subdomains',
                        'command': 'python3 discovery.py --dns {domain} --verbose'
                    }
                ]
            },
            '2': {
                'name': 'Port Scanning & Service Detection',
                'description': 'Scan ports and identify services',
                'tools': [
                    {
                        'name': 'TCP SYN Scan',
                        'script': 'portscan.py',
                        'description': 'Perform TCP SYN port scanning',
                        'command': 'python3 portscan.py --targets {targets} --scan-type tcp_syn --verbose'
                    },
                    {
                        'name': 'UDP Scan',
                        'script': 'portscan.py',
                        'description': 'Perform UDP port scanning',
                        'command': 'python3 portscan.py --targets {targets} --scan-type udp --verbose'
                    },
                    {
                        'name': 'Stealth Scan',
                        'script': 'portscan.py',
                        'description': 'Perform stealth port scanning',
                        'command': 'python3 portscan.py --targets {targets} --scan-type stealth --verbose'
                    }
                ]
            },
            '3': {
                'name': 'Service Enumeration & Fingerprinting',
                'description': 'Enumerate services and identify versions',
                'tools': [
                    {
                        'name': 'Service Enumeration',
                        'script': 'service_enum.py',
                        'description': 'Enumerate services and identify versions',
                        'command': 'python3 service_enum.py --targets {targets} --vulnerability-scan'
                    },
                    {
                        'name': 'Web Service Enumeration',
                        'script': 'service_enum.py',
                        'description': 'Enumerate web services specifically',
                        'command': 'python3 service_enum.py --targets {targets} --aggressive'
                    }
                ]
            },
            '4': {
                'name': 'Vulnerability Assessment',
                'description': 'Identify vulnerabilities and security issues',
                'tools': [
                    {
                        'name': 'Vulnerability Scan',
                        'script': 'vuln_scan.py',
                        'description': 'Scan for known vulnerabilities',
                        'command': 'python3 vuln_scan.py --targets {targets} --check-cves --verbose'
                    },
                    {
                        'name': 'Aggressive Vulnerability Scan',
                        'script': 'vuln_scan.py',
                        'description': 'Perform aggressive vulnerability scanning',
                        'command': 'python3 vuln_scan.py --targets {targets} --aggressive --check-cves'
                    }
                ]
            },
            '5': {
                'name': 'Comprehensive IT Assessment',
                'description': 'Run complete reconnaissance and vulnerability assessment',
                'tools': [
                    {
                        'name': 'Full IT Security Assessment',
                        'script': 'all',
                        'description': 'Execute complete reconnaissance and vulnerability assessment',
                        'command': 'comprehensive_assessment'
                    }
                ]
            }
        }
        
        # Quick assessment templates
        self.quick_assessments = {
            '1': {
                'name': 'Network Discovery Assessment',
                'description': 'Focus on host discovery and network reconnaissance',
                'tools': ['discovery.py', 'portscan.py']
            },
            '2': {
                'name': 'Service Enumeration Assessment',
                'description': 'Focus on service enumeration and fingerprinting',
                'tools': ['portscan.py', 'service_enum.py']
            },
            '3': {
                'name': 'Vulnerability Assessment',
                'description': 'Focus on vulnerability identification and assessment',
                'tools': ['service_enum.py', 'vuln_scan.py']
            },
            '4': {
                'name': 'Web Application Assessment',
                'description': 'Focus on web application security',
                'tools': ['portscan.py', 'service_enum.py', 'vuln_scan.py']
            }
        }
    
    def display_main_menu(self):
        """Display the main reconnaissance menu"""
        print("\n" + "="*80)
        print("🔍 RECONNAISSANCE MASTER - IT CYBERSECURITY ASSESSMENT")
        print("="*80)
        print("Select a reconnaissance category:")
        print()
        
        for key, category in self.recon_categories.items():
            print(f"  {key}. {category['name']}")
            print(f"     {category['description']}")
            print()
        
        print("  Q. Quick Assessment Templates")
        print("  R. View Results")
        print("  H. Help")
        print("  X. Exit")
        print("="*80)
    
    def display_quick_assessments(self):
        """Display quick assessment templates"""
        print("\n" + "="*60)
        print("QUICK ASSESSMENT TEMPLATES")
        print("="*60)
        print("Select a quick assessment:")
        print()
        
        for key, assessment in self.quick_assessments.items():
            print(f"  {key}. {assessment['name']}")
            print(f"     {assessment['description']}")
            print()
        
        print("  B. Back to Main Menu")
        print("="*60)
    
    def display_category_tools(self, category_key):
        """Display tools for a specific category"""
        category = self.recon_categories[category_key]
        
        print(f"\n" + "="*60)
        print(f"TOOLS: {category['name'].upper()}")
        print("="*60)
        print(f"Description: {category['description']}")
        print()
        print("Available tools:")
        print()
        
        for i, tool in enumerate(category['tools'], 1):
            print(f"  {i}. {tool['name']}")
            print(f"     {tool['description']}")
            print()
        
        print("  A. Run All Tools in Category")
        print("  B. Back to Main Menu")
        print("="*60)
    
    def run_tool(self, tool, category_name, targets=None):
        """Run a specific tool"""
        print(f"\n[*] Running: {tool['name']}")
        print(f"[*] Category: {category_name}")
        print(f"[*] Description: {tool['description']}")
        print(f"[*] Command: {tool['command']}")
        print("-" * 60)
        
        try:
            # Create output filename
            output_file = f"{self.results_dir}/{tool['script'].replace('.py', '')}_{self.timestamp}.json"
            
            # Modify command to include output file and targets
            if tool['script'] != 'all':
                if 'python3' in tool['command']:
                    tool['command'] += f" --output {output_file}"
                    if targets and '{targets}' in tool['command']:
                        tool['command'] = tool['command'].replace('{targets}', targets)
                    if '{network}' in tool['command']:
                        tool['command'] = tool['command'].replace('{network}', '192.168.1.0/24')
                    if '{domain}' in tool['command']:
                        tool['command'] = tool['command'].replace('{domain}', 'example.com')
            
            # Execute the command
            self.logger.info(f"Executing: {tool['command']}")
            result = subprocess.run(
                tool['command'],
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                print(f"[✓] {tool['name']} completed successfully")
                if result.stdout:
                    print("Output:")
                    print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
            else:
                print(f"[✗] {tool['name']} failed with return code {result.returncode}")
                if result.stderr:
                    print("Error:")
                    print(result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr)
            
            # Save execution log
            self._save_execution_log(tool, result, output_file)
            
        except subprocess.TimeoutExpired:
            print(f"[✗] {tool['name']} timed out after 5 minutes")
        except Exception as e:
            print(f"[✗] Error running {tool['name']}: {e}")
            self.logger.error(f"Error running {tool['name']}: {e}")
    
    def run_category_tools(self, category_key, targets=None):
        """Run all tools in a category"""
        category = self.recon_categories[category_key]
        
        print(f"\n[*] Running all tools in category: {category['name']}")
        print("="*60)
        
        for tool in category['tools']:
            self.run_tool(tool, category['name'], targets)
            print()
            time.sleep(2)  # Brief pause between tools
        
        print(f"[✓] Completed all tools in category: {category['name']}")
    
    def run_quick_assessment(self, assessment_key, targets=None):
        """Run a quick assessment template"""
        assessment = self.quick_assessments[assessment_key]
        
        print(f"\n[*] Running Quick Assessment: {assessment['name']}")
        print(f"[*] Description: {assessment['description']}")
        print("="*60)
        
        for tool_script in assessment['tools']:
            # Find the tool in categories
            tool = self._find_tool_by_script(tool_script)
            if tool:
                self.run_tool(tool, "Quick Assessment", targets)
                print()
                time.sleep(2)
        
        print(f"[✓] Completed Quick Assessment: {assessment['name']}")
    
    def _find_tool_by_script(self, script_name):
        """Find a tool by its script name"""
        for category in self.recon_categories.values():
            for tool in category['tools']:
                if tool['script'] == script_name:
                    return tool
        return None
    
    def run_comprehensive_assessment(self, targets=None):
        """Run comprehensive reconnaissance assessment"""
        print("\n[*] Starting Comprehensive IT Security Assessment")
        print("="*60)
        print("This will run all available reconnaissance tools...")
        print()
        
        # Run all categories in order
        categories_to_run = ['1', '2', '3', '4']
        
        for category_key in categories_to_run:
            category = self.recon_categories[category_key]
            print(f"\n[*] Category: {category['name']}")
            print("-" * 40)
            
            for tool in category['tools']:
                self.run_tool(tool, category['name'], targets)
                print()
                time.sleep(3)  # Pause between tools
        
        print("\n[✓] Comprehensive IT Security Assessment Completed!")
        self._generate_assessment_summary()
    
    def _save_execution_log(self, tool, result, output_file):
        """Save execution log for a tool"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'tool_name': tool['name'],
            'script': tool['script'],
            'command': tool['command'],
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'output_file': output_file
        }
        
        log_file = f"{self.results_dir}/execution_log_{self.timestamp}.json"
        
        # Load existing log or create new
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(log_entry)
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def _generate_assessment_summary(self):
        """Generate assessment summary"""
        summary = {
            'assessment_timestamp': datetime.now().isoformat(),
            'assessment_type': 'Comprehensive IT Security Assessment',
            'results_directory': self.results_dir,
            'tools_executed': [],
            'summary': {
                'total_tools': 0,
                'successful_tools': 0,
                'failed_tools': 0
            }
        }
        
        # Count results
        log_file = f"{self.results_dir}/execution_log_{self.timestamp}.json"
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
            
            summary['tools_executed'] = logs
            summary['summary']['total_tools'] = len(logs)
            summary['summary']['successful_tools'] = len([log for log in logs if log['return_code'] == 0])
            summary['summary']['failed_tools'] = len([log for log in logs if log['return_code'] != 0])
        
        # Save summary
        summary_file = f"{self.results_dir}/assessment_summary_{self.timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[*] Assessment summary saved to: {summary_file}")
        print(f"[*] Results directory: {self.results_dir}")
    
    def view_results(self):
        """View available results"""
        print("\n" + "="*60)
        print("RECONNAISSANCE RESULTS")
        print("="*60)
        
        if not os.path.exists(self.results_dir):
            print("No results directory found.")
            return
        
        # List result files
        result_files = []
        for file in os.listdir(self.results_dir):
            if file.endswith('.json'):
                result_files.append(file)
        
        if not result_files:
            print("No result files found.")
            return
        
        print("Available result files:")
        print()
        for i, file in enumerate(sorted(result_files), 1):
            file_path = os.path.join(self.results_dir, file)
            file_size = os.path.getsize(file_path)
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            print(f"  {i}. {file}")
            print(f"     Size: {file_size} bytes, Modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print()
        
        # Show summary if available
        summary_files = [f for f in result_files if 'summary' in f]
        if summary_files:
            print("Assessment Summary:")
            latest_summary = sorted(summary_files)[-1]
            summary_path = os.path.join(self.results_dir, latest_summary)
            
            try:
                with open(summary_path, 'r') as f:
                    summary = json.load(f)
                
                print(f"  Assessment Type: {summary.get('assessment_type', 'Unknown')}")
                print(f"  Total Tools: {summary['summary']['total_tools']}")
                print(f"  Successful: {summary['summary']['successful_tools']}")
                print(f"  Failed: {summary['summary']['failed_tools']}")
            except Exception as e:
                print(f"  Error reading summary: {e}")
    
    def show_help(self):
        """Show help information"""
        print("\n" + "="*80)
        print("RECONNAISSANCE MASTER - HELP")
        print("="*80)
        print()
        print("This tool provides a comprehensive interface for IT security reconnaissance.")
        print("It orchestrates multiple specialized tools for general IT environments.")
        print()
        print("CATEGORIES:")
        print("  1. Host Discovery & Network Reconnaissance - Discover hosts and networks")
        print("  2. Port Scanning & Service Detection - Scan ports and identify services")
        print("  3. Service Enumeration & Fingerprinting - Enumerate services and versions")
        print("  4. Vulnerability Assessment - Identify vulnerabilities and security issues")
        print("  5. Comprehensive IT Assessment - Run all tests")
        print()
        print("QUICK ASSESSMENTS:")
        print("  Pre-configured assessment templates for common scenarios")
        print()
        print("RESULTS:")
        print("  All results are saved in JSON format in the 'recon_results' directory")
        print("  Execution logs track the success/failure of each tool")
        print()
        print("SAFETY:")
        print("  - Always obtain proper authorization before testing")
        print("  - Use stealth modes when available")
        print("  - Review configurations for your specific environment")
        print("  - Be mindful of network impact and rate limiting")
        print()
        print("For detailed help on individual tools, use:")
        print("  python3 <tool_name>.py --help")
        print("="*80)
    
    def run_interactive_mode(self):
        """Run the interactive menu system"""
        while True:
            self.display_main_menu()
            choice = input("Enter your choice: ").strip().upper()
            
            if choice == 'X':
                print("\n[*] Exiting Reconnaissance Master")
                break
            elif choice == 'H':
                self.show_help()
            elif choice == 'R':
                self.view_results()
            elif choice == 'Q':
                self._handle_quick_assessments()
            elif choice in self.recon_categories:
                if choice == '5':  # Comprehensive assessment
                    confirm = input("This will run ALL tools. Continue? (y/N): ").strip().lower()
                    if confirm == 'y':
                        self.run_comprehensive_assessment()
                else:
                    self._handle_category_selection(choice)
            else:
                print("\n[!] Invalid choice. Please try again.")
    
    def _handle_quick_assessments(self):
        """Handle quick assessment selection"""
        while True:
            self.display_quick_assessments()
            choice = input("Enter your choice: ").strip()
            
            if choice.upper() == 'B':
                break
            elif choice in self.quick_assessments:
                confirm = input(f"Run {self.quick_assessments[choice]['name']}? (y/N): ").strip().lower()
                if confirm == 'y':
                    self.run_quick_assessment(choice)
                    input("\nPress Enter to continue...")
            else:
                print("\n[!] Invalid choice. Please try again.")
    
    def _handle_category_selection(self, category_key):
        """Handle category tool selection"""
        while True:
            self.display_category_tools(category_key)
            choice = input("Enter your choice: ").strip().upper()
            
            if choice == 'B':
                break
            elif choice == 'A':
                confirm = input(f"Run all tools in {self.recon_categories[category_key]['name']}? (y/N): ").strip().lower()
                if confirm == 'y':
                    self.run_category_tools(category_key)
                    input("\nPress Enter to continue...")
            elif choice.isdigit():
                tool_index = int(choice) - 1
                category = self.recon_categories[category_key]
                if 0 <= tool_index < len(category['tools']):
                    tool = category['tools'][tool_index]
                    confirm = input(f"Run {tool['name']}? (y/N): ").strip().lower()
                    if confirm == 'y':
                        self.run_tool(tool, category['name'])
                        input("\nPress Enter to continue...")
                else:
                    print("\n[!] Invalid tool number. Please try again.")
            else:
                print("\n[!] Invalid choice. Please try again.")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Reconnaissance Master - IT Cybersecurity Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_master.py                    # Interactive mode
  python3 recon_master.py --quick 1          # Run Network Discovery Assessment
  python3 recon_master.py --category 2       # Run Port Scanning Assessment
  python3 recon_master.py --comprehensive    # Run all assessments
  python3 recon_master.py --results          # View results
        """
    )
    
    parser.add_argument(
        '--quick',
        type=str,
        choices=['1', '2', '3', '4'],
        help='Run a quick assessment template'
    )
    
    parser.add_argument(
        '--category',
        type=str,
        choices=['1', '2', '3', '4'],
        help='Run all tools in a specific category'
    )
    
    parser.add_argument(
        '--comprehensive',
        action='store_true',
        help='Run comprehensive IT security assessment'
    )
    
    parser.add_argument(
        '--results',
        action='store_true',
        help='View available results'
    )
    
    parser.add_argument(
        '--help-tool',
        action='store_true',
        help='Show detailed help'
    )
    
    args = parser.parse_args()
    
    # Create recon master instance
    master = ReconMaster()
    
    try:
        if args.quick:
            # Run quick assessment
            assessment = master.quick_assessments[args.quick]
            print(f"[*] Running Quick Assessment: {assessment['name']}")
            master.run_quick_assessment(args.quick)
            
        elif args.category:
            # Run category tools
            category = master.recon_categories[args.category]
            print(f"[*] Running Category: {category['name']}")
            master.run_category_tools(args.category)
            
        elif args.comprehensive:
            # Run comprehensive assessment
            master.run_comprehensive_assessment()
            
        elif args.results:
            # View results
            master.view_results()
            
        elif args.help_tool:
            # Show help
            master.show_help()
            
        else:
            # Interactive mode
            master.run_interactive_mode()
            
    except KeyboardInterrupt:
        print("\n[*] Reconnaissance Master interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

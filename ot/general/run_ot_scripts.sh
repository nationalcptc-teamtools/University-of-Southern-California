#!/bin/bash
# OT Cybersecurity Automation Scripts - Linux Shell Runner
# =========================================================
# 
# This shell script provides an easy way to run OT cybersecurity scripts
# on Linux systems with proper safety checks and user prompts.
#
# WARNING: These scripts are designed for OT environments and must be used
# with extreme caution. Never run on production systems without proper
# authorization and safety procedures.
#
# Author: USC-CPTC
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python installation
check_python() {
    if ! command_exists python3; then
        print_color $RED "ERROR: Python 3 is not installed"
        print_color $YELLOW "Please install Python 3.7 or higher:"
        print_color $YELLOW "  Ubuntu/Debian: sudo apt install python3 python3-pip"
        print_color $YELLOW "  CentOS/RHEL: sudo yum install python3 python3-pip"
        exit 1
    fi
    
    # Check Python version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if (( $(echo "$python_version < 3.7" | bc -l) )); then
        print_color $RED "ERROR: Python 3.7 or higher is required"
        print_color $YELLOW "Current version: $python_version"
        exit 1
    fi
}

# Function to check and install required packages
check_packages() {
    print_color $BLUE "Checking required packages..."
    
    # Check if pip is installed
    if ! command_exists pip3; then
        print_color $YELLOW "Installing pip..."
        if command_exists apt; then
            sudo apt update && sudo apt install python3-pip
        elif command_exists yum; then
            sudo yum install python3-pip
        else
            print_color $RED "ERROR: Cannot install pip automatically"
            print_color $YELLOW "Please install pip manually and try again"
            exit 1
        fi
    fi
    
    # Check if required packages are installed
    python3 -c "import requests, numpy, scapy" 2>/dev/null
    if [ $? -ne 0 ]; then
        print_color $YELLOW "Installing required packages..."
        pip3 install -r requirements.txt
        if [ $? -ne 0 ]; then
            print_color $RED "ERROR: Failed to install required packages"
            print_color $YELLOW "Please check your internet connection and try again"
            exit 1
        fi
    fi
}

# Function to check if running as root
check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        print_color $YELLOW "WARNING: Running as root"
        print_color $YELLOW "Consider running as a regular user with sudo privileges"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to display safety warning
safety_warning() {
    clear
    print_color $RED "========================================"
    print_color $RED "OT Cybersecurity Automation Scripts"
    print_color $RED "========================================"
    echo
    print_color $RED "WARNING: These scripts are designed for OT environments!"
    print_color $RED "NEVER run on production systems without proper authorization."
    echo
    print_color $YELLOW "Press any key to continue or Ctrl+C to exit..."
    read -n 1 -s
}

# Function to run asset enumeration
run_asset_enum() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "Asset Enumeration Script"
    print_color $BLUE "========================================"
    echo
    print_color $YELLOW "This script will discover and catalog OT assets, protocols, and services."
    echo
    print_color $RED "SAFETY WARNING: This script will generate network traffic."
    print_color $RED "Only run on authorized networks during appropriate time windows."
    echo
    
    read -p "Enter target network (e.g., 192.168.1.0/24): " target
    if [ -z "$target" ]; then
        print_color $RED "ERROR: Target network is required"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Running asset enumeration..."
    print_color $GREEN "Target: $target"
    echo
    
    python3 asset_enumeration.py "$target" --safe-mode --report --verbose
    if [ $? -ne 0 ]; then
        print_color $RED "ERROR: Asset enumeration failed"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Asset enumeration completed successfully!"
    print_color $GREEN "Check the generated JSON and report files."
    read -p "Press Enter to continue..."
}

# Function to run network segmentation validation
run_network_seg() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "Network Segmentation Validation"
    print_color $BLUE "========================================"
    echo
    print_color $YELLOW "This script will validate network segmentation and isolation."
    echo
    print_color $RED "SAFETY WARNING: This script may generate test traffic."
    print_color $RED "Only run on authorized networks during appropriate time windows."
    echo
    
    print_color $GREEN "Running network segmentation validation..."
    echo
    
    python3 network_segmentation.py --report --verbose
    if [ $? -ne 0 ]; then
        print_color $RED "ERROR: Network segmentation validation failed"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Network segmentation validation completed successfully!"
    print_color $GREEN "Check the generated JSON and report files."
    read -p "Press Enter to continue..."
}

# Function to run anomaly detection
run_anomaly_det() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "Anomaly Detection Script"
    print_color $BLUE "========================================"
    echo
    print_color $YELLOW "This script will detect unusual patterns and potential threats."
    echo
    print_color $RED "SAFETY WARNING: This script will monitor network traffic."
    print_color $RED "Only run on authorized networks with proper monitoring."
    echo
    
    read -p "Enter network interface (e.g., eth0, wlan0): " interface
    if [ -z "$interface" ]; then
        print_color $RED "ERROR: Network interface is required"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Starting anomaly detection..."
    print_color $GREEN "Interface: $interface"
    echo
    print_color $YELLOW "Press Ctrl+C to stop monitoring..."
    
    python3 anomaly_detection.py --interface "$interface" --ml-enabled --report --verbose
    if [ $? -ne 0 ]; then
        print_color $RED "ERROR: Anomaly detection failed"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Anomaly detection completed successfully!"
    print_color $GREEN "Check the generated JSON and report files."
    read -p "Press Enter to continue..."
}

# Function to run security event monitoring
run_security_mon() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "Security Event Monitoring"
    print_color $BLUE "========================================"
    echo
    print_color $YELLOW "This script will monitor security events from various sources."
    echo
    print_color $RED "SAFETY WARNING: This script will collect and analyze security events."
    print_color $RED "Only run on authorized systems with proper monitoring."
    echo
    
    read -p "Enter syslog port (default: 514): " port
    if [ -z "$port" ]; then
        port=514
    fi
    
    echo
    print_color $GREEN "Starting security event monitoring..."
    print_color $GREEN "Syslog port: $port"
    echo
    print_color $YELLOW "Press Ctrl+C to stop monitoring..."
    
    python3 security_monitoring.py --syslog-port "$port" --report --verbose
    if [ $? -ne 0 ]; then
        print_color $RED "ERROR: Security event monitoring failed"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    print_color $GREEN "Security event monitoring completed successfully!"
    print_color $GREEN "Check the generated JSON and report files."
    read -p "Press Enter to continue..."
}

# Function to display safety guidelines
show_safety_guide() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "Safety Guidelines"
    print_color $BLUE "========================================"
    echo
    
    if [ -f "SAFETY_GUIDELINES.md" ]; then
        print_color $GREEN "Opening safety guidelines document..."
        if command_exists less; then
            less SAFETY_GUIDELINES.md
        elif command_exists more; then
            more SAFETY_GUIDELINES.md
        else
            cat SAFETY_GUIDELINES.md
        fi
    else
        print_color $RED "ERROR: Safety guidelines document not found"
        print_color $YELLOW "Please ensure SAFETY_GUIDELINES.md is in the same directory"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to display main menu
show_menu() {
    clear
    print_color $BLUE "========================================"
    print_color $BLUE "OT Cybersecurity Scripts - Main Menu"
    print_color $BLUE "========================================"
    echo
    print_color $GREEN "1. Asset Enumeration"
    print_color $GREEN "2. Network Segmentation Validation"
    print_color $GREEN "3. Anomaly Detection"
    print_color $GREEN "4. Security Event Monitoring"
    print_color $GREEN "5. Safety Guidelines"
    print_color $GREEN "6. Exit"
    echo
}

# Main function
main() {
    # Check system requirements
    check_python
    check_packages
    check_permissions
    
    # Display safety warning
    safety_warning
    
    # Main menu loop
    while true; do
        show_menu
        read -p "Enter your choice (1-6): " choice
        
        case $choice in
            1) run_asset_enum ;;
            2) run_network_seg ;;
            3) run_anomaly_det ;;
            4) run_security_mon ;;
            5) show_safety_guide ;;
            6) 
                clear
                print_color $GREEN "========================================"
                print_color $GREEN "Thank you for using OT Cybersecurity Scripts"
                print_color $GREEN "========================================"
                echo
                print_color $YELLOW "Remember: Safety is everyone's responsibility."
                print_color $YELLOW "When in doubt, stop and ask for guidance."
                echo
                exit 0
                ;;
            *) 
                print_color $RED "Invalid choice. Please enter 1-6."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Run main function
main

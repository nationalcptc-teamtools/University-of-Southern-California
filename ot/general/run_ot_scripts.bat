@echo off
REM OT Cybersecurity Automation Scripts - Windows Batch Runner
REM =========================================================
REM 
REM This batch file provides an easy way to run OT cybersecurity scripts
REM on Windows systems with proper safety checks and user prompts.
REM
REM WARNING: These scripts are designed for OT environments and must be used
REM with extreme caution. Never run on production systems without proper
REM authorization and safety procedures.
REM
REM Author: USC-CPTC
REM Version: 1.0

echo.
echo ========================================
echo OT Cybersecurity Automation Scripts
echo ========================================
echo.
echo WARNING: These scripts are designed for OT environments!
echo NEVER run on production systems without proper authorization.
echo.
echo Press any key to continue or Ctrl+C to exit...
pause >nul

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://python.org
    pause
    exit /b 1
)

REM Check if required packages are installed
echo Checking required packages...
python -c "import requests, numpy, scapy" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install required packages
        echo Please check your internet connection and try again
        pause
        exit /b 1
    )
)

REM Main menu
:menu
cls
echo.
echo ========================================
echo OT Cybersecurity Scripts - Main Menu
echo ========================================
echo.
echo 1. Asset Enumeration
echo 2. Network Segmentation Validation
echo 3. Anomaly Detection
echo 4. Security Event Monitoring
echo 5. Safety Guidelines
echo 6. Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto asset_enum
if "%choice%"=="2" goto network_seg
if "%choice%"=="3" goto anomaly_det
if "%choice%"=="4" goto security_mon
if "%choice%"=="5" goto safety_guide
if "%choice%"=="6" goto exit
goto menu

:asset_enum
cls
echo.
echo ========================================
echo Asset Enumeration Script
echo ========================================
echo.
echo This script will discover and catalog OT assets, protocols, and services.
echo.
echo SAFETY WARNING: This script will generate network traffic.
echo Only run on authorized networks during appropriate time windows.
echo.
set /p target="Enter target network (e.g., 192.168.1.0/24): "
if "%target%"=="" (
    echo ERROR: Target network is required
    pause
    goto menu
)

echo.
echo Running asset enumeration...
echo Target: %target%
echo.
python asset_enumeration.py %target% --safe-mode --report --verbose
if errorlevel 1 (
    echo ERROR: Asset enumeration failed
    pause
    goto menu
)

echo.
echo Asset enumeration completed successfully!
echo Check the generated JSON and report files.
pause
goto menu

:network_seg
cls
echo.
echo ========================================
echo Network Segmentation Validation
echo ========================================
echo.
echo This script will validate network segmentation and isolation.
echo.
echo SAFETY WARNING: This script may generate test traffic.
echo Only run on authorized networks during appropriate time windows.
echo.
echo Running network segmentation validation...
echo.
python network_segmentation.py --report --verbose
if errorlevel 1 (
    echo ERROR: Network segmentation validation failed
    pause
    goto menu
)

echo.
echo Network segmentation validation completed successfully!
echo Check the generated JSON and report files.
pause
goto menu

:anomaly_det
cls
echo.
echo ========================================
echo Anomaly Detection Script
echo ========================================
echo.
echo This script will detect unusual patterns and potential threats.
echo.
echo SAFETY WARNING: This script will monitor network traffic.
echo Only run on authorized networks with proper monitoring.
echo.
set /p interface="Enter network interface (e.g., eth0, Ethernet): "
if "%interface%"=="" (
    echo ERROR: Network interface is required
    pause
    goto menu
)

echo.
echo Starting anomaly detection...
echo Interface: %interface%
echo.
echo Press Ctrl+C to stop monitoring...
python anomaly_detection.py --interface %interface% --ml-enabled --report --verbose
if errorlevel 1 (
    echo ERROR: Anomaly detection failed
    pause
    goto menu
)

echo.
echo Anomaly detection completed successfully!
echo Check the generated JSON and report files.
pause
goto menu

:security_mon
cls
echo.
echo ========================================
echo Security Event Monitoring
echo ========================================
echo.
echo This script will monitor security events from various sources.
echo.
echo SAFETY WARNING: This script will collect and analyze security events.
echo Only run on authorized systems with proper monitoring.
echo.
set /p port="Enter syslog port (default: 514): "
if "%port%"=="" set port=514

echo.
echo Starting security event monitoring...
echo Syslog port: %port%
echo.
echo Press Ctrl+C to stop monitoring...
python security_monitoring.py --syslog-port %port% --report --verbose
if errorlevel 1 (
    echo ERROR: Security event monitoring failed
    pause
    goto menu
)

echo.
echo Security event monitoring completed successfully!
echo Check the generated JSON and report files.
pause
goto menu

:safety_guide
cls
echo.
echo ========================================
echo Safety Guidelines
echo ========================================
echo.
echo Opening safety guidelines document...
echo.
if exist "SAFETY_GUIDELINES.md" (
    start notepad "SAFETY_GUIDELINES.md"
) else (
    echo ERROR: Safety guidelines document not found
    echo Please ensure SAFETY_GUIDELINES.md is in the same directory
)
pause
goto menu

:exit
cls
echo.
echo ========================================
echo Thank you for using OT Cybersecurity Scripts
echo ========================================
echo.
echo Remember: Safety is everyone's responsibility.
echo When in doubt, stop and ask for guidance.
echo.
echo Press any key to exit...
pause >nul
exit /b 0

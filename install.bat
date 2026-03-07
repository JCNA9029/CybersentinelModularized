@echo off
title CyberSentinel Setup
echo ===================================================
echo     CyberSentinel EDR - Single-Click Installer
echo ===================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python is not installed or not in your PATH.
    echo [-] Please install Python 3.8+ from python.org and try again.
    pause
    exit /b
)

echo [+] Python detected. Installing required enterprise libraries...
pip install -r requirements.txt

echo.
echo [+] Setup Complete! 
echo [+] You can now run CyberSentinel via the command line or TamperGuard.bat.
pause
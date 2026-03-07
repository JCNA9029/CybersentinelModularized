@echo off
title CyberSentinel TamperGuard

:: This line forces the terminal to switch to the exact folder where CyberSentinel lives
cd /d "%~dp0"

echo [*] EDR Survivability Protocol Active.
echo [*] Monitoring CyberSentinel.py...

:loop
:: Run the Python Daemon (Make sure this path points to your actual testing folder!)
python CyberSentinel.py --daemon C:\Users\Acer\Desktop\test

:: If the malware force-closes the Python script, it hits this line instantly
echo [!] WARNING: CyberSentinel process terminated unexpectedly!
echo [*] Auto-Resurrecting EDR in 2 seconds...
timeout /t 2 /nobreak >nul

:: Loop back and restart the EDR
goto loop
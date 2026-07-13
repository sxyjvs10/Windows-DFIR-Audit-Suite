@echo off
color 0B
echo ================================================================================
echo                    COMPREHENSIVE SECURITY AUDIT WRAPPER
echo ================================================================================
echo.

:: Require admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo [ERROR] This script MUST be run as Administrator!
    echo Please right-click this file and select "Run as Administrator".
    pause
    exit /b
)

set "DESK=%USERPROFILE%\OneDrive\Desktop"
if not exist "%DESK%" set "DESK=%USERPROFILE%\Desktop"

echo [1/3] Running User-Mode Threat Hunter...
python -X utf8 "%DESK%\ThreatHunter.py"

echo.
echo [2/3] Running Kernel Rootkit Scanner...
python -X utf8 "%DESK%\KernelRootkitScanner.py"

echo.
echo [3/3] Merging Reports...
timeout /t 2 >nul

:: Get the newest ThreatHunter report
for /f "delims=" %%F in ('dir /b /o-d /tc "%DESK%\ThreatHunter_Report_*.txt" 2^>nul') do (
    set "TH_REPORT=%%F"
    goto :found_th
)
:found_th

:: Get the newest Kernel report
for /f "delims=" %%F in ('dir /b /o-d /tc "%DESK%\KernelRootkit_Report_*.txt" 2^>nul') do (
    set "KR_REPORT=%%F"
    goto :found_kr
)
:found_kr

if defined TH_REPORT if defined KR_REPORT (
    set "MASTER=%DESK%\MASTER_SECURITY_AUDIT_%RANDOM%.txt"
    
    echo ================================================================================ > "!MASTER!"
    echo                     MASTER SECURITY AUDIT REPORT >> "!MASTER!"
    echo ================================================================================ >> "!MASTER!"
    echo. >> "!MASTER!"
    
    type "%DESK%\%TH_REPORT%" >> "!MASTER!"
    echo. >> "!MASTER!"
    echo. >> "!MASTER!"
    type "%DESK%\%KR_REPORT%" >> "!MASTER!"
    
    del "%DESK%\%TH_REPORT%"
    del "%DESK%\%KR_REPORT%"
    
    echo.
    echo [SUCCESS] Unified report saved to your Desktop!
) else (
    echo.
    echo [WARNING] Could not find the generated reports to merge.
)

echo.
pause

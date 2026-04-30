@echo off
setlocal
title Windows DFIR Offline Log Triage and Exporter

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator access...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ===============================================
echo  Windows DFIR Offline Log Triage and Exporter
echo ===============================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Security_Logs.ps1"

echo.
echo ===============================================
echo  Process Finished
echo ===============================================
echo.
pause

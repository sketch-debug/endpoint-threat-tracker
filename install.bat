@echo off
REM One-command installer for the Endpoint Threat Detection & Incident Tracker.
REM All arguments are passed through to install.ps1 (e.g. -NoStart, -Offline).
setlocal
cd /d "%~dp0"

where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: Windows PowerShell was not found. PowerShell 5.1 or newer is required.
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
exit /b %errorlevel%

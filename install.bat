@echo off
REM One-command installer for the Endpoint Threat Detection & Incident Tracker.
REM All arguments are passed through to install.ps1 (e.g. -NoStart, -Offline).
setlocal
cd /d "%~dp0"

REM PowerShell 7 (pwsh) exports its own PSModulePath. When this batch file is
REM started from a pwsh prompt, powershell.exe below would inherit it and then
REM fail to resolve Windows PowerShell's own modules - install.ps1 would die
REM on Get-FileHash. Remove the variable so Windows PowerShell rebuilds its
REM native module path. From cmd/Explorer this is a no-op (5.1 rebuilds the
REM same defaults), so it is safe to do unconditionally.
set "PSModulePath="

where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: Windows PowerShell was not found. PowerShell 5.1 or newer is required.
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
exit /b %errorlevel%

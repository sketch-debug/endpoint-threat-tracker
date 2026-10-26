@echo off
REM End-to-end smoke test with fake data. Prints PASS/FAIL per step and
REM exits non-zero if any step fails. See smoke_test.ps1 for the steps.
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0smoke_test.ps1" %*
exit /b %errorlevel%

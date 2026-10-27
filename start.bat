@echo off
REM start.bat - run the tracker in the foreground (first-run / lab use).
REM For production use scripts\Install-Service.ps1 instead.
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python was not found on PATH.
  echo Install Python 3.11 or newer, tick "Add python.exe to PATH", then run start.bat again.
  echo For an air-gapped machine, use the offline installer: install.bat -Offline
  exit /b 1
)

if not exist .venv (
  echo Creating virtual environment and installing pinned dependencies...
  python -m venv .venv
  if errorlevel 1 (
    echo ERROR: could not create the virtual environment in .venv
    echo Check that .venv is not locked by another process and that Python is complete.
    exit /b 1
  )
  .venv\Scripts\python -m pip install --no-index --find-links packages -r requirements.txt 2>nul ^
    || .venv\Scripts\python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo ERROR: dependency install failed. If this machine is offline, run:
    echo   .venv\Scripts\python -m pip install --no-index --find-links packages -r requirements.txt
    exit /b 1
  )
)

if not exist .env (
  echo Creating .env from .env.example - EDIT IT before production use.
  copy .env.example .env >nul
  echo   WARNING: this .env still has the default SECRET_KEY and admin password admin1234.
  echo   Run install.bat to generate random values, or edit .env, before production use.
)

if not exist .venv\Scripts\python.exe (
  echo ERROR: .venv is missing or incomplete. Delete the .venv folder and run start.bat again.
  exit /b 1
)

echo Starting tracker on http://127.0.0.1:8043/ (Ctrl+C to stop)...
.venv\Scripts\python -m app.main
if errorlevel 1 echo ERROR: the tracker exited with an error. Check data\logs\tracker.log for details.
endlocal

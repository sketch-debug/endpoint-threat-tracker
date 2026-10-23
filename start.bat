@echo off
REM start.bat - run the tracker in the foreground (first-run / lab use).
REM For production use scripts\Install-Service.ps1 instead.
setlocal
cd /d "%~dp0"

if not exist .venv (
  echo Creating virtual environment and installing pinned dependencies...
  python -m venv .venv
  .venv\Scripts\python -m pip install --no-index --find-links packages -r requirements.txt 2>nul ^
    || .venv\Scripts\python -m pip install -r requirements.txt
)

if not exist .env (
  echo Creating .env from .env.example - EDIT IT before production use.
  copy .env.example .env >nul
)

echo Starting tracker on http://127.0.0.1:8043/ (Ctrl+C to stop)...
.venv\Scripts\python -m app.main
endlocal

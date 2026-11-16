@echo off
chcp 65001 >nul
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] v2 is not set up yet - run SETUP.bat first.
  pause
  exit /b 1
)
set PYTHONUTF8=1
.venv\Scripts\python.exe tools\migrate_v1.py %*
pause

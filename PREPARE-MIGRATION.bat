@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==============================================
echo   IT Ops - PREPARE MIGRATION (run on the OLD machine)
echo   Backs up live data + packs the source and files not in Git
echo   into one zip file on the Desktop.
echo   BEFORE RUNNING: stop IT Ops in VS Code (Shift+F5).
echo ==============================================
echo.
if not exist "backend\.venv\Scripts\python.exe" (
  echo [ERROR] backend\.venv not found - has SETUP.bat been run on this machine?
  pause
  exit /b 1
)
set PYTHONUTF8=1
backend\.venv\Scripts\python.exe backend\tools\migrate_machine.py pack %*
if errorlevel 1 (
  echo.
  echo [ERROR] Packing did not finish - see the error above.
)
pause

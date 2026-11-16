@echo off
REM IT Ops - SETUP ON A NEW MACHINE. Double-click this file (NO need to Run as administrator - it asks once when opening the firewall).
REM Installs Python + VS Code if missing, sets up IT Ops, restores data from the migration package, opens VS Code.
REM Backup file somewhere else:  SETUP-NEW-MACHINE.bat "D:\path\itops-backup-....zip"
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0backend\tools\setup_new_machine.ps1" %*
pause

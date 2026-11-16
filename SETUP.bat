@echo off
chcp 65001 >nul
cd /d "%~dp0"
REM SETUP.bat /auto : do not wait for a key press (used by SETUP-NEW-MACHINE.bat)
set "NP=pause"
if /i "%~1"=="/auto" set "NP=rem"
echo ==============================================
echo   IT Ops Workspace v2 - setup (Windows)
echo ==============================================
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install Python 3.12 from https://www.python.org/downloads/
  echo         tick "Add python.exe to PATH", then run this file again.
  %NP%
  exit /b 1
)
python --version
echo.
echo [0/5] Checking source files (modified / incompletely unzipped?) ...
python backend\tools\verify_files.py
if errorlevel 1 (
  echo [ERROR] Source differs from the release - see the list above.
  %NP%
  exit /b 1
)
echo.
echo [1/5] Copying VS Code settings to .vscode ...
if not exist ".vscode" mkdir ".vscode"
copy /Y "vscode-config\*.json" ".vscode\" >nul
echo       done.
echo.
echo [2/5] Creating Python environment (backend\.venv) ...
cd backend
REM a .venv copied from another machine points to that machine's Python -> does not run -> delete and recreate
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe -c "import sys" >nul 2>nul
  if errorlevel 1 (
    echo       old .venv does not run on this machine ^(copied from another machine^) - deleting and recreating ...
    rmdir /s /q ".venv"
  )
)
if exist ".venv" if not exist ".venv\Scripts\python.exe" rmdir /s /q ".venv"
if exist ".venv\pyvenv.cfg" if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Could not delete backend\.venv - close VS Code / terminal windows using it, then run again.
  %NP%
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" python -m venv .venv
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Could not create backend\.venv - close VS Code and run again, or delete the backend\.venv folder by hand.
  %NP%
  exit /b 1
)
echo       done.
echo.
echo [3/5] Installing libraries (1-3 minutes) ...
.venv\Scripts\python.exe -m pip install --upgrade pip -q
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Library install failed - see the error above - check the Internet connection and the Python version.
  %NP%
  exit /b 1
)
echo.
cd ..
echo.
echo [4/5] Creating admin password (.env.local) ...
if exist ".env.local" (
  echo       .env.local already exists - keeping the current password.
) else (
  backend\.venv\Scripts\python.exe -c "import secrets;p=secrets.token_urlsafe(12);open('.env.local','w',newline='').write('ADMIN_USER=admin\nADMIN_PASSWORD='+p+'\n')"
  echo       done.
)
echo.
echo [5/5] Downloading portable PostgreSQL (~30 MB, sha512 verified) ...
backend\.venv\Scripts\python.exe backend\tools\get_postgres.py
if errorlevel 1 (
  echo [WARNING] PostgreSQL not downloaded yet - the app will retry when you press F5.
  echo           If the company network blocks registry.npmjs.org: ask IT to allow it, or see README.md.
)
echo.
echo ==============================================
echo   DONE! Open this folder in VS Code and press F5.
echo   Web: http://127.0.0.1:8100
echo   Login account (keep it):
type .env.local
echo ==============================================
if /i not "%~1"=="/auto" (
  where code >nul 2>nul && code .
)
%NP%
exit /b 0

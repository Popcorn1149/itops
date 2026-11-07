@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==============================================
echo   IT Ops Workspace v2 - cai dat chay thu (Windows)
echo ==============================================
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [LOI] Chua co Python. Cai Python 3.12 tu https://www.python.org/downloads/
  echo       nho tick "Add python.exe to PATH", roi chay lai file nay.
  pause
  exit /b 1
)
python --version
echo.
echo [1/4] Chep cau hinh VS Code vao .vscode ...
if not exist ".vscode" mkdir ".vscode"
copy /Y "vscode-config\*.json" ".vscode\" >nul
echo       xong.
echo.
echo [2/4] Tao moi truong Python (backend\.venv) ...
cd backend
if not exist ".venv" python -m venv .venv
echo       xong.
echo.
echo [3/4] Cai thu vien (1-3 phut) ...
.venv\Scripts\python.exe -m pip install --upgrade pip -q
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
  echo [LOI] Cai thu vien that bai - kiem tra mang Internet roi chay lai.
  pause
  exit /b 1
)
cd ..
echo.
echo [4/4] Tao mat khau admin (.env.local) ...
if exist ".env.local" (
  echo       Da co .env.local - giu nguyen mat khau cu.
) else (
  backend\.venv\Scripts\python.exe -c "import secrets;p=secrets.token_urlsafe(12);open('.env.local','w',newline='').write('ADMIN_USER=admin\nADMIN_PASSWORD='+p+'\n')"
  echo       xong.
)
echo.
echo ==============================================
echo   XONG! Mo thu muc nay bang VS Code, bam F5.
echo   Web: http://127.0.0.1:8100
echo   Tai khoan dang nhap (luu lai):
type .env.local
echo ==============================================
where code >nul 2>nul && code .
pause

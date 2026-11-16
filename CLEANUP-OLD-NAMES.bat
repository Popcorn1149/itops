@echo off
REM ONE-TIME cleanup after renaming files to English (2026-11-16). Deletes itself when finished.
REM Deletes each OLD file only if its NEW file exists. Copies of the old backups are in _backup\2026-11-16 (see _backup\README.md).
cd /d "%~dp0"
echo ==============================================
echo   IT Ops - remove files with old (Vietnamese) names
echo ==============================================
echo.
call :swap "CAI-DAT.bat"                          "SETUP.bat"
call :swap "CAI-DAT-MAY-MOI.bat"                  "SETUP-NEW-MACHINE.bat"
call :swap "CHUAN-BI-CHUYEN-MAY.bat"              "PREPARE-MIGRATION.bat"
call :swap "MO-TUONG-LUA.bat"                     "OPEN-FIREWALL.bat"
call :swap "CHUYEN-DU-LIEU-V1.bat"                "MIGRATE-V1-DATA.bat"
call :swap "CHUYEN-MAY-MOI.md"                    "MIGRATE-TO-NEW-MACHINE.md"
call :swap "CHAY-THU-VSCODE.md"                   "RUN-IN-VSCODE.md"
call :swap "GIAM-SAT-AN-NINH.md"                  "SECURITY-MONITORING.md"
call :swap "THEM-THIET-BI-THAT.md"                "ADD-REAL-DEVICES.md"
call :swap "TU-DONG-HOA.md"                       "AUTOMATION.md"
call :swap "DECISIONS\0002-bao-mat-p1.md"         "DECISIONS\0002-security-p1.md"
call :swap "DECISIONS\0004-agent-go-va-event-log.md" "DECISIONS\0004-go-agent-and-event-log.md"
call :swap "backend\tools\chuyen_may.py"          "backend\tools\migrate_machine.py"
call :swap "backend\tools\cai_dat_may_moi.ps1"    "backend\tools\setup_new_machine.ps1"
call :swap "backend\tools\kiem_tra_file.py"       "backend\tools\verify_files.py"
call :swap "backend\tools\chuyen_v1.py"           "backend\tools\migrate_v1.py"
call :swap "backend\tools\mo_phong_thiet_bi.py"   "backend\tools\simulate_devices.py"
call :swap "backend\tools\so_sanh_v1_v2.py"       "backend\tools\compare_v1_v2.py"
call :swap "CAI-DAT.bat.bak"                      "_backup\2026-11-16\CAI-DAT.bat.bak"
call :swap "CHUYEN-MAY-MOI.md.bak"                "_backup\2026-11-16\CHUYEN-MAY-MOI.md.bak"
call :swap "chuan-bi-chuyen-may-may-cu.zip"       "_backup\2026-11-16\chuan-bi-chuyen-may-may-cu.zip"
echo.
echo Updating VS Code tasks (.vscode\tasks.json) with the new tool names ...
if not exist ".vscode" mkdir ".vscode"
copy /Y "vscode-config\tasks.json" ".vscode\tasks.json" >nul && echo   done.
echo.
if exist "backend\.venv\Scripts\python.exe" (
  echo Regenerating MANIFEST.sha256 with the new names ...
  backend\.venv\Scripts\python.exe tools_make_manifest.py
  backend\.venv\Scripts\python.exe backend\tools\verify_files.py
) else (
  echo [WARNING] backend\.venv not found - MANIFEST.sha256 not regenerated ^(PREPARE-MIGRATION.bat does it when packing^).
)
echo.
echo DONE. This file now deletes itself.
pause
(goto) 2>nul & del "%~f0"
exit /b 0

:swap
if not exist "%~1" (
  echo   -        %~1  ^(already gone^)
  exit /b 0
)
if not exist "%~2" (
  echo   [KEPT]   %~1  - new file %~2 is missing, not deleting
  exit /b 0
)
del /q "%~1"
if exist "%~1" (
  echo   [ERROR]  %~1  could not be deleted ^(open in another program?^)
) else (
  echo   deleted  %~1
)
exit /b 0

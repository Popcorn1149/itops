# IT Ops - setup on a new machine (called from SETUP-NEW-MACHINE.bat). ASCII only: PowerShell 5.1 reads BOM-less files as ANSI.
#   1. Find Python >= 3.12, install Python 3.12 if missing (winget, or download from python.org without winget) - no admin rights needed
#   2. SETUP.bat /auto: verify source, create .venv, install libraries, portable PostgreSQL
#   3. Restore live data from the backup inside the package (_migration\)
#   4. Open Windows Firewall (asks for admin once - UAC)
#   5. Find / install VS Code + Python extension, open VS Code in this folder
param([string]$Backup = "")
$ErrorActionPreference = "Continue"   # "Stop" turns pip/VS Code stderr warnings into script-stopping errors (PS 5.1) - each step is checked instead
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$Tmp = Join-Path $env:TEMP "itops-setup"
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null

function Step($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "   $t" -ForegroundColor Green }
function Warn($t) { Write-Host "   [!] $t" -ForegroundColor Yellow }
function Fail($t) { Write-Host ""; Write-Host "[ERROR] $t" -ForegroundColor Red; exit 1 }
function Has-Winget { [bool](Get-Command winget -ErrorAction SilentlyContinue) }
function Download($url, $out) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}

function Test-Python($exe) {
    # a Python that really runs and is >= 3.12 (skip the fake Microsoft Store "python.exe" in WindowsApps)
    if (-not $exe) { return $false }
    if ($exe -like "*\WindowsApps\*") { return $false }
    try {
        $v = & $exe -c "import sys; print(sys.version_info >= (3, 12))" 2>$null
        return ($LASTEXITCODE -eq 0 -and "$v".Trim() -eq "True")
    } catch { return $false }
}

function Find-Python {
    $c = @()
    foreach ($v in "3.13", "3.12", "3.14") {
        try { $p = & py "-$v" -c "import sys; print(sys.executable)" 2>$null; if ($LASTEXITCODE -eq 0 -and $p) { $c += "$p".Trim() } } catch {}
    }
    $c += (Get-Command python -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    foreach ($d in "$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles", "$env:LOCALAPPDATA\Python") {
        if (Test-Path $d) { $c += (Get-ChildItem $d -Recurse -Depth 2 -Filter python.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
    }
    foreach ($e in $c) { if (Test-Python $e) { return $e } }
    return $null
}

function Find-Code {
    $c = @("$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd", "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd")
    $c += (Get-Command code.cmd -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    foreach ($e in $c) { if ($e -and (Test-Path $e)) { return $e } }
    return $null
}

# ---------------------------------------------------------------- 1. Python
Step "[1/5] Python"
$py = Find-Python
if (-not $py) {
    Warn "Python >= 3.12 not found - installing Python 3.12 (1-3 minutes, no admin rights needed) ..."
    if (Has-Winget) {
        & winget install -e --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements | Out-Host
    }
    $py = Find-Python
    if (-not $py) {
        $inst = Join-Path $Tmp "python-3.12.10-amd64.exe"
        Download "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe" $inst
        Start-Process -FilePath $inst -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_launcher=1", "Include_test=0" -Wait
        $py = Find-Python
    }
    if (-not $py) { Fail "Could not install Python. Install Python 3.12 by hand from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run again." }
}
Ok "$py ($(& $py --version))"
# SETUP.bat calls "python" -> put the Python found first on PATH for this session
$env:PATH = (Split-Path $py) + ";" + (Join-Path (Split-Path $py) "Scripts") + ";" + $env:PATH

# ---------------------------------------------------------------- 2. SETUP.bat
Step "[2/5] Setup (SETUP.bat): verify source, .venv, libraries, PostgreSQL"
& cmd.exe /c "`"$Root\SETUP.bat`" /auto"
if ($LASTEXITCODE -ne 0) { Fail "SETUP.bat reported an error - see the error above, fix it and run SETUP-NEW-MACHINE.bat again." }
$venvPy = Join-Path $Root "backend\.venv\Scripts\python.exe"

# ---------------------------------------------------------------- 3. Data
Step "[3/5] Restore live data"
$env:PYTHONUTF8 = "1"
$a = @("backend\tools\migrate_machine.py", "restore")
if ($Backup) { $a += $Backup }
& $venvPy @a
if ($LASTEXITCODE -ne 0) { Fail "Data restore failed - see the error above." }

# ---------------------------------------------------------------- 4. Firewall
Step "[4/5] Windows Firewall (ports 8100, 514, 162, 2055, 6343)"
$fw = Join-Path $Root "OPEN-FIREWALL.bat"
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$fw`"" -Verb RunAs -Wait
    Ok "OPEN-FIREWALL.bat done"
} catch {
    Warn "Could not open it (admin rights refused?). Do it later: right-click OPEN-FIREWALL.bat > Run as administrator."
}

# ---------------------------------------------------------------- 5. VS Code
Step "[5/5] VS Code + Python extension"
$code = Find-Code
if (-not $code) {
    Warn "VS Code not found - installing (1-2 minutes) ..."
    if (Has-Winget) {
        & winget install -e --id Microsoft.VisualStudioCode --scope user --silent --accept-package-agreements --accept-source-agreements --override "/VERYSILENT /NORESTART /MERGETASKS=!runcode,addcontextmenufiles,addcontextmenufolders,addtopath" | Out-Host
    }
    $code = Find-Code
    if (-not $code) {
        $inst = Join-Path $Tmp "VSCodeUserSetup-x64.exe"
        Download "https://update.code.visualstudio.com/latest/win32-x64-user/stable" $inst
        Start-Process -FilePath $inst -ArgumentList "/VERYSILENT", "/NORESTART", "/MERGETASKS=!runcode,addcontextmenufiles,addcontextmenufolders,addtopath" -Wait
        $code = Find-Code
    }
}
if (-not $code) {
    Warn "Could not install VS Code. Install it by hand from https://code.visualstudio.com and open this folder."
} else {
    Ok $code
    # F5 needs these 2 extensions (.vscode\launch.json uses "type": "debugpy")
    & $code --install-extension ms-python.python --install-extension ms-python.debugpy --force 2>&1 | Select-String -Pattern "installed|already" | ForEach-Object { Ok $_.Line }
}

$ips = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | ForEach-Object { $_.IPAddress }) -join ", "
Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " DONE. In the VS Code window that just opened:" -ForegroundColor Green
Write-Host "   Ctrl+Shift+D > choose '> Thiet bi that (cong 514/162)' (real devices) > F5"
Write-Host "   (VS Code asks 'Do you trust the authors' > Yes. Next time just F5.)"
Write-Host "   Sign in with the OLD admin account (+ 2FA as before)."
Write-Host " IP of this machine: $ips"
Write-Host "   -> point pfSense syslog/softflowd, SNMP traps and agents to this IP (MIGRATE-TO-NEW-MACHINE.md section 7)."
Write-Host "==============================================" -ForegroundColor Green
if ($code) { & $code $Root }
exit 0

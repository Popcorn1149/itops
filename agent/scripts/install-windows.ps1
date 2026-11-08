<#
  Cài / nâng cấp IT Ops Agent trên Windows – chạy được nhiều lần (dùng làm GPO Startup Script).

  GPO: Computer Configuration → Policies → Windows Settings → Scripts → Startup → PowerShell Scripts
       Script: \\FILESERVER\itops$\install-windows.ps1
       Tham số: -Server https://itops.cty.local:8443 -Token itk_xxx -CaPin <sha256> -Source \\FILESERVER\itops$\itops-agent-windows-amd64.exe

  Thư mục chia sẻ \\FILESERVER\itops$: Domain Computers chỉ ĐỌC, chỉ admin được ghi (ai ghi được file .exe ở đây = chạy code
  bằng SYSTEM trên mọi máy). Script kiểm SHA-256 với SHA256SUMS.txt cùng thư mục trước khi cài.
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$CaPin = "",
  [string]$UpdatePubKey = "",
  [string]$Source = "$PSScriptRoot\itops-agent-windows-amd64.exe",
  [switch]$AllowHttp
)
$ErrorActionPreference = "Stop"
$log = "$env:WINDIR\Temp\itops-agent-install.log"
function Log($m) { "$(Get-Date -Format s) $m" | Out-File -FilePath $log -Append -Encoding utf8 }

try {
  $installed = "$env:ProgramFiles\ITOpsAgent\itops-agent.exe"
  $svc = Get-Service -Name ITOpsAgent -ErrorAction SilentlyContinue
  $want = (& $Source version).Trim()
  if ($svc -and (Test-Path $installed)) {
    $have = (& $installed version).Trim()
    if ($have -eq $want) {
      if ($svc.Status -ne "Running") { Start-Service ITOpsAgent; Log "khởi động lại dịch vụ ($have)" }
      exit 0                                   # đã cài đúng phiên bản – không làm gì (GPO chạy mỗi lần khởi động)
    }
  }
  # kiểm SHA-256 của file cài với danh sách công bố
  $sums = Join-Path (Split-Path $Source) "SHA256SUMS.txt"
  if (Test-Path $sums) {
    $name = Split-Path $Source -Leaf
    $line = Get-Content $sums | Where-Object { $_ -match "\s\*?$([regex]::Escape($name))$" } | Select-Object -First 1
    $hash = (Get-FileHash $Source -Algorithm SHA256).Hash.ToLower()
    if (-not $line -or -not $line.ToLower().StartsWith($hash)) { Log "SAI MÃ BĂM ${name} – dừng cài"; exit 1 }
  } else { Log "CẢNH BÁO: không có SHA256SUMS.txt cạnh file cài" }

  $tmp = Join-Path $env:WINDIR "Temp\itops-agent-setup.exe"
  Copy-Item $Source $tmp -Force
  $agentArgs = @("install", "--server", $Server, "--token", $Token)
  if ($CaPin) { $agentArgs += @("--ca-pin", $CaPin) }
  if ($UpdatePubKey) { $agentArgs += @("--update-pubkey", $UpdatePubKey) }
  if ($AllowHttp) { $agentArgs += "--allow-http" }
  $out = & $tmp @agentArgs 2>&1
  Log "cài ${want}: $out"
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
} catch {
  Log "LỖI: $_"
  exit 1
}

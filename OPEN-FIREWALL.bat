@echo off
REM Open Windows Firewall so IT Ops can receive Syslog (514) / SNMP Trap (162) / NetFlow-IPFIX (2055) / sFlow (6343) and web (8100) from the internal network
net session >nul 2>&1
if errorlevel 1 (
  echo Must run as Administrator: right-click this file ^> Run as administrator
  pause
  exit /b 1
)
netsh advfirewall firewall delete rule name="ITOps Syslog UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps Syslog TCP" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps SNMP Trap" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps v2 Web" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps Flow UDP" >nul 2>&1
netsh advfirewall firewall add rule name="ITOps Syslog UDP" dir=in action=allow protocol=UDP localport=514 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps Syslog TCP" dir=in action=allow protocol=TCP localport=514 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps SNMP Trap" dir=in action=allow protocol=UDP localport=162 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps v2 Web" dir=in action=allow protocol=TCP localport=8100 remoteip=localsubnet
netsh advfirewall firewall add rule name="ITOps Flow UDP" dir=in action=allow protocol=UDP localport=2055,6343 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
REM Windows creates a BLOCK rule for goflow2*.exe if the "Windows Defender Firewall has blocked..." dialog is dismissed -> remove it so port 2055 receives data
powershell -NoProfile -Command "Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*goflow*' -and $_.Action -eq 'Block' } | Remove-NetFirewallRule" >nul 2>&1
echo.
echo Checking the Windows SNMP Trap service (if running it takes port 162):
sc query SNMPTRAP | find "RUNNING" >nul && (
  echo   SNMPTRAP is running - stopping it so IT Ops can use port 162...
  sc stop SNMPTRAP >nul
  sc config SNMPTRAP start= disabled >nul
) || echo   OK, port 162 is free.
echo.
echo IP address of this machine (point devices here to send logs):
ipconfig | findstr /R /C:"IPv4"
echo.
echo DONE. To remove later: netsh advfirewall firewall delete rule name="ITOps Syslog UDP" (same for the other rules)
pause

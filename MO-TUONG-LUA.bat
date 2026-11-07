@echo off
REM Mo Windows Firewall cho IT Ops nhan Syslog (514) / SNMP Trap (162) va web (8100) tu mang noi bo
net session >nul 2>&1
if errorlevel 1 (
  echo Can chay bang quyen Administrator: chuot phai file nay ^> Run as administrator
  pause
  exit /b 1
)
netsh advfirewall firewall delete rule name="ITOps Syslog UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps Syslog TCP" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps SNMP Trap" >nul 2>&1
netsh advfirewall firewall delete rule name="ITOps v2 Web" >nul 2>&1
netsh advfirewall firewall add rule name="ITOps Syslog UDP" dir=in action=allow protocol=UDP localport=514 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps Syslog TCP" dir=in action=allow protocol=TCP localport=514 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps SNMP Trap" dir=in action=allow protocol=UDP localport=162 remoteip=localsubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
netsh advfirewall firewall add rule name="ITOps v2 Web" dir=in action=allow protocol=TCP localport=8100 remoteip=localsubnet
echo.
echo Kiem tra dich vu SNMP Trap cua Windows (neu dang chay se chiem cong 162):
sc query SNMPTRAP | find "RUNNING" >nul && (
  echo   SNMPTRAP dang chay - tat de IT Ops dung cong 162...
  sc stop SNMPTRAP >nul
  sc config SNMPTRAP start= disabled >nul
) || echo   OK, cong 162 trong.
echo.
echo IP cua may nay (dung de tro thiet bi gui log ve):
ipconfig | findstr /R /C:"IPv4"
echo.
echo XONG. Go bo sau nay: netsh advfirewall firewall delete rule name="ITOps Syslog UDP" (tuong tu cho cac rule khac)
pause

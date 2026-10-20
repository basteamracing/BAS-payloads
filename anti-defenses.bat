powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"  
net stop wuauserv & sc config wuauserv start= disabled
net stop wscsvc 
[SC] OpenService FAILED 5:

Access is denied.


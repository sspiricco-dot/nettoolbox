@echo off
title Windows Time Sync
echo NTP Server: {{NTP_SERVER}}
w32tm /config /manualpeerlist:"{{NTP_SERVER}}" /syncfromflags:manual /update
net stop w32time
net start w32time
w32tm /resync
echo Done. NTP={{NTP_SERVER}}

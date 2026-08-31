@echo off
echo Disabling SMBv1 (reboot required)
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart
powershell -NoProfile -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
echo Done. Reboot when you can.

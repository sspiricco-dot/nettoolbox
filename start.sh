#!/bin/bash
set -e

# Web terminal (ssh/telnet/anything) bound to loopback only.
ttyd -W -a -i lo -p 7681 -t fontSize=15 -t 'theme={"background":"#0a0a0a","foreground":"#e9ebec","cursor":"#00d6c9","selectionBackground":"#1677ff66"}' /app/connect.sh &

# Headless display + noVNC for the RDP client (loopback only).
/app/rdp-display.sh || echo "RDP display failed; the RDP tab will retry on connect" >&2

# Dashboard API + UI, also loopback only.
# OpenSpeedTest nginx and the LAN file drop stay off until started from the UI.
exec python3 /app/app.py

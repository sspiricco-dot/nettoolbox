#!/bin/bash
set -e

# Web terminal (ssh/telnet/anything) bound to loopback only.
ttyd -W -a -i lo -p 7681 /app/connect.sh &

# Headless display + noVNC for the RDP client (loopback only).
/app/rdp-display.sh || echo "RDP display failed; the RDP tab will retry on connect" >&2

# Dashboard API + UI, also loopback only.
exec python3 /app/app.py

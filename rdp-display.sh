#!/bin/bash
# Headless display for the in-browser RDP client (FreeRDP → x11vnc → noVNC).
# Bound to loopback only — same model as ttyd / the Flask UI.
set -e
export DISPLAY=:99

Xvfb :99 -screen 0 1600x900x24 -ac +extension RANDR >/tmp/xvfb.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
  xdpyinfo -display :99 >/dev/null 2>&1 && break
  sleep 0.2
done

x11vnc -display :99 -localhost -nopw -forever -shared -rfbport 5901 \
  -ncache 0 -quiet >/tmp/x11vnc.log 2>&1 &

websockify --web=/usr/share/novnc 127.0.0.1:7682 127.0.0.1:5901 \
  >/tmp/websockify.log 2>&1 &

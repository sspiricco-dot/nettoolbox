#!/bin/bash
# Headless display for the in-browser RDP client (FreeRDP → x11vnc → noVNC).
# Bound to loopback only — same model as ttyd / the Flask UI.
# docker restart leaves /tmp/.X99-lock behind; wipe it if :99 is actually dead.
export DISPLAY=:99

display_up() {
  xdpyinfo -display :99 >/dev/null 2>&1
}

port_up() {
  python3 -c "import socket; s=socket.create_connection(('127.0.0.1', int('$1')), 0.4); s.close()" 2>/dev/null
}

if ! display_up; then
  rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
  mkdir -p /tmp/.X11-unix
  chmod 1777 /tmp/.X11-unix
  Xvfb :99 -screen 0 1600x900x24 -ac +extension RANDR >/tmp/xvfb.log 2>&1 &
  ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
    if display_up; then
      ok=1
      break
    fi
    sleep 0.2
  done
  if [ "$ok" != 1 ]; then
    echo "Xvfb failed on :99" >&2
    cat /tmp/xvfb.log >&2 || true
    exit 1
  fi
fi

if ! port_up 5901; then
  x11vnc -display :99 -localhost -nopw -forever -shared -rfbport 5901 \
    -ncache 0 -quiet >/tmp/x11vnc.log 2>&1 &
  sleep 0.3
fi

if ! port_up 7682; then
  websockify --web=/usr/share/novnc 127.0.0.1:7682 127.0.0.1:5901 \
    >/tmp/websockify.log 2>&1 &
  sleep 0.2
fi

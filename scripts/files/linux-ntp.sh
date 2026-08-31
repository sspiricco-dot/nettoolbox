#!/bin/bash
set -euo pipefail
NTP_SERVER="{{NTP_SERVER}}"
if command -v timedatectl >/dev/null 2>&1; then
  mkdir -p /etc/systemd/timesyncd.conf.d
  cat >/etc/systemd/timesyncd.conf.d/nettoolbox.conf <<EOF
[Time]
NTP=${NTP_SERVER}
EOF
  timedatectl set-ntp true
  systemctl restart systemd-timesyncd 2>/dev/null || true
  timedatectl status || true
elif command -v chronyc >/dev/null 2>&1; then
  echo "server ${NTP_SERVER} iburst" >/etc/chrony/sources.d/nettoolbox.sources
  systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
  chronyc sources || true
else
  echo "Install systemd-timesyncd or chrony"; exit 1
fi
echo "NTP=${NTP_SERVER}"

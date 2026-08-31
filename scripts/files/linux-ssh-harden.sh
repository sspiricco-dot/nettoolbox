#!/bin/bash
set -euo pipefail
SSH_PORT="{{SSH_PORT}}"
PERMIT_ROOT="{{PERMIT_ROOT}}"
PASSWORD_AUTH="{{PASSWORD_AUTH}}"
CFG=/etc/ssh/sshd_config
cp -a "$CFG" "${CFG}.bak.$(date +%Y%m%d%H%M%S)"
set_kv() {
  local key="$1" val="$2"
  if grep -qiE "^[# ]*${key} " "$CFG"; then
    sed -i -E "s|^[# ]*${key} .*|${key} ${val}|" "$CFG"
  else
    printf '\n%s %s\n' "$key" "$val" >> "$CFG"
  fi
}
set_kv Port "$SSH_PORT"
set_kv PermitRootLogin "$PERMIT_ROOT"
set_kv PasswordAuthentication "$PASSWORD_AUTH"
set_kv ChallengeResponseAuthentication no
set_kv UsePAM yes
set_kv X11Forwarding no
set_kv MaxAuthTries 4
sshd -t
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi
echo "sshd updated. Port=${SSH_PORT} PermitRootLogin=${PERMIT_ROOT} PasswordAuthentication=${PASSWORD_AUTH}"
echo "Keep this SSH session open until you confirm a new login."

#!/bin/bash
set -euo pipefail
SSH_PORT="{{SSH_PORT}}"
if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed"; exit 1
fi
ufw allow "${SSH_PORT}/tcp" comment 'ssh'
ufw --force enable
ufw status verbose
echo "UFW on, SSH ${SSH_PORT}/tcp allowed."

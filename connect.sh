#!/bin/bash
# Invoked by ttyd (via --url-arg) as: connect.sh <proto> <host> <port> <user> [key-name]
# Falls back to a plain shell when no/unknown proto is given.
proto="$1"
host="$2"
port="$3"
user="$4"
key="$5"
key_dir="${NETTOOLBOX_SSH_DIR:-/data/ssh-keys}"

case "$proto" in
  ssh)
    key_opts=()
    if [ -n "$key" ]; then
      if [[ "$key" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] && [ -f "$key_dir/$key" ]; then
        key_opts=(-i "$key_dir/$key" -o IdentitiesOnly=yes)
      else
        echo "SSH key '$key' not found; continuing without it." >&2
      fi
    fi
    if [ -n "$user" ]; then
      exec ssh "${key_opts[@]}" -p "${port:-22}" "${user}@${host}"
    else
      exec ssh "${key_opts[@]}" -p "${port:-22}" "${host}"
    fi
    ;;
  telnet)
    exec telnet "$host" "${port:-23}"
    ;;
  *)
    exec bash
    ;;
esac

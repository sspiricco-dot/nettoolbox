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
  serial)
    # connect.sh serial <ttyUSB0|ttyACM0> <baud> <frame e.g. 8N1> <flow n|h|s> [log]
    dev="$host"; baud="${port:-9600}"; frame="${user:-8N1}"; flow="${key:-n}"; log="$6"
    dev_root="${NETTOOLBOX_HOSTDEV:-/hostdev}"
    if ! [[ "$dev" =~ ^tty(USB|ACM)[0-9]{1,3}$ ]]; then echo "invalid serial device"; sleep 5; exit 1; fi
    if ! [[ "$baud" =~ ^(1200|2400|4800|9600|19200|38400|57600|115200|230400|460800|921600)$ ]]; then echo "invalid baud rate"; sleep 5; exit 1; fi
    if ! [[ "$frame" =~ ^([5-8])([NEO])([12])$ ]]; then echo "invalid frame (use e.g. 8N1)"; sleep 5; exit 1; fi
    bits="${BASH_REMATCH[1]}"; par="${BASH_REMATCH[2],,}"; stop="${BASH_REMATCH[3]}"
    [[ "$flow" =~ ^[nhs]$ ]] || flow=n
    if [ ! -e "$dev_root/$dev" ]; then
      echo "Serial device $dev not found. Plug in the console cable and press Connect again."
      sleep 8; exit 1
    fi
    log_opts=()
    if [ "$log" = "1" ]; then
      log_dir="${NETTOOLBOX_SERIAL_LOGS:-/tmp/serial-logs}"
      mkdir -p "$log_dir"
      log_opts=(--logfile "$log_dir/$dev-$(date +%Y%m%d-%H%M%S).log")
    fi
    printf '\033[2mSerial %s  %s %s  flow=%s   exit: Ctrl-A Ctrl-X   BREAK: Ctrl-A Ctrl-\\\033[0m\r\n' "$dev" "$baud" "$frame" "$flow"
    exec picocom --quiet -b "$baud" -d "$bits" -p "$par" --stopbits "$stop" -f "$flow" \
      --noreset --nolock "${log_opts[@]}" "$dev_root/$dev"
    ;;
  *)
    exec bash
    ;;
esac

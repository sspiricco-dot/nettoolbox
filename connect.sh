#!/bin/bash
# Invoked by ttyd (via --url-arg) as: connect.sh <proto> <host> <port> <user>
# Falls back to a plain shell when no/unknown proto is given.
proto="$1"
host="$2"
port="$3"
user="$4"

case "$proto" in
  ssh)
    if [ -n "$user" ]; then
      exec ssh -p "${port:-22}" "${user}@${host}"
    else
      exec ssh -p "${port:-22}" "${host}"
    fi
    ;;
  telnet)
    exec telnet "$host" "${port:-23}"
    ;;
  *)
    exec bash
    ;;
esac

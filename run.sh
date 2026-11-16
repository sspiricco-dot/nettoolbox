#!/bin/sh
# Launches the NetToolbox dashboard as a persistent background service.
# Uses host networking so scans/CDP/bandwidth monitoring see the real interfaces.
# The dashboard and terminal only bind to 127.0.0.1 inside the container
# (see start.sh / app.py), so this does not expose anything to the LAN.
docker_nm=""
if [ -d /etc/NetworkManager/system-connections ]; then
  docker_nm="-v /etc/NetworkManager/system-connections:/host/nm-connections:ro"
fi
# Serial Console: host /dev is mounted read-only and only USB-serial adapters
# (major 188 = ttyUSB, 166 = ttyACM) are allowed, so console cables plugged in
# later still work without restarting the container.
# SSH keys made in the SSH keys tab live here on the host, so they survive
# container rebuilds. Losing a key can lock you out of a server.
ssh_dir="${NETTOOLBOX_SSH_HOST_DIR:-$HOME/.config/nettoolbox/ssh-keys}"
mkdir -p "$ssh_dir" && chmod 700 "$ssh_dir"
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  $docker_nm \
  -v "$ssh_dir:/data/ssh-keys" \
  -v /dev:/hostdev:ro \
  --device-cgroup-rule='c 188:* rmw' \
  --device-cgroup-rule='c 166:* rmw' \
  -e NETTOOLBOX_HOST_UID="$(id -u)" -e NETTOOLBOX_HOST_GID="$(id -g)" \
  --name nettoolbox \
  nettoolbox

echo "NetToolbox is running at http://127.0.0.1:8642"
echo "LAN OpenSpeedTest (port 3000) stays off until you start it in the Speed Test tab"
echo "LAN file drop (port 8765) stays off until you start it in the File drop tab"
echo "TFTP server (UDP 69) stays off until you start it in the TFTP tab"
echo "SSH keys are stored on the host in $ssh_dir"
echo "Serial Console sees USB console cables (ttyUSB*/ttyACM*) as they are plugged in"

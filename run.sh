#!/bin/sh
# Launches the NetToolbox dashboard as a persistent background service.
# Uses host networking so scans/CDP/bandwidth monitoring see the real interfaces.
# The dashboard and terminal only bind to 127.0.0.1 inside the container
# (see start.sh / app.py), so this does not expose anything to the LAN.
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --name nettoolbox \
  nettoolbox

echo "NetToolbox is running at http://127.0.0.1:8642"

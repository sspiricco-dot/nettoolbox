FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    tcpdump \
    tshark \
    iw \
    wireless-tools \
    openssl \
    openssh-client \
    telnet \
    netcat-openbsd \
    iproute2 \
    net-tools \
    iputils-ping \
    mtr-tiny \
    traceroute \
    dnsutils \
    whois \
    curl \
    wget \
    vim-tiny \
    less \
    ca-certificates \
    python3 \
    python3-flask \
    python3-websockify \
    snmp \
    sshpass \
    freerdp2-x11 \
    xvfb \
    x11vnc \
    x11-utils \
    xdotool \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# ttyd: static binary, provides a browser-based terminal for ssh/telnet
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) TTYD_ARCH=x86_64 ;; \
      arm64) TTYD_ARCH=aarch64 ;; \
      *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL -o /usr/local/bin/ttyd \
      "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${TTYD_ARCH}" && \
    chmod +x /usr/local/bin/ttyd

# Lightweight HTML5 VNC client (avoid Debian novnc → node/numpy stack)
RUN curl -fsSL https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.tar.gz \
    | tar -xz -C /tmp \
    && mv /tmp/noVNC-1.5.0 /usr/share/novnc

WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static
COPY start.sh /app/start.sh
COPY connect.sh /app/connect.sh
COPY rdp-display.sh /app/rdp-display.sh
COPY scripts /app/scripts
RUN chmod +x /app/start.sh /app/connect.sh /app/rdp-display.sh

CMD ["/app/start.sh"]

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

WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static
COPY start.sh /app/start.sh
COPY connect.sh /app/connect.sh
RUN chmod +x /app/start.sh /app/connect.sh

CMD ["/app/start.sh"]

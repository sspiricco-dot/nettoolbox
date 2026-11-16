FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Only what the dashboard actually calls. Everything else (docs, man pages, Mesa/LLVM GL
# drivers Xvfb never needs, nmap NSE scripts) is deleted in the same layer so it never ships.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iw \
    openssh-client \
    sshpass \
    picocom \
    telnet \
    iproute2 \
    iputils-ping \
    mtr-tiny \
    traceroute \
    dnsutils \
    whois \
    curl \
    ca-certificates \
    python3 \
    python3-flask \
    python3-brotli \
    python3-zstandard \
    python3-cryptography \
    freerdp2-x11 \
    xvfb \
    x11vnc \
    x11-utils \
    xdotool \
    fonts-dejavu-core \
    nginx \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log \
       /usr/share/doc/* /usr/share/man/* /usr/share/info/* /usr/share/lintian /usr/share/locale/* \
       /usr/share/nmap/scripts /usr/share/nmap/nselib \
    && rm -f /usr/lib/*-linux-gnu/dri/*.so /usr/lib/*-linux-gnu/libLLVM-*.so* /usr/lib/*-linux-gnu/libz3.so* \
    && find /usr/lib/python3* -name __pycache__ -type d -prune -exec rm -rf {} +

# websockify (noVNC bridge) as plain Python: the Debian package drags in numpy for nothing.
RUN curl -fsSL https://github.com/novnc/websockify/archive/refs/tags/v0.11.0.tar.gz | tar -xz -C /tmp \
    && mv /tmp/websockify-0.11.0/websockify /usr/local/lib/python3.11/dist-packages/websockify \
    && rm -rf /tmp/websockify-0.11.0 \
    && printf '#!/bin/sh\nexec python3 -W ignore -c "from websockify.websocketproxy import websockify_init; websockify_init()" "$@"\n' > /usr/local/bin/websockify \
    && chmod +x /usr/local/bin/websockify

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
    && mv /tmp/noVNC-1.5.0 /usr/share/novnc \
    && rm -rf /usr/share/novnc/tests /usr/share/novnc/docs /usr/share/novnc/snap /usr/share/novnc/utils /usr/share/novnc/po /usr/share/novnc/.github

# Self-hosted OpenSpeedTest (LAN speed test). Static HTML/JS + 30MB download blob.
RUN curl -fsSL https://github.com/openspeedtest/Speed-Test/archive/refs/heads/main.tar.gz \
    | tar -xz -C /tmp \
    && mkdir -p /usr/share/openspeedtest \
    && mv /tmp/Speed-Test-main/* /usr/share/openspeedtest/ \
    && rm -rf /tmp/Speed-Test-main /usr/share/openspeedtest/downloading /usr/share/openspeedtest/*.md /usr/share/openspeedtest/.git* \
    && rm -f /etc/nginx/sites-enabled/default \
    && mkdir -p /var/lib/nginx/body /var/lib/nginx/proxy /run/nginx

COPY openspeedtest.conf /etc/nginx/conf.d/openspeedtest.conf

WORKDIR /app
COPY app.py /app/app.py
COPY netmap.py /app/netmap.py
COPY audit.py /app/audit.py
COPY share_http.py /app/share_http.py
COPY tftp.py /app/tftp.py
COPY compress.py /app/compress.py
COPY sshkeys.py /app/sshkeys.py
COPY sslconv.py /app/sslconv.py
COPY neighbors.py /app/neighbors.py
COPY serialports.py /app/serialports.py
COPY webproxy.py /app/webproxy.py
COPY static /app/static
COPY start.sh /app/start.sh
COPY connect.sh /app/connect.sh
COPY rdp-display.sh /app/rdp-display.sh
COPY scripts /app/scripts
RUN chmod +x /app/start.sh /app/connect.sh /app/rdp-display.sh

CMD ["/app/start.sh"]

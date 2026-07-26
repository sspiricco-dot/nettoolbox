# NetToolbox

A portable network & security dashboard for field technicians. Build it once, carry it on your laptop, and spin it up on whatever network you're plugged into — client site, home lab, or your own office.

![NetToolbox screenshot](screenshot.png)

Everything runs in a single Docker container with a web UI. No install on the host beyond Docker itself, no data leaves your machine except for the handful of tools that explicitly need the internet (see [Security notes](#security-notes) below).

## Features

**Network**
- Network discovery (ARP/ping sweep) with a graphical topology view
- Port scanner (custom port list or full 1–65535 range)
- Ping with a one-shot check and a live latency monitor
- Traceroute
- Neighbor discovery — CDP (Cisco) and LLDP (standard)
- WiFi analyzer (nearby SSIDs, signal, frequency)
- Speed test (download/upload/ping via Cloudflare)
- Wake-on-LAN
- Local ARP table viewer
- Live bandwidth monitor (RX/TX per interface)

**Security**
- Multi-record DNS lookup (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Public IP / IP geolocation lookup (yours or any IP)
- Domain recon: main A record + subdomains from public SSL certificate transparency logs (crt.sh) — fully passive
- SSL/TLS certificate inspector (works on self-signed/internal certs too)
- HTTP security header checker (HSTS, CSP, X-Frame-Options, etc.)
- Hash / Base64 / JWT toolkit — MD5, SHA-1/256/384/512, Base64 encode/decode, JWT decode, all client-side

**Utility**
- Quick Connect — save frequently-used hosts and ping/scan/SSH/Telnet them in one click
- Full SSH/Telnet terminal in the browser (via [ttyd](https://github.com/tsl0922/ttyd))
- QR code generator for sharing an IP/URL with a phone

Bilingual UI (Persian/English) with light and dark themes.

## Quick start

```bash
git clone https://github.com/<your-username>/nettoolbox.git
cd nettoolbox
docker build -t nettoolbox .
./run.sh
```

Then open **http://127.0.0.1:8642**.

`run.sh` starts the container with `--restart unless-stopped`, so it comes back automatically after a reboot as long as Docker itself is set to start on boot (`sudo systemctl enable docker` on Linux, or enable "Start Docker Desktop on login" on Mac/Windows).

## Security notes

This tool is intentionally powerful, so it's worth understanding what it does before running it on a machine you care about:

- **Host networking + `NET_ADMIN`/`NET_RAW`**: the container runs with `--net=host` and raw-socket capabilities so tools like `nmap`, `arp-scan`, and CDP/LLDP capture can see the real network your host is on. This is what makes it a useful field tool, but it also means the container has broad visibility into (and can send packets on) whatever network you plug into.
- **Dashboard and terminal are loopback-only.** The web UI (`:8642`) and the browser terminal (`:7681`, via ttyd) both bind to `127.0.0.1` inside the container — they are **not** exposed to the LAN you're connected to, even though the container itself has host networking. Only processes on your own machine can reach them.
- **A handful of tools call out to the internet**: Speed Test (Cloudflare), IP Geolocation / "My IP" (ipinfo.io), and Domain recon's subdomain lookup (crt.sh). Everything else (scanning, ARP, CDP/LLDP, SSH/Telnet, hashing) stays local.
- **The terminal is a real shell** with `ssh`/`telnet` clients and your container's privileges — treat it like any other terminal you carry around.

Because of the above, only run this on hardware you control, and don't publish the dashboard port beyond loopback.

## Requirements

- Docker
- Linux host recommended (host networking works most predictably there; on Mac/Windows via Docker Desktop, host networking support varies by version)

## Tech stack

- Backend: Python/Flask, calling out to `nmap`, `arp-scan`, `tshark`, `dig`, `openssl`, `iw`, `traceroute`, `curl`
- Frontend: single-file HTML/CSS/JS, no build step, no external CDN dependencies
- Terminal: [ttyd](https://github.com/tsl0922/ttyd)
- QR codes: [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase (MIT), bundled in `static/qrcode.js`

## License

MIT — see [LICENSE](LICENSE).

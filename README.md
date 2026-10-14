# NetToolbox

**v2.4.0** — a portable network & security dashboard for network engineers, system administrators, and field technicians.

One Docker container. One web UI. Run it on your laptop, workstation, server, home lab, or client site.

[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/sajadprp/nettoolbox)
[![Docker Pulls](https://img.shields.io/docker/pulls/sajadprp/nettoolbox?logo=docker)](https://hub.docker.com/r/sajadprp/nettoolbox)
[![Version](https://img.shields.io/badge/version-2.4.0-d4894a)](https://hub.docker.com/r/sajadprp/nettoolbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20mac%20%7C%20windows-lightgrey)](https://www.docker.com/)
[![No CDN](https://img.shields.io/badge/dependencies-self--contained-success)](https://hub.docker.com/r/sajadprp/nettoolbox)

![NetToolbox demo](https://raw.githubusercontent.com/sspiricco-dot/nettoolbox/main/demo.gif)

Demo walkthrough (sample lab data only — not a real customer network): This link, Subnet 10.20.30.0/24, Ping 1.1.1.1, DNS example.com, SHA-256, QR.

## Quick start

Docker Hub: https://hub.docker.com/r/sajadprp/nettoolbox

Tags: `sajadprp/nettoolbox:latest` · `sajadprp/nettoolbox:v2` · `sajadprp/nettoolbox:v2.4.0`

### 1. Pull the Docker image

```bash
docker pull sajadprp/nettoolbox:latest
```

Or pin a version:

```bash
docker pull sajadprp/nettoolbox:v2.4.0
```

### 2. Run NetToolbox

```bash
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --name nettoolbox \
  sajadprp/nettoolbox:latest
```

### 3. Open the dashboard

```text
http://127.0.0.1:8642
```

That is it.

If a container named `nettoolbox` already exists: `docker rm -f nettoolbox` first.

## Why NetToolbox?

Network and IT technicians often need several different tools during a site visit:

- Network scanner
- Ping and traceroute
- Port scanner
- SSH/Telnet client
- RDP client
- DNS and Whois tools
- SSL certificate checker
- HTTP security header checker
- SNMP tools
- WiFi analyzer
- Subnet calculator
- Wake-on-LAN
- Hash and JWT utilities
- Network monitoring tools
- Cisco/MikroTik maps and a router security audit

NetToolbox brings these tools together in a single browser-based dashboard running inside Docker.

No desktop installation.
No separate applications.
No account required.

Just pull the Docker image and start the container.

## Run a specific version

```bash
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --name nettoolbox \
  sajadprp/nettoolbox:v2.4.0
```

## Build from source

```bash
git clone https://github.com/sspiricco-dot/nettoolbox.git
cd nettoolbox
docker build -t nettoolbox .
./run.sh
```

`run.sh` starts the container with `--restart unless-stopped`. Enable Docker at boot if you want it back after a reboot (`sudo systemctl enable docker` on Linux, or start Docker Desktop on login on Mac/Windows).

**Copy a pre-built image to another laptop (USB, no rebuild)**

```bash
docker save nettoolbox:v2.4.0 nettoolbox:latest | gzip > nettoolbox-v2.4.0.tar.gz
gzip -dc nettoolbox-v2.4.0.tar.gz | docker load
docker run -d --restart unless-stopped --net=host \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --name nettoolbox nettoolbox:v2.4.0
```

## Versions

`main` is always **v2**. v1 stays as a git tag.

| | v1 | v2.0 | v2.1 | v2.2 | v2.3 | **v2.4** |
|---|---|---|---|---|---|---|
| Discover, ping, traceroute, port scan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSH/Telnet in the browser | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSL, headers, hash/JWT, DNS, WiFi, WoL | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| In-browser RDP | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Link status / MTR / subnet / whois / export | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Host profiles | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SNMP, site report, script library | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| WiFi QR | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Network map, OpenSpeedTest LAN | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Domain IPs + MikroTik list export, whois intel, router audit | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

```bash
git clone --branch v1.0.0 https://github.com/sspiricco-dot/nettoolbox.git nettoolbox-v1
```

## Features

### Network tools

**Network discovery** — ARP and ping sweep on the LAN, well-known port checks, topology view, CSV/JSON export.

**Port scanner** — custom list, range, or 1–65535.

**Ping** — one-shot check or live latency monitor.

**Traceroute** — hop-by-hop path.

**MTR** — live hop latency and loss.

**Subnet calculator** — IPv4 CIDR, broadcast, usable range, typical gateway, split.

**Neighbor discovery** — CDP and LLDP.

**Network map** — paste Cisco running-config / CDP or MikroTik export / IP neighbor; layered topology SVG and a customer Excel (devices, VLANs, links, IPs).

**SNMP** — GET/WALK, community v1/v2c. Switches, printers, UPS, cameras, Dahua, Hikvision. Hostname, uptime, port names, VLANs.

**WiFi analyzer** — nearby SSIDs, signal, frequency (needs a wireless interface).

**Speed test** — download, upload, ping via Cloudflare, then Hetzner / OVH / others if one is blocked. Self-hosted [OpenSpeedTest](https://openspeedtest.com/) on this laptop for LAN tests; start it from the Speed Test tab, then stop so port 3000 is not left open.

**Wake-on-LAN**, **ARP table**, **live bandwidth** (RX/TX per interface).

**Link status** — interface IP, gateway, DNS, DHCP vs static, public IP.

### Security tools

**DNS lookup** — A, AAAA, MX, TXT, NS, CNAME, SOA.

**Whois** — domain and IP. Also abuse DNSBLs, owner/org, ping, and OS guess (nmap or TTL).

**Public IP / geolocation** — yours or any IP, with fallbacks if ipinfo is unreachable.

**Domain recon** — DNS A/AAAA for the domain and subdomains from public SSL certificates (crt.sh). Export notepad text or a MikroTik address-list `.rsc` with a name you choose. Passive lookup; nothing is sent to the target host for subdomain discovery.

**Router audit** — SSH or Telnet to MikroTik or Cisco (same user as Winbox on SSH). Status dashboard and common holes: open management services, unrestricted dst-nat, MAC Winbox, discovery, bandwidth-server, weak Cisco passwords. Read-only; suggested fix commands to copy. Password is not stored. Winbox itself is not a login protocol.

**SSL/TLS inspector** — public, internal, and self-signed certificates.

**HTTP security headers** — HSTS, CSP, X-Frame-Options, and similar.

**Hash / Base64 / JWT** — MD5, SHA-1/256/384/512, Base64, JWT decode, all in the browser.

### Remote access

**SSH / Telnet** — full terminal in the browser via [ttyd](https://github.com/tsl0922/ttyd). Type the password in the terminal after connect.

**RDP** — Windows desktop in the browser (FreeRDP + noVNC). Internal/self-signed certs are ignored. Shared drive for Windows scripts in the session.

### Host profiles

Save hostname, protocol, port, username, and site notes. Passwords are not stored.

### Script library

Windows, Linux, and MikroTik templates with `{{VARIABLES}}`. Edit, copy, download, or run over SSH. From the SSH/Telnet or RDP tab you can run the same scripts on the host you are already connected to.

### Site visit report

Last discover + neighbors + link status + notes. Download Markdown or text for a ticket.

### QR codes

Text, URL, or WiFi join. Copy or download PNG. WiFi QR from this laptop’s network or typed by hand.

### Interface

Persian and English. Light and dark themes. Single HTML page, no CDN.

## Docker configuration

```bash
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --name nettoolbox \
  sajadprp/nettoolbox:latest
```

**`--net=host`** — the container sees the host’s real interfaces. Needed for ARP, discovery, CDP/LLDP, SNMP, WoL, and LAN analysis.

**`NET_ADMIN` / `NET_RAW`** — required by nmap, arp-scan, packet capture, and similar tools.

## Web interface ports

| Service | Port | Bind |
|---|---:|---|
| Dashboard | 8642 | loopback (`127.0.0.1`) |
| Web terminal | 7681 | loopback |
| RDP / noVNC | 7682 | loopback |
| OpenSpeedTest | 3000 | LAN, **only while started** from the Speed Test tab |

Dashboard:

```text
http://127.0.0.1:8642
```

The UI, terminal, and RDP viewer are **not** published on the LAN even with host networking. Only processes on this machine can reach them. OpenSpeedTest is the exception, and only while you leave it on.

## Security notes

This tool is powerful. Understand what it does before you run it.

- **Host networking + `NET_ADMIN`/`NET_RAW`**: the container can see and send packets on whatever network you plug into.
- **Dashboard / terminal / RDP are loopback-only** (`8642`, `7681`, `7682`).
- **OpenSpeedTest (`:3000`) is off until you start it.** Other devices on the LAN can then measure speed to this laptop (static HTML/JS, no shell). Stop it when you are done.
- **The terminal is a real shell** with ssh/telnet and the container’s privileges.
- **RDP passwords** go to FreeRDP on stdin, not on the command line.
- **Internet-connected features**: Speed Test (Cloudflare and other CDNs as fallbacks), public IP / geolocation, domain recon (crt.sh, DNS), Whois, abuse DNSBLs. Router audit talks only to the device you name over SSH/Telnet. Scanning, ARP, CDP/LLDP, RDP, hashing, and OpenSpeedTest LAN stay local.
- Run only on hardware and networks you are authorized to administer. Do not expose the dashboard beyond loopback unless you add your own authentication.

## Updating

```bash
docker pull sajadprp/nettoolbox:latest
docker rm -f nettoolbox
docker run -d \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --name nettoolbox \
  sajadprp/nettoolbox:latest
```

Treat container state as disposable unless you mount your own volumes.

## Linux / Windows / macOS

Linux is the most predictable for discovery because Docker uses the host network namespace.

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

On Windows and macOS, use Docker Desktop. Host-network and raw sockets often run inside a VM, so ARP/CDP/WiFi may not see the physical NIC the way they do on Linux. PowerShell example:

```powershell
docker pull sajadprp/nettoolbox:latest
docker run -d `
  --restart unless-stopped `
  --net=host `
  --cap-add=NET_ADMIN `
  --cap-add=NET_RAW `
  --name nettoolbox `
  sajadprp/nettoolbox:latest
```

## Docker Hub

**https://hub.docker.com/r/sajadprp/nettoolbox**

```text
sajadprp/nettoolbox:latest
sajadprp/nettoolbox:v2
sajadprp/nettoolbox:v2.4.0
```

## How it compares

| | NetToolbox | [NETworkManager](https://github.com/BornToBeRoot/NETworkManager) | Angry IP Scanner | Fing |
|---|---|---|---|---|
| Platform | Any (Docker) | Windows only | Cross-platform | Mobile + desktop |
| Interface | Browser | Native WPF | Native app | Native app |
| Install | One container | .NET/WPF | Java | App install |
| SSH/Telnet | ✅ in-browser | ✅ | ❌ | ❌ |
| RDP | ✅ in-browser | ✅ | ❌ | ❌ |
| Cert / header / hash | ✅ | ❌ | ❌ | ❌ |
| No account | ✅ | ✅ | ✅ | Partial |

NetToolbox is a portable field kit, not a replacement for a full Windows admin suite.

## Tech stack

Python/Flask calling `nmap`, `arp-scan`, `tshark`, `dig`, `openssl`, `iw`, `traceroute`, `curl`. LAN speed test: [OpenSpeedTest](https://github.com/openspeedtest/Speed-Test) (MIT) via nginx on `:3000`. Frontend: one HTML/CSS/JS file, no CDN. Terminal: [ttyd](https://github.com/tsl0922/ttyd). RDP: [FreeRDP](https://github.com/FreeRDP/FreeRDP) + [noVNC](https://novnc.com). QR: [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT), bundled in `static/qrcode.js`.

## License

MIT — see [LICENSE](LICENSE).

---

ممنون میشم نظرتون رو بدونم.

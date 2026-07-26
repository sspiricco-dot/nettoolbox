import json
import re
import socket
import subprocess
import time
import urllib.parse
import xml.etree.ElementTree as ET

from flask import Flask, Response, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")

IFACE_RE = re.compile(r"^[a-zA-Z0-9_.@-]{1,15}$")
SUBNET_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
PORTS_RE = re.compile(r"^[0-9,\-]{1,200}$")
HOST_RE = re.compile(r"^(?!-)[a-zA-Z0-9.-]{1,253}$")

EXCLUDED_IFACE_PREFIXES = ("lo", "docker", "br-", "veth")


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/interfaces")
def interfaces():
    out = subprocess.run(
        ["ip", "-brief", "addr"], capture_output=True, text=True, check=False
    ).stdout
    result = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        name, state = parts[0], parts[1] if len(parts) > 1 else ""
        if name.startswith(EXCLUDED_IFACE_PREFIXES):
            continue
        addrs = parts[2:]
        result.append({"name": name, "state": state, "addrs": addrs})
    return jsonify(result)


@app.route("/api/discover", methods=["POST"])
def discover():
    subnet = (request.json or {}).get("subnet", "")
    if not SUBNET_RE.match(subnet):
        return jsonify({"error": "invalid subnet, expected e.g. 192.168.1.0/24"}), 400

    proc = subprocess.run(
        ["nmap", "-sn", "-oX", "-", subnet],
        capture_output=True,
        text=True,
        timeout=120,
    )
    hosts = []
    try:
        root = ET.fromstring(proc.stdout)
        for host in root.findall("host"):
            if host.find("status").get("state") != "up":
                continue
            entry = {"ip": None, "mac": None, "vendor": None, "hostname": None}
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    entry["ip"] = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    entry["mac"] = addr.get("addr")
                    entry["vendor"] = addr.get("vendor")
            hn = host.find("hostnames/hostname")
            if hn is not None:
                entry["hostname"] = hn.get("name")
            if entry["ip"]:
                hosts.append(entry)
    except ET.ParseError:
        return jsonify({"error": "failed to parse nmap output", "raw": proc.stderr}), 500

    return jsonify({"hosts": hosts})


@app.route("/api/portscan", methods=["POST"])
def portscan():
    body = request.json or {}
    ip = body.get("ip", "")
    ports = body.get("ports", "")
    scan_all = bool(body.get("all", False))

    if not IP_RE.match(ip):
        return jsonify({"error": "invalid ip"}), 400
    if ports and not PORTS_RE.match(ports):
        return jsonify({"error": "invalid ports, use e.g. 22,80,443 or 1-1000"}), 400

    cmd = ["nmap", "-oX", "-"]
    if scan_all:
        cmd += ["-p-"]
    elif ports:
        cmd += ["-p", ports]
    cmd.append(ip)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    result = []
    try:
        root = ET.fromstring(proc.stdout)
        for port in root.findall("host/ports/port"):
            state = port.find("state")
            service = port.find("service")
            result.append(
                {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name") if service is not None else "",
                }
            )
    except ET.ParseError:
        return jsonify({"error": "failed to parse nmap output", "raw": proc.stderr}), 500

    return jsonify({"ip": ip, "ports": result})


NEIGHBOR_PROTOCOLS = {
    "cdp": {
        "filter": "cdp",
        "fields": ["cdp.deviceid", "cdp.platform", "cdp.portid"],
    },
    "lldp": {
        "filter": "lldp",
        "fields": ["lldp.tlv.system.name", "lldp.chassis.id", "lldp.port.id"],
    },
}


@app.route("/api/neighbors", methods=["POST"])
def neighbors():
    body = request.json or {}
    iface = body.get("iface", "")
    duration = body.get("duration", 15)
    protocol = body.get("protocol", "cdp")

    if not IFACE_RE.match(iface):
        return jsonify({"error": "invalid interface"}), 400
    if protocol not in NEIGHBOR_PROTOCOLS:
        return jsonify({"error": "invalid protocol"}), 400
    try:
        duration = max(3, min(int(duration), 60))
    except (TypeError, ValueError):
        duration = 15

    spec = NEIGHBOR_PROTOCOLS[protocol]
    cmd = ["tshark", "-i", iface, "-Y", spec["filter"], "-a", f"duration:{duration}", "-T", "fields"]
    for f in spec["fields"]:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 15)

    found = []
    seen = set()
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        device_id, platform, port_id = cols[0], cols[1], cols[2]
        key = (device_id, port_id)
        if not device_id or key in seen:
            continue
        seen.add(key)
        found.append({"device_id": device_id, "platform": platform, "port_id": port_id})

    return jsonify({"iface": iface, "duration": duration, "protocol": protocol, "neighbors": found})


@app.route("/api/ping", methods=["POST"])
def ping():
    target = (request.json or {}).get("ip", "").strip()
    if not HOST_RE.match(target):
        return jsonify({"error": "invalid target"}), 400

    proc = subprocess.run(
        ["ping", "-c", "4", "-W", "1", target], capture_output=True, text=True, timeout=15
    )
    loss_match = re.search(r"([\d.]+)% packet loss", proc.stdout)
    avg_match = re.search(r"= [\d.]+/([\d.]+)/", proc.stdout)
    return jsonify(
        {
            "target": target,
            "reachable": proc.returncode == 0,
            "loss_percent": float(loss_match.group(1)) if loss_match else None,
            "avg_ms": float(avg_match.group(1)) if avg_match else None,
            "raw": proc.stdout or proc.stderr,
        }
    )


@app.route("/api/traceroute", methods=["POST"])
def traceroute():
    target = (request.json or {}).get("target", "").strip()
    if not HOST_RE.match(target):
        return jsonify({"error": "invalid target"}), 400

    proc = subprocess.run(
        ["traceroute", "-I", "-n", "-w", "2", "-m", "20", target],
        capture_output=True,
        text=True,
        timeout=60,
    )
    hops = []
    for line in proc.stdout.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if m:
            hops.append({"hop": int(m.group(1)), "detail": m.group(2).strip()})
    return jsonify({"target": target, "hops": hops})


@app.route("/api/whatismyip")
def whatismyip():
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "8", "https://ipinfo.io/json"],
            capture_output=True,
            text=True,
            timeout=12,
        )
        data = json.loads(proc.stdout)
    except Exception:
        return jsonify({"error": "could not reach ipinfo.io (check internet connection)"}), 502
    return jsonify(data)


@app.route("/api/domain", methods=["POST"])
def domain_recon():
    domain = (request.json or {}).get("domain", "").strip().lower()
    if not HOST_RE.match(domain) or "." not in domain:
        return jsonify({"error": "invalid domain"}), 400

    dig_proc = subprocess.run(
        ["dig", "+short", "A", domain], capture_output=True, text=True, timeout=10
    )
    ips = [line.strip() for line in dig_proc.stdout.splitlines() if IP_RE.match(line.strip())]

    subdomains = set()
    crt_error = None
    try:
        query = urllib.parse.quote(f"%.{domain}")
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "15", f"https://crt.sh/?q={query}&output=json"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        entries = json.loads(proc.stdout)
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(domain) and "*" not in name:
                    subdomains.add(name)
    except Exception:
        crt_error = "crt.sh unreachable or no internet connection"

    return jsonify(
        {
            "domain": domain,
            "ips": ips,
            "subdomains": sorted(subdomains)[:300],
            "crt_error": crt_error,
        }
    )


DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


@app.route("/api/dns", methods=["POST"])
def dns_lookup():
    domain = (request.json or {}).get("domain", "").strip().lower()
    if not HOST_RE.match(domain):
        return jsonify({"error": "invalid domain"}), 400

    records = {}
    for rtype in DNS_RECORD_TYPES:
        proc = subprocess.run(
            ["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=8
        )
        values = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if values:
            records[rtype] = values

    return jsonify({"domain": domain, "records": records})


@app.route("/api/ping/stream")
def ping_stream():
    target = request.args.get("target", "").strip()
    if not HOST_RE.match(target):
        return jsonify({"error": "invalid target"}), 400

    def generate():
        proc = subprocess.Popen(
            ["ping", "-i", "1", "-c", "120", target],
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            for line in proc.stdout:
                m = re.search(r"icmp_seq=(\d+).*?time=([\d.]+)", line)
                if m:
                    payload = {"seq": int(m.group(1)), "rtt": float(m.group(2))}
                    yield f"data: {json.dumps(payload)}\n\n"
                elif "icmp_seq=" in line:
                    m2 = re.search(r"icmp_seq=(\d+)", line)
                    if m2:
                        yield f"data: {json.dumps({'seq': int(m2.group(1)), 'rtt': None})}\n\n"
        finally:
            proc.terminate()

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/wifi/interfaces")
def wifi_interfaces():
    proc = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=8)
    names = re.findall(r"Interface\s+(\S+)", proc.stdout)
    return jsonify(names)


@app.route("/api/wifi/scan", methods=["POST"])
def wifi_scan():
    iface = (request.json or {}).get("iface", "")
    if not IFACE_RE.match(iface):
        return jsonify({"error": "invalid interface"}), 400

    proc = subprocess.run(
        ["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or "scan failed (interface may not support scanning)"
        return jsonify({"error": msg}), 500

    networks = []
    current = None
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if line.startswith("BSS "):
            if current:
                networks.append(current)
            current = {"bssid": line.split()[1].split("(")[0], "ssid": None, "signal": None, "freq": None}
        elif current is None:
            continue
        elif line.startswith("freq:"):
            current["freq"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            current["signal"] = line.split(":", 1)[1].strip()
        elif line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
    if current:
        networks.append(current)

    networks.sort(key=lambda n: float(n["signal"].split()[0]) if n["signal"] else -999, reverse=True)
    return jsonify({"networks": networks})


@app.route("/api/speedtest", methods=["POST"])
def speedtest():
    try:
        dl = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}",
             "https://speed.cloudflare.com/__down?bytes=25000000"],
            capture_output=True, text=True, timeout=30,
        )
        download_mbps = round(float(dl.stdout.strip() or 0) * 8 / 1_000_000, 2)

        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/tmp/speedtest_upload.bin", "bs=1M", "count=5"],
            capture_output=True, timeout=15,
        )
        ul = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{speed_upload}",
             "-X", "POST", "--data-binary", "@/tmp/speedtest_upload.bin",
             "https://speed.cloudflare.com/__up"],
            capture_output=True, text=True, timeout=30,
        )
        upload_mbps = round(float(ul.stdout.strip() or 0) * 8 / 1_000_000, 2)

        pg = subprocess.run(
            ["ping", "-c", "4", "-W", "1", "1.1.1.1"], capture_output=True, text=True, timeout=10
        )
        avg_match = re.search(r"= [\d.]+/([\d.]+)/", pg.stdout)
        ping_ms = float(avg_match.group(1)) if avg_match else None
    except Exception:
        return jsonify({"error": "speed test failed (check internet connection)"}), 502

    return jsonify({"download_mbps": download_mbps, "upload_mbps": upload_mbps, "ping_ms": ping_ms})


@app.route("/api/tls", methods=["POST"])
def tls_check():
    body = request.json or {}
    domain = body.get("domain", "").strip().lower()
    port = body.get("port", 443)

    if not HOST_RE.match(domain):
        return jsonify({"error": "invalid domain"}), 400
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 443
    if not (1 <= port <= 65535):
        return jsonify({"error": "invalid port"}), 400

    conn = subprocess.run(
        ["openssl", "s_client", "-connect", f"{domain}:{port}", "-servername", domain],
        input="", capture_output=True, text=True, timeout=15,
    )
    output = conn.stdout + conn.stderr

    verify_match = re.search(r"Verify return code: (\d+) \(([^)]+)\)", output)
    verified = bool(verify_match) and verify_match.group(1) == "0"
    verify_message = verify_match.group(2) if verify_match else None

    cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
    if not cert_match:
        return jsonify({"error": "could not retrieve certificate (connection or handshake failed)"}), 502

    x509 = subprocess.run(
        ["openssl", "x509", "-noout", "-dates", "-issuer", "-subject", "-fingerprint", "-sha256"],
        input=cert_match.group(0), capture_output=True, text=True, timeout=10,
    )
    fields = {}
    for line in x509.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()

    days_left = None
    not_after = fields.get("notAfter")
    if not_after:
        try:
            import datetime
            normalized = re.sub(r"\s+", " ", not_after).strip()
            exp = datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.datetime.utcnow()).days
        except ValueError:
            pass

    return jsonify(
        {
            "domain": domain,
            "port": port,
            "verified": verified,
            "verify_message": verify_message,
            "issuer": fields.get("issuer"),
            "subject": fields.get("subject"),
            "not_before": fields.get("notBefore"),
            "not_after": not_after,
            "days_left": days_left,
            "fingerprint_sha256": fields.get("sha256 Fingerprint"),
        }
    )


SECURITY_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


@app.route("/api/headers", methods=["POST"])
def http_headers():
    url = (request.json or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "invalid url"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host_part = url.split("://", 1)[1].split("/")[0].split(":")[0]
    if not HOST_RE.match(host_part):
        return jsonify({"error": "invalid url"}), 400

    proc = subprocess.run(
        ["curl", "-sI", "-m", "10", "-L", "--max-redirs", "5", url],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return jsonify({"error": "request failed"}), 502

    blocks = [b for b in proc.stdout.split("\r\n\r\n") if b.strip()]
    last_block = blocks[-1] if blocks else proc.stdout
    lines = [line for line in last_block.splitlines() if line.strip()]
    status_line = lines[0] if lines else ""

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    lower_headers = {k.lower(): v for k, v in headers.items()}
    security = {name: lower_headers.get(name) for name in SECURITY_HEADER_NAMES}

    return jsonify({"url": url, "status": status_line, "headers": headers, "security": security})


@app.route("/api/wol", methods=["POST"])
def wake_on_lan():
    body = request.json or {}
    mac = body.get("mac", "").strip()
    broadcast = body.get("broadcast", "255.255.255.255").strip()

    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(mac_clean) != 12:
        return jsonify({"error": "invalid MAC address"}), 400
    if not IP_RE.match(broadcast):
        return jsonify({"error": "invalid broadcast address"}), 400

    mac_bytes = bytes.fromhex(mac_clean)
    packet = b"\xff" * 6 + mac_bytes * 16

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast, 9))
    finally:
        sock.close()

    return jsonify({"sent": True, "mac": mac_clean.upper(), "broadcast": broadcast})


@app.route("/api/arp")
def arp_table():
    proc = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=8)
    entries = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        entry = {"ip": parts[0], "iface": None, "mac": None, "state": parts[-1]}
        if "dev" in parts:
            entry["iface"] = parts[parts.index("dev") + 1]
        if "lladdr" in parts:
            entry["mac"] = parts[parts.index("lladdr") + 1]
        entries.append(entry)
    return jsonify({"entries": entries})


def _read_iface_bytes(iface):
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            if name.strip() == iface:
                fields = rest.split()
                return int(fields[0]), int(fields[8])
    return None


@app.route("/api/bandwidth/stream")
def bandwidth_stream():
    iface = request.args.get("iface", "")
    if not IFACE_RE.match(iface):
        return jsonify({"error": "invalid interface"}), 400

    def generate():
        prev = _read_iface_bytes(iface)
        prev_time = time.time()
        for _ in range(180):
            time.sleep(1)
            cur = _read_iface_bytes(iface)
            now = time.time()
            if prev and cur:
                dt = now - prev_time
                rx_bps = (cur[0] - prev[0]) * 8 / dt if dt > 0 else 0
                tx_bps = (cur[1] - prev[1]) * 8 / dt if dt > 0 else 0
                yield f"data: {json.dumps({'rx_bps': rx_bps, 'tx_bps': tx_bps})}\n\n"
            prev, prev_time = cur, now

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/geoip", methods=["POST"])
def geoip():
    ip = (request.json or {}).get("ip", "").strip()
    if not IP_RE.match(ip):
        return jsonify({"error": "invalid ip"}), 400
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "8", f"https://ipinfo.io/{ip}/json"],
            capture_output=True, text=True, timeout=12,
        )
        data = json.loads(proc.stdout)
    except Exception:
        return jsonify({"error": "could not reach ipinfo.io (check internet connection)"}), 502
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8642, threaded=True)

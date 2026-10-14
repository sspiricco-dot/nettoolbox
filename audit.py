"""Read-only MikroTik / Cisco security audit over SSH or Telnet."""
from __future__ import annotations

import os
import re
import socket
import subprocess

RISKY_MT_SERVICES = {
    "api": "high",
    "api-ssl": "medium",
    "ftp": "high",
    "www": "medium",
    "www-ssl": "medium",
    "telnet": "high",
    "winbox": "medium",
}

MT_CMDS = (
    "/system identity print",
    "/system resource print",
    "/system clock print",
    "/system ntp client print",
    "/interface print",
    "/ip address print",
    "/ip service print",
    "/ip firewall nat print",
    "/ip firewall filter print",
    "/tool mac-server mac-winbox print",
    "/ip neighbor discovery-settings print",
    "/tool bandwidth-server print",
    "/ip upnp print",
    "/ip socks print",
    "/ip proxy print",
    "/user print",
)

CISCO_CMDS = (
    "terminal length 0",
    "show version",
    "show clock",
    "show ntp status",
    "show ip interface brief",
    "show cdp",
    "show snmp community",
    "show ip nat translations verbose",
    "show running-config",
)


def _redact(text: str) -> str:
    out = text or ""
    out = re.sub(r"(?i)password[=:\s]+\S+", "password=***", out)
    out = re.sub(r"(?i)secret[=:\s]+\S+", "secret=***", out)
    return out


def _kv(text: str) -> dict:
    found = {}
    for match in re.finditer(r"(?m)^\s*([A-Za-z0-9_./ -]+?)\s*:\s*(.+?)\s*$", text or ""):
        key = match.group(1).strip().lower().replace(" ", "-")
        found[key] = match.group(2).strip()
    return found


def _section(raw: dict, cmd: str) -> str:
    return raw.get(cmd) or ""


def detect_vendor(blob: str) -> str:
    low = (blob or "").lower()
    if "routeros" in low or "/system" in low or "mikrotik" in low:
        return "mikrotik"
    if "cisco ios" in low or "cisco nx-os" in low or "technical support: http://www.cisco.com" in low:
        return "cisco"
    if "ios-xe" in low or "ios xe" in low:
        return "cisco"
    return ""


def _ssh_run(host: str, user: str, password: str, port: int, script: str, timeout: int = 45) -> tuple[str, str, int]:
    ssh = [
        "sshpass",
        "-e",
        "ssh",
        "-T",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=/tmp/nettoolbox-known-hosts",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "ConnectTimeout=8",
        "-p",
        str(port),
        f"{user}@{host}",
    ]
    env = os.environ.copy()
    env["SSHPASS"] = password
    try:
        proc = subprocess.run(
            ssh,
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "", "remote run timed out", 124
    except OSError as exc:
        return "", str(exc), 1
    return proc.stdout or "", proc.stderr or "", proc.returncode


def _sock_read_until(sock: socket.socket, needles: tuple[bytes, ...], timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return buf
        if not chunk:
            return buf
        buf += chunk
        low = buf.lower()
        if any(n.lower() in low for n in needles):
            return buf
        if len(buf) > 200000:
            return buf


def _telnet_run(host: str, user: str, password: str, port: int, commands: list[str], timeout: int = 20) -> tuple[str, str, int]:
    try:
        sock = socket.create_connection((host, port), timeout=min(timeout, 12))
    except OSError as exc:
        return "", str(exc), 1
    try:
        sock.settimeout(10)
        banner = _sock_read_until(sock, (b":", b">", b"#"), 8)
        text_banner = banner.decode("utf-8", "replace").lower()
        if "login" in text_banner or "user" in text_banner or "name" in text_banner:
            sock.sendall(user.encode("utf-8", "replace") + b"\n")
            _sock_read_until(sock, (b":",), 8)
        sock.sendall(password.encode("utf-8", "replace") + b"\n")
        chunks = [banner, _sock_read_until(sock, (b"#", b">"), 8)]
        for cmd in commands:
            if not cmd.strip():
                continue
            sock.sendall(cmd.encode("utf-8", "replace") + b"\n")
            chunks.append(_sock_read_until(sock, (b"#", b">"), 10))
        sock.sendall(b"quit\n")
        try:
            chunks.append(sock.recv(4096))
        except OSError:
            pass
        text = b"".join(chunks).decode("utf-8", "replace")
        return text, "", 0
    except Exception as exc:
        return "", str(exc), 1
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _mt_script() -> str:
    lines = []
    for cmd in MT_CMDS + ("/iot bluetooth print",):
        lines.append(f':put "===NT:{cmd}==="')
        lines.append(cmd)
    return "\n".join(lines) + "\n"


def _cisco_script() -> str:
    lines = ["terminal length 0"]
    for cmd in CISCO_CMDS:
        if cmd == "terminal length 0":
            continue
        lines.append(f"! ===NT:{cmd}===")
        lines.append(cmd)
    return "\n".join(lines) + "\n"


def _split_marked(stdout: str) -> dict:
    parts = {}
    current = "_preamble"
    buf = []
    for line in (stdout or "").splitlines():
        mark = re.search(r"===NT:(.*?)===", line)
        if mark:
            parts[current] = "\n".join(buf).strip()
            current = mark.group(1).strip()
            buf = []
            continue
        buf.append(line)
    parts[current] = "\n".join(buf).strip()
    return parts


def _split_cisco_raw(stdout: str) -> dict:
    parts = _split_marked(stdout)
    if "show running-config" not in parts and (stdout or "").strip():
        parts["show running-config"] = stdout
        parts.setdefault("show version", stdout)
    return parts


def _finding(fid: str, severity: str, title: str, detail: str, fix: str = "") -> dict:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


def _denied(text: str) -> bool:
    low = (text or "").lower()
    return any(
        needle in low
        for needle in (
            "permission denied",
            "not enough permissions",
            "bad command name",
            "no such command",
            "invalid command",
            "authorization failed",
            "% error: ",
            "command authorization failed",
        )
    )


def _mt_services(text: str) -> list[dict]:
    rows = []
    for line in (text or "").splitlines():
        name = re.search(r'name="?([^"\s]+)"?', line)
        if not name or "port=" not in line:
            continue
        port = re.search(r"port=(\d+)", line)
        addr = re.search(r'address="?([^"\s]*)"?', line)
        address = (addr.group(1) if addr else "").strip()
        if address in ("", '""', "*"):
            address = ""
        disabled = bool(re.match(r"^\s*\d+\s+X\b", line)) or "disabled=yes" in line.lower()
        rows.append(
            {
                "name": name.group(1).lower(),
                "port": port.group(1) if port else "",
                "address": address,
                "disabled": disabled,
            }
        )
    return rows


def _mt_nat_unrestricted(text: str) -> list[str]:
    hits = []
    blocks = re.split(r"\n(?=\s*\d+\s)", text or "")
    for block in blocks:
        if "action=dst-nat" not in block and "action=netmap" not in block and "action=redirect" not in block:
            if "dst-nat" not in block and "redirect" not in block:
                continue
        if "chain=srcnat" in block or "action=masquerade" in block or "action=src-nat" in block:
            continue
        if re.search(r"\bX\b|disabled=yes", block) and "dst-nat" in block:
            continue
        if "src-address=" in block or "src-address-list=" in block:
            continue
        dst_port = re.search(r"dst-port=([0-9,-]+)", block)
        to_addr = re.search(r"to-addresses=([0-9.]+)", block)
        label = []
        if dst_port:
            label.append(":" + dst_port.group(1))
        if to_addr:
            label.append("-> " + to_addr.group(1))
        hits.append(" ".join(label) or block.strip()[:80])
    return hits[:12]


def _flag_enabled(text: str, enabled_true: tuple[str, ...] = ("enabled: yes", "enabled=yes")) -> bool | None:
    low = (text or "").lower()
    if _denied(text) or not low.strip():
        return None
    if any(tok in low for tok in enabled_true):
        return True
    if "enabled: no" in low or "enabled=no" in low:
        return False
    return None


def audit_mikrotik(raw: dict) -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    ident = _kv(_section(raw, "/system identity print"))
    res = _kv(_section(raw, "/system resource print"))
    clock = _kv(_section(raw, "/system clock print"))
    ntp = _section(raw, "/system ntp client print")
    ifaces = _section(raw, "/interface print")
    up_ifaces = re.findall(r"(?m)^\s*\d+\s+R\s+\S*\s+(\S+)", ifaces)
    if not up_ifaces:
        up_ifaces = re.findall(r"(?im)^[^\n]*\bR\b[^\n]*?([A-Za-z0-9_.-]+)\s+(ether|bridge|wlan|pppoe|vlan)", ifaces)
        up_ifaces = [x[0] if isinstance(x, tuple) else x for x in up_ifaces]
    status = {
        "vendor": "mikrotik",
        "hostname": ident.get("name") or ident.get("identity") or "",
        "version": res.get("version", ""),
        "board": res.get("board-name", "") or res.get("platform", ""),
        "uptime": res.get("uptime", ""),
        "cpu": res.get("cpu-load", "") or res.get("cpu", ""),
        "memory": (res.get("free-memory", "") + (" / " + res.get("total-memory") if res.get("total-memory") else "")).strip(" /"),
        "clock": clock.get("time", "") + (" " + clock.get("date", "")).rstrip(),
        "ntp": "on" if re.search(r"(?i)enabled:\s*yes|status:\s*synchronized", ntp) else ("off" if ntp.strip() else "unknown"),
        "interfaces_up": up_ifaces[:16],
    }

    denied_cmds = [cmd for cmd, text in raw.items() if cmd.startswith("/") and _denied(text)]
    if denied_cmds:
        findings.append(
            _finding(
                "mt-permission",
                "medium",
                "دسترسی ناکافی برای بعضی دستورها",
                "یوزر read بعضی منوها را نمی‌بیند: " + ", ".join(denied_cmds[:8]),
                "",
            )
        )

    for svc in _mt_services(_section(raw, "/ip service print")):
        if svc["disabled"]:
            continue
        if svc["name"] == "ssh" and not svc["address"]:
            findings.append(
                _finding(
                    "mt-ssh-all",
                    "low",
                    "SSH روی همه آدرس‌ها گوش می‌دهد",
                    "سرویس ssh بدون available-from / address است. اگر فقط LAN لازم است محدودش کن.",
                    "/ip service set ssh address=192.168.0.0/16",
                )
            )
            continue
        sev = RISKY_MT_SERVICES.get(svc["name"])
        if not sev:
            continue
        open_all = svc["address"] in ("", "0.0.0.0/0", "0.0.0.0")
        if open_all:
            findings.append(
                _finding(
                    "mt-svc-" + svc["name"],
                    sev,
                    f"سرویس {svc['name']} باز است (پورت {svc['port'] or '?'})",
                    "بدون محدود کردن IP روی 0.0.0.0 گوش می‌دهد. از اینترنت قابل سوءاستفاده است مگر فایروال جدا آن را ببندد.",
                    f"/ip service set {svc['name']} disabled=yes",
                )
            )

    nat_hits = _mt_nat_unrestricted(_section(raw, "/ip firewall nat print"))
    for hit in nat_hits:
        findings.append(
            _finding(
                "mt-dstnat-open",
                "high",
                "فوروارد پورت بدون قفل IP",
                "dst-nat/redirect بدون src-address یا src-address-list: " + hit,
                "/ip firewall nat set [find] src-address-list=admin-wan",
            )
        )

    macw = _section(raw, "/tool mac-server mac-winbox print")
    if macw and not _denied(macw):
        allowed = re.search(r"allowed-interface-list:\s*(\S+)", macw, re.I)
        name = (allowed.group(1) if allowed else "").strip()
        if name.lower() in ("all", "none") or not name:
            if name.lower() != "none":
                findings.append(
                    _finding(
                        "mt-mac-winbox",
                        "medium",
                        "Winbox از روی مک آدرس باز است",
                        f"allowed-interface-list={name or 'all'}. از لایه ۲ می‌توان بدون IP وصل شد.",
                        "/tool mac-server mac-winbox set allowed-interface-list=none",
                    )
                )

    disc = _section(raw, "/ip neighbor discovery-settings print")
    if disc and not _denied(disc):
        dlist = re.search(r"discover-interface-list:\s*(\S+)", disc, re.I)
        val = (dlist.group(1) if dlist else "").lower()
        if val in ("all", ""):
            findings.append(
                _finding(
                    "mt-discovery",
                    "medium",
                    "دیسکاوری روی همه اینترفیس‌ها روشن است",
                    "MNDP/CDP ممکن است روی WAN هم تبلیغ شود.",
                    "/ip neighbor discovery-settings set discover-interface-list=LAN",
                )
            )

    bw = _section(raw, "/tool bandwidth-server print")
    if _flag_enabled(bw) is True:
        findings.append(
            _finding(
                "mt-btest",
                "medium",
                "Bandwidth-server (btest) روشن است",
                "هر کس به روتر برسد می‌تواند تست پهنای‌باند بزند و CPU را پر کند.",
                "/tool bandwidth-server set enabled=no",
            )
        )

    upnp = _section(raw, "/ip upnp print")
    if _flag_enabled(upnp, ("enabled: yes", "allow-disable-external-interface: yes")) is True or re.search(
        r"(?i)enabled:\s*yes", upnp or ""
    ):
        findings.append(
            _finding(
                "mt-upnp",
                "high",
                "UPnP روشن است",
                "کلاینت داخلی می‌تواند پورت روی WAN باز کند.",
                "/ip upnp set enabled=no",
            )
        )

    socks = _section(raw, "/ip socks print")
    if re.search(r"(?i)enabled:\s*yes", socks or ""):
        findings.append(
            _finding(
                "mt-socks",
                "high",
                "SOCKS پروکسی روشن است",
                "اگر به اینترنت باز باشد ترافیک دیگران از روتر رد می‌شود.",
                "/ip socks set enabled=no",
            )
        )

    proxy = _section(raw, "/ip proxy print")
    if re.search(r"(?i)enabled:\s*yes", proxy or ""):
        findings.append(
            _finding(
                "mt-proxy",
                "medium",
                "HTTP proxy روشن است",
                "سرویس پروکسی میکروتیک فعال است.",
                "/ip proxy set enabled=no",
            )
        )

    filt = _section(raw, "/ip firewall filter print")
    if filt and not _denied(filt):
        has_input_drop = bool(re.search(r"(?is)chain=input.*action=drop", filt))
        has_wan_in = bool(re.search(r"(?i)in-interface(?:-list)?=.*(WAN|Internet|ether1)", filt))
        if not has_input_drop:
            findings.append(
                _finding(
                    "mt-input-filter",
                    "medium",
                    "فیلتر input ضعیف یا نامشخص",
                    "drop واضح روی chain=input دیده نشد. سرویس‌های مدیریت ممکن است از WAN برسند.",
                    "/ip firewall filter add chain=input in-interface-list=WAN action=drop",
                )
            )
        elif not has_wan_in:
            findings.append(
                _finding(
                    "mt-input-wan",
                    "low",
                    "محدودیت input روی WAN مشخص نیست",
                    "drop روی input هست اما in-interface WAN/Internet دیده نشد.",
                    "",
                )
            )

    users = _section(raw, "/user print")
    if users and not _denied(users):
        open_users = []
        for line in users.splitlines():
            if re.search(r"allowed-address=0\.0\.0\.0/0", line) or (
                "name=" in line and "allowed-address=" not in line and re.search(r"group=", line)
            ):
                uname = re.search(r'name="?([^"\s]+)"?', line)
                if uname:
                    open_users.append(uname.group(1))
        # RouterOS table format without name=
        if not open_users:
            for match in re.finditer(r"(?m)^\s*\d+\s+\S+\s+(\S+)\s+\S+", users):
                open_users.append(match.group(1))
            open_users = [u for u in open_users if u.lower() not in ("name", "group")]
            if open_users and "allowed-address" not in users.lower():
                findings.append(
                    _finding(
                        "mt-user-addr",
                        "low",
                        "یوزرها بدون allowed-address",
                        "از هر IP می‌توان با این حساب‌ها لاگین کرد: " + ", ".join(open_users[:8]),
                        '/user set [find] address=192.168.0.0/16',
                    )
                )

    bt = raw.get("/iot bluetooth print") or ""
    if bt and not _denied(bt) and re.search(r"(?i)enabled:\s*yes|running", bt):
        findings.append(
            _finding(
                "mt-bluetooth",
                "low",
                "Bluetooth روشن است",
                "ماژول bluetooth/iot فعال به نظر می‌رسد.",
                "/iot bluetooth set disabled=yes",
            )
        )

    if not any(f["severity"] == "high" for f in findings):
        findings.append(
            _finding("mt-ok-high", "ok", "یافته بحرانی high نبود", "سرویس API/FTP/telnet بازِ بدون قفل یا dst-nat آزاد دیده نشد، یا دسترسی کامل نبود.", "")
        )
    return status, findings


def _cisco_hostname(cfg: str, version: str) -> str:
    match = re.search(r"(?im)^hostname\s+(\S+)", cfg or "")
    if match:
        return match.group(1)
    match = re.search(r"(?im)^(\S+)\s+uptime is", version or "")
    return match.group(1) if match else ""


def audit_cisco(raw: dict) -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    ver = _section(raw, "show version") or _section(raw, "_preamble")
    cfg = _section(raw, "show running-config")
    brief = _section(raw, "show ip interface brief")
    ntp = _section(raw, "show ntp status")
    clock = _section(raw, "show clock")
    cdp = _section(raw, "show cdp")
    snmp = _section(raw, "show snmp community")
    nat = _section(raw, "show ip nat translations verbose")

    ver_ios = re.search(r"Version\s+([^\s,]+)", ver or "")
    model = re.search(r"(?im)^cisco\s+(\S+)", ver or "")
    uptime = re.search(r"uptime is\s+(.+)", ver or "", re.I)
    cpu = re.search(r"CPU utilization[^\n]*?(\d+)\s*%", ver or "", re.I)
    up_ifaces = re.findall(r"(?im)^(\S+)\s+\S+\s+\S+\s+\S+\s+up\s+up", brief or "")

    status = {
        "vendor": "cisco",
        "hostname": _cisco_hostname(cfg, ver),
        "version": ver_ios.group(1) if ver_ios else "",
        "board": model.group(1) if model else "",
        "uptime": (uptime.group(1).strip() if uptime else ""),
        "cpu": (cpu.group(1) + "%" if cpu else ""),
        "memory": "",
        "clock": (clock or "").strip().split("\n")[0][:80],
        "ntp": "on" if re.search(r"(?i)clock is synchronized", ntp or "") else ("off" if ntp.strip() else "unknown"),
        "interfaces_up": up_ifaces[:16],
    }

    if _denied(cfg) or (cfg and "authorization failed" in cfg.lower()):
        findings.append(
            _finding(
                "cisco-priv",
                "medium",
                "privilege برای running-config کافی نیست",
                "بدون enable/سطح ۱۵ ممیزی کانفیگ ناقص است. یافته‌ها فقط از showهای موجود است.",
                "enable",
            )
        )

    blob = "\n".join([cfg, ver, snmp, nat, cdp])
    if re.search(r"(?im)^enable password\b", cfg or blob):
        findings.append(
            _finding(
                "cisco-enable-password",
                "high",
                "enable password به‌جای enable secret",
                "رمز enable از نوع password است (ضعیف / type 7). باید enable secret باشد.",
                "enable secret",
            )
        )
    if cfg and not re.search(r"(?im)^enable secret\b", cfg):
        if not _denied(cfg) and "hostname" in cfg.lower():
            findings.append(
                _finding(
                    "cisco-no-enable-secret",
                    "high",
                    "enable secret تنظیم نشده",
                    "در running-config enable secret دیده نشد.",
                    "enable secret",
                )
            )

    weak_users = re.findall(r"(?im)^username\s+(\S+)\s+.*\bpassword\b", cfg or "")
    if weak_users:
        findings.append(
            _finding(
                "cisco-user-password",
                "high",
                "یوزر با password به‌جای secret",
                "حساب‌ها با دستور password (type 0/7): " + ", ".join(weak_users[:8]),
                "username <user> secret",
            )
        )

    if re.search(r"(?im)^service password-encryption\s*$", cfg or "") and not re.search(
        r"(?im)^enable secret\b", cfg or ""
    ):
        findings.append(
            _finding(
                "cisco-type7",
                "medium",
                "فقط service password-encryption",
                "type 7 برگشت‌پذیر است و جایگزین enable secret نیست.",
                "enable secret",
            )
        )

    vty = re.search(r"(?is)^line vty\s+0.*?(?=^line |\Z)", cfg or "", re.M)
    vty_text = vty.group(0) if vty else ""
    if vty_text:
        if re.search(r"(?i)transport input.*telnet", vty_text) or not re.search(r"(?i)transport input\s+ssh\b", vty_text):
            if re.search(r"(?i)transport input\s+all", vty_text) or "telnet" in vty_text.lower() or not re.search(
                r"transport input", vty_text
            ):
                findings.append(
                    _finding(
                        "cisco-vty-telnet",
                        "high",
                        "VTY تلنت یا بدون محدود به SSH",
                        "line vty تلنت را می‌پذیرد یا transport input ssh ندارد.",
                        "line vty 0 4\n transport input ssh",
                    )
                )
        if not re.search(r"(?i)access-class\s+\S+", vty_text):
            findings.append(
                _finding(
                    "cisco-vty-acl",
                    "high",
                    "VTY بدون access-class",
                    "ورود مدیریت از هر IP ممکن است.",
                    "line vty 0 4\n access-class MGMT in",
                )
            )

    if re.search(r"(?im)^ip http server\b", cfg or blob):
        if not re.search(r"(?im)^ip http access-class\b", cfg or ""):
            findings.append(
                _finding(
                    "cisco-http",
                    "medium",
                    "HTTP مدیریت بدون ACL",
                    "ip http server روشن است و access-class دیده نشد.",
                    "no ip http server",
                )
            )

    if re.search(r"(?i)cdp is enabled|Sending CDP packets", cdp or "") or re.search(
        r"(?im)^cdp run\b", cfg or ""
    ):
        findings.append(
            _finding(
                "cisco-cdp",
                "low",
                "CDP روشن است",
                "روی لبه اینترنت CDP توپولوژی را لو می‌دهد.",
                "no cdp run",
            )
        )

    if re.search(r"(?i)\b(public|private)\b", snmp or "") or re.search(
        r"(?im)^snmp-server community\s+(public|private)\b", cfg or ""
    ):
        findings.append(
            _finding(
                "cisco-snmp",
                "high",
                "SNMP community پیش‌فرض",
                "public یا private در SNMP دیده شد.",
                "no snmp-server community public",
            )
        )

    if re.search(r"(?im)^ip nat inside source static\b", cfg or "") or re.search(
        r"(?i)tcp\s+\d+\s+.*:.*\d+", nat or ""
    ):
        if not re.search(r"(?im)^ip nat.*access-list", cfg or ""):
            findings.append(
                _finding(
                    "cisco-nat-static",
                    "medium",
                    "NAT استاتیک / فوروارد پورت",
                    "ip nat inside source static یا ترجمه پورت بدون ACL مشخص.",
                    "ip nat inside source static ... extendable  + ACL",
                )
            )

    if not any(f["severity"] == "high" for f in findings):
        findings.append(
            _finding("cisco-ok-high", "ok", "یافته بحرانی high نبود", "رمز واضح، VTY باز، یا SNMP public در خروجی موجود دیده نشد.", "")
        )
    return status, findings


def run_audit(
    host: str,
    user: str,
    password: str,
    port: int,
    proto: str,
    vendor: str,
) -> dict:
    proto = (proto or "ssh").lower()
    vendor = (vendor or "auto").lower()
    if proto not in ("ssh", "telnet"):
        return {"error": "protocol must be ssh or telnet"}
    if vendor not in ("auto", "mikrotik", "cisco"):
        return {"error": "vendor must be auto, mikrotik, or cisco"}

    guess_script = "/system resource print\nshow version\n"
    stdout = stderr = ""
    code = 0
    if proto == "ssh":
        if vendor == "mikrotik":
            stdout, stderr, code = _ssh_run(host, user, password, port, _mt_script())
        elif vendor == "cisco":
            stdout, stderr, code = _ssh_run(host, user, password, port, _cisco_script())
        else:
            stdout, stderr, code = _ssh_run(host, user, password, port, guess_script, timeout=20)
            vendor = detect_vendor(stdout + stderr) or vendor
            if vendor == "mikrotik":
                stdout, stderr, code = _ssh_run(host, user, password, port, _mt_script())
            elif vendor == "cisco":
                stdout, stderr, code = _ssh_run(host, user, password, port, _cisco_script())
    else:
        if vendor == "auto":
            stdout, stderr, code = _telnet_run(host, user, password, port, ["show version", "/system resource print"])
            vendor = detect_vendor(stdout + stderr) or "cisco"
        script = _mt_script() if vendor == "mikrotik" else _cisco_script()
        stdout, stderr, code = _telnet_run(host, user, password, port, script.splitlines())

    blob = _redact((stdout or "") + ("\n" + stderr if stderr else ""))
    if code != 0 and not (stdout or "").strip():
        err = (stderr or "connection failed").strip()
        if "timed out" in err.lower() or code == 124:
            return {"error": "remote run timed out"}
        if "permission denied" in (stdout + stderr).lower():
            return {"error": "authentication failed"}
        return {"error": err[:400] or "connection failed"}

    if vendor == "auto":
        vendor = detect_vendor(blob) or ""
    if vendor not in ("mikrotik", "cisco"):
        return {"error": "could not detect vendor — pick MikroTik or Cisco", "raw": blob[-4000:]}

    raw = _split_marked(stdout) if vendor == "mikrotik" else _split_cisco_raw(stdout)
    if vendor == "mikrotik":
        status, findings = audit_mikrotik(raw)
    else:
        status, findings = audit_cisco(raw)

    rank = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    findings.sort(key=lambda f: rank.get(f.get("severity"), 9))
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ("high", "medium", "low", "ok")}
    return {
        "vendor": vendor,
        "proto": proto,
        "host": host,
        "status": status,
        "findings": findings,
        "counts": counts,
        "raw": blob[-20000:],
    }

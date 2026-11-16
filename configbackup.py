"""Config backup & diff: pull running configs over SSH/Telnet, keep versions, show what changed.

Devices (no passwords) live in CONFIG_DIR/devices.json; each backup is CONFIG_DIR/<id>/<ts>.cfg.
A new version is stored only when the config really changed (volatile lines such as timestamps
are ignored for that comparison).
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import socket
import subprocess
import threading
import time

CONFIG_DIR = os.environ.get("NETTOOLBOX_CONFIG_DIR", "/data/configs")
KEY_DIR = os.environ.get("NETTOOLBOX_SSH_DIR", "/data/ssh-keys")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VER_RE = re.compile(r"^\d{8}-\d{6}$")

# vendor: (label, ssh mode, commands, telnet commands)
#   "exec": one command on the SSH exec channel (clean output, no prompts)
#   "shell": commands piped to an interactive shell; output trimmed between markers
VENDORS = {
    "cisco_ios": ("Cisco IOS / IOS-XE", "exec", ["show running-config"], ["terminal length 0", "show running-config"]),
    "cisco_nxos": ("Cisco NX-OS", "exec", ["show running-config"], ["terminal length 0", "show running-config"]),
    "cisco_asa": ("Cisco ASA", "shell", ["terminal pager 0", "show running-config"], ["terminal pager 0", "show running-config"]),
    "mikrotik": ("MikroTik RouterOS", "exec", ["/export"], ["/export"]),
    "juniper": ("Juniper Junos", "exec", ["show configuration | display set | no-more"], ["show configuration | display set | no-more"]),
    "huawei": ("Huawei VRP", "shell", ["screen-length 0 temporary", "display current-configuration"], ["screen-length 0 temporary", "display current-configuration"]),
    "hp_comware": ("HPE Comware / H3C", "shell", ["screen-length disable", "display current-configuration"], ["screen-length disable", "display current-configuration"]),
    "aruba": ("HPE Aruba / ProCurve", "shell", ["no page", "show running-config"], ["no page", "show running-config"]),
    "fortinet": ("Fortinet FortiGate", "exec", ["show"], ["show"]),
    "linux": ("Linux / custom command", "exec", ["cat /etc/network/interfaces"], ["cat /etc/network/interfaces"]),
}

VOLATILE = [
    re.compile(r"^! (Last configuration change|NVRAM config last updated) .*$", re.M),
    re.compile(r"^Building configuration\.\.\.\s*$", re.M),
    re.compile(r"^Current configuration\s*:.*$", re.M),
    re.compile(r"^\s*ntp clock-period \d+.*$", re.M),
    re.compile(r"^# \w{3}/\d{2}/\d{4} \d\d:\d\d:\d\d by RouterOS.*$", re.M),
    re.compile(r"^# \d{4}-\d\d-\d\d \d\d:\d\d:\d\d by RouterOS.*$", re.M),
    re.compile(r"^## Last commit: .*$", re.M),
    re.compile(r"^Time: .*$", re.M),
    re.compile(r"^\s*$", re.M),
]

_lock = threading.Lock()


class ConfigError(Exception):
    pass


def _own(path):
    try:
        uid = int(os.environ.get("NETTOOLBOX_HOST_UID", ""))
        gid = int(os.environ.get("NETTOOLBOX_HOST_GID", "") or uid)
        os.chown(path, uid, gid)
    except (ValueError, OSError):
        pass


def _dir(*parts):
    path = os.path.join(CONFIG_DIR, *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    _own(path)
    return path


def persistent():
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            points = {line.split()[4] for line in fh if len(line.split()) > 4}
    except OSError:
        return False
    path = os.path.realpath(CONFIG_DIR)
    while path and path != "/":
        if path in points:
            return True
        path = os.path.dirname(path)
    return False


# ---------------------------------------------------------------- devices
def _devices_path():
    return os.path.join(_dir(), "devices.json")


def load_devices():
    try:
        with open(_devices_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_devices(devs):
    path = _devices_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(devs, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _own(path)


def _slug(text):
    s = re.sub(r"[^a-z0-9._-]+", "-", (text or "").lower()).strip("-.")[:60]
    return s or "device"


def save_device(d):
    host = (d.get("host") or "").strip()
    if not host or not re.match(r"^[A-Za-z0-9.:_-]{1,253}$", host):
        raise ConfigError("invalid host")
    vendor = d.get("vendor") or "cisco_ios"
    if vendor not in VENDORS:
        raise ConfigError("unknown vendor")
    proto = d.get("proto") or "ssh"
    if proto not in ("ssh", "telnet"):
        raise ConfigError("proto must be ssh or telnet")
    try:
        port = int(d.get("port") or (22 if proto == "ssh" else 23))
    except ValueError:
        raise ConfigError("invalid port") from None
    user = (d.get("user") or "").strip()
    if not re.match(r"^[A-Za-z0-9._@\\-]{0,64}$", user):
        raise ConfigError("invalid user")
    key = (d.get("key") or "").strip()
    if key and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", key):
        raise ConfigError("invalid key name")
    command = (d.get("command") or "").strip()[:300]
    name = (d.get("name") or host).strip()[:80]
    with _lock:
        devs = load_devices()
        did = d.get("id") or ""
        if did:
            if not ID_RE.match(did) or not any(x["id"] == did for x in devs):
                raise ConfigError("device not found")
        else:
            base = _slug(name)
            did, n = base, 2
            while any(x["id"] == did for x in devs):
                did, n = f"{base}-{n}", n + 1
        dev = {"id": did, "name": name, "host": host, "port": port, "proto": proto, "user": user,
               "vendor": vendor, "key": key, "command": command}
        devs = [x for x in devs if x["id"] != did] + [dev]
        devs.sort(key=lambda x: x["name"].lower())
        _save_devices(devs)
    return dev


def delete_device(did):
    with _lock:
        devs = load_devices()
        if not any(x["id"] == did for x in devs):
            raise ConfigError("device not found")
        _save_devices([x for x in devs if x["id"] != did])
    vdir = os.path.join(CONFIG_DIR, did)
    if ID_RE.match(did) and os.path.isdir(vdir):
        for f in os.listdir(vdir):
            os.remove(os.path.join(vdir, f))
        os.rmdir(vdir)


def _device(did):
    for d in load_devices():
        if d["id"] == did:
            return d
    raise ConfigError("device not found")


# ---------------------------------------------------------------- versions
def normalize(text):
    for rx in VOLATILE:
        text = rx.sub("", text)
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip())


def versions(did):
    vdir = os.path.join(CONFIG_DIR, did)
    if not ID_RE.match(did) or not os.path.isdir(vdir):
        return []
    out = []
    for f in sorted(os.listdir(vdir), reverse=True):
        if f.endswith(".json") and VER_RE.match(f[:-5]):
            try:
                with open(os.path.join(vdir, f), encoding="utf-8") as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                pass
    return out


def read_version(did, ver):
    if not ID_RE.match(did or "") or not VER_RE.match(ver or ""):
        raise ConfigError("invalid version")
    path = os.path.join(CONFIG_DIR, did, ver + ".cfg")
    if not os.path.isfile(path):
        raise ConfigError("version not found")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def diff(did, a, b):
    old, new = read_version(did, a), read_version(did, b)
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), f"{a}", f"{b}", n=3, lineterm=""))
    added = sum(1 for x in lines if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))
    return {"a": a, "b": b, "added": added, "removed": removed, "lines": lines[:5000]}


def overview():
    out = []
    for d in load_devices():
        vs = versions(d["id"])
        out.append({**d, "versions": len(vs), "last": vs[0] if vs else None})
    return out


# ---------------------------------------------------------------- fetching
SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/tmp/nettoolbox-known-hosts",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10",
            # old switches still speak only these
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc"]


def _ssh(dev, password, passphrase, remote_cmd=None, stdin=None, timeout=90):
    target = f"{dev['user']}@{dev['host']}" if dev["user"] else dev["host"]
    cmd = ["ssh", "-p", str(dev["port"]), *SSH_OPTS]
    env = os.environ.copy()
    if dev.get("key"):
        kp = os.path.join(KEY_DIR, dev["key"])
        if not os.path.isfile(kp):
            raise ConfigError(f"SSH key '{dev['key']}' not found")
        cmd += ["-i", kp, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"]
        if passphrase:
            env["SSHPASS"] = passphrase
            cmd = ["sshpass", "-e", "-P", "passphrase", *cmd]
        else:
            cmd += ["-o", "BatchMode=yes"]
    else:
        if not password:
            raise ConfigError("password needed (or pick an SSH key for this device)")
        env["SSHPASS"] = password
        cmd = ["sshpass", "-e", *cmd, "-o", "PreferredAuthentications=password,keyboard-interactive",
               "-o", "PubkeyAuthentication=no"]
    cmd += (["-T"] if remote_cmd is None else []) + [target]
    if remote_cmd is not None:
        cmd.append(remote_cmd)
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise ConfigError("timed out while reading the config") from None
    err = (proc.stderr or "").strip()
    if proc.returncode == 5 or "permission denied" in err.lower():
        raise ConfigError("login failed: wrong user / password / key")
    if proc.returncode == 255 and not proc.stdout:
        raise ConfigError(err.splitlines()[-1] if err else "ssh failed")
    return proc.stdout or ""


def _telnet(dev, password, commands, timeout=60, enable_password=""):
    sock = socket.create_connection((dev["host"], dev["port"]), timeout=10)
    buf = b""

    def read_until(needles, wait):
        nonlocal buf
        end = time.time() + wait
        chunk_all = b""
        while time.time() < end:
            sock.settimeout(max(0.2, end - time.time()))
            try:
                c = sock.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            # answer telnet option negotiation with "won't / don't"
            out, i = b"", 0
            while i < len(c):
                if c[i] == 255 and i + 2 < len(c) and c[i + 1] in (251, 252, 253, 254):
                    sock.sendall(bytes([255, 254 if c[i + 1] in (251, 252) else 252, c[i + 2]]))
                    i += 3
                    continue
                out += c[i:i + 1]
                i += 1
            chunk_all += out
            low = chunk_all.lower().rstrip()
            if any(low.endswith(n) for n in needles):
                break
        buf += chunk_all
        return chunk_all

    try:
        first = read_until((b"username:", b"login:", b"password:", b">", b"#"), 10).lower()
        if b"username:" in first or b"login:" in first:
            sock.sendall(dev["user"].encode() + b"\r\n")
            read_until((b"password:",), 8)
        if b"password:" in first or b"username:" in first or b"login:" in first:
            sock.sendall((password or "").encode() + b"\r\n")
        after = read_until((b">", b"#", b"]"), 10).lower()
        if b"fail" in after or b"invalid" in after or b"denied" in after:
            raise ConfigError("login failed: wrong user / password")
        if dev["vendor"].startswith("cisco") and after.rstrip().endswith(b">"):
            sock.sendall(b"enable\r\n")
            if b"password" in read_until((b"password:", b"#"), 6).lower():
                sock.sendall((enable_password or password or "").encode() + b"\r\n")
                if not read_until((b"#", b">", b"password:"), 6).lower().rstrip().endswith(b"#"):
                    raise ConfigError("enable failed: wrong enable password")
        out = b""
        for c in commands:
            sock.sendall(c.encode() + b"\r\n")
            out = read_until((b"#", b">", b"]"), timeout)
        sock.sendall(b"exit\r\n")
        return out.decode("utf-8", "replace")
    finally:
        sock.close()


def _clean(text, commands):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r"(?m)^ ?-+ ?[Mm]ore ?-+ ?(\x08+ *\x08+)?", "", text)
    lines = text.split("\n")
    # drop leading echo of the last command and the trailing prompt
    last = commands[-1].strip()
    for i, line in enumerate(lines[:6]):
        if line.strip().endswith(last):
            lines = lines[i + 1:]
            break
    while lines and (not lines[-1].strip() or re.match(r"^[\w().\[\]<>/@:-]+[#>\]]\s*$", lines[-1].strip())):
        lines.pop()
    return "\n".join(lines).strip("\n") + "\n"


def fetch(dev, password="", passphrase="", enable_password=""):
    _label, mode, cmds, tcmds = VENDORS[dev["vendor"]]
    if dev.get("command"):
        cmds = tcmds = [dev["command"]]
    if dev["proto"] == "telnet":
        try:
            raw = _telnet(dev, password, tcmds, enable_password=enable_password)
        except OSError as exc:
            raise ConfigError(f"telnet: {exc.strerror or exc}") from None
        return _clean(raw, tcmds)
    if mode == "exec" or dev.get("command"):
        raw = _ssh(dev, password, passphrase, remote_cmd=cmds[-1] if len(cmds) == 1 else " ; ".join(cmds))
        return _clean(raw, ["\0"])
    marker = "NTB-CFG-END"
    pre = []
    if enable_password and dev["vendor"].startswith("cisco"):
        pre = ["enable", enable_password]
    script = "\n".join(pre + cmds) + "\n" + marker + "\nquit\nexit\n"
    raw = _ssh(dev, password, passphrase, stdin=script)
    return _clean(raw.split(marker)[0], cmds)


def backup(did, password="", passphrase="", enable_password=""):
    dev = _device(did)
    text = fetch(dev, password, passphrase, enable_password)
    if len(text.strip()) < 20:
        raise ConfigError("the device returned an empty config (wrong vendor / no privilege?)")
    norm = normalize(text)
    digest = hashlib.sha256(norm.encode()).hexdigest()
    prev = versions(did)
    if prev and prev[0].get("digest") == digest:
        return {"changed": False, "version": prev[0], "device": dev}
    ver = time.strftime("%Y%m%d-%H%M%S")
    vdir = _dir(did)
    cfg_path = os.path.join(vdir, ver + ".cfg")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(cfg_path, 0o600)
    _own(cfg_path)
    meta = {"version": ver, "time": time.time(), "size": len(text), "lines": text.count("\n"),
            "digest": digest, "added": 0, "removed": 0}
    if prev:
        old = normalize(read_version(did, prev[0]["version"])).splitlines()
        sm = difflib.SequenceMatcher(None, old, norm.splitlines(), autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                meta["removed"] += i2 - i1
            if tag in ("replace", "insert"):
                meta["added"] += j2 - j1
    meta_path = os.path.join(vdir, ver + ".json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    _own(meta_path)
    return {"changed": True, "first": not prev, "version": meta, "device": dev}


def delete_version(did, ver):
    read_version(did, ver)
    for ext in (".cfg", ".json"):
        p = os.path.join(CONFIG_DIR, did, ver + ext)
        if os.path.exists(p):
            os.remove(p)

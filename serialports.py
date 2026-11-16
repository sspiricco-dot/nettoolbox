"""USB serial console adapters (ttyUSB / ttyACM) for the Serial Console tab.

run.sh mounts the host /dev read-only at /hostdev and allows only the USB-serial device
majors (188 ttyUSB, 166 ttyACM) through the device cgroup, so adapters plugged in after
the container started still show up.
"""
from __future__ import annotations

import os
import re

DEV_ROOT = os.environ.get("NETTOOLBOX_HOSTDEV", "/hostdev")
LOG_DIR = os.environ.get("NETTOOLBOX_SERIAL_LOGS", "/tmp/serial-logs")
NAME_RE = re.compile(r"^tty(USB|ACM)[0-9]{1,3}$")
BAUDS = (1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600)
FRAMES = ("8N1", "7E1", "7O1", "8E1", "8O1", "8N2", "7N1")
FLOWS = ("n", "h", "s")


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _usb_info(name):
    """Walk up from /sys/class/tty/<name>/device to the USB device that has idVendor."""
    base = f"/sys/class/tty/{name}/device"
    try:
        path = os.path.realpath(base)
    except OSError:
        return {}
    for _ in range(4):
        if os.path.exists(os.path.join(path, "idVendor")):
            return {
                "vendor_id": _read(os.path.join(path, "idVendor")),
                "product_id": _read(os.path.join(path, "idProduct")),
                "manufacturer": _read(os.path.join(path, "manufacturer")),
                "product": _read(os.path.join(path, "product")),
                "serial": _read(os.path.join(path, "serial")),
            }
        path = os.path.dirname(path)
    drv = os.path.basename(os.path.realpath(base + "/driver")) if os.path.exists(base + "/driver") else ""
    return {"driver": drv} if drv else {}


def mounted():
    return os.path.isdir(DEV_ROOT)


def list_ports():
    ports = []
    if not mounted():
        return ports
    by_id = {}
    id_dir = os.path.join(DEV_ROOT, "serial", "by-id")
    if os.path.isdir(id_dir):
        for link in os.listdir(id_dir):
            try:
                target = os.path.basename(os.readlink(os.path.join(id_dir, link)))
            except OSError:
                continue
            by_id[target] = link
    for name in sorted(os.listdir(DEV_ROOT)):
        if not NAME_RE.match(name):
            continue
        path = os.path.join(DEV_ROOT, name)
        info = _usb_info(name)
        ok = os.access(path, os.R_OK | os.W_OK)
        label = info.get("product") or by_id.get(name, "") or name
        ports.append({
            "name": name,
            "label": label,
            "by_id": by_id.get(name, ""),
            "usb": info,
            "accessible": ok,
        })
    return ports


def logs():
    if not os.path.isdir(LOG_DIR):
        return []
    out = []
    for fname in sorted(os.listdir(LOG_DIR), reverse=True):
        p = os.path.join(LOG_DIR, fname)
        if fname.endswith(".log") and os.path.isfile(p):
            st = os.stat(p)
            out.append({"name": fname, "size": st.st_size, "mtime": st.st_mtime})
    return out[:50]


def log_path(name):
    if not re.match(r"^[A-Za-z0-9._-]{1,120}\.log$", name or ""):
        raise ValueError("invalid log name")
    path = os.path.join(LOG_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)
    return path

"""Small syslog receiver (UDP) for the Syslog tab: switches, routers and firewalls log to the laptop.

Runs as a thread inside the app. Keeps the last MAX_KEEP messages in memory (for the live view)
and appends every message to a log file you can download.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import socket
import threading
import time
from collections import deque

LOG_DIR = os.environ.get("NETTOOLBOX_SYSLOG_DIR", "/tmp/syslog")
MAX_KEEP = 5000
FILE_MAX = 50 * 1024 * 1024

SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
              "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
              "local3", "local4", "local5", "local6", "local7")

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\])\s?(.*)$", re.S)
_3164 = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$", re.S)
_CISCO = re.compile(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+)")


class SyslogError(Exception):
    pass


def parse(data: bytes, src_ip: str) -> dict:
    text = data.decode("utf-8", "replace").strip("\x00\r\n ")
    pri, fac, sev = None, None, None
    m = _PRI.match(text)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            fac, sev = pri >> 3, pri & 7
        text = text[m.end():]
    host, app, msg = src_ip, "", text
    m = _5424.match(text)
    if m:
        host = m.group(2) if m.group(2) != "-" else src_ip
        app = m.group(3) if m.group(3) != "-" else ""
        msg = m.group(7)
    else:
        m = _3164.match(text)
        if m:
            host, msg = m.group(2), m.group(3)
            tag = re.match(r"^([\w./-]{1,48})(\[\d+\])?:\s*(.*)$", msg, re.S)
            if tag:
                app, msg = tag.group(1), tag.group(3)
    mnemonic = ""
    c = _CISCO.search(msg)
    if c:  # Cisco %FAC-SEV-MNEMONIC carries its own severity
        mnemonic = f"%{c.group(1)}-{c.group(2)}-{c.group(3)}"
        if sev is None:
            sev = int(c.group(2))
    return {
        "src": src_ip,
        "host": host[:80],
        "app": app[:48],
        "sev": sev if sev is not None else 6,
        "fac": FACILITIES[fac] if fac is not None and fac < len(FACILITIES) else "",
        "mnemonic": mnemonic,
        "msg": msg[:2000],
    }


class Receiver:
    def __init__(self):
        self.lock = threading.Lock()
        self.buf = deque(maxlen=MAX_KEEP)
        self.next_id = 1
        self.sock = None
        self.thread = None
        self.port = 514
        self.started = None
        self.total = 0
        self.by_src: dict[str, int] = {}
        self.by_sev = [0] * 8
        self.file = os.path.join(LOG_DIR, "syslog.log")

    @property
    def up(self):
        return self.sock is not None

    def start(self, port=514):
        if self.up:
            return
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise SyslogError("invalid port") from None
        if not 1 <= port <= 65535:
            raise SyslogError("invalid port")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            sock.close()
            if exc.errno == 98:
                raise SyslogError(f"UDP port {port} is already in use on this machine "
                                  "(rsyslog / syslog-ng listening?). Stop it or pick another port.") from None
            raise SyslogError(str(exc)) from None
        os.makedirs(LOG_DIR, exist_ok=True)
        sock.settimeout(1.0)
        self.sock, self.port, self.started = sock, port, time.time()
        self.thread = threading.Thread(target=self._loop, name="syslogd", daemon=True)
        self.thread.start()

    def stop(self):
        sock, self.sock = self.sock, None
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        self.started = None

    def _loop(self):
        sock = self.sock
        fh = open(self.file, "a", encoding="utf-8")
        try:
            while self.sock is sock:
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                entry = parse(data, addr[0])
                entry["t"] = time.time()
                with self.lock:
                    entry["id"] = self.next_id
                    self.next_id += 1
                    self.buf.append(entry)
                    self.total += 1
                    self.by_src[entry["src"]] = self.by_src.get(entry["src"], 0) + 1
                    self.by_sev[entry["sev"]] += 1
                stamp = _dt.datetime.fromtimestamp(entry["t"]).strftime("%Y-%m-%d %H:%M:%S")
                fh.write(f"{stamp} {entry['src']} {SEVERITIES[entry['sev']]:<7} {entry['host']} "
                         f"{entry['app'] + ': ' if entry['app'] else ''}{entry['msg']}\n")
                fh.flush()
                if fh.tell() > FILE_MAX:  # keep one rotated copy
                    fh.close()
                    os.replace(self.file, self.file + ".1")
                    fh = open(self.file, "a", encoding="utf-8")
        finally:
            fh.close()

    def entries(self, since=0, limit=1000):
        with self.lock:
            items = [e for e in self.buf if e["id"] > since]
        return items[-limit:]

    def clear(self):
        with self.lock:
            self.buf.clear()
            self.total = 0
            self.by_src = {}
            self.by_sev = [0] * 8
        try:
            open(self.file, "w").close()
        except OSError:
            pass

    def state(self):
        with self.lock:
            return {
                "up": self.up,
                "port": self.port,
                "started": self.started,
                "total": self.total,
                "last_id": self.next_id - 1,
                "sources": sorted(({"ip": k, "count": v} for k, v in self.by_src.items()),
                                  key=lambda x: -x["count"])[:50],
                "by_sev": list(self.by_sev),
                "file_size": os.path.getsize(self.file) if os.path.exists(self.file) else 0,
            }


receiver = Receiver()

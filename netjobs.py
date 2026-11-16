"""iperf3 server/client and tcpdump packet capture, run as managed background processes."""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque

PCAP_DIR = os.environ.get("NETTOOLBOX_PCAP_DIR", "/tmp/captures")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$|^any$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")


class JobError(Exception):
    pass


def _stop(proc, sig_wait=3):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=sig_wait)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


# ---------------------------------------------------------------- iperf3
class Iperf:
    def __init__(self):
        self.server = None
        self.server_port = 5201
        self.server_log = deque(maxlen=200)
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()

    @property
    def server_up(self):
        return self.server is not None and self.server.poll() is None

    def start_server(self, port=5201):
        if self.server_up:
            return
        port = int(port)
        if not 1024 <= port <= 65535:
            raise JobError("port must be 1024-65535")
        self.server_log.clear()
        self.server = subprocess.Popen(["iperf3", "-s", "-p", str(port), "--forceflush"],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.server_port = port
        threading.Thread(target=self._read_server, args=(self.server,), daemon=True).start()
        time.sleep(0.4)
        if self.server.poll() is not None:
            msg = " ".join(self.server_log)[-300:]
            self.server = None
            if "in use" in msg.lower():
                raise JobError(f"TCP port {port} is already in use")
            raise JobError(msg or "iperf3 server exited")

    def _read_server(self, proc):
        for line in proc.stdout:
            line = line.rstrip()
            if line and not line.startswith("-----"):
                self.server_log.append(line)

    def stop_server(self):
        _stop(self.server)
        self.server = None

    def run_client(self, host, port=5201, duration=10, parallel=1, reverse=False, udp=False, bitrate="", bidir=False):
        if not HOST_RE.match(host or ""):
            raise JobError("invalid host")
        duration = max(1, min(int(duration), 120))
        parallel = max(1, min(int(parallel), 32))
        port = int(port)
        cmd = ["iperf3", "-c", host, "-p", str(port), "-t", str(duration), "-P", str(parallel), "-J",
               "--connect-timeout", "5000"]
        if bidir:
            cmd.append("--bidir")
        elif reverse:
            cmd.append("-R")
        if udp:
            cmd.append("-u")
            if bitrate and not re.match(r"^\d+(\.\d+)?[KMG]?$", bitrate):
                raise JobError("bitrate like 100M or 1G")
            cmd += ["-b", bitrate or "100M"]
        elif bitrate:
            if not re.match(r"^\d+(\.\d+)?[KMG]?$", bitrate):
                raise JobError("bitrate like 100M or 1G")
            cmd += ["-b", bitrate]
        jid = uuid.uuid4().hex[:10]
        job = {"id": jid, "host": host, "port": port, "duration": duration, "parallel": parallel,
               "mode": "bidir" if bidir else ("reverse" if reverse else "normal"), "udp": udp,
               "started": time.time(), "state": "running", "result": None, "error": ""}
        with self.lock:
            self.jobs[jid] = job
            for old in sorted(self.jobs.values(), key=lambda j: j["started"])[:-10]:
                self.jobs.pop(old["id"], None)
        threading.Thread(target=self._client, args=(job, cmd), daemon=True).start()
        return job

    def _client(self, job, cmd):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=job["duration"] + 30)
            try:
                data = json.loads(proc.stdout)
            except ValueError:
                raise JobError((proc.stderr or proc.stdout or "iperf3 failed").strip()[-300:]) from None
            if data.get("error"):
                raise JobError(data["error"])
            job["result"] = _summarize(data, job)
            job["state"] = "done"
        except (JobError, subprocess.TimeoutExpired, OSError) as exc:
            job["state"] = "error"
            job["error"] = str(exc) if not isinstance(exc, subprocess.TimeoutExpired) else "timed out"

    def state(self):
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: -j["started"])
        return {"server": {"up": self.server_up, "port": self.server_port, "log": list(self.server_log)[-30:]},
                "jobs": jobs}


def _summarize(d, job):
    end = d.get("end", {})
    out = {"intervals": [], "protocol": "UDP" if job["udp"] else "TCP"}
    for iv in d.get("intervals", []):
        s = iv.get("sum", {})
        row = {"t": round(s.get("end", 0), 1), "bps": s.get("bits_per_second", 0)}
        if "sum_bidir_reverse" in iv:
            row["bps_rev"] = iv["sum_bidir_reverse"].get("bits_per_second", 0)
        if not job["udp"]:
            row["retr"] = s.get("retransmits")
        else:
            row["lost"] = s.get("lost_percent")
        out["intervals"].append(row)
    if job["udp"]:
        s = end.get("sum", {})
        out.update(bps=s.get("bits_per_second", 0), jitter_ms=s.get("jitter_ms"), lost_percent=s.get("lost_percent"),
                   packets=s.get("packets"), lost_packets=s.get("lost_packets"))
    else:
        sent, recv = end.get("sum_sent", {}), end.get("sum_received", {})
        out.update(bps_sent=sent.get("bits_per_second", 0), bps=recv.get("bits_per_second", 0),
                   retransmits=sent.get("retransmits"), bytes=recv.get("bytes"))
        if "sum_sent_bidir_reverse" in end:
            out["bps_rev"] = end.get("sum_received_bidir_reverse", {}).get("bits_per_second", 0)
    cpu = end.get("cpu_utilization_percent", {})
    out["cpu_local"] = cpu.get("host_total")
    out["cpu_remote"] = cpu.get("remote_total")
    start = d.get("start", {})
    conn = (start.get("connected") or [{}])[0]
    out["local"] = f"{conn.get('local_host', '')}:{conn.get('local_port', '')}"
    out["remote"] = f"{conn.get('remote_host', '')}:{conn.get('remote_port', '')}"
    return out


# ---------------------------------------------------------------- tcpdump
class Capture:
    def __init__(self):
        self.proc = None
        self.meta = {}
        self.lines = deque(maxlen=300)
        self.count = 0
        self.lock = threading.Lock()

    @property
    def up(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, iface, bpf="", max_mb=50, max_secs=300, snaplen=0):
        if self.up:
            raise JobError("a capture is already running")
        if not IFACE_RE.match(iface or ""):
            raise JobError("invalid interface")
        bpf = (bpf or "").strip()
        if len(bpf) > 500 or "\n" in bpf:
            raise JobError("filter too long")
        max_mb = max(1, min(int(max_mb), 500))
        max_secs = max(5, min(int(max_secs), 6 * 3600))
        snaplen = max(0, min(int(snaplen or 0), 262144))
        if bpf:
            chk = subprocess.run(["tcpdump", "-d", "-i", iface, bpf], capture_output=True, text=True, timeout=10)
            if chk.returncode != 0:
                raise JobError("filter: " + (chk.stderr.strip().splitlines() or ["invalid"])[-1])
        os.makedirs(PCAP_DIR, exist_ok=True)
        name = f"{iface}-{time.strftime('%Y%m%d-%H%M%S')}.pcap"
        path = os.path.join(PCAP_DIR, name)
        cmd = ["tcpdump", "-i", iface, "-nn", "-l", "-U", "-w", path, "--print", "-s", str(snaplen or 262144)]
        if bpf:
            cmd.append(bpf)
        self.lines.clear()
        self.count = 0
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.proc = proc
        self.meta = {"file": name, "iface": iface, "filter": bpf, "max_mb": max_mb, "max_secs": max_secs,
                     "started": time.time(), "stopped": None, "reason": ""}
        threading.Thread(target=self._read, args=(proc,), daemon=True).start()
        threading.Thread(target=self._guard, args=(proc, path, max_mb, max_secs), daemon=True).start()
        time.sleep(0.5)
        if proc.poll() is not None:
            err = (proc.stderr.read() or "").strip().splitlines()
            self.proc = None
            raise JobError(err[-1] if err else "tcpdump exited")
        return self.state()

    def _read(self, proc):
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                with self.lock:
                    self.count += 1
                    self.lines.append(line[:300])

    def _guard(self, proc, path, max_mb, max_secs):
        while proc.poll() is None:
            time.sleep(0.5)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            if size >= max_mb * 1024 * 1024:
                self.meta["reason"] = "size limit"
                break
            if time.time() - self.meta["started"] >= max_secs:
                self.meta["reason"] = "time limit"
                break
        if proc.poll() is None:
            _stop(proc)
        self.meta["stopped"] = self.meta.get("stopped") or time.time()

    def stop(self):
        if self.up:
            self.meta["reason"] = "stopped"
            _stop(self.proc)
            self.meta["stopped"] = time.time()

    def files(self):
        if not os.path.isdir(PCAP_DIR):
            return []
        out = []
        for f in sorted(os.listdir(PCAP_DIR), reverse=True):
            p = os.path.join(PCAP_DIR, f)
            if f.endswith(".pcap") and os.path.isfile(p):
                out.append({"name": f, "size": os.path.getsize(p), "mtime": os.path.getmtime(p)})
        return out[:50]

    def path(self, name):
        if not re.match(r"^[A-Za-z0-9_.:@-]{1,15}-\d{8}-\d{6}\.pcap$", name or ""):
            raise JobError("invalid file")
        p = os.path.join(PCAP_DIR, name)
        if not os.path.isfile(p):
            raise JobError("file not found")
        return p

    def state(self):
        with self.lock:
            lines = list(self.lines)[-80:]
            count = self.count
        m = dict(self.meta)
        size = 0
        if m.get("file"):
            try:
                size = os.path.getsize(os.path.join(PCAP_DIR, m["file"]))
            except OSError:
                pass
        return {"up": self.up, "meta": m, "packets": count, "size": size, "lines": lines, "files": self.files()}


iperf = Iperf()
capture = Capture()

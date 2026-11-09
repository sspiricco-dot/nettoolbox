#!/usr/bin/env python3
"""Small TFTP server + client (RFC 1350, with blksize/tsize/timeout options).

Server: `python3 tftp.py serve` — started/stopped from the dashboard.
  NETTOOLBOX_TFTP_DIR    root folder (default /tmp/nettoolbox-tftp)
  NETTOOLBOX_TFTP_PORT   UDP port (default 69)
  NETTOOLBOX_TFTP_WRITE  "1" lets devices upload (WRQ), "0" makes it read-only
  NETTOOLBOX_TFTP_LOG    JSON-lines transfer log

Client: tftp_get()/tftp_put() are imported by app.py.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6

ERR_UNDEF, ERR_NOTFOUND, ERR_ACCESS, ERR_DISKFULL, ERR_ILLEGAL, ERR_TID, ERR_EXISTS, ERR_USER, ERR_OPTION = range(9)

DEFAULT_BLKSIZE = 512
MAX_BLKSIZE = 65464
MAX_FILE = 4 * 1024 ** 3
RETRIES = 6


class TftpError(Exception):
    pass


# --------------------------------------------------------------------------- packets

def _pkt_error(code, msg):
    return struct.pack("!HH", OP_ERROR, code) + msg.encode("ascii", "replace")[:200] + b"\x00"


def _pkt_ack(block):
    return struct.pack("!HH", OP_ACK, block & 0xFFFF)


def _pkt_data(block, payload):
    return struct.pack("!HH", OP_DATA, block & 0xFFFF) + payload


def _pkt_oack(opts):
    body = b"".join(k.encode() + b"\x00" + str(v).encode() + b"\x00" for k, v in opts.items())
    return struct.pack("!H", OP_OACK) + body


def _pkt_request(op, filename, opts):
    body = filename.encode("utf-8") + b"\x00octet\x00"
    body += b"".join(k.encode() + b"\x00" + str(v).encode() + b"\x00" for k, v in opts.items())
    return struct.pack("!H", op) + body


def _parse_strings(raw):
    parts = raw.split(b"\x00")
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    return [p.decode("utf-8", "replace") for p in parts]


def _parse_error(pkt):
    code = struct.unpack("!H", pkt[2:4])[0] if len(pkt) >= 4 else 0
    msg = pkt[4:].split(b"\x00")[0].decode("utf-8", "replace")
    return code, msg


def _parse_oack(pkt):
    items = _parse_strings(pkt[2:])
    return {items[i].lower(): items[i + 1] for i in range(0, len(items) - 1, 2)}


# --------------------------------------------------------------------------- paths

def safe_rel(name):
    """Map a requested TFTP filename to a safe relative path (or None)."""
    name = (name or "").replace("\\", "/").replace("\x00", "")
    parts = []
    for part in name.split("/"):
        part = part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            return None
        if any(ord(c) < 32 for c in part):
            return None
        parts.append(part[:180])
        if len(parts) > 8:
            return None
    if not parts:
        return None
    return "/".join(parts)


def resolve(root, name):
    rel = safe_rel(name)
    if not rel:
        return None, None
    root = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root, *rel.split("/")))
    if path == root or not path.startswith(root + os.sep):
        return None, None
    return path, rel


# --------------------------------------------------------------------------- server

class _Logger:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, **row):
        row["ts"] = time.time()
        line = json.dumps(row, ensure_ascii=False)
        sys.stderr.write(line + "\n")
        if not self.path:
            return
        with self.lock:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass


def _negotiate(req_opts, size=None):
    """Return (options to OACK, blksize, timeout)."""
    oack = {}
    blksize = DEFAULT_BLKSIZE
    timeout = 2.0
    if "blksize" in req_opts:
        try:
            want = int(req_opts["blksize"])
            if want >= 8:
                blksize = min(want, MAX_BLKSIZE)
                oack["blksize"] = blksize
        except ValueError:
            pass
    if "timeout" in req_opts:
        try:
            want = int(req_opts["timeout"])
            if 1 <= want <= 255:
                timeout = float(want)
                oack["timeout"] = want
        except ValueError:
            pass
    if "tsize" in req_opts:
        if size is not None:
            oack["tsize"] = size
        else:
            try:
                oack["tsize"] = int(req_opts["tsize"])
            except ValueError:
                pass
    return oack, blksize, timeout


def _send_wait(sock, peer, pkt, timeout, want_op, want_block):
    """Send pkt, wait for (want_op, want_block) from peer. Retransmit on timeout."""
    for _ in range(RETRIES):
        sock.sendto(pkt, peer)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(MAX_BLKSIZE + 4)
            except socket.timeout:
                break
            if addr != peer:
                sock.sendto(_pkt_error(ERR_TID, "Unknown transfer ID"), addr)
                continue
            if len(data) < 4:
                continue
            op, block = struct.unpack("!HH", data[:4])
            if op == OP_ERROR:
                code, msg = _parse_error(data)
                raise TftpError(f"peer error {code}: {msg}")
            if op == want_op and block == (want_block & 0xFFFF):
                return data
            # duplicate / stale packet: keep waiting
    raise TftpError("timeout")


def _serve_read(sock, peer, path, rel, opts, log):
    try:
        size = os.path.getsize(path)
        fh = open(path, "rb")
    except OSError:
        sock.sendto(_pkt_error(ERR_NOTFOUND, "File not found"), peer)
        log.write(op="read", peer=peer[0], file=rel, ok=False, error="not found")
        return
    oack, blksize, timeout = _negotiate(opts, size)
    sent = 0
    started = time.time()
    try:
        with fh:
            if oack:
                _send_wait(sock, peer, _pkt_oack(oack), timeout, OP_ACK, 0)
            block = 1
            while True:
                chunk = fh.read(blksize)
                _send_wait(sock, peer, _pkt_data(block, chunk), timeout, OP_ACK, block)
                sent += len(chunk)
                if len(chunk) < blksize:
                    break
                block += 1
        log.write(op="read", peer=peer[0], file=rel, ok=True, bytes=sent,
                  secs=round(time.time() - started, 2))
    except TftpError as exc:
        log.write(op="read", peer=peer[0], file=rel, ok=False, bytes=sent, error=str(exc))


def _serve_write(sock, peer, path, rel, opts, log):
    oack, blksize, timeout = _negotiate(opts)
    if "tsize" in oack and oack["tsize"] > MAX_FILE:
        sock.sendto(_pkt_error(ERR_DISKFULL, "File too large"), peer)
        log.write(op="write", peer=peer[0], file=rel, ok=False, error="too large")
        return
    tmp = path + ".part"
    got = 0
    started = time.time()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = open(tmp, "wb")
    except OSError as exc:
        sock.sendto(_pkt_error(ERR_ACCESS, "Cannot create file"), peer)
        log.write(op="write", peer=peer[0], file=rel, ok=False, error=str(exc))
        return
    try:
        with fh:
            first = _pkt_oack(oack) if oack else _pkt_ack(0)
            block = 1
            reply = first
            while True:
                data = _send_wait(sock, peer, reply, timeout, OP_DATA, block)
                payload = data[4:]
                got += len(payload)
                if got > MAX_FILE:
                    sock.sendto(_pkt_error(ERR_DISKFULL, "File too large"), peer)
                    raise TftpError("too large")
                fh.write(payload)
                if len(payload) < blksize:
                    sock.sendto(_pkt_ack(block), peer)
                    break
                reply = _pkt_ack(block)
                block += 1
        os.replace(tmp, path)
        log.write(op="write", peer=peer[0], file=rel, ok=True, bytes=got,
                  secs=round(time.time() - started, 2))
    except (TftpError, OSError) as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        log.write(op="write", peer=peer[0], file=rel, ok=False, bytes=got, error=str(exc))


def _handle(req, peer, root, allow_write, log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        if len(req) < 4:
            return
        op = struct.unpack("!H", req[:2])[0]
        items = _parse_strings(req[2:])
        if op not in (OP_RRQ, OP_WRQ) or len(items) < 2:
            sock.sendto(_pkt_error(ERR_ILLEGAL, "Illegal TFTP operation"), peer)
            return
        filename, mode = items[0], items[1].lower()
        opts = {items[i].lower(): items[i + 1] for i in range(2, len(items) - 1, 2)}
        kind = "read" if op == OP_RRQ else "write"
        if mode not in ("octet", "netascii"):
            sock.sendto(_pkt_error(ERR_ILLEGAL, "Only octet/netascii"), peer)
            log.write(op=kind, peer=peer[0], file=filename, ok=False, error="mode " + mode)
            return
        path, rel = resolve(root, filename)
        if not path:
            sock.sendto(_pkt_error(ERR_ACCESS, "Access violation"), peer)
            log.write(op=kind, peer=peer[0], file=filename, ok=False, error="bad path")
            return
        if op == OP_RRQ:
            if not os.path.isfile(path):
                sock.sendto(_pkt_error(ERR_NOTFOUND, "File not found"), peer)
                log.write(op="read", peer=peer[0], file=rel, ok=False, error="not found")
                return
            _serve_read(sock, peer, path, rel, opts, log)
        else:
            if not allow_write:
                sock.sendto(_pkt_error(ERR_ACCESS, "Server is read-only"), peer)
                log.write(op="write", peer=peer[0], file=rel, ok=False, error="read-only")
                return
            _serve_write(sock, peer, path, rel, opts, log)
    finally:
        sock.close()


def serve(root, port, allow_write, log_path):
    os.makedirs(root, exist_ok=True)
    log = _Logger(log_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as exc:
        sys.stderr.write(f"BIND_ERROR: UDP {port}: {exc.strerror or exc}\n")
        sys.stderr.flush()
        sys.exit(2)
    sys.stderr.write(f"READY udp/{port} root={root} write={'on' if allow_write else 'off'}\n")
    sys.stderr.flush()
    while True:
        try:
            req, peer = sock.recvfrom(2048)
        except OSError:
            continue
        threading.Thread(target=_handle, args=(req, peer, root, allow_write, log), daemon=True).start()


# --------------------------------------------------------------------------- client

def _client_sock(timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(timeout)
    return sock


def _first_reply(sock, server, req, timeout):
    """Send request, return (packet, server_tid_addr)."""
    for _ in range(RETRIES):
        sock.sendto(req, server)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(MAX_BLKSIZE + 4)
            except socket.timeout:
                break
            if addr[0] != server[0] or len(data) < 2:
                continue
            return data, addr
    raise TftpError("no reply from server (timeout)")


def _addr(host, port):
    try:
        info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise TftpError(f"cannot resolve {host}: {exc}")
    return info[0][4]


def tftp_get(host, port, remote, local_path, blksize=1468, timeout=3.0, progress=None):
    """Download `remote` from a TFTP server into local_path. Returns bytes received."""
    server = _addr(host, port)
    sock = _client_sock(timeout)
    tmp = local_path + ".part"
    got = 0
    try:
        opts = {"tsize": 0, "timeout": int(timeout)}
        if blksize and blksize != DEFAULT_BLKSIZE:
            opts["blksize"] = blksize
        data, peer = _first_reply(sock, server, _pkt_request(OP_RRQ, remote, opts), timeout)
        bs = DEFAULT_BLKSIZE
        total = None
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(tmp, "wb") as fh:
            op = struct.unpack("!H", data[:2])[0]
            if op == OP_ERROR:
                code, msg = _parse_error(data)
                raise TftpError(f"server error {code}: {msg}")
            if op == OP_OACK:
                got_opts = _parse_oack(data)
                bs = int(got_opts.get("blksize", DEFAULT_BLKSIZE))
                if "tsize" in got_opts:
                    total = int(got_opts["tsize"])
                if progress:
                    progress(0, total)
                data = _send_wait(sock, peer, _pkt_ack(0), timeout, OP_DATA, 1)
            elif op != OP_DATA:
                raise TftpError("unexpected reply")
            block = 1
            while True:
                if struct.unpack("!H", data[2:4])[0] != (block & 0xFFFF):
                    raise TftpError("out-of-order block")
                payload = data[4:]
                fh.write(payload)
                got += len(payload)
                if progress:
                    progress(got, total)
                if len(payload) < bs:
                    sock.sendto(_pkt_ack(block), peer)
                    break
                data = _send_wait(sock, peer, _pkt_ack(block), timeout, OP_DATA, block + 1)
                block += 1
        os.replace(tmp, local_path)
        return got
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    finally:
        sock.close()


def tftp_put(host, port, local_path, remote, blksize=1468, timeout=3.0, progress=None):
    """Upload local_path to a TFTP server as `remote`. Returns bytes sent."""
    server = _addr(host, port)
    size = os.path.getsize(local_path)
    sock = _client_sock(timeout)
    sent = 0
    try:
        opts = {"tsize": size, "timeout": int(timeout)}
        if blksize and blksize != DEFAULT_BLKSIZE:
            opts["blksize"] = blksize
        data, peer = _first_reply(sock, server, _pkt_request(OP_WRQ, remote, opts), timeout)
        op = struct.unpack("!H", data[:2])[0]
        bs = DEFAULT_BLKSIZE
        if op == OP_ERROR:
            code, msg = _parse_error(data)
            raise TftpError(f"server error {code}: {msg}")
        if op == OP_OACK:
            bs = int(_parse_oack(data).get("blksize", DEFAULT_BLKSIZE))
        elif not (op == OP_ACK and struct.unpack("!H", data[2:4])[0] == 0):
            raise TftpError("unexpected reply")
        if progress:
            progress(0, size)
        with open(local_path, "rb") as fh:
            block = 1
            while True:
                chunk = fh.read(bs)
                _send_wait(sock, peer, _pkt_data(block, chunk), timeout, OP_ACK, block)
                sent += len(chunk)
                if progress:
                    progress(sent, size)
                if len(chunk) < bs:
                    break
                block += 1
        return sent
    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve(
            os.environ.get("NETTOOLBOX_TFTP_DIR", "/tmp/nettoolbox-tftp"),
            int(os.environ.get("NETTOOLBOX_TFTP_PORT", "69")),
            os.environ.get("NETTOOLBOX_TFTP_WRITE", "1") == "1",
            os.environ.get("NETTOOLBOX_TFTP_LOG", ""),
        )
    else:
        sys.stderr.write("usage: tftp.py serve\n")
        sys.exit(1)

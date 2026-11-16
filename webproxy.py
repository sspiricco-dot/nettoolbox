"""Web Console: open a device's web UI (router, switch, printer, NAS ...) inside the dashboard.

Each target gets its own reverse proxy on 127.0.0.1:<port> (loopback only), so absolute paths
in the device UI keep working. The proxy:
  * talks TLS to the device without verifying (self-signed certs, old TLS / ciphers),
  * strips headers that block framing (X-Frame-Options, CSP frame-ancestors) and HSTS,
  * rewrites redirects, cookie flags and absolute links back to the proxy,
  * passes WebSocket upgrades straight through.
"""
from __future__ import annotations

import http.client
import http.server
import ipaddress
import re
import select
import socket
import ssl
import threading
import time
import urllib.parse

PORT_BASE = 8700
MAX_TARGETS = 20
TEXT_MAX = 20 * 1024 * 1024
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
       "trailers", "transfer-encoding", "upgrade", "proxy-connection"}
TEXTY = ("text/html", "text/css", "javascript", "application/json", "text/xml", "application/xml",
         "text/plain", "application/xhtml")

_lock = threading.Lock()
_targets: dict[int, "Target"] = {}


class WebConsoleError(Exception):
    pass


def _tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # old switches/printers: TLS 1.0, SHA-1, small DH, legacy renegotiation
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    ctx.options |= 0x4  # SSL_OP_LEGACY_SERVER_CONNECT
    return ctx


_CTX = _tls_ctx()


class Target:
    def __init__(self, scheme, host, port, path):
        self.scheme, self.host, self.port, self.path = scheme, host, port, path or "/"
        self.proxy_port = None
        self.server = None
        self.created = time.time()
        self.last_used = time.time()
        self.requests = 0

    @property
    def hostport(self):
        h = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return h if self.port == default else f"{h}:{self.port}"

    @property
    def origin(self):
        return f"{self.scheme}://{self.hostport}"

    @property
    def proxy_origin(self):
        return f"http://127.0.0.1:{self.proxy_port}"

    def origin_regex(self):
        """Absolute URLs of this device in a body (also JSON-escaped), not 192.168.1.10 for .1."""
        h = f"[{self.host}]" if ":" in self.host else self.host
        ports = sorted({self.port, 80, 443})
        alts = [re.escape(f"{sch}://{h}") + (re.escape(f":{p}") if p else "")
                for sch in ("http", "https") for p in [None, *ports]]
        alts += [a.replace("/", r"\\/") for a in alts]
        alts.sort(key=len, reverse=True)
        return re.compile(("(?:" + "|".join(alts) + r")(?![\w.:-])").encode())

    def public(self):
        return {
            "id": self.proxy_port,
            "target": self.origin + (self.path if self.path != "/" else ""),
            "host": self.host,
            "url": f"{self.proxy_origin}{self.path}",
            "created": self.created,
            "last_used": self.last_used,
            "requests": self.requests,
        }


def _rewrite_location(t, loc):
    try:
        u = urllib.parse.urlsplit(loc)
    except ValueError:
        return loc
    if not u.scheme or not u.netloc:
        return loc
    host = u.hostname or ""
    if host.lower() != t.host.lower():
        return loc
    port = u.port or (443 if u.scheme == "https" else 80)
    if (u.scheme, port) != (t.scheme, t.port) and u.scheme in ("http", "https"):
        t.scheme, t.port = u.scheme, port  # device moved us (usually http -> https): follow it
    return urllib.parse.urlunsplit(("http", f"127.0.0.1:{t.proxy_port}", u.path or "/", u.query, u.fragment))


def _rewrite_cookie(v):
    parts = [p for p in v.split(";")]
    keep = [parts[0]]
    for p in parts[1:]:
        k = p.strip().split("=", 1)[0].lower()
        if k in ("secure", "domain", "partitioned"):
            continue
        if k == "samesite" and p.strip().lower().endswith("none"):
            p = " SameSite=Lax"
        keep.append(p)
    return ";".join(keep)


def _rewrite_csp(v):
    keep = []
    for d in v.split(";"):
        name = d.strip().split(" ", 1)[0].lower()
        if name in ("frame-ancestors", "upgrade-insecure-requests", "block-all-mixed-content"):
            continue
        if d.strip():
            keep.append(d.strip())
    return "; ".join(keep)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetToolbox-WebConsole"

    def log_message(self, *a):
        pass

    # every method goes through the same path
    def do_GET(self):
        self._proxy()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_GET

    def _req_headers(self, t):
        out = []
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP or lk == "host" or lk == "accept-encoding" or lk == "content-length":
                continue
            if lk == "origin":
                v = t.origin
            elif lk == "referer":
                v = v.replace(t.proxy_origin, t.origin, 1)
            out.append((k, v))
        out.append(("Host", t.hostport))
        out.append(("Accept-Encoding", "identity"))
        return out

    def _body(self):
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            data = b""
            while True:
                line = self.rfile.readline()
                size = int(line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
            return data
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else None

    def _upstream(self, t):
        if t.scheme == "https":
            return http.client.HTTPSConnection(t.host, t.port, timeout=30, context=_CTX)
        return http.client.HTTPConnection(t.host, t.port, timeout=30)

    def _error(self, code, msg):
        body = (f"<!doctype html><meta charset=utf-8><body style='font:14px system-ui;padding:24px;"
                f"background:#0b1220;color:#e8eef6'><h3>Web Console</h3><p>{msg}</p></body>").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _proxy(self):
        t: Target = self.server.target
        t.last_used = time.time()
        t.requests += 1
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            return self._tunnel(t)
        try:
            body = self._body()
            conn = self._upstream(t)
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for k, v in self._req_headers(t):
                conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return self._error(502, f"Could not reach {t.origin}: {exc}")

        try:
            headers = []
            ctype = ""
            for k, v in resp.getheaders():
                lk = k.lower()
                if lk in HOP or lk in ("content-length", "x-frame-options", "strict-transport-security",
                                       "content-security-policy-report-only", "public-key-pins"):
                    continue
                if lk == "content-type":
                    ctype = v.lower()
                if lk == "location":
                    v = _rewrite_location(t, v)
                elif lk == "set-cookie":
                    v = _rewrite_cookie(v)
                elif lk == "content-security-policy":
                    v = _rewrite_csp(v)
                    if not v:
                        continue
                headers.append((k, v))

            no_body = self.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
            length = resp.getheader("Content-Length")
            texty = any(x in ctype for x in TEXTY)
            if not no_body and texty and (length is None or int(length) <= TEXT_MAX):
                data = resp.read(TEXT_MAX + 1)
                po = t.proxy_origin.encode()
                data = t.origin_regex().sub(lambda m: po.replace(b"/", b"\\/") if b"\\/" in m.group(0) else po, data)
                self.send_response(resp.status, resp.reason)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_response(resp.status, resp.reason)
            for k, v in headers:
                self.send_header(k, v)
            if no_body:
                if length is not None:
                    self.send_header("Content-Length", length)
                self.end_headers()
                return
            if length is not None:
                self.send_header("Content-Length", length)
                self.end_headers()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            else:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.write(b"0\r\n\r\n")
        except (OSError, http.client.HTTPException, ssl.SSLError):
            self.close_connection = True
        finally:
            conn.close()

    def _tunnel(self, t):
        try:
            raw = socket.create_connection((t.host, t.port), timeout=15)
            up = _CTX.wrap_socket(raw) if t.scheme == "https" else raw
        except OSError as exc:
            return self._error(502, f"WebSocket to {t.origin} failed: {exc}")
        lines = [f"{self.command} {self.path} HTTP/1.1"]
        for k, v in self.headers.items():
            lk = k.lower()
            if lk == "host":
                v = t.hostport
            elif lk == "origin":
                v = t.origin
            lines.append(f"{k}: {v}")
        up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        client = self.connection
        up.settimeout(None)
        client.settimeout(None)
        socks = [client, up]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 300)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is client else client).sendall(data)
        except OSError:
            pass
        finally:
            self.close_connection = True
            try:
                up.close()
            except OSError:
                pass


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------- management
def _parse(url):
    url = (url or "").strip()
    if not url:
        raise WebConsoleError("enter a device address, e.g. 192.168.1.1 or https://10.0.0.2:8443")
    if "://" not in url:
        url = "http://" + url
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise WebConsoleError("only http:// and https:// addresses")
    host = u.hostname
    if host in ("localhost",) or host.startswith("127."):
        raise WebConsoleError("open local pages directly in the browser")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", host):
            raise WebConsoleError("invalid host name") from None
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return u.scheme, host, port, path


def open_target(url):
    scheme, host, port, path = _parse(url)
    try:
        socket.create_connection((host, port), timeout=5).close()
    except OSError as exc:
        raise WebConsoleError(f"{host}:{port} is not reachable ({exc.strerror or exc})") from None
    with _lock:
        for t in _targets.values():
            if (t.scheme, t.host, t.port) == (scheme, host, port):
                t.path = path
                return t.public()
        if len(_targets) >= MAX_TARGETS:
            oldest = min(_targets.values(), key=lambda x: x.last_used)
            _close(oldest.proxy_port)
        t = Target(scheme, host, port, path)
        for p in range(PORT_BASE, PORT_BASE + 100):
            if p in _targets:
                continue
            try:
                srv = _Server(("127.0.0.1", p), Handler)
            except OSError:
                continue
            srv.target = t
            t.proxy_port, t.server = p, srv
            threading.Thread(target=srv.serve_forever, name=f"webconsole-{p}", daemon=True).start()
            _targets[p] = t
            return t.public()
    raise WebConsoleError("no free local port for the proxy")


def _close(pid):
    t = _targets.pop(pid, None)
    if t and t.server:
        threading.Thread(target=lambda s=t.server: (s.shutdown(), s.server_close()), daemon=True).start()


def close_target(pid):
    with _lock:
        if pid not in _targets:
            raise WebConsoleError("not open")
        _close(pid)


def list_targets():
    with _lock:
        return [t.public() for t in sorted(_targets.values(), key=lambda x: x.created)]

#!/usr/bin/env python3
"""Read-only LAN file drop. Started/stopped from the dashboard. No uploads here."""
from __future__ import annotations

import html
import os
import posixpath
import sys
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

SHARE_DIR = os.environ.get("NETTOOLBOX_SHARE", "/tmp/nettoolbox-share")
SHARE_PORT = int(os.environ.get("NETTOOLBOX_SHARE_PORT", "8765"))

PAGE = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetToolbox · فایل‌ها</title>
<style>
  :root {
    --bg:#0b1220; --card:#141e2e; --line:rgba(148,174,204,.16);
    --ink:#e8eef6; --dim:#8a9bb0; --accent:#d4894a; --cyan:#5ec8e0; --up:#3ecf8e;
  }
  * { box-sizing:border-box; }
  body {
    margin:0; min-height:100vh; color:var(--ink);
    font-family:"Segoe UI","Vazirmatn",system-ui,sans-serif;
    background:
      radial-gradient(ellipse 70% 50% at 8% -10%, rgba(212,137,74,.28), transparent 60%),
      radial-gradient(ellipse 55% 40% at 100% 0%, rgba(94,200,224,.22), transparent 55%),
      var(--bg);
  }
  .wrap { max-width:720px; margin:0 auto; padding:32px 20px 64px; }
  .brand { display:flex; gap:12px; align-items:center; margin-bottom:8px; }
  .mark {
    width:40px; height:40px; border-radius:12px;
    background:linear-gradient(135deg,#d4894a,#e0a15e 55%,#5ec8e0);
    display:grid; place-items:center; color:#1a1208; font-weight:800;
  }
  h1 { margin:0; font-size:22px; letter-spacing:-.02em; }
  .sub { color:var(--dim); font-size:14px; margin:6px 0 22px; line-height:1.6; }
  .card {
    background:var(--card); border:1px solid var(--line); border-radius:16px;
    overflow:hidden;
  }
  a.row {
    display:grid; grid-template-columns:1fr auto auto; gap:12px; align-items:center;
    padding:14px 16px; color:var(--ink); text-decoration:none;
    border-bottom:1px solid var(--line); direction:ltr;
  }
  a.row:last-child { border-bottom:0; }
  a.row:hover { background:rgba(94,200,224,.08); }
  .name { font-family:ui-monospace,Menlo,monospace; font-size:14px; word-break:break-all; }
  .meta { color:var(--dim); font-size:12px; font-family:ui-monospace,Menlo,monospace; white-space:nowrap; }
  .dl {
    background:linear-gradient(135deg,#d4894a,#e0a15e); color:#1a1208;
    font-size:12px; font-weight:700; padding:6px 12px; border-radius:999px;
  }
  .empty { padding:28px 16px; text-align:center; color:var(--dim); }
  footer { margin-top:18px; color:var(--dim); font-size:12px; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="brand"><div class="mark">NT</div><div><h1>NetToolbox</h1></div></div>
    <p class="sub">فایل‌های این بازدید را از همین صفحه دانلود کنید. چند نفر هم‌زمان می‌توانند بگیرند.<br>
    Download files from this site visit. Several people can grab them at once.</p>
    <div class="card">__LIST__</div>
    <footer>Read-only · LAN only while the toolbox leaves this server on</footer>
  </div>
</body>
</html>
"""


def _safe_rel(rel):
    rel = (rel or "").replace("\\", "/").replace("\x00", "")
    parts = []
    for part in rel.split("/"):
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        parts.append(part)
        if len(parts) > 8:
            return None
    if not parts:
        return None
    return "/".join(parts)


def _under_share(path):
    root = os.path.realpath(SHARE_DIR)
    real = os.path.realpath(path)
    return real == root or real.startswith(root + os.sep)


def _files():
    if not os.path.isdir(SHARE_DIR):
        return []
    root = os.path.realpath(SHARE_DIR)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".", "..")]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            if not os.path.isfile(full) or not _under_share(full):
                continue
            rel = os.path.relpath(full, root).replace("\\", "/")
            if rel.startswith(".."):
                continue
            out.append((rel, os.path.getsize(full)))
            if len(out) >= 500:
                return sorted(out, key=lambda row: row[0].lower())
    return sorted(out, key=lambda row: row[0].lower())


def _fmt_size(n):
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f} GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"


class Handler(BaseHTTPRequestHandler):
    server_version = "NetToolboxShare/1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_POST(self):
        self.send_error(405, "Uploads are disabled on the LAN page")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = posixpath.normpath(urllib.parse.unquote(parsed.path))
        if path in ("/", "/index.html"):
            return self._index()
        if path.startswith("/d/"):
            return self._file(path[3:])
        self.send_error(404, "Not found")

    def _index(self):
        rows = []
        for name, size in _files():
            href = "/d/" + urllib.parse.quote(name, safe="/")
            rows.append(
                '<a class="row" href="%s">'
                '<span class="name">%s</span>'
                '<span class="meta">%s</span>'
                '<span class="dl">Download</span></a>'
                % (html.escape(href, quote=True), html.escape(name), _fmt_size(size))
            )
        body = PAGE.replace("__LIST__", "".join(rows) or '<div class="empty">No files yet / هنوز فایلی نیست</div>')
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _file(self, name):
        rel = _safe_rel(name)
        if not rel:
            self.send_error(400, "Bad name")
            return
        path = os.path.join(SHARE_DIR, *rel.split("/"))
        if not os.path.isfile(path) or not _under_share(path):
            self.send_error(404, "File gone")
            return
        size = os.path.getsize(path)
        download_name = os.path.basename(rel)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header(
            "Content-Disposition",
            "attachment; filename*=UTF-8''%s" % urllib.parse.quote(download_name),
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 256)
                if not chunk:
                    break
                self.wfile.write(chunk)


def main():
    os.makedirs(SHARE_DIR, exist_ok=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", SHARE_PORT), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Local server for مِفتاح مكنون — Maknoon PS4 Exploit Host.

Why a custom server instead of `python3 -m http.server`:
  * The 9.00 pages rely on Application Cache. The browser refuses to cache
    unless `cache.manifest` is served as `text/cache-manifest`.
  * PS4 payloads are `.bin` blobs that must be served as binary, byte-exact,
    with working Content-Length (and Range, for loaders that ask for it).
  * The console needs the machine's LAN IP, so we print it on startup.

Usage:
    python3 serve.py                # port 8080, all interfaces
    python3 serve.py --port 80      # needs sudo on macOS
    python3 serve.py --port 9000 --bind 0.0.0.0
"""

import argparse
import io
import os
import posixpath
import re
import socket
import sys
import urllib.parse
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Explicit table: do not rely on the system mimetypes database.
EXTENSIONS = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".manifest": "text/cache-manifest",
    ".appcache": "text/cache-manifest",
    ".bin": "application/octet-stream",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}

# Assets the console caches itself; do not let an intermediate layer keep a
# stale copy. HTML and the manifest must always be revalidated so that edits
# to the host show up on the next load.
NO_STORE = {".html", ".htm", ".manifest", ".appcache"}

# Injected only when the URL carries ?preview (local editing aid). The exploit
# cannot run off-console, so without this every host page is stuck on its
# "Loading Jailbreak..." screen and the menu is impossible to inspect.
PREVIEW_SNIPPET = b"""
<div id="__preview_badge" style="position:fixed;left:0;bottom:0;z-index:99999;
  background:#b8860b;color:#000;font:bold 13px/1.6 sans-serif;padding:2px 10px;
  border-top-right-radius:6px;">PREVIEW - exploit not running</div>
<script>
(function () {
  function reveal() {
    var p = document.getElementById("progress");
    if (p) p.style.display = "none";
    var m = document.getElementById("menu");
    if (m) m.style.display = "block";
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reveal);
  } else {
    reveal();
  }
  setTimeout(reveal, 400);
})();
</script>
"""


class ExploitHostHandler(SimpleHTTPRequestHandler):
    server_version = "PS4ExploitHost/1.0"
    protocol_version = "HTTP/1.1"

    def guess_type(self, path):
        ext = posixpath.splitext(path)[1].lower()
        return EXTENSIONS.get(ext, "application/octet-stream")

    def end_headers(self):
        url_path = urllib.parse.urlsplit(self.path).path
        ext = posixpath.splitext(url_path)[1].lower()
        # "/" and "/900v3/" resolve to index.html, so treat them as documents.
        if url_path.endswith("/"):
            ext = ".html"
        if ext in NO_STORE:
            self.send_header("Cache-Control", "no-cache, must-revalidate")
        else:
            self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    @staticmethod
    def _preview_document(path):
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as fh:
            data = fh.read()
        # Drop the exploit trigger: on a desktop the kernel exploit either
        # throws or spins forever, which leaves the menu unpaintable.
        data = re.sub(rb'(<body\b[^>]*?)\s+onload="[^"]*"', rb"\1", data,
                      count=1, flags=re.I)
        # External exploit bundles also navigate/reload the tab at load time,
        # and some pages carry ~850KB inline memory-spray scripts that starve
        # the renderer. Preview is a static UI inspection, so every script is
        # dropped and the small reveal snippet below takes over.
        data = re.sub(rb"<script\b[^>]*>.*?</script>", b"", data, flags=re.S | re.I)
        marker = data.lower().rfind(b"</body>")
        if marker == -1:
            return data + PREVIEW_SNIPPET
        return data[:marker] + PREVIEW_SNIPPET + data[marker:]

    # --- Range support -------------------------------------------------
    def send_head(self):
        parts = urllib.parse.urlsplit(self.path)
        if "preview" in parts.query and parts.path.lower().endswith((".html", ".htm")):
            injected = self._preview_document(self.translate_path(self.path))
            if injected is not None:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(injected)))
                self.end_headers()
                return io.BytesIO(injected)

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            return super().send_head()

        range_header = self.headers.get("Range")
        if not range_header or not os.path.isfile(path):
            return super().send_head()

        try:
            size = os.path.getsize(path)
            unit, _, spec = range_header.partition("=")
            if unit.strip().lower() != "bytes":
                return super().send_head()
            start_s, _, end_s = spec.partition("-")
            if start_s.strip() == "":
                # suffix range: last N bytes
                length = int(end_s)
                start = max(size - length, 0)
                end = size - 1
            else:
                start = int(start_s)
                end = int(end_s) if end_s.strip() else size - 1
            if start > end or start >= size:
                self.send_error(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                return None
            end = min(end, size - 1)
        except (ValueError, OSError):
            return super().send_head()

        f = open(path, "rb")
        f.seek(start)
        self._range_remaining = end - start + 1
        self.send_response(HTTPStatus.PARTIAL_CONTENT)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Length", str(self._range_remaining))
        self.end_headers()
        return f

    def copyfile(self, source, outputfile):
        remaining = getattr(self, "_range_remaining", None)
        if remaining is None:
            return super().copyfile(source, outputfile)
        self._range_remaining = None
        while remaining > 0:
            chunk = source.read(min(64 * 1024, remaining))
            if not chunk:
                break
            outputfile.write(chunk)
            remaining -= len(chunk)

    def log_message(self, fmt, *args):
        sys.stdout.write("  %s  %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()


def lan_addresses():
    """Best-effort list of this machine's LAN IPv4 addresses."""
    found = []

    # UDP connect trick: no packet is sent, but the kernel picks the
    # outbound interface, which is the address the console will reach.
    for probe in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.4)
                s.connect((probe, 53))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127.") and ip not in found:
                    found.append(ip)
                    break
        except OSError:
            continue

    if not found:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if not ip.startswith("127.") and ip not in found:
                    found.append(ip)
        except OSError:
            pass

    return found


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Serve the PS4 exploit host locally.")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--dir", default=here)
    args = parser.parse_args()

    root = os.path.abspath(args.dir)
    handler = partial(ExploitHostHandler, directory=root)

    try:
        httpd = ThreadingHTTPServer((args.bind, args.port), handler)
    except PermissionError:
        print(f"\n  Port {args.port} needs administrator rights. Try:")
        print(f"    sudo python3 serve.py --port {args.port}\n")
        raise SystemExit(1)
    except OSError as exc:
        print(f"\n  Could not start on port {args.port}: {exc}")
        print("  Another program may already be using it. Try --port 8081.\n")
        raise SystemExit(1)

    print("\n  PS4 Exploit Host - local server")
    print("  " + "-" * 46)
    print(f"  Serving : {root}")
    print(f"  Local   : http://127.0.0.1:{args.port}/")
    for ip in lan_addresses():
        print(f"  Console : http://{ip}:{args.port}/")
    print("  " + "-" * 46)
    print("  Open the Console URL above in the PS4 browser.")
    print("  Editing a menu? Add ?preview=1 to the page URL to see it here.")
    print("  Ctrl+C to stop.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.\n")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# bmail-site: Landing Page (apex) + PWA unter /app/ + Relay-Proxy unter /relay-a|/relay-b.
# Einprozess-Stdlib-Server vor dem cloudflared-Tunnel auf CT113 — bewusst klein und langweilig.
import http.client, os, sys, mimetypes, posixpath
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, unquote

SITE = "/root/lightningmail/site"
DIST = "/root/lightningmail/client/app/dist"
RELAYS = {"/relay-a": 8443, "/relay-b": 9443}
BIND, PORT = "127.0.0.1", 5180

class H(SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

    def _static(self, root, path, spa=None):
        path = unquote(path).split("?")[0].lstrip("/")
        full = posixpath.normpath(posixpath.join(root, path or "."))
        if not full.startswith(root):
            return self.send_error(403)
        if os.path.isdir(full):
            full = posixpath.join(full, "index.html")
        if not os.path.isfile(full) and spa:
            full = spa
        if not os.path.isfile(full):
            return self.send_error(404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if full.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _proxy(self, port):
        ln = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(ln) if ln else None
        up = urlparse(self.path)
        target = up.path[len("/relay-a"):] if up.path.startswith("/relay-a") else up.path[len("/relay-b"):]
        target = target or "/"
        if up.query:
            target += "?" + up.query
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        try:
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
            hdrs["Host"] = "127.0.0.1:%d" % port
            conn.request(self.command, target, body=body, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(502, str(e))
        finally:
            conn.close()

    def _route(self):
        p = urlparse(self.path).path
        for pref, port in RELAYS.items():
            if p == pref or p.startswith(pref + "/"):
                return self._proxy(port)
        if p == "/app" or p.startswith("/app/"):
            rel = p[4:] or "/"
            return self._static(DIST, rel, spa=os.path.join(DIST, "index.html"))
        if p.startswith("/keys/"):
            return self.send_error(404)  # Demo-Keys bleiben aus dem öffentlichen Pfad raus
        # Landing bis auf Weiteres offline (Bernd, 15.11.): files liegen weiter in site/
        return self.send_error(404)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = _route

if __name__ == "__main__":
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()

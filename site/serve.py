#!/usr/bin/env python3
# bmail-site: Landing Page (apex) + PWA unter /app/ + Relay-Proxy unter /relay-a|/relay-b.
# Inkl. cookielosem, DSGVO-konformem 100%-anonymem Besucherzaehler (/stats & /stats.json).
import datetime, hashlib, http.client, json, mimetypes, os, posixpath, sqlite3, sys, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, unquote

SITE = "/root/lightningmail/site"
DIST = "/root/lightningmail/client/app/dist"
RELAYS = {"/relay-a": 8443, "/relay-b": 9443}
BIND, PORT = "127.0.0.1", 5180
STATS_DB = os.environ.get("BMAIL_STATS_DB", "/var/lib/bmail/site_stats.db")

_db_lock = threading.Lock()
TRACKED_PATHS = {
    "/": "/",
    "/architecture": "/architecture",
    "/app/": "/app/",
    "/impressum": "/impressum",
    "/lightningmail.apk": "/lightningmail.apk",
    "/lightningmail-linux-amd64": "/lightningmail-linux-amd64",
    "/lightningmail-thunderbird.xpi": "/lightningmail-thunderbird.xpi",
}

def _init_db():
    try:
        os.makedirs(os.path.dirname(STATS_DB), exist_ok=True)
        with sqlite3.connect(STATS_DB) as c:
            c.execute("CREATE TABLE IF NOT EXISTS daily_hits (day TEXT, path TEXT, hits INTEGER DEFAULT 0, PRIMARY KEY(day, path))")
            c.execute("CREATE TABLE IF NOT EXISTS daily_visitors (day TEXT, vhash TEXT, PRIMARY KEY(day, vhash))")
    except Exception:
        pass

_init_db()

def record_hit(handler, canonical_path):
    if handler.command != "GET":
        return
    ua = handler.headers.get("User-Agent", "")
    # offensichtliche Health-Checks von lokalem curl ignorieren
    ip = handler.headers.get("CF-Connecting-IP") or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip() or handler.client_address[0]
    if ip == "127.0.0.1" and ua.startswith("curl/"):
        return
    day = datetime.date.today().isoformat()
    # Tages-Hash (SHA-256 ueber Tag + IP + UA): nicht rueckrechenbar, keine IP-Speicherung, keine Cookies!
    vhash = hashlib.sha256(f"{day}|bmail-anon|{ip}|{ua}".encode("utf-8")).hexdigest()[:20]
    try:
        with _db_lock, sqlite3.connect(STATS_DB) as c:
            c.execute("INSERT INTO daily_hits(day, path, hits) VALUES(?,?,1) ON CONFLICT(day,path) DO UPDATE SET hits=hits+1", (day, canonical_path))
            c.execute("INSERT OR IGNORE INTO daily_visitors(day, vhash) VALUES(?,?)", (day, vhash))
            c.execute("DELETE FROM daily_visitors WHERE day < date('now', '-35 days')")
    except Exception:
        pass

def get_stats():
    out = {"total_hits": 0, "total_unique_daily_visitors": 0, "by_path": {}, "days": []}
    try:
        with _db_lock, sqlite3.connect(STATS_DB) as c:
            for p, h in c.execute("SELECT path, SUM(hits) FROM daily_hits GROUP BY path ORDER BY SUM(hits) DESC"):
                out["by_path"][p] = h
                out["total_hits"] += h
            row = c.execute("SELECT COUNT(*) FROM daily_visitors").fetchone()
            out["total_unique_daily_visitors"] = row[0] if row else 0
            days_hits = {d: h for d, h in c.execute("SELECT day, SUM(hits) FROM daily_hits GROUP BY day ORDER BY day DESC LIMIT 30")}
            days_vis = {d: v for d, v in c.execute("SELECT day, COUNT(*) FROM daily_visitors GROUP BY day")}
            for d in sorted(days_hits.keys(), reverse=True):
                out["days"].append({"day": d, "visitors": days_vis.get(d, 0), "hits": days_hits.get(d, 0)})
    except Exception as e:
        out["error"] = str(e)
    return out

class H(SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _stats_html(self):
        st = get_stats()
        rows_days = "".join(f"<tr><td>{d['day']}</td><td><b>{d['visitors']}</b></td><td>{d['hits']}</td></tr>" for d in st["days"]) or "<tr><td colspan='3'>Noch keine Daten</td></tr>"
        rows_paths = "".join(f"<tr><td><code>{p}</code></td><td><b>{h}</b></td></tr>" for p, h in st["by_path"].items()) or "<tr><td colspan='2'>Noch keine Daten</td></tr>"
        html = f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>lightningmail · Besucherstatistik (cookielos)</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#f5f3ec;color:#122338;margin:0;padding:clamp(16px,4vw,48px)}}
main{{max-width:860px;margin:0 auto}}
h1{{margin:0 0 8px}} .sub{{color:#526377;margin-bottom:24px;font-size:.95rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:28px}}
.card{{background:#fff;border:1px solid #d8d3c4;border-top:4px solid #122338;border-radius:10px;padding:16px 20px}}
.num{{font-size:2rem;font-weight:800;color:#122338}} .lbl{{color:#526377;font-size:.88rem;font-weight:600}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d8d3c4;border-radius:10px;overflow:hidden;margin-bottom:24px}}
th,td{{text-align:left;padding:10px 14px;border-bottom:1px solid #eae6da;font-size:.95rem}}
th{{background:#122338;color:#fff;font-size:.85rem;text-transform:uppercase;letter-spacing:.04em}}
code{{background:#eae6da;padding:2px 6px;border-radius:4px}}
a{{color:#122338;font-weight:600}}
</style></head><body><main>
<h1>⚡ lightningmail.app — Statistik</h1>
<p class="sub">100 % cookielos &amp; ohne Tracking-Profile: gezählt werden nur Seiten-/Download-Abrufe sowie ein nicht rückrechenbarer Tages-Hash (keine IP-Speicherung, keine Cookies).</p>
<div class="cards">
  <div class="card"><div class="num">{st['total_unique_daily_visitors']}</div><div class="lbl">Besucher gesamt (Tages-Uniques)</div></div>
  <div class="card"><div class="num">{st['total_hits']}</div><div class="lbl">Seiten- &amp; Download-Aufrufe</div></div>
  <div class="card"><div class="num">{st['days'][0]['visitors'] if st['days'] else 0} / {st['days'][0]['hits'] if st['days'] else 0}</div><div class="lbl">Heute (Besucher / Aufrufe)</div></div>
</div>
<h2>Tagesverlauf (letzte 30 Tage)</h2>
<table><thead><tr><th>Datum</th><th>Besucher (Unique)</th><th>Aufrufe</th></tr></thead><tbody>{rows_days}</tbody></table>
<h2>Aufrufe &amp; Downloads nach Pfad</h2>
<table><thead><tr><th>Seite / Download</th><th>Aufrufe</th></tr></thead><tbody>{rows_paths}</tbody></table>
<p><a href="/">← Zur Startseite</a> · <a href="/stats.json">JSON-Rohdaten</a></p>
</main></body></html>""".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html)

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
        if p == "/stats.json":
            return self._json(get_stats())
        if p in ("/stats", "/stats/"):
            return self._stats_html()
        for pref, port in RELAYS.items():
            if p == pref or p.startswith(pref + "/"):
                return self._proxy(port)
        if p == "/app" or p.startswith("/app/"):
            if p in ("/app", "/app/", "/app/index.html"):
                record_hit(self, "/app/")
            rel = p[4:] or "/"
            return self._static(DIST, rel, spa=os.path.join(DIST, "index.html"))
        if p in ("/impressum", "/impressum.html", "/imprint"):
            record_hit(self, "/impressum")
            return self._static(SITE, "impressum.html")
        if p in ("/architecture", "/architecture.html", "/architektur"):
            record_hit(self, "/architecture")
            return self._static(SITE, "architecture.html")
        if p.startswith("/keys/"):
            return self.send_error(404)  # Demo-Keys bleiben aus dem öffentlichen Pfad raus
        if p in ("/", "/index.html"):
            record_hit(self, "/")
        elif p in TRACKED_PATHS:
            record_hit(self, TRACKED_PATHS[p])
        return self._static(SITE, p, spa=os.path.join(SITE, "index.html"))

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = _route

if __name__ == "__main__":
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()

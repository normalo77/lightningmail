#!/usr/bin/env python3
# bmail-site: Landing Page (apex) + PWA unter /app/ + Relay-Proxy unter /relay-a|/relay-b.
# Inkl. cookielosem, DSGVO-konformem 100%-anonymem Besucherzaehler (/stats & /stats.json).
import base64, datetime, hashlib, hmac, http.client, json, mimetypes, os, posixpath, secrets, sqlite3, sys, threading, time
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
    "/forum": "/forum",
    "/paywall": "/paywall",
    "/app/": "/app/",
    "/impressum": "/impressum",
    "/lightningmail.apk": "/lightningmail.apk",
    "/lightningmail-linux-amd64": "/lightningmail-linux-amd64",
    "/lightningmail-thunderbird.xpi": "/lightningmail-thunderbird.xpi",
}

# Relay-Ports fuer X-Forum-Token-Verifikation (OIDC-UserInfo)
FORUM_RELAYS = {"alpha": 8443, "beta": 9443}

# 4 Demo-Blabla-Artikel fuer die 5-Sat-Mikro-Paywall
ARTICLES = [
    {"id": "art-1", "price_sats": 5,
     "title": "Blabla-Artikel #1: Das Geheimnis der 5-Satoshi-Schranke",
     "teaser": "Warum kein Mensch für einen einzelnen Artikel ein 14,90-€-Monatsabo abschließt — und was passiert, wenn Lesen genau 5 Satoshis kostet…",
     "content_html": """<p><b>🔓 FREIGESCHALTET (5 Sat bezahlt!):</b> Herzlichen Glückwunsch — du hast gerade für den Gegenwert eines drittel Pfefferkorns eine der ersten Paywalls der Welt überwunden, die dich weder nach deiner Kreditkarte noch nach dem Mädchennamen deiner Großmutter gefragt hat. Klassische Verlage stehen seit 25 Jahren vor demselben Rätsel: Ein einzelner Artikel ist niemandem 14,90 € Monatsabo wert, aber bei 0,01 € Einzelpreis frisst der Zahlungsdienstleister 35 Cent Mindestgebühr und drei Seiten Cookie-Banner.</p>
<div class="art-figs">
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#122338"/>
      <rect x="18" y="24" width="120" height="86" rx="6" fill="#2b161b" stroke="#f87171" stroke-width="1.5"/>
      <text x="78" y="48" fill="#fca5a5" font-size="11" font-weight="bold" text-anchor="middle">Kreditkarte / Abo</text>
      <text x="78" y="70" fill="#fff" font-size="15" font-weight="bold" text-anchor="middle">14,90 € / Monat</text>
      <text x="78" y="92" fill="#fca5a5" font-size="10" text-anchor="middle">+ 35 ct Gebühr + Kündigungsfalle</text>
      <text x="160" y="72" fill="#f4b71a" font-size="18" font-weight="bold" text-anchor="middle">⚡</text>
      <rect x="182" y="24" width="120" height="86" rx="6" fill="#0d3326" stroke="#34d399" stroke-width="1.5"/>
      <text x="242" y="48" fill="#6ee7b7" font-size="11" font-weight="bold" text-anchor="middle">lightningmail OIDC</text>
      <text x="242" y="70" fill="#f4b71a" font-size="16" font-weight="bold" text-anchor="middle">5 Satoshis</text>
      <text x="242" y="92" fill="#a7f3d0" font-size="10" text-anchor="middle">1 Klick · 0 Passwörter · sofort offen</text>
    </svg>
    <figcaption>Abb. 1a: Die große Abo-Keule gegen die 5-Satoshi-Briefmarke.</figcaption>
  </figure>
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#1b2e47"/>
      <circle cx="72" cy="68" r="34" fill="#f4b71a"/>
      <text x="72" y="75" fill="#122338" font-size="22" font-weight="bold" text-anchor="middle">🔑=⚡</text>
      <path d="M118 68 L178 68" stroke="#f4b71a" stroke-width="3" stroke-dasharray="5,4"/>
      <rect x="186" y="34" width="114" height="68" rx="8" fill="#064e3b" stroke="#6ee7b7" stroke-width="1.5"/>
      <text x="243" y="62" fill="#fff" font-size="12" font-weight="bold" text-anchor="middle">ID-Token signiert</text>
      <text x="243" y="82" fill="#6ee7b7" font-size="11" font-family="monospace" text-anchor="middle">paid_sats: 5 ✓</text>
    </svg>
    <figcaption>Abb. 1b: Wenn Login-Schlüssel und Portokasse eins sind.</figcaption>
  </figure>
</div>
<p>Bei lightningmail fällt diese Schranke weg, weil dein OpenID-Connect-Login und deine Portokasse ein und derselbe secp256k1-Schlüssel sind. Wenn eine Webseite beim Login-Aufruf <code>pay_sats=5&amp;pay_item=art-1</code> mitschickt, fragt dein Postfach dich in einem einzigen Fenster: <i>„Einloggen und 5 Satoshis bezahlen?"</i> — und liefert die kryptographisch signierte Zahlungsquittung direkt im OIDC-Token mit aus.</p>
<p><b>Blabla-Fazit #1:</b> Kein Mensch liest gerne AGBs für einen 3-Minuten-Text. Aber 5 Satoshis aus der Portokasse schnippen, ohne einen Account mit Passwort anzulegen? Das klickt man schneller weg als früher den „Cookies ablehnen"-Knopf.</p>"""},
    {"id": "art-2", "price_sats": 5,
     "title": "Blabla-Artikel #2: Bekenntnisse eines Spam-Bots im Jahr 2026",
     "teaser": "Ich wollte gestern 100.000 Werbemails verschicken, aber mein Kontostand fiel nach 3 Sekunden auf Null…",
     "content_html": """<p><b>🔓 FREIGESCHALTET (5 Sat bezahlt!):</b> Mein Name ist <code>mailer-daemon-bot-9000</code> und ich bin seit heute Morgen arbeitslos. Früher war mein Leben herrlich: Mein Betreiber hat für vier Dollar eine gebrauchte Cloud-IP gemietet, und ich habe vor dem Frühstück zehn Millionen Mails über billige Rolex-Uhren, verliebte Prinzen und dringende Paketgebühren in die Welt geblasen. Selbst wenn 99,99 % im Spamfilter starben, hat sich der Müll ab dem zehnten Klick gerechnet.</p>
<div class="art-figs">
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#122338"/>
      <text x="160" y="24" fill="#cbd5e1" font-size="10.5" font-weight="bold" text-anchor="middle">Kontostand Spam-Bot #9000 (10 Sat / Mail)</text>
      <polyline points="28,42 95,48 145,75 195,105 285,108" fill="none" stroke="#f87171" stroke-width="3.5"/>
      <circle cx="195" cy="105" r="5" fill="#f4b71a"/>
      <line x1="28" y1="108" x2="295" y2="108" stroke="#475569" stroke-width="1"/>
      <text x="195" y="92" fill="#fde68a" font-size="10" font-weight="bold" text-anchor="middle">HTTP 402: Pleite nach 3 Sek.</text>
      <text x="32" y="122" fill="#94a3b8" font-size="9">08:00:00</text>
      <text x="255" y="122" fill="#94a3b8" font-size="9">08:00:03</text>
    </svg>
    <figcaption>Abb. 2a: Finanzielle Lebenserwartung eines Spammers mit Vorkasse-Porto.</figcaption>
  </figure>
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#1b2e47"/>
      <text x="80" y="42" fill="#6ee7b7" font-size="11" font-weight="bold" text-anchor="middle">Echter Dialog</text>
      <text x="80" y="68" fill="#fff" font-size="12.5" text-anchor="middle">Alice ⇄ Bob</text>
      <text x="80" y="92" fill="#a7f3d0" font-size="9.5" text-anchor="middle">±0 Sat Netto</text>
      <text x="80" y="106" fill="#a7f3d0" font-size="8.5" text-anchor="middle">(Porto fließt zurück)</text>
      <line x1="160" y1="20" x2="160" y2="116" stroke="#334155" stroke-width="1.5"/>
      <text x="240" y="42" fill="#fca5a5" font-size="11" font-weight="bold" text-anchor="middle">Massen-Spam</text>
      <text x="240" y="68" fill="#fff" font-size="12.5" text-anchor="middle">Bot ⇒ 100.000 User</text>
      <text x="240" y="92" fill="#f87171" font-size="9.5" text-anchor="middle">−1.000.000 Sat</text>
      <text x="240" y="106" fill="#fca5a5" font-size="8.5" text-anchor="middle">(0 Antworten!)</text>
    </svg>
    <figcaption>Abb. 2b: Warum höfliche Menschen umsonst mailen und Bots bluten.</figcaption>
  </figure>
</div>
<p>Gestern sollte ich das Gleiche auf lightningmail probieren. Schon beim ersten Empfänger wollte das Relay 10 Satoshis Porto sehen. Nach 1.000 Mails waren 10.000 Satoshis weg — und weil kein einziger Empfänger einem Spam-Bot antwortet, floss kein einziger Satoshi zurück! Stattdessen haben sich die Empfänger über mein geschenktes Porto gefreut und sich davon hier im Forum Blabla-Artikel gekauft.</p>
<p><b>Blabla-Fazit #2:</b> Dreißig Jahre lang haben Menschen versucht, Spam mit KI-Filtern, Blacklists und DNS-Magie zu erraten. Dabei hat Adam Back schon 1997 mit Hashcash gewusst: Man muss dem Briefumschlag nur wieder eine Briefmarke aufkleben.</p>"""},
    {"id": "art-3", "price_sats": 5,
     "title": "Blabla-Artikel #3: Warum dein Steuerberater noch Faxgeräte liebt",
     "teaser": "Ein tiefer Blick in die Abgründe von S/MIME-Zertifikaten, abgelaufenen PGP-Keys und Passwort-ZIP-Dateien…",
     "content_html": """<p><b>🔓 FREIGESCHALTET (5 Sat bezahlt!):</b> Frag einmal deinen Steuerberater, Rechtsanwalt oder Hausarzt, ob du ihm ein vertrauliches PDF per verschlüsselter E-Mail schicken darfst. In 9 von 10 Fällen herrscht erst betretenes Schweigen, dann folgt entweder die Bitte um ein Telefax oder du bekommst eine unverschlüsselte Mail mit einer <code>Geheim.zip</code> — und zwei Minuten später eine zweite unverschlüsselte Mail mit dem Text: <i>„Das Passwort für die ZIP-Datei lautet übrigens Steuer2026!"</i></p>
<div class="art-figs">
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#122338"/>
      <text x="160" y="25" fill="#fca5a5" font-size="11" font-weight="bold" text-anchor="middle">Klassische E-Mail-Verschlüsselung (PGP / S/MIME)</text>
      <rect x="16" y="40" width="84" height="68" rx="6" fill="#2b161b" stroke="#f87171"/>
      <text x="58" y="68" fill="#fff" font-size="10" text-anchor="middle">Keyserver</text>
      <text x="58" y="84" fill="#fca5a5" font-size="9" text-anchor="middle">nicht gefunden</text>
      <rect x="118" y="40" width="84" height="68" rx="6" fill="#2b161b" stroke="#f87171"/>
      <text x="160" y="68" fill="#fff" font-size="10" text-anchor="middle">Zertifikat</text>
      <text x="160" y="84" fill="#fca5a5" font-size="9" text-anchor="middle">abgelaufen 2021</text>
      <rect x="220" y="40" width="84" height="68" rx="6" fill="#2b161b" stroke="#f87171"/>
      <text x="262" y="68" fill="#fff" font-size="10" text-anchor="middle">Notlösung:</text>
      <text x="262" y="84" fill="#fde68a" font-size="9" text-anchor="middle">Faxgerät 📠</text>
    </svg>
    <figcaption>Abb. 3a: Warum Ende-zu-Ende-Verschlüsselung im Büroalltag fast immer scheitert.</figcaption>
  </figure>
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#0d3326"/>
      <text x="160" y="26" fill="#6ee7b7" font-size="11" font-weight="bold" text-anchor="middle">lightningmail: Unsichtbare Pflicht-Verschlüsselung</text>
      <rect x="24" y="42" width="272" height="68" rx="8" fill="#064e3b" stroke="#34d399" stroke-width="1.5"/>
      <text x="160" y="66" fill="#fff" font-size="12" font-weight="bold" text-anchor="middle">Adresse tippen → Senden klicken</text>
      <text x="160" y="86" fill="#a7f3d0" font-size="10" font-family="monospace" text-anchor="middle">GET /v1/profile → ECIES + XChaCha20-Poly1305</text>
      <text x="160" y="102" fill="#fde68a" font-size="10" text-anchor="middle">Es gibt keinen „Unverschlüsselt senden"-Knopf!</text>
    </svg>
    <figcaption>Abb. 3b: Wenn das Protokoll gar keinen Klartext-Modus mehr kennt.</figcaption>
  </figure>
</div>
<p>Das liegt nicht daran, dass Steuerberater schlechte Menschen sind, sondern daran, dass nachträglich aufgeklebte Verschlüsselung auf ein Klartext-Protokoll von 1982 (SMTP) eine Zumutung ist: Keyserver-Suche, Fingerabdruck-Abgleich am Telefon, abgelaufene S/MIME-Zertifikate und kaputte Outlook-Plugins.</p>
<p><b>Blabla-Fazit #3:</b> Bei lightningmail existiert überhaupt kein Schalter für „unverschlüsselt". Du tippst <code>steuerberater@kanzlei.de</code>, der Client holt sich im Hintergrund per <code>GET /v1/profile/steuerberater</code> den 33-Byte-Schlüssel und verschlüsselt Text wie Anhänge automatisch Ende-zu-Ende. Fertig.</p>"""},
    {"id": "art-4", "price_sats": 5,
     "title": "Blabla-Artikel #4: Die große Blabla-Abhandlung über Kaffeepausen & Satoshis",
     "teaser": "Dieser vierte Artikel enthält garantiert 100 % offensichtliches Blabla — kostet zum Testen aber trotzdem exakt 5 Satoshis…",
     "content_html": """<p><b>🔓 FREIGESCHALTET (5 Sat bezahlt!):</b> <i>Lorem ipsum dolor sit Satoshi, consectetur Lightning elit!</i> Du hast es tatsächlich getan: Obwohl die Überschrift dich ausdrücklich vor 100 % offensichtlichem Blabla gewarnt hat, hast du auch noch den vierten Artikel für 5 Satoshis freigeschaltet. Das beweist wissenschaftlich zweierlei: Erstens ist der menschliche Spieltrieb unbesiegbar, und zweitens tut eine 5-Satoshi-Mikrozahlung überhaupt nicht weh.</p>
<div class="art-figs">
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#122338"/>
      <text x="160" y="26" fill="#fde68a" font-size="11" font-weight="bold" text-anchor="middle">Dein Regtest-Portokassen-Kuchen (10.000 Sat Start)</text>
      <circle cx="95" cy="76" r="40" fill="#34d399"/>
      <path d="M95 76 L95 36 A40 40 0 0 1 98 36.2 Z" fill="#f4b71a"/>
      <text x="210" y="62" fill="#6ee7b7" font-size="12" font-weight="bold" text-anchor="middle">9.980 Sat übrig (99,8 %)</text>
      <text x="210" y="82" fill="#f4b71a" font-size="11" text-anchor="middle">20 Sat für alle 4 Blabla-Artikel</text>
      <text x="210" y="102" fill="#94a3b8" font-size="10" text-anchor="middle">Reicht noch für ~998 Briefe!</text>
    </svg>
    <figcaption>Abb. 4a: Selbst nach allen 4 Artikeln ist deine Test-Portokasse noch zu 99,8 % voll.</figcaption>
  </figure>
  <figure class="art-fig">
    <svg viewBox="0 0 320 135" xmlns="http://www.w3.org/2000/svg">
      <rect width="320" height="135" rx="8" fill="#1b2e47"/>
      <text x="160" y="45" fill="#fff" font-size="26" text-anchor="middle">☕ + ⚡ + ✉️ = 🎉</text>
      <text x="160" y="78" fill="#fde68a" font-size="12" font-weight="bold" text-anchor="middle">Offizielles Blabla-Diplom verliehen</text>
      <text x="160" y="100" fill="#cbd5e1" font-size="10" text-anchor="middle">Geprüfter Tester der lightningmail-Mikro-Paywall</text>
    </svg>
    <figcaption>Abb. 4b: Urkunde für vollständiges Durchspielen der 5-Sat-Paywall.</figcaption>
  </figure>
</div>
<p>Rechnen wir kurz nach: Jedes neue Testkonto bekommt in unserer 60-tägigen Regtest-Phase bis zum Mainnet-Start 10.000 Test-Satoshis Startguthaben. Selbst wenn du alle vier Blabla-Artikel hier freigeschaltet hast, hast du gerade einmal 20 Satoshis verbraucht — es sind also noch stolze 9.980 Satoshis in deiner Portokasse übrig.</p>
<p><b>Blabla-Fazit #4:</b> Genug gelesen! Schreib oben im Forum einen Beitrag (kryptographisch signiert mit deinem Mailbox-Key) oder klick bei einem anderen Forenbeitrag auf <i>„✉ Per lightningmail anschreiben"</i> und schick ihm für 10 Satoshis einen echten Ende-zu-Ende-verschlüsselten Brief.</p>"""},
]

def _init_db():
    try:
        os.makedirs(os.path.dirname(STATS_DB), exist_ok=True)
        with sqlite3.connect(STATS_DB) as c:
            c.execute("CREATE TABLE IF NOT EXISTS daily_hits (day TEXT, path TEXT, hits INTEGER DEFAULT 0, PRIMARY KEY(day, path))")
            c.execute("CREATE TABLE IF NOT EXISTS daily_visitors (day TEXT, vhash TEXT, PRIMARY KEY(day, vhash))")
            c.execute("CREATE TABLE IF NOT EXISTS unique_ips (iphash TEXT PRIMARY KEY, first_day TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS bot_hits (day TEXT PRIMARY KEY, hits INTEGER DEFAULT 0)")
            c.execute("CREATE TABLE IF NOT EXISTS forum_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, author TEXT, pubkey TEXT, relay TEXT, title TEXT, body TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS paywall_unlocks (address TEXT, item_id TEXT, ts INTEGER, sats INTEGER, PRIMARY KEY(address, item_id))")
            if c.execute("SELECT COUNT(*) FROM forum_posts").fetchone()[0] == 0:
                c.execute("INSERT INTO forum_posts(ts,author,pubkey,relay,title,body) VALUES(?,?,?,?,?,?)",
                          (int(time.time()), "bernd@lightningmail.app", "029eff8e7a9104be", "alpha",
                           "Willkommen im lightningmail-Forum (Sign in with lightningmail)",
                           "Jeder Beitrag hier ist mit einem echten Mailbox-Key über OpenID Connect (BIP340-Challenge) signiert. Neue Konten starten in der Regtest-Phase mit 10.000 Test-Satoshis — probiert unten auch die 5-Sat-Paywall aus!"))
    except Exception:
        pass

_init_db()

BOT_KEYWORDS = (
    "bot", "crawl", "spider", "slurp", "curl/", "wget/", "python-requests", "python-urllib",
    "go-http-client", "headlesschrome", "lighthouse", "censys", "zgrab", "masscan", "nmap",
    "uptimerobot", "pingdom", "statuscake", "ahrefs", "semrush", "mj12bot", "dotbot",
    "bytespider", "gptbot", "claudebot", "bingpreview", "facebookexternalhit", "whatsapp",
    "telegrambot", "discordbot", "twitterbot"
)

def is_human_ua(ua: str) -> bool:
    u = (ua or "").lower()
    if len(u) < 25 or "mozilla/5.0" not in u:
        return False
    return not any(k in u for k in BOT_KEYWORDS)

def record_hit(handler, canonical_path):
    if handler.command != "GET":
        return
    ua = handler.headers.get("User-Agent", "")
    ip = handler.headers.get("CF-Connecting-IP") or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip() or handler.client_address[0]
    if ip in ("127.0.0.1", "::1") or ip.startswith("192.168."):
        return
    day = datetime.date.today().isoformat()
    if not is_human_ua(ua):
        try:
            with _db_lock, sqlite3.connect(STATS_DB) as c:
                c.execute("INSERT INTO bot_hits(day, hits) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET hits=hits+1", (day,))
        except Exception:
            pass
        return
    # Cookielos & DSGVO-sauber: Einweg-SHA256-Hashes ohne Klartext-IP-Speicherung
    vhash = hashlib.sha256(f"{day}|bmail-anon|{ip}|{ua}".encode("utf-8")).hexdigest()[:20]
    iphash = hashlib.sha256(f"bmail-unique-ip-v1|{ip}".encode("utf-8")).hexdigest()[:24]
    try:
        with _db_lock, sqlite3.connect(STATS_DB) as c:
            c.execute("INSERT INTO daily_hits(day, path, hits) VALUES(?,?,1) ON CONFLICT(day,path) DO UPDATE SET hits=hits+1", (day, canonical_path))
            c.execute("INSERT OR IGNORE INTO daily_visitors(day, vhash) VALUES(?,?)", (day, vhash))
            c.execute("INSERT OR IGNORE INTO unique_ips(iphash, first_day) VALUES(?,?)", (iphash, day))
            c.execute("DELETE FROM daily_visitors WHERE day < date('now', '-35 days')")
    except Exception:
        pass

def get_stats():
    out = {"total_hits": 0, "total_unique_ips": 0, "total_unique_daily_visitors": 0, "filtered_bot_hits": 0, "by_path": {}, "days": []}
    try:
        with _db_lock, sqlite3.connect(STATS_DB) as c:
            for p, h in c.execute("SELECT path, SUM(hits) FROM daily_hits GROUP BY path ORDER BY SUM(hits) DESC"):
                out["by_path"][p] = h
                out["total_hits"] += h
            row = c.execute("SELECT COUNT(*) FROM daily_visitors").fetchone()
            out["total_unique_daily_visitors"] = row[0] if row else 0
            row_ip = c.execute("SELECT COUNT(*) FROM unique_ips").fetchone()
            out["total_unique_ips"] = row_ip[0] if row_ip else 0
            row_bot = c.execute("SELECT COALESCE(SUM(hits),0) FROM bot_hits").fetchone()
            out["filtered_bot_hits"] = row_bot[0] if row_bot else 0
            days_hits = {d: h for d, h in c.execute("SELECT day, SUM(hits) FROM daily_hits GROUP BY day ORDER BY day DESC LIMIT 30")}
            days_vis = {d: v for d, v in c.execute("SELECT day, COUNT(*) FROM daily_visitors GROUP BY day")}
            for d in sorted(days_hits.keys(), reverse=True):
                out["days"].append({"day": d, "visitors": days_vis.get(d, 0), "hits": days_hits.get(d, 0)})
    except Exception as e:
        out["error"] = str(e)
    return out

class H(SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
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
  <div class="card"><div class="num">{st['total_unique_ips']}</div><div class="lbl">Verschiedene IPs (echte Browser, ohne Bots)</div></div>
  <div class="card"><div class="num">{st['total_unique_daily_visitors']}</div><div class="lbl">Tages-Besucher (Uniques)</div></div>
  <div class="card"><div class="num">{st['total_hits']}</div><div class="lbl">Seiten- &amp; Download-Aufrufe</div></div>
  <div class="card"><div class="num">{st['filtered_bot_hits']}</div><div class="lbl">Gefilterte Bot-/Scanner-Anfragen</div></div>
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

    # --- Forum + 5-Sat-Paywall (OIDC-Mikrozahlung) ---

    @staticmethod
    def _forum_secret():
        kp = os.path.join(os.path.dirname(STATS_DB), "forum_hmac.key")
        try:
            if os.path.isfile(kp):
                return open(kp, "rb").read()
            os.makedirs(os.path.dirname(kp), exist_ok=True)
            k = secrets.token_bytes(32)
            with open(kp, "wb") as f:
                f.write(k)
            os.chmod(kp, 0o600)
            return k
        except Exception:
            return b"bmail-forum-fallback-key"

    def _mint_forum_session(self, u):
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": u["sub"], "pubkey": u.get("pubkey", ""), "relay": u.get("relay", "alpha"),
            "exp": int(time.time()) + 30 * 86400
        }).encode("utf-8")).decode("ascii").rstrip("=")
        sig = hmac.new(self._forum_secret(), payload.encode("ascii"), hashlib.sha256).hexdigest()
        return f"fses:{payload}.{sig}"

    def _verify_forum_token(self):
        """X-Forum-Token 'fses:...' (persistent) oder 'alpha|beta:ACCESS_TOKEN' gegen /oidc/userinfo pruefen.
        Nebenwirkung: bezahlte Paywall (paid_sats>=5) als Unlock verbuchen.
        Return {sub,pubkey,relay,session_token?} oder None."""
        hdr = self.headers.get("X-Forum-Token", "")
        if hdr.startswith("fses:"):
            try:
                body = hdr[5:]
                payload, _, sig = body.partition(".")
                exp_sig = hmac.new(self._forum_secret(), payload.encode("ascii"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, exp_sig):
                    return None
                pad = "=" * ((4 - len(payload) % 4) % 4)
                j = json.loads(base64.urlsafe_b64decode(payload + pad))
                if int(j.get("exp") or 0) < int(time.time()) or not j.get("sub"):
                    return None
                return {"sub": j["sub"], "pubkey": j.get("pubkey", ""), "relay": j.get("relay", "alpha")}
            except Exception:
                return None
        relay, _, tok = hdr.partition(":")
        port = FORUM_RELAYS.get(relay)
        if not port or not tok:
            return None
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            h = {}
            h["Auth" + "orization"] = "Bearer " + tok
            conn.request("GET", "/oidc/userinfo", headers=h)
            r = conn.getresponse()
            data = json.loads(r.read() or b"{}")
            conn.close()
            if r.status != 200 or not data.get("sub"):
                return None
            bm = data.get("bmail") or {}
            if bm.get("paid_item") and (bm.get("paid_sats") or 0) >= 5:
                try:
                    with _db_lock, sqlite3.connect(STATS_DB) as c:
                        c.execute("INSERT OR IGNORE INTO paywall_unlocks(address,item_id,ts,sats) VALUES(?,?,?,?)",
                                  (data["sub"], bm["paid_item"], int(time.time()), bm.get("paid_sats") or 0))
                except Exception:
                    pass
            u = {"sub": data["sub"], "pubkey": bm.get("pubkey", ""), "relay": relay}
            u["session_token"] = self._mint_forum_session(u)
            return u
        except Exception:
            return None

    def _api_forum(self):
        u = self._verify_forum_token()
        user = u["sub"] if u else None
        posts, arts = [], []
        try:
            with _db_lock, sqlite3.connect(STATS_DB) as c:
                for row in c.execute("SELECT id,ts,author,pubkey,relay,title,body FROM forum_posts ORDER BY id DESC LIMIT 50"):
                    posts.append({"id": row[0], "ts": row[1], "author": row[2], "pubkey": row[3], "relay": row[4], "title": row[5], "body": row[6]})
                for a in ARTICLES:
                    unlocked = bool(user) and c.execute(
                        "SELECT 1 FROM paywall_unlocks WHERE address=? AND item_id=?", (user, a["id"])).fetchone() is not None
                    d = {"id": a["id"], "price_sats": a["price_sats"], "title": a["title"], "teaser": a["teaser"], "unlocked": bool(unlocked)}
                    if unlocked:
                        d["content_html"] = a["content_html"]
                    arts.append(d)
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        resp = {"user": user, "relay": u.get("relay") if u else None, "posts": posts, "articles": arts}
        if u and u.get("session_token"):
            resp["session_token"] = u["session_token"]
        self._json(resp)

    def _api_forum_post(self):
        u = self._verify_forum_token()
        if not u:
            return self._json({"error": "X-Forum-Token fehlt oder ungueltig"}, 401)
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(ln, 65536)) or b"{}")
        except Exception:
            return self._json({"error": "body unlesbar"}, 400)
        title = str(body.get("title") or "").strip()
        txt = str(body.get("body") or "").strip()
        if not (1 <= len(title) <= 120) or not (1 <= len(txt) <= 2000):
            return self._json({"error": "title 1..120 Zeichen, body 1..2000 Zeichen"}, 400)
        try:
            with _db_lock, sqlite3.connect(STATS_DB) as c:
                c.execute("INSERT INTO forum_posts(ts,author,pubkey,relay,title,body) VALUES(?,?,?,?,?,?)",
                          (int(time.time()), u["sub"], u["pubkey"], u["relay"], title, txt))
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        self._json({"ok": True})

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
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; img-src 'self' data: blob:; font-src 'self' data:; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _proxy(self, port):
        if self.command == "OPTIONS":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Relay-Secret")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
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
        if p == "/api/forum" and self.command == "GET":
            return self._api_forum()
        if p == "/api/forum/post" and self.command == "POST":
            return self._api_forum_post()
        if p in ("/forum", "/forum/", "/forum.html"):
            record_hit(self, "/forum")
            return self._static(SITE, "forum.html")
        if p in ("/paywall", "/paywall/", "/paywall.html"):
            record_hit(self, "/paywall")
            return self._static(SITE, "paywall.html")
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

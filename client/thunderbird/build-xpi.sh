#!/usr/bin/env bash
# build-xpi.sh — baut die PWA und paketiert site/lightningmail-thunderbird.xpi.
# Laeuft dort, wo vite funktioniert (CT113; lokal mit Node >= 18).
# SKIP_BUILD=1 paketiert das vorhandene client/app/dist ohne Neubau.
set -euo pipefail
cd "$(dirname "$0")"                 # client/thunderbird
APP="$(cd ../app && pwd)"            # client/app
ROOT="$(cd ../.. && pwd)"            # Repo-Wurzel
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ "${SKIP_BUILD:-0}" = "1" ] || ( cd "$APP" && npx vite build )
[ -f "$APP/dist/index.html" ] || { echo "✗ kein $APP/dist — erst bauen (ohne SKIP_BUILD=1)"; exit 1; }

# Staging: dist/ -> app/
mkdir -p "$STAGE/app"
cp -r "$APP/dist/." "$STAGE/app/"
# Demo-Keys gehoeren nicht ins Add-on (und /keys/ gibt es in moz-extension:// nicht)
rm -rf "$STAGE/app/keys"

# absolute /app/-Asset-Pfade -> relativ (vite base './' liefert sie schon relativ;
# der sed bleibt als Netz, falls base je auf /app/ gestellt wird)
find "$STAGE/app" -name '*.html' -exec sed -i 's#"/app/#"./#g' {} +

python3 - "$STAGE/app/index.html" <<'PY'
import sys
p = sys.argv[1]
h = open(p, encoding="utf-8").read()
# Relay-Optionen: Thunderbird hat keinen /relay-* Proxy -> absolute URLs
h = h.replace('value="/relay-a"', 'value="https://lightningmail.app/relay-a"')
h = h.replace('value="/relay-b"', 'value="https://lightningmail.app/relay-b"')
# Impressum: relativer Serverpfad existiert im Add-on nicht
h = h.replace('href="/impressum"', 'href="https://lightningmail.app/impressum"')
# Eigenes Relay: dritte Option, fragt eine URL ab und merkt sie sich
custom = """<script>
(function () {
  var s = document.getElementById("l-relay");
  if (!s) return;
  var KEY = "lm_tb_" + "custom_relay";
  var saved = localStorage.getItem(KEY);
  var other = document.createElement("option");
  other.value = "__custom";
  other.textContent = "Anderes Relay\\u2026 (URL)";
  if (saved) {
    var c = document.createElement("option");
    c.value = saved; c.textContent = saved;
    s.insertBefore(c, other);
  }
  s.appendChild(other);
  s.addEventListener("change", function () {
    if (s.value !== "__custom") return;
    var u = prompt("Relay-URL (https://\\u2026):", localStorage.getItem(KEY) || "https://");
    if (!u) { s.selectedIndex = 0; return; }
    u = u.replace(/\\/+$/, "");
    localStorage.setItem(KEY, u);
    var c2 = document.createElement("option");
    c2.value = u; c2.textContent = u;
    s.insertBefore(c2, other);
    s.value = u;
  });
})();
</script>
</body>"""
assert "</body>" in h
h = h.replace("</body>", custom)
open(p, "w", encoding="utf-8").write(h)
print("index.html: Relay-Optionen + Custom-Relay-Skript gesetzt")
PY

cp manifest.json background.js icon.svg "$STAGE/"
mkdir -p "$ROOT/site"
OUT="$ROOT/site/lightningmail-thunderbird.xpi"
rm -f "$OUT"
( cd "$STAGE" && python3 -m zipfile -c "$OUT" manifest.json background.js icon.svg app )
echo "✓ $OUT ($(du -h "$OUT" | cut -f1))"
python3 -m zipfile -l "$OUT" | head -12

#!/usr/bin/env bash
# build-xpi.sh — builds the PWA and packages site/lightningmail-thunderbird.xpi.
# Runs wherever vite works (CT113; locally with Node >= 18).
# SKIP_BUILD=1 packages the existing client/app/dist without rebuilding.
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
# demo keys must not ship inside the add-on (and /keys/ does not exist under moz-extension://)
rm -rf "$STAGE/app/keys"

# absolute /app/ asset paths -> relative (vite base './' already emits them relative;
# the sed stays as a safety net in case base is ever set to /app/)
find "$STAGE/app" -name '*.html' -exec sed -i 's#"/app/#"./#g' {} +

python3 - "$STAGE/app/index.html" <<'PY'
import sys
p = sys.argv[1]
h = open(p, encoding="utf-8").read()
# Relay-Optionen: Thunderbird hat keinen /relay-* Proxy -> absolute URLs
h = h.replace('value="/relay-a"', 'value="https://lightningmail.app/relay-a"')
h = h.replace('value="/relay-b"', 'value="https://lightningmail.app/relay-b"')
# impressum: the relative server path does not exist inside the add-on
h = h.replace('href="/impressum"', 'href="https://lightningmail.app/impressum"')
h = h.replace('href="/forum"', 'href="https://lightningmail.app/forum"')
h = h.replace('href="/paywall"', 'href="https://lightningmail.app/paywall"')
# own relay: third dropdown option, asks for a URL and remembers it
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

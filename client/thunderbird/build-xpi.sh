#!/usr/bin/env bash
# build-xpi.sh — builds the PWA and packages site/lightningmail-thunderbird.xpi.
# Runs wherever vite works (dev-relay; locally with Node >= 18).
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
import re, sys
p = sys.argv[1]
h = open(p, encoding="utf-8").read()
# Relay options: Thunderbird has no local /relay-* proxy -> absolute URLs
h = h.replace('value="/relay-a"', 'value="https://lightningmail.app/relay-a"')
h = h.replace('value="/relay-b"', 'value="https://lightningmail.app/relay-b"')
# Relative site links do not exist inside moz-extension://
for path in ("/impressum", "/forum", "/paywall", "/architecture", "/"):
    h = h.replace(f'href="{path}"', f'href="https://lightningmail.app{path}"')
assert 'value="https://lightningmail.app/relay-a"' in h, "relay-a rewrite failed"
assert "</body>" in h, "missing </body>"
# Load external custom-relay.js (Thunderbird MV2 CSP blocks inline <script>)
h = h.replace("</body>", '<script src="./custom-relay.js" defer></script>\n</body>')
assert not re.search(r'<script(?![^>]*\bsrc=)[^>]*>', h, re.I), "inline <script> forbidden by Thunderbird CSP"
open(p, "w", encoding="utf-8").write(h)
print("index.html: Relay-Optionen + externes custom-relay.js gesetzt (CSP-safe)")
PY

cp custom-relay.js "$STAGE/app/custom-relay.js"
cp manifest.json background.js icon.svg "$STAGE/"
mkdir -p "$ROOT/site"
OUT="$ROOT/site/lightningmail-thunderbird.xpi"
rm -f "$OUT"
( cd "$STAGE" && python3 -m zipfile -c "$OUT" manifest.json background.js icon.svg app )
echo "✓ $OUT ($(du -h "$OUT" | cut -f1))"
python3 -m zipfile -l "$OUT" | head -12

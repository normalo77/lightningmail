#!/usr/bin/env bash
# M2b GUI evidence (CT114): live reader actions + reply (B4), draft button
# (B2), read-sync (B3) — xdotool-driven on Xvfb. Run FROM desktop/:
#   bash scripts/run-m2b.sh b4|b5   (screenshots+logs land in $EV)
# Inner/outer split: xvfb-run sets DISPLAY -> this same script runs the body.
set -u
cd "$(dirname "$0")/.."
EV=cmd/lmdesk/evidence
PH=${1:-b4}
CFG=$EV/m2b-config-b.json; [ "$PH" = b5 ] && CFG=$EV/m2b-config-b5.json
LOG=$EV/m2b-$PH.log

# click/type/screenshot helpers — window sits at 0,0 of the 1280x800 screen
X() { xdotool mousemove "$1" "$2" click 1; sleep "${3:-1}"; }
T() { xdotool type --clearmodifiers --delay 40 "$1"; sleep 0.5; }
S() { import -window root "$EV/$1"; echo "SHOT $1"; }
W() { for _ in $(seq 40); do grep -q "$1" $LOG 2>/dev/null && return 0; sleep 1; done; echo "WARN: '$1' nicht im Log"; }

b4() {
  S m2b-b4-0-inbox.png
  X 405 76 3                                # Mail oeffnen -> B3 read-flag
  S m2b-b4-1-gelesen.png
  W "openMail"
  X 659 73 2                                # Antworten
  S m2b-b4-2-reply.png
  X 600 330 1                               # Body-Feld im Dialog
  T 'Danke fuer den Anhang!'
  X 852 588 1                               # Senden
  W "send ok"
  S m2b-b4-3-gesendet.png
  X 74 30 2                                 # Schreiben
  X 620 150 1                               # An-Feld
  T 'irgendwer'
  X 620 190 1                               # Betreff-Feld
  T 'M2B-Entwurf Test'
  X 600 330 1                               # Body
  T 'Entwurf aus dem GUI-Flow.'
  X 740 588 2                               # Als Entwurf speichern
  W "entwurf gespeichert"
  X 115 149 2                               # Ordner Entwürfe
  S m2b-b2-entwuerfe.png
  X 115 73 1                                # zurueck zu Posteingang
  sleep 8                                   # debounced Push (5s) ausloesen
  W "push ok"
}

b5() {
  S m2b-b5-0-dialog.png
  T 'falsche-passage'
  xdotool key Return; sleep 1
  S m2b-b5-1-fehler.png
  xdotool key ctrl+a; xdotool key Delete
  T "${LMKEY_PASS_EXPECTED:-test1234wort}"
  xdotool key Return
  W "Keyfile entsperrt"
  sleep 8
  S m2b-b5-2-angemeldet.png
}

if [ -n "${DISPLAY:-}" ]; then           # ---- inner: X is up ----
  export GSK_RENDERER=cairo WEBKIT_DISABLE_COMPOSITING_MODE=1
  export LIBGL_ALWAYS_SOFTWARE=1 WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
  export LMDESK_DEMO=0
  LMDESK_CONFIG=$CFG ./bin/lmdesk > $LOG 2>&1 &
  LPID=$!
  trap 'kill $LPID 2>/dev/null; pkill -f "bin/lmdesk" 2>/dev/null; true' EXIT
  sleep 10
  $PH
  exit 0
fi                                        # ---- outer: start Xvfb ----
dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash "$0" "$PH"
echo "M2B_${PH}_DONE"

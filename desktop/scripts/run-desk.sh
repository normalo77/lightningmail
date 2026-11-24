#!/usr/bin/env bash
# M1b evidence run (auf dev-sandbox): tunnel check -> build -> optional seed ->
# Xvfb-Screenshots @8s/@20s + DOM-Check-Pass -> cmd/lmdesk/evidence/.
# Run:  bash scripts/run-desk.sh [--seed]     (from the desktop/ directory)
set -euo pipefail
cd "$(dirname "$0")/.."
EV=cmd/lmdesk/evidence
mkdir -p "$EV" bin

export CGO_ENABLED=0
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

bash scripts/tunnel.sh start

echo "== go build ./cmd/lmdesk =="
go build -o bin/lmdesk ./cmd/lmdesk
echo BUILD_OK

if [ "${1:-}" = "--seed" ]; then
  echo "== seed inbox (throwaway account) =="
  go run scripts/seed-inbox.go 2>&1 | tee "$EV/seed.log"
fi

rm -f "$EV"/shot-*.png "$EV"/lmdesk.log "$EV"/domcheck.log
echo "== evidence pass (screenshots @8s/@20s) =="
dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash scripts/xvfb-inner.sh 2>&1 | tee "$EV/lmdesk.log"

echo "== domcheck pass (A2 DOM-Inspektion, JS nur hier an) =="
LMDESK_DOMCHECK=1 dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash scripts/xvfb-inner.sh 2>&1 | tee "$EV/domcheck.log"

echo "== done: $EV =="
ls -la "$EV"

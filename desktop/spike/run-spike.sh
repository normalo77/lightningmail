#!/usr/bin/env bash
# M0-Spike: baut das Binary CGO-frei und faengt Screenshot + Log unter Xvfb.
# Aufruf: bash spike/run-spike.sh   (aus dem Verzeichnis desktop/)
set -euo pipefail
cd "$(dirname "$0")/.."

export CGO_ENABLED=0
echo "== go build ./... (CGO disabled) =="
go build -o /dev/null ./...
go build -o spike/bin/lm-spike ./spike
echo "BUILD_OK"

mkdir -p spike/evidence spike/bin
rm -f spike/evidence/screenshot.png spike/evidence/spike.log

# Xvfb + inneres Skript: Binary starten, 7s rendern lassen, screenshot, kill.
# dbus-run-session: der systemd-Userbus auf CT114 haengt g_application_register auf.
dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash spike/xvfb-inner.sh | tee spike/evidence/spike.log
echo "== exit inner: $? =="

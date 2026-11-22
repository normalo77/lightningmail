#!/usr/bin/env bash
# M3 evidence run (CT114): throwaway desktop account seeded via LMDESK_M3DEMO
# -> screenshots of Adressbuch / Laufwerk / Einstellungen(Umsaetze).
# Prereq: scripts/tunnel.sh up, /root/lm-m3-desktop.key + env ACCT set.
# Run FROM desktop/:  ACCT=m3xyz KEY=/root/lm-m3-desktop.key bash scripts/run-m3.sh
set -u
cd "$(dirname "$0")/.."
EV=cmd/lmdesk/evidence
: "${ACCT:?ACCT=throwaway-account}"
: "${KEY:?KEY=path-to-sec1-pem}"
mkdir -p "$EV" bin
[ -f /tmp/m3-zufall.bin ] || head -c 1048576 /dev/urandom > /tmp/m3-zufall.bin
sha256sum /tmp/m3-zufall.bin | cut -d' ' -f1 > /tmp/m3-zufall.sha

cat > "$EV/m3-config.json" <<JSON
{"relay":"http://127.0.0.1:18443","name":"$ACCT","keyfile":"$KEY"}
JSON

export CGO_ENABLED=0
go build -o bin/lmdesk ./cmd/lmdesk || exit 1
echo BUILD_OK

bash scripts/tunnel.sh start

EV="$EV" ACCT_CFG="$EV/m3-config.json" dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash scripts/xvfb-m3-inner.sh 2>&1 | tee "$EV/m3-run.log"
echo "== done =="
ls -la "$EV"/m3-*.png 2>/dev/null

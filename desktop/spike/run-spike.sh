#!/usr/bin/env bash
# M0 spike: builds the binary without CGO and captures screenshot + log under Xvfb.
# Run: bash spike/run-spike.sh   (from the desktop/ directory)
set -euo pipefail
cd "$(dirname "$0")/.."

export CGO_ENABLED=0
echo "== go build ./... (CGO disabled) =="
go build -o /dev/null ./...
go build -o spike/bin/lm-spike ./spike
echo "BUILD_OK"

mkdir -p spike/evidence spike/bin
rm -f spike/evidence/screenshot.png spike/evidence/spike.log

# Xvfb + inner script: start the binary, let it render for 7s, screenshot, kill.
# dbus-run-session: the systemd user bus on the dev sandbox hangs g_application_register.
dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash spike/xvfb-inner.sh | tee spike/evidence/spike.log
echo "== exit inner: $? =="

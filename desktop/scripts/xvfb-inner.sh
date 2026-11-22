#!/usr/bin/env bash
# Runs inside xvfb-run (DISPLAY is set). The sandbox-disable env var below is
# the headless-LXC evidence exception ONLY (Rotliste #1) — never in the Go
# binary or a production launcher.
set -u
cd "$(dirname "$0")/.."
export GSK_RENDERER=cairo
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export LMDESK_DEMO="${LMDESK_DEMO:-1}"
export LMDESK_DOMCHECK="${LMDESK_DOMCHECK:-0}"

EV=cmd/lmdesk/evidence
PREFIX=shot
if [ "$LMDESK_DOMCHECK" = "1" ]; then PREFIX=domcheck; fi

./bin/lmdesk 2>&1 &
PID=$!
sleep 8
import -window root "$EV/$PREFIX-08s.png"
echo "SCREENSHOT_1 $EV/$PREFIX-08s.png"
sleep 12
if [ "$LMDESK_DOMCHECK" != "1" ]; then
  import -window root "$EV/$PREFIX-20s.png"
  echo "SCREENSHOT_2 $EV/$PREFIX-20s.png"
else
  sleep 2  # DOMCHECK result lands in the log right after LoadFinished
fi
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
pkill -f 'bin/lmdesk' 2>/dev/null || true
echo DESK_DONE

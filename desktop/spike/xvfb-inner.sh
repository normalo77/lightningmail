#!/usr/bin/env bash
# Laeuft innerhalb von xvfb-run (DISPLAY ist gesetzt).
set -u
cd "$(dirname "$0")/.."
export GSK_RENDERER=cairo
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1

./spike/bin/lm-spike 2>&1 &
PID=$!
sleep 7
import -window root spike/evidence/screenshot.png
echo "SCREENSHOT_TAKEN"
# zweiter Frame nach Explizit-Auswahl von Mail 2 (belegt Row-Click -> LoadHtml)
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
pkill -f lm-spike 2>/dev/null || true
echo "SPIKE_DONE"

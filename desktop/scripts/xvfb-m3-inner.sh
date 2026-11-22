#!/usr/bin/env bash
# Inner M3 pass: runs inside dbus-run-session + xvfb (DISPLAY set).
# Headless sandbox exception like xvfb-inner.sh — evidence ONLY.
# Screenshots are LOG-DRIVEN (wall-clock sleeps drift under container start
# latency — lesson from the first m3 run: all four shots showed the final
# frame because demo timers and imports disagreed on t0).
set -u
cd "$(dirname "$0")/.."
export GSK_RENDERER=cairo
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export LMDESK_DEMO=1
export LMDESK_M3DEMO=1
export LMDESK_CONFIG="$ACCT_CFG"

EV=cmd/lmdesk/evidence
LOG=$EV/m3-stdout.log
rm -f "$LOG"
./bin/lmdesk > "$LOG" 2>&1 &
PID=$!
W() { for _ in $(seq 120); do grep -q "$1" "$LOG" 2>/dev/null && return 0; sleep 0.5; done; echo "MISS $1"; }
S() { import -window root "$EV/$1"; echo "SHOT $1"; }

W "UI steht";                       sleep 1.5; S m3-08-inbox.png
W "m3ev:ab";                        sleep 1.5; S m3-13-adressbuch.png
W "m3ev:drv";                       sleep 3.0; S m3-19-laufwerk.png
W "m3ev:cfg";                       sleep 3.0; S m3-25-einstellungen.png
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
pkill -f 'bin/lmdesk' 2>/dev/null || true
grep -E "m3ev|drive upload|push ok" "$LOG" | tail -6
echo M3_DESK_DONE

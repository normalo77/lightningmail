#!/usr/bin/env bash
# M2a Interop-Test: lmcli -> relayd (interop mode) -> TS client.
# Proves: E2EE envelope + real Go crypto + TS fetch/decode roundtrip.
# Exit 0 = green.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
RELAY_URL="http://127.0.0.1:8443"

reap() {
  pkill -f "interop-relay" 2>/dev/null || true
  for i in $(seq 1 10); do
    (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null && { exec 3>&-; sleep 0.5; continue; }
    return 0
  done
}
reap
trap "pkill -f interop-relay 2>/dev/null || true" EXIT

fail() { echo "[interop] FAIL: $*" >&2; exit 1; }
note() { echo "[interop] $*"; }

# Build
note "Building interop relay + lmcli ..."
cd "$REPO/relay" && go build -o /dev/null ./cmd/interop-relay/ ./cmd/lmcli/ && cd "$REPO"

# Start interop relay
TMPDIR=$(mktemp -d)
note "Starting interop relay (data=$TMPDIR) ..."
cd "$REPO/relay" && go run ./cmd/interop-relay/ "$TMPDIR" > /tmp/interop-relay.log 2>&1 &
RELAY_PID=$!
cd "$REPO"
trap "kill $RELAY_PID 2>/dev/null || true" EXIT

# Health check
for i in $(seq 1 20); do
  curl -sf "$RELAY_URL/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$RELAY_URL/health" >/dev/null || fail "interop relay not healthy"

note "Interop relay healthy"

# Setup test home
HOME_B="$TMPDIR/home"
mkdir -p "$HOME_B/bernd" "$HOME_B/gisela"

run_lmcli() {
  local home="$1" acct="$2"; shift 2
  BMAIL_HOME="$home" BMAIL_RELAY="$RELAY_URL" BMAIL_ACCOUNT="$acct" \
    go run -C "$REPO/relay" ./cmd/lmcli/ "$@" 2>&1
}

# Init accounts
note "Creating accounts (bernd, gisela) ..."
BERND_PUBKEY=$(run_lmcli "$HOME_B/bernd" bernd init bernd | grep '^pubkey:' | awk '{print $2}')
GISELA_PUBKEY=$(run_lmcli "$HOME_B/gisela" gisela init gisela | grep '^pubkey:' | awk '{print $2}')
[ -n "$BERND_PUBKEY" ] || fail "bernd keygen"
[ -n "$GISELA_PUBKEY" ] || fail "gisela keygen"

# Fund bernd (100000 sats in msat)
python3 -c "
import sqlite3
db = sqlite3.connect('$TMPDIR/ledger.db')
db.execute('UPDATE account SET balance_msat=100000000000 WHERE name=\"bernd\"')
db.commit()
" || fail "fund bernd"

# Check balance
BAL=$(run_lmcli "$HOME_B/bernd" bernd balance)
echo "$BAL" | grep -q '100000000000' || fail "bernd start balance: $BAL"
note "Balance OK"

# Send: bernd -> gisela
BODY="Interop-Test $(date +%s)"
note "Sending bernd -> gisela ..."
SEND_OUT=$(run_lmcli "$HOME_B/bernd" bernd send gisela "Interop" "$BODY")
echo "$SEND_OUT" | grep -q '"msg_id"' || fail "send failed: $SEND_OUT"
MSG_ID=$(echo "$SEND_OUT" | sed 's/^sent: //' | python3 -c "import sys,json; print(json.load(sys.stdin)['msg_id'])")
note "Sent msg_id=$MSG_ID"

# Get gisela token for TS client
GISELA_TOKEN=$(run_lmcli "$HOME_B/gisela" gisela token | tail -1)
[ -n "$GISELA_TOKEN" ] || fail "gisela token empty"

# TS interop: fetch inbox via Node.js client
note "TS interop: fetching inbox via Node.js ..."
node "$REPO/test/interop-client.mjs" "$RELAY_URL" gisela "$GISELA_TOKEN" || fail "TS interop client failed"

# Verify via Go inbox
note "Checking gisela inbox (Go) ..."
INBOX=$(run_lmcli "$HOME_B/gisela" gisela inbox)
echo "$INBOX" | grep -q "Interop" || fail "Message not in gisela inbox"
note "Message delivered OK"

# Check gisela balance (should be +10 sats = 10000 msat)
BAL=$(run_lmcli "$HOME_B/gisela" gisela balance)
echo "$BAL" | grep -q '10000' || fail "gisela credit: $BAL"
note "Balance gisela: +10 sats OK"

note "PASS: lmcli -> interop-relay -> lmcli inbox Roundtrip erfolgreich"
note "Chain: Go-crypto E2EE envelope + real signature verification"
exit 0
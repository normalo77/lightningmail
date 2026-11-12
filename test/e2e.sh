#!/usr/bin/env bash
# bmail Etappe 3 — E2E-Test: Portomail-Flow über beide regtest-LND-Nodes.
# Exit 0 = gruen.
set -euo pipefail
# Idempotenz: Prozesse frueherer Laeute reapen, Ports freigeben
reap() {
  pkill -f "cmd/relayd" 2>/dev/null || true
  pkill -f "[r]elayd -config" 2>/dev/null || true
  for i in $(seq 1 30); do
    busy=0
    (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null && busy=1
    (exec 3<>/dev/tcp/127.0.0.1/9443) 2>/dev/null && busy=1
    [ $busy -eq 0 ] && return 0
    sleep 0.5
  done
  echo "[e2e] FAIL: relay-Ports nicht frei" >&2; exit 1
}
reap
trap "pkill -f cmd/relayd 2>/dev/null; pkill -f [r]elayd -config 2>/dev/null" EXIT

cd "$(dirname "$0")/.."
REPO="$(pwd)"
export PATH="$PATH:/usr/local/go/bin"

RELAY_ALPHA="http://127.0.0.1:8443"
RELAY_BETA="http://127.0.0.1:9443"
HOME_B="$REPO/test/e2e-home"

fail() { echo "[e2e] FAIL: $*" >&2; exit 1; }
note() { echo "[e2e] $*"; }

# 1. Docker stack
note "Ensuring Docker stack..."
./test/smoke.sh > /dev/null || fail "smoke.sh"

# 2. Build
note "Building..."
cd relay
go build -o /dev/null ./... || fail "go build"
cd "$REPO"

# 3. Clean state
rm -rf /tmp/bmail-alpha /tmp/bmail-beta "$HOME_B"
mkdir -p "$HOME_B"

# 4. Start relays
note "Starting relayd-alpha..."
cd relay && go run ./cmd/relayd/ -config "$REPO/relay-alpha.yaml" -addr 127.0.0.1:8443 > /tmp/relayd-alpha.log 2>&1 &
ALPHA_PID=$!
cd "$REPO"

note "Starting relayd-beta..."
cd relay && go run ./cmd/relayd/ -config "$REPO/relay-beta.yaml" -addr 127.0.0.1:9443 > /tmp/relayd-beta.log 2>&1 &
BETA_PID=$!
cd "$REPO"

cleanup() { kill $ALPHA_PID 2>/dev/null; kill $BETA_PID 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

# 5. Wait for health
for i in $(seq 1 30); do
  curl -sf $RELAY_ALPHA/health >/dev/null 2>&1 && curl -sf $RELAY_BETA/health >/dev/null 2>&1 && break
  sleep 1
done
curl -sf $RELAY_ALPHA/health >/dev/null || fail "alpha not healthy"
curl -sf $RELAY_BETA/health >/dev/null || fail "beta not healthy"
note "Both relays healthy"

# 6. Generate keypairs + register accounts
note "Generating keys..."
cd relay
BERND_PUBKEY=$(BMAIL_HOME="$HOME_B/bernd" BMAIL_RELAY="$RELAY_ALPHA" \
  go run ./cmd/lmcli/ init bernd 2>&1 | tee /dev/stderr | grep '^pubkey:' | awk '{print $2}')
GISELA_PUBKEY=$(BMAIL_HOME="$HOME_B/gisela" BMAIL_RELAY="$RELAY_BETA" \
  go run ./cmd/lmcli/ init gisela 2>&1 | tee /dev/stderr | grep '^pubkey:' | awk '{print $2}')
cd "$REPO"

[ -n "$BERND_PUBKEY" ] || fail "bernd keygen"
[ -n "$GISELA_PUBKEY" ] || fail "gisela keygen"

# Register gisela on alpha (so bernd can look up her profile)
curl -s -X POST "$RELAY_ALPHA/v1/account" -H 'Content-Type: application/json' \
  -d "{\"name\":\"gisela\",\"pubkey\":\"$GISELA_PUBKEY\"}" -w "%{http_code}" -o /dev/null | grep -qE "^(200|409)$" || fail "register gisela on alpha"

# Register bernd on beta (not strictly needed, but for completeness)
curl -s -X POST "$RELAY_BETA/v1/account" -H 'Content-Type: application/json' \
  -d "{\"name\":\"bernd\",\"pubkey\":\"$BERND_PUBKEY\"}" -w "%{http_code}" -o /dev/null | grep -qE "^(200|409)$" || fail "register bernd on beta"

note "Accounts: bernd=$BERND_PUBKEY gisela=$GISELA_PUBKEY"

# 7. Fund bernd
note "Funding bernd (100000 sats)..."
python3 -c "
import sqlite3
db = sqlite3.connect('/tmp/bmail-alpha/ledger.db')
db.execute('UPDATE account SET balance_msat=100000000000 WHERE name=\"bernd\"')
db.commit()
db.close()
print('funded')
" || fail "fund bernd"

# 8. Send message
BODY="Hallo Gisela — E2E Test $(date +%s)"
note "Sending: bernd -> gisela"
cd relay
SEND_OUT=$(BMAIL_HOME="$HOME_B/bernd" BMAIL_RELAY="$RELAY_ALPHA" BMAIL_ACCOUNT="bernd" \
  go run ./cmd/lmcli/ send gisela "E2E Test" "$BODY" 2>&1)
cd "$REPO"
echo "$SEND_OUT"
echo "$SEND_OUT" | grep -q '"msg_id"' || fail "send failed: $SEND_OUT"
note "Send OK"

# 9. Wait for delivery
note "Waiting for delivery..."
DELIVERED=0
for i in $(seq 1 30); do
  cd relay
  INBOX=$(BMAIL_HOME="$HOME_B/gisela" BMAIL_RELAY="$RELAY_BETA" BMAIL_ACCOUNT="gisela" \
    go run ./cmd/lmcli/ inbox 2>&1)
  cd "$REPO"
  if echo "$INBOX" | grep -q "E2E Test"; then
    DELIVERED=1
    echo "$INBOX"
    break
  fi
  sleep 2
done
[ "$DELIVERED" -eq 1 ] || fail "message not delivered after 60s"

# 10. Verify
cd relay
VERIFY=$(BMAIL_HOME="$HOME_B/gisela" BMAIL_RELAY="$RELAY_BETA" BMAIL_ACCOUNT="gisela" \
  go run ./cmd/lmcli/ inbox 2>&1)
cd "$REPO"
echo "$VERIFY" | grep -q "E2E Test" || fail "subject not found in inbox"
note "PASS: Full Portomail flow — bernd -> gisela delivered"
exit 0
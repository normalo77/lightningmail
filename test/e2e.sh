#!/usr/bin/env bash
# bmail Etappe 4a -- E2E: Portomail + 1-MB-Attachment + Replay + Blob-ACL +
# Persistent-Sessions + Quota.
set -euo pipefail
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

run_lmcli() {
  local home="$1" acct="$2" relay="$3"; shift 3
  cd "$REPO/relay"
  BMAIL_HOME="$home" BMAIL_RELAY="$relay" BMAIL_ACCOUNT="$acct"     go run ./cmd/lmcli/ "$@" 2>&1
  cd "$REPO"
}
# 1. Docker stack
note "Ensuring Docker stack..."
./test/smoke.sh > /dev/null || fail "smoke.sh"

# 2. Build
note "Building..."
cd relay && go build -o /dev/null ./... && cd "$REPO"

# 3. Clean state
rm -rf /tmp/bmail-alpha /tmp/bmail-beta "$HOME_B"
mkdir -p "$HOME_B"

# 4. Start relays
note "Starting relays..."
cd relay && go run ./cmd/relayd/ -config "$REPO/relay-alpha.yaml" -addr 127.0.0.1:8443 > /tmp/relayd-alpha.log 2>&1 &
ALPHA_PID=$!; cd "$REPO"
cd relay && go run ./cmd/relayd/ -config "$REPO/relay-beta.yaml" -addr 127.0.0.1:9443 > /tmp/relayd-beta.log 2>&1 &
BETA_PID=$!; cd "$REPO"

cleanup() { kill $ALPHA_PID 2>/dev/null || true; kill $BETA_PID 2>/dev/null || true; }
trap cleanup EXIT

# 5. Health check
for i in $(seq 1 30); do
  curl -sf $RELAY_ALPHA/health >/dev/null 2>&1 && curl -sf $RELAY_BETA/health >/dev/null 2>&1 && break
  sleep 1
done
curl -sf $RELAY_ALPHA/health >/dev/null || fail "alpha not healthy"
curl -sf $RELAY_BETA/health >/dev/null || fail "beta not healthy"
note "Both relays healthy"

# 6. Keygen + register
note "Generating keys..."
BERND_PUBKEY=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" init bernd | grep '^pubkey:' | awk '{print $2}')
GISELA_PUBKEY=$(run_lmcli "$HOME_B/gisela" gisela "$RELAY_BETA" init gisela | grep '^pubkey:' | awk '{print $2}')
[ -n "$BERND_PUBKEY" ] || fail "bernd keygen"
[ -n "$GISELA_PUBKEY" ] || fail "gisela keygen"

curl -s -X POST "$RELAY_ALPHA/v1/account" -H 'Content-Type: application/json' \
  -d "{\"name\":\"gisela\",\"pubkey\":\"$GISELA_PUBKEY\"}" -w "%{http_code}" -o /dev/null | grep -qE "^(200|409)$" || fail "register gisela on alpha"
curl -s -X POST "$RELAY_BETA/v1/account" -H 'Content-Type: application/json' \
  -d "{\"name\":\"bernd\",\"pubkey\":\"$BERND_PUBKEY\"}" -w "%{http_code}" -o /dev/null | grep -qE "^(200|409)$" || fail "register bernd on beta"
note "Accounts ready"

# 7. Fund bernd
note "Funding bernd (100000 sats)..."
python3 -c "
import sqlite3
db = sqlite3.connect('/tmp/bmail-alpha/ledger.db')
db.execute('UPDATE account SET balance_msat=100000000000 WHERE name=\"bernd\"')
db.commit()
db.close()
" || fail "fund bernd"

# -- A: Basic Portomail + Balance-Assertions --
BAL=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" balance)
echo "$BAL" | grep -q '"balance_msat":100000000000' || fail "bernd start balance: $BAL"
note "Balance start: 100000000000 msat OK"

BODY="Hallo Gisela -- E2E $(date +%s)"
note "Sending bernd -> gisela..."
SEND_OUT=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" send gisela "E2E Test" "$BODY")
echo "$SEND_OUT" | grep -q '"msg_id"' || fail "send failed: $SEND_OUT"
note "Send OK"

BAL=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" balance)
echo "$BAL" | grep -q '"balance_msat":99999990000' || fail "bernd post-send: $BAL"
note "Balance bernd after send: 99999990000 msat OK"

note "Waiting for delivery..."
for i in $(seq 1 30); do
  INBOX=$(run_lmcli "$HOME_B/gisela" gisela "$RELAY_BETA" inbox)
  if echo "$INBOX" | grep -q "E2E Test"; then DELIVERED=1; break; fi
  sleep 2
done
[ "${DELIVERED:-0}" -eq 1 ] || fail "message not delivered"
note "Delivered OK"

BAL=$(run_lmcli "$HOME_B/gisela" gisela "$RELAY_BETA" balance)
echo "$BAL" | grep -q '"balance_msat":10000' || fail "gisela credit: $BAL"
note "Balance gisela: 10000 msat credit OK"
note "PASS A: Portomail + Balances"

# -- B: 1-MB-Attachment-Roundtrip --
note "Creating 1 MB test blob..."
dd if=/dev/urandom of=/tmp/e2e-blob.bin bs=1024 count=1024 2>/dev/null
BLOB_SHA=$(sha256sum /tmp/e2e-blob.bin | awk '{print $1}')
note "Blob SHA256: $BLOB_SHA"

note "Uploading blob..."
UPLOAD=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" blob upload /tmp/e2e-blob.bin)
echo "$UPLOAD" | grep -q "$BLOB_SHA" || fail "blob upload: $UPLOAD"
note "Blob uploaded OK"

note "Sending with attachment..."
SEND2=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" send gisela "E2E Attach" "body-attach-$(date +%s)" --attach "$BLOB_SHA")
echo "$SEND2" | grep -q '"msg_id"' || fail "send attach failed: $SEND2"
note "Send with attach OK"

note "Waiting for attach delivery..."
for i in $(seq 1 30); do
  INBOX=$(run_lmcli "$HOME_B/gisela" gisela "$RELAY_BETA" inbox)
  if echo "$INBOX" | grep -q "E2E Attach"; then break; fi
  sleep 2
done

note "Downloading blob..."
run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" blob get "$BLOB_SHA" > /tmp/e2e-blob-dl.bin
DOWNLOAD_SHA=$(sha256sum /tmp/e2e-blob-dl.bin | awk '{print $1}')
[ "$DOWNLOAD_SHA" = "$BLOB_SHA" ] || fail "blob sha mismatch: $DOWNLOAD_SHA != $BLOB_SHA"
[ "$(stat -c%s /tmp/e2e-blob-dl.bin)" -eq 1048576 ] || fail "blob size mismatch"
note "PASS B: 1-MB attachment roundtrip OK"

# -- C: Replay-Ablehnung --
note "Testing replay rejection..."

ENV_HEX=$(python3 -c "
import sqlite3
db = sqlite3.connect('/tmp/bmail-beta/ledger.db')
row = db.execute('SELECT hex(envelope) FROM mailbox ORDER BY seq ASC LIMIT 1').fetchone()
db.close()
print(row[0])
")
[ -n "$ENV_HEX" ] || fail "no envelope for replay"

BERND_TOKEN=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" token | tail -1)
[ -n "$BERND_TOKEN" ] || fail "bernd token empty"

REPLAY_CODE=$(python3 -c "
import urllib.request
env_bin = bytes.fromhex('$ENV_HEX')
req = urllib.request.Request('$RELAY_ALPHA/v1/send', data=env_bin, method='POST')
req.add_header('Authorization', 'Bearer $BERND_TOKEN')
req.add_header('Content-Type', 'application/octet-stream')
try:
    resp = urllib.request.urlopen(req)
    print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
")
[ "$REPLAY_CODE" = "409" ] || fail "replay not rejected: got $REPLAY_CODE"
note "PASS C: Replay rejected with 409"
# -- D: Blob-ACL (unauthorized access blocked) --
note "Testing blob ACL..."
GISELA_TOKEN=$(run_lmcli "$HOME_B/gisela" gisela "$RELAY_BETA" token | tail -1)
[ -n "$GISELA_TOKEN" ] || fail "gisela token empty"

# gisela tries to download bernd's blob from alpha -> should NOT succeed
ACL_CODE=$(python3 -c "
import urllib.request, urllib.error
req = urllib.request.Request('$RELAY_ALPHA/v1/blob/$BLOB_SHA')
req.add_header('Authorization', 'Bearer $GISELA_TOKEN')
try:
    resp = urllib.request.urlopen(req)
    print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
")
[ "$ACL_CODE" != "200" ] || fail "blob ACL: unauthorized access returned 200"
note "PASS D: Blob ACL blocks unauthorized access (code=$ACL_CODE)"

# -- E: Persistent Sessions (token survives relay restart) --
note "Testing persistent tokens (restart proof)..."

# Get bernd token before restart
BERND_TOKEN_PRE=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" token | tail -1)
[ -n "$BERND_TOKEN_PRE" ] || fail "bernd pre token"

# Kill alpha relay
kill $ALPHA_PID 2>/dev/null || true
sleep 2

# Restart alpha relay
cd relay && go run ./cmd/relayd/ -config "$REPO/relay-alpha.yaml" -addr 127.0.0.1:8443 > /tmp/relayd-alpha.log 2>&1 &
ALPHA_PID=$!; cd "$REPO"
trap "kill $ALPHA_PID 2>/dev/null || true; kill $BETA_PID 2>/dev/null || true" EXIT

# Wait for health
for i in $(seq 1 20); do
  curl -sf $RELAY_ALPHA/health >/dev/null 2>&1 && break
  sleep 1
done
curl -sf $RELAY_ALPHA/health >/dev/null || fail "alpha not healthy after restart"

# Reuse the old token -- must still work (persisted in SQLite)
RESTART_BAL=$(curl -s -H "Authorization: Bearer $BERND_TOKEN_PRE" "$RELAY_ALPHA/v1/balance")
echo "$RESTART_BAL" | grep -q '"balance_msat"' || fail "persistent token rejected after restart: $RESTART_BAL"
note "PASS E: Token survives relay restart"

# -- F: Quota enforcement --
note "Testing storage quota..."

# Create a 5 MB blob
dd if=/dev/urandom of=/tmp/e2e-blob-5mb.bin bs=1024 count=5120 2>/dev/null
BLOB_5MB_SHA=$(sha256sum /tmp/e2e-blob-5mb.bin | awk '{print $1}')

# Upload it -- OK (under 100 MiB quota)
UPLOAD5=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" blob upload /tmp/e2e-blob-5mb.bin)
echo "$UPLOAD5" | grep -q "$BLOB_5MB_SHA" || fail "5MB blob upload: $UPLOAD5"
note "5 MB blob uploaded OK"

# Set bernd quota to 6291456 (6 MiB, just above current usage of 6 MB)
python3 -c "
import sqlite3
db = sqlite3.connect('/tmp/bmail-alpha/ledger.db')
db.execute('UPDATE account SET quota_bytes=6291456 WHERE name=\"bernd\"')
db.commit()
db.close()
" || fail "set quota"

# Try another upload that would exceed the quota
dd if=/dev/urandom of=/tmp/e2e-blob-2mb.bin bs=1024 count=2048 2>/dev/null
UPLOAD_FAIL=$(run_lmcli "$HOME_B/bernd" bernd "$RELAY_ALPHA" blob upload /tmp/e2e-blob-2mb.bin 2>&1 || true)
echo "$UPLOAD_FAIL" | grep -qi "quota" && QUOTA_HIT=1 || QUOTA_HIT=0
[ "$QUOTA_HIT" -eq 1 ] || fail "quota not enforced: $UPLOAD_FAIL"
note "PASS F: Quota enforcement blocks over-limit upload"

note "ALL PASS: Etappe 4a complete"
exit 0

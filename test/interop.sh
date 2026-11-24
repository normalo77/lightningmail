#!/usr/bin/env bash
# lightningmail M2a interop: real relayd + LND (regtest) -> lmcli send -> TS client decrypts.
set -euo pipefail
REPO=<repo>; export PATH=$PATH:/usr/local/go/bin
RA=http://127.0.0.1:8443; RB=http://127.0.0.1:9443
H="$REPO/test/interop-home"
fail(){ echo "INTEROP FAIL: $*" >&2; exit 1; }
reap(){ pkill -f lm-relayd 2>/dev/null || true; pkill -f "relayd -config" 2>/dev/null || true; sleep 1.5; }
trap 'pkill -f lm-relayd 2>/dev/null || true' EXIT
reap
rm -rf /tmp/bmail-alpha /tmp/bmail-beta "$H"; mkdir -p "$H/bernd" "$H/gisela"

echo "[interop] build..."
cd "$REPO/relay"
go build -o /tmp/lm-relayd ./cmd/relayd
go build -o /tmp/lm-cli ./cmd/lmcli

echo "[interop] starting relays (live LND via relay-beta.yaml/relay-alpha.yaml)..."
/tmp/lm-relayd -config "$REPO/relay-alpha.yaml" -addr 127.0.0.1:8443 >/tmp/lm-i-a.log 2>&1 &
/tmp/lm-relayd -config "$REPO/relay-beta.yaml" -addr 127.0.0.1:9443 >/tmp/lm-i-b.log 2>&1 &
for i in $(seq 1 40); do curl -sf $RA/health >/dev/null 2>&1 && curl -sf $RB/health >/dev/null 2>&1 && break; sleep 1; done
curl -sf $RA/health >/dev/null || { cat /tmp/lm-i-a.log; fail "alpha not healthy"; }

cli(){ local home=$1 acct=$2 relay=$3; shift 3; BMAIL_HOME="$home" BMAIL_RELAY="$relay" BMAIL_ACCOUNT="$acct" /tmp/lm-cli "$@" 2>&1; }

BP=$(cli "$H/bernd" bernd "$RA" init bernd | grep '^pubkey:' | awk '{print $2}')
GP=$(cli "$H/gisela" gisela "$RB" init gisela | grep '^pubkey:' | awk '{print $2}')
[ -n "$BP" ] && [ -n "$GP" ] || fail "keygen"
curl -s -X POST "$RA/v1/account" -H 'Content-Type: application/json' -d "{\"name\":\"gisela\",\"pubkey\":\"$GP\"}" -o /dev/null
curl -s -X POST "$RB/v1/account" -H 'Content-Type: application/json' -d "{\"name\":\"bernd\",\"pubkey\":\"$BP\"}" -o /dev/null
python3 -c "import sqlite3;db=sqlite3.connect('/tmp/bmail-alpha/ledger.db');db.execute('UPDATE account SET balance_msat=100000000000 WHERE name=\"bernd\"');db.commit()"
echo "[interop] accounts ready"

BODY="Interop TS-Proof $(date +%s)"
dd if=/dev/urandom of=/tmp/lm-blob.bin bs=1024 count=1024 2>/dev/null
SHA=$(sha256sum /tmp/lm-blob.bin | awk '{print $1}')
cli "$H/bernd" bernd "$RA" blob upload /tmp/lm-blob.bin | grep -q "$SHA" || fail "blob upload"
cli "$H/bernd" bernd "$RA" send gisela "Interop Test" "$BODY" --attach "$SHA" | grep -q '"msg_id"' || fail "send"
echo "[interop] sent with attachment; waiting delivery..."
sleep 5

cd "$REPO/client"
BETA_URL=$RB GISELA_HOME="$H/gisela" EXPECT_BODY="$BODY" EXPECT_SHA=$SHA \
  npx tsx test/interop-client.ts || fail "TS client interop"
echo "INTEROP OK"

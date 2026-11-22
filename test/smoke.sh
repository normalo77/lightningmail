#!/usr/bin/env bash
# bmail Etappe 1 — smoke test.
# Brings up the regtest stack, rolls 110 blocks for alpha, opens a channel
# alpha->beta (6 BTC, 200k sats push -> beta gets outbound), pays a keysend
# alpha->beta (1000 sats) with bmail custom TLVs (34349334..34349343) and
# verifies at the destination: funds received + TLV content readable.
# Idempotent: existing state (wallet/channel) is detected and reused.
# Exit 0 = green, 1 = error.
set -euo pipefail
cd "$(dirname "$0")/docker"

PW=bmaildevpass              # lnd wallet password (regtest-only, public by design)
MSG="hello-bmail-$(date +%s)"
AMT=1000

compose() { docker compose -p lightningmail-test -f docker-compose.yml "$@"; }
btc()   { compose exec -T bitcoind bitcoin-cli -regtest -rpcuser=bmail -rpcpassword=bmaildev "$@"; }
lnA()   { compose exec -T lnd-alpha lncli --network=regtest "$@"; }
lnB()   { compose exec -T lnd-beta  lncli --network=regtest "$@"; }
jget()  { python3 -c "import sys,json;print($1)"; }

fail() {
  echo "FAIL: $*" >&2
  compose ps || true
  compose logs --tail=15 2>&1 | tail -40 >&2 || true
  exit 1
}
note() { echo "[smoke] $*"; }

# Wallet: create on first run, unlock after restart.
ensure_wallet() { # $1=service
  local svc="$1" st
  for _ in $(seq 1 24); do
    if compose exec -T "$svc" lncli --network=regtest getinfo >/dev/null 2>&1; then return 0; fi
    st="$(compose exec -T "$svc" lncli --network=regtest getstate 2>/dev/null || true)"
    case "$st" in
      *NEEDS_WALLET_INIT*) printf '%s\n%s\n\n' "$PW" "$PW" | compose exec -T "$svc" lncli --network=regtest create >/dev/null 2>&1 || true ;;
      *LOCKED_WALLET*)     printf '%s\n' "$PW" | compose exec -T "$svc" lncli --network=regtest unlock  >/dev/null 2>&1 || true ;;
    esac
    sleep 5
  done
  fail "$svc: Wallet nicht offen"
}

note "Stack hoch ..."
compose up -d --wait >/dev/null || fail "compose up"
for _ in $(seq 1 24); do btc getblockcount >/dev/null 2>&1 && break; sleep 5; done
btc getblockcount >/dev/null 2>&1 || fail "bitcoind RPC nicht erreichbar"
ensure_wallet lnd-alpha
ensure_wallet lnd-beta
note "beide LND-Knoten laufen"

# Money: alpha needs confirmed >= 1 BTC for the channel.
if [ "$(lnA walletbalance | jget 'json.loads(sys.stdin.read())["confirmed_balance"]' 2>/dev/null || echo 0)" -lt 100000000 ]; then
  ADDR=$(lnA newaddress p2wkh | jget 'json.loads(sys.stdin.read())["address"]')
  btc generatetoaddress 110 "$ADDR" >/dev/null || fail "mining"
  note "110 Blende gemined"
fi
READY=0
for _ in $(seq 1 24); do
  [ "$(lnA walletbalance | jget 'json.loads(sys.stdin.read())["confirmed_balance"]' 2>/dev/null || echo 0)" -ge 100000000 ] && { READY=1; break; }
  sleep 5
done
[ "$READY" -eq 1 ] || fail "alpha-Wallet nie confirmed (coinbase-Maturity?)"

BETA_PUB=$(lnB getinfo | jget 'json.loads(sys.stdin.read())["identity_pubkey"]')
ALPHA_PUB=$(lnA getinfo | jget 'json.loads(sys.stdin.read())["identity_pubkey"]')

# Channel alpha->beta, if none exists yet.
if [ "$(lnA listchannels | jget 'len(json.loads(sys.stdin.read()).get("channels",[]))')" -eq 0 ]; then
  lnA connect "$BETA_PUB@lnd-beta:9735" >/dev/null 2>&1 || true
  note "Kanal alpha->beta: 600000000 sats (6 BTC), 2000000 sats push"
  lnA openchannel --node_key="$BETA_PUB" --local_amt=600000000 --push_amt=2000000 --private >/dev/null || fail "openchannel"
fi
ACT=0
for _ in $(seq 1 12); do
  if lnA listchannels | grep -q '"active": true'; then ACT=1; break; fi
  btc generatetoaddress 1 "$(btc getnewaddress)" >/dev/null
  sleep 5
done
[ "$ACT" -eq 1 ] || fail "Kanal nicht ACTIVE nach 12 Blenden"
note "Kanal ACTIVE"

# keysend with bmail TLVs: 34349334=message, 34349337=signature placeholder (64x00),
# 34349339=sender pubkey, 34349343=timestamp.
DATA=$(python3 -c '
import sys, time
msg, pub = sys.argv[1], sys.argv[2]
sig = "00" * 64
print(",".join([
    f"34349334={msg.encode().hex()}",
    f"34349337={sig}",
    f"34349339={pub}",
    f"34349343={str(int(time.time())).encode().hex()}",
]))' "$MSG" "$ALPHA_PUB")

BEFORE=$(lnB listchannels --peer="$ALPHA_PUB" | jget 'json.loads(sys.stdin.read())["channels"][0]["local_balance"]' 2>/dev/null || echo 0)

note "keysend alpha->beta (${AMT} sats, msg=${MSG})"
RESP=$(lnA sendpayment --dest="$BETA_PUB" --amt="$AMT" --keysend --data="$DATA" 2>&1) || fail "sendpayment fehlgeschlagen: $RESP"
echo "$RESP" | grep -qi "SUCCEEDED" || fail "Payment nicht SUCCEEDED: $RESP"

ok=0
for _ in $(seq 1 12); do
  AFTER=$(lnB listchannels --peer="$ALPHA_PUB" | jget 'json.loads(sys.stdin.read())["channels"][0]["local_balance"]' 2>/dev/null || echo "$BEFORE")
  [ "${AFTER:-0}" -ge $((BEFORE + AMT)) ] && { ok=1; break; }
  sleep 5
done
[ "$ok" -eq 1 ] || fail "Geldeingang bei beta nicht sichtbar ($BEFORE -> $AFTER)"
note "Geldeingang beta: local_balance $BEFORE -> $AFTER"

# TLV roundtrip: with lnd 0.21, keysend records land in htlcs[].custom_records (hex).
lnB listinvoices | python3 -c '
import sys, json, base64, binascii
msg = sys.argv[1]
data = json.load(sys.stdin)
def as_hex(v):
    try:
        return bytes.fromhex(v).hex()
    except (binascii.Error, ValueError):
        return base64.b64decode(v).hex()
hit = recs = None
for inv in data.get("invoices", []):
    for h in inv.get("htlcs", []):
        r = h.get("custom_records") or {}
        if r.get("34349334") and as_hex(r["34349334"]) == msg.encode().hex():
            hit, recs = inv, r
            break
    if hit: break
if not hit:
    sys.exit(-1)
print("[smoke] keysend-Invoice bei beta: value=%s state=%s" % (hit.get("value"), hit.get("state")))
for t in ("34349334", "34349337", "34349339", "34349343"):
    assert t in recs, "TLV-Typ %s fehlt" % t
    print("[smoke]   TLV %s -> %s" % (t, bytes.fromhex(as_hex(recs[t])).hex()))
print("[smoke]   Nachricht (34349334): %r" % bytes.fromhex(as_hex(recs["34349334"])).decode())
assert bytes.fromhex(as_hex(recs["34349339"])).hex() == sys.argv[2], "Absender-Pubkey-TLV passt nicht"
' "$MSG" "$ALPHA_PUB" || fail "TLV-Roundtrip nicht verifiziert (keine keysend-HTLC mit 34349334=$MSG)"

note "PASS: Stack laeuft, Kanal ACTIVE, keysend SUCCEEDED, bmail-TLV am Ziel lesbar ($MSG)"
exit 0

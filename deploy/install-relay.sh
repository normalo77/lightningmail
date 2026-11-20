#!/usr/bin/env bash
# install-relay.sh — Etappe O (CONCEPT §27): erzeugt relay.yaml (+ .env) fuer
# Light-Relay (LND/Neutrino) oder Full-Relay (LND + eigener bitcoind) und
# druckt die DNS-TXT-Anleitung (_bmail._tcp, CONCEPT §4.2 / spec §6.1).
#
# Usage: ./install-relay.sh --mode light|full --domain example.org
#                           [--name relay] [--foreign-sats 10] [--welcome-sats 30] [--force]
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  sed -n '5,7p' "$0"
  exit 2
}

MODE="" DOMAIN="" NAME="relay" FOREIGN=10 WELCOME="" FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)         MODE="${2:?--mode braucht light|full}"; shift 2 ;;
    --domain)       DOMAIN="${2:?--domain braucht einen Wert}"; shift 2 ;;
    --name)         NAME="${2:?}"; shift 2 ;;
    --foreign-sats) FOREIGN="${2:?}"; shift 2 ;;
    --welcome-sats) WELCOME="${2:?}"; shift 2 ;;
    --force)        FORCE=1; shift ;;
    *)              usage ;;
  esac
done
case "$MODE" in light|full) ;; *) usage ;; esac
[ -n "$DOMAIN" ] || usage
[[ "$FOREIGN" =~ ^[0-9]+$ ]] && [ "$FOREIGN" -ge 1 ] || { echo "error: --foreign-sats muss Zahl >= 1 sein" >&2; exit 2; }
[ -n "$WELCOME" ] || WELCOME=$((FOREIGN * 3))   # Default wie relayd: 3x foreign
[[ "$WELCOME" =~ ^[0-9]+$ ]] && [ "$WELCOME" -ge "$FOREIGN" ] || { echo "error: --welcome-sats muss Zahl >= foreign-sats sein" >&2; exit 2; }
DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"

command -v docker >/dev/null || echo "warn: docker nicht gefunden — es werden nur Dateien erzeugt" >&2
hexrand() { openssl rand -hex "$1" 2>/dev/null || od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

for f in relay.yaml .env; do
  if [ -e "$f" ] && [ "$FORCE" != 1 ]; then
    echo "error: $f existiert bereits — Ueberschreiben mit --force" >&2
    exit 1
  fi
done

umask 077
cat > .env <<EOF
# erzeugt von install-relay.sh ($(date -Is)) — nur fuer docker-compose.full-relay.yml
BITCOIN_RPC_USER=bmail
BITCOIN_RPC_PASS="$(hexrand 16)"
EOF

cat > relay.yaml <<EOF
# relay.yaml — erzeugt von install-relay.sh ($MODE-relay, $DOMAIN)
name: $NAME
listen_addr: 0.0.0.0:8443
data_dir: /var/lib/bmail

# Web-UI (Etappe O): relayd serviert die gebaute PWA unter /app/ — Nutzer
# schalten dann direkt auf dieses Relay auf (https://$DOMAIN/app/).
# Inhalte siehe Bau-Anweisung am Ende. Leer/fehlend = UI wird nicht serviert.
ui_dir: /var/lib/bmail/ui

lnd:
  network: mainnet
  rpc_host: lnd:8080                # REST; relayd leitet gRPC 10009 selbst ab
  tls_cert_path: /lnd/tls.cert
  macaroon_path: /lnd/data/chain/bitcoin/mainnet/admin.macaroon

postage:
  foreign_sats: $FOREIGN
  contact_sats: 0
  welcome_sats: $WELCOME            # Erstkontakt-Porto (CONCEPT §28 Stufe B)
  min_sats: 1
  byte_porto_meur_per_mb: 10        # 1 ct/MiB Upload (§22); 0 = aus

# Blob-Mirror-Shared-Secret zwischen Relays (peers[].token beim Gegenueber)
relay_secret: $(hexrand 32)

retention:
  grace_days: 7
  max_days: 90

webauthn:
  rp_id: "$DOMAIN"
  rp_name: lightningmail
  origins:
    - "https://$DOMAIN"

# Tageskurs-Feed (§25) fuer Steuerstempel + Byte-Porto — Mainnet: echter Kurs.
rates:
  rate_url: "https://api.binance.com/api/v3/ticker/price?symbol=BTCEUR"
  public_rpm: 30

peers: []
EOF
chmod 600 .env relay.yaml
COMPOSE="docker-compose.$MODE-relay.yml"

cat <<EOF

relay.yaml + .env erzeugt fuer $MODE-relay ($DOMAIN).

Naechste Schritte:
  1. LND (+ bitcoind) starten:
       docker compose -f $COMPOSE up -d lnd
  2. LND-Wallet EINMALIG anlegen — die 24 Seed-Woerter sicher offline verwahren!
       docker compose -f $COMPOSE exec lnd lncli create
     (mainnet-IBD: Neutrino ~30–60 Min, Full-Node mehrere Tage)
  3. Alles starten (relayd crasht bis Schritt 2 fertig ist und startet dann neu):
       docker compose -f $COMPOSE up -d

  4. Web-UI am Relay aktivieren (aus dem Repo-Checkout, relativ zu dieser Datei):
       cd client/app && npm install && npx vite build
       mkdir -p ../../deploy/ui && cp -r dist/. ../../deploy/ui/
       docker compose -f deploy/docker-compose.$MODE-relay.yml up -d relayd
     Danach liegt die App direkt auf diesem Relay:  https://$DOMAIN/app/
     (Oder das Verzeichnis leer lassen — Gaeste koennen in jeder App per
      „Eigenes Relay (URL)“ hierher wechseln, Discovery bleibt bei Schritt 5.)

  5. DNS-TXT-Record bei deinem Registrar/Nameserver anlegen (CONCEPT §4.2):

       _bmail._tcp.$DOMAIN.  IN TXT  "v=bmail1; relay=https://$DOMAIN:8443; node=<NODE_PUBKEY>"

     <NODE_PUBKEY> (33B hex) liefert nach Schritt 2:
       docker compose -f $COMPOSE exec lnd lncli getinfo | grep identity_pubkey
     Optionale Felder: onion=<v3>.onion; policy=https://$DOMAIN/policy.json; key=pgp:<fpr>
     Pruefen: dig +short TXT _bmail._tcp.$DOMAIN

  6. TLS: relayd spricht HTTP — vor Produktivbetrieb TLS-Terminierung
     (Reverse Proxy, z.B. Caddy/nginx mit Cert fuer $DOMAIN) davorsetzen
     und ggf. den Port-Bindung in $COMPOSE auf 127.0.0.1:8443 begrenzen.
EOF

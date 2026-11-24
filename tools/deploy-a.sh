#!/usr/bin/env bash
# Etappe A deploy on dev-relay: admin panel listener on LAN ports 8480 (alpha) / 8481 (beta).
set -euo pipefail
export PATH=$PATH:/usr/local/go/bin
R=<repo>

echo '== binaries'
cd $R/relay
go build -o /usr/local/bin/relayd ./cmd/relayd
go build -o /usr/local/bin/lmcli ./cmd/lmcli

echo '== append admin section (idempotent)'
grep -q '^admin:' $R/relay-alpha.yaml || printf '\n# Etappe A: LAN-only admin panel (second listener; tunnel never points here)\nadmin:\n  listen: "<lan-host>:8480"\n  node_pubkey: ""   # empty = own lnd node (alpha)\n' >> $R/relay-alpha.yaml
grep -q '^admin:' $R/relay-beta.yaml || printf '\n# Etappe A: LAN-only admin panel (second listener; tunnel never points here)\nadmin:\n  listen: "<lan-host>:8481"\n  node_pubkey: ""   # empty = own lnd node (beta)\n' >> $R/relay-beta.yaml
tail -5 $R/relay-alpha.yaml; tail -5 $R/relay-beta.yaml

echo '== restart units'
systemctl restart bmail-relay-alpha bmail-relay-beta
sleep 2
systemctl is-active bmail-relay-alpha bmail-relay-beta
curl -sf http://127.0.0.1:8443/health >/dev/null && curl -sf http://127.0.0.1:9443/health >/dev/null && echo 'relay healths ok'

echo '== admin listeners'
curl -sf http://<lan-host>:8480/ -o /dev/null -w 'alpha panel: %{http_code}\n'
curl -sf http://<lan-host>:8481/ -o /dev/null -w 'beta  panel: %{http_code}\n'
echo '== DEPLOY A OK'

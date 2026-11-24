#!/usr/bin/env bash
# Etappe TL deploy on dev-relay: build, test, quota 200MB, unit swap, clamp DBs.
set -euo pipefail
export PATH=$PATH:/usr/local/go/bin
R=<repo>

echo '== go build + tests (units still running)'
cd $R/lm1 && go test ./envelope/ -count=1
cd $R/relay && go build ./... && go test ./internal/ledger/ -run 'Hold' -count=1

echo '== PWA build'
cd $R/client/app && npx vite build > /tmp/vite-tl.log 2>&1 && tail -2 /tmp/vite-tl.log

echo '== stop units, swap binaries'
systemctl stop bmail-relay-alpha bmail-relay-beta
cd $R/relay
go build -o /usr/local/bin/relayd ./cmd/relayd
go build -o /usr/local/bin/lmcli ./cmd/lmcli

echo '== clamp existing account quotas to 200MiB'
python3 - <<'EOF'
import sqlite3
for d in ("alpha", "beta"):
    c = sqlite3.connect(f"/var/lib/bmail/{d}/ledger.db")
    c.execute("UPDATE account SET quota_bytes=209715200 WHERE quota_bytes>209715200")
    print(d, "clamped rows:", c.total_changes)
    c.commit(); c.close()
EOF

echo '== start units'
systemctl start bmail-relay-alpha bmail-relay-beta
sleep 2
curl -sf http://127.0.0.1:8443/health | head -c 200 && echo
curl -sf http://127.0.0.1:9443/health | head -c 120 && echo
echo '== DEPLOY OK'

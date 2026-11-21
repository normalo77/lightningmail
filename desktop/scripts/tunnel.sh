#!/usr/bin/env bash
# CT114→CT113 relay tunnel (spec M1b): ALPHA/BETA hoeren auf 127.0.0.1 von
# CT113 -> dauerhaft forwarden: 18443→8443 (ALPHA), 19443→9443 (BETA).
# Usage: tunnel.sh start   (idempotent; "check" only tests, exit 1 if absent)
set -euo pipefail
MODE="${1:-check}"
if ss -tln 2>/dev/null | grep -q ':18443 '; then
  echo TUNNEL_OK
  exit 0
fi
if [ "$MODE" != "start" ]; then
  echo NO_TUNNEL
  exit 1
fi
ssh -f -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no \
  -L 18443:127.0.0.1:8443 -L 19443:127.0.0.1:9443 root@192.168.177.77
for _ in $(seq 1 10); do
  sleep 1
  if ss -tln 2>/dev/null | grep -q ':18443 '; then
    echo TUNNEL_STARTED
    exit 0
  fi
done
echo TUNNEL_FAIL
exit 1

# lightningmail

Lightning-Porto-Mail (Arbeitstitel). Docs: docs/CONCEPT.md, docs/PRECODING.md

## Dev: regtest-Stack + Smoke-Test

`make smoke` (auf dem Dev-CT, Docker erforderlich): bringt bitcoind + 2 LND-Knoten
(alpha/beta) via `test/docker/docker-compose.yml` hoch, eroeffnet einen 6-BTC-Kanal
alpha->beta und beweist einen keysend-Payment-Roundtrip mit bmail-Custom-TLV
(34349334..34349343). Idempotent, Exit-Code 0 = gruen.
Stack abbauen: `make smoke-down` (Daten bleiben in `test/docker/data/`, git-ignoriert).

# lightningmail

Lightning-Porto-Mail (Arbeitstitel). Docs: docs/CONCEPT.md, docs/PRECODING.md,
**docs/spec.md** (verbindliche M0-Spec: Wire-Format, Receipt-Flow, Discovery,
Ledger, Relay-API — Basis gegen die Etappe 2/3 baut).

## Bauen & Testen: Relay-Core (Go, Etappe 2a)

Voraussetzung: Go >= 1.22 (offizielles Tarball nach `/usr/local/go`, PATH via
`/etc/profile.d/go.sh`; kein apt-golang). Kein CGO noetig (SQLite-Treiber
`modernc.org/sqlite`).

```
cd relay && make all        # fmt-check + vet + test + build
go vet ./... && go test ./...   # dasselbe direkt
```

Pakete: `internal/envelope` (Wire-Format v0.1, §3 Spec), `internal/config`
(relay.yaml/relays.yaml, §6), `internal/crypto` (btcec/XChaCha20/Schnorr, §5),
`internal/ledger` (SQLite-WAL-Ledger, §8). `proto/bmail/v1/envelope.proto` ist
nur Doku (kein Codegen in v0.1). `cmd/relayd`, `lnclient`, HTTP-Server folgen
in Etappe 3.

Wurzeln Makefile delegiert: `make relay-check` (fmt+vet+test+build),
`make relay-test` usw.

## Dev: regtest-Stack + Smoke-Test

`make smoke` (auf dem Dev-CT, Docker erforderlich): bringt bitcoind + 2 LND-Knoten
(alpha/beta) via `test/docker/docker-compose.yml` hoch, eroeffnet einen 6-BTC-Kanal
alpha->beta und beweist einen keysend-Payment-Roundtrip mit bmail-Custom-TLV
(34349334..34349343). Idempotent, Exit-Code 0 = gruen.
Stack abbauen: `make smoke-down` (Daten bleiben in `test/docker/data/`, git-ignoriert).

## Release (v0.1.x)

Statisches Binary: `cd relay && CGO_ENABLED=0 go build ./...`
(NAS/Umbrel/Start9-tauglich, auch ARM: GOOS/GOARCH setzen). Go/Go-Modul
dokumentiert in `relay/go.mod` + `go.sum`; Releases als Tag `v0.1.0` auf main,
Backup-Remote `backup` (NAS-Bare-Repo). Deployment-Assets (Docker) = Etappe 3.

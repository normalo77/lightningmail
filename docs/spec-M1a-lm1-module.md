# Etappe M1a — lm1-Modul-Extraktion (shared Go-Krypto für relay + desktop)

Ziel: relay/internal/crypto und relay/internal/envelope werden ein eigenes Go-Modul
lm1/ auf Repo-Wurzel (github.com/lightningmail/lm1), das relay UND desktop importieren.
Reines Umziehen + Import-Pfade — KEINE Verhaltensänderung, KEine API-Umbenennung.

Arbeitsverzeichnis: /root/lm-m1 (lokaler Klon HEAD 0131c7a, Hermes-Host, Go
/usr/local/go/bin/go). NICHT committen, NICHT rsyncen Richtung CT — Parent macht
Deploy + Commit. Kommentare englisch (Konvention).

## Schritte
1. mkdir lm1; git mv-artig: relay/internal/crypto -> lm1/crypto, relay/internal/envelope
   -> lm1/envelope (Dateien inkl. Tests 1:1, package-Namen bleiben crypto/envelope).
2. lm1/go.mod: module github.com/lightningmail/lm1; require btcec/v2 + golang.org/x/crypto
   (Versionen von relay/go.mod kopieren); go mod tidy.
3. relay/go.mod: require github.com/lightningmail/lm1 v0.0.0 + replace => ../lm1.
4. Alle Importstellen umschreiben (15 Dateien, grep internal/crypto|internal/envelope).
5. desktop/go.mod: dasselbe require+replace ../lm1 (noch ohne Import — nur Vorbereitung,
   damit der Build des spike unveraendert laeuft).
6. proto/bmail/v1/envelope.proto bleibt unberuehrt (Doku-Artefakt).

## Gates (alle lokal auf Hermes)
- cd relay && go vet ./... && go test -count=1 ./... gruen (15 Import-Dateien, keine
  Testloeschen!)
- cd lm1 && go vet ./... && go test ./... gruen
- cd desktop && go vet ./... && go build -o /dev/null ./spike (spike.go importiert lm1
  noch nicht — muss unveraendert bauen)
- go build ./cmd/... in relay (relayd, lmcli, interop-relay)
- grep -rn "internal/crypto\|internal/envelope" relay desktop lm1 --include="*.go" = leer
  (auch in Kommentaren auf neue Pfade zeigen)
Report: Datei-Liste, Gate-Outputs, Auffaelligkeiten. Deutsch.

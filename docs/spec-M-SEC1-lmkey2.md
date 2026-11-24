# Etappe M-SEC.1 — LMKEY2 (argon2id) + Desktop-Hyggiene

Bernd-Beschluss: Keydatei ist das größte Risiko. Ziel dieses Blocks:
1. LMKEY2-Schluesseldatei-Format mit memory-hard KDF (argon2id), Lese-Kompat zu LMKEY1
   fuer alle Ewigkeit, Schriftpfad immer V2 — betrifft PWA (TS), lmcli + desktop (Go),
   und damit automatisch auch den serverseitig gespeicherten wrap_pass (derselbe String).
2. Desktop-Hyggiene: core-dumps aus, mlockall best-effort, PEM-Puffer zeroen.
NICHT in diesem Block (bewusst, Begruendung Doku): TPM2-Siegel (kein TPM in der
Build-Sandbox, hardwarefaehig), libfido2-PRF am Desktop (CGO-Rueckkehr), Auto-Rewrap
bestehender Dateien (ueberrascht Nutzer — V1 bleibt lesbar und sicher genug fuer den
Start, UI-Hinweis folgt spaeter).

Arbeitsverzeichnis <workspace> (Hermes; HEAD = neuster main). Kein git, kein rsync
Richtung dev-relay — Parent. Kommentare englisch, User-Strings deutsch.

## Format
LMKEY2$m=65536,t=3,p=1$<b64 16B salt>$<b64 24B nonce>$<b64 ct>
KDF: argon2id(passphrase, salt, time=3, mem=64*1024 KiB, threads=1, keyLen=32)
AEAD: XChaCha20-Poly1305 wie V1. Die Parameter-Sektion ist exakt ein
'k=v,k=v,...'-Feld (parser-tolerant: unbekannten key ignorieren NICHT, Fehler werfen —
streitig? NEIN: unbekannte Parameter = Fehler, damit niemand vergisst, dass m=1M
ignoriert wurde). V1-Erkennung bleibt (LMKEY1$-Praefix, PRF-Sonderfall wie bisher).
Min-Passphrase: 8 Zeichen wie bisher (keine UX-Aenderung; Doku-Hinweis auf Wortkette im
placeholder des Wizard-Felds wenn trivial ergaenzbar, sonst weglassen).

## Code-Orte
- lm1/crypto/keyfile.go (NEU): WrapKey/UnwrapKey fuer V1+V2, identische Semantik wie
  keywrap.ts (Include-Check 'PRIVATE KEY' nach Decodierung, Fehlermeldungen koennen
  deutsch sein wie im TS-Pendant? NEIN — Go-Fehlerstrings englisch (Code), API-
  Fehlermeldungen nach aussen bleiben wo sie sind). x/crypto/argon2 + chacha20poly1305 +
  pbkdf2 als deps in lm1/go.mod.
- client/src/keywrap.ts: V2 als canonicaler Schriftpfad (wrapKey erzeugt V2), unwrapKey
  akzeptiert V1|V2. Argon2 aus @noble/hashes/argon2.js (pruefe den import-Pfad gegen den
  installierten noble-Stand in lm-work node_modules und den im client/package-lock
  versionierten — beide Muessen denselben Export haben; sonst V2-TS-Pfad auf den
  vorhandenen Export anpassen, KEINE neue npm-Dependency ohne Report).
- lmcli + desktop/core config.go: Keyfile laden via lm1 keyfile (PEM, LMKEY1, LMKEY2);
  desktop: passphrase prompt im Terminal-Pfad (config hat keyfile-Pfad; wenn Datei
  gewrappt ist und keine Passphrase-Env -> gefuehrter Prompt; GUI-Client M1 hat dafuer
  noch kein Dialogfenster — dann klare Fehlermeldung, dass M2-Login-Dialog kommt;
  bewerte ob der run-desk-Pfad mit Klartext-PEM-Secretfile weiterlaeuft (tut er, seed
  nutzt .key PEM) — Hygiene zuerst, Prompt-UX spaeter).
- desktop/cmd/lmdesk main.go Start: syscall.Setrlimit(RLIMIT_CORE,{0,0});
  unix.Mlockall(MCL_CURRENT|MCL_FUTURE) best effort mit log-Zeile bei EPERM/RLIMIT —
  niemals abort. PEM-Lesepuffer []byte mit bytes.Replace(null,...) zeroen nach Parsen;
  shortcut: comment dass Go-Strings aus Config/JSON nicht garantiert zero-bar sind.
- Wizard/Download-Pfade die LMKEY1 schreiben: alle aufrufer bleiben wie sie sind,
  bekommen aber V2-Material (wrapKey-Ausgang). UI-Dateiname .lmkey bleibt.

## Tests (Herzstick — Paritaet)
1. client/test/m-sec-golden.mts (Node, Hermes): erzeugt deterministische Fixture-Date
   desktop/core/testdata/m-sec-golden.json: 3 V2-Faelle (feste salt/nonce/passphrase/pem,
   ct als b64) + 1 V1-Fall + 1 PRF-Weigerungsfall + 2 Negative (falsche Passphrase,
   unbekannter Parameter). Argon2-Parameter kleinster Code: noble argon2id EXAKT mit
   m=65536 (KiB), t=3, p=1, dkLen=32 — gegen x/crypto/argon2's ID(argon2id) mit
   memory=65536 iterations=3 parallelism=1. PRUEFE die Einheiten-Differenz (noble
   memoryKiB vs Go memory-KiB — sollten identisch sein; falls Paritaets-Test fehlschlaegt,
   Doku+Report, nicht stillschweigend Parameter biegen!).
2. lm1/crypto/keyfile_test.go: Golden-Abspielung (V2 lesen), V1-PBKDF2-Roundtrip selbst
   erzeugt gegen golden-Fixture, Unwrap->Wrap->Unwrap-Stabilitaet, Negative.
3. TS-unit: keywrap-test.mts erweitern um V1/V2 Roundtrip + V2->V1-Date lesbar (falls
   Fixture vorhanden; sonst node-seitig selbst erzeugen).
4. lmcli-key-Pfad: kleiner Go-Test oder manuelles Kommando (Parent) mit erzeugter
   V2-Testdatei: 'lmcli init/login liest V2'. lmcli main.go anpassen falls dort PEM-only
   Parser steht (grep 'PRIVATE KEY\|LMKEY' cmd/lmcli).

## Gates
- lm1: go vet+test gruen (neue Tests aktiv!), relay: go test ./... gruen, desktop:
  go vet/test ./core/... gruen, Hermes-Node: npx tsx client/test/keywrap-test.mts +
  m-sec-golden.mts erzeugen OK, desktop-Build auf dev-sandbox NICHT noetig (nur core — Parent
  macht GUI-Deploy-Check), mlockall/Rlimit-Code laeuft ohne root (best-effort-Pfad
  testweise in Testmain oder Comment mit Referenz).

## Report
Dateien, Gate-Outputs, Paritaetsbefund noble-vs-xcrypto (Einheiten!), lmcli-Anpassung,
offene UX-Punkte (M2-Login-Dialog), Abweichungen. Deutsch.

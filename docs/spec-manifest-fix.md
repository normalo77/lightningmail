# Protokollfix — Manifest-only Blob-Refs (Etappe 7 Nachzug, Bernd-Freigabe 21.11.)

Arbeitsverzeichnis: <workspace> (lokaler Klon HEAD baa8923). NICHT committen, NICHT
rsyncen, kein ssh auf dev-relay/Prod — Parent deployt. Go: /usr/local/go/bin/go.
Kommentare: ENGLISCH (Konvention). Kein UI-String darf sich aendern.

## Problem (verifiziert)
- Ein >1MiB-Anhang wird in 1MiB-Scheiben + Manifest-Blob zerlegt; send.ts schreibt AKTUELL
  JEDES Slice-Hash ins Envelope-Feld BlobRefs (Zeile ~78 Kommentar "all hashes into the
  envelope"). Folge: Envelope-Historie skaliert O(Scheiben), Go-Decode kappt bei
  MaxBlobRefs=16 (relay/internal/envelope/envelope.go:31,71), der 600B-Plan aus
  docs/spec.md §Envelope und echte Onion-Groessen laufen davon weg.
- Ziel: Im Envelope steht pro Anhang NUR noch der Manifest-Hash (1 Ref). Die Scheiben
  spiegelt das Empfaenger-Relay, indem es das (unverschluesselte JSON-)Manifest liest —
  Scheiben-Hashes sind Content-Adressen von Chiffrat-Slices, fuer das Relay also blinde
  Zahlen. Empfaenger-Client laedt sie wie ueblich GET /v1/blob/<sha> (funktioniert schon,
  weil die Slice-Refs bis jetzt von der Mirror-Registrierung kamen — das liefert neu die
  Manifest-Walk-Registrierung).

## BEVOR du irgendetwas aenderst — Erstverifikation (im Report dokumentieren!)
V1. Wo wird das 600B-Envelope-Limit CODE-SEITIG erzwungen? (grep 600/len(env) in
    relay/internal/**; relaysrv handleSend, lmcli, envelope.go.) m11-test hat 20 Refs
    durchgewinkt — wenn es KEINEN 600B-Guard gibt, ist das keine neue Baustelle, sondern
    dokumentierte Realitaet: Limits sind 255 Refs-Feldbyte + Onion-Praxis. Erfinde keinen
    neuen Guard.
V2. Baue einen 3MB-Zufallsanhang roundtrip auf den LOCALEN Weg: TS-Decode/Encode reicht
    fuer den Beweis des neuen Formats; der echte Cross-Relay-Beweis passiert spaeter auf
    dev-relay durch den Parent — versuche NICHT, Regtest-Relays zu starten.

## Aenderungen

### 1. envelope.go
MaxBlobRefs = 255 (comment: field count byte holds 255; manifest-only makes >1 per
attachment exceptional, legacy envelopes may carry many slice refs).

### 2. client/src/send.ts — Attachment-Pipeline
Pro Anhang nur manifest-sha in blobRefs (und als parts-id wie bisher). Alte Multi-Ref-
Anhange bleiben decode-bar (nichts loeschen). Achte auf die Dedup-Logik: slice-sha und
manifest-sha werden weiterhin GELADEN (POST /v1/blob), nur die Envelope-Referenzliste
schrumpft. upload() Rueckgabe + Fehlerpfade unveraendert.

### 3. relayd mirrorBlobs (cmd/relayd/main.go:250ff) — Manifest-Walk
Nach dem Spiegeln jedes envelope-refs: content-type/JSON-Heuristik — wenn der gespiegelte
Blob wie ein Manifest aussieht (parse als {v:1, parts:[{sha(hex64),size},...]} mit exakt
den manifestBytes-Feldern aus client/src/chunks.ts — LIES zuerst manifestBytes/Manifest
und kopiere die Toleranzen 1:1), dann:
  - max 255 parts akzeptieren, mehr verwerfen (log)
  - jede part-sheibe vom Sender-Relay holen (bestehender fetch-Mechanismus) + lokal
    speichern + RegisterBlobRef(empfaenger) wie beim Haupt-Ref
  - NUR EINE EBENE (manifest-inside-manifest ignorieren), keine Rekursion
  - Gesamtvolumen-Guard: sum(size) > 4GiB -> abbrechen + loggen (shortcut-Kommentar:
    hartcodiert, config kommt wenn je noetig)
  - ein fehlendes Slice darf den Rest nicht kippen: pro-Slice-Fehler = log + skip
    (Empfaenger-Client zeigt Stueck dann als nicht laden — besser als Halbwaisen-Brief)
  - Idempotenz: os.Stat-Check wie vorhanden weiter nutzen
WICHTIG: Die Mirror-Funktion laeuft im Settlement-Pfad — alles was du dort einziehst muss
schnell/fehlerfrei sein; kein Retry-Feuerwerk, keine blocking-Sleeps.

### 4. Tests
- Go envelope: Roundtrip mit 255 Refs (Encode->Decode), 256 -> Fehler. (Datei envelope_test.go)
- Go relaysrv/relayd: Unit-Test fuer den Manifest-Parser/Heuristik (echtes manifestBytes-
  JSON-Fixture vs. Nicht-Manifest-Binaerdaten; cap 255; cap volume; hex64-Validierung).
  Der Parser lebt in einer exportierbaren Funktion, damit er ohne LND testbar ist.
- client/test/m9b-manifest-only.mts (Neu, Muster m9-chunked-attachment.mts + m10):
  * 12MB-Zufallsdatei (crypto-Zufall, NICHT periodisch!) alice->bob ueber die echten
    Regtest-Relays (RELAY_A/RELAY_B env, wie m9) — war mit 16-Ref-Limit undichte Grenze;
  * Beweis 1: bob downloadet 12MB bytegleich (sha256-Vergleich im Test);
  * Beweis 2: Enviro-Ref-Liste der Mail == genau 1 Blob-Ref (manifest) — via GET inbox
    raw envelope b64 -> Feld 0x03 zahlen;
  * Beweis 3: auf BOBs Relay existieren 12 Slice-Blobs + 1 Manifest auf Platte (ssh? NEIN —
    via bob GET /v1/blob/<slice> 200 fuer zufaellig 3 slices);
  * Beweis 4: legacy-Kompat — ein Manuell gebauter Multi-Ref-Envelope (wie alter Client,
    3 slices refs) wird weiterhin zugestellt und laedt (klein, 1.5MB).
- Bestehende m9/m10/m11 lassen wir auf dem Parent laeuft nach Deploy — du pruefst lokal
  NUR go test + tsx-Syntax (node --check oder esbuild der .mts) — die mts gegen echte
  Relays kann hier nicht laufen, das ist okay und im Report so zu sagen.

### 5. Doku im gleichen Diff
- docs/spec.md: Envelope-BlobRefs-Abschnitt auf manifest-only umschreiben (deutsch wie der
  Rest der Doku — Doku-Regel: docs bleiben deutsch; §-Nummer beibehalten, Satz
  "(seit 21.11. traegt das Envelope nur noch Manifest-Refs, Slice-Spiegelung uebernimmt
  das Relay per Manifest-Walk)" ergaenzen).
- CONCEPT.md §22: gleicher Hinweis, + dass 254MB-Grenze jetzt praktisch gilt.

## Gates bevor du reportest
go vet ./... && go test -count=1 ./internal/... ./cmd/... (relay-Modul, gruen)
npx esbuild client/src/send.ts --bundle (Hermes-Node 18 vorhanden, Symlink wie ueblich) —
KEIN V-irgendwas-Wort im Befehl fuer Bundle-Checks, nutze tools/esb-bundle.sh.

## Report
V1/V2-Befund, geaenderte Dateien, Gate-Outputs, Test-Entwuerfe m9b (laeuft erst auf CT),
offene Risiken. Deutsch.

# Etappe R — Versand-Spool: store-and-forward am Sender-Relay

Beschluss Bernd 22.11.: Relay-Downtime darf keine Mails kosten. Der Sender-Relay wird
die Postwagen-Station: scheitert die keysend-Zustellung beim Empfaenger-Relay, wird die
Mail persistent 'pending' gespeichert und mit Backoff erneut versucht; nach Retention
wird sie zum Dead Letter mit Porto-Rueckerstattung. Kein Protokollbruch, keine neue
Trust-Grenze (alles bleibt beim ohnehin vertrauten eigenen Relay).

Arbeitsverzeichnis <workspace> Kein git/rsync — Parent deployt/committet. Kommentare
englisch, User-Texte deutsch.

## Vorab-Verifikation (Report!)
R0a. handleSend-Zustellpfad exakt nachlesen (relay/internal/relaysrv + cmd/relayd
     interceptor + mailbox INSERT): Wo genau scheitert heute 'Empfaenger down' (Zeile mit
     502), und wo koennte man ohne Race persistieren, BESSER: direkt in handleSend
     (relaysrv) oder im keysend-Aufruf (relayd)? Der Spool muss den Prozess-Reload
     ueberleben -> SQLite, nicht In-Memory.
R0b. Mailbox-Schema pruefen: msg_id UNIQUE? Falls nein: INSERT OR IGNORE / unique index
     nachlegen (Migration nach ensure-Muster), damit Retry nie doppelt zustellt.
R0c. Wo wird dem Absender das Porto abgebucht (POST /v1/send Payment? foreign_sats
     Einbehalt local)? Rueckerstattung muss auf derselben Waelhrungs-/txlog-Schiene
     (KindFee refund, ref 'dead-refund:<msg_id>').

## Design
- Neue Tabelle pending_send (id INTEGER PK, msg_id TEXT UNIQUE, recipient TEXT,
  envelope BLOB, blob_refs TEXT json, status TEXT ('pending'|'dead'), attempts INT,
  next_try INT, created_at INT, updated_at INT). ensurePendingSend()-Migration.
- handleSend-Pfad: bei keysend-/peer-Fehler NICHT mehr 502-an-Client-verlieren, sondern:
  persist pending_send (wenn msg_id fehlt: lokal generieren? NEIN — msg_id kommt aus dem
  Envelope-Feld, existsiert schon), Antwort an Client 202 {status:'pending'} statt 200.
  Erfolg bleibt 200 {status:'settled'}.
- Retry-Engine (relayd-Service-Ticker 60s, wie 6b Receipts-Muster):
  alle pending mit next_try<=now -> Zustellversuch (derselbe Code-Pfad wie initial).
  Erfolg: row loeschen (oder status='delivered' mit TTL-Cleanup 90d? — loeschen ist
  ehrlicher, delivered-Info steht im Receipt-System).
  Misserfolg: attempts++, next_try = backoff: 5m,30m,2h,6h,12h,24h, danach taeglich;
  created_at aelter als retention (Konstante 14 Tage, shortcut-Kommentar) -> status='dead'
  + Porto-Rueckerstattung an Absender-Konto (txlog refund) und Blob-Quota bleiben wie sie
  sind (Anhange verfallen ja mit der normalen Mail-Retention).
  Idempotenz: gleicher msg_id im Envelope -> mailbox INSERT OR IGNORE (R0b).
  Kein Retry-Feuerwerk parallel zum Ticker: ein Versuch pro row pro Tick, singleflight.
- GET /v1/outbox (auth): [{msg_id,status,since}] pending+dead fuer dieses Konto.
- Cleanup: dead rows aelter 90d loeschen; pending bleiben bis Erfolg/Retention.
- /health bekommt spool: {pending:N} (klein, fuer Monitoring).

## UI (PWA minimal, desktop bleibt M2)
- client/app/main.ts: 'Gesendet' Liste zeigt pro Mail Status-Chip: kein pending=kei Chip;
  pending -> 'unterwegs seit <datum>' (gelb), dead -> 'unzustellbar, Porto
  zurueckerstattet' (rot). Datenquelle: GET /v1/outbox beim Rendern der Gesendet-Ordners
  (ein Fetch, keine Polling-Expansion); msg_id-Matching aus Envelope-Feld 0x01.
- Send-Erfolgsmeldung im Compose-Dialog: bei 202 'wird nachgeliefert (Empfaenger
  voruebergehend nicht erreichbar)' statt 'gesendet'.

## Tests
1. Go (relaysrv + relayd): Unit mit httptest-Peers die erst 500 liefern dann 200:
   pending-Zeile entsteht, Ticker-Funktion (exportiert, direkt aufrufbar) liefert nach
   'Heben' zu, mailbox bekommt GENAU eine Zeile (R0b-Idempotenz), double-settle-Szenario
   (Ticker laeuft zweimal).
2. Go: dead-letter nach Retention (Test setzt created_at zurueck), Refund-Buchung auf
   Absender-Balance, outbox-Eintrag status dead.
3. client/test/m-r-spool.mts (CT, Parent faehrt): alice sendet an bob waehrend beta
   gestoppt -> 202 pending; Parent startet beta; Test pollt /v1/outbox bis settled und
   prueft bobs inbox 1x, balance-Rueckstand konsistent. (Kein refund noetig im Happy.)
   Script nimmt an: beta stop/start kann der Parent (unit-Tests nicht), deshalb
   zweigeteilt: tsx-Teil prueft nur API+Anzeige-Pfaden gegen bereits laufendes System
   mit seedbarer pending-Row (direkter sqlite-insert wie chunk-test-Muster).
4. UI-Chip: kleiner DOM-Test nur wenn vorhanden (renderSent), sonst Parent browsercheck.

## Gates
go vet/test relay ./internal/... ./cmd/... gruen; lm1 unberuehrt gruen; desktop core
gruen; tsx m-r-spool.mts Syntax+Bereitstellung lokal gegen mock? (reicht node-check);
bestehende m10/m-r? Regression vom Parent nach Deploy.

## Report
R0a-c Befunde mit Datei:Zeile, Dateien, Gates, welche Tests erst auf CT laufen,
Abweichungen. Deutsch.

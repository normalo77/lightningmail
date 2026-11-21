# Etappe J1 — Drive Server-Kern (relayd)

Arbeitsverzeichnis: /root/lm-drive (lokaler Git-Klon, NICHT committen, NICHT rsyncen,
NICHT auf CT113 sshen — Parent deployt und verifiziert). Go liegt in /usr/local/go/bin.
Stil: existierende Muster im Code 1:1 nachbauen (ensureRetention, byteporto, ApplyDeltaMeta).
Keine neuen Dependencies.

## Kontext (bereits recherchiert, glaub das)
- internal/ledger/ledger.go: blob-Rechte über Tabelle blob_refs (sha256, account_id, bytes,
  created_at, +downloaded_at via ensureRetention()). Funktionen: RegisterBlobRef(accountID,
  sha [32]byte, size) (fresh,err) mit INSERT OR IGNORE (Zeile UNIQUE pro (sha,account)),
  HasBlobAccess, BlobUsage (SUM bytes), CheckQuota, DeleteBlobRefs(sha) (löscht ALLE refs),
  RetentionSweep(now,grace,max) GROUP BY sha256 über ALLE refs.
- account.quota_bytes: in CreateAccount hart auf 104857600 gesetzt (ledger.go ~192).
- POST /v1/blob Handler = handleBlobUpload in internal/relaysrv/relaysrv.go (~572):
  ContentLength/LimitReader gegen cfg.Postage.BlobMaxBytes, CheckQuota, sha256,
  Datei Pfad cfg.DataDir+"/blob/"+hex[:2]+"/"+hex, Byte-Porto NUR bei !HasBlobAccess
  (ApplyDeltaMeta KindFee ref "blob:"+hex), erst kassieren dann schreiben, Fehlerpfade
  refundBytePorto. Route: mux.HandleFunc("/v1/blob", s.auth(s.handleBlobUpload)).
- config: relay/internal/config/config.go, Sektionen Postage/Retention/Rates/WebAuthn;
  ParseConfig setzt Defaults; Validierung sammelt errs (ErrValidation).
- schema.sql (internal/ledger/schema.sql, embed) baut frische DBs; neuere Spalten kommen
  per ensure*-ALTER (Muster ensureRetention), user_version bleibt 4.

## Zu bauen

### 1. ledger: kind-Spalte
ensureDrive() exakt nach ensureRetention-Muster:
  ALTER TABLE blob_refs ADD COLUMN kind TEXT NOT NULL DEFAULT 'mail'
(duplicate-column ignorieren). In RegisterBlobRef/RemoveDriveRef/Sweep zuerst aufrufen.
- RegisterBlobRef(accountID, sha, size, kind string): INSERT OR IGNORE ... (sha,acct,bytes,
  created,kind). Wenn Zeile schon existierte (n==0) UND neue kind='drive': UPDATE diese
  Zeile SET kind='drive' (Promotion ist stickig; mail darf drive nie zurücksetzen).
  Rückgabe fresh unverändert semantisch: true nur wenn Zeile neu entstand.
- RetentionSweep: GROUP-Abfrage erweitern, so dass ein sha, der MINDESTENS EINE
  kind='drive'-Ref hat, NIE gelöscht wird. SQLite: ... GROUP BY sha256
  HAVING SUM(CASE WHEN kind='drive' THEN 1 ELSE 0 END)=0.
- RemoveDriveRef(accountID int64, sha [32]byte) (remaining int64, err error):
  DELETE FROM blob_refs WHERE sha256=? AND account_id=? AND kind='drive'; dann
  SELECT COUNT(*) nach sha → remaining. Kein Rückweg für mail-refs (v0).
- AddQuotaBytes(name string, delta int64) error: UPDATE account SET quota_bytes=quota_bytes+?,
  updated_at=now() WHERE name=? (returniert ErrAccountNotFound bei 0 rows analog GetAccount).
- CreateAccount(name, pubkey, quotaBytes int64): Signaturen-Erweiterung; INSERT nutzt
  den Parameter statt der Konstanten.
- Tests (internal/ledger/*_test.go, :memory:-Muster wie retention_test.go):
  Promotion mail->drive stickig, drive->mail bleibt drive; Sweep verschont drive-sha
  (auch Mischfall mail+drive gleiches sha), mail-sha fällt weiterhin; RemoveDriveRef
  zählt remaining; AddQuotaBytes rundet auf / erhöht usage-Spielraum.

### 2. config: Drive-Sektion
type DriveTier struct { GB int64 `yaml:"gb"`; Sats int64 `yaml:"sats"` }
type Drive struct { Enabled bool `yaml:"enabled"`; QuotaMB int64 `yaml:"quota_mb"`;
  Tiers []DriveTier `yaml:"tiers"` }
Config += Drive Drive `yaml:"drive"`. Default wenn 0/ungesetzt: QuotaMB=5120.
Validierung: QuotaMB>0; Tier gb>0 und sats>0. config_test.go += parse/default/fall-Tests.

### 3. relaysrv
handleAccount: CreateAccount(..., s.cfg.Drive.QuotaMB*1048576).
handleBlobUpload: am Anfang kind := r.URL.Query().Get("kind"); Default "mail"; wenn
  kind=="drive" && !cfg.Drive.Enabled → 404 {"error":"drive disabled"}; nur "mail"|"drive"
  akzeptieren sonst 400. Alle RegisterBlobRef-Aufrufe mit kind durchreichen (auch chunks?
  Chunk-Uploads gehen durch denselben Endpoint, Client setzt ?kind=drive — fertig).
Methoden-Verzweigung: wenn r.Method=="DELETE" → handleDriveRelease (Route bleibt die
  vorhandene "/v1/blob" auth-Route; 405-Check oben umbauen auf POST/DELETE erlaubt).
handleDriveRelease (auth): JSON {sha:"<hex64>"}; sha parsen (Fehler 400); acct lookup;
  RemoveDriveRef → wenn die account-überhaupt keine drive-Zeile hatte (remaining unverändert
  bzw. Referenz existierte nicht als drive) → 403. Sonst: wenn remaining==0 →
  os.Remove(DataDir/blob/hex[:2]/hex) (IsNotExist ok) und refs für alle Accounts? NEIN —
  nur wenn keine refs mehr für den sha existieren (remaining==0), Zeilen sind dann eh weg,
  andere Accounts haben eigene Zeilen und damit remaining>0. Response
  200 {"released":true,"remaining_refs":N}.
GET /v1/drive/usage (auth): {"enabled":cfg.Drive.Enabled,"used_bytes":BlobUsage,
  "quota_bytes":acct.QuotaBytes,"tiers":[{gb,sats},...]}.
POST /v1/drive/buy (auth): JSON {"tier":<index>}; enabled prüfen; index gültig sonst 400;
  Preis sats→msat (*1000); ApplyDeltaMeta(name, -msat, ledger.KindFee,
  "drive-tier:"+<gb>+"GB", "btc", s.ratePtr()) — bei Balance-Fehler 402 wie byteporto;
  dann AddQuotaBytes(name, gb*1073741824); Response {"quota_bytes":neu,"cost_sats":sats}.
  Reihenfolge: ERST kassieren, DANN quota erhöhen (AddQuotaBytes-Fehler → Refund über
  Gegenbuchung KindFee ref "refund:drive-tier:...").
routes(): += "/v1/drive/usage", "/v1/drive/buy".
/health: JSON += "drive":{"enabled":...,"quota_mb":...}.
Go-Tests in internal/relaysrv (httptest + routes()-Muster aus ui_test.go/byteporto_test.go):
  drive disabled → 404; enabled: POST ?kind=drive 200 + usage zählt; DELETE-Flow lässt
  usage sinken und Datei ist weg wenn letzte ref; fremdes-sha DELETE → 403; buy: Balance
  -5000 sat, quota +gb, txlog ref 'drive-tier:' vorhanden; 402 bei Pleite.

## Verifikation bevor du fertig bist
/usr/local/go/bin/go vet ./...  &&  /usr/local/go/bin/go test ./internal/... ./cmd/...
Muss GRÜN sein (die laufenden Bestehenden auch — nothing breaks). report: geänderte Dateien
+ Testoutput-Kurzfassung. Keine git-Operationen.

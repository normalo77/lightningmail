# bmail v0.1 — M0-Spec (Wire-Format, Receipt, Discovery, Ledger, API)

Stand: 12.11.2026 · Etappe 3b · Portomail-Flow, 1-MB-Attachment-Roundtrip, Replay-Ablehnung, Balance-Assertions.
Verbindliche Setzungen: docs/PRECODING.md §B, vorgegeben durch Bernd/Hermes.
Code: `relay/internal/{envelope,config,crypto,ledger}` — Spec und Code müssen
schrittgehalten; bei Abweichung gewinnt diese Spec (Issue öffnen).

---

## 1. Schichten und Transport

```
Client ──(HTTPS: auth/send/inbox/balance/blob)──► Relay
Relay  ──(LN-Keysend: Porto + Envelope als Onion-TLVs)──► Relay   [Etappe 3]
```

Der Envelope ist die kanonische Nachrichten-Einheit. Er wandert
(a) als HTTP-Body client→relay und (b) als Wert von Keysend-TLV 34349334
relay→relay. Etappe-1-Verifikation (test/smoke.sh): Envelope-TLVs kommen am
Empfänger-Relay über die keysend-Invoice an und sind aus den `custom_records`
der Invoice bzw. der HTLCs lesbar.

**LND-Grenze (Etappe-1-Erkenntnis, designkritisch):**
`lnrpc.Invoice.cltv_limit… protocol.custom-message` akzeptiert als notierbare
Invoice-Custom-Records nur Keys ≤ uint16 (65535). Die bmail-TLV-Typen
(34349334 ff.) passen nicht in diesen Key-Raum. **Folge:** der einzahlende
Relay liest die Records aus der PayAddr-/Onion-Ebene (SubscribeSingleInvoice →
`htlcs[].custom_records`), nicht als registrierte Invoice-Records. Kein Design-
hindernis, nur Implementierungspfad für Etappe 3 (lnclient).

## 2. Keysend-TLV-Registry (Onion-Ebene)

Registry-Nummern folgen dem sphinx/whatsat/satoshis.stream-Konsens (interoperabel,
in Etappe 1 real verifiziert); bmail erfindet die Nummern nicht neu:

| TLV-Typ  | Name               | Länge / Format                                   | Pflicht |
|----------|--------------------|--------------------------------------------------|---------|
| 548997074| keysend preimage   | 32 B (LND-Keysend-Konvention)                    | ja      |
| 34349334 | bmail envelope     | Envelope-Binary (Abschnitt 3), ≤ 600 B           | ja      |
| 34349337 | transport sig      | 64 B BIP340-Schnorr, Signierschlüssel = Relay-Nodekey, Digest = sha256(Envelope-Binary) | ja |
| 34349339 | relay pubkey       | 33 B compressed secp256k1 (sender-relay NodeKey) | ja      |
| 34349343 | timestamp          | 8 B BE unix-secs (= Envelope-Feld 0x06, Redundanz für Onion-Ebenen-Freshness) | ja |

Größenrahmen: Onion-Payload pro Hop ≈ 1300 B; TLV 34349334 deshalb auf
**600 B Envelope-Hardlimit** gedeckelt (Payload-Ciphertext ≤ 480 B; größere
Inhalte → Attachment-/Chunking-Pfad, M2). Das empfangende Relay verifiziert
34349337 mit der NodeKey aus 34349339 gegen die im Ledger hinterlegte Peering-
Identität (Abschnitt 7.3), prüft dann Envelope-Signatur (3) und legt die
Nachricht ins Postfach.

## 3. Wire-Format v0.1: Envelope (Binär, ohne protoc)

Enkodiert von Hand, length-prefixed. `proto/bmail/v1/envelope.proto` ist
ausschließlich Doku/Single-Source der Feld-Tags (kein Codegen in v0.1).

### 3.1 Framing

```
 0        3        4
+--------+--------+-----------------------------+
| "LM1"  |  ver   |  Felder …                   |
+--------+--------+-----------------------------+
```
- magic: 3 B `0x4C 0x4D 0x31` ("LM1")
- version: 1 B, v0.1 = `0x01`
- Felder, nacheinander: **Tag (1 B) | Länge (2 B BE) | Wert (Länge B)**
- Canonical: Tags streng aufsteigend, jeder bekannte Tag höchstens einmal,
  unbekannte Tag-Nummer → Decode-Fehler (harte Versionierung über das
  version-Byte).编码器/Decoder: `relay/internal/envelope`.

### 3.2 Feld-Tags

| Tag  | Feld                 | Wert-Länge        | Pflicht | Bedeutung |
|------|----------------------|-------------------|---------|-----------|
| 0x01 | recipient_hash       | 32 B              | ja      | `sha256(mailbox_pubkey[33 B])` des Empfänger-Postfachs; der Relay routet übers Postfach-Verzeichnis (Ledger UNIQUE-Index), Adresse/Key bleibt portabel (CONCEPT §4.1) |
| 0x02 | msg_id               | 32 B              | ja      | Zufall vom Sender-Client; Dedup-Key im Postfach |
| 0x03 | blob_refs            | 1 B n + n×32 B    | nein    | n ≤ 255; sha256 der Attachment-Blobs (Blob-Store, Abschnitt 6.3), Reihenfolge = JSON-Reihenfolge. (seit 21.11. trägt das Envelope nur noch Manifest-Refs, Slice-Spiegelung übernimmt das Relay per Manifest-Walk, Abschnitt 6.5) |
| 0x04 | sender_pubkey        | 33 B              | ja      | compressed secp256k1, Absender-Mailbox-Key (Signatur-Key) |
| 0x05 | signature            | 64 B              | ja      | BIP340-Schnorr über `sha256(Serialisierung OHNE Feld 0x05)` |
| 0x06 | timestamp            | 8 B BE            | ja      | unix-secs, Erzeugung |
| 0x07 | postage_receipt      | 8 B BE sats + 32 B preimage | nein | Quittung einer früheren Portozahlung (Receipt-Modell, Abschnitt 4); belegt Zustell-Akzeptanz z. B. fürs Konversationsfenster (M3) |
| 0x08 | payload_ciphertext   | 24 B nonce + ct   | ja      | XChaCha20-Poly1305; ct = plaintext‖16-B-Tag |
| 0x09 | ephemeral_pubkey     | 33 B              | ja      | ECIES: ephemeraler Sender-Key, aus dem der Empfänger das Payload-Secret ableitet (5.2) |

Reservierte Tags für M2: 0x0A reply_to_msg_id (32 B), 0x0B conversation (32 B),
0x0C–0x0F padding-Klassen. Neue Pflichtfelder bekommen neue Tag-Nummern und
werden erst mit version `0x02` Pflicht.

### 3.3 Innerer Payload (JSON, nur vom Empfänger lesbar)

Klartext vor Verschlüsselung, UTF-8, keine Feld-Order-Garantie:

```json
{
  "subject": "Betreff",
  "body": "Rumpftext (UTF-8)",
  "headers": {"antwort-an": "gisela@bmail.de", "in-reply-to": "<hex msg_id>"},
  "attachments": [
    {"sha256": "<hex32>", "name": "foto.jpg", "size": 123456}
  ]
}
```
Konsistenz-Regel (Client-seitig beim Dekodieren zu prüfen):
`attachments[i].sha256 == blob_refs[i]`; Blobgröße ≤ 10 MB (PRECODING §B).

## 4. Receipt-Modell (Porto-Flow, Preimage = Quittung)

Hold-Invoice ist M3 (PRECODING §B). v0.1: ganz normale keysend-Zahlung; die
von LND dem Zahler mitgeteilte Preimage ist die Zustell-Quittung.

```
Client A        Sender-Relay α          LND α ──────── LND β          Empfänger-Relay β      Client B
   │ POST /v1/send      │                    │              │                │                   │
   │ (Envelope)         │                    │              │                │                   │
   ├───────────────────►│ Ledger: A um Porto │              │                │                   │
   │                    │  belasten (8.2)    │              │                │                   │
   │                    │  keysend: β-NodeKey│              │                │                   │
   │                    │  amt=porto_sats,   │              │                │                   │
   │                    │  TLV 34349334=Env, ├─────────────►│   onion+AMT    │                   │
   │                    │  37/39/43 Meta     │              ├───settled─────►│ 1) 34349337 verif. │
   │                    │                    │              │                │    (Peering-Key)   │
   │                    │                    │              │                │ 2) Envelope-Sig    │
   │                    │                    │              │                │    0x05 verif.     │
   │                    │                    │              │                │ 3) recipient_hash  │
   │                    │                    │              │                │    → Postfach (β)  │
   │                    │                    │              │                │ 4) Ledger: B       │
   │                    │                    │              │                │    +porto (8.2)    │
   │                    │ PaymentStatus(R)   │              │                │    (preimage R)    │
   │                    │◄───────────────────┤              │                │                    │
   │◄─── 202 {msg_id, receipt:{sats,R}} ─────┤              │                │                    │
   │ (Quittung lokal speichern;              │              │                │   WebSocket-Push   │
   │  spätere Antwort trägt sie in Tag 0x07) │              │                │   / Poll GET /inbox ─►│
```

Regeln:
- **No stamp, no delivery:** ohne beglelichene keysend-Zahlung mit gültigem
  Envelope-TLV legt das Empfänger-Relay nichts ins Postfach (CONCEPT §3).
  Porto geht als Guthaben an das Empfänger-Postfach (Pay-to-Recipient, §6).
- Preis: Empfänger-Profil; v0.1-Default 10 sats Fremde / 0 Kontakte
  (`postage.*` in relay.yaml, Abschnitt 7.2). Der Sender-Relay erfragt den
  Preis vor dem Senden (GET /v1/profile/{address}, M1-Implementierung).
- **Quittung = Preimage R:** die Zahlung ist eine ganz normale Bolt11/Keysend-
  Rechnung; der zahlende Relay liest R aus dem PaymentStatus und gibt sie dem
  Client. Tag 0x07 in einer Gegenantwort beweist dem Empfänger-Relay: „für
  msg_id X wurde Porto akzeptiert“ → Basis für das Konversationsfenster (M3).
- Ablehnbar ohne Hold: Zustell-Zusage 24 h über Invoice-Expiry
  (CONCEPT §13), Dead-Mail-Porto fällt an den Relay-Pool (§4.2 Ebene 2).
- Reload des Kontos: Client zahlt per LUD-16-Adresse des Relays ein (Topup),
  der Relay schreibt die einzahlende Payment (custom_records der
  keysend-Invoice, Abschnitt 1) dem Konto gut (Etappe 3).

## 5. Krypto

| Zweck            | Verfahren                                                              |
|------------------|------------------------------------------------------------------------|
| AEAD (Payload)   | XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`), 24 B Nonce, random pro Nachricht; AAD = `recipient_hash ‖ msg_id` (32+32 B) |
| Payload-Key      | ECIES light: `eph` Zufalls-Key, SharedSecret = X-Koordinate `sha/ECDH(eph_priv, recipient_pub)`, Key = HKDF-SHA256(secret, salt="", info="bmail-payload-v1") → 32 B. Dekodierung nur mit Empfänger-PrivKey; der Relay sieht nur ct (CONCEPT §2.4) |
| Envelope-Signatur| **BIP340-Schnorr** über secp256k1 (btcec/v2). Wahl statt ECDSA, dokumentiert: deterministischer Nonce (kein RFC6979-/Nonce-Wiederverwendungs-Risiko), 64 B fest, x-only-Identität passt zu LN/sphinx-Kosystem |
| Node/Relay-Key   | secp256k1 (LND-NodeKey), Transport-Sig 34349337 desselbe Verfahren      |
| Key-Ablage Client| SEC1 `EC PRIVATE KEY`-PEM, DER von Hand kodiert (crypto/x509 lehnt secp256k1 bei EC-Marshal ab, Go 1.27 verifiziert); Datei 0600; Backup = Seed (M2) |

`crypto`: `relay/internal/crypto` (Generate/PEM-Load, Seal/Open, Sign/Verify,
EncryptForRecipient/DecryptForRecipient).

## 6. Discovery & Blob (Relay-seitig)

### 6.1 relays.yaml (statisch, M0) — parsergleich zum späteren DNS-TXT

Schema spiegelt 1:1 den TXT-Record aus CONCEPT §4.2 (`_bmail._tcp.<domain>`,
`v=bmail1; relay=…; onion=…; node=…; policy=…; key=…`). DNS-Lookup ist dann ein
Drop-in: gleiche Struktur, gleicher Parser.

```yaml
schema: bmail1              # Pflicht, sonst Fehler (== v=bmail1)
records:                    # mindestens 1 Eintrag
  - domain: bmail.de        # Pflicht, lowercase (IDN→Punycode-Regel: Client)
    relay: https://alpha.internal:8443   # Pflicht, https-URL
    onion: abcdef234567.onion           # optional (M2+)
    node: 03ab..cdef                    # Pflicht: 33 B hex (LND-NodeKey)
    policy: https://bmail.de/policy.json # optional (Preisprofile, M3)
    key: pgp:1234…                      # optional (WoT-Anker, M3)
```
Validierung (config-Paket): schema-Feld == bmail1; domain nicht leer/uniq;
relay-URL: https (http nur localhost/127.* für regtest-Dev, Etappe 3 verschärft
auf mTLS-https durchgehend); node = valides compressed secp256k1 (btcec-Parse);
doppelte domains → Fehler.

### 6.2 relay.yaml (eigene Relay-Konfiguration)

```yaml
name: alpha                          # Pflicht
listen_addr: 127.0.0.1:8443          # Pflicht (API-Server, Etappe 3)
data_dir: /var/lib/bmail             # Pflicht; ledger.db + blob/ darunter
lnd:                                 # Pfad-Set (Etappe 3 nutzt lnclient)
  rpc_host: 127.0.0.1:10009          # Pflicht
  tls_cert_path: /secrets/tls.cert   # Pflicht
  macaroon_path: /secrets/admin.mac  # Pflicht
postage:
  foreign_sats: 10                   # Pflicht, > 0
  contact_sats: 0                    # Default (Whitelist-Effekt = M3)
  min_sats: 1                        # Pflicht, 1 ≤ min ≤ foreign
  blob_max_bytes: 10485760           # Default 10 MiB, > 0
peers:                               # Empfänger-/Nachbar-Relays (M1: 1 Peer)
  - name: beta                       # Pflicht
    url: https://127.0.0.1:9443      # Pflicht, parsebar
    node_pubkey: 03ab..              # Pflicht, 33 B hex, valides secp256k1
```
Validierungsfehler sind kumuliert (eine Liste), damit Config-Tests jede Regel
einzeln ansprechen. Keine Defaults für Pflichtfelder — Tippfehler ≠ Runtime.

### 6.3 Blob-Store

Content-addressiert: `data_dir/blob/<sha[0:2]>/<sha-hex>` (FS, keine DB).
Upload 10 MB-Hardlimit + Konto-Quota (Default 100 MiB, M1-Implementierung).
Dedup automatisch über Pfad. Envelope trägt nur refs (Tag 0x03) + Key im JSON.
Implementierung Etappe 3; Format/Struktur hier gesetzt.

## 7. Relay-API (HTTP, mTLS zw. Relays; Client: Bearer-Token)

Alle Antworten `application/json`, Fehler `{error, code}` mit passendem HTTP-Status.
Binärbody nur bei Envelope/Blob (`application/octet-stream`).

| Endpoint             | Methode | Zweck                                                                 |
|----------------------|---------|-----------------------------------------------------------------------|
| `/v1/auth`           | POST    | Challenge-Response: `{address, pubkey_hex, sig_over_challenge(64B)}` → `{token}`. Signiert mit Mailbox-Key (0x05-Verfahren, Digest = sha256("bmail-auth-v1"‖challenge)). Session 24 h. |
| `/v1/balance`        | GET     | `{balance_msat}` des Kontos; Quelle = Ledger (8)                       |
| `/v1/send`           | POST    | Body: Envelope-Binary. Prüfung Sig+Größe, Ledger-Debit Porto, keysend an Peer → `202 {msg_id, receipt:{amount_sats, preimage_b64}}` (Abschnitt 4). Duplikat msg_id → `409`. |
| `/v1/inbox`          | GET     | `?after=<seq>&limit=50` → `{messages:[{seq, msg_id_b64, received_at, envelope_b64}], next_seq}`. Envelope-Bytes uninterpreted (Relay blind), Client decrypted. |
| `/v1/blob`           | POST    | Attachment-Upload, body = Rohbytes, Antwort `{sha256_hex, bytes}`; Limit 6.3 |
| `/v1/blob/{sha256}`  | GET     | Abruf (Client holt selbst, Relay liefert nur an Postfach-Inhaber mit ref im Envelope — Etappe 3) |
| `/v1/profile/{addr}` | GET     | Preisprofil des Postfachs (Porto, M1-minimal `foreign_sats`)           |

Relay↔Relay: gleiche Schnittstelle plus TLV-Pfad (Abschnitt 2) über mTLS/HTTP/2
(PRECODING §B: kein Onion-Routing in v0.1). Server-Implementierung = Etappe 3.

## 8. Ledger (SQLite, WAL, optimistic locking)

Driver: `modernc.org/sqlite` (CGO-frei, ARM-Build sauber). WAL an, `busy_timeout=5s`.
Beträge intern **msat** (INTEGER, CHECK ≥ 0); Sats nur an API/Grenzen.
Eingebettetes Migration-SQL, Version über `PRAGMA user_version`; Migration
idempotent, v0.1 = Stufe 1.

### 8.1 DDL

```sql
CREATE TABLE account (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT    NOT NULL UNIQUE,            -- local part des Postfachs
  mailbox_pubkey BLOB    NOT NULL,                   -- 33 B compressed
  recipient_hash BLOB    NOT NULL UNIQUE,            -- 32 B, Envelope 0x01-Routing
  balance_msat   INTEGER NOT NULL DEFAULT 0 CHECK (balance_msat >= 0),
  version        INTEGER NOT NULL DEFAULT 0,         -- optimistic lock
  created_at     INTEGER NOT NULL,                   -- unix-secs
  updated_at     INTEGER NOT NULL
);

CREATE TABLE txlog (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES account(id),
  delta_msat INTEGER NOT NULL,                       -- +/-
  kind       TEXT    NOT NULL CHECK (kind IN
             ('postage_out','postage_in','topup','withdraw','fee')),
  ref        TEXT,                                   -- msg_id/payment_hash hex
  created_at INTEGER NOT NULL
);
CREATE INDEX txlog_account_idx ON txlog(account_id, id);

-- Postfach-Zeilen (Store&Forward) = Tabelle `mailbox (msg_id BLOB PRIMARY KEY,
-- account_id, envelope BLOB, received_msat, seq, seen, created_at)` —
-- definiert, aber Nicht-Implementierung in Etappe 2a (Aufgabe von Mailbox/Etappe 3).
```

### 8.2 Schreibregel (optimistic locking, keine Lost Updates)

```
wiederhole (max 32, linearer Backoff; retry exhaustion → Fehler)
  SELECT id, balance_msat, version WHERE name=?
  neu = balance_msat + delta;  neu < 0 → ERR_INSUFFICIENT_FUNDS (kein Log, kein Update)
  BEGIN IMMEDIATE
    UPDATE account SET balance_msat=neu, version=version+1, updated_at=?
      WHERE name=? AND version=<gelesene version>
    falls RowsAffected()==0: ROLLBACK → retry           -- Version fortgeschritten
    INSERT txlog(account_id, delta_msat, kind, ref, now)
  COMMIT
```
`balance_msat >= 0` als CHECK = letzte Leitplanke gegen Buchführungsfehler.
API (Go-Paket `ledger`): `Open/Close`, `CreateAccount(name, pubkey)`,
`LookupByRecipientHash(h)`, `Balance(name)`, `ApplyDelta(name, delta, kind, ref)`,
`History(name, limit)`.

## 9. Paket-Landkarte (Etappe 2a geliefert / 3 später)

| Paket                  | Inhalt                                   | Status 2a |
|------------------------|------------------------------------------|-----------|
| `internal/envelope`    | Binär-Marshal/Decode, Sign-Pre-Image     | ✅ + Tests |
| `internal/config`      | relay.yaml/relays.yaml, Validierung      | ✅ + Tests |
| `internal/crypto`      | btcec PEM, AEAD, Schnorr, ECIES          | ✅ + Tests |
| `internal/ledger`      | SQLite-Schema, Konten, Optimistic Lock   | ✅ + Tests |
| `internal/{lnclient,mailbox,postage,relay}` + `cmd/relayd` | Node-Anbindung, HTTP, Store&Forward | Etappe 3 |
| `proto/bmail/v1/envelope.proto` | Nur-Doku der Tags (kein Codegen) | ✅ |

## 10. Registry-Nummern auf einen Blick (Zusammenfassung)

| Ebene   | Bezeichner          | Wert                          |
|---------|---------------------|-------------------------------|
| Onion   | envelope / sig / relay-pubkey / timestamp | 34349334 / 34349337 / 34349339 / 34349343 |
| Onion   | keysend preimage    | 548997074                     |
| Envelope| Tags 0x01–0x09      | recipient_hash … ephemeral_pubkey |
| Format  | magic / version     | "LM1" / 0x01                  |
| Ledger  | user_version        | 1                             |

### 6.4 Blob-Mirror (M2a, 12.11.)
Empfaenger-Relay holt bei Zustellung referenzierte Blobs per GET /v1/relay/blob/{sha}
(X-Relay-Secret, peer.token) vom Sender-Relay, prueft sha256, legt lokal ab und
registriert blob_ref fuer das Empfaenger-Konto (ACL). Spaegelfehler blockieren die
Zustellung nicht (Log + Retry-Moeglichkeit M3). Beweis: make client-interop.
## 7. State-Sync (M2.5)

`GET /v1/state` (auth) → `{"version": int64, "state_b64": "..."}` — Blob ist
client-seitig selbst verschluesselt (ECIES ans eigene Mailbox-Paar,
`[eph33|sealed]`, base64 im JSON-Feld). `PUT /v1/state` mit
`{"expect_version": N, "state_b64": ...}` → 200 `{"version": N+1}` oder
409 `{"error":"version conflict","version": Ist}`. Groessenlimit 256 kB.

State-Doc (klartext nur fuer den Eigentümer): `read{msgid}`, `spam{senderhex12}`,
`deleted{msgid}`, `drafts[{id,ts,to,subject,body,gone?}]`,
`contacts{id:{ts,gone?,name,given,org,title,url,cell,phone,fax,email,addr,lnaddr,btc,crypto,pubkey,pgp,note}}`
(Etappe A: privates Adressbuch, Felder ~vCard 4.0). Merge: Flags OR;
Drafts und Contacts reines LWW pro id — Loeschen stempelt hoeheren ts, ein
spaeter mit gleicher id angelegter Eintrag erwaehlt ihn. Konflikt-Pfad:
409 → pull → merge → einmaliger Retry.

Grenzen & geplante Obergrenzen: Das 256-kB-Limit des State-Slots (PUT → 413)
trägt ~500 Adressbucheinträge; bei Überlauf braucht es Sub-Tiles pro Kontakt
statt einem Gesamt-Blob — bewusste Verschiebung, vor der Beta nicht nötig.
Für anonyme Key-Lookups (`GET /v1/profile/{addr}`) begrenzt ein 429-Rate-Limit
pro IP (`rates.public_rpm`, Default 30/min) das Abfragen von Adressen.
## 7b. Retention-Cleanup (M3)

blob_refs.erweitert um `downloaded_at` (0=nie). Sweep (Start +60s, dann 24h,
auch via `relayd -cleanup-once`): Loscht Blob-Datei + refs, wenn
(a) ALLE Referenzen geladen und die letzte Erstladung aelter als
retention.grace_days (Default 7), oder (b) die aelteste Referenz aelter als
retention.max_days (Default 90). grace_days/max_days = -1 deaktiviert den
Zweig; 0 bedeutet "nicht gesetzt" -> Default. Quota sinkt mit den refs.

## 7c. Empfangsbestaetigung ✓/✓✓ (Etappe 6b, CONCEPT §23)

WhatsApp-Semantik: ✓ = LN-Settle am Empfaenger-Relay (Send-Preimage, spec §4).
✓✓ = Empfaenger-CLIENT hat die Nachricht abgerufen. Kein Gelesen-Status.

Stempel: `GET /v1/inbox` (auth) decodiert die zurueckgegebenen Envelopes und
schreibt (msg_id, account_id, sender_pub, ts) nach `receipts`
(INSERT OR IGNORE = Dedup, PK(msg_id, account_id), mirrored-Flag). Frische
Stempel gehen async als Batch an alle Peers: `POST /v1/relay/receipt`
(X-Relay-Secret, Muster aus 6.4), Body `{"receipts":[{msg_id,sender_pub,ts}]}`
(hex). Sender-im-gleichen-Relay wird direkt lokal verbucht. 60s-Ticker
wiederholt fehlgeschlagene Mirrors (mirrored=0, Limit 200).

Absender-Zuordnung: sha256(sender_pub) = recipientHash →
LookupByRecipientHash → `receipts_in` (PK(msg_id, account_id), ts).
Abfrage: `GET /v1/receipts` (auth) → `{"receipts":[{"msg_id":hex,"ts":int}]}`
(Limit 1000). UI merged das gegen den lokalen Gesendet-Ordner (msg_id hex aus
/v1/send) und rendert ✓ / ✓✓ + Abrufzeit. Immer an (v0.1); Opt-out pro Konto
ist M3-Kandidat.

## 7d. Steuer-Log & Tageskurs-Feed (§25 G1, Beschluss 15.11.2026)

`txlog` (schema v4, Migration v3→v4 baut die Tabelle wegen des kind-CHECKs neu,
Zeilen bleiben) trägt `currency` (Default 'btc') + `eur_micro` (µEUR-Integer
statt eur_cent-Float: Porto wäre in ganzen Cent 0) + `rate_ts` + `rate_src` +
`rate_meur_per_btc` auf JEDER Zeile, solange ein Kurs da ist; ohne Kurs NULL =
ungeratet (Regtest-Müll bleibt ungeratet, §25).
Kurs-Feed (`rates.rate_url` / `rates.manual_eur_per_btc`): ein Abruf pro Tag
(Binance/BSi-Format `{"price":"…"}`, Plausibilitätsgrenze 1e9), manueller
Config-Kurs als Fallback/Test (`rate_src="manual"`).

Tests: `go test ./internal/ledger/ -run 'RateStamp|Migrate3to4|Statement'`.

## 6.5 Chunked Blobs & Byte-Porto (Etappe 7, CONCEPT §22)

**Chunking (Client):** Anhänge > 1 MiB werden in 1-MiB-Scheiben zerlegt
(`src/chunks.ts`). Jede Scheibe ist ein eigener Blob (sha256-adressiert →
Content-Dedup relay- und kontoweit), das Manifest `{"v":1,"size":N,
"chunks":["sha-hex",…]}` ebenfalls. (seit 21.11. trägt das Envelope nur noch
Manifest-Refs, Slice-Spiegelung übernimmt das Relay per Manifest-Walk):
Im Envelope steht pro chunked-Anhang NUR der Manifest-Hash in blob_refs;
das Empfänger-Relay spiegelt beim Mirror (6.4) zusätzlich die im Manifest
genannten Scheiben (max. 255 Parts, Volumen-Guard 4 GiB, pro-Slice-Fehler =
log + skip, nur eine Ebene). Scheiben-Hashes sind Content-Adressen von
Chiffrat-Slices — für das Relay blinde Zahlen; ACL (blob_refs) bleibt
unverändert. Payload-attachment: `{sha256:<manifest>, name, size,
chunked:true, chunks:N}`. Obergrenze 255 Refs/Brief (count = 1 Byte,
≈254 MB); echte Grenze = Konto-Quota. Dateien ≤ 1 MiB gehen weiter als
Single-Blob (e2e/lmcli-interop unverändert); alte Multi-Ref-Envelope
(Scheiben + Manifest in blob_refs) bleiben decode- und liefer-bar.
Download: Manifest holen →
Scheiben sequentiell → konkatenieren, Längencheck gegen `size`.

**Byte-Porto (Server):** `postage.byte_porto_meur_per_mb` (0 = aus,
Default). `POST /v1/blob` kassiert pro FRISCHEM blob_ref (erste Speicherung
für dieses Konto — Dedup lädt nicht doppelt zur Kasse):
`msat = ceil(ceil(size·bp·1000/MiB)·1e8/kurs)`, zweistufig aufgerundet
(int64-sicher, niemand speichert gratis). Buchung `kind='fee'`,
`ref='blob:<sha>'`; Refund bei Infra-Fehler nach Kassierung
(`ref='refund:blob:<sha>'`). Reihenfolge: erst kassieren, dann speichern —
bei `ErrInsufficient` 402 `{fee_msat}`, es liegt dann kein Byte auf Platte.
Kein Kurs im Feed → 503 (Preis wäre erfunden). `/health` liefert
`byte_porto_meur_per_mb` + `rate_meur_per_btc` für die UI-Schätzung.
Prod-Regtest: 10 mEUR/MiB = 1 ct/MiB (Vorschlag an Bernd, Config-Sache).
Zeitkomponente ("pro Zeit", §22) bewusst NICHT gebaut — Retention-Cleanup
(7b) begrenzt die Lebensdauer bereits; Upgrade-Pfad: Preis = f(bytes, tage).

Tests: `go test ./internal/relaysrv -run BytePorto` (Mathematik inkl.
Overflow-Wache), `npx tsx test/chunk-test.mts` (Unit + 2,5-MiB-Roundtrip
A→B mit Mirror, exakte Byte-Gleichheit, Abbuchungskontrolle aufs msat,
Dedup, 402). Falle beim Testbau: Testdaten NICHT periodisch füllen
(i·7&0xff hat Periode 256 → identische Scheiben → Dedup „klaut" eine
Buchung und der Test lügt rot).

## 7e. OIDC-IdP „Sign in with lightningmail" (CONCEPT §21/§29, Beschluss 18.11.)

Authorization-Code-Flow + PKCE (S256 Pflicht, public clients — kein Secret,
kein DCR, kein refresh_token; shortcuts v0.1). Issuer = relay-URL; Config
`oidc:{issuer, login_page, address_domain, clients[{id,name,redirect_uris}]}`;
issuer leer = IdP aus (503).

Zwei getrennte Krypto-Welten (§21, Absicht):
- **IdP-Signatur:** ES256/P-256, Schlüssel auto-generiert in
  `data_dir/idp_es256.pem` (0600, NIE löschen — sonst bricht das Vertrauen
  aller angebundenen Dienste). JWKS unter `/oidc/jwks` (kid = sha256(pub)[:8]).
- **Föderations-Beweis:** BIP340-Signatur des MAILBOX-Keys (secp256k1) über
  eine 32-Byte-Server-Challenge. Entsteht im Browser (PWA im OIDC-Modus) —
  der Relay sieht den privaten Mailbox-Key nie. Im ID-Token als Claim
  `bmail:{pubkey, sig, challenge, alg:"bip340-sha256"}`. Dienst verifiziert
  Signatur selbst + Pubkey↔Adresse via Directory (§4.2 Ebene 3) =
  LNURL-auth-Muster mit OIDC-Wrapper.

Flow: GET `/oidc/auth` (client_id/redirect_uri exakt, scope∋openid, PKCE)
→ 302 `login_page?oidc=<issuer>&sid=…` → PWA login wie üblich (Passkey/Datei/
Auto) → POST `/oidc/auth/login` {sid} mit Bearer → {challenge_b64,
client_name, address} → Consent-Screen → Browser signiert → POST
`/oidc/auth/sign` {sid, sig|deny} → {redirect: redirect_uri?code&state} →
POST `/oidc/token` (form: code, code_verifier, client_id, redirect_uri;
single-use, 2 min TTL) → {id_token (ES256, 1 h), access_token (opak, 1 h)} →
GET `/oidc/userinfo` (Bearer). CORS auf auth/login+sign für
webauthn.origins (= PWA-Origin(s)).

ID-Token-Claims: iss, sub = `name@address_domain`, aud, exp/iat/auth_time,
nonce (durchgereicht), email (= sub), **email_verified: true** (Beweis =
Mailbox-Key-Signatur, nicht MX), preferred_username, bmail{…}.

Demo-RP: `/oidc/demo-callback.html` (eingebettet, reines JS): startet Flow,
tauscht Code, verifiziert ES256 via WebCrypto gegen JWKS, zeigt Claims.
Tests: `go test ./internal/relaysrv -run 'OIDC|Pkce'` (5 Tests, Vollflow
in-process inkl. ES256-Verify, Replay, Fremdsig-403, Param-Mutationen,
Deny-Pfad, 503), `npx tsx test/oidc-rp-test.mts` (RP-Simulation über echtes
HTTP, WebCrypto-JWKS-Verify, bmail-BIP340-Check, Replay; läuft auch gegen
https://relay-a.lightningmail.app durch den Tunnel).

## 7f. Statement-Export mit Hash-Kette (§25 G2, Beschluss 15.11., gebaut 18.11.)

- `GET /v1/statement?from&to&fmt=csv|json` (Bearer, eigenes Konto; from/to =
  Unix-Sekunden, 0/offen = unbegrenzt; Default fmt=json).
- `GET /v1/relay/statement?from&to&fmt=…` (X-Relay-Secret, Betreiber-Sicht):
  Zeilen aus txlog kind='fee' über ALLE Konten (Vorzeichen gedreht — was der
  Nutzer zahlt, ist Betreiber-Einnahme; refund: negativ).
- **Hash-Kette:** hash_i = sha256(hash_{i-1} || kanon), kanon = Felder mit '|'
  in fester Reihenfolge (NULL = Leerstring), Genesis Konto =
  sha256("bmail-statement-v1:"+konto), Betreiber =
  sha256("bmail-operator-v1:"+relay-name). Kette wird IMMER von Genesis
  gerechnet; from filtert nur die Ausgabe — der exportierte Kopf ist damit der
  Monats-/Zeit-Anker für spätere Fortsetzungsprüfungen. Jede Zeile trägt
  prev_hash+hash (CSV-Spalten bzw. JSON-Felder), Export-Kopf trägt genesis+kopf.
- CSV: 2 Kommentarzeilen (Kennung/Bereich/genesis/kopf + LND-Hinweis), dann
  Header, dann Daten. EUR-Spalten aus dem G1-Stempel; ungeratet = leer.
- **G1-Vervollständigung (mit G2):** postage_out (auch refunds), byte-porto
  fee + refund werden jetzt per ApplyDeltaMeta mit Kursstempel gebucht —
  zuvor nur card_* und postage_in. Jede Wert-Buchung ist damit gestempelt
  oder bewusst NULL.
- UI: Nav „💶 Umsätze" — Monatsliste (Ein/Aus sats+EUR, „≈…(Teile ungeratet)"
  wenn gemischt), Monats-Detail als Tabelle, CSV-Download pro Monat/komplett.
- Tests: ledger/statement_test.go (Kette, from-Filter, NULL vs Stempel,
  Operator-Vorzeichen/Determinismus), relaysrv/statement_test.go (CSV-Form +
  Kettenfelder, JSON, 403 ohne Secret), client/test/statement-test.mts 14/14 —
  rechnet Genesis+Kette clientseitig nach (Kanon-Formel = Doku).

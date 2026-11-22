# Etappe M2 — Desktop Schreibpfad (Senden/Anhänge/Entwürfe/Read-Sync)

Ziel: Der Linux-Client kann schreiben was die PWA kann: Mail senden (mit Anhängen bis
Quota), Antworten, Entwürfe anlegen/löschen, Gelesen-Status — und alles davon ueberlebt
Client-Neustart und ist auf der PWA derselben Kontos sichtbar (echter Server-Sync,
keine lokale Insellösung).

Umgebungen: Code /root/lm-m1 (Hermes), Bauen/Laufen CT114 (.79, Repo /root/lm, rsync
desktop/ lm1/ hin, Tunnel ssh -L 18443:127.0.0.1:8443 -L 19443:127.0.0.1:9443).
Regel alt: kein git/rsync nach CT113, kein ssh-Promi. Kommentare englisch, UI-Labels
deutsch. Rotliste docs/review-M1-desktop.md unveraendlich.

## Was M1b schon liefert (nicht nochmal bauen)
core: api.go (auth/inbox/blob/state GET), statedoc.go Merge+Fixture-Paritaet, sanitize,
cache, Harden; cmd: Liste+Reader+Sidebar+sync-Loop. M2 setzt darauf auf (keine Duplikate bauen).

## Bausteine

### 1. core/state-write: Save-Pfad (das Herz, hohes Risiko — Paritaet zuerst)
- OpenStateDoc existiert (lesen). NEU: SealDoc(doc) — exakt das Gegenstueck zu
  state.ts seal() (selbe AAD-Konvention, dieselbe JSON-Sortierung/Field-Reihenfolge wie
  im Golden-Fixture Generator m1-golden.mts nachpruefen und ggf. Generator erweitern:
  SEALED-Fixtures jetzt auch als Go->TS-Richtung: Go-Seal -> tsx-Entschluessel-Check).
- PushState(expectVersion, sealed): POST /v1/state {expect_version, state_b64} mit
  Bearer; 409 -> PullState -> MergeDocs -> erneut (max 3 Versuche, dann Fehlermeldung).
- API-Semantik aus client/src/state.ts StateSync.save lesen (Feldnamen! base64! content-type).
- Aenderungsfunktionen setzen erst den ts-Stempel (Re-Stempel-Regel aus der Spec M1b —
  golden-Fixture-Tests decken beide Richtungen ab).

### 2. core/send: Mail bauen + senden
- profile.go: GET /v1/profile/{name[@domain]} -> pubkey_hex, postage_sats (Semantik wie
  lmcli/TS; Domain-Faelle: lokaler Empfaenger ohne @ = eigenes Relay).
- chunk.go: 1MiB-Slicing + Manifest (Feldformat client/src/chunks.ts 1:1: v,size,chunks),
  Upload ueber POST /v1/blob mit Bearer (kind=mail), byte-porto 402 -> deutsche
  Fehlermeldung 'Guthaben unzureichend' statt Panik. MANIFEST-ONLY Envelope-Refs (Fix vom
  21.11.): pro Anhang nur msha ins Envelope!
- crypto-Pfad: ECIES an Empfaenger-pubkey (lm1/crypto existiert), AAD recipientHash+msgID,
  msgID = crypto/rand 32B, BIP340-Signatur mit Mailbox-priv, Envelope-Encode (lm1),
  POST /v1/send?to=... body=raw envelope. Antwort 202 {msg_id,status} (pending-Status an
  UI durchreichen — Etappe R Chips!).
- payload-JSON Felder exakt wie TS (subject,body,headers,attachments[{sha256,name,size,
  chunked?,chunks?,s?}]) — Feld-Namen aus send.ts kopieren, NICHT erfinden; sonst
  versteht die PWA die Mail nicht. Test-Golden: eine Go-gebaute Mail muss die PWA
  rendern koennen (Evidence ueber tsx-Rechnung im Test).

### 3. UI Ergaenzungen (bestehendes Fenster, neue Actions)
- Toolbar/HeaderBar: [+] Schreiben — AdwWindow/Dialog: An(TextField, Vorschlag aus
  Adressbuch-contacts wenn vorhanden), Betreff, Body (GtkTextView plain), [Anhang]
  FileChooser (Dateigroessen-Check quota via /health+balance), [Senden] mit Porto-Anzeige
  (profile postage), Statuszeile 'unterwegs' wenn 202-pending.
- Reader: Buttons [Antworten] (An=Absender der Mail — Absender-Name/Adresse kommt aus
  headers bzw. profile-Request, like PWA; 'from' im payload: Existenz des Feldes pruefen! aus
  renderMail in main.ts uebernehmen) und [🗑 Löschen] (deleted-Map im StateDoc + push,
  PWA-Semantik 'gone').
- Ordner-Aktivierung M2: 📤 Gesendet (Liste aus eigenem lokalen sent-Cache
  ~/.local/share/lightningmail/sent.json MIT msg_id+subject+ts+status — Draft/sent
  Mirror im StateDoc reicht als Quelle wenn Felder da, dann kein Zusatz-Cache;
  bewerten, Entscheidung im Report begruenden) und 📝 Entwürfe (Drafts-Map im StateDoc —
  draft-Felder exakt wie state.ts drafts: {id, to, subject, body, attachments?, ts, gone}).
  📇/🗂/💶 bleiben M3-Platzhalter.
- Gelesen-Status: Klick auf Mail setzt read[msg_id]=ts + PushState (debounced 5s, kein
  Push pro Klick — Sammel-Queue).
- Login UX: LMKEY2/PBKDF2 gewrappte Keydatei -> AdwDialog Passphrase (ein Feld, Enter),
  Fehler als inline-red; BMAIL_KEYPASS Env bleibt Vorzug (headless Tests!).

### 4. E2E-Beweis (CT114 gegen echte Regtest-Relays, Screenshots!)
B1: GUI: alice -> bob (bob@beta Domain-Angabe), 3MB crypto-zufaelliger Anhang,
    Screenshot 'unterwegs/settled', dann PWA-API-Check tsx: bob laedt 3MB bytegleich
    (Manifest-Walk vom 21.11. muss tragen!), Envelope nur 1 Ref.
B2: Enturf: GUI Draft anlegen+save, Screenshot Entwürfe-Ordner; tsx gegen BETA:
    bob... nein: gleicher Account alice — zweites StateSync (tsx) holt state -> Draft
    sichtbar = echtes Cross-Device (Schriftlicher Beweis im Log + Screenshot).
B3: Read-Sync: Mail in GUI anklicken, 5s warten, tsx state-Check: read[msg]=ts gesetzt.
B4: Reply: Antwortmail an Absender landet in dessen Posteingang (zwei Einweg-Konten!
    kei Prod-Keys), Subject 'Re:' Konvention der PWA uebernehmen.
B5: LMKEY2-Passphrase-Dialog: .lmkey V2 Datei + falsche Passphrase -> inline error;
    richtig -> Login durchlaeuft (Screenshot beides).
Evidence unter desktop/cmd/lmdesk/evidence/m2-* + REPORT-M2.md. Parent gegen-Sicht.

## Gates
- go vet+test core (neue Tests: SealDoc-Golden bidirektional, chunk-Manifest-Fixtures
  gegen node-Generator, profile-parse, payload-Feld-Golden gegen TS-Beispiel),
- relay/lm1 unberuehrt gruen, desktop-Build CT114, GUI laeuft mit Harden (M-SEC.1!) ohne
  root, m-r/m1b Regressionen (tsx) gruen.

## Report
Dateien, Gate-Outputs, B1-B5 Einzelergebnisse mit Screenshot-Pfaden, Entscheidungen
(sent-Cache ja/nein mit Grund), Abweichungen, Blocker-Optionen. Deutsch.

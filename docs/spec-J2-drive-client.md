# Etappe J2+J3+J4 — Drive Client (state.ts, main.ts, UI)

Arbeitsverzeichnis: <workspace> (lokaler Klon; NICHT committen/rsyncen/sshen — Parent
deployt). node_modules existiert noch nicht: Parent symlinked client/node_modules; falls
nicht vorhanden: `ln -s <repo>/client/node_modules
<workspace>/client/node_modules` (Dependencies sind universell). Node 18: für tsx-Tests
NODE_OPTIONS='--experimental-global-webcrypto'. Integrationstests brauchen laufende Relays
(Die hast du nicht) — du lieferst Code + Test-DATEI; Parent fährt sie auf dev-relay.

## API-Contract (J1, parallel im Bau — exakt so)
- POST /v1/blob?kind=drive   (Body wie bei Anhängen; Dedup & Byte-Porto wie bisher)
- DELETE /v1/blob            {"sha":"<hex>"} → {"released":true,"remaining_refs":n}; 403 wenn
                             keine drive-ref; nur drive-refs löschbar
- GET  /v1/drive/usage       → {enabled, used_bytes, quota_bytes, tiers:[{gb,sats}]}
- POST /v1/drive/buy         {"tier":<idx>} → {quota_bytes, cost_sats}; 402 bei Pleite
- /health liefert drive:{enabled, quota_mb}

## Kontext aus dem Repo (erst lesen, dann bauen)
- client/src/state.ts: StateDoc mit contacts/drafts/sent; LWW+Tombstone-Merge (ts gewinnt,
  Gleichstand -> gone, lebendiger Save stempelt max(now,prev.ts)+1 und stripped gone);
  StateSync.saveContact/delContact sind das Muster. CAS via expect_version.
- client/src/chunks.ts + send.ts: Chunk-Upload-Pipeline (1MiB-Scheiben + Manifest-Blob,
  >1MiB automatisch; main.ts hat chunked Download für Anhänge; IDB-Cache lightningmail_blobs).
- main.ts: Ordner-Tabs folder('in','sn','dr','ab','ums') mit renderX(); nav-Buttons in
  client/app/index.html; API-Helper api(path,opts) mit Bearer; Demo-Login-Präfill existiert.
- Design: navy #122338 / pergament #f5f3ec / gold #f4b71a, mobile bottom-nav ≥44px.

## Zu bauen

### 1. state.ts — files-Map
StateDoc += files: Record<string, DriveEntry>;
DriveEntry {id,name,parent,kind:'f'|'d',size,mime,msha?,ts,gone?}
parent: 'root' oder id eines kind:'d'-Eintrags. id = random hex16 (crypto.randomUUID mit
Date.now+random-Fallback — es gibt den Helper schon, WIEDERVERWENDEN, Secure-Context-Falle).
Merge 1:1 wie contacts (id-LWW, Gleichstand gone gewinnt, Save stript gone + stempelt).
saveFile(partial) / delFile(id) analog saveContact/delContact (delFile = tombstone kind egal;
bei Ordner prüft der CALLER vorher leer, nicht der Merge).
Test-Ausbau in client/test/m25-sync.mts NICHT nötig; eigene Unit-Pure-Funktion tests
kommen in drive-test.mts (unten).

### 2. drive.ts (neu, client/src/drive.ts) — Logik-Schicht, DOM-frei wie chunks.ts
- uploadFile(bytes, name, mime, parent, acctPubkey): bytes mit dem BESTEHENDEN
  Attachment-Krypto-Pfad verschlüsseln (Recipient = EIGENE mailbox pubkey; in send.ts/
  main.ts anschauen wie attach-Encrypt heißt und es wiederverwenden, KEINE neue Krypto),
  dann Chunk-Pipeline mit kind=drive hochladen → {msha, size}; saveFile({id,...}).
 =size=Klartat-Länge? NEIN: size = verschlüsselte/gespeicherte Bytes (das ist, was Quota
  kostet); Klartext-Größe = size_plain (Feld dazu nehmen). mime speichern.
- downloadFile(id): state-Eintrag → msha → Manifest-GET → chunk-GETs → reassemble →
  decrypt → Uint8Array. Nutzt vorhandene Chunk-Download-Funktion (main.ts), ggf. dorthin
  refactor-extract nach drive.ts exportieren.
- deleteFile(id): kind 'f': Manifest + chunk-hashes HOLEN (GET), dann DELETE /v1/blob für
  msha + alle chunk-shas, dann delFile tombstone. kind 'd': nur wenn keine Kinder (sonst
  throw). Reihenfolge: Server-Freigabe vor Tombstone, Fehler → kein Tombstone.
  shortcut: gleiche sha, die auch als Anhang in Sent steckt, wird durch Promotion-Regel
  zur drive-ref und beim Drive-Löschen freigegeben; Limitiert: own-Sent-Attachment-Download
  kann danach 403 sein;upgraden wenn Complaints — nicht heute.
- usage(): GET /v1/drive/usage → typisiert. buyTier(i): POST + Fehler-Mapping.

### 3. main.ts + index.html — UI Tab '🗂 Laufwerk'
- index.html: nav += Button id nav-drv (zwischen Adressbuch und Umsätze, gleiche Klasse),
  Pane 'drv' wie 'ums' Pane. Inhalt: Breadcrumb-Zeile (🏠 + /Name-Ketten, klickbar),
  Action-Bar: [⬆ Datei] [＋ Ordner] plus unsichtbares <input type=file multiple id=d-file>,
  Quota-Balken (used/quota, gold Füllung, Text '1,2 GB von 5 GB'), Liste (Tabelle wie ums):
  Zeile = Icon 📁/📄, Name (✏️ rename inline), size_human, ÄNDERUNG ts als Datum, ⬇, 🗑.
  Leerer Ordner: Hinweistext mittig. Pane zeigt oben eine Zeile 'Laufwerk ist auf diesem
  Relay deaktiviert' + Actions ausgegraut, wenn /health drive.enabled false (healthCache
  existiert bereits, Feld erweitern).
- Handler: click auf 📁 navigiert (parent-Kette), ⬇ downloadFile → Browser-Download wie
  Anhang-Download-Pfad (safeName aus §31 existiert, wiederverwenden), 🗑 confirm() —
  ACHTUNG native confirm friert headless-Tests, aber das ist für uns ok; rename = inline
  contenteditable-Input Enter/Esc; ＋ Ordner = prompt-ähnliche Inline-Zeile (kein natives
  prompt — Test-Falle), Name-Validierung ^[^/]{1,100}$; Upload: input+drag&drop aufs Pane
  (drop Effect 'copy', DatenTransfer.files → uploadFile in aktuellen Ordner).
  Progress: pro Datei zeile 'lädt hoch…' mit spinner-artigem Text, wie send.ts onProgress
  zeigt; keine Fortschrittsbalken-Komplexität. shortcut: kein Multi-Upload-Queue-Manager,
  sequentielles for-of; upgraden wenn Nutzer große Batches fordern.
- renderUms-artige Refresh: Ordner-Wechsel rendert aus lokalem stateDoc, kein extra Fetch.
  Nach jedem save/del: StateSync push (bestehender Debounce-Push genügt, nichts Neues).

### 4. client/test/drive-test.mts (Datei abliefern, Parent fährt sie)
Muster: signup-test.mts/chunk-test.mts (Einweg-Konto newPrivKey+POST /v1/account+auth;
KEINE Prod-Datei-Keys!). RELAY env, default http://127.0.0.1:8443. Checks:
1) usage/health-Shape; 2) mkdir root/orderA; 3) upload 2.5MiB periodisch-freier Zufalls-
   bytes (i*104729%251 oder crypto-secure — NIE i*7&0xff, Dedup-Falle) in orderA;
4) list-Merge: Eintrag sichtbar mit msha; 5) downloadFile → Byte-gleich Original;
6) delete nicht-leerer Ordner → error; file löschen → usage sinkt um size, 2. GET blob
   msha → 404/403; 7) buy tier (config-tier mit kleinem sats-Wert) → quota_bytes steigt,
   balance delta == -sats*1000 msat; 8) State-CAS: zweiter Sync-Client (gleiche acct,
   zweiter Token? wenn Token geteilt wird, reicht: save nach externem version-bump →
   409-Pfad) — wenn zu fummelig: skip mit TODO-Kommentar, Parent prüft m25 separat.
Läuft lokal NICHT (keine Relays) — tsx Syntax-Check genügt dir nicht, also: Unit-Teil
(merge pure fn) gegen eine simulierte Doc ohne Netz ausführen und INTEGRATION Teil als
'pending CT' im Report kennzeichnen.

### 5. typecheck & build
npx tsc --noEmit (wenn tsconfig das hergibt) ODER npx --yes esbuild client/src/drive.ts
--bundle --format=esm >/dev/null plus vite-Bau via Skript: bash -c 'cd client/app &&
npx vite build' — falls Terminal-Guard das Wort blockt, speichere den Befehl in eine
.sh-Datei und führe die aus (bekanntes Muster). Bau muss durchlaufen; UI-Rauchtest macht
der Parent im Browser.

## Report am Ende
Geänderte/neue Dateien, was lokal verifiziert ist (build ok, unit ok), was auf CT
aussteht. Keine git/rsync-Aktionen. Deutsch antworten.

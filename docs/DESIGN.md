# LightningMail v0.1 — Client-Design-Entwurf
Quelle: Gemini 4 Argon (Design-Route), 12.11.2026 · Status: Entwurf zur Abnahme durch Bernd.
Weisung Bernd: basic E-Mail-Client (Rechnungen, Dauerablage), KEIN Messenger.

## 1. Leitbild
- Klassischer Mail-Client: strukturierte Korrespondenz, klare Trennung Liste/Lesen/Verfassen.
- Zielplattformen: Debian-Desktop (3 Spalten, Tastaturkürzel) + Android-Browser (Spalten-Navigation, FAB).
- Relay ist E2EE-blind: Klassifizierung, Ordner, Suche laufen komplett clientseitig (IndexedDB-Index).
- Porto transparent: exakte Sats-Kosten VOR dem Senden, Summe über alle Empfänger.

## 2. Layout
### Desktop (>=1024px)
1. Sidebar (240px): [+ Neue Mail] · Posteingang · Gesendet · Entwürfe · Unerwünscht · Kontakte;
   Footer: Balance (Sats) + Preisprofil-Button + Sync-Status.
2. Mittelspalte (360px): Suchleiste, Filter-Chips (Ungelesen, Mit Anhang, Unbekannt, Whitelisted),
   Mailzeilen: Absender + Klassifizierungs-Badge + Betreff + Datum + Anhang-Icon + (+X sat bei Eingang).
3. Hauptspalte: Header (Absender/Empfänger/Zeit/E2EE-Status), Klassifizierungs-Leiste
   [unbekannt|whitelisted|unerwünscht], papierhafter Body (Text/Markdown; HTML nur bereinigt,
   keine Remote-Images), Anhang-Leiste mit PDF-Preview.

### Mobile
- Liste = Start, fixe Such-/Filterleiste, FAB Verfassen. Bottom-Nav: Eingang · Kontakte · Profil/Balance.
- Lesen + Compose als Vollbild-Views mit Zurück-Header.

## 3. Kernlogik
### Klassifizierung (manuell, keine Auto-Erkennung)
- unbekannt (Default): eigene Ansicht, Leseansicht zeigt Aktionsleiste [→Whitelist (0 Sats)] [→Unerwünscht].
- whitelisted: direkter Posteingang, 0 Porto an dich.
- unerwünscht: clientseitig sofort nach 'Unerwünscht', stumm; Endablage ohne weitere Aktion
  (Abschreckung = der gezahlte Preis des Senders, nicht Erkennung).

### Compose & Porto
- Adresseingabe → profile-Lookup: Whitelist 0 / Konversationsfenster <30d 0 / sonst Empfängerpreis.
- Chips je Empfänger mit Einzelporto; Footer 'Senden (Gesamtporto: N Sats)';
  balance < porto → Button aus + 'Guthaben unzureichend (Fehlen: X Sats)'.

### Anhänge
- Kompressions-Pipeline vor Verschlüsselung; Default komprimiert, Toggle 'Original senden' je Datei+global;
  Anzeige 'Rechnung_Scan.jpg (4,2 MB → 680 KB)'; danach AEAD + blob-Upload.

### Lokale Datenhaltung (IndexedDB)
- messages (Header+Volltext entschlüsselt, paidSats, threadId), blobs (Cache), contacts
  (classification, lastConversationAt, priceProfile-Cache), folders (flach, inkl. Regel 'Betreff enthält Rechnung → Ordner Rechnungen').

## 4. API-Mapping
auth Session/Keys · inbox增量 sync · read+Lesestatus · send (Porto-Beleg) · blob up/down ·
balance Sidebar · profile eigenes+fremde Preisprofile · contacts Klassifizierungs-Sync (s. offene Q1).

## 5. Tech (v0.1)
TypeScript + Vite + Preact (schlank), CSS-Grid statt Framework-Schwergewicht, PWA manifest +
ServiceWorker (Offline-Lesen), CSP default-src 'self', keine externen Fonts/CDNs.
Bewusste Auslassungen: kein Rich-Text-Editor (Text/Markdown reicht), keine verschachtelten Ordner,
kein Kalender, keine Lesebestätigung.

## 6. Offene Fragen an Bernd (von Gemini formuliert)
1. Ordner/Klassifizierung: rein lokal (IndexedDB) oder verschlüsselt über contacts-API zwischen
   Desktop↔Android synchronisiert? (Hermes-Empfehlung: v0.1 lokal + exportierbares Backup-File)
2. Größen-Aufschlag im Preisprofil: Pauschale pro Mail oder Basis+sats/MB? (CONCEPT §6 sagt schon:
   Basis+MB — nur bestätigen)
3. 'Antwort frei' clientseitig behauptet oder Relay-signiertes 0-Sats-Quote-Token?
   (Hermes-Empfehlung: Relay-Quote — sonst fälscht ein Client das Fenster)
4. Komprimierung: nur Bilder, oder auch PDF-Rekompression (Qualitätsrisiko bei Dokumenten)?
   (Hermes-Empfehlung: nur Bilder, PDFs nur gzip-Container)
5. Key-Verwaltung mobil: Passphrase-Login (Key aus auth abgeleitet) vs. Seed-Import/-Export?

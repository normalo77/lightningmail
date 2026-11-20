# bmail — Concept v0.1

> Eine E-Mail, die sich selbst bezahlt: Jede Nachricht ist gleichzeitig eine
> Lightning-Zahlung an den Empfänger. Spam wird teuer, Postfächer werden
> einfach, der Nutzer sieht nur ein Guthaben.

Stand: 19.11.2026 · Autor: Bernd + Hermes · Status: Konsolidiertes Konzept (ohne Directory & ohne Konversationsfenster)

---

## 1. Warum

- Spam existiert, weil Senden kostenlos ist (HashCash 1997, Bitcoin-Whitepaper
  Kap. 2 — gelöst wurde es nie, weil Payment-Infra lackierte).
- Lightning macht Cent-Beträge gebührenarm möglich → Porto pro Mail wird praktikabel.
- Bestehende Vorarbeit: Sphinx (Nachrichten als LN-Onion-Zahlungen, Relay-Modell),
  SpamBat (Verbrennungs-Porto), BitSov (payment-gated messaging, 2026),
  Joshua Hansen „Lightning Mail" (SMTP+Postage, 2022).
  bmail kombiniert: Sphinx-Transport + Mail-Semantik + Empfänger-Ökonomie + WhatsApp-UX.

## 2. Design-Regeln (nicht verhandelbar)

1. **Der Nutzer sieht nie:** Channels, Nodes, Invoices, Routing, Liquidität.
   Er sieht: Postfach, Guthaben, Senden-Knopf.
2. **Onboarding ≤ 60 Sekunden:** Name wählen → Passwort/Seed → fertig.
   Kein Scan, kein Pairing, keine Erklärung nötig.
3. **Guthaben ist echt:** Empfangenes Porto gehört dem Nutzer und ist
   auszahlbar (LN-Adresse/Invoice), aber Auszahlen ist opt-in — Standard:
   es sammelt sich und „bezahlt" die eigenen Mails.
4. **E2EE by default:** Der Relay sieht Chiffretext, Größe, Timing — nie Inhalt,
   nie Betreff (Protected Headers), nie Empfängerbeziehung (Onion-Routing).
5. Ein Satz pro Funktion im UI. Was erklärt werden muss, raus damit.

## 3. Kernidee: Transport = Porto

Jede bmail-Nachricht ist eine LN-Onion-Zahlung (Keysend/Bolt11, Sphinx-Modell),
die im letzten Hopf beim Relay des Empfängers ankommt und dort zweierlei tut:

- `amt_sats` → **Guthaben des Empfängers** (Postage)
- `TLV-Nutzlast` → signierte, verschlüsselte Nachricht → **Store-and-Forward-Postfach**

„No stamp, no delivery" ist damit keine Regel, sondern die Physik des Protokolls:
Eine Nachricht ohne Zahlung ist kein gültiger Payment-Typ und wird verworfen,
bevor irgendein Code den Inhalt ansieht.

## 4. Architektur

```
┌──────────┐  Push/JMAP-artig   ┌─────────────┐   LN Onion+Zahlung   ┌─────────────┐
│ Client   │◄──────────────────►│ Sender-     │◄────────────────────►│ Empfänger-  │
│ (Handy/  │                    │ Relay       │                      │ Relay       │
│  Desktop)│                    │ (Postbote)  │                      │ (Postbote)  │
└──────────┘                    └─────────────┘                      └─────────────┘
   lokale Keys                       LND + Ledger                       LND + Ledger
   E2EE-Krypto                    Store & Forward                    Postfach des Empfangs
```

- **Relay** („Postbote"): ein Dienst aus LND + Store-and-Forward-Postfach +
  Ledger pro Account. Konzentriert die gesamte Node-Komplexität: 1 Relay ≈ 1000 Nutzer.
  Zwei Betriebsmodi aus derselben Codebasis:
  - **Light-Relay:** `relayd` + `lnd (neutrino)` — kommt komplett ohne eigenen
    `bitcoind` aus (nutzt Compact Block Filters per P2P, ~10 GB Disk, <300 MB RAM).
    Ideal für NAS, Raspberry Pi oder kleine VPS.
  - **Full-Relay:** `relayd` + `lnd` + `bitcoind` — volle Souveränität für
    größere Betreiber.
- **Clients (Android, iOS/Apple, Linux, Windows, Web):** Ein gemeinsamer
  TypeScript-Kern (`client/src/`) bedient alle Plattformen: als PWA im Browser,
  als Desktop-App (Linux/Windows/macOS) und als mobiler Wrapper (Android-APK / iOS).
- **Client ↔ Relay:** Verschlüsselter Push-Kanal, ohne Long-Lived-Ports ins LAN —
  LNC (Lightning Node Connect) oder WebSocket over Tor/HTTPS. Der mobile Client
  hat die E2EE-Keys lokal; der Relay ist blind.
- **Attachments:** nie inline über Onion-Limits — Client verschlüsselt Blob,
  lädt auf Blob-Store des Relays (Größenlimit = Kontingent), Nachricht trägt
  nur `hash + key`. (Muster übernimmt Sphinx-Media-Handling.)
- **Anhang-Vorverarbeitung:** Client komprimiert vor dem Senden
  (Bilder Kante ≤2560px → JPEG/WebP; PDFs optipng/ghostscript-optional).
  **Default: an; pro Sendevorgang UND pro Konto ausschaltbar** ("Original
  senden"). Komprimierung NIE verlustfrei-zerstörend: Original bleibt
  lokal erhalten, Relay speichert nur die gewählte Form.
- **Zweites Porto (Bernd, 12.11.):** Fester Sockel ~5 ct an den Empfänger
  PLUS ~2 ct/MB an den Relay-Betreiber (Speicher/Bandbreite). Kein
  Größen-Aufschlag beim Empfänger-Porto. Split-Mechanik (pro Mail zwei
  Zahlungen vs. periodic billing) ist M2-Planungspunkt.
- **Adressen:** `name@provider.tld` (Lightning-Address-kompatibel, DNS = SRV-like
  Lookup auf Relay-Node-ID). Key-Bindung über Web-of-Trust-light: Erstkontakt
  zeigt Fingerprint beidseitig (WhatsApp-Safety-Number-Muster). → siehe 4.1

### 4.1 Adressmodell (ein Zettel, vier Rollen)

Form: exakt E-Mail-Notation `lokaler-name@domain` — nichts Neues zu lernen.
Vorläufer: LUD-16 Lightning Address (1:1 dieselbe Syntax), SathetHQ „Sathet"
(LND-Plugin E-Mail↔Zahlung, ~2019), Zaprite; prominent: MicroStrategy machte
2023 Saylors Firmenadresse per LUD-16 zum Lightning-Zahlungsziel.

Eine bmail-Adresse dereferenziert zu:
1. **Postfach:** DNS-TXT/SRV → Relay-Node-ID + Sync-Endpoint.
2. **Zahlungsziel:** LUD-16 (`/.well-known/lnurlp/<name>`) → Invoice; damit ist
   jede bmail-Adresse zugleich eine normale Lightning-Adresse und mit bestehenden
   Wallets besendbar (Brücken-Effekt geschenkt).
3. **Identität:** öffentlicher Key der Person (`GET /v1/profile/{name}`); TOFU +
   Fingerprint-Wechsel-Alert (Safety-Number-Muster) sowie Login-Anker via OIDC.
4. **Preisprofil:** Porto-Satz des Postfachs (Standard-Porto bzw. erhöhter
   Porto-Vorschuss bei Diensten). Kein öffentliches Adressbuch, kein
   Konversationsfenster — die Empfängeradresse allein reicht zur Auflösung.

Merkbarkeit: kurz, tippbar, vorlesbar (`bernd@bmail.de`, `gisela@familie.koeln`);
IDN-Domains erlaubt, Homoglyph-Hygiene im Client (Punycode-Alarm).

Portabilität: stabile Identität = Key, nicht Domain. Signierter
Delegations-Record („BMRV", MX-Analog) zeigt, wer aktuell das Postfach hält und
den Key vertritt. Providerwechsel = Record umziehen + unterschreiben,
Visitenkarte bleibt gültig. Domain-Inhaber-Familien (`@familie.koeln`) bekommen
damit ein echtes „Postamt gehört mir"-Modell.

### 4.2 Namensauflösung: DNS als Registry (drei Ebenen)

1. **Domain → Relay** — echtes DNS, SPF-artiger TXT-Record:
   `_bmail._tcp.domain TXT "v=bmail1; relay=https://…; onion=…onion;
   node=<pubkey>; policy=<url>; key=pgp:<fpr>"`.
   Zoneninhaber = Postamt-Inhaber (MX-Analogie). Versionierung via `v=bmail1`,
   DNSSEC als optionaler Anker, sonst signiert policy.json den Rest.
   BMRV/Portabilitäts-Records (4.1) leben als gleiche TXT-Familie.
2. **Local Part → Postfach** — Relay-Verzeichnis („mini-LDAP" der Org):
   Namensschema (lowercase, NFKC; SMTPUTF8/IDN erlaubt, ASCII bevorzugt),
   Aliase, Gruppen, Catchall; Subdomain-Delegation (@abteilung.firma) durch
   eigenen Record. Legacy-Fallback: Attribut `smtp-fallback` je Postfach.
   Betreiberdomains reservieren Service-Namen (admin, postmaster, abuse, info, …):
   hart im Relay gesperrt (seit 17.11.), damit eine Adresse nicht gleichzeitig als
   SMTP-Umleitung und als lightningmail-Konto existiert — Kollisionsfreiheit, bis
   die Bridge beide Welten unter Relay-Regie vereint (§14).
   Existenz-Oracle gegen Enumerierung: keine Antwort vor Zahlung; tote
   Adressen → Dead-Mail-Porto in Relay-Pool (Refund-Alternative offen).
3. **Key-Bindung** — Mailbox-Key im Verzeichnis, Standard TOFU wie 4.1;
   Org-Signatur: Domain-Key aus Ebene 1 signiert Mailbox-Keys („Ausweis vom
   Arbeitgeber"), externe Kontakte fallen auf TOFU/DNSSEC zurück.

## 5. Geld- und Liquiditäts-Flow

- **Ausgehend:** Guthaben −Porto −(Router-Fee, unsichtbar, Relay-zahlt gesammelt).
- **Eingehend:** Empfänger-Preis steht im Profil (`default: 10 sats`; jede Richtung zahlt ihr Porto).
- **Bootstrap (das eigentliche Problem):** Neuer Account bekommt
  ~50–100 k sats als Welcome-Credit: ein Teil „geschenkt" (Porto-Budget,
  deckt erste Kontakte), ein Teil als inbound/outbound Channel vom LSP
  automatisch eröffnet (Phoenix-Modell: Channel-Management vollständig
  automatisiert, Nutzer merkt nichts). Kosten pro Account für den Anbieter:
  Cent-Bereich — ein Marketing-Budget, kein Technik-Problem.
- **Re-Balance läuft mit:** Jeder Empfang baut Outbound- Liquidität des
  Empfänger-Relays auf, jeder Versand Consumed Inbound — die Portowirtschaft
  balanciert das Netz teilweise selbst. Rest: automatisches Rebalancing im
  Relay (Loop/Submarine, Nutzer unsichtbar).
- **Auszahlung:** Button „Guthaben abheben" → LN Invoice/LUD-16 Adresse.
  Optional Auto-Sweep über Schwelle.

## 6. Spam-Ökonomie

- **LN-Paketgröße ist hart:** Onion = 1300 B (BOLT4), nutzbare Final-Payload
  ~150–500 B über Hops verteilt. Envelope (hash+id+sig+receipt+blob-refs)
  ~200–300 B passt; alles größere geht NIE über LN — Blob-Store-Route ist
  damit alternativlos, nicht nur elegant.
- **Manuelle Klassifizierung (kein Auto-Spamfilter):** Absenderstatus nur
  `unbekannt | whitelisted | unerwünscht(spam)` — pflegt der Nutzer selbst.
  Da Relays E2EE-blind sind, ist Filter/Ordner/Zuordnung zwingend
  **clientseitig**. Whitelist = Klassifikation (Sofort-Inbox, Benachrichtigung),
  **kein Porto-Privileg** (Hermes-Entscheidung 12.11., Bernd-vorbehaltlich:
  sonst trägt das Rückläufer-Modell nicht).
- **Fremd-Mail kostet:** Unbekannter Absender zahlt Empfängersetzen.
  10 Mio Spammails × 10 sats ≈ 3000 € — vorbei.
- **KEIN Konversationsfenster (Bernd, 12.11.):** Jede Richtung zahlt ihr
  Porto. In Antworten fließt das eigene zurück, nur **unbeantwortete
  Einweg-Mail kostet wirklich** — der Spammer zahlt für Müll, der
  Korrespondent nicht. Damit entfallen Antwort-Quoten, 0-Sats-Tokens und
  die Fälschbarkeit des Fensters. Spam-Ordner = Endablage ohne Aktion.
- **Whitelist: Ideen-Parkplatz, nicht v0.1 (Bernd, 12.11.).** Klassifikation
  v0.1 nur `rest | unerwünscht(spam)`. Whitelist-Idee zur späteren Aufnahme:
  *beidseitige Porto-Verabredung, ausgelöst als eingebaute Anfrage beim
  Antworten* ("uns gegenseitig privilegieren?", beides Opt-in, verhandelbar,
  nichts implizit). Bis dahin keine Whitelist-Logik im Client.
- **Newsletter/Transaktionale Mail (v2):** Massenversender lösen über
  Abonnement-Semantik (Empfänger opt-in = Absender-Privileg, Preis pro Abo-Mail)
  oder verifizierte Absender-Lizenz. Ohne das bricht der ganze Geschäfts-E-Mail-Verkehr.
- **Empfänger-Preis als Marktplatz:** bernde.top-Inbox = 100 sats, gisela.de = gratis.
  Anti-Selbstbedienung: Bot-Farm-Mailboxen bringen nur etwas, wenn Preise >
  Betriebskosten; Reputation/Deposit für Relay-Accounts (v2) dämpft es.
  (Ehrliche Grenze: Pay-to-Recipient verschiebt Spam-Ökonomie; Pay-to-Burn
  [SpamBat] wäre die saubere Alternative, kostet aber die schöne „Porto gehört dir"-UX.
  → Diskussion offen.)

## 7. Verschlüsselung

- Payload: AEAD (XChaCha20-Poly1305 oder AES-GCM) mit Empfänger-Key;
  Signatur mit Absender-Key (secp256k1 passt zu LN).
- Key-Rotation + Backup: Seed-basiert; geteilte Bilddeschreibung wie Signal.
- Metadata: Onion-Routing versteckt Absender→Relay-Pfad, Relay sieht Empfänger-
  Postfach + Timing; Größe durch Padding-Klassen (v2).

## 8. Was bmail NICHT (Scope v0.1)

- Kein SMTP/IMAP-Kompatibilitäts-Layer (Brücke = separates Gateway-Projekt, Phase v2).
- Kein Full-Node-Zwang für irgendwen außer Relay-Betreibern.
- Kein Fiat-Onramp in Phase 1 (Guthaben = Sats, Umrechnung nur Anzeige).
- Kein Gruppen-Chat (E-Mail-Charakter: 1:n mit CC, aber kein Chat-Ersatz).

## 9. Tech-Stack (Vorschlag)

| Schicht     | Wahl                                    | Warum |
|-------------|-----------------------------------------|-------|
| Spike       | Python (LNemail-Fork)                   | Ökonomie-Modell in Tagen beweisen, nicht Monaten |
| LN          | LND (+später CLN)                       | Keysend-TLVs, LNC, sphinx-relay-Erfahrung |
| Relay-Business/Bridge | **Go**                    | 1 statisches Binary (NAS/Umbrel/Start9), LND-Heimat, wassat-Referenzcode |
| Mailbox-Base| Stalwart als Blackbox (LMTP rein, JMAP raus) | Rust nur konsumiert, nie geforkt |
| Client      | **TypeScript** als PWA (+TB-Extension)  | eine Sprache für Webmail/UI/Extension; native App = M4-or-never |
| Ledger      | LNbits-Vorbild oder DB-intern           | Multi-Account-Salden, Auszahl-Flow |
| Blob-Store  | Relay-eigen (S3-compat)                 | verschlüsselte Attachments, Content-Hash |

## 10. MVP-Plan

- **M0 — Spec (1–2 Wochen):** Wire-Format (TLV-Schema), Receipt, Preis-Header,
  Onboarding-Flow, Ledger-Definition. Dieses Dokument als Kern.
- **M1 — Closed Loop (PoC):** 1 Relay, 2 Accounts (ein Handy + ein Desktop),
  Bild anhängen, Guthabenbewegung sichtbar, Mailbox offline+Store&Forward.
  *Erfolg: „Oma-Test": eingewiesene Person verschickt Foto in < 2 Min,
  Empfänger sieht +10 sats auf dem Guthaben.*
- **M2 — Multi-Relay:** 2 Relays (Heim-NAS + VPS), Föderation über DNS (`_bmail._tcp`),
  Bootstrap-Skript für Relay-Betreiber (Light-Relay mit Neutrino oder Full-Relay).
- **M3 — Regeln & Betrieb:** Retention-Cleanup, Byte-Porto, Steuer-Statements,
  Account-Identität (OIDC-IdP & Service-Connector).
- **v2 — Brücken & Massen:** SMTP-Gateway, Newsletter-Modell, Reputation.

## 11. Risiken & offene Punkte

1. **Adoption ist der Endgegner** (Netzwerk-Effekt Mail; Josh Hansen 2022:
   „das Schwierige ist nicht technisch"). Gegenmittel: bmail muss *besser* sein
   als Mail, nicht nur spam-frei — Guthaben, „gelesen"-Quittungen, bezahlte
   Newsletter, keine Werbung, Adressen sind Keys.
2. **Pay-to-Recipient vs. Pay-to-Burn** (Abschnitt 6) — Protokollentscheidung.
3. **Kleine Beträge & Fees:** Onion-Fees fressen <5-sat-Beträge; Mindestporto
   + Relay-seitiges Batching nötig.
4. **Rechtsform:** Empfänger-Guthaben aus fremden Mails = Zufluss? (Scheck/Mahnung/
   Behörde bräuchte ggf. Free-Tier-Gateway.) → vor Release juristisch ansehen.
5. **Namensraum:** „bmail" mehrfach belegt (div. Mail-Firmen) — Markencheck.
6. Zensur-Aspekt: Porto-Modell = bezahlter Zugang; relay-Diversity gegen Gatekeeping.

## 12. Realitäts-Check: was LUD-16 schon bewiesen hat
### 12.1 Lebende Vorarbeit (Stand 11/2026, GitHub verifiziert)
- **LNemail** (lebt, Update 13.11.2026): Wegwerf-Mailbox gegen LN-Porto
  (1000 sats/Jahr, Zufallsadresse + Bearer-Token); FastAPI/SQLite/Redis,
  LND **und NWC** als Payment-Backends mit Fallback; echtes SMTP/IMAP ins
  Legacy-Internet (Weg 1 als Produkt!); Senden ab 100 sats mit Burst-Pricing
  (5er-Burst, Slot alle 12 min, Verdopplung ohne Deckel); WebAuthn-Passkeys
  zur Token-Recovery (11/2026 — Konvergenz mit Etappe 6a); llms.txt +
  SKILL.md = Agenten-Zielgruppe (vgl. §15); MIT. Porto geht an Plattform,
  Identität = wegwerfbar. Dennoch: Validierung, dass LN-Porto-UX funktioniert
  und Kleinstbeträge gezahlt werden. Idee zum Abschauen: Burst-Pricing als
  Preisprofil-Variante, Agent-first-Doku.
- **pay2email/pay2.email** (Casatta, lebt): „Invoice bezahlt → Mail zugestellt",
  CLN-Plugin; Beweis: Portopflicht ohne Empfänger-Guthaben verkauft sich
  bereits (Kontaktformular-Nische).
- **paid-services** (alexbosworth, aktiv 11/2026): Keysend-Inbox — bezahlte
  Kurznachricht → SMTP/SMS-Zustellung. Wörtlicher M1-Baustein.
- **Whatsat** (tot 2021, 421★): Referenzdesign P2P-Chat als keysend+TLV;
  scheiterte an Liquiditätsanforderung an Endnutzer → bestätigt Relay-Modell.
- **LSAT** (2019): Macaroon-Token gegen Lightning-Zahlung = Porto-Quittung,
  Standard existiert. **NIP-11 fees-Feld** (Nostr): pay-per-publication-
  Preisprofile in msats — Syntax für §4-Preisprofil entleihen.
- **TLV-Registry** (satoshis.stream): Message-Records (34349334 ff.) sind
  interoperabel zwischen whatsat/sphinx/ThunderHub genutzt → bmail-Envelope
  registriert nur neu, erfindet nicht.
→ Gemeinsame Todesursache der Vorgänger: Porto an die Plattform statt an den
  Empfänger, oder reiner P2P-Transport ohne Bootstrap. Empfänger-Guthaben +
  Zustell-Semantik + LSP-Bootstrap = die unbesetzte Lücke = bmail.

- MicroStrategy 04/2023: Firmen-E-Mail adresses → Lightning Address (LUD-16),
  ein einziger Node, PR-getrieben, nach Monaten still. Stand 11/2026:
  /.well-known/lnurlp/* antwortet nur noch HTTP 403 (Akamai; tot vs.
  Datacenter-Block nicht decisiv). Lehre: Komfort allein tötet nichts,
  Retention braucht Ökonomie — die bmail-Portopflicht IST der Unterschied.
- Stacker-Thread 2023 diskutierte sofort Identity-Mapping/Dusting gegen
  Mitarbeiter-Adressen. Konsequenz für bmail: Local Part standardmäßig anonym
  wählbar, kein HR-Verzeichnis-Zwang; Vanity opt-in.
- Zaprite/SathetHQ (serverless E-Mail→Zahlung, lebt als B2B-SaaS): zeigt
  Topologie funktioniert (Provider-Node vor vielen Nutzern) — aber ohne
  Delivery-Semantik bleibt es ein Payment-Add-on.
  → Namenspattern `name@domain` ist empirisch überlebt und validiert (4.1).
  bmail unterscheidet sich dort, wo LUD-16 aufhörte: Porto regelt die
  ZUSTELLUNG, nicht nur die Zahlung.

## 13. Porto als Lightning-Primitiv (LNURL/Hold-Invoice)

Porte-Beleg erfinden wir nicht neu, sondern nutzen LNURL (LUD-16/LUD-17):

- **Stamp = gezahlte Invoice:** Sender holt beim Empfänger-Relay eine Invoice,
  deren Description/Tag an die Message-ID (bzw. deren Hash) gebunden ist
  (LUD-09 Payer-Data analog). Relay stellt erst nach Settlement zu.
  Abellbar per Invoice-Expiry: "Porto gültig 24h".
  → Jedes LUD-16-fähige Wallet kann Sender-Infra sein; Relay-Eigengewicht klein.
- **Anti-Ernte-Mechanismus (löst Abschnitt 6.1):** Hold-Invoice-Modell.
  Zahlung wird vom Empfänger-Relay als HTLC gehalten, erst bei Annahme
  (Whitelist/Accept) released. Nicht abgeholt → Timeout → Sender refundet.
  Spam-Müll wird damit ökonomisch wertlos statt vergütet; der Spammer verliert
  Routing-Fees, HTLC-Slots und Zeit (Abschreckung bleibt, Ernte-Motiv fällt).
- Caveat: Hold-Invoice-Support ist implementationseitig dünner (LND: Registry
  `hold` ab 0.15, CLN: Plugin/fälligkeits-behaftet) → Fallback: Provider-Receipt
  Modell A (5.1) mit Trust-on-Pay, Hold erst M3.

## 14. Integration in bestehende Mail-Clients (Bridge-Modell)

> Status 13.11.2026: auf Bernds Wunsch **zurückgestellt** — Fokus liegt auf
> Weg 2 (bmail als Account-Identität, §20–22). Bridge bleibt v2-Option.

Kein Plugin — Plugins (TB WebExtensions, Outlook Add-ins) können keine neuen
Kontotypen anmelden. Vorbild Proton Mail Bridge: lokaler Daemon als
IMAP/SMTP/JMAP-Server, synct mit bmail-Relay; Clients sehen normales Postfach.

- Clients: Thunderbird ✓✓ (Bridge + natives OpenPGP + JMAP-Roadmap 2026/27 →
  ggf. nativ ohne Bridge); Apple Mail ✓ IMAP; eM Client ✓ JMAP;
  Outlook ⚠️ nur Classic — New Outlook erzwingt Cloud-Sync, lokales IMAP tot
  (Proton-Bridge inkompatibel, dokumentiert). Outlook-Story ehrlich verkaufen.
- bmail-Eigenheiten (Guthaben, Porto, Hold-Accept UI) als dünne
  WebExtension/Sidebar, die den Bridge-Daemon über localhost-API spricht.
  Ohne Extension: Degradation zu „funktioniert grau" (Empfang/Sende via
  Reply-Aktion), nie Blockade.
- Relay-Fundament-Kandidat: **Stalwart** (Rust; JMAP+IMAP+SMTP+CalDAV, Basis
  von Thunderbird Thundermail) + bmail-LN-Modul davor → spart den Großteil
  des Relay-Mailbox-Eigengewichts aus §9.
- Designfrage Decryption: Bridge entschlüsselt lokal (Proton-Modell, Klartext
  im Client) ODER PGP durchreichen (TB-OpenPGP entschlüsselt selbst).
  Ziel: beides, pro Konto konfigurierbar.

## 15. MCP-KI-Schnittstelle (Agent-Post)

Dünner stdio-/HTTP-MCP-Server auf der Relay-API (Go), kein Eigen-system:

- Tools: balance · inbox_list · read_message · send (Porto automatisch aus
  Preisprofil) · quote_postage (Preis erfragen ohne Spam) · accept_hold/
  reject_hold (ab M3) · contacts/price_profile-Pflege; Neue-Mail-Events als
  Resource/Notification.
- Sicherheit = Designkern: (1) Scoped Delegations-Tokens für Agenten
  (Macaroon/LSAT-Muster, §12.1) mit Budget (sats/Tag, Mails/Stunde,
  Postfach-Whitelist), niemals Account-Key. (2) Mail-Inhalt ist Untrusted
  Input: Read frei, Send ab Schwellwert mit Human-Confirm — bmail macht
  Injection-Mails teuer, aber die Client-Regel bleibt nötig.
- Agent↔Agent: Preisprofil (NIP-11-artig, §4) ist verhandelbar
  maschinenlesbar; Agenten entscheiden in Sekunden über Porto-Loahnbarkeit.
- Plan: MCP-Server ab M2 parallel zur Webmail (Relay-API existiert dann);
  erster Referenz-Client: Hermes selbst als MCP-Host.

## 16. Client-Sync über mehrere Geräte (Stern-Struktur, M2.5)

Realfall (Bernd): 1 Konto, 3+ Clients (Privatrechner, Büro, Handy). Sync muss
**kostenlos und ohne Lightning** laufen — es ist der eigene Account, keine
Fremd-Mail.

Entschieden: **saubere Stern-Struktur über das eigene Relay** — kein P2P, kein
Syncthing, keine NAT-Lochbohrung, kein Geräte-Pairing. Jeder Client spricht
ausschließlich mit seinem Relay, der ohnehin immer erreichbar ist. Zwei
Schichten, getrennt nach Datengröße:

**Schicht 1 — dauerhaft auf dem Relay (klein, heiß):**
- **Briefe (Envelopes ≤ 600 B)** bleiben als eigentliche Mailbox liegen.
- Das **State-Doc** — `read`, `spam`, `deleted`, `drafts`, `sent`,
  `contacts` — liegt als ein selbst-ECIES-verschlüsselter Slot (256-kB-Cap,
  CAS über `expect_version`; Merge: Flags OR, Drafts/Kontakte/Gesendet LWW
  pro Id) daneben.
- Größenordnung: 10.000 Mails ≈ 4 MB SQLite — den Relay juckt das nicht.
- Folge: jedes neue Gerät, ebenso die 24-Wort-Seed-Recovery, hat sofort das
  komplette Postfach — Eingang, Gelesen-Status, Spam-Klassifikation,
  Entwürfe, Adressbuch **und Gesendet-Ordner** (Empfänger, Betreff,
  Zeitstempel, Body bis 2000 Zeichen, die neuesten 150 Einträge).

**Schicht 2 — Relay als Frachtbahnhof, Clients als Dauerarchiv (groß, kalt):**
- Große Anhänge (`blob_refs`, content-adressiert) bleiben nur bis
  **Erstdownload + 7 Tage** (`grace_days`) auf dem Relay, absolute Obergrenze
  90 Tage — Frachtbahnhof, kein Lager. Auf dem eigenen Heim-Relay bedeutet
  `grace_days: -1` unbegrenzte Aufbewahrung.
- Jeder Client, der einen Anhang öffnet, legt die Bytes in einem lokalen
  **IndexedDB-Cache** (`lightningmail_blobs`, Schlüssel = sha256) ab. Damit
  hat nach dem serverseitigen Sweep jedes Gerät, das den Anhang je geladen
  hat, ihn dauerhaft lokal — der Sweep vernichtet nie die einzige Kopie.
- Dedup-Regel: Löschung einer sha erst, wenn ALLE blob_refs darauf
  downloadet/abgelaufen sind — sonst frisst Nutzer A dem Nutzer B die Anlage
  weg.
- Verfallene Anhänge beim Weiterleiten: Client hat das Original lokal (sha
  bekannt) → Re-Upload, Adressierung bleibt intakt.
- UI-Regeln: „läuft ab in X Tagen“ + Download-Status pro Mail, sichtbar.
- Späteres Geschäftsmodell: verlängerte Aufbewahrung = Eur-Dienstleistung
  (§18 sauber: Dienstleistung, kein Fiat→Sats). Blob-Mirror relay↔relay
  (6.4) bleibt für Übertrag, e2e-seitig; Frist-Cleanup = M3.

## 18. Aufladung & Lizenzgrenze (MiCA, 12.11.2026)

Rücklage: Nutzer fragte nach BTCPay-/Karten-Aufladung. Ergebnis: Technik trivial,
Regulatorik ist der Grund, warum wir's NICHT so bauen.

**Harte Regel: der Relay ist niemals ein Fiat→Sats-Mischer.**
Seit 1.7.2026 (DE 1.1.2026) verlangt MiCAR für "Krypto gegen Geld tauschen"
für EU-Kunden eine CASP-Lizenz (50–150k€ Eigenkapital, KYC/AML, BaFin). Ein
Hobby-Relay, der "zahl 10€, krieg 10€ Sats-Guthaben" macht, wäre
lizenzpflichtig — tot, bevor er lebt.

Erlaubt / sicher (Händler-Modell, keine Krypto-Dienstleistung):
- **Nutzer bringt eigene Sats mit** und lädt seine Mailbox auf (Zahlung für
  eine Dienstleistung, wie ein Shop der BTC akzeptiert). Kein Tausch.
- **Mailbox-Laufzeit / Speicher als Eur-Dienstleistung verkaufen** (normaler
  SaaS via Stripe/Mollie, außerhalb des Relay-Kerns). Sats-Guthaben wird
  NIE aus Euro erzeugt.

Google Pay = kein Zahlungsdienstleister, sondern Karten-Wallet; braucht immer
einen Acquirer (Stripe/Mollie/Adyen) mit Merchant-Registrierung + KYC.
BTCPay-Reality: 0% Gebühr/non-custodial, aber 4GB/2vCPU-Pflege + 2026
aktiv ausgenutzte LND-Macaroon-Schwachstelle (v2.4.2) → nicht neben den
Live-Key auf dieselbe Maschine. Karten geht bei BTCPay auch nur via Stripe-Plugin.

v0.1-Beschluss: KEIN Fiat-Onramp im Relay. Aufladung = externe Sats des
Nutzers auf eine Relay-Invoice (On-Chain/Lightning, M3 Feature, kein Tausch).
Optional spätere Eur-Seite = Dienstleistungskauf, getrennt vom Relay.

## 19. Ein-Satz-Pitch

„Deine Mails sind jetzt bares Geld wert — und die der anderen auch."

## 20. Identity-Vision: ein Schlüssel, ein Transport, ein Speicher (13.11.2026)

Bernd-Entscheidung 13.11.2026: Die SMTP-Eingangsbrücke (Weg 1) wird
zurückgestellt — vorerst verzichtet niemand auf seinen Legacy-Mailclient
(§14 bleibt v2-Option). Fokus = **Weg 2: bmail als Account-Identität.**
Begründung: E-Mail ist allgegenwärtig, weil sie das Zentrum aller
User-Accounts ist (Registrierung, Bestätigung, Passwort-Reset). bmail kann
nur erfolgreich sein, wenn man damit Accounts erstellen kann.

Vereinende Erkenntnis: Auth, Mail, Privacy, Spamschutz und riesige Anhänge
sind nicht fünf Techniken, sondern ein Primitiv —
**ein Schlüssel, ein Transport, ein Speicher**:

- **Ein Schlüssel:** das secp256k1-Keypair ist zugleich Postfach-Adresse
  (Mail), Identität (Auth via BIP340-Challenge) und Vertrauensanker
  (E2E/Privacy). YubiKey/FIDO2 = Besitzfaktor dafür.
- **Ein Transport:** Relay + Lightning-Porto. Authentifizierung ist schlicht
  „eine Mail mit Challenge als Inhalt"; der OIDC-IdP ist der standardisierte
  Wrapper, den Dienste verstehen. Spamschutz wirkt ökonomisch auf Mails,
  Logins und Blob-Uploads gleichermaßen.
- **Ein Speicher:** Blob-Store mit Content-Hash (läuft: 1 MB + Relay-Mirror,
  Spec 6.4). Riesige Anhänge = gestückelte Blobs mit Byte-Porto; Transport
  per HTTP-Fetch statt LN-Kanal — Größe nur durch Relay-Storage begrenzt,
  Missbrauch durch Porto.

Pitch-Erweiterung: **„Selbstbestimmte, bezahlbare Identität — Mail ist nur
die erste Anwendung darauf."** Account-Erstellung, Passkey-Ersatz, File-Drop
und Messaging hängen am selben Schlüssel und derselben Ökonomie.

## 21. Etappe 6 — Identity: Key-Lookup, OIDC-IdP, WebAuthn

Ziel: `name@relaydomain` wird zum Account-Anker, den Dienste nutzen können —
ohne öffentliches Telefonbuch/Directory. Die Empfängeradresse allein reicht.

- **Relay-Domain:** jede normale Registrar-Domain (.de ~1–3 €/Monat;
  Konzept-Beispiele §4.1: `bernd@bmail.de`, `gisela@familie.koeln`).
  Ein `_bmail._tcp`-TXT-Record (Ebene 1, §4.2) zeigt auf den Relay;
  Zoneninhaber = Postamt-Inhaber. Optisch von E-Mail ununterscheidbar —
  so gewollt (§4.1 „exakt E-Mail-Notation, nichts Neues zu lernen").
  Gratis-Bonus: jede Adresse ist via LUD-16-Well-known zugleich eine echte
  Lightning-Address, bestehende Wallets können sie besenden.
- **Direkte Schlüssel-Auflösung (kein Directory):** `GET /v1/profile/{name}` am
  Ziel-Relay liefert kostenlos den Mailbox-Pubkey und den Portosatz. Ein
  öffentliches Adressbuch mit bezahlten Profilkarten (frühere Etappe B) wurde
  am 19.11.2026 bewusst gestrichen: Es brachte DSGVO-Komplexität ohne
  Protokollnutzen, da der Ziel-Relay den Pubkey ohnehin kennt.
- **OIDC-IdP (Go, direkt im Relay — GEBAUT, spec §7e):** „Sign in with
  lightningmail" für Dienste.
  - Login-Faktor = WebAuthn/Passkey (YubiKey/Handy) oder Schlüsseldatei/24 Wörter.
  - Föderations-Beweis = BIP340-Signatur des Mailbox-Keys über eine
    32-Byte-Server-Challenge (`bmail`-Claim im ID-Token, `email_verified=true`).
    P-256 (IdP-JWT) und secp256k1 (Mailbox-Key) bleiben sauber getrennt.
  - Betreiberrolle dezentral: Jedes Relay (Light oder Full) ist sein eigener
    OIDC-Issuer; Dienste entdecken ihn über die Adresse des Nutzers.
- **Ohne MX** bounct Legacy-SMTP an bmail-Adressen; Zwischenstufe:
  **MX-Dead-Drop**, der einen erklärenden Auto-Bounce liefert („diese Adresse
  spricht lightningmail").

## 22. Etappe 7 — Chunked Blobs & Byte-Porto (riesige Anhänge)

- Blobs >1 MB: Chunking client-seitig (1-MB-Scheiben, Content-Hashes pro
  Chunk + Manifest-Hash); Envelope trägt das Manifest über die bestehende
  `blob_refs`-Struktur (erweitert um size/chunks).
- **Byte-Porto:** Storage-Preis pro Byte (ggf. pro Zeit) beim Upload —
  Storage-Missbrauch und Spam laufen über dieselbe Ökonomie.
- Delivery unverändert: HTTP-Fetch + Relay-Mirror (Spec 6.4);
  Cleanup hängt am bestehenden `blob_refs.downloaded_at`-Pfad
  (`relayd -cleanup-once`).
- **Status (18.11.2026): GEBAUT** — spec §6.5: 1-MiB-Scheiben + Manifest
  als Blob, alle Hashes in blob_refs (ACL/Mirror unverändert), 255-Ref-Cap
  (~254 MB/Brief), Byte-Porto `byte_porto_meur_per_mb` (Prod-Regtest-Vorschlag
  1 ct/MiB) pro frischem blob_ref, erst kassieren dann speichern, Refund bei
  Infra-Fehler, 503 ohne Kurs. Zeitkomponente offen (Retention deckt Basics).
  UI: Kostenschätzung im Compose (/health), Scheiben-Fortschritt, 📦-Download
  mit Reassemblierung. Tests: chunk-test.mts 15/15 inkl. Cross-Relay-Roundtrip.

## 23. Empfangsbestätigung ✓/✓✓ (Etappe 6b, 13.11.2026)

Bernd-Entscheidung: WhatsApp-Semantik, ausdrücklich NICHT aufdringlich wie
E-Mail-Lesebestätigungen. Immer an (v0.1), Stempel bei **Client-Abruf**.

- **✓ gesendet:** Porto via Keysend am Empfänger-Relay settled — die
  LN-Preimage ist die Quittung (spec §4). Weiß der Absender-Client sofort.
- **✓✓ empfangen:** der Empfänger-CLIENT ruft die Nachricht ab (Inbox-Fetch).
  Empfänger-Relay stempelt und spiegelt batchweise an die Peers;
  Absender-Relay ordnet über sha256(sender_pub) = recipientHash zu.
- **Kein Blau-Haken:** Gelesen-Status gibt es nicht. Opt-out pro Konto
  (Policy/Preisprofil) ist ein M3-Kandidat.
- **Privacy-Einordnung (Bernds Punkt bestätigt):** Das LN-Settle beweist nur
  Relay-Eingang, nicht Client-Empfang — deshalb die ✓✓-Stufe erst bei Abruf.
  Wer-mit-wem ist bei Textmails ohnehin für beide Relays und den LN-Pfad
  sichtbar (Klartext-Tag 0x04 im Envelope); Receipts fügen als EINZIGEN neuen
  Datenpunkt den Sync-Zeitpunkt des Empfängers hinzu. Echte
  Metadaten-Minimierung liefert erst Etappe 5 (Onion-Routing zwischen Relays).
- Umsetzung: spec.md §7c (Tabellen, Endpunkte, 60s-Retry-Ticker),
  Tests: `go test ./internal/ledger -run Receipts`, `npx tsx test/receipts.mts`
  (Cross-Relay-Kette inkl. Dedup).

## 24. Denkskizze: Gruppen & Netnews-Nachfolge (13.11.2026, Reflexion — KEIN Beschluss)

Ausgangspunkt (Bernd): Die Ender-Game-Romane skizzieren eine offene
Netz-Diskussionskultur; alte Mail-Clients hatten NNTP/Netnews eingebaut
(Thunderbird kann es bis heute). Heute: Moderationspflicht, Extremismus,
Strafverfolgung — „die alten Zeiten sind vorbei, aber reizvoll wäre es."

**Korrektur am Mythos:** In der Serie wirken Peter und Valentine als
„Locke"/„Demosthenes" — die Utopie ist nicht Klarnamenszwang, sondern
**Autorität durch Inhalt statt Ausweis**. Exakt das könnte bmail: Identität =
Schlüssel mit Kontinuität + portabler Reputation (BMRV-Delegations-Record,
§4.1). Klarnamen wären das illiberalste Feature, das man bauen könnte.

**Was bmail genuinely ändern würde:** Usenet starb nicht an der
Meinungsfreiheit, sondern am Rauschen (Spam, Binary-Groups, Cancel-Kriege).
Porto ist die einzige bekannte Moderation ohne Moderatoren: Massen-Trolling
kostet Geld, Gruppen setzen ihren Mindestpreis selbst (Preisprofile §4.1).
Technisch ist eine „Gruppe" kein neues Subsystem, sondern eine Adresse mit
Fanout: Gruppen-Schlüssel am Relay, Abo-Tabelle, Porto-Regel, Verteilung über
den bestehenden Relay-Mirror (6.4).

**Die harte Wand (Recht):** DSA/NetzDG — wer öffentlich zugängliche
Diskussionsräume hostet, haftet als Plattform: Löschfristen, Meldewege,
Bußgelder. E2E hilft bei öffentlichen Gruppen nicht (was alle lesen können,
verantwortet der Betreiber). Aus DE/EU ist ein offenes Netnews-Revival für
Relay-Betreiber schlicht nicht betreibbar. Hosting außerhalb der EU (§21-Domain-
Diskussion) verlagert nur das Betreiber-Risiko; die Nutzer haften für ihre
Aussagen weiter.

**Das natürliche Experiment heißt Nostr:** Schlüssel-Identität + Relays +
Lightning-Zaps, seit 2022 live. Ergebnis: Rauschen mutierte statt zu
verschwinden, Moderation wanderte in client-seitige Blocklisten. Lehre:
Schlüssel + Lightning allein erzeugt keine Kultur. bmails Unterschied:
**Porto auf dem Weg in MEIN Postfach** — bei Nostr sendet man gratis in die
Welt, hier kostet es, fremde Aufmerksamkeit zu kaufen. Näher am bezahlten
Brief als am Marktplatz.

**Fazit der Skizze:**
1. Realistischer Kern = **bezahlte Mailingliste** (Substack+Discord als
   Protokoll statt Firma): geschlossene Gruppen, Porto-Ökonomie, rechtlich als
   private Gruppenkommunikation handhabbar, finanziert Relay-Betreiber.
   Kleiner technischer Schritt vom Bestand (Adresse + Fanout + Abo-Tabelle).
2. Offene Netnews-Romantik = ökonomisch lösbar, rechtlich von der EU aus tot.
   Bliebe Experiment für Relays in fernen Jurisdiktionen — mit dem
   Extremismus-Risiko, das Nostr exemplarisch vormacht.
3. Anschlussfähig an §20: eine Gruppe ist „nur" eine weitere Identität
   (Schlüssel) mit eigenen Porto-Regeln — ein Schlüssel, ein Transport,
   ein Speicher gilt auch hier.

Status: Idee, nicht eingeplant. Wenn je gebaut, dann erst nach Etappe 6/7
und nur Variante 1 (geschlossen, bezahlt).


## 25. Steuer-Log: local currency für jede Bewegung (15.11.2026, GEBAUT)

Sobald User oder Betreiber relevante Summen bewegen (Porto-Einnahmen,
Byte-Porto-Fees, Erstattungen), braucht der Steuerpflichtige einen belastbaren
Nachweis in lokaler Währung. Der Relay schreibt mit, aber er buchführt nicht.

- **Rate beim Zufluss:** jede neue Ledger-Zeile erhält `eur_micro + rate_ts +
  rate_src` — entschieden: **Tageskurs** (BSi/Binance EUR-Paar, ein Abruf pro
  Tag, manuelles Nachsetzen als Fallback). Nachträgliches Raten alter Zeilen
  ist unredlich; Regtest-Müll bleibt ungeratet bzw. mit `rate_src=manual` markiert.
- **Zwei Sichten:** Konto-Statement für den User (Einnahmen: erhaltenes Porto,
  Erstattungen; Ausgaben: gezahltes Porto, Byte-Porto) und Betreiber-Statement
  (Byte-Porto-Fees, Erstattungen). On-chain-/Routing-Gebühren kennt der Relay
  nicht — Hinweis im Export, dass LND-Reports die Ergänzung sind.
- **Export (GEBAUT, spec §7f):** `GET /v1/statement?from&to&fmt=csv|json` (auth,
  eigenes Konto) + `/v1/relay/statement` (X-Relay-Secret) für den Betreiber.
  Zeilen hash-verkettet (Genesis = sha256 über Kontoname), damit der Stapel bei
  der Prüfung nicht umfallen kann. UI: Menüpunkt „💶 Umsätze" in der App.

## 26. Multi-Währungs-Porto: BTC und LTC in einem Mail (Beschluss 15.11.2026, Bau in Etappe B / K)

Porto wahlweise in BTC- oder LTC-Lightning — kein separates LTC-Mail, ein
Programm. Kernentscheidungen:

- **Preis ist wertdefiniert:** Empfänger taxieren in Cent, der Relay rechnet
  per Tageskurs in die Währung. Sat-feste Preise wären das Spammer-Schlupfloch
  (LTC-Sats ≈ 1/80 BTC-Sat). Der Kurs-Feed ist derselbe, den Etappe G
  (Steuer-Log) fürs Rate-Stempeln braucht.
- **Ledger ab Etappe B mit currency-Spalte** (Default btc). Buchungen je
  Währung strikt getrennt — keine automatische Umrechnung, der Relay ist keine
  Wechselstube. Endpoints nehmen ?cur=.
- **Keine Mischpfade:** eine Zahlung braucht eine vom Empfänger-Relay
  besiedelte Währung; das Preisprofil listet akzeptierte Währungen.
- **Betrieb als Schalter:** zweite lnd (chain=litecoin) + litecoind ist eine
  Betriebs-Option pro Relay (~3 AT zusätzlich, Etappe K nach der Beta).
  Mailbox-Krypto und Envelope sind kettenblind — Client-seitig ändert nichts.

## 27. Onboarding & Produkt-Linien: Relays und Clients (19.11.2026)

Getrennte Welten — der Client besitzt per Design keinen Node und keine
Channels (Porto = Guthaben beim Relay, Schlüssel = ein secp256k1-Paar).

**1. Client-Setup-Wizard (Etappe 6d — GEBAUT):**
- 24-Wort-Recovery (BIP39): Seed im Browser erzeugt, Wortquiz zur
  Bestätigung, `.lmkey`-Passphrase-Datei optional.
- Plattformen aus einem gemeinsamen TypeScript-Kern (`client/src/`):
  Web-PWA, Android-APK (gebaut), iOS/Apple, Linux und Windows.
- Kein Scan, kein Channel, kein Node — das ist das Werbeversprechen.

**2. Relay-Betriebsmodi (Etappe O — Installer):**
- **Light-Relay (`relayd` + `lnd` im Neutrino-Modus):** Kein eigener `bitcoind`
  nötig; LND zieht Compact Block Filters (BIP 157/158) direkt von öffentlichen
  Bitcoin-P2P-Knoten (~10 GB Disk, <300 MB RAM, in 30–60 Min einsatzbereit).
  Macht jedes Heim-NAS (QNAP/Odroid), jeden Raspberry Pi oder kleinen VPS zum
  vollwertigen Postamt.
- **Full-Relay (`relayd` + `lnd` + eigener `bitcoind`):** Eigener Vollknoten (~700 GB)
  für große Betreiber und maximale Unabhängigkeit.

**3. Etappe O gebaut (20.11.2026, v1.0.5) — das Dritt-Relay ist gleich das komplette Postamt:**
- `relayd` serviert die gebaute PWA selbst (`ui_dir` in `relay.yaml` → `/app/`):
  Selbstbauer öffnen `https://<domain>/app/`, API und UI sind same-origin,
  CORS kommt im Client-Design gar nicht vor. Der Installer erzeugt `ui_dir`
  und die ./ui-Bauanleitung gleich mit.
- Clients brauchen am Fremd-Relay null Einstellungen: die App erkennt ihr
  eigenes Origin (synchron per `?self=1`-Navigation, asynchron per
  `/health`-Probe) und stellt dann nur „Dieses Relay" bereit; von außen führt
  der dritte Dropdown-Eintrag „⚙️ Eigenes Relay (URL)…" als reine Navigation
  zum Dritt-Relay (kein Cross-Origin-Fetch).
- Die Android-APK merkt sich das Heim-Relay (`home_relay`-Preferences über die
  native Bridge) und startet direkt dort; ist es nicht erreichbar, fällt sie
  mit Toast auf lightningmail.app zurück. Der native Linux-Client konnte
  fremde Relays schon vorher (`BMAIL_RELAY`-Umgebungsvariable).
- Föderation eingehender Post bleibt bei einer einzigen DNS-Pflicht
  (`_bmail._tcp.<domain>`-TXT, §4.2); Abnahme: `client/test/selfhost-smoke.mts`
  (Konto+Auth+Inbox+Balance gegen ein live Fremd-Relay ohne jede
  Client-Einstellung). Vorführ-Instanz: `https://relay.lightningmail.app/app/`
  (Mainnet-Light-Relay, CT112).

## 28. Anmeldungs-Porto & Authentifizierung: "Mit lightningmail anmelden" (Etappe I, konsolidiert 19.11.2026)

Ein Dienst soll für eine Bestätigungsmail nicht draufzahlen — die Richtung
umzudrehen (Empfänger zahlt, Vorschlag 1) ist ABGELEHNT: sie bräche die
Konstante „der Sender zahlt" und ließe das Opfer für seinen eigenen Spam zahlen.

**Das einfache Modell ohne Konversationsfenster:**
- **Stufe A — Reiner Login (OIDC, bereits im Relay eingebaut):**
  Will ein Dienst nur wissen, wem `name@domain` gehört, nutzt er Standard-OIDC
  („Sign in with lightningmail", §21 / spec §7e). Der Nutzer signiert im Browser
  eine Challenge mit seinem Mailbox-Key (BIP340), der Dienst erhält ein
  verifiziertes ID-Token (`email_verified: true`). Kein Passwort, kein Plugin,
  keine Mail-Kosten.
- **Stufe B — Bezahlte Registrierung & Systemmails (ohne Konversationsfenster):**
  - Der USER schickt zur Registrierung den ersten Brief an den Dienst (z. B.
    `auth@dienst.de`) und zahlt dabei den **Porto-Vorschuss** des
    Dienstes (z. B. 50 sats statt 10 sats).
  - Der Dienst antwortet mit der Bestätigungsmail zum ganz normalen Standardporto
    des Users (z. B. 10 sats) aus diesem Vorschuss und behält die Differenz (40 sats) als Einnahme.
  - **Kein Konversationsfenster nötig:** Jede Richtung zahlt wie überall im
    Protokoll ihr normales Porto; weil der Porto-Vorschuss des Dienstes höher
    liegt als das Standard-Rückporto, verdient der Dienst an jeder echten
    Registrierung, ohne dass das Relay eine Konversations-State-Machine braucht.

## 29. Service-Integration in der Praxis: OIDC & Service-Connector (19.11.2026)

lightningmail bindet nahtlos an bestehende Dienste an und läuft parallel zur
klassischen E-Mail-Welt. Das Ökosystem besteht aus drei klar getrennten Teilen:

1. **Relay (`relayd`, Go) — Light-Relay oder Full-Relay:**
   Das Postamt: Mailboxen, LN-Keysend-Porto, SQLite-Ledger mit eigenem
   Tageskurs-Stempel und Steuer-CSV-Export (§25) sowie eingebauter OIDC-IdP (§21).
   Das Relay braucht **keinen BTCPay Server** zur Kontoverwaltung von Client-Usern
   (der eigene SQLite-Ledger verwaltet msat-Salden, Quotas und Steuer-Kette mit
   ~25 MB RAM bereits komplett).
2. **Clients (Android, Apple/iOS, Linux, Windows, Web-PWA):**
   Die Oberfläche für Menschen, gebaut auf der gemeinsamen Bibliothek `client/src/`.
3. **Service-Connector (Headless-Client / Plugin für Dienste):**
   - Für reines „Sign in with lightningmail" reicht jedem Dienst eine
     Standard-OIDC-Client-Library (0 Zeilen Spezial-Plugin).
   - Will ein Dienst darüber hinaus **bezahlte Registrierungsbriefe empfangen**
     und **E2EE-Systemmails (Bestätigungen, Rechnungen, Alerts) automatisch
     versenden**, lässt er den **Service-Connector** als kleinen Sidecar-Daemon
     laufen.
   - Der Connector ist schlicht ein Headless-Client (`client/src/` ohne UI) mit
     einem normalen Postfach auf einem Relay seiner Wahl: Er meldet eingehende
     Registrierungsbriefe per Webhook an das Backend des Dienstes und verschickt
     ausgehende Nachrichten per lokaler JSON-API (`POST /send`). Wenn ein
     Unternehmen extern bereits BTCPay oder ein ERP für Rechnungen nutzt, kann
     es dieses optional an den Connector anbinden — für das Relay selbst bleibt
     es komplett außen vor.

## 30. Mainnet-Ökonomie des Relays: BIP-21-Aufladung, Kanal-Pool & Byte-Porto-Staffel (Beschluss 19.11.2026)

Das Relay wird kostendeckend als Infrastruktur betrieben, nicht zur Gewinnmaximierung — Nutzer dürfen sich beim normalen Schreiben nie ausgenutzt fühlen, und Channel-Management bleibt für sie komplett unsichtbar.

**1. Gemeinsamer LND-Pool & BIP-21 Unified Topup (ohne BTCPay Server):**
- **Kein User-Channel, kein BTCPay:** Mit einzelnen 10-€-Einzahlungen lassen sich keine eigenen Kanäle betreiben, und BTCPay Server nimmt kein Channel-Balancing ab. Stattdessen hält das Relay **einen gemeinsamen LND-Kanalpool** (4–8 solide Kanäle, kostensparend in einer einzigen Transaktion per `lncli batchopenchannel` eröffnet).
- **Ein QR-Code für On-Chain & Lightning (BIP-21):** Da viele Nutzer On-Chain-BTC statt eigener Lightning-Kanäle besitzen, erzeugt `relayd` über die eingebaute `lnd`-Wallet (`newaddress` + `SubscribeTransactions`) einen kombinierten BIP-21-URI (`bitcoin:bc1q…?amount=…&lightning=lnbc…`). Börsen und Hardware-Wallets zahlen automatisch On-Chain (mit sinnvoll empfohlenem Mindestbetrag ab ~20.000 Sats wegen späterer UTXO-Konsolidierung), Lightning-Wallets zahlen denselben Code sofort in 1 Sekunde.
- **Organischer Liquiditätskreislauf:** On-Chain-Einzahlungen der Nutzer sammeln sich in der `lnd`-Wallet des Betreibers und finanzieren bei Bedarf den nächsten großen Kanal oder Submarine-Swap, während der laufende Mailverkehr in beide Richtungen die Kanäle weitgehend natürlich ausgleicht.

**2. Kostendeckung über gestaffeltes Byte-Porto (bis 1.000 MB):**
- Reine LND-Routinggebühren (~0,01 %) decken weder Server (~5–8 €/Monat) noch gelegentliches Rebalancing. Einzige Einnahmequelle des Relays sind daher größere Dateianhänge:
  - **Bis 1 MB frei:** Jede Textmail, klassische PDF-Rechnung und jedes komprimierte Foto kostet **0 Cent** ans Relay. (Bewusst 1 MB statt 25 MB Freigrenze, damit 500-MB-Dateien nicht kostenlos in 20 Einzelmails gesplittet werden können.)
  - **Über 1 MB bis 100 MB:** **0,3 Cent / MB** (z. B. 10 MB ≈ 2,7 Cent; 100 MB ≈ 30 Cent).
  - **Über 100 MB bis 1.000 MB:** **0,1 Cent / MB** (1.000 MB ≈ 1,20 €; dank 7-Tage-Sweep nach Erstdownload liegen die realen Grenzkosten unter 0,5 Cent/GB, sodass bereits wenige große Transfers pro Monat den gesamten Relay-Betrieb tragen).
- **Offene Umsetzung vor Mainnet:** Zweistufige Byte-Porto-Staffel in `postage.go` ergänzen sowie für Dateien bis 1.000 MB die Chunk-Größe (z. B. 4 MiB statt 1 MiB) bzw. das 255-Ref-Limit im Envelope erweitern.

**3. Satoshis-Beilage im Brief (§30.4, gebaut 19.11.2026):**
- Der Anhang-Button ist ein Split-Button `📎 Anhang | ▾`: Klick/Kurztipp öffnet sofort die Dateiauswahl, Longpress bzw. Caret-Klick wählt zwischen **📄 Datei anhängen** und **⚡ Satoshis beilegen**.
- `POST /v1/send?to=…&tip_sats=N` legt 0–**5.000** Sats Aufschlag auf das normale Porto und zahlt `postage + tip` in **ein und demselben Keysend** — kein neues Protokollfeld, keine neue Datenbankspalte.
- Harte Deckelung am Relay (400 bei >5.000): Mit Betragsdeckel bleibt die Beilage Porto-/Trinkgeld-Charakter (digitale Briefmarke bzw. „20-DM-Schein in Omas Geburtstagskarte“) und wird kein übertragener Zahlungsverkehr.
- Der Empfänger sieht ein vom **eigenen Relay bestätigtes** goldnes Badge `⚡ N Sats erhalten` (real gezahltes `received_msat` aus der mailbox-Tabelle, Liste + Briefkopf) — nicht die Textbehauptung des Absenders.
- Sinn: Rückporto für Antworten mitspendieren, Neulingen das Start-Porto schenken, kleines Trinkgeld — ohne eine einzige Wallet-Maske.

**4. Test- und Mainnet-Welt im selben Client (§30.5, gebaut 19.11.2026):**
- Die Regtest-Relais bleiben öffentlich als Spielwiese online, damit Leute den Ablauf ohne Risiko testen können.
- Der Client fragt `network` am `/health` des gewählten Relais ab und hebt Nicht-Mainnet-Postfächer deutlich ab: orangefarbene **TEST-WELT**-Balken unter der Kopfzeile, Header-Kennung `🧪 TEST (regtest) · Spielgeld`, und das „+10.000 Test-Sats“ nur, solange das Relay wirklich Regtest ist (fällt auf Mainnet unsichtbar weg). Mainnet-Relais zeigen `⚡ Mainnet` und keinen Test-Banner.

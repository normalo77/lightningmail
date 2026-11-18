# bmail — Concept v0.1

> Eine E-Mail, die sich selbst bezahlt: Jede Nachricht ist gleichzeitig eine
> Lightning-Zahlung an den Empfänger. Spam wird teuer, Postfächer werden
> einfach, der Nutzer sieht nur ein Guthaben.

Stand: 11.11.2026 · Autor: Bernd + Hermes · Status: Entwurf zur Diskussion

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
  Self-hostable auf NAS/Umbrel/Start9 als 1-Click-App; kommerzielle/nonprofit
  Hosted-Relays für Normalnutzer.
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
3. **Identität:** öffentlicher Key der Person im Profil; TOFU + Fingerprint-
   Wechsel-Alert (Safety-Number-Muster).
4. **Preisprofil:** Fremdporto, Konversationsfenster, Whitelist-Policy.

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
- **Eingehend:** Empfänger-Preis steht im Profil (`default: 10 sats Fremde, 0 für Kontakte`).
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
- **M2 — Multi-Relay:** 2 Relays (Heim-NAS + VPS), Onion-Routing zwischen ihnen,
  Bootstrap-Skript für Relay-Betreiber (1-Click, wie Umbrel-App).
- **M3 — Regeln:** Preis-Profile, Konversationsfenster, Whitelist, Report/Block.
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

## 16. Client-Sync über mehrere Geräte (Planungsthema, M2.5)

Realfall (Bernd): 1 Konto, 3+ Clients (Privatrechner, Büro, Handy). Sync muss
**kostenlos und ohne Lightning** laufen — es ist der eigene Account, keine
Fremd-Mail.

Optionen:
- **A) Relay-zentriert, "blind IMAP" (Empfehlung Hermes):** Client-Status
  (Ordner, Klassifizierung, Labels, Entwürfe) als **verschlüsseltes
  State-Dokument** im bestehenden Blob-Store des eigenen Relays; Clients
  tauschen es per CAS (compare-and-swap auf Version/Hash), Konflikt =
  letzterwinscht mit Merge-Log. Kein Porto, keine neue Infrastruktur,
  funktioniert durch jede Firewall (der Relay ist ohnehin erreichbar).
  Aufwand klein: 1 Endpunkt + versioniertes JSON, AEAD wie Mails.
- **B) Syncthing-artig P2P:** verschlüsselte State-CRDT direkt zwischen
  Clients. Datenschutz-schön, aber CGNAT/NAT-Partner-Suche, Geräte-
  Pairing-UX, Verfügbarkeit ohne Server — für "Oma" der bessere Weg zum
  Abbruch. Als Power-User-Option später denkbar.
- C) beides: A als Grundschicht (immer da), B als optionaler Accelerator.

Entschieden (Bernd, 12.11.): **C** — verschlüsseltes State-Doc über den
eigenen Relay als Grundschicht (M2.5-Bau), P2P(Syncthing-artiger)
Accelerator als optionale Power-User-Erweiterung. v0.1-Client bleibt derweil
rein lokal mit exportierbarer Backup-Datei.

P2P-Wahl **Syncthing** (MPL-2.0, aktiv; Android via gepflegtem Syncthing-Fork,
~Aug 2026 — Upstream-Wrapper tot; Resilio/BTSync abgelehnt: closed/dead).
Integrationsmuster: kein In-Place-Edit — jeder Client schreibt immutable
`state-<device>-<version>.json` in den Sync-Ordner, Merge/Conflict-Resolution
leistet der CAS-Layer der App.

**Architektur-Rollenteilung (Bernd, 12.11.):**
- Server/Relay = **Zeitlimit-Frachtbahnhof (POP3-Semantik)**: Anhänge
  überleben bis **Erstdownload des Empfängers + 7 Tage Nachladesperre**
  (Bernd, 12.11.), absolute Obergrenze 30–90 d konfigurierbar für
  Niemals-Geladenes. Dedup-Regel: Content-Addressierung heißt Löschung erst,
  wenn ALLE blob_refs auf dieselbe sha downloadet/abgelaufen sind — sonst
  frisst Nutzer A dem Nutzer B die Anlage weg.
- Clients = **Dauerarchiv**: Syncthingclient↔client trägt Staat, herunter-
  geladene Blobs UND lokale Archive; einmal heruntergeladene Anhänge brauchen
  den Server nicht erneut. Solo-Gerät: Server-Fallback innerhalb Frist (P2P =
  Accelerator, nie Voraussetzung).
- Verfallene Anhänge beim Weiterleiten: Client hat Original lokal (sha bekannt)
  → re-Upload, Adressierung bleibt intakt.
- UI-Regeln: "läuft ab in X Tagen" + Download-Status pro Mail, sichtbar.
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

## 21. Etappe 6 — Identity: Directory, OIDC-IdP, WebAuthn

Ziel: `name@relaydomain` wird zum Account-Anker, den Dienste nutzen können.

- **Relay-Domain:** jede normale Registrar-Domain (.de ~1–3 €/Monat;
  Konzept-Beispiele §4.1: `bernd@bmail.de`, `gisela@familie.koeln`).
  Ein `_bmail._tcp`-TXT-Record (Ebene 1, §4.2) zeigt auf den Relay;
  Zoneninhaber = Postamt-Inhaber. Optisch von E-Mail ununterscheidbar —
  so gewollt (§4.1 „exakt E-Mail-Notation, nichts Neues zu lernen").
  Gratis-Bonus: jede Adresse ist via LUD-16-Well-known zugleich eine echte
  Lightning-Address, bestehende Wallets können sie besenden.
- **Public Directory:** Relay-Well-known + DNS liefern den Mailbox-Pubkey;
  BIP-353-kompatibler Marker (`name'pay@domain`) als zweite Entdeckungsebene.
- **OIDC-IdP (Go, neben dem Relay):** „Sign in with bmail" für Dienste.
  Login-Faktor = WebAuthn/Passkey (YubiKey; mehrere Authenticators pro
  Identität sind Normalfall: primär + backup). Föderations-Beweis =
  BIP340-Signatur des Mailbox-Keys (LMKEY1-Keystore) — NICHT der FIDO-Key
  selbst (P-256 ≠ secp256k1, die Welten bleiben getrennt).
- **Challenge/Response:** Dienst schickt Challenge an die Adresse, Nutzer
  signiert, Dienst verifiziert via Directory — LNURL-auth-Muster mit
  OIDC als Industrie-Wrapper.
- **Ohne MX** bounct Legacy-SMTP an bmail-Adressen; Dienste mit reiner
  Syntaxprüfung akzeptieren sie, Dienste mit MX-Check lehnen ab.
  Billige Zwischenlösung (Entscheidung offen): MX-Dead-Drop, der nur einen
  erklärenden Auto-Bounce liefert („diese Adresse spricht bmail") —
  keine Brücke, kein Klartext-Zugriff.
- **Offen:** Betreiber/Vertrauensrolle des IdP (pro Relay? zentral?);
  YubiKey-Ebene B (OpenPGP-Applet, secp256k1, signiert ECDSA statt
  BIP340) nur anfassen, falls echter Bedarf; Bernds YubiKey-Modelle
  klären (FIDO2 + secp256k1 brauchen 5er-Serie).

## 22. Etappe 7 — Chunked Blobs & Byte-Porto (riesige Anhänge)

- Blobs >1 MB: Chunking client-seitig (1-MB-Scheiben, Content-Hashes pro
  Chunk + Manifest-Hash); Envelope trägt das Manifest über die bestehende
  `blob_refs`-Struktur (erweitert um size/chunks).
- **Byte-Porto:** Storage-Preis pro Byte (ggf. pro Zeit) beim Upload —
  Storage-Missbrauch und Spam laufen über dieselbe Ökonomie.
- Delivery unverändert: HTTP-Fetch + Relay-Mirror (Spec 6.4);
  Cleanup hängt am bestehenden `blob_refs.downloaded_at`-Pfad
  (`relayd -cleanup-once`).

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


## 25. Steuer-Log: local currency für jede Bewegung (15.11.2026, Beschluss — Bau mit Etappe B/G)

Sobald User oder Betreiber relevante Summen verdienen (Karten-Erlöse, Fees,
Porto-Rückerstattungen), braucht der Steuerpflichtige einen belastbaren Nachweis
in lokaler Währung. Der Relay schreibt mit, aber er buchführt nicht.

- **Rate beim Zufluss:** jede neue Ledger-Zeile erhält `eur_cent + rate_ts +
  rate_src` — entschieden: **Tageskurs** (BSi/Binance EUR-Paar, ein Abruf pro
  Tag, manuelles Nachsetzen als Fallback). Nachträgliches Raten alter Zeilen
  ist unredlich; Regtest-Müll bleibt ungeratet und wird als Testdaten markiert.
- **Zwei Sichten:** Konto-Statement für den User (Einnahmen: Karten, Erstattungen;
  Ausgaben: Porto) und Betreiber-Statement (Porto-Einnahmen, Karten-Fees,
  Auszahlungen). On-chain-/Routing-Gebühren kennt der Relay nicht — Hinweis im
  Export, dass LND-Reports die Ergänzung sind.
- **Export:** `GET /v1/statement?from&to&fmt=csv` (auth, eigenes Konto) +
  Admin-Pendant für den Betreiber. Zeilen hash-verkettet (Monatsanfang = Anker),
  damit der Stapel bei der Prüfung nicht umfallen kann.
- **Bewusste Grenzen:** keine Doppelbuchhaltung, keine USt-Logik, kein
  Elster-Export — Fakten liefern, der Mensch bucht. Format entschieden: **reines
  CSV** (DATEV-Chiffren nicht nötig, Bernd 15.11.).
- **UI (G3):** Menüpunkt „Umsätze" in PWA/Clients — übersichtliche Liste
  Einnahmen/Ausgaben pro Monat (EUR-Spalte aus dem Statement, plus CSV-Knopf).
  Kein neues Subsystem: es liest nur `GET /v1/statement`.
- **Reihenfolge:** G1 Rate-Stempeln (fällt mit Etappe B zusammen, da entstehen
  die ersten Erlöse), G2 Statement-Endpunkte + Kette + UI-Knopf „Export".

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

## 27. Onboarding: Client-Wizard und Relay-Installer (Beschluss 15.11.2026)

Getrennte Welten — der Client besitzt per Design keinen Node und keine
Channels (Porto = Guthaben beim Relay, Schlüssel = ein secp256k1-Paar).

**Etappe 6d — Client-Setup-Wizard (BAUEN, direkt nach Etappe B, vor externer
Beta):**
- 24-Wort-Recovery (BIP39): Seed im Browser erzeugt, Wortquiz zur
  Bestaetigung, .lmkey-Passphrase-Datei optional statt Pflicht.
- Währungsfrage: "Womit zahlst du Porto?" — Auswahl aus den vom Relay
  besiedelten Währungen (§26).
- Bestehendes bleibt: Adressgenerierung (6c), LMKEY1-Passwort.
- Kein Scan, kein Channel, kein Node — das ist das Werbeversprechen.

**Etappe O — Relay-Installer (NUR VORBEMERKT, Bau wenn Fremd-Betreiber
ernst macht):**
- One-Click via Docker-Compose: Domain, ACME-TLS, relayd, lnd, Chain-Backend.
- Wizard-Frage Backend: Neutrino (~25-30 GB, QNAP-tauglich) | eigener
  bitcoind (Vollknoten ~700 GB; PRUNED GEHT NICHT — lnd braucht Backfill) |
  fremder Node.
- Kanal-Autopilot: lnd-autopilot ist blind (beliebige Gegenstellen);
  sinnvoll fuer bmail nur gezielt: Wizard-Frage "mit wem abrechnen?" +
  Ein-Klick-Kanaele zu Relay-Partnern, Liquiditaet via Loop-out (Boltz).
- Groessenordnung: Client-Wizard 1-2 AT, Relay-Wizard ~1 Woche + Pflege.

## 28. Anmeldungs-Porto: "Mit bmail registrieren" (Etappe I, Beschluss 15.11.2026)

Ein Dienst soll fuer eine Bestaetigungsmail nicht zahlen — die Richtung
umzudrehen (Empfaenger zahlt whitelistet, Vorschlag 1) ist ABGELEHNT: sie
bricht die Konstante "der Sender zahlt" und liesse das Opfer fuer seinen
eigenen Spam zahlen.

angenommen (Vorschlag 2, verfeinert):
- Der USER zahlt einmalig die Willkommensgebuehr — das ist schlicht sein
  Erstkontakt-Porto an den Dienst, dessen Preisprofil den Fremdp Reis um den
  Willkommensfaktor (3-10) erhoeht. Gebuehr = Einnahme des Dienstes.
- Die Bestaetigungsmail antwortet PORTOFREI im bestehenden
  Konversationsfenster (§4.1). Der Dienst zahlt nie, er verdiente pro
  Registrierung — der Adoptionssatz: bmail ist fuer Dienste keine
  SMTP-Kostenzeile, sondern ein Mikro-Umsatzkanal.
- Neu gebaut: Envelope-Tag 0x0A signup=1 (LM1), PWA-Cap "Mit bmail
  registrieren" + Linkformat bmail://anmelden?an=dienst@domain&g=3;
  Verrechnungskonto/Treuhand gibt es nicht — nimmt ein Dienst die Gebuehr
  und antwortet nicht, hilft Spammarkierung + Reputation.
- Einordnung: Etappe I, nach B, vor externer Beta (passt zur
  Freunde-Runde mit echten Diensten).
- Invoice-Abwicklung der Willkommensgebuehr: §29 (BTCPay, Beschluss 18.11.).

## 29. Service-Registrierung in der Praxis: Parallelbetrieb + Invoice-Schicht (Beschluss 18.11.2026)

Bernds Anforderung: lightningmail soll an etablierte Registrierungs-Prozesse
moeglichst nahtlos anbinden und PARALLEL zur E-Mail-Welt nutzbar sein —
keine Entweder-oder-Entscheidung fuer Dienste oder Nutzer.

**Wie Registrierung bei Diensten heute hinter den Kulissen laeuft** (vier Muster):
1. **E-Mail + Passwort:** Dienst speichert Passwort-Hash, schickt Bestaetigungsmail
   mit Token-Link (SMTP-Roundtrip). Die Adresse ist Identitaetsanker UND
   Recovery-Kanal (Passwort-Reset, Benachrichtigungen).
2. **OAuth2/OIDC-Foederation:** „Sign in with Google/Apple/GitHub" — Redirect,
   Authorization-Code, ID-Token (JWT mit email/sub-Claim). Der IdP verbuergt die
   verifizierte Adresse; der Dienst speichert kein Passwort.
3. **Magic-Link/Passwordless:** Ein Token-Link per Mail ist Verifikation und
   Login in einem (Slack/Notion-Muster).
4. **Passkeys/WebAuthn:** Adresse = Username, Passkey = Credential; kein
   Mail-Roundtrip mehr zur Anmeldung, aber weiterhin fuer Recovery.
Allen gemeinsam: die Adresse muss (a) Erreichbarkeitschecks bestehen
(Syntax → MX → Zustellbarkeit) und (b) als Rueckkanaal funktionieren.

**Anbindung von lightningmail an alle vier Muster — ohne Umbau beim Dienst:**
- **Syntax:** Adresse ist exakte E-Mail-Notation (§4.1) — Dienste mit reiner
  Syntaxpruefung akzeptieren sie sofort, heute schon.
- **SMTP:** MX fuer lightningmail.app existiert (Cloudflare). Ohne Bridge
  wuerden Bestaetigungsmails an Nutzeradressen bouncen → Zwischenstufe
  **MX-Dead-Drop** (§21, hiermit beschlossen): Auto-Bounce mit Erklaerung
  „diese Adresse spricht lightningmail" statt stillem Bounce, plus Hinweis
  auf den nativen Weg. Voller Parallelbetrieb kommt mit der Bridge (§14, v2):
  SMTP rein/raus in dieselbe Mailbox, beide Kanaele in einer UI.
- **OIDC:** „Sign in with lightningmail" (§21) ist der nahtlose Weg fuer
  Neuanbindungen — Standard-OIDC-Bibliothek beim Dienst, kein
  Lightning-Wissen noetig; Foederations-Beweis = BIP340-Signatur des
  Mailbox-Keys, Challenge/Response ueber das Directory (§4.2 Ebene 3).
- **Zahlung:** LUD-16/BIP-353 (§4.1/§12) — jede Adresse ist direkt ein
  Lightning-Zahlungsziel, Wallets koennen sie ohne Registrierung besenden.

**Parallelbetriebs-Prinzip:** eine Adresse, mehrere Kanaele. Ein Dienst, der
nur SMTP spricht, einer, der nur OIDC spricht, und einer, der nativ lightningmail
nutzt (§28), erreichen dieselbe Mailbox. Nativer Weg ist Zusatz, nie Ersatz;
kein Kanal darf einen anderen blockieren.

**Invoice-Schicht fuer Anmeldegebuehren: BTCPay Server (Bernd-Vorschlag 18.11.)**
- Warum nicht direkt LND/§13: Ein Dienst will fuer die Willkommensgebuehr eine
  echte Rechnung — Fiat-Denominierung (Gebuehr deckt seine Bestätigungsmail-
  Kosten, Preis in EUR → Invoice in Sats zum Kurs), Buchhaltung fuer das
  Steuer-Log (§25), Refunds, Zahlungs-Erinnerungen. BTCPay liefert das
  komplett; Selbstbau waere ein zweites Buchhaltungssystem.
- **Multi-Store-Modell:** eine BTCPay-Instanz, EIN STORE PRO DIENST (je eigener
  On-Chain-Wallet + eigener Lightning-Anbindung moeglich). Relay-Betreiber
  koennen gehostete Stores anbieten — analog zum Relay-Hosting (§21 offene
  Betreiberrolle wird damit teilweise beantwortet: Invoice-Hosting ≠ IdP-Hosting).
- **Flow:** Registrierungs-Brief (§28, Tag 0x0A) → Dienst legt per Greenfield-API
  eine Invoice an (Betrag, Ablauf = Konversationsfenster) → Antwort-Brief traegt
  Bolt11/Payment-Link → BTCPay-Webhook `InvoiceSettled` → Dienst schickt
  portofreie Bestaetigung (✓✓, §23) im Konversationsfenster → Registrierung gilt.
  Invoice abgelaufen → Erinnerungs-Brief (Dead-Man, §5).
- **Abgrenzung zu §13:** User↔User-Porto bleibt LNURL/keysend direkt
  (Mikro-Cents, kein Custodian, keine Buchhaltung). BTCPay kommt nur auf die
  Dienste-Seite, wo Rechnungen noetig sind —spaeter ggf. auch Byte-Porto-
  Rechnungen (§22) fuer Firmenkunden.
- **Homelab/PoC (offen, nicht gebaut):** BTCPay an lnd-main (LND-REST, CT113) +
  NBXplorer → bitcoind (.75, nach IBD); PoC zuerst auf dem Regtest-Stack CT113.
  Bedarf ~1–2 GB RAM → eigener kleiner CT. Reihenfolge: erst Etappe B (Directory),
  dann IdP/§28, Invoice-Schicht mit Etappe I.

### 29.1 Drei-Programm-Modell (Bernd, 18.11.2026)

Das Oekosystem besteht aus drei Programmen:
1. **Relay** (relayd, Go) — das Postamt: Mailboxen, Porto/LN, Directory,
   spaeter OIDC-IdP (§21). Geteilte Infrastruktur des Relay-Betreibers.
2. **Client** (PWA/APK) — die Oberflaeche fuer Menschen. Die E2E-/Geld-Logik
   liegt bereits als Bibliothek in `client/src/` (crypto, send, state,
   keywrap), unabhaengig vom DOM-Leim `main.ts`.
3. **Service-Registrierungs-Plugin** — ein HEADLESS CLIENT: wie ein Client,
   nur ohne UI und ohne Menschen davor. Der Dienst braucht KEIN eigenes
   Relay — nur ein Postfach auf einem Relay seiner Wahl (wie man heute
   einen Mail-Provider waehlt) und seinen eigenen Schluessel.

Das Plugin = Wiederverwendung der Client-Bibliothek + drei Adapter:
- **Registrierungs-State-Machine:** Brief mit Tag 0x0A empfangen →
  Invoice via BTCPay-Greenfield-API anlegen → Webhook `InvoiceSettled`
  abwarten → portofreie Bestaetigung (✓✓) im Konversationsfenster.
- **Service-Backend-Anbindung:** Webhook/REST rein und raus — jeder Stack
  (PHP, Node, Django, …) kann sich einklinken, ohne Lightning zu verstehen.
- **Key-Haltung:** LMKEY1-Datei/Env beim Dienst; E2E bleibt unveraehrt —
  der Relay sieht nie Klartext, das Plugin ist kein Vertrauensanker.

Form: TS-Bibliothek + duenner Referenz-Daemon (webhook-faehig, ein Postfach,
ein Prozess); Go-Variante spaeter nur bei Bedarf. Derselbe Headless-Kern
traegt spaeter auch die MCP-Agenten-Post (§15) und den Bridge-Daemon (§14) —
das „dritte Programm" ist also generell ein Client-Kern mit Adaptern, die
Registrierung ist nur der erste Anwendungsfall.

Voraussetzungen im Relay (noch offen; Reihenfolge wie §29: erst B, dann I):
Envelope-Tag 0x0A, Konversationsfenster mit Portofreiheit im Relay (Status:
Baustelle), Directory-Aufloesung (§21), Webhook-Zustaellgarantien.

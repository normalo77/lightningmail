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
- **Porto skaliert mit Größe:** Preis = Basis + sats/MB (Empfänger-Preisprofil,
  §6/§4.1) — schwere Mails kosten mehr; adressiert sowohl Spam-Bulk als auch
  das 12-MB-Foto-Problem ohne technische Limitschlacht.
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
  **clientseitig**: Ordner Inbox/Entwürfe/Gesendet/Spam, Suche als lokaler
  Index, Status-Flags im Client (verschlüsselt zu den Mailbox-Metadaten).
  Whitelist = 0 Porto + Antwort-frei; unbekannt = vollen Porto-Preis;
  Spam-Ordner = Endablage ohne weitere Aktion (Abschreckung wirkt über den
  bereits gezahlten Preis des Senders, nicht durch Erkennung).
- **Fremd-Mail kostet:** Unbekannter Absender zahlt Empfängersetzen.
  10 Mio Spammails × 10 sats ≈ 3000 € — vorbei.
- **Antwort frei:** Konversationsfenster (z. B. 30 Tage) nach erstem bezahltem
  Kontakt → normale Unterhaltung kostet nichts mehr. (Spam-Bait „erst zahlt der
  Spammer 10, dann 1000 Gratis-Antworten" begrenzt: Fenster = N Antworten, dann neu.)
- **Kontakte/Whitelist:** gratis, vom Nutzer bestätigt.
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
- **LNemail** (lebt, 09/2026): Wegwerf-Mailbox gegen LN-Porto; LND/NWC-Backend,
  SMTP/IMAP — Architekturschablone für Relay-M1. Porto geht an Plattform.
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

## 16. Ein-Satz-Pitch

„Deine Mails sind jetzt bares Geld wert — und die der anderen auch."

# bmail — Tester-Runde (3 Freunde)

Voraussetzung: Relay öffentlich erreichbar (Domain + Ports, siehe TODO unten).
Bis dahin nur im LAN: https://bmail.192-168-177-77.sslip.io:5173 (Self-signed-Warnung bestätigen).

## Ablauf pro Tester (2 Minuten, kein Server-Zugriff nötig)
1. Handytaster/Chrome öffnen, URL laden, Seite zum Startbildschirm hinzufügen (PWA).
2. Konto-Namen eintippen (klein, 2–32 Zeichen) → **＋ Neues Konto**.
3. Passphrase wählen (min. 8 Zeichen) → die heruntergeladene Datei
   `lightningmail-<name>.lmkey` sicher ablegen (Passwort-Manager). Sie ist der Notausgang.
4. Direkt danach **🔑 Passkey / Handy** → Passkey anlegen (Google Password Manager / Bildschirmsperre).
   Ab jetzt Login ohne Datei.
5. Gegenstücke eintragen: Adresse ist `name@relay` — Senden an den bloßem Vornamen genügt,
   solange alle auf demselben Relay sind.
6. Porto: Kontakte senden sich kostenlos (contact_sats=0). Für Mails an Fremd-Relays braucht das
   Konto Guthaben — Betreiber zahlt ein:
   `UPDATE account SET balance_msat=balance_msat+10000000 WHERE name='NAME'` in
   /var/lib/bmail/alpha/ledger.db (10.000 sats Regtest-Spielgeld; bewährtes Rezept aus receipts.mts).
7. **Öffentliche Karte (Etappe B):** Adressbuch → 🌐 Meine Karte → Felder anhaken (nur die
   erscheinen öffentlich), Preis in ct, DSGVO-Häkchen → Veröffentlichen. Andere finden dich über
   die Suchzeile (🌐 Directory-Zeile, exakter Treffer): Schlüssel gratis, Karte kostet
   (2,5 ct Betreiber + dein Preis) — einmal pro Karteninhalt, Update = neue Karte.
   Löschen entfernt Karte + Einwilligung serverseitig komplett.

## Was Tester sehen werden / Soll so
- ✓ = Porto settled, ✓✓ = Empfänger hat abgerufen. Kein Gelesen-Häkchen.
- „Guthaben zu niedrig“ (402) = kein Porto → Betreiber-Credit (Punkt 6).
- Passkey-Login in Firefox/Safari zeigt Notfall-Passphrase-Feld — Absicht (PRF-Lücke, §21).
- Kartenkauf ohne Guthaben → 402 mit Preisangebot — kein Fehler, nur leere Tasche.
- 429 nach vielen Directory-Suchen — Enumerierungsschutz, Minute warten.

## TODO vor externem Test (blockiert)
- [ ] Domain + echtes TLS (Let's Encrypt) → rp_id/origins in relay-alpha.yaml anpassen, vite-preview-TLS ersetzen
- [ ] Ports am Router Leverkusen (und ggf. QNAP-Frechen als beta)
- [ ] öffentlich erreichbare beta-URL im Relay-Select der UI (client/app/index.html l-relay)
- [ ] demo/keys aus dist nehmen (public/keys/*.key) — sonst liegen echte Private Keys offen

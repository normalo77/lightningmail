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
8. **Riesige Anhänge (Etappe 7):** Dateien über 1 MiB werden automatisch in Scheiben
   verschickt (📦 im Anhang-Namen) — Grenze ist jetzt die Konto-Quota (100 MB), nicht mehr
   10 MB pro Datei. Kostet Byte-Porto: 1 ct pro MiB (Schätzung erscheint beim Dateiauswahl);
   Guthaben zu niedrig → 402, es wird nichts hochgeladen.

## Was Tester sehen werden / Soll so
- ✓ = Porto settled, ✓✓ = Empfänger hat abgerufen. Kein Gelesen-Häkchen.
- „Guthaben zu niedrig“ (402) = kein Porto → Betreiber-Credit (Punkt 6).
- Passkey-Login in Firefox/Safari zeigt Notfall-Passphrase-Feld — Absicht (PRF-Lücke, §21).
- Kartenkauf ohne Guthaben → 402 mit Preisangebot — kein Fehler, nur leere Tasche.
- 429 nach vielen Directory-Suchen — Enumerierungsschutz, Minute warten.

## Relay-Administration (Web-Panel, Etappe A)
Betreiber sehen Konten, Speichernutzung, Traffic und können Konten kaskadiert löschen —
auf einem **zweiten Listener, der nur im lokalen Netz gebunden wird** (Der öffentliche
Tunnel zeigt nie darauf). Aktivierung in `relay.yaml`:

    admin:
      listen: "<lan-host>:8480"   # LAN-Adresse:Port des Relay-Hosts
      node_pubkey: ""                  # leer = eigener lnd-Node; sonst 66-Hex pinnen

Zugang ohne Passwörter: Panel öffnet „Challenge holen“, auf dem Relay-Host läuft
`lncli signmessage <nonce>`, die Signatur kommt zurück ins Panel. Der Relay verifiziert
sie an seinem LND-Node — wer den Node-Key nicht hat, kommt nicht rein. Sitzungen leben
im Speicher (Relay-Neustart = abmelden), Fehlversuche sperren 15 Minuten.
Löschen entfernt Konto, Briefe, Sync-State, Passkey-Hüllen, Token und Datendateien,
die sonst niemand mehr besitzt.

## Erledigte Vorbedingungen
- Domain + TLS via Cloudflare-Tunnel live (15.11.), `rp_id/origins` in relay-alpha.yaml gesetzt
- Demo-/Private-Keys: `/keys` öffentlich 404 (site/serve.py), APK/XPI bauen ohne keys/

## Historische Notizen (externer Test, alt)
- [ ] Domain + echtes TLS (Let's Encrypt) → rp_id/origins in relay-alpha.yaml anpassen, vite-preview-TLS ersetzen
- [ ] Ports am Router Leverkusen (und ggf. QNAP-Frechen als beta)
- [ ] öffentlich erreichbare beta-URL im Relay-Select der UI (client/app/index.html l-relay)
- [ ] demo/keys aus dist nehmen (public/keys/*.key) — sonst liegen echte Private Keys offen

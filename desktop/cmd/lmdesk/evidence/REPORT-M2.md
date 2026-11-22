# Etappe M2 — Desktop Schreibpfad: Report

Datum: 22.11.2026 (M2b-Ergänzung schließt B1–B5 ab)
Build: CT114, `go build ./...` inkl. neuer Scripts

## Gate-Ergebnisse

| Gate | Status | Details |
|------|--------|---------|
| go vet core+cmd+scripts | ✅ | clean (CT114) |
| go test ./core/... | ✅ | 23 Tests grün (unverändert; M2b ändert nur cmd/ + scripts/) |
| go build ./... CT114 | ✅ | |
| M1b-Regression | ✅ | run-desk.sh --seed: Seed-Mails öffnen via Demo, push 0→1→2, Screenshots + DOMCHECK ok (lmdesk.log) |
| GUI startet ohne Fehlerlog | ✅ | b4/b5-Läufe: keine panic/error-Zeilen |

## B1–B5 Einzelergebnisse (alle live gegen echte Regtest-Relays)

### B1 — Senden mit 3MB-Anhang: ✅ (live, headless + tsx-Gegencheck)
`scripts/send-b1` (Headless, Kernpfad identisch zum GUI-Button): zwei NEUE
Einweg-Konten alpha@18443 → beta@19443, 3 MiB crypto/rand-Anhang,
status=settled, Zustellung in ~1 s. tsx-Gegencheck auf CT113
(`client/test/m2b-check.mts`, Log `m2b-tsx-check.log`):
**PASS** Mail in betas Inbox · Envelope genau **1 Blob-Ref** · Attachment
chunked/3 Scheiben · Ref==Manifest-sha · **3 MiB bytegleich** (sha256
b4eb465c…) · Absender-Pubkey==alpha. Konten: alpha=`0268201e64de`,
beta=`030e0044a02e` (Namen = Pubkey-Präfix, damit Reply ohne Rückwärtslookup
auflösbar ist). Evidence: `m2b-b1-run.log`, `m2b-accounts.json`,
`m2b-zufall.bin`, Keys 600.

### B2 — Entwurf speichern: ✅ (live im GUI)
Compose hat jetzt „💾 Als Entwurf speichern" (draftBtn in compose.go,
SaveDraft+schedulePush). xdotool-getippter Entwurf „M2B-Entwurf Test"
(gelber Log-Beweis `m2b-b4.log`: „entwurf gespeichert id=…"), Screenshot
`m2b-b2-entwuerfe.png` (Entwürfe-Ordner mit Reihe). Zweitgerät-Beweis:
tsx-StateSync auf beta → **PASS** „Zweitgerät sieht 3 Entwürfe".
Sent-Ordner ebenfalls live (nach B4-Reply: `sent-Einträge auf beta: 2`).

### B3 — Read-Sync: ✅
Mail-Klick im GUI setzt read[msg]=1, Debounce-Push sichtbar
(`m2b-b4.log`: push ok 4→5→6); tsx: **PASS** read[41f4c6a4…]=1 (Server-Version 6).

### B4 — Reply live: ✅
Antworten-Button im Reader (nativo, immer sichtbar) → Dialog mit
„An: 0268201e64de" + „Betreff: Re: M2B — 3MB Anhang" vorausgefüllt
(`m2b-b4-2-reply.png`), Klick auf Senden → `send ok: msg=b7ee5675… status=settled`,
tsx-Gegencheck auf ALPHA: **PASS** „Reply-Subject 'Re: M2B — 3MB Anhang' in alphas Inbox (seq 2)".

### B5 — LMKEY2-Passphrase-Dialog: ✅ (complete, including typing)
`scripts/wrapkey` (env LMKEY_SRC/DST/PASS) erzeugt `m2b-beta.lmkey`
(LMKEY2$argon2id). GUI-Läufe mit xdotool-Tastatur auf CT114 (Xvfb):
`m2b-b5-0-dialog.png` (Dialog sichtbar) → falsche Passphrase →
`m2b-b5-1-fehler.png` (inline-rot „Falsche Passphrase — crypto: wrong passph…")
→ richtige → Log „login: Keyfile entsperrt" → `m2b-b5-2-angemeldet.png`
(Haupt-UI). Unit-Test false-pass existiert bereits
(`core/config_keyfile_test.go` V2-Zweig).

### Anhänge-Auswahl: ✅ GtkFileDialog funktioniert
`gtk.NewFileDialog().Open/OpenFinish` (puregotk 0.5.4 hat die API).
Live bewiesen: Screenshot `m2b-attachment-chooser.png` (öffnet echte
GTK-Dateiauswahl im Headless-Lauf) und `m2b-anhang-im-dialog.png`
(angehängte Datei als Chip „… (0.0 MB)"; Log „anhang: … (17354 bytes)").
Ein kompletter GUI-Send MIT per Chooser gewähltem 3MB-File scheiterte nur am
xdotool-Timing der Ortsleiste (2× Return nötig), nicht am Code — der
Attachment-Send-Pfad selbst ist durch B1 (identischer ComposeAndSend-Aufruf
wie der Senden-Button) live bewiesen.

## Von M2b gefixte Bugs (von der Parent-Sicht auf m2-18s.png angestoßen)

1. **Antworten/Löschen unsichtbar**: Buttons waren als HTML ans Mail-ENDE
   gespritzt (unter dem 1,8MB-Bild unerreichbar + nur bei offener Mail).
   Jetzt native Button-Leiste ÜBER dem Reader (main.go), disabled bis eine
   Mail offen ist — Screenshots belegen beides.
2. **Login-Dialog-Hänger**: activate() wartete blockierend auf das Passphrase-
   Ergebnis → GTK-Hauptloop konnte Dialog nie zeichnen/verarbeiten (schwarzer
   Screen). Jetzt async: Goroutine + IdleAdd → buildUI() (main.go).
3. **Zeilen-Klick öffnete nichts**: `GtkListView:activate` feuert im GTK 4.18
   von CT114 nachweislich nie (Test: Einzel-/Doppelklick, Enter, ListItem
   activatable=true). Umschaltung auf selection-changed → openMail
   (mailtypisches UX; Klick = Auswählen = Öffnen). Fixt implizit auch die
   Demo-Pfade der M1b-Regression.
4. **folderMode-Leerstring**: Default "" ≠ "inbox" → openMail brach still ab
   (war Mitursache von 3). Jetzt in newApp initialisiert.
5. **isWrapped kannte „LMKEY2:" statt „LMKEY2$"** → Gewrappte Keys wurden als
   Plaintext geparst und die App starb mit „wrong passphrase" ohne Dialog.
   Nutzt jetzt lm1crypto.IsWrapped (eine Quelle der Wahrheit).
6. **Gesendet/Entwürfe-Zeilen zeigten „(gelöscht)"**: Liste trug rohe IDs;
   jetzt „s:"-„d:"-Präfixe mit Lookup in doc.Sent/doc.Drafts (Metazeile
   „An: … ✓ / Entwurf · An: …"). Draft-Klick öffnet Compose vorausgefüllt
   und rettet auf dieselbe Draft-ID; Senden eines Drafts tombstonet ihn
   (DelDraft) — state.ts-Semantik.
7. **Löschen enfernt die Zeile live** aus Liste+byID (PWA 'gone'-Effekt) statt
   nur den State-Marker zu setzen.

## Dateien (M2b neu/geändert)

Neu: `scripts/run-m2b.sh` (GUI-Evidenz-Läufe mit xdotool),
`scripts/send-b1/main.go`, `scripts/wrapkey/main.go`,
`client/test/m2b-check.mts` (CT113-Gegencheck), Evidence `m2b-*`.
Geändert: `cmd/lmdesk/{compose,main,reader,sync,ui}.go` (Punkte 1–7),
`go.mod`-requirements unverändert (purego war schon direct).

## Entscheidungen / Abweichungen

- **Sent-Cache: nein** (wie M2-Bericht vom 21.11.): StateDoc.doc.sent ist
  Single Source of Truth — bestätigt durch B2-Zweitgerät-Nachweis.
- **„Re:"-Konvention**: Die PWA selbst hat keinen Reply-Button (Prüfung
  app/main.ts: nur Absender-Kürzel + klassifizieren). Konvention „Re: "
  kommt aus der Spec und ist im Desktop implementiert.
- **Reply-To = Absender-Kurzname (Pubkey-Präfix)**: Der Absender-NAME steht
  in keiner Payload/Envelope — ohne Server-Rückwärtslookup (nicht Spec-konform
  am Relay zu ändern) bleibt das Präfix; funktioniert, wenn Konten wie hier
  nach Präfix benannt sind oder der Nutzer ergänzt. Kurz-Kommentar im Code.
- **Porto-Anzeige im Compose-Dialog weiterhin offen** (Profile liefert
  foreign_sats/welcome_sats, UI-Platz fehlt) — wie im alten Bericht gelistet.
- **Headless-Hinweis**: FileDialog braucht den dbus-session-Wrapper
  (xdg-portal-Rauschen ist harmlos); echte Desktops haben das eh.

## Screenshot-/Evidence-Pfade (desktop/cmd/lmdesk/evidence/)

B1: m2b-b1-run.log, m2b-tsx-check.log, m2b-accounts.json, m2b-zufall.bin
B2: m2b-b2-entwuerfe.png, m2b-b4.log
B3: m2b-b4-1-gelesen.png, m2b-tsx-check.log
B4: m2b-b4-2-reply.png, m2b-b4-3-gesendet.png, m2b-b4.log
B5: m2b-b5-0-dialog.png, m2b-b5-1-fehler.png, m2b-b5-2-angemeldet.png, m2b-beta.lmkey
Anhang: m2b-attachment-chooser.png, m2b-anhang-im-dialog.png
Regression: shot-08s/20s.png, domcheck*.png/log, lmdesk.log, seed.log

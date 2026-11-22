# Etappe M1b — Desktop Lese-Pfad (Go-Kern + GUI, read-only)

Ziel: Der native Client (desktop/) loggt sich per Keydatei gegen ein Regtest-Relay ein,
synced Posteingang + StateDoc und liest Mails: Liste links/Reader rechts, HTML sauber
sanitisiert, cid-Bilder ueber lm-mail:-Schema aus dem RAM. Schreiben kommt in M2,
Adressbuch/Laufwerk/Umsaetze in M3. Reiner Lese-Pfad = maximal beweisbar, minimaler Scope.

Umgebungen (wie M0): Code in <workspace> (Hermes) — bauen/laufen auf dev-sandbox
(ssh -i <ssh-key> -o StrictHostKeyChecking=no <dev-sandbox-host>,
Repo <workspace>). Sync: rsync -a 'ssh -i ...' <workspace>/desktop/ root@...:<workspace>/desktop/
und <workspace>/lm1/ root@...:<workspace>/lm1/. dev-sandbox hat go1.24 + GTK4/adw/webkit6 Runtime.
Relay-Erreichbarkeit dev-sandbox->dev-relay: ALPHA/ALPHAhoeren auf 127.0.0.1! Auf dev-sandbox dauerhaft
tunneln: ssh -f -N -o ExitOnForwardFailure=yes -L 18443:127.0.0.1:8443 -L 19443:127.0.0.1:9443 <dev-relay-host>
(dafuer desktop/scripts/tunnel.sh anlegen; Tunnel vor jedem Run pruefen).
Repos auf dev-sandbox sind auf 0131c7a; M1a ist bereits auf dev-relay committet — nach dem ersten
rsync auch dort lm1/ vorhanden, also nichts pullen, alles rsyncen (Parent kaemmert sich um
git). Keine git/rsync Richtung dev-relay/NAS.

Referenz-Quellen VOR Coding lesen:
- lm1/envelope + lm1/crypto (APIs), relay/cmd/lmcli/main.go (auth-Signatur, inbox-Aufruf,
  SEC1-PEM-Key laden), client/src/state.ts (StateDoc-Felder, merge-Regeln, seal/offen —
  Byte-Kompat ist Pflicht!), client/src/crypto.ts (encryptPayload/decryptPayload AAD-Form),
  client/app/main.ts (renderBody: wie Inline-Bilder/Anhänge im HTML verortet werden —
  EXAKT dieselbe Konvention fuers Reader-HTML uebernehmen), desktop/spike/main.go
  (puregotk-Grundgeruest + Scheme-Handler-Idiome), docs/review-M1-desktop.md (Rotliste!).

## Module (desktop/ eigenes Go-Modul, importiert ../lm1 via replace — M1a hats vorbereitet)

### desktop/core/ — DOM-freier Kern, unit-testbar
- config.go: ~/.config/lightningmail/config.json {relay, name, keyfile, tor_socks:""}
  (tor_socks jetzt nur Feld + Doku-Kommentar Etappe T; leer = direkt).
- api.go: http.Client mit optionalem SOCKS5-Dialer (tor_socks), Basis-Methoden: auth
  (POST /v1/auth, Signatur wie lmcli), inbox GET mit after+limit, state GET, blob GET
  (Timeouts, keine 2xx -> Fehlerobjekt ohne panic). Basis-URL aus Config.
- mail.go: envelope decoden (lm1), payload decrypten (recipientHash+msgID AAD — wie
  lmcli/state.ts), {subject, body, headers, attachments[], received_at, seq} -> Mail-Strukt;
  Inbox DESC-Regel nur fürs Anzeigen umsortieren (neueste oben), Cursor = max(seq) lokal.
- statedoc.go: StateDoc JSON-Struktur byte-kompatibel zu state.ts (read/spam/deleted/
  drafts/sent/contacts/files), versiegelt = decryptPayload(mailbox-priv, blob, AAD?) —
  AAD-Konvention 1:1 aus state.ts/chunks.ts uebernehmen (DORT nachlesen, nicht raten!).
  Merge-Funktion mit wins()-Regel (ts, Gleichstand gone; Re-Stempeln max(now,prev)+1 nur
  bei eigenem Save, nicht beim puren Merge-Anzeigen — Save kommt M2, M1 liest nur).
- sanitize.go: bluemonday (go get github.com/microcosm-cc/bluemonday — dev-sandbox hat Netz,
  go.sum im Klon aktualisieren und Report), Policy: p,br,hr,i,b,u,em,strong,a[href^=
  http/mailto],img[src^=lm-mail:// ^data:image],ul,ol,li,blockquote,pre,code,span/div/font
  mit Whitlist-Style-Denylist (expression/behavior/url(javascript... absolut raus),
  h1-h6, table-Kette, center. <style>-Tags und on*-Attribute komplett entfernen (shortcut:
  Mail-CSS-Klassen-Support folgt wenn Nutzer es vermissen). Body-HTML-Bau wie PWA
  renderBody-Konvention (cid-Bilder -> <img src="lm-mail://blob/<sha>">).
- cache.go: LRU 64 Eintraege /bytes, ref-zaehler-gesichert (Mu), loeschen beim Shutdown.

### desktop/cmd/lmdesk/ — GUI
- AdwApplication app.lightningmail.Desktop, Fenster 1200x760, HeaderBar: Titel + Konto +
  Guthaben-Label (GET /v1/balance beim Start + nach jedem Poll).
- Sidebar (GtkListBox Buttons, 220px): 📥 Posteingang (aktiv), 📤 Gesendet, 📝 Entwürfe,
  📇 Adressbuch, 🗂 Laufwerk, 💶 Umsaetze, ⚙ Einstellungen — die letzten fuenf zeigen
  M1-bedingt einen ehrlichen Platzhalter-Text ("folgt in Etappe M2/M3") NUR Posteingang
  funktional. Reihenfolge wie PWA-Nav.
- Mitte: GtkListView mit GListStore + SignalListItemFactory (ROT-LISTE! kein Append pro
  Mail): Spalten-artig in einer ListBox-Zelle: fett Betreff (ungelesen) / normal gelesen,
  zweizeilgrau Absender + Datum. Unread-Status aus StateDoc.read-Map. Klick -> Reader.
- Rechts: WebKit Reader aus dem spike-Grundgeruest: ephemeraler WebContext, Scheme-Handler
  lm-mail://blob/<sha> async (req.Ref + Go-Fetch-Goroutine + GLib.IdleAdd zur Antwort;
  Cache vor Netz; 404 via error), decide-policy: NEW_WINDOW_ACTION / external ->
  Gio.AppInfoLaunchDefault (xdg-open-Aequivalent) und true; about:blank/LoadHtml-Phase
  durchlassen (Spike-Erkenntnis 4!), Navigation erst nach LoadFinished (Erkenntnis 5).
  JS aus per webkit_settings (enable-javascript false — Rotliste). Remote-Bilder per CSP
  img-src 'self' lm-mail: data: geblockt; Button "Bilder laden" existiert M1 noch NICHT
  (Platzhalter-Alt-Text reicht) — Shortcut-Kommentar.
- Sync-Loop: Start-fetch (inbox once + state), dann adaptiv: 10s wenn letzte Interaktion
  <60s, sonst 60s; Fehler: Backoff x2 bis 15min, UI-Statuszeile "verbindung getrennt —
  erneuter Versuch in Xs" statt silent. UI-Updates ausschliesslich per IdleAdd.
- scripts/run-desk.sh (auf dev-sandbox): tunnel check -> dbus-run-session -- xvfb-run -a
  DISPLAY :77, Fenster per import nach 8/20s screenshots -> evidence/.
- scripts/seed-inbox.mts ODER .go (Hermes-Node hat tsx + lm-work node_modules): legt auf
  dem getunnelten ALPHA ein Einweg-Konto an (newPrivKey-Muster aus drive-test, kein
  Prod-Key!), sendet sich selbst 3 Mails: (1) plain, (2) HTML bunt mit Liste+Link+<style>
  (muss sanitisiert weg sein), (3) mit 2MB-Bildanhang inline-Referenz. Ausgangspunkt
  fuer GUI-Beweis.

## Beweise (Screenshot + Log, evidence/ unter desktop/cmd/lmdesk/evidence/)
A1 Liste zeigt die 3 Seed-Mails korrekten Alters, (2) zeigt Betreff+Absender.
A2 Mail (2) offen: Farben/Liste/Link gerendert, kein <style>-Leak (DOM-Inspektion via
   webkit-EvaluateJavaScript-Script nach load: querySelectorAll('style').length==0 und
   getComputedStyle(gelbesElement)!=gelb falls style-Klassentrick). Mindestens: Screenshot
   + Unit-Test der sanitize-Funktion gegen die drei Fallen (style-Tag, onclick,
   javascript: href, img external http).
A3 Mail (3): Inline-Bild laedt ueber lm-mail (im Screenshot sichtbar — 2MB-Zufaalls-PNG
   mit deutlichem Muster), Log zeigt scheme-cache-hit.
A4 Read-Status: Mail anklicken -> StateDoc-Read-MARKierung wird lokal gesetzt (M1 nur
   Anzeige-Umschaltung; Server-Save = M2, entsprechend kommentieren).
A5 Balance-Label zeigt Regtest-Guthaben des Seed-Kontos.
A6 Unit-Tests: statedoc-golden (TS-Fixtures aus tsx-Generator-Skript client/test/
   m1-golden.mts NEU — 20 Faelle, Hermes-Node generiert, Go-Test spielt sie ab),
   sanitize 4 Fallen, cache LRU, mail-decode roundtrip gegen echte lm1-Ausgabe.
## Gates
go vet + go test ./core/... auf dev-sandbox ODER Hermes? core braucht kein GTK -> Hermes
(go1.26 ok), GUI-Build nur auf dev-sandbox (go build ./cmd/lmdesk), spike unveraendert gruen.

## Regeln
- Rotliste docs/review-M1-desktop.md ist Vertrag: kein SetMarkup, ListView+Factory,
  ephemeraler Context, scheme async + req.Ref, decide-policy Typ-Check, streams Unref.
- Keine UI-Strings auf Deutsch im Go-Code ausser den sichtbaren Labels (Nutzer = Bernd:
  Labels deutsch wie PWA; Kommentare englisch!).
- Kein Commit, kein dev-relay/rsync hoch — Parent.
Report: Dateien, Gates, 6 Beweise einzeln, Screenshot-Pfade, Abweichungen. Deutsch.

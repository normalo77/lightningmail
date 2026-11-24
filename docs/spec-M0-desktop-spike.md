# Etappe M0 — Spike: nativer Linux-Desktop-Client (Go + GTK4/Adwaita + WebKitGTK 6.0)

Ziel-Nachweis in EINEM Programm: Go-Binary, das unter Xvfb ein natives Adwaita-Fenster öffnet,
darin eine WebKitGTK-6.0-View, die eine HTML-Mail mit CSS-Fonts, Farb-Formatierungen, Liste,
anklickbarem Link, eingebettetem Base64-Bild UND einem Bild über ein eigenes URI-Schema
lm-mail:// anzeigt. Beweis = Screenshot + sauberer Console-Log.

## Umgebungen (wichtig: zwei Maschinen!)
- HERMES (hier, Debian 12, KEIN GTK4/WebKit): Code schreiben in <workspace> (Git-Klon).
- dev-sandbox lm-desktop (<lan-host>, root, Key <ssh-key>, StrictHostKeyChecking=no):
  Debian 13, GTK 4.16 / libadwaita 1.6 / webkitgtk-6.0 (2.48) runtime+dev, Go 1.24.4,
  xvfb-run, import (ImageMagick), Fonts (liberation/dejavu/noto-color-emoji). Repo liegt in <workspace>.
- Arbeitszyklus: Dateien in <workspace> bearbeiten ->
  rsync -a -e "ssh -i <ssh-key> -o StrictHostKeyChecking=no" <workspace>/desktop/ <dev-sandbox-host>:<workspace>/desktop/
  -> ssh ... 'cd <workspace>/desktop && bash spike/run-spike.sh' -> scp screenshot zurück ->
  vision_analyze selbst prüfen. NIEMALS Build/Versuch direkt auf Hermes (kein GTK).

## Stack-Entscheidung (researchiert, vertrau dem)
- Bindings: github.com/bnema/puregotk v4 (GTK4+Adwaita via purego, KEIN CGO) und
  github.com/bnema/puregotk-webkit (WebKit-6.0+Soup-3.0 Add-On). Reines dlopen — Build auf
  Hermes wäre zwar möglich, aber Ausführung nur auf dev-sandbox.
- Wenn das WebKit-Add-On API-Lücken zeigt: NICHT in Endlosschleife debuggen — 1:1 mit
  github.com/ebitengine/purego (Dlopen/Dlsym) einen ~30-Funktionen-Shim um die
  webkit_web_view_* C-ABI selbst bauen (symbole: webkit_web_view_new,
  webkit_web_view_load_uri, webkit_web_view_load_html, webkit_settings_* via
  webkit_web_view_get_settings, webkit_web_context_new +
  webkit_web_context_register_uri_scheme + webkit_uri_scheme_request_* ). Dev-Pakete sind
  installiert, CGO-Fallback (gotk4) wäre Option 3 — aber erst melden, nicht anfangen.
- Zeitbox: Wenn nach ~6 Build-Iterationen kein Screenshot-Beweis existiert: abbrechen und
  Report liefern: Was blocking war, welche Optionen bleiben, was sie kosten.

## UI-Form (M0 nur anreißen, M1 wird das richtig)
Adwindow mit AdwToolbarView + HeaderBar (Titel 'lightningmail'). Inhalt: eine Aufgeteilte
Ansicht reicht als Liste-links/Reader-rechts Skeleton (GtkBox + zwei Panes, links GtkListBox
mit 3 Pseudo-Mails, Klick lädt HTML in die View). Reicht für den Machbarkeitsbeweis.

## Die HTML-Testmail (fest vorgegeben, spike/testmail.html)
Erzeuge sie als Go-String/Fixture:
- font-family-Mix: serif + monospace gemischt
- <b>/<i>/farbiger Text
- <ul>-Liste, <a href="https://lightningmail.app">Link</a>
- eingebettetes PNG als data:image/png;base64 (kleines selbst generiertes 40x40 Bild)
- <img src="lm-mail://blob/demo1"> — Bild, das NUR über den registrierten Custom-Scheme
  aus dem RAM kommt (Go-Handler antwortet mit einem zweiten generierten PNG, Content-Type
  image/png, plus ein <img src="lm-mail://blob/fehlt"> das 404 liefert — kaputte Bilder
  dürfen das Layout nicht zerschießen).
- Meta-Viewport wie echte Mails.

## Abnahmekriterien (alle vier, im Report einzeln bewerten)
A1: spike/run-spike.sh baut (go build ./...) ohne CGO, Fehler frei.
A2: xvfb-run startet das Binary; nach 6s zeigt ein import-Screenshot: Fenster mit HeaderBar,
    Liste links, rechts gerenderte Mail — sichtbar: Serif+Mono Fonts, Farbe, Liste,
    BEIDE gerenderten Bilder, graues kaputtes Bildicon für das 404-Bild.
A3: stderr-Log ohne ERROR/FATAL (WARN ok); Custom-Scheme-Handler wurde aufgerufen
    (Log zeigt die zwei lm-mail-Anfragen).
A4: Link klickbar? (Nur notieren, ob WebKit-Navigation-Callback ausgelöst wird —
    kein Browser-Fenster-Test nötig; M1 verbindet es mit xdg-open.)
Screenshot + Log nach <workspace>/desktop/spike/evidence/ zurückkopieren (scp von dev-sandbox).

## Repo-Hygiene
- Neues Top-Level-Verzeichnis desktop/ ( spike/, später cmd/ui-core/ ), go.mod mit eigenem
  Modul-Pfad github.com/lightningmail/desktop (Getrennt vom relay-Modul — CGO-freies schmales
  Modul, relay bleibt davon unberührt).
- Keine git-Commits, kein rsync Richtung dev-relay — Parent macht das.
- run-spike.sh MUSS als Datei deployed werden (bash-Aufruf enthaelt keine verbotenen Woerter).

## Report
Dateien, Build-Status, die 4 Kriterien einzeln, Screenshot-Pfad, Log-Auszug, und bei
Abbruch: Blocker-Analyse + Optionen. Deutsch.

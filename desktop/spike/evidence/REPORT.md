# M0-Spike Report — Go + GTK4/Adwaita + WebKitGTK 6.0 (purego, kein CGO)

Ergebnis: **alle 4 Abnahmekriterien BESTANDEN**. Zeitbox (6–8 Build-Iterationen) eingehalten.

## Dateien
- `desktop/go.mod` / `go.sum` — Modul `github.com/lightningmail/desktop`, go 1.26.1
  (dev-sandbox schaltet via GOTOOLCHAIN=auto auf gecachten go1.26.1-Toolchain)
- Bindings: `github.com/bnema/puregotk@v0.5.4` (pinned — v0.7.x hat andere Signaturen als
  die verifizierte API) + `github.com/bnema/puregotk-webkit@v0.1.0` (Importpfad `.../webkit`)
- `desktop/spike/main.go` — AdwApplication + AdwToolbarView/HeaderBar + GtkPaned
  (ListBox links / WebView rechts), lm-mail://-Scheme-Handler, PNG-Generatoren
- `desktop/spike/testmail.html` — go:embed-Fixture mit {{IMG_DATAURI}}-Platzhalter
- `desktop/spike/run-spike.sh` + `spike/xvfb-inner.sh` — Build + Xvfb-Screenshot-Pipeline
- Evidenz: `desktop/spike/evidence/screenshot.png`, `desktop/spike/evidence/spike.log`

## Abnahmekriterien
- **A1 BESTANDEN** — `CGO_ENABLED=0 go build ./...` fehlerfrei (Hinweis: nacktes
  `go build ./...` kollidiert mit dem Verzeichnisnamen `spike`, daher `-o /dev/null`).
- **A2 BESTANDEN** — Screenshot (1280x800 Xvfb, 7s Renderzeit) per vision_analyze bestätigt:
  HeaderBar „lightningmail/M0-Spike“, 3-Mail-Liste (Zeile 1 ausgewählt), rechts gerenderte
  Mail mit Serif-Fließtext + Mono-Code, rot/blau/grün, <ul>-Liste, data-URI-Schachbrettbild,
  lm-mail://-Kreisbild, Broken-Image-Icon fürs 404-Bild ohne Layoutbruch, Link, Mono-Block.
- **A3 BESTANDEN** — stderr-Log: 0 ERROR/FATAL/CRITICAL/panic. Scheme-Handler wurde 2x
  aufgerufen (`lm-mail://blob/demo1`, `lm-mail://blob/fehlt`), load-changed 0→2→3 (finished).
  Einmalige WARN-Zeile von JSC („Overriding existing handler for signal 10“) ist unkritisch.
- **A4 BESTANDEN** — decide-policy-Callback feuert bei externer Navigation
  (`https://lightningmail.example/simulierter-linkklick`), wird abgefangen (Ignore + return
  true), View bleibt auf der Mail. M1 hängt dort xdg-open dran.

## Erkenntnisse für M1 (in den Stack eingebrannt, keine Option mehr)
1. **dbus-run-session zwingend**: dev-sandboxs systemd-Userbus lässt `g_application_run` vor
   activate hängen (ohne Bus ebenso). Run-Pipeline nutzt `dbus-run-session -- xvfb-run ...`.
2. **WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1** nötig: WebKit-Sandbox (bwrap/dbus-proxy)
   abortet in der LXC (kein fuse). Für Produktionsclientlater: User-Namespaces prüfen.
3. `URISchemeRequestCallback(uintptr, uintptr)` = **(request, user_data)** — nicht
   (context, request); falsche Reihenfolge gibt GLib-CRITICALs. Reiner Dlsym-Shim nicht nötig.
4. decide-policy NICHT global Ignore()n — blockiert auch das initiale LoadHtml (about:blank).
5. LoadUri während laufendem LoadHtml bricht den Load ab → erst nach LoadFinished navigieren.

## Build/Run
    rsync -a -e "ssh -i <ssh-key> -o StrictHostKeyChecking=no" \
      <workspace>/desktop/ <dev-sandbox-host>:<workspace>/desktop/
    ssh <dev-sandbox-host> 'cd <workspace>/desktop && bash spike/run-spike.sh'

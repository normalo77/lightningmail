# M1b-Evidenz — Desktop Lese-Pfad (Go-Kern + GUI, read-only)

Lauf: CT114 (LXC, go1.26.10 via GOTOOLCHAIN=auto, WebKitGTK 2.54.0, GTK4/adw),
Relay ALPHA auf CT113 getunnelt (127.0.0.1:18443 → CT113:8443, scripts/tunnel.sh).
Seed-Konto: desk-m1b-07359ad6 (Einweg-Key scripts/seed.key, Regtest-Faucet).

## Dateien
- shot-08s.png  — Screenshot @8s: Mail „Seed 2 — HTML bunt" offen (A1, A2, A4, A5)
- shot-20s.png  — Screenshot @20s: Mail „Seed 3 — Inline-Bild" offen, 2-MB-PNG
                  inline via lm-mail:// (A3, A4, A5)
- lmdesk.log    — Evidenz-Run (JS aus, LMDESK_DEMO=1): Sync, markRead,
                  scheme-handler/fetch/cache-hit, reassemble
- domcheck.log  — 2. Run mit LMDESK_DOMCHECK=1 (JS nur hier): DOMCHECK-Zeile = A2
- domcheck-08s.png — Screenshot des DOM-Check-Runs (gleicher Zustand wie shot-08s)
- seed.log      — Anlage Seed-Konto + 3 Mails ( Plain / HTML-Fallen / 2-MB-Bild
                  chunked: 2 Scheiben + Manifest)

## Beweise
- A1: Liste zeigt Seed 3 (21:47:08) / Seed 2 (21:47:06) / Seed 1 (21:47:04)
  neueste oben, korrekte Altersreihenfolge (2s-Versatz des Seeds); Betreff +
  Absender (02f5cbff2a59…) + Datum zweizeilig. OCR der shot-*-list bestätigt.
- A2: Mail 2 offen: h2 rot (DOMCHECK h2Color rgb(192,57,43)), grüner
  Listeneintrag, Link gerendert. Kein <style>-Leak: DOMCHECK
  {"mailStyles":0,"scripts":0,"onclickAttrs":0,"jsHrefs":0,
   "probeBg":"rgba(0,0,0,0)"} (gelbe Klasse wirkt NICHT), remote-img
  geblockt (imgSrcs[0]=""), data:image erlaubt. Pixel-Check: 0 gelbe
  Flächenpx. Unit-Tests: sanitize_test.go (style-Tag, onclick,
  javascript:-href, externes http-img + style-Denylist).
- A3: Mail 3: scheme-handler #1 (body-img) + #2 (?thumb=1),
  „reassemble ok: 2 Scheiben, 1867639 Bytes", „scheme-fetch ok … image/png",
  „scheme-cache-hit 4cdd05fabfc1… (1867639 bytes, single-flight)".
  shot-20s.png zeigt das Muster (rot/weiß-Schachbrett 5485/6414 Sample-px,
  blaues Diagonalband 1506 px, Noise-Bereich 40193 eindeutige Farben).
- A4: markRead-Logzeilen (lokal, „Server-Save = M2"); Listen-Umschaltung
  per Tinten-Messung: Seed-3-Betreff shot-08s (ungelesen, fett):
  ink 602, Dunkelheit 87 → shot-20s (gelesen): ink 244, Dunkelheit 139;
  Seed 1 bleibt in beiden fett (ink 396/88).
- A5: HeaderBar rechts „Guthaben: 9964 sats" (OCR aus shot-*-bal2),
  Regtest-Guthaben des Seed-Kontos (10000 Faucet − Porto/Byte-Porto).
  Statuszeile: „verbunden · 3 Mails · zuletzt 22:32:22".
- A6: go test ./core/... grün (Hermes go1.26.10 UND CT114):
  TestGoldenMerge (17 Fälle) + TestGoldenSealed (3 Fälle) gegen
  client/test/m1-golden.mts (Fixtures testdata/m1-golden.json, aus dem
  echten state.ts mergeDocs + StateSync.seal generiert), TestSanitize*
  (4 Fallen + Denylist), TestCacheLRU, TestMailDecodeRoundtrip +
  TestMailBlobRefsFallback (echte lm1-Envelope inkl. Relay-Sig-Check).

## Gates
- go vet ./core/... ./cmd/...: clean (Hermes + CT114)
- go test ./core/...: ok (Hermes + CT114)
- go build ./cmd/lmdesk (CT114): OK; go build ./... inkl. spike: OK
- spike/run-spike.sh (CT114, unveränderter Spike): BUILD_OK,
  SCREENSHOT_TAKEN, SPIKE_DONE, 0 CRITICAL/panic
- Logs lmdesk.log/domcheck.log: 0 × CRITICAL|panic|ERROR|FATAL

## Rotlisten-Konformität (Auszug)
- Kein SetMarkup mit Mail-Daten (SetText + CSS-Klassen heading/dim-label)
- GtkListView + GtkSingleSelection + GtkSignalListItemFactory auf
  GtkStringList (msg_id-Strings), Callbacks einmalig in activate gebunden
- Ephemeraler WebKit-NetworkSession via GtkBuilder-XML (WebKitGTK 2.54 hat
  webkit_web_view_new_with_network_session entfernt — construct-property
  „network-session" + „default-content-security-policy" im Builder gesetzt);
  Scheme-Registrierung am view-eigenen WebContext
- Scheme-Handler async: req.Ref + Goroutine + glib.IdleAddOnce, GBytes/
  MemoryInputStream + Unref nach Finish, GError.Free, Cache-Control:no-store
  (entschlüsselte Bytes bleiben nur im zero-on-evict LRU)
- decide-policy: Typ-Switch (nur NavigationAction/NewWindow gecastet),
  Allowlist about:blank + lm-mail://, https/mailto nur bei IsUserGesture →
  AppInfoLaunchDefaultForUri, sonst Ignore
- Kein WEBKIT_DISABLE_SANDBOX… im Go-Code/Launcher — nur in xvfb-inner.sh
  (Headless-LXC-Evidenz); dbus-run-session nur in den Test-Skripten
- Kein os.Exit im Sync-/API-Pfad; Fehler → Statuszeile/Toast, Backoff x2 ≤ 15 min

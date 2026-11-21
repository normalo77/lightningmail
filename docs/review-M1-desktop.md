# Review Gemini-4-Argon: M0-Spike & M1-Architektur Linux-Desktop (21.11.2026)

Verbindliche Grundlage fuer Etappe M1. Kernaussagen (after-Cursor, mirrorBlobs-Idempotenz, 600-B-Limit, 16/255-Ref-Discrepanz) vom Parent gegen den Code verifiziert.

### 0. Vorab: Auflösung der `MAX_REFS=255` vs. `MaxBlobRefs=16`-Diskrepanz (inkl. Retro-Kompat)

**Befund im Code:**
- Client (`client/src/chunks.ts:11`, `client/src/send.ts:96`, `client/test/chunk-test.mts:34`, `docs/spec.md:388`, `docs/CONCEPT.md:490`): erlaubt `MAX_REFS = 255` (1-Byte-Count im TLV `0x03`, ~254 MiB Chunked Attachments).
- Server (`relay/internal/envelope/envelope.go:31,71,236`): hart auf `MaxBlobRefs = 16` verdrahtet (`n > MaxBlobRefs` wirft `ErrSize`).
- **Harte Transport-Bremse (Onion-Limit!):** Bei Cross-Relay-Zustellung wird das komplette Envelope-Binary in Keysend-TLV `34349334` übertragen (`relay/internal/relaysrv/relaysrv.go:443`). Die Sphinx-Onion-Payload von LND fasst maximal ~1300 Bytes (`docs/spec.md:44`: 600 B Envelope-Hardlimit). Schon **16 BlobRefs** kosten `1 + 16×32 = 513 Bytes` allein für Tag `0x03` (+ ~220 B Pflichtfelder > 730 B); **255 BlobRefs** wären `8161 Bytes` und crashen `lncli sendpayment --keysend` (`relay/internal/lnclient/lnclient.go:139`) garantiert an der Bolt-4-Onion-Grenze!

**Entscheidungsreife Empfehlung:**
1. **`envelope.MaxBlobRefs` in `relay/internal/envelope/envelope.go:31` auf `255` anheben** (damit das Wire-Format `uint8`-konsistent zu `chunks.ts:11` ist und `uint16`-TLV-Länge `1 + 255*32 = 8161` nicht als `ErrSize` abweist).
2. **Manifest-Only in `blob_refs` beim Chunking + Server-Manifest-Walk (Retro-Kompat):**
   - `client/src/send.ts:89` (und analog der M1-Client) schreibt bei Chunked Attachments **nur den Manifest-Hash `msha`** in `env.BlobRefs` (1 Ref pro Anhang statt `N+1`), sobald `blobRefs.length` sonst `16` überschreiten würde (oder generell ab M1).
   - **Retro-Kompat im Relay (`relay/cmd/relayd/main.go:250`, `mirrorBlobs`):** Nach dem Spiegel-Download eines Blobs prüft `mirrorBlobs`, ob der Blob ein gültiges JSON-Manifest `{"v":1,"size":...,"chunks":[...]}` ist (`len(raw) < 64*1024 && raw[0] == '{'`). Falls ja, iteriert `mirrorBlobs` zusätzlich über `man.Chunks`, spiegelt fehlende Chunk-Blobs vom Peer nach und ruft `l.RegisterBlobRef(acctID, chunkSha, ..., "mail")` auf.
   - **Effekt:** Alte Envelopes (die alle Chunk-Hashes + Manifest in `blob_refs` hatten, z. B. der 2,5-MiB-Test mit 4 Refs in `chunk-test.mts:121`) funktionieren 100 % unverändert (Idempotenz in `mirrorBlobs` Zeile 254 via `os.Stat`). Neue Envelopes mit 250-MiB-Anhängen brauchen nur 1 `blob_ref` (33 Bytes im Onion-TLV!) und überleben jedes LND-Keysend-Routing.

---

### (1) Code-Qualität `desktop/spike/main.go` — Kritische Funde & Pflicht-Refaktorisierung vor M1

1. **Purego Callback-Lebensdauer & FFI-Slot-Limit:**
   - *Befund:* `schemeCB` (`main.go:38`) ist global, aber `actcb` (`main.go:59`), `selcb` (`main.go:99`), `decide` (`main.go:108`) und `loadcb` (`main.go:127`) sind lokale Stack-/Heap-Closures, deren Adressen (`&selcb`) an `puregotk` übergeben werden. `purego.NewCallback` belegt pro Aufruf einen permanenten, nicht freigebbaren Trampolin-Slot (hartes Limit in purego: 2000 Callbacks pro Prozess) und hält die Go-Funktion nur solange der Wrapper lebt. Werden Signal-Connects in M1 dynamisch pro Zeile/Reload ausgeführt, droht Slot-Exhaustion (`panic: purego: max callbacks`).
   - *M1-Pflicht:* Alle Signal-Callbacks als Methoden/Felder einer zentralen `AppUI`-Struct einmalig bei Widget-Erzeugung binden — **niemals** `Connect*` innerhalb von Render-/Update-Schleifen aufrufen.
2. **GObject Ref-Zähler & Memory-Leaks:**
   - *Befund:* `win := adw.NewApplicationWindow(...)` mit `defer win.Unref()` (`main.go:71-72`) ist **falsch und gefährlich**: `defer` in `activate()` feuert sofort beim Rücksprung aus `activate()`, während das Fenster noch offen ist! Es überlebt im Spike nur zufällig, weil `GtkApplication` intern eine Referenz hält. Umgekehrt werden in `handleLMScheme` (`main.go:188-192`) `stream := gio.NewMemoryInputStreamFromData(...)` (`g_object_new` -> Full Reference!) und `glib.NewErrorLiteral(...)` **nie freigegeben**: `webkit_uri_scheme_request_finish` nimmt selbst `g_object_ref(stream)`, d. h. ohne `stream.Unref()` und `g_error_free` leakt jeder `lm-mail://`-Aufruf das GObject + Buffer. Auch `rowWidget` (`main.go:87,150`) erzeugt floating Refs, die von `list.Append` gesunken werden, während `view.GetSettings()` (`main.go:138`) `transfer none` ist (kein `Unref` nötig).
   - *M1-Pflicht:* `defer win.Unref()` in `activate()` ersatzlos streichen (`GtkWindow.Destroy()` gibt frei). Nach `req.Finish(...)` zwingend `stream.Unref()` aufrufen.
3. **Scheme-Handler (`main.go:182-194`):**
   - *Befund:* Nutzt einen globalen Slice `imgScheme` ohne `GDestroyNotify` (`nil` als 3. Argument in Zeile 188) und wertet Pfade nur per `strings.HasSuffix(uri, "/demo1")` aus.
   - *M1-Pflicht:* Striktes URI-Parsing (`lm-mail://cid/<msg_id>/<part_id>`) mit Host-/Pfad-Validierung und sauberem `GBytes`/`GDestroyNotify`-Lifecycle (siehe Punkt 3).
4. **`decide-policy`-Verzweigung (`main.go:108-123`):**
   - *Befund:* In Zeile 110 wird `decPtr` **blind** mittels `webkit.NavigationPolicyDecisionNewFromInternalPtr(decPtr)` gecastet, ohne `t` (`webkit.PolicyDecisionType`) zu prüfen! Bei `WEBKIT_POLICY_DECISION_TYPE_RESPONSE` (Typ 2, z. B. MIME-/Download-Entscheidung) ist `decPtr` eine `WebKitResponsePolicyDecision`, kein `WebKitNavigationPolicyDecision` -> Undefined Behavior / GType-Cast-Critical. Zudem fängt Zeile 116 nur `http://`, `https://`, `mailto:` ab; Schemata wie `file://`, `javascript:`, `ws://`, `ftp://`, `data:` (als Top-Level-Navigation) fallen durch `return false` auf Default-Allow!
   - *M1-Pflicht:* **Allowlist statt Blocklist** und Typ-Switch über `t`:
     - Nur bei `t == webkit.PolicyDecisionTypeNavigationActionValue` oder `NewWindowActionValue` auf `NavigationPolicyDecision` casten.
     - Erlaubt (`d.Use(); return true`) ist **ausschließlich** `uri == "about:blank"` (initialer `LoadHtml`-Frame) und `strings.HasPrefix(uri, "lm-mail://")`.
     - Bei `https://` und `mailto:` nur dann `gio.AppInfoLaunchDefaultForUri(uri, nil)` triggern, wenn `na.IsUserGesture() == true` (verhindert Auto-Redirect-Popups durch Meta-Refresh).
     - **Alles andere** (inkl. `NewWindowAction`, `http://`, `file://`) hart `d.Ignore(); return true`.
5. **Markup-Injection (Pango-XSS/DoS) in der Mail-Liste (`main.go:158-164`) & HTML-Titel (`main.go:176`):**
   - *Befund:* `subj.SetMarkup("<b>" + m.subj + "</b>")` (`main.go:158,161,164`) übergibt unescaped Mail-Strings an den Pango-Markup-Parser. Enthält ein Betreff `<`, `&` oder ungültige Tags (z. B. `Re: <kein Betreff>`), verwirft GTK das gesamte Label als leer und wirft `Gtk-WARNING: Failed to set text from markup`. In Zeile 176 ist `fmt.Sprintf("<h2>%s</h2>", mails[i].subj)` direktes HTML-XSS im Reader.
   - *M1-Pflicht:* `SetMarkup` komplett verbannen! Stattdessen `label.SetText(&m.subj)` + Styling rein über GTK4-CSS-Klassen (`label.AddCssClass("title-4")`, `"dim-label"`, `"caption"`).

---

### (2) Sicherheit HTML-Mail-Rendering

**Entscheidungsreife Empfehlung:**
1. **WebKitSettings-Härtung + Dual-Defense (Go-Sanitizer + Content-Security-Policy):**
   - Da `puregotk-webkit` keine `WebKitUserContentFilterStore`-Bindings exponiert, wird Remote-Content (Tracking-Pixel, externe CSS/Fonts/Frames) **dreifach** ohne ContentFilter-API abgeklemmt:
     1. **HTML-Sanitizer in Go vor `LoadHtml`:** Jede HTML-Mail läuft vor dem Rendern durch `github.com/microcosm-cc/bluemonday` (Striktes Allowlist-Profil: erlaubt Tabellen/Listen/Basis-Typografie und `img[src]` **nur** nach Rewrite von `cid:` auf `lm-mail://cid/...` sowie `data:image/(png|jpeg|gif|webp);base64,...`; entfernt `<script>`, `<iframe/frame/object/embed>`, `<form>`, `<meta http-equiv>`, `<base>`, `<link>`, `<style>` mit `url(...)`). Plaintext-Mails (`client/app/main.ts:548`) werden via `html.EscapeString` in ein lokales `<pre>`-Template eingebettet.
     2. **Injektion einer harten `<meta http-equiv="Content-Security-Policy">` im `<head>` des Reader-Wrappers:**
        `default-src 'none'; img-src lm-mail: data:; style-src 'unsafe-inline'; font-src 'none'; connect-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none';` — WebKit blockiert damit auf Engine-Ebene jeden Netzwerk-Fetch (auch CSS-`background: url(https://...)`), bevor die Netzwerk-Schicht überhaupt gefragt wird.
     3. **`WebKitSettings` (auf der `WebView` in `activate`):**
        `SetEnableJavascript(false)`, `SetEnableJavascriptMarkup(false)`, `SetAllowFileAccessFromFileUrls(false)`, `SetAllowUniversalAccessFromFileUrls(false)`, `SetEnableBackForwardNavigationGestures(false)`, `SetEnableDeveloperExtras(false)`, `SetEnablePageCache(false)` (wichtig für RAM-Hygiene!), `SetEnableHtml5LocalStorage(false)`, `SetEnableHtml5Database(false)`.
2. **WebProcess-Sandbox-Realität (Ubuntu 24.04+ AppArmor / LXC-Fallback):**
   - **Befund:** In `desktop/spike/xvfb-inner.sh:8` wurde `WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1` gesetzt, weil CT114 ein unprivilegierter LXC-Container ohne Nesting/`userns` ist. Auf echten Nutzer-Desktops (Debian 12/13, Fedora, Arch, Ubuntu 24.04+ mit System-Paket `libwebkitgtk-6.0-4`, das ein eigenes AppArmor-Profil für `/usr/libexec/webkitgtk-6.0/WebKitWebProcess` mitbringt) funktioniert `bwrap` out-of-the-box.
   - **Empfehlung:** `WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGOX...` darf **niemals** im Go-Binary oder Launcher-Skript gesetzt werden! Stattdessen beim Start von `main()` `ctx.SetSandboxEnabled(true)` explizit aufrufen. Nur für die Headless-CI auf CT114 bleibt die Env-Var lokal in `xvfb-inner.sh`. Falls der Desktop-Client beim Start erkennt, dass er in einem Container ohne `userns` läuft (`/proc/sys/kernel/unprivileged_userns_clone == "0"` oder `EPERM`), loggt er eine Warnung auf stderr, schaltet aber nicht stillschweigend die Sandbox auf Host-Systemen ab.
3. **WebContext-Isolation:**
   - **Nicht** `webkit.WebContextGetDefault()` (`main.go:67`) verwenden! Stattdessen eine ephemere Network-Session + eigenen `WebContext` instanziieren (`webkit_network_session_new_ephemeral()` bzw. über `g_object_new` mit `is-ephemeral=TRUE`, `webkit_network_session_set_itp_enabled(false)`), die Proxy-Einstellungen auf `NO_PROXY` / ungültigen Loopback-Port `127.0.0.1:1` nagelt. Damit schreibt WebKit keinerlei Cookies, HSTS-Caches oder Disk-Artefakte unter `~/.cache` oder `~/.local/share`.

---

### (3) RAM-Hygiene `lm-mail:`-Handler für entschlüsselte Anhänge

**Befund im Spike (`main.go:182-194`):**
`gio.NewMemoryInputStreamFromData(imgScheme, len(imgScheme), nil)` übergibt den Go-Slice-Pointer direkt an C. Das verletzt zwei Regeln: (1) Go-GC/Memory-Safety (C liest asynchron aus dem Stream, während der Go-Slice ohne Referenz in Go vom GC abgeräumt werden könnte), (2) mit `destroy = nil` wird der Puffer nach dem Rendern nie genullt oder freigegeben.

**Entscheidungsreife Empfehlung:**
1. **Kein synchrones HTTP/Entschlüsseln im Scheme-Callback:**
   - `handleLMScheme` läuft auf dem **GTK Main Thread**! Ein synchroner `GET /v1/blob/{sha}` oder `reassemble()` im Callback friert die gesamte GUI ein.
   - **Architektur:** `WebKitURISchemeRequest` ist ein GObject. Wenn der angeforderte Anhang (`lm-mail://cid/<msg_id>/<sha>`) noch nicht im RAM-Cache liegt, macht `handleLMScheme` ein `req.Ref()`, startet eine Go-Goroutine (die die Chunks per HTTP holt, reassembliert und per `crypto.DecryptForRecipient` / `decryptPayload` entschlüsselt) und kehrt **sofort** zurück. Sobald die Goroutine fertig ist, dispatchet sie den Abschluss via `glib.IdleAdd` zurück auf den GTK-Main-Thread, ruft dort `req.Finish(...)` (bzw. bei Fehler `req.FinishError(...)`) und `req.Unref()` auf.
2. **Sichere Buffer-Lebensdauer & Zeroing ohne C-Callback-Overhead:**
   - Statt `NewMemoryInputStreamFromData` mit C-Destroy-Callback zu verwenden:
     1. Einen `final class ActiveMailCache` in Go halten, der **exakt nur die Inline-Blobs der aktuell im Reader geöffneten `msg_id`** als `map[string][]byte` im RAM hält.
     2. Harte Cache-Grenze: **Max. 16 MiB pro Inline-Bild, max. 32 MiB gesamt für `ActiveMailCache`** (größere Anhänge werden nie inline als `lm-mail://` gerendert, sondern nur über „Speichern unter" gestreamt).
     3. Für `req.Finish` wird `gBytes := glib.NewBytes(buf, uint(len(buf)))` erzeugt (kopiert die Bytes einmal sauber in den GLib-Allocator), daraus `stream := gio.NewMemoryInputStreamFromBytes(gBytes)` gebaut, `req.Finish(&stream.InputStream, int64(len(buf)), &ct)` aufgerufen und **sofort danach** `stream.Unref()` sowie `gBytes.Unref()` ausgeführt (WebKit hält seine eigene Referenz bis zum Stream-EOF und gibt den C-Puffer danach deterministisch frei).
     4. **Explizites Zeroing beim Mail-Wechsel / Fenster-Schließen:** Sobald der Nutzer in der Liste eine andere Mail anklickt (`loadMail(newMsgID)`), wird vor dem Laden der neuen Mail über alle Slices im `ActiveMailCache` der alten Mail `clear(buf)` (Go 1.21+ Builtin, überschreibt das Backing-Array zuverlässig mit Nullbytes) aufgerufen und die Map geleert, gefolgt von `view.LoadHtml(...)` (mit `EnablePageCache(false)` verwirft WebKit den alten DOM-/Decoded-Image-Speicher sofort).

---

### (4) M1-Architektur

1. **Gemeinsames Go-Modul für `crypto` & `envelope` (Go `internal/`-Regel!):**
   - *Befund:* `desktop/go.mod` (`module github.com/lightningmail/desktop`) kann `github.com/lightningmail/relay/internal/crypto` und `.../internal/envelope` **nicht** importieren, weil Go den Import von `internal/`-Packages über Modulgrenzen hinweg auf Compiler-Ebene verbietet.
   - *Empfehlung:* In `relay/` die beiden leichtgewichtigen, SQLite-/LND-freien Packages von `relay/internal/crypto` und `relay/internal/envelope` nach **`relay/pkg/crypto`** und **`relay/pkg/envelope`** verschieben (19 Importzeilen in `relay/` per `patch` anpassen; sie ziehen nur `btcec/v2` und `golang.org/x/crypto`, kein `modernc.org/sqlite`!). In `desktop/go.mod` dann `require github.com/lightningmail/relay v0.0.0` mit **`replace github.com/lightningmail/relay => ../relay`** eintragen. Null Code-Duplikation, null drittes Repo/Modul nötig.
2. **Byte-kompatibler `StateDoc`-Merge-Port (`client/src/state.ts:47-86`):**
   - *Exakte Regeln für `desktop/internal/state/state.go`:*
     - Selbst-ECIES (`seal`/`open`, `state.ts:105-121`): Empfänger ist `priv.PubKey()`, `aad = nil` (`[]byte{}`), Wire-Blob = `ephPub(33B) || sealed(24B Nonce + Ciphertext + 16B Tag)`, im JSON von `GET/PUT /v1/state` als Standard-Base64 (`state_b64`, max. 256 KiB; Hinweis: der Kommentar in `state.ts:137` „Inhalt ist hex" ist veraltet, `relaysrv.go:732,743` und `state.ts:109,114` nutzen `StdEncoding` Base64!).
     - `Read`, `Spam`, `Deleted`: `map[string]int` (Wert `1`), Merge = Mengen-Vereinigung (OR). (`toggleSpam(sender, false)` löscht den Key lokal vor dem Push, aber ein 409-Re-Pull-Merge vereinigt `a` und `b`).
     - **`wins(cand, cur)`-Regel (`state.ts:61-62,78,83`):** Für `Drafts` (nach `id`), `Contacts` (Map-Key `id`) und `Files` (Map-Key `id`) gewinnt `cand` über `cur` genau dann, wenn:
       `cur == nil || cand.Ts > cur.Ts || (cand.Ts == cur.Ts && cand.Gone == 1 && cur.Gone == 0)`
       *(Bei `ts`-Gleichstand zweier Geräte in derselben Sekunde gewinnt immer der Tombstone `gone: 1`!).*
     - **Re-Stempeln beim Schreiben (`state.ts:173,188,198`):** Jede lokale Mutation (Save oder Delete/Tombstone) setzt `ts = max(time.Now().Unix(), prev.Ts) + 1`. Ein lebendiger Save auf einen existierenden Kontakt/DriveEntry löscht das `gone`-Feld (`gone: 0` mit `omitempty`), übernimmt bestehende Felder (`...prev, ...c`) und gewinnt dank `+1` streng über jedem älteren Tombstone.
     - **Sortierung & Caps:**
       - `Drafts`: Nach Merge aufsteigend nach `Ts` sortieren (`slices.SortStableFunc` mit `a.Ts - b.Ts`, Reihenfolge: erst `a.Drafts`, dann `b.Drafts`), danach die **letzten 30** behalten (`out[max(0, len-30):]`, `state.ts:66`).
       - `Sent`: Dedup nach `MsgID`; ein Kandidat `s` überschreibt `cur`, wenn `len(utf16/runes(s.Body)) > len(cur.Body) || s.Ts > cur.Ts` (`state.ts:72`, Body beim Speichern auf 2000 Zeichen gekürzt, `state.ts:180`). Danach **absteigend** nach `Ts` sortieren (`y.Ts - x.Ts`) und die **ersten 150** behalten (`out[:min(len, 150)]`, `state.ts:74`).
       - JSON-Tags: Optionale Felder (`gone`, `body`, `msha`) zwingend mit `omitempty`, damit `JSON.parse` in der PWA (`!d.gone`) identisch reagiert.
3. **Adaptives Polling:**
   - Da `/v1/inbox` (`relaysrv.go:478`) bereits inkrementelles Cursor-Fetching via `?after=<last_seq>&limit=50` unterstützt (was `lmcli` und die PWA aktuell noch verschenken!):
   - M1 pollt in einer Hintergrund-Goroutine mit `GET /v1/inbox?after=<highWaterSeq>&limit=100`.
   - **Intervall-Steuerung:** Fenster aktiv & fokussiert (`win.IsActive() == true`): **10 s** (nach eigenem Send oder neuem Eingang für 60 s auf **5 s** verkürzt). Fenster im Hintergrund / unfokussiert: **60 s**. Bei Netzwerkfehler: Exponential Backoff bis **120 s** mit Jitter. Balance + Receipts + State werden nur alle 60 s (oder wenn `len(newMsgs) > 0`) mitgezogen.
4. **Liste bei 10.000 Mails (`GtkListView` + `GtkSignalListItemFactory` statt `GtkListBox` oder `GtkColumnView`):**
   - *Befund:* `gtk.NewListBox()` (`main.go:84-88`) instanziiert für jede der 10.000 Mails sofort ein `GtkBox` + 3 `GtkLabel`-GObjects (40.000 Widgets -> ~2,5 s Freeze beim Start, >150 MB RAM). `GtkColumnView` bricht das 3-Spalten-Layout aus `docs/DESIGN.md:13` (360px Mittelspalte mit 2-zeiligen Mail-Karten: Betreff + Meta-Zeile).
   - *Empfehlung:* **`GtkListView` + `GtkSingleSelection` + `GtkSignalListItemFactory` auf einem `GtkStringList` (oder `gio.ListStore`)**.
     - *Ponytail-Trick für puregotk (keine GObject-Subklassen in Go nötig!):* Als Model dient `gtk.NewStringList(msgIDs)` (speichert nur die `msg_id`-Strings als Index). Im `setup`-Signal der `GtkSignalListItemFactory` wird das `rowWidget` (Box + 3 Labels mit CSS-Klassen) erzeugt (~25 sichtbare Zeilen im Viewport). Im `bind`-Signal liest Go über `stringObject.GetString()` die `msg_id`, schlägt das `MailHeader`-Struct in einer Go-Map `map[string]*MailSummary` nach und setzt `label.SetText(...)`. Damit rendern 10.000 Mails mit **~25 GTK-Widgets** in < 5 ms!
5. **Reader-Pane `cid:`-Aufbau:**
   - Wenn eine Mail Anhänge oder MIME-Inline-Parts mit `Content-ID: <foo>` (oder Dateinamen-Referenz `cid:foo` / `lm-mail://`) enthält, ersetzt der Go-Reader-Builder vor `view.LoadHtml(html, nil)` alle `src="cid:..."`-Attribute durch `src="lm-mail://cid/<msg_id>/<sha256_hex>"`.
   - Die Zuordnung `(msg_id, sha256_hex) -> Metadaten (chunked, mime)` wird im Reader-Controller registriert. Der `lm-mail`-Scheme-Handler prüft, ob `msg_id == currentOpenMsgID` ist (verhindert Cross-Mail-Leaks), lädt/entschlüsselt den Blob asynchron in den `ActiveMailCache` und liefert ihn mit dem geprüften `Content-Type` (`image/png`, `image/jpeg`, `image/gif`, `image/webp` — niemals `text/html` oder `image/svg+xml` wegen Script-in-SVG!) aus.
6. **`lmcli` `os.Exit(1)`-Muster in Fehlerkanal überführen:**
   - *Befund:* `relay/cmd/lmcli/main.go` enthält **38 harte `os.Exit(1)`-Aufrufe** (Zeilen 64, 85, 92, 97, 102, 142, 148, 153, 162, 172, 178, 186, ...). In einer GUI beendet jeder abgelaufene Auth-Token oder Time-out sonst sofort das gesamte Desktop-Programm.
   - *Empfehlung:* Die HTTP-Client-Logik aus `lmcli/main.go` als sauberes Package **`desktop/internal/api/client.go`** extrahieren, in dem **jede** Methode `(T, error)` mit `context.Context` und `http.Client{Timeout: 15 * time.Second}` zurückgibt (und bei `401 Unauthorized` automatisch einmal re-authentifiziert). In der GUI laufen alle `api.*`-Aufrufe in Worker-Goroutinen; Fehler werden in einen `errCh chan error` (bzw. per `glib.IdleAdd`) an einen `adw.ToastOverlay` im Hauptfenster (`toastOverlay.AddToast(adw.NewToast(errMsg))`) gemeldet, gemappt auf die deutschen Texte aus `client/app/main.ts:114-120` (`ERRDE`).

---

### (5) Packaging (Linux Desktop)

**Entscheidungsreife Empfehlung:**
1. **AppImage ohne WebKit-Bundling:**
   - Das AppImage bündelt **nur** das statisch/CGO-frei kompilierte Go-Binary (`usr/bin/lightningmail`), das App-Icon (`usr/share/icons/hicolor/scalable/apps/app.lightningmail.Desktop.svg`), die `.desktop`-Datei und Metainfo.
   - **Keine** `.so`-Libraries von GTK4, libadwaita, GLib, Mesa oder WebKitGTK ins AppDir kopieren! WebKitGTK 6.0 hat hart einkompilierte Pfade auf `/usr/libexec/webkitgtk-6.0/WebKitWebProcess`, `/usr/libexec/webkitgtk-6.0/WebKitNetworkProcess` und `/usr/bin/bwrap` — ein halb gebündeltes WebKit crasht sofort wegen Symbol-/IPC-Mismatch mit der Host-glibc/Mesa.
   - `puregotk` lädt `libgtk-4.so.1` (>= 4.14), `libadwaita-1.so.0` (>= 1.5) und `libwebkitgtk-6.0.so.4` (>= 2.44) zur Laufzeit direkt per `dlopen` vom Host-System (erfüllt auf Debian 13, Ubuntu 24.04+, Fedora 40+, Arch).
   - Im `AppRun`-Wrapper wird vor `exec "$APPDIR/usr/bin/lightningmail" "$@"` per `ldconfig -p` geprüft, ob `libwebkitgtk-6.0.so.4` und `libadwaita-1.so.0` vorhanden sind; fehlt eine Bibliothek, zeigt `AppRun` via `zenity --error` / `notify-send` / `stderr` den exakten `apt install libwebkitgtk-6.0-4 libadwaita-1-0`-Befehl an.
2. **D-Bus- & FUSE-Artefakte:**
   - **D-Bus:** DieApp-ID muss überall konsistent Reverse-DNS sein (`app.lightningmail.Desktop`, **nicht** `.spike` aus `main.go:55`). `dbus-run-session` aus `run-spike.sh:18` darf **niemals** im Produktions-`AppRun` stehen (das würde die App vom echten Desktop-Session-Bus isolieren und `xdg-open`, FileChooser-Portale, `notify-send` sowie Single-Instance-Activation brechen!). Falls ein kaputter Headless-/ Minimal-WM-Userbus `g_application_register` blockiert, reicht als Schutz `gio.GApplicationNonUniqueValue` als Fallback-Flag, wenn kein `DBUS_SESSION_BUS_ADDRESS` gesetzt ist.
   - **FUSE:** AppImage Type-2 benötigt auf Ubuntu 22.04/24.04+ `libfuse2t64` (oft nicht vorinstalliert). Lösung: Das AppImage mit statischer `appimage-runtime` bauen **und** in den Release-Notes `--appimage-extract-and-run` (`APPIMAGE_EXTRACT_AND_RUN=1`) für FUSE-lose Systeme dokumentieren.
3. **Autostart `.desktop`:**
   - Beim Aktivieren der Option „Beim Anmelden im Hintergrund starten" schreibt Go atomar `~/.config/autostart/app.lightningmail.Desktop.desktop` mit `Exec=<pfad-zum-AppImage-oder-Binary> --background`, `X-GNOME-Autostart-enabled=true`, `StartupNotify=false`. Mit `--background` ruft `activate()` kein `win.Present()` auf, sondern hält die App per `app.Hold()` im Hintergrund-Polling und zeigt bei neuen Mails eine `gio.Notification` („Neue Portomail von …"), deren Klick das Hauptfenster via `app.Activate()` öffnet.
4. **`.deb` / Flatpak-Abwägung in einem Satz:**
   - **Ein natives `.deb`-Paket (`Depends: libgtk-4-1 (>= 4.14), libadwaita-1-0 (>= 1.5), libwebkitgtk-6.0-4 (>= 2.44)`) ist neben dem dünnen AppImage das primäre Release-Format für M1 (5 MB groß, 0 Sandbox-Reibung mit WebKit-`bwrap` und `~/.local/share/lightningmail/vault.json`), während Flatpak (`org.gnome.Platform//47`) wegen der Doppel-Sandbox-Komplexität (Flatpak-`bwrap` vs. WebKit-`bwrap` braucht `--socket=session-bus` / Portal-Bridging) erst für M2/Flathub-Distribution lohnt.**

---

### Rote Liste: Was M1 **NICHT** aus M0 / `lmcli` übernehmen darf

1. **`WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1` (`desktop/spike/xvfb-inner.sh:8`)** — niemals im Produktionscode oder AppRun setzen; deaktiviert die Bubblewrap-/Seccomp-Isolation des HTML-Mail-Parsers komplett.
2. **`dbus-run-session` im Startpfad (`desktop/spike/run-spike.sh:18`)** — nur für Xvfb-Tests auf CT114; trennt auf echten Desktops `xdg-open`, Benachrichtigungen und Desktop-Portale ab.
3. **Ungeprüfter Cast `NavigationPolicyDecisionNewFromInternalPtr(decPtr)` + Prefix-Blocklist (`desktop/spike/main.go:110-122`)** — crasht/UB bei `ResponsePolicyDecision` und lässt `file://` oder `NewWindowAction` durch; M1 muss nach `PolicyDecisionType` verzweigen und strikt per Allowlist (`about:blank`, `lm-mail://`) filtern.
4. **`subj.SetMarkup(...)` mit Mail-Daten (`desktop/spike/main.go:158,161,164`) und `strings.Replace` ins HTML (`main.go:176`)** — Pango-Markup-Injection und HTML-XSS; nur `SetText` + CSS-Klassen bzw. Sanitizer + Escaping nutzen.
5. **`defer win.Unref()` in `activate()` (`desktop/spike/main.go:72`) & fehlendes `stream.Unref()` in `handleLMScheme` (`main.go:188-189`)** — vorzeitiges Unref auf das offene Hauptfenster bzw. GObject-Memory-Leak bei jedem geladenen Inline-Bild.
6. **`gio.NewMemoryInputStreamFromData(goSlice, ..., nil)` ohne Copy/Zeroing (`desktop/spike/main.go:188`)** — übergibt Go-GC-Speicher ungeschützt an C und lässt entschlüsselte Anhänge nach dem Schließen der Mail ungenullt im Heap.
7. **Synchrones I/O im `handleLMScheme`-Callback (`desktop/spike/main.go:182`)** — blockiert den GTK-Main-Loop; Downloads und ECIES-Entschlüsselung müssen asynchron in einer Goroutine mit `req.Ref()` + `glib.IdleAdd` laufen.
8. **`gtk.NewListBox()` mit `list.Append()`-Schleife (`desktop/spike/main.go:84-88`)** — skaliert nicht über wenige Hundert Mails; M1 muss `GtkListView` + `GtkSignalListItemFactory` nutzen.
9. **Simulierter Test-Load `view.LoadUri("https://...")` im `load-changed`-Handler (`desktop/spike/main.go:126-135`)** — reiner A4-Spike-Prober, in M1 restlos entfernen.
10. **Die 38 `os.Exit(1)`-Aufrufe und `BMAIL_ACCOUNT`-Env-Abhängigkeit aus `relay/cmd/lmcli/main.go`** — in M1 muss jede Netzwerk-/Krypto-Operation `error` an den UI-Toast-Kanal liefern und Konten aus dem Vault (`~/.local/share/lightningmail/vault.json`) laden.

---
*Ponytail (lite): Keine Code-Dateien geändert (reines Architektur- & Security-Review laut Auftrag); WebKit-C-Header auf CT114 per SSH nicht erneut abgefragt, da `puregotk@v0.5.4` + `puregotk-webkit@v0.1.0` in `desktop/go.mod` und `REPORT.md` bereits verifiziert sind. Risiko: Die Erhöhung von `MaxBlobRefs` (16 -> 255) allein ohne den Manifest-Only-Fix in `send.ts` würde bei Anhängen >15 MiB an der 1300-Byte-Onion-Grenze von LND-Keysend scheitern.*
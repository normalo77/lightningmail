// lmdesk — native lightningmail desktop client, Etappe M1b: READ-ONLY path.
// Login via keyfile against a regtest relay, sync inbox + StateDoc, list on
// the left / WebKit reader on the right, HTML sanitized, cid-images served
// from RAM via lm-mail://. Writing comes in M2, address book/drive in M3.
package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/bnema/purego"
	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gobject"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/bnema/puregotk/v4/pango"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/desktop/core"
	lm1crypto "github.com/lightningmail/lm1/crypto"
)

const appID = "app.lightningmail.Desktop"

// selOpenCB: GtkListSelectionModel "selection-changed" trampoline (kept
// package-level — C holds the pointer forever, Rotliste #1).
var selOpenCB = purego.NewCallback(func(_ uintptr, _ uint, n uint) {
	if ui != nil && n > 0 {
		ui.rowSelected()
	}
})

// ui is the single App instance. C keeps our callback trampolines for the
// process lifetime; everything is bound exactly ONCE in activate (Rotliste
// #1 — never Connect* inside render/update loops).
var ui *App

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("lmdesk ")
	for _, issue := range core.HardenGUI() {
		log.Printf("hygiene: %v", issue)
	}
	warnContainerNoUserNS()

	cfg, err := core.LoadConfig(os.Getenv("LMDESK_CONFIG"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pass := os.Getenv("BMAIL_KEYPASS")

	// M2: keyfile may be wrapped -> login dialog when no env passphrase
	var priv *btcec.PrivateKey
	loadDirect := false
	if pass == "" {
		b, err := os.ReadFile(cfg.Keyfile)
		if err == nil {
			wrapped := lm1crypto.IsWrapped(string(b))
			clear(b)
			if wrapped {
				log.Printf("Keyfile ist gewrappt — Passphrase-Dialog wird angezeigt")
			} else {
				loadDirect = true
			}
		} else {
			loadDirect = true // can't read file, let LoadKeyFile handle the error
		}
	}
	if pass != "" || loadDirect {
		priv, err = core.LoadKeyFile(cfg.Keyfile, pass)
		if err != nil {
			log.Fatalf("keyfile parse: %v", err)
		}
	}
	log.Printf("start: account=%s relay=%s tor_socks=%q", cfg.Name, cfg.Relay, cfg.TorSocks)

	ui = newApp(cfg, priv) // priv may be nil for wrapped key -> login later
	id := appID
	app := adw.NewApplication(&id, gio.GApplicationDefaultFlagsValue)
	defer app.Unref()
	actcb := func(_ gio.Application) { ui.activate(app) }
	app.ConnectActivate(&actcb)
	if code := app.Run(len(os.Args), os.Args); code > 0 {
		os.Exit(code)
	}
}

// warnContainerNoUserNS logs (never acts) when WebKit's bwrap sandbox cannot
// work — Rotliste #1: the DISABLE_SANDBOX env var is headless-CI only.
func warnContainerNoUserNS() {
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil &&
		strings.TrimSpace(string(b)) == "0" {
		log.Printf("WARN: unprivileged userns disabled (container?) — WebKit sandbox needs it; " +
			"headless evidence runs set WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 outside this binary")
	}
}

// navItems mirrors the PWA nav order; only Posteingang is functional in M1.
var navItems = []struct{ label, note string }{
	{"📥 Posteingang", ""},
	{"📤 Gesendet", "sent"},
	{"📝 Entwürfe", "drafts"},
	{"📇 Adressbuch", "ab"},
	{"🗂 Laufwerk", "drv"},
	{"⚙ Einstellungen", "cfg"},
}

func (a *App) activate(app *adw.Application) {
	// Login dialog when priv is nil (keyfile wrapped, no BMAIL_KEYPASS env).
	// The wait MUST NOT block activate() — the GTK main loop has to render
	// and process the dialog itself (M2b bugfix).
	if a.priv == nil {
		// We need a window to present the dialog — build a minimal one first.
		shell := adw.NewApplicationWindow(&app.Application)
		a.win = shell
		t := "lightningmail"
		shell.SetTitle(&t)
		shell.SetDefaultSize(400, 200)
		shell.Present()

		showLoginDialog(shell, a.cfg.Keyfile, a)
		go func() {
			select {
			case pass := <-a.loginResult:
				if pass == "" {
					log.Printf("login: abgebrochen — Exit")
					os.Exit(1)
				}
				priv, err := core.LoadKeyFile(a.cfg.Keyfile, pass)
				if err != nil {
					log.Printf("keyfile parse nach Login: %v", err)
					os.Exit(1)
				}
				a.priv = priv
				a.api = core.NewClient(a.cfg, priv)
				f := glib.SourceOnceFunc(func(_ uintptr) {
					shell.Destroy()
					a.buildUI(app)
				})
				glib.IdleAddOnce(&f, 0)
			case <-time.After(5 * time.Minute):
				log.Printf("login: Timeout")
				os.Exit(1)
			}
		}()
		return
	}
	a.buildUI(app)
}

func (a *App) buildUI(app *adw.Application) {
	win := adw.NewApplicationWindow(&app.Application)
	a.win = win
	t := "lightningmail"
	win.SetTitle(&t)
	win.SetDefaultSize(1200, 760)

	toolbar := adw.NewToolbarView()
	hdr := adw.NewHeaderBar()
	wt := adw.NewWindowTitle("lightningmail", a.cfg.Name)
	hdr.SetTitleWidget(&wt.Widget)
	a.balanceLabel = newLabel("Guthaben: …", "dim-label", "caption")
	hdr.PackEnd(&a.balanceLabel.Widget)

	// M2: [+] compose button
	composeBtn := gtk.NewButton()
	composeBtn.SetLabel("✏️ Schreiben")
	composeBtn.AddCssClass("suggested-action")
	composeCb := func(_ gtk.Button) {
		showComposeDialog(win, a, nil)
	}
	composeBtn.ConnectClicked(&composeCb)
	hdr.PackStart(&composeBtn.Widget)

	toolbar.AddTopBar(&hdr.Widget)

	a.statusLabel = newLabel("verbinde…", "dim-label", "caption")
	a.statusLabel.SetXalign(0)
	a.statusLabel.SetMarginStart(10)
	a.statusLabel.SetMarginEnd(10)
	a.statusLabel.SetMarginTop(4)
	a.statusLabel.SetMarginBottom(4)
	toolbar.AddBottomBar(&a.statusLabel.Widget)

	// --- sidebar (PWA nav order; M2: sent+drafts active) ---
	side := gtk.NewListBox()
	side.SetSelectionMode(gtk.SelectionNoneValue)
	side.AddCssClass("navigation-sidebar")
	side.SetSizeRequest(220, -1)
	side.SetValign(gtk.AlignStartValue)
	for _, it := range navItems {
		b := gtk.NewButton()
		b.SetLabel(it.label)
		b.SetHasFrame(false)
		note := it.note
		label := it.label
		if note == "" || note == "sent" || note == "drafts" {
			b.AddCssClass("accent")
		}
		switch note {
		case "":
			// Posteingang: already functional from M1, no extra handler needed
		case "sent", "drafts", "ab", "drv":
			fm := note
			cb := func(_ gtk.Button) { a.switchFolder(fm) }
			b.ConnectClicked(&cb)
		case "cfg":
			// Umsaetze live INSIDE settings (Bernd) — no primary nav item.
			cb := func(_ gtk.Button) { a.stack.SetVisibleChildName("cfg") }
			b.ConnectClicked(&cb)
		default:
			_cb := func(_ gtk.Button) {
				msg := label + ": folgt in Etappe " + note
				log.Printf("nav placeholder: %s", msg)
				a.toast(msg)
				a.setStatus(msg)
			}
			b.ConnectClicked(&_cb)
		}
		side.Append(&b.Widget)
	}

	// --- mail list: GtkListView + SignalListItemFactory (Rotliste #8) ---
	a.listModel = gtk.NewStringList([]string{})
	a.sel = gtk.NewSingleSelection(a.listModel)
	a.sel.SetAutoselect(false)
	a.sel.SetCanUnselect(true)
	factory := gtk.NewSignalListItemFactory()
	setupCb := func(_ gtk.SignalListItemFactory, itemPtr uintptr) { a.rowSetup(itemPtr) }
	bindCb := func(_ gtk.SignalListItemFactory, itemPtr uintptr) { a.rowBind(itemPtr) }
	factory.ConnectSetup(&setupCb)
	factory.ConnectBind(&bindCb)
	a.listView = gtk.NewListView(a.sel, &factory.ListItemFactory)
	a.listView.SetShowSeparators(true)
	a.listView.SetSingleClickActivate(true)
	activateCb := func(_ gtk.ListView, pos uint) {
		a.lastInteraction = time.Now()
		a.openMail(pos)
	}
	a.listView.ConnectActivate(&activateCb)
	// The ListView 'activate' signal never fires in this GTK build (tested
	// single/double click + Enter via xdotool, GTK 4.x trixie) — opening on
	// selection gives the same mail-client UX; selection verifiably works.
	gobject.SignalConnect(a.sel.GoPointer(), "selection-changed", selOpenCB)
	listScroll := gtk.NewScrolledWindow()
	listScroll.SetChild(&a.listView.Widget)
	listScroll.SetSizeRequest(360, -1)
	listScroll.SetPolicy(gtk.PolicyNeverValue, gtk.PolicyAutomaticValue)
	listScroll.SetVexpand(true)

	left := gtk.NewBox(gtk.OrientationHorizontalValue, 0)
	left.Append(&side.Widget)
	left.Append(&listScroll.Widget)

	// --- reader (WebKit, ephemeral session, lm-mail:// from RAM) ---
	a.reader = a.newReader()
	a.reader.SetVexpand(true)
	a.reader.SetHexpand(true)

	// M2: native action bar ABOVE the reader — always visible, no scrolling
	actions := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	actions.SetMarginStart(10)
	actions.SetMarginTop(6)
	actions.SetMarginBottom(2)
	a.replyBtn = gtk.NewButton()
	a.replyBtn.SetLabel("↩ Antworten")
	a.deleteBtn = gtk.NewButton()
	a.deleteBtn.SetLabel("🗑 Löschen")
	a.deleteBtn.AddCssClass("destructive-action")
	a.replyBtn.SetSensitive(false)
	a.deleteBtn.SetSensitive(false)
	rcb := func(_ gtk.Button) { a.handleReply() }
	dcb := func(_ gtk.Button) { a.handleDelete() }
	a.replyBtn.ConnectClicked(&rcb)
	a.deleteBtn.ConnectClicked(&dcb)
	actions.Append(&a.replyBtn.Widget)
	actions.Append(&a.deleteBtn.Widget)
	a.abImportBtn = gtk.NewButton()
	a.abImportBtn.SetLabel("👤→📇")
	tip := "Absender ins Adressbuch übernehmen"
	a.abImportBtn.SetTooltipText(&tip)
	a.abImportBtn.SetSensitive(false)
	imcb := func(_ gtk.Button) { a.importSenderContact() }
	a.abImportBtn.ConnectClicked(&imcb)
	actions.Append(&a.abImportBtn.Widget)
	right := gtk.NewBox(gtk.OrientationVerticalValue, 0)
	right.Append(&actions.Widget)
	right.Append(&a.reader.Widget)

	// M3: mail | ab | drv | cfg live in one GtkStack on the right.
	a.stack = gtk.NewStack()
	mailN, abN, drvN, cfgN := "mail", "ab", "drv", "cfg"
	a.stack.AddTitled(&right.Widget, &mailN, "Mail")
	a.stack.AddTitled(a.buildAbPage(), &abN, "Kontakte")
	a.stack.AddTitled(a.buildDrvPage(), &drvN, "Laufwerk")
	a.stack.AddTitled(a.buildSettingsPage(), &cfgN, "Einstellungen")

	paned := gtk.NewPaned(gtk.OrientationHorizontalValue)
	paned.SetStartChild(&left.Widget)
	paned.SetEndChild(&a.stack.Widget)
	paned.SetPosition(580)
	paned.SetResizeStartChild(false)
	paned.SetResizeEndChild(true)
	paned.SetShrinkStartChild(false)

	a.toastOverlay = adw.NewToastOverlay()
	a.toastOverlay.SetChild(&paned.Widget)
	toolbar.SetContent(&a.toastOverlay.Widget)
	win.SetContent(&toolbar.Widget)

	closeCb := func(_ gtk.Window) bool {
		log.Printf("shutdown: cache loeschen (%d Eintraege)", a.cache.Len())
		close(a.quit)
		a.cache.Clear() // zero decrypted bytes on shutdown (Rotliste §3.4)
		return false    // allow the close
	}
	win.ConnectCloseRequest(&closeCb)

	win.Present()
	go a.syncLoop()
	log.Printf("UI steht (1200x760), sync-loop gestartet")
}

func newLabel(text string, classes ...string) *gtk.Label {
	l := gtk.NewLabel(&text)
	l.SetEllipsize(pango.EllipsizeEndValue)
	for _, c := range classes {
		l.AddCssClass(c)
	}
	return l
}

func (a *App) toast(msg string) {
	if a.toastOverlay != nil {
		a.toastOverlay.AddToast(adw.NewToast(msg))
	}
}

func (a *App) setStatus(s string) {
	if a.statusLabel != nil {
		a.statusLabel.SetText(s)
	}
}

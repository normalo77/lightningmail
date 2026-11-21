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

	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/bnema/puregotk/v4/pango"
	"github.com/lightningmail/desktop/core"
	"github.com/lightningmail/lm1/crypto"
)

const appID = "app.lightningmail.Desktop"

// ui is the single App instance. C keeps our callback trampolines for the
// process lifetime; everything is bound exactly ONCE in activate (Rotliste
// #1 — never Connect* inside render/update loops).
var ui *App

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("lmdesk ")
	for _, issue := range core.Harden() { // M-SEC.1 hygiene, best effort — never aborts
		log.Printf("hygiene: %v", issue)
	}
	warnContainerNoUserNS()

	cfg, err := core.LoadConfig(os.Getenv("LMDESK_CONFIG"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pass := os.Getenv("BMAIL_KEYPASS")
	if pass == "" { // GUI M1 has no dialog window yet — fail with a clear hint.
		if b, err := os.ReadFile(cfg.Keyfile); err == nil {
			wrapped := crypto.IsWrapped(string(b))
			clear(b)
			if wrapped {
				log.Fatal("keyfile ist gewrappt — BMAIL_KEYPASS setzen; gefuehrter Prompt folgt mit dem M2-Login-Dialog.")
			}
		}
	}
	priv, err := core.LoadKeyFile(cfg.Keyfile, pass) // zeroes its read buffer (M-SEC.1)
	if err != nil {
		log.Fatalf("keyfile parse: %v", err)
	}
	log.Printf("start: account=%s relay=%s tor_socks=%q", cfg.Name, cfg.Relay, cfg.TorSocks)

	ui = newApp(cfg, priv)
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
	{"📤 Gesendet", "M2"},
	{"📝 Entwürfe", "M2"},
	{"📇 Adressbuch", "M3"},
	{"🗂 Laufwerk", "M3"},
	{"💶 Umsätze", "M3"},
	{"⚙ Einstellungen", "M2"},
}

func (a *App) activate(app *adw.Application) {
	// No defer win.Unref() — Rotliste #5: the window outlives activate().
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
	toolbar.AddTopBar(&hdr.Widget)

	a.statusLabel = newLabel("verbinde…", "dim-label", "caption")
	a.statusLabel.SetXalign(0)
	a.statusLabel.SetMarginStart(10)
	a.statusLabel.SetMarginEnd(10)
	a.statusLabel.SetMarginTop(4)
	a.statusLabel.SetMarginBottom(4)
	toolbar.AddBottomBar(&a.statusLabel.Widget)

	// --- sidebar (PWA nav order; five honest placeholders) ---
	side := gtk.NewListBox()
	side.SetSelectionMode(gtk.SelectionNoneValue)
	side.AddCssClass("navigation-sidebar")
	side.SetSizeRequest(220, -1)
	side.SetValign(gtk.AlignStartValue)
	for _, it := range navItems {
		b := gtk.NewButton()
		b.SetLabel(it.label)
		b.SetHasFrame(false)
		if it.note == "" {
			b.AddCssClass("accent") // the one functional entry (M1)
		} else {
			label := it.label
			note := it.note
			cb := func(_ gtk.Button) {
				msg := label + ": folgt in Etappe " + note
				log.Printf("nav placeholder: %s", msg)
				a.toast(msg)
				a.setStatus(msg)
			}
			b.ConnectClicked(&cb)
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

	paned := gtk.NewPaned(gtk.OrientationHorizontalValue)
	paned.SetStartChild(&left.Widget)
	paned.SetEndChild(&a.reader.Widget)
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

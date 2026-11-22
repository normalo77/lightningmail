package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/bnema/puregotk/v4/pango"
	"github.com/lightningmail/desktop/core"
)

// Einstellungen page (Etappe M3 + T): home relay, Tor SOCKS5 (Etappe T),
// RAM cache size, autostart — plus the Umsaetze list UNDER settings per
// Bernd's instruction (it is not a primary nav item on desktop).
// Widgets are built once in buildUI; this file only wires + refreshes.

func (a *App) buildSettingsPage() *gtk.Widget {
	scroll := gtk.NewScrolledWindow()
	box := gtk.NewBox(gtk.OrientationVerticalValue, 8)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(14)
	box.SetMarginBottom(14)

	section := func(title string) *gtk.Label {
		l := newLabel(title, "heading")
		l.SetXalign(0)
		l.SetMarginTop(10)
		box.Append(&l.Widget)
		return l
	}
	row := func(label string) *gtk.Entry {
		r := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
		l := newLabel(label, "dim-label")
		l.SetSizeRequest(170, -1)
		l.SetXalign(0)
		e := gtk.NewEntry()
		e.SetHexpand(true)
		r.Append(&l.Widget)
		r.Append(&e.Widget)
		box.Append(&r.Widget)
		return e
	}

	section("Verbindung")
	a.cfgRelayEntry = row("Home-Relay (URL):")
	a.cfgRelayEntry.SetText(a.cfg.Relay)
	a.cfgTorEntry = row("Tor SOCKS5:")
	a.cfgTorEntry.SetText(a.cfg.TorSocks)
	hint := newLabel("Etappe T: z. B. 127.0.0.1:9050 — erreicht .onion-Relays und kapselt den Client-Traffic in Tor. Leer = direkt.", "dim-label", "caption")
	hint.SetWrap(true)
	hint.SetXalign(0)
	box.Append(&hint.Widget)

	section("Speicher")
	a.cfgCacheEntry = row("Cache (MiB):")
	mb := a.cfg.CacheMB
	if mb == 0 {
		mb = 32
	}
	a.cfgCacheEntry.SetText(strconv.Itoa(mb))

	section("Start")
	autorow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	al := newLabel("Autostart (Anmeldung)", "dim-label")
	al.SetSizeRequest(170, -1)
	al.SetXalign(0)
	a.cfgAutoSwitch = gtk.NewSwitch()
	a.cfgAutoSwitch.SetState(autostartEnabled())
	achCb := func(_ gtk.Switch, want bool) bool {
		if err := setAutostart(want); err != nil {
			a.errToast(err)
			a.cfgAutoSwitch.SetState(!want) // revert visual
			return true
		}
		if want {
			a.toast("Autostart aktiviert")
		} else {
			a.toast("Autostart deaktiviert")
		}
		return true
	}
	a.cfgAutoSwitch.ConnectStateSet(&achCb)
	autorow.Append(&al.Widget)
	autorow.Append(&a.cfgAutoSwitch.Widget)
	box.Append(&autorow.Widget)

	saveBtn := gtk.NewButton()
	saveBtn.SetLabel(" Einstellungen speichern")
	saveBtn.AddCssClass("suggested-action")
	saveBtn.SetHalign(gtk.AlignStartValue)
	scb := func(_ gtk.Button) { a.saveSettings() }
	saveBtn.ConnectClicked(&scb)
	box.Append(&saveBtn.Widget)

	section("💶 Umsätze")
	umsBtns := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	refresh := gtk.NewButton()
	refresh.SetLabel("🔄 Aktualisieren")
	rcb := func(_ gtk.Button) { a.refreshStatement() }
	refresh.ConnectClicked(&rcb)
	csv := gtk.NewButton()
	csv.SetLabel("⬇ CSV exportieren…")
	ccb := func(_ gtk.Button) { a.exportStatementCSV() }
	csv.ConnectClicked(&ccb)
	a.umsStatus = newLabel("", "dim-label", "caption")
	umsBtns.Append(&refresh.Widget)
	umsBtns.Append(&csv.Widget)
	umsBtns.Append(&a.umsStatus.Widget)
	box.Append(&umsBtns.Widget)

	a.umsList = gtk.NewListBox()
	a.umsList.AddCssClass("boxed-list")
	inner := gtk.NewBox(gtk.OrientationVerticalValue, 6)
	inner.Append(&a.umsList.Widget)
	inner.SetVexpand(true)
	box.Append(&inner.Widget)

	scroll.SetChild(&box.Widget)
	return &scroll.Widget
}

func (a *App) saveSettings() {
	relay := strings.TrimSpace(a.cfgRelayEntry.GetText())
	tor := strings.TrimSpace(a.cfgTorEntry.GetText())
	mb, _ := strconv.Atoi(strings.TrimSpace(a.cfgCacheEntry.GetText()))
	if relay == "" || a.cfg.Name == "" {
		a.toast("Relay-URL fehlt")
		return
	}
	if tor != "" {
		if _, err := core.ParseTorSocks(tor); err != nil {
			a.toast("Ungültige Tor-SOCKS5-Adresse (z. B. 127.0.0.1:9050)")
			return
		}
	}
	oldTor, oldRelay := a.cfg.TorSocks, a.cfg.Relay
	a.cfg.Relay = relay
	a.cfg.TorSocks = tor
	if mb > 0 {
		a.cfg.CacheMB = mb
	} else {
		a.cfg.CacheMB = 0
	}
	if err := a.cfg.Save(); err != nil {
		a.errToast(err)
		return
	}
	// Tor routing can go live immediately (fresh transport, re-auth on first
	// 401). Relay/cache changes take effect on restart — say so honestly.
	if tor != oldTor {
		a.setClient(core.NewClient(a.cfg, a.priv))
		a.toast("Tor-Einstellung aktiv (sofort)")
	}
	if relay != oldRelay {
		a.toast("Relay-Wechsel wirksam nach Neustart")
	} else if mb != 0 {
		a.toast("Gespeichert — Cache-Größe gilt nach Neustart")
	}
	log.Printf("settings: relay=%s tor=%q cacheMB=%d", relay, tor, a.cfg.CacheMB)
}

// --- autostart (.desktop in XDG autostart dir) ---

func autostartDesktopPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autostart", appID+".desktop"), nil
}

func autostartEnabled() bool {
	p, err := autostartDesktopPath()
	if err != nil {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func setAutostart(enable bool) error {
	p, err := autostartDesktopPath()
	if err != nil {
		return err
	}
	if !enable {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe := os.Getenv("APPIMAGE")
	if exe == "" {
		exe, err = os.Executable()
		if err != nil {
			return err
		}
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	content := "[Desktop Entry]\nType=Application\nName=lightningmail\nExec=" + exe +
		"\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
	return os.WriteFile(p, []byte(content), 0644)
}

// --- Umsätze (statement) ---

func (a *App) refreshStatement() {
	a.umsStatus.SetText("lade…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rows, err := a.client().Statement(ctx)
		f := glib.SourceOnceFunc(func(_ uintptr) {
			if err != nil {
				a.umsStatus.SetText("Fehler: " + err.Error())
				return
			}
			a.umsList.RemoveAll()
			// newest first (server returns chain order asc)
			for i := len(rows) - 1; i >= 0; i-- {
				x := rows[i]
				line := fmt.Sprintf("%s · %s · %d sats", x.Zeit, artLabel(x.Art), x.Sat)
				if x.Eur != nil {
					line += fmt.Sprintf(" · %.4f €", *x.Eur)
				}
				if x.Ref != "" {
					line += " · " + x.Ref
				}
				lbl := newLabel(line, "caption")
				lbl.SetXalign(0)
				lbl.SetEllipsize(pango.EllipsizeEndValue)
				a.umsList.Append(&lbl.Widget)
			}
			a.umsStatus.SetText(fmt.Sprintf("%d Buchungen", len(rows)))
		})
		glib.IdleAddOnce(&f, 0)
	}()
}

func artLabel(kind string) string {
	switch kind {
	case "fee":
		return " Porto"
	case "topup":
		return "⚡ Aufladung"
	case "refund":
		return "↩ Erstattung"
	case "signup":
		return "🔑 Porto-Vorschuss"
	case "withdraw":
		return "⬇ Auszahlung"
	default:
		return kind
	}
}

func (a *App) exportStatementCSV() {
	fileSave(&a.win.ApplicationWindow.Window, "statement.csv", "Umsätze als CSV speichern", func(path string) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			raw, err := a.client().CsvStatement(ctx)
			f := glib.SourceOnceFunc(func(_ uintptr) {
				if err != nil {
					a.errToast(err)
					return
				}
				if err := writeFileAbs(path, raw); err != nil {
					a.errToast(err)
					return
				}
				a.toast("CSV gespeichert")
			})
			glib.IdleAddOnce(&f, 0)
		}()
	})
}

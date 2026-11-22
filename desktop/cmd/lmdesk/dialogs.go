package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/gtk"
)

// Shared dialog helpers for M3 (form dialogs, one-line prompt, confirm).
// All are async like GTK demands: results leave via callbacks, never by
// blocking return values (Rotliste #1).

// formDialog is an adw.Dialog with a header (Abbrechen/Speichern) and a
// vertically stacked form area the caller fills with rows.
type formDialog struct {
	dialog     *adw.Dialog
	form       *gtk.Box
	status     *gtk.Label
	onOk       func()
	formScroll *gtk.ScrolledWindow
}

func newFormDialog(title string, w, h int) *formDialog {
	fd := &formDialog{}
	fd.dialog = adw.NewDialog()
	fd.dialog.SetTitle(title)
	fd.dialog.SetPresentationMode(adw.DialogAutoValue)
	fd.dialog.SetContentWidth(w)
	fd.dialog.SetContentHeight(h)

	tt := adw.NewToolbarView()
	hdr := adw.NewHeaderBar()
	wt := adw.NewWindowTitle(title, "")
	hdr.SetTitleWidget(&wt.Widget)

	cancelBtn := gtk.NewButton()
	cancelBtn.SetLabel("Abbrechen")
	ccb := func(_ gtk.Button) { fd.dialog.Close() }
	cancelBtn.ConnectClicked(&ccb)
	hdr.PackStart(&cancelBtn.Widget)

	okBtn := gtk.NewButton()
	okBtn.SetLabel("💾 Speichern")
	okBtn.AddCssClass("suggested-action")
	ocb := func(_ gtk.Button) {
		if fd.onOk != nil {
			fd.onOk() // caller closes the dialog itself on validation failure
			return
		}
		fd.dialog.Close()
	}
	okBtn.ConnectClicked(&ocb)
	hdr.PackEnd(&okBtn.Widget)
	tt.AddTopBar(&hdr.Widget)

	fd.form = gtk.NewBox(gtk.OrientationVerticalValue, 6)
	fd.form.SetMarginStart(16)
	fd.form.SetMarginEnd(16)
	fd.form.SetMarginTop(12)
	fd.form.SetMarginBottom(12)
	fd.formScroll = gtk.NewScrolledWindow()
	fd.formScroll.SetChild(&fd.form.Widget)
	fd.formScroll.SetVexpand(true)

	fd.status = newLabel("", "dim-label", "caption")
	fd.status.SetXalign(0)
	wrap := gtk.NewBox(gtk.OrientationVerticalValue, 0)
	wrap.Append(&fd.formScroll.Widget)
	wrap.Append(&fd.status.Widget)
	tt.SetContent(&wrap.Widget)
	fd.dialog.SetChild(&tt.Widget)
	return fd
}

func (fd *formDialog) present(parent *gtk.Widget) { fd.dialog.Present(parent) }

// formRow appends a labelled entry line and returns the entry.
func (fd *formDialog) formRow(label, initial string) *gtk.Entry {
	row := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	lbl := newLabel(label, "dim-label")
	lbl.SetSizeRequest(170, -1)
	lbl.SetXalign(0)
	e := gtk.NewEntry()
	e.SetHexpand(true)
	if initial != "" {
		e.SetText(initial)
	}
	row.Append(&lbl.Widget)
	row.Append(&e.Widget)
	fd.form.Append(&row.Widget)
	return e
}

// promptText shows a single-entry dialog; cb("") on cancel.
func (a *App) promptText(title, label, initial string, cb func(string)) {
	dialog := adw.NewDialog()
	dialog.SetTitle(title)
	dialog.SetPresentationMode(adw.DialogAutoValue)
	dialog.SetContentWidth(400)

	tt := adw.NewToolbarView()
	content := gtk.NewBox(gtk.OrientationVerticalValue, 8)
	content.SetMarginStart(16)
	content.SetMarginEnd(16)
	content.SetMarginTop(12)
	content.SetMarginBottom(12)
	l := newLabel(label)
	l.SetXalign(0)
	e := gtk.NewEntry()
	e.SetHexpand(true)
	if initial != "" {
		e.SetText(initial)
		e.GrabFocus()
	}
	content.Append(&l.Widget)
	content.Append(&e.Widget)
	tt.SetContent(&content.Widget)
	dialog.SetChild(&tt.Widget)

	var once sync.Once
	done := func(v string) { once.Do(func() { cb(v) }) }

	cancelCb := func(_ gtk.Button) { dialog.Close() }
	okCb := func(_ gtk.Button) {
		done(e.GetText())
		dialog.Close()
	}
	actCb := func(_ gtk.Entry) {
		done(e.GetText())
		dialog.Close()
	}
	closeCb := func(_ adw.Dialog) { done("") }

	btnRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	btnRow.SetHalign(gtk.AlignEndValue)
	btnRow.SetMarginBottom(12)
	cancelBtn := gtk.NewButton()
	cancelBtn.SetLabel("Abbrechen")
	cancelBtn.ConnectClicked(&cancelCb)
	okBtn := gtk.NewButton()
	okBtn.SetLabel("OK")
	okBtn.AddCssClass("suggested-action")
	okBtn.ConnectClicked(&okCb)
	btnRow.Append(&cancelBtn.Widget)
	btnRow.Append(&okBtn.Widget)
	content.Append(&btnRow.Widget)

	e.ConnectActivate(&actCb)
	dialog.ConnectClosed(&closeCb)
	dialog.Present(&a.win.ApplicationWindow.Widget)
}

// confirm uses GtkAlertDialog (native, no custom buttons to wire).
func (a *App) confirm(msg string, cb func(bool)) {
	ad := gtk.NewAlertDialog(msg)
	ad.SetButtons([]string{"Abbrechen", "Okay"})
	ad.SetDefaultButton(1)
	ready := gio.AsyncReadyCallback(func(_, resPtr, _ uintptr) {
		res := &gio.AsyncResultBase{Ptr: resPtr}
		idx, err := ad.ChooseFinish(res)
		cb(err == nil && idx == 1)
	})
	ad.Choose(&a.win.ApplicationWindow.Window, nil, &ready, 0)
}

// info shows a one-button notice dialog (errors, hints).
func (a *App) info(msg string) {
	ad := gtk.NewAlertDialog(msg)
	ad.SetButtons([]string{"OK"})
	ready := gio.AsyncReadyCallback(func(_, _, _ uintptr) {})
	ad.Choose(&a.win.ApplicationWindow.Window, nil, &ready, 0)
}

func (a *App) errToast(err error) {
	log.Printf("fehler: %v", err)
	a.toast("Fehler: " + err.Error())
}

func randID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// fileDialog helpers (GTK 4.10 FileDialog; paths only — shortcut: gio URIs
// non-file:// are not followed, the desktop talks to the local FS).
func fileSave(parent *gtk.Window, suggestName, title string, cb func(path string)) {
	fd := gtk.NewFileDialog()
	if title != "" {
		fd.SetTitle(title)
	}
	n := suggestName
	fd.SetInitialName(&n)
	ready := gio.AsyncReadyCallback(func(_, resPtr, _ uintptr) {
		res := &gio.AsyncResultBase{Ptr: resPtr}
		f, err := fd.SaveFinish(res)
		if err != nil || f == nil {
			return
		}
		if p := f.GetPath(); p != "" {
			cb(p)
		}
	})
	fd.Save(parent, nil, &ready, 0)
}

func writeFileAbs(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func readFileAbs(path string) ([]byte, error) { return os.ReadFile(path) }

func basename(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

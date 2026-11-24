package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/bnema/puregotk/v4/pango"
	"github.com/lightningmail/desktop/core"
)

// M3 panels: address book + drive reuse the shared list column (StringList
// keys "c:<id>" / "f:<id>"); details show in the right-hand GtkStack pages
// "ab" and "drv". Settings is page "cfg" (settings.go). Bindings happen
// exactly once at build time (Rotliste #1).

// --- address book ---

// abFields mirrors the PWA ABFIELDS table: state.ts field -> label. New
// field = one line here + one in core.Contact.
var abFields = []struct{ key, label string }{
	{"name", "Name (Anzeige)"}, {"given", "Vorname"}, {"org", "Organisation"},
	{"title", "Rolle"}, {"url", "Web"}, {"cell", "Mobil"}, {"phone", "Telefon"},
	{"fax", "Fax"}, {"email", "E-Mail"}, {"addr", "Adresse"}, {"lnaddr", "LN-Adresse"},
	{"btc", "BTC"}, {"crypto", "Crypto"}, {"pubkey", "Public Key"}, {"pgp", "PGP"},
	{"note", "Notiz"},
}

func setContactField(c *core.Contact, key, val string) {
	switch key {
	case "name":
		c.Name = val
	case "given":
		c.Given = val
	case "org":
		c.Org = val
	case "title":
		c.Title = val
	case "url":
		c.URL = val
	case "cell":
		c.Cell = val
	case "phone":
		c.Phone = val
	case "fax":
		c.Fax = val
	case "email":
		c.Email = val
	case "addr":
		c.Addr = val
	case "lnaddr":
		c.Lnaddr = val
	case "btc":
		c.BTC = val
	case "crypto":
		c.Crypto = val
	case "pubkey":
		c.Pubkey = val
	case "pgp":
		c.PGP = val
	case "note":
		c.Note = val
	}
}

func getContactField(c core.Contact, key string) string {
	switch key {
	case "name":
		return c.Name
	case "given":
		return c.Given
	case "org":
		return c.Org
	case "title":
		return c.Title
	case "url":
		return c.URL
	case "cell":
		return c.Cell
	case "phone":
		return c.Phone
	case "fax":
		return c.Fax
	case "email":
		return c.Email
	case "addr":
		return c.Addr
	case "lnaddr":
		return c.Lnaddr
	case "btc":
		return c.BTC
	case "crypto":
		return c.Crypto
	case "pubkey":
		return c.Pubkey
	case "pgp":
		return c.PGP
	case "note":
		return c.Note
	}
	return ""
}

// showContactForm edits or creates a contact. The full record is saved
// (editor prefills from prev); core.SaveContact does resurrect + restamp.
func showContactForm(parent *gtk.Widget, a *App, existing *core.Contact) {
	fd := newFormDialog("Kontakt", 620, 640)
	entries := map[string]*gtk.Entry{}
	for _, f := range abFields {
		init := ""
		if existing != nil {
			init = getContactField(*existing, f.key)
		}
		entries[f.key] = fd.formRow(f.label, init)
	}
	fd.onOk = func() {
		c := core.Contact{}
		if existing != nil {
			c = *existing
		}
		if c.ID == "" {
			c.ID = randID(8)
		}
		for k, e := range entries {
			setContactField(&c, k, strings.TrimSpace(e.GetText()))
		}
		if core.ContactDisplay(c) == c.ID { // completely empty record
			fd.status.SetText("Mindestens ein Feld ausfüllen (Name, E-Mail, …)")
			return
		}
		a.mu.Lock()
		a.doc.SaveContact(c)
		a.mu.Unlock()
		a.schedulePush()
		a.refreshFolderList()
		log.Printf("kontakt gespeichert id=%s", c.ID)
		fd.dialog.Close()
	}
	fd.present(parent)
}

func (a *App) newContact() {
	showContactForm(&a.win.ApplicationWindow.Widget, a, nil)
}

// importSenderContact adds/merges the open mail's sender (id keyed by pubkey
// so the same sender merges into one record on every device).
func (a *App) importSenderContact() {
	a.mu.Lock()
	var c core.Contact
	found := false
	if m := a.byID[a.currentMsgID]; m != nil {
		id := "pk:" + m.SenderPub
		if ex, ok := a.doc.Contacts[id]; ok {
			c = ex
		} else {
			c = core.Contact{ID: id, Pubkey: m.SenderPub}
		}
		found = true
	}
	a.mu.Unlock()
	if found {
		showContactForm(&a.win.ApplicationWindow.Widget, a, &c)
	}
}

func (a *App) showContactDetail(key string) {
	id := key[2:]
	a.mu.Lock()
	c, ok := a.doc.Contacts[id]
	a.mu.Unlock()
	a.stack.SetVisibleChildName("ab")
	if !ok || c.Gone != 0 {
		return
	}
	for _, d := range a.abDetail {
		d.row.SetVisible(false)
	}
	used := 0
	for _, f := range abFields {
		v := getContactField(c, f.key)
		if v == "" || used >= len(a.abDetail) {
			continue
		}
		d := a.abDetail[used]
		d.key.SetText(f.label)
		d.val.SetText(v)
		d.val.SetWrap(true)
		d.val.SetSelectable(true)
		d.val.SetEllipsize(pango.EllipsizeNoneValue)
		d.val.SetXalign(0)
		d.row.SetVisible(true)
		used++
	}
	a.curContactID = id
	a.abMailBtn.SetSensitive(c.Lnaddr != "" || c.Email != "")
}

func (a *App) abWriteMail() {
	a.mu.Lock()
	c := a.doc.Contacts[a.curContactID]
	a.mu.Unlock()
	to := c.Lnaddr
	if to == "" {
		to = c.Email
	}
	showComposeDialog(a.win, a, &composeSeed{To: to})
}

func (a *App) abEdit() {
	a.mu.Lock()
	c, ok := a.doc.Contacts[a.curContactID]
	a.mu.Unlock()
	if !ok {
		return
	}
	showContactForm(&a.win.ApplicationWindow.Widget, a, &c)
}

func (a *App) abDelete() {
	a.mu.Lock()
	c := a.doc.Contacts[a.curContactID]
	a.mu.Unlock()
	a.confirm("🗑 Kontakt „"+core.ContactDisplay(c)+"“ löschen?", func(yes bool) {
		if !yes {
			return
		}
		a.mu.Lock()
		a.doc.DelContact(c.ID)
		a.mu.Unlock()
		a.schedulePush()
		a.refreshFolderList()
		a.toast("Kontakt gelöscht")
	})
}

// --- drive ---

// driveEntries: live entries inside the current folder; dirs first, both
// alphabetical (the PWA drv sort order). Caller must NOT hold a.mu.
func (a *App) driveEntries() []core.DriveEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var dirs, files []core.DriveEntry
	for _, e := range a.doc.Files {
		if e.Gone != 0 || e.Parent != a.driveParent {
			continue
		}
		if e.Kind == "d" {
			dirs = append(dirs, e)
		} else {
			files = append(files, e)
		}
	}
	nameSort(dirs)
	nameSort(files)
	return append(dirs, files...)
}

func nameSort(x []core.DriveEntry) {
	for i := 1; i < len(x); i++ {
		for j := i; j > 0 && x[j].Name < x[j-1].Name; j-- {
			x[j], x[j-1] = x[j-1], x[j]
		}
	}
}

// driveCrumbName renders "Ordner / Unterordner" of the current folder.
func (a *App) driveCrumbName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var names []string
	cur := a.driveParent
	for guard := 0; cur != "" && guard < 32; guard++ {
		e, ok := a.doc.Files[cur]
		if !ok {
			break
		}
		names = append([]string{e.Name}, names...)
		cur = e.Parent
	}
	return strings.Join(names, " / ")
}

// openDrive reacts to an "f:" row: folders descend, files show details.
func (a *App) openDrive(key string) {
	id := key[2:]
	a.mu.Lock()
	e, ok := a.doc.Files[id]
	a.mu.Unlock()
	if !ok || e.Gone != 0 {
		return
	}
	if e.Kind == "d" {
		a.driveParent = id
		a.refreshFolderList()
		return
	}
	a.curFileID = id
	lines := []string{
		"📄 " + e.Name,
		fmt.Sprintf("Größe: %s · gespeichert (verschlüsselt): %s", fmtSize(e.SizePlain), fmtSize(e.Size)),
		"Typ: " + orNone(e.Mime),
	}
	if c := a.driveCrumbName(); c != "" {
		lines = append(lines, "Pfad: /"+c)
	}
	a.drvInfo.SetText(strings.Join(lines, "\n"))
	a.drvDownBtn.SetSensitive(e.Msha != "")
	a.drvDelBtn.SetSensitive(true)
	a.drvRenameBtn.SetSensitive(true)
	a.stack.SetVisibleChildName("drv")
}

func orNone(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func fmtSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1000:
		return fmt.Sprintf("%.1f kB", float64(b)/1000)
	}
	return fmt.Sprintf("%d B", b)
}

func (a *App) driveUpload() {
	fd := gtk.NewFileDialog()
	fd.SetTitle("Datei ins Laufwerk legen")
	cb := gio.AsyncReadyCallback(func(_, resPtr, _ uintptr) {
		res := &gio.AsyncResultBase{Ptr: resPtr}
		f, err := fd.OpenFinish(res)
		if err != nil || f == nil {
			return
		}
		path := f.GetPath()
		if path == "" {
			a.toast("Nur lokale Dateien werden unterstützt")
			return
		}
		a.uploadDrivePath(path)
	})
	fd.Open(&a.win.ApplicationWindow.Window, nil, &cb, 0)
}

// uploadDrivePath reads + encrypts + uploads off the UI thread.
func (a *App) uploadDrivePath(path string) {
	go func() {
		data, err := readFileAbs(path)
		if err != nil {
			a.errToast(err)
			return
		}
		a.mu.Lock()
		parent := a.driveParent
		a.mu.Unlock()
		a.setStatus(fmt.Sprintf("Lade %s hoch (%s)…", basename(path), fmtSize(int64(len(data)))))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		a.mu.Lock()
		doc := &a.doc
		a.mu.Unlock()
		e, upErr := core.UploadFile(ctx, a.client(), a.priv, doc, data, basename(path),
			core.MimeByName(path), parent, func(s string) {
				f := glib.SourceOnceFunc(func(_ uintptr) { a.setStatus(s) })
				glib.IdleAddOnce(&f, 0)
			})
		f := glib.SourceOnceFunc(func(_ uintptr) {
			if upErr != nil {
				a.setStatus("Hochladen fehlgeschlagen")
				a.errToast(upErr)
				return
			}
			log.Printf("drive upload ok id=%s name=%q", e.ID, e.Name)
			a.schedulePush()
			a.refreshFolderList()
			a.refreshDriveQuota()
			a.setStatus("Hochgeladen: " + e.Name)
			a.toast("Datei im Laufwerk gespeichert")
		})
		glib.IdleAddOnce(&f, 0)
	}()
}

func (a *App) driveMkdir() {
	a.promptText("Neuer Ordner", "Name:", "", func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		a.mu.Lock()
		parent := a.driveParent
		core.Mkdir(&a.doc, name, parent)
		a.mu.Unlock()
		a.schedulePush()
		a.refreshFolderList()
	})
}

func (a *App) driveRename() {
	a.mu.Lock()
	e, ok := a.doc.Files[a.curFileID]
	a.mu.Unlock()
	if !ok || e.Gone != 0 {
		return
	}
	a.promptText("Umbenennen", "Neuer Name:", e.Name, func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || name == e.Name {
			return
		}
		a.mu.Lock()
		err := core.RenameFile(&a.doc, e.ID, name)
		a.mu.Unlock()
		if err != nil {
			a.errToast(err)
			return
		}
		a.schedulePush()
		a.refreshFolderList()
	})
}

func (a *App) driveDelete() {
	a.mu.Lock()
	e, ok := a.doc.Files[a.curFileID]
	a.mu.Unlock()
	if !ok {
		return
	}
	a.confirm("🗑 „"+e.Name+"“ entfernen? Die Server-Blobs werden freigegeben.", func(yes bool) {
		if !yes {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			a.mu.Lock()
			doc := &a.doc
			a.mu.Unlock()
			err := core.DeleteFile(ctx, a.client(), doc, e.ID)
			f := glib.SourceOnceFunc(func(_ uintptr) {
				if err != nil {
					a.errToast(err)
					return
				}
				a.schedulePush()
				a.refreshFolderList()
				a.refreshDriveQuota()
				a.drvInfo.SetText("Gelöscht.")
				a.drvDownBtn.SetSensitive(false)
				a.drvDelBtn.SetSensitive(false)
				a.drvRenameBtn.SetSensitive(false)
			})
			glib.IdleAddOnce(&f, 0)
		}()
	})
}

func (a *App) driveDownload() {
	a.mu.Lock()
	e, ok := a.doc.Files[a.curFileID]
	a.mu.Unlock()
	if !ok || e.Msha == "" {
		return
	}
	fileSave(&a.win.ApplicationWindow.Window, e.Name, "Datei speichern unter", func(path string) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			a.mu.Lock()
			doc := &a.doc
			a.mu.Unlock()
			a.setStatus("Lade „" + e.Name + "“ herunter…")
			data, err := core.DownloadFile(ctx, a.client(), a.priv, doc, e.ID)
			var writeErr error
			if err == nil {
				writeErr = writeFileAbs(path, data)
			}
			f := glib.SourceOnceFunc(func(_ uintptr) {
				if err != nil {
					a.setStatus("Download fehlgeschlagen")
					a.errToast(err)
					return
				}
				if writeErr != nil {
					a.errToast(writeErr)
					return
				}
				a.setStatus("Gespeichert: " + basename(path))
				a.toast("Datei gespeichert")
			})
			glib.IdleAddOnce(&f, 0)
		}()
	})
}

// refreshDriveQuota pulls GET /v1/drive/usage (entering the drive, after
// uploads/deletes/tier buys).
func (a *App) refreshDriveQuota() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		u, err := a.client().DriveUsage(ctx)
		if err != nil {
			log.Printf("drive usage: %v", err)
			return
		}
		f := glib.SourceOnceFunc(func(_ uintptr) {
			pct := 0.0
			if u.QuotaBytes > 0 {
				pct = float64(u.UsedBytes) / float64(u.QuotaBytes)
			}
			a.drvQuota.SetFraction(pct)
			a.drvQuotaLabel.SetText(fmt.Sprintf("%s / %s", fmtSize(u.UsedBytes), fmtSize(u.QuotaBytes)))
			a.drvTiers = u.Tiers
			if len(u.Tiers) > 0 {
				t := u.Tiers[0]
				a.drvTierBtn.SetLabel(fmt.Sprintf("＋ %d GB für %d sats", t.GB, t.Sats))
				a.drvTierBtn.SetVisible(u.Enabled)
			}
		})
		glib.IdleAddOnce(&f, 0)
	}()
}

func (a *App) buyTier() {
	if len(a.drvTiers) == 0 {
		return
	}
	t := a.drvTiers[0]
	a.confirm(fmt.Sprintf("Speicherstufe kaufen: %d GB für %d sats?", t.GB, t.Sats), func(yes bool) {
		if !yes {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := a.client().BuyTier(ctx, 0)
			f := glib.SourceOnceFunc(func(_ uintptr) {
				if err != nil {
					a.errToast(err)
					return
				}
				a.toast("Speicherstufe gekauft")
				a.refreshDriveQuota()
			})
			glib.IdleAddOnce(&f, 0)
		}()
	})
}

// --- page builders (called once from buildUI) ---

// buildAbPage: contact detail with action buttons. 16 fixed rows are created
// once; showContactDetail fills/hides them (Rotliste #1: no rebuild loops).
func (a *App) buildAbPage() *gtk.Widget {
	scroll := gtk.NewScrolledWindow()
	box := gtk.NewBox(gtk.OrientationVerticalValue, 8)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(14)
	title := newLabel("📇 Kontakt", "title-1")
	title.SetXalign(0)
	box.Append(&title.Widget)

	detailBox := gtk.NewBox(gtk.OrientationVerticalValue, 2)
	for range abFields {
		row := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
		k := newLabel("", "dim-label", "caption")
		k.SetSizeRequest(150, -1)
		k.SetXalign(0)
		v := newLabel("")
		v.SetXalign(0)
		row.Append(&k.Widget)
		row.Append(&v.Widget)
		row.SetVisible(false)
		detailBox.Append(&row.Widget)
		a.abDetail = append(a.abDetail, detailRow{row: row, key: k, val: v})
	}
	box.Append(&detailBox.Widget)

	btns := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	btns.SetMarginTop(10)
	mk := func(label string, cls string, cb func()) *gtk.Button {
		b := gtk.NewButton()
		b.SetLabel(label)
		if cls != "" {
			b.AddCssClass(cls)
		}
		b.SetSensitive(false)
		c := func(_ gtk.Button) { cb() }
		b.ConnectClicked(&c)
		btns.Append(&b.Widget)
		return b
	}
	newBtn := gtk.NewButton()
	newBtn.SetLabel("＋ Neue Person")
	newBtn.AddCssClass("suggested-action")
	ncb := func(_ gtk.Button) { a.newContact() }
	newBtn.ConnectClicked(&ncb)
	btns.Append(&newBtn.Widget)

	a.abMailBtn = mk("✉️ Mail schreiben", "suggested-action", func() { a.abWriteMail() })
	editBtn := mk("✏️ Bearbeiten", "", func() { a.abEdit() })
	_ = editBtn
	a.abDelBtn = mk("🗑 Löschen", "destructive-action", func() { a.abDelete() })
	// mail/delete sensitivity follows content; edit always live once selected
	a.abMailBtn.SetSensitive(false)
	a.abDelBtn.SetSensitive(true)
	box.Append(&btns.Widget)

	scroll.SetChild(&box.Widget)
	return &scroll.Widget
}

// buildDrvPage: selected-file details + actions + quota bar.
func (a *App) buildDrvPage() *gtk.Widget {
	box := gtk.NewBox(gtk.OrientationVerticalValue, 8)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(14)

	head := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	title := newLabel("🗂 Laufwerk", "title-1")
	title.SetXalign(0)
	head.Append(&title.Widget)
	a.drvHomeBtn = gtk.NewButton()
	a.drvHomeBtn.SetLabel("🏠")
	a.drvHomeBtn.AddCssClass("flat")
	hcb := func(_ gtk.Button) {
		a.driveParent = ""
		a.refreshFolderList()
	}
	a.drvHomeBtn.ConnectClicked(&hcb)
	head.Append(&a.drvHomeBtn.Widget)
	box.Append(&head.Widget)

	a.drvInfo = newLabel("Datei auswählen — oder oben eine neue Datei hochladen.")
	a.drvInfo.SetXalign(0)
	a.drvInfo.SetWrap(true)
	box.Append(&a.drvInfo.Widget)

	btns := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	mk := func(label, cls string, cb func()) *gtk.Button {
		b := gtk.NewButton()
		b.SetLabel(label)
		if cls != "" {
			b.AddCssClass(cls)
		}
		b.SetSensitive(false)
		c := func(_ gtk.Button) { cb() }
		b.ConnectClicked(&c)
		btns.Append(&b.Widget)
		return b
	}
	upBtn := gtk.NewButton()
	upBtn.SetLabel("📤 Datei hochladen")
	upcb := func(_ gtk.Button) { a.driveUpload() }
	upBtn.ConnectClicked(&upcb)
	btns.Append(&upBtn.Widget)
	mkdirBtn := gtk.NewButton()
	mkdirBtn.SetLabel("＋ Ordner")
	mcb := func(_ gtk.Button) { a.driveMkdir() }
	mkdirBtn.ConnectClicked(&mcb)
	btns.Append(&mkdirBtn.Widget)
	a.drvDownBtn = mk("⬇ Herunterladen", "suggested-action", func() { a.driveDownload() })
	a.drvRenameBtn = mk("✏️ Umbenennen", "", func() { a.driveRename() })
	a.drvDelBtn = mk("🗑 Löschen", "destructive-action", func() { a.driveDelete() })
	box.Append(&btns.Widget)

	quota := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	quota.SetMarginTop(8)
	a.drvQuota = gtk.NewProgressBar()
	a.drvQuota.SetHexpand(true)
	a.drvQuotaLabel = newLabel("— / —", "dim-label", "caption")
	a.drvTierBtn = gtk.NewButton()
	a.drvTierBtn.SetLabel("＋ Speicher kaufen")
	tcb := func(_ gtk.Button) { a.buyTier() }
	a.drvTierBtn.ConnectClicked(&tcb)
	a.drvTierBtn.SetVisible(false)
	quota.Append(&a.drvQuotaLabel.Widget)
	quota.Append(&a.drvQuota.Widget)
	quota.Append(&a.drvTierBtn.Widget)
	box.Append(&quota.Widget)

	return &box.Widget
}

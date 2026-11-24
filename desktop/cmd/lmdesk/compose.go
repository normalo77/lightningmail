package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/lightningmail/desktop/core"
	lm1crypto "github.com/lightningmail/lm1/crypto"
)

// showLoginDialog opens a passphrase dialog for LMKEY2-wrapped keyfiles.
func showLoginDialog(win *adw.ApplicationWindow, keypath string, parent *App) {
	log.Printf("login: Prompt für Keyfile %s", keypath)
	b, err := os.ReadFile(keypath)
	if err != nil {
		log.Printf("login: kann Keyfile nicht lesen: %v", err)
		parent.loginResult <- ""
		return
	}
	wrapped := lm1crypto.IsWrapped(string(b))
	clear(b)
	if !wrapped {
		log.Printf("login: ungewrappte Keydatei — kein Passwort nötig")
		parent.loginResult <- ""
		return
	}
	dialog := adw.NewDialog()
	dialog.SetTitle("Passphrase")
	dialog.SetPresentationMode(adw.DialogAutoValue)

	tt := adw.NewToolbarView()
	content := gtk.NewBox(gtk.OrientationVerticalValue, 12)
	content.SetMarginStart(24)
	content.SetMarginEnd(24)
	content.SetMarginTop(16)
	content.SetMarginBottom(16)

	label := newLabel("Gib die Passphrase für die Schlüsseldatei ein:")
	label.SetXalign(0)
	entry := gtk.NewPasswordEntry()
	entry.SetShowPeekIcon(true)
	errLabel := newLabel("")
	errLabel.AddCssClass("error")
	errLabel.SetXalign(0)
	errLabel.SetVisible(false)

	activateCb := func(_ gtk.PasswordEntry) {
		pass := entry.GetText()
		_, err := core.LoadKeyFile(keypath, pass)
		if err != nil {
			errLabel.SetText("Falsche Passphrase — " + err.Error())
			errLabel.SetVisible(true)
			return
		}
		log.Printf("login: Keyfile entsperrt")
		parent.loginResult <- pass
		dialog.Close()
	}
	entry.ConnectActivate(&activateCb)
	closeCb := func(_ adw.Dialog) {
		select {
		case parent.loginResult <- "":
		default:
		}
	}
	dialog.ConnectClosed(&closeCb)

	content.Append(&label.Widget)
	content.Append(&entry.Widget)
	content.Append(&errLabel.Widget)
	tt.SetContent(&content.Widget)
	dialog.SetChild(&tt.Widget)

	dialog.Present(&win.Widget)
}

// composeSeed prefills a compose dialog: fresh mail (nil seed), reply or
// draft-edit (DraftID set => re-saving updates that draft).
type composeSeed struct {
	To, Cc, Subject, Body string
	DraftID               string
}

// showComposeDialog opens a compose window for new mail, reply or draft edit.
func showComposeDialog(win *adw.ApplicationWindow, a *App, seed *composeSeed) {
	dialog := adw.NewDialog()
	dialog.SetTitle("Neue Mail")
	dialog.SetPresentationMode(adw.DialogAutoValue)
	dialog.SetContentWidth(600)
	dialog.SetContentHeight(500)

	tt := adw.NewToolbarView()
	content := gtk.NewBox(gtk.OrientationVerticalValue, 8)
	content.SetMarginStart(16)
	content.SetMarginEnd(16)
	content.SetMarginTop(12)
	content.SetMarginBottom(12)

	// To field
	toRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	toRow.Append(&newLabel("An:").Widget)
	toEntry := gtk.NewEntry()
	toEntry.SetHexpand(true)
	if seed != nil {
		toEntry.SetText(seed.To)
	}
	toRow.Append(&toEntry.Widget)

	// CC field: comma/semicolon-separated, fan-out like To (encrypted headers only)
	ccRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	ccRow.Append(&newLabel("CC:").Widget)
	ccEntry := gtk.NewEntry()
	ccEntry.SetHexpand(true)
	if seed != nil {
		ccEntry.SetText(seed.Cc)
	}
	ccRow.Append(&ccEntry.Widget)

	// Subject
	subjRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	subjRow.Append(&newLabel("Betreff:").Widget)
	subjEntry := gtk.NewEntry()
	subjEntry.SetHexpand(true)
	if seed != nil {
		subjEntry.SetText(seed.Subject)
	}
	subjRow.Append(&subjEntry.Widget)

	// Body (TextView in ScrolledWindow)
	bodyView := gtk.NewTextView()
	bodyView.SetMonospace(true)
	bodyView.SetVexpand(true)
	if seed != nil && seed.Body != "" {
		buf := bodyView.GetBuffer()
		buf.SetText(seed.Body, len(seed.Body))
	}
	bodyScroll := gtk.NewScrolledWindow()
	bodyScroll.SetChild(&bodyView.Widget)
	bodyScroll.SetMinContentHeight(200)

	// M2: attachments via GtkFileDialog (Open = file-chooser, GTK 4.10+)
	atts := []core.ComposeAttachment{} // GTK-thread only, no lock needed
	statusLabel := newLabel("")
	statusLabel.AddCssClass("dim-label")
	statusLabel.AddCssClass("caption")
	attLabel := newLabel("📎 keine Anhänge")
	attLabel.AddCssClass("dim-label")
	attLabel.SetXalign(0)
	attBtn := gtk.NewButton()
	attBtn.SetLabel("📎 Anhang…")
	attCb := func(_ gtk.Button) {
		fd := gtk.NewFileDialog()
		fd.SetTitle("Anhang auswählen")
		cb := gio.AsyncReadyCallback(func(_, resPtr, _ uintptr) {
			res := &gio.AsyncResultBase{Ptr: resPtr}
			f, err := fd.OpenFinish(res)
			if err != nil || f == nil {
				return // cancelled
			}
			path := f.GetPath()
			data, err := os.ReadFile(path)
			if err != nil {
				statusLabel.SetText("Anhang nicht lesbar: " + err.Error())
				return
			}
			atts = append(atts, core.ComposeAttachment{
				Name: f.GetBasename(), Bytes: data})
			names := make([]string, len(atts))
			for i, at := range atts {
				names[i] = fmt.Sprintf("%s (%.1f MB)", at.Name, float64(len(at.Bytes))/1048576)
			}
			attLabel.SetText("📎 " + strings.Join(names, ", "))
			log.Printf("anhang: %s (%d bytes)", path, len(data))
		})
		fd.Open(&win.Window, nil, &cb, 0)
	}
	attBtn.ConnectClicked(&attCb)
	attClear := gtk.NewButton()
	attClear.SetLabel("✕")
	attClear.AddCssClass("flat")
	clearCb := func(_ gtk.Button) {
		atts = atts[:0]
		attLabel.SetText("📎 keine Anhänge")
	}
	attClear.ConnectClicked(&clearCb)
	attRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	attRow.Append(&attBtn.Widget)
	attRow.Append(&attClear.Widget)
	attRow.Append(&attLabel.Widget)

	// Status + actions
	fields := func() (to, cc, subj, body string) {
		to = strings.TrimSpace(toEntry.GetText())
		cc = strings.TrimSpace(ccEntry.GetText())
		subj = strings.TrimSpace(subjEntry.GetText())
		buf := bodyView.GetBuffer()
		var start, end gtk.TextIter
		buf.GetStartIter(&start)
		buf.GetEndIter(&end)
		return to, cc, subj, buf.GetText(&start, &end, false)
	}

	sendBtn := gtk.NewButton()
	sendBtn.SetLabel("Senden")
	sendBtn.AddCssClass("suggested-action")
	sendCb := func(_ gtk.Button) {
		to, cc, subj, body := fields()
		if to == "" || subj == "" {
			statusLabel.SetText("Empfänger und Betreff erforderlich")
			return
		}
		sentAtts := append([]core.ComposeAttachment{}, atts...)
		statusLabel.SetText("sende…")
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			res, err := core.ComposeAndSend(ctx, a.client(), a.priv, core.ComposeOpts{
				To: to, Cc: cc, From: a.cfg.Name, Subject: subj, Body: body, Attachments: sentAtts,
			})
			f := glib.SourceOnceFunc(func(_ uintptr) {
				if err != nil {
					statusLabel.SetText("Fehler: " + err.Error())
					log.Printf("send error: %v", err)
					return
				}
				// fan-out visibility: report exactly which recipients failed
				var failed []string
				for _, r := range res.Results {
					if !r.OK {
						failed = append(failed, r.To)
					}
				}
				if len(failed) > 0 {
					statusLabel.SetText(fmt.Sprintf("⚠ teilweise gesendet — fehlgeschlagen: %s", strings.Join(failed, ", ")))
				} else {
					statusLabel.SetText(fmt.Sprintf("✓ gesendet — %s (%s)", res.MsgID[:12], res.Status))
				}
				log.Printf("send ok: msg=%s… status=%s recipients=%d failed=%d", res.MsgID[:12], res.Status, len(res.Results), len(failed))
				var bytes int64
				for _, at := range sentAtts {
					bytes += int64(len(at.Bytes))
				}
				a.mu.Lock()
				a.doc.AddSent(core.SentItem{
					MsgID: res.MsgID, Ts: time.Now().Unix(), To: to,
					Subject: subj, Body: body, Bytes: int64(len(body)) + bytes,
				})
				if seed != nil && seed.DraftID != "" {
					a.doc.DelDraft(seed.DraftID) // sent mail consumes its draft
				}
				a.mu.Unlock()
				a.schedulePush()
				dialog.Close()
			})
			glib.IdleAddOnce(&f, 0)
		}()
	}
	sendBtn.ConnectClicked(&sendCb)

	draftBtn := gtk.NewButton()
	draftBtn.SetLabel("💾 Als Entwurf speichern")
	draftCb := func(_ gtk.Button) {
		to, _, subj, body := fields() // shortcut: the Draft schema has no CC field (state-doc golden fixtures) — drafts keep To only
		if to == "" && subj == "" && body == "" {
			statusLabel.SetText("Nichts zu speichern")
			return
		}
		id := ""
		if seed != nil {
			id = seed.DraftID
		}
		if id == "" {
			var nb [8]byte
			rand.Read(nb[:])
			id = hex.EncodeToString(nb[:])
		}
		a.mu.Lock()
		a.doc.SaveDraft(core.Draft{ID: id, To: to, Subject: subj, Body: body})
		a.mu.Unlock()
		a.schedulePush()
		log.Printf("entwurf gespeichert id=%s subj=%q", id, subj)
		a.toast("Entwurf gespeichert")
		dialog.Close()
	}
	draftBtn.ConnectClicked(&draftCb)

	btnRow := gtk.NewBox(gtk.OrientationHorizontalValue, 8)
	btnRow.SetHalign(gtk.AlignEndValue)
	btnRow.Append(&statusLabel.Widget)
	sp := gtk.NewBox(gtk.OrientationHorizontalValue, 0)
	sp.SetHexpand(true)
	btnRow.Append(&sp.Widget)
	btnRow.Append(&draftBtn.Widget)
	btnRow.Append(&sendBtn.Widget)

	content.Append(&toRow.Widget)
	content.Append(&ccRow.Widget)
	content.Append(&subjRow.Widget)
	content.Append(&bodyScroll.Widget)
	content.Append(&attRow.Widget)
	content.Append(&btnRow.Widget)
	tt.SetContent(&content.Widget)
	dialog.SetChild(&tt.Widget)

	dialog.Present(&win.Widget)
}

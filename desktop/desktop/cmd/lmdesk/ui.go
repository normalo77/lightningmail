package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bnema/puregotk-webkit/webkit"
	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gtk"
	"github.com/bnema/puregotk/v4/pango"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/desktop/core"
)

// App is the central UI struct — all signal callbacks are bound here exactly
// once (Rotliste #1: no Connect* in render/update loops).
type App struct {
	cfg  *core.Config
	priv *btcec.PrivateKey
	api  *core.Client

	adwApp *adw.Application
	win    *adw.ApplicationWindow

	// widgets
	listModel     *gtk.StringList
	sel           *gtk.SingleSelection
	listView      *gtk.ListView
	reader        *webkit.WebView
	readerBuilder *gtk.Builder // keeps the builder-owned WebView reference alive
	balanceLabel  *gtk.Label
	statusLabel   *gtk.Label
	toastOverlay  *adw.ToastOverlay

	// row widgets created by the factory setup (recycled, ~viewport count)
	rows map[uintptr]*rowWidgets

	// shared state — mu guards everything below (sync goroutine vs GTK thread)
	mu           sync.Mutex
	mails        []*core.Mail // display order: newest first
	byID         map[string]*core.Mail
	doc          core.StateDoc
	stateVersion int64
	cursor       int64 // max(seq) seen
	balanceMsat  int64
	currentMsgID string
	currentShas  map[string]string // sha256 hex -> content type (open mail only)

	cache           *core.Cache
	fmu             sync.Mutex
	flights         map[string]*flight
	lastInteraction time.Time
	backoff         time.Duration
	firstLoad       bool
	demoStarted     bool
	domCheckDone    atomic.Bool
	quit            chan struct{}
}

type rowWidgets struct {
	subj, meta *gtk.Label
	msgID      string
}

func newApp(cfg *core.Config, priv *btcec.PrivateKey) *App {
	return &App{
		cfg:         cfg,
		priv:        priv,
		api:         core.NewClient(cfg, priv),
		byID:        map[string]*core.Mail{},
		doc:         core.EmptyDoc(),
		rows:        map[uintptr]*rowWidgets{},
		cache:       core.NewCache(),
		currentShas: map[string]string{},
		quit:        make(chan struct{}),
	}
}

// rowSetup builds the cell once per recycled row: bold-capable subject +
// dim meta line. NO SetMarkup with mail data — Rotliste #4: SetText + CSS.
func (a *App) rowSetup(itemPtr uintptr) {
	item := gtk.ListItemNewFromInternalPtr(itemPtr)
	box := gtk.NewBox(gtk.OrientationVerticalValue, 2)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(8)
	box.SetMarginBottom(8)
	empty := ""
	subj := gtk.NewLabel(&empty)
	subj.SetXalign(0)
	subj.SetEllipsize(pango.EllipsizeEndValue)
	meta := gtk.NewLabel(&empty)
	meta.SetXalign(0)
	meta.SetEllipsize(pango.EllipsizeEndValue)
	meta.AddCssClass("dim-label")
	meta.AddCssClass("caption")
	box.Append(&subj.Widget)
	box.Append(&meta.Widget)
	item.SetChild(&box.Widget)
	a.rows[item.GoPointer()] = &rowWidgets{subj: subj, meta: meta}
}

// rowBind reads the msg_id (GtkStringObject) and looks the mail up in Go —
// the Ponytail pattern from the review: 10k mails render with ~25 widgets.
func (a *App) rowBind(itemPtr uintptr) {
	item := gtk.ListItemNewFromInternalPtr(itemPtr)
	row, ok := a.rows[item.GoPointer()]
	if !ok {
		return
	}
	so := gtk.StringObjectNewFromInternalPtr(item.GetItem().GoPointer())
	msgID := so.GetString()
	row.msgID = msgID

	a.mu.Lock()
	m := a.byID[msgID]
	_, read := a.doc.Read[msgID]
	a.mu.Unlock()

	if m == nil {
		row.subj.SetText("(gelöscht)")
		row.meta.SetText("")
		return
	}
	subj := m.Subject
	if subj == "" {
		subj = "(ohne Betreff)"
	}
	if m.Signup {
		subj = "[🔑 Registrierung] " + subj
	}
	row.subj.SetText(subj)
	row.meta.SetText(metaLine(m))

	// unread = bold ("heading"), read = normal + dim (PWA list convention)
	if read {
		row.subj.RemoveCssClass("heading")
		row.subj.AddCssClass("dim-label")
	} else {
		row.subj.RemoveCssClass("dim-label")
		row.subj.AddCssClass("heading")
	}
}

func metaLine(m *core.Mail) string {
	line := m.SenderShort + "… · " + core.FormatDateDE(m.ReceivedAt)
	if len(m.Attachments) > 0 {
		line += " 📎"
	}
	if m.ReceivedSats > 0 {
		line += " ⚡"
	}
	return line
}

// refreshRows restyles the ~viewport-many bound rows (main thread only).
func (a *App) refreshRows() {
	for ptr, row := range a.rows {
		if row.msgID == "" {
			continue
		}
		item := gtk.ListItemNewFromInternalPtr(ptr)
		a.rowBind(item.GoPointer())
	}
}

// openMail shows position pos in the reader and marks it read LOCALLY.
// M1: read state is display-only — the StateDoc push (server save) comes
// with the M2 write path, there is no PUT /v1/state in this binary.
func (a *App) openMail(pos uint) {
	a.mu.Lock()
	if int(pos) >= len(a.mails) {
		a.mu.Unlock()
		return
	}
	m := a.mails[pos]
	switched := a.currentMsgID != m.MsgID
	a.currentMsgID = m.MsgID
	a.lastInteraction = time.Now() // opening a mail counts as interaction
	shas := map[string]string{}
	for _, at := range m.Attachments {
		shas[at.SHA256] = core.MimeByName(at.Name)
	}
	a.currentShas = shas
	_, wasRead := a.doc.Read[m.MsgID]
	a.doc.Read[m.MsgID] = 1
	htmlStr := core.BuildReaderHTML(m)
	a.mu.Unlock()

	if !wasRead {
		log.Printf("markRead local msg=%s… (Anzeige-Umschaltung; Server-Save = M2)", m.MsgID[:12])
		a.refreshRows()
	}
	// zero the decrypted bytes of the PREVIOUS mail on a switch (Rotliste
	// §3.4); re-opening the same mail keeps its cache (scheme-cache-hit)
	if switched {
		a.cache.Clear()
	}
	a.reader.LoadHtml(htmlStr, nil)
	log.Printf("openMail seq=%d msg=%s… subj=%q attachments=%d", m.Seq, m.MsgID[:12], m.Subject, len(m.Attachments))
}

// findMailPos locates a mail by subject prefix (demo mode helper).
func (a *App) findMailPos(subjectPrefix string) (uint, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, m := range a.mails {
		if len(m.Subject) >= len(subjectPrefix) && m.Subject[:len(subjectPrefix)] == subjectPrefix {
			return uint(i), true
		}
	}
	return 0, false
}

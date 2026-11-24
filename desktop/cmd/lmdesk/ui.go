package main

import (
	"log"
	"strings"
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

	// M2: write path
	loginResult chan string // passphrase or "" (empty = failed/cancelled)
	pushTimer   *time.Timer // debounced state push (read-sync 5s)
	pushPending bool
	folderMode  string // "inbox" | "sent" | "drafts" | "ab" | "drv"
	replyBtn    *gtk.Button
	replyAllBtn *gtk.Button
	deleteBtn   *gtk.Button

	// M3: panels — GtkStack right side (mail | ab | drv | cfg)
	stack         *gtk.Stack
	abDetail      []detailRow // fixed label/value lines, filled on selection
	abMailBtn     *gtk.Button
	curContactID  string // open contact id ("" none)
	driveParent   string // folder id, "" = drive root
	curFileID     string // opened drive entry id
	drvInfo       *gtk.Label
	drvDownBtn    *gtk.Button
	drvDelBtn     *gtk.Button
	drvRenameBtn  *gtk.Button
	drvQuota      *gtk.ProgressBar
	drvQuotaLabel *gtk.Label
	drvTierBtn    *gtk.Button
	drvTiers      []core.DriveTier
	abImportBtn   *gtk.Button
	abDelBtn      *gtk.Button
	drvHomeBtn    *gtk.Button
	// settings page widgets
	cfgRelayEntry *gtk.Entry
	cfgTorEntry   *gtk.Entry
	cfgCacheEntry *gtk.Entry
	cfgAutoSwitch *gtk.Switch
	umsList       *gtk.ListBox
	umsStatus     *gtk.Label
}

// detailRow is one label/value line of the contact detail page (built once).
type detailRow struct {
	row *gtk.Box
	key *gtk.Label
	val *gtk.Label
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
		cache:       core.NewCache(cfg),
		currentShas: map[string]string{},
		quit:        make(chan struct{}),
		loginResult: make(chan string, 1),
		folderMode:  "inbox",
	}
}

func (a *App) client() *core.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.api
}

func (a *App) setClient(c *core.Client) {
	a.mu.Lock()
	a.api = c
	a.mu.Unlock()
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
	item.SetActivatable(true) // default is FALSE -> clicks would only select
	a.rows[item.GoPointer()] = &rowWidgets{subj: subj, meta: meta}
}

// rowBind reads the item string (msgID, or "d:<id>"/"s:<msgID>" in folder
// mode) and looks it up in Go — the Ponytail pattern from the review.
func (a *App) rowBind(itemPtr uintptr) {
	item := gtk.ListItemNewFromInternalPtr(itemPtr)
	row, ok := a.rows[item.GoPointer()]
	if !ok {
		return
	}
	so := gtk.StringObjectNewFromInternalPtr(item.GetItem().GoPointer())
	key := so.GetString()
	row.msgID = key

	a.mu.Lock()
	subj, meta, read := "", "", false
	switch {
	case strings.HasPrefix(key, "d:"):
		for _, d := range a.doc.LiveDrafts() {
			if "d:"+d.ID == key {
				subj = d.Subject
				if subj == "" {
					subj = "(ohne Betreff)"
				}
				meta = "Entwurf · An: " + d.To + " · " + core.FormatDateDE(d.Ts)
			}
		}
	case strings.HasPrefix(key, "s:"):
		sid := key[2:]
		for _, s := range a.doc.Sent {
			if s.MsgID == sid {
				subj = s.Subject
				if subj == "" {
					subj = "(ohne Betreff)"
				}
				meta = "An: " + s.To + " · " + core.FormatDateDE(s.Ts) + " ✓"
			}
		}
	case strings.HasPrefix(key, "c:"):
		if c, ok := a.doc.Contacts[key[2:]]; ok && c.Gone == 0 {
			subj = core.ContactDisplay(c)
			var bits []string
			if c.Org != "" {
				bits = append(bits, c.Org)
			}
			if c.Lnaddr != "" {
				bits = append(bits, c.Lnaddr)
			} else if c.Email != "" {
				bits = append(bits, c.Email)
			}
			meta = strings.Join(bits, " · ")
		}
	case strings.HasPrefix(key, "f:"):
		if e, ok := a.doc.Files[key[2:]]; ok && e.Gone == 0 {
			if e.Kind == "d" {
				subj = "📁 " + e.Name
			} else {
				subj = "📄 " + e.Name
				meta = fmtSize(e.SizePlain)
			}
		}
	default:
		m := a.byID[key]
		if m != nil {
			subj = m.Subject
			if subj == "" {
				subj = "(ohne Betreff)"
			}
			if m.Signup {
				subj = "[🔑 Registrierung] " + subj
			}
			meta = metaLine(m)
		}
		_, read = a.doc.Read[key]
	}
	a.mu.Unlock()

	if subj == "" {
		subj = "(gelöscht)"
		meta = ""
	}
	row.subj.SetText(subj)
	row.meta.SetText(meta)

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

// rowSelected opens the newly selected list row (GTK main thread, called
// from the selection-changed trampoline). M3: contacts/drive rows dispatch
// to their detail pages, everything else keeps the mail path.
func (a *App) rowSelected() {
	pos := a.sel.GetSelected()
	if pos == 0xFFFFFFFF { // GTK_INVALID_LIST_POSITION
		return
	}
	a.mu.Lock()
	mode := a.folderMode
	a.mu.Unlock()
	switch mode {
	case "ab":
		a.mu.Lock()
		l := a.doc.LiveContacts()
		a.mu.Unlock()
		if int(pos) < len(l) {
			a.showContactDetail("c:" + l[pos].ID)
		}
		return
	case "drv":
		if l := a.driveEntries(); int(pos) < len(l) {
			a.openDrive("f:" + l[pos].ID)
		}
		return
	case "cfg":
		return
	}
	a.mu.Lock()
	cur := ""
	if mode != "sent" && mode != "drafts" && int(pos) < len(a.mails) {
		cur = a.mails[pos].MsgID
	}
	seen := cur != "" && cur == a.currentMsgID
	a.mu.Unlock()
	if seen {
		return
	}
	a.lastInteraction = time.Now()
	a.openMail(pos)
}

// openMail shows position pos of the current folder. Inbox mails render in
// the reader and mark read LOCALLY; M2 pushes the read flag debounced (5s)
// and enables the native Antworten/Löschen action bar. Draft rows reopen the
// compose dialog; sent rows show a plain-text echo.
func (a *App) openMail(pos uint) {
	if a.stack != nil {
		a.stack.SetVisibleChildName("mail")
	}
	a.mu.Lock()
	mode := a.folderMode
	a.lastInteraction = time.Now()
	var draft *core.Draft
	var sent *core.SentItem
	switch mode {
	case "drafts":
		dl := a.doc.LiveDrafts()
		if int(pos) < len(dl) {
			d := dl[pos]
			draft = &d
		}
	case "sent":
		sl := a.doc.LiveSent()
		if int(pos) < len(sl) {
			s := sl[pos]
			sent = &s
		}
	}
	a.mu.Unlock()

	switch {
	case draft != nil:
		showComposeDialog(a.win, a, &composeSeed{
			To: draft.To, Subject: draft.Subject, Body: draft.Body, DraftID: draft.ID})
		return
	case sent != nil:
		html := "<html><body style='font-family:sans-serif;padding:16px'>" +
			"<h3>" + escHTML(sent.Subject) + "</h3><p>" + escHTML(sent.Body) + "</p></body></html>"
		a.reader.LoadHtml(html, nil)
		a.setReaderActions(false)
		return
	case mode != "inbox":
		return
	}

	a.mu.Lock()
	if int(pos) >= len(a.mails) {
		a.mu.Unlock()
		return
	}
	m := a.mails[pos]
	switched := a.currentMsgID != m.MsgID
	a.currentMsgID = m.MsgID
	shas := map[string]string{}
	for _, at := range m.Attachments {
		shas[at.SHA256] = core.MimeByName(at.Name)
	}
	a.currentShas = shas
	_, wasRead := a.doc.Read[m.MsgID]
	a.doc.MarkRead(m.MsgID)
	htmlStr := core.BuildReaderHTML(m)
	a.mu.Unlock()

	a.setReaderActions(true)
	if !wasRead {
		log.Printf("markRead msg=%s… (push scheduled)", m.MsgID[:12])
		a.refreshRows()
		a.schedulePush() // M2: debounced server push
	}
	// zero the decrypted bytes of the PREVIOUS mail on a switch
	if switched {
		a.cache.Clear()
	}
	a.reader.LoadHtml(htmlStr, nil)
	log.Printf("openMail seq=%d msg=%s… subj=%q attachments=%d", m.Seq, m.MsgID[:12], m.Subject, len(m.Attachments))
}

// setReaderActions enables/disables the native reply/delete/contact bar
// (main thread). Reply-All is only sensitive when the open letter actually
// has multiple recipients (To list >1 or any CC).
func (a *App) setReaderActions(on bool) {
	if a.replyBtn != nil {
		a.replyBtn.SetSensitive(on)
	}
	if a.replyAllBtn != nil {
		multi := false
		if on {
			a.mu.Lock()
			if m := a.byID[a.currentMsgID]; m != nil {
				multi = m.Cc() != "" || len(core.UniqueRecipients(m.To(), m.Cc())) > 1
			}
			a.mu.Unlock()
		}
		a.replyAllBtn.SetSensitive(multi)
	}
	if a.deleteBtn != nil {
		a.deleteBtn.SetSensitive(on)
	}
	if a.abImportBtn != nil {
		a.abImportBtn.SetSensitive(on)
	}
}

func escHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
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

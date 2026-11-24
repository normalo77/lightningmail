package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bnema/puregotk/v4/glib"
	"github.com/lightningmail/desktop/core"
)

// Sync loop (spec M1b): start-fetch, then adaptive — 10s while the user
// interacted <60s ago, else 60s; on error backoff x2 up to 15min with an
// honest status line instead of silence. UI updates ONLY via IdleAdd.

const (
	pollFast   = 10 * time.Second
	pollSlow   = 60 * time.Second
	backoffMax = 15 * time.Minute
)

func (a *App) syncLoop() {
	for {
		delay := a.poll()
		select {
		case <-a.quit:
			log.Printf("sync-loop beendet")
			return
		case <-time.After(delay):
		}
	}
}

// poll runs one sync round and returns the delay until the next one.
func (a *App) poll() time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := a.pollOnce(ctx); err != nil {
		a.mu.Lock()
		if a.backoff == 0 {
			a.backoff = pollFast
		} else {
			a.backoff *= 2
			if a.backoff > backoffMax {
				a.backoff = backoffMax
			}
		}
		d := a.backoff
		a.mu.Unlock()
		log.Printf("sync-fehler: %v — erneuter Versuch in %s", err, d)
		f := glib.SourceOnceFunc(func(_ uintptr) {
			a.setStatus(fmt.Sprintf("verbindung getrennt — erneuter Versuch in %ds", int(d.Seconds())))
		})
		glib.IdleAddOnce(&f, 0)
		return d
	}

	a.mu.Lock()
	a.backoff = 0
	interactive := time.Since(a.lastInteraction) < time.Minute
	a.mu.Unlock()

	if interactive {
		return pollFast
	}
	return pollSlow
}

// pollOnce fetches inbox (server returns seq DESC = newest first), state and
// balance. Runs OFF the GTK thread; UI mutation only inside IdleAddOnce.
func (a *App) pollOnce(ctx context.Context) error {
	// Cursor protocol: after=<max seq seen> only ever returns NEWER mails.
	// shortcut: the relay cannot page backwards (WHERE seq>after ORDER BY
	// DESC LIMIT n) — the initial sync uses one big limit; mailboxes beyond
	// that need a server-side "before" cursor (M2).
	a.mu.Lock()
	cursor := a.cursor
	a.mu.Unlock()
	limit := 100
	if cursor == 0 {
		limit = 1000 // initial sync
	}
	api := a.client()
	p, err := api.Inbox(ctx, cursor, limit)
	if err != nil {
		return fmt.Errorf("inbox: %w", err)
	}
	if len(p.Messages) >= limit {
		log.Printf("WARN: %d Mails = limit %d — aeltere Mails in M1 nicht abrufbar", len(p.Messages), limit)
	}
	var newMails []*core.Mail
	for _, msg := range p.Messages {
		m, err := core.DecodeMail(a.priv, msg)
		if err != nil {
			log.Printf("decode seq=%d: %v (Mail übersprungen)", msg.Seq, err)
			continue
		}
		if msg.Seq > cursor {
			cursor = msg.Seq
		}
		a.mu.Lock()
		_, dup := a.byID[m.MsgID]
		a.mu.Unlock()
		if !dup {
			newMails = append(newMails, m)
			log.Printf("neu: seq=%d msg=%s… subj=%q", m.Seq, m.MsgID[:12], m.Subject)
		}
	}

	// state: open (self-ECIES, empty AAD) + pure merge — no re-stamping in M1
	ver, blob, err := api.State(ctx)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	remote, err := core.OpenStateDoc(a.priv, blob)
	if err != nil {
		return fmt.Errorf("state open: %w", err)
	}

	bal, err := api.Balance(ctx)
	if err != nil {
		return fmt.Errorf("balance: %w", err)
	}

	a.mu.Lock()
	if remote != nil {
		a.doc = core.MergeDocs(a.doc, *remote)
	}
	a.stateVersion = ver
	a.cursor = cursor
	a.balanceMsat = bal
	first := !a.firstLoad
	a.firstLoad = true
	a.mu.Unlock()

	f := glib.SourceOnceFunc(func(_ uintptr) {
		a.applyUI(newMails, bal, first)
	})
	glib.IdleAddOnce(&f, 0)
	return nil
}

// applyUI runs on the GTK main thread: prepend new mails (newest first),
// update balance label + rows, kick the demo sequence once.
func (a *App) applyUI(newMails []*core.Mail, bal int64, first bool) {
	if len(newMails) > 0 {
		// the server already delivers seq DESC (newest first) — keep that
		// order and prepend the (newer) block before the older mails
		ids := make([]string, 0, len(newMails))
		for _, m := range newMails {
			ids = append(ids, m.MsgID)
		}
		a.mu.Lock()
		a.mails = append(newMails, a.mails...)
		for _, m := range newMails {
			a.byID[m.MsgID] = m
		}
		inInbox := a.folderMode == "inbox"
		a.mu.Unlock()
		if inInbox {
			a.listModel.Splice(0, 0, ids)
		}
	}
	a.balanceLabel.SetText(fmt.Sprintf("Guthaben: %d sats", bal/1000))
	a.refreshRows()
	a.mu.Lock()
	n := len(a.mails)
	a.mu.Unlock()
	a.setStatus(fmt.Sprintf("verbunden · %d Mails · zuletzt %s", n, time.Now().Format("15:04:05")))

	if first && os.Getenv("LMDESK_DEMO") == "1" {
		a.mu.Lock()
		start := !a.demoStarted
		a.demoStarted = true
		a.mu.Unlock()
		if start {
			a.runDemo()
			a.runM3Demo()
		}
	}
}

// runDemo drives the headless evidence timeline (scripts/run-desk.sh):
// t+1s open the HTML seed mail (A1/A2/A4/A5 screenshot @8s), t+13s open
// the inline-image mail (A3/A4 screenshot @20s).
func (a *App) runDemo() {
	log.Printf("demo-modus: steuere Seed-Mails fuer Evidenz an")
	step := func(prefix string) {
		if pos, ok := a.findMailPos(prefix); ok {
			a.sel.SetSelected(pos) // selection-changed -> rowSelected -> openMail
		} else {
			log.Printf("demo: Mail %q nicht gefunden", prefix)
		}
	}
	one := glib.SourceFunc(func(_ uintptr) bool { step("Seed 2"); return false })
	glib.TimeoutAdd(1000, &one, 0)
	two := glib.SourceFunc(func(_ uintptr) bool { step("Seed 3"); return false })
	glib.TimeoutAdd(13000, &two, 0)
}

// --- M2: state push (debounced 5s) ---

func (a *App) schedulePush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pushTimer != nil {
		a.pushTimer.Stop()
	}
	a.pushTimer = time.AfterFunc(5*time.Second, func() {
		a.doPush()
	})
}

func (a *App) doPush() {
	a.mu.Lock()
	ver := a.stateVersion
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build sealed doc
	a.mu.Lock()
	b64, err := core.SealDoc(a.priv, a.doc)
	a.mu.Unlock()
	if err != nil {
		log.Printf("push: seal error: %v", err)
		return
	}

	// Try up to 3 times with merge on 409
	api := a.client()
	for attempt := 1; attempt <= 3; attempt++ {
		newVer, err := api.PushState(ctx, ver, b64)
		if err == nil {
			a.mu.Lock()
			a.stateVersion = newVer
			a.mu.Unlock()
			log.Printf("push ok: version %d -> %d", ver, newVer)
			return
		}
		if strings.Contains(err.Error(), "409") {
			log.Printf("push conflict (attempt %d), pulling & merging…", attempt)
			rv, blob, err2 := api.State(ctx)
			if err2 != nil {
				log.Printf("push pull error: %v", err2)
				continue
			}
			remote, err2 := core.OpenStateDoc(a.priv, blob)
			if err2 != nil || remote == nil {
				log.Printf("push open error: %v", err2)
				continue
			}
			a.mu.Lock()
			a.doc = core.MergeDocs(a.doc, *remote)
			a.stateVersion = rv
			ver = rv
			b64, _ = core.SealDoc(a.priv, a.doc)
			a.mu.Unlock()
			continue
		}
		log.Printf("push error: %v", err)
		return
	}
	log.Printf("push: max retries exceeded")
}

// --- M2: folder switching (sent/drafts) ---

func (a *App) switchFolder(mode string) {
	a.mu.Lock()
	a.folderMode = mode
	a.currentMsgID = ""
	a.currentShas = map[string]string{}
	a.mu.Unlock()
	a.setReaderActions(false)
	switch mode {
	case "ab":
		a.stack.SetVisibleChildName("ab")
	case "drv":
		a.stack.SetVisibleChildName("drv")
		a.refreshDriveQuota()
	default:
		a.stack.SetVisibleChildName("mail")
	}
	a.refreshFolderList()
}

func (a *App) refreshFolderList() {
	a.mu.Lock()
	mode := a.folderMode
	var ids []string
	switch mode {
	case "sent":
		for _, s := range a.doc.LiveSent() {
			ids = append(ids, "s:"+s.MsgID)
		}
	case "drafts":
		for _, d := range a.doc.LiveDrafts() {
			ids = append(ids, "d:"+d.ID)
		}
	case "ab":
		for _, c := range a.doc.LiveContacts() {
			ids = append(ids, "c:"+c.ID)
		}
	case "drv":
		a.mu.Unlock() // driveEntries locks on its own
		for _, e := range a.driveEntries() {
			ids = append(ids, "f:"+e.ID)
		}
		a.mu.Lock()
	default:
		for _, m := range a.mails {
			if _, del := a.doc.Deleted[m.MsgID]; !del {
				ids = append(ids, m.MsgID)
			}
		}
	}
	a.mu.Unlock()

	if a.listModel != nil {
		a.listModel.Splice(0, a.listModel.GetNItems(), ids)
	}
	a.setStatus(fmt.Sprintf("%s · %d Einträge", a.folderLabel(), len(ids)))
}

func (a *App) folderLabel() string {
	switch a.folderMode {
	case "sent":
		return "Gesendet"
	case "drafts":
		return "Entwürfe"
	case "ab":
		return "Adressbuch"
	case "drv":
		if c := a.driveCrumbName(); c != "" {
			return "🗂 " + c
		}
		return "Laufwerk"
	default:
		return "Posteingang"
	}
}

// --- M2: reply/delete actions ---

func (a *App) handleReply() {
	a.mu.Lock()
	msgID := a.currentMsgID
	m := a.byID[msgID]
	// reply target is the bare sender short-name (pubkey hex prefix): the
	// relay peer-loop resolves foreign accounts by name. shortcut: the
	// envelope carries no from-address, a reverse lookup needs server work.
	var to, subj string
	if m != nil {
		to = m.SenderShort
		subj = m.Subject
		if !strings.HasPrefix(subj, "Re:") {
			subj = "Re: " + subj
		}
	}
	a.mu.Unlock()
	if m == nil || a.win == nil {
		return
	}
	showComposeDialog(a.win, a, &composeSeed{To: to, Subject: subj})
}

// handleReplyAll prefills compose with the original sender in To and every
// other To/Cc address (minus self) in CC — core.ReplyAll does the collecting.
func (a *App) handleReplyAll() {
	a.mu.Lock()
	msgID := a.currentMsgID
	m := a.byID[msgID]
	self := a.cfg.Name
	var to, cc, subj string
	if m != nil {
		// no From header: fall back to the plain-reply convention (sender
		// short-name; the relay peer-loop resolves foreign accounts by name)
		sender := core.HeaderCI(m.Headers, "From")
		if sender == "" {
			sender = m.SenderShort
		}
		t, c := core.ReplyAll(sender, m.To(), m.Cc(), self)
		to, cc = strings.Join(t, ", "), strings.Join(c, ", ")
		subj = m.Subject
		if !strings.HasPrefix(subj, "Re:") {
			subj = "Re: " + subj
		}
	}
	a.mu.Unlock()
	if m == nil || a.win == nil {
		return
	}
	showComposeDialog(a.win, a, &composeSeed{To: to, Cc: cc, Subject: subj})
}

func (a *App) handleDelete() {
	a.mu.Lock()
	msgID := a.currentMsgID
	if msgID == "" {
		a.mu.Unlock()
		return
	}
	a.doc.MarkDeleted(msgID)
	for i, m := range a.mails {
		if m.MsgID == msgID {
			a.mails = append(a.mails[:i], a.mails[i+1:]...)
			break
		}
	}
	delete(a.byID, msgID)
	a.currentMsgID = ""
	a.currentShas = map[string]string{}
	a.mu.Unlock()
	a.schedulePush()
	a.setReaderActions(false)
	a.refreshFolderList()
	a.reader.LoadHtml("<html><body></body></html>", nil)
	a.toast("Gelöscht — wird mit dem Server synchronisiert")
	log.Printf("deleted msg=%s…", msgID[:12])
}

// --- M3 evidence demo (LMDESK_M3DEMO=1, scripts/run-m3.sh) ---
// Seeds a contact + a drive folder/file through the SAME code paths the GUI
// buttons use (SaveContact / Mkdir / uploadDrivePath), then flips the pages
// on a timer so xvfb screenshots capture real panel state.

func (a *App) runM3Demo() {
	expect := os.Getenv("LMDESK_M3EXPECT_SHA") != ""
	if expect && os.Getenv("LMDESK_M3DEMO") != "1" {
		// download-verification-only pass (interop proof round 2)
		one2 := func(ms uint, fn func()) {
			f := glib.SourceFunc(func(_ uintptr) bool { fn(); return false })
			glib.TimeoutAdd(ms, &f, 0)
		}
		one2(6000, func() { log.Printf("m3ev:drv"); a.switchFolder("drv"); a.m3ExpectDownload() })
		return
	}
	if os.Getenv("LMDESK_M3DEMO") != "1" {
		return
	}
	log.Printf("m3-demo: säe Kontakt + Laufwerk über die GUI-Pfade")
	seed := func() {
		// contact via the store path (identical to the editor dialog result)
		a.mu.Lock()
		a.doc.SaveContact(core.Contact{ID: "m3demo1", Name: "Gisela", Given: "Gisela",
			Org: "Familie", Lnaddr: "gisela@relay.example", Pubkey: "02c4a7a8f6f6b0e0b5f7d9c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"})
		a.doc.SaveContact(core.Contact{ID: "m3demo2", Name: "Bernd", Email: "bernd@example.de"})
		parent := core.Mkdir(&a.doc, "belege", "").ID
		core.Mkdir(&a.doc, "urlaubsfotos", parent)
		a.mu.Unlock()
		a.schedulePush()
		a.mu.Lock()
		a.driveParent = parent
		a.mu.Unlock()
		a.refreshFolderList()
		// real upload through the panel path (1 MiB random from /tmp)
		if _, err := os.Stat("/tmp/m3-zufall.bin"); err == nil {
			a.uploadDrivePath("/tmp/m3-zufall.bin")
		} else {
			log.Printf("m3-demo: /tmp/m3-zufall.bin fehlt — Upload skipped")
		}
	}
	// NOTE: IdleAddOnce's second arg is user data, NOT a delay (trap hit in
	// the first m3 run — all steps fired at once). Real timers via TimeoutAdd.
	one := func(ms uint, fn func()) {
		f := glib.SourceFunc(func(_ uintptr) bool { fn(); return false })
		glib.TimeoutAdd(ms, &f, 0)
	}
	one(3000, func() { log.Printf("m3ev:seed"); seed() })
	one(9000, func() {
		log.Printf("m3ev:ab")
		a.switchFolder("ab")
		if a.sel.GetNItems() > 0 {
			a.sel.SetSelected(0)
		}
	})
	one(16000, func() { log.Printf("m3ev:drv"); a.switchFolder("drv"); a.m3ExpectDownload() })
	one(22000, func() {
		log.Printf("m3ev:cfg")
		a.stack.SetVisibleChildName("cfg")
		a.refreshStatement()
	})
}

// m3ExpectDownload closes the interop loop: if LMDESK_M3EXPECT_SHA is set
// (sha256 of the PWA-side drive file), download pwa-reply.bin through the
// same core path the GUI download button uses and record the result.
func (a *App) m3ExpectDownload() {
	want := os.Getenv("LMDESK_M3EXPECT_SHA")
	if want == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		a.mu.Lock()
		var id string
		for fid, e := range a.doc.Files {
			if e.Gone == 0 && e.Kind == "f" && e.Name == "pwa-reply.bin" {
				id = fid
			}
		}
		doc := a.doc
		a.mu.Unlock()
		if id == "" {
			log.Printf("m3dl: pwa-reply.bin nicht gefunden")
			return
		}
		data, err := core.DownloadFile(ctx, a.client(), a.priv, &doc, id)
		if err != nil {
			log.Printf("m3dl: %v", err)
			return
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got == want {
			log.Printf("m3dl: sha256 ok (%d bytes aus PWA-Upload)", len(data))
			os.WriteFile("/tmp/m3-desktop-download.sha", []byte(got+"\n"), 0600)
		} else {
			log.Printf("m3dl: MISMATCH got=%s want=%s", got, want)
		}
	}()
}

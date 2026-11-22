package main

import (
	"context"
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
	p, err := a.api.Inbox(ctx, cursor, limit)
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
	ver, blob, err := a.api.State(ctx)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	remote, err := core.OpenStateDoc(a.priv, blob)
	if err != nil {
		return fmt.Errorf("state open: %w", err)
	}

	bal, err := a.api.Balance(ctx)
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
		a.mu.Unlock()
		a.listModel.Splice(0, 0, ids)
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
	for attempt := 1; attempt <= 3; attempt++ {
		newVer, err := a.api.PushState(ctx, ver, b64)
		if err == nil {
			a.mu.Lock()
			a.stateVersion = newVer
			a.mu.Unlock()
			log.Printf("push ok: version %d -> %d", ver, newVer)
			return
		}
		if strings.Contains(err.Error(), "409") {
			log.Printf("push conflict (attempt %d), pulling & merging…", attempt)
			// pull fresh state
			a.mu.Lock()
			a.mu.Unlock()
			rv, blob, err2 := a.api.State(ctx)
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

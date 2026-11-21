package main

import (
	"context"
	"fmt"
	"log"
	"os"
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
			a.sel.SetSelected(pos)
			a.openMail(pos)
		} else {
			log.Printf("demo: Mail %q nicht gefunden", prefix)
		}
	}
	one := glib.SourceFunc(func(_ uintptr) bool { step("Seed 2"); return false })
	glib.TimeoutAdd(1000, &one, 0)
	two := glib.SourceFunc(func(_ uintptr) bool { step("Seed 3"); return false })
	glib.TimeoutAdd(13000, &two, 0)
}

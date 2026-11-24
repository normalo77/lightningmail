package imapserver

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// inboxPageLimit: the relay answers /v1/inbox newest-first with no way to
// page down (after= only filters upwards), so one big page keeps the cursor
// honest. shortcut: if a single poll ever returns exactly this many rows, the
// older unseen letters between the cursor and the page are skipped — raise
// the limit when a bridge first-syncs a mailbox larger than that.
const inboxPageLimit = 10000

// Syncer keeps the SQLite mirror fresh: it pulls new inbox letters from the
// relay (decrypting locally), applies remote flag state, pushes IMAP flag
// changes back to /v1/state and records locally sent letters.
type Syncer struct {
	relay    *relayclient.Client
	priv     *btcec.PrivateKey
	store    *Store
	account  string
	interval time.Duration
}

// NewSyncer wires a syncer; interval <= 0 falls back to 15s.
func NewSyncer(relay *relayclient.Client, priv *btcec.PrivateKey, store *Store, account string, interval time.Duration) *Syncer {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Syncer{relay: relay, priv: priv, store: store, account: account, interval: interval}
}

// SMTPRelay is the relay facet the SMTP router consumes (structurally matches
// smtpserver.Relay; declared here so smtpserver need not know the syncer).
type SMTPRelay interface {
	LookupProfile(ctx context.Context, addr string) (*relayclient.Profile, bool, error)
	SendMessage(ctx context.Context, to string, prof *relayclient.Profile, m *relayclient.Message) (*relayclient.SendResult, error)
}

// RecordingRelay decorates the relay client so every successful LM send lands
// in the Sent folder (and state.sent on the next push).
type RecordingRelay struct {
	Inner SMTPRelay
	S     *Syncer
}

func (r *RecordingRelay) LookupProfile(ctx context.Context, addr string) (*relayclient.Profile, bool, error) {
	return r.Inner.LookupProfile(ctx, addr)
}

func (r *RecordingRelay) SendMessage(ctx context.Context, to string, prof *relayclient.Profile, m *relayclient.Message) (*relayclient.SendResult, error) {
	res, err := r.Inner.SendMessage(ctx, to, prof, m)
	if err == nil {
		// Never fail an accepted delivery over bookkeeping.
		if qerr := r.S.store.QueueSent(SentRecord{MsgID: res.MsgID, Ts: time.Now().Unix(),
			To: to, Subject: m.Subject, Body: m.Body}); qerr != nil {
			log.Printf("imap sync: queue sent %s: %v", res.MsgID, qerr)
		}
	}
	return res, err
}

// Run polls until ctx is done. Transient relay failures are logged, not
// returned: the bridge must keep serving IMAP from cache while the relay is
// down, and the next tick retries anyway.
func (s *Syncer) Run(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		if err := s.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("imap sync: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// SyncOnce is one full cycle: read the state doc, pull new inbox letters,
// mirror remote flags into the cache, then push local flag/sent changes back
// under CAS. Exported for tests.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	state, err := s.relay.GetState(ctx)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	read, del := state.Doc.Read(), state.Doc.Deleted()
	if err := s.pullInbox(ctx, read, del); err != nil {
		return fmt.Errorf("inbox: %w", err)
	}
	if err := s.store.ApplyRemoteFlags(read, del); err != nil {
		return fmt.Errorf("remote flags: %w", err)
	}
	if err := s.pushLocal(ctx); err != nil {
		return fmt.Errorf("push: %w", err)
	}
	return nil
}

// pullInbox fetches everything above the stored cursor, oldest-first, and
// caches each letter as RFC-5322.
func (s *Syncer) pullInbox(ctx context.Context, read, del map[string]int) error {
	after, err := s.store.MetaInt(metaLastInboxSeq)
	if err != nil {
		return err
	}
	page, err := s.relay.Inbox(ctx, after, inboxPageLimit)
	if err != nil {
		return err
	}
	msgs := append([]relayclient.InboxMessage(nil), page.Messages...)
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Seq < msgs[j].Seq }) // wire order is newest-first
	cursor := after
	for _, im := range msgs {
		if im.Seq > cursor {
			cursor = im.Seq
		}
		mail, err := relayclient.DecodeMail(s.priv, im)
		if err != nil {
			// An undecryptable letter (wrong key, corrupt envelope) must not
			// stall the rest of the inbox.
			log.Printf("imap sync: decode seq %d: %v", im.Seq, err)
			continue
		}
		if del[mail.MsgID] == 1 {
			continue // deleted elsewhere: do not resurrect it locally
		}
		atts := make([]AttachmentBlob, 0, len(mail.Attachments))
		for _, a := range mail.Attachments {
			data, err := s.relay.FetchAttachment(ctx, a)
			if err != nil {
				// 403/missing blobs are normal for same-relay recipients (no
				// LN keysend → no mirror ACL grant yet): degrade the part to a
				// placeholder note instead of aborting the whole inbox sync.
				log.Printf("imap sync: attachment %q of %s: %v", a.Name, mail.MsgID, err)
				atts = append(atts, AttachmentBlob{Att: a, Err: err.Error()})
				continue
			}
			atts = append(atts, AttachmentBlob{Att: a, Data: data})
		}
		raw := BuildRFC822(mail, s.account, atts)
		date := time.Unix(im.ReceivedAt, 0)
		if _, err := s.store.AddMessage(FolderInbox, mail.MsgID, im.Seq, date, raw, read[mail.MsgID] == 1); err != nil {
			return err
		}
	}
	if len(msgs) >= inboxPageLimit {
		log.Printf("imap sync: page limit %d hit; letters between seq %d and %d may have been skipped",
			inboxPageLimit, after, cursor)
	}
	if cursor != after {
		return s.store.SetMetaInt(metaLastInboxSeq, cursor)
	}
	return nil
}

// pushLocal commits pending flag pushes and sent records in ONE CAS update so
// a concurrent PWA write costs a single retry, not two.
func (s *Syncer) pushLocal(ctx context.Context) error {
	flags, err := s.store.PeekPendingFlags()
	if err != nil {
		return err
	}
	sents, err := s.store.PeekPendingSent()
	if err != nil {
		return err
	}
	if len(flags) == 0 && len(sents) == 0 {
		return nil
	}
	_, err = s.relay.UpdateState(ctx, func(doc *relayclient.StateDoc) error {
		for _, f := range flags {
			if f.Seen {
				doc.SetRead(f.MsgID)
			}
			if f.Deleted {
				doc.SetDeleted(f.MsgID)
			}
		}
		for _, r := range sents {
			doc.AddSent(relayclient.SentItem{MsgID: r.MsgID, Ts: r.Ts, To: r.To,
				Subject: r.Subject, Body: r.Body, Bytes: int64(len(r.Body))})
		}
		return nil
	})
	if err != nil {
		return err // rows stay pending; the next tick retries
	}
	// The state push committed: materialize Sent rows and clear pending.
	for _, r := range sents {
		raw := BuildSentRFC822(r, s.account)
		if _, err := s.store.AddMessage(FolderSent, r.MsgID, 0, time.Unix(r.Ts, 0), raw, true); err != nil {
			return err
		}
	}
	return s.store.ClearPending(flags, sents)
}

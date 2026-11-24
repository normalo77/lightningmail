package imapserver

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"sort"
	"time"

	"github.com/emersion/go-imap/v2"
	goimap "github.com/emersion/go-imap/v2/imapserver"
	gmtextproto "github.com/emersion/go-message/textproto"
)

// Options wires one bridge IMAP server.
type Options struct {
	Addr     string
	AuthUser string
	AuthPass string
	// TLSConfig enables STARTTLS. When nil, plaintext LOGIN is allowed
	// (localhost/regtest policy, identical to the SMTP side).
	TLSConfig *tls.Config
	Store     *Store
}

// NewServer builds the go-imap server. LOGIN is the only auth mechanism;
// AUTHENTICATE/SASL is deliberately not offered (single local user, no realm)
// and un-marking flags never propagates (see Store.MarkPendingFlag).
func NewServer(opts Options) *goimap.Server {
	return goimap.New(&goimap.Options{
		NewSession: func(c *goimap.Conn) (goimap.Session, *goimap.GreetingData, error) {
			return &session{opts: &opts}, nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapMove:      {},
			imap.CapIdle:      {},
		},
		TLSConfig:    opts.TLSConfig,
		InsecureAuth: opts.TLSConfig == nil,
	})
}

type selection struct {
	f        *Folder
	tracker  *goimap.SessionTracker
	readOnly bool
}

type session struct {
	opts *Options
	sel  *selection // nil when no mailbox is selected
}

var (
	_ goimap.Session     = (*session)(nil)
	_ goimap.SessionMove = (*session)(nil)
)

func errNo(what string) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Text: what}
}

var errNotSelected = errNo("no mailbox selected")

func errNoMailbox(name string) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeNonExistent, Text: "no such mailbox: " + name}
}

// Login checks the bridge credentials. Both halves are compared in constant
// time so neither user nor password leak through response timing.
func (sess *session) Login(username, password string) error {
	u := subtle.ConstantTimeCompare([]byte(username), []byte(sess.opts.AuthUser))
	p := subtle.ConstantTimeCompare([]byte(password), []byte(sess.opts.AuthPass))
	if u != 1 || p != 1 {
		return goimap.ErrAuthFailed
	}
	return nil
}

func (sess *session) Close() error {
	if sess.sel != nil {
		sess.sel.tracker.Close()
		sess.sel = nil
	}
	return nil
}

// --- fixed mailbox set: no creation, renaming, subscription or APPEND ---

func (sess *session) Create(mailbox string, options *imap.CreateOptions) error {
	return errNo("CREATE not supported: the bridge has fixed INBOX/Sent/Trash mailboxes")
}

func (sess *session) Delete(mailbox string) error {
	return errNo("DELETE not supported: the bridge has fixed INBOX/Sent/Trash mailboxes")
}

func (sess *session) Rename(mailbox, newName string, options *imap.RenameOptions) error {
	return errNo("RENAME not supported: the bridge has fixed INBOX/Sent/Trash mailboxes")
}

func (sess *session) Subscribe(mailbox string) error   { return nil } // no-ops: single user
func (sess *session) Unsubscribe(mailbox string) error { return nil }

func (sess *session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, errNo("APPEND not supported: the bridge records Sent itself")
}

// --- mailbox listing and status ---

func (sess *session) List(w *goimap.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	st := sess.opts.Store
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(patterns) == 0 {
		// LIST "" probes the hierarchy delimiter
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: '/',
		})
	}
	for _, name := range folderNames {
		match := false
		for _, p := range patterns {
			if goimap.MatchList(name, '/', ref, p) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		data := &imap.ListData{
			Mailbox: name,
			Delim:   '/',
			Attrs:   []imap.MailboxAttr{imap.MailboxAttrHasNoChildren},
		}
		if options.ReturnStatus != nil {
			data.Status = st.statusDataLocked(st.folders[name], options.ReturnStatus)
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

func (sess *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	st := sess.opts.Store
	st.mu.Lock()
	defer st.mu.Unlock()
	f := st.folders[mailbox]
	if f == nil {
		return nil, errNoMailbox(mailbox)
	}
	return st.statusDataLocked(f, options), nil
}

func (s *Store) statusDataLocked(f *Folder, opts *imap.StatusOptions) *imap.StatusData {
	d := &imap.StatusData{Mailbox: f.Name}
	if opts.NumMessages {
		n := uint32(len(f.msgs))
		d.NumMessages = &n
	}
	if opts.NumRecent {
		n := uint32(0) // the bridge has no \Recent semantics: every client sees everything
		d.NumRecent = &n
	}
	if opts.UIDNext {
		d.UIDNext = s.uidNext
	}
	if opts.UIDValidity {
		d.UIDValidity = f.uidValidity
	}
	if opts.NumUnseen {
		n := uint32(len(f.msgs)) - f.countFlag(imap.FlagSeen)
		d.NumUnseen = &n
	}
	if opts.NumDeleted {
		n := f.countFlag(imap.FlagDeleted)
		d.NumDeleted = &n
	}
	if opts.Size {
		var sz int64
		for _, m := range f.msgs {
			sz += m.Size
		}
		d.Size = &sz
	}
	return d
}

// --- select / unselect ---

func (sess *session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	st := sess.opts.Store
	st.mu.Lock()
	defer st.mu.Unlock()
	f := st.folders[name]
	if f == nil {
		return nil, errNoMailbox(name)
	}
	if sess.sel != nil {
		sess.sel.tracker.Close()
	}
	sess.sel = &selection{f: f, tracker: f.tracker.NewSession(),
		readOnly: options != nil && options.ReadOnly}

	flags := f.flagsUnion()
	// PermanentFlags is the fixed supported set (not the observed union) so
	// clients can STORE \Seen even in a currently empty mailbox.
	perm := []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged,
		imap.FlagDeleted, imap.FlagDraft, imap.FlagWildcard}
	return &imap.SelectData{
		Flags:             flags,
		PermanentFlags:    perm,
		NumMessages:       uint32(len(f.msgs)),
		FirstUnseenSeqNum: f.firstUnseen(),
		UIDNext:           st.uidNext,
		UIDValidity:       f.uidValidity,
		ReadOnly:          sess.sel.readOnly,
	}, nil
}

func (sess *session) Unselect() error {
	if sess.sel != nil {
		sess.sel.tracker.Close()
		sess.sel = nil
	}
	return nil
}

// --- updates ---

// Poll and Idle must not touch the store lock (lock order mu → tracker.mu),
// they only drain the per-session tracker queue.
func (sess *session) Poll(w *goimap.UpdateWriter, allowExpunge bool) error {
	if sess.sel == nil {
		return nil
	}
	return sess.sel.tracker.Poll(w, allowExpunge)
}

func (sess *session) Idle(w *goimap.UpdateWriter, stop <-chan struct{}) error {
	if sess.sel == nil {
		return nil
	}
	return sess.sel.tracker.Idle(w, stop)
}

// --- fetch ---

func (sess *session) Fetch(w *goimap.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if sess.sel == nil {
		return errNotSelected
	}
	st, f := sess.opts.Store, sess.sel.f
	st.mu.Lock()
	defer st.mu.Unlock()

	// Non-peek BODY[] implies \Seen (RFC 3501) unless the select is read-only.
	markSeen := false
	if !sess.sel.readOnly {
		for _, bs := range options.BodySection {
			if !bs.Peek {
				markSeen = true
				break
			}
		}
	}
	set := sess.staticNumSetLocked(numSet)
	for i, m := range f.msgs {
		seqNum := uint32(i) + 1
		if !numSetContains(set, sess.sel.tracker, m, seqNum) {
			continue
		}
		if markSeen && !m.has(imap.FlagSeen) {
			m.Flags[canonicalFlag(imap.FlagSeen)] = struct{}{}
			if err := st.persistFlagsLocked(m); err != nil {
				return err
			}
			if err := st.markPendingLocked(m.MsgID, true, false); err != nil {
				return err
			}
			// source = this session: its FETCH response already carries the flag
			f.tracker.QueueMessageFlags(seqNum, m.UID, m.flagList(), sess.sel.tracker)
		}
		raw, err := st.rawLocked(m.UID)
		if err != nil {
			return err
		}
		rw := w.CreateMessage(sess.sel.tracker.EncodeSeqNum(seqNum))
		if err := writeFetchMessage(rw, raw, m, options); err != nil {
			return err
		}
	}
	return nil
}

func writeFetchMessage(w *goimap.FetchResponseWriter, raw []byte, m *Msg, options *imap.FetchOptions) error {
	w.WriteUID(m.UID)
	if options.Flags {
		w.WriteFlags(m.flagList())
	}
	if options.InternalDate {
		w.WriteInternalDate(m.InternalDate)
	}
	if options.RFC822Size {
		w.WriteRFC822Size(m.Size)
	}
	if options.Envelope {
		if h, err := gmtextproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			w.WriteEnvelope(goimap.ExtractEnvelope(h))
		}
	}
	if options.BodyStructure != nil {
		w.WriteBodyStructure(goimap.ExtractBodyStructure(bytes.NewReader(raw)))
	}
	for _, bs := range options.BodySection {
		buf := goimap.ExtractBodySection(bytes.NewReader(raw), bs)
		wc := w.WriteBodySection(bs, int64(len(buf)))
		if _, err := wc.Write(buf); err != nil {
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
	}
	// shortcut: BINARY sections are ignored — the capability is not
	// advertised, so only misbehaving clients could request them.
	return w.Close()
}

// --- store ---

func (sess *session) Store(w *goimap.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if sess.sel == nil {
		return errNotSelected
	}
	if sess.sel.readOnly {
		return errNo("mailbox is read-only")
	}
	st, f := sess.opts.Store, sess.sel.f
	err := func() error {
		st.mu.Lock()
		defer st.mu.Unlock()
		set := sess.staticNumSetLocked(numSet)
		for i, m := range f.msgs {
			seqNum := uint32(i) + 1
			if !numSetContains(set, sess.sel.tracker, m, seqNum) {
				continue
			}
			wasSeen, wasDel := m.has(imap.FlagSeen), m.has(imap.FlagDeleted)
			switch flags.Op {
			case imap.StoreFlagsSet:
				m.Flags = map[imap.Flag]struct{}{}
				fallthrough
			case imap.StoreFlagsAdd:
				for _, fl := range flags.Flags {
					m.Flags[canonicalFlag(fl)] = struct{}{}
				}
			case imap.StoreFlagsDel:
				for _, fl := range flags.Flags {
					delete(m.Flags, canonicalFlag(fl))
				}
			default:
				return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "unknown STORE flag operation"}
			}
			if err := st.persistFlagsLocked(m); err != nil {
				return err
			}
			// Only newly SET flags round-trip to /v1/state (OR-only merge):
			// \Seen → read, \Deleted → deleted tombstone for the PWA.
			if !wasSeen && m.has(imap.FlagSeen) {
				if err := st.markPendingLocked(m.MsgID, true, false); err != nil {
					return err
				}
			}
			if !wasDel && m.has(imap.FlagDeleted) {
				if err := st.markPendingLocked(m.MsgID, false, true); err != nil {
					return err
				}
			}
			f.tracker.QueueMessageFlags(seqNum, m.UID, m.flagList(), sess.sel.tracker)
		}
		return nil
	}()
	if err != nil {
		return err
	}
	if !flags.Silent {
		// Unsolicited-flag-free echo: re-fetch only the flag list, as the
		// go-imap reference backend does.
		return sess.Fetch(w, numSet, &imap.FetchOptions{Flags: true})
	}
	return nil
}

// --- expunge / copy / move ---

func (sess *session) Expunge(w *goimap.ExpungeWriter, uids *imap.UIDSet) error {
	if sess.sel == nil {
		return errNotSelected
	}
	st, f := sess.opts.Store, sess.sel.f
	st.mu.Lock()
	defer st.mu.Unlock()
	// Reverse order keeps sequence numbers of the remaining messages valid.
	for i := len(f.msgs) - 1; i >= 0; i-- {
		m := f.msgs[i]
		if uids != nil && !uids.Contains(m.UID) {
			continue
		}
		if !m.has(imap.FlagDeleted) {
			continue
		}
		if err := st.removeMsgLocked(f, i); err != nil {
			return err
		}
	}
	return nil
}

// removeMsgLocked deletes row i (must carry \Deleted semantics upstream):
// pushes the state tombstone, drops the DB row and queues the EXPUNGE update
// for every session (the Poll after the command delivers it to the origin).
func (s *Store) removeMsgLocked(f *Folder, i int) error {
	m := f.msgs[i]
	if err := s.markPendingLocked(m.MsgID, false, true); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM msgs WHERE uid=?`, int64(m.UID)); err != nil {
		return err
	}
	f.msgs = append(f.msgs[:i], f.msgs[i+1:]...)
	f.tracker.QueueExpunge(uint32(i + 1))
	return nil
}

func (sess *session) Copy(numSet imap.NumSet, destName string) (*imap.CopyData, error) {
	if sess.sel == nil {
		return nil, errNotSelected
	}
	st, src := sess.opts.Store, sess.sel.f
	st.mu.Lock()
	defer st.mu.Unlock()
	dest := st.folders[destName]
	if dest == nil {
		return nil, errNoMailbox(destName)
	}
	if dest == src {
		return nil, errNo("source and destination mailboxes are identical")
	}
	var srcUIDs, destUIDs imap.UIDSet
	set := sess.staticNumSetLocked(numSet)
	for i, m := range src.msgs {
		seqNum := uint32(i) + 1
		if !numSetContains(set, sess.sel.tracker, m, seqNum) {
			continue
		}
		newUID, err := st.copyRowLocked(m, dest)
		if err != nil {
			return nil, err
		}
		srcUIDs.AddNum(m.UID)
		destUIDs.AddNum(newUID)
	}
	return &imap.CopyData{UIDValidity: dest.uidValidity, SourceUIDs: srcUIDs, DestUIDs: destUIDs}, nil
}

// copyRowLocked duplicates one message into dest under a fresh UID.
func (s *Store) copyRowLocked(m *Msg, dest *Folder) (imap.UID, error) {
	raw, err := s.rawLocked(m.UID)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO msgs (folder, msg_id, seq, internal_date, seen, deleted, raw)
		VALUES (?,?,?,?,?,?,?)`, dest.Name, m.MsgID, m.Seq, m.InternalDate.Unix(),
		b2i(m.has(imap.FlagSeen)), b2i(m.has(imap.FlagDeleted)), raw)
	if err != nil {
		return 0, err
	}
	uid, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if imap.UID(uid)+1 > s.uidNext {
		s.uidNext = imap.UID(uid) + 1
	}
	nm := &Msg{UID: imap.UID(uid), MsgID: m.MsgID, Seq: m.Seq,
		InternalDate: m.InternalDate, Size: m.Size, Flags: map[imap.Flag]struct{}{}}
	for fl := range m.Flags {
		nm.Flags[fl] = struct{}{}
	}
	dest.msgs = append(dest.msgs, nm)
	sort.Slice(dest.msgs, func(i, j int) bool { return dest.msgs[i].UID < dest.msgs[j].UID })
	dest.tracker.QueueNumMessages(uint32(len(dest.msgs)))
	return nm.UID, nil
}

func (sess *session) Move(w *goimap.MoveWriter, numSet imap.NumSet, destName string) error {
	if sess.sel == nil {
		return errNotSelected
	}
	st, src := sess.opts.Store, sess.sel.f
	st.mu.Lock()
	defer st.mu.Unlock()
	dest := st.folders[destName]
	if dest == nil {
		return errNoMailbox(destName)
	}
	if dest == src {
		return errNo("source and destination mailboxes are identical")
	}
	set := sess.staticNumSetLocked(numSet)
	var srcUIDs, destUIDs imap.UIDSet
	// Reverse order: removals keep the remaining sequence numbers valid.
	for i := len(src.msgs) - 1; i >= 0; i-- {
		m := src.msgs[i]
		seqNum := uint32(i + 1)
		if !numSetContains(set, sess.sel.tracker, m, seqNum) {
			continue
		}
		// The global UID counter keeps the UID valid and unused in dest, so a
		// move is a folder update — no renumbering (RFC 6851 allows it via
		// COPYUID, which we report below).
		if _, err := st.db.Exec(`UPDATE msgs SET folder=? WHERE uid=?`, destName, int64(m.UID)); err != nil {
			return err
		}
		src.msgs = append(src.msgs[:i], src.msgs[i+1:]...)
		dest.msgs = append(dest.msgs, m)
		if src.Name == FolderInbox {
			// Leaving INBOX is a deletion in LM terms (the PWA has no folders):
			// tombstone it in the state doc. Shortcut: moving back cannot
			// un-delete — the state merge is OR-only.
			if err := st.markPendingLocked(m.MsgID, false, true); err != nil {
				return err
			}
		}
		src.tracker.QueueExpunge(seqNum)
		dest.tracker.QueueNumMessages(uint32(len(dest.msgs)))
		srcUIDs.AddNum(m.UID)
		destUIDs.AddNum(m.UID)
	}
	sort.Slice(dest.msgs, func(i, j int) bool { return dest.msgs[i].UID < dest.msgs[j].UID })
	return w.WriteCopyData(&imap.CopyData{
		UIDValidity: dest.uidValidity,
		SourceUIDs:  srcUIDs,
		DestUIDs:    destUIDs,
	})
}

// --- search (small honest subset) ---

func (sess *session) Search(kind goimap.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if !searchSupported(criteria) {
		return nil, errNo("search criteria not supported by the bridge")
	}
	if sess.sel == nil {
		return nil, errNotSelected
	}
	st, f := sess.opts.Store, sess.sel.f
	st.mu.Lock()
	defer st.mu.Unlock()

	var data imap.SearchData
	seqSet := imap.SeqSet{}
	uidSet := imap.UIDSet{}
	for i, m := range f.msgs {
		seqNum := sess.sel.tracker.EncodeSeqNum(uint32(i) + 1)
		if !matchSearch(sess.sel.tracker, m, seqNum, criteria) {
			continue
		}
		uidSet.AddNum(m.UID)
		var num uint32
		switch kind {
		case goimap.NumKindSeq:
			if seqNum == 0 {
				continue
			}
			seqSet.AddNum(seqNum)
			num = seqNum
		case goimap.NumKindUID:
			num = uint32(m.UID)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if data.Max == 0 || num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	if kind == goimap.NumKindSeq {
		data.All = seqSet
	} else {
		data.All = uidSet
	}
	return &data, nil
}

// searchSupported rejects criteria the bridge does not evaluate instead of
// silently returning wrong hits. shortcut: header/body/text search would need
// MIME parsing per message — add it when a client workflow actually needs it.
func searchSupported(c *imap.SearchCriteria) bool {
	return len(c.Header) == 0 && len(c.Body) == 0 && len(c.Text) == 0 &&
		len(c.Not) == 0 && len(c.Or) == 0 &&
		c.SentSince.IsZero() && c.SentBefore.IsZero() &&
		c.Larger == 0 && c.Smaller == 0 && c.ModSeq == nil
}

func matchSearch(tracker *goimap.SessionTracker, m *Msg, seqNum uint32, c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if seqNum == 0 || !set.Contains(seqNum) {
			return false
		}
	}
	for _, set := range c.UID {
		if !set.Contains(m.UID) {
			return false
		}
	}
	// RFC 3501 date comparisons are zone-unaware day granularity.
	day := time.Date(m.InternalDate.Year(), m.InternalDate.Month(), m.InternalDate.Day(), 0, 0, 0, 0, time.UTC)
	if !c.Since.IsZero() && day.Before(truncDay(c.Since)) {
		return false
	}
	if !c.Before.IsZero() && !day.Before(truncDay(c.Before)) {
		return false
	}
	for _, fl := range c.Flag {
		if !m.has(fl) {
			return false
		}
	}
	for _, fl := range c.NotFlag {
		if m.has(fl) {
			return false
		}
	}
	return true
}

func truncDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// --- sequence set helpers (mirrors the go-imap reference backend) ---

// staticNumSetLocked resolves the dynamic "*" against the current mailbox so
// later mutations cannot shift the set mid-command.
func (sess *session) staticNumSetLocked(numSet imap.NumSet) imap.NumSet {
	if imap.IsSearchRes(numSet) {
		return imap.UIDSet{} // SEARCHRES is not supported
	}
	f := sess.sel.f
	switch numSet := numSet.(type) {
	case imap.SeqSet:
		max := uint32(len(f.msgs))
		for i := range numSet {
			staticNumRange(&numSet[i].Start, &numSet[i].Stop, max)
		}
	case imap.UIDSet:
		var max imap.UID
		if n := len(f.msgs); n > 0 {
			max = f.msgs[n-1].UID
		}
		for i := range numSet {
			staticNumRange((*uint32)(&numSet[i].Start), (*uint32)(&numSet[i].Stop), uint32(max))
		}
	}
	return numSet
}

func staticNumRange(start, stop *uint32, max uint32) {
	dyn := false
	if *start == 0 {
		*start = max
		dyn = true
	}
	if *stop == 0 {
		*stop = max
		dyn = true
	}
	if dyn && *start > *stop {
		*start, *stop = *stop, *start
	}
}

// numSetContains matches one message against a static set, translating the
// server-view sequence number into what this client sees (its own expunge
// backlog may shift the view).
func numSetContains(set imap.NumSet, tracker *goimap.SessionTracker, m *Msg, seqNum uint32) bool {
	switch set := set.(type) {
	case imap.SeqSet:
		enc := tracker.EncodeSeqNum(seqNum)
		return enc != 0 && set.Contains(enc)
	case imap.UIDSet:
		return set.Contains(m.UID)
	}
	return false
}

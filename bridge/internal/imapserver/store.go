// Package imapserver serves the LM mailbox over IMAP (Etappe B2): decrypted
// LM letters are cached in a pure-Go SQLite store and exposed as INBOX,
// locally sent letters appear in Sent, deletions land in Trash. Flag changes
// round-trip against the relay's /v1/state document (see sync.go).
package imapserver

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	goimap "github.com/emersion/go-imap/v2/imapserver"
	_ "modernc.org/sqlite" // pure-Go driver: keeps the bridge CGO-free
)

// Fixed mailbox layout: LM has exactly one real mailbox; Sent and Trash are
// local comforts that never round-trip to the relay as folders.
const (
	FolderInbox = "INBOX"
	FolderSent  = "Sent"
	FolderTrash = "Trash"
)

var folderNames = []string{FolderInbox, FolderSent, FolderTrash}

const metaLastInboxSeq = "last_inbox_seq"

// Msg is the runtime index entry of one cached message. The raw RFC-5322
// bytes stay in SQLite and are read on demand to keep the heap small.
type Msg struct {
	UID          imap.UID
	MsgID        string // LM msg_id hex — the /v1/state read/deleted key
	Seq          int64  // relay inbox seq (0 outside INBOX)
	InternalDate time.Time
	Size         int64
	Flags        map[imap.Flag]struct{}
}

func (m *Msg) has(f imap.Flag) bool {
	_, ok := m.Flags[canonicalFlag(f)]
	return ok
}

func (m *Msg) flagList() []imap.Flag {
	l := make([]imap.Flag, 0, len(m.Flags))
	for f := range m.Flags {
		l = append(l, displayFlag(f))
	}
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return l
}

// canonicalFlag lowercases like the go-imap reference backend: flags are
// case-insensitive on the wire but must compare equal in the index.
func canonicalFlag(f imap.Flag) imap.Flag {
	return imap.Flag(strings.ToLower(string(f)))
}

// stdFlags re-displays canonical lowercase keys as the RFC spellings clients
// match against.
var stdFlags = map[imap.Flag]imap.Flag{
	"\\seen":     imap.FlagSeen,
	"\\answered": imap.FlagAnswered,
	"\\flagged":  imap.FlagFlagged,
	"\\deleted":  imap.FlagDeleted,
	"\\draft":    imap.FlagDraft,
}

func displayFlag(f imap.Flag) imap.Flag {
	if s, ok := stdFlags[canonicalFlag(f)]; ok {
		return s
	}
	return f
}

// Folder is one mailbox: the shared in-memory index (UID order) plus a
// tracker that fans unilateral updates out to every selected session, so a
// syncer insert shows up as EXISTS on live connections.
type Folder struct {
	Name        string
	uidValidity uint32
	msgs        []*Msg
	tracker     *goimap.MailboxTracker
}

func (f *Folder) countFlag(fl imap.Flag) uint32 {
	var n uint32
	for _, m := range f.msgs {
		if m.has(fl) {
			n++
		}
	}
	return n
}

func (f *Folder) flagsUnion() []imap.Flag {
	seen := map[imap.Flag]struct{}{}
	for _, m := range f.msgs {
		for fl := range m.Flags {
			seen[fl] = struct{}{}
		}
	}
	l := make([]imap.Flag, 0, len(seen))
	for fl := range seen {
		l = append(l, displayFlag(fl))
	}
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return l
}

func (f *Folder) firstUnseen() uint32 {
	for i, m := range f.msgs {
		if !m.has(imap.FlagSeen) {
			return uint32(i) + 1
		}
	}
	return 0
}

// Store owns the SQLite cache and the three folder views. All methods are
// safe for concurrent use (several IMAP sessions plus the syncer); one mutex
// covers index and DB together so they can never drift apart.
type Store struct {
	db *sql.DB
	// mu guards the folder indexes, the DB and every tracker queue call.
	// Poll/Idle must NOT take it (they only touch per-session trackers),
	// keeping the lock order strictly mu → tracker.mu.
	mu      sync.Mutex
	folders map[string]*Folder
	// uidNext is a global counter: UIDs never repeat across folders, so a
	// MOVE keeps its UID and stays valid and unseen in the destination.
	uidNext imap.UID
}

// OpenStore creates or opens state_dir/bridge.db and loads the folder indexes.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "bridge.db"))
	if err != nil {
		return nil, err
	}
	// Single connection: no SQLITE_BUSY handling needed anywhere, and a
	// personal bridge (one syncer, few IMAP clients) never needs parallelism.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, folders: map[string]*Folder{}}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS msgs (
	uid           INTEGER PRIMARY KEY AUTOINCREMENT,
	folder        TEXT NOT NULL,
	msg_id        TEXT NOT NULL,
	seq           INTEGER NOT NULL DEFAULT 0,
	internal_date INTEGER NOT NULL,
	seen          INTEGER NOT NULL DEFAULT 0,
	deleted       INTEGER NOT NULL DEFAULT 0,
	raw           BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_msgs_folder_msgid ON msgs(folder, msg_id);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_flags (
	msg_id  TEXT PRIMARY KEY,
	seen    INTEGER NOT NULL DEFAULT 0,
	deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pending_sent (
	msg_id  TEXT PRIMARY KEY,
	ts      INTEGER NOT NULL,
	rcpt    TEXT NOT NULL,
	subject TEXT NOT NULL,
	body    TEXT NOT NULL
);`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	var maxUID sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(uid) FROM msgs`).Scan(&maxUID); err != nil {
		return err
	}
	s.uidNext = imap.UID(maxUID.Int64 + 1)
	for _, name := range folderNames {
		f := &Folder{Name: name}
		var uv sql.NullInt64
		if err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, "uid_validity:"+name).Scan(&uv); err == sql.ErrNoRows {
			f.uidValidity = newUIDValidity()
			if _, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES (?, ?)`,
				"uid_validity:"+name, f.uidValidity); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			f.uidValidity = uint32(uv.Int64)
		}
		rows, err := s.db.Query(`SELECT uid, msg_id, seq, internal_date, seen, deleted, LENGTH(raw)
			FROM msgs WHERE folder=? ORDER BY uid`, name)
		if err != nil {
			return err
		}
		for rows.Next() {
			m := &Msg{Flags: map[imap.Flag]struct{}{}}
			var date int64
			var seen, del int
			if err := rows.Scan(&m.UID, &m.MsgID, &m.Seq, &date, &seen, &del, &m.Size); err != nil {
				rows.Close()
				return err
			}
			m.InternalDate = time.Unix(date, 0)
			if seen != 0 {
				m.Flags[canonicalFlag(imap.FlagSeen)] = struct{}{}
			}
			if del != 0 {
				m.Flags[canonicalFlag(imap.FlagDeleted)] = struct{}{}
			}
			f.msgs = append(f.msgs, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		f.tracker = goimap.NewMailboxTracker(uint32(len(f.msgs)))
		s.folders[name] = f
	}
	return nil
}

// newUIDValidity picks a nonzero random UIDVALIDITY (persisted on first use).
func newUIDValidity() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1 // crypto/rand failure is fatal elsewhere anyway
	}
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// Folder returns one mailbox by name.
func (s *Store) Folder(name string) (*Folder, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.folders[name]
	return f, ok
}

// FolderNames lists the fixed mailboxes in LIST order.
func (s *Store) FolderNames() []string { return folderNames }

// AddMessage caches a new RFC-5322 message. Duplicate (folder, msg_id) rows
// are silently ignored so replayed poll pages never double-insert; added
// reports whether the row is new.
func (s *Store) AddMessage(folder, msgID string, seq int64, date time.Time, raw []byte, seen bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.folders[folder]
	if f == nil {
		return false, fmt.Errorf("unknown folder %q", folder)
	}
	seenInt := 0
	if seen {
		seenInt = 1
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO msgs
		(folder, msg_id, seq, internal_date, seen, deleted, raw) VALUES (?,?,?,?,?,0,?)`,
		folder, msgID, seq, date.Unix(), seenInt, raw)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil // already cached
	}
	uid, err := res.LastInsertId()
	if err != nil {
		return false, err
	}
	if imap.UID(uid)+1 > s.uidNext {
		s.uidNext = imap.UID(uid) + 1
	}
	m := &Msg{UID: imap.UID(uid), MsgID: msgID, Seq: seq, InternalDate: date,
		Size: int64(len(raw)), Flags: map[imap.Flag]struct{}{}}
	if seen {
		m.Flags[canonicalFlag(imap.FlagSeen)] = struct{}{}
	}
	f.msgs = append(f.msgs, m)
	f.tracker.QueueNumMessages(uint32(len(f.msgs)))
	return true, nil
}

// Raw returns the full RFC-5322 bytes of one message.
func (s *Store) Raw(uid imap.UID) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rawLocked(uid)
}

func (s *Store) rawLocked(uid imap.UID) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT raw FROM msgs WHERE uid=?`, int64(uid)).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("message uid %d vanished", uid)
	}
	return raw, err
}

// MarkPendingFlag records a flag change for the next /v1/state push. Flags
// are OR-sticky (state.ts never un-marks), so clearing a flag locally is not
// pushed. shortcut: a locally unread message stays read for other clients
// until the user re-marks it there; upgrade when the state doc grows resets.
func (s *Store) MarkPendingFlag(msgID string, seen, deleted bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.markPendingLocked(msgID, seen, deleted)
}

func (s *Store) markPendingLocked(msgID string, seen, deleted bool) error {
	_, err := s.db.Exec(`INSERT INTO pending_flags (msg_id, seen, deleted) VALUES (?,?,?)
		ON CONFLICT(msg_id) DO UPDATE SET
			seen=MAX(pending_flags.seen, excluded.seen),
			deleted=MAX(pending_flags.deleted, excluded.deleted)`,
		msgID, b2i(seen), b2i(deleted))
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// persistFlagsLocked writes the seen/deleted columns of one message.
func (s *Store) persistFlagsLocked(m *Msg) error {
	_, err := s.db.Exec(`UPDATE msgs SET seen=?, deleted=? WHERE uid=?`,
		b2i(m.has(imap.FlagSeen)), b2i(m.has(imap.FlagDeleted)), int64(m.UID))
	return err
}

// ApplyRemoteFlags mirrors the state doc flag maps into the cache: letters
// read/deleted elsewhere (PWA, desktop) get their IMAP flags set without
// producing a local pending push.
func (s *Store) ApplyRemoteFlags(read, del map[string]int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.folders {
		for i, m := range f.msgs {
			var changed bool
			if read[m.MsgID] == 1 && !m.has(imap.FlagSeen) {
				m.Flags[canonicalFlag(imap.FlagSeen)] = struct{}{}
				changed = true
			}
			if del[m.MsgID] == 1 && !m.has(imap.FlagDeleted) {
				m.Flags[canonicalFlag(imap.FlagDeleted)] = struct{}{}
				changed = true
			}
			if !changed {
				continue
			}
			if err := s.persistFlagsLocked(m); err != nil {
				return err
			}
			f.tracker.QueueMessageFlags(uint32(i+1), m.UID, m.flagList(), nil)
		}
	}
	return nil
}

// PendingFlag is one locally changed flag waiting for the /v1/state push.
type PendingFlag struct {
	MsgID   string
	Seen    bool
	Deleted bool
}

// PeekPendingFlags returns (without removing) all queued flag pushes.
func (s *Store) PeekPendingFlags() ([]PendingFlag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT msg_id, seen, deleted FROM pending_flags`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingFlag
	for rows.Next() {
		var p PendingFlag
		var seen, del int
		if err := rows.Scan(&p.MsgID, &seen, &del); err != nil {
			return nil, err
		}
		p.Seen, p.Deleted = seen != 0, del != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// QueueSent records one bridge-sent LM letter for the Sent folder and the
// state.sent list; the syncer materializes both on its next push.
func (s *Store) QueueSent(rec SentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR IGNORE INTO pending_sent (msg_id, ts, rcpt, subject, body)
		VALUES (?,?,?,?,?)`, rec.MsgID, rec.Ts, rec.To, rec.Subject, rec.Body)
	return err
}

// PeekPendingSent returns (without removing) all queued sent records.
func (s *Store) PeekPendingSent() ([]SentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT msg_id, ts, rcpt, subject, body FROM pending_sent`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SentRecord
	for rows.Next() {
		var r SentRecord
		if err := rows.Scan(&r.MsgID, &r.Ts, &r.To, &r.Subject, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClearPending removes exactly the rows that were pushed. The value match
// keeps flags/sends that changed between peek and clear queued for the next
// round instead of dropping them.
func (s *Store) ClearPending(flags []PendingFlag, sents []SentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range flags {
		if _, err := s.db.Exec(`DELETE FROM pending_flags WHERE msg_id=? AND seen=? AND deleted=?`,
			f.MsgID, b2i(f.Seen), b2i(f.Deleted)); err != nil {
			return err
		}
	}
	for _, r := range sents {
		if _, err := s.db.Exec(`DELETE FROM pending_sent WHERE msg_id=?`, r.MsgID); err != nil {
			return err
		}
	}
	return nil
}

// MetaInt reads one int meta value (0 when unset).
func (s *Store) MetaInt(key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v int64
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return v, err
}

// SetMetaInt writes one int meta value.
func (s *Store) SetMetaInt(key string, v int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES (?, ?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, v)
	return err
}

// Package ledger: SQLite-backed account balances + transaction log
// (docs/spec.md §8). Driver modernc.org/sqlite — pure Go, no CGO.
// Money is stored as integer msat; writes use optimistic locking on the
// account.version column (spec §8.2), never balance-UPDATE-without-check.
// v3 (Etappe 4a): persistent auth tokens, blob ACL, storage quota.
package ledger

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

const schemaVersion = 3

type Kind string

const (
	KindPostageOut Kind = "postage_out"
	KindPostageIn  Kind = "postage_in"
	KindTopup      Kind = "topup"
	KindWithdraw   Kind = "withdraw"
	KindFee        Kind = "fee"
)

var (
	ErrNotFound         = errors.New("ledger: account not found")
	ErrInsufficient     = errors.New("ledger: insufficient balance")
	ErrConflict         = errors.New("ledger: version conflict retries exhausted")
	ErrInvalidKind      = errors.New("ledger: invalid tx kind")
	ErrDuplicateAccount = errors.New("ledger: account name or recipient_hash already exists")
	ErrQuotaExceeded    = errors.New("ledger: storage quota exceeded")
	ErrBlobNotFound     = errors.New("ledger: blob not found")
)

const maxRetries = 32

type Ledger struct{ db *sql.DB }

type Account struct {
	ID            int64
	Name          string
	MailboxPubkey []byte
	RecipientHash [32]byte
	BalanceMsat   int64
	QuotaBytes    int64
	Version       int64
}

type Tx struct {
	ID        int64
	AccountID int64
	DeltaMsat int64
	Kind      Kind
	Ref       string
	CreatedAt int64
}

func Open(path string) (*Ledger, error) {
	dsn := path
	if path != ":memory:" {
		dsn = path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	l := &Ledger{db: db}
	if err := l.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

func (l *Ledger) Close() error { return l.db.Close() }

func (l *Ledger) migrate() error {
	var v int
	if err := l.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v == schemaVersion {
		return nil
	}
	if v > schemaVersion {
		return fmt.Errorf("ledger: unsupported schema version %d (max %d)", v, schemaVersion)
	}
	if v != 0 {
		return fmt.Errorf("ledger: unsupported schema version %d", v)
	}
	stmts, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(string(stmts)); err != nil {
		tx.Rollback()
		return fmt.Errorf("ledger: migrate: %w", err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func now() int64 { return time.Now().Unix() }

func RecipientHash(mailboxPubkey []byte) [32]byte {
	return sha256.Sum256(mailboxPubkey)
}

func (l *Ledger) CreateAccount(name string, mailboxPubkey []byte) (*Account, error) {
	h := RecipientHash(mailboxPubkey)
	t := now()
	res, err := l.db.Exec(
		`INSERT INTO account (name, mailbox_pubkey, recipient_hash, balance_msat, quota_bytes, version, created_at, updated_at)
     VALUES (?,?,?,0,104857600,0,?,?)`, name, mailboxPubkey, h[:], t, t)
	if err != nil {
		if isUnique(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAccount, name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Account{ID: id, Name: name, MailboxPubkey: mailboxPubkey,
		RecipientHash: h, BalanceMsat: 0, QuotaBytes: 104857600, Version: 0}, nil
}

func (l *Ledger) GetAccount(name string) (*Account, error) {
	a := &Account{}
	var h []byte
	err := l.db.QueryRow(
		`SELECT id, name, mailbox_pubkey, recipient_hash, balance_msat, quota_bytes, version
     FROM account WHERE name=?`, name).
		Scan(&a.ID, &a.Name, &a.MailboxPubkey, &h, &a.BalanceMsat, &a.QuotaBytes, &a.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	copy(a.RecipientHash[:], h)
	return a, nil
}

func (l *Ledger) LookupByRecipientHash(h [32]byte) (*Account, error) {
	a := &Account{}
	var hb []byte
	err := l.db.QueryRow(
		`SELECT id, name, mailbox_pubkey, recipient_hash, balance_msat, quota_bytes, version
     FROM account WHERE recipient_hash=?`, h[:]).
		Scan(&a.ID, &a.Name, &a.MailboxPubkey, &hb, &a.BalanceMsat, &a.QuotaBytes, &a.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	copy(a.RecipientHash[:], hb)
	return a, nil
}

func (l *Ledger) Balance(name string) (int64, error) {
	a, err := l.GetAccount(name)
	if err != nil {
		return 0, err
	}
	return a.BalanceMsat, nil
}

func (l *Ledger) ApplyDelta(name string, deltaMsat int64, kind Kind, ref string) error {
	if !validKind(kind) {
		return fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		var id, bal, ver int64
		err := l.db.QueryRow(`SELECT id, balance_msat, version FROM account WHERE name=?`, name).
			Scan(&id, &bal, &ver)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		newBal := bal + deltaMsat
		if newBal < 0 {
			return ErrInsufficient
		}
		tx, err := l.db.Begin()
		if err != nil {
			return err
		}
		t := now()
		res, err := tx.Exec(
			`UPDATE account SET balance_msat=?, version=?, updated_at=? WHERE id=? AND version=?`,
			newBal, ver+1, t, id, ver)
		if err != nil {
			tx.Rollback()
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			tx.Rollback()
			time.Sleep(time.Duration(attempt) * time.Millisecond / 4)
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO txlog (account_id, delta_msat, kind, ref, created_at) VALUES (?,?,?,?,?)`,
			id, deltaMsat, string(kind), ref, t); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return nil
	}
	return ErrConflict
}

func (l *Ledger) History(name string, limit int) ([]Tx, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := l.db.Query(
		`SELECT t.id, t.account_id, t.delta_msat, t.kind, COALESCE(t.ref,''), t.created_at
     FROM txlog t JOIN account a ON a.id=t.account_id
     WHERE a.name=? ORDER BY t.id DESC LIMIT ?`, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tx
	for rows.Next() {
		var tx Tx
		if err := rows.Scan(&tx.ID, &tx.AccountID, &tx.DeltaMsat, &tx.Kind, &tx.Ref, &tx.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	return out, rows.Err()
}

// HasMessage checks if msgID already exists in the mailbox (dedup, replay rejection).
func (l *Ledger) HasMessage(msgID [32]byte) (bool, error) {
	var exists int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM mailbox WHERE msg_id=?`, msgID[:]).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// MsgWasSent checks txlog for a postage_out entry with this ref (send dedup).
func (l *Ledger) MsgWasSent(ref string) (bool, error) {
	var exists int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM txlog WHERE kind="postage_out" AND ref=?`, ref).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (l *Ledger) CreditRecipient(name string, amountMsat int64, ref string) error {
	return l.ApplyDelta(name, amountMsat, KindPostageIn, ref)
}

// --- Mailbox (store & forward, spec §8.1 mailbox table) ---

type Message struct {
	MsgID        [32]byte
	AccountID    int64
	Envelope     []byte
	ReceivedMsat int64
	Seq          int64
	Seen         bool
	CreatedAt    int64
}

// PutMessage legt eine zugestellte Nachricht ab. msg_id ist UNIQUE:
// wiederholte Events derselben Zahlung liefern inserted=false zurueck, damit
// der Aufrufer Guthaben NICHT doppelt gutschreibt (Geld-Identitaet!).
func (l *Ledger) PutMessage(msgID [32]byte, accountID int64, envelope []byte, receivedMsat int64) (int64, bool, error) {
	var dupSeq sql.NullInt64
	_ = l.db.QueryRow(`SELECT seq FROM mailbox WHERE msg_id=?`, msgID[:]).Scan(&dupSeq)
	if dupSeq.Valid {
		return dupSeq.Int64, false, nil
	}
	var maxSeq sql.NullInt64
	err := l.db.QueryRow(`SELECT MAX(seq) FROM mailbox WHERE account_id=?`, accountID).Scan(&maxSeq)
	if err != nil {
		return 0, false, err
	}
	nextSeq := int64(1)
	if maxSeq.Valid {
		nextSeq = maxSeq.Int64 + 1
	}
	t := now()
	res, err := l.db.Exec(
		`INSERT OR IGNORE INTO mailbox (msg_id, account_id, envelope, received_msat, seq, seen, created_at)
     VALUES (?,?,?,?,?,0,?)`, msgID[:], accountID, envelope, receivedMsat, nextSeq, t)
	if err != nil {
		return 0, false, err
	}
	n, _ := res.RowsAffected()
	return nextSeq, n > 0, nil
}

func (l *Ledger) ListMessages(accountID int64, afterSeq int64, limit int) ([]Message, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := l.db.Query(
		`SELECT msg_id, account_id, envelope, received_msat, seq, seen, created_at
     FROM mailbox WHERE account_id=? AND seq > ? ORDER BY seq DESC LIMIT ?`,
		accountID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var m Message
		var mid, env []byte
		var seen int
		if err := rows.Scan(&mid, &m.AccountID, &env, &m.ReceivedMsat, &m.Seq, &seen, &m.CreatedAt); err != nil {
			return nil, err
		}
		copy(m.MsgID[:], mid)
		m.Envelope = env
		m.Seen = seen != 0
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// --- Persistent auth tokens (Etappe 4a) ---

const tokenLifetime = 24 * 3600 // 24 hours

func (l *Ledger) StoreToken(tokenHex, accountName string) error {
	h := sha256.Sum256([]byte(tokenHex))
	t := now()
	_, err := l.db.Exec(
		`INSERT OR REPLACE INTO auth_tokens (token_hash, account_name, created_at, expires_at)
     VALUES (?,?,?,?)`, h[:], accountName, t, t+tokenLifetime)
	return err
}

// LookupToken returns the account name for a valid, non-expired token.
func (l *Ledger) LookupToken(tokenHex string) (string, error) {
	h := sha256.Sum256([]byte(tokenHex))
	var name string
	var expires int64
	err := l.db.QueryRow(
		`SELECT account_name, expires_at FROM auth_tokens WHERE token_hash=?`, h[:]).
		Scan(&name, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if now() > expires {
		l.db.Exec(`DELETE FROM auth_tokens WHERE token_hash=?`, h[:])
		return "", nil
	}
	return name, nil
}

// CleanExpiredTokens removes expired tokens from the DB.
func (l *Ledger) CleanExpiredTokens() error {
	_, err := l.db.Exec(`DELETE FROM auth_tokens WHERE expires_at < ?`, now())
	return err
}

// --- Blob ACL + Quota (Etappe 4a) ---

// RegisterBlobRef records that an account owns/has access to a blob.
func (l *Ledger) RegisterBlobRef(accountID int64, sha256 [32]byte, size int64) error {
	t := now()
	_, err := l.db.Exec(
		`INSERT OR IGNORE INTO blob_refs (sha256, account_id, bytes, created_at)
     VALUES (?,?,?,?)`, sha256[:], accountID, size, t)
	return err
}

// HasBlobAccess returns true if the account has a blob_ref for this sha256.
func (l *Ledger) HasBlobAccess(accountID int64, sha256 [32]byte) (bool, error) {
	var exists int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM blob_refs WHERE sha256=? AND account_id=?`,
		sha256[:], accountID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// BlobUsage returns total bytes stored by an account.
func (l *Ledger) BlobUsage(accountID int64) (int64, error) {
	var total sql.NullInt64
	err := l.db.QueryRow(
		`SELECT SUM(bytes) FROM blob_refs WHERE account_id=?`, accountID).Scan(&total)
	if err != nil {
		return 0, err
	}
	if !total.Valid {
		return 0, nil
	}
	return total.Int64, nil
}

// CheckQuota returns nil if account can store additionalBytes without exceeding quota.
func (l *Ledger) CheckQuota(name string, additionalBytes int64) error {
	a, err := l.GetAccount(name)
	if err != nil {
		return err
	}
	used, err := l.BlobUsage(a.ID)
	if err != nil {
		return err
	}
	if used+additionalBytes > a.QuotaBytes {
		return ErrQuotaExceeded
	}
	return nil
}

func validKind(k Kind) bool {
	switch k {
	case KindPostageOut, KindPostageIn, KindTopup, KindWithdraw, KindFee:
		return true
	}
	return false
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

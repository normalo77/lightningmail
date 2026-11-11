// Package ledger: SQLite-backed account balances + transaction log
// (docs/spec.md §8). Driver modernc.org/sqlite — pure Go, no CGO.
// Money is stored as integer msat; writes use optimistic locking on the
// account.version column (spec §8.2), never balance-UPDATE-without-check.
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

const schemaVersion = 1

// schema v2 (mailbox table, store&forward) belongs to Etappe 3/mailbox —
// deliberately not created here (spec §8.1).

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
)

// maxRetries: optimistic locking gives up after this many version conflicts.
// 32 + linear backoff, because the single-writer SQLite pool can starve a
// loser under test-level contention; real relay traffic is far below this.
const maxRetries = 32

type Ledger struct{ db *sql.DB }

type Account struct {
	ID            int64
	Name          string
	MailboxPubkey []byte
	RecipientHash [32]byte
	BalanceMsat   int64
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

// Open creates the DB (path ":memory:" for tests), turns on WAL for files.
func Open(path string) (*Ledger, error) {
	dsn := path
	if path != ":memory:" {
		dsn = path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc + concurrent writers: serialize at the pool level; WAL/
	// busy_timeout covers multi-process. shortcut: single-conn pool, upgrade
	// when relayd shows contention (Etappe 3 benchmarks).
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
		`INSERT INTO account (name, mailbox_pubkey, recipient_hash, balance_msat, version, created_at, updated_at)
     VALUES (?,?,?,0,0,?,?)`, name, mailboxPubkey, h[:], t, t)
	if err != nil {
		if isUnique(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAccount, name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Account{ID: id, Name: name, MailboxPubkey: mailboxPubkey,
		RecipientHash: h, BalanceMsat: 0, Version: 0}, nil
}

func (l *Ledger) GetAccount(name string) (*Account, error) {
	a := &Account{}
	var h []byte
	err := l.db.QueryRow(
		`SELECT id, name, mailbox_pubkey, recipient_hash, balance_msat, version
     FROM account WHERE name=?`, name).
		Scan(&a.ID, &a.Name, &a.MailboxPubkey, &h, &a.BalanceMsat, &a.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	copy(a.RecipientHash[:], h)
	return a, nil
}

// LookupByRecipientHash is the inbox-routing call for the relay: envelope
// tag 0x01 -> account (spec §3.2, §8.1 UNIQUE index).
func (l *Ledger) LookupByRecipientHash(h [32]byte) (*Account, error) {
	a := &Account{}
	var hb []byte
	err := l.db.QueryRow(
		`SELECT id, name, mailbox_pubkey, recipient_hash, balance_msat, version
     FROM account WHERE recipient_hash=?`, h[:]).
		Scan(&a.ID, &a.Name, &a.MailboxPubkey, &hb, &a.BalanceMsat, &a.Version)
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

// ApplyDelta moves the balance of one account with optimistic locking on
// version (spec §8.2). Negative deltas that would underflow return
// ErrInsufficient without writing anything.
func (l *Ledger) ApplyDelta(name string, deltaMsat int64, kind Kind, ref string) error {
	if !validKind(kind) {
		return fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		// 1. read current version outside the write txn (the optimistic part)
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
		// 2. conditional update + log in one txn
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
			tx.Rollback() // version moved under us -> back off and retry
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

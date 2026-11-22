// Etappe R: Versand-Spool (docs/spec-R-spool.md) — the sending relay acts as
// post wagon: failed peer keysend is persisted in pending_send (SQLite,
// survives process restart) and retried by the 60s ticker. Ensure pattern
// like state/retention (CREATE TABLE IF NOT EXISTS, no schemaVersion bump).
// msg_id UNIQUE + INSERT OR IGNORE: a retry can never double-post; recipient
// side is covered by the mailbox msg_id PRIMARY KEY (R0b).
package ledger

type PendingSend struct {
	ID        int64
	MsgID     string // hex of envelope tag 0x02
	Account   string // sender — the dead-refund books to this account
	Recipient string // routing hint from ?to=
	DestNode  string // peer node pubkey resolved on the first attempt
	Envelope  []byte
	BlobRefs  string // JSON array of sha hexes, informational (envelope is authoritative)
	Sats      int64  // postage+tip already debited from the sender
	Status    string // pending | dead
	Attempts  int
	NextTry   int64
	CreatedAt int64
	UpdatedAt int64
}

func (l *Ledger) ensurePendingSend() error {
	_, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS pending_send (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		msg_id      TEXT    NOT NULL UNIQUE,
		account     TEXT    NOT NULL,
		recipient   TEXT,
		dest_node   TEXT,
		envelope    BLOB    NOT NULL,
		blob_refs   TEXT,
		sats        INTEGER NOT NULL,
		status      TEXT    NOT NULL DEFAULT 'pending',
		attempts    INTEGER NOT NULL DEFAULT 0,
		next_try    INTEGER NOT NULL,
		created_at  INTEGER NOT NULL,
		updated_at  INTEGER NOT NULL
	)`)
	return err
}

// SpoolEnqueue stores a pending delivery; false = msg_id already spooled.
// created_at is stamped here (retention anchor), next_try comes from the caller.
func (l *Ledger) SpoolEnqueue(p *PendingSend) (bool, error) {
	if err := l.ensurePendingSend(); err != nil {
		return false, err
	}
	t := now()
	res, err := l.db.Exec(
		`INSERT OR IGNORE INTO pending_send
		 (msg_id, account, recipient, dest_node, envelope, blob_refs, sats, status, attempts, next_try, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,'pending',0,?,?,?)`,
		p.MsgID, p.Account, p.Recipient, p.DestNode, p.Envelope, p.BlobRefs, p.Sats, p.NextTry, t, t)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SpoolDue: pending rows whose backoff has elapsed (retry ticker).
func (l *Ledger) SpoolDue(nowUnix int64, limit int) ([]PendingSend, error) {
	if err := l.ensurePendingSend(); err != nil {
		return nil, err
	}
	rows, err := l.db.Query(
		`SELECT id, msg_id, account, COALESCE(recipient,''), COALESCE(dest_node,''), envelope,
		        COALESCE(blob_refs,''), sats, status, attempts, next_try, created_at, updated_at
		 FROM pending_send WHERE status='pending' AND next_try<=? ORDER BY next_try LIMIT ?`,
		nowUnix, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingSend
	for rows.Next() {
		var p PendingSend
		if err := rows.Scan(&p.ID, &p.MsgID, &p.Account, &p.Recipient, &p.DestNode, &p.Envelope,
			&p.BlobRefs, &p.Sats, &p.Status, &p.Attempts, &p.NextTry, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SpoolDelivered removes the row — "delivered" lives on in the receipts system.
func (l *Ledger) SpoolDelivered(id int64) error {
	_, err := l.db.Exec(`DELETE FROM pending_send WHERE id=?`, id)
	return err
}

func (l *Ledger) SpoolFailed(id, nextTry int64) error {
	_, err := l.db.Exec(`UPDATE pending_send SET attempts=attempts+1, next_try=?, updated_at=? WHERE id=?`,
		nextTry, now(), id)
	return err
}

// SpoolMarkDead flips pending→dead; true only for the caller that performed the
// transition, so the postage refund books exactly once.
func (l *Ledger) SpoolMarkDead(id int64) (bool, error) {
	if err := l.ensurePendingSend(); err != nil {
		return false, err
	}
	res, err := l.db.Exec(`UPDATE pending_send SET status='dead', updated_at=? WHERE id=? AND status='pending'`,
		now(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SpoolPurgeDead drops dead rows older than maxAgeSec (outbox TTL).
func (l *Ledger) SpoolPurgeDead(nowUnix, maxAgeSec int64) error {
	if err := l.ensurePendingSend(); err != nil {
		return err
	}
	_, err := l.db.Exec(`DELETE FROM pending_send WHERE status='dead' AND ?-updated_at > ?`, nowUnix, maxAgeSec)
	return err
}

// OutboxEntry is the GET /v1/outbox wire shape (msg_id/status/since).
type OutboxEntry struct {
	MsgID  string `json:"msg_id"`
	Status string `json:"status"`
	Since  int64  `json:"since"`
}

// SpoolOutbox: pending+dead sends of one sender account (newest first).
func (l *Ledger) SpoolOutbox(account string) ([]OutboxEntry, error) {
	if err := l.ensurePendingSend(); err != nil {
		return nil, err
	}
	rows, err := l.db.Query(
		`SELECT msg_id, status, created_at FROM pending_send
		 WHERE account=? AND status IN ('pending','dead') ORDER BY created_at DESC`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxEntry{}
	for rows.Next() {
		var e OutboxEntry
		if err := rows.Scan(&e.MsgID, &e.Status, &e.Since); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SpoolPendingCount feeds /health spool:{pending:N}.
func (l *Ledger) SpoolPendingCount() (int, error) {
	if err := l.ensurePendingSend(); err != nil {
		return 0, err
	}
	var n int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM pending_send WHERE status='pending'`).Scan(&n)
	return n, err
}

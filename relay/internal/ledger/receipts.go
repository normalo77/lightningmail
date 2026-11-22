// Etappe 6b: delivery receipts (CONCEPT §23, WhatsApp semantics).
//
//	✓  = LN settle at the receiving relay (the sending client knows locally)
//	✓✓ = client fetch: the receiving relay stamps on inbox fetch and
//	     mirrors the receipt to the peers; the sending relay maps it
//	     to the sender account via sha256(sender_pub) = recipientHash.
//
// No read status (deliberately less than WhatsApp). Always on (v0.1).
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
)

// ReceiptStamp = new receipt stamped at inbox fetch (receiving side).
type ReceiptStamp struct {
	MsgID     [32]byte
	SenderPub []byte // 33B compressed, plaintext tag 0x04 of the envelope
	Ts        int64
}

// ReceiptOut = stamped receipt incl. receiving account (for mirroring).
type ReceiptOut struct {
	ReceiptStamp
	AccountID int64
}

// IncomingReceipt = receipt reported by a peer (sending side).
type IncomingReceipt struct {
	MsgIDHex     string `json:"msg_id"`
	SenderPubHex string `json:"sender_pub"`
	Ts           int64  `json:"ts"`
}

func (l *Ledger) ensureReceipts() error {
	_, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS receipts (
		msg_id     BLOB NOT NULL,
		account_id INTEGER NOT NULL,
		sender_pub BLOB NOT NULL,
		ts         INTEGER NOT NULL,
		mirrored   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (msg_id, account_id)
	)`)
	if err != nil {
		return err
	}
	_, err = l.db.Exec(`CREATE TABLE IF NOT EXISTS receipts_in (
		msg_id     BLOB NOT NULL,
		account_id INTEGER NOT NULL,
		ts         INTEGER NOT NULL,
		PRIMARY KEY (msg_id, account_id)
	)`)
	return err
}

// StampReceipts insert-or-ignores fetch stamps; returns only the NEWLY
// stamped ones (for the mirror). Duplicate fetches have no effect.
func (l *Ledger) StampReceipts(accountID int64, items []ReceiptStamp) ([]ReceiptStamp, error) {
	if err := l.ensureReceipts(); err != nil {
		return nil, err
	}
	var fresh []ReceiptStamp
	for _, it := range items {
		res, err := l.db.Exec(
			`INSERT OR IGNORE INTO receipts (msg_id, account_id, sender_pub, ts, mirrored) VALUES (?,?,?,?,0)`,
			it.MsgID[:], accountID, it.SenderPub, it.Ts)
		if err != nil {
			return fresh, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			fresh = append(fresh, it)
		}
	}
	return fresh, nil
}

// PendingReceipts returns unmirrored stamps (retry ticker).
func (l *Ledger) PendingReceipts(limit int) ([]ReceiptOut, error) {
	if err := l.ensureReceipts(); err != nil {
		return nil, err
	}
	rows, err := l.db.Query(
		`SELECT msg_id, account_id, sender_pub, ts FROM receipts WHERE mirrored=0 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReceiptOut
	for rows.Next() {
		var r ReceiptOut
		var mid []byte
		if err := rows.Scan(&mid, &r.AccountID, &r.SenderPub, &r.Ts); err != nil {
			return nil, err
		}
		copy(r.MsgID[:], mid)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (l *Ledger) MarkReceiptsMirrored(items []ReceiptOut) error {
	for _, it := range items {
		if _, err := l.db.Exec(
			`UPDATE receipts SET mirrored=1 WHERE msg_id=? AND account_id=?`,
			it.MsgID[:], it.AccountID); err != nil {
			return err
		}
	}
	return nil
}

// StoreIncomingReceipt maps a peer receipt to the local sender account
// (recipientHash = sha256(sender_pub), as in mailbox routing).
// accountFound=false when the "sender" has no account here (foreign peer).
func (l *Ledger) StoreIncomingReceipt(msgID [32]byte, senderPub []byte, ts int64) (bool, error) {
	if err := l.ensureReceipts(); err != nil {
		return false, err
	}
	acct, err := l.LookupByRecipientHash(sha256.Sum256(senderPub))
	if err != nil {
		return false, nil // unknown sender here = legitimate foreign-peer case
	}
	_, err = l.db.Exec(
		`INSERT OR IGNORE INTO receipts_in (msg_id, account_id, ts) VALUES (?,?,?)`,
		msgID[:], acct.ID, ts)
	return err == nil, err
}

// ListIncomingReceipts for GET /v1/receipts (own account).
func (l *Ledger) ListIncomingReceipts(accountID int64, limit int) ([]map[string]any, error) {
	if err := l.ensureReceipts(); err != nil {
		return nil, err
	}
	rows, err := l.db.Query(
		`SELECT msg_id, ts FROM receipts_in WHERE account_id=? ORDER BY ts LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var mid []byte
		var ts int64
		if err := rows.Scan(&mid, &ts); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"msg_id": hex.EncodeToString(mid), "ts": ts})
	}
	return out, rows.Err()
}

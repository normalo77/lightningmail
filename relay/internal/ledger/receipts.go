// Etappe 6b: Empfangsbestaetigungen (CONCEPT §23, WhatsApp-Semantik).
//
//	✓  = LN-Settle am Empfaenger-Relay (weiss der Absender-Client schon lokal)
//	✓✓ = Client-Abruf: Empfaenger-Relay stempelt beim Inbox-Abruf und
//	     spiegelt den Receipt an die Peers; das Absender-Relay ordnet ihn
//	     via sha256(sender_pub) = recipientHash dem Absender-Konto zu.
//
// Kein Gelesen-Status (bewusst weniger als WhatsApp). Immer an (v0.1).
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
)

// ReceiptStamp = beim Inbox-Abruf gestempelter neuer Empfang (Empfaenger-Seite).
type ReceiptStamp struct {
	MsgID     [32]byte
	SenderPub []byte // 33B compressed, Klartext-Tag 0x04 des Envelopes
	Ts        int64
}

// ReceiptOut = gestempelter Receipt inkl. Empfaenger-Konto (fuer Mirror).
type ReceiptOut struct {
	ReceiptStamp
	AccountID int64
}

// IncomingReceipt = von einem Peer gemeldeter Receipt (Absender-Seite).
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

// StampReceipts insert-or-ignores Abruf-Stempel; zurueck kommen nur die NEU
// gestempelten (fuer den Mirror). Doppelter Abruf bleibt folgenlos.
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

// PendingReceipts liefert ungespiegelte Stempel (Retry-Ticker).
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

// StoreIncomingReceipt ordnet einen Peer-Receipt dem lokalen Absender-Konto zu
// (recipientHash = sha256(sender_pub), wie beim Postfach-Routing).
// accountFound=false, wenn der "Absender" hier kein Konto hat (fremder Peer).
func (l *Ledger) StoreIncomingReceipt(msgID [32]byte, senderPub []byte, ts int64) (bool, error) {
	if err := l.ensureReceipts(); err != nil {
		return false, err
	}
	acct, err := l.LookupByRecipientHash(sha256.Sum256(senderPub))
	if err != nil {
		return false, nil // unbekannter Sender hier = legitimer Fremd-Peer-Fall
	}
	_, err = l.db.Exec(
		`INSERT OR IGNORE INTO receipts_in (msg_id, account_id, ts) VALUES (?,?,?)`,
		msgID[:], acct.ID, ts)
	return err == nil, err
}

// ListIncomingReceipts fuer GET /v1/receipts (eigenes Konto).
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

package ledger

// Etappe A (relay admin panel): aggregate operator views and the account
// cascade delete. Read queries are single-statement GROUPs; the delete runs
// in one tx and reports orphaned blob hashes so the caller can unlink files.

import (
	"database/sql"
	"encoding/hex"
	"time"
)

type AdminAccountRow struct {
	Name        string `json:"name"`
	CreatedAt   int64  `json:"created_at"`
	BalanceMsat int64  `json:"balance_msat"`
	QuotaBytes  int64  `json:"quota_bytes"`
	DriveBytes  int64  `json:"drive_bytes"`
	MailBytes   int64  `json:"mail_bytes"`
	Msgs        int    `json:"msgs"`
	Held        int    `json:"held"`
	StateBytes  int    `json:"state_bytes"`
	LastTx      int64  `json:"last_tx"`
}

type AdminDayRow struct {
	Day     string `json:"day"`
	NewMsgs int    `json:"new_msgs"`
	SatsIn  int64  `json:"sats_in"`
	SatsOut int64  `json:"sats_out"`
}

// ensureAllTables materializes every lazily created table so the admin
// queries below never hit "no such table" on a fresh DB.
func (l *Ledger) ensureAllTables() error {
	for _, ens := range []func() error{
		l.ensureState, l.ensureRetention, l.ensureHold, l.ensureDrive,
		l.ensureReceipts, l.ensurePendingSend, l.ensureWA,
	} {
		if err := ens(); err != nil {
			return err
		}
	}
	return nil
}

type AdminOverview struct {
	RelayName    string            `json:"relay_name"`
	Network      string            `json:"network,omitempty"`
	Generated    int64             `json:"generated"`
	Accounts     []AdminAccountRow `json:"accounts"`
	Days         []AdminDayRow     `json:"days"`
	Totals       map[string]int64  `json:"totals"`
	SpoolPending int               `json:"spool_pending"`
	MailboxTotal int               `json:"mailbox_total"`
}

// AdminOverview: per-account storage/messages plus 14-day traffic.
// accounts is sorted by claimed bytes desc (biggest consumers first).
func (l *Ledger) AdminOverview() (*AdminOverview, error) {
	if err := l.ensureAllTables(); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	out := &AdminOverview{Generated: now, Totals: map[string]int64{}}

	rows, err := l.db.Query(`
SELECT a.name, a.created_at, a.balance_msat, a.quota_bytes,
  (SELECT COALESCE(SUM(CASE WHEN b.kind='drive' THEN b.bytes ELSE 0 END),0) FROM blob_refs b WHERE b.account_id=a.id),
  (SELECT COALESCE(SUM(CASE WHEN b.kind!='drive' THEN b.bytes ELSE 0 END),0) FROM blob_refs b WHERE b.account_id=a.id),
  (SELECT COUNT(*) FROM mailbox m WHERE m.account_id=a.id),
  (SELECT COUNT(*) FROM mailbox m WHERE m.account_id=a.id AND m.hold_until > ?),
  COALESCE((SELECT LENGTH(s.blob) FROM state s WHERE s.account_id=a.id),0),
  (SELECT COALESCE(MAX(t.created_at),0) FROM txlog t WHERE t.account_id=a.id)
FROM account a
ORDER BY (SELECT COALESCE(SUM(b.bytes),0) FROM blob_refs b WHERE b.account_id=a.id) DESC, a.name`, now)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r AdminAccountRow
		if err := rows.Scan(&r.Name, &r.CreatedAt, &r.BalanceMsat, &r.QuotaBytes,
			&r.DriveBytes, &r.MailBytes, &r.Msgs, &r.Held, &r.StateBytes, &r.LastTx); err != nil {
			rows.Close()
			return nil, err
		}
		out.Accounts = append(out.Accounts, r)
		out.Totals["drive_bytes"] += r.DriveBytes
		out.Totals["mail_bytes"] += r.MailBytes
		out.Totals["balance_msat"] += r.BalanceMsat
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out.Totals["accounts"] = int64(len(out.Accounts))

	// Traffic: last 14 days of new letters and sats movement.
	from := now - 14*86400
	msgs := map[string]int{}
	mr, err := l.db.Query(`SELECT date(created_at,'unixepoch'), COUNT(*) FROM mailbox WHERE created_at>=? GROUP BY 1`, from)
	if err != nil {
		return nil, err
	}
	for mr.Next() {
		var d string
		var n int
		if err := mr.Scan(&d, &n); err == nil {
			msgs[d] = n
		}
	}
	mr.Close()

	sats := map[string][2]int64{}
	tr, err := l.db.Query(`SELECT date(created_at,'unixepoch'),
  COALESCE(SUM(CASE WHEN delta_msat>0 THEN delta_msat ELSE 0 END),0),
  COALESCE(SUM(CASE WHEN delta_msat<0 THEN -delta_msat ELSE 0 END),0)
  FROM txlog WHERE created_at>=? GROUP BY 1`, from)
	if err != nil {
		return nil, err
	}
	for tr.Next() {
		var d string
		var din, dout int64
		if err := tr.Scan(&d, &din, &dout); err == nil {
			sats[d] = [2]int64{din, dout}
		}
	}
	tr.Close()

	dayset := map[string]bool{}
	for d := range msgs {
		dayset[d] = true
	}
	for d := range sats {
		dayset[d] = true
	}
	for d := range dayset {
		var dr AdminDayRow
		dr.Day = d
		dr.NewMsgs = msgs[d]
		v := sats[d]
		dr.SatsIn = v[0] / 1000 // msat -> sats (display unit)
		dr.SatsOut = v[1] / 1000
		out.Days = append(out.Days, dr)
	}
	// newest first
	for i, j := 0, len(out.Days)-1; i < j; i, j = i+1, j-1 {
		out.Days[i], out.Days[j] = out.Days[j], out.Days[i]
	}

	_ = l.db.QueryRow(`SELECT COUNT(*) FROM mailbox`).Scan(&out.MailboxTotal)
	_ = l.db.QueryRow(`SELECT COUNT(*) FROM pending_send WHERE status='pending'`).Scan(&out.SpoolPending)
	return out, nil
}

// DeleteAccountCascade removes an account with every row and ACL that
// references it (the orphan recipe from ops, productized). Returns hex
// sha256 of blob files that lost their last ref — caller unlinks them.
func (l *Ledger) DeleteAccountCascade(name string) ([]string, error) {
	if err := l.ensureAllTables(); err != nil {
		return nil, err
	}
	var id int64
	if err := l.db.QueryRow(`SELECT id FROM account WHERE name=?`, name).Scan(&id); err == sql.ErrNoRows {
		return nil, nil // idempotent: nothing to delete
	} else if err != nil {
		return nil, err
	}

	shas, err := func() ([][]byte, error) {
		rows, err := l.db.Query(`SELECT sha256 FROM blob_refs WHERE account_id=?`, id)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var v [][]byte
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return nil, err
			}
			v = append(v, b)
		}
		return v, rows.Err()
	}()
	if err != nil {
		return nil, err
	}

	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, stmt := range []struct {
		q string
		a []any
	}{
		{`DELETE FROM mailbox WHERE account_id=?`, []any{id}},
		{`DELETE FROM receipts WHERE account_id=?`, []any{id}},
		{`DELETE FROM receipts_in WHERE account_id=?`, []any{id}},
		{`DELETE FROM state WHERE account_id=?`, []any{id}},
		{`DELETE FROM txlog WHERE account_id=?`, []any{id}},
		{`DELETE FROM blob_refs WHERE account_id=?`, []any{id}},
		{`DELETE FROM auth_tokens WHERE account_name=?`, []any{name}},
		{`DELETE FROM wa_credentials WHERE account=?`, []any{name}},
		{`DELETE FROM pending_send WHERE account=?`, []any{name}},
		{`DELETE FROM account WHERE id=?`, []any{id}},
	} {
		if _, err := tx.Exec(stmt.q, stmt.a...); err != nil {
			return nil, err
		}
	}
	// wa_wraps hangs off cred_id — drop orphans table-wide (cheap, tiny).
	if _, err := tx.Exec(`DELETE FROM wa_wraps WHERE cred_id NOT IN (SELECT cred_id FROM wa_credentials)`); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var orphans []string
	seen := map[string]bool{}
	for _, sha := range shas {
		h := hex.EncodeToString(sha)
		if seen[h] {
			continue
		}
		seen[h] = true
		var n int
		if err := l.db.QueryRow(`SELECT COUNT(*) FROM blob_refs WHERE sha256=?`, sha).Scan(&n); err != nil {
			continue
		}
		if n == 0 {
			orphans = append(orphans, h)
		}
	}
	return orphans, nil
}

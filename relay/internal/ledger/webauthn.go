// Etappe 6: WebAuthn/Passkey-Speicher (CONCEPT §21).
// Credentials + Schluessel-Wraps pro Konto; Zeremonie-Sessions leben
// fluechtig im relaysrv ( shortcut: single-process relay, kein shared
// Session-Store noetig — upgrade bei Multi-Instanz-Betrieb).
package ledger

import (
	"database/sql"
	"errors"
	"time"
)

type WACredential struct {
	CredID    string // base64url(credential ID)
	Account   string
	Name      string
	PublicKey []byte
	SignCount uint32
	Created   int64
}

func (l *Ledger) ensureWA() error {
	_, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS wa_credentials (
		cred_id   TEXT PRIMARY KEY,
		account   TEXT NOT NULL,
		name      TEXT NOT NULL DEFAULT '',
		pubkey    BLOB NOT NULL,
		signcount INTEGER NOT NULL DEFAULT 0,
		created   INTEGER NOT NULL
	)`)
	if err != nil {
		return err
	}
	_, err = l.db.Exec(`CREATE TABLE IF NOT EXISTS wa_wraps (
		cred_id   TEXT PRIMARY KEY,
		wrap_prf  TEXT NOT NULL DEFAULT '',
		wrap_pass TEXT NOT NULL DEFAULT ''
	)`)
	return err
}

func (l *Ledger) WAStoreCredential(c WACredential) error {
	if err := l.ensureWA(); err != nil {
		return err
	}
	if c.Created == 0 {
		c.Created = time.Now().Unix()
	}
	_, err := l.db.Exec(
		`INSERT OR REPLACE INTO wa_credentials (cred_id, account, name, pubkey, signcount, created)
		 VALUES (?,?,?,?,?,?)`,
		c.CredID, c.Account, c.Name, c.PublicKey, c.SignCount, c.Created)
	return err
}

func (l *Ledger) WALookupCredential(credID string) (WACredential, error) {
	var c WACredential
	if err := l.ensureWA(); err != nil {
		return c, err
	}
	err := l.db.QueryRow(
		`SELECT cred_id, account, name, pubkey, signcount, created FROM wa_credentials WHERE cred_id=?`,
		credID).Scan(&c.CredID, &c.Account, &c.Name, &c.PublicKey, &c.SignCount, &c.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil // zero value = not found (CredID == "")
	}
	return c, err
}

func (l *Ledger) WACredentialsFor(account string) ([]WACredential, error) {
	if err := l.ensureWA(); err != nil {
		return nil, err
	}
	rows, err := l.db.Query(
		`SELECT cred_id, account, name, pubkey, signcount, created FROM wa_credentials
		 WHERE account=? ORDER BY created`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WACredential
	for rows.Next() {
		var c WACredential
		if err := rows.Scan(&c.CredID, &c.Account, &c.Name, &c.PublicKey, &c.SignCount, &c.Created); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (l *Ledger) WAUpdateSignCount(credID string, count uint32) error {
	_, err := l.db.Exec(`UPDATE wa_credentials SET signcount=? WHERE cred_id=?`, count, credID)
	return err
}

func (l *Ledger) WAStoreWraps(credID, wrapPRF, wrapPass string) error {
	if err := l.ensureWA(); err != nil {
		return err
	}
	_, err := l.db.Exec(
		`INSERT OR REPLACE INTO wa_wraps (cred_id, wrap_prf, wrap_pass) VALUES (?,?,?)`,
		credID, wrapPRF, wrapPass)
	return err
}

// WAUpdateWrapPRF hebt nur den PRF-Anteil (PRF-Selbstheilung); der
// Passphrase-Wrap bleibt als Fallback erhalten.
func (l *Ledger) WAUpdateWrapPRF(credID, wrapPRF string) error {
	if err := l.ensureWA(); err != nil {
		return err
	}
	_, err := l.db.Exec(
		`INSERT INTO wa_wraps (cred_id, wrap_prf, wrap_pass) VALUES (?,?,'')
		 ON CONFLICT(cred_id) DO UPDATE SET wrap_prf=excluded.wrap_prf`,
		credID, wrapPRF)
	return err
}

func (l *Ledger) WAGetWraps(credID string) (prf, pass string, err error) {
	if err = l.ensureWA(); err != nil {
		return "", "", err
	}
	err = l.db.QueryRow(`SELECT wrap_prf, wrap_pass FROM wa_wraps WHERE cred_id=?`, credID).Scan(&prf, &pass)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return prf, pass, err
}

func (l *Ledger) WADeleteCredential(credID string) error {
	if _, err := l.db.Exec(`DELETE FROM wa_wraps WHERE cred_id=?`, credID); err != nil {
		return err
	}
	_, err := l.db.Exec(`DELETE FROM wa_credentials WHERE cred_id=?`, credID)
	return err
}
